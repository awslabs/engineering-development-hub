# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CDK bootstrap state probe.

Lets the installer skip 'cdk bootstrap' when the environment is already at an
acceptable version. Re-bootstrapping is an UpdateStack on CDKToolkit, which a
centrally managed toolkit stack may refuse or have its settings changed by.

Deliberately stdlib plus botocore only, so it is importable without the rest of
the installer helpers.
"""

import logging

from botocore.client import ClientError

logger = logging.getLogger("soca_logger")

# Highest bootstrap version aws-cdk-lib requires for the paths this app uses.
# The binding one is the lookup role (8), not the stack or asset manifest (6):
# the CLI raises InsufficientBootstrapStackVersion during synth, before
# CloudFormation evaluates the template's CheckBootstrapVersion rule.
# Pinned by tests/cdk_bootstrap_version/test_bootstrap_probe.py against a
# throwaway synth, which fails when an aws-cdk-lib bump raises a floor.
CDK_BOOTSTRAP_MIN_VERSION: int = 8

CDK_BOOTSTRAP_DEFAULT_QUALIFIER: str = "hnb659fds"


def build_bootstrap_command(
    common_args: str,
    context: str,
    account_id: str,
    region: str,
    termination_protection: bool = True,
) -> str:
    """The 'cdk bootstrap' command line, assembled in one place.

    Both installers and '--cdk-cmd bootstrap' route through here, so a bootstrap
    is the same command however it was asked for: the same explicit
    aws://account/region target and the same termination-protection choice.

    --require-approval is deliberately absent. cdk bootstrap does not define it
    (verified against CLI 2.1139.0, which prints 'Unknown option(s)' and ignores
    it), so passing it only ever produced a warning.
    """
    _protection = " --termination-protection" if termination_protection else ""

    return (
        f"cdk bootstrap{_protection} {common_args} "
        f"aws://{account_id}/{region} {context}"
    )


def cdk_bootstrap_version(
    ssm_client,
    qualifier: str = CDK_BOOTSTRAP_DEFAULT_QUALIFIER,
) -> int | None:
    """Bootstrap version in this account and region, or None when unknown.

    None covers every uncertain case alike (absent, denied, unparseable)
    because the caller treats them the same way: bootstrap.
    """
    _parameter_name = f"/cdk-bootstrap/{qualifier}/version"

    try:
        _value = ssm_client.get_parameter(Name=_parameter_name)["Parameter"]["Value"]
    except ClientError as e:
        _code = e.response.get("Error", {}).get("Code", "Unknown")
        if _code == "ParameterNotFound":
            logger.debug(f"{_parameter_name} absent, environment is not bootstrapped")
        else:
            logger.debug(f"Unable to read {_parameter_name}: {_code}")
        return None
    except Exception as err:
        logger.debug(f"Unable to read {_parameter_name}: {err}")
        return None

    try:
        return int(_value)
    except (TypeError, ValueError):
        logger.warning(f"{_parameter_name} is not an integer: {_value}")
        return None


def cdk_bootstrap_is_current(
    ssm_client,
    qualifier: str = CDK_BOOTSTRAP_DEFAULT_QUALIFIER,
) -> tuple[bool, int | None]:
    """(whether bootstrap can be skipped, detected version or None)."""
    _version = cdk_bootstrap_version(ssm_client=ssm_client, qualifier=qualifier)

    if _version is None:
        return False, None

    return _version >= CDK_BOOTSTRAP_MIN_VERSION, _version
