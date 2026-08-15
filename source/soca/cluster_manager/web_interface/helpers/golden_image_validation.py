# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Golden Image Post-Publish Validation.

Optional, advisory-only health check that runs after a golden image is
published. Launches a throwaway instance from the published AMI, executes
a configurable validation script via SSM, and stamps the version record
with the result (passed/failed).

Does NOT block publish. Does NOT auto-rollback on failure. Admin decides
what to do if validation fails (they see a badge in the version table).

Validation is opt-in per software stack via a SocaConfig key:
  /configuration/GoldenImage/Validation/<stack_id>/Script

If no script is configured for a stack, validation is skipped entirely.
The script value is the SSM command(s) to run — they should exit 0 on
success, non-zero on failure.

Default validation (when Script is set to "default"):
  - Windows: check DCV agent responds (Test-NetConnection localhost -Port 8443)
  - Linux: check DCV agent responds (ss -tlnp | grep 8443)
"""

import logging
import threading
import time
from typing import Optional

import utils.aws.boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from models import db, SoftwareStackVersion
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

_DEFAULT_VALIDATION_TIMEOUT = 900  # 15 min for the whole validation cycle
_POLL_INTERVAL = 15

_DEFAULT_WINDOWS_CHECK = (
    '$r = Test-NetConnection -ComputerName localhost -Port 8443 -InformationLevel Quiet; '
    'if ($r) { Write-Output "VALIDATION_PASSED" } else { Write-Output "VALIDATION_FAILED"; exit 1 }'
)

_DEFAULT_LINUX_CHECK = (
    'if ss -tlnp | grep -q ":8443"; then echo "VALIDATION_PASSED"; else echo "VALIDATION_FAILED"; exit 1; fi'
)


def trigger_validation(
    app,
    stack_id: int,
    version_id: int,
    ami_id: str,
    os_family: str,
) -> SocaResponse:
    """Fire-and-forget background validation. `app` is the real Flask app object
    (captured in the parent context) for the daemon thread's app_context.

    Returns a SocaResponse as an in-process dispatch ack (consumed programmatically,
    not an HTTP response; intentionally not .as_flask()-wrapped).
    """
    _script = _get_validation_script(stack_id, os_family)
    if not _script:
        logger.info(f"Golden validation: no script configured for stack {stack_id}, skipping")
        return SocaResponse(success=True, message="no validation script configured; skipped")

    # Mark as pending
    _update_validation_status(version_id, "pending")

    _thread = threading.Thread(
        target=_validation_worker,
        args=(app, stack_id, version_id, ami_id, os_family, _script),
        daemon=True,
        name=f"golden-validate-{stack_id}-v{version_id}",
    )
    _thread.start()
    logger.info(f"Golden validation: started for stack {stack_id} version {version_id}")
    return SocaResponse(
        success=True,
        message=f"Validation started for stack {stack_id} version {version_id}",
    )


def _get_validation_script(stack_id: int, os_family: str) -> Optional[str]:
    """Read the validation script from SocaConfig. Returns None if not configured."""
    try:
        _val = SocaConfig(
            key=f"/configuration/GoldenImage/Validation/{stack_id}/Script"
        ).get_value().get("message")
        if not _val:
            return None
        _c = SocaCastEngine(_val).cast_as(expected_type=str)
        _s = _c.get("message", "").strip() if _c.get("success") is True else ""
        if not _s:
            return None
        if _s.lower() == "default":
            return _DEFAULT_WINDOWS_CHECK if os_family == "windows" else _DEFAULT_LINUX_CHECK
        return _s
    except Exception:
        return None


def _get_validation_timeout(stack_id: int) -> int:
    """Read configurable timeout for this stack's validation."""
    try:
        _val = SocaConfig(
            key=f"/configuration/GoldenImage/Validation/{stack_id}/Timeout"
        ).get_value().get("message")
        if _val:
            _c = SocaCastEngine(_val).cast_as(expected_type=int)
            if _c.get("success") is True:
                return _c.get("message")
    except Exception:
        pass
    return _DEFAULT_VALIDATION_TIMEOUT


def _validation_worker(
    app, stack_id: int, version_id: int, ami_id: str, os_family: str, script: str
) -> None:
    """Background worker: launch instance, run check, stamp result."""
    with app.app_context():
        try:
            _passed = _do_validation(stack_id, ami_id, os_family, script)
            _status = "passed" if _passed else "failed"
            logger.info(f"Golden validation: stack {stack_id} version {version_id} → {_status}")
            _update_validation_status(version_id, _status)
        except Exception as err:
            logger.error(f"Golden validation: failed for stack {stack_id}: {err}")
            _update_validation_status(version_id, "failed")


def _do_validation(stack_id: int, ami_id: str, os_family: str, script: str) -> bool:
    """Launch throwaway, run validation script, return True if passed."""
    _resp_ec2 = utils_boto3.get_boto(service_name="ec2")
    if not _resp_ec2.get("success"):
        raise RuntimeError("Failed to get boto3 ec2 client")
    client_ec2 = _resp_ec2.get("message")
    _resp_ssm = utils_boto3.get_boto(service_name="ssm")
    if not _resp_ssm.get("success"):
        raise RuntimeError("Failed to get boto3 ssm client")
    client_ssm = _resp_ssm.get("message")

    _subnet_id = _get_private_subnet()
    _instance_profile_arn = _get_instance_profile_arn()
    _security_group_id = _get_controller_sg()

    if not _subnet_id or not _instance_profile_arn:
        raise RuntimeError("Cannot resolve subnet or instance profile for validation")

    _timeout = _get_validation_timeout(stack_id)
    instance_id = None

    try:
        # Launch
        instance_id = _launch_validation_instance(
            client_ec2, ami_id, _subnet_id, _instance_profile_arn, _security_group_id
        )
        logger.info(f"Golden validation: launched {instance_id} from {ami_id}")

        # Wait for SSM
        _wait_for_ssm(client_ssm, instance_id, _timeout)

        # Run validation script
        _passed = _run_validation_script(client_ssm, instance_id, os_family, script)

        return _passed

    finally:
        if instance_id:
            try:
                client_ec2.terminate_instances(InstanceIds=[instance_id])
                logger.info(f"Golden validation: terminated {instance_id}")
            except Exception:
                pass


def _launch_validation_instance(client_ec2, ami_id: str, subnet_id: str,
                                instance_profile_arn: str,
                                security_group_id: Optional[str]) -> str:
    """Launch a throwaway instance for validation."""
    _params = {
        "ImageId": ami_id,
        "InstanceType": "m7i-flex.large",
        "MinCount": 1,
        "MaxCount": 1,
        "SubnetId": subnet_id,
        "IamInstanceProfile": {"Arn": instance_profile_arn},
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "edh-golden-validation"},
                    {"Key": "edh:Purpose", "Value": "golden-image-validation"},
                    {"Key": "edh:Ephemeral", "Value": "true"},
                ],
            }
        ],
    }
    if security_group_id:
        _params["SecurityGroupIds"] = [security_group_id]

    _response = client_ec2.run_instances(**_params)
    return _response["Instances"][0]["InstanceId"]


def _wait_for_ssm(client_ssm, instance_id: str, total_timeout: int):
    """Wait for SSM to come online, bounded by the total validation timeout."""
    _ssm_deadline = min(time.time() + 600, time.time() + total_timeout)
    while time.time() < _ssm_deadline:
        try:
            _resp = client_ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            if _resp.get("InstanceInformationList"):
                if _resp["InstanceInformationList"][0].get("PingStatus") == "Online":
                    return
        except Exception:
            pass
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"SSM did not come online for validation instance {instance_id}")


def _run_validation_script(client_ssm, instance_id: str, os_family: str, script: str) -> bool:
    """Execute the validation script via SSM and return True if exit code 0."""
    _doc = "AWS-RunPowerShellScript" if os_family == "windows" else "AWS-RunShellScript"

    _resp = client_ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName=_doc,
        Parameters={"commands": [script]},
        TimeoutSeconds=300,
    )
    _command_id = _resp["Command"]["CommandId"]

    # Wait for command completion
    _deadline = time.time() + 360
    while time.time() < _deadline:
        try:
            _inv = client_ssm.get_command_invocation(
                CommandId=_command_id, InstanceId=instance_id
            )
            if _inv["Status"] in ("Success", "Failed", "TimedOut", "Cancelled"):
                break
        except Exception:
            pass
        time.sleep(10)

    _inv = client_ssm.get_command_invocation(
        CommandId=_command_id, InstanceId=instance_id
    )
    return _inv["Status"] == "Success"


def _update_validation_status(version_id: int, status: str) -> None:
    """Stamp the version record with validation result."""
    try:
        _version = SoftwareStackVersion.query.filter_by(id=version_id).first()
        if _version:
            _version.validation_status = status
            db.session.commit()
    except Exception as err:
        db.session.rollback()
        logger.error(f"Golden validation: failed to update status to {status}: {err}")


def _get_private_subnet() -> Optional[str]:
    """First private subnet from cluster config (stored as a list, not CSV)."""
    try:
        _r = SocaConfig(key="/configuration/PrivateSubnets").get_value(return_as=list)
        _subnets = _r.get("message") if _r.get("success") is True else None
        if _subnets:
            _c = SocaCastEngine(_subnets[0]).cast_as(expected_type=str)
            return _c.get("message", "").strip() if _c.get("success") is True else None
    except Exception:
        pass
    return None


def _get_instance_profile_arn() -> Optional[str]:
    try:
        return SocaConfig(key="/configuration/VdiNodeInstanceProfileArn").get_value().get("message")
    except Exception:
        pass
    return None


def _get_controller_sg() -> Optional[str]:
    try:
        return SocaConfig(key="/configuration/ControllerSecurityGroup").get_value().get("message")
    except Exception:
        pass
    return None
