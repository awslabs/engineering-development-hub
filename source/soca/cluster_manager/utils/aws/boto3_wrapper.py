# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
import botocore
import logging
from functools import lru_cache
from typing import Optional, Literal
from utils.error import SocaError
from utils.response import SocaResponse
from utils.version import __version__

logger = logging.getLogger("soca_logger")

# Shared boto3 / botocore error codes, grouped by the condition they represent.
# Centralized here so a caller inspecting err.response["Error"]["Code"] tests
# against one definition rather than a set literal repeated at each call site.
BOTO3_ACCESS_DENIED_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
    }
)

BOTO3_THROTTLING_ERROR_CODES = frozenset(
    {
        "InternalError",
        "ProvisionedThroughputExceededException",
        "RequestLimitExceeded",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    }
)


def get_boto_session_credentials():
    try:
        return SocaResponse(success=True, message=boto3.Session().get_credentials())
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="boto3",
            helper=f"Unable to get boto3 credentials because of {err}",
        )


def get_boto_session_region():
    try:
        return SocaResponse(success=True, message=boto3.Session().region_name)
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="boto3",
            helper=f"Unable to get boto3 region because of {err}",
        )


@lru_cache(maxsize=None)
def get_boto(
    service_name: str,
    region_name: Optional[str] = None,
    extra_config: Optional[bool] = True,
    resource: Optional[bool] = False,
    endpoint_url: Optional[str] = None,
    max_attempts: int = 3,
    retry_mode: Literal[
        "standard", "adaptive"
    ] = "standard",  # note: adaptive is experimental  https://docs.aws.amazon.com/boto3/latest/guide/retries.html#standard-retry-mode
    read_timeout: Optional[int] = None,
    connect_timeout: Optional[int] = None,
) -> SocaResponse:

    # https://docs.aws.amazon.com/boto3/latest/guide/retries.html
    retry_config = {"max_attempts": max_attempts, "mode": retry_mode}

    if extra_config:
        _extra_parameters = {
            "user_agent_extra": f"AwsSolution/SO0072/{__version__}",
            "retries": retry_config,
        }
    else:
        _extra_parameters = {"retries": retry_config}

    # Socket timeouts, opt-in. Left unset by default so every existing caller keeps
    # botocore's defaults (60s read) rather than silently inheriting a new value.
    # Needed by a caller that invokes a long-running Lambda synchronously: the
    # ResourceMirrorTrigger blocks for the whole mirror run, up to its 15 minute
    # timeout, which a 60s read timeout would abort while the run continued
    # server-side -- reporting a client failure over work that then succeeded.
    if read_timeout is not None:
        _extra_parameters["read_timeout"] = read_timeout
    if connect_timeout is not None:
        _extra_parameters["connect_timeout"] = connect_timeout

    # Resolve region BEFORE the S3 endpoint block below, since that
    # block embeds the region in the endpoint URL.
    if not region_name:
        region_name = boto3.Session().region_name
        if not region_name:
            return SocaError.AWS_API_ERROR(
                service_name="boto3",
                helper="Unable to get boto3 region. Please source /etc/environment or export AWS_DEFAULT_REGION=<region_name>",
            )

    # SigV4 + virtual-hosted addressing for S3.
    #
    # Without these, presigned URLs returned by `generate_presigned_url`
    # against a non-us-east-1 bucket get HTTP 403 SignatureDoesNotMatch
    # in the browser. Root cause: boto3 defaults sign against the
    # global / us-east-1 endpoint internally even when `region_name` is
    # passed -- the URL host says regional but the signing-time
    # canonical request was built for global, so signatures don't
    # match at S3's verification step. The bug is latent because every
    # SOCA cluster bucket historically lived in us-east-1 where global
    # == regional. As soon as a non-us-east-1 bucket appears (e.g. the
    # dedicated DCV screenshot bucket in us-east-2), it bites.
    #
    # We do NOT override `endpoint_url` -- boto3 auto-resolves to the
    # correct regional endpoint when `region_name` is set and the
    # signature/addressing config below is in place. Leaving
    # endpoint_url alone preserves operator-supplied VPC interface
    # endpoints (PrivateLink), AWS_ENDPOINT_URL_S3 env var,
    # AWS config-file overrides, and test stubs.
    if service_name == "s3":
        _extra_parameters["signature_version"] = "s3v4"
        _extra_parameters["s3"] = {"addressing_style": "virtual"}

    _config = botocore.config.Config(**_extra_parameters)

    _boto3_params = {
        "service_name": service_name,
        "region_name": region_name,
        "endpoint_url": endpoint_url,
        "config": _config,
    }

    logger.debug(f"Building boto3 {service_name} with params {_boto3_params}")

    try:
        if not resource:
            return SocaResponse(success=True, message=boto3.client(**_boto3_params))
        else:
            return SocaResponse(success=True, message=boto3.resource(**_boto3_params))
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="boto3",
            helper=f"Unable to create boto3 {'resource' if resource else 'client'} for {service_name} because of {err}",
        )
