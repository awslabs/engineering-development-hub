# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import botocore
import utils.aws.boto3_wrapper as utils_boto3
from utils.cache.decorator import soca_cache
from utils.error import SocaError
from utils.response import SocaResponse


client_iam = utils_boto3.get_boto(service_name="iam").message
logger = logging.getLogger("soca_logger")


@soca_cache(prefix="edh:webui:aws:iam:get_instance_profile")
def get_instance_profile(instance_profile_name: str) -> SocaResponse:
    logger.info(f"Get Instance Profile: {instance_profile_name}")
    try:
        _get_instance_profile = client_iam.get_instance_profile(
            InstanceProfileName=instance_profile_name
        )
        logger.debug(f"get_instance_profile Results: {_get_instance_profile}")
        return SocaResponse(success=True, message=_get_instance_profile)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to get_instance_profile for {instance_profile_name} due to {e}"
        )

    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run get_instance_profile due to {e}"
        )


@soca_cache(prefix="edh:webui:aws:iam:list_instance_profiles", ttl=60)
def list_instance_profiles() -> SocaResponse:
    """List every IAM instance profile in the account (paginated). Each entry includes its
    embedded Roles, so callers can inspect the role name/path without a follow-up call."""
    logger.info("Listing IAM instance profiles")
    _instance_profiles = []
    try:
        _paginator = client_iam.get_paginator("list_instance_profiles")
        for _page in _paginator.paginate():
            _instance_profiles.extend(_page.get("InstanceProfiles", []))
        return SocaResponse(success=True, message=_instance_profiles)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to list_instance_profiles due to {e}"
        )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run list_instance_profiles due to {e}"
        )
