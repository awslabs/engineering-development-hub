# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.metadata
import logging
import sys
import os
import time
import botocore
import re

from botocore.exceptions import ClientError
from typing import Literal, Optional

import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.cfn_tag_helper import build_dry_run_tag_specifications
from utils.aws.quota_family import quota_match_token
from utils.cache.decorator import soca_cache, _check_response_filter
from utils.datamodels.soca_node import SocaNode
from utils.error import SocaError
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.validators import Validators


client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_service_quotas = utils_boto3.get_boto(service_name="service-quotas").message


def _installed_boto3_version() -> str:
    """
    The installed boto3 version, for diagnostics only.

    Read from package metadata rather than by importing boto3: the AWS SDK usage
    standard reserves a direct `import boto3` for utils/aws/boto3_wrapper.py, and
    this module obtains every client through get_boto(). The whole module was
    previously imported for this one string.

    Never raises. Its only caller is inside an exception handler, so a
    PackageNotFoundError here would replace the API error the operator actually
    needs to read.
    """
    try:
        return importlib.metadata.version("boto3")
    except Exception:
        return "unknown"

logger = logging.getLogger("soca_logger")


def create_placement_group(
    group_name: str,
    strategy: Literal["cluster", "spread", "partition"] = "cluster",
    spread_level: Optional[Literal["spread", "rack"]] = None,
    partition_count: Optional[int] = None,
) -> SocaResponse:
    logger.info(f"Creating Placement Group {group_name=}")

    try:
        _cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        _request_args = {
            "GroupName": group_name,
            "Strategy": strategy,
            "TagSpecifications": [
                {
                    "ResourceType": "placement-group",
                    "Tags": [
                        {"Key": "edh:ClusterId", "Value": _cluster_id},
                        {"Key": "edh:AssociatedStackId", "Value": group_name},
                    ],
                },
            ],
        }

        if strategy == "spread":
            _request_args["SpreadLevel"] = spread_level

        if strategy == "partition":
            _request_args["PartitionCount"] = partition_count

        _create_pg = client_ec2.create_placement_group(**_request_args)

        logger.debug(f"create_pg Results: {_create_pg}")
        return SocaResponse(success=True, message=_create_pg)

    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run create_placement_group because of {err}"
        )


def delete_placement_group(
    group_name: str,
) -> SocaResponse:
    logger.info(f"Deleting Placement Group {group_name=}")
    try:
        _delete_pg = client_ec2.delete_placement_group(
            GroupName=group_name,
        )

        logger.debug(f"_delete_pg Results: {_delete_pg}")
        return SocaResponse(success=True, message=_delete_pg)
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run delete_placement_group because of {err}"
        )


def describe_instances(
    instance_ids: list,
    filters: list = [{"Name": "instance-state-name", "Values": ["pending", "running"]}],
) -> SocaResponse:
    logger.info(f"Running describe_instances with {instance_ids=} and {filters=}")
    try:
        _describe_instances = client_ec2.describe_instances(
            InstanceIds=instance_ids, Filters=filters
        )
        logger.debug(f"describe_instances Results: {_describe_instances}")
        return SocaResponse(success=True, message=_describe_instances)
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_instances because of {err}"
        )


def describe_instances_paginate(
    filters: list = [{"Name": "instance-state-name", "Values": ["pending", "running"]}]
) -> SocaResponse:
    # Note: This function returns a list of dictionary (key = instance type name, value = instance type info) and now raw boto3 response
    logger.info(f"Running describe_instances_paginate with {filters=}")
    _instance_info = []
    try:
        paginator = client_ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=filters):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    _instance_info.append(instance)
        return SocaResponse(success=True, message=_instance_info)
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to describe_instances_paginate because of {err}"
        )


# Wrapper for describe_instances_paginate. Return a list of SocaNode
def describe_instances_as_soca_nodes(
    instance_ids: list | None = None,
    filters: list | None = None,
    scheduler_info: Optional[SocaHpcScheduler] = None,
) -> SocaResponse:
    """
    Returns a list of SocaNode, not the raw boto3 describe_instance response
    Pass an optional SocaHpcScheduler if you want to forward the scheduler information to your SocaNode.scheduler_info object
    """
    # A FRESH list per call. This default was a literal list, which Python binds
    # once at definition, and the scheduler_info branch below APPENDS to it -- so
    # the three scheduler tag filters leaked into the shared default and were
    # silently applied to every later caller that passed no filters and no
    # scheduler_info, narrowing results they never asked to narrow.
    if filters is None:
        filters = [{"Name": "instance-state-name", "Values": ["pending", "running"]}]
    logger.info(f"Running describe_instances_as_soca_nodes: {instance_ids=} {filters=}")

    try:
        paginator = client_ec2.get_paginator("describe_instances")
        if scheduler_info:
            logger.debug(f"{scheduler_info=} passed, adding extra filters if needed")
            # Adding additional filters if scheduler_info is not already specified
            _existing_filters = [filter["Name"] for filter in filters]
            if not "tag:edh:SchedulerEndpoint" in _existing_filters:
                logger.debug(
                    f"Adding tag:edh:SchedulerEndpoint = [{scheduler_info.endpoint}]"
                )
                filters.append(
                    {
                        "Name": "tag:edh:SchedulerEndpoint",
                        "Values": [scheduler_info.endpoint],
                    }
                )

            if not "tag:edh:SchedulerProvider" in _existing_filters:
                logger.debug(
                    f"Adding tag:edh:SchedulerProvider = [{scheduler_info.provider.value}]"
                )
                filters.append(
                    {
                        "Name": "tag:edh:SchedulerProvider",
                        "Values": [
                            scheduler_info.provider.value
                        ],  # need the Enum, not  <SocaHpcSchedulerProvider.OPENPBS: 'openpbs'>
                    }
                )

            if not "tag:edh:SchedulerIdentifier" in _existing_filters:
                logger.debug(
                    f"Adding tag:edh:SchedulerIdentifier = [{scheduler_info.identifier}]"
                )
                filters.append(
                    {
                        "Name": "tag:edh:SchedulerIdentifier",
                        "Values": [scheduler_info.identifier],
                    }
                )

        paginate_args = {"Filters": filters}
        if instance_ids:
            paginate_args["InstanceIds"] = instance_ids

        pages = list(paginator.paginate(**paginate_args))

        _instance_list = []
        for _page in pages:
            for _reservation in _page.get("Reservations", []):
                for _instance in _reservation.get("Instances", []):
                    logger.debug(f"Instance {_instance.get('InstanceId')} found")
                    try:
                        _instance_list.append(
                            SocaNode.from_ec2_instance(
                                instance=_instance, scheduler_info=scheduler_info
                            )
                        )
                    except Exception as err:
                        logger.error(
                            f"Unable to parse instance {_instance} due to {err}"
                        )
                        continue

        return SocaResponse(success=True, message=_instance_list)

    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_instances with paginate because of {err}"
        )


@soca_cache(
    prefix="edh:webui:aws:ec2:describe_instance_type"
)  # note: ok to use long ttl (Default) as these EC2 instance info won't change
def describe_instance_types(instance_types: list[str]) -> SocaResponse:
    logger.info(f"Describe Instance Type for {instance_types}")
    try:
        if Validators.is_list_length_greater_than(instance_types, 100):  # AWS DescribeInstanceTypes max is 100 (inclusive)
            return SocaError.GENERIC_ERROR(
                helper="You cannot pass more than 100 instance types in a single call."
            )

        _describe_instance_types = client_ec2.describe_instance_types(
            InstanceTypes=instance_types
        )
        logger.debug(f"Describe Instance Type Results: {_describe_instance_types}")
        return SocaResponse(success=True, message=_describe_instance_types)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to describe_instance_types for {instance_types} due to {e}"
        )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_instance_types due to {e}"
        )


@soca_cache(
    prefix="edh:webui:aws:ec2:describe_subnets", ttl=3600
)  # note: Configure a low TTL if the AMI is deregistered from the AWS account through the AWS Management Console or API outside of SOCA
def describe_subnets(subnet_ids: list[str]) -> SocaResponse:
    logger.info(f"Describe subnet for {subnet_ids}")
    try:
        _describe_subnets = client_ec2.describe_subnets(SubnetIds=subnet_ids)
        logger.debug(f"Describe Subnets  Results: {_describe_subnets}")
        return SocaResponse(success=True, message=_describe_subnets)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to describe_subnets for {subnet_ids} due to {e}"
        )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_subnets due to {e}"
        )


@soca_cache(
    prefix="edh:webui:aws:ec2:describe_capacity_reservations", ttl=15
)  # Use a very low TTL for this cache.
def describe_capacity_reservations(capacity_reservation_ids: list[str]) -> SocaResponse:
    logger.info(f"Describe Capacity Reservations for {capacity_reservation_ids}")
    try:
        _describe_capacity_reservations = client_ec2.describe_capacity_reservations(
            CapacityReservationIds=capacity_reservation_ids
        )
        logger.debug(
            f"Describe Capacity Reservations  Results: {_describe_capacity_reservations}"
        )
        return SocaResponse(success=True, message=_describe_capacity_reservations)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to describe_capacity_reservations for {capacity_reservation_ids} due to {e}"
        )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_capacity_reservations due to {e}"
        )


@soca_cache(
    prefix="edh:webui:aws:ec2:describe_security_groups", ttl=3600
)  # note: Configure a low TTL if the AMI is deregistered from the AWS account through the AWS Management Console or API outside of SOCA
def describe_security_groups(security_groups_ids: list[str]) -> SocaResponse:
    logger.info(f"Describe Security Groups Type for {security_groups_ids}")
    try:
        _describe_security_groups = client_ec2.describe_security_groups(
            GroupIds=security_groups_ids
        )
        logger.debug(f"Describe Security Groups Results: {_describe_security_groups}")
        return SocaResponse(success=True, message=_describe_security_groups)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to describe_security_groups for {security_groups_ids} due to {e}"
        )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_security_groups due to {e}"
        )


@soca_cache(
    prefix="edh:webui:aws:ec2:describe_images",
    ttl=3600,
    cache_if=lambda r: _check_response_filter(r, "message.Images.0.State", "available"),
)  # note: Configure a low TTL if the AMI is deregistered from the AWS account through the AWS Management Console or API outside of SOCA. Only cache if the image is available
def describe_images(
    image_ids: list,
    filters: list = [{"Name": "state", "Values": ["available"]}],
) -> SocaResponse:
    logger.info(f"Retrieving information about AMI {image_ids} with filters {filters}")
    try:
        ami_info = client_ec2.describe_images(ImageIds=image_ids, Filters=filters)
        logger.debug(f"AMI info: {ami_info}")
        return SocaResponse(success=True, message=ami_info)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to fetch AMI {image_ids} due to {e}"
        )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_images due to {e}"
        )


@soca_cache(prefix="edh:webui:aws:ec2:is_ebs_optimized")
def is_ebs_optimized(instance_types: list[str]) -> SocaResponse:
    try:
        logger.info(f"Checking if {instance_types} supports EBS Optimization")
        _describe_instances_type = describe_instance_types(
            instance_types=instance_types
        )
        if _describe_instances_type.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Failed to check EBS optimization for {instance_types}: {_describe_instances_type.get('message')}"
            )
        else:
            _instances_info = _describe_instances_type.get("message")
            _details_list = _instances_info.get("InstanceTypes", [])

        for _details in _details_list:
            instance_type = _details.get("InstanceType")
            ebs_support = (
                _details.get("EbsInfo", {})
                .get("EbsOptimizedSupport", "unsupported")
                .lower()
            )
            if ebs_support not in {"default", "supported"}:
                logger.info(f"{instance_type} does not support Ebs Optimized")
                return SocaResponse(success=True, message=False)

        _found_instance_types = {_d["InstanceType"] for _d in _details_list}
        _missing_instance_types = set(instance_types) - _found_instance_types
        if _missing_instance_types:
            return SocaError.GENERIC_ERROR(
                helper=f"Instance types not found: {_missing_instance_types}, default to EbsOptimized=False"
            )

        logger.debug("All instances are EBS Optimized")
        return SocaResponse(success=True, message=True)

    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Failed to check EBS optimization for {instance_types}: {e}"
        )


def get_instance_types_by_architecture(instance_type_pattern: list) -> dict:
    """
    This function take a list of EC2 pattern such as c5.large, c6i.* and generate the relevant list of associated instance type
    grouped by architecture:
    {"x86_64": ["instance1", ...], "arm64": [...]}
    """
    logger.info(
        f"Building all supported EC2 instance type based on {instance_type_pattern}"
    )

    if (_is_list := SocaCastEngine(data=instance_type_pattern).cast_as(list)).get(
        "success"
    ):
        SocaCastEngine(data=_is_list.get("message"))
    else:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to cast {instance_type_pattern} to list"
        )

    _matching_instances = {"x86_64": [], "arm64": [], "i386": []}

    try:
        paginator = client_ec2.get_paginator("describe_instance_types")
        for page in paginator.paginate(
            MaxResults=100,
            Filters=[
                {
                    "Name": "instance-type",
                    "Values": sorted(set(instance_type_pattern)),
                },
            ],
        ):
            for instance_type in page["InstanceTypes"]:
                _instance_type = instance_type["InstanceType"]
                _instance_arch = instance_type["ProcessorInfo"][
                    "SupportedArchitectures"
                ][0]
                _matching_instances[_instance_arch].append(_instance_type)

    except botocore.exceptions.ClientError as e:
        return SocaResponse(
            success=False,
            message=f"Error fetching instance types: {e}. Verify if the instance type and if there is any newer version of boto {_installed_boto3_version()}",
        )

    except Exception as e:
        return SocaResponse(
            success=False,
            message=f"Unexpected error querying describe_instance_types: {e}",
        )

    return SocaResponse(success=True, message=_matching_instances)


def create_capacity_dry_run(
    disk_size: int,
    security_group_id: list,
    instance_type: str,
    instance_profile: str,
    subnet_id: str,
    user_data: str,
    image_id: str,
    desired_capacity: int,
    key_name: str,
    placement: Optional[str] = "default",
    hibernate: Optional[bool] = False,
    custom_tags: Optional[dict] = {},
    volume_type: Optional[str] = "gp2",
    metadata_http_tokens: Optional[str] = "required",
    node_type: Optional[str] = None,
    volume_iops: Optional[int] = None,
    volume_throughput: Optional[int] = None,
) -> SocaResponse:
    """
    Run EC2 RunInstance DryRun to validate basic parameter config
    DryRun won't validate that capacity is available - use odcr_helper for that
    """
    _enable_dryrun = (
        SocaConfig(key="/configuration/FeatureFlags/Hpc/EnableDryRun")
        .get_value(return_as=bool, default=False)
        .get("message")
    )
    if _enable_dryrun is False:
        logger.info(
            "DryRun is disabled via /configuration/FeatureFlags/Hpc/EnableDryRun, skipping dryrun"
        )
        return SocaResponse(
            success=True,
            message="DryRun is disabled via /configuration/FeatureFlags/Hpc/EnableDryRun, skipping dryrun",
        )

    try:
        logger.debug("Trying to perform DryRun with")
        _build_tags = build_dry_run_tag_specifications(
            custom_tags=custom_tags, node_type=node_type
        )
        if _build_tags.get("success") is False:
            return _build_tags
        _tag_specifications = _build_tags.get("message")

        _get_image_info = describe_images(image_ids=[image_id])
        if _get_image_info.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve AMI information: {_get_image_info.get('message')}"
            )
        else:
            _ami_information = _get_image_info.get("message").get("Images")[0]

        logger.info("Submitting EC2 run_instance DryRun")
        _root_ebs = {
            "DeleteOnTermination": True,
            "VolumeSize": disk_size,
            "VolumeType": volume_type,
            "Encrypted": True,
        }
        # io1/io2 reject a missing Iops and gp2 rejects any, so only send what
        # the caller resolved.
        for _ebs_key, _value in (("Iops", volume_iops), ("Throughput", volume_throughput)):
            if not _value:
                continue
            _cast = SocaCastEngine(data=_value).cast_as(int)
            if _cast.get("success") is not True:
                return SocaError.GENERIC_ERROR(
                    helper=f"Root volume {_ebs_key} {_value!r} is not an integer"
                )
            _root_ebs[_ebs_key] = _cast.get("message")
        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": _ami_information.get("RootDeviceName"),
                    "Ebs": _root_ebs,
                },
            ],
            MaxCount=desired_capacity,  # note: capacity count is managed by odcr_helper
            MinCount=desired_capacity,
            SecurityGroupIds=security_group_id,
            InstanceType=instance_type,
            IamInstanceProfile={"Arn": instance_profile},
            SubnetId=subnet_id,
            MetadataOptions={"HttpTokens": metadata_http_tokens},
            Placement={"Tenancy": placement},  # default if not specified
            UserData=user_data,
            ImageId=image_id,
            KeyName=key_name,
            DryRun=True,
            HibernationOptions={"Configured": hibernate},  # default if not specified
            TagSpecifications=_tag_specifications,
        )

    except ClientError as err:
        _error_code = err.response["Error"].get("Code")
        if _error_code == "DryRunOperation":
            return SocaResponse(success=True, message=None)
        elif _error_code in utils_boto3.BOTO3_ACCESS_DENIED_ERROR_CODES:
            # Not a capacity problem: the caller is not permitted to RunInstances
            # with these parameters. A tag-policy SCP conditioned on aws:RequestTag
            # is the common cause when the probe's tag set is incomplete.
            return SocaError.AWS_API_ERROR(
                service_name="ec2",
                helper=(
                    f"DryRun denied by IAM or an SCP ({_error_code}), this is NOT a capacity shortage. "
                    f"Tags submitted with the probe: {_tag_specifications}. "
                    f"Verify the controller role and any tag-policy SCP allow ec2:RunInstances with these tags. "
                    f"Original error: {err.response['Error']}"
                ),
            )
        else:
            return SocaError.AWS_API_ERROR(
                service_name="ec2",
                helper=f"Unable to launch capacity: {err.response['Error']}",
            )
    except Exception as err:
        return SocaError.GENERIC_ERROR(helper=f"Unable to launch capacity: {err}")


# Two different things are cached here, on purpose.
#
# get_ec2_quotas() is DISCOVERY: which "Running On-Demand ..." quotas exist and
# what their quota codes are. ec2 exposes ~1750 quotas and only ~10 are wanted,
# so a full paginate costs ~18 ListServiceQuotas requests at the maximum page
# size (~89 at the default one, measured us-east-2 2026-09-12). That mapping of
# name to code effectively never changes, so it is cached for a day.
#
# get_ec2_quota_value() is the VALUE, which does change the moment an operator's
# quota increase is granted. ListServiceQuotas accepts a QuotaCode filter, so one
# quota costs exactly ONE request (~0.5s) and needs no IAM beyond the
# servicequotas:ListServiceQuotas the controller already has. Keep this window
# short: a stale limit compared against live usage is what rejects a job whose
# quota was raised minutes ago.
#
# ListServiceQuotas is throttled at 10 requests/second per account and is not
# adjustable, so do not restore a full paginate to the per-job path: four
# controller crons run every minute and soca_cache has no single-flight.
#
# Both windows are operator-tunable. The TTLs are passed as CALLABLES because the
# decorator runs once at import: an int read from configuration here would be
# frozen until the controller restarted.
QUOTA_VALUE_TTL_DEFAULT = 900  # 15 minutes
QUOTA_DISCOVERY_TTL_DEFAULT = 86400  # 24 hours
QUOTA_REVALIDATION_FLOOR_DEFAULT = 60  # see _may_revalidate
QUOTA_REVALIDATION_MINT_GRACE = 2.0  # seconds; "I just opened this window"
QUOTA_TTL_MIN = 15
QUOTA_TTL_MAX = 86400
QUOTA_PAGE_SIZE = 100  # API maximum; the default is ~20 and costs 5x the requests


def _quota_ttl(config_key: str, default: int) -> int:
    """
    Operator-tunable cache window, clamped. A missing or unparseable value falls
    back to the default rather than to zero, which would turn every quota check
    into a fresh API call and risk throttling the account.
    """
    try:
        _value = (
            SocaConfig(key=f"/configuration/ServiceQuotas/{config_key}")
            .get_value(return_as=int, default=default)
            .get("message")
        )
        return max(QUOTA_TTL_MIN, min(int(_value), QUOTA_TTL_MAX))
    except Exception as err:  # noqa: BLE001
        logger.warning(
            f"Unable to read /configuration/ServiceQuotas/{config_key} ({err}), using {default}s"
        )
        return default


ONDEMAND = "on-demand"
SPOT = "spot"

# Why a quota check produced no verdict. Returned as message["skipped"] alongside
# success=True, replacing the bare status_code=201 sentinel the caller used to
# test for: 201 could not distinguish "an operator turned the check off" from
# "this family has no quota for this lifecycle", and a reader had no way to learn
# what the number meant without finding the one comment that explained it.
QUOTA_SKIPPED_DISABLED = "quota-check-disabled"
QUOTA_SKIPPED_NO_QUOTA_FOR_LIFECYCLE = "no-quota-for-lifecycle"

# Status code marking a failure where the quota COULD NOT BE READ, as distinct
# from one where it was read and is genuinely exhausted. Both arrive at a caller
# as success=False, so a caller that cannot tell them apart refuses a launch
# because Service Quotas or EC2 was briefly throttled.
#
# An interactive caller should ADMIT on this code. That matches the fail-open
# bias plan_starts_within_quota() already documents, and it is safe because AWS
# still enforces the real limit at RunInstances: the worst case is the error the
# gate exists to pre-empt, whereas failing closed invents a refusal that no
# quota justifies. A genuine exhaustion keeps the default error status.
QUOTA_CHECK_UNAVAILABLE = 503


def quota_check_skip_reason(response) -> str:
    """
    The reason a quota check was SKIPPED, or None if it was not skipped.

    Exists because reading it inline crashed the fail-open path. On success the
    response's message is a dict carrying "skipped"; on failure SocaError builds
    message as a STRING. So `(response.get("message") or {}).get("skipped")` --
    which all three interactive gates used -- raised AttributeError on any failed
    check, turning an intended admit into an HTTP 500. The gates fell through to
    that line precisely because the fail-open branch does not return.

    A single shape-safe reader is used by every gate instead, so the mistake cannot
    be repeated in one of them and missed in the others.
    """
    if response is None:
        return None
    if response.get("success") is not True:
        # A failed check was not "skipped", whatever its message looks like.
        return None
    _message = response.get("message")
    if not Validators.is_dict(_message):
        return None
    return _message.get("skipped")


def merge_quota_charges(base: dict, addition: dict) -> dict:
    """
    Add one set of per-quota vcpu charges onto another, returning a new dict.

    Used for the ADDITIVE dimension of a job's request: the spot/on-demand split,
    where a job genuinely launches nodes of both lifecycles and both charges are
    real. Returns a copy rather than mutating, so a caller cannot accidentally book
    capacity into a map shared with the rest of the scheduling pass.
    """
    _merged = dict(base or {})
    for _quota_name, _vcpus in (addition or {}).items():
        _merged[_quota_name] = _merged.get(_quota_name, 0) + _vcpus
    return _merged


def accumulate_candidate_charge(charges: dict, quota_check_message: dict) -> dict:
    """
    Add one validated quota check onto a single candidate's running charges.

    Reads the quota row and the CHARGE from a validate_ec2_quota_for_instance
    message, returning a new dict. Exists so the choice of field is executable by a
    test: it lived inside provision_capacity(), which needs a scheduler, a database
    session and a live EC2 endpoint to drive, so the only guard possible was a
    substring search of the source -- and reading the wrong field there is how both
    accounting defects on this path reached review.

    charged_vcpus, not requested_vcpus: they differ for a job launching into a
    counted reservation, whose charge is 0 because the reservation's vcpus are
    already in measured usage. And not running_vcpus, which is measured usage with
    any override passed in already folded back, so accumulating it compounds.
    """
    _charges = dict(charges or {})
    _quota_name = (quota_check_message or {}).get("quota_name")
    if _quota_name is None:
        return _charges
    _charged = (quota_check_message or {}).get("charged_vcpus") or 0
    _charges[_quota_name] = _charges.get(_quota_name, 0) + _charged
    return _charges


def fold_candidate_charges(charges_by_candidate: dict) -> dict:
    """
    Collapse per-candidate charges to the capacity one job can actually consume.

    Takes {candidate_instance_type: {quota_name: vcpus}} and returns
    {quota_name: vcpus} using the MAXIMUM across candidates, not the sum.

    instance_types is a candidate LIST for EC2 Fleet, which picks ONE type and
    launches the job's node count of it. Summing across candidates books capacity
    that will never all exist, and the effect is perverse: adding candidate types
    to improve placement odds made a job progressively harder to admit, because
    each candidate was measured against the phantom reservation its own siblings
    had just booked. A job could refuse itself.

    max rather than the first candidate's figure because candidates may differ in
    vcpus per instance, and the booking should stay conservative -- whichever
    candidate Fleet picks, the capacity booked is at least what it consumes.

    Every quota row present in the input appears in the output, including one whose
    charge folds to 0 (a reservation-targeted job). Booking 0 and omitting the row
    are equivalent to the caller, but the row is what shows an operator that it was
    considered and deliberately not charged.
    """
    _folded = {}
    for _charges in (charges_by_candidate or {}).values():
        for _quota_name, _vcpus in (_charges or {}).items():
            if _quota_name not in _folded or _vcpus > _folded[_quota_name]:
                _folded[_quota_name] = _vcpus
    return _folded


def classify_quota_gate(response) -> dict:
    """
    Turn a validate_ec2_quota_for_instance() response into a gate verdict.

    Exists so the admit/refuse decision can be EXECUTED by a test. The three
    interactive gates previously inlined this reasoning inside Flask handlers that
    need a request context, a user, a software stack and a cluster config to run, so
    the only tests possible asserted on the SHAPE of the source. Two defects reached
    review through that gap: a fail-open branch that collapsed "could not read the
    quota" into "no such instance family" and admitted a mistyped instance type, and
    an inline skip read that raised AttributeError and returned HTTP 500 on the very
    path meant to admit. Both are behaviours a source-shape assertion cannot see.

    Returns a dict with:
      admit       -- True when the launch may proceed.
      refusal     -- the operator-facing reason, set only when admit is False.
      unavailable -- True when the quota could not be READ, as opposed to having
                     been shown to be exhausted. Admitting is correct here: AWS
                     still enforces the real limit at RunInstances, whereas
                     refusing invents a denial no quota justifies.
      skip_reason -- why the check was skipped, or None.
    """
    if response is None:
        # No verdict is not a refusal. A caller that cannot even obtain a response
        # is in the unavailable case, not the exhausted one.
        return {
            "admit": True,
            "refusal": None,
            "unavailable": True,
            "skip_reason": None,
        }

    _unavailable = (
        response.get("success") is False
        and response.get("status_code") == QUOTA_CHECK_UNAVAILABLE
    )
    if _unavailable:
        return {
            "admit": True,
            "refusal": str(response.get("message")),
            "unavailable": True,
            "skip_reason": None,
        }
    if response.get("success") is False:
        return {
            "admit": False,
            "refusal": str(response.get("message")),
            "unavailable": False,
            "skip_reason": None,
        }
    return {
        "admit": True,
        "refusal": None,
        "unavailable": False,
        "skip_reason": quota_check_skip_reason(response),
    }

# Two families have no Spot counterpart in Service Quotas: HPC and High Memory.
# A Spot request for one of those has no quota to check, which is a real answer
# and not a lookup failure.
_QUOTA_NAME_SHAPES = {
    # "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"
    ONDEMAND: re.compile(r"^running on-demand (?P<families>.+?) instances$"),
    # "All Standard (A, C, D, H, I, M, R, T, Z) Spot Instance Requests"
    SPOT: re.compile(r"^all (?P<families>.+?) spot instance requests$"),
}


def _classify_quota_name(quota_name: str):
    """
    (lifecycle, families_text) for a vCPU quota name, or (None, None).

    The two lifecycles use completely different name shapes, which is why a filter
    written for one silently excludes the other.
    """
    _name = quota_name.strip().lower()
    for _lifecycle, _pattern in _QUOTA_NAME_SHAPES.items():
        _match = _pattern.match(_name)
        if _match:
            return _lifecycle, _match.group("families")
    return None, None


def _families_in_quota(families_text: str) -> list:
    """
    Family tokens a quota covers, from the family text of either name shape.

    Handles the three forms seen live: a parenthesised list
    ("standard (a, c, d, h, i, m, r, t, z)"), a pair ("g and vt"), and a single
    token ("hpc", "high memory").
    """
    _parenthesised = re.search(r"\((?P<list>[^)]*)\)", families_text)
    if _parenthesised:
        return [t.strip() for t in _parenthesised.group("list").split(",") if t.strip()]
    if " and " in families_text:
        return [t.strip() for t in families_text.split(" and ") if t.strip()]
    if families_text.strip() == "high memory":
        return ["u-"]
    return [families_text.strip()]


@soca_cache(
    prefix="edh:webui:aws:ec2:get_ec2_quotas",
    ttl=lambda: _quota_ttl("DiscoveryCacheTTL", QUOTA_DISCOVERY_TTL_DEFAULT),
    serializer="json",
    # The only expensive refill in this module (~18 requests), and the one the
    # four per-minute controller crons can stampede when it expires.
)
def get_ec2_quotas() -> SocaResponse:
    """
    Every EC2 vCPU quota, On-Demand and Spot, with the families each one covers.

    Both lifecycles ride in this one cached entry because the cost is the paginate,
    not the filter: ec2 returns ~1750 quotas either way, so adding the 8 Spot rows
    to the 10 On-Demand ones costs no extra request.

    Each row carries Lifecycle and Families so callers do not have to re-parse the
    quota name, and so that the two name shapes stay decoded in one place.
    """
    logger.info("Fetching EC2 On-Demand and Spot vCPU quotas")
    _quotas = []
    try:
        paginator = client_service_quotas.get_paginator("list_service_quotas")
        for page in paginator.paginate(
            ServiceCode="ec2", PaginationConfig={"PageSize": QUOTA_PAGE_SIZE}
        ):
            for quota in page["Quotas"]:
                _lifecycle, _families_text = _classify_quota_name(quota["QuotaName"])
                if _lifecycle is None:
                    continue
                _quotas.append(
                    {
                        "QuotaName": quota["QuotaName"],
                        "Value": quota["Value"],
                        "QuotaCode": quota["QuotaCode"],
                        "Lifecycle": _lifecycle,
                        "Families": _families_in_quota(_families_text),
                    }
                )

        return SocaResponse(success=True, message=_quotas)
    except Exception as err:
        return SocaError.GENERIC_ERROR(helper=f"Unable to fetch EC2 quotas: {err}")


@soca_cache(
    prefix="edh:webui:aws:ec2:get_ec2_quota_value",
    ttl=lambda: _quota_ttl("ValueCacheTTL", QUOTA_VALUE_TTL_DEFAULT),
    serializer="json",
)
def get_ec2_quota_value(quota_code: str) -> SocaResponse:
    """
    Read the current limit for ONE ec2 quota. ListServiceQuotas filtered by
    QuotaCode returns a single row in a single request, so this is the call that
    belongs on the per-job path rather than a full paginate of ~1750 quotas.
    """
    logger.info(f"Fetching current value for EC2 quota {quota_code}")
    try:
        _quotas = client_service_quotas.list_service_quotas(
            ServiceCode="ec2", QuotaCode=quota_code
        ).get("Quotas", [])
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 quota {quota_code}: {err}"
        )

    for _quota in _quotas:
        if _quota.get("QuotaCode") == quota_code:
            return SocaResponse(success=True, message=_quota.get("Value"))

    return SocaError.GENERIC_ERROR(helper=f"EC2 quota {quota_code} was not returned")


def _current_quota_limit(quota_code: str, fallback, force_refresh: bool = False):
    """
    Current limit for quota_code, falling back to the value discovery already
    returned. A transient API failure must not be read as a quota of zero, which
    would reject every job.

    force_refresh discards the cached entry first. Reserved for the moment a job is
    about to be REFUSED: the limit is then re-read at its source before the refusal
    stands, so the tunable window can be long without an operator's fresh quota
    increase costing them a rejected job. Costs one extra request, and only on the
    path that was about to fail anyway.
    """
    if force_refresh:
        try:
            get_ec2_quota_value.invalidate_cache(quota_code=quota_code)
        except Exception as err:  # noqa: BLE001
            logger.warning(f"Unable to invalidate cached quota {quota_code}: {err}")

    _fresh = get_ec2_quota_value(quota_code=quota_code)
    if _fresh.get("success") is not True:
        logger.warning(
            f"Falling back to the discovered limit for {quota_code}: {_fresh.get('message')}"
        )
        return fallback
    return _fresh.get("message")


@soca_cache(
    prefix="edh:webui:aws:ec2:list_active_capacity_reservations",
    ttl=60,
    serializer="json",
)
def list_active_capacity_reservations() -> SocaResponse:
    """
    Every ACTIVE On-Demand Capacity Reservation in the account and region.

    Distinct from describe_capacity_reservations(), which answers about ids the
    caller already knows. Quota accounting needs the whole set, because reserved
    capacity consumes the On-Demand quota whether or not anything is running in it.

    Only the fields quota accounting needs are returned, and deliberately so: the
    raw boto response carries datetimes (StartDate, EndDate, CreateDate) which are
    not JSON-serializable, and this entry is cached as JSON to keep pickle out of
    the quota path.
    """
    logger.info("Listing active capacity reservations")
    _reservations = []
    try:
        _paginator = client_ec2.get_paginator("describe_capacity_reservations")
        for _page in _paginator.paginate(
            Filters=[{"Name": "state", "Values": ["active"]}]
        ):
            for _r in _page.get("CapacityReservations", []):
                _reservations.append(
                    {
                        "CapacityReservationId": _r.get("CapacityReservationId"),
                        "InstanceType": _r.get("InstanceType"),
                        "InstancePlatform": _r.get("InstancePlatform"),
                        "Tenancy": _r.get("Tenancy"),
                        "TotalInstanceCount": _r.get("TotalInstanceCount"),
                        "AvailableInstanceCount": _r.get("AvailableInstanceCount"),
                        "State": _r.get("State"),
                    }
                )
        return SocaResponse(success=True, message=_reservations)
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to list active capacity reservations: {err}"
        )


def _vcpus_by_instance_type(instance_types) -> SocaResponse:
    """
    {instance_type: DefaultVCpus} for a set of types, sized once per DISTINCT type.

    The counting loop used to call describe_instance_types() per running instance,
    so a cluster with 300 nodes of four distinct types paid 300 lookups for four
    answers. Cached lookups are cheap individually but not free: each one is a
    round trip to Valkey inside a loop that runs on every quota check.
    """
    _sizes = {}
    for _type in sorted(set(t for t in instance_types if t)):
        _info = describe_instance_types(instance_types=[_type])
        if _info.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to fetch EC2 instance information for {_type}: {_info.get('message')}"
            )
        _sizes[_type] = _info.get("message")["InstanceTypes"][0]["VCpuInfo"][
            "DefaultVCpus"
        ]
    return SocaResponse(success=True, message=_sizes)


def _vcpus_in_use(families: list, lifecycle: str = ONDEMAND) -> SocaResponse:
    """
    vCPUs the account consumes against the quota for these families and lifecycle.

    All of the following was measured against a live EC2 endpoint in a region where
    quota enforcement was first PROVEN by a control: a launch of 80 vCPUs against a
    64 vCPU limit was refused with VcpuLimitExceeded.

    ON-DEMAND AND SPOT ARE SEPARATE BUCKETS. Overflowing the Spot quota is refused
    with MaxSpotInstanceCountExceeded, a different error code, while On-Demand
    usage was zero. So Spot instances must not be counted against an On-Demand
    quota, and a Spot request must be checked against the Spot quota.

    RESERVED ODCR CAPACITY COUNTS, FOR ON-DEMAND. With 64 of 64 vCPUs reserved and
    NOTHING running, a launch outside the reservation was refused with
    VcpuLimitExceeded, and creating a reservation for 80 vCPUs against the same
    64 vCPU limit was refused outright with InstanceLimitExceeded. Reserved capacity
    is therefore consumed at reservation time, not at launch time. Capacity
    reservations are an On-Demand construct, so they are not counted for Spot.

    Instances running INSIDE a reservation are already covered by that
    reservation's TotalInstanceCount and are skipped, so they are not counted twice.
    """
    _reserved_vcpus = 0
    _reservation_ids = set()
    _relevant_reservations = []

    if lifecycle == ONDEMAND:
        _describe_reservations = list_active_capacity_reservations()
        if _describe_reservations.get("success") is False:
            # Under-counting is the unsafe direction, so say so rather than silently
            # continuing with a running-instances-only total.
            logger.warning(
                f"Unable to read capacity reservations, On-Demand usage may be "
                f"under-counted: {_describe_reservations.get('message')}"
            )
        else:
            for _reservation in _describe_reservations.get("message") or []:
                _type = _reservation.get("InstanceType", "")
                if quota_match_token(_type) not in families:
                    continue
                _reservation_ids.add(_reservation.get("CapacityReservationId"))
                _relevant_reservations.append(_reservation)

    _find_all = describe_instances_paginate()
    if _find_all.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 instance information: {_find_all.get('message')}"
        )

    _instances = []
    for _instance in _find_all.get("message"):
        _type = _instance.get("InstanceType")
        if quota_match_token(_type) not in families:
            continue
        # InstanceLifecycle is "spot" for Spot instances and absent for On-Demand.
        _instance_lifecycle = (
            SPOT if _instance.get("InstanceLifecycle") == "spot" else ONDEMAND
        )
        if _instance_lifecycle != lifecycle:
            continue
        if _instance.get("CapacityReservationId") in _reservation_ids:
            logger.debug(
                f"Skipping {_type}, already counted via reservation "
                f"{_instance.get('CapacityReservationId')}"
            )
            continue
        _instances.append(_instance)

    # One sizing pass over the distinct types, rather than one per instance.
    _sizes = _vcpus_by_instance_type(
        [i.get("InstanceType") for i in _instances]
        + [r.get("InstanceType") for r in _relevant_reservations]
    )
    if _sizes.get("success") is False:
        return _sizes
    _sizes = _sizes.get("message")

    for _reservation in _relevant_reservations:
        _count = _reservation.get("TotalInstanceCount", 0)
        _vcpus = _sizes.get(_reservation.get("InstanceType"), 0)
        _reserved_vcpus += _vcpus * _count
        logger.debug(
            f"Reservation {_reservation.get('CapacityReservationId')} holds "
            f"{_count} x {_reservation.get('InstanceType')} = {_vcpus * _count} vcpus"
        )

    _running_vcpus = sum(_sizes.get(i.get("InstanceType"), 0) for i in _instances)

    return SocaResponse(
        success=True,
        message={
            "total": _running_vcpus + _reserved_vcpus,
            "running": _running_vcpus,
            "reserved": _reserved_vcpus,
            "reservation_ids": sorted(_reservation_ids),
        },
    )


@soca_cache(
    prefix="edh:webui:aws:ec2:quota_revalidation_window",
    ttl=lambda: _quota_ttl("RevalidationFloor", QUOTA_REVALIDATION_FLOOR_DEFAULT),
    serializer="json",
)
def _revalidation_window(quota_code: str) -> SocaResponse:
    """
    Opens a revalidation window for one quota and returns the epoch it opened at.

    The value is the timestamp, and the cache TTL is the window, so the marker
    expires on its own with no stored deadline to compare or clean up. The first
    caller in a window gets a fresh timestamp; everyone arriving inside the window
    is handed the same older one.
    """
    return SocaResponse(success=True, message=time.time())


def _may_revalidate(quota_code: str) -> bool:
    """
    True when this caller should spend a forced re-read on quota_code.

    Without this gate, 100 jobs queued on the same exhausted quota force 100
    invalidate-plus-reread cycles per dispatcher pass, all returning the same
    number. With it, one job per window pays for the re-read and the other 99 reuse
    the answer.

    Two properties worth knowing. There is no atomic set-if-absent in the cache
    client, so two processes racing at the moment a window opens can both mint one
    and both revalidate; the ceiling is one re-read per controller cron per window,
    not per job, which is the blow-up being prevented. And a clock skew between
    controllers only ever makes a caller revalidate when it did not have to.
    """
    _opened = _revalidation_window(quota_code=quota_code)
    if _opened.get("success") is not True:
        # Cache unavailable: fall back to allowing it. One extra API call is a far
        # smaller problem than refusing a job whose quota was just raised.
        return True
    # The value is an epoch this module wrote, but it arrives back through the
    # cache, so a corrupted or hand-edited entry must not raise out of the gate.
    _minted_at = SocaCastEngine(data=_opened.get("message")).cast_as(float)
    if _minted_at.get("success") is not True:
        logger.warning(
            f"Revalidation window for {quota_code} held an uncastable value "
            f"{_opened.get('message')!r}, treating the window as freshly opened"
        )
        return True
    _age = time.time() - _minted_at.get("message")
    return _age < QUOTA_REVALIDATION_MINT_GRACE


def find_quota_for_instance(instance_type: str, lifecycle: str = ONDEMAND) -> SocaResponse:
    """
    The quota governing instance_type for this lifecycle.

    Selection is by FAMILY TOKEN against the families the quota declares, not by
    substring on the quota name. Matching Spot and On-Demand names with one regex is
    not possible anyway (different shapes), and matching by token avoids the trap
    where a family whose name merely contains another quota's word is mis-assigned.

    Returns status_code 204 with a message when the family has no quota for this
    lifecycle. HPC and High Memory have no Spot counterpart, so a Spot request for
    an hpc type is a real "no such quota", not a lookup failure, and the caller
    should treat it as "Spot is not available here" rather than as an error.
    """
    _discovery = get_ec2_quotas()
    if _discovery.get("success") is False:
        # Transient: the quota list could not be READ. Marked so an interactive
        # caller can admit. Contrast with the unmatched-family return below, which
        # is a hard failure because the instance type itself is wrong.
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 quotas: {_discovery.get('message')}",
            status_code=QUOTA_CHECK_UNAVAILABLE,
        )

    # One shared collapse, so the quota LOOKUP here and the usage COUNT in
    # _vcpus_in_use() cannot disagree about which family an instance belongs to.
    # They did: this side collapsed High Memory to "u-" while the usage loops
    # compared the raw token, so High Memory usage always measured 0.
    _token = quota_match_token(instance_type)

    _any_lifecycle_matched = False
    for _quota in _discovery.get("message"):
        if _token not in _quota.get("Families", []):
            continue
        _any_lifecycle_matched = True
        if _quota.get("Lifecycle") == lifecycle:
            return SocaResponse(success=True, message=_quota)

    if _any_lifecycle_matched:
        return SocaResponse(
            success=True,
            message=None,
            status_code=204,
        )
    return SocaError.GENERIC_ERROR(
        helper=f"Unable to find a {lifecycle} quota for {instance_type}"
    )


def ec2_quota_headroom(
    instance_type: str, lifecycle: str = ONDEMAND
) -> SocaResponse:
    """
    How much of the governing quota is left, and what one instance costs against it.

    Exists for BATCH callers. validate_ec2_quota_for_instance() answers "may I launch
    this one thing", and each call re-measures account usage with a
    describe_instances paginate plus a reservation list. Asking it once per instance
    for a 50-instance batch pays that cost 50 times to learn the same number, and
    asking it independently per instance is also WRONG: every call sees the same
    usage, so all 50 are admitted when only 10 fit.

    A caller that has many instances to place should call this once per DISTINCT
    instance type, then subtract as it admits, which is what
    schedule_management.plan_starts_within_quota() does.

    message on success:
        quota_name, quota_code, vcpus_per_instance, limit, in_use, available
    status_code 201 with message["skipped"] when there is nothing to enforce, in
    which case the caller should admit everything rather than treating a missing
    number as zero headroom.
    """
    _find_quota = find_quota_for_instance(
        instance_type=instance_type, lifecycle=lifecycle
    )
    if _find_quota.get("success") is False:
        # Could not READ the quota, which is not the same as the quota being
        # exhausted. Marked so an interactive caller can admit rather than
        # refuse a launch over a transient Service Quotas failure.
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to determine the {lifecycle} quota for {instance_type}: {_find_quota.get('message')}",
            status_code=_find_quota.get("status_code"),
        )
    if _find_quota.get("status_code") == 204:
        return SocaResponse(
            success=True,
            message={"skipped": QUOTA_SKIPPED_NO_QUOTA_FOR_LIFECYCLE},
            status_code=201,
        )

    _quota = _find_quota.get("message")

    _describe = describe_instance_types(instance_types=[instance_type])
    if _describe.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 instance type information: {_describe.get('message')}"
        )
    _vcpus_per_instance = _describe.message["InstanceTypes"][0]["VCpuInfo"][
        "DefaultVCpus"
    ]

    _limit = _current_quota_limit(
        quota_code=_quota["QuotaCode"], fallback=_quota["Value"]
    )

    _usage = _vcpus_in_use(families=_quota["Families"], lifecycle=lifecycle)
    if _usage.get("success") is False:
        return _usage

    return SocaResponse(
        success=True,
        message={
            "quota_name": _quota["QuotaName"].lower(),
            "quota_code": _quota["QuotaCode"],
            "vcpus_per_instance": _vcpus_per_instance,
            "limit": _limit,
            "in_use": _usage.message["total"],
            "available": _limit - _usage.message["total"],
        },
    )


def validate_ec2_quota_for_instance(
    instance_type: str,
    desired_capacity: int,
    override_vcpus_quotas_for_pending_instances: dict = {},
    lifecycle: str = ONDEMAND,
    capacity_reservation_id: str = None,
) -> SocaResponse:
    """
    Whether this account has quota headroom for desired_capacity x instance_type.

    lifecycle selects WHICH quota and WHICH usage: On-Demand and Spot are separate
    enforcement buckets, proven by the distinct error codes VcpuLimitExceeded and
    MaxSpotInstanceCountExceeded. A
    Spot request checked against the On-Demand quota is checking the wrong number.

    capacity_reservation_id, when the job targets a reservation, suppresses charging
    the job's own request: that capacity is already inside the reservation's total
    and is therefore already counted. Measured in the same account -- with 64 of 64
    vCPUs reserved and nothing running, a launch OUTSIDE the reservation was refused
    with VcpuLimitExceeded while a launch TARGETING it succeeded.
    """
    logger.info(f"Verifying {lifecycle} quota for {instance_type}")
    enforce_quota = (
        SocaConfig(key="/configuration/FeatureFlags/Hpc/EnableQuotasCheck")
        .get_value(return_as=bool, default=True)
        .get("message")
    )
    if enforce_quota is False:
        logger.info(
            f"EnforceQuota check is disabled via /configuration/FeatureFlags/Hpc/EnableQuotasCheck, skipping quota check for {instance_type}"
        )
        # status_code 201 is kept for callers that still test for it; the
        # "skipped" reason is what new code should read.
        return SocaResponse(
            success=True,
            message={"skipped": QUOTA_SKIPPED_DISABLED},
            status_code=201,
        )

    _find_quota = find_quota_for_instance(
        instance_type=instance_type, lifecycle=lifecycle
    )
    if _find_quota.get("success") is False:
        # PROPAGATE the lookup's own status rather than assuming every failure is
        # transient. find_quota_for_instance() fails in two different ways: the
        # quota list could not be read (marked QUOTA_CHECK_UNAVAILABLE, so an
        # interactive caller admits), or no family matched at all -- which means
        # the instance type is unknown or mistyped and must stay a HARD failure.
        # Collapsing both let a mistyped instance type bypass the gate entirely.
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to determine the {lifecycle} quota for {instance_type}: {_find_quota.get('message')}",
            status_code=_find_quota.get("status_code"),
        )
    if _find_quota.get("status_code") == 204:
        # The family has quotas, but none for this lifecycle: HPC and High Memory
        # have no Spot counterpart. Nothing to enforce, and refusing here would
        # block a request AWS itself will answer.
        logger.info(
            f"No {lifecycle} quota exists for {instance_type}, skipping the check"
        )
        return SocaResponse(
            success=True,
            message={"skipped": QUOTA_SKIPPED_NO_QUOTA_FOR_LIFECYCLE},
            status_code=201,
        )

    _quota = _find_quota.get("message")
    _quota_name = _quota["QuotaName"].lower()
    _quota_code = _quota["QuotaCode"]
    _families = _quota["Families"]

    _describe_instance_info = describe_instance_types(instance_types=[instance_type])
    if _describe_instance_info.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 instance type information: {_describe_instance_info.get('message')}",
            status_code=QUOTA_CHECK_UNAVAILABLE,
        )
    _instance_info = _describe_instance_info.message["InstanceTypes"][0]

    _vcpus_per_instance = _instance_info["VCpuInfo"]["DefaultVCpus"]
    _total_vcpus_requested_for_job = _vcpus_per_instance * desired_capacity

    # The discovered mapping may be up to a day old, but the LIMIT must not be:
    # one filtered ListServiceQuotas request reads the current value.
    _quota_max_vcpus_allowed = _current_quota_limit(
        quota_code=_quota_code, fallback=_quota["Value"]
    )
    logger.info(
        f"Quota {_quota_name} ({_quota_code}) = {_quota_max_vcpus_allowed}, "
        f"families {_families}, counting {lifecycle} usage"
    )

    _usage = _vcpus_in_use(families=_families, lifecycle=lifecycle)
    if _usage.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to count {lifecycle} vcpus in use for {instance_type}: {_usage.get('message')}",
            status_code=QUOTA_CHECK_UNAVAILABLE,
        )

    _running_vcpus = _usage.message["total"]

    if _quota_name in override_vcpus_quotas_for_pending_instances:
        # Track EC2 quota usage across multiple jobs.
        # Example: If we plan to launch 2 c6i.24xlarge instances, the first one (96 vCPUs) may not be
        # running yet, but we still need to count its vCPUs when scheduling the second job. This
        # ensures we do not exceed account quotas by ignoring pending (yet-to-be-provisioned) capacity.
        _running_vcpus += override_vcpus_quotas_for_pending_instances.get(_quota_name)

    # A job launching INTO a reservation is asking for capacity the reservation
    # already holds, so charging its request again would refuse a launch AWS accepts.
    _charge_for_request = _total_vcpus_requested_for_job
    if capacity_reservation_id and capacity_reservation_id in _usage.message.get(
        "reservation_ids", []
    ):
        logger.info(
            f"Job targets reservation {capacity_reservation_id}; its "
            f"{_total_vcpus_requested_for_job} vcpus are already counted as reserved"
        )
        _charge_for_request = 0

    logger.info(
        f"{lifecycle} vcpus in use for {_quota_name}: {_running_vcpus} "
        f"(running {_usage.message['running']}, reserved via ODCR {_usage.message['reserved']}), "
        f"charging {_charge_for_request} for this job"
    )

    # The capacity this job is asking for must be part of the comparison, otherwise a
    # single job larger than the entire quota passes the gate and fails at RunInstances.
    if (_running_vcpus + _charge_for_request) > _quota_max_vcpus_allowed:
        # About to refuse. Usage was counted live while the limit may be as old as
        # the tunable window, so re-read the limit at its source before the refusal
        # stands. This is what stops an operator who raised the quota a minute ago
        # from being told their job exceeds it.
        #
        # Gated: a queue of jobs blocked on the same quota would otherwise force one
        # re-read each, all returning the same number.
        if _may_revalidate(quota_code=_quota_code):
            _revalidated = _current_quota_limit(
                quota_code=_quota_code,
                fallback=_quota_max_vcpus_allowed,
                force_refresh=True,
            )
            if _revalidated != _quota_max_vcpus_allowed:
                logger.info(
                    f"Cached limit for {_quota_name} was {_quota_max_vcpus_allowed}, "
                    f"a forced re-read returns {_revalidated}"
                )
                _quota_max_vcpus_allowed = _revalidated

        if (_running_vcpus + _charge_for_request) > _quota_max_vcpus_allowed:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Job cannot start due to AWS Service limit. Max Vcpus allowed {_quota_max_vcpus_allowed}. "
                    f"Detected {lifecycle} Vcpus in use {_running_vcpus} "
                    f"(running {_usage.message['running']}, reserved via capacity reservations {_usage.message['reserved']}). "
                    f"Requested Vcpus for this job {_total_vcpus_requested_for_job}. "
                    f"Quota Name {_quota_name} ({_quota_code}), {instance_type=} * {desired_capacity=}. "
                    f"Request an increase for quota {_quota_code} in the AWS Service Quotas console for this region."
                )
            )

    logger.info(
        f"Quota Validated {_quota_name=}, {_quota_max_vcpus_allowed=}, {_running_vcpus=}, {_total_vcpus_requested_for_job=}, {instance_type=} * {desired_capacity=}"
    )
    return SocaResponse(
        success=True,
        message={
            "quota_name": _quota_name,
            "quota_code": _quota_code,
            "lifecycle": lifecycle,
            "running_vcpus": _running_vcpus,
            "reserved_vcpus": _usage.message["reserved"],
            "max_vcpus_allowed": _quota_max_vcpus_allowed,
            "vcpus_per_instance": _vcpus_per_instance,
            # What THIS request asked for. Reported for messages and for callers
            # sizing a request; it is NOT the figure to accumulate.
            "requested_vcpus": _total_vcpus_requested_for_job,
            # What this request actually adds to the quota, which is what a caller
            # tracking pending capacity across several checks must accumulate.
            # These differ: a job launching INTO a counted reservation is charged
            # 0, because the reservation's vcpus are already in measured usage and
            # stay there on every later check. Accumulating the full request for
            # such a job books capacity twice and can refuse a later instance type
            # that fits.
            #
            # Neither figure is running_vcpus -- that is measured usage which
            # already includes any override passed in, so a caller adding it back
            # grew its own override by the full usage on every check.
            "charged_vcpus": _charge_for_request,
        },
    )


def validate_instance_ri_coverage(
    instance_type: str, desired_capacity: int, override_pending_instances_count: int = 0
) -> SocaResponse:
    logger.info(
        f"Checking if we have enough Reserved Instances for: {instance_type=} * {desired_capacity=} "
    )

    # Track EC2 RI usage across multiple jobs.
    # Example: If we plan to launch 2 c6i.24xlarge instances the first one may not be running yet,
    # but we still need to count its capacity (2 nodes) when scheduling the second job. This ensures we don’t exceed
    # account RI by ignoring pending (yet-to-be-provisioned) capacity.

    current_in_use = 0 + override_pending_instances_count
    current_ri = 0

    logger.info(f"Counting running/pending {instance_type}")
    try:
        get_provisioned_instances = describe_instances_paginate(
            filters=[
                {"Name": "instance-type", "Values": [instance_type]},
                {"Name": "instance-state-name", "Values": ["running", "pending"]},
            ]
        )

        if get_provisioned_instances.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to fetch EC2 instance information: {get_provisioned_instances.get('message')}"
            )
        else:
            for instance in get_provisioned_instances.get("message"):
                current_in_use += 1

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return SocaError.GENERIC_ERROR(
            helper=f"Error checking provisioned instances ({instance_type}) due to {e}"
        )

    logger.info(f"Counting reserved instances for {instance_type}")
    try:
        ri_response = client_ec2.describe_reserved_instances(
            Filters=[
                {"Name": "instance-type", "Values": [instance_type]},
                {"Name": "state", "Values": ["active"]},
            ]
        )

        for ri in ri_response.get("ReservedInstances", []):
            current_ri += ri.get("InstanceCount", 0)

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return SocaError.GENERIC_ERROR(
            helper=f"Error checking RIs ({instance_type}) due to {e}"
        )

    if current_in_use + desired_capacity > current_ri:
        return SocaError.GENERIC_ERROR(
            helper=f"Instance type {instance_type} is not covered by Reserved Instances. Running={current_in_use}, RI={current_ri}, DesiredCapacity={desired_capacity}"
        )
    else:
        logger.info(
            f"[COVERED] {instance_type}: Running={current_in_use}, RI={current_ri}, DesiredCapacity={desired_capacity}"
        )
        return SocaResponse(
            success=True,
            message=f"{instance_type}: Running={current_in_use}, RI={current_ri}, DesiredCapacity={desired_capacity}",
        )
