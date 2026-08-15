# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import sys
import os
import boto3
import botocore
import re

from botocore.exceptions import ClientError
from typing import Optional

import utils.aws.boto3_wrapper as utils_boto3
from utils.cache.decorator import soca_cache, _check_response_filter
from utils.datamodels.soca_node import SocaNode
from utils.error import SocaError
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.validators import Validators


client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_service_quotas = utils_boto3.get_boto(service_name="service-quotas").message

logger = logging.getLogger("soca_logger")


def create_placement_group(
    group_name: str,
    strategy: Literal["cluster", "spread", "partition"] = "cluster",
    spread_level: Optional[Literal["spread", "rack"]] = None,
    partition_count: Optiona[int] = None,
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
            InstancesIds=instance_ids, Filters=filters
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
    filters: list = [{"Name": "instance-state-name", "Values": ["pending", "running"]}],
    scheduler_info: Optional[SocaHpcScheduler] = None,
) -> SocaResponse:
    """
    Returns a list of SocaNode, not the raw boto3 describe_instance response
    Pass an optional SocaHpcScheduler if you want to forward the scheduler information to your SocaNode.scheduler_info object
    """
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
            message=f"Error fetching instance types: {e}. Verify if the instance type and if there is any newer version of boto {boto3.__version__}",
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
        _custom_tags = []
        for tag in custom_tags.values():
            if tag.get("Enabled", ""):
                _custom_tags.append({"Key": tag["Key"], "Value": tag["Value"]})
            else:
                logger.warning(f"{tag} does not have Enabled key or Enabled is False.")

        _get_image_info = describe_images(image_ids=[image_id])
        if _get_image_info.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve AMI information: {_get_image_info.get('message')}"
            )
        else:
            _ami_information = _get_image_info.get("message").get("Images")[0]

        logger.info("Submitting EC2 run_instance DryRun")
        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": _ami_information.get("RootDeviceName"),
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "VolumeSize": disk_size,
                        "VolumeType": volume_type,
                        "Encrypted": True,
                    },
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
            TagSpecifications=(
                [{"ResourceType": "instance", "Tags": _custom_tags}]
                if _custom_tags
                else []
            ),
        )

    except ClientError as err:
        if err.response["Error"].get("Code") == "DryRunOperation":
            return SocaResponse(success=True, message=None)
        else:
            return SocaError.AWS_API_ERROR(
                service_name="ec2",
                helper=f"Unable to launch capacity: {err.response['Error']}",
            )
    except Exception as err:
        return SocaError.GENERIC_ERROR(helper=f"Unable to launch capacity: {err}")


@soca_cache(prefix="edh:webui:aws:ec2:get_ec2_quotas", ttl=86400)
def get_ec2_quotas() -> SocaResponse:
    logger.info("Fetching all 'Running on Demand' EC2 Quotas")
    _quotas = []
    try:
        paginator = client_service_quotas.get_paginator("list_service_quotas")
        for page in paginator.paginate(ServiceCode="ec2"):
            for quota in page["Quotas"]:
                if "running on-demand" in quota["QuotaName"].lower():
                    _quotas.append(
                        {
                            "QuotaName": quota["QuotaName"],
                            "Value": quota["Value"],
                            "QuotaCode": quota["QuotaCode"],
                        }
                    )

        return SocaResponse(success=True, message=_quotas)
    except Exception as err:
        return SocaError.GENERIC_ERROR(helper=f"Unable to fetch EC2 quotas: {err}")


def validate_ec2_quota_for_instance(
    instance_type: str,
    desired_capacity: int,
    override_vcpus_quotas_for_pending_instances: dict = {},
) -> SocaResponse:
    logger.info(f"Verifying Quota for {instance_type}")
    enforce_quota = (
        SocaConfig(key="/configuration/FeatureFlags/Hpc/EnableQuotasCheck")
        .get_value(return_as=bool, default=True)
        .get("message")
    )
    if enforce_quota is False:
        logger.info(
            f"EnforceQuota check is disabled via /configuration/FeatureFlags/Hpc/EnableQuotasCheck, skipping quota check for {instance_type}"
        )
        # return 201 tells jobs.py the EnforceQuota is disabled
        return SocaResponse(success=True, message={}, status_code=201)

    _get_quotas_info = get_ec2_quotas()

    if _get_quotas_info.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 quotas: {_get_quotas_info.get('message')}"
        )
    else:
        _quotas_info = _get_quotas_info.get("message")

    _describe_instance_info = describe_instance_types(instance_types=[instance_type])
    if _describe_instance_info.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 instance type information: {_describe_instance_info.get('message')}"
        )
    else:
        _instance_info = _describe_instance_info.message["InstanceTypes"][0]

    _vcpus_per_instance = _instance_info["VCpuInfo"]["DefaultVCpus"]
    _total_vcpus_requested_for_job = _vcpus_per_instance * desired_capacity

    # QuotaName will always be lower()
    _instance_quota_name = (
        re.search(r"(.*)\d", instance_type.split(".")[0]).group(1).lower()
    )
    if _instance_quota_name.startswith("u-"):
        _instance_quota_name = "High Memory".lower()

    logger.debug(
        f"Checking if Quota will let us deploy an additional of {_total_vcpus_requested_for_job=} vCpus"
    )
    _quota_max_vcpus_allowed = False
    _quota_name = False
    for _quota in _quotas_info:
        if "running on-demand" in _quota["QuotaName"].lower() and re.search(
            rf"(\s|\(){_instance_quota_name}(\s|\)|,)", _quota["QuotaName"].lower()
        ):
            logger.debug(f"Found Associated Quota for {instance_type}: {_quota}")
            _quota_max_vcpus_allowed = _quota["Value"]
            _quota_name = _quota["QuotaName"].lower()

    if _quota_max_vcpus_allowed is False and _quota_name is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to find Quota for {instance_type}"
        )
    else:
        logger.info(
            f"Found Quota {_quota_name=} with {_quota_max_vcpus_allowed}, calculating the number of currently running instances"
        )

    # Standard Quota e.g "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"
    if "standard" in _quota_name.lower():
        _instances_family_allowed_in_quota = [
            item.strip()
            for item in re.search(
                r"running on-demand standard \((.*)\) instances", _quota_name.lower()
            )
            .group(1)
            .split(",")
            if item.strip()
        ]
    elif " and " in _quota_name.lower():
        # Quota with AND e.g "Running On-Demand G and VT instances"
        _check_instances = re.search(
            r"running on-demand\s+([\w-]+)\s+and\s+([\w-]+)\s+instances",
            _quota_name.lower(),
        )
        _instances_family_allowed_in_quota = [
            _check_instances.group(1),
            _check_instances.group(2),
        ]
    else:
        # Instance Specific Quota e.g "Running On-Demand HPC instances"
        _instances_family_allowed_in_quota = [
            re.search(r"running on-demand (.*) instances", _quota_name.lower()).group(1)
        ]

    logger.info(
        f"{instance_type=} associated quota: {_instances_family_allowed_in_quota} for {_quota_name}, finding all relevant EC2 instances"
    )
    _find_all_provisioned_instances_type = describe_instances_paginate()
    if _find_all_provisioned_instances_type.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 instance information: {_find_all_provisioned_instances_type.get('message')}"
        )
    else:
        all_provisioned_instances = _find_all_provisioned_instances_type.get("message")

    if _quota_name in override_vcpus_quotas_for_pending_instances:
        # Track EC2 quota usage across multiple jobs.
        # Example: If we plan to launch 2 c6i.24xlarge instances, the first one (96 vCPUs) may not be running yet,
        # but we still need to count its vCPUs when scheduling the second job. This ensures we don’t exceed
        # account quotas by ignoring pending (yet-to-be-provisioned) capacity.
        _running_vcpus = override_vcpus_quotas_for_pending_instances.get(_quota_name)
    else:
        _running_vcpus = 0

    for instance in all_provisioned_instances:
        _instance_type_name = instance.get("InstanceType")
        _get_instance_info = describe_instance_types(
            instance_types=[_instance_type_name]
        )
        if _get_instance_info.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to fetch EC2 instance information for {_instance_type_name=}: {_get_instance_info.get('message')}"
            )
        else:
            _instance_info = _get_instance_info.get("message")

        _instance_cpus_count = (
            _instance_info.get("InstanceTypes")[0].get("VCpuInfo").get("DefaultVCpus")
        )

        if _instance_type_name.startswith(tuple(_instances_family_allowed_in_quota)):
            _running_vcpus += _instance_cpus_count
            logger.debug(
                f"Found {_instance_type_name} with {_instance_cpus_count} vcpus. Total Running Vcpus {_running_vcpus}"
            )
            if _running_vcpus >= _quota_max_vcpus_allowed:
                return SocaError.GENERIC_ERROR(
                    helper=f"Job cannot start due to AWS Service limit. Max Vcpus allowed {_quota_max_vcpus_allowed}. Detected running Vcpus {_running_vcpus}. Requested Vcpus for this job {_total_vcpus_requested_for_job}. Quota Name {_quota_name}, {instance_type=} * {desired_capacity=}"
                )

    logger.info(
        f"Quota Validated {_quota_name=}, {_quota_max_vcpus_allowed=}, {_running_vcpus=}, {_total_vcpus_requested_for_job=}, {instance_type=} * {desired_capacity=}"
    )
    return SocaResponse(
        success=True,
        message={
            "quota_name": _quota_name,
            "running_vcpus": _running_vcpus,
            "max_vcpus_allowed": _quota_max_vcpus_allowed,
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
