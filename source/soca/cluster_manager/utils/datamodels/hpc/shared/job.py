# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import random
import logging
import math
import sys
import re
import botocore
import uuid
from itertools import product
from pathlib import Path
import shutil

from typing import Optional, get_args

from utils.aws.boto3_wrapper import get_boto
from utils.validators import Validators
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.config import SocaConfig
from utils.aws.ec2_helper import (
    create_capacity_dry_run,
    describe_images,
    describe_instance_types,
    describe_security_groups,
    validate_ec2_quota_for_instance,
    create_placement_group,
    delete_placement_group,
)
from utils.aws.fsx_helper import describe_file_systems
from utils.aws.odcr_helper import (
    create_capacity_reservation,
    cancel_reservation,
    validate_existing_capacity_reservation,
)

from utils.aws.iam_helper import get_instance_profile
from utils.aws.cloudformation_client import SocaCfnClient
from utils.hpc.job_controller import SocaHpcJobController
from utils.datamodels.hpc.shared.job_resources import (
    SocaHpcJobResourceModel,
    SocaHpcJobProvisioningState,
    SocaHpcJobState,
    SocaHpcJobOrchestrationMethod,
)
from utils.datamodels.hpc.scheduler import SocaHpcScheduler, SocaHpcSchedulerProvider
from utils.datamodels.constants import SocaLinuxBaseOS
from orchestrator.cloudformation_builder import SocaCloudFormationBuilderHpc

logger = logging.getLogger("soca_logger")

_cloudformation_client = get_boto(service_name="cloudformation").get("message")


class SocaHpcJob(SocaHpcJobResourceModel):

    # Additional SocaHpcJobResourceModel resources are loaded from utils.datamodels.job_resources
    # Scheduler Specific attributes will extend this class when you call SocaHpcJobLSF /SocaHpcJobPBS ...

    # The job_id attribute is defined as a string data type to maintain flexibility.
    # This allows for potential future integration with other job schedulers that might use different identifier formats, such as UUIDs, rather than being limited to numeric IDs.
    job_id: str = None

    # Name of the HPC job
    job_name: str = None

    # Owner of the HPC job
    job_owner: str = None

    # Queue where the HPC job is submitted
    job_queue: str = None

    # When the job was queued
    job_queue_time: int = None

    # When the job started running (None until it starts)
    job_start_time: Optional[int] = None

    # When the job finished (None until it completes)
    job_end_time: Optional[int] = None

    # Compute Node ID assigned to the job. TBD = no capacity being provisioned yet
    job_compute_node: str = "tbd"

    # Number of nodes assigned to the job
    nodes: int = None

    # Number of cpus assigned to the job
    cpus: int = None

    # State of the HPC job (queued, running  ...) in their respective queues. Common to all scheduler, mapping is done via job_fetcher
    job_state: SocaHpcJobState = None

    # Raw Job state specific to the scheduler (R, H, S ...). Can be different for each scheduler type
    job_scheduler_state: str

    # State of the Compute Provisioning managed by SOCA
    job_provisioning_state: SocaHpcJobProvisioningState = (
        SocaHpcJobProvisioningState.PENDING
    )

    # Scheduler information assigned to the job
    job_scheduler_info: SocaHpcScheduler

    # How many times SOCA provisioned capacity but job failed to run. Max attempts count configurable via dispatcher.py
    job_failed_provisioning_retry_count: int = 0

    # If the job configuration has been validated
    job_config_validated: bool = False

    # Associated cloudformation template if capacity is provisioned
    stack_id: Optional[str] = None

    # Project assiged to the job
    job_project: Optional[str] = None

    # Path of the current working directory where the job was submitted from
    # it does not necessarily mean the job output will be in the same folder
    job_working_directory: Optional[str] = None

    # Path to the job error file if specified
    job_error_log_path: Optional[str] = None

    # Path to the job output file if specified
    job_output_log_path: Optional[str] = None

    # Job orchestration method
    job_orchestration_method: SocaHpcJobOrchestrationMethod = (
        SocaHpcJobOrchestrationMethod.FLEET
    )

    def validate(self) -> SocaResponse:
        """
        Validate the SocaHpcCustomResourceModel & SocaHpcJob instances
        """
        try:
            # Assign defaults and normalize values
            self._normalize()

            # Pydantic validations
            self.__class__.model_validate(self.__dict__)

            # Reset job_errors
            if self.error_message:
                logger.debug(
                    f"Previous error messages {self.error_message} found, removing them as we have validated the configurations"
                )
                if self.job_scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
                    SocaHpcJobController(job=self).lsf_update_job_description(
                        resource_name="error_message",
                    )
                elif self.job_scheduler_info.provider in [
                    SocaHpcSchedulerProvider.PBSPRO,
                    SocaHpcSchedulerProvider.OPENPBS,
                ]:
                    SocaHpcJobController(job=self).pbs_update_resource(
                        resource_name="error_message", resource_value=""
                    )
            self.error_message = []

            # Setting job_config_validated flag to True
            self.job_config_validated = True

            logger.info(f"Validated all resources for: {self.job_id=}")
            return SocaResponse(success=True, message=None)
        except Exception as e:
            logger.error(f"Unable to validate SocaHpcJob due to {e}")
            # retrieve any potential other errors
            _sanitized_error = re.sub(r"[^a-zA-Z0-9_ ]", "", str(e)).replace(" ", "_")
            if _sanitized_error not in self.error_message:
                self.error_message.append(_sanitized_error)

            # Assign error_message= resource to the job if called from SocaHpcJob
            SocaHpcJobController(job=self).set_error_message(errors=self.error_message)
            return SocaResponse(success=False, message=self.error_message)

    # _normalize will validate, reformat and apply default value if needed for required SOCA job resources
    def _normalize(self) -> SocaHpcJob:
        try:
            # Scheduler resources are received as string. Convert them to bool if possible
            for attr_name, attr_value in self.__dict__.items():
                if isinstance(attr_value, str):
                    attr_value_lower = attr_value.strip().lower()
                    if attr_value_lower == "true":
                        setattr(self, attr_name, True)
                    elif attr_value_lower == "false":
                        setattr(self, attr_name, False)

            if (
                self.instance_types is None
                or self.root_size is None
                or self.base_os is None
            ):
                if self.job_scheduler_info.soca_managed_nodes_provisioning is True:
                    raise ValueError(
                        "instance_types, root_size and base_os are required when job_scheduler_info.soca_managed_nodes_provisioning is True"
                    )

            # ------------ base_os ------------ #
            logger.debug(f"Validating base_os: {self.base_os}")
            if self.base_os is None:
                raise ValueError("base_os cannot be null")
            else:
                if self.base_os not in SocaLinuxBaseOS:
                    raise ValueError(
                        f"{self.base_os} is not part of allowed base_os: {SocaLinuxBaseOS}"
                    )

            logger.debug(f"base_os validated: {self.base_os}")
            # ------------ /base_os ------------ #

            # ------------ subnet_ids ------------ #
            logger.debug(f"Validating subnet_ids: {self.subnet_ids}")
            _allowed_private_subnets = (
                SocaConfig(key="/configuration/PrivateSubnets")
                .get_value(return_as=list)
                .get("message")
            )
            if not self.subnet_ids:
                self.subnet_ids = [random.choice(_allowed_private_subnets)]
            else:
                if Validators.is_string(self.subnet_ids) is True:
                    # subnet_ids will always be a string when received via SocaHpcJob, however we do accept integer as a valid input to specify how many subnets to randomly select from allowed private subnets list
                    if self.subnet_ids.isdigit():
                        _subnet_count = int(self.subnet_ids)
                        _subnet_list = random.sample(
                            _allowed_private_subnets,
                            min(_subnet_count, len(_allowed_private_subnets)),
                        )
                    else:
                        # subnet_ids received a a string but string is not a digit, so we expect a list of subnet_ids separated by + as we cannot receive list when job is created via CLI
                        logger.debug(
                            f"{self.subnet_ids} is a string, casting it as list with + as separator"
                        )
                        _subnet_list = self.subnet_ids.split("+")

                elif Validators.is_list(self.subnet_ids) is True:
                    # subnet_ids received as list are only received via our internal APIs
                    _subnet_list = self.subnet_ids

                else:
                    raise ValueError(
                        f"{self.subnet_ids=} must be an integer or a string"
                    )

                for _subnet in _subnet_list:
                    if _subnet not in _allowed_private_subnets:
                        raise ValueError(
                            f"{_subnet} does not seems to be a SOCA registered private subnet. Allowed values: {_allowed_private_subnets}"
                        )
                self.subnet_ids = _subnet_list

            logger.debug(f"subnet_id validated: {self.subnet_ids}")
            # ------------ /subnet_id ------------ #

            # ------------ instance_types ------------ #
            logger.debug(f"Validating instance_types: {self.instance_types}")
            if not self.instance_types:
                raise ValueError("instance_types cannot be null")
            else:
                if Validators.is_string(self.instance_types) is True:
                    logger.debug(
                        f"{self.instance_types} is a string, casting it as list with + as separator"
                    )
                    _instances = self.instance_types.split("+")
                elif Validators.is_list(self.instance_types) is True:
                    _instances = self.instance_types
                else:
                    raise ValueError(
                        f"{self.instance_types=} must either be a list or str"
                    )

                _min_vcpus_per_instance = None
                _supported_instance_architectures = {}
                try:

                    _get_instance_type = describe_instance_types(
                        instance_types=_instances
                    )
                    if _get_instance_type.get("success") is False:
                        raise ValueError(
                            f"Unable to retrieve instance information: {_get_instance_type.get('message')}"
                        )
                    else:
                        _describe_instance_types = _get_instance_type.get("message")

                    for instance_info in _describe_instance_types.get("InstanceTypes"):
                        _instance_type = instance_info.get("InstanceType")
                        if self.ht_support is True:
                            _vcpus_per_instance = instance_info["VCpuInfo"][
                                "DefaultVCpus"
                            ]
                        else:
                            _vcpus_per_instance = instance_info["VCpuInfo"][
                                "DefaultCores"
                            ]
                        if (
                            not _instance_type
                            in _supported_instance_architectures.keys()
                        ):
                            _supported_instance_architectures[
                                _instance_type
                            ] = instance_info.get("ProcessorInfo").get(
                                "SupportedArchitectures"
                            )  # return a list

                        logger.debug(
                            f"Detected {_vcpus_per_instance=} / {_supported_instance_architectures[_instance_type]=} for {_instance_type=}"
                        )

                        if _min_vcpus_per_instance is None:
                            _min_vcpus_per_instance = _vcpus_per_instance
                        else:
                            logger.warning(
                                "Minimum nodes required based on CPUs/Instance Type count is only available when only one instance is specified"
                            )

                        # ------------ efa_support ------------ #
                        if self.efa_support:
                            logger.debug(f"Validating efa_support: {self.efa_support}")
                            _instance_efa_supported = instance_info.get(
                                "NetworkInfo"
                            ).get("EfaSupported")
                            if _instance_efa_supported is False:
                                raise ValueError(
                                    f"efa_support: Instance type {instance_info.get('InstanceType')} does not support EFA"
                                )
                            logger.debug(f"efa_support validated: {self.efa_support}")
                        # ------------ /efa_support ------------ #

                    self.instance_types = _instances

                except Exception as err:
                    raise ValueError(
                        f"Invalid instance type in {_instances}, error {err}"
                    )

                if _min_vcpus_per_instance is None:
                    raise ValueError(
                        f"Failed to fetch vCPU info for {self.instance_types=}"
                    )
                else:
                    _minimal_number_of_nodes_for_job = math.ceil(
                        self.cpus / _min_vcpus_per_instance
                    )
                    logger.info(
                        f"Calculated minimal number of nodes: {_minimal_number_of_nodes_for_job} based on cpus: {self.cpus} and instance_types selected {self.instance_types}"
                    )

                    if self.nodes < _minimal_number_of_nodes_for_job:
                        raise ValueError(
                            f"Number of required nodes for this job {self.nodes} does not match the combination of cpus requested {self.cpus} and instance type {self.instance_types}. Nodes count should be {_minimal_number_of_nodes_for_job}"
                        )

            logger.debug(f"instance_types validated: {self.instance_types}")
            # ------------ /instance_types ------------ #

            # ------------ placement_group ------------ #
            logger.debug(f"Validating placement_group: {self.placement_group}")
            try:
                self.placement_group = bool(self.placement_group)
                if self.placement_group:
                    if self.nodes == 1:
                        logger.info(
                            "placement_group is set but will be ignored when nodes=1. Ignoring placement_group"
                        )
                        self.placement_group = False

                    if Validators.is_list_length_equal_of(self.subnet_ids, 1) is False:
                        raise ValueError(
                            "You must specify only one subnet_ids when using placement_group"
                        )

            except (ValueError, TypeError) as err:
                raise ValueError(
                    f"Unable to validate placement_group due to {err}. Must be a boolean"
                )
            logger.debug(f"placement_group validated: {self.placement_group}")
            # ------------ /placement_group ------------ #

            # ------------ instance_profile ------------ #
            logger.debug(f"Validating instance_profile: {self.instance_profile}")
            if not self.instance_profile:
                self.instance_profile = (
                    SocaConfig(key="/configuration/ComputeNodeInstanceProfileArn")
                    .get_value()
                    .get("message")
                )
            else:
                _get_instance_profile = get_instance_profile(
                    instance_profile_name=self.instance_profile.split("/")[-1]
                )  # get the name in case we receive the full arn
                if _get_instance_profile.get("success") is False:
                    raise ValueError(
                        f"Unable to validate custom IAM instance profile {self.instance_profile} due to {_get_instance_profile.get('message')}"
                    )
                else:
                    self.instance_profile = (
                        _get_instance_profile.get("message")
                        .get("InstanceProfile")
                        .get("Arn")
                    )
            logger.debug(f"instance_profile validated: {self.instance_profile}")
            # ------------ /instance_profile ------------ #

            # ------------ security_groups ------------ #
            logger.debug(f"Validating security_groups: {self.security_groups}")
            _default_compute_security_group = (
                SocaConfig(key="/configuration/ComputeNodeSecurityGroup")
                .get_value()
                .get("message")
            )
            if not self.security_groups:
                self.security_groups = [_default_compute_security_group]
            else:
                if Validators.is_string(self.security_groups) is True:
                    logger.debug(
                        f"{self.security_groups} is string, casting it as list"
                    )
                    _security_groups_ids = self.security_groups.split("+")
                elif Validators.is_list(self.security_groups) is True:
                    _security_groups_ids = self.security_groups
                else:
                    raise ValueError(
                        f"{self.security_groups=} must either be a list or str"
                    )

                if _default_compute_security_group not in _security_groups_ids:
                    _security_groups_ids.append(_default_compute_security_group)

                if (
                    Validators.is_list_length_greater_than(_security_groups_ids, 4)
                    is True
                ):
                    raise ValueError(
                        "You can specify a maximum of 4 additional security groups"
                    )
                else:
                    if (
                        describe_security_groups(
                            security_groups_ids=_security_groups_ids
                        ).get("success")
                        is False
                    ):
                        raise ValueError(
                            f"Unable to validate one SG from {_security_groups_ids}"
                        )

                self.security_groups = _security_groups_ids
            logger.debug(f"security_groups validated: {self.security_groups}")
            # ------------ /security_groups ------------ #

            # ------------ instance_ami ------------ #
            logger.debug(f"Validating instance_ami: {self.instance_ami}")
            _custom_ami_map = (
                SocaConfig(key="/configuration/CustomAMIMap")
                .get_value(return_as=dict, default={})
                .get("message")
            )
            if self.instance_ami is None:
                # find common architecture accross all specified instance type
                # e.g: if multiple instance types are specified, ensure they are all x86_64 pr arm64
                _sets_of_arch = [
                    set(arch_list)
                    for arch_list in _supported_instance_architectures.values()
                ]
                _common_architectures = set.intersection(*_sets_of_arch)
                for arch in _common_architectures:
                    ami = _custom_ami_map.get(arch, {}).get(self.base_os)
                    if ami:
                        logger.debug(
                            f"Found default AMI for {self.base_os=} and {arch=}"
                        )
                        self.instance_ami = ami
                        break

            if self.instance_ami is None:
                raise ValueError(
                    f"Unable to find default AMI for {self.base_os=} / accepted architectures: {_common_architectures=} in this region"
                )

            try:
                _get_ami_information = describe_images(image_ids=[self.instance_ami])
                if _get_ami_information.get("success") is False:
                    raise ValueError(
                        f"{self.instance_ami} does not seems to be a valid image in this current region"
                    )
                else:
                    _ami_information = _get_ami_information.message["Images"][0]
                    _ami_architecture = _ami_information.get("Architecture")
                    logger.debug(f"AMI Architecture {_ami_architecture}")
                    if not all(
                        _ami_architecture in arch_list
                        for arch_list in _supported_instance_architectures.values()
                    ):
                        raise ValueError(
                            f"AMI {_ami_architecture} does not match at least one instance architecture"
                        )

            except Exception as err:
                raise ValueError(f"Unable to validate {self.instance_ami} due to {err}")
            logger.debug(f"instance_ami validated: {self.instance_ami}")
            # ------------ /instance_ami ------------ #

            # ------------ scratch_size ------------ #
            logger.debug(f"Validating scratch_size: {self.scratch_size}")
            if self.scratch_size:
                try:
                    self.scratch_size = int(self.scratch_size)
                    if self.scratch_size <= 0:
                        raise ValueError(
                            f"scratch_size must be a positive integer, detected {self.scratch_size}"
                        )
                except (ValueError, TypeError):
                    raise ValueError(
                        f"scratch_size must be an int, detected {self.scratch_size}"
                    )
            logger.debug(f"scratch_size validated: {self.scratch_size}")
            # ------------ /scratch_size ------------ #

            # ------------ root_size ------------ #
            logger.debug(f"Validating root_size: {self.root_size}")
            try:
                self.root_size = int(self.root_size)
                if self.root_size <= 0:
                    raise ValueError(
                        f"root_size must be a positive int, detected {self.root_size}"
                    )
            except (ValueError, TypeError):
                raise ValueError(
                    f"root_size must be an integer, detected {self.root_size}"
                )

            _block_devices = _ami_information.get("BlockDeviceMappings", [])
            _root_device_name = _ami_information.get("RootDeviceName")
            _ami_root_size = None
            for device in _block_devices:
                if device.get("DeviceName") == _root_device_name:
                    if "Ebs" in device:
                        _ami_root_size = device["Ebs"]["VolumeSize"]
                        break

            if _ami_root_size and self.root_size < _ami_root_size:
                raise ValueError(
                    f"root_size must be >= AMI root device size ({_ami_root_size}), detected {self.root_size}"
                )
            logger.debug(f"root_size validated: {self.root_size}")
            # ------------ /root_size ------------ #

            # ------------ SPOT section (spot_price / spot_allocation_count / spot_allocation_strategy) ------------ #
            if self.spot_price:
                logger.debug(f"Validating spot_price: {self.spot_price}")
                if str(self.spot_price) != "auto":
                    try:
                        self.spot_price = float(self.spot_price)
                        if self.spot_price < 0:
                            raise ValueError(
                                f"spot_price must be a positive float or 'auto', detected {self.spot_price}"
                            )
                    except ValueError:
                        raise ValueError(
                            f"Must be a valid float or 'auto', detected {self.spot_price}"
                        )
                logger.debug(f"spot_price validated: {self.spot_price}")

                # spot_allocation_count
                if self.spot_allocation_count:
                    logger.debug(
                        f"Validating spot_allocation_count: {self.spot_allocation_count}"
                    )
                    try:
                        self.spot_allocation_count = int(self.spot_allocation_count)
                        if self.spot_allocation_count > self.nodes:
                            logger.warning(
                                f"spot_allocation_count ({self.spot_allocation_count}) must be an lower or equal to the number of nodes provisioned for this simulation ({self.nodes}). Updating value ... "
                            )
                            self.spot_allocation_count = self.nodes
                    except ValueError:
                        raise ValueError(
                            f"spot_allocation_count must be an integer, detected {self.spot_allocation_count}"
                        )
                    logger.debug(
                        f"spot_allocation_count validated: {self.spot_allocation_count}"
                    )
                else:
                    logger.info(
                        f"spot_allocation_count not specified, default to number of nodes {self.nodes}"
                    )
                    self.spot_allocation_count = self.nodes

                # spot_allocation_strategy
                if self.spot_allocation_strategy:
                    logger.debug(f"Validating {self.spot_allocation_strategy}")

                    # Extract the Literal part of the type hint (filter out NoneType)
                    # -> (typing.Literal['capacity-optimized', 'lowest-price', 'diversified'])
                    literal_type = [
                        arg
                        for arg in get_args(
                            SocaHpcJobResourceModel.__annotations__[
                                "spot_allocation_strategy"
                            ]
                        )
                        if arg is not type(None)
                    ][0]

                    # Get the actual literal values
                    # ('capacity-optimized', 'lowest-price', 'diversified')
                    _allowed_spot_allocation_strategy_values = get_args(literal_type)

                    if (
                        self.spot_allocation_strategy
                        not in _allowed_spot_allocation_strategy_values
                    ):
                        raise ValueError(
                            f"spot_allocation_strategy must be {_allowed_spot_allocation_strategy_values}, detected {self.spot_allocation_strategy}"
                        )
                    logger.debug(
                        f"spot_allocation_strategy validated: {self.spot_allocation_strategy}"
                    )
                else:
                    logger.info(
                        "spot_allocation_strategy not specified, default to 'capacity-optimized'"
                    )
                    self.spot_allocation_strategy = "capacity-optimized"
            # ------------ /SPOT section (spot_price / spot_allocation_count / spot_allocation_strategy) ------------ #

            # ------------ FSxLustre section (fsx_lustre / fsx_lustre_deployment_type / fsx_lustre_size / fsx_lustre_per_unit_throughput) ------------ #
            if self.fsx_lustre:
                _allowed_fsx_deployment_type = [
                    "PERSISTENT_1",
                    "PERSISTENT_2",
                    "SCRATCH_1",
                    "SCRATCH_2",
                ]

                _allowed_fsx_per_unit_throughput = {
                    "PERSISTENT_1": [50, 100, 200],
                    "PERSISTENT_2": [125, 250, 500, 1000],
                    "SCRATCH_1": [200],
                    "SCRATCH_2": [200],
                }

                if self.fsx_lustre_deployment_type:
                    # force fsx_lustre_deployment_type to uppercase
                    self.fsx_lustre_deployment_type = str(
                        self.fsx_lustre_deployment_type
                    ).upper()
                else:
                    logger.info(
                        "fsx_lustre_deployment_type not set, default to SCRATCH_2"
                    )
                    self.fsx_lustre_deployment_type = "SCRATCH_2"

                if self.fsx_lustre_per_unit_throughput is None:
                    logger.info(
                        "fsx_lustre_per_unit_throughput not set, default to 200"
                    )
                    self.fsx_lustre_per_unit_throughput = 200

                if self.fsx_lustre is True or str(self.fsx_lustre).startswith("s3://"):
                    logger.debug(
                        f"Validating {self.fsx_lustre=} / {self.fsx_lustre_size=} / {self.fsx_lustre_deployment_type=} / {self.fsx_lustre_per_unit_throughput=}  "
                    )
                    if (
                        self.fsx_lustre_deployment_type
                        not in _allowed_fsx_deployment_type
                    ):
                        raise ValueError(
                            f"fsx_lustre is set but fsx_lustre_deployment_type not in {_allowed_fsx_deployment_type}"
                        )

                    if self.fsx_lustre_size is not None:
                        # For SCRATCH_1 deployment types, valid values are 1,200, 2,400, 3,600, then continuing in increments of 3,600 GiB
                        if self.fsx_lustre_deployment_type == "SCRATCH_1":
                            if self.fsx_lustre_size not in [1200, 2400, 3600]:
                                if not (
                                    self.fsx_lustre_size > 3600
                                    and (self.fsx_lustre_size - 3600) % 3600 == 0
                                ):
                                    raise ValueError(
                                        "fsx_lustre_size: Must be 1200, 2400, 3600 or increments of 3600 above"
                                    )

                        # For SCRATCH_2, PERSISTENT_2 and PERSISTENT_1 deployment types using SSD storage type, the valid values are 1200 GiB, 2400 GiB, and increments of 2400 GiB.
                        if self.fsx_lustre_deployment_type in [
                            "SCRATCH_2",
                            "PERSISTENT_1",
                            "PERSISTENT_2",
                        ]:
                            if self.fsx_lustre_size not in [1200, 2400]:
                                if (
                                    not self.fsx_lustre_size > 2400
                                    and (self.fsx_lustre_size - 2400) % 2400 == 0
                                ):
                                    raise ValueError(
                                        "fsx_lustre_size: Must be 1200, 2400 and increments of 2400"
                                    )
                    else:
                        raise ValueError(
                            "fsx_lustre_size: must be set when fsx_lustre is provided"
                        )

                    if self.fsx_lustre_per_unit_throughput is None:
                        # default to minimal value if not set
                        self.fsx_lustre_per_unit_throughput = (
                            _allowed_fsx_per_unit_throughput[
                                self.fsx_lustre_deployment_type
                            ][0]
                        )
                    else:
                        if (
                            self.fsx_lustre_per_unit_throughput
                            not in _allowed_fsx_per_unit_throughput[
                                self.fsx_lustre_deployment_type
                            ]
                        ):
                            raise ValueError(
                                f"fsx_lustre_per_unit_throughput must be {_allowed_fsx_per_unit_throughput[self.fsx_lustre_deployment_type]}"
                            )
                    logger.debug(
                        f"Validated fsx_lustre general config: {self.fsx_lustre=} / {self.fsx_lustre_size=} / {self.fsx_lustre_deployment_type=} / {self.fsx_lustre_per_unit_throughput=} "
                    )
                else:
                    logger.debug(
                        f"fsx_lustre is set with value {self.fsx_lustre=}, checking if it's a valid FSxL"
                    )
                    _check_fs = describe_file_systems(filesystem_ids=[self.fsx_lustre])
                    if _check_fs.get("success") is False:
                        raise ValueError(
                            f"Unable to validate {self.fsx_lustre} due to {_check_fs.get('message')}"
                        )
                    else:
                        _fs_info = _check_fs.get("message").get("FileSystems")[0]
                        if _fs_info.get("FileSystemType") != "LUSTRE":
                            raise ValueError(
                                f"Unable to validate {self.fsx_lustre} due to filesystem type mismatch. Only LUSTRE filesystems are supported, not {_fs_info.get('FileSystemType')}"
                            )
                        if _fs_info.get("Lifecycle") != "AVAILABLE":
                            raise ValueError(
                                f"Unable to validate {self.fsx_lustre} due to filesystem lifecycle mismatch. Only AVAILABLE filesystems are supported, not {_fs_info.get('Lifecycle')}"
                            )
                    logger.debug(f"Existing fsx_lustre validated: {self.fsx_lustre=}")
            else:
                logger.debug("FSx for Lustre is not enabled for this job")
                pass
            # ------------ /FSxLustre section (fsx_lustre / fsx_lustre_deployment_type / fsx_lustre_size / fsx_lustre_per_unit_throughput) ------------ #

            # ------------ capacity_reservation_id ------------ #
            if self.capacity_reservation_id is not None:
                logger.debug(
                    f"Validating capacity_reservation_id: {self.capacity_reservation_id}  {self.subnet_ids=} and {self.instance_types=}"
                )
                _all_odcr_combination = list(
                    product(self.instance_types, self.subnet_ids)
                )
                logger.info(f"ODCR Combinations to check {_all_odcr_combination}")
                _cr_validated = False
                for _instance_type, _subnet_id in _all_odcr_combination:
                    logger.info(
                        f"Checking if {self.capacity_reservation_id=} is valid for {_instance_type=} and {_subnet_id=}"
                    )

                    _validate_cr_info = validate_existing_capacity_reservation(
                        capacity_reservation=self.capacity_reservation_id,
                        instance_type=_instance_type,
                        desired_capacity=self.nodes,
                        instance_ami=self.instance_ami,
                        subnet_id=_subnet_id,
                    )
                    if _validate_cr_info.get("success") is False:
                        logger.error(
                            f"Unable to validate {self.capacity_reservation_id=} due to {_validate_cr_info.get('message')}"
                        )
                    else:
                        logger.info(
                            f"Validated ODCR with {_subnet_id=} and {_instance_type=}"
                        )
                        # enforce only valid subnet for the capacity reservation
                        self.subnet_ids = [_subnet_id]
                        self.instance_types = [_instance_type]
                        logger.debug(
                            f"capacity_reservation_id validated: {self.capacity_reservation_id}"
                        )
                        _cr_validated = True
                        break

                if not _cr_validated:
                    raise ValueError(
                        f"Unable to validate specified capacity reservation configuration"
                    )
                # ------------ /capacity_reservation_id ------------ #

            # ----- MISC ---#
            if self.force_ri is True and self.capacity_reservation_id is not None:
                raise ValueError(
                    "force_ri and capacity_reservation_id cannot be used together"
                )

            if self.spot_price is not None and self.capacity_reservation_id is not None:
                raise ValueError(
                    "spot_price and capacity_reservation_id cannot be used together"
                )

            return self
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            raise ValueError(
                f"Unable to normalize job due to {err} on line {exc_tb.tb_lineno}"
            )

    def get_job_provisioning_state(self) -> SocaHpcJobProvisioningState:
        """
        This function retrieve the status of the cloudformation stack associated to the job.
        In case of cloudformation create error, this function will automatically delete the stack and reset "stack_id" job resource.
        Dispatcher script will automatically re-process the job during its next run
        """
        if (
            _check_max_retry := SocaConfig(
                key="/system/orchestration/stack_max_retry_attempts"
            ).get_value(return_as=int)
        ).get("success"):
            max_retry_attempts = _check_max_retry.get("message")
        else:
            logger.error(f"{_check_max_retry} is not a valid integer, default to 2")
            max_retry_attempts = 3

        if self.job_failed_provisioning_retry_count >= max_retry_attempts:
            logger.error(
                f"Reached maximum retry for job provisioning, marking {self.job_id} as blocked. {self.job_failed_provisioning_retry_count=} / {max_retry_attempts=}"
            )
            self.job_provisioning_state = (
                SocaHpcJobProvisioningState.MAX_RETRY_ATTEMPTS_REACHED
            )
        else:
            if self.stack_id:
                logger.info(
                    f"Checking Stack Provisioning State for {self.job_id=} with {self.stack_id=}"
                )

                try:
                    _check_cfn_stack = _cloudformation_client.describe_stacks(
                        StackName=self.stack_id
                    )
                    _cfn_status = _check_cfn_stack["Stacks"][0]["StackStatus"]
                    logger.debug(
                        f"CloudFormation stack status for {self.job_id=} with {self.stack_id=} is {_cfn_status}"
                    )

                    if _cfn_status == "CREATE_IN_PROGRESS":
                        self.job_provisioning_state = (
                            SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_IN_PROGRESS
                        )
                    elif _cfn_status == "CREATE_COMPLETE":
                        self.job_provisioning_state = (
                            SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_COMPLETE
                        )

                    elif _cfn_status in ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"]:
                        # CloudFormation stack associated to the job is being deleted
                        self.job_provisioning_state = (
                            SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_DELETE
                        )
                    elif _cfn_status.endswith("_IN_PROGRESS"):
                        # Transient CFN transition (e.g. ROLLBACK_IN_PROGRESS,
                        # UPDATE_IN_PROGRESS, UPDATE_ROLLBACK_IN_PROGRESS). CFN is still
                        # processing this stack -- do NOT delete/rebuild it here; a delete
                        # mid-transition is rejected/unsafe. Treat as in-progress and
                        # re-evaluate next cycle once the stack settles to a terminal state.
                        self.job_provisioning_state = (
                            SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_IN_PROGRESS
                        )
                        logger.info(
                            f"CloudFormation status for {self.job_id=} is transient {_cfn_status=}; waiting for it to settle before any rebuild"
                        )
                    else:
                        # Settled failure (CREATE_FAILED / ROLLBACK_(COMPLETE|FAILED) /
                        # DELETE_FAILED / UPDATE_*_FAILED). Safe to delete + rebuild now.
                        self.job_provisioning_state = (
                            SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_ERROR
                        )
                        logger.info(
                            f"CloudFormation status for {self.job_id=} is a settled error state {_cfn_status=}, deleting Stack and updating Job resource. Dispatcher will try to process this job again soon"
                        )
                        SocaHpcJobController(
                            job=self
                        ).reset_cloudformation_stack_creation()

                except botocore.exceptions.ClientError as e:
                    _error = e.response["Error"]
                    _code = _error.get("Code")
                    _message = _error.get("Message", "")
                    _throttling_errors = [
                        "Throttling",
                        "ThrottlingException",
                        "RequestLimitExceeded",
                        "TooManyRequestsException",
                        "ProvisionedThroughputExceededException",
                        "InternalError",
                    ]
                    if _code == "ValidationError":
                        if (
                            f"stack with id {self.stack_id} does not exist".lower()
                            in _message.lower()
                        ):
                            # Previous stack was deleted but stack_id job variable was not flushed correctly, setting state to Pending
                            self.job_provisioning_state = (
                                SocaHpcJobProvisioningState.PENDING
                            )
                        else:
                            logger.error(
                                f"Failed to fetch {self.stack_id} stack status for {self.job_id=}: {str(e)}"
                            )
                            self.job_provisioning_state = (
                                SocaHpcJobProvisioningState.UNKNOWN
                            )
                    elif _code in _throttling_errors:
                        logger.error(
                            f"Unable to fetch {self.stack_id} stack status for {self.job_id=} due to throttling {str(e)}, no error message will attach to the job for now"
                        )
                        self.job_provisioning_state = (
                            SocaHpcJobProvisioningState.UNKNOWN
                        )
                    else:
                        logger.error(
                            f"Failed to fetch {self.stack_id} stack status for {self.job_id=}: {str(e)}"
                        )
                        SocaHpcJobController(job=self).set_error_message(
                            errors=["Unable to fetch associated CloudFormation Stack"]
                        )
                        self.job_provisioning_state = (
                            SocaHpcJobProvisioningState.UNKNOWN
                        )

                except Exception as e:
                    logger.error(
                        f"Failed to fetch {self.stack_id} stack status for {self.job_id=}: {str(e)}"
                    )
                    SocaHpcJobController(job=self).set_error_message(
                        errors=["Unable to fetch associated CloudFormation Stack"]
                    )
                    self.job_provisioning_state = SocaHpcJobProvisioningState.UNKNOWN
            else:
                # no cloudformation stack assigned yet
                self.job_provisioning_state = SocaHpcJobProvisioningState.PENDING

        logger.debug(
            f"Found {self.job_provisioning_state=} for {self.job_id=} with {self.stack_id=}"
        )
        return self.job_provisioning_state

    def provision_capacity(
        self,
        cluster_id: str,
        stack_name: str,
        keep_forever: bool = False,
        terminate_when_idle: int = 0,
        override_vcpus_quotas_for_pending_instances: dict = {},
    ) -> SocaResponse:

        # Sanitize stack_name
        stack_name = stack_name.replace("_", "-")
        # Remove all invalid characters (keep only letters, numbers, hyphens)
        stack_name = re.sub(r"[^A-Za-z0-9-]", "", stack_name)
        if not re.match(r"^[A-Za-z]", stack_name):
            return SocaError.GENERIC_ERROR(
                helper=f"{stack_name=} must start with a letter"
            )

        # Ensure CloudFormation stack name is lower than 128
        if Validators.is_string_length_lower_than(stack_name, 128) is False:
            return SocaError.GENERIC_ERROR(
                helper=f"{stack_name=} must be less than 128 characters"
            )

        logger.info(
            f"Trying to provision capacity for {self.job_id} with {stack_name=}"
        )

        if not self.job_config_validated:
            logger.info(
                "Job Configuration has not been validated yet , validating it ..."
            )
            _validate_job_resources = self.validate()
            if _validate_job_resources.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to validate Job Resource due to {_validate_job_resources.get('message')}"
                )

        # Provides extra information not yet exposed by the AWS API but useful for downstream jobs.
        # For example, if the request succeeds, temporarily override the vCPU quota check so the next job
        # accounts for this pending job (since AWS does not report it as provisioned yet).
        _response_message = {
            "override_vcpus_quotas_for_pending_instances": override_vcpus_quotas_for_pending_instances,
            "stack_name": stack_name,
        }

        logger.info(f"Validating DryRun for {self.job_id=}")
        _dry_run = create_capacity_dry_run(
            user_data=b"#!/bin/bash",
            disk_size=self.root_size,
            instance_type=self.instance_types[
                0
            ],  # at this point we have validated list of EC2 instance is fine. since dry run do not validate capacity availability we can just validate IAM/API permission wit hthe first instance
            desired_capacity=1,  # Note: Dry Run will not validate capacity availability. This will be done via capacity probing using odcr_helper
            security_group_id=self.security_groups,
            image_id=self.instance_ami,
            instance_profile=self.instance_profile,
            subnet_id=self.subnet_ids[0],
            key_name=SocaConfig(key="/configuration/SSHKeyPair")
            .get_value(return_as=str)
            .get("message"),
        )

        if _dry_run.get("success") is False:
            SocaHpcJobController(job=self).set_error_message(
                errors=[_dry_run.get("message")]
            )
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to provision capacity for {self.job_id=} due to {_dry_run.get('message')}"
            )
        else:
            logger.info(f"Dry Run validated for {self.job_id=}")

        logger.info(
            f"Validating Quotas check for {self.job_id=} and {self.instance_types=}"
        )
        _quota_validated = True
        for _instance in self.instance_types:
            _check_quota = validate_ec2_quota_for_instance(
                instance_type=_instance,
                desired_capacity=self.nodes,
                override_vcpus_quotas_for_pending_instances=_response_message[
                    "override_vcpus_quotas_for_pending_instances"
                ],
            )
            if _check_quota.get("success") is False:
                logger.error(
                    f"Quota: Unable to provision capacity for {self.job_id=} for instance type {_instance} due to {_check_quota.get('message')}"
                )
                _quota_validated = False
            else:
                if _check_quota.get("status_code") == 201:
                    logger.info("Quotas check disabled, skipping ")
                    _quota_validated = True
                else:
                    _quotas_info = _check_quota.get("message")
                    if (
                        _quotas_info.get("quota_name")
                        in _response_message[
                            "override_vcpus_quotas_for_pending_instances"
                        ].keys()
                    ):
                        _response_message[
                            "override_vcpus_quotas_for_pending_instances"
                        ][_quotas_info.get("quota_name")] = _response_message[
                            "override_vcpus_quotas_for_pending_instances"
                        ][
                            _quotas_info.get("quota_name")
                        ] + _quotas_info.get(
                            "running_vcpus"
                        )
                    else:
                        _response_message[
                            "override_vcpus_quotas_for_pending_instances"
                        ][_quotas_info.get("quota_name")] = _quotas_info.get(
                            "running_vcpus"
                        )
                        logger.info(
                            f"Quota check validated for {_instance} instance type"
                        )

        if not _quota_validated:
            SocaHpcJobController(job=self).set_error_message(
                errors=["You have exceeded the AWS Quotas for this type of instance"]
            )
            return SocaError.GENERIC_ERROR(
                helper="You have exceeded the AWS Quotas for this type of instance"
            )
        else:
            logger.info("Quotas check validated")

        logger.info(
            f"Probing EC2 capacity availability for {self.nodes=} {self.instance_types=} and {self.subnet_ids=}"
        )

        if self.placement_group:
            _create_pg = create_placement_group(stack_name)
            if _create_pg.get("success") is True:
                _placement_group = {
                    "group_arn": _create_pg.get("message")
                    .get("PlacementGroup")
                    .get("GroupArn"),
                    "group_name": _create_pg.get("message")
                    .get("PlacementGroup")
                    .get("GroupName"),
                    "group_id": _create_pg.get("message")
                    .get("PlacementGroup")
                    .get("GroupId"),
                }
                logger.info(
                    f"Placement Group created successfully for {self.job_id=}: {_placement_group}"
                )
            else:
                SocaHpcJobController(job=self).set_error_message(
                    errors=["Unable to create Placement Group"]
                )
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to provision capacity for {self.job_id=} due to {_create_pg.get('message')}"
                )
        else:
            _placement_group = {}

        if self.spot_price is None:
            if self.capacity_reservation_id is None:
                if (
                    SocaConfig(
                        key="/configuration/FeatureFlags/EnableCapacityReservation"
                    )
                    .get_value(return_as=bool)
                    .get("message")
                    is False
                ):
                    logger.warning(
                        "/configuration/FeatureFlags/EnableCapacityReservation is false, ignoring ODCR check"
                    )
                else:
                    _probe_capacity_only = False  # We actually enforce ODCR ID (and not only probe for capacity availability) which we pass to the SocaCloudFormationBuilderHpc

                    logger.info(
                        f"Creating On-Demand Capacity Reservation for {self.job_id=}"
                    )

                    # ODCR are 1:1 mapping between an instance type and a subnet ID
                    # We will try to see if we can secure capacity with any of the combination
                    _all_odcr_combination = list(
                        product(self.instance_types, self.subnet_ids)
                    )
                    logger.info(f"ODCR Combinations to check {_all_odcr_combination}")

                    _capacity_available = False

                    # We will try to get the entire capacity on a single subnet
                    # If we can't, SOCA will reject the job unless there is multiple subnet_ids specified, as EC2Fleet may be able to provision the capacity in multiple subnets
                    for _instance_type, _subnet_id in _all_odcr_combination:
                        _request_on_demand_capacity_reservation = (
                            create_capacity_reservation(
                                probe_capacity_only=_probe_capacity_only,
                                desired_capacity=self.nodes,
                                capacity_reservation_name=stack_name,
                                instance_type=_instance_type,
                                subnet_id=_subnet_id,
                                instance_ami=self.instance_ami,
                                placement_group_arn=_placement_group.get(
                                    "group_arn", None
                                ),
                            )
                        )

                        if (
                            _request_on_demand_capacity_reservation.get("success")
                            is True
                        ):
                            logger.info(
                                f"ODCR capacity validated for {self.job_id=} {self.nodes=} of {_instance_type} on {_subnet_id=} via {_request_on_demand_capacity_reservation.get('message')}"
                            )

                            # enforce specific subnet/instance type since we have validated capacity
                            self.subnet_ids = [_subnet_id]
                            self.instance_types = [_instance_type]
                            self.capacity_reservation_id = (
                                _request_on_demand_capacity_reservation.get("message")
                            )

                            _capacity_available = True
                            if _probe_capacity_only:
                                logger.warning(
                                    f"Capacity probing is True. SOCA has cancelled the reservation ID and the reservation ID will not be passed to the SocaCloudFormationBuilderHpc. use probe_capacity_only=False if you want to enforce capacity_reservation for your job"
                                )

                            break
                        else:
                            logger.error(
                                f"Unable to validate EC2 Capacity via ODCR request on {_subnet_id} for {_instance_type} due to {_request_on_demand_capacity_reservation}, testing another subnet if possible"
                            )

                    if not _capacity_available:
                        # Still accept the job if we can't secure a 1:1 ODCR and if there is multiple instance_types / subnet_id as EC2 Fleet may be able to
                        # provision the capacity in multiple subnets/instance types (unless /configuration/FeatureFlags/EnforceStrictCapacityReservation is True)
                        if (
                            Validators.is_list_length_greater_than(self.subnet_ids, 1)
                            is True
                            or Validators.is_list_length_greater_than(
                                self.instance_types, 1
                            )
                            is True
                        ):
                            if (
                                SocaConfig(
                                    key="/configuration/FeatureFlags/EnforceStrictCapacityReservation"
                                )
                                .get_value(return_as=bool)
                                .get("message")
                                is True
                            ):
                                logger.error(
                                    f"Unable to validate EC2 Capacity via ODCR on {self.subnet_ids} for {self.instance_types} and /configuration/FeatureFlags/EnforceStrictCapacityReservation is set to True"
                                )
                                SocaHpcJobController(job=self).set_error_message(
                                    errors=[
                                        "Unable to provision nodes because the available AWS capacity is insufficient in the selected subnet"
                                    ]
                                )
                                return SocaError.GENERIC_ERROR(
                                    helper="Unable to validate EC2 Capacity. See logs for more details."
                                )
                            else:
                                logger.warning(
                                    "SOCA was not able to secure capacity in a single subnets, but this job has been setup with multiple subnets or instance type: Capacity is not blocked as EC2Fleet may be able to provision the job using all combinations."
                                )

                        else:
                            logger.error(
                                f"Unable to validate EC2 Capacity via ODCR on {self.subnet_ids} for {self.instance_types}"
                            )
                            SocaHpcJobController(job=self).set_error_message(
                                errors=[
                                    "Unable to validate capacity availability via capacity reservation"
                                ]
                            )
                            return SocaError.GENERIC_ERROR(
                                helper="Unable to validate EC2 Capacity. See logs for more details."
                            )

            else:
                logger.info(
                    f"Existing Capacity Reservation specified, will use {self.capacity_reservation_id=}"
                )
        else:
            logger.warning(
                "SPOT instance detected, capacity reservation will NOT be checked "
            )

        logger.info(f"Creating CloudFormation Template for {self.job_id=}")
        _bootstrap_uuid = str(uuid.uuid4())
        _build_cloudformation_template = SocaCloudFormationBuilderHpc(
            job=self,
            stack_name=stack_name,
            keep_forever=keep_forever,
            terminate_when_idle=terminate_when_idle,
            placement_group_name=_placement_group.get("group_name", None),
            bootstrap_uuid=_bootstrap_uuid,
        ).render()
        if _build_cloudformation_template.get("success") is False:
            SocaHpcJobController(job=self).set_error_message(
                errors=[_build_cloudformation_template.get("message")]
            )
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to provision capacity for {self.job_id=} due to {_build_cloudformation_template.get('message')}"
            )
        else:
            logger.info(
                f"CloudFormation Template created successfully for {self.job_id=}"
            )
            logger.debug(
                f"Cloudformation Template for {self.job_id=}: {_build_cloudformation_template.get('message')}"
            )

        logger.info(
            f"Trying to create CloudFormation Stack for {self.job_id=} with stack name {stack_name}"
        )
        _create_cfn_stack = SocaCfnClient(stack_name=stack_name).create_stack(
            template_body=_build_cloudformation_template.get("message"),
            tags=[
                {
                    "Key": "edh:JobId",
                    "Value": str(self.job_id),
                },  # note: tag value must be str
                {"Key": "edh:NodeType", "Value": "compute_node"},
                {"Key": "edh:ClusterId", "Value": cluster_id},
                {
                    "Key": "edh:SchedulerProvider",
                    "Value": self.job_scheduler_info.provider,
                },
                {
                    "Key": "edh:SchedulerEndpoint",
                    "Value": self.job_scheduler_info.endpoint,
                },
                {
                    "Key": "edh:SchedulerIdentifier",
                    "Value": self.job_scheduler_info.identifier,
                },
                {"Key": "Name", "Value": stack_name},
            ],
        )

        if _create_cfn_stack.get("success") is False:
            SocaHpcJobController(job=self).set_error_message(
                errors=[_create_cfn_stack.get("message")]
            )

            # remove the bootstrap folder since the provisioning will not happen
            _bootstrap_log_folder = f"/apps/edh/{cluster_id}/shared/logs/bootstrap/compute_node/{self.job_id}/"
            try:
                folder = Path(_bootstrap_log_folder)
                logger.info(
                    f"{_bootstrap_log_folder} folder status for UUID {_bootstrap_uuid}"
                )
                if folder.exists():
                    logger.info(f"Removing {_bootstrap_log_folder} folder")
                    shutil.rmtree(folder)
            except Exception as err:
                logger.warning(f"Unable to delete {_bootstrap_log_folder} due to {err}")

            # Stack could not be created, delete capacity reservation ID
            if self.capacity_reservation_id:
                cancel_reservation(reservation_id=self.capacity_reservation_id)

            # Stack could not be created, delete placement_group
            if _placement_group:
                delete_placement_group(group_name=_placement_group.get("group_name"))

            return SocaError.GENERIC_ERROR(
                helper=f"Unable to provision capacity for {self.job_id=} due to {_create_cfn_stack.get('message')}"
            )
        else:
            logger.info(f"{stack_name} created successfully")
            if keep_forever:
                logger.info(
                    f"{stack_name} has {keep_forever=} flag set to True. Stack will be running until you delete it manually, no resource updates are required"
                )
                return SocaResponse(success=True, message=_response_message)

            logger.info("Retrieving the Job Resource Selector")
            if self.job_scheduler_info.provider in [
                SocaHpcSchedulerProvider.PBSPRO,
                SocaHpcSchedulerProvider.OPENPBS,
            ]:
                logger.info("Detected OpenPBS/PBSPro job, updating select resource")
                _resource_selector_name = "select"
                _current_select = self.pbs_resource_list.get("select")
                # Remove existing compute_node if present to avoid duplicates in case of re-provisioning after failure
                _current_select = re.sub(r":?compute_node=[^:\s]*", "", _current_select)
                _resource_selector_value = (
                    f"{_current_select}:compute_node={self.job_id}"
                )
            elif self.job_scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
                logger.info(
                    "Detected LSF job, updating select[compute_node==xx] resource"
                )
                _resource_selector_name = "compute_node"
                _resource_selector_value = self.job_id

            elif self.job_scheduler_info.provider == SocaHpcSchedulerProvider.SLURM:
                logger.info(
                    "Detected Slurm job, updating --constraint='compute_node=xx' constraint"
                )
                _resource_selector_name = "compute_node"
                _resource_selector_value = self.job_id
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to provision capacity for {self.job_id=} due to unsupported scheduler {self.job_scheduler_info.provider}"
                )

            logger.info(
                f"Found Job Selector Resource: {_resource_selector_name} with value {_resource_selector_value}"
            )

            logger.info(f"Updating {self.job_id=} Job Resources")
            job_resources_to_update = {
                _resource_selector_name: _resource_selector_value,  # update resource selector
                "stack_id": stack_name,  # update with the new cloudformation stack name
                "error_message": "",  # flush all errors
            }
            _ressources_update_error = []
            for (
                _resource_name,
                _resource_value,
            ) in job_resources_to_update.items():
                logger.info(
                    f"Updating Job Resource: {_resource_name}={_resource_value}"
                )

                if self.job_scheduler_info.provider in [
                    SocaHpcSchedulerProvider.PBSPRO,
                    SocaHpcSchedulerProvider.OPENPBS,
                ]:
                    _update_res = SocaHpcJobController(job=self).pbs_update_resource(
                        resource_name=_resource_name,
                        resource_value=_resource_value,
                    )
                elif self.job_scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
                    if _resource_name == "compute_node":
                        _update_res = SocaHpcJobController(
                            job=self
                        ).lsf_update_resource(
                            resource_name=_resource_name,
                            resource_value=_resource_value,
                            resource_type="Numeric",
                        )
                    else:
                        _update_res = SocaHpcJobController(
                            job=self
                        ).lsf_update_job_description(
                            resource_name=_resource_name, resource_value=_resource_value
                        )

                elif self.job_scheduler_info.provider == SocaHpcSchedulerProvider.SLURM:
                    if _resource_name == "compute_node":
                        logger.info(
                            f"On SLURM, the default constraint='compute_node={self.job_id}' is assigned at job submission via LUA SOCA plugins, no action needed here"
                        )
                    else:
                        _update_res = SocaHpcJobController(
                            job=self
                        ).slurm_update_comment(
                            resource_name=_resource_name, resource_value=_resource_value
                        )

            if _update_res.get("success") is False:
                logger.error(
                    f"Capacity provisioned but unable to update resources for {self.job_id=} due to {_update_res.get('message')}, {stack_name=} will be deleted"
                )
                _ressources_update_error.append(_resource_name)
            else:
                logger.info(
                    f"Successfully updated {_resource_name} for {self.job_id=} with value {_resource_selector_value}"
                )

            if _ressources_update_error:
                if (
                    _resource_selector_name in _ressources_update_error
                    or "stack_id" in _ressources_update_error
                ):
                    if (
                        SocaCfnClient(stack_name=stack_name)
                        .delete_stack()
                        .get("success")
                        is False
                    ):
                        return SocaError.GENERIC_ERROR(
                            helper=f"Capacity provisioned but unable to update resources for {self.job_id=} due to {_update_res.get('message')}. Unable to delete {stack_name=}"
                        )

                return SocaError.GENERIC_ERROR(
                    helper=f"Capacity was provisioned successfully but unable to update resources for {self.job_id=} due to {_update_res.get('message')}. Capacity has been removed."
                )

            return SocaResponse(success=True, message=_response_message)

    def apply_default_queue_values(
        self, queue_configuration: SocaHpcQueue, scheduler_info: SocaHpcScheduler
    ) -> SocaHpcJobLSF | SocaHpcJobPBS | SocaHpcJobSlurm:
        logger.info(
            "Checking all unset job attributes and replacing them with default value found in queue_mapping if available"
        )
        _excluded_fields = ["error_message", "licenses"]
        # only proceed to the job resources from SocaHpcJobResourceModel
        _fields_to_process = [
            field_name
            for field_name in SocaHpcJobResourceModel.model_fields
            if field_name not in _excluded_fields
        ]
        for _field_name in _fields_to_process:
            if getattr(self, _field_name, None) is None:
                logger.debug(
                    f"Checking if {_field_name=} has a default value in the queue config"
                )

                if hasattr(queue_configuration, _field_name):
                    value = getattr(queue_configuration, _field_name)
                    if value is not None:
                        logger.info(
                            f"Default value for {_field_name} found in queue configuration: {getattr(queue_configuration, _field_name)} "
                        )

                        # Update current SocaHpcJob instance
                        setattr(self, _field_name, value)

                        # Update resource on the job for analytics tracking
                        if scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
                            SocaHpcJobController(job=self).lsf_update_job_description(
                                resource_name=_field_name, resource_value=value
                            )
                        elif scheduler_info.provider in [
                            SocaHpcSchedulerProvider.PBSPRO,
                            SocaHpcSchedulerProvider.OPENPBS,
                        ]:
                            SocaHpcJobController(job=self).pbs_update_resource(
                                resource_name=_field_name, resource_value=value
                            )

        return self
