# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import os
import sys
import re
import pathlib
import logging
import uuid
import json
import datetime
import gzip

from typing import Optional

from troposphere import GetAtt
from troposphere import Ref, Template

from troposphere.cloudformation import AWSCustomObject
from troposphere.autoscaling import (
    AutoScalingGroup as AutoScalingGroup,
    LaunchTemplate as asg_LaunchTemplate,
    LaunchTemplateSpecification as asg_LaunchTemplateSpecification,
    LaunchTemplateOverrides as asg_LaunchTemplateOverrides,
)

from troposphere.ec2 import (
    BlockDeviceMapping,
    CpuOptions,
    EC2Fleet,
    EBSBlockDevice,
    CapacityRebalance,
    CapacityReservationSpecification,
    CapacityReservationTarget,
    FleetLaunchTemplateConfigRequest,
    FleetLaunchTemplateOverridesRequest,
    FleetLaunchTemplateSpecificationRequest,
    IamInstanceProfile,
    InstanceMarketOptions,
    LaunchTemplate,
    LaunchTemplateBlockDeviceMapping,
    LaunchTemplateData,
    MaintenanceStrategies,
    MetadataOptions,
    NetworkInterfaces,
    Placement,
    SpotOptions,
    SpotOptionsRequest,
    Tag,
    Tags,
    TagSpecifications,
    TargetCapacitySpecificationRequest,
)

from troposphere.fsx import FileSystem, LustreConfiguration

from utils.validators import Validators
from utils.config import SocaConfig
from utils.jinjanizer import SocaJinja2Generator
from utils.cast import SocaCastEngine
from utils.aws.ec2_helper import (
    is_ebs_optimized,
    describe_instance_types,
    describe_images,
)
from utils.aws.boto3_wrapper import get_boto
from utils.response import SocaResponse
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.datamodels.hpc.shared.job_resources import SocaHpcJobOrchestrationMethod


ec2_client = get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def sanitize_user_data(text_to_remove: list, user_data: str) -> str:
    for _t in text_to_remove:
        user_data = re.sub(f"{_t}", "", user_data, flags=re.IGNORECASE)

    # Remove leading spaces
    user_data = re.sub(r"^[ \t]+", "", user_data, flags=re.MULTILINE)

    # Remove lines that start with '#' but not '#!'
    user_data = re.sub(r"^(?!#!)#.*\n?", "", user_data, flags=re.MULTILINE)

    # Finally remove blank lines
    user_data = re.sub(r"^\s*\n", "", user_data, flags=re.MULTILINE)

    return user_data


class CustomResourceSendAnonymousMetrics(AWSCustomObject):
    resource_type = "Custom::SendAnonymousMetrics"
    props = {
        "ServiceToken": (str, True),
        "DesiredCapacity": (str, True),
        "InstanceType": (str, True),
        "Efa": (str, True),
        "ScratchSize": (str, True),
        "RootSize": (str, True),
        "SpotPrice": (str, True),
        "BaseOS": (str, True),
        "StackUUID": (str, True),
        "KeepForever": (str, True),
        "TerminateWhenIdle": (str, True),
        "FsxLustre": (str, True),
        "Dcv": (str, True),
        "Version": (str, True),
        "Region": (str, True),
        "Misc": (str, True),
    }


class CustomResourceNestedVirtLauncher(AWSCustomObject):
    resource_type = "Custom::NestedVirtLauncher"
    props = {
        "ServiceToken": (str, True),
        "LaunchTemplateId": (str, True),
        "LaunchTemplateVersion": (str, True),
        "NodeCount": (str, True),
        "InstanceTypes": (list, True),
        "StackName": (str, True),
        "CoreCount": (str, False),
        "ThreadsPerCore": (str, False),
    }


class SocaCloudFormationBuilderHpc:

    def __init__(
        self,
        job: SocaHpcJob,
        stack_name: str,
        bootstrap_uuid: uuid.UUID,
        keep_forever: bool = False,
        terminate_when_idle: int = 0,
        placement_group_name: Optional[str] = None,
    ):
        self.job = job
        self.keep_forever = keep_forever
        self.terminate_when_idle = terminate_when_idle
        self.stack_name = stack_name
        self.placement_group_name = placement_group_name
        self.bootstrap_uuid = str(bootstrap_uuid)

    def render(self):
        try:
            _job = self.job
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to render CloudFormation. Cannot unpack SocaHpcJob because of: {err}"
            )

        try:
            logger.info(f"Building CloudFormation stack for {_job.job_id}")

            # Retrieve SOCA specific variable from AWS Parameter Store
            _soca_parameters = (
                SocaConfig(key="/").get_value(return_as=dict).get("message")
            )

            if not _soca_parameters:
                return SocaError.GENERIC_ERROR(
                    helper=" Unable to query SSM for this SOCA environment"
                )

            _cluster_id = _soca_parameters.get("/configuration/ClusterId")

            # Metadata
            t = Template()
            t.set_version("2010-09-09")
            t.set_description(
                f"(SOCA) - Base template to deploy compute nodes. Version {_soca_parameters.get('/configuration/Version')}"
            )

            ltd = LaunchTemplateData("NodeLaunchTemplateData")

            _get_ami_info = describe_images(image_ids=[_job.instance_ami])
            if _get_ami_info.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to retrieve AMI information for {_job.instance_ami} due to {_get_ami_info.get('message')}"
                )
            else:
                _ami_information = _get_ami_info.get("message")
            logger.debug(f"AMI information for {_job.job_id=}: {_ami_information=}")

            # Retrieve a dictionary: Key: Type of the instance, Value: Instance Info
            _get_instance_type_info = describe_instance_types(
                instance_types=_job.instance_types
            )
            if _get_instance_type_info.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to retrieve instance type information for {_job.instance_types} due to {_get_instance_type_info.get('message')}"
                )
            else:
                _instance_type_mapping_info = {}
                for instance_type_info in _get_instance_type_info.get("message").get(
                    "InstanceTypes"
                ):
                    _instance_type_mapping_info[
                        instance_type_info.get("InstanceType")
                    ] = instance_type_info

            _total_instance_types = len(_job.instance_types)
            logger.debug(
                f"Found {_total_instance_types} instance type for {_job.job_id=} with value: {_instance_type_mapping_info}"
            )

            # Add SOCA job specific variables
            # job/xxx -> Job Specific (JobId, InstanceType, JobProject ...)
            # configuration/xxx -> SOCA environment specific (ClusterName, Base OS, Region ...)
            # system/xxx -> system related information (e.g: packages to install, DCV version, EFA version ...)
            _soca_parameters["/job/JobResources"] = (
                _job.model_dump()
            )  # send the SocaHpcJob information as a dictionary to jinja template
            _soca_parameters["/job/JobId"] = _job.job_id
            _soca_parameters["/job/JobOwner"] = _job.job_owner
            _soca_parameters["/job/JobName"] = _job.job_name
            _soca_parameters["/job/JobProject"] = _job.job_project
            _soca_parameters["/job/JobQueue"] = _job.job_queue
            _soca_parameters["/job/StackId"] = (
                self.stack_name
            )  # cannot ass AWS:StackName as this is a troposphere ref object
            _soca_parameters["/job/TerminateWhenIdle"] = str(self.terminate_when_idle)
            _soca_parameters["/job/KeepForever"] = str(self.keep_forever)
            _soca_parameters["/job/SchedulerIdentifier"] = (
                _job.job_scheduler_info.identifier
            )
            _soca_parameters["/job/BaseOS"] = _job.base_os
            _soca_parameters["/configuration/BaseOS"] = _job.base_os  # legacy
            # Location of Boostrap scripts on S3
            _bootstrap_s3_location_folder = f"{_cluster_id}/config/do_not_delete/bootstrap/compute_node/{self.bootstrap_uuid}"

            # Add custom bootstrap path specific to current job id
            _soca_parameters["/job/BootstrapPath"] = (
                f"/apps/edh/{_cluster_id}/shared/logs/bootstrap/compute_node/{_job.job_id}/{self.bootstrap_uuid}"
            )

            # add custom NodeType
            _soca_parameters["/job/NodeType"] = "compute_node"

            _soca_parameters["/job/BootstrapScriptsS3Location"] = (
                f"s3://{_soca_parameters.get('/configuration/S3Bucket')}/{_bootstrap_s3_location_folder}/"
            )

            logger.debug(f"Full Jinja context for {_job.job_id}: {_soca_parameters}")

            # NOTE: UserData (compute_node/01_user_data.sh.j2) is rendered
            # AFTER render_bootstrap_bundle() below, once
            # /job/BootstrapScriptsS3Location (cache URI) and
            # /job/SessionEnvS3Location (per-session) hold their final
            # values. Rendering it here would bake in the early per-session
            # prefix, and the worker would `s3 sync` from a dir that only
            # contains 00_session_env.sh -- the cache holds the big bootstrap
            # bodies (02_setup.sh etc.) elsewhere -- so 02_setup.sh would
            # never land on the node and `bash 02_setup.sh` fails. Mirrors the
            # DCV create path. See docs/BootstrapTemplateCache.md.

            # Create bootstrap setup invoked by user data
            # Create directory structure
            pathlib.Path(_soca_parameters.get("/job/BootstrapPath")).mkdir(
                parents=True, exist_ok=True
            )

            # Check if using AD, if yes check if we need to auto join the HPC nodes
            if _soca_parameters.get("/configuration/UserDirectory/provider") in [
                "aws_ds_managed_activedirectory",
                "existing_activedirectory",
            ]:
                _check_ephemeral_nodes_domain_join = SocaCastEngine(
                    data=_soca_parameters.get(
                        "/configuration/FeatureFlags/Hpc/JoinEphemeralNodesToAD"
                    )
                ).cast_as(expected_type=bool)
                if _check_ephemeral_nodes_domain_join.get("success") is True:
                    _join_ephemeral_nodes_to_ad = (
                        _check_ephemeral_nodes_domain_join.get("message")
                    )
                else:
                    logger.warning(
                        f"Unable to determine if JoinEphemeralNodesToAD is true or false: {_check_ephemeral_nodes_domain_join.get('message')}, node will NOT join AD by default"
                    )
                    _join_ephemeral_nodes_to_ad = False

                logger.info(
                    f"/configuration/FeatureFlags/Hpc/JoinEphemeralNodesToAD is set to {_join_ephemeral_nodes_to_ad}"
                )

                if _join_ephemeral_nodes_to_ad is False:
                    logger.info(
                        "AD is enabled and JoinEphemeralNodesToAD is False will attempt to sync AD users"
                    )
                    _json_output_file = f"/apps/edh/{_cluster_id}/shared/active_directory/sync/users_info.json"
                    if not pathlib.Path(_json_output_file).exists():
                        logger.error(
                            f"Unable to sync AD users because {_json_output_file} does not exist, creating it automatically"
                        )
                        _create_user_mapping_file = SocaSubprocessClient(
                            run_command=f"/opt/edh/{_cluster_id}/cluster_manager/edhctl ad export"
                        ).run()
                        if _create_user_mapping_file.get("success") is False:
                            logger.error(
                                f"Unable to create {_json_output_file} because of {_create_user_mapping_file.get('message')}"
                            )
                            return SocaError.GENERIC_ERROR(
                                helper=f"Unable to create {_json_output_file} because of {_create_user_mapping_file.get('message')}",
                            )
                    else:
                        logger.info(f"Found {_json_output_file}")
                        # Update the file if older than 60 minutes
                        with open(_json_output_file) as f:
                            _local_user_to_sync = json.load(f)

                        last_sync_str = _local_user_to_sync["last_sync"]
                        last_sync_dt = datetime.datetime.fromisoformat(last_sync_str)

                        if last_sync_dt.tzinfo is None:
                            last_sync_dt = last_sync_dt.replace(
                                tzinfo=datetime.timezone.utc
                            )

                        now_utc = datetime.datetime.now(datetime.timezone.utc)
                        age = now_utc - last_sync_dt
                        if age > datetime.timedelta(minutes=60):
                            logger.info(
                                "AD Local User Last sync is older than 60 minutes, updating file ..."
                            )
                            _create_user_mapping_file = SocaSubprocessClient(
                                run_command=f"/opt/edh/{_cluster_id}/cluster_manager/edhctl ad export"
                            ).run()
                            if _create_user_mapping_file.get("success") is False:
                                logger.error(
                                    f"Unable to create {_json_output_file} because of {_create_user_mapping_file.get('message')}"
                                )
                                return SocaError.GENERIC_ERROR(
                                    helper=f"Unable to create {_json_output_file} because of {_create_user_mapping_file.get('message')}",
                                )

                else:
                    logger.info(
                        "AD is enabled and JoinEphemeralNodesToAD is true will not attempt to sync AD users."
                    )

            # Bootstrap Sequence: Generate templates and upload them to S3.
            #
            # Routed through the BootstrapTemplateCache (default
            # enabled) so the big bootstrap bodies are rendered once
            # per (stack-config, .j2 tree) and reused across HPC jobs
            # of the same shape. Per-session values are surfaced via
            # a small env file (00_session_env.sh) that the worker
            # UserData stub sources before running the cached big
            # bootstrap.
            #
            # See docs/BootstrapTemplateCache.md.
            from utils.bootstrap_render import render_bootstrap_bundle

            try:
                _render_result = render_bootstrap_bundle(
                    soca_parameters=_soca_parameters,
                    bootstrap_root=(
                        f"/opt/edh/{_cluster_id}/cluster_node_bootstrap/"
                    ),
                    s3_client=get_boto(service_name="s3").message,
                    bucket=_soca_parameters.get("/configuration/S3Bucket"),
                    cluster_id=_cluster_id,
                    per_session_prefix=_bootstrap_s3_location_folder,
                    cache_prefix=f"{_cluster_id}/bootstrap/cache",
                    big_templates=[
                        "templates/linux/system_packages/install_required_packages.sh",
                        "templates/linux/filesystems_automount.sh",
                        "compute_node/02_setup.sh",
                        "compute_node/03_setup_post_reboot.sh",
                        "compute_node/04_setup_user_customization.sh",
                    ],
                    session_env_template="templates/linux/00_session_env.sh",
                    session_env_filename="00_session_env.sh",
                )
            except Exception as exc:
                logger.exception(
                    "HPC bootstrap render failed for job=%s: %s",
                    _job.job_id,
                    exc,
                )
                return SocaResponse(
                    success=False,
                    message=(
                        f"Unable to generate bootstrap templates for "
                        f"job {_job.job_id} because of {exc}"
                    ),
                )

            _soca_parameters["/job/BootstrapScriptsS3Location"] = (
                _render_result.bootstrap_scripts_s3
            )
            _soca_parameters["/job/SessionEnvS3Location"] = (
                _render_result.session_env_s3
            )
            logger.info(
                "HPC bootstrap render: job=%s cache_key=%s cache_hit=%s",
                _job.job_id,
                _render_result.cache_key,
                _render_result.cache_hit,
            )

            # Render UserData now that /job/BootstrapScriptsS3Location (cache
            # URI) and /job/SessionEnvS3Location (per-session) are finalized,
            # so the worker s3-syncs the big bootstrap scripts from the cache
            # prefix and cp's 00_session_env.sh from the per-session prefix.
            logger.debug(f"Creating User Data for {_job.job_id=}")
            _render_user_data = SocaJinja2Generator(
                get_template="compute_node/01_user_data.sh.j2",
                template_dirs=[f"/opt/edh/{_cluster_id}/cluster_node_bootstrap/"],
                variables=_soca_parameters,
            ).to_stdout(autocast_values=True)

            if _render_user_data.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to generate compute_node/01_user_data.sh.j2 Jinja2 template because of {_render_user_data.get('message')}",
                )
            else:
                _user_data = sanitize_user_data(
                    text_to_remove=[
                        "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                        "# SPDX-License-Identifier: Apache-2.0",
                    ],
                    user_data=_render_user_data.get("message"),
                )
                logger.debug(
                    f"UserData: 01_user_data.sh generated successfully for {_job.job_id}"
                )

            # Base tags
            _base_tags = {
                "Name": f"{_cluster_id}-compute-job-{_job.job_id}",
                "edh:JobId": str(_job.job_id),
                "edh:JobName": str(_job.job_name),
                "edh:JobQueue": str(_job.job_queue),
                "edh:StackId": Ref("AWS::StackName"),
                "edh:JobOwner": str(_job.job_owner),
                "edh:NodeType": "compute_node",
                "edh:JobProject": str(_job.job_project),
                "edh:ClusterId": str(_cluster_id),
                "edh:TerminateWhenIdle": str(self.terminate_when_idle),
                "edh:KeepForever": str(self.keep_forever),
                "edh:SchedulerProvider": _job.job_scheduler_info.provider,
                "edh:SchedulerEndpoint": _job.job_scheduler_info.endpoint,
                "edh:SchedulerIdentifier": _job.job_scheduler_info.identifier,
            }

            # Get custom tags if specified
            _tags_allowed = SocaConfig(
                key="/configuration/FeatureFlags/Hpc/AllowCustomTags"
            ).get_value(return_as=bool)
            if _tags_allowed.get("success") is True:
                if _tags_allowed.get("message") is True:
                    from utils.aws.odcr_helper import get_cluster_custom_tags
                    for _ct in get_cluster_custom_tags():
                        if _ct["Key"] in _base_tags:
                            logger.warning(
                                f"Specified custom tags {_ct.get('Key')} is already defined in tag list, skipping ..."
                            )
                        else:
                            _base_tags[_ct["Key"]] = _ct.get("Value", "")
                else:
                    logger.info(
                        "Custom tags are not allowed. AllowCustomTagsHPC is set to false"
                    )

            logger.debug(f"Tags to apply: {_base_tags}")

            # Begin LaunchTemplateData
            ltd.IamInstanceProfile = IamInstanceProfile(Arn=_job.instance_profile)
            ltd.KeyName = _soca_parameters.get("/configuration/SSHKeyPair")
            ltd.ImageId = _job.instance_ami
            ltd.InstanceType = _job.instance_types[
                0
            ]  # Note: Will configure Instance Override later in the code

            ltd.UserData = base64.b64encode(
                gzip.compress(_user_data.encode("utf-8"))
            ).decode("utf-8")

            _check_ebs_optimized = is_ebs_optimized(instance_types=_job.instance_types)
            if _check_ebs_optimized.get("success") is False:
                logger.error(
                    f"Unable to check if {_job.instance_types} is EBS optimized because of {_check_ebs_optimized.get('message')}. Disabling EbsOptimized"
                )
                ltd.EbsOptimized = False
            else:
                ltd.EbsOptimized = _check_ebs_optimized.get("message")

            # Begin CpuOptions
            if Validators.is_list_length_equal_of(_job.instance_types, 1) is True:
                # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/cpu-options-supported-instances-values.html
                # CpusOptions can only be used if we use only one instance type
                _cpus_option_supported = True
                _vcpus_info = _instance_type_mapping_info.get(
                    _job.instance_types[0]
                ).get("VCpuInfo", {})

                if _instance_type_mapping_info.get(_job.instance_types[0]).get(
                    "BareMetal", False
                ):
                    logger.warning(
                        "CpusOption is not supported on metal instance, skipping"
                    )
                    _cpus_option_supported = False

                elif not _vcpus_info:
                    logger.warning(
                        f"Missing VCpuInfo means no CPUOptions support for {_job.instance_types}"
                    )
                    _cpus_option_supported = False

                elif _vcpus_info.get("ValidThreadsPerCore", [1]) == [1]:
                    logger.warning(
                        f"CPUOptions not supported for {_job.instance_types}"
                    )
                    _cpus_option_supported = False

                if _cpus_option_supported:
                    _core_count = _vcpus_info.get("DefaultCores")
                    if _job.ht_support is False:
                        _thread_per_core = 1
                    else:
                        if 2 in _vcpus_info.get("ValidThreadsPerCore"):
                            _thread_per_core = 2
                        else:
                            logger.warning(
                                f"ht_support disabled but {_job.instance_types} does not support 2 threads per core, defaulting to 1"
                            )
                            _thread_per_core = 1

                    ltd.CpuOptions = CpuOptions(
                        CoreCount=_core_count,
                        ThreadsPerCore=_thread_per_core,
                    )
            else:
                logger.warning(
                    "CpuOptions cannot be used when the number of instance types for the job is greater than one, ignoring ..."
                )
            # End CpuOptions

            # Begin Capacity Reservation
            # note: CR can only be used for on-demand (spot_price and force_ri must not be set). This is validated as part of job.validate()
            if _job.capacity_reservation_id is not None:
                logger.info(
                    f"Using existing capacity reservation ID {_job.capacity_reservation_id}"
                )

                ltd.CapacityReservationSpecification = CapacityReservationSpecification(
                    CapacityReservationPreference="capacity-reservations-only",
                    CapacityReservationTarget=CapacityReservationTarget(
                        CapacityReservationId=_job.capacity_reservation_id.reservation_id
                    ),
                )

                if _job.capacity_reservation_id.reservation_type == "capacity-block":
                    logger.info(
                        "Capacity Block reservation detected, enforcing ASG until EC2 Fleet support it via CloudFormation handler and updating InstanceMarketOptions"
                    )
                    _job.job_orchestration_method = SocaHpcJobOrchestrationMethod.ASG
                    ltd.InstanceMarketOptions = InstanceMarketOptions(
                        MarketType="capacity-block"
                    )

            if _job.spot_price:
                if _job.spot_price == "auto":
                    # auto -> cap at OD price
                    ltd.InstanceMarketOptions = InstanceMarketOptions(MarketType="spot")
                else:
                    ltd.InstanceMarketOptions = InstanceMarketOptions(
                        MarketType="spot",
                        SpotOptions=SpotOptions(MaxPrice=str(_job.spot_price)),
                    )

            # Network Interfaces including EFA
            ltd.NetworkInterfaces = []
            if not _job.efa_support:
                ltd.NetworkInterfaces.append(
                    NetworkInterfaces(
                        InterfaceType=Ref("AWS::NoValue"),
                        DeleteOnTermination=True,
                        DeviceIndex=0,
                        NetworkCardIndex=0,
                        Groups=_job.security_groups,
                        AssociatePublicIpAddress=False,
                    )
                )
            else:
                for instance_type in _job.instance_types:
                    for efa_index in range(
                        _instance_type_mapping_info.get(instance_type)
                        .get("NetworkInfo", {})
                        .get("EfaInfo", {})
                        .get("MaximumEfaInterfaces", 0)
                    ):

                        ltd.NetworkInterfaces.append(
                            NetworkInterfaces(
                                # Card 0 is the primary ENI (full networking: SSH, NFS, SSM, IP traffic).
                                # Cards 1+ are EFA-fabric-only -- no IP
                                InterfaceType=("efa" if efa_index == 0 else "efa-only"),
                                DeleteOnTermination=True,
                                DeviceIndex=0,
                                NetworkCardIndex=efa_index,
                                Groups=_job.security_groups,
                                AssociatePublicIpAddress=False,
                            )
                        )

            # When using nested virt, the Lambda calls RunInstances with the launch
            # template directly — subnet must be in NetworkInterfaces
            if _job.nested_virtualization:
                for ni in ltd.NetworkInterfaces:
                    ni.SubnetId = _job.subnet_ids[0]

            # Configure EBS Root Device
            _ebs_root_device_name = _ami_information["Images"][0].get("RootDeviceName")
            _ebs_scratch_device_name = "/dev/xvdbx"
            _volume_type: str = _soca_parameters.get("VolumeType", "gp3")
            ltd.BlockDeviceMappings = [
                LaunchTemplateBlockDeviceMapping(
                    DeviceName=_ebs_root_device_name,
                    Ebs=EBSBlockDevice(
                        VolumeSize=_job.root_size,
                        VolumeType=_volume_type,
                        DeleteOnTermination=(
                            "false" if _job.keep_ebs is True else "true"
                        ),
                        Encrypted=True,
                    ),
                )
            ]

            # Configure EBS Scratch Device
            if _job.scratch_size:
                ltd.BlockDeviceMappings.append(
                    BlockDeviceMapping(
                        DeviceName=_ebs_scratch_device_name,
                        Ebs=EBSBlockDevice(
                            VolumeSize=_job.scratch_size,
                            VolumeType=(
                                "io2"
                                if (_job.scratch_iops and _job.scratch_iops > 0)
                                else _volume_type
                            ),
                            Iops=(
                                _job.scratch_iops
                                if (_job.scratch_iops and _job.scratch_iops > 0)
                                else Ref("AWS::NoValue")
                            ),
                            DeleteOnTermination=(
                                "false" if _job.keep_ebs is True else "true"
                            ),
                            Encrypted=True,
                        ),
                    )
                )

            # Tags
            ltd.TagSpecifications = [
                TagSpecifications(
                    ResourceType="instance",
                    Tags=[Tag(Key=k, Value=v) for k, v in _base_tags.items()],
                )
            ]

            ltd.MetadataOptions = MetadataOptions(
                HttpEndpoint="enabled",
                HttpTokens=_soca_parameters.get("/configuration/MetadataHttpTokens"),
            )

            # note: _job.placement_group is a boolean checking whether SOCA has created a placement group via provision_job()
            # if _job_placement_group is True, provision_job() create a placement group and send the group name to SocaCloudFormationBuilderHpc
            if self.placement_group_name:
                ltd.Placement = Placement(GroupName=self.placement_group_name)

            logger.debug(f"LaunchTemplateData completed for {_job.job_id}: {ltd}")

            # Configure LaunchTemplate
            lt = LaunchTemplate("NodeLaunchTemplate")
            lt.LaunchTemplateName = f"{_cluster_id}-{_job.job_id}"
            lt.LaunchTemplateData = ltd
            t.add_resource(lt)
            logger.debug(f"LaunchTemplate completed for {_job.job_id}: {lt}")

            _fleet_overrides = []

            logger.info(
                f"{len(_job.instance_types)} instance types detected, configure FleetLaunchTemplateOverridesRequest for EC2Fleet"
            )
            if Validators.is_list_length_greater_than(_job.instance_types, 1) is True:
                logger.info(
                    f"Multiple EC2 Instance Type specified: {_job.instance_types} and {_job.subnet_ids=}"
                )
                for _index, _instance_type in enumerate(_job.instance_types):
                    weight_per_subnet = (_total_instance_types - _index) // len(
                        _job.subnet_ids
                    )
                    # Ensure at least weight=1 per override
                    weight_per_subnet = max(weight_per_subnet, 1)

                    for subnet_id in _job.subnet_ids:
                        _fleet_overrides.append(
                            FleetLaunchTemplateOverridesRequest(
                                InstanceType=_instance_type,
                                SubnetId=subnet_id,
                                WeightedCapacity=str(weight_per_subnet),
                            )
                        )
            else:
                logger.info(
                    f"Single EC2 Instance Type specified: {_job.instance_types} and {_job.subnet_ids=}"
                )
                for subnet_id in _job.subnet_ids:
                    _fleet_overrides.append(
                        FleetLaunchTemplateOverridesRequest(
                            InstanceType=_job.instance_types[0], SubnetId=subnet_id
                        )
                    )

            # ASG or EC2Fleet job orchestration
            logger.info(
                f"Determining the SocaHpcJobOrchestrationMethod: {_job.job_orchestration_method=}"
            )

            if _job.nested_virtualization is True:
                # Check feature flag
                _nested_virt_allowed = SocaConfig(
                    key="/configuration/FeatureFlags/Hpc/EnableNestedVirtualization"
                ).get_value(return_as=bool)
                if not (_nested_virt_allowed.get("success") is True and _nested_virt_allowed.get("message") is True):
                    logger.warning(
                        "nested_virtualization=True requested but FeatureFlags/Hpc/EnableNestedVirtualization is not enabled, ignoring"
                    )
                    _job.nested_virtualization = False

            if _job.nested_virtualization is True:
                # Nested virtualization requires CpuOptions.NestedVirtualization which is not
                # supported by CloudFormation. Use a Custom Resource Lambda to call RunInstances directly.
                logger.info(
                    f"nested_virtualization=True, using Custom::NestedVirtLauncher instead of EC2Fleet/ASG"
                )
                _nested_virt_cr = CustomResourceNestedVirtLauncher("NestedVirtLauncher")
                _nested_virt_cr.DependsOn = "NodeLaunchTemplate"
                _nested_virt_cr.ServiceToken = _soca_parameters.get(
                    "/configuration/NestedVirtLauncherLambda"
                )
                _nested_virt_cr.LaunchTemplateId = Ref(lt)
                _nested_virt_cr.LaunchTemplateVersion = GetAtt(lt, "LatestVersionNumber")
                _nested_virt_cr.NodeCount = str(_job.nodes)
                _nested_virt_cr.InstanceTypes = _job.instance_types
                _nested_virt_cr.StackName = self.stack_name

                # Pass CpuOptions if they were computed for HT control
                if hasattr(ltd, "CpuOptions") and ltd.CpuOptions:
                    logger.info(f"LTD has CpuOptions {ltd.CpuOptions=}")
                    _nested_virt_cr.CoreCount = str(ltd.CpuOptions.resource.get("CoreCount", ""))
                    _nested_virt_cr.ThreadsPerCore = str(ltd.CpuOptions.resource.get("ThreadsPerCore", ""))
                    # Remove CpuOptions from LaunchTemplateData since the Lambda handles it
                    #del ltd.CpuOptions

                t.add_resource(_nested_virt_cr)

            elif _job.job_orchestration_method == SocaHpcJobOrchestrationMethod.ASG:
                logger.info(f"Generating ASG due to SocaHpcJobOrchestrationMethod")
                _asg_lt = asg_LaunchTemplate()

                _asg_lt.LaunchTemplateSpecification = asg_LaunchTemplateSpecification(
                    LaunchTemplateId=Ref(lt), Version=GetAtt(lt, "LatestVersionNumber")
                )
                logger.info(
                    f"Building ASG LaunchTemplateSpecification from the first instance specified in job ({_job.instance_types[0]}). ASG_LT {_asg_lt.LaunchTemplateSpecification=}"
                )
                _asg_lt.Overrides = []
                logger.info(f"Adding instance {_job.instance_types[0]} to to ASG LT")
                _asg_lt.Overrides.append(
                    asg_LaunchTemplateOverrides(InstanceType=_job.instance_types[0])
                )
                _asg = AutoScalingGroup("AutoScalingComputeGroup")
                _asg.DependsOn = "NodeLaunchTemplate"
                _asg.LaunchTemplate = asg_LaunchTemplateSpecification(
                    LaunchTemplateId=Ref(lt),
                    Version=GetAtt(lt, "LatestVersionNumber"),
                )
                _asg.MinSize = str(_job.nodes)
                _asg.MaxSize = str(_job.nodes)
                _asg.DesiredCapacity = str(_job.nodes)
                _asg.VPCZoneIdentifier = _job.subnet_ids
                _asg.CapacityRebalance = False

                logger.info(f"ASG completed for {_job.job_id}: {_asg}")

                t.add_resource(_asg)

            else:
                # Configure EC2Fleet
                ## Need to make sure the instance type is available in the AZ/subnet
                ## As the Override generation with incompatible deployment would cause the entire API
                ## to reject even if it could be fulfilled by another AZ.
                ## This resolution takes place with the EC2 API for describe-offerings
                logger.info(
                    f"Generating EC2 Fleet due to SocaHpcJobOrchestrationMethod"
                )

                _ec2_fleet = EC2Fleet(title="Ec2Fleet", Type="instant")
                _ec2_fleet.LaunchTemplateConfigs = [
                    FleetLaunchTemplateConfigRequest(
                        LaunchTemplateSpecification=FleetLaunchTemplateSpecificationRequest(
                            LaunchTemplateId=Ref(lt),
                            Version=GetAtt(lt, "LatestVersionNumber"),
                        ),
                        Overrides=_fleet_overrides,
                    )
                ]

                if _job.spot_price:
                    logger.info(
                        "Enforcing EC2Fleet FleetType to maintain when using spot"
                    )
                    _ec2_fleet.Type = "maintain"

                    logger.debug("Adding SpotOptions support for EC2Fleet")
                    _ec2_fleet.SpotOptions = SpotOptionsRequest(
                        InstanceInterruptionBehavior="terminate",
                        AllocationStrategy=_job.spot_allocation_strategy,
                        MaintenanceStrategies=MaintenanceStrategies(
                            CapacityRebalance=CapacityRebalance(
                                ReplacementStrategy="launch"
                            )
                        ),
                    )
                    _spot_instances_to_request = (
                        _job.spot_allocation_count
                        if _job.spot_allocation_count
                        else _job.nodes
                    )
                    _ondemand_instance_to_request = (
                        _job.nodes - _spot_instances_to_request
                    )
                    _ec2_fleet.TargetCapacitySpecification = (
                        TargetCapacitySpecificationRequest(
                            TotalTargetCapacity=_job.nodes,
                            SpotTargetCapacity=_spot_instances_to_request,
                            OnDemandTargetCapacity=_ondemand_instance_to_request,
                            DefaultTargetCapacityType="spot",
                        )
                    )

                else:
                    _ec2_fleet.TargetCapacitySpecification = (
                        TargetCapacitySpecificationRequest(
                            TotalTargetCapacity=int(_job.nodes),
                            DefaultTargetCapacityType="on-demand",
                            OnDemandTargetCapacity=int(_job.nodes),
                        )
                    )

                t.add_resource(_ec2_fleet)

            logger.info(f"Completed SocaHpcJobOrchestrationMethod")
            # End of Job Orchestration type (ASG/Fleet)
            # Back to other template items

            # FSx for Lustre
            if _job.fsx_lustre:
                if isinstance(_job.fsx_lustre, str):
                    logger.info(
                        f"Detected fsx_lustre to {_job.fsx_lustre}. Job will use an existing FSxL, ignoring FSxL creation"
                    )
                else:
                    # value: bool (True)
                    logger.info(
                        f"Detected fsx_lustre to {_job.fsx_lustre}, will provision a new FSx for Lustre"
                    )
                    fsx_lustre = FileSystem("FSxForLustre")
                    fsx_lustre.FileSystemType = "LUSTRE"
                    fsx_lustre.FileSystemTypeVersion = "2.15"
                    fsx_lustre.StorageCapacity = _job.fsx_lustre_size
                    fsx_lustre.SecurityGroupIds = _job.security_groups
                    fsx_lustre.SubnetIds = _job.subnet_ids
                    fsx_lustre_configuration = LustreConfiguration()
                    fsx_lustre_configuration.DeploymentType = (
                        _job.fsx_lustre_deployment_type.upper()
                    )
                    if _job.fsx_lustre_deployment_type.upper() in {
                        "PERSISTENT_1",
                        "PERSISTENT_2",
                    }:
                        fsx_lustre_configuration.PerUnitStorageThroughput = (
                            _job.fsx_lustre_per_unit_throughput
                        )
                    if str(_job.fsx_lustre).startswith("s3://"):
                        logger.info("FSxL + s3:// backend detected, configuring it ...")
                        # Syntax is fsx_lustre=<bucket>+<export_path>+<import_path>
                        check_user_specified_path = _job.fsx_lustre.split("+")
                        _import_path = False
                        _export_path = False
                        _s3_bucket_backend = check_user_specified_path[0]
                        if (
                            Validators.is_list_length_equal_of(
                                check_user_specified_path, 1
                            )
                            is True
                        ):
                            logger.info(
                                "only S3 bucket is specified for FSxL, not using Import/Export path"
                            )
                            pass
                        elif (
                            Validators.is_list_length_equal_of(
                                check_user_specified_path, 2
                            )
                            is True
                        ):
                            logger.info(
                                "Import path default to bucket root if not specified"
                            )
                            _export_path = check_user_specified_path[1]
                            _import_path = check_user_specified_path[0]

                        elif (
                            Validators.is_list_length_equal_of(
                                check_user_specified_path, 3
                            )
                            is True
                        ):
                            _export_path = check_user_specified_path[1]
                            _import_path = check_user_specified_path[2]

                        fsx_lustre_configuration.ImportPath = (
                            _import_path
                            if _import_path is not False
                            else _s3_bucket_backend
                        )
                        fsx_lustre_configuration.ExportPath = (
                            _export_path
                            if _export_path is not False
                            else f"{_s3_bucket_backend}/{_cluster_id}-fsx_lustre_output/job-{_job.job_id}/"
                        )

                    fsx_lustre.LustreConfiguration = fsx_lustre_configuration
                    fsx_lustre.Tags = Tags({**_base_tags, "edh:FSxL": "true"})
                    t.add_resource(fsx_lustre)
            # End FSx For Lustre

            # Begin Custom Resource
            # Change Mapping to No if you want to disable this
            if _job.anonymous_metrics is True:
                metrics = CustomResourceSendAnonymousMetrics("SendAnonymousData")
                metrics.ServiceToken = _soca_parameters.get(
                    "/configuration/SolutionMetricsLambda"
                )
                metrics.DesiredCapacity = str(_job.nodes)
                metrics.InstanceType = str(_job.instance_types)
                metrics.Efa = str(_job.efa_support)
                metrics.ScratchSize = str(_job.scratch_size)
                metrics.RootSize = str(_job.root_size)
                metrics.SpotPrice = str(_job.spot_price)
                metrics.BaseOS = str(_job.base_os)
                metrics.StackUUID = str(self.bootstrap_uuid)
                metrics.KeepForever = str(self.keep_forever)
                metrics.FsxLustre = str(
                    {
                        "fsx_lustre": _job.fsx_lustre,
                        "deployment_type": _job.fsx_lustre_deployment_type,
                        "capacity": _job.fsx_lustre_size,
                        "per_unit_throughput": _job.fsx_lustre_per_unit_throughput,
                    }
                )
                metrics.TerminateWhenIdle = str(self.terminate_when_idle)
                metrics.Dcv = "false"
                metrics.Region = str(_soca_parameters.get("/configuration/Region"))
                metrics.Version = str(_soca_parameters.get("/configuration/Version"))
                metrics.Misc = str(_soca_parameters.get("/configuration/Misc"))
                t.add_resource(metrics)
            # End Custom Resource

            _rendered_cloudformation_template = t.to_yaml()
            return SocaResponse(success=True, message=_rendered_cloudformation_template)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to generate cloudformation template for HPC {_job.job_id}: {e} {exc_type} {fname} {exc_tb.tb_lineno}"
            )
