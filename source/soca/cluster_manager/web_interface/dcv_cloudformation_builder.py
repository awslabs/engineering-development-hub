######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import os
import sys
import random
from troposphere import Base64, GetAtt
from troposphere import Ref, Template, Sub, Parameter, If, Equals, Not
from troposphere import Tags as base_Tags  # without PropagateAtLaunch
from troposphere.cloudformation import AWSCustomObject
from troposphere.ec2 import (
    CapacityReservationSpecification,
    CapacityReservationTarget,
    LaunchTemplate,
    LaunchTemplateData,
    MetadataOptions,
    EBSBlockDevice,
    IamInstanceProfile,
    LaunchTemplateBlockDeviceMapping,
    NetworkInterfaces,
    Placement,
    Tag,
)
import troposphere.ec2 as ec2
import logging
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.aws.ec2_helper import describe_images

logger = logging.getLogger("soca_logger")


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
        "VolumeType": (str, True),  # The volume_type of the Root Volume
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


def _resolve_volume_initialization_rate(stack_accel, global_default):
    """Resolve effective EBS volume initialization rate in MiB/s, or None (off)."""
    def _as_rate(_v):
        try:
            _n = int(str(_v).strip())
        except (TypeError, ValueError):
            return None
        return _n if 100 <= _n <= 300 else None

    # Per-stack override wins when set; "off" forces lazy regardless of global.
    if stack_accel is not None and str(stack_accel).strip() != "":
        _s = str(stack_accel).strip().lower()
        if _s == "off":
            return None
        return _as_rate(_s)
    # Otherwise inherit the fleet default.
    return _as_rate(global_default)


def main(**launch_parameters):
    try:
        logger.debug(f"Received DCV Cloudformation Parameters: {launch_parameters}")
        t = Template()
        t.set_version("2010-09-09")
        t.set_description(
            "(SOCA) - Base template to deploy DCV nodes version 26.8.0"
        )
        # Async placement: subnet + ODCR are chosen by the DcvPlacement Lambda
        # at stack-create time and injected as CFN parameters by CapacityExecutor,
        # so the controller skips the synchronous ODCR probe entirely. When the
        # async flag is off, the template bakes literal values exactly as before.
        _async_placement = launch_parameters.get("async_placement", False)
        if _async_placement:
            t.add_parameter(Parameter("SubnetId", Type="String"))
            t.add_parameter(
                Parameter("CapacityReservationId", Type="String", Default="")
            )
            # Source of the reservation ("auto" = per-session probe-and-mint,
            # "admin" = operator-supplied CR-id). Decided by DcvPlacement at
            # runtime and injected by CapacityExecutor; surfaced as an instance
            # tag so the resume path knows whether it may re-secure the CR.
            t.add_parameter(
                Parameter("CapacityReservationSource", Type="String", Default="auto")
            )
            t.add_parameter(
                Parameter("LaunchTemplateNameSuffix", Type="String", Default="")
            )
            t.add_condition(
                "HasOdcr", Not(Equals(Ref("CapacityReservationId"), ""))
            )
        _subnet_value = (
            Ref("SubnetId") if _async_placement else launch_parameters["subnet_id"]
        )
        allow_anonymous_data_collection = launch_parameters["DefaultMetricCollection"]
        # Launch Actual Capacity
        ltd = LaunchTemplateData("DesktopLaunchTemplateData")

        _get_image = describe_images(image_ids=[launch_parameters.get("image_id")])
        if _get_image.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=f"Unable to describe the provided image ID because of {_get_image.get('message')}").as_flask()
        else:
            _image_details = _get_image.get("message")
            _ebs_root_device_name = _image_details["Images"][0].get("RootDeviceName")
        # Base tags
        _base_tags = {
            "Name": f"{launch_parameters['cluster_id']}-{launch_parameters['session_name']}-{launch_parameters['user']}",
            "edh:JobName": str(launch_parameters["session_name"]),
            "edh:JobOwner": str(launch_parameters["user"]),
            "edh:NodeType": "dcv_node",
            "edh:JobProject": str(launch_parameters["project"]),
            "edh:DCVSupportHibernate": str(launch_parameters["hibernate"]).lower(),
            "edh:ClusterId": str(launch_parameters["cluster_id"]),
            "edh:DCVSessionUUID": str(launch_parameters["session_uuid"]),
            "edh:DCVSystem": str(launch_parameters["base_os"]),
        }

        if launch_parameters.get("custom_tags"):
            for tag in launch_parameters["custom_tags"].values():
                if tag.get("Enabled", ""):
                    if tag["Key"] in _base_tags.keys():
                        logger.warning(
                            f"Specified custom tags {tag.get('Key')} is already defined in tag list, skipping ..."
                        )
                    else:
                        _base_tags[tag["Key"]] = tag["Value"]
                else:
                    logger.warning(
                        f"{tag} does not have Enabled key or Enabled is False."
                    )

        # Make sure that the requested disk size is proper
        # This allows the admin to define a min size for DCV sessions
        # and register this size as part of the AMI registration process.
        # This in turn cannot be smaller than the AMI size either.

        _root_size_gb_list = []

        # What did the user ask for?
        if "disk_size" not in launch_parameters or not launch_parameters.get(
            "disk_size", False
        ):
            _root_size_gb_list.append(40)  # DEFAULT size fallback
        else:
            _root_size_gb_list.append(int(launch_parameters["disk_size"]))

        # Per-stack override falls back to the fleet SocaConfig default. The
        # fleet key is optional: allow_unknown_key + success gate resolve an
        # unset key to no-PRVI without emitting a not-found error every launch.
        _fleet_vir_resp = SocaConfig(
            key="/configuration/VolumeInitializationRate"
        ).get_value(default=None, allow_unknown_key=True)
        _effective_vir = _resolve_volume_initialization_rate(
            launch_parameters.get("volume_acceleration"),
            _fleet_vir_resp.message if _fleet_vir_resp.success else None,
        )
        if launch_parameters["disk_size"] is False:
            _root_volume_size = 40
        else:
            _dsz = SocaCastEngine(launch_parameters["disk_size"]).cast_as(expected_type=int)
            _root_volume_size = _dsz.get("message") if _dsz.get("success") else 40
        _ebs_root_kwargs = dict(
            VolumeSize=_root_volume_size,
            VolumeType=launch_parameters.get("volume_type", "gp3"),
            DeleteOnTermination=True,
            Encrypted=True,
        )
        if _effective_vir:
            # Native kwarg; requires troposphere >= 4.9.6 (pinned in
            # soca_python_controller_requirements.txt.j2).
            _ebs_root_kwargs["VolumeInitializationRate"] = _effective_vir
            logger.info(
                f"PRVI enabled on root volume at {_effective_vir} MiB/s "
                f"(stack override={launch_parameters.get('volume_acceleration')})"
            )

        ltd.BlockDeviceMappings = [
            LaunchTemplateBlockDeviceMapping(
                DeviceName=_ebs_root_device_name,
                Ebs=EBSBlockDevice(**_ebs_root_kwargs),
            )
        ]
        ltd.ImageId = launch_parameters["image_id"]
        _enable_ipv6 = launch_parameters.get("enable_ipv6") is True
        if launch_parameters.get("nested_virtualization") is True:
            _vdi_ni = NetworkInterfaces(
                DeleteOnTermination=True,
                DeviceIndex=0,
                Groups=[launch_parameters["security_group_id"]],
                SubnetId=_subnet_value,
                AssociatePublicIpAddress=False,
            )
            if _enable_ipv6:
                _vdi_ni.Ipv6AddressCount = 1
            ltd.NetworkInterfaces = [_vdi_ni]
        elif _enable_ipv6:
            # IPv6: SG + IPv6 + subnet go on the ENI (NetworkInterfaces can't coexist with top-level SecurityGroupIds)
            ltd.NetworkInterfaces = [
                NetworkInterfaces(
                    DeleteOnTermination=True,
                    DeviceIndex=0,
                    Groups=[launch_parameters["security_group_id"]],
                    SubnetId=_subnet_value,
                    AssociatePublicIpAddress=False,
                    Ipv6AddressCount=1,
                )
            ]
        else:
            ltd.SecurityGroupIds = [launch_parameters["security_group_id"]]
        if _enable_ipv6:
            # Resource-name DNS + AAAA so the DcvServer DefaultDnsName resolves IPv6 (gateway dials the host over v6); A kept as fallback
            ltd.PrivateDnsNameOptions = ec2.PrivateDnsNameOptions(
                HostnameType="resource-name",
                EnableResourceNameDnsAAAARecord=True,
                EnableResourceNameDnsARecord=True,
            )
        if launch_parameters["hibernate"] is True:
            ltd.HibernationOptions = ec2.HibernationOptions(Configured=True)
        ltd.InstanceType = launch_parameters["instance_type"]
        if launch_parameters.get("spot") is True:
            ltd.InstanceMarketOptions = ec2.InstanceMarketOptions(MarketType="spot")
        ltd.IamInstanceProfile = IamInstanceProfile(
            Arn=launch_parameters["VdiNodeInstanceProfileArn"]
        )

        ltd.UserData = launch_parameters["user_data"]  # expects b64

        # Capacity-reservation provenance tag, read by the resume path
        # (start_virtual_desktop) to decide whether the CR may be re-secured:
        #   async  -> driven by the CapacityReservationSource CFN parameter
        #   sync + admin CR-id -> literal "admin" (never auto-replaced)
        #   sync, no CR        -> untagged (no reservation pinned to the instance)
        if _async_placement:
            _cr_source_tags = [
                Tag(
                    Key="edh:CapacityReservationSource",
                    Value=Ref("CapacityReservationSource"),
                )
            ]
        elif launch_parameters.get("capacity_reservation_id"):
            _cr_source_tags = [
                Tag(Key="edh:CapacityReservationSource", Value="admin")
            ]
        else:
            _cr_source_tags = []

        ltd.TagSpecifications = [
            ec2.TagSpecifications(
                ResourceType="instance",
                Tags=[Tag(Key=k, Value=v) for k, v in _base_tags.items()]
                + _cr_source_tags,
            )
        ]

        ltd.MetadataOptions = MetadataOptions(
            HttpEndpoint="enabled",
            HttpTokens=launch_parameters["metadata_http_tokens"],
            InstanceMetadataTags="enabled",
        )

        # Instance Launch Tenancy in the Launch Template
        _desired_tenancy: str = (
            launch_parameters["tenancy"].lower()
            if "tenancy" in launch_parameters
            else "default"
        )

        if _async_placement and not launch_parameters.get("spot"):
            # ODCR id is supplied at stack-create time via the
            # CapacityReservationId parameter. If/NoValue omits the spec
            # entirely when the Lambda reserved no ODCR (empty string).
            ltd.CapacityReservationSpecification = If(
                "HasOdcr",
                CapacityReservationSpecification(
                    CapacityReservationPreference="capacity-reservations-only",
                    CapacityReservationTarget=CapacityReservationTarget(
                        CapacityReservationId=Ref("CapacityReservationId")
                    ),
                ),
                Ref("AWS::NoValue"),
            )
        elif launch_parameters["capacity_reservation_id"] and not launch_parameters.get("spot"):
            logger.info(
                f"Using existing capacity reservation ID {launch_parameters['capacity_reservation_id']=}"
            )
            ltd.CapacityReservationSpecification = CapacityReservationSpecification(
                CapacityReservationPreference="capacity-reservations-only",
                CapacityReservationTarget=CapacityReservationTarget(
                    CapacityReservationId=str(
                        launch_parameters["capacity_reservation_id"]
                    )
                ),
            )

        # Add SSH Key
        ltd.KeyName = SocaConfig(key="/configuration/SSHKeyPair").get_value().message

        # Only set HostId if we need it (dedicated host mode)
        if _desired_tenancy.lower() == "host":
            _desired_host_id: str = str(launch_parameters["host_id"]).lower()
            ltd.Placement = Placement(Tenancy=_desired_tenancy, HostId=_desired_host_id)
        else:
            # We do not need set a HostId for default(shared) or dedicated(aka dedicated instance)
            ltd.Placement = Placement(Tenancy=_desired_tenancy)

        lt = LaunchTemplate("DesktopLaunchTemplate")
        _lt_base = f"{launch_parameters['cluster_id']}-{launch_parameters['session_uuid']}"
        if _async_placement:
            lt.LaunchTemplateName = Sub(_lt_base + "${LaunchTemplateNameSuffix}")
        else:
            lt.LaunchTemplateName = _lt_base

        lt.LaunchTemplateData = ltd
        # Tag the launch template resource itself (LaunchTemplateData.TagSpecifications
        # only tags the instances/volumes it launches, not the LT). (V2149182652)
        lt.TagSpecifications = [
            ec2.TagSpecifications(
                ResourceType="launch-template",
                Tags=[Tag(Key=k, Value=v) for k, v in _base_tags.items()],
            )
        ]
        t.add_resource(lt)

        if launch_parameters.get("nested_virtualization") is True:
            _nested_virt_cr = CustomResourceNestedVirtLauncher("NestedVirtLauncher")
            _nested_virt_cr.DependsOn = "DesktopLaunchTemplate"
            _nested_virt_cr.ServiceToken = launch_parameters["NestedVirtLauncherLambda"]
            _nested_virt_cr.LaunchTemplateId = Ref(lt)
            _nested_virt_cr.LaunchTemplateVersion = GetAtt(lt, "LatestVersionNumber")
            _nested_virt_cr.NodeCount = "1"
            _nested_virt_cr.InstanceTypes = [launch_parameters["instance_type"]]
            _nested_virt_cr.StackName = lt.LaunchTemplateName
            t.add_resource(_nested_virt_cr)
        else:
            instance = ec2.Instance("VirtualDesktopInstance")
            if not _enable_ipv6:
                # IPv6 path carries the subnet on the LT ENI; setting it here too conflicts
                instance.SubnetId = _subnet_value
            instance.Tenancy = launch_parameters["tenancy"]
            instance.LaunchTemplate = ec2.LaunchTemplateSpecification(
                LaunchTemplateId=Ref(lt), Version=GetAtt(lt, "LatestVersionNumber")
            )
            t.add_resource(instance)

        # Begin Custom Resource
        # Change Mapping to No if you want to disable this
        if allow_anonymous_data_collection is True:
            metrics = CustomResourceSendAnonymousMetrics("SendAnonymousData")
            metrics.ServiceToken = launch_parameters["SolutionMetricsLambda"]
            metrics.DesiredCapacity = "1"
            metrics.InstanceType = str(launch_parameters["instance_type"])
            metrics.Efa = "false"
            metrics.ScratchSize = "0"
            metrics.RootSize = str(launch_parameters["disk_size"])
            metrics.VolumeType = launch_parameters.get("volume_type", "gp3")
            metrics.SpotPrice = "false"
            metrics.BaseOS = str(launch_parameters["base_os"])
            metrics.StackUUID = str(launch_parameters["session_uuid"])
            metrics.KeepForever = "false"
            metrics.FsxLustre = str(
                {
                    "fsx_lustre": "false",
                    "existing_fsx": "false",
                    "s3_backend": "false",
                    "import_path": "false",
                    "export_path": "false",
                    "deployment_type": "false",
                    "per_unit_throughput": "false",
                    "capacity": 1200,
                }
            )
            metrics.TerminateWhenIdle = "false"
            metrics.Dcv = "true"
            metrics.Version = str(launch_parameters.get("Version", ""))
            metrics.Region = launch_parameters.get("Region", "")
            metrics.Misc = launch_parameters.get("Misc", "")
            t.add_resource(metrics)
        # End Custom Resource

        # Tags must use "edh:<Key>" syntax
        template_output = t.to_yaml()
        return SocaResponse(success=True, message=template_output)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error(
            f"Unable to generate CloudFormation for DCV because of {e} {exc_type} {fname} {exc_tb.tb_lineno}"
        )
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to generate CloudFormation for DCV because of {e}"
        )
