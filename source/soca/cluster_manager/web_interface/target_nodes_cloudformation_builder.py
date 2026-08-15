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
from troposphere import Ref, Template, Sub
from troposphere import Tags as base_Tags  # without PropagateAtLaunch
from troposphere.cloudformation import AWSCustomObject
from troposphere.ec2 import (
    LaunchTemplate,
    LaunchTemplateData,
    MetadataOptions,
    EBSBlockDevice,
    IamInstanceProfile,
    LaunchTemplateBlockDeviceMapping,
    Placement,
    CapacityReservationSpecification,
    CapacityReservationTarget,
    Tag,
)
import troposphere.ec2 as ec2
import logging
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.error import SocaError
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
        "SubnetIds": (list, True),
        "InstanceTypes": (list, True),
        "StackName": (str, True),
        "CoreCount": (str, False),
        "ThreadsPerCore": (str, False),
    }


def main(**launch_parameters):
    try:
        logger.debug(f"Received DCV Cloudformation Parameters: {launch_parameters}")
        t = Template()
        t.set_version("2010-09-09")
        t.set_description(
            "(SOCA) - Base template to deploy Target nodes version 26.8.0"
        )
        allow_anonymous_data_collection = launch_parameters["DefaultMetricCollection"]
        # Launch Actual Capacity
        ltd = LaunchTemplateData("TargetHostLaunchTemplateData")

        _get_image = describe_images(image_ids=[launch_parameters.get("image_id")])
        if _get_image.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to describe the provided image ID because of {_get_image.get('message')}"
            ).as_flask()
        else:
            _image_details = _get_image.get("message")
            _ebs_root_device_name = _image_details["Images"][0].get("RootDeviceName")

        # Base tags
        _base_tags = {
            "Name": f"{launch_parameters['cluster_id']}-{launch_parameters['session_name']}-{launch_parameters['user']}",
            "edh:JobName": str(launch_parameters["session_name"]),
            "edh:JobOwner": str(launch_parameters["user"]),
            "edh:JobProject": str(launch_parameters["project"]),
            "edh:NodeType": "target_node",
            "edh:TargetNodeSessionUUID": str(launch_parameters["session_uuid"]),
            "edh:ClusterId": str(launch_parameters["cluster_id"]),
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
        # This allows the admin to define an min size for DCV sessions
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

        ltd.BlockDeviceMappings = [
            LaunchTemplateBlockDeviceMapping(
                DeviceName=_ebs_root_device_name,
                Ebs=EBSBlockDevice(
                    VolumeSize=(
                        40
                        if launch_parameters["disk_size"] is False
                        else int(launch_parameters["disk_size"])
                    ),
                    VolumeType=launch_parameters.get("volume_type", "gp3"),
                    DeleteOnTermination=True,
                    Encrypted=True,
                ),
            )
        ]
        ltd.ImageId = launch_parameters["image_id"]
        ltd.SecurityGroupIds = [launch_parameters["security_group_id"]]
        ltd.InstanceType = launch_parameters["instance_type"]
        ltd.IamInstanceProfile = IamInstanceProfile(
            Arn=launch_parameters["TargetNodeInstanceProfileArn"]
        )

        ltd.UserData = launch_parameters["user_data"]  # expects b64

        if launch_parameters.get("capacity_reservation_id", None) is not None:
            ltd.CapacityReservationSpecification = CapacityReservationSpecification(
                CapacityReservationPreference="capacity-reservations-only",
                CapacityReservationTarget=CapacityReservationTarget(
                    CapacityReservationId=launch_parameters["capacity_reservation_id"]
                ),
            )

        ltd.TagSpecifications = [
            ec2.TagSpecifications(
                ResourceType="instance",
                Tags=[Tag(Key=k, Value=v) for k, v in _base_tags.items()],
            )
        ]

        ltd.MetadataOptions = MetadataOptions(
            HttpEndpoint="enabled", HttpTokens=launch_parameters["metadata_http_tokens"]
        )

        # Instance Launch Tenancy in the Launch Template
        _desired_tenancy: str = (
            launch_parameters["tenancy"].lower()
            if "tenancy" in launch_parameters
            else "default"
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
        lt.LaunchTemplateName = (
            f"{launch_parameters['cluster_id']}-{launch_parameters['session_uuid']}"
        )

        lt.LaunchTemplateData = ltd
        t.add_resource(lt)

        if launch_parameters.get("nested_virtualization") is True:
            _nested_virt_cr = CustomResourceNestedVirtLauncher("NestedVirtLauncher")
            _nested_virt_cr.DependsOn = "DesktopLaunchTemplate"
            _nested_virt_cr.ServiceToken = launch_parameters["NestedVirtLauncherLambda"]
            _nested_virt_cr.LaunchTemplateId = Ref(lt)
            _nested_virt_cr.LaunchTemplateVersion = GetAtt(lt, "LatestVersionNumber")
            _nested_virt_cr.NodeCount = "1"
            _nested_virt_cr.SubnetIds = [launch_parameters["subnet_id"]]
            _nested_virt_cr.InstanceTypes = [launch_parameters["instance_type"]]
            _nested_virt_cr.StackName = lt.LaunchTemplateName
            t.add_resource(_nested_virt_cr)
        else:
            instance = ec2.Instance("TargetNodeInstance")
            instance.SubnetId = launch_parameters["subnet_id"]
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
            metrics.BaseOS = "unknown"
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
            metrics.Dcv = "false"
            metrics.Version = launch_parameters.get("Version", "")
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
            f"Unable to generate CloudFormation for Target Host because of {e} {exc_type} {fname} {exc_tb.tb_lineno}"
        )
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to generate CloudFormation for Target Host because of {e}"
        )
