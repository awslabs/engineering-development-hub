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

import argparse
import ast
import os
import random
import re
import sys
import uuid
from math import ceil
from botocore.exceptions import ClientError
from botocore import exceptions
import utils.aws.odcr_helper as odcr_helper

sys.path.append(
    f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID', 'SOCA_CONFIGURATION_NOT_FOUND')}/cluster_manager"
)
import cloudformation_builder
from utils.config import SocaConfig
from utils.aws.boto3_wrapper import get_boto
import logging

logger = logging.getLogger("soca_logger")
cloudformation = get_boto(service_name="cloudformation").message
s3 = get_boto(service_name="s3").message
ec2 = get_boto(service_name="ec2").message
iam = get_boto(service_name="iam").message
servicequotas = get_boto(service_name="service-quotas").message


def is_placement_group_supported(
    instance_type: [str, list[str]], placement_group_type: str = "cluster"
) -> bool:
    """
    Determine if a given instance type supports the given placement group type by sending a query to the AWS API.
    """
    _query_instance_list: list = []
    _pg_supported_list: list = []
    _pg_unsupported_list: list = []

    if isinstance(instance_type, list):
        _query_instance_list = instance_type
    elif isinstance(instance_type, str):
        _query_instance_list.append(instance_type)

    if not _query_instance_list:
        return False

    if placement_group_type not in {"cluster", "partition", "spread"}:
        print(
            f"ERROR - {placement_group_type} is not a valid placement group type. Must be one of cluster, partition, spread."
        )
        return False

    try:
        # Paginator not needed since this should be an exact match query
        _resp: dict = ec2.describe_instance_types(InstanceTypes=_query_instance_list)
        for _instance_type in _resp.get("InstanceTypes", []):
            _instance_type_name: str = _instance_type.get(
                "InstanceType", "unknown-instance-name"
            )
            # If we see the proper supported PG type - append to our running list of supported
            _supported_pgs: list = _instance_type.get("PlacementGroupInfo", {}).get(
                "SupportedStrategies", []
            )

            if placement_group_type in _supported_pgs:
                if _instance_type_name not in _pg_supported_list:
                    _pg_supported_list.append(_instance_type_name)
            else:
                if _instance_type_name not in _pg_unsupported_list:
                    _pg_unsupported_list.append(_instance_type_name)

    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidParameterValue":
            return False
        else:
            raise err

    # Do we have any instances in the query list that are unsupported?
    if _pg_unsupported_list:
        return False
    else:
        return True


def find_running_cpus_per_instance(instance_list) -> int:
    # The term 'vcpu' is used for both vcpu and phycpu for quota
    # calculation purposes.
    # It comes down to what each instance counts torwards the quota
    running_vcpus: int = 0
    ec2_paginator = ec2.get_paginator("describe_instances")
    ec2_iterator = ec2_paginator.paginate(
        Filters=[
            {"Name": "instance-type", "Values": instance_list},
            {"Name": "instance-state-name", "Values": ["running", "pending"]},
        ],
    )

    for page in ec2_iterator:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                _core_count: int = instance.get("CpuOptions", {}).get("CoreCount", 1)
                _threads_per_core: int = instance.get("CpuOptions", {}).get(
                    "ThreadsPerCore", 1
                )
                running_vcpus += _core_count * _threads_per_core

    return running_vcpus


def verify_ri_saving_availabilities(instance_type, instance_type_info):
    if instance_type not in instance_type_info.keys():
        instance_type_info[instance_type] = {
            "current_instance_in_use": 0,
            "current_ri_purchased": 0,
        }

        # List all instances from this type currently running
        ec2_paginator = ec2.get_paginator("describe_instances")
        ec2_iterator = ec2_paginator.paginate(
            Filters=[
                {"Name": "instance-type", "Values": [instance_type]},
                {"Name": "instance-state-name", "Values": ["running", "pending"]},
            ],
        )

        for page in ec2_iterator:
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    try:
                        if instance["InstanceType"] == instance_type:
                            instance_type_info[instance_type][
                                "current_instance_in_use"
                            ] += 1
                    except Exception as _e:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                        print(exc_type, fname, exc_tb.tb_lineno)

        # Now list of many RI we have for this instance type
        get_ri_count = ec2.describe_reserved_instances(
            Filters=[
                {"Name": "instance-type", "Values": [instance_type]},
                {"Name": "state", "Values": ["active"]},
            ]
        )

        if get_ri_count["ReservedInstances"]:
            for reservation in get_ri_count["ReservedInstances"]:
                instance_type_info[instance_type][
                    "current_ri_purchased"
                ] += reservation["InstanceCount"]

    # print(f"Detected {instance_type_info[instance_type]["current_instance_in_use"]} running {instance_type} instance ")
    # print(f"Detected {instance_type_info[instance_type]['current_ri_purchased']} RI for {instance_type} instance")
    return instance_type_info


def verify_vcpus_limit(instance_type, desired_capacity, quota_info):
    cpus_count_pattern = re.search(r"[.](\d+)", instance_type)
    find_instance_family = re.search(r"(.*)\d", instance_type.split(".")[0])
    if find_instance_family:
        instance_family = find_instance_family.group(1)
    else:
        return {
            "message": f"Unable to detect instance type for {instance_type}",
            "quota_info": "",
        }

    if cpus_count_pattern:
        vcpus_per_instance = int(cpus_count_pattern.group(1)) * 4
    else:
        if "xlarge" in instance_type:
            vcpus_per_instance = 4
        else:
            vcpus_per_instance = 2

    total_vcpus_requested = vcpus_per_instance * int(desired_capacity)
    running_vcpus = 0

    max_vcpus_allowed = False
    quota_name = False

    if not quota_info or instance_type not in quota_info.keys():
        servicequotas_paginator = servicequotas.get_paginator("list_service_quotas")
        servicequotas_iterator = servicequotas_paginator.paginate(ServiceCode="ec2")

        for page in servicequotas_iterator:
            for quota in page["Quotas"]:
                if "running on-demand" in quota["QuotaName"].lower() and re.search(
                    f"(\s|\(){instance_family}(\s|\)|,)", quota["QuotaName"].lower()
                ):
                    max_vcpus_allowed = quota["Value"]
                    quota_name = quota["QuotaName"]
                    # print(f"Instance Type {instance_type}. Quota {quota_name}, Max CPUs {max_vcpus_allowed}")
    else:
        max_vcpus_allowed = quota_info[instance_type]["max_vcpus_allowed"]
        quota_name = quota_info[instance_type]["quota_name"]

    if max_vcpus_allowed is False:
        return {
            "message": f"Unable to find ServiceQuota for {instance_type}",
            "quota_info": quota_info,
        }

    # list all ec2 instances
    if "standard" in quota_name.lower():
        instances_family_allowed_in_quota = (
            re.search(
                r"running on-demand standard \((.*)\) instances", quota_name.lower()
            )
            .group(1)
            .split(",")
        )
    else:
        instances_family_allowed_in_quota = list(
            re.search(r"running on-demand (.*) instances", quota_name.lower()).group(1)
        )

    if not quota_info or instance_type not in quota_info.keys():
        all_instances_available = []
        paginator = ec2.get_paginator("describe_instance_types")
        for page in paginator.paginate():
            for instance in page["InstanceTypes"]:
                all_instances_available.append(instance["InstanceType"])

        all_instances_for_quota = [
            instance_family
            for x in instances_family_allowed_in_quota
            for instance_family in all_instances_available
            if instance_family.startswith(x.rstrip().lstrip())
        ]
        required_api_calls = ceil(len(all_instances_for_quota) / 190)
        for i in range(0, required_api_calls):
            # DescribeInstances has a limit of 200 attributes per filter
            instances_to_check = all_instances_for_quota[i * 190 : (i + 1) * 190]
            if instances_to_check:
                running_vcpus += find_running_cpus_per_instance(instances_to_check)

    else:
        running_vcpus = quota_info[instance_type]["vcpus_provisioned"]

    quota_info[instance_type] = {
        "max_vcpus_allowed": max_vcpus_allowed,
        "vcpus_provisioned": running_vcpus + total_vcpus_requested,
        "quota_name": quota_name,
    }

    if max_vcpus_allowed >= (running_vcpus + total_vcpus_requested):
        return {"message": True, "quota_info": quota_info}
    else:
        return {
            "message": f"Job cannot start due to AWS Service limit. Max Vcpus allowed {max_vcpus_allowed}. Detected running Vcpus {running_vcpus}. Requested Vcpus for this job {total_vcpus_requested}. Quota Name {quota_name}",
            "quota_info": quota_info,
        }


def can_launch_capacity(
    instance_type, desired_capacity, image_id, subnet_id, security_group, custom_tags
):
    # Allow skipping DryRun and Quotas - default to False if they are not set in the config
    skip_dryrun: bool = (
        SocaConfig(key="/configuration/FeatureFlags/Hpc/EnableDryRun")
        .get_value(return_as=bool, default=False)
        .get("message")
    )
    enforce_quota: bool = (
        SocaConfig(key="/configuration/FeatureFlags/Hpc/EnableQuotasCheck")
        .get_value(return_as=bool, default=True)
        .get("message")
    )

    _custom_tags = []
    if custom_tags:
        for tag in custom_tags.values():
            if tag.get("Enabled", ""):
                _custom_tags.append({"Key": tag["Key"], "Value": tag["Value"]})
            else:
                print(f"{tag} does not have Enabled key or Enabled is False.")

    if skip_dryrun and enforce_quota is False:
        # No need to even send the API calls if we have both knobs set to Skip
        return True

    for instance in instance_type:
        try:
            ec2.run_instances(
                ImageId=image_id,
                InstanceType=instance,
                SubnetId=subnet_id,
                SecurityGroupIds=[security_group],
                MaxCount=int(desired_capacity),
                MinCount=int(desired_capacity),
                MetadataOptions={
                    "HttpTokens": SocaConfig(key="/configuration/MetadataHttpTokens")
                    .get_value(default="required")
                    .get("message")
                },
                DryRun=True,
                TagSpecifications=(
                    [{"ResourceType": "instance", "Tags": _custom_tags}]
                    if _custom_tags
                    else []
                ),
            )

        except ClientError as e:
            if e.response["Error"].get("Code") == "DryRunOperation":
                # Dry Run Succeed.
                if not enforce_quota:
                    return True
                else:
                    try:
                        quota_info
                    except NameError:
                        quota_info = {}

                    vcpus_check = verify_vcpus_limit(
                        instance, desired_capacity, quota_info
                    )
                    quota_info = vcpus_check["quota_info"]
                    if vcpus_check["message"] is True:
                        return True
                    else:
                        return vcpus_check["message"]
            else:
                print(
                    "Dry Run Failed, capacity "
                    + instance
                    + " can not be added: "
                    + str(e),
                    "error",
                )
                return str(instance + " can not be added: " + str(e))


def check_config(**kwargs):
    try:
        error = []
        skip = False
        # Convert str to bool when possible
        for k, v in kwargs.items():
            if str(v).lower() in ["true", "yes", "y", "on"]:
                kwargs[k] = True
            if str(v).lower() in ["false", "no", "n", "off"]:
                kwargs[k] = False

        # Transform instance_type as list in case multiple type are specified
        kwargs["instance_type"] = kwargs["instance_type"].split("+")

        # Get Instance information
        try:
            instance_attributes = ec2.describe_instance_types(
                InstanceTypes=[kwargs["instance_type"][0]]
            )
            if len(instance_attributes["InstanceTypes"]) == 0:
                skip = True
                error.append("No instance returned from DescribeInstanceTypes")
        except ClientError as e:
            skip = True
            if e.response["Error"].get("Code") == "InvalidInstanceType":
                error.append(
                    "Instance type does not seem to be valid. Update boto3 to refresh the list if needed"
                )
            else:
                error.append(f"Unable to get instance information due to {e}")
        except Exception as e:
            skip = True
            error.append(f"Unable to run describe_instance_types API due to {e}")

        if not skip:
            # Transform weighted_capacity as a list in case multiple instance types are specified
            # Confirm that the length of weighted_capacity list is consistent with the length of instance_type list
            weighted_capacity = []
            if kwargs["weighted_capacity"] is not False:
                for item in kwargs["weighted_capacity"].split("+"):
                    try:
                        item = int(item)
                    except ValueError:
                        error.append(
                            f"All values specified for --weighted_capacity must be integers. Found {item}"
                        )
                    weighted_capacity.append(item)
                kwargs["weighted_capacity"] = weighted_capacity
                if len(kwargs["instance_type"]) != len(kwargs["weighted_capacity"]):
                    error.append(
                        "Number of --weighted_capacity entries is not consistent with --instance_type entries"
                    )

            # Validate terminate_when_idle
            if "terminate_when_idle" not in kwargs.keys():
                kwargs["terminate_when_idle"] = 0

            # Must convert true,True into bool() and false/False
            if (
                kwargs["job_id"] is None
                and kwargs["keep_forever"] is False
                and int(kwargs["terminate_when_idle"]) == 0
            ):
                error.append(
                    "--job_id, --keep_forever True, or --terminate_when_idle N>0 must be specified"
                )

            # Ensure jobId is not None when using keep_forever
            if kwargs["job_id"] is None and (
                kwargs["keep_forever"] is True or int(kwargs["terminate_when_idle"]) > 0
            ):
                kwargs["job_id"] = kwargs["stack_uuid"]

            # Ensure anonymous metric is either True or False.
            if kwargs["anonymous_metrics"] not in [True, False]:
                kwargs["anonymous_metrics"] = True

            # Ensure force_ri is either True or False.
            if kwargs["force_ri"] not in [True, False]:
                kwargs["force_ri"] = False

            if kwargs["force_ri"] is True and kwargs["spot_price"] is False:
                # Job can only run on Reserved Instance. We ignore if SpotFleet is enabled
                try:
                    instance_type_info
                except NameError:
                    instance_type_info = {}

                for instance_type in kwargs["instance_type"]:
                    check_ri = verify_ri_saving_availabilities(
                        instance_type, instance_type_info
                    )
                    if (
                        check_ri[instance_type]["current_instance_in_use"]
                        + int(kwargs["desired_capacity"])
                    ) > check_ri[instance_type]["current_ri_purchased"]:
                        error.append(
                            f"Not enough RI to cover for this job. Instance type: {instance_type}, number of running instances: {check_ri[instance_type]['current_instance_in_use']}, number of purchased RIs: {check_ri[instance_type]['current_ri_purchased']}, capacity requested: {kwargs['desired_capacity']}. Either purchase more RI or allow usage of On Demand"
                        )
                    else:
                        # Update the number of current_instance_in_use with the number of new instance that this job will launch
                        instance_type_info[instance_type] = {
                            "current_instance_in_use": check_ri[instance_type][
                                "current_instance_in_use"
                            ]
                            + int(kwargs["desired_capacity"])
                        }

            # Default System metrics to False unless explicitly set to True
            if kwargs["system_metrics"] is not True:
                kwargs["system_metrics"] = False

            if not isinstance(int(kwargs["desired_capacity"]), int):
                error.append("Desired Capacity must be an int")

            if "tags" not in kwargs.keys() or kwargs["tags"] is None:
                kwargs["tags"] = {}
            else:
                try:
                    kwargs["tags"] = ast.literal_eval(kwargs["tags"])
                    if not isinstance(kwargs["tags"], dict):
                        error.append("Tags must be a valid dictionary")
                except ValueError:
                    error.append("Tags must be a valid dictionary")

            # FSx Management
            kwargs["fsx_lustre_configuration"] = {
                "fsx_lustre": kwargs["fsx_lustre"],
                "s3_backend": False,
                "existing_fsx": False,
                "import_path": False,
                "export_path": False,
                "deployment_type": kwargs["fsx_lustre_deployment_type"],
                "per_unit_throughput": False,
                "capacity": 1200,
            }

            if kwargs["fsx_lustre"] is not False:
                fsx_deployment_type_allowed = [
                    "scratch_1",
                    "scratch_2",
                    "persistent_1",
                    "persistent_2",
                ]
                fsx_lustre_per_unit_throughput_allowed = {
                    "persistent_1": [50, 100, 200],
                    "persistent_2": [125, 250, 500, 1000],
                }

                # Default to SCRATCH_2 if incorrect value is specified
                if (
                    kwargs["fsx_lustre_deployment_type"].lower()
                    not in fsx_deployment_type_allowed
                ):
                    error.append(
                        f"FSx Deployment Type must be: {','.join(fsx_deployment_type_allowed)}"
                    )

                else:
                    kwargs["fsx_lustre_configuration"]["fsx_lustre_deployment_type"] = (
                        kwargs["fsx_lustre_deployment_type"].upper()
                    )

                # If deployment_type is PERSISTENT, configure Per unit throughput and default to 200mb/s
                if kwargs["fsx_lustre_configuration"][
                    "fsx_lustre_deployment_type"
                ].lower() in {
                    "persistent_1",
                    "persistent_2",
                }:
                    if not isinstance(
                        int(kwargs["fsx_lustre_per_unit_throughput"]), int
                    ):
                        error.append("FSx Per Unit Throughput must be an int")
                    else:
                        if (
                            kwargs["fsx_lustre_per_unit_throughput"]
                            not in fsx_lustre_per_unit_throughput_allowed[
                                kwargs["fsx_lustre_configuration"][
                                    "fsx_lustre_deployment_type"
                                ].lower()
                            ]
                        ):
                            error.append(
                                f"FSx Per Unit Throughput must one of: {fsx_lustre_per_unit_throughput_allowed[kwargs['fsx_lustre_configuration']['fsx_lustre_deployment_type'].lower()]}"
                            )
                        else:
                            kwargs["fsx_lustre_configuration"][
                                "per_unit_throughput"
                            ] = int(kwargs["fsx_lustre_per_unit_throughput"])

                if kwargs["fsx_lustre"] is not True:
                    # when fsx_lustre is set to True, only create a FSx without S3 backend
                    if kwargs["fsx_lustre"].startswith("fs-"):
                        kwargs["fsx_lustre_configuration"]["existing_fsx"] = kwargs[
                            "fsx_lustre"
                        ]
                    else:
                        if kwargs["fsx_lustre"].startswith("s3://"):
                            kwargs["fsx_lustre_configuration"]["s3_backend"] = kwargs[
                                "fsx_lustre"
                            ]
                        else:
                            kwargs["fsx_lustre_configuration"]["s3_backend"] = (
                                "s3://" + kwargs["fsx_lustre"]
                            )

                        # Verify if SOCA has permissions to access S3 backend
                        try:
                            s3.get_bucket_acl(
                                Bucket=kwargs["fsx_lustre"].split("s3://")[-1]
                            )
                        except exceptions.ClientError:
                            error.append(
                                f"SOCA does not have access to this bucket ({kwargs['fsx_lustre']}). Refer to the documentation to update IAM policy."
                            )

                        # Verify if user specified custom Import/Export path.
                        # Syntax is fsx_lustre=<bucket>+<export_path>+<import_path>
                        check_user_specified_path = kwargs["fsx_lustre"].split("+")
                        if check_user_specified_path.__len__() == 1:
                            pass
                        elif check_user_specified_path.__len__() == 2:
                            # import path default to bucket root if not specified
                            kwargs["fsx_lustre_configuration"]["export_path"] = (
                                check_user_specified_path[1]
                            )
                            kwargs["fsx_lustre_configuration"]["import_path"] = kwargs[
                                "fsx_lustre_configuration"
                            ]["s3_backend"]
                        elif check_user_specified_path.__len__() == 3:
                            # When customers specified both import and export path
                            kwargs["fsx_lustre_configuration"]["export_path"] = (
                                check_user_specified_path[1]
                            )
                            kwargs["fsx_lustre_configuration"]["import_path"] = (
                                check_user_specified_path[2]
                            )
                        else:
                            error.append(
                                f"Error setting up Import/Export path: {kwargs['fsx_lustre']}). Syntax is <bucket_name>+<export_path>+<import_path>. If import_path is not specified it defaults to bucket root level"
                            )

                if kwargs["fsx_lustre_size"] is not False:
                    fsx_lustre_capacity_allowed = [1200, 2400, 3600, 7200, 10800]
                    if (
                        int(kwargs["fsx_lustre_size"])
                        not in fsx_lustre_capacity_allowed
                    ):
                        error.append(
                            f"fsx_lustre_size must be: {','.join(str(x) for x in fsx_lustre_capacity_allowed)}"
                        )

                    else:
                        kwargs["fsx_lustre_configuration"]["capacity"] = kwargs[
                            "fsx_lustre_size"
                        ]

            SpotFleet = (
                True
                if (
                    kwargs["spot_price"] is not False
                    and kwargs["spot_allocation_count"] is False
                    and (
                        int(kwargs["desired_capacity"]) > 1
                        or kwargs["instance_type"].__len__() > 1
                    )
                )
                else False
            )

            if kwargs["subnet_id"] is False:
                if SpotFleet:
                    kwargs["subnet_id"] = (
                        SocaConfig(key="/configuration/PrivateSubnets")
                        .get_value(return_as=list)
                        .get("message")
                    )

                else:
                    kwargs["subnet_id"] = [
                        random.choice(
                            SocaConfig(key="/configuration/PrivateSubnets")
                            .get_value(return_as=list)
                            .get("message")
                        )
                    ]
            else:
                if isinstance(kwargs["subnet_id"], int):
                    if kwargs["subnet_id"] == 2:
                        kwargs["subnet_id"] = random.sample(
                            SocaConfig(key="/configuration/PrivateSubnets")
                            .get_value(return_as=list)
                            .get("message"),
                            2,
                        )
                    elif kwargs["subnet_id"] == 3:
                        kwargs["subnet_id"] = random.sample(
                            SocaConfig(key="/configuration/PrivateSubnets")
                            .get_value(return_as=list)
                            .get("message"),
                            3,
                        )
                    else:
                        error.append(
                            "Approved value for subnet_id are either the actual subnet ID or 2 or 3"
                        )
                else:
                    kwargs["subnet_id"] = kwargs["subnet_id"].split("+")
                    for subnet in kwargs["subnet_id"]:
                        if subnet not in SocaConfig(
                            key="/configuration/PrivateSubnets"
                        ).get_value(return_as=list).get("message"):
                            error.append(
                                f"Invalid subnet_id ({subnet}). Must be one of {','.join(SocaConfig(key='/configuration/PrivateSubnets').get_value(return_as=list).message)}"
                            )

            # Handle placement group logic
            if "placement_group" not in kwargs.keys():
                pg_user_defined = False
                # Default PG to True if not present
                kwargs["placement_group"] = True if SpotFleet is False else False
            else:
                pg_user_defined = True
                if kwargs["placement_group"] not in [True, False]:
                    kwargs["placement_group"] = False
                    error.append("Incorrect placement_group. Must be True or False")

            if int(kwargs["desired_capacity"]) > 1:
                if (
                    kwargs["subnet_id"].__len__() > 1
                    and pg_user_defined is True
                    and kwargs["placement_group"] is True
                    and SpotFleet is False
                ):
                    # more than 1 subnet specified but placement group is also configured, default to the first subnet and enable PG
                    kwargs["subnet_id"] = [kwargs["subnet_id"][0]]
                else:
                    if kwargs["subnet_id"].__len__() > 1 and pg_user_defined is False:
                        kwargs["placement_group"] = False
            else:
                if int(kwargs["desired_capacity"]) == 1:
                    kwargs["placement_group"] = False
                else:
                    # default to user specified value
                    pass

            if kwargs["subnet_id"].__len__() > 1:
                if kwargs["placement_group"] is True and SpotFleet is False:
                    # if placement group is True and more than 1 subnet is defined, force default to 1 subnet
                    kwargs["subnet_id"] = [kwargs["subnet_id"][0]]

            # Final validation that our instances support Placement groups
            if (
                is_placement_group_supported(
                    instance_type=kwargs["instance_type"],
                    placement_group_type="cluster",
                )
                is False
            ):
                # Placement group of cluster is not supported by this instance type
                kwargs["placement_group"] = False
                print(
                    f"WARNING - Placement group of cluster is not supported by {kwargs['instance_type']} - defaulting to no PG"
                )

            # Validate additional security group ids
            if kwargs["security_groups"]:
                sgs_id = kwargs["security_groups"].split("+")
                if sgs_id.__len__() > 4:
                    error.append(
                        "You can specify a maximum of 4 additional security groups"
                    )
                try:
                    ec2.describe_security_groups(GroupIds=sgs_id)["SecurityGroups"]
                    kwargs["security_groups"] = sgs_id
                except Exception as err:
                    error.append(
                        f"Unable to validate one SG from {sgs_id} due to {err}"
                    )

            # Validate custom IAM Instance Profile
            if kwargs["instance_profile"]:
                try:
                    kwargs["instance_profile"] = iam.get_instance_profile(
                        InstanceProfileName=kwargs["instance_profile"]
                    )["InstanceProfile"]["Arn"]
                except Exception as err:
                    error.append(
                        f"Unable to validate custom IAM instance profile {kwargs['instance_profile']} due to {err}"
                    )

            # Check core_count and ht_support
            # boto3 does not return Default Cores/ThreadsPerCore T2 instances does not have DefaultCores
            if kwargs["instance_type"][0] in ["t2.micro", "t2.nano", "t2.small"]:
                kwargs["ht_support"] = False
            elif kwargs["instance_type"][0] in [
                "t2.medium",
                "t2.large",
                "t2.xlarge",
                "t2.2xlarge",
            ]:
                # do not set ht_support. Will default to None if not explicitly set by the user
                pass
            else:
                kwargs["core_count"] = instance_attributes["InstanceTypes"][0][
                    "VCpuInfo"
                ]["DefaultCores"]
                if (
                    instance_attributes["InstanceTypes"][0]["VCpuInfo"][
                        "DefaultThreadsPerCore"
                    ]
                    == 1
                ):
                    # Set ht_support to False for instances with DefaultThreadsPerCore = 1 (e.g. Graviton)
                    kwargs["ht_support"] = False

                # Keep instance_attributes from the API response for later use
                kwargs["instance_attributes"] = instance_attributes["InstanceTypes"][0]

            # Validate Spot Allocation Strategy
            mapping = {
                "lowest-price": {
                    "ASG": "lowest-price",
                    "SpotFleet": "lowestPrice",
                    "accepted_values": ["lowest-price", "lowestprice"],
                },
                "diversified": {
                    "ASG": "capacity-optimized",
                    "SpotFleet": "diversified",
                    "accepted_values": ["diversified"],
                },
                "capacity-optimized": {
                    "ASG": "capacity-optimized",
                    "SpotFleet": "capacityOptimized",
                    "accepted_values": [
                        "capacityoptimized",
                        "capacity-optimized",
                        "optimized",
                    ],
                },
            }

            if kwargs["spot_allocation_strategy"] is not False:
                for k, v in mapping.items():
                    if (
                        kwargs["spot_allocation_strategy"].lower()
                        in v["accepted_values"]
                    ):
                        if SpotFleet:
                            kwargs["spot_allocation_strategy"] = v["SpotFleet"]
                            break
                        else:
                            kwargs["spot_allocation_strategy"] = v["ASG"]
                            break
                spot_allocation_strategy_allowed = [
                    "lowestPrice",
                    "lowest-price",
                    "diversified",
                    "capacityOptimized",
                    "capacity-optimized",
                ]
                if (
                    kwargs["spot_allocation_strategy"]
                    not in spot_allocation_strategy_allowed
                ):
                    error.append(
                        f"spot_allocation_strategy_allowed ({kwargs['spot_allocation_strategy']}) must be one of the following value: {', '.join(spot_allocation_strategy_allowed)}"
                    )
            else:
                kwargs["spot_allocation_strategy"] = (
                    "capacityOptimized" if SpotFleet is True else "capacity-optimized"
                )

            # Validate Spot Allocation Percentage
            if kwargs["spot_allocation_count"] is not False:
                if isinstance(kwargs["spot_allocation_count"], int):
                    if (
                        int(kwargs["spot_allocation_count"])
                        > kwargs["desired_capacity"]
                    ):
                        error.append(
                            f"spot_allocation_count ({kwargs['spot_allocation_count']}) must be an lower or equal to the number of nodes provisioned for this simulation ({(kwargs['desired_capacity'])})"
                        )
                else:
                    error.append(
                        f"spot_allocation_count ({kwargs['spot_allocation_count']})) must be an integer"
                    )

            # Validate ht_support
            if kwargs["ht_support"] is None:
                kwargs["ht_support"] = False
            else:
                if kwargs["ht_support"] not in [True, False]:
                    error.append(
                        f"ht_support ({kwargs['ht_support']}) must be either True or False"
                    )

            # Validate Base OS
            if kwargs["base_os"] is not False:
                base_os_allowed = [
                    "rhel7",
                    "rhel8",
                    "rhel9",
                    "centos7",
                    "centos8",
                    "rocky8",
                    "rocky9",
                    "amazonlinux2",
                    "amazonlinux2023",
                    "ubuntu2204",
                    "ubuntu2404",
                ]
                if kwargs["base_os"] not in base_os_allowed:
                    error.append(
                        f"base_os ({kwargs['base_os']}) must be one of the following value: {','.join(base_os_allowed)}"
                    )
            else:
                kwargs["base_os"] = (
                    SocaConfig(key="/configuration/BaseOS").get_value().get("message")
                )

            # Validate Spot Price
            if kwargs["spot_price"] is not False:
                if kwargs["spot_price"] == "auto" or isinstance(
                    kwargs["spot_price"], float
                ):
                    pass
                else:
                    error.append('spot_price must be either "auto" or a float value"')

            # Validate EFA
            if kwargs["efa_support"] not in [True, False]:
                kwargs["efa_support"] = False

            if kwargs["efa_support"] is True:
                # TODO - This won't really work with multiple instance types since
                # our instance_attributes is for a single instance type.
                for instance_type in kwargs["instance_type"]:
                    _is_efa_supported: bool = (
                        kwargs.get("instance_attributes", {})
                        .get("NetworkInfo", {})
                        .get("EfaSupported", False)
                    )
                    _max_efa_interfaces: int = (
                        kwargs.get("instance_attributes", {})
                        .get("NetworkInfo", {})
                        .get("EfaInfo", {})
                        .get("MaximumEfaInterfaces", 0)
                    )

                    if _is_efa_supported is False or _max_efa_interfaces <= 0:
                        error.append(
                            f"You have requested EFA support but instance {instance_type} does not support EFA ({_is_efa_supported}/{_max_efa_interfaces} interfaces)"
                        )
                    # Make sure we store our max EFA interfaces for future use
                    kwargs["max_efa_interfaces"] = _max_efa_interfaces

            # Validate Keep EBS
            if kwargs["keep_ebs"] not in [True, False]:
                kwargs["keep_ebs"] = False

            _instance_architecture = (
                kwargs.get("instance_attributes", {})
                .get("ProcessorInfo", {})
                .get("SupportedArchitectures", [])[-1]
            )

            # Validate there is an AMI selected, if not - use the default
            if kwargs.get("instance_ami", None) is None:
                # TODO - Validate the selected AMI and the selected instance_type have matching architectures
                _custom_ami_map = (
                    SocaConfig(key="/configuration/CustomAMIMap")
                    .get_value(return_as=dict, default={})
                    .get("message")
                )
                kwargs["instance_ami"] = _custom_ami_map.get(
                    _instance_architecture
                ).get(kwargs["base_os"])
                if kwargs.get("instance_ami", None) is None:
                    error.append(
                        f"Unable to find AMI for {kwargs['base_os']} in this region"
                    )

            else:
                # todo, change to API call
                _regex_ami = r"^ami-[a-fA-F0-9]{8,17}$"
                if not re.match(_regex_ami, kwargs["instance_ami"]):
                    error.append(
                        f"This AMI {kwargs['instance_ami']} does not seems to be valid"
                    )

        if error:
            return return_message(
                message=f"ERROR={',ERROR='.join(error)}", success=False
            )
        else:
            return kwargs

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return f"Unable to validate config due to {e}, {exc_type}, {fname}, {exc_tb.tb_lineno}"


def return_message(message, success=False):
    return {"success": success, "message": message}


def main(**kwargs):
    try:
        # Create default value for optional parameters if needed
        optional_job_parameters = {
            "anonymous_metrics": SocaConfig(
                key="/configuration/DefaultMetricCollection"
            )
            .get_value(return_as=bool)
            .message,
            "force_ri": False,
            "base_os": False,
            "efa_support": False,
            "fsx_lustre": False,
            "fsx_lustre_size": False,
            "fsx_lustre_deployment_type": "SCRATCH_2",
            "fsx_lustre_per_unit_throughput": 200,
            "ht_support": False,
            "keep_ebs": False,
            "root_size": 10,
            "volume_type": SocaConfig(key="/configuration/DefaultVolumeType")
            .get_value(default="gp2")
            .get("message"),
            "scratch_size": 0,
            "security_groups": False,
            "instance_profile": False,
            "spot_allocation_count": False,
            "spot_allocation_strategy": "capacity-optimized",
            "spot_price": False,
            "subnet_id": False,
            "system_metrics": False,
            "scratch_iops": 0,
            "stack_uuid": str(uuid.uuid4()),
            "weighted_capacity": False,
        }

        for k, v in optional_job_parameters.items():
            if k not in kwargs.keys():
                kwargs[k] = v

        # Validate Job parameters
        try:
            params = check_config(**kwargs)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return return_message(
                f"Unable to verify parameters {e}, {exc_type}, {fname}, {exc_tb.tb_lineno}, {kwargs}"
            )

        # If error is detected, return error message
        if "message" in params.keys():
            return params

        # Force Tag if they don't exist. DO NOT DELETE them or host won't be able to be registered by nodes_manager.py
        tags = params["tags"]

        if params["keep_forever"] is True:
            cfn_stack_name = (
                SocaConfig(key="/configuration/ClusterId").get_value().get("message")
                + f"-keepforever-{params['queue']}-{params['stack_uuid']}"
            )
            tags["edh:KeepForever"] = "true"
        else:
            cfn_stack_name = (
                SocaConfig(key="/configuration/ClusterId").get_value().get("message")
                + "-job-"
                + str(params["job_id"])
            )
            tags["edh:KeepForever"] = "false"

        if int(params["terminate_when_idle"]) > 0:
            tags["edh:TerminateWhenIdle"] = params["terminate_when_idle"]

        if "edh:NodeType" not in tags.keys():
            tags["edh:NodeType"] = "compute_node"

        if "edh:ClusterId" not in tags.keys():
            tags["edh:ClusterId"] = (
                SocaConfig(key="/configuration/ClusterId").get_value().get("message")
            )

        if "edh:JobId" not in tags.keys():
            tags["edh:JobId"] = params["job_id"]

        if "Name" not in tags.keys():
            tags["Name"] = cfn_stack_name.replace("_", "-")

        # These parameters will be used to build the cloudformation template
        parameters_list = {
            "DIRECTORY_IDENTITY_PROVIDER": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/UserDirectory/provider")
                .get_value()
                .message,
            },
            "BaseOS": {
                "Key": "base_os",
                "Default": params.get(
                    "base_os",
                    SocaConfig(key="/configuration/BaseOS").get_value().get("message"),
                ),
            },
            "ClusterId": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/ClusterId")
                .get_value()
                .message,
            },
            "MetadataHttpTokens": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/MetadataHttpTokens")
                .get_value()
                .message,
            },
            "ComputeNodeInstanceProfileArn": {
                "Key": None,
                "Default": SocaConfig(
                    key="/configuration/ComputeNodeInstanceProfileArn"
                )
                .get_value()
                .message,
            },
            "CoreCount": {
                "Key": "core_count",
                "Default": None,
            },
            "DesiredCapacity": {
                "Key": "desired_capacity",
                "Default": None,
            },
            "Efa": {
                "Key": "efa_support",
                "Default": False,
            },
            "MaxEfaInterfaces": {
                "Key": "max_efa_interfaces",
                "Default": params.get("max_efa_interfaces", 0),
            },
            "FSxLustreConfiguration": {
                "Key": "fsx_lustre_configuration",
                "Default": False,
            },
            "ImageId": {
                "Key": "instance_ami",
                "Default": params.get(
                    "instance_ami",
                    SocaConfig(key="/configuration/CustomAMI")
                    .get_value()
                    .get("message"),
                ),
            },
            "CustomIamInstanceProfile": {"Key": "instance_profile", "Default": False},
            "InstanceType": {"Key": "instance_type", "Default": None},
            "JobId": {"Key": "job_id", "Default": None},
            "JobName": {"Key": "job_name", "Default": None},
            "JobOwner": {"Key": "job_owner", "Default": None},
            "JobProject": {"Key": "job_project", "Default": None},
            "JobQueue": {"Key": "queue", "Default": None},
            "KeepEbs": {"Key": "keep_ebs", "Default": False},
            "KeepForever": {"Key": "keep_forever", "Default": False},
            "MetricCollectionAnonymous": {
                "Key": "anonymous_metrics",
                "Default": SocaConfig(key="/configuration/DefaultMetricCollection")
                .get_value(return_as=bool)
                .message,
            },
            "PlacementGroup": {"Key": "placement_group", "Default": True},
            "RootSize": {"Key": "root_size", "Default": 10},
            "VolumeType": {
                "Key": "volume_type",
                "Default": SocaConfig(key="/configuration/DefaultVolumeType")
                .get_value(default="gp2")
                .get("message"),
            },
            "S3Bucket": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/S3Bucket")
                .get_value()
                .get("message"),
            },
            "S3InstallFolder": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/S3InstallFolder")
                .get_value()
                .get("message"),
            },
            "ControllerPrivateDnsName": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/ControllerPrivateDnsName")
                .get_value()
                .get("message"),
            },
            "ScratchSize": {"Key": "scratch_size", "Default": 0},
            "AdditionalSecurityGroupIds": {"Key": "security_groups", "Default": None},
            "SecurityGroupId": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/ComputeNodeSecurityGroup")
                .get_value()
                .get("message"),
            },
            "ControllerHostname": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/ControllerPrivateDnsName")
                .get_value()
                .get("message"),
            },
            "SolutionMetricsLambda": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/SolutionMetricsLambda")
                .get_value()
                .get("message"),
            },
            "SpotAllocationCount": {"Key": "spot_allocation_count", "Default": False},
            "SpotAllocationStrategy": {
                "Key": "spot_allocation_strategy",
                "Default": "capacity-optimized",
            },
            "SpotFleetIAMRoleArn": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/SpotFleetIAMRoleArn")
                .get_value()
                .get("message"),
            },
            "SpotPrice": {"Key": "spot_price", "Default": False},
            "SSHKeyPair": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/SSHKeyPair")
                .get_value()
                .get("message"),
            },
            "StackUUID": {"Key": None, "Default": params["stack_uuid"]},
            "SubnetId": {"Key": "subnet_id", "Default": None},
            "SystemMetrics": {"Key": "system_metrics", "Default": False},
            "TerminateWhenIdle": {"Key": "terminate_when_idle", "Default": 0},
            "ThreadsPerCore": {"Key": "ht_support", "Default": False},
            "Version": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/Version")
                .get_value()
                .get("message"),
            },
            "Region": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/Region")
                .get_value()
                .get("message"),
            },
            "Misc": {
                "Key": None,
                "Default": SocaConfig(key="/configuration/Misc")
                .get_value(default="false")
                .get("message"),
            },
            "VolumeTypeIops": {"Key": "scratch_iops", "Default": 0},
            "WeightedCapacity": {"Key": "weighted_capacity", "Default": False},
            "CustomTags": {"Key": None, "Default": {}},
        }
        cfn_stack_parameters = {}
        for k, v in parameters_list.items():
            if v["Key"] is not None:
                if v["Key"] not in params.keys():
                    cfn_stack_parameters[k] = v["Default"]
                else:
                    cfn_stack_parameters[k] = params[v["Key"]]
            else:
                if v["Default"] is None:
                    error = return_message(f"Unable to detect value for {k}")
                    return error
                else:
                    cfn_stack_parameters[k] = v["Default"]

        # Custom tags are read by cloudformation_builder via get_cluster_custom_tags().

        cfn_stack_body = cloudformation_builder.main(**cfn_stack_parameters)
        if cfn_stack_body["success"] is False:
            return return_message(cfn_stack_body["output"])
        cfn_stack_tags = [
            {"Key": str(k), "Value": str(v)} for k, v in tags.items() if v
        ]

        # Dry Run (note: licenses checks is handled by dispatcher.py. This dry run only check for AWS related commands)
        can_launch = can_launch_capacity(
            cfn_stack_parameters["InstanceType"],
            cfn_stack_parameters["DesiredCapacity"],
            cfn_stack_parameters["ImageId"],
            cfn_stack_parameters["SubnetId"][0],
            cfn_stack_parameters["SecurityGroupId"],
            cfn_stack_parameters["CustomTags"],
        )

        if cfn_stack_parameters.get("SpotPrice") is None:
            # Submit ODCR
            _request_capacity_reservation = odcr_helper.create_capacity_reservation(
                instance_type=cfn_stack_parameters["InstanceType"],
                instance_count=cfn_stack_parameters["DesiredCapacity"],
                instance_ami=cfn_stack_parameters["ImageId"],
                instance_subnet=cfn_stack_parameters["SubnetId"],
                instance_security_group=cfn_stack_parameters["SecurityGroupId"],
            )
            print(f"Request Capacity Reservation: {_request_capacity_reservation}")
            if _request_capacity_reservation.get("success"):
                # Add the reservation ID tag to Stack
                cfn_stack_tags.append(
                    {
                        "Key": "capacity-reservation-id",
                        "Value": _request_capacity_reservation.get("message"),
                    }
                )
            else:
                can_launch = False

        if can_launch is True:
            try:
                cloudformation.create_stack(
                    StackName=cfn_stack_name,
                    TemplateBody=cfn_stack_body["output"],
                    Tags=cfn_stack_tags,
                )

                return {
                    "success": True,
                    "stack_name": cfn_stack_name,
                    "compute_node": "job" + str(params["job_id"]),
                }

            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return return_message(
                    str(e)
                    + ": error:"
                    + str(exc_type)
                    + " "
                    + str(fname)
                    + " "
                    + str(exc_tb.tb_lineno)
                    + " "
                    + str(kwargs)
                )

        else:
            return return_message("Dry Run failed: " + str(can_launch))

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return return_message(
            str(e)
            + ": error:"
            + str(exc_type)
            + " "
            + str(fname)
            + " "
            + str(exc_tb.tb_lineno)
            + " "
            + str(kwargs)
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Required
    parser.add_argument(
        "--desired_capacity",
        nargs="?",
        required=True,
        help="Number of EC2 instances to deploy",
    )
    parser.add_argument(
        "--instance_type",
        nargs="?",
        required=True,
        help="Instance type you want to deploy",
    )
    parser.add_argument(
        "--job_name",
        nargs="?",
        required=True,
        help="Job Name for which the capacity is being provisioned",
    )
    parser.add_argument(
        "--job_owner",
        nargs="?",
        required=True,
        help="Job Owner for which the capacity is being provisioned",
    )
    parser.add_argument(
        "--queue", nargs="?", required=True, help="Queue to map the capacity"
    )

    # Const
    parser.add_argument("--efa_support", default=False, help="Support for EFA")
    parser.add_argument("--ht_support", default=False, help="Enable Hyper Threading")
    parser.add_argument(
        "--keep_forever",
        default=False,
        help="Whether or not capacity will stay forever",
    )

    # Optional
    parser.add_argument(
        "--force_ri",
        default=False,
        help="If True, job can only run if we have reserved instance available",
    )
    parser.add_argument("--base_os", default=False, help="Specify custom Base OS")
    parser.add_argument(
        "--terminate_when_idle",
        default=0,
        nargs="?",
        help="If instances will be terminated when idle for N minutes",
    )
    parser.add_argument(
        "--fsx_lustre", default=False, help="Mount existing FSx by providing the DNS"
    )
    parser.add_argument(
        "--fsx_lustre_size", default=False, help="Specify size of your FSx"
    )
    parser.add_argument(
        "--fsx_lustre_per_unit_throughput",
        default=200,
        help="Storage baseline if FSX type is Persistent",
    )
    parser.add_argument(
        "--fsx_lustre_deployment_type",
        default="SCRATCH_2",
        help="Type of your FSx for Lustre",
    )
    parser.add_argument("--instance_ami", required=False, nargs="?", help="AMI to use")
    parser.add_argument(
        "--job_id", nargs="?", help="Job ID for which the capacity is being provisioned"
    )
    parser.add_argument(
        "--job_project",
        nargs="?",
        default=False,
        help="Job Owner for which the capacity is being provisioned",
    )
    parser.add_argument(
        "--placement_group", default=True, help="Enable or disable placement group"
    )
    parser.add_argument(
        "--root_size", default=10, nargs="?", help="Size of Root partition in GB"
    )
    parser.add_argument(
        "--volume_type", default="gp3", nargs="?", help="Root Volume Type"
    )
    parser.add_argument(
        "--scratch_iops", default=0, nargs="?", help="IOPS for /scratch"
    )
    parser.add_argument(
        "--scratch_size", default=0, nargs="?", help="Size of /scratch in GB"
    )
    parser.add_argument(
        "--spot_allocation_count",
        default=False,
        nargs="?",
        help="When using mixed OD and SPOT, choose %% of SPOT",
    )
    parser.add_argument(
        "--spot_allocation_strategy",
        default=False,
        nargs="?",
        help="lowest-price or capacity-optimized or diversified (supported only for SpotFleet)",
    )
    parser.add_argument("--spot_price", nargs="?", default=False, help="Spot Price")
    parser.add_argument(
        "--keep_ebs",
        action="store_const",
        const=True,
        default=False,
        help="Do not delete EBS disk",
    )
    parser.add_argument(
        "--subnet_id", default=False, help="Launch capacity in a special subnet"
    )
    parser.add_argument(
        "--security_groups",
        default=False,
        help="Configure additional security groups for your compute nodes",
    )
    parser.add_argument(
        "--instance_profile",
        default=False,
        help="Assign a different IAM role to the compute nodes",
    )

    parser.add_argument(
        "--tags", nargs="?", help="Tags, format must be {'Key':'Value'}"
    )
    parser.add_argument(
        "--weighted_capacity",
        default=False,
        nargs="?",
        help="Weighted capacity for EC2 instances",
    )

    arg = parser.parse_args()
    launch = main(**dict(arg._get_kwargs()))
    if launch["success"] is True:
        if arg.keep_forever.lower() == "true":
            print(
                """
            IMPORTANT:
            You specified --keep_forever flag. This instance will be running 24/7 until you MANUALLY terminate the Cloudformation Stack
            """
            )
    else:
        print("Error: " + str(launch))
