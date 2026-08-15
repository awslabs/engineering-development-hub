#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

import shutil
import os
from aws_cdk import (
    Tags,
    aws_ec2 as ec2,
    aws_iam as iam,
    CfnTag,
    Annotations,
)

import sys
from types import SimpleNamespace

from helpers import (
    secretsmanager as secretsmanager_helper,
    storage as storage_helper,
    user_data as user_data_helper,
)
import pathlib
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# SOCA controller instance + bootstrap

logger = logging.getLogger("soca_logger")


def controller(
    scope,
    *,
    endpoints_suffix=None,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    flatten_parameterstore_config=None,
    return_ebs_volume_type=None,
    get_supported_azs_list_by_instance_type=None,
):
    """
    Create the Controller EC2 instance, configure user data and assign EIP
    """

    logger.debug(f"DEBUG: UserSpecVars: {user_specified_variables}")

    # Make sure our filesystems are fully qualified
    _fs_apps_provider: str = user_specified_variables.fs_apps_provider
    if user_specified_variables.fs_apps_provider:
        _fs_apps_dns: str = f"{user_specified_variables.fs_apps}"
    else:
        _fs_apps_dns: str = storage_helper.get_filesystem_dns(
            storage_construct=scope.soca_resources["fs_apps"],
            storage_provider=_fs_apps_provider,
            endpoints_suffix=endpoints_suffix,
            fsx_ontap_junction_path=(
                None
                if _fs_apps_provider != "fsx_ontap"
                else get_config_key(
                    key_name="Config.storage.apps.fsx_ontap.junction_path",
                    expected_type=str,
                )
            ),
        )
    _fs_data_provider: str = user_specified_variables.fs_data_provider
    if user_specified_variables.fs_data_provider:
        _fs_data_dns: str = f"{user_specified_variables.fs_data}"
    else:
        _fs_data_dns: str = storage_helper.get_filesystem_dns(
            storage_construct=scope.soca_resources["fs_data"],
            storage_provider=_fs_data_provider,
            endpoints_suffix=endpoints_suffix,
            fsx_ontap_junction_path=(
                None
                if _fs_data_provider != "fsx_ontap"
                else get_config_key(
                    key_name="Config.storage.data.fsx_ontap.junction_path",
                    expected_type=str,
                )
            ),
        )

    # We manually replace  the variable with the relevant ParameterStore as all ParamStore hierarchy is created at the very end of this CDK
    _user_data_variables = {
        "/configuration/BaseOS": user_specified_variables.base_os,  # legacy
        "/configuration/ClusterId": user_specified_variables.cluster_id,
        "/configuration/UserDirectory/provider": get_config_key(
            key_name="Config.directoryservice.provider"
        ),
        "/configuration/Region": user_specified_variables.region,
        "/configuration/Version": "26.4.0",
        "/configuration/CustomAMI": scope.soca_resources["ami_id"],
        "/configuration/S3Bucket": user_specified_variables.bucket,
        "/configuration/Cache/enabled": scope.cache_info.get("enabled"),
        "/configuration/Cache/port": scope.cache_info.get("port"),
        "/configuration/Cache/endpoint": scope.cache_info.get("endpoint"),
        "/job/NodeType": "controller",
        "/job/BaseOS": user_specified_variables.base_os,
    }

    # add all System hierarchy
    _parameter_store_keys = flatten_parameterstore_config(
        get_config_key(key_name="Parameters", expected_type=dict),
    )
    for _ssm_parameter_key, _ssm_parameter_value in _parameter_store_keys.items():
        _user_data_variables[f"/{_ssm_parameter_key}"] = _ssm_parameter_value

    # Generate EC2 User Data and clean all copyright header to save some space.
    # Controller LT user_data is the only path bound by the EC2 16KB cap, so
    # we use remove_text_aggressive here (also strips indented function-body
    # comments). The S3-bound _templates_to_render loop below stays on
    # remove_text -- those files have no size cap.
    _user_data = user_data_helper.remove_text_aggressive(
        text_to_remove=[
            "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
            "# SPDX-License-Identifier: Apache-2.0",
        ],
        data=scope.jinja2_env.get_template(
            "user_data/controller/01_user_data.sh.j2"
        ).render(
            context=_user_data_variables,
            ns=SimpleNamespace(template_already_included=[]),
        ),
    )

    os.makedirs(
        f"{pathlib.Path.cwd().parent}/upload_to_s3/{user_specified_variables.cluster_id}/{user_specified_variables.region}/bootstrap/controller/",
        exist_ok=True,
    )

    # Because of size limitation, scripts needed during bootstrap are stored on s3
    _templates_to_render = [
        "user_data/controller/02_prerequisites",
        "templates/linux/system_packages/install_required_packages",
        "templates/linux/filesystems_automount",
    ]

    for template in _templates_to_render:

        _t = user_data_helper.remove_text(
            text_to_remove=[
                "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                "# SPDX-License-Identifier: Apache-2.0",
            ],
            data=scope.jinja2_env.get_template(f"{template}.sh.j2").render(
                context=_user_data_variables,
                ns=SimpleNamespace(template_already_included=[]),
            ),
        )
        with open(
            f"{pathlib.Path.cwd().parent}/upload_to_s3/{user_specified_variables.cluster_id}/{user_specified_variables.region}/bootstrap/controller/{template.split('/')[-1]}.sh",
            "w",
        ) as f:
            f.write(_t)

    shutil.copy(
        f"{pathlib.Path.cwd().parent}/user_data/controller/03_setup.sh.j2",
        f"{pathlib.Path.cwd().parent}/upload_to_s3/{user_specified_variables.cluster_id}/{user_specified_variables.region}/bootstrap/controller",
    )

    # Choose subnet where to deploy the controller
    # Grab the list of AZs that are supported by our desired instance_type
    _azs_for_instance_type: list = get_supported_azs_list_by_instance_type(
        region=scope._region,
        instance_type=scope._instance_type,
    )

    _potential_subnets: list = []

    if not user_specified_variables.vpc_id:

        # We know where our instance_type is supported (_azs_for_instance_type)- now we can determine the subnet
        logger.debug(
            f"Controller Priv subnets (new) (potential): {scope.soca_resources['vpc'].private_subnets}"
        )

        for _sn in scope.soca_resources["vpc"].private_subnets:
            # Probably a TODO / FIXME
            if "dummy" in _sn.availability_zone:
                # New can have AZ of 'dummy1a', 'dummy1b'
                # update it with our region name
                _sn_az: str = (
                    f"{scope._region}{_sn.availability_zone.replace('dummy1', '')}"
                )
            else:
                _sn_az: str = _sn.availability_zone

            if _sn_az not in _azs_for_instance_type:
                logger.debug(
                    f"Subnet: {_sn=} / AZ: {_sn.availability_zone} {_sn_az} / ID: {_sn.subnet_id} - NO MATCH For AZ availability: {_azs_for_instance_type}"
                )
                continue
            else:
                # First Match wins or ?
                logger.debug(
                    f"Subnet: {_sn=} / AZ: {_sn.availability_zone} {_sn_az} / ID: {_sn.subnet_id} - MATCH For AZ availability: {_azs_for_instance_type}"
                )
                _potential_subnets.append(_sn)
                break

        # Did we find any matching AZs for our desired instance type?
        if not _potential_subnets:
            logger.error(
                f"Unable to find an available AZ for Instance Type: {scope._instance_type}"
            )
            sys.exit(1)
        vpc_subnets = ec2.SubnetSelection(subnets=_potential_subnets)

        launch_subnet_id: str = _potential_subnets[0].subnet_id

    else:
        # Existing VPC was used
        # format is subnet-123,us-east-1a
        # but we still need to make sure this meets our instance requirements
        # Some of this is a bit redundant from the above code - but the format is different
        #

        logger.debug(
            f"Starting existing VPC/subnet instance_type probe for the following subnet entries: {user_specified_variables.private_subnets}"
        )
        for _existing_entry in user_specified_variables.private_subnets:
            logger.debug(f"Processing {_existing_entry=}")
            # format is subnet-123,us-east-1a
            _sn_info: list = _existing_entry.split(",")

            if not _sn_info or len(_sn_info) < 2 or len(_sn_info) > 2:
                logger.error(
                    f"Unable to decode existing subnet information from: {_existing_entry}. Aborting."
                )
                sys.exit(1)
            _sn = _sn_info[0]
            _sn_az = _sn_info[1]

            logger.debug(
                f"Existing subnet entry: {_existing_entry=} => SubnetID: {_sn=} / AZ: {_sn_az=}"
            )

            if _sn_az not in _azs_for_instance_type:
                logger.debug(
                    f"Subnet: {_sn=} / AZ: {_sn_az} - NO MATCH For AZ availability: {_azs_for_instance_type}"
                )
                continue
            else:
                logger.debug(
                    f"Subnet: {_sn=} / AZ: {_sn_az} - MATCH For AZ availability: {_azs_for_instance_type}"
                )
                # Note the tuple format in the list for existing resources mode
                _potential_subnets.append((_sn, _sn_az))
                break

        # Did we find any matching AZs for our desired instance type?
        if not _potential_subnets:
            logger.error(
                f"Unable to find an available AZ for Instance Type: {scope._instance_type}"
            )
            sys.exit(1)
        logger.debug(
            f"Potential Subnets for existing VPC/subnets: {_potential_subnets}"
        )

        launch_subnet = ec2.Subnet.from_subnet_attributes(
            scope,
            "ControllerSubnet",
            availability_zone=_potential_subnets[0][1],
            subnet_id=_potential_subnets[0][0],
        )
        launch_subnet_id: str = _potential_subnets[0][0]

        Annotations.of(launch_subnet).acknowledge_warning(
            id="@aws-cdk/aws-ec2:noSubnetRouteTableId",
            message="RouteTableId will not be processed",
        )

        vpc_subnets = ec2.SubnetSelection(subnets=[launch_subnet])

    logger.debug(
        f"Final Controller Subnet selected: {vpc_subnets=} / AZ: {vpc_subnets.availability_zones}"
    )

    # Create the Controller Instance

    _volume_type_str: str = get_config_key(
        key_name="Config.controller.volume_type",
        required=False,
        default="gp3",
        expected_type=str,
    ).lower()

    _volume_type = return_ebs_volume_type(volume_string=_volume_type_str)

    _ebs_volume_key_id: str = get_kms_key_id(
        config_key_names=[
            "Config.controller.volume_kms_key_id",  # Current key name
            "Config.controller.kms_key_id",  # Alternative
            "Config.scheduler.volume_kms_key_id",  # legacy key name
            "Config.scheduler.kms_key_id",  # Alternative
        ],
        allow_global_default=True,
    )
    logger.debug(f"Controller EBS encryption: KeyID: {_ebs_volume_key_id}")

    _volume_iops = get_config_key(
        key_name="Config.controller.volume_iops",
        required=False,
        default=0,
        expected_type=int,
    )

    _volume_throughput = get_config_key(
        key_name="Config.controller.volume_throughput",
        required=False,
        default=0,
        expected_type=int,
    )

    # Fixup some configs for specific volume types
    logger.debug(f"Performing EBS fixups for volume_type - {_volume_type}")

    match _volume_type_str:
        case "gp3":
            logger.debug("Performing EBS fixups for gp3")
            if not _volume_iops:
                _volume_iops = 3000
            if not _volume_throughput:
                _volume_throughput = 125
        case "io1":
            logger.debug("Performing EBS fixups for io1")
            if _volume_throughput:
                _volume_throughput = None

    logger.debug(f"Controller EBS volume IOPS: {_volume_iops}")
    logger.debug(f"Controller EBS volume throughput: {_volume_throughput}")

    logger.debug(
        f"Using Controller instance IAM role: {scope.soca_resources['controller_role'].role_arn}"
    )

    _iam_instance_profile = iam.CfnInstanceProfile(
        scope,
        "ControllerInstanceProfile",
        roles=[scope.soca_resources["controller_role"].role_name],
    )

    #
    logger.debug(f"Security group: {scope.soca_resources['controller_sg']}")
    logger.debug(
        f"Security group Str: {scope.soca_resources['controller_sg'].to_string()}"
    )
    logger.debug(
        f"Security group Id: {scope.soca_resources['controller_sg'].security_group_id}"
    )
    logger.debug(
        f"Security group VPC: {scope.soca_resources['controller_sg'].security_group_vpc_id}"
    )

    _network_interfaces = ec2.CfnLaunchTemplate.NetworkInterfaceProperty(
        associate_public_ip_address=False,
        description="",
        device_index=0,
        groups=[scope.soca_resources["controller_sg"].security_group_id],
        subnet_id=launch_subnet_id,
    )

    # LTD == LaunchTemplateData
    _ltd = ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
        instance_type=scope._instance_type,
        iam_instance_profile=ec2.CfnLaunchTemplate.IamInstanceProfileProperty(
            arn=_iam_instance_profile.attr_arn,
        ),
        key_name=user_specified_variables.ssh_keypair,
        image_id=scope.soca_resources["ami_id"],
        block_device_mappings=[
            ec2.CfnLaunchTemplate.BlockDeviceMappingProperty(
                device_name=scope.return_ebs_volume_name(
                    base_os=user_specified_variables.base_os
                ),
                ebs=ec2.CfnLaunchTemplate.EbsProperty(
                    volume_type=_volume_type_str,
                    volume_size=get_config_key(
                        key_name="Config.controller.volume_size",
                        expected_type=int,
                        required=False,
                        default=200,
                    ),
                    iops=_volume_iops if _volume_iops else None,
                    throughput=_volume_throughput if _volume_throughput else None,
                    encrypted=True,
                    kms_key_id=_ebs_volume_key_id if _ebs_volume_key_id else None,
                ),
            ),
        ],
        metadata_options=ec2.CfnLaunchTemplate.MetadataOptionsProperty(
            http_endpoint="enabled",
            # http_protocol_ipv6="enabled",
            # http_put_response_hop_limit=123,
            http_tokens=get_config_key(
                key_name="Config.metadata_http_tokens",
                default="required",
                required=False,
            ).lower(),
        ),
        user_data=user_data_helper.encode_for_lt(_user_data, label="ControllerNodeLT"),
        network_interfaces=[_network_interfaces],
    )

    # Make sure the Controller LT gets proper tags
    _lt_tags: list = []

    for _tag in scope.cluster_tags:
        _lt_tags.append(
            CfnTag(
                key=_tag.get("Key"),
                value=_tag.get("Value"),
            )
        )

    logger.debug(f"Complete custom_tags for Controller LT: {_lt_tags=}")

    _lt_tag_spec = ec2.CfnLaunchTemplate.LaunchTemplateTagSpecificationProperty(
        resource_type="launch-template", tags=_lt_tags
    )

    scope.soca_resources["controller_launch_template"] = ec2.CfnLaunchTemplate(
        scope,
        "ControllerNodeLT",
        launch_template_data=_ltd,
        tag_specifications=[_lt_tag_spec],
    )

    scope.soca_resources["controller_instance"] = ec2.CfnInstance(
        scope,
        "ControllerInstance",
        launch_template=ec2.CfnInstance.LaunchTemplateSpecificationProperty(
            version=scope.soca_resources[
                "controller_launch_template"
            ].attr_default_version_number,
            launch_template_id=scope.soca_resources[
                "controller_launch_template"
            ].attr_launch_template_id,
        ),
    )

    Annotations.of(scope.soca_resources["controller_instance"]).acknowledge_warning(
        id="@aws-cdk/aws-ec2:throughputNotSupported", message="Known Constraint"
    )

    Tags.of(scope.soca_resources["controller_instance"]).add(
        key="Name", value=f"{user_specified_variables.cluster_id}-Controller"
    )

    Tags.of(scope.soca_resources["controller_instance"]).add(
        key="edh:NodeType", value="controller"
    )

    # XXX FIXME TODO - Should this take place when there isn't active backup plan?
    Tags.of(scope.soca_resources["controller_instance"]).add(
        key="edh:BackupPlan", value=f"{user_specified_variables.cluster_id}"
    )

    # Ensure Filesystem are already up and running before creating the controller instance
    if not user_specified_variables.fs_apps:
        scope.soca_resources["controller_instance"].node.add_dependency(
            scope.soca_resources["fs_apps"]
        )
    if not user_specified_variables.fs_data:
        scope.soca_resources["controller_instance"].node.add_dependency(
            scope.soca_resources["fs_data"]
        )

    # OpenLDAP is installed by default on the controller machine
    if scope.directory_service_resource_setup.get("provider") == "openldap":
        _secret_name = f"/edh/{user_specified_variables.cluster_id}/UserDirectoryServiceAccount"
        _openldap_secret = secretsmanager_helper.create_secret(
            scope=scope,
            construct_id="UserDirectoryServiceAccount",
            secret_name=_secret_name,
            secret_string_template=f'{{"username":"CN=admin,{scope.directory_service_resource_setup.get("domain_base")}"}}',
            kms_key_id=(
                scope.soca_resources["secretsmanager_kms_key_id"]
                if scope.soca_resources["secretsmanager_kms_key_id"]
                else None
            ),
        )
        _openldap_secret.node.add_dependency(
            scope.soca_resources["controller_instance"]
        )

        scope.directory_service_resource_setup["service_account_secret_arn"] = (
            _openldap_secret.secret_full_arn
        )
        scope.directory_service_resource_setup["endpoint"] = (
            f"ldaps://{scope.soca_resources['controller_instance'].attr_private_ip}"
        )

    # Ensure AWS Managed AD is ready before controller boots
    if scope.directory_service_resource_setup.get("ds"):
        scope.soca_resources["controller_instance"].node.add_dependency(
            scope.directory_service_resource_setup["ds"]
        )

    if scope.soca_resources["elasticache"]:
        scope.soca_resources["controller_instance"].node.add_dependency(
            scope.soca_resources["elasticache"]
        )
