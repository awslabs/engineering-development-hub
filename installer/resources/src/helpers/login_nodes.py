#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

import os
from aws_cdk import (
    Tags,
    CfnOutput,
    aws_ec2 as ec2,
    aws_autoscaling as autoscaling,
    aws_elasticloadbalancingv2 as elbv2,
    aws_kms as kms,
    Annotations,
)

from types import SimpleNamespace

from helpers import storage as storage_helper, user_data as user_data_helper
import pathlib
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# Login node ASG + bootstrap

logger = logging.getLogger("soca_logger")


def login_nodes(
    scope,
    *,
    endpoints_suffix=None,
    install_props=None,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    flatten_parameterstore_config=None,
    return_ebs_volume_type=None,
):
    """
    Create ASG for Login Node
    """

    # Make sure our filesystems are fully qualified
    # duplicate from controller(),
    if user_specified_variables.fs_apps_provider:
        _fs_apps_provider: str = user_specified_variables.fs_apps_provider
        _fs_apps_dns: str = f"{user_specified_variables.fs_apps}"
    else:
        _fs_apps_provider: str = install_props.fs_apps_provider
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

    if user_specified_variables.fs_data_provider:
        _fs_data_provider: str = user_specified_variables.fs_data_provider
        _fs_data_dns: str = f"{user_specified_variables.fs_data}"
    else:
        _fs_data_provider: str = install_props.fs_data_provider
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

    # Generate EC2 User Data
    # We manually replace  the variable with the relevant ParameterStore as all ParamStore hierarchy is created at the very end of this CDK
    _user_data_variables = {
        "/configuration/BaseOS": user_specified_variables.base_os,  # legacy
        "/configuration/ClusterId": user_specified_variables.cluster_id,
        "/configuration/UserDirectory/provider": get_config_key(
            "Config.directoryservice.provider"
        ),
        "/configuration/Region": user_specified_variables.region,
        "/configuration/Cache/enabled": scope.cache_info.get("enabled"),
        "/configuration/Cache/port": scope.cache_info.get("port"),
        "/configuration/Cache/endpoint": scope.cache_info.get("endpoint"),
        "/configuration/ControllerPrivateDnsName": scope.soca_resources[
            "controller_instance"
        ].attr_private_dns_name,
        "/configuration/ControllerPrivateIp": scope.soca_resources[
            "controller_instance"
        ].attr_private_ip,
        "/configuration/S3Bucket": user_specified_variables.bucket,
        "/job/BootstrapPath": f"/apps/edh/{user_specified_variables.cluster_id}/shared/logs/bootstrap/login_node",
        "/job/BootstrapScriptsS3Location": f"s3://{user_specified_variables.bucket}/{user_specified_variables.cluster_id}/config/do_not_delete/bootstrap/login_node",
        "/job/NodeType": "login_node",
        "/job/BaseOS": user_specified_variables.base_os,
    }

    # add all System hierarchy
    _parameter_store_keys = flatten_parameterstore_config(
        get_config_key(key_name="Parameters", expected_type=dict)
    )
    for _ssm_parameter_key, _ssm_parameter_value in _parameter_store_keys.items():
        _user_data_variables[f"/{_ssm_parameter_key}"] = _ssm_parameter_value

    # Generate EC2 User Data
    os.makedirs(
        f"{pathlib.Path.cwd().parent}/upload_to_s3/{user_specified_variables.cluster_id}/{user_specified_variables.region}/bootstrap/login_node/",
        exist_ok=True,
    )

    # Because of size limitation, the main setup script is stored on S3 as it's only called once.
    _user_data = user_data_helper.remove_text(
        text_to_remove=[
            "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
            "# SPDX-License-Identifier: Apache-2.0",
        ],
        data=scope.jinja2_env.get_template(
            "user_data/login_node/01_user_data.sh.j2"
        ).render(
            context=_user_data_variables,
            ns=SimpleNamespace(template_already_included=[]),
        ),
    )

    # Because of size limitation, scripts needed during bootstrap are stored on s3
    _templates_to_render = [
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
            f"{pathlib.Path.cwd().parent}/upload_to_s3/{user_specified_variables.cluster_id}/{user_specified_variables.region}/bootstrap/login_node/{template.split('/')[-1]}.sh",
            "w",
        ) as f:
            f.write(_t)

    _configured_instance_type: list = get_config_key(
        key_name="Config.login_node.instance_type",
        expected_type=list,
        required=False,
        default=["m8i-flex.large", "m7i-flex.large", "m5.large"],
    )
    logger.debug(
        f"LoginNode - Configured instance type: {_configured_instance_type}"
    )

    _selected_instance, _instance_arch, _default_instance_ami_for_instance = (
        scope.select_best_instance(
            instance_list=_configured_instance_type,
            region=user_specified_variables.region,
            fallback_instance="m5.large",
        )
    )

    logger.debug(
        f"LoginNode - Selected instance type: {_selected_instance} / Arch: {_instance_arch}"
    )

    # Do we have any configuration over-rides in the login_node.ami.<arch> configuration?
    _desired_ami: str = get_config_key(
        key_name=f"Config.login_node.ami.{_instance_arch}",
        expected_type=str,
        required=False,  # Fallback to default if needed
        default=_default_instance_ami_for_instance,
    )

    # show what we landed on
    logger.debug(
        f"LoginNode - Instance / AMI / Arch determination - InstanceType: {_selected_instance} / AMI: {_desired_ami} / Arch: {_instance_arch}"
    )

    _ebs_volume_key_id: str = get_kms_key_id(
        config_key_names=["Config.login_node.volume_kms_key_id"],
        allow_global_default=True,
    )

    logger.debug(f"login_node EBS encryption: KeyID: {_ebs_volume_key_id}")

    _volume_type_str: str = get_config_key(
        key_name="Config.login_node.volume_type",
        required=False,
        default="gp3",
        expected_type=str,
    ).lower()

    _volume_type = return_ebs_volume_type(volume_string=_volume_type_str)

    _volume_iops = get_config_key(
        key_name="Config.login_node.volume_iops",
        required=False,
        default=0,
        expected_type=int,
    )

    _volume_throughput = get_config_key(
        key_name="Config.login_node.volume_throughput",
        required=False,
        default=0,
        expected_type=int,
    )
    logger.debug(f"login_node EBS volume IOPS: {_volume_iops}")
    logger.debug(f"login_node EBS volume throughput: {_volume_throughput}")

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

    _login_node_launch_template = ec2.LaunchTemplate(
        scope,
        "LoginNodeLT",
        associate_public_ip_address=False,
        machine_image=ec2.MachineImage.generic_linux(
            {user_specified_variables.region: _desired_ami}
        ),
        instance_type=ec2.InstanceType(_selected_instance),
        key_pair=ec2.KeyPair.from_key_pair_attributes(
            scope,
            "LoginNodeKeyPair",
            key_pair_name=user_specified_variables.ssh_keypair,
        ),
        require_imdsv2=True,
        role=scope.soca_resources["login_node_role"],
        block_devices=[
            ec2.BlockDevice(
                device_name=scope.return_ebs_volume_name(
                    base_os=user_specified_variables.base_os
                ),
                volume=ec2.BlockDeviceVolume(
                    ebs_device=ec2.EbsDeviceProps(
                        encrypted=True,
                        kms_key=(
                            kms.Key.from_key_arn(
                                scope,
                                id="LoginEBSKMSKey",
                                key_arn=_ebs_volume_key_id,
                            )
                            if _ebs_volume_key_id
                            else None
                        ),
                        volume_size=get_config_key(
                            key_name="Config.login_node.volume_size",
                            expected_type=int,
                            required=False,
                            default=50,
                        ),
                        volume_type=_volume_type,
                        iops=_volume_iops if _volume_iops else None,
                        throughput=(
                            _volume_throughput if _volume_throughput else None
                        ),
                    ),
                ),
            )
        ],
        security_group=scope.soca_resources["login_node_sg"],
    )
    _login_node_launch_template.node.default_child.add_property_override(
        "LaunchTemplateData.UserData",
        user_data_helper.encode_for_lt(_user_data, label="LoginNodeLT"),
    )

    # Update networking for the LT to set the IPv6 address as primary
    if scope.is_networking_af_enabled(address_family="ipv6"):
        logger.debug("Setting LoginNode LT NetworkInterfaces.0.PrimaryIpv6 to True")
        _login_node_launch_template_node = (
            _login_node_launch_template.node.default_child
        )
        _login_node_launch_template_node.add_property_override(
            "LaunchTemplateData.NetworkInterfaces.0.Ipv6AddressCount", 1
        )  # TODO - make configurable
        #
        # IPv6 prefix delegation is also possible?
        # _login_node_launch_template_node.add_property_override("LaunchTemplateData.NetworkInterfaces.0.Ipv6PrefixCount", 1)
        #
        _login_node_launch_template_node.add_property_override(
            "LaunchTemplateData.NetworkInterfaces.0.PrimaryIpv6", True
        )

    # _login_node_subnets == subnetIds
    # _login_node_isubnets == ISubnets (CDK)
    _login_node_subnets: list = []
    _login_node_isubnets: list = []
    _subnets_for_login_nodes: list = []
    logger.debug("Determining the LoginNode placement subnets for the ASG")

    # If we are using an existing VPC - we use our specific marked private subnets
    if user_specified_variables.vpc_id:
        logger.debug(f"Using pre-existing VPC: {user_specified_variables.vpc_id}")
        for _sn_info in user_specified_variables.private_subnets:
            # subnet-123,az1
            _exact_subnet_id = _sn_info.split(",")[0]
            logger.debug(f"Adding subnet for LoginNodes ASG: {_exact_subnet_id}")
            _subnets_for_login_nodes.append(_exact_subnet_id)

    else:
        # SOCA Created subnets
        logger.debug("Using SOCA-created VPC subnets for LoginNode ASG")
        for _sn_info in scope.soca_resources["vpc"].private_subnets:
            logger.debug(
                f"Adding SOCA-created subnet for LoginNodes ASG: {_sn_info.subnet_id}"
            )
            _subnets_for_login_nodes.append(_sn_info.subnet_id)

    logger.debug(
        f"Final List of SubnetIDs for Login Nodes ASG: {_subnets_for_login_nodes}"
    )
    _subnet_i: int = 1
    for _sn_id in _subnets_for_login_nodes:
        if _sn_id not in _login_node_subnets:
            logger.debug(f"Adding subnet #{_subnet_i} for LoginNodes ASG: {_sn_id}")
            _login_node_subnets.append(_sn_id)

            _login_node_isubnet_entry = ec2.Subnet.from_subnet_id(
                scope,
                f"LoginNodePrivateSubnet{_subnet_i}",
                subnet_id=_sn_id,
            )
            Annotations.of(_login_node_isubnet_entry).acknowledge_warning(
                id="@aws-cdk/aws-ec2:noSubnetRouteTableId",
                message="RouteTableId will not be processed",
            )
            _login_node_isubnets.append(_login_node_isubnet_entry)

        _subnet_i += 1

    # Read our configuration for min/max/desired with defaults to 1
    _login_node_count: dict = {}
    for _node_count in ("min", "max", "desired"):
        _login_node_count[_node_count] = get_config_key(
            key_name=f"Config.login_node.{_node_count}_count",
            expected_type=int,
            required=False,
            default=(
                _login_node_count.get("min", 1) if _node_count == "desired" else 1
            ),
        )
        logger.debug(
            f"Configuring LoginNode ASG for {_node_count} == {_login_node_count[_node_count]}"
        )

    # Sanity check
    _login_node_count["min"] = min(
        _login_node_count["desired"], _login_node_count["min"]
    )
    _login_node_count["max"] = max(
        _login_node_count["desired"], _login_node_count["max"]
    )
    logger.debug(f"LoginNode ASG sizing post-check/fixups: {_login_node_count}")

    _login_node_asg = autoscaling.AutoScalingGroup(
        scope,
        "LoginNodeASG",
        vpc=scope.soca_resources["vpc"],
        launch_template=_login_node_launch_template,
        max_capacity=_login_node_count["max"],
        min_capacity=min(_login_node_count["min"], _login_node_count["desired"]),
        desired_capacity=_login_node_count["desired"],
        vpc_subnets=ec2.SubnetSelection(subnets=_login_node_isubnets),
    )
    # Expose the ASG on soca_resources so other methods (e.g. webshell
    # listener rule setup in alb()) can attach additional target groups
    # to the same ASG without duplicating the launch template.
    scope.soca_resources["login_node_asg"] = _login_node_asg
    Annotations.of(_login_node_asg).acknowledge_warning(
        id="@aws-cdk/aws-autoscaling:desiredCapacitySet",
        message="DesiredCapacity is OK to reset",
    )
    #
    _login_node_ssh_back_port: int = get_config_key(
        key_name="Config.login_node.security.ssh_backend_port",
        expected_type=int,
        required=False,
        default=22,
    )
    _login_node_ssh_front_port: int = get_config_key(
        key_name="Config.login_node.security.ssh_frontend_port",
        expected_type=int,
        required=False,
        default=22,
    )
    logger.debug(
        f"LoginNode SSH port: Front: {_login_node_ssh_back_port} / Back: {_login_node_ssh_front_port}"
    )

    _login_node_target_groups = elbv2.NetworkTargetGroup(
        scope,
        f"{user_specified_variables.cluster_id}-LoginNodesTargetGroup",
        port=_login_node_ssh_back_port,
        protocol=elbv2.Protocol.TCP,
        target_type=elbv2.TargetType.INSTANCE,
        vpc=scope.soca_resources["vpc"],
        targets=[_login_node_asg],
        target_group_name=f"{user_specified_variables.cluster_id}-LoginNodes",
        health_check=elbv2.HealthCheck(
            port=str(_login_node_ssh_back_port), protocol=elbv2.Protocol.TCP
        ),
        connection_termination=True,
    )

    # Create NLB
    # Plaintext list of subnets to launch the NLB into
    _nlb_public_bool: bool = (
        True if user_specified_variables.deployment_mode == "public" else False
    )

    logger.debug(f"NLB / Cluster Entry Point Public?: {_nlb_public_bool}")

    _nlb_subnets_list: list = []
    _source_subnets: list = []

    # Did we use existing resources?
    if user_specified_variables.vpc_id:
        # Existing resources
        logger.debug(
            f"Using imported VPC Subnets for NLB from VPC {user_specified_variables.vpc_id}"
        )
        if _nlb_public_bool:
            _source_subnets = user_specified_variables.public_subnets
        else:
            _source_subnets = user_specified_variables.private_subnets

        for _subnet in _source_subnets:
            _subnet_id: str = _subnet.split(",")[0]
            _subnet_az: str = _subnet.split(",")[1]
            _nlb_subnets_list.append(_subnet_id)
            logger.debug(
                f"Adding existing subnet for NLB: {_subnet_id} / AZ: {_subnet_az}"
            )

    else:
        # SOCA created the VPC
        logger.debug("Using SOCA created VPC Subnets for NLB")
        if _nlb_public_bool:
            logger.debug("Adding SOCA created public subnets")
            for _soca_sn in scope.soca_resources["vpc"].public_subnets:
                logger.debug(
                    f"Adding SOCA created public subnet: {_soca_sn.subnet_id}"
                )
                _source_subnets.append(_soca_sn.subnet_id)
        else:
            logger.debug("Adding SOCA created private subnets")
            for _soca_sn in scope.soca_resources["vpc"].private_subnets:
                logger.debug(
                    f"Adding SOCA created private subnet: {_soca_sn.subnet_id}"
                )
                _source_subnets.append(_soca_sn.subnet_id)

        logger.debug(f"Scanning Source subnets: {_source_subnets}")
        # TODO - still needed?
        for _subnet in _source_subnets:
            logger.debug(f"Adding subnet: {_subnet}")
            _nlb_subnets_list.append(_subnet)
            logger.debug(f"Adding existing subnet for NLB: {_subnet}")

    logger.debug(
        f"Final subnets for NLB: {_nlb_subnets_list} / Public: {_nlb_public_bool}"
    )

    # Convert our subnet list to a list of ISubnets
    _nlb_isubnets_list: list = []

    for _i, _subnet in enumerate(_nlb_subnets_list):
        _nlb_isubnet_entry = ec2.Subnet.from_subnet_id(
            scope,
            f"NLBSubnet{_i}",
            subnet_id=_subnet,
        )
        Annotations.of(_nlb_isubnet_entry).acknowledge_warning(
            id="@aws-cdk/aws-ec2:noSubnetRouteTableId",
            message="RouteTableId will not be processed",
        )
        _nlb_isubnets_list.append(_nlb_isubnet_entry)

    logger.debug(f"Final ISubnets for NLB: {_nlb_isubnets_list}")

    scope.soca_resources["nlb"] = elbv2.NetworkLoadBalancer(
        scope,
        "SOCANLB",
        load_balancer_name=f"{user_specified_variables.cluster_id}-nlb",
        ip_address_type=(
            elbv2.IpAddressType.DUAL_STACK
            if scope.is_networking_af_enabled(address_family="ipv6")
            else elbv2.IpAddressType.IPV4
        ),
        vpc=scope.soca_resources["vpc"],
        security_groups=[scope.soca_resources["nlb_sg"]],
        internet_facing=_nlb_public_bool,
        vpc_subnets=ec2.SubnetSelection(subnets=_nlb_isubnets_list),
        # deletion_protection=get_config_key(
        #     key_name="Config.termination_protection",
        #     expected_type=bool,
        #     required=False,
        #     default=True,
        # ),
        cross_zone_enabled=get_config_key(
            key_name="Config.network.cross_zone_enabled",
            expected_type=bool,
            required=False,
            default=True,
        ),
    )

    # Create listener
    elbv2.NetworkListener(
        scope,
        "SSHListener",
        load_balancer=scope.soca_resources["nlb"],
        protocol=elbv2.Protocol.TCP,
        port=_login_node_ssh_front_port,
        default_action=elbv2.NetworkListenerAction.forward(
            target_groups=[_login_node_target_groups]
        ),
    )

    Tags.of(_login_node_asg).add(
        key="Name", value=f"{user_specified_variables.cluster_id}-LoginNode"
    )
    Tags.of(_login_node_asg).add(key="edh:NodeType", value="login_node")

    # Login Nodes creation is triggered at the end of the deployment as we have to wait for bootstrap.d folder to be deployed on the filesystem
    if (
        get_config_key(key_name="Config.analytics.enabled", expected_type=bool)
        is True
    ):
        if not user_specified_variables.os_endpoint:
            scope.soca_resources["nlb"].node.add_dependency(
                scope.soca_resources["os_domain"]
            )

    # Other LoginNode Deps (ElastiCache)
    if scope.soca_resources["elasticache"]:
        scope.soca_resources["nlb"].node.add_dependency(
            scope.soca_resources["elasticache"]
        )

    # Give the controller a head start in resource creation since the LoginNodes need to do some items that depend on Controller
    _login_node_asg.node.add_dependency(scope.soca_resources["controller_instance"])

    scope.soca_resources["nlb"].node.add_dependency(
        scope.soca_resources["controller_instance"]
    )

    CfnOutput(
        scope,
        "SSHEndpoint",
        value=f"{scope.soca_resources['nlb'].load_balancer_dns_name}",
    )
    CfnOutput(
        scope,
        "SSHPort",
        value=str(_login_node_ssh_front_port),
    )
