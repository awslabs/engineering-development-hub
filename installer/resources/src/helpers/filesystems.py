#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import (
    Tags,
    CfnDeletionPolicy,
    aws_efs as efs,
    aws_ec2 as ec2,
    aws_fsx as fsx,
    CfnTag,
)

import json
import sys

from helpers import (
    security_groups as security_groups_helper,
    secretsmanager as secretsmanager_helper,
)
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# Filesystem/storage construction (uses helpers/storage.get_filesystem_dns)

logger = logging.getLogger("soca_logger")


def storage(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
):
    """
    Create filesystems that will be mounted. This reads Config.storage to create all filesystems.
    An entry for apps and data are required. Others are optional.
    """

    _fs_list: dict = get_config_key(
        key_name="Config.storage", required=True, expected_type=dict
    )

    logger.debug(f"Storage Configuration tree: {_fs_list}")

    # First - make sure we have our required apps and data
    # , and they are mounted on /apps and /data
    for _req_fs in {"apps", "data"}:
        if not _fs_list.get(_req_fs):
            raise ValueError(f"Missing required {_req_fs} filesystem configuration")
        if not isinstance(_fs_list.get(_req_fs), dict):
            raise ValueError(f"Invalid {_req_fs} filesystem configuration")

        # Allow for mount_point or mountpoint in the YML
        _configured_mountpoint_str: str = _fs_list.get(_req_fs).get(
            "mount_point", _fs_list.get(_req_fs).get("mountpoint", "")
        )

        if not _configured_mountpoint_str:
            raise ValueError(f"Missing required {_req_fs} filesystem mountpoint")

        if _configured_mountpoint_str != f"/{_req_fs}":
            raise ValueError(
                f"Mountpoint for {_req_fs} must be /{_req_fs}. Found {_configured_mountpoint_str}"
            )

        logger.debug(f"Validated {_req_fs} filesystem configuration")

    # Do a quick sanity check on the names to make sure they are alnum
    for _fs in _fs_list:
        if _fs == "kms_key_id":
            logger.debug(
                "Skipping Storage-wide KMS key ID specification as a filesystem (Config.kms_key_id) - (this is perfectly OK)"
            )
            continue

        if not _fs.isalnum():
            raise ValueError(
                f"Invalid filesystem key name: {_fs} . Use only alphanumeric key names and try again"
            )

    # Do a quick scan to see if we need EFS/SNS alarms
    # We have to do this prior to the filesystem create loop since the downstream resources will need this to be created
    for _fs in _fs_list:
        if _fs == "kms_key_id":
            logger.debug(
                "Skipping Storage-wide KMS key ID specification as a filesystem (Config.kms_key_id) - (this is perfectly OK)"
            )
            continue

        _fs_provider: str = get_config_key(
            key_name=f"Config.storage.{_fs}.provider",
            required=False,
            expected_type=str,
            default="efs",
        ).lower()

    # Continue with creating filesystems
    for _fs in _fs_list:
        if _fs == "kms_key_id":
            logger.debug(
                "Skipping Storage-wide KMS key ID specification as a filesystem (Config.kms_key_id) - (this is perfectly OK)"
            )
            continue
        _fs_provider = getattr(user_specified_variables, f"fs_{_fs}_provider", None)
        _fs_id = getattr(user_specified_variables, f"fs_{_fs}", None)

        logger.debug(f"UserSpec Provider for {_fs=}: {_fs_provider=} / {_fs_id=}")

        #
        # Only call these methods to create/build _new_ filesystems
        # NOTE - New filesystems are responsible for returning an identifier for registration
        #
        if not _fs_id:
            match _fs_provider:
                case "efs":
                    _fs_id = scope._storage_build_efs_filesystem(fs_key=_fs)
                case "fsx_lustre":
                    _fs_id = scope._storage_build_fsx_lustre_filesystem(fs_key=_fs)
                case "fsx_ontap":
                    _fs_id = scope._storage_build_fsx_ontap_filesystem(fs_key=_fs)
                case "fsx_openzfs":
                    _fs_id = scope._storage_build_fsx_openzfs_filesystem(fs_key=_fs)
                case _:
                    raise ValueError(
                        f"Invalid provider: {_fs_provider} for {_fs} - unable to continue"
                    )
            logger.debug(
                f"After create - got back {_fs_id=} from _storage_build provider"
            )

        # Now that we have either created the new filesystems or gotten here via existing resources
        # we register it for our config tree
        logger.debug(
            f"Preparing to register filesystem {_fs=} / {_fs_id=} via {_fs_provider=}"
        )
        scope._storage_register_filesystem(
            fs_id=_fs_id, fs_key=_fs, fs_provider=_fs_provider
        )

    logger.debug(
        f"Storage Configuration completed. All SOCA filesystems: {scope.soca_filesystems=}"
    )


def _storage_build_fsx_ontap_filesystem(
    scope,
    fs_key: str,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    get_subnet_route_table_by_subnet_id=None,
):
    """
    Build an FSx/ONTAP filesystem.
    """
    logger.debug(f"_storage_build_fsx_ontap_filesystem called for {fs_key}")

    _deployment_type: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.deployment_type",
        expected_type=str,
        required=False,
        default="MULTI_AZ_2",
    ).upper()

    # Determine the regions that various FSx types are supported
    _fsx_regional_capability: dict = scope.get_fsx_deployment_options_by_region(
        region=user_specified_variables.region
    )

    _throughput_capacity: int = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.throughput_capacity",
        expected_type=int,
        required=False,
        default=256,
    )

    _allowed_throughput_capacity = {
        "MULTI_AZ_1": [128, 256, 512, 1024, 2048, 4096],
        "MULTI_AZ_2": [384, 768, 1536, 3072, 6144],
        "SINGLE_AZ_1": [128, 256, 512, 1024, 2048, 4096],
        # "SINGLE_AZ_2": Too many options, will let CLoudFormation returns the error based on HA pair
    }

    if _deployment_type in _allowed_throughput_capacity:
        if (
            _throughput_capacity
            not in _allowed_throughput_capacity[_deployment_type]
        ):
            logger.fatal(
                f"Invalid throughput_capacity {_throughput_capacity} for {_deployment_type}. Accepted value: {_allowed_throughput_capacity[_deployment_type]}"
            )
            sys.exit(1)

    _storage_capacity: int = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.storage_capacity",
        expected_type=int,
        required=False,
        default=1024,
    )

    # Is the desired deployment type supported in the region?
    # Note that the Pricing API uses underscore (_) while the CFN string uses dashes (-)
    # So we need to convert the CFN string to underscore
    # There is also a case difference between the service names to accomodate
    # So we make an extra copy of the string that we plan to mutate
    _dep_type_lookup: str = _deployment_type.replace("_", "-").upper()

    if _deployment_type == "MULTI_AZ_1":
        _dep_type_lookup = "Multi-AZ"
    elif _deployment_type == "MULTI_AZ_2":
        _dep_type_lookup = "Multi-AZ-2"
    elif _deployment_type == "SINGLE_AZ_1":
        _dep_type_lookup = "Single-AZ_2N"
    elif _deployment_type == "SINGLE_AZ_2":
        _dep_type_lookup = "Single-AZ_2N-2"

    logger.debug(
        f"Checking if deployment type {_deployment_type} ({_dep_type_lookup=}) is supported in region {user_specified_variables.region}"
    )

    if _dep_type_lookup not in _fsx_regional_capability.get(
        user_specified_variables.region, {}
    ).get("ONTAP", []):
        logger.fatal(
            f"Config.storage.{fs_key}.fsx_ontap.deployment_type {_deployment_type} ({_dep_type_lookup=}) is not supported in region {user_specified_variables.region}"
        )
        sys.exit(1)

    _automatic_backup_retention_days: int = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.automatic_backup_retention_days",
        expected_type=int,
        required=False,
        default=7,
    )

    _daily_automatic_backup_start_time: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.daily_automatic_backup_start_time",
        expected_type=str,
        required=False,
        default="00:00",
    )

    _junction_path: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.junction_path",
        expected_type=str,
        required=True,
    )

    _netbios_name: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.netbios_name",
        expected_type=str,
        required=True,
    ).upper()

    if len(_netbios_name) > 15:
        logger.fatal(
            f"Config.storage.{fs_key}.fsx_ontap.netbios_name must be 15 characters or less"
        )
        sys.exit(1)

    _file_system_administrators_group: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.file_system_administrators_group",
        expected_type=str,
        default="AWS Delegated FSx Administrators",
        required=False,
    ).upper()

    _organizational_unit_distinguished_name: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_ontap.organizational_unit_distinguished_name",
        expected_type=str,
        default=f"OU=Computers, OU={scope.directory_service_resource_setup.get('short_name')},{scope.directory_service_resource_setup.get('domain_base')}",
        required=False,
    ).upper()

    _secret_name = (
        f"/edh/{user_specified_variables.cluster_id}/FSxOntapAdminPassword{fs_key}"
    )
    _fsx_admin_password = secretsmanager_helper.create_secret(
        scope=scope,
        construct_id=f"FSxOntapAdminPassword{fs_key}",
        secret_name=_secret_name,
        secret_string_template=json.dumps({"username": "fsxadmin"}),
        kms_key_id=(
            scope.soca_resources["secretsmanager_kms_key_id"]
            if scope.soca_resources["secretsmanager_kms_key_id"]
            else None
        ),
    )

    # Find all private subnets VPC to deploy FSxONTAP. Note Only 2 can be configured
    # Associate FSxN with all Private Route Tables of your VPC

    _vpc_subnets_id: list = []
    _route_table_ids: list = []

    logger.debug(
        f"FSx/ONTAP - User selected the following private subnets: {user_specified_variables.private_subnets=}"
    )

    # Determine our subnet usage
    # did we select private subnets / existing resources during installation?
    _fsx_ontap_source_subnets: dict = {}

    if user_specified_variables.private_subnets is not None:
        logger.debug(
            "FSx/ONTAP - User selected subnets - probable Existing Resources installation"
        )
        for _sn in user_specified_variables.private_subnets:
            # ['subnet-123,us-east-1b', ...]
            _sn_id: str = _sn.split(",")[0]
            if _sn_id not in _fsx_ontap_source_subnets:
                # route_table_id comes later
                _fsx_ontap_source_subnets[_sn_id] = {
                    "subnet_id": _sn_id,
                }
                logger.debug(
                    f"FSx/ONTAP - User selected the following private subnet: {_sn_id=} / AZ: {_sn.split(',')[1]}"
                )
            else:
                logger.fatal(
                    f"FSx/ONTAP - Duplicate subnet {_sn_id} selected. Subnets now {_fsx_ontap_source_subnets=}. Probable defect?"
                )
                sys.exit(1)

        # Now that we have built up _fsx_ontap_source_subnets, we need to populate the route table info
        _rt_dict: dict = get_subnet_route_table_by_subnet_id(
            subnet_ids=list(_fsx_ontap_source_subnets.keys())
        )

        if not _rt_dict:
            logger.fatal(
                f"FSx/ONTAP - Unable to lookup route tables for {_fsx_ontap_source_subnets=}"
            )
            sys.exit(1)

        for _sn_id in _rt_dict:
            _rt_id: str = _rt_dict.get(_sn_id, "")
            if not _rt_id:
                logger.fatal(
                    f"FSx/ONTAP - Unable to lookup route table for subnet {_sn_id}"
                )
                sys.exit(1)
            logger.debug(
                f"FSx/ONTAP - Using Route Table {_rt_id} for subnet {_sn_id}"
            )
            _fsx_ontap_source_subnets[_sn_id].update({"route_table_id": _rt_id})

    else:
        # New VPC
        logger.debug(
            "FSx/ONTAP - No User selected subnets - probable New VPC installation"
        )
        for _sn in (
            scope.soca_resources["vpc"]
            .select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            .subnets
        ):
            if _sn.subnet_id not in _fsx_ontap_source_subnets:
                _fsx_ontap_source_subnets[_sn.subnet_id] = {
                    "subnet_id": _sn.subnet_id,
                    "route_table_id": _sn.route_table.route_table_id,
                }
                logger.debug(
                    f"FSx/ONTAP - Using VPC subnet {_sn.subnet_id} / RTB: {_sn.route_table.route_table_id} . Subnets now {_fsx_ontap_source_subnets=}"
                )
            else:
                logger.fatal(
                    f"FSx/ONTAP - Duplicate subnet {_sn.subnet_id} selected. Subnets now {_fsx_ontap_source_subnets=}. Probable defect?"
                )
                sys.exit(1)

    logger.debug(
        f"FSx/ONTAP - Final FSx/Source Subnets/RTB for consideration: {_fsx_ontap_source_subnets=}"
    )

    for _subnet in list(_fsx_ontap_source_subnets.keys()):
        if _subnet not in _vpc_subnets_id:

            logger.debug(f"FSx/ONTAP - Adding VPC subnet {_subnet}")
            _vpc_subnets_id.append(_subnet)

            _route_id = _fsx_ontap_source_subnets.get(_subnet, {}).get(
                "route_table_id", ""
            )
            if not _route_id:
                logger.fatal(
                    f"FSx/ONTAP - Unable to lookup route table for subnet {_subnet}"
                )
                sys.exit(1)

            if _route_id not in _route_table_ids:
                _route_table_ids.append(_route_id)
                logger.debug(
                    f"FSx/ONTAP - Adding Route Table {_route_id} . Route Tables now {_route_table_ids=}"
                )
            else:
                # This is just when multiple subnets share the same route table, which is fine
                logger.info(
                    f"FSx/ONTAP - Route Table {_route_id} already exists for filesystem consideration. Route Tables now {_route_table_ids=} (not an indication of a problem)"
                )
        else:
            # This gets a warning as it shouldn't happen
            logger.warning(
                f"FSx/ONTAP - Subnet {_subnet} already exists. Subnets now {_vpc_subnets_id=}.  Defect?"
            )

    # Determine KMS config
    _kms_key_id = get_kms_key_id(
        config_key_names=[
            f"Config.storage.{fs_key}.kms_key_id",  # The proper location providing per-fs keys
            "Config.storage.kms_key_id",  # Fallback to a global storage kms_key_id
        ],
        allow_global_default=True,
    )
    logger.debug(f"FSx KMS for {fs_key}: {_kms_key_id}")

    # Create the Security group for the filesystem
    scope.soca_resources[f"fs_{fs_key}_sg"] = (
        security_groups_helper.create_security_groups(
            scope=scope,
            construct_id=f"FSxOntap{fs_key.capitalize()}SecurityGroup",
            vpc=scope.soca_resources["vpc"],
            allow_all_outbound=True,
            allow_all_ipv6_outbound=True,
            description=f"FSx/ONTAP {fs_key.capitalize()} Security Group",
        )
    )
    Tags.of(scope.soca_resources[f"fs_{fs_key}_sg"]).add(
        key="Name",
        value=f"{user_specified_variables.cluster_id}-ONTAP{fs_key.capitalize()}SG",
    )

    # Create our rules (TCP and UDP) for each peer expected to consume the filesystem
    # https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/limit-access-security-groups.html
    for _sg_peer in [
        f"fs_{fs_key}_sg",
        "compute_node_sg",
        "vdi_node_sg",
        "target_node_sg",
        "controller_sg",
        "login_node_sg",
    ]:
        for _port, _desc in {
            "22-11105": f"Allow FSx/ONTAP from {_sg_peer}"
        }.items():
            logger.debug(f"Adding TCP {_port} for {_sg_peer}")
            _rules: list[ec2.Port] = []
            if "-" in _port:
                _from_port: int = int(_port.split("-")[0])
                _to_port: int = int(_port.split("-")[1])
                _rules.append(
                    ec2.Port.tcp_range(start_port=_from_port, end_port=_to_port)
                )
                _rules.append(
                    ec2.Port.udp_range(start_port=_from_port, end_port=_to_port)
                )
            else:
                _rules.append(ec2.Port.tcp(int(_port)))
                _rules.append(ec2.Port.udp(int(_port)))

            for _rule in _rules:
                logger.debug(f"Adding ingress rule for {_rule}")
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources[f"fs_{fs_key}_sg"],
                    peer=scope.soca_resources[_sg_peer],
                    connection=_rule,
                    description=f"{_sg_peer} {_port}",
                )

    if _deployment_type in ["MULTI_AZ_1", "MULTI_AZ_2"]:
        _ontap_configuration_property = fsx.CfnFileSystem.OntapConfigurationProperty(
            preferred_subnet_id=_vpc_subnets_id[0],
            route_table_ids=_route_table_ids,
            deployment_type=_deployment_type,
            throughput_capacity=_throughput_capacity,
            automatic_backup_retention_days=_automatic_backup_retention_days,
            daily_automatic_backup_start_time=_daily_automatic_backup_start_time,
            fsx_admin_password=secretsmanager_helper.resolve_secret_as_str(
                secret_construct=_fsx_admin_password, password_key="password"
            ),
        )
    elif _deployment_type in ["SINGLE_AZ_1", "SINGLE_AZ_2"]:
        # TODO: implement SINGLE_AZ ONTAP configuration
        logger.fatal(
            f"Config.storage.{fs_key}.fsx_ontap.deployment_type {_deployment_type} is not yet implemented"
        )
        sys.exit(1)
    else:
        logger.fatal(
            f"Ontap {_deployment_type=} must be SINGLE_AZ_1, SINGLE_AZ_2, MULTI_AZ_1 or MULTI_AZ_2 "
        )
        sys.exit(1)

    # Define the FSx for ONTAP filesystem
    _ontap_filesystem = fsx.CfnFileSystem(
        scope,
        f"FSxOntap{fs_key.capitalize()}",
        subnet_ids=_vpc_subnets_id[:2],  # 2 subnets max
        file_system_type="ONTAP",
        kms_key_id=_kms_key_id if _kms_key_id else "alias/aws/fsx",
        storage_capacity=_storage_capacity,
        ontap_configuration=_ontap_configuration_property,
        security_group_ids=[
            scope.soca_resources[f"fs_{fs_key}_sg"].security_group_id
        ],
        tags=[
            {
                "key": "Name",
                "value": f"{user_specified_variables.cluster_id}-{fs_key.capitalize()}",
            },
            {
                "key": "edh:BackupPlan",
                "value": user_specified_variables.cluster_id,
            },
            {"key": "edh:FsxAdminSecretName", "value": _secret_name},
        ],
    )

    # Create the SVM
    if not scope.directory_service_resource_setup.get("domain_controller_ips", []):
        logger.fatal(
            "Unable to retrieve Domain Controller IPs. If using existing AD, you must specific dc_ips"
        )
        sys.exit(1)

    logger.debug(
        f"Using AD/DC IP addresses: {scope.directory_service_resource_setup.get('domain_controller_ips')}"
    )

    _fsx_active_directory_configuration = fsx.CfnStorageVirtualMachine.ActiveDirectoryConfigurationProperty(
        net_bios_name=_netbios_name,
        self_managed_active_directory_configuration=fsx.CfnStorageVirtualMachine.SelfManagedActiveDirectoryConfigurationProperty(
            dns_ips=scope.directory_service_resource_setup["domain_controller_ips"],
            domain_name=scope.directory_service_resource_setup.get("domain_name"),
            file_system_administrators_group=_file_system_administrators_group,
            organizational_unit_distinguished_name=_organizational_unit_distinguished_name,
            password=(
                scope.directory_service_resource_setup["ds_admin_password"]
                .secret_value_from_json("password")
                .to_string()
                if scope.directory_service_resource_setup["use_existing_directory"]
                is False
                else scope.directory_service_resource_setup["ds_admin_password"]
            ),
            user_name=scope.directory_service_resource_setup["ds_admin_username"],
        ),
    )

    scope.soca_resources[f"fs_{fs_key}"] = fsx.CfnStorageVirtualMachine(
        scope,
        f"SVMFSxOntap{fs_key.capitalize()}",
        file_system_id=_ontap_filesystem.ref,
        name=f"SVMFSxOntap{fs_key.capitalize()}",
        active_directory_configuration=_fsx_active_directory_configuration,
        root_volume_security_style="UNIX",
    )

    if scope.directory_service_resource_setup.get("use_existing_directory") is False:
        scope.soca_resources[f"fs_{fs_key}"].node.add_dependency(
            scope.directory_service_resource_setup.get("ds")
        )

    _volume = fsx.CfnVolume(
        scope,
        f"VolumeFSxOntap{fs_key.capitalize()}",
        name=f"VolumeFSxOntap{fs_key.capitalize()}",
        volume_type="ONTAP",
        ontap_configuration=fsx.CfnVolume.OntapConfigurationProperty(
            storage_virtual_machine_id=scope.soca_resources[
                f"fs_{fs_key}"
            ].attr_storage_virtual_machine_id,
            ontap_volume_type="RW",
            storage_efficiency_enabled="true",
            volume_style="FLEXVOL",
            junction_path=_junction_path,
            size_in_bytes=str(_storage_capacity * 1024**3),
            security_style="UNIX",
        ),
        tags=[CfnTag(key="edh:OntapFirstSetup", value="true")],
    )

    return str(_volume.attr_volume_id)


def _storage_build_fsx_lustre_filesystem(
    scope,
    fs_key: str,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
):
    """
    Build an FSx/Lustre filesystem.
    """

    logger.debug(f"_storage_build_fsx_filesystem called for {fs_key}")

    _storage_type: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_lustre.storage_type",
        required=False,
        expected_type=str,
        default="SSD",
    ).upper()

    _deployment_type: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_lustre.deployment_type",
        expected_type=str,
        required=False,
        default="PERSISTENT_2",
    ).upper()

    _per_unit_storage_throughput: int = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_lustre.per_unit_storage_throughput",
        expected_type=int,
        required=False,
        default=125 if _deployment_type == "PERSISTENT_2" else 100,
    )

    _drive_cache_type: str = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_lustre.drive_cache_type",
        required=False,
        expected_type=str,
        default="READ",
    ).upper()

    _storage_capacity: int = get_config_key(
        key_name=f"Config.storage.{fs_key}.fsx_lustre.storage_capacity",
        expected_type=int,
        required=False,
        default=1200 if _deployment_type == "PERSISTENT_2" else 300,
    )

    match _storage_type:
        case "SSD":
            if _deployment_type in {"PERSISTENT_1", "PERSISTENT_2"}:
                lustre_configuration = (
                    fsx.CfnFileSystem.LustreConfigurationProperty(
                        per_unit_storage_throughput=_per_unit_storage_throughput,
                        deployment_type=_deployment_type,
                    )
                )
            else:
                lustre_configuration = (
                    fsx.CfnFileSystem.LustreConfigurationProperty(
                        deployment_type=_deployment_type
                    )
                )
        case "HDD":
            lustre_configuration = (
                fsx.CfnFileSystem.LustreConfigurationProperty(
                    deployment_type=_deployment_type,
                    per_unit_storage_throughput=_per_unit_storage_throughput,
                    drive_cache_type=_drive_cache_type,
                )
            )
        case _:
            raise ValueError(f"Invalid storage type: {_storage_type} for {fs_key}")

    # Determine KMS config
    _kms_key_id = get_kms_key_id(
        config_key_names=[
            f"Config.storage.{fs_key}.kms_key_id",  # The proper location providing per-fs keys
            "Config.storage.kms_key_id",  # Fallback to a global storage kms_key_id
        ],
        allow_global_default=True,
    )
    logger.debug(f"FSx KMS for {fs_key}: {_kms_key_id}")

    # Create the Security group for the filesystem
    scope.soca_resources[f"fs_{fs_key}_sg"] = (
        security_groups_helper.create_security_groups(
            scope=scope,
            construct_id=f"FSxLustre{fs_key.capitalize()}SecurityGroup",
            vpc=scope.soca_resources["vpc"],
            allow_all_outbound=True,
            allow_all_ipv6_outbound=True,
            description=f"FSx/Lustre {fs_key.capitalize()} Security Group",
        )
    )
    Tags.of(scope.soca_resources[f"fs_{fs_key}_sg"]).add(
        key="Name",
        value=f"{user_specified_variables.cluster_id}-FSxLustre{fs_key.capitalize()}SG",
    )

    # Create our rules for each peer expected to consume the filesystem
    for _sg_peer in [
        f"fs_{fs_key}_sg",
        "compute_node_sg",
        "vdi_node_sg",
        "controller_sg",
        "login_node_sg",
        "target_node_sg",
    ]:
        for _tcp_port_spec in {"988", "1018-1023"}:
            logger.debug(f"Adding TCP {_tcp_port_spec} for {_sg_peer}")

            if "-" in _tcp_port_spec:
                _tcp_from_port: int = int(_tcp_port_spec.split("-")[0])
                _tcp_to_port: int = int(_tcp_port_spec.split("-")[1])
                _conn_spec: ec2.Port = ec2.Port.tcp_range(
                    start_port=_tcp_from_port, end_port=_tcp_to_port
                )
            else:
                _conn_spec: ec2.Port = ec2.Port.tcp(int(_tcp_port_spec))

            logger.debug(f"Adding ingress rule for {_conn_spec}")
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources[f"fs_{fs_key}_sg"],
                peer=scope.soca_resources[_sg_peer],
                connection=_conn_spec,
                description=f"Allow FSx/Lustre from {_sg_peer}",
            )

    scope.soca_resources[f"fs_{fs_key}"] = fsx.CfnFileSystem(
        scope,
        f"FSxLustre{fs_key.capitalize()}",
        file_system_type="LUSTRE",
        subnet_ids=[
            scope.soca_resources["vpc"]
            .select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            .subnets[0]
            .subnet_id
        ],
        lustre_configuration=lustre_configuration,
        security_group_ids=[
            scope.soca_resources[f"fs_{fs_key}_sg"].security_group_id
        ],
        storage_capacity=_storage_capacity,
        storage_type=_storage_type,
        kms_key_id=_kms_key_id if _kms_key_id else None,
    )

    scope.soca_resources[f"fs_{fs_key}"].node.add_dependency(
        scope.soca_resources[f"fs_{fs_key}_sg"]
    )

    Tags.of(scope.soca_resources[f"fs_{fs_key}"]).add(
        "Name", f"{user_specified_variables.cluster_id}-{fs_key.capitalize()}"
    )
    Tags.of(scope.soca_resources[f"fs_{fs_key}"]).add(
        "edh:BackupPlan", user_specified_variables.cluster_id
    )

    # Return our FSx/L ID for registration
    return str(scope.soca_resources[f"fs_{fs_key}"].ref)

def _storage_build_efs_filesystem(
    scope,
    fs_key: str,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
):
    """
    Build an EFS filesystem.
    """
    logger.debug(f"_storage_build_efs_filesystem called for {fs_key}")
    _kms_key_id: str = get_kms_key_id(
        config_key_names=[
            f"Config.storage.{fs_key}.kms_key_id",
            "Config.storage.kms_key_id",
        ],
        allow_global_default=True,
    )
    if _kms_key_id:
        logger.debug(f"EFS KMS for {fs_key}: {_kms_key_id}")

    scope.soca_resources[f"fs_{fs_key}"] = efs.CfnFileSystem(
        scope,
        id=f"EFS{fs_key.capitalize()}",
        encrypted=True,
        kms_key_id=_kms_key_id if _kms_key_id else "alias/aws/elasticfilesystem",
        throughput_mode=get_config_key(
            key_name=f"Config.storage.{fs_key}.efs.throughput_mode",
            required=False,
            expected_type=str,
            default="bursting",
        ),
        file_system_tags=[
            efs.CfnFileSystem.ElasticFileSystemTagProperty(
                key="edh:BackupPlan", value=user_specified_variables.cluster_id
            ),
            efs.CfnFileSystem.ElasticFileSystemTagProperty(
                key="Name",
                value=f"{user_specified_variables.cluster_id}-{fs_key.capitalize()}",
            ),
        ],
        lifecycle_policies=[
            efs.CfnFileSystem.LifecyclePolicyProperty(
                transition_to_ia=get_config_key(
                    key_name=f"Config.storage.{fs_key}.efs.transition_to_ia",
                    required=False,
                    expected_type=str,
                    default="AFTER_30_DAYS",
                )
            )
        ],
        performance_mode=get_config_key(
            key_name=f"Config.storage.{fs_key}.efs.performance_mode",
            required=False,
            expected_type=str,
            default="generalPurpose",
        ),
    )

    if (
        get_config_key(f"Config.storage.{fs_key}.efs.deletion_policy").upper()
        == "RETAIN"
    ):
        scope.soca_resources[f"fs_{fs_key}"].cfn_options.deletion_policy = (
            CfnDeletionPolicy.RETAIN
        )

    # Create the Security group for the filesystem
    scope.soca_resources[f"fs_{fs_key}_sg"] = (
        security_groups_helper.create_security_groups(
            scope=scope,
            construct_id=f"EFS{fs_key.capitalize()}SecurityGroup",
            vpc=scope.soca_resources["vpc"],
            allow_all_outbound=True,
            allow_all_ipv6_outbound=True,
            description=f"EFS {fs_key.capitalize()} Security Group",
        )
    )
    Tags.of(scope.soca_resources[f"fs_{fs_key}_sg"]).add(
        key="Name",
        value=f"{user_specified_variables.cluster_id}-EFS{fs_key.capitalize()}SG",
    )

    # Create our rules for each SG expected to consume the filesystem
    for _sg_peer in [
        "compute_node_sg",
        "vdi_node_sg",
        "controller_sg",
        "login_node_sg",
        "target_node_sg",
    ]:
        for _tcp_port in {2049}:
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources[f"fs_{fs_key}_sg"],
                peer=scope.soca_resources[_sg_peer],
                connection=ec2.Port.tcp(_tcp_port),
                description=f"Allow NFS from {_sg_peer}",
            )

    # Where do we need EFS mount points created?
    _efs_mount_subnets: list = []
    if not user_specified_variables.vpc_id:
        for _sn_id in [
            *scope.soca_resources["vpc"].isolated_subnets,
            *scope.soca_resources["vpc"].private_subnets,
        ]:
            if _sn_id.subnet_id not in _efs_mount_subnets:
                logger.debug(
                    f"Adding subnet for EFS mountpoint: {_sn_id.subnet_id}"
                )
                _efs_mount_subnets.append(_sn_id.subnet_id)

    else:
        # Existing subnets selected
        # Note - cannot include multiple subnets in a single AZ
        # TODO FIXME - deconflict the subnet/AZs
        # _subnets_for_efs_mounts: list = [*user_specified_variables.private_subnets, *user_specified_variables.public_subnets]
        _subnets_for_efs_mounts: list = [*user_specified_variables.private_subnets]

        logger.debug(
            f"Using existing subnets for EFS mountpoint: {_subnets_for_efs_mounts}"
        )
        for _sn_id in _subnets_for_efs_mounts:
            _exact_subnet_id = _sn_id.split(",")[0]
            if _exact_subnet_id not in _efs_mount_subnets:
                logger.debug(
                    f"Adding subnet for EFS mountpoint: {_exact_subnet_id}"
                )
                _efs_mount_subnets.append(_exact_subnet_id)

    # Complete list of subnets needing EFS mount points

    logger.debug(f"Creating EFS mount targets for {fs_key} - {_efs_mount_subnets}")

    for _i in range(len(_efs_mount_subnets)):
        logger.debug(
            f"Creating EFS mount target for {fs_key} - {_efs_mount_subnets[_i]}"
        )
        _efs_mt = efs.CfnMountTarget(
            scope,
            id=f"EFS{fs_key.capitalize()}MountTarget{_i + 1}",
            file_system_id=scope.soca_resources[f"fs_{fs_key}"].ref,
            security_groups=[
                scope.soca_resources[f"fs_{fs_key}_sg"].security_group_id,
            ],
            subnet_id=_efs_mount_subnets[_i],
        )
        # _efs_mt.node.add_dependency(
        #     scope.soca_resources[f"fs_{fs_key}"],
        #     scope.soca_resources[f"fs_{fs_key}_sg"],
        # )

    # Return our FS_ID for register process
    return str(scope.soca_resources[f"fs_{fs_key}"].attr_file_system_id)
