#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import (
    Tags,
    Aws,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_opensearchservice as opensearch,
    aws_iam as iam,
    aws_kms as kms,
    Annotations,
)

import sys

from helpers import (
    security_groups as security_groups_helper,
    boto3_wrapper as boto3_helper,
)
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# Provisioned OpenSearch analytics domain

logger = logging.getLogger("soca_logger")


def analytics_opensearch(
    scope,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    return_ebs_volume_type=None,
    get_service_principal_url_suffix=None,
):
    """
    Create OpenSearch cluster.
    """

    _opensearch_client = boto3_helper.get_boto(
        service_name="opensearch",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )
    logger.debug(f"OpenSearch query client: {_opensearch_client=}")

    sanitized_domain: str = user_specified_variables.cluster_id.lower()

    _data_node_instance_types: list = get_config_key(
        key_name="Config.analytics.data_node_instance_type",
        expected_type=list,
        required=False,
        default=[
            "m8g.large.search",
            "m7g.large.search",
            "m6g.large.search",
            "t3.medium.search",
            "t3.small.search",
        ],
    )

    logger.debug(
        f"OpenSearch Data_node instance_type: {_data_node_instance_types=}"
    )

    # _data_nodes supports automatic based on the AZ count
    _data_nodes: int = get_config_key(
        key_name="Config.analytics.data_nodes",
        expected_type=int,
        required=False,
        default=0,
    )
    _volume_size: int = get_config_key(
        key_name="Config.analytics.ebs_volume_size",
        expected_type=int,
    )
    _deletion_policy: str = get_config_key(
        key_name="Config.analytics.deletion_policy",
        expected_type=str,
    ).upper()
    _desired_engine: str = get_config_key(
        key_name="Config.analytics.engine",
        required=False,
        default="opensearch",
        expected_type=str,
    ).lower()

    _desired_engine_version: str = get_config_key(
        key_name="Config.analytics.engine_version",
        required=False,
        expected_type=str,
        default="3.3",
    )

    # Build an OpenSearch version string
    # This allows:
    # 1. Query for the supported version in the region
    # 2. Query for supported instance types (data_node_types) in the region
    #
    # FIXME TODO / What about ElasticSearch engine types? (Unsupported?)
    _engine_string: str = (
        _desired_engine.lower().replace("opensearch", "OpenSearch")
        + f"_{_desired_engine_version}"
    )
    logger.debug(
        f"OpenSearch engine string (for region validation): {_engine_string=}"
    )

    # Not paginated as of 3 Mar 2026
    _all_versions_available: list = _opensearch_client.list_versions().get(
        "Versions", []
    )

    # Did we get any responses?
    if not len(_all_versions_available):
        logger.fatal(
            f"Unable to probe Analytics engines for region: {user_specified_variables.region}"
        )
        sys.exit(1)

    # Is this version available in this region?
    if _engine_string not in _all_versions_available:
        logger.fatal(
            f"Analytics version {_engine_string} not available in region {user_specified_variables.region}. Engines available: {', '.join(_all_versions_available)}"
        )
        sys.exit(1)

    # Now that we have a _engine_string , lets see if our desired instance type is available for that engine.
    # We don't use a paginated operation here because we are sending an InstanceType and only expect a single
    # response.

    logger.debug(
        f"Validating Instance type {_data_node_instance_types} is available on engine {_engine_string}"
    )

    _selected_instance_type: str = scope.select_best_instance_for_opensearch(
        opensearch_client=_opensearch_client,
        opensearch_engine=_engine_string,
        instance_types=_data_node_instance_types,
        instance_role="data",
        region=user_specified_variables.region,
    )

    logger.debug(
        f"Selected best available instance type for OpenSearch: {_selected_instance_type=}"
    )

    if not user_specified_variables.os_endpoint:
        logger.debug(
            f"OpenSearch subnet selection: VPC public subnets: {scope.soca_resources['vpc'].public_subnets} (only for new VPC)"
        )
        logger.debug(
            f"OpenSearch subnet selection: VPC private subnets: {scope.soca_resources['vpc'].private_subnets} (only for new VPC)"
        )
        logger.debug(
            f"OpenSearch User Spec Pub subnets: {user_specified_variables.public_subnets} (only for Existing VPC)"
        )
        logger.debug(
            f"OpenSearch User Spec Priv subnets: {user_specified_variables.private_subnets} (only for Existing VPC)"
        )

        # OpenSearch should always be deployed in private subnets in a given VPC (new or existing)

        _opensearch_isubnets_list: list = []
        _opensearch_subnet_num: int = 1

        if user_specified_variables.private_subnets:
            # Existing VPC/resources
            logger.debug("Using Existing Resources (VPC) for OpenSearch")

            for _sn in user_specified_variables.private_subnets:
                logger.debug(
                    f"Adding Private subnet entry #{_opensearch_subnet_num} to OpenSearch ISubnet list: {_sn=}"
                )
                # user_specified_variables.private_subnets (when using existing VPC) look like this:
                # ['subnet-123,us-east-1a', 'subnet-456,us-east-1b']
                _sn_subnet_id: str = _sn.split(",")[0]
                _sn_subnet_az: str = _sn.split(",")[1]

                # We have to use .from_subnet_attributes() here since future calls require the availability_zone
                # be attached to the internal CDK subnet object. This doesn't take place when importing existing subnets
                # using the .from_subnet_id() call
                _sn_isubnet = ec2.Subnet.from_subnet_attributes(
                    scope,
                    f"OpenSearchSubnet{_opensearch_subnet_num}",
                    subnet_id=_sn_subnet_id,
                    availability_zone=_sn_subnet_az,
                )

                # Make sure to CDK Ack
                Annotations.of(_sn_isubnet).acknowledge_warning(
                    id="@aws-cdk/aws-ec2:noSubnetRouteTableId",
                    message="RouteTableId will not be processed",
                )
                _opensearch_isubnets_list.append(_sn_isubnet)

                _opensearch_subnet_num += 1
        else:
            # New VPC / resources
            logger.debug("Creating a new OpenSearch cluster/new VPC")

            if not scope.soca_resources["vpc"].private_subnets:
                logger.fatal(
                    "Unable to continue - Private Subnets are empty for OpenSearch! Bug?"
                )
                sys.exit(1)

            for _sn in scope.soca_resources["vpc"].private_subnets:
                logger.debug(
                    f"Adding Private subnet entry #{_opensearch_subnet_num} to OpenSearch ISubnet list: {_sn=}"
                )
                # They are already ISubnets , so we just append
                _opensearch_isubnets_list.append(_sn)
                _opensearch_subnet_num += 1

        logger.debug(
            f"Final ISubnets for OpenSearch ({len(_opensearch_isubnets_list)}): {_opensearch_isubnets_list}"
        )
        if len(_opensearch_isubnets_list) <= 1:
            logger.fatal("Unable to continue - OpenSearch ISubnets list is <= 1")
            sys.exit(1)

        # OpenSearch can be 1-3 AZ deployment
        # so take the min of 3 or the subnet listings size (new or existing)
        # Data nodes must then be a min of the subnet_count as well

        es_zone_awareness = opensearch.ZoneAwarenessConfig(
            availability_zone_count=min(3, len(_opensearch_isubnets_list)),
            enabled=True,
        )

        _min_data_node_value: int = max(_data_nodes, len(_opensearch_isubnets_list))
        logger.debug(
            f"Min OpenSearch data nodes: {_min_data_node_value=} ( max(_data_nodes, subnet_list) method)"
        )

        # TODO FIXME - Should this auto-update or fail loudly as it could impact the cost modeling?
        if not _data_nodes:
            logger.info(
                f"Updated OpenSearch data-nodes to {_min_data_node_value} due to automatic setting in configuration file"
            )
            _data_nodes = _min_data_node_value
        elif _data_nodes < _min_data_node_value:
            logger.warning(
                f"Updating Data nodes to {_min_data_node_value} due to OpenSearch requirements (data_nodes >= AZs)"
            )
            _data_nodes = _min_data_node_value
        elif _data_nodes > 1000:
            logger.fatal(
                f"OpenSearch data node cluster size is too large! ({_data_nodes=} > 1000)"
            )
            sys.exit(1)
        elif _data_nodes > 200:
            logger.warning(
                "OpenSearch cluster larger than 200 data nodes requires AWS Service Quota increase - Make sure this is already completed!"
            )

        logger.debug(f"Final data nodes selection: {_data_nodes}")

        #
        # Create the SG for the Analytics cluster
        # This happens here versus the security group area in case analytics is disabled.
        scope.soca_resources["os_sg"] = (
            security_groups_helper.create_security_groups(
                scope=scope,
                construct_id="OpenSearchSecurityGroup",
                vpc=scope.soca_resources["vpc"],
                allow_all_outbound=True,
                allow_all_ipv6_outbound=(
                    True
                    if scope.is_networking_af_enabled(address_family="ipv6")
                    else False
                ),
                description="OpenSearch Analytics Security Group",
            )
        )

        Tags.of(scope.soca_resources["os_sg"]).add(
            "Name", f"{user_specified_variables.cluster_id}-OpenSearchSG"
        )

        # Allow nodes to analytics SG

        for _sg_peer_name in [
            "controller_sg",
            "compute_node_sg",
            "vdi_node_sg",
            "login_node_sg",
            "target_node_sg",
        ]:
            logger.debug(f"Allowing {_sg_peer_name} to access OpenSearch Analytics")
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["os_sg"],
                peer=scope.soca_resources[_sg_peer_name],
                connection=ec2.Port.tcp(443),
                description=f"Allow OpenSearch from {_sg_peer_name}",
            )

        _kms_key_id: str = get_kms_key_id(
            config_key_names=[
                "Config.analytics.kms_key_id",  # Current configuration parameter
            ],
            allow_global_default=True,
        )

        # FIXME TODO - Not all volume types may work with OpenSearch
        # They should be sanity checked
        _volume_type = return_ebs_volume_type(
            volume_string=get_config_key(
                key_name="Config.analytics.volume_type",
                required=False,
                default="gp3",
                expected_type=str,
            ).lower()
        )

        scope.soca_resources["os_domain"] = opensearch.Domain(
            scope,
            "OpenSearch",
            domain_name=sanitized_domain,
            ip_address_type=(
                opensearch.IpAddressType.DUAL_STACK
                if scope.is_networking_af_enabled(address_family="ipv6")
                else opensearch.IpAddressType.IPV4
            ),
            enforce_https=True,
            node_to_node_encryption=True,
            tls_security_policy=opensearch.TLSSecurityPolicy.TLS_1_2,
            version=opensearch.EngineVersion.open_search(_desired_engine_version),
            encryption_at_rest=opensearch.EncryptionAtRestOptions(
                enabled=True,
                kms_key=(
                    kms.Key.from_key_arn(
                        scope, id="OpenSearchKMS", key_arn=_kms_key_id
                    )
                    if _kms_key_id
                    else None
                ),
            ),
            ebs=opensearch.EbsOptions(
                volume_size=_volume_size,
                volume_type=_volume_type,
            ),
            capacity=opensearch.CapacityConfig(
                data_node_instance_type=_selected_instance_type,
                data_nodes=_data_nodes,
            ),
            automated_snapshot_start_hour=0,
            removal_policy=(
                RemovalPolicy.RETAIN
                if _deletion_policy == "RETAIN"
                else RemovalPolicy.DESTROY
            ),
            access_policies=[
                iam.PolicyStatement(
                    principals=[iam.AnyPrincipal()],
                    actions=["es:ESHttp*"],
                    resources=[
                        f"arn:{Aws.PARTITION}:es:{Aws.REGION}:{Aws.ACCOUNT_ID}:domain/{sanitized_domain}/*"
                    ],
                )
            ],
            advanced_options={"rest.action.multi.allow_explicit_index": "true"},
            security_groups=[scope.soca_resources["os_sg"]],
            zone_awareness=es_zone_awareness if _data_nodes > 1 else None,
            vpc=scope.soca_resources["vpc"],
            vpc_subnets=[ec2.SubnetSelection(subnets=_opensearch_isubnets_list)],
        )

        if user_specified_variables.create_es_service_role:
            service_linked_role = iam.CfnServiceLinkedRole(
                scope,
                "AOSSServiceLinkedRole",
                aws_service_name=f"opensearchservice.{get_service_principal_url_suffix()}",
                description="Role for AOSS to access resources in the VPC",
            )

            # When creating the SLR - it should be set to RETAIN to decouple it from the Stack
            service_linked_role.apply_removal_policy(RemovalPolicy.RETAIN)

            scope.soca_resources["os_domain"].node.add_dependency(
                service_linked_role,
                scope.soca_resources["os_sg"],
            )
