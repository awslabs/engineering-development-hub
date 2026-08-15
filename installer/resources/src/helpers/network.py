#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import (
    Tags,
    Fn,
    aws_ec2 as ec2,
    aws_route53resolver as route53resolver,
)

import sys

from helpers import (
    security_groups as security_groups_helper,
    boto3_wrapper as boto3_helper,
)
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# VPC/network, managed prefix lists, VPC endpoints

logger = logging.getLogger("soca_logger")


def network(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
):
    """
    Create a VPC with 3 public and 3 private subnets.
    To save IP space, public subnets have a smaller range compared to private subnets (where we deploy compute node)

    Example: vpc_cidr: 10.0.0.0/17 --> vpc_cidr_prefix_bits = 17
    public_subnet_mask_prefix_bits = 4
    private_subnet_mask_prefix_bits = 2
    public_subnet_mask = 17 + 4 = 21
    Added condition to reduce size of public_subnet_mask to a maximum of /26
    private_SubnetMask = 17 + 2 = 19
    """
    if not user_specified_variables.vpc_id:
        vpc_cidr_prefix_bits = user_specified_variables.vpc_cidr.split("/")[1]
        public_subnet_mask_prefix_bits = 4
        private_subnet_mask_prefix_bits = 2
        public_subnet_mask = int(vpc_cidr_prefix_bits) + int(
            public_subnet_mask_prefix_bits
        )
        if public_subnet_mask < 26:
            public_subnet_mask = 26
        private_subnet_mask = int(vpc_cidr_prefix_bits) + int(
            private_subnet_mask_prefix_bits
        )

        # Add IPv6 if enabled
        # TODO - Dynamically determine address-family / CIDR blocks that should be enabled in existing-VPC scenarios
        # e.g. Detect and enable IPv6 on existing resources / VPC mode
        # versus static config var

        if get_config_key(
            key_name="Config.feature_flags.Networking.EnableIPv6",
            expected_type=bool,
            required=False,
            default=False,
        ):
            logger.debug(
                "Enable IPv6 due to FeatureFlag setting (Config.feature_flags.Networking.EnableIPv6)"
            )
            if "ipv6" not in scope.networking_enabled_af:
                scope.networking_enabled_af.append("ipv6")

        vpc_params = {
            "ip_addresses": ec2.IpAddresses.cidr(user_specified_variables.vpc_cidr),
            "ip_protocol": (
                ec2.IpProtocol.DUAL_STACK
                if scope.is_networking_af_enabled(address_family="ipv6")
                else ec2.IpProtocol.IPV4_ONLY
            ),
            "nat_gateways": get_config_key(
                key_name="Config.network.nat_gateways", expected_type=int
            ),
            "enable_dns_support": True,
            "enable_dns_hostnames": True,
            "max_azs": get_config_key(
                key_name="Config.network.max_azs", expected_type=int
            ),
            "subnet_configuration": [
                ec2.SubnetConfiguration(
                    cidr_mask=public_subnet_mask,
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    map_public_ip_on_launch=False,  # Explicitly disable public IPv4 on public subnets for EC2 resources
                    ipv6_assign_address_on_creation=(
                        True
                        if scope.is_networking_af_enabled(address_family="ipv6")
                        else None
                    ),
                ),
                ec2.SubnetConfiguration(
                    cidr_mask=private_subnet_mask,
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    ipv6_assign_address_on_creation=(
                        True
                        if scope.is_networking_af_enabled(address_family="ipv6")
                        else None
                    ),
                ),
            ],
        }
        scope.soca_resources["vpc"] = ec2.Vpc(scope, "SOCAVpc", **vpc_params)
        Tags.of(scope.soca_resources["vpc"]).add(
            "Name", f"{user_specified_variables.cluster_id}-VPC"
        )

        #
        # TODO - Examples of Manually adding IPv6 via lower level CDK L1 constructs if customization is needed
        #
        # TODO - This section should be removed later if not needed and the L2s work out enough.
        #
        # if scope.is_networking_af_enabled(address_family="ipv6"):
        #     logger.debug(f"IPv6 is enabled -adding IPv6 CIDR block")
        #     scope.soca_resources["vpc_ipv6_block"] = ec2.CfnVPCCidrBlock(
        #         self,
        #         "SOCA-IPv6-VPC-CIDR",
        #         vpc_id=scope.soca_resources["vpc"].vpc_id,
        #         amazon_provided_ipv6_cidr_block=True,
        #     )
        #     Tags.of(scope.soca_resources["vpc_ipv6_block"]).add(
        #         "Name", f"{user_specified_variables.cluster_id}-VPC-CIDR-IPv6"
        #     )

        # Add an EIGW (Egress-Only IPv6 gateway)
        # logger.debug(f"Adding EIGW (IPv6)")
        # scope.soca_resources["eigw"] = ec2.CfnEgressOnlyInternetGateway(
        #     self,
        #     "SOCA-egress-igw",
        #     vpc_id=scope.soca_resources["vpc"].vpc_id
        # )
        # Tags.of(scope.soca_resources["eigw"]).add(
        #     "Name", f"{user_specified_variables.cluster_id}-EIGW"
        # )

        # Attach IPv6 to subnets and create an IPv6 default route going to the IGW or EIGW
        # logger.debug(f"Adding IPv6 to subnets")
        # _ipv6_sn_count: int = 0
        #
        # These are discrete loops over the subnets in case you want to adjust the options for public/private
        #
        # for subnet_info in scope.soca_resources["vpc"].public_subnets:
        #     logger.debug(f"Adding IPv6 to public subnet: {subnet_info.subnet_id}")
        #     _sn = subnet_info.node.default_child
        #     # Make sure to wait for the IPv6 CIDR to be stable
        #     _sn.node.add_dependency(scope.soca_resources["vpc_ipv6_block"])
        #     #_sn.node.add_dependency(scope.soca_resources["eigw"])
        #     _sn.ipv6_cidr_block = Fn.select(
        #         _ipv6_sn_count,
        #         Fn.cidr(
        #             Fn.select(0, scope.soca_resources["vpc"].vpc_ipv6_cidr_blocks),
        #             256,
        #             str(128 - 64),
        #         ),
        #     )
        #
        # Update our IPv6 default route for _public subnets_ to the IGW
        #
        # scope.soca_resources[f"ipv6_default_route_{_ipv6_sn_count}"] = ec2.CfnRoute(
        #     self,
        #     f"SOCA-IPv6-Default-Route_{_ipv6_sn_count}",
        #     destination_ipv6_cidr_block="::/0",
        #     route_table_id=subnet_info.route_table.route_table_id,
        #     gateway_id=scope.soca_resources["vpc"].internet_gateway_id,
        # )
        # _sn.assign_ipv6_address_on_creation = True
        # _ipv6_sn_count += 1

        # for subnet_info in scope.soca_resources["vpc"].private_subnets:
        #     logger.debug(f"Adding IPv6 to private subnet: {subnet_info.subnet_id}")
        #     _sn = subnet_info.node.default_child
        #     # Make sure to wait for the IPv6 CIDR to be stable
        #     _sn.node.add_dependency(scope.soca_resources["vpc_ipv6_block"])
        #     #_sn.node.add_dependency(scope.soca_resources["eigw"])
        #     _sn.ipv6_cidr_block = Fn.select(
        #         _ipv6_sn_count,
        #         Fn.cidr(
        #             Fn.select(0, scope.soca_resources["vpc"].vpc_ipv6_cidr_blocks),
        #             256,
        #             str(128 - 64),
        #         ),
        #     )
        #
        # Update our IPv6 default route for _private subnets_ to the EIGW
        #
        # scope.soca_resources[f"ipv6_default_route_{_ipv6_sn_count}"] = ec2.CfnRoute(
        #     self,
        #     f"SOCA-IPv6-Default-Route_{_ipv6_sn_count}",
        #     destination_ipv6_cidr_block="::/0",
        #     route_table_id=subnet_info.route_table.route_table_id,
        #     #egress_only_internet_gateway_id=scope.soca_resources["eigw"].ref,
        # )
        # _sn.assign_ipv6_address_on_creation = True
        # _ipv6_sn_count += 1

        #
        # Retrieve all NAT Gateways associated to the public subnets.
        #
        for subnet_info in scope.soca_resources["vpc"].public_subnets:
            logger.debug(
                f"NAT PROCESSING - processing {subnet_info=} / {type(subnet_info)}"
            )
            nat_eip_for_subnet = subnet_info.node.try_find_child("EIP")
            if nat_eip_for_subnet:
                logger.debug(
                    f"NAT PROCESSING - FOUND EIP - {nat_eip_for_subnet=} / Appending"
                )
                scope.soca_resources["nat_gateway_ips"].append(
                    nat_eip_for_subnet.attr_public_ip
                )

    else:
        logger.debug("Using existing VPC and subnets for connectivity")
        # Use existing VPC
        #
        # TODO - Dynamically detect if we should turn on IPv6 based on the existing resources
        # Perhaps the VPC info screen can save the enabled address-family for us for later?
        public_subnet_ids = []
        private_subnet_ids = []
        # Note: syntax is ["subnet1,az1","subnet2,az2" ....]
        for pub_subnet in user_specified_variables.public_subnets:
            logger.debug(f"Adding Public subnet: {pub_subnet}")
            public_subnet_ids.append(pub_subnet.split(",")[0])
        for priv_subnet in user_specified_variables.private_subnets:
            logger.debug(f"Adding Private subnet: {priv_subnet}")
            private_subnet_ids.append(priv_subnet.split(",")[0])

        logger.debug(
            f"Complete subnet listings:  Public: {public_subnet_ids} / Private: {private_subnet_ids}"
        )

        scope.soca_resources["vpc"] = ec2.Vpc.from_lookup(
            scope,
            "SOCAVpc",
            vpc_id=user_specified_variables.vpc_id,
        )

        # # Check the VPC for DNS support
        # logger.debug(f"VPC DNS Support: {scope.soca_resources['vpc'].dns_support_enabled}")
        # logger.debug(f"VPC DNS Hostname Support: {scope.soca_resources['vpc'].dns_hostnames_enabled}")
        #
        # if not scope.soca_resources["vpc"].dns_support_enabled or not scope.soca_resources["vpc"].dns_hostnames_enabled:
        #     logger.error(f"SOCA requires VPCs to have DNS and DNS hostname supported enabled. Update VPC ({user_specified_variables.vpc_id}) and try again. Unable to continue.")
        #     sys.exit(1)

        #
        # Retrieve all NAT Gateways associated to the public subnets of our existing VPC
        # TODO - do we already have an ec2_client built we can use here?

        ec2_client = boto3_helper.get_boto(
            service_name="ec2",
            profile_name=user_specified_variables.profile,
            region_name=user_specified_variables.region,
        )
        logger.debug("Probing NAT / EIP for egress ACL allowances ...")
        logger.debug(
            f"Processing Public subnet for NAT lookup: {public_subnet_ids}"
        )

        _nat_gw_pager = ec2_client.get_paginator("describe_nat_gateways")
        _nat_gw_iter = _nat_gw_pager.paginate(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [user_specified_variables.vpc_id],
                },
                {
                    "Name": "subnet-id",
                    "Values": [
                        _sn
                        for _subnet_list in [public_subnet_ids, private_subnet_ids]
                        for _sn in _subnet_list
                    ],
                },
            ]
        )

        # Are we looking for public or private NATs?
        _nat_is_public: bool = (
            True if user_specified_variables.deployment_mode == "public" else False
        )
        logger.debug(f"Looking for public NATs: {_nat_is_public}")

        for _page in _nat_gw_iter:
            for _nat_gw_info in _page.get("NatGateways", []):
                logger.debug(f"Existing NAT GW Info: {_nat_gw_info}")

                _nat_gw_id: str = _nat_gw_info.get("NatGatewayId", "")
                _nat_gw_state: str = _nat_gw_info.get("State", "")
                _nat_gw_type: str = _nat_gw_info.get("ConnectivityType", "")

                # Shouldn't need to check the VPC/subnet IDs since we use a filter for the query

                if not _nat_gw_id or not _nat_gw_state or not _nat_gw_type:
                    logger.debug(
                        f"Skipping NAT GW: {_nat_gw_info} due to missing ID, state, or type from API call"
                    )
                    continue

                if _nat_gw_state not in {"available"}:
                    logger.debug(
                        f"Skipping NAT GW: {_nat_gw_info} due to undesired state: {_nat_gw_state}"
                    )
                    continue

                for _addresses in _nat_gw_info.get("NatGatewayAddresses", ""):
                    logger.debug(f"Processing Address spec: {_addresses}")
                    _public_ip: str = _addresses.get("PublicIp", "")
                    _private_ip: str = _addresses.get("PrivateIp", "")
                    _ip_status: str = _addresses.get("Status", "")

                    # Only stable NATs are allowed
                    if _ip_status not in {"succeeded"}:
                        logger.debug(
                            f"Skipping NAT IP: {_addresses} due to undesired status: {_ip_status}"
                        )
                        continue

                    # Check the IPs
                    if not _private_ip:
                        logger.debug(
                            f"Found EIP: {_public_ip} and Private IP: {_private_ip} for NAT GW: {_nat_gw_info}"
                        )
                        continue

                    if _nat_is_public:
                        if _public_ip:
                            logger.debug(
                                f"Found Public NAT: {_public_ip} for NAT GW: {_nat_gw_info}"
                            )
                            if (
                                _public_ip
                                not in scope.soca_resources["nat_gateway_ips"]
                            ):
                                logger.debug(
                                    f"Adding Public EIP: {_public_ip} to list of NAT GW IPs"
                                )
                                scope.soca_resources["nat_gateway_ips"].append(
                                    _public_ip
                                )
                    else:
                        if _private_ip:
                            logger.debug(
                                f"Found Private NAT: {_private_ip} for NAT GW: {_nat_gw_info}"
                            )
                            if (
                                _private_ip
                                not in scope.soca_resources["nat_gateway_ips"]
                            ):
                                logger.debug(
                                    f"Adding Private IP: {_private_ip} to list of NAT GW IPs"
                                )
                                scope.soca_resources["nat_gateway_ips"].append(
                                    _private_ip
                                )

        logger.debug(
            f"Final list of NAT GW EIP/IPs: {scope.soca_resources['nat_gateway_ips']} / {_nat_is_public=}"
        )


def managed_prefix_lists(
    scope,
    *,
    user_specified_variables=None,
):
    """
    Create automatic Managed Prefix Lists (MPL) for various resources.
    These are later used in Security Groups (SG) to make updates easier.
    This feature is considered Early Access (EA) as of July 2025.
    """
    logger.debug("[PREVIEW] managed_prefix_lists() - Creating MPLs")

    _cluster_id: str = user_specified_variables.cluster_id.lower()

    # Our client-source MPL is used to determine originating clients
    # Previously this was a static entry in the SGs that could become entanged in NAT
    # layers or other items that made updates difficult.
    # With MPLs - the admin can simply update the MPL to include new remote client IP addresses.

    scope.managed_prefix_list_for_clients(cluster_id=_cluster_id)
    scope.managed_prefix_list_for_vpc(cluster_id=_cluster_id)


def create_vpc_endpoints(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
):
    """
    Create VPC Endpoints for accessing AWS services.
    """

    # If using an existing VPC first import any existing vpc endpoints
    if user_specified_variables.vpc_id:
        ec2_client = boto3_helper.get_boto(
            service_name="ec2",
            profile_name=user_specified_variables.profile,
            region_name=user_specified_variables.region,
        )
        filters = [{"Name": "vpc-id", "Values": [user_specified_variables.vpc_id]}]
        existing_security_groups = {}
        for page in ec2_client.get_paginator("describe_vpc_endpoints").paginate(
            Filters=filters
        ):
            for vpc_endpoint in page["VpcEndpoints"]:
                service_name = vpc_endpoint["ServiceName"]
                short_service_name = service_name.split(".")[-1]
                resource_name = short_service_name + "VpcEndpoint"
                security_groups = []
                for group in vpc_endpoint["Groups"]:
                    group_id = group["GroupId"]
                    security_group = existing_security_groups.get(group_id, None)
                    if not security_group:
                        group_name = group["GroupName"]
                        security_group = ec2.SecurityGroup.from_security_group_id(
                            scope, group_name, group_id
                        )
                        existing_security_groups[group_id] = security_group
                    security_groups.append(security_group)
                logger.debug(
                    f"Importing resource {resource_name} for {service_name} {short_service_name}"
                )

                if vpc_endpoint["VpcEndpointType"] == "Gateway":
                    scope.vpc_gateway_endpoints[short_service_name] = (
                        ec2.GatewayVpcEndpoint.from_gateway_vpc_endpoint_id(
                            scope,
                            resource_name,
                            gateway_vpc_endpoint_id=vpc_endpoint["VpcEndpointId"],
                        )
                    )
                elif vpc_endpoint["VpcEndpointType"] == "Interface":
                    scope.vpc_interface_endpoints[short_service_name] = (
                        ec2.InterfaceVpcEndpoint.from_interface_vpc_endpoint_attributes(
                            scope,
                            resource_name,
                            vpc_endpoint_id=vpc_endpoint["VpcEndpointId"],
                            security_groups=security_groups,
                            port=443,
                        )
                    )
                else:
                    logger.fatal(
                        f"Unknown VPC Endpoint Type: {vpc_endpoint['VpcEndpointType']}"
                    )
                    sys.exit(1)

    #
    # We have now collected all existing information if using an existing VPC
    #
    for short_service_name in get_config_key(
        key_name="Config.network.vpc_gateway_endpoints",
        expected_type=list,
        required=False,
        default=[],
    ):
        endpoint_service = ec2.GatewayVpcEndpointAwsService(short_service_name)
        if short_service_name in scope.vpc_gateway_endpoints:
            continue
        resource_name = f"{short_service_name}VpcEndpoint"
        logger.debug(
            f"Creating VPC Gateway Endpoint {resource_name} for {short_service_name}"
        )
        scope.vpc_gateway_endpoints[short_service_name] = scope.soca_resources[
            "vpc"
        ].add_gateway_endpoint(resource_name, service=endpoint_service)
        Tags.of(scope.vpc_gateway_endpoints[short_service_name]).add(
            key="Name",
            value=f"{user_specified_variables.cluster_id}-{short_service_name}",
        )

    #
    # These regions are special as they contain the IAM control-plane and represent
    # the only region in their partitions that can have a VPC Endpoint created for IAM.
    # Other regions must create arrangements via Transit Gateway or other methods.
    # See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_interface_vpc_endpoints.html#reference_iam_vpc_endpoint_create
    #
    _vpc_iam_control_plane_regions_list: list = [
        "us-east-1",
        "us-gov-west-1",
        "cn-north-1",
    ]

    for short_service_name in get_config_key(
        key_name="Config.network.vpc_interface_endpoints",
        expected_type=list,
        required=False,
        default=[],
    ):
        if short_service_name == "iam":
            if scope.region not in _vpc_iam_control_plane_regions_list:
                logger.info(
                    f"Skipping IAM VPC-Endpoint for non IAM Control Plane region (this is normal outside of the following regions: {', '.join(_vpc_iam_control_plane_regions_list)})"
                )
                continue
            endpoint_service = ec2.InterfaceVpcEndpointAwsService.IAM
        else:
            endpoint_service = ec2.InterfaceVpcEndpointAwsService(
                short_service_name
            )

        if short_service_name in scope.vpc_interface_endpoints:
            continue
        resource_name = f"{short_service_name}VpcEndpoint"
        logger.debug(
            f"Creating VPC Interface Endpoint {resource_name} for {short_service_name}"
        )

        scope.vpc_interface_endpoints[short_service_name] = ec2.InterfaceVpcEndpoint(
            scope,
            resource_name,
            vpc=scope.soca_resources["vpc"],
            service=endpoint_service,
            private_dns_enabled=True,
            ip_address_type=(
                ec2.VpcEndpointIpAddressType.DUALSTACK
                if scope.is_networking_af_enabled(address_family="ipv6")
                else ec2.VpcEndpointIpAddressType.IPV4
            ),
            dns_record_ip_type=(
                ec2.VpcEndpointDnsRecordIpType.DUALSTACK
                if scope.is_networking_af_enabled(address_family="ipv6")
                else ec2.VpcEndpointDnsRecordIpType.IPV4
            ),
            security_groups=[scope.soca_resources["vpc_endpoint_sg"]],
        )

        # Make sure the VPC-Endpoint gets a Name tag
        Tags.of(scope.vpc_interface_endpoints[short_service_name]).add(
            key="Name",
            value=f"{user_specified_variables.cluster_id}-{short_service_name}",
        )

    for short_service_name, vpc_endpoint in scope.vpc_interface_endpoints.items():
        # Ingress
        for _sg_peer_name in [
            "compute_node_sg",
            "vdi_node_sg",
            "controller_sg",
            "login_node_sg",
            "target_node_sg",
        ]:
            vpc_endpoint.connections.allow_from(
                scope.soca_resources[_sg_peer_name],
                ec2.Port.tcp(443),
                security_groups_helper.clamp_sg_description(
                    f"Allow HTTPS traffic to {short_service_name} endpoint from {_sg_peer_name}"
                ),
            )
    logger.debug("Completed VPC-Endpoints")


def aws_route53_resolver(
    scope,
    launch_subnets: list,
    dns_ip_addresses: list,
    *,
    user_specified_variables=None,
):
    """
    Create AWS Route53 resolver configurations for domain forwarding.
    """

    # Prepare a security group for the Route53 Resolver(outbound)
    _r53_security_group = security_groups_helper.create_security_groups(
        scope=scope,
        construct_id=f"{user_specified_variables.cluster_id}-route53-resolver",
        vpc=scope.soca_resources["vpc"],
        allow_all_outbound=False,
        allow_all_ipv6_outbound=False,
        description=f"{user_specified_variables.cluster_id} Route53 Resolver SG",
    )
    Tags.of(_r53_security_group).add(
        key="Name", value=f"{user_specified_variables.cluster_id}-Route53ResolverSG"
    )

    # Ingress to the Route53 SG
    for _sg_id in [
        "controller_sg",
        "compute_node_sg",
        "vdi_node_sg",
        "login_node_sg",
        "target_node_sg",
    ]:
        logger.debug(
            f"Adding ingress traffic for {_sg_id} to Route53 Outbound resolver SG"
        )

        for _proto in ("TCP", "UDP"):
            logger.debug(f"Adding {_proto} DNS {_sg_id} -> {_r53_security_group}")
            security_groups_helper.create_ingress_rule(
                security_group=_r53_security_group,
                peer=scope.soca_resources[_sg_id],
                connection=ec2.Port(
                    protocol=ec2.Protocol(_proto),
                    string_representation=f"{_proto} DNS",
                    from_port=53,
                    to_port=53,
                ),
                description=f"Allow {_sg_id} {_proto} DNS",
            )

    # After explicitly listing the cluster SGs, we also include the VPC CIDR range.
    # This allows for the cluster to work properly with the per-cluster SGs and this rule
    # to match any missed items. This rule could then be removed if it is considered
    # too broad by local security policy.

    # TODO - jasackle - This needs update for MPL mode

    for _proto in ("TCP", "UDP"):
        security_groups_helper.create_ingress_rule(
            security_group=_r53_security_group,
            peer=ec2.Peer.ipv4(scope.soca_resources["vpc"].vpc_cidr_block),
            connection=ec2.Port(
                protocol=ec2.Protocol(_proto),
                string_representation=f"VPC {_proto} DNS",
                from_port=53,
                to_port=53,
            ),
            description=f"Allow VPC CIDR {_proto} DNS",
        )

    # Egress from the Route53 SG - restricted to DNS traffic only
    for _address_family in ("ipv4", "ipv6"):
        logger.debug(f"Adding egress rule for address family: {_address_family}")
        for _proto in ("TCP", "UDP"):
            logger.debug(f"Adding egress rule - {_proto} DNS {_r53_security_group}")
            security_groups_helper.create_egress_rule(
                security_group=_r53_security_group,
                peer=(
                    ec2.Peer.any_ipv4()
                    if _address_family == "ipv4"
                    else ec2.Peer.any_ipv6()
                ),
                connection=ec2.Port(
                    protocol=ec2.Protocol(_proto),
                    string_representation=f"{_address_family}/{_proto} DNS",
                    from_port=53,
                    to_port=53,
                ),
                description=f"Allow {_address_family}/{_proto} DNS",
            )

    # Create DNS Forwarder. Requests sent to AD will be forwarded to AD DNS
    # Other requests will remain the same. Do not create custom DHCP Option Set otherwise resources such as FSx or EFS won't resolve
    resolver = route53resolver.CfnResolverEndpoint(
        scope,
        "ADRoute53OutboundResolver",
        direction="OUTBOUND",
        name=user_specified_variables.cluster_id,
        ip_addresses=[
            route53resolver.CfnResolverEndpoint.IpAddressRequestProperty(
                subnet_id=launch_subnets[0]
            ),
            route53resolver.CfnResolverEndpoint.IpAddressRequestProperty(
                subnet_id=launch_subnets[1]
            ),
        ],
        security_group_ids=[_r53_security_group.security_group_id],
    )

    resolver_rule = route53resolver.CfnResolverRule(
        scope,
        "ADRoute53OutboundResolverRule",
        name=user_specified_variables.cluster_id,
        domain_name=scope.directory_service_resource_setup.get("domain_name"),
        rule_type="FORWARD",
        resolver_endpoint_id=resolver.attr_resolver_endpoint_id,
        target_ips=[
            route53resolver.CfnResolverRule.TargetAddressProperty(
                ip=Fn.select(
                    0,
                    dns_ip_addresses,
                ),
                port="53",
            ),
            route53resolver.CfnResolverRule.TargetAddressProperty(
                ip=Fn.select(
                    1,
                    dns_ip_addresses,
                ),
                port="53",
            ),
        ],
    )

    route53resolver.CfnResolverRuleAssociation(
        scope,
        "ADRoute53ResolverRuleAssociation",
        resolver_rule_id=resolver_rule.attr_resolver_rule_id,
        vpc_id=scope.soca_resources["vpc"].vpc_id,
    )
