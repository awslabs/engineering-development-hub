#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import Tags, aws_ec2 as ec2, Annotations, Fn

import sys

from helpers import (
    security_groups as security_groups_helper,
    database as database_helper,
)
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# Cluster security-group orchestration (uses helpers/security_groups primitives)

logger = logging.getLogger("soca_logger")


def security_groups(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
):
    """
    Create security groups (or re-use existing ones).
    """

    # Determine if we are in MPL mode.
    # MPL mode will create/use Managed Prefix Lists (MPL) instead of the raw CIDRs
    # This max future updates much easier to the VPC.
    # Resolved once by the construct: config flag AND deploy-identity has MPL create permission.
    _mpl: bool = scope._auto_mpl_enabled()
    logger.debug(f"MPL mode: {_mpl}")

    _vpc_peer_by_af: dict = {
        #
        # IPv4 is a requirement for now (July 2025)
        # So we always start with IP_V4 in the dict
        "IP_V4": {
            "enabled": True,
            # Eventually if we want it to be a toggle
            # "enabled": get_config_key(
            #     key_name="Config.feature_flags.Networking.EnableIPv4",
            #     expected_type=bool,
            #     required=False,
            #     default=True
            # ),
            "peer": {
                "any": ec2.Peer.any_ipv4(),
                "vpc": ec2.Peer,
                "client": [
                    ec2.Peer.ipv4(_client_ip)
                    for _client_ip in user_specified_variables.client_ip
                ],
                "prefix_list": (
                    ec2.Peer.prefix_list(user_specified_variables.prefix_list_id)
                    if user_specified_variables.prefix_list_id
                    else None
                ),
            },
        },
    }

    _is_ipv6_enabled: bool = get_config_key(
        key_name="Config.feature_flags.Networking.EnableIPv6",
        expected_type=bool,
        required=False,
        default=False,
    )

    if _is_ipv6_enabled:
        _vpc_peer_by_af["IP_V6"] = {
            "enabled": get_config_key(
                key_name="Config.feature_flags.Networking.EnableIPv6",
                expected_type=bool,
                required=False,
                default=False,
            ),
            "peer": {
                "any": ec2.Peer.any_ipv6(),
                "vpc": ec2.Peer,
                "client": [
                    ec2.Peer.ipv6(_client_ip)
                    for _client_ip in user_specified_variables.client_ipv6
                ],
                "prefix_list": (
                    ec2.Peer.prefix_list(user_specified_variables.prefix_list_id_ipv6)
                    if scope.is_networking_af_enabled(address_family="ipv6")
                    and user_specified_variables.prefix_list_id_ipv6
                    else None
                ),
            },
        }

    # If we are in MPL mode - we replace some peer objs
    if _mpl:
        logger.debug("MPL Enabled")
        for _af, _af_config in _vpc_peer_by_af.items():
            _vpc_af_enabled = _af_config.get(
                "enabled", False
            )  # If we don't explicitly see enabled, assume Disabled
            if not _vpc_af_enabled:
                logger.debug(f"Skipping {_af} - not explicitly enabled")
                continue
            else:
                logger.debug(f"Address-family {_af} is enabled.")

            # Grab the MPL that we have created for the address-family
            _vpc_af_mpl = scope.soca_resources.get(f"vpc_mpl_{_af}", None)

            if not _vpc_af_mpl:
                # TODO - This may be OK if IPv6 is disabled?
                # Only .fatal on IPv4?
                logger.fatal(
                    f"Error determining VPC Peer MPL with MPL mode enabled for address-family {_af}. Possible Bug? Unable to continue"
                )
                sys.exit(1)
            else:
                logger.debug(f"VPC AF MPL found: {_af=} MPL: {_vpc_af_mpl=}")

            _vpc_peer_by_af[_af]["peer"]["vpc"] = ec2.Peer.prefix_list(
                _vpc_af_mpl.prefix_list_id
            )

            # Grab our clients MPL and replace the client object
            _clients_af_mpl = scope.soca_resources.get(f"clients_mpl_{_af}", None)
            if not _clients_af_mpl and _af == "IP_V4":
                # TODO - This may be OK if IPv6 is disabled?
                # Only .fatal on IPv4?
                logger.fatal(
                    f"Error determining Clients Peer MPL with MPL mode enabled for address-family {_af}. Possible Bug? Unable to continue"
                )
                sys.exit(1)
            else:
                logger.debug(f"Clients AF MPL found: {_af=} MPL: {_clients_af_mpl=}")

            # Keep client as a list so the existing per-client ingress loops apply the MPL peer
            _vpc_peer_by_af[_af]["peer"]["client"] = (
                [ec2.Peer.prefix_list(_clients_af_mpl.prefix_list_id)]
                if _clients_af_mpl
                else []
            )

    else:
        #
        # Non-MPL mode (classic VPC CIDR)
        # Main restriction is that this does not accomodate multiple CIDRs per VPC
        #
        logger.debug("Non-MPL mode - obtain the VPC CIDR")

        _vpc_peer_by_af["IP_V4"]["peer"]["vpc"]: ec2.IPeer = ec2.Peer.ipv4(
            scope.soca_resources["vpc"].vpc_cidr_block
        )
        # Non-MPL IPv6: use the VPC's first IPv6 CIDR block (single-CIDR only; MPL mode handles multi-CIDR)
        if scope.is_networking_af_enabled(address_family="ipv6"):
            _vpc_peer_by_af["IP_V6"]["peer"]["vpc"]: ec2.IPeer = ec2.Peer.ipv6(
                Fn.select(0, scope.soca_resources["vpc"].vpc_ipv6_cidr_blocks)
            )

    logger.debug(f"Using a VPC Peer by AF of {_vpc_peer_by_af=}")

    # These represent the base template Security Groups (SG)
    # SGs are multi address-family (AF) aware. So they are not created as a discrete SG per address-family.
    # The _rules_ have the address-family as we add them. Rules can be address-family agnostic as well (e.g. TCP/22 - any address-family)
    _security_groups: dict = {
        "compute_node_sg": {
            "name": f"{user_specified_variables.cluster_id}-ComputeNodeSG",
            "description": "Security Group used for all compute nodes",
            "existing_security_group_id": (
                user_specified_variables.compute_node_sg
                if user_specified_variables.compute_node_sg
                else None
            ),
            "allow_all_outbound": False,
            "allow_all_ipv6_outbound": False,
        },
        "vdi_node_sg": {
            "name": f"{user_specified_variables.cluster_id}-VdiNodeSG",
            "description": "Security Group used for all VDI (eVDI/DCV) nodes",
            "existing_security_group_id": (
                user_specified_variables.vdi_node_sg
                if getattr(user_specified_variables, "vdi_node_sg", None)
                else None
            ),
            "allow_all_outbound": False,
            "allow_all_ipv6_outbound": False,
        },
        "target_node_sg": {
            "name": f"{user_specified_variables.cluster_id}-TargetNodeSG",
            "description": "Security Group used for all target nodes",
            "existing_security_group_id": None,
            # Target nodes are the most permissive plane by design (wide ingress from
            # compute/login/controller/VPC). Egress must be open too: allow_all_outbound
            # =False left only CDK's unreachable "disallow all" sentinel (ICMP 252/86 ->
            # 255.255.255.255/32) as the sole egress rule, with no real egress. (V1942340926)
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "alb_sg": {
            "name": f"{user_specified_variables.cluster_id}-ALBFrontendSG",
            "description": "Security Group used by ALB frontend",
            "existing_security_group_id": (
                user_specified_variables.alb_sg
                if user_specified_variables.alb_sg
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "nlb_sg": {
            "name": f"{user_specified_variables.cluster_id}-NLBSG",
            "description": "Security Group used by NLB",
            "existing_security_group_id": (
                user_specified_variables.nlb_sg
                if user_specified_variables.nlb_sg
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "dcv_frontend_nlb_sg": {
            "name": f"{user_specified_variables.cluster_id}-DCVFrontendNLBSG",
            "description": (
                "Security Group used by the DCV Frontend NLB "
                "(client-facing). Replaces the dev-time placeholder of "
                "ComputeNodeSG."
            ),
            "existing_security_group_id": (
                user_specified_variables.dcv_frontend_nlb_sg
                if getattr(
                    user_specified_variables, "dcv_frontend_nlb_sg", None
                )
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "dcv_backend_nlb_sg": {
            "name": f"{user_specified_variables.cluster_id}-DCVBackendNLBSG",
            "description": (
                "Security Group used by the DCV Backend NLB "
                "(intra-VPC: gateway to broker, agent to broker). "
                "Replaces the dev-time placeholder of ComputeNodeSG."
            ),
            "existing_security_group_id": (
                user_specified_variables.dcv_backend_nlb_sg
                if getattr(
                    user_specified_variables, "dcv_backend_nlb_sg", None
                )
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "dcv_screenshot_lambda_sg": {
            "name": f"{user_specified_variables.cluster_id}-DCVScreenshotLambdaSG",
            "description": "Security Group used by DcvScreenshotPoller Lambda",
            "existing_security_group_id": (
                user_specified_variables.dcv_screenshot_lambda_sg
                if getattr(
                    user_specified_variables, "dcv_screenshot_lambda_sg", None
                )
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "dcv_event_relay_lambda_sg": {
            "name": f"{user_specified_variables.cluster_id}-DCVEventRelayLambdaSG",
            "description": "Security Group used by DcvEventRelay Lambda",
            "existing_security_group_id": (
                user_specified_variables.dcv_event_relay_lambda_sg
                if getattr(
                    user_specified_variables, "dcv_event_relay_lambda_sg", None
                )
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "ssm_config_sync_lambda_sg": {
            "name": f"{user_specified_variables.cluster_id}-SsmConfigSyncLambdaSG",
            "description": "Security Group used by SsmConfigSync Lambda",
            "existing_security_group_id": (
                user_specified_variables.ssm_config_sync_lambda_sg
                if getattr(
                    user_specified_variables, "ssm_config_sync_lambda_sg", None
                )
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "controller_sg": {
            "name": f"{user_specified_variables.cluster_id}-ControllerSG",
            "description": "Security Group used by Controller node",
            "existing_security_group_id": (
                user_specified_variables.controller_sg
                if user_specified_variables.controller_sg
                else None
            ),
            "allow_all_outbound": False,
            "allow_all_ipv6_outbound": False,
        },
        "login_node_sg": {
            "name": f"{user_specified_variables.cluster_id}-LoginNodeSG",
            "description": "Security Group used by Login node",
            "existing_security_group_id": (
                user_specified_variables.login_node_sg
                if user_specified_variables.login_node_sg
                else None
            ),
            "allow_all_outbound": False,
            "allow_all_ipv6_outbound": False,
        },
        "vpc_endpoint_sg": {
            "name": f"{user_specified_variables.cluster_id}-VPCEndpointSG",
            "description": "Security Group used by VPC Endpoints",
            "existing_security_group_id": (
                user_specified_variables.vpc_endpoint_sg
                if user_specified_variables.vpc_endpoint_sg
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "elasticache_sg": {
            "name": f"{user_specified_variables.cluster_id}-ElastiCacheSG",
            "description": "Security Group used by ElastiCache",
            "existing_security_group_id": (
                user_specified_variables.elasticache_sg
                if user_specified_variables.elasticache_sg
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
        "database_sg": {
            "name": f"{user_specified_variables.cluster_id}-DatabaseSG",
            "description": "Security Group used by the SOCA database",
            "existing_security_group_id": (
                user_specified_variables.database_sg
                if getattr(user_specified_variables, "database_sg", None)
                else None
            ),
            "allow_all_outbound": True,
            "allow_all_ipv6_outbound": True,
        },
    }

    # This can be a bit noisy for here
    # logger.debug(f"User spec vars: {user_specified_variables}")

    if get_config_key(
        key_name="Config.dcv.high_scale",
        expected_type=bool,
        required=False,
        default=False,
    ):
        logger.debug("DCV High Scale SG skeleton creation ..")
        for _dcv_host_type in ("broker", "gateway"):
            logger.debug(f"DCV High Scale SG skeleton for {_dcv_host_type}..")
            _security_groups[f"dcv_{_dcv_host_type}_sg"] = {
                "name": f"{user_specified_variables.cluster_id}-{_dcv_host_type}_sg",
                "description": f"Security Group for {_dcv_host_type}",
                "existing_security_group_id": get_config_key(
                    key_name=f"Config.dcv.{_dcv_host_type}.security_group_id",
                    required=False,
                    expected_type=str,
                    default=None,
                ),
                "allow_all_outbound": True,
                "allow_all_ipv6_outbound": True,
            }

    using_existing_sgs = False
    #
    # Now create the Security Group stubs
    #
    for _sg_idx, sg_data in _security_groups.items():

        # _sg_idx - the Index name for finding the template SG in config data structures e.g. login_node_sg
        # _sg_name - same as _sg_idx for now
        # _sg_full_name - The full name (AWS Name tag) of the SG. Cluster aware E.g. soca-clust1-fooSG

        # Yes, this dupes the string - but we may want to influence it later
        sg_name: str = f"{_sg_idx}"
        _sg_full_name: str = f"{sg_data.get('name', 'NoName')}"  # soca-foo-sg

        # Enter our per-address family for loop
        # While the SG is automatically multi-address-family, we have some objects that need to be resolved on a per-AF basis.

        if sg_data.get("existing_security_group_id", ""):
            scope.soca_resources[sg_name] = (
                security_groups_helper.use_existing_security_group(
                    scope=scope,
                    construct_id=sg_data["name"],
                    security_group_id=sg_data["existing_security_group_id"],
                )
            )
            using_existing_sgs = True
        else:
            # Create a new SG stub in our structure
            logger.debug(f"Creating resource structure for SG at {sg_name=}")
            scope.soca_resources[sg_name] = (
                security_groups_helper.create_security_groups(
                    scope=scope,
                    construct_id=_sg_full_name,
                    vpc=scope.soca_resources["vpc"],
                    allow_all_outbound=sg_data.get("allow_all_outbound", True),
                    allow_all_ipv6_outbound=(
                        sg_data.get("allow_all_ipv6_outbound", False)
                        if scope.is_networking_af_enabled(address_family="ipv6")
                        else False
                    ),
                    description=f"{sg_data.get('description', 'NoDescr')}",
                )
            )

        # FIXME TODO - CDK ACK
        # This doesn't appear to be working properly
        logger.debug(
            f"CDK ACK @aws-cdk/aws-ec2:ipv4IgnoreEgressRule for {sg_name=}"
        )
        Annotations.of(scope.soca_resources[sg_name]).acknowledge_warning(
            id="@aws-cdk/aws-ec2:ipv4IgnoreEgressRule",
            message="IPv4 Egress traffic to be defined",
        )
        # This doesn't need to be protected with an IPv6 guard
        Annotations.of(scope.soca_resources[sg_name]).acknowledge_warning(
            id="@aws-cdk/aws-ec2:ipv6IgnoreEgressRule",
            message="IPv6 Egress traffic to be defined",
        )

        # Set Friendly Name tag and don't use the one generated by CDK
        Tags.of(scope.soca_resources[sg_name]).add(key="Name", value=_sg_full_name)

    logger.debug("All SG placeholders have been created")
    # POPULATE SECURITY GROUP RULES
    # This must take place _AFTER_ all the SGs are created as some SGs reference other SGs by object IDs.
    # This must take place within an address-family for loop for _peer resolution of the ec2.Peer objects

    for _af, _af_config in _vpc_peer_by_af.items():
        logger.debug(f"Creating SGs for {_af} from {_af_config=}")
        # Is this address-family enabled?
        _vpc_af_is_enabled: bool = _af_config.get("enabled", False)

        if not _vpc_af_is_enabled:
            # This can be .debug() for now
            logger.debug(
                f"Skipping Address-family {_af=} for SGs - not enabled (see FeatureFlags.Networking)"
            )
            continue

        # A suffix for our SGs (Name tags, etc.)
        _sg_suffix_formal: str = "IPv6" if _af == "IP_V6" else "IPv4"
        _sg_suffix: str = _sg_suffix_formal.lower()

        #
        # Validate we have peer entries for this address-family
        # These represent address-family specific constructs so we look them up in our dict within our AF loop
        # to be used in the future
        #
        _peers: dict = {
            "any": _vpc_peer_by_af.get(_af, {}).get("peer", {}).get("any", None),
            "client": _vpc_peer_by_af.get(_af, {})
            .get("peer", {})
            .get("client", None),
            "vpc": _vpc_peer_by_af.get(_af, {}).get("peer", {}).get("vpc", None),
            "prefix_list": _vpc_peer_by_af.get(_af, {})
            .get("peer", {})
            .get("prefix_list", None),
        }

        # Sanity check that we have proper peers
        for _p_name, _p_data in _peers.items():
            logger.debug(f"Peer {_p_name=} is {_p_data=}")
            # Some are optional
            if not _p_data and _p_name not in {"prefix_list"}:
                # Only .fatal for ipv4?
                logger.fatal(f"Peer failed for {_p_name=}")
                sys.exit(1)

        #
        ## LOGIN from the customer IP
        #
        _login_node_ssh_front_port: int = get_config_key(
            key_name="Config.login_node.security.ssh_frontend_port",
            expected_type=int,
            default=22,
            required=False,
        )

        _login_node_ssh_back_port: int = get_config_key(
            key_name="Config.login_node.security.ssh_backend_port",
            expected_type=int,
            default=22,
            required=False,
        )

        logger.debug(
            f"Configuring LoginNode SG with SSH ports:  FrontEnd: {_login_node_ssh_front_port} / BackEnd: {_login_node_ssh_back_port}"
        )

        # A little extra logging here as it is the first set of rules
        # So any breakage would be seen here first
        logger.debug(f"LoginNode SG: {scope.soca_resources['login_node_sg']}")
        logger.debug(f"_Peers Any: {_peers.get('any')}")
        logger.debug(f"_Peers Client: {_peers.get('client')}")
        logger.debug(f"_Peers VPC: {_peers.get('vpc')}")

        if isinstance(_peers.get("client"), list):
            # Multiple --client-ip are supported so this is a list of peer objs
            for _c in _peers.get("client"):
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["login_node_sg"],
                    peer=_c,
                    connection=ec2.Port.tcp(_login_node_ssh_front_port),
                    description=f"Allow SSH access from client-IP ({_sg_suffix_formal})",
                )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["login_node_sg"],
            peer=scope.soca_resources["target_node_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from Target Nodes",
        )
        #
        # VPC-Endpoints by default get a TCP/443
        #
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources.get("vpc_endpoint_sg"),
            peer=_peers.get("any"),
            connection=ec2.Port.tcp(443),
            description="Allow TCP/443 traffic to VPC-Endpoints",
        )

        #
        # NLB Healthchecks on the SSH port
        #
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["login_node_sg"],
            peer=scope.soca_resources["nlb_sg"],
            connection=ec2.Port.tcp(_login_node_ssh_back_port),
            description="Allow NLB health checks",
        )
        #
        # The customer prefix-list-id / prefix-list-id-ipv6
        # Has to be guarded for optional CLI user_specified_variables.prefix_list_id/ipv6
        #
        logger.debug(f"Configuring LoginNode SG with customer {_af} prefix-list")
        if (_af == "IP_V4" and user_specified_variables.prefix_list_id) or (
            _af == "IP_V6" and user_specified_variables.prefix_list_id_ipv6
        ):
            _pl_id = (
                user_specified_variables.prefix_list_id_ipv6
                if _af == "IP_V6"
                else user_specified_variables.prefix_list_id
            )
            logger.debug(f"Prefix list ID: {_pl_id}")
            for _sg in {"login_node_sg", "nlb_sg"}:
                logger.debug(f"Adding {_af} prefix list ({_pl_id}) rule to {_sg}")
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources[_sg],
                    peer=_peers.get("prefix_list"),
                    connection=ec2.Port.tcp(_login_node_ssh_front_port),
                    description=f"Allow SSH access from customer prefix list ({_sg_suffix_formal})",
                )

        if get_config_key("Config.directoryservice.provider") in {
            "aws_ds_managed_activedirectory",
            "existing_active_directory",
        }:
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["login_node_sg"],
                peer=_peers.get("vpc"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow all {_sg_suffix_formal} UDP traffic from VPC to login node. Required for Directory Service",
            )

            # FIXME TODO - Still needed with the CDK escape egress rule?
            security_groups_helper.create_egress_rule(
                security_group=scope.soca_resources["login_node_sg"],
                peer=_peers.get("any"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow all Egress {_sg_suffix_formal} UDP traffic for login node SG. Required for Directory Service",
            )

        # Controller
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=scope.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_icmp(),
            description="Allow PING traffic from compute nodes for LSF",
        )
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=scope.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_udp(),
            description="Allow UDP traffic from compute nodes for LSF",
        )
        # COMPUTE/DCV
        # Ingress
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic between compute node SG members (required for EFA)",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=_peers.get("vpc"),
            connection=ec2.Port.tcp_range(0, 65535),
            description=f"Allow all {_sg_suffix_formal} TCP traffic from VPC to compute nodes",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["controller_sg"],
            connection=ec2.Port.all_icmp(),
            description="Allow PING traffic from controller host for LSF",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["controller_sg"],
            connection=ec2.Port.all_udp(),
            description="Allow UDP traffic from controller host for LSF",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["controller_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from Controller host",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["target_node_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all traffic from Target Nodes",
        )

        # FIXME - TODO - ComputeNode custom SSH port via config
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["login_node_sg"],
            connection=ec2.Port.tcp(22),
            description="Allow SSH from login node",
        )

        # Egress is explicitly done so that we can activate EFA for this SG
        logger.debug("Creating EFA traffic egress rule")
        security_groups_helper.create_egress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic between compute node SG members (required for EFA)",
        )

        # Rest of Egress
        # This cannot be done as CDK complains that allowAllOutbound should be set for true
        # But this does not allow us to create egress rule entry - which prevents EFA from working correctly.
        # Instead - we must use a CDK escape hatch to manually create the rule
        # 20 Oct 2024
        # Per-SG escape hatch: apply to each newly-created SG independently so a
        # pre-existing unrelated SG does not suppress egress on the new
        # compute/controller/login SGs (which would break EFA).
        for _egress_sg in {"compute_node_sg", "vdi_node_sg", "controller_sg", "login_node_sg"}:
            if _security_groups.get(_egress_sg, {}).get("existing_security_group_id", ""):
                logger.debug(f"Skipping escape hatch for existing SG: {_egress_sg}")
                continue
            logger.debug(
                f"Adding (via CDK Escape Hatch) egress rule for {_egress_sg=}"
            )
            _sg_egress_rule = scope.soca_resources[_egress_sg].node.default_child
            # FIXME TODO - per-af?
            _sg_egress_rule.add_property_override(
                "SecurityGroupEgress",
                [
                    {
                        "CidrIp": "0.0.0.0/0",
                        "IpProtocol": "-1",
                        "Description": "Allow All egress for IPv4",
                    },
                    {
                        "CidrIpv6": "::/0",
                        "IpProtocol": "-1",
                        "Description": "Allow All egress for IPv6",
                    },
                ],
            )
            logger.debug(f"Done with Escape Hatch for {_egress_sg=}!")
        logger.debug("Done with all Escape Hatch Egress rules")

            # security_groups_helper.create_egress_rule(
            #     security_group=scope.soca_resources["compute_node_sg"],
            #     peer=ec2.Peer.ipv4("0.0.0.0/0"),
            #     connection=ec2.Port.all_traffic(),
            #     description="Allow all egress traffic from ComputeNodes",
            # )

        if get_config_key("Config.directoryservice.provider") in (
            "aws_ds_managed_activedirectory",
            "existing_active_directory",
        ):
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["compute_node_sg"],
                peer=_peers.get("vpc"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow all {_sg_suffix_formal} UDP traffic from VPC to compute. Required for Directory Service",
            )

            # FIXME TODO - is this still needed with the egress rules now covering all?
            security_groups_helper.create_egress_rule(
                security_group=scope.soca_resources["compute_node_sg"],
                peer=_peers.get("any"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow all Egress {_sg_suffix_formal} UDP traffic for ComputeNode SG. Required for Directory Service",
            )

        # ---------------------------------------------------------------
        # VDI (eVDI/DCV virtual desktop) nodes
        # ---------------------------------------------------------------
        # VDIs were historically launched into compute_node_sg; they now
        # own a dedicated SG so VDI and compute exposure can diverge.
        # VDIs remain full HPC-complex participants (they run PBS/LSF
        # scheduler clients), so the scheduler heartbeat rules
        # (controller<->VDI ICMP/UDP) are preserved -- they are NOT
        # compute-only. The intra-SG open mesh is kept (VDI-to-VDI),
        # minus the EFA justification (VDIs do not use EFA). A
        # bidirectional all-traffic mesh between VDI and compute is added
        # so a VDI can attach to server-style processes a compute node may
        # start (remote viz, license daemons, GUI backends).

        # Controller <- VDI : scheduler heartbeat (LSF/PBS) + all TCP
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=scope.soca_resources["vdi_node_sg"],
            connection=ec2.Port.all_icmp(),
            description="Allow PING traffic from VDI nodes for LSF",
        )
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=scope.soca_resources["vdi_node_sg"],
            connection=ec2.Port.all_udp(),
            description="Allow UDP traffic from VDI nodes for LSF",
        )
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=scope.soca_resources["vdi_node_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from the VDI nodes",
        )

        # VDI <- VDI : open intra-SG mesh (ingress + explicit egress)
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["vdi_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic between VDI SG members",
        )
        security_groups_helper.create_egress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["vdi_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic between VDI SG members",
        )

        # VDI <-> Compute : bidirectional open mesh. Compute nodes may
        # start server-style processes (remote viz, license daemons, GUI
        # backends) that VDIs attach to, and the return path.
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from compute nodes",
        )
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["compute_node_sg"],
            peer=scope.soca_resources["vdi_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from VDI nodes",
        )

        # VDI <- VPC : all TCP (mirror compute)
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=_peers.get("vpc"),
            connection=ec2.Port.tcp_range(0, 65535),
            description=f"Allow all {_sg_suffix_formal} TCP traffic from VPC to VDI nodes",
        )

        # VDI <- Controller : scheduler heartbeat (LSF/PBS) + all TCP
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["controller_sg"],
            connection=ec2.Port.all_icmp(),
            description="Allow PING traffic from controller host for LSF",
        )
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["controller_sg"],
            connection=ec2.Port.all_udp(),
            description="Allow UDP traffic from controller host for LSF",
        )
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["controller_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from Controller host",
        )

        # VDI <- Target nodes
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["target_node_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all traffic from Target Nodes",
        )

        # VDI <- Login node SSH
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["vdi_node_sg"],
            peer=scope.soca_resources["login_node_sg"],
            connection=ec2.Port.tcp(22),
            description="Allow SSH from login node",
        )

        # Target nodes <- VDI : VDIs can reach target nodes
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["target_node_sg"],
            peer=scope.soca_resources["vdi_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from the VDI nodes",
        )

        # VDI Directory Service rules (mirror compute)
        if get_config_key("Config.directoryservice.provider") in (
            "aws_ds_managed_activedirectory",
            "existing_active_directory",
        ):
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["vdi_node_sg"],
                peer=_peers.get("vpc"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow all {_sg_suffix_formal} UDP traffic from VPC to VDI. Required for Directory Service",
            )
            security_groups_helper.create_egress_rule(
                security_group=scope.soca_resources["vdi_node_sg"],
                peer=_peers.get("any"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow all Egress {_sg_suffix_formal} UDP traffic for VDI SG. Required for Directory Service",
            )

        # ElastiCache SG
        _cache_port_list: list = []
        _cache_provider = get_config_key(
            key_name="Config.services.aws_elasticache.engine", default="valkey"
        ).lower()

        if _cache_provider in {"redis", "valkey"}:
            _cache_port_list = [6379]
        elif _cache_provider == "memcached":
            _cache_port_list = [11211, 11212]
        else:
            logger.error(
                f"Unknown cache provider specified: {_cache_provider}  . Must be one of redis, valkey, or memcached."
            )
            sys.exit(1)
        for _port in _cache_port_list:
            for _sg_peer_name in [
                "controller_sg",
                "compute_node_sg",
                "vdi_node_sg",
                "login_node_sg",
                "target_node_sg",
                "ssm_config_sync_lambda_sg",
            ]:
                if scope.soca_resources.get(_sg_peer_name) is None:
                    # SsmConfigSync SG only created when feature flag is on.
                    continue
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["elasticache_sg"],
                    peer=scope.soca_resources[_sg_peer_name],
                    connection=ec2.Port.tcp(_port),
                    description=f"Allow ElastiCache traffic from the {_sg_peer_name}",
                )

        # Database SG ingress rules (TCP 5432 from controller/login/target
        database_helper.wire_database_ingress(
            soca_resources=scope.soca_resources,
            get_config_key=get_config_key,
            security_groups_helper=security_groups_helper,
        )

        #
        # Target Nodes have very relaxed security groups by design
        #
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["target_node_sg"],
            peer=scope.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from the compute nodes",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["target_node_sg"],
            peer=scope.soca_resources["login_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from the Login nodes",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["target_node_sg"],
            peer=scope.soca_resources["controller_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from the Controller nodes",
        )
        #
        # Allow entire VPC to TargetNode
        # this can be disabled and preserve the above rules if needed
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["target_node_sg"],
            peer=_peers.get("vpc"),
            connection=ec2.Port.all_traffic(),
            description=f"Allow all {_sg_suffix_formal} traffic from the VPC",
        )

        # CONTROLLER
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=scope.soca_resources["compute_node_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from the compute nodes",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=scope.soca_resources["alb_sg"],
            connection=ec2.Port.tcp(8443),
            description=f"Allow ELB healthcheck to communicate with the UI",
        )

        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["controller_sg"],
            peer=_peers.get("vpc"),
            connection=ec2.Port.tcp_range(0, 65535),
            description=f"VPC - allow all {_sg_suffix_formal} TCP traffic from VPC to controller",
        )

        if get_config_key("Config.directoryservice.provider") in (
            "aws_ds_managed_activedirectory",
            "existing_active_directory",
        ):
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["controller_sg"],
                peer=_peers.get("vpc"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow {_sg_suffix_formal} UDP traffic from VPC to controller. Required for Directory Service",
            )

            # FIXME TODO - Still needed since we already create this with the Escape hatch?
            security_groups_helper.create_egress_rule(
                security_group=scope.soca_resources["controller_sg"],
                peer=_peers.get("any"),
                connection=ec2.Port.udp_range(0, 1024),
                description=f"Allow Egress {_sg_suffix_formal} UDP traffic for controller SG. Required for Directory Service",
            )

        # ALB FRONTEND
        if isinstance(_peers.get("client"), list):
            for _c in _peers.get("client"):
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["alb_sg"],
                    peer=_c,
                    connection=ec2.Port.tcp(80),
                    description=f"Allow HTTP from client {_sg_suffix_formal}",
                )

                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["alb_sg"],
                    peer=_c,
                    connection=ec2.Port.tcp(443),
                    description=f"Allow HTTPS from client {_sg_suffix_formal}",
                )

        # The ALB FRONTEND block above applies client rules for every address-family (IPv4 + IPv6); no separate IPv6 client block is needed.

        # TODO - need?
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["alb_sg"],
            peer=_peers.get("vpc"),
            connection=ec2.Port.all_traffic(),
            description=f"Allow all {_sg_suffix_formal} traffic from VPC",
        )

        # TODO - merge this / unify the behavior of the NAT IPs
        if user_specified_variables.vpc_id:
            # Existing VPC/IPs
            for nat_eip in scope.soca_resources["nat_gateway_ips"]:
                logger.debug(f"Allowing {nat_eip} to access ALB")
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["alb_sg"],
                    peer=ec2.Peer.ipv4(f"{nat_eip}/32"),
                    connection=ec2.Port.tcp(443),
                    description="Allow NAT EIP to communicate to ALB",
                )
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["nlb_sg"],
                    peer=ec2.Peer.ipv4(f"{nat_eip}/32"),
                    connection=ec2.Port.tcp(_login_node_ssh_front_port),
                    description="Allow NAT EIP to communicate to NLB",
                )
        else:
            # Newly created
            logger.debug(
                f"Using NAT EIPs for newly created NAT gateways - {scope.soca_resources['nat_gateway_ips']} / {type(scope.soca_resources['nat_gateway_ips'])}"
            )
            for nat_eip in scope.soca_resources["nat_gateway_ips"]:
                logger.debug(f"Allowing {nat_eip} to access ELBs")
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["alb_sg"],
                    peer=ec2.Peer.ipv4(f"{nat_eip}/32"),
                    connection=ec2.Port.tcp(443),
                    description="Allow NAT EIP to communicate to ALB",
                )
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["nlb_sg"],
                    peer=ec2.Peer.ipv4(f"{nat_eip}/32"),
                    connection=ec2.Port.tcp(_login_node_ssh_front_port),
                    description="Allow NAT EIP to communicate to NLB",
                )

        if _af == "IP_V4" and user_specified_variables.prefix_list_id:
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["alb_sg"],
                peer=_peers.get("prefix_list"),
                connection=ec2.Port.tcp(443),
                description=f"Allow HTTPS from {_sg_suffix_formal} customer prefix list",
            )

            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["alb_sg"],
                peer=_peers.get("prefix_list"),
                connection=ec2.Port.tcp(80),
                description=f"Allow HTTP from {_sg_suffix_formal} customer prefix list",
            )

            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["nlb_sg"],
                peer=_peers.get("prefix_list"),
                connection=ec2.Port.tcp(_login_node_ssh_front_port),
                description=f"Allow {_sg_suffix_formal} SSH from customer prefix list",
            )

        for _sg_peer_name in ["controller_sg", "compute_node_sg", "login_node_sg"]:
            logger.debug(
                f"Allowing {_sg_suffix_formal} {_sg_peer_name} to access NLB on SSH"
            )
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["nlb_sg"],
                peer=scope.soca_resources[_sg_peer_name],
                connection=ec2.Port.tcp(_login_node_ssh_front_port),
                description=f"Allow SSH from {_sg_peer_name}",
            )

        # Allow NLB access from customer location
        if isinstance(_peers.get("client"), list):
            for _c in _peers.get("client"):
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["nlb_sg"],
                    peer=_c,
                    connection=ec2.Port.tcp(_login_node_ssh_front_port),
                    description=f"Allow {_sg_suffix_formal} SSH from client IP",
                )

        # Additional LoginNode traffic
        _login_node_additional_ports: dict = get_config_key(
            key_name="Config.login_node.security.additional_ports",
            default={},
            required=False,
            expected_type=dict,
        )

        logger.debug(
            f"Additional LoginNode traffic: {_login_node_additional_ports}"
        )

        for _proto in _login_node_additional_ports:
            logger.debug(f"Allowing additional traffic for {_proto}")
            for _port in _login_node_additional_ports.get(_proto, []):
                logger.debug(
                    f"Allowing additional traffic {_proto}:{_port} to NLB / LoginNodes"
                )
                for _sg in {"login_node_sg", "nlb_sg"}:
                    logger.debug(f"Updating {_sg} to access {_proto}:{_port}")
                    if isinstance(_peers.get("client"), list):
                        for _c in _peers.get("client"):
                            security_groups_helper.create_ingress_rule(
                                security_group=scope.soca_resources[_sg],
                                peer=_c,
                                connection=(
                                    ec2.Port.udp(_port)
                                    if _proto.lower() == "udp"
                                    else ec2.Port.tcp(_port)
                                ),
                                description=f"Allow {_sg_suffix_formal} {_proto}:{_port}",
                            )

        # TODO - Needed?
        security_groups_helper.create_ingress_rule(
            security_group=scope.soca_resources["login_node_sg"],
            peer=_peers.get("vpc"),
            connection=ec2.Port.all_traffic(),
            description=f"Allow all {_sg_suffix_formal} traffic from VPC",
        )

        # DCV High Scale infra
        if get_config_key(
                key_name="Config.dcv.high_scale",
                expected_type=bool,
                required=False,
                default=False,
        ):
            logger.debug(f"Creating SG rules for DCV High-Scale infrastructure")

            # ----- Client-side ingress on dcv_frontend_nlb_sg -----
            # The frontend NLB is the only public-facing surface in
            # high-scale mode. Customers reach DCV sessions over
            # TCP + UDP 443 (NLB listener forwards to gateway).
            # We restrict ingress the same way we do for alb_sg /
            # nlb_sg: from the clients_mpl (built from
            # user_specified_variables.client_ip / client_ipv6) and
            # optionally from a customer-supplied prefix list.
            if isinstance(_peers.get("client"), list):
                for _c in _peers.get("client"):
                    security_groups_helper.create_ingress_rule(
                        security_group=scope.soca_resources["dcv_frontend_nlb_sg"],
                        peer=_c,
                        connection=ec2.Port.tcp(443),
                        description=f"DCV {_sg_suffix_formal} clients TCP/443",
                    )
                    security_groups_helper.create_ingress_rule(
                        security_group=scope.soca_resources["dcv_frontend_nlb_sg"],
                        peer=_c,
                        connection=ec2.Port.udp(443),
                        description=f"DCV {_sg_suffix_formal} clients UDP/443 (QUIC)",
                    )

            if (
                _af == "IP_V4"
                and user_specified_variables.prefix_list_id
            ):
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["dcv_frontend_nlb_sg"],
                    peer=_peers.get("prefix_list"),
                    connection=ec2.Port.tcp(443),
                    description="DCV TCP/443 from customer prefix list",
                )
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["dcv_frontend_nlb_sg"],
                    peer=_peers.get("prefix_list"),
                    connection=ec2.Port.udp(443),
                    description="DCV UDP/443 (QUIC) from customer prefix list",
                )

            # ----- Service-side ingress (NLB -> service) -----
            # The DCV NLBs each have their own dedicated SG. Each
            # service SG accepts ingress from the matching NLB SG
            # only -- frontend NLB -> gateway, backend NLB -> broker.
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["dcv_gateway_sg"],
                peer=scope.soca_resources["dcv_frontend_nlb_sg"],
                connection=ec2.Port.all_traffic(),
                description="Allow Frontend NLB to DCV gateway",
            )
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["dcv_broker_sg"],
                peer=scope.soca_resources["dcv_backend_nlb_sg"],
                connection=ec2.Port.all_traffic(),
                description="Allow Backend NLB to DCV broker",
            )

            # ----- Backend NLB inbound (intra-VPC only) -----
            # The backend NLB exposes three listeners; each maps to
            # a specific caller class. Scope ingress per listener so
            # we don't leak (e.g.) the agent2broker port to the
            # controller, or the broker client API to compute nodes.
            #
            # TODO(jasackle): expose a customer-owned MPL for the
            # broker + gateway so customers can plug in additional
            # callers (custom API/Lambda, monitoring, custom auth
            # integrations) without forking SOCA. Pattern mirrors
            # the clients_mpl + prefix_list_id approach already in
            # place for alb_sg / nlb_sg / dcv_frontend_nlb_sg --
            # add `dcv_broker_extra_mpl` and `dcv_gateway_extra_mpl`
            # SocaConfig keys + matching ingress-rule emission here
            # and at the frontend NLB SG block above.
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["dcv_backend_nlb_sg"],
                peer=scope.soca_resources["controller_sg"],
                connection=ec2.Port.tcp(8443),
                description="Controller WebUI to broker client API (TCP/8443)",
            )
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["dcv_backend_nlb_sg"],
                peer=scope.soca_resources["dcv_screenshot_lambda_sg"],
                connection=ec2.Port.tcp(8443),
                description="DcvScreenshotPoller Lambda to broker client API (TCP/8443)",
            )
            for _agent_peer in ("compute_node_sg", "vdi_node_sg", "target_node_sg"):
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources["dcv_backend_nlb_sg"],
                    peer=scope.soca_resources[_agent_peer],
                    connection=ec2.Port.tcp(8445),
                    description=f"DCV SM agent on {_agent_peer} to broker (TCP/8445)",
                )
            security_groups_helper.create_ingress_rule(
                security_group=scope.soca_resources["dcv_backend_nlb_sg"],
                peer=scope.soca_resources["dcv_gateway_sg"],
                connection=ec2.Port.tcp(8447),
                description="DCV gateway to broker resolver (TCP/8447)",
            )

            # QUIC: gateway -> DCV server uses UDP/8443. The DCV host
            # SGs by default only allow UDP 0-1024 from the VPC
            # (Directory Service). Without this rule the QUIC splice
            # times out and the client transparently falls back to
            # TCP/WebSocket. See gateway.log: 'Connection to 10.x.y.z:8443
            # timed out'. (This is the server-side rule -- not the
            # NLB-side -- so the peer is the gateway SG and the rule's
            # *target* is each DCV-server host SG.) VDIs are DCV servers
            # on vdi_node_sg now, so the rule applies there as well as on
            # compute_node_sg (high-scale compute-hosted desktops).
            for _dcv_server_sg in ("compute_node_sg", "vdi_node_sg"):
                security_groups_helper.create_ingress_rule(
                    security_group=scope.soca_resources[_dcv_server_sg],
                    peer=scope.soca_resources["dcv_gateway_sg"],
                    connection=ec2.Port.udp(8443),
                    description="Allow DCV Gateway to reach DCV Server via QUIC (UDP/8443)",
                )
