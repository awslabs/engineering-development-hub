#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import CfnOutput, aws_globalaccelerator as globalaccelerator


import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# AWS Global Accelerator for the cluster

logger = logging.getLogger("soca_logger")


def configure_aws_aga(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
):
    """
    Configure an AWS Global Accelerator (AGA) for the SOCA environment.
    """

    _aga_address_type_str = get_config_key(
        key_name="Config.network.aws_aga.address_type",
        expected_type=str,
        default="IPV4",
        required=False,
    ).upper()

    logger.debug(f"Creating AWS AGA using address-type {_aga_address_type_str}")

    scope.soca_resources["aga"] = globalaccelerator.CfnAccelerator(
        scope,
        f"{user_specified_variables.cluster_id}-AGA",
        name=f"{user_specified_variables.cluster_id}-AGA",
        enabled=True,
        ip_address_type=_aga_address_type_str,
    )

    # Define our listeners to resource mappings
    # Listeners are arranged in Endpoint groups that go to specific
    # region resources (ALB, NLB, EC2, etc.)

    _aga_listeners_needed = {
        #
        # ALB contains the WebUI
        #
        "ALB": {
            "protocols": {
                "TCP": {
                    "ports": [80, 443],
                },
            },
            "client_affinity": "SOURCE_IP",
            "endpoint": scope.soca_resources["alb"].load_balancer_arn,
        },
        #
        # NLB contains the VDI/DCV and SSH/login_nodes
        #
        "NLB": {
            "protocols": {
                "UDP": {
                    "ports": [8443],
                },
                "TCP": {
                    # "ports": [22, 8443],
                    "ports": [8443],
                },
            },
            "client_affinity": "SOURCE_IP",
            "endpoint": scope.soca_resources["nlb"].load_balancer_arn,
        },
    }

    # Create our required listeners as configured in the dict
    logger.debug(f"Creating AGA listeners: {_aga_listeners_needed}")

    _aga_listeners_created: list = []

    for _aga_listener in _aga_listeners_needed:
        _aga_listener = _aga_listener.upper()
        logger.debug(
            f"Creating AGA listener for {_aga_listener}: {_aga_listeners_needed[_aga_listener]}"
        )

        for _aga_protocol in _aga_listeners_needed[_aga_listener]["protocols"]:
            logger.debug(
                f"Creating AGA listener for {_aga_listener}/{_aga_protocol}"
            )

            _port_spec_list: list = []
            for _port in _aga_listeners_needed[_aga_listener]["protocols"][
                _aga_protocol
            ]["ports"]:
                logger.debug(f"Adding {_aga_listener}/{_port} to PortSpec")
                _port_spec_list.append(
                    globalaccelerator.CfnListener.PortRangeProperty(
                        from_port=_port, to_port=_port
                    )
                )

            logger.debug(
                f"Final PortSpec for {_aga_listener}/{_aga_protocol}: {_port_spec_list}"
            )

            # Now that we have built a portspec - we can create the multi-port listener
            scope.soca_resources[f"aga_listener_{_aga_listener}_{_aga_protocol}"] = (
                globalaccelerator.CfnListener(
                    scope,
                    f"{user_specified_variables.cluster_id}-AGAListener-{_aga_listener}-{_aga_protocol}",
                    client_affinity=_aga_listeners_needed[_aga_listener][
                        "client_affinity"
                    ],
                    accelerator_arn=scope.soca_resources["aga"].attr_accelerator_arn,
                    port_ranges=_port_spec_list,
                    protocol=_aga_protocol,
                )
            )

            logger.debug(f"Creating AGA endpoint groups for {_aga_listener}")
            _aga_endpoint_group = globalaccelerator.CfnEndpointGroup(
                scope,
                f"{user_specified_variables.cluster_id}-AGAEndpointGroup{_aga_listener}-{_aga_protocol}",
                listener_arn=scope.soca_resources[
                    f"aga_listener_{_aga_listener}_{_aga_protocol}"
                ].attr_listener_arn,
                endpoint_group_region=user_specified_variables.region,
                endpoint_configurations=[
                    globalaccelerator.CfnEndpointGroup.EndpointConfigurationProperty(
                        endpoint_id=_aga_listeners_needed[_aga_listener][
                            "endpoint"
                        ],
                        weight=100,
                        client_ip_preservation_enabled=True,
                    )
                ],
            )
            _aga_endpoint_group.node.add_dependency(
                scope.soca_resources[f"aga_listener_{_aga_listener}_{_aga_protocol}"]
            )

    # Make sure all of our listeners are listed as deps
    # for _aga_listener_name in _aga_listeners_created:
    #     logger.debug(f"Adding Dep for Endpoint group: {_aga_listener_name}")
    #     _aga_endpoint_group.node.add_dependency(scope.soca_resources[_aga_listener_name])

    CfnOutput(
        scope,
        "AGAAccessPoint",
        value=f'https://{scope.soca_resources["aga"].attr_dns_name}/',
    )

    # _aga_ipv4_str: str = ", ".join(scope.soca_resources["aga"].attr_ipv4_addresses)
    # CfnOutput(
    #     self,
    #     "AGAIPAddressList_ipv4",
    #     value=_aga_ipv4_str,
    # )

    # FIXME TODO
    # Output for IPv6?
    # _aga_ipv6_list = scope.soca_resources["aga"].attr_ipv6_addresses
    # CfnOutput(
    #     self,
    #     "AGAIPAddresses_ipv4",
    #     value=f"{scope.soca_resources["aga"].attr_ipv4_addresses}",
    # )
