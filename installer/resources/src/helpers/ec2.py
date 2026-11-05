# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared EC2/VPC helpers for the installer.

Subnet selection tolerant of NAT-instance VPCs.

CDK infers a subnet's type from its default-route target: an Internet Gateway
maps to PUBLIC, a managed NAT Gateway (nat-...) maps to PRIVATE_WITH_EGRESS,
and anything else (including a default route to a NAT *instance* ENI) is left
as PRIVATE_ISOLATED. A NAT instance therefore provides real egress that CDK
does not recognize, so selecting PRIVATE_WITH_EGRESS finds no subnets and the
synth fails even though the network is functional.

`private_subnet_type` / `private_subnet_type_selection` prefer PRIVATE_WITH_EGRESS
and fall back to PRIVATE_ISOLATED so those clusters can deploy. The fallback
only fixes CDK's labeling -- the subnet must still reach AWS control planes at
runtime via a NAT instance or VPC endpoints.
"""

import logging

from aws_cdk import aws_ec2 as ec2

logger = logging.getLogger("soca_logger")


def private_subnet_type(vpc) -> ec2.SubnetType:
    """Return the best available private subnet type for in-VPC compute.

    Prefers PRIVATE_WITH_EGRESS; falls back to PRIVATE_ISOLATED when the VPC
    has no subnets CDK recognizes as egress-capable (e.g. NAT-instance VPCs).

    Raises:
        ValueError: the VPC exposes neither private subnet type.
    """
    for subnet_type in [
        ec2.SubnetType.PRIVATE_WITH_EGRESS,
        ec2.SubnetType.PRIVATE_ISOLATED,
    ]:
        try:
            if vpc.select_subnets(subnet_type=subnet_type).subnets:
                if subnet_type is ec2.SubnetType.PRIVATE_ISOLATED:
                    logger.warning(
                        "No PRIVATE_WITH_EGRESS subnets found in VPC %s; falling "
                        "back to PRIVATE_ISOLATED. In-VPC compute still needs "
                        "egress (NAT instance or VPC endpoints) to reach AWS "
                        "control planes.",
                        getattr(vpc, "vpc_id", "<unknown>"),
                    )
                return subnet_type
        except Exception:  # noqa: BLE001 -- CDK raises when a type has no groups
            continue
    raise ValueError(
        "VPC has no PRIVATE_WITH_EGRESS or PRIVATE_ISOLATED subnets available "
        "for in-VPC compute."
    )


def private_subnet_type_selection(vpc) -> ec2.SubnetSelection:
    """SubnetSelection wrapping `private_subnet_type` (egress preferred)."""
    return ec2.SubnetSelection(subnet_type=private_subnet_type(vpc))
