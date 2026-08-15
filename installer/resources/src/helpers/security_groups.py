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

import logging
import re

from aws_cdk import aws_ec2 as ec2
from constructs import Construct

logger = logging.getLogger("soca_logger")

# AWS hard limit for Security Group and SG rule descriptions (characters).
MAX_SG_DESCRIPTION_LENGTH = 256

# AWS-allowed character set for SG and SG-rule descriptions:
#   a-zA-Z0-9. _-:/()#,@[]+=&;{}!$*
# Anything outside this set (e.g. '>' in an '->' arrow) is rejected by EC2 at
# deploy time. Match the complement so we can replace offending characters.
_SG_DESCRIPTION_DISALLOWED = re.compile(r"[^A-Za-z0-9 ._:/()#,@\[\]+=&;{}!$*-]")


def clamp_sg_description(description: str) -> str:
    """Sanitize and truncate a description to satisfy the AWS SG limits.

    Two independent EC2 constraints are enforced:
      1. Characters must come from the allowed set. Offending characters are
         replaced with spaces.
      2. Length must be <= 256. Longer descriptions are truncated to 253 + '...'.

    Both fixes only prevent the CloudFormation deploy error -- they do not make
    the description good. Each transformation emits a WARNING so admins can
    shorten or clean up the source string.

    Uses ASCII '...' (not the Unicode ellipsis) because the allowed-character
    set excludes non-ASCII characters.
    """
    if description is None:
        return ""

    sanitized = _SG_DESCRIPTION_DISALLOWED.sub(" ", description)
    if sanitized != description:
        logger.warning(
            "Security Group description contained characters outside the AWS "
            "allowed set; they were replaced with spaces. "
            f"Original: {description!r} -> Sanitized: {sanitized!r}"
        )

    if len(sanitized) <= MAX_SG_DESCRIPTION_LENGTH:
        return sanitized
    clamped = sanitized[: MAX_SG_DESCRIPTION_LENGTH - 3] + "..."
    logger.warning(
        f"Security Group description exceeded the AWS {MAX_SG_DESCRIPTION_LENGTH}-char "
        f"limit by {len(sanitized) - MAX_SG_DESCRIPTION_LENGTH} chars and was "
        f"truncated. Please shorten it. Original: {sanitized!r} -> Clamped: {clamped!r}"
    )
    return clamped


def create_security_groups(
    scope: Construct,
    construct_id: str,
    vpc: str,
    allow_all_outbound: bool = False,
    allow_all_ipv6_outbound: bool = False,
    description: str = "",
) -> ec2.SecurityGroup:
    return ec2.SecurityGroup(
        scope=scope,
        id=construct_id,
        vpc=vpc,
        allow_all_outbound=allow_all_outbound,
        allow_all_ipv6_outbound=allow_all_ipv6_outbound,
        description=clamp_sg_description(description),
    )


def use_existing_security_group(
    scope: Construct, construct_id: str, security_group_id: str
) -> ec2.SecurityGroup:
    return ec2.SecurityGroup.from_security_group_id(
        scope=scope, id=construct_id, security_group_id=security_group_id
    )


def create_ingress_rule(
    security_group: ec2.SecurityGroup,
    peer: list | ec2.Peer,
    connection: ec2.Port,
    description: str,
):
    return security_group.add_ingress_rule(
        peer, connection, clamp_sg_description(description)
    )


def create_egress_rule(
    security_group: ec2.SecurityGroup,
    peer: ec2.Peer,
    connection: ec2.Port,
    description: str,
):
    return security_group.add_egress_rule(
        peer, connection, clamp_sg_description(description)
    )
