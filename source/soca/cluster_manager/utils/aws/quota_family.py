# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Instance family reduction for EC2 On-Demand Service Quota matching.

Deliberately dependency-free (stdlib `re` only) so it can be unit tested without
boto3 clients or AWS credentials.
"""

from __future__ import annotations

import re

# Families whose reduced token is multi-letter but which belong to a single-letter
# Standard quota designator, so equality against the quota's family list still holds.
# Im4gn and Is4gen are "I" family members covered by the Standard quota.
STANDARD_FAMILY_TOKEN_ALIASES = {"im": "i", "is": "i"}

# The sentinel this codebase uses for the High Memory family, because the quota is
# named "high memory" rather than after a family letter. See
# ec2_helper._families_in_quota(), which yields exactly this token for that row.
HIGH_MEMORY_FAMILY_TOKEN = "u-"


def reduce_instance_family_token(instance_type: str) -> str:
    """
    Reduce an instance type to the family token used inside the EC2 On-Demand quota
    names: hpc8a.96xlarge -> "hpc", h1.16xlarge -> "h", c7i.48xlarge -> "c".

    Compare this token for EQUALITY against a quota's family list, never with
    startswith(). The Standard quota advertises single-letter designators
    (A, C, D, H, I, M, R, T, Z) and hpc*, inf*, trn* and mac* each begin with one
    of those letters while belonging to their own separate quota. A prefix match
    therefore charges HPC, Inf and Trn vCPUs against the Standard limit, which
    rejects Standard-family jobs for a limit they are not consuming.

    This is the RAW token. To compare against a quota's Families list use
    quota_match_token() instead, which also collapses the High Memory family.
    """
    _family = instance_type.split(".")[0].lower()
    _match = re.search(r"(.*)\d", _family)
    _token = _match.group(1) if _match else _family
    return STANDARD_FAMILY_TOKEN_ALIASES.get(_token, _token)


def quota_match_token(instance_type: str) -> str:
    """
    The token to compare against a quota's Families list.

    This is the ONLY function that should be used for that comparison. The raw
    reduction is not enough on its own: a High Memory quota row carries the single
    family token "u-", while the raw reduction of u-6tb1.metal is "u-6tb", so an
    equality test against the raw token never matches.

    That mismatch was a live defect. find_quota_for_instance() collapsed the token
    to "u-" itself, but the two usage loops in _vcpus_in_use() tested membership
    with the raw token, so every High Memory instance and every High Memory ODCR
    reservation was skipped when counting usage. The limit was read correctly and
    usage always came out as 0, which means the gate could never refuse a High
    Memory job however far over its limit the account was. Collapsing in one shared
    place is what stops the two sides disagreeing again.

    KNOWN GAP, deliberately not guessed at here: u7i-* reduces to "u7i-1", which
    does not begin with "u-", so it collapses to neither "u-" nor a Standard
    designator and matches no quota row. find_quota_for_instance() therefore reports
    "Unable to find a ... quota" and the gate refuses the launch outright. Which
    Service Quotas row actually counts U7i has not been MEASURED against a live
    account, and every other family rule in this module was measured rather than
    inferred, so mapping it here on the strength of the marketing name would charge
    U7i against a limit it may not consume.
    """
    _token = reduce_instance_family_token(instance_type)
    if _token.startswith(HIGH_MEMORY_FAMILY_TOKEN):
        return HIGH_MEMORY_FAMILY_TOKEN
    return _token
