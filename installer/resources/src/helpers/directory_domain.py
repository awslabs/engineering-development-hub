#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Directory domain name derivation and validation.

Deliberately free of aws_cdk imports so the rules can be exercised without a
CDK environment.
"""

import re
from typing import Tuple, List

# ICANN reserved .internal for private internal use (2024), and unlike .local
# no resolver assigns it a special meaning. Sibling of the VPC's own
# <region>.compute.internal rather than a parent or child of it.
DEFAULT_DOMAIN_SUFFIX = "internal"

# RFC 6762 reserves .local for mDNS. systemd-resolved answers a .local query
# with a definitive error rather than UNAVAIL, so nsswitch never falls through
# to dns and the AD join fails after discovery has already succeeded.
MDNS_RESERVED_SUFFIX = "local"

# Providers where EDH creates the directory itself, so the domain name is a free
# choice at install time rather than a fact about the customer's estate.
_EDH_CREATES_DIRECTORY = frozenset({"aws_ds_managed_activedirectory", "openldap"})

# Providers that perform a realm join, and therefore depend on the domain
# resolving through nsswitch rather than only through libresolv.
_REALM_JOIN_PROVIDERS = frozenset(
    {"aws_ds_managed_activedirectory", "existing_active_directory"}
)

# CreateMicrosoftAD accepts Name matching ^([a-zA-Z0-9]+[\.-])+([a-zA-Z0-9])+$ --
# alphanumeric runs separated by a dot or a hyphen, so a label may contain an
# interior hyphen but cannot start or end with one, and underscores are refused.
_AD_LABEL = re.compile(r"^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$")

# The NetBIOS name AD derives from the first label, and what short_name is
# truncated to when it is not set explicitly.
NETBIOS_MAX_LENGTH = 15

_DNS_NAME_MAX_LENGTH = 253
_DNS_LABEL_MAX_LENGTH = 63


def default_domain_name(cluster_id: str) -> str:
    """The domain name used when directoryservice.domain_name is not set."""
    return f"{cluster_id}.{DEFAULT_DOMAIN_SUFFIX}"


def default_short_name(domain_name: str) -> str:
    """The NetBIOS name derived from a domain when short_name is not set."""
    return domain_name.split(".")[0].upper()[:NETBIOS_MAX_LENGTH]


def default_domain_base(domain_name: str) -> str:
    """The LDAP base DN derived from a domain when domain_base is not set."""
    return f"dc={',dc='.join(domain_name.split('.'))}".lower()


def validate_domain_name(
    domain_name: str,
    provider: str,
    short_name_is_explicit: bool = False,
) -> Tuple[List[str], List[str]]:
    """
    Check a resolved directory domain name.

    Returns (errors, warnings). Errors mean the install cannot succeed; warnings
    mean it can but something derived from the name will not be what the
    operator expects. The caller decides how to surface each.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not domain_name:
        return (["Config.directoryservice.domain_name resolved to an empty value"], [])

    if domain_name != domain_name.strip():
        errors.append(
            f"Config.directoryservice.domain_name {domain_name!r} has leading or trailing whitespace"
        )
        domain_name = domain_name.strip()

    if domain_name.endswith("."):
        errors.append(
            f"Config.directoryservice.domain_name {domain_name!r} must not end with a dot"
        )
        domain_name = domain_name.rstrip(".")

    if len(domain_name) > _DNS_NAME_MAX_LENGTH:
        errors.append(
            f"Config.directoryservice.domain_name is {len(domain_name)} characters, "
            f"which exceeds the {_DNS_NAME_MAX_LENGTH}-character DNS limit"
        )

    _labels = domain_name.split(".")

    if len(_labels) < 2:
        errors.append(
            f"Config.directoryservice.domain_name {domain_name!r} is a single-label name. "
            "A fully qualified name with at least two labels is required "
            f"(e.g. edh-cluster.{DEFAULT_DOMAIN_SUFFIX})"
        )

    for _label in _labels:
        if not _label:
            errors.append(
                f"Config.directoryservice.domain_name {domain_name!r} contains an empty label"
            )
        elif len(_label) > _DNS_LABEL_MAX_LENGTH:
            errors.append(
                f"Config.directoryservice.domain_name label {_label!r} is "
                f"{len(_label)} characters, which exceeds the {_DNS_LABEL_MAX_LENGTH}-character DNS limit"
            )
        elif provider == "aws_ds_managed_activedirectory" and not _AD_LABEL.match(
            _label
        ):
            errors.append(
                f"Config.directoryservice.domain_name label {_label!r} is not accepted by "
                "AWS Directory Service. Labels must be alphanumeric, may contain interior "
                "hyphens, and must not contain underscores or other characters"
            )

    if _labels[-1].lower() == MDNS_RESERVED_SUFFIX:
        _reason = (
            f"RFC 6762 reserves .{MDNS_RESERVED_SUFFIX} for mDNS, so systemd-resolved refuses it by "
            "policy. 'realm discover' still succeeds because it resolves SRV records through "
            "libresolv, but the join, adcli, sssd and Kerberos all use getaddrinfo() and fail"
        )
        if provider in _EDH_CREATES_DIRECTORY and provider in _REALM_JOIN_PROVIDERS:
            errors.append(
                f"Config.directoryservice.domain_name {domain_name!r} uses the reserved "
                f".{MDNS_RESERVED_SUFFIX} suffix. {_reason}. Use .{DEFAULT_DOMAIN_SUFFIX} "
                "or a subdomain of a domain you own"
            )
        elif provider in _REALM_JOIN_PROVIDERS:
            warnings.append(
                f"Config.directoryservice.domain_name {domain_name!r} uses the reserved "
                f".{MDNS_RESERVED_SUFFIX} suffix. {_reason}. EDH applies a per-link routing "
                "domain during the join to work around this, which cannot be relied on for "
                "every base OS. AWS Managed Microsoft AD cannot be renamed after creation"
            )

    if not short_name_is_explicit and len(_labels[0]) > NETBIOS_MAX_LENGTH:
        warnings.append(
            f"The first label of {domain_name!r} is {len(_labels[0])} characters, so the derived "
            f"NetBIOS name is silently truncated to {default_short_name(domain_name)!r}. "
            "Set Config.directoryservice.short_name to choose it explicitly"
        )

    return (errors, warnings)
