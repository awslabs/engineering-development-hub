# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Mesh table naming for the cross-region overlay mesh.

Each mesh owns its own set of DynamoDB Global Tables. Without mesh-aware
naming, two meshes in the same account and region collide on physical table
names, so every table carries a per-mesh prefix:

    edh_<prefix>_<short_name>
    edh_a1b2c3d4_cluster_state      (prefix derived from the mesh UUID)
    edh_main_cluster_state          (operator-supplied override)

The prefix is the first 8 hex characters of the mesh UUID unless the operator
sets Config.services.cross_region.mesh_table_prefix_override, which wins
verbatim. Every cluster in a mesh computes the same prefix because they share
the same mesh_id and the same override.

This module deliberately knows nothing about WHICH tables exist. The table set
is defined once in ddb_global_tables.TABLE_SCHEMAS and derived from there.
"""

from __future__ import annotations

import re
from typing import Optional

# Hex characters taken from the mesh UUID when no override is set.
# 8 gives 4,294,967,296 distinct prefixes.
_DEFAULT_PREFIX_LEN = 8

# Override constraints, kept tight so the composed table name stays short and
# DynamoDB-legal. Lowercase letter first, then alphanumerics and underscores.
# No dashes, which would read as UUID separators, and no leading digit.
# DynamoDB itself allows [a-zA-Z0-9_.-]{3,255}; this is a deliberate subset.
_OVERRIDE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def compute_prefix(mesh_id: str, override: Optional[str] = None) -> str:
    """Return the per-mesh table prefix.

    Args:
        mesh_id: UUID string identifying the mesh.
        override: optional operator-supplied prefix. Wins over UUID derivation.

    Raises:
        ValueError: if the override is set but malformed, or if mesh_id is
            absent or too short to derive a prefix from. An invalid override
            raises rather than falling back to the UUID, because silently
            using a different prefix than the operator asked for would name
            the tables differently on this cluster than on its peers.
    """
    if override:
        if not _OVERRIDE_RE.match(override):
            raise ValueError(
                f"mesh_table_prefix_override={override!r} is invalid. It must match "
                f"{_OVERRIDE_RE.pattern}: a lowercase letter followed by up to 31 "
                f"alphanumerics or underscores, no leading digit."
            )
        return override

    if not mesh_id:
        raise ValueError(
            "compute_prefix() needs either a mesh_id or an override; both are empty."
        )

    # UUIDs are hex, so stripping dashes leaves [0-9a-f] only.
    _hex_only = mesh_id.replace("-", "").lower()
    if len(_hex_only) < _DEFAULT_PREFIX_LEN:
        raise ValueError(
            f"mesh_id={mesh_id!r} is too short to derive a {_DEFAULT_PREFIX_LEN}-character "
            f"prefix from; a mesh_id is expected to be a UUID."
        )
    return _hex_only[:_DEFAULT_PREFIX_LEN]


def make_table_name(prefix: str, short_name: str) -> str:
    """Compose a physical table name from a prefix and a short name.

    Short names are the trailing segment, for example "cluster_state" or
    "routing_history". Underscores throughout keep the tables sorting together
    in the DynamoDB console.
    """
    if not prefix:
        raise ValueError("make_table_name() received an empty prefix")
    if not short_name:
        raise ValueError("make_table_name() received an empty short_name")
    return f"edh_{prefix}_{short_name}"
