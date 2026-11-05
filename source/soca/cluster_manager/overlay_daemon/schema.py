######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Schema versioning and validation registry for the mesh Global Table rows.

Every row carries an explicit schema_version and an optional
min_compatible_version. Together they let clusters running different EDH
versions share one mesh without a coordinated upgrade.

Read path:
  1. Read the raw row.
  2. Look up a validator for (table, row.schema_version).
  3. On a hit, validate and return the typed model.
  4. On a miss, if the row declares a different min_compatible_version that IS
     supported, validate with that earlier validator and emit
     ForwardCompatRowApplied.
  5. If neither lookup succeeds, return None so the caller skips the row, and
     emit UnsupportedSchemaVersion. A row this daemon cannot read must not stop
     it reading the rows it can, or one cluster upgrading would partition the
     mesh for everyone else.

Write path:
  1. Construct the model with schema_version = CURRENT_VERSION.
  2. Set min_compatible_version when the change is additive only, so older
     daemons can still consume the row.
  3. For mutable rows, increment revision and write conditionally on the prior
     value. See ddb_client.py.

Adding a schema version:
  1. Add the integer to SUPPORTED_VERSIONS.
  2. Implement _validate_<table>_v<N>(item) returning the model.
  3. Register it with registry.register("<table>", N, _validate_<table>_vN).
  4. If the change is additive only, write min_compatible_version=N-1.
  5. Raise CURRENT_VERSION.
  6. Cover both directions by test: an old daemon reading a new row and a new
     daemon reading an old row.

This module has no non-standard-library dependencies at import time, so it can
be imported from the daemon, a Lambda, a test or a CLI. The metric emitter is
pluggable for the same reason, and imports boto3 only when actually built.

Validators for the health and audit tables, and for the fence protocol's rows,
ship with the subsystems that read them. The registry is the extension point
for that, so adding them requires no change here.
"""

from __future__ import annotations
import logging
from typing import Any, Callable, Dict, Optional, Set, Tuple

from .models import (
    Lifecycle,
    MeshMeta,
    Peer,
)

logger = logging.getLogger("soca_logger")


# ----------------------------------------------------------------------------
# Versioning constants
# ----------------------------------------------------------------------------

# The schema versions this daemon understands. The daemon maintains support for
# the current version and exactly one prior version. When the first real bump
# ships, add 2 here alongside v2 validators.
SUPPORTED_VERSIONS: Set[int] = {1}

# The version written on new rows. Always the highest supported.
CURRENT_VERSION: int = 1

# Logical table identifiers used by the registry. These are NOT the physical
# DynamoDB table names, which are per-mesh and resolved in table_names.py.
# Registration uses logical names so the same code works for any mesh prefix.
# Note that peer rows and the metadata row share one physical table but are
# separate logical tables here, because they validate into different models.
TABLE_PEER = "overlay_config_peer"
TABLE_META = "overlay_config_meta"


# ----------------------------------------------------------------------------
# Pluggable metric emitter
# ----------------------------------------------------------------------------


_metric_emitter: Optional[Callable[[str, float, Dict[str, str]], None]] = None


def set_metric_emitter(
    fn: Optional[Callable[[str, float, Dict[str, str]], None]]
) -> None:
    """Install a callable that publishes metrics. Pass None to disable."""
    global _metric_emitter
    _metric_emitter = fn


def _emit(metric_name: str, value: float = 1.0, **dimensions: str) -> None:
    if _metric_emitter is None:
        return
    try:
        _metric_emitter(metric_name, value, dimensions)
    except Exception:
        # A metrics failure must never break the data path.
        logger.exception("metric emitter failed for %s", metric_name)


def make_cloudwatch_emitter(
    namespace: str = "MeshControlPlane",
    region: Optional[str] = None,
    cluster_id: Optional[str] = None,
):
    """
    Build a CloudWatch emitter suitable for set_metric_emitter().

    boto3 is imported here rather than at module scope so that importing this
    module stays dependency-free. The returned emitter logs and swallows its
    own errors, so a CloudWatch outage cannot break the daemon.

    `region` is required. It was optional, with an unpinned fallback for a caller
    that had none to give, and the daemon's own caller passed a value that could
    be None, so the fallback was reachable in production and the client resolved a
    region from instance metadata. An optional pin is not a pin: the only version
    that holds is the one with no unpinned branch to reach.
    """
    import boto3

    if not region:
        raise ValueError(
            "make_cloudwatch_emitter requires a region. Without one the CloudWatch "
            "client resolves a region from the ambient environment, which on an "
            "instance means metadata, and it can differ from the region this "
            "cluster runs in."
        )
    cw = boto3.client("cloudwatch", region_name=region)

    def emit(metric_name: str, value: float, dimensions: Dict[str, str]) -> None:
        all_dims = dict(dimensions)
        if cluster_id:
            all_dims.setdefault("cluster_id", cluster_id)
        cw_dims = [
            {"Name": k, "Value": str(v)} for k, v in all_dims.items() if v is not None
        ]
        try:
            cw.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Value": float(value),
                        "Unit": "Count",
                        "Dimensions": cw_dims,
                    }
                ],
            )
        except Exception:
            logger.exception(
                "CloudWatch put_metric_data failed for %s.%s; continuing",
                namespace,
                metric_name,
            )

    return emit


# ----------------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------------


class SchemaRegistry:
    """
    Maps (logical table, version) to a validator callable.

    A validator takes a raw DynamoDB item dict and returns a typed model. A
    validator MAY raise on bad row content, and the read path treats that as a
    corrupt row, which is a different condition from an unsupported version and
    is logged differently.
    """

    def __init__(self) -> None:
        self._validators: Dict[Tuple[str, int], Callable[[dict], Any]] = {}

    def register(
        self,
        table: str,
        version: int,
        validator: Callable[[dict], Any],
    ) -> None:
        self._validators[(table, version)] = validator

    def has(self, table: str, version: int) -> bool:
        return (table, version) in self._validators

    def get(self, table: str, version: int) -> Optional[Callable[[dict], Any]]:
        return self._validators.get((table, version))

    def validate(self, table: str, item: dict) -> Tuple[Optional[Any], bool]:
        """
        Validate a raw item against the registry.

        Returns (model, was_fallback) on success, where was_fallback is True
        when the row's declared version was unsupported but its
        min_compatible_version applied. Returns (None, False) when no
        compatible validator exists, and the caller skips the row.

        Raises ValueError, KeyError or TypeError when the row content is
        malformed for the validator that matched.
        """
        declared = int(item.get("schema_version", 1))
        min_compat = int(item.get("min_compatible_version", declared))

        validator = self.get(table, declared)
        if validator is not None:
            return validator(item), False

        if min_compat != declared and self.has(table, min_compat):
            fallback = self.get(table, min_compat)
            if fallback is None:
                # has() said otherwise, so this is unreachable; treat a
                # disagreement as unsupported rather than raising.
                return None, False
            _emit(
                "ForwardCompatRowApplied",
                table=table,
                declared_version=str(declared),
                applied_version=str(min_compat),
            )
            logger.info(
                "row in %s declares schema_version=%d; applying the supported "
                "min_compatible_version=%d instead",
                table,
                declared,
                min_compat,
            )
            return fallback(item), True

        _emit(
            "UnsupportedSchemaVersion",
            table=table,
            declared_version=str(declared),
            min_compatible_version=str(min_compat),
        )
        logger.warning(
            "row in %s declares schema_version=%d (min_compatible=%d); this "
            "daemon supports versions %s. Skipping row.",
            table,
            declared,
            min_compat,
            sorted(SUPPORTED_VERSIONS),
        )
        return None, False


# ----------------------------------------------------------------------------
# v1 validators
# ----------------------------------------------------------------------------


def _validate_peer_v1(item: dict) -> Peer:
    """Validate a v1 peer row from the overlay_config table."""
    return Peer(
        mesh_id=item["mesh_id"],
        cluster_id=item["cluster_id"],
        cluster_name=item.get("cluster_name", item["cluster_id"]),
        region=item.get("region", ""),
        account_id=item.get("account_id", ""),
        site_seq=int(item.get("site_seq", 0)),
        pubkey=item.get("pubkey", ""),
        pubkey_next=item.get("pubkey_next"),
        endpoint=item.get("endpoint", ""),
        ula_prefix=item.get("ula_prefix", ""),
        cgn_prefix=item.get("cgn_prefix", ""),
        lifecycle=Lifecycle(item.get("lifecycle", "pending")),
        joined_at=int(item.get("joined_at", 0)),
        joined_by=item.get("joined_by", ""),
        decommissioned_at=(
            int(item["decommissioned_at"]) if item.get("decommissioned_at") else None
        ),
        tombstoned_at=(
            int(item["tombstoned_at"]) if item.get("tombstoned_at") else None
        ),
        lifecycle_history=list(item.get("lifecycle_history", [])),
        endpoint_ipv6=item.get("endpoint_ipv6"),
        schema_version=int(item.get("schema_version", 1)),
        min_compatible_version=int(item.get("min_compatible_version", 1)),
        revision=int(item.get("revision", 0)),
    )


def _validate_meta_v1(item: dict) -> MeshMeta:
    """Validate a v1 mesh metadata row, the _meta row in overlay_config."""
    return MeshMeta(
        mesh_id=item["mesh_id"],
        mesh_ula_prefix=item.get("mesh_ula_prefix", ""),
        mesh_cgn_prefix=item.get("mesh_cgn_prefix", "100.64.0.0/16"),
        next_site_seq=int(item.get("next_site_seq", 1)),
        created_at=int(item.get("created_at", 0)),
        created_by=item.get("created_by", ""),
        key_rotation_days=int(item.get("key_rotation_days", 90)),
        auto_decommission_days=(
            int(item["auto_decommission_days"])
            if item.get("auto_decommission_days") is not None
            else None
        ),
        decommission_to_tombstone_days=int(
            item.get("decommission_to_tombstone_days", 30)
        ),
        schema_version=int(item.get("schema_version", 1)),
        min_compatible_version=int(item.get("min_compatible_version", 1)),
        revision=int(item.get("revision", 0)),
    )


registry = SchemaRegistry()
registry.register(TABLE_PEER, 1, _validate_peer_v1)
registry.register(TABLE_META, 1, _validate_meta_v1)
