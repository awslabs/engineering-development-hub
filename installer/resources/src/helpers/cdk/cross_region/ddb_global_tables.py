# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DynamoDB Global Tables for the cross-region overlay mesh and job routing.

The mesh keeps all of its shared state here, replicated across every region a
member cluster lives in. TABLE_SCHEMAS below is the single definition of that
table set; SHORT_NAMES is derived from it so the two cannot disagree.

    overlay_config       authoritative peer registry, one row per cluster plus a _meta row
    overlay_health       per-pair tunnel health observations
    overlay_audit        append-only audit of administrative actions
    cluster_state        per-cluster health and heartbeat, distinct from tunnel health
    routing_history      per-job routing decisions
    routing_policy       rule definitions, production and draft versions
    routing_evaluations  sampled per-evaluation traces
    delegations          one row per locally-submitted job delegated to a peer

Physical names are namespaced per mesh as edh_<prefix>_<short_name>; see
mesh_table_naming.py.

The first cluster in a mesh creates the tables and every later cluster imports
them. That decision is made before cdk runs and arrives here as a flag.

Invoked from cdk_construct.py before self.controller(), because the controller
IAM role's grants reference these tables.

Redeploy after a failed deploy: the tables use RemovalPolicy.RETAIN so mesh
data outlives any single stack, which means they survive a stack rollback and a
plain redeploy would fail with "already exists". The force_import flag exists
for that case and is set by the installer's mesh preflight when the operator
chooses to adopt the existing tables.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as ddb

from helpers.cdk.cross_region.mesh_table_naming import compute_prefix, make_table_name

logger = logging.getLogger("soca_logger")

# Key on scope.soca_resources under which the table map is published, so later
# constructs and the post-controller pass can find it.
GLOBAL_TABLES_KEY = "cross_region_global_tables"


# ---------------------------------------------------------------------------
# Table schemas: the single source of truth for the mesh's table set.
#
# Streams are enabled on every table. See _create_tables() for why the created
# stream view type is always NEW_AND_OLD_IMAGES regardless of what a schema
# asks for.
# ---------------------------------------------------------------------------

TABLE_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "overlay_config": {
        "partition_key": ddb.Attribute(name="mesh_id", type=ddb.AttributeType.STRING),
        "sort_key": ddb.Attribute(name="cluster_id", type=ddb.AttributeType.STRING),
        "global_secondary_indexes": [
            # Look up clusters by lifecycle state, for example every pending peer.
            {
                "index_name": "lifecycle-index",
                "partition_key": ddb.Attribute(
                    name="lifecycle", type=ddb.AttributeType.STRING
                ),
                "sort_key": ddb.Attribute(
                    name="cluster_id", type=ddb.AttributeType.STRING
                ),
            },
        ],
        "stream": ddb.StreamViewType.NEW_AND_OLD_IMAGES,
    },
    "overlay_health": {
        "partition_key": ddb.Attribute(name="mesh_id", type=ddb.AttributeType.STRING),
        # pair_id is "<observer_cluster_id>:<observed_cluster_id>"
        "sort_key": ddb.Attribute(name="pair_id", type=ddb.AttributeType.STRING),
        "global_secondary_indexes": [],
        "stream": ddb.StreamViewType.NEW_IMAGE,
    },
    "overlay_audit": {
        "partition_key": ddb.Attribute(name="mesh_id", type=ddb.AttributeType.STRING),
        # event_id is built by models.new_event_id: a zero-padded millisecond
        # timestamp then a uniqueness suffix, so the sort key is chronological and
        # the reader's ScanIndexForward=False really does mean newest first. This
        # comment previously claimed event_id was a KSUID, which would also have
        # sorted correctly, but no KSUID generator has ever existed here and the
        # only writer was emitting a random UUID.
        "sort_key": ddb.Attribute(name="event_id", type=ddb.AttributeType.STRING),
        "global_secondary_indexes": [],
        "stream": ddb.StreamViewType.NEW_IMAGE,
        "ttl_attribute": "expires_at",
    },
    "cluster_state": {
        "partition_key": ddb.Attribute(name="mesh_id", type=ddb.AttributeType.STRING),
        "sort_key": ddb.Attribute(name="cluster_id", type=ddb.AttributeType.STRING),
        "global_secondary_indexes": [],
        "stream": ddb.StreamViewType.NEW_AND_OLD_IMAGES,
    },
    "routing_history": {
        "partition_key": ddb.Attribute(name="job_uuid", type=ddb.AttributeType.STRING),
        # event_seq is monotonic per job
        "sort_key": ddb.Attribute(name="event_seq", type=ddb.AttributeType.NUMBER),
        "global_secondary_indexes": [
            # Recent routing activity for one cluster.
            {
                "index_name": "cluster-events-index",
                "partition_key": ddb.Attribute(
                    name="cluster_id", type=ddb.AttributeType.STRING
                ),
                "sort_key": ddb.Attribute(
                    name="event_ts", type=ddb.AttributeType.NUMBER
                ),
            },
        ],
        "stream": ddb.StreamViewType.NEW_IMAGE,
        "ttl_attribute": "expires_at",
    },
    "routing_policy": {
        "partition_key": ddb.Attribute(name="mesh_id", type=ddb.AttributeType.STRING),
        # version_id is "v<NNN>" for promoted versions or "draft-<KSUID>"
        "sort_key": ddb.Attribute(name="version_id", type=ddb.AttributeType.STRING),
        "global_secondary_indexes": [
            # Resolve the production version for a mesh in one query.
            {
                "index_name": "production-index",
                "partition_key": ddb.Attribute(
                    name="mesh_id", type=ddb.AttributeType.STRING
                ),
                "sort_key": ddb.Attribute(name="status", type=ddb.AttributeType.STRING),
            },
        ],
        "stream": ddb.StreamViewType.NEW_AND_OLD_IMAGES,
    },
    "routing_evaluations": {
        "partition_key": ddb.Attribute(name="mesh_id", type=ddb.AttributeType.STRING),
        # eval_id is a KSUID
        "sort_key": ddb.Attribute(name="eval_id", type=ddb.AttributeType.STRING),
        "global_secondary_indexes": [
            # Aggregate by rule_id for per-rule hit rates.
            {
                "index_name": "rule-hits-index",
                "partition_key": ddb.Attribute(
                    name="rule_id", type=ddb.AttributeType.STRING
                ),
                "sort_key": ddb.Attribute(name="eval_ts", type=ddb.AttributeType.NUMBER),
            },
        ],
        "stream": ddb.StreamViewType.NEW_IMAGE,
        "ttl_attribute": "expires_at",
    },
    "delegations": {
        # The cross-region ledger: one row per locally-submitted job that was
        # delegated to a peer. local_job_id is the scheduler id of the parked stub.
        "partition_key": ddb.Attribute(name="mesh_id", type=ddb.AttributeType.STRING),
        "sort_key": ddb.Attribute(name="local_job_id", type=ddb.AttributeType.STRING),
        "global_secondary_indexes": [
            # Open delegations still to reconcile, by originating cluster.
            {
                "index_name": "origin-open-index",
                "partition_key": ddb.Attribute(
                    name="local_cluster_id", type=ddb.AttributeType.STRING
                ),
                "sort_key": ddb.Attribute(
                    name="updated_ts", type=ddb.AttributeType.NUMBER
                ),
            },
        ],
        "stream": ddb.StreamViewType.NEW_AND_OLD_IMAGES,
        "ttl_attribute": "expires_at",
    },
}

# Derived from TABLE_SCHEMAS rather than restated, so adding a table cannot
# leave a second list behind. Every consumer that needs the table set should
# import this rather than keeping its own copy.
SHORT_NAMES: tuple = tuple(TABLE_SCHEMAS)

# Tables whose rows must never be rewritten or removed once written.
#
# This lives beside TABLE_SCHEMAS because it is a property of the TABLE, not of
# any one role. Three separate principals write overlay_audit: the overlay
# daemon, the policy console, and the cross-account mesh participant role. The
# append-only guarantee holds only if all three respect it, so they call
# enforce_append_only() rather than each carrying its own conditional. Anything
# added here is narrowed everywhere at once.
APPEND_ONLY_TABLES = frozenset({"overlay_audit"})

# Tables a mesh writer may WRITE. Read access is granted across the whole mesh
# so a cluster can see every peer; writes are confined to this set.
#
# Both the overlay daemon role and the cross-account participant role select
# from here, because the participant role exists so a joiner can do the daemon's
# work against the creator's tables. Selecting separately let the participant
# role write a table the daemon cannot.
#
# routing_history is deliberately ABSENT and therefore read-only for both. Its
# writers are the qmove orchestrator and the PBS movejob hook, which arrive with
# the routing subsystem, and whether they run under the daemon role or the
# controller's own role is a decision that belongs with that code rather than
# here. Granting it now would be a write permission with no writer.
MESH_WRITER_TABLES = (
    "overlay_config",
    "overlay_health",
    "overlay_audit",
    "cluster_state",
    # Routing tables. Granted only when present in the table map, so the
    # statements stay absent on a mesh that has tables but no routing yet.
    "routing_policy",
    "routing_evaluations",
    "delegations",
)


def enforce_append_only(short_name: str, actions: List[str]) -> List[str]:
    """Reduce a write action set to PutItem alone for an append-only table.

    Writers of these tables append with a condition expression such as
    attribute_not_exists(event_id), but withholding UpdateItem and DeleteItem at
    the IAM layer means a compromised or mistaken caller cannot rewrite history
    even if that condition is bypassed.
    """
    if short_name in APPEND_ONLY_TABLES:
        return ["dynamodb:PutItem"]
    return list(actions)


def mesh_scoped_condition(short_name: str, mesh_id: str) -> Dict[str, Any]:
    """The LeadingKeys condition pinning a statement to one mesh partition.

    Returns an EMPTY condition for a table not partitioned on mesh_id, because
    dynamodb:LeadingKeys matches the partition key VALUE. Attaching it to
    routing_history, whose partition key is job_uuid, would require
    job_uuid == mesh_id and deny every read of that table.

    Losing the condition there costs little, because each mesh has its own tables:
    the physical name carries the mesh prefix, so a table only ever holds one
    mesh's rows and cross-mesh isolation is the table boundary rather than this
    condition. The condition remains worthwhile on the mesh_id-partitioned tables
    as a second line of defence.
    """
    _pk = TABLE_SCHEMAS[short_name]["partition_key"]
    if getattr(_pk, "name", None) != "mesh_id":
        return {}
    return {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [mesh_id]}}


def mesh_write_actions(short_name: str) -> List[str]:
    """The write actions a mesh writer needs on one table.

    Shared by the overlay daemon role and the cross-account participant role,
    because a joiner assumes the participant role to do the SAME work against
    the creator's tables that the daemon does locally. Deriving that set in two
    places let it drift in both directions at once: the participant role was
    missing TransactWriteItems on routing_policy, so a cross-account policy
    promote would have failed with AccessDenied, while holding DeleteItem on
    every table, which the daemon deliberately does not.

    A table needing a new action is therefore a one-line change here that both
    roles pick up, rather than two places to keep in step.

    The policy console is deliberately NOT a caller: it writes three tables
    rather than the whole mesh, and its action set is scoped to what an
    administrator does in the UI.
    """
    _actions = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
    if short_name == "overlay_config":
        # Reclaim and tombstone paths delete a peer row outright.
        _actions.append("dynamodb:DeleteItem")
    if short_name == "routing_policy":
        # promote() moves the production pointer and the new version together,
        # so it needs a transaction.
        _actions.append("dynamodb:TransactWriteItems")
    return enforce_append_only(short_name, _actions)


def build_global_tables(
    scope,
    *,
    mesh_id: str,
    replica_regions: List[str],
    is_mesh_creator: bool,
    table_prefix_override: Optional[str] = None,
    force_import: bool = False,
) -> Dict[str, ddb.ITable]:
    """Create or import the mesh's Global Tables.

    Args:
        scope: the SOCAInstall construct, which exposes soca_resources.
        mesh_id: UUID shared by every cluster in this mesh.
        replica_regions: regions to pre-seed replicas in. May be empty; replicas
            are also added at runtime as joiners install in new regions.
        is_mesh_creator: True on the first cluster of a new mesh, which creates
            the tables. Every later cluster imports them.
        table_prefix_override: optional operator-supplied table prefix.
        force_import: import even when is_mesh_creator is True. Set by the
            installer's mesh preflight when the operator adopts tables left
            behind by a failed deploy.

    Returns:
        Map of short table name to ITable. Also published on
        scope.soca_resources[GLOBAL_TABLES_KEY].
    """
    _prefix = compute_prefix(mesh_id, table_prefix_override)

    if is_mesh_creator and not force_import:
        _tables = _create_tables(scope, prefix=_prefix, replica_regions=replica_regions)
    else:
        _tables = _import_tables(scope, prefix=_prefix)

    scope.soca_resources[GLOBAL_TABLES_KEY] = _tables
    scope.soca_resources["cross_region_table_prefix"] = _prefix
    return _tables


def _create_tables(
    scope, *, prefix: str, replica_regions: List[str]
) -> Dict[str, ddb.ITable]:
    """Create every mesh table. Runs only on the first cluster of a new mesh.

    The stream view type is always NEW_AND_OLD_IMAGES on creation, whatever a
    schema entry asks for, for two reasons. CDK rejects any other stream type
    when replication_regions is set, even to an empty list. And a table created
    without NEW_AND_OLD_IMAGES cannot be promoted to a Global Table later,
    because the AWS API refuses ReplicaUpdates against the wrong stream type,
    so forcing it here keeps every install able to gain replicas at runtime. A
    schema asking for NEW_IMAGE still gets what it needs, since NEW_IMAGE is a
    subset of what consumers receive.
    """
    _tables: Dict[str, ddb.ITable] = {}

    for _short_name, _schema in TABLE_SCHEMAS.items():
        _physical_name = make_table_name(prefix, _short_name)
        _kwargs: Dict[str, Any] = {
            "table_name": _physical_name,
            "partition_key": _schema["partition_key"],
            "billing_mode": ddb.BillingMode.PAY_PER_REQUEST,
            "stream": ddb.StreamViewType.NEW_AND_OLD_IMAGES,
            "replication_regions": replica_regions,
            # Mesh state outlives any single cluster's stack.
            "removal_policy": RemovalPolicy.RETAIN,
            "point_in_time_recovery_specification": ddb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
        }
        if "sort_key" in _schema:
            _kwargs["sort_key"] = _schema["sort_key"]
        if "ttl_attribute" in _schema:
            _kwargs["time_to_live_attribute"] = _schema["ttl_attribute"]

        _table = ddb.Table(scope, f"CrossRegionGT-{_short_name}", **_kwargs)

        for _gsi in _schema.get("global_secondary_indexes", []):
            _gsi_kwargs: Dict[str, Any] = {
                "index_name": _gsi["index_name"],
                "partition_key": _gsi["partition_key"],
                "projection_type": ddb.ProjectionType.ALL,
            }
            if "sort_key" in _gsi:
                _gsi_kwargs["sort_key"] = _gsi["sort_key"]
            _table.add_global_secondary_index(**_gsi_kwargs)

        _tables[_short_name] = _table
        if replica_regions:
            logger.info(
                f"Created cross-region Global Table {_physical_name}, replicating to "
                f"{', '.join(replica_regions)}"
            )
        else:
            logger.info(
                f"Created cross-region Global Table {_physical_name} as regional; "
                f"replicas can be added at runtime via UpdateTable"
            )

    return _tables


def _import_tables(scope, *, prefix: str) -> Dict[str, ddb.ITable]:
    """Import the mesh's existing tables. Runs on every joining cluster.

    Imports by attributes rather than by name so the live stream ARN comes
    along, which downstream stream consumers need: a table imported with
    from_table_name() carries no stream and fails synth with "DynamoDB Streams
    must be enabled". The ARN is read with a DescribeTable call at synth time,
    from the stack's own region, since replication has already extended these
    tables to the joiner's region by the time it installs.
    """
    import boto3

    _tables: Dict[str, ddb.ITable] = {}
    _ddb_client = boto3.client("dynamodb", region_name=Stack.of(scope).region)

    for _short_name in SHORT_NAMES:
        _physical_name = make_table_name(prefix, _short_name)
        try:
            _resp = _ddb_client.describe_table(TableName=_physical_name)
            _stream_arn = _resp.get("Table", {}).get("LatestStreamArn")
        except Exception:
            logger.exception(
                f"describe_table failed for {_physical_name}; importing it without a "
                f"stream ARN, so any downstream stream consumer will fail synth"
            )
            _stream_arn = None

        if _stream_arn:
            _tables[_short_name] = ddb.Table.from_table_attributes(
                scope,
                f"CrossRegionGTImport-{_short_name}",
                table_name=_physical_name,
                table_stream_arn=_stream_arn,
            )
            logger.info(
                f"Imported cross-region Global Table {_physical_name} with stream "
                f"{_stream_arn}"
            )
        else:
            _tables[_short_name] = ddb.Table.from_table_name(
                scope, f"CrossRegionGTImport-{_short_name}", _physical_name
            )
            logger.info(
                f"Imported cross-region Global Table {_physical_name} without a stream"
            )

    return _tables
