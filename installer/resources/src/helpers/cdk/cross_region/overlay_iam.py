# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
IAM for the cross-region overlay daemon and the mesh policy console.

Two roles live here.

The overlay daemon role is used by the edh-overlay-daemon unit on the
controller. It reads every peer row in its own mesh so it can render the
WireGuard config, writes its own peer row and heartbeat, appends to the audit
log, reads its WireGuard private key, and maintains the managed prefix list
that keeps the mesh security-group ingress current.

The policy console role is used by the WebUI when an administrator drives the
mesh admin endpoints. It has broader DynamoDB access than the daemon, because
approving, decommissioning or reclaiming a peer means writing rows the daemon
must never touch.

Every DynamoDB statement is scoped to the cluster's own mesh with a
dynamodb:LeadingKeys condition on the partition key. IAM cannot restrict by
sort-key VALUE, since dynamodb:Attributes matches attribute names rather than
key values, so "own row only" is enforced application-side and IAM scopes to
the mesh partition. That split is deliberate and is why the daemon's write
statements look broader than the daemon's actual behaviour.

Grants are exposed as functions taking a role, not as a construct holding
state, because the same grants are applied twice: once to the dedicated daemon
role, and once to the controller's own instance role in a single-account mesh
where the daemon runs on the controller and never assumes a separate role.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional

from aws_cdk import Aws
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_secretsmanager as secretsmanager

from helpers.cdk.cross_region.ddb_global_tables import (
    MESH_WRITER_TABLES,
    enforce_append_only,
    mesh_scoped_condition,
    mesh_write_actions,
)

logger = logging.getLogger("soca_logger")

# Tables the policy console may WRITE. Everything else in the mesh is read-only
# to the console. Keyed on the short table name rather than on a CDK construct
# id so that renaming a construct cannot silently change permissions.
_CONSOLE_WRITABLE_TABLES = frozenset(
    {
        "overlay_config",  # approve, decommission, reclaim, tombstone a peer
        "overlay_audit",  # record who did it
        "routing_policy",  # save, promote and roll back rule versions
    }
)

# Tables the daemon may write are defined once in ddb_global_tables as
# MESH_WRITER_TABLES, so the cross-account participant role selects the same set.


def _sid(*parts: str) -> str:
    """Compose an IAM Sid. Sid must match [0-9A-Za-z]*, so strip everything else."""
    _joined = "".join(p.title().replace("_", "") for p in parts)
    return "".join(c for c in _joined if c.isalnum()) or "Statement"


def _mesh_scoped(short_name: str, mesh_id: str) -> Dict[str, Any]:
    """Per-table mesh scoping, empty for tables not partitioned on mesh_id."""
    return mesh_scoped_condition(short_name, mesh_id)


def build_overlay_daemon_role(
    scope,
    *,
    cluster_id: str,
    mesh_id: str,
    tables: Dict[str, ddb.ITable],
    private_key_secret: secretsmanager.ISecret,
    cluster_cmk: kms.IKey,
) -> iam.Role:
    """Create the dedicated overlay daemon role and grant it everything it needs.

    Args:
        scope: the SOCAInstall construct.
        cluster_id: this cluster's id, used in the role name and tag conditions.
        mesh_id: the mesh this cluster belongs to; scopes every DDB statement.
        tables: short name to ITable, as returned by build_global_tables().
        private_key_secret: this cluster's WireGuard private key.
        cluster_cmk: the CMK the secret is encrypted under.

    Returns:
        The created role.
    """
    _role = iam.Role(
        scope,
        "CrossRegionOverlayDaemonRole",
        role_name=f"{cluster_id}-overlay-daemon",
        assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        description=f"Overlay daemon for cluster {cluster_id} in mesh {mesh_id}",
    )
    grant_overlay_daemon_permissions(
        _role,
        cluster_id=cluster_id,
        mesh_id=mesh_id,
        tables=tables,
        private_key_secret=private_key_secret,
        cluster_cmk=cluster_cmk,
    )
    return _role


def grant_overlay_daemon_permissions(
    role: iam.IRole,
    *,
    cluster_id: str,
    mesh_id: str,
    tables: Dict[str, ddb.ITable],
    private_key_secret: Optional[secretsmanager.ISecret] = None,
    cluster_cmk: Optional[kms.IKey] = None,
) -> None:
    """Grant one role everything the overlay daemon needs.

    Applied to the dedicated daemon role, and applied a second time to the
    controller's instance role in a single-account mesh, where the daemon runs
    on the controller under that role and never assumes the daemon role. Without
    the second application the daemon gets AccessDenied on every mesh query.

    Call this at most once per role: re-applying adds duplicate statements,
    which is harmless but makes the rendered policy hard to read.
    """
    _grant_mesh_table_access(role, mesh_id=mesh_id, tables=tables)
    if private_key_secret is not None:
        _grant_private_key_access(role, secret=private_key_secret, cluster_cmk=cluster_cmk)
    _grant_ec2_describe(role)
    _grant_prefix_list_maintenance(role, cluster_id=cluster_id)
    _grant_metrics(role)


def _grant_mesh_table_access(
    role: iam.IRole, *, mesh_id: str, tables: Dict[str, ddb.ITable]
) -> None:
    """Read the whole mesh, write the rows the daemon owns.

    Read is granted across every table present so the daemon can see every peer
    when rendering config, and so the routing paths can consult history they must
    not modify. Writes are granted only on MESH_WRITER_TABLES, scoped to the mesh
    partition; which row within the partition gets written is enforced by the
    daemon itself, because IAM cannot condition on a sort-key value.
    """
    for _short_name, _table in tables.items():
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("read", _short_name),
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:GetItem",
                    "dynamodb:Query",
                    "dynamodb:DescribeTable",
                ],
                resources=[_table.table_arn],
                conditions=_mesh_scoped(_short_name, mesh_id),
            )
        )
        # Secondary indexes get their own statement with NO LeadingKeys
        # condition. Most of these indexes are partitioned on something other
        # than mesh_id (lifecycle, cluster_id, rule_id, local_cluster_id), and a
        # LeadingKeys value is matched against the partition key of whatever is
        # being queried, so a condition pinned to mesh_id risks denying every
        # query against them. Scoping is the table boundary, as it is for
        # routing_history: the physical name carries the mesh prefix, so an index
        # only ever spans one mesh's rows.
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("read", _short_name, "indexes"),
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:Query"],
                resources=[f"{_table.table_arn}/index/*"],
            )
        )

    for _short_name in MESH_WRITER_TABLES:
        _table = tables.get(_short_name)
        if _table is None:
            # Routing tables are absent on a mesh without routing; skip rather
            # than emitting a statement against a table that does not exist.
            continue

        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("write", _short_name),
                effect=iam.Effect.ALLOW,
                actions=mesh_write_actions(_short_name),
                resources=[_table.table_arn],
                conditions=_mesh_scoped(_short_name, mesh_id),
            )
        )


def _grant_private_key_access(
    role: iam.IRole,
    *,
    secret: secretsmanager.ISecret,
    cluster_cmk: Optional[kms.IKey],
) -> None:
    """Read the WireGuard private key, and write it once on first boot.

    The write grant is needed because the daemon generates its own keypair the
    first time it starts: a secret created by CDK holds an auto-generated
    placeholder that is not a valid Curve25519 private key, so the daemon
    replaces it. Scoped to this cluster's own secret ARN, so the daemon cannot
    write any other secret.
    """
    secret.grant_read(role)
    role.add_to_principal_policy(
        iam.PolicyStatement(
            sid="CrossRegionWireGuardSecretWriteSelf",
            effect=iam.Effect.ALLOW,
            actions=["secretsmanager:PutSecretValue"],
            resources=[secret.secret_arn],
        )
    )
    if cluster_cmk is not None:
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid="CrossRegionClusterCmkDecrypt",
                effect=iam.Effect.ALLOW,
                actions=["kms:Decrypt", "kms:DescribeKey"],
                resources=[cluster_cmk.key_arn],
            )
        )


def _grant_ec2_describe(role: iam.IRole) -> None:
    """Describe calls used to resolve peer endpoints and read the prefix list.

    Resource is "*" because none of these actions support resource-level
    scoping. They are all read-only.
    """
    role.add_to_principal_policy(
        iam.PolicyStatement(
            sid="CrossRegionEc2Describe",
            effect=iam.Effect.ALLOW,
            actions=[
                "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeAddresses",
                "ec2:DescribeManagedPrefixLists",
                "ec2:GetManagedPrefixListEntries",
            ],
            resources=["*"],
        )
    )


def _grant_prefix_list_maintenance(role: iam.IRole, *, cluster_id: str) -> None:
    """Keep the managed prefix list of mesh peer endpoints current.

    The prefix list backs the security-group rules that admit WireGuard
    traffic, so the daemon rewrites it as peers join and leave. Restricted to
    prefix lists tagged with this cluster's id, and the ARN uses Aws.PARTITION
    so the statement is correct in GovCloud and China as well as commercial.
    """
    role.add_to_principal_policy(
        iam.PolicyStatement(
            sid="CrossRegionManagedPrefixListUpdate",
            effect=iam.Effect.ALLOW,
            actions=[
                "ec2:ModifyManagedPrefixList",
                "ec2:GetManagedPrefixListEntries",
                "ec2:DescribeManagedPrefixLists",
            ],
            resources=[f"arn:{Aws.PARTITION}:ec2:*:{Aws.ACCOUNT_ID}:prefix-list/*"],
            conditions={
                "StringEquals": {"aws:ResourceTag/edh:ClusterId": cluster_id}
            },
        )
    )


def _grant_metrics(role: iam.IRole) -> None:
    """Emit and read the mesh's CloudWatch metrics.

    PutMetricData takes no resource-level scoping, so each write is pinned to
    one namespace with a cloudwatch:namespace condition instead. The read
    actions support neither, so they are unconditioned; they are read-only.
    """
    for _namespace in ("MeshControlPlane", "EDH/Mesh"):
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("metrics", "write", _namespace.replace("/", "")),
                effect=iam.Effect.ALLOW,
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
                conditions={"StringEquals": {"cloudwatch:namespace": _namespace}},
            )
        )
    role.add_to_principal_policy(
        iam.PolicyStatement(
            sid="CrossRegionMeshMetricsRead",
            effect=iam.Effect.ALLOW,
            actions=[
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:GetMetricData",
                "cloudwatch:ListMetrics",
            ],
            resources=["*"],
        )
    )


def build_policy_console_role(
    scope,
    *,
    cluster_id: str,
    mesh_id: str,
    tables: Dict[str, ddb.ITable],
    assumed_by: iam.IPrincipal,
) -> iam.Role:
    """Create the role the WebUI assumes for mesh administration.

    Reads every mesh table so the admin console can render peers, health, audit
    and policy. Writes only the tables an administrator actually changes, listed
    in _CONSOLE_WRITABLE_TABLES.

    Args:
        assumed_by: the principal allowed to assume this role, normally the
            controller's instance role, since the WebUI runs on the controller.
    """
    _role = iam.Role(
        scope,
        "CrossRegionPolicyConsoleRole",
        role_name=f"{cluster_id}-policy-console",
        assumed_by=assumed_by,
        description=f"Mesh policy console for cluster {cluster_id} in mesh {mesh_id}",
    )

    for _short_name, _table in tables.items():
        _role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("console", "read", _short_name),
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:GetItem",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                    "dynamodb:DescribeTable",
                ],
                resources=[_table.table_arn],
                conditions=_mesh_scoped(_short_name, mesh_id),
            )
        )
        # Indexes carry no LeadingKeys condition; see the comment in
        # _grant_mesh_table_access above. The console is the third reader of
        # these indexes and needs the same treatment as the other two.
        _role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("console", "read", _short_name, "indexes"),
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:Query", "dynamodb:Scan"],
                resources=[f"{_table.table_arn}/index/*"],
            )
        )

        if _short_name in _CONSOLE_WRITABLE_TABLES:
            _console_write_actions = enforce_append_only(
                _short_name,
                [
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    # Reclaiming a tombstoned peer removes its row.
                    "dynamodb:DeleteItem",
                ],
            )

            _role.add_to_principal_policy(
                iam.PolicyStatement(
                    sid=_sid("console", "write", _short_name),
                    effect=iam.Effect.ALLOW,
                    actions=_console_write_actions,
                    resources=[_table.table_arn],
                    conditions=_mesh_scoped(_short_name, mesh_id),
                )
            )

    return _role


def console_writable_tables() -> Iterable[str]:
    """The tables the policy console may write. Exposed for tests."""
    return tuple(sorted(_CONSOLE_WRITABLE_TABLES))
