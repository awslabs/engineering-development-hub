# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cross-account IAM for the mesh.

A mesh may span AWS accounts, for example to bill separate departments. The
Global Tables live in the mesh creator's account, so a joining cluster in
another account cannot reach them directly. The creator deploys one
MeshParticipantRole and each joiner's overlay daemon assumes it.

Two sides, both here:

  build_mesh_participant_role()          deployed by the mesh creator
  grant_assume_role_to_overlay_daemon()  applied on each joiner

Trust is granted at ACCOUNT level: naming an account as a participant lets any
principal in that account which its own IAM permits assume this role. That is
the standard cross-account shape, and it means the joining account's IAM is
what narrows access to its overlay daemon. Set an ExternalId in production to
close the confused-deputy gap that account-level trust leaves open.

Nothing here is created in a single-account mesh.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from aws_cdk import Aws, CfnOutput
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_iam as iam

from helpers.cdk.cross_region.ddb_global_tables import (
    MESH_WRITER_TABLES,
    mesh_scoped_condition,
    mesh_write_actions,
)

logger = logging.getLogger("soca_logger")

_ROLE_NAME_SUFFIX = "-MeshParticipantRole"

# IAM role names are capped at 64 characters and must match [\w+=,.@-]+.
_ROLE_NAME_MAX = 64

# Characters IAM accepts in a role name, beyond alphanumerics.
_ROLE_NAME_EXTRA_CHARS = "_=,.@-"


def mesh_participant_role_name(mesh_id: str) -> str:
    """Compose the participant role name for a mesh, within IAM's limits.

    A mesh_id is normally a 36-character UUID, which fits comfortably. Any
    character IAM would reject becomes a hyphen, and the result is truncated
    so the suffix always survives.
    """
    _sanitized = "".join(
        c if (c.isalnum() or c in _ROLE_NAME_EXTRA_CHARS) else "-" for c in mesh_id
    )
    _max_prefix = _ROLE_NAME_MAX - len(_ROLE_NAME_SUFFIX)
    return f"{_sanitized[:_max_prefix]}{_ROLE_NAME_SUFFIX}"


def _sid(*parts: str) -> str:
    """Compose an IAM Sid. Sid must match [0-9A-Za-z]*."""
    _joined = "".join(p.title().replace("_", "") for p in parts)
    return "".join(c for c in _joined if c.isalnum()) or "Statement"


def build_mesh_participant_role(
    scope,
    *,
    mesh_id: str,
    participant_account_ids: List[str],
    tables: Dict[str, ddb.ITable],
    external_id: Optional[str] = None,
) -> iam.Role:
    """Create the role joining accounts assume to reach the mesh's tables.

    Deployed by the mesh creator only.

    Args:
        scope: the SOCAInstall construct.
        mesh_id: the mesh UUID. Scopes each table statement via LeadingKeys,
            except on tables not partitioned on mesh_id, where the condition
            cannot apply and the table boundary does the scoping instead.
        participant_account_ids: AWS account ids of joining clusters. The
            creator's own account is not listed, since it reaches the tables
            directly through the overlay daemon role.
        tables: short name to ITable, as returned by build_global_tables().
        external_id: shared ExternalId required on assume. Recommended in
            production.

    Returns:
        The created role.
    """
    _accounts = list(participant_account_ids)

    if not _accounts:
        logger.warning(
            "cross_region: MeshParticipantRole is being created with no participant "
            "accounts, so no account can assume it yet. That is expected on a mesh "
            "whose joiners have not been registered, and is configuration drift if "
            "joiners already exist. Add accounts at runtime from Admin then Mesh "
            "then Participants."
        )

    _principals = [iam.AccountPrincipal(_account) for _account in _accounts]
    if not _principals:
        # CDK rejects an empty principal list. Trust this account only, which
        # grants nothing new, until real participants are registered.
        _principals = [iam.AccountPrincipal(Aws.ACCOUNT_ID)]

    _role = iam.Role(
        scope,
        "CrossRegionMeshParticipantRole",
        role_name=mesh_participant_role_name(mesh_id),
        assumed_by=iam.CompositePrincipal(*_principals),
        description=(
            f"Cross-account access to the DynamoDB Global Tables of mesh {mesh_id}, "
            f"assumed by overlay daemons in joining accounts"
        ),
    )

    if external_id:
        # Enforced as a DENY with a NEGATED condition rather than an allow with
        # StringEquals, because a negated match also evaluates true when the
        # condition key is absent entirely. That means a caller who supplies no
        # ExternalId at all is denied, which an Allow-side StringEquals on the
        # existing trust statement would not achieve.
        _role.assume_role_policy.add_statements(
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                actions=["sts:AssumeRole"],
                principals=_principals,
                conditions={"StringNotEquals": {"sts:ExternalId": external_id}},
            )
        )

    _grant_mesh_table_access(_role, mesh_id=mesh_id, tables=tables)

    # The joining account's installer needs this ARN, so surface it as a stack
    # output rather than making an operator go looking in the IAM console.
    CfnOutput(
        scope,
        "CrossRegionMeshParticipantRoleArn",
        value=_role.role_arn,
        description=(
            "ARN of the cross-account role joining clusters assume to reach this "
            "mesh's Global Tables. Pass it to the installer in the joining account "
            "with --cross-region-mesh-role-arn."
        ),
    )
    if external_id:
        # The VALUE is deliberately not published here. It is necessarily present
        # in this role's trust policy, since conditioning on sts:ExternalId is how
        # the check is enforced, so dropping the output reduces copies rather than
        # making the value private. The output is the copy worth dropping: stack
        # outputs are what get pasted into tickets and screenshots, and the
        # operator supplied the value already.
        CfnOutput(
            scope,
            "CrossRegionMeshParticipantExternalIdRequired",
            value="true",
            description=(
                "This mesh participant role requires an ExternalId on assume. Pass "
                "the value you configured to the installer in the joining account "
                "with --cross-region-mesh-role-external-id. The value itself is not "
                "published here, because it is a shared secret."
            ),
        )

    return _role


def _grant_mesh_table_access(
    role: iam.IRole, *, mesh_id: str, tables: Dict[str, ddb.ITable]
) -> None:
    """Mirror the local daemon's table access for cross-account callers.

    Scoped to the mesh partition. Which row inside that partition a joiner may
    write is enforced by the daemon, because IAM cannot condition on a sort-key
    value, so the trust boundary here is the mesh rather than the cluster.
    """
    for _short_name, _table in tables.items():
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("participant", "read", _short_name),
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:GetItem",
                    "dynamodb:Query",
                    "dynamodb:DescribeTable",
                ],
                resources=[_table.table_arn],
                conditions=mesh_scoped_condition(_short_name, mesh_id),
            )
        )
        # Indexes carry no LeadingKeys condition; see the matching comment in
        # overlay_iam._grant_mesh_table_access.
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("participant", "read", _short_name, "indexes"),
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:Query"],
                resources=[f"{_table.table_arn}/index/*"],
            )
        )
        # A joiner installing in a new region adds its own region as a Global
        # Table replica before it pre-registers. UpdateTable is a control-plane
        # action and takes no LeadingKeys condition, so this is scoped to the
        # mesh's tables and nothing finer.
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("participant", "replicas", _short_name),
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:UpdateTable"],
                resources=[_table.table_arn],
            )
        )

    for _short_name in MESH_WRITER_TABLES:
        _table = tables.get(_short_name)
        if _table is None:
            continue
        role.add_to_principal_policy(
            iam.PolicyStatement(
                sid=_sid("participant", "write", _short_name),
                effect=iam.Effect.ALLOW,
                actions=mesh_write_actions(_short_name),
                resources=[_table.table_arn],
                conditions=mesh_scoped_condition(_short_name, mesh_id),
            )
        )


def grant_assume_role_to_overlay_daemon(
    *,
    overlay_daemon_role: iam.IRole,
    mesh_role_arn: str,
) -> None:
    """Let a joining cluster's overlay daemon assume the participant role.

    The ARN comes from the mesh creator after its stack deploys, and reaches
    the joiner as Config.services.cross_region.mesh_role_arn. A no-op when
    unset, which is the single-account case.
    """
    if not mesh_role_arn:
        return
    overlay_daemon_role.add_to_principal_policy(
        iam.PolicyStatement(
            sid="CrossRegionAssumeMeshParticipantRole",
            effect=iam.Effect.ALLOW,
            actions=["sts:AssumeRole"],
            resources=[mesh_role_arn],
        )
    )
