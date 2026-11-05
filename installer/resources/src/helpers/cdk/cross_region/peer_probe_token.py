# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cross-region overlay mesh: the peer-probe token secret.

WHAT THIS PROVISIONS. One Secrets Manager secret per cluster holding the shared
bearer token the mesh job endpoints authenticate with, and the controller-role
grant that lets the web tier read it. CR-307548143 shipped
`job_auth.read_token_pair`, which resolves
`/configuration/Overlay/peer_probe_token_secret_arn` and reads the secret behind
it; until this module runs there is no ARN under that key, so
`authenticate_peer` answers 503 "not enabled on this cluster" on every request.
This is what switches those endpoints on.

THE PAYLOAD SHAPE IS A CONTRACT, not a convenience. `read_token_pair` parses the
SecretString as JSON and takes `current` and `previous` out of it, and
`_token_field` REFUSES a field that is present and not a string rather than
coercing it. So the value written here must be a JSON object whose `current` is a
string and whose `previous` is a string or null. `previous` is null on a cluster
that has never rotated, which `_token_field` reads as absent.

    {
      "current":     "<64 alphanumeric characters>",
      "previous":    null,
      "rotation_id": "initial",
      "rotated_at":  "1970-01-01T00:00:00Z"
    }

The generated value is 64 alphanumeric characters rather than hex. That is what
`exclude_punctuation` plus `password_length` produces, and it is worth stating
because the shape this was ported from documented the same call as hex.

CREATOR AND JOINER DIFFER, and the difference is which cluster can mint a token.
The mesh creator's secret is generated with a live token. A joiner's is created
with an empty `current`, because the token is shared across the mesh and a joiner
minting its own would produce a value no peer accepts. A joiner's endpoints
therefore keep answering 503 until the creator's rotation broadcast reaches it,
which is the next change rather than this one. An empty `current` reads as absent
through `_token_field`, so a joiner behaves exactly as it does today.

WHY THERE IS NO DEDICATED KMS KEY. The shape this was ported from created a
customer-managed key per cluster with `enable_key_rotation` and RETAIN. This uses
`_resolve_secrets_cmk`, the same key the WireGuard private key is encrypted with,
which is the configured EDH CMK or the AWS managed key when none is set. Two
reasons. The installer contains no other `kms.Key` construct at all, so a
dedicated key here would be the only one. And the WireGuard secret IS this
cluster's mesh identity, pinned by every peer and unrecoverable if lost, while
this token is regenerable by rotation - encrypting the token more strictly than
the identity it travels beside is not a defensible ordering.

WHY DESTROY RATHER THAN RETAIN, which is also a departure. RETAIN is right for
the WireGuard secret because that secret is an identity: losing it removes the
cluster from the mesh permanently. This token is regenerable, and EDH clusters
are created and destroyed rather than updated in place, so RETAIN would leave a
secret behind on every teardown - and Secrets Manager refuses to create a secret
whose name matches one pending deletion, so the next cluster built under the same
id would fail on the name. The recovery window still applies to the deletion
itself, so a destroy is not immediate.
"""

from __future__ import annotations

import logging
from typing import Optional

from aws_cdk import RemovalPolicy, SecretValue
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_secretsmanager as secretsmanager

logger = logging.getLogger("soca_logger")

# soca_resources key this module publishes, so the post-controller pass and later
# changes can find the secret the first pass created.
PROBE_TOKEN_SECRET_KEY = "cross_region_peer_probe_token_secret"

# Length of a generated token. 64 alphanumeric characters is what the two shipped
# session secrets use, and it is well past what a shared bearer token needs.
TOKEN_LENGTH = 64

# The fields around the generated one. `previous` is null rather than an empty
# string because `job_auth._token_field` reads null as absent and would refuse a
# non-string, and because a cluster that has never rotated genuinely has no
# previous token rather than an empty one.
_CREATOR_TEMPLATE = (
    '{"previous": null, "rotation_id": "initial", '
    '"rotated_at": "1970-01-01T00:00:00Z"}'
)

# A joiner's whole payload. Written literally rather than generated: the value
# carries no secret material, precisely because a joiner must not mint a token of
# its own.
_JOINER_PAYLOAD = (
    '{"current": "", "previous": null, "rotation_id": "pending-broadcast", '
    '"rotated_at": "1970-01-01T00:00:00Z"}'
)


def secret_name_for(cluster_id: str) -> str:
    """The secret's name, as both the construct and the grants need it."""
    return f"/edh/{cluster_id}/overlay/peer_probe_token"


def build_peer_probe_token_secret(
    scope,
    *,
    cluster_id: str,
    mesh_id: str,
    is_mesh_creator: bool,
    cluster_cmk: Optional[kms.IKey] = None,
) -> secretsmanager.ISecret:
    """Create this cluster's peer-probe token secret.

    Created on every cluster, creator and joiner alike, so that the ARN the web
    tier resolves exists everywhere and the difference between clusters is the
    token's value rather than the presence of the secret.

    Args:
        scope: the SOCAInstall construct.
        cluster_id: this cluster's id, which names the secret.
        mesh_id: the mesh this cluster belongs to. Description only.
        is_mesh_creator: whether this cluster mints the initial token.
        cluster_cmk: the CMK to encrypt with, or None for the AWS managed key.
    """
    _secret_name = secret_name_for(cluster_id)

    if is_mesh_creator:
        logger.info(
            f"cross_region: generating the initial peer-probe token in "
            f"{_secret_name} for mesh {mesh_id}"
        )
        return secretsmanager.Secret(
            scope,
            "CrossRegionPeerProbeTokenSecret",
            secret_name=_secret_name,
            description=(
                f"Shared bearer token for cross-cluster mesh job requests in mesh "
                f"{mesh_id}. Generated on the mesh creator."
            ),
            encryption_key=cluster_cmk,
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template=_CREATOR_TEMPLATE,
                generate_string_key="current",
                password_length=TOKEN_LENGTH,
                exclude_punctuation=True,
                include_space=False,
                # False explicitly, matching the shipped session secrets. Left at
                # its default of True it asks for one character of every class
                # while exclude_punctuation removes a class, which is a
                # contradiction to hand a generator.
                require_each_included_type=False,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

    logger.info(
        f"cross_region: creating {_secret_name} with an empty token; this cluster "
        f"is a joiner and receives the mesh token by broadcast"
    )
    return secretsmanager.Secret(
        scope,
        "CrossRegionPeerProbeTokenSecret",
        secret_name=_secret_name,
        description=(
            f"Shared bearer token for cross-cluster mesh job requests in mesh "
            f"{mesh_id}. Empty until the mesh creator broadcasts the live token."
        ),
        encryption_key=cluster_cmk,
        secret_string_value=SecretValue.unsafe_plain_text(_JOINER_PAYLOAD),
        removal_policy=RemovalPolicy.DESTROY,
    )


def grant_controller_read_probe_token(
    controller_role: iam.IRole,
    *,
    secret: secretsmanager.ISecret,
    cluster_cmk: Optional[kms.IKey] = None,
) -> None:
    """Let the controller's web tier read the token.

    The web tier runs on the controller under its instance role, and
    `job_auth.read_token_pair` reads the secret on a cache miss on every mesh job
    request.

    Written as explicit PolicyStatements rather than `secret.grant_read()` to
    match how every other grant in this package is written, and because
    grant_read on an imported secret attaches to whatever principal CDK infers
    rather than the one named here.

    The ARN is matched with a trailing wildcard as well as bare, because Secrets
    Manager appends a random six-character suffix to a secret's ARN at creation.
    A policy naming only the bare ARN matches nothing at runtime.

    No KMS statement when `cluster_cmk` is None: that is the AWS managed key,
    which authorizes through the Secrets Manager call itself and needs no grant
    on the caller.
    """
    controller_role.add_to_principal_policy(
        iam.PolicyStatement(
            sid="CrossRegionPeerProbeTokenRead",
            effect=iam.Effect.ALLOW,
            actions=[
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
            ],
            resources=[secret.secret_arn, f"{secret.secret_arn}-*"],
        )
    )

    if cluster_cmk is None:
        return

    controller_role.add_to_principal_policy(
        iam.PolicyStatement(
            sid="CrossRegionPeerProbeTokenDecrypt",
            effect=iam.Effect.ALLOW,
            actions=["kms:Decrypt", "kms:DescribeKey"],
            resources=[cluster_cmk.key_arn],
        )
    )
