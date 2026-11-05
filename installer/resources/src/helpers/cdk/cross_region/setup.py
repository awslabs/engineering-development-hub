# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cross-region overlay mesh: CDK orchestration.

Provisions the mesh's shared state and the IAM around it. Everything here is
gated on Config.services.cross_region.enabled; with the flag off, nothing in
this module runs and the stack deploys exactly as it does without the feature.

The work is split across two passes that straddle self.controller():

  cross_region_setup()                 before self.controller()
    Global Tables, WireGuard private-key secret, peer-probe token secret,
    overlay daemon role, the cross-account participant role, and the SSM keys
    the controller bootstrap reads.

  cross_region_post_controller_setup()  after self.controller()
    Policy console role, the daemon grants replicated onto the controller's
    instance role, the controller's read grant on the peer-probe token, and the
    joiner-side assume-role grant.

The split is a grouping rather than an ordering requirement, and it is worth
being precise about that because the shape suggests otherwise. Everything the
second pass reads already exists before the FIRST pass runs: controller_role is
created by self.iam_roles(), secretsmanager_kms_key_id is resolved earlier
still, and self.controller() itself references no cross-region resource. Both
passes could be called together after iam_roles(). The split is kept because it
puts the console role and the controller-role grants next to the controller they
concern, and because it mirrors the structure this was ported from.

What is deliberately NOT here yet, because the code that consumes it lands in
later changes: key rotation, the managed prefix list and its sync Lambda, the
peer-probe token's ROTATION (the secret itself is here; the Lambda, its schedule
and the broadcast that reaches a joiner are not, so a joiner's token stays empty),
loop detection, the routing canary, and the mesh dashboard and alarms. Each
arrives with its consumer rather than ahead of it.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from aws_cdk import RemovalPolicy
from aws_cdk import aws_kms as kms
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm

from helpers.cdk.cross_region.ddb_global_tables import (
    GLOBAL_TABLES_KEY,
    build_global_tables,
)
from helpers.cdk.cross_region.mesh_iam import (
    build_mesh_participant_role,
    grant_assume_role_to_overlay_daemon,
)
from helpers.cdk.cross_region.overlay_iam import (
    build_overlay_daemon_role,
    build_policy_console_role,
    grant_overlay_daemon_permissions,
)
from helpers.cdk.cross_region.peer_probe_token import (
    PROBE_TOKEN_SECRET_KEY,
    build_peer_probe_token_secret,
    grant_controller_read_probe_token,
)

logger = logging.getLogger("soca_logger")

# soca_resources keys this module publishes, so the post-controller pass and
# later changes can find what the first pass created.
WG_SECRET_KEY = "cross_region_wg_private_key"
DAEMON_ROLE_KEY = "cross_region_overlay_daemon_role"
PARTICIPANT_ROLE_KEY = "cross_region_mesh_participant_role"


def is_enabled(get_config_key) -> bool:
    """Whether the cross-region feature is switched on for this install."""
    return bool(
        get_config_key(
            key_name="Config.services.cross_region.enabled",
            expected_type=bool,
            required=False,
            default=False,
        )
    )


def _read_mesh_settings(get_config_key) -> dict:
    """Read the cross-region config block into a plain dict.

    Raises:
        ValueError: if the feature is on but mesh_id is unset. Deriving the
            table prefix needs it, and continuing without one would name this
            cluster's tables differently from its peers.
    """
    _mesh_id = get_config_key(
        key_name="Config.services.cross_region.mesh_id",
        expected_type=str,
        required=False,
        default="",
    )
    if not _mesh_id:
        raise ValueError(
            "Config.services.cross_region.enabled is true but "
            "Config.services.cross_region.mesh_id is not set. Generate one UUID per "
            "fleet and use the same value on every cluster in the mesh."
        )

    _replica_regions = get_config_key(
        key_name="Config.services.cross_region.replica_regions",
        expected_type=str,
        required=False,
        default="",
    )
    _participants = get_config_key(
        key_name="Config.services.cross_region.participant_accounts",
        expected_type=str,
        required=False,
        default="",
    )

    return {
        "mesh_id": _mesh_id,
        "is_mesh_creator": bool(
            get_config_key(
                key_name="Config.services.cross_region.is_mesh_creator",
                expected_type=bool,
                required=False,
                default=False,
            )
        ),
        "table_prefix_override": get_config_key(
            key_name="Config.services.cross_region.mesh_table_prefix_override",
            expected_type=str,
            required=False,
            default="",
        )
        or None,
        "replica_regions": _split_csv(_replica_regions),
        "participant_accounts": _split_csv(_participants),
        "mesh_role_arn": get_config_key(
            key_name="Config.services.cross_region.mesh_role_arn",
            expected_type=str,
            required=False,
            default="",
        ),
        "mesh_role_external_id": get_config_key(
            key_name="Config.services.cross_region.mesh_role_external_id",
            expected_type=str,
            required=False,
            default="",
        ),
        "import_overlay_secret": bool(
            get_config_key(
                key_name="Config.services.cross_region.preflight.import_overlay_secret",
                expected_type=bool,
                required=False,
                default=False,
            )
        ),
        "import_mesh_tables": bool(
            get_config_key(
                key_name="Config.services.cross_region.preflight.import_mesh_tables",
                expected_type=bool,
                required=False,
                default=False,
            )
        ),
    }


def _split_csv(value: Optional[str]) -> List[str]:
    """Split a comma-separated config value, dropping blanks and whitespace."""
    if not value:
        return []
    return [_item.strip() for _item in value.split(",") if _item.strip()]


def cross_region_setup(scope, *, get_config_key, user_specified_variables) -> None:
    """First pass. Runs before self.controller().

    Creates the mesh's Global Tables, this cluster's WireGuard private-key
    secret, the overlay daemon role, and on a mesh creator the cross-account
    participant role. Publishes the SSM keys the controller bootstrap reads.
    """
    _settings = _read_mesh_settings(get_config_key)
    _cluster_id = user_specified_variables.cluster_id
    _mesh_id = _settings["mesh_id"]

    logger.info(
        f"cross_region: configuring mesh {_mesh_id} for cluster {_cluster_id} as "
        f"{'creator' if _settings['is_mesh_creator'] else 'joiner'}"
    )

    _tables = build_global_tables(
        scope,
        mesh_id=_mesh_id,
        replica_regions=_settings["replica_regions"],
        is_mesh_creator=_settings["is_mesh_creator"],
        table_prefix_override=_settings["table_prefix_override"],
        force_import=_settings["import_mesh_tables"],
    )

    _wg_secret = _build_wg_secret(
        scope,
        cluster_id=_cluster_id,
        import_existing=_settings["import_overlay_secret"],
    )
    scope.soca_resources[WG_SECRET_KEY] = _wg_secret

    _cluster_cmk = _resolve_secrets_cmk(scope)

    # Created on every cluster so the ARN the web tier resolves always exists; on
    # a joiner the token inside it is empty until the creator broadcasts one.
    _probe_token_secret = build_peer_probe_token_secret(
        scope,
        cluster_id=_cluster_id,
        mesh_id=_mesh_id,
        is_mesh_creator=_settings["is_mesh_creator"],
        cluster_cmk=_cluster_cmk,
    )
    scope.soca_resources[PROBE_TOKEN_SECRET_KEY] = _probe_token_secret

    _daemon_role = build_overlay_daemon_role(
        scope,
        cluster_id=_cluster_id,
        mesh_id=_mesh_id,
        tables=_tables,
        private_key_secret=_wg_secret,
        cluster_cmk=_cluster_cmk,
    )
    scope.soca_resources[DAEMON_ROLE_KEY] = _daemon_role

    if _settings["is_mesh_creator"]:
        _participant_role = build_mesh_participant_role(
            scope,
            mesh_id=_mesh_id,
            participant_account_ids=_settings["participant_accounts"],
            tables=_tables,
            external_id=_settings["mesh_role_external_id"] or None,
        )
        scope.soca_resources[PARTICIPANT_ROLE_KEY] = _participant_role

    _publish_ssm_keys(
        scope,
        cluster_id=_cluster_id,
        settings=_settings,
        wg_secret=_wg_secret,
        probe_token_secret=_probe_token_secret,
    )


def cross_region_post_controller_setup(
    scope, *, get_config_key, user_specified_variables
) -> None:
    """Second pass. Runs after self.controller().

    Everything here concerns the controller's instance role: the console role it
    assumes, and the daemon grants replicated onto it. That role already exists
    before the first pass, created by iam_roles(), so this runs here for
    proximity rather than out of necessity. See the module docstring.
    """
    _settings = _read_mesh_settings(get_config_key)
    _cluster_id = user_specified_variables.cluster_id
    _mesh_id = _settings["mesh_id"]
    _tables = scope.soca_resources[GLOBAL_TABLES_KEY]
    _controller_role = scope.soca_resources["controller_role"]

    # The WebUI runs on the controller, so the controller's role is what assumes
    # the policy console role.
    build_policy_console_role(
        scope,
        cluster_id=_cluster_id,
        mesh_id=_mesh_id,
        tables=_tables,
        assumed_by=_controller_role,
    )

    # In a single-account mesh the daemon runs on the controller under the
    # controller's own instance role and never assumes the daemon role, so the
    # same grants have to land there too. In a cross-account mesh this is
    # redundant but harmless, because the mesh tables live in another account
    # and the LeadingKeys conditions still apply.
    grant_overlay_daemon_permissions(
        _controller_role,
        cluster_id=_cluster_id,
        mesh_id=_mesh_id,
        tables=_tables,
        private_key_secret=scope.soca_resources[WG_SECRET_KEY],
        cluster_cmk=_resolve_secrets_cmk(scope),
    )

    # The web tier runs on the controller, and job_auth.read_token_pair reads the
    # token secret on a cache miss on every mesh job request. This grant is what
    # makes the difference between a 503 naming a transient secret-read failure
    # and a request that authenticates.
    grant_controller_read_probe_token(
        _controller_role,
        secret=scope.soca_resources[PROBE_TOKEN_SECRET_KEY],
        cluster_cmk=_resolve_secrets_cmk(scope),
    )

    # Joiner side of a cross-account mesh: let the daemon reach the creator's
    # tables. A no-op when mesh_role_arn is unset, which is the single-account case.
    if _settings["mesh_role_arn"]:
        for _role in (scope.soca_resources[DAEMON_ROLE_KEY], _controller_role):
            grant_assume_role_to_overlay_daemon(
                overlay_daemon_role=_role,
                mesh_role_arn=_settings["mesh_role_arn"],
            )


def _build_wg_secret(
    scope, *, cluster_id: str, import_existing: bool
) -> secretsmanager.ISecret:
    """Create or adopt this cluster's WireGuard private-key secret.

    The whole secret string is the private key, with no JSON wrapper and no
    generation parameters of ours. CloudFormation still seeds a default random
    placeholder, which the daemon overwrites with the output of `wg genkey` the
    first time it starts; that is why the daemon holds PutSecretValue on this
    ARN. What matters is that the template carries no generation settings for a
    value CFN must never meaningfully produce, so no later edit to them can
    replace a live key.

    RETAIN is load-bearing rather than cautious. This secret IS the cluster's
    mesh identity: its public key is pinned by every peer. Two things break
    without it. A replacement, from a changed secret name or logical id, would
    delete the identity during an otherwise routine deploy. And a failed deploy
    would schedule the secret for deletion, after which Secrets Manager refuses
    to create another secret with the same name, so the redeploy fails on the
    name instead of adopting the identity through import_overlay_secret below.
    """
    _secret_name = f"/edh/{cluster_id}/overlay/private_key"

    if import_existing:
        logger.info(
            f"cross_region: adopting the existing WireGuard private-key secret "
            f"{_secret_name} rather than creating a new one, preserving this "
            f"cluster's mesh identity"
        )
        # from_secret_name_v2 rather than from_secret_complete_arn: Secrets
        # Manager appends a random 6-character suffix to the ARN at creation and
        # that suffix is not knowable here.
        return secretsmanager.Secret.from_secret_name_v2(
            scope, "CrossRegionWireGuardSecretImported", secret_name=_secret_name
        )

    return secretsmanager.Secret(
        scope,
        "CrossRegionWireGuardSecret",
        secret_name=_secret_name,
        description=f"WireGuard private key for cluster {cluster_id} in the cross-region overlay mesh",
        encryption_key=_resolve_secrets_cmk(scope),
        removal_policy=RemovalPolicy.RETAIN,
    )


def _resolve_secrets_cmk(scope) -> Optional[kms.IKey]:
    """The CMK EDH encrypts Secrets Manager secrets with, if one is configured.

    None means the AWS managed key, which is what every other EDH secret falls
    back to, so the daemon needs no KMS grant in that case.
    """
    return scope.soca_resources.get("secretsmanager_kms_key_id") or None


def _publish_ssm_keys(
    scope, *, cluster_id: str, settings: dict, wg_secret, probe_token_secret
) -> None:
    """Publish the runtime keys the controller bootstrap and daemon read.

    These are the /configuration/Overlay/* keys registered in
    socaconfig_key_validator.yml, written here at deploy time because the
    bootstrap shell scripts resolve them before any daemon exists to write them.

    peer_probe_token_secret_arn is read by job_auth.read_token_pair on the web
    tier, and its ABSENCE is a supported state there rather than an error: that
    function reports a cluster with no key as one that is in the mesh but not
    taking job requests. Publishing it is therefore what turns the mesh job
    endpoints on, and unpublishing it would turn them off without breaking them.
    """
    _prefix = f"/edh/{cluster_id}/configuration/Overlay"

    _params = {
        "mesh_id": settings["mesh_id"],
        "is_mesh_creator": str(settings["is_mesh_creator"]).lower(),
        "mesh_table_prefix": scope.soca_resources["cross_region_table_prefix"],
        "wg_secret_arn": wg_secret.secret_arn,
        "peer_probe_token_secret_arn": probe_token_secret.secret_arn,
    }
    if settings["mesh_role_arn"]:
        _params["mesh_role_arn"] = settings["mesh_role_arn"]
    if settings["mesh_role_external_id"]:
        _params["mesh_role_external_id"] = settings["mesh_role_external_id"]

    for _key, _value in _params.items():
        ssm.StringParameter(
            scope,
            f"CrossRegionSsm-{_key}",
            parameter_name=f"{_prefix}/{_key}",
            string_value=_value,
            description=f"Cross-region overlay mesh: {_key}. Read at controller bootstrap.",
        )
