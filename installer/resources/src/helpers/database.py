# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Database capability provisioning for the EDH web application state store.

The "database" is a capability with selectable providers (mirrors
directoryservice.provider = AD vs OpenLDAP):

  Config.database.provider:
    * aurora_serverless_v2 -- Aurora PostgreSQL Serverless v2 (provisioned here)
    * sqlite               -- legacy local file, no infrastructure to provision

This backs the EDH web app authoritative state (sessions, software stacks,
projects, API keys, profiles) -- a prerequisite for AZ-level controller HA so
the state survives a controller failover.

Implementation extracted from cdk_construct.py to keep the main stack thin
(same pattern as helpers/webshell.py). Entry points:
  * setup_database()        -- called from the thin SOCAInstall.database() wrapper
  * wire_database_ingress() -- called from SOCAInstall.security_groups()

Resource/SSM naming is capability-generic ("Database", DatabaseAdminSecret,
/configuration/Database/*) so consumers read "the database" without needing to
know the provider. The RDS cluster identifier stays provider-descriptive
(-aurorapg) since it is a concrete Aurora resource.
"""

import json
import logging
import re
from typing import Any, Callable, Dict

from aws_cdk import CfnOutput, Duration, RemovalPolicy
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_kms as kms
from aws_cdk import aws_rds as rds
from constructs import Construct

logger = logging.getLogger("soca_logger")

# Provider value (Config.database.provider) that selects the Aurora implementation.
AURORA_PROVIDER = "aurora_serverless_v2"


def setup_database(
    scope: Construct,
    soca_resources: Dict[str, Any],
    user_specified_variables: Any,
    get_config_key: Callable,
    get_kms_key_id: Callable,
    secretsmanager_helper: Any,
) -> Dict[str, Any]:
    """
    Provision the database backend for the SOCA web app authoritative state.

    When Config.database.provider == "aurora_serverless_v2", deploys an Aurora
    PostgreSQL Serverless v2 cluster (auto-scaling ACUs, multi-AZ writer, optional
    reader replica). For any other provider (e.g. "sqlite") this is a no-op --
    no infrastructure is created.

    Parameters
    ----------
    scope
        The CDK construct scope (typically the Stack).
    soca_resources
        The SOCA resource dictionary. Reads vpc / database_sg /
        secretsmanager_kms_key_id; writes database / database_secret.
    user_specified_variables
        The global user-specified-variables namespace (cluster_id, vpc_id,
        private_subnets).
    get_config_key
        Reference to the config-lookup function.
    get_kms_key_id
        Reference to the cdk_construct KMS-resolver helper. Passed in rather than
        imported to avoid a circular import on cdk_construct.
    secretsmanager_helper
        The helpers.secretsmanager module (provides create_secret()).

    Returns
    -------
    dict
        The database_info dict surfaced via SSM at
        /edh/<cluster_id>/configuration/Database/* so the web app can build the
        SQLAlchemy URI dynamically at startup. Always returned -- for non-Aurora
        providers the endpoint/secret fields are None so the SSM publish and the
        web app's provider check still see a well-formed payload.
    """
    _provider = get_config_key(
        key_name="Config.database.provider",
        expected_type=str,
        default=AURORA_PROVIDER,
        required=False,
    )

    _database_name = get_config_key(
        key_name=f"Config.database.{AURORA_PROVIDER}.database_name",
        expected_type=str,
        default="edh",
        required=False,
    )

    # Info skeleton surfaced via SSM regardless of provider, so the web app
    # /configuration/Database/provider check always has a value to read.
    database_info: Dict[str, Any] = {
        "provider": _provider,
        "endpoint": None,
        "reader_endpoint": None,
        "port": 5432,
        "name": _database_name,
        "secret_arn": None,
        "app_user": "edh_app",
        "iam_auth": True,
        "cluster_resource_id": None,
    }

    if _provider != AURORA_PROVIDER:
        logger.debug(
            f"Database provider '{_provider}' is not '{AURORA_PROVIDER}' - skipping Aurora provisioning"
        )
        return database_info

    # ----- Aurora PostgreSQL Serverless v2 provider -----
    _cfg = f"Config.database.{AURORA_PROVIDER}"

    # Determine subnets for the Aurora cluster. Use ALL available private subnets
    # so the cluster spans every AZ in the cluster's private subnet inventory.
    if not user_specified_variables.vpc_id:
        # Newly created VPC -- use all private subnets
        _launch_subnets = [
            s.subnet_id for s in soca_resources["vpc"].private_subnets
        ]
    else:
        # Existing VPC -- use all user-specified private subnets
        # Each entry is "subnet-id,az" or just "subnet-id"; take the subnet ID part.
        _launch_subnets = [
            s.split(",")[0] for s in user_specified_variables.private_subnets
        ]

    # ACU (Aurora Capacity Unit) limits for Serverless v2 scaling
    _acu_min = get_config_key(
        key_name=f"{_cfg}.acu.min", required=False, expected_type=float, default=0.5
    )
    _acu_max = get_config_key(
        key_name=f"{_cfg}.acu.max", required=False, expected_type=float, default=2.0
    )

    # Master username for the cluster admin
    _admin_username = get_config_key(
        key_name=f"{_cfg}.admin_username",
        required=False,
        expected_type=str,
        default="edh_admin",
    )

    # Allowlist-validate the admin username (BSC1 input validation). It becomes
    # the RDS master username and the secret's "username" field, so it must meet
    # PostgreSQL/RDS identifier rules: start with a letter, then letters/digits/
    # underscore, max 63 chars. Fail fast at synth with a clear message rather
    # than letting an invalid value surface as an opaque CFN create error.
    if not re.match(r"^[A-Za-z][A-Za-z0-9_]{0,62}$", str(_admin_username)):
        logger.error(
            f"{_cfg}.admin_username '{_admin_username}' is invalid: it must start "
            "with a letter and contain only letters, digits, or underscores "
            "(max 63 characters)."
        )
        raise ValueError(f"Invalid database admin_username: '{_admin_username}'")

    # Aurora PostgreSQL engine version (must be Serverless v2 capable: 13.6+)
    _engine_version = get_config_key(
        key_name=f"{_cfg}.engine_version",
        required=False,
        expected_type=str,
        default="17.9",
    )

    # Backup retention period in days
    _backup_retention_days = get_config_key(
        key_name=f"{_cfg}.backup.retention_days",
        required=False,
        expected_type=int,
        default=7,
    )

    # Deletion protection. Linked to the stack-level termination protection
    # (Config.termination_protection, default True) so ONE flag controls both:
    # disabling termination protection for teardown also clears RDS deletion
    # protection, so `cdk destroy` never hits DELETE_FAILED. An explicit
    # Config.database.<provider>.deletion_protection overrides the link.
    _deletion_protection = get_config_key(
        key_name=f"{_cfg}.deletion_protection",
        required=False,
        expected_type=bool,
        default=get_config_key(
            key_name="Config.termination_protection",
            required=False,
            expected_type=bool,
            default=True,
        ),
    )

    # CFN removal policy on stack delete, decoupled from deletion_protection:
    # snapshot (recoverable, default) | retain | destroy.
    _removal_policy_str = get_config_key(
        key_name=f"{_cfg}.removal_policy",
        required=False,
        expected_type=str,
        default="snapshot",
    ).strip().lower()
    _removal_policy = {
        "snapshot": RemovalPolicy.SNAPSHOT,
        "retain": RemovalPolicy.RETAIN,
        "destroy": RemovalPolicy.DESTROY,
    }.get(_removal_policy_str, RemovalPolicy.SNAPSHOT)

    # Optional reader replica for failover speed (extra cost: roughly 2x ACU at idle)
    _enable_reader = get_config_key(
        key_name=f"{_cfg}.enable_reader",
        required=False,
        expected_type=bool,
        default=False,
    )

    # KMS key for encryption at rest (optional; defaults to AWS-managed key)
    _kms_key_id = get_kms_key_id(
        config_key_names=[
            f"{_cfg}.kms_key_id",
        ],
        allow_global_default=True,
    )

    # Master user secret in Secrets Manager. Capability-generic name
    # (DatabaseAdminSecret) so the web app reads it regardless of provider.
    soca_resources["database_secret"] = secretsmanager_helper.create_secret(
        scope=scope,
        construct_id="DatabaseAdminSecret",
        secret_name=f"/edh/{user_specified_variables.cluster_id}/DatabaseAdminSecret",
        secret_string_template=json.dumps({"username": _admin_username}),
        kms_key_id=(
            soca_resources["secretsmanager_kms_key_id"]
            if soca_resources["secretsmanager_kms_key_id"]
            else None
        ),
    )
    # Align master-secret removal with the cluster: DESTROY removes it with the
    # cluster (no orphan); snapshot/retain keep it (recoverable credentials).
    soca_resources["database_secret"].apply_removal_policy(
        RemovalPolicy.DESTROY
        if _removal_policy == RemovalPolicy.DESTROY
        else RemovalPolicy.RETAIN
    )

    # Aurora subnet group spans all selected private subnets
    _subnet_group = rds.SubnetGroup(
        scope,
        "DatabaseSubnetGroup",
        description=f"{user_specified_variables.cluster_id} database subnet group",
        vpc=soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_filters=[ec2.SubnetFilter.by_ids(_launch_subnets)]
        ),
        removal_policy=RemovalPolicy.DESTROY,
    )

    # Aurora cluster parameter group placeholder; left at default for Phase 1.
    # Future: enable logging, custom timeouts, extensions via custom param group.

    # Compose the Serverless v2 cluster
    _cluster_kwargs = dict(
        engine=rds.DatabaseClusterEngine.aurora_postgres(
            version=rds.AuroraPostgresEngineVersion.of(
                aurora_postgres_full_version=_engine_version,
                aurora_postgres_major_version=_engine_version.split(".")[0],
            ),
        ),
        credentials=rds.Credentials.from_secret(
            soca_resources["database_secret"]
        ),
        default_database_name=_database_name,
        cluster_identifier=f"{user_specified_variables.cluster_id.lower()}-aurorapg",
        vpc=soca_resources["vpc"],
        subnet_group=_subnet_group,
        security_groups=[soca_resources["database_sg"]],
        serverless_v2_min_capacity=_acu_min,
        serverless_v2_max_capacity=_acu_max,
        writer=rds.ClusterInstance.serverless_v2("Writer"),
        backup=rds.BackupProps(
            retention=Duration.days(_backup_retention_days),
        ),
        deletion_protection=_deletion_protection,
        storage_encrypted=True,
        iam_authentication=True,
        removal_policy=_removal_policy,
    )

    # Optional reader replica
    if _enable_reader:
        _cluster_kwargs["readers"] = [
            rds.ClusterInstance.serverless_v2(
                "Reader1",
                scale_with_writer=True,
            ),
        ]

    # Optional CMK for storage encryption
    if _kms_key_id:
        _cluster_kwargs["storage_encryption_key"] = kms.Key.from_key_arn(
            scope, "DatabaseKmsKeyImport", _kms_key_id
        )

    soca_resources["database"] = rds.DatabaseCluster(
        scope,
        "Database",
        **_cluster_kwargs,
    )

    # Explicit dependency on VPC so subnets/SGs exist before cluster
    soca_resources["database"].node.add_dependency(soca_resources["vpc"])

    # Populate database_info so the SSM publisher can surface these to the
    # web app at /edh/<cluster_id>/configuration/Database/*
    database_info["endpoint"] = soca_resources["database"].cluster_endpoint.hostname
    database_info["reader_endpoint"] = soca_resources[
        "database"
    ].cluster_read_endpoint.hostname
    database_info["port"] = soca_resources["database"].cluster_endpoint.port
    database_info["secret_arn"] = soca_resources["database_secret"].secret_arn
    # Cluster resource id (cluster-XXXX) for the rds-db:connect IAM grant on the
    # IAM-auth app user. Resolves at deploy time.
    database_info["cluster_resource_id"] = soca_resources[
        "database"
    ].cluster_resource_identifier

    # CfnOutput for ops convenience -- endpoint and port surfaced in stack outputs
    CfnOutput(
        scope,
        "DatabaseEndpoint",
        value=soca_resources["database"].cluster_endpoint.hostname,
        description="Database writer endpoint hostname",
    )
    CfnOutput(
        scope,
        "DatabaseReaderEndpoint",
        value=soca_resources["database"].cluster_read_endpoint.hostname,
        description="Database reader endpoint hostname (load-balanced across readers)",
    )
    CfnOutput(
        scope,
        "DatabaseSecretArn",
        value=soca_resources["database_secret"].secret_arn,
        description="ARN of the Secrets Manager secret with master credentials",
    )

    return database_info


def wire_database_ingress(
    soca_resources: Dict[str, Any],
    get_config_key: Callable,
    security_groups_helper: Any,
) -> None:
    """Add TCP 5432 ingress to the database security group.

    The database backs the SOCA web app authoritative state. Only the controller
    runs the web app, so it is the sole DB client; login, target, and compute
    nodes do not need DB access.

    Called from cdk_construct.SOCAInstall.security_groups() AFTER the central
    SG-creation loop has built database_sg and the peer SGs. No-op when the
    database provider does not provision a network database (e.g. sqlite).

    Parameters
    ----------
    soca_resources
        The SOCA resource dictionary. Reads database_sg / controller_sg.
    get_config_key
        Reference to the config-lookup function.
    security_groups_helper
        The helpers.security_groups module (provides create_ingress_rule()).
    """
    _provider = get_config_key(
        key_name="Config.database.provider",
        expected_type=str,
        default=AURORA_PROVIDER,
        required=False,
    )
    if _provider != AURORA_PROVIDER:
        logger.debug(
            f"Database provider '{_provider}' has no network DB - skipping 5432 ingress"
        )
        return

    for _sg_peer_name in [
        "controller_sg",
    ]:
        security_groups_helper.create_ingress_rule(
            security_group=soca_resources["database_sg"],
            peer=soca_resources[_sg_peer_name],
            connection=ec2.Port.tcp(5432),
            description=f"Allow database traffic from the {_sg_peer_name}",
        )
