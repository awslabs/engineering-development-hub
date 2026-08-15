# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
AWS ElastiCache (Valkey/Redis) backend for the SOCA controller.

Extracted verbatim from cdk_construct.py. The construct
instance is passed as ``scope`` -- used both as the CDK parent and to reach
instance state (``scope.cache_info`` / ``scope._partition``). Module-level
utilities from cdk_construct (``get_config_key``, ``get_kms_key_id``) are
dependency-injected to avoid a circular import; ``soca_resources`` and
``user_specified_variables`` are passed explicitly, matching the convention
already used by helpers/vdi_pools.py and helpers/aoss.py.
"""

import logging
import sys

from aws_cdk import Aws
from aws_cdk import aws_elasticache as elasticache
from aws_cdk import aws_iam as iam

logger = logging.getLogger("soca_logger")


def setup(
    scope,
    soca_resources,
    user_specified_variables,
    *,
    get_config_key,
    get_kms_key_id,
):
    """Deploy AWS ElastiCache for SOCA Controller."""

    # Do we just set the engine to valkey always at this stage?
    _supported_cache_engines: set[str] = {"valkey", "redis"}

    if not user_specified_variables.vpc_id:
        # Newly created VPC
        _launch_subnets = [
            soca_resources["vpc"].private_subnets[0].subnet_id,
            soca_resources["vpc"].private_subnets[1].subnet_id,
        ]
    else:
        # Existing resources/existing VPC
        _launch_subnets = [
            user_specified_variables.private_subnets[0].split(",")[0],
            user_specified_variables.private_subnets[1].split(",")[0],
        ]

    _cache_engine = get_config_key(
        key_name="Config.services.aws_elasticache.engine",
        required=False,
        default="valkey",
    )

    # What default cache_engine version?
    # Note this must be after reading _cache_engine since it can change per engine_type
    _cache_engine_version: str = get_config_key(
        key_name="Config.services.aws_elasticache.engine_version",
        required=False,
        default="8" if _cache_engine == "valkey" else "7",
    )

    if _cache_engine not in _supported_cache_engines:
        logger.fatal(
            f"Unsupported option for Config.services.aws_elasticache.engine. Specify one of {', '.join(_supported_cache_engines)} ."
        )
        sys.exit(1)

    if _cache_engine in {"redis", "valkey"}:
        # IAM-only auth: no password secrets are created. All users authenticate
        # via SigV4 IAM tokens (AuthenticationMode=iam); there is no stored cache
        # password to fetch or leak.
        _cache_readonly_user = elasticache.CfnUser(
            scope,
            "SOCACacheReadOnlyUser",
            user_id=f"{user_specified_variables.cluster_id.lower()}-readonlyuser",
            user_name=f"{user_specified_variables.cluster_id.lower()}-readonlyuser",
            engine="redis",
            # authentication_mode is an `Any` prop -> pass a raw PascalCase dict (per AWS docs); the AuthenticationModeProperty helper emits lowercase `type` and CFN rejects it.
            authentication_mode={"Type": "iam"},
            # Node-facing user: read ONLY the reserved shared namespace; sessions
            # (session:*) and the SSM config hash (/edh/<cluster>/_cache_hashes/*)
            # are unreadable. -scan/-randomkey/-@dangerous also block key-name
            # discovery. resetchannels = no pub/sub. +ping for client liveness.
            access_string=(
                f"on resetchannels -@all +@read +ping -@dangerous "
                f"-scan -randomkey %R~/edh/{user_specified_variables.cluster_id}/shared:*"
            ),
        )

        # Username must be default. https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Clusters.RBAC.html
        _cache_admin_user = elasticache.CfnUser(
            scope,
            "SOCACacheAdminUser",
            user_id=f"{user_specified_variables.cluster_id.lower()}-adminuser",
            user_name="default",
            engine="redis",
            # Locked: the group-required `default` user cannot use IAM auth, so it
            # is disabled entirely (no password, no keys, no commands). All real
            # access is via the IAM users (controller / configsync / readonly).
            no_password_required=True,
            access_string="off -@all",
        )

        # Controller/admin IAM user (replaces password-auth via `default`).
        # IAM requires UserName == UserId, lowercase. Broad trusted-plane access.
        _cache_controller_user = elasticache.CfnUser(
            scope,
            "SOCACacheControllerUser",
            user_id=f"{user_specified_variables.cluster_id.lower()}-controller",
            user_name=f"{user_specified_variables.cluster_id.lower()}-controller",
            engine="redis",
            authentication_mode={"Type": "iam"},
            access_string="on ~* &* +@all",
        )

        # Config-sync Lambda IAM user: only the atomic-swap config hash. No pub/sub,
        # no other keys. +@read/+@write covers HSET/HGET/HGETALL/HDEL/RENAME/DEL on
        # _cache_hashes/*; nothing outside that prefix is reachable.
        _cache_configsync_user = elasticache.CfnUser(
            scope,
            "SOCACacheConfigSyncUser",
            user_id=f"{user_specified_variables.cluster_id.lower()}-configsync",
            user_name=f"{user_specified_variables.cluster_id.lower()}-configsync",
            engine="redis",
            authentication_mode={"Type": "iam"},
            access_string=(
                f"on resetchannels -@all +@read +@write +ping "
                f"~/edh/{user_specified_variables.cluster_id}/_cache_hashes/*"
            ),
        )

        # Associate users with the Redis cluster
        # Node: default user will automatically be removed via user-data.
        # `default` user must be part of CfnUserGroup
        _redis_user_group = elasticache.CfnUserGroup(
            scope,
            "SOCACacheUserGroup",
            engine="redis",
            user_group_id=f"socausers-{user_specified_variables.cluster_id.lower()}",
            user_ids=[
                _cache_admin_user.user_id,
                _cache_readonly_user.user_id,
                _cache_controller_user.user_id,
                _cache_configsync_user.user_id,
            ],
        )
        _redis_user_group.node.add_dependency(_cache_admin_user)
        _redis_user_group.node.add_dependency(_cache_readonly_user)
        _redis_user_group.node.add_dependency(_cache_controller_user)
        _redis_user_group.node.add_dependency(_cache_configsync_user)

        # IAM `elasticache:Connect` grants (WS2): each connecting role is granted
        # Connect on the serverless cache AND the specific Valkey user it
        # authenticates as -- controller -> controller user; node roles -> the
        # scoped readonly user. Purely additive: it enables IAM auth but does not
        # affect the password auth still in use until the cutover. BYO/reused
        # roles (imported IRole) safely no-op via add_to_principal_policy.
        _cache_arn = (
            f"arn:{Aws.PARTITION}:elasticache:{Aws.REGION}:{Aws.ACCOUNT_ID}"
            f":serverlesscache:{user_specified_variables.cluster_id.lower()}-cache"
        )

        def _user_arn(_user_id: str) -> str:
            return (
                f"arn:{Aws.PARTITION}:elasticache:{Aws.REGION}:{Aws.ACCOUNT_ID}"
                f":user:{_user_id}"
            )

        _connect_grants = {
            "controller_role": _cache_controller_user.user_id,
            "login_node_role": _cache_readonly_user.user_id,
            "compute_node_role": _cache_readonly_user.user_id,
            "vdi_node_role": _cache_readonly_user.user_id,
        }
        for _role_key, _grant_user_id in _connect_grants.items():
            _role = soca_resources.get(_role_key)
            if _role is None:
                continue
            _role.add_to_principal_policy(
                iam.PolicyStatement(
                    sid="ElastiCacheConnect",
                    actions=["elasticache:Connect"],
                    resources=[_cache_arn, _user_arn(_grant_user_id)],
                )
            )

        _kms_key_id = get_kms_key_id(
            config_key_names=[
                "Config.services.aws_elasticache.kms_key_id",  # Current config key
            ],
            allow_global_default=True,
        )

        if _kms_key_id is not None:
            _redis_user_group.kms_key_id = _kms_key_id

        # Not supported in all regions/partitions so we guard with scope._partition
        _cache_usage_limits = elasticache.CfnServerlessCache.CacheUsageLimitsProperty(
            data_storage=elasticache.CfnServerlessCache.DataStorageProperty(
                unit="GB",
                minimum=get_config_key(
                    key_name="Config.services.aws_elasticache.limits.memory.min",
                    required=False,
                    expected_type=int,
                    default=2,
                ),
                maximum=get_config_key(
                    key_name="Config.services.aws_elasticache.limits.memory.max",
                    required=False,
                    expected_type=int,
                    default=24,
                ),
            ),
            ecpu_per_second=elasticache.CfnServerlessCache.ECPUPerSecondProperty(
                minimum=get_config_key(
                    key_name="Config.services.aws_elasticache.limits.ecpu.min",
                    required=False,
                    expected_type=int,
                    default=1000,
                ),
                maximum=get_config_key(
                    key_name="Config.services.aws_elasticache.limits.ecpu.max",
                    required=False,
                    expected_type=int,
                    default=1000,
                ),
            ),
        )

        soca_resources["elasticache"] = elasticache.CfnServerlessCache(
            scope,
            "ElastiCache",
            engine=_cache_engine,
            kms_key_id=_kms_key_id if _kms_key_id else None,
            major_engine_version=_cache_engine_version,
            serverless_cache_name=f"{user_specified_variables.cluster_id.lower()}-cache",  # FIXME TODO - sanitize/check
            description=f"{user_specified_variables.cluster_id.lower()}-cache",
            security_group_ids=[
                soca_resources["elasticache_sg"].security_group_id
            ],
            subnet_ids=_launch_subnets,
            user_group_id=_redis_user_group.user_group_id,
            cache_usage_limits=(
                _cache_usage_limits
                if scope._partition in {"aws"}
                else None  # Only apply limits to commercial partition for now
            ),
        )

        soca_resources["elasticache"].node.add_dependency(_redis_user_group)
        soca_resources["elasticache"].node.add_dependency(
            soca_resources["vpc"]
        )

        # Flatten Cache
        scope.cache_info["port"] = soca_resources[
            "elasticache"
        ].attr_endpoint_port
        scope.cache_info["endpoint"] = soca_resources[
            "elasticache"
        ].attr_endpoint_address
        # Cache name (not endpoint) -- IAM connect tokens are SigV4-signed against this.
        scope.cache_info["name"] = soca_resources[
            "elasticache"
        ].serverless_cache_name
