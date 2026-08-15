#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

import typing
from aws_cdk import (
    Duration,
    Aws,
    CustomResource,
    aws_ec2 as ec2,
    aws_events as events,
    aws_events_targets,
    aws_lambda as aws_lambda,
    aws_iam as iam,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_ssm as ssm,
    aws_s3_assets as s3_assets,
)

import json
import hashlib
import tempfile

import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# SSM config sync (flatten config -> parameter store)

logger = logging.getLogger("soca_logger")


def ssm_config_sync(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
    get_lambda_runtime_version=None,
):
    """
    SSM ElastiCache ConfigSync feature.

    Mirror SSM Parameter Store changes under /edh/<cluster>/ into the
    cluster's Valkey HASH so SocaConfig path queries hit O(1) HGETALL
    instead of O(n) SSM walks. See docs/SsmConfigSync.md for the full
    design (forthcoming) and config.py for the controller-side reader.

    Components built here:
      - Lambda function (private subnets, redis layer, env vars)
      - Lambda execution role + IAM (ssm:GetParameter, sm:GetSecretValue,
        cloudwatch:PutMetricData, logs)
      - EventBridge rule on aws.ssm Parameter Store Change with
        detail.name prefix filter
      - Runtime SSM mirror of the feature flag for the controller
      - Auto-enable rule: when DCV HS is on, force ConfigSync on
        unless the operator explicitly set it False

    Feature flag: Config.services.ssm_elasticache_config_sync.enabled
    Default during dev cycle: True (flip at GA per release plan).
    """
    # Auto-enable: DCV HS implies ConfigSync (perf dependency).
    # Only force-ON when the flag is not explicitly set; if operator
    # set it False with DCV HS True, log a warning but allow it
    # (debug escape hatch).
    _dcv_hs_enabled = get_config_key(
        key_name="Config.dcv.high_scale",
        expected_type=bool,
        required=False,
        default=False,
    )
    _config_sync_explicit = get_config_key(
        key_name="Config.services.ssm_elasticache_config_sync.enabled",
        expected_type=bool,
        required=False,
        default=None,  # None = not explicitly set
    )

    if _dcv_hs_enabled and _config_sync_explicit is None:
        logger.info(
            "DCV High Scale is enabled; auto-enabling SSM ElastiCache "
            "ConfigSync for /virtual_desktops performance. Set "
            "Config.services.ssm_elasticache_config_sync.enabled=False "
            "to override (will fall back to per-key cache + workaround)."
        )
        _config_sync_enabled = True
    elif _dcv_hs_enabled and _config_sync_explicit is False:
        logger.warning(
            "DCV High Scale is enabled but SSM ElastiCache ConfigSync "
            "was explicitly disabled. /virtual_desktops will use the "
            "60s app-cache workaround. Recommend enabling ConfigSync."
        )
        _config_sync_enabled = False
    else:
        # Default: True during dev cycle, per release plan.
        _config_sync_enabled = (
            _config_sync_explicit if _config_sync_explicit is not None else True
        )

    # Always write the runtime SSM flag so the controller knows the
    # final resolved value (post auto-enable). The controller reads
    # this via _read_config_sync_flag in utils/config.py.
    ssm.StringParameter(
        scope,
        "SsmConfigSyncFlagParam",
        parameter_name=(
            f"/edh/{user_specified_variables.cluster_id}"
            "/configuration/services/ssm_elasticache_config_sync/enabled"
        ),
        string_value="true" if _config_sync_enabled else "false",
        description=(
            "Runtime feature flag for the SSM ElastiCache ConfigSync. "
            "When True, SocaConfig.get_value reads from the cluster Valkey "
            "HASH first, with SSM fallback. Mirror of the CDK-time config "
            "key Config.services.ssm_elasticache_config_sync.enabled."
        ),
    )

    if not _config_sync_enabled:
        logger.info(
            "SSM ElastiCache ConfigSync disabled; skipping Lambda + "
            "EventBridge rule. Controller will use legacy SocaConfig."
        )
        return

    # Hard prerequisite: Valkey/Redis cluster must be present.
    if scope.soca_resources.get("elasticache") is None:
        logger.warning(
            "SSM ElastiCache ConfigSync is enabled but no ElastiCache "
            "cluster is provisioned (Config.services.aws_elasticache.enabled "
            "is False?). Skipping ConfigSync deployment."
        )
        return
    if scope.soca_resources.get("redis_layer") is None:
        logger.warning(
            "SSM ElastiCache ConfigSync is enabled but redis Lambda layer "
            "was not built (Config.lambda_layers.RedisVersion empty?). "
            "Skipping ConfigSync deployment."
        )
        return

    _cluster_id = user_specified_variables.cluster_id
    _hash_fqdn = (
        f"/edh/{_cluster_id}/_cache_hashes/{{configuration}}"
    )  # MUST match SocaConfig._CONFIG_SYNC_HASH_KEY after key_fqdn prefixing

    # ----- IAM execution role -----
    _role = iam.Role(
        scope,
        "SsmConfigSyncLambdaRole",
        role_name=f"{_cluster_id}-SsmConfigSyncLambdaRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        description=(
            "Execution role for SsmConfigSync Lambda. Reads SSM params "
            "under the cluster prefix, fetches Valkey admin creds from "
            "SecretsManager, writes to Valkey HASH, emits CloudWatch "
            "metrics, and produces standard Lambda logs."
        ),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
        inline_policies=dict(
            SsmConfigSyncInline=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        sid="SsmReadClusterPrefix",
                        actions=["ssm:GetParameter"],
                        resources=[
                            f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:parameter/edh/{_cluster_id}/*"
                        ],
                    ),
                    iam.PolicyStatement(
                        # WS2: connect as the scoped configsync IAM user
                        # (replaces the admin-password path at cutover).
                        # Additive -- does not affect current auth.
                        sid="ElastiCacheConnectConfigSync",
                        actions=["elasticache:Connect"],
                        resources=[
                            f"arn:{Aws.PARTITION}:elasticache:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:serverlesscache:"
                            f"{_cluster_id.lower()}-cache",
                            f"arn:{Aws.PARTITION}:elasticache:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:user:"
                            f"{_cluster_id.lower()}-configsync",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="CloudWatchPutScopedMetrics",
                        actions=["cloudwatch:PutMetricData"],
                        resources=["*"],
                        conditions={
                            "StringEquals": {
                                "cloudwatch:namespace": "EDH/SsmConfigSync",
                            }
                        },
                    ),
                    iam.PolicyStatement(
                        sid="LogsCommon",
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources=["*"],
                    ),
                ],
            )
        ),
    )

    # ----- Lambda function -----
    _lambda = aws_lambda.Function(
        scope,
        f"{_cluster_id}-SsmConfigSync",
        function_name=f"{_cluster_id}-SsmConfigSync",
        description=(
            "Mirrors SSM ParameterChange under cluster prefix into the "
            "Valkey config hash. Read by SocaConfig for O(1) path queries."
        ),
        memory_size=128,
        runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        timeout=Duration.seconds(15),
        log_group=scope.generate_log_group(name="SsmConfigSyncLambda"),
        role=_role,
        handler="SsmConfigSync.lambda_handler",
        code=aws_lambda.Code.from_asset("../functions/SsmConfigSync"),
        environment={
            "EDH_CLUSTER_ID": _cluster_id,
            "EDH_VALKEY_ENDPOINT": scope.soca_resources[
                "elasticache"
            ].attr_endpoint_address,
            "EDH_VALKEY_PORT": scope.soca_resources[
                "elasticache"
            ].attr_endpoint_port,
            "EDH_VALKEY_CACHE_NAME": f"{_cluster_id.lower()}-cache",
            "EDH_VALKEY_USER": f"{_cluster_id.lower()}-configsync",
            "EDH_CONFIG_HASH_FQDN": _hash_fqdn,
        },
        # Lambda retries on Errors (exception path). EventBridge will
        # also retry on Lambda invocation failures up to its own limit.
        # Keep retries=2 -- combined with EB retries this is enough
        # tolerance for transient Valkey blips without storming the cache.
        retry_attempts=2,
        # VPC-attached so the Lambda can reach the ElastiCache cluster
        # (private endpoint). Same pattern as DcvEventRelay.
        vpc=scope.soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[scope.soca_resources["ssm_config_sync_lambda_sg"]],
        layers=[
            l
            for l in [
                scope.soca_resources.get("redis_layer"),
                scope.soca_resources.get("boto3_layer"),
            ]
            if l
        ],
    )
    scope.soca_resources["ssm_config_sync_lambda"] = _lambda

    # ----- EventBridge rule -----
    # Filter on detail.name prefix so this Lambda is only invoked
    # for parameters under THIS cluster's namespace. Cross-cluster
    # leakage is also defended against in-Lambda (defense in depth).
    events.Rule(
        scope,
        "SsmConfigSyncRule",
        description=(
            f"Trigger {_cluster_id}-SsmConfigSync on SSM Parameter Store "
            f"Change events under /edh/{_cluster_id}/"
        ),
        enabled=True,
        event_pattern=events.EventPattern(
            source=["aws.ssm"],
            detail_type=["Parameter Store Change"],
            detail={
                "name": [{"prefix": f"/edh/{_cluster_id}/"}],
            },
        ),
        targets=[aws_events_targets.LambdaFunction(_lambda)],
    )

    # ===========================================================
    # ConfigAuditor: hourly drift detector + auto-healer
    # ===========================================================
    # The auditor reuses the same IAM role as ConfigSync (it
    # performs the same operations: SSM read, Valkey write/delete,
    # CloudWatch metrics). Different metric Source dimension
    # (Auditor vs Live) keeps the alarm streams separate.
    _auditor_role = iam.Role(
        scope,
        "SsmConfigAuditorLambdaRole",
        role_name=f"{_cluster_id}-SsmConfigAuditorLambdaRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        description=(
            "Execution role for SsmConfigAuditor Lambda. Walks the "
            "cluster SSM prefix, reads the Valkey config hash, diffs "
            "for drift, auto-heals via HSET/HDEL when AUTOHEAL is on, "
            "and emits drift/integrity metrics with Source=Auditor."
        ),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
        inline_policies=dict(
            SsmConfigAuditorInline=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        sid="SsmReadClusterPrefixRecursive",
                        actions=[
                            "ssm:GetParameter",
                            "ssm:GetParametersByPath",
                        ],
                        resources=[
                            f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:parameter/edh/{_cluster_id}/*"
                        ],
                    ),
                    iam.PolicyStatement(
                        # WS2: connect as the scoped configsync IAM user
                        # (shared by Auditor + Flusher). Additive.
                        sid="ElastiCacheConnectConfigSync",
                        actions=["elasticache:Connect"],
                        resources=[
                            f"arn:{Aws.PARTITION}:elasticache:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:serverlesscache:"
                            f"{_cluster_id.lower()}-cache",
                            f"arn:{Aws.PARTITION}:elasticache:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:user:"
                            f"{_cluster_id.lower()}-configsync",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="CloudWatchPutScopedMetrics",
                        actions=["cloudwatch:PutMetricData"],
                        resources=["*"],
                        conditions={
                            "StringEquals": {
                                "cloudwatch:namespace": "EDH/SsmConfigSync",
                            }
                        },
                    ),
                    iam.PolicyStatement(
                        sid="LogsCommon",
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources=["*"],
                    ),
                ],
            )
        ),
    )

    _auditor_lambda = aws_lambda.Function(
        scope,
        f"{_cluster_id}-SsmConfigAuditor",
        function_name=f"{_cluster_id}-SsmConfigAuditor",
        description=(
            "Hourly drift detector + auto-healer for the SSM/Valkey "
            "config hash (diffs vs HGETALL, applies HSET/HDEL). "
            "Emits Auditor metrics + alarm suppressor."
        ),
        memory_size=256,  # walks SSM (~hundreds of params) into RAM
        runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        timeout=Duration.minutes(5),  # paginated SSM walk + diff + heal
        log_group=scope.generate_log_group(name="SsmConfigAuditorLambda"),
        role=_auditor_role,
        handler="SsmConfigAuditor.lambda_handler",
        code=aws_lambda.Code.from_asset("../functions/SsmConfigAuditor"),
        environment={
            "EDH_CLUSTER_ID": _cluster_id,
            "EDH_VALKEY_ENDPOINT": scope.soca_resources[
                "elasticache"
            ].attr_endpoint_address,
            "EDH_VALKEY_PORT": scope.soca_resources[
                "elasticache"
            ].attr_endpoint_port,
            "EDH_VALKEY_CACHE_NAME": f"{_cluster_id.lower()}-cache",
            "EDH_VALKEY_USER": f"{_cluster_id.lower()}-configsync",
            "EDH_CONFIG_HASH_FQDN": _hash_fqdn,
            "EDH_AUDIT_AUTOHEAL": str(
                get_config_key(
                    key_name="Config.services.ssm_elasticache_config_sync.audit_autoheal",
                    expected_type=bool,
                    required=False,
                    default=True,
                )
            ).lower(),
        },
        # Auditor is idempotent over its inputs (SSM + hash). No
        # retry needed -- next hour's run picks up where we left
        # off. Avoids retry storms during transient Valkey hiccups.
        retry_attempts=0,
        vpc=scope.soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[scope.soca_resources["ssm_config_sync_lambda_sg"]],
        layers=[
            l
            for l in [
                scope.soca_resources.get("redis_layer"),
                scope.soca_resources.get("boto3_layer"),
            ]
            if l
        ],
    )
    scope.soca_resources["ssm_config_auditor_lambda"] = _auditor_lambda

    # Per-cluster minute jitter so fleet-wide audits don't all land at :00.
    # sha256 (not hash()) because Python's hash() is per-process randomized.
    _audit_minute = (
        int(hashlib.sha256(_cluster_id.encode()).hexdigest()[:8], 16) % 60
    )
    events.Rule(
        scope,
        "SsmConfigAuditorSchedule",
        description=(
            f"Hourly trigger for {_cluster_id}-SsmConfigAuditor. "
            f"Jittered to minute {_audit_minute} so cross-cluster "
            f"audits do not collide."
        ),
        enabled=True,
        schedule=events.Schedule.cron(minute=str(_audit_minute)),
        targets=[aws_events_targets.LambdaFunction(_auditor_lambda)],
    )

    # ===========================================================
    # ConfigFlusher: 24h atomic full rebuild via build-then-RENAME
    # ===========================================================
    # Same IAM scopes as the Auditor (SSM walk + Valkey + metrics).
    # We share the role rather than duplicate it -- both Lambdas
    # touch the same resources with the same actions.
    _flusher_lambda = aws_lambda.Function(
        scope,
        f"{_cluster_id}-SsmConfigFlusher",
        function_name=f"{_cluster_id}-SsmConfigFlusher",
        description=(
            "24h atomic rebuild of the cluster Valkey config hash "
            "from SSM (RENAME swap; readers never see partial). "
            "Can be invoked on demand."
        ),
        memory_size=512,  # holds the full SSM dict in RAM during walk
        runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        timeout=Duration.minutes(10),  # full rebuild is bounded
        log_group=scope.generate_log_group(name="SsmConfigFlusherLambda"),
        role=_auditor_role,  # shared scope: SSM read, Valkey write, CW
        handler="SsmConfigFlusher.lambda_handler",
        code=aws_lambda.Code.from_asset("../functions/SsmConfigFlusher"),
        environment={
            "EDH_CLUSTER_ID": _cluster_id,
            "EDH_VALKEY_ENDPOINT": scope.soca_resources[
                "elasticache"
            ].attr_endpoint_address,
            "EDH_VALKEY_PORT": scope.soca_resources[
                "elasticache"
            ].attr_endpoint_port,
            "EDH_VALKEY_CACHE_NAME": f"{_cluster_id.lower()}-cache",
            "EDH_VALKEY_USER": f"{_cluster_id.lower()}-configsync",
            "EDH_CONFIG_HASH_FQDN": _hash_fqdn,
        },
        # Idempotent over its inputs (build-then-RENAME pattern).
        # The :_new key cleanup at the start of every run handles
        # whatever a prior crashed invocation left behind. No
        # automatic retries needed.
        retry_attempts=0,
        vpc=scope.soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[scope.soca_resources["ssm_config_sync_lambda_sg"]],
        layers=[
            l
            for l in [
                scope.soca_resources.get("redis_layer"),
                scope.soca_resources.get("boto3_layer"),
            ]
            if l
        ],
    )
    scope.soca_resources["ssm_config_flusher_lambda"] = _flusher_lambda

    # Daily flush, jittered per-cluster on hour + offset 30min from auditor.
    _flush_hour = (
        int(hashlib.sha256(f"{_cluster_id}-flush".encode()).hexdigest()[:8], 16) % 24
    )
    _flush_minute = (_audit_minute + 30) % 60
    events.Rule(
        scope,
        "SsmConfigFlusherSchedule",
        description=(
            f"24h trigger for {_cluster_id}-SsmConfigFlusher. "
            f"Jittered to {_flush_hour:02d}:{_flush_minute:02d} UTC "
            f"to avoid fleet-wide collisions and to offset from the "
            f"hourly auditor."
        ),
        enabled=True,
        schedule=events.Schedule.cron(
            minute=str(_flush_minute),
            hour=str(_flush_hour),
        ),
        targets=[aws_events_targets.LambdaFunction(_flusher_lambda)],
    )

    # ===========================================================
    # CloudWatch alarms
    # ===========================================================
    # Two alarm classes:
    #
    # VALIDATION alarms (always fire on chronic drift / errors):
    #   - BackfillDriftCount sustained -- ConfigSync is missing events
    #   - IntegrityHashMismatch sustained -- auditor cannot self-heal
    #   - FlushFailures -- 24h sweep cannot complete
    #   - Lambda function Errors per role
    #
    # OPS alarms (suppressed during scheduled sweeps):
    #   - EventsFailed (Source=Live) spike
    #   - EventLatencyMs (Source=Live) p99 elevated
    #
    # The suppressor alarm goes ALARM whenever ANY source is publishing
    # SuppressorActive=1 (auditor running, flusher running). Composite
    # alarms wrap each ops alarm in `OPS AND NOT SUPPRESSOR` so the
    # ops alarms automatically silence themselves during sweep windows
    # without operators having to remember the schedule. Validation
    # alarms are NOT wrapped -- their whole purpose is to fire when
    # the system is not self-healing.
    _alarm_dims = {"ClusterId": _cluster_id}
    _alarm_topic = scope.soca_resources.get("sns_cluster_topic")

    def _attach_actions(_alarm):
        """Attach the cluster SNS topic if available. Skip silently if
        the topic was not provisioned (notification feature disabled)."""
        if _alarm_topic is not None:
            _alarm.add_alarm_action(cw_actions.SnsAction(_alarm_topic))
            _alarm.add_ok_action(cw_actions.SnsAction(_alarm_topic))

    # ----- Validation alarms (always-fire) -----

    # Drift > 5 sustained for 3 hours = chronic ConfigSync miss rate.
    # The auditor heals each run; persistent drift means events are
    # being lost faster than the auditor can correct.
    _drift_alarm = cloudwatch.Alarm(
        scope,
        "SsmConfigSyncDriftSustainedAlarm",
        alarm_name=f"{_cluster_id}-SsmConfigSync-DriftSustained",
        alarm_description=(
            "Chronic drift between SSM and Valkey config hash. "
            "ConfigSync Lambda is likely missing ParameterChange events "
            "or Valkey writes are failing. Investigate Lambda logs "
            "and EventBridge delivery health."
        ),
        metric=cloudwatch.Metric(
            namespace="EDH/SsmConfigSync",
            metric_name="BackfillDriftCount",
            statistic="Maximum",
            period=Duration.hours(1),
            dimensions_map={**_alarm_dims, "Source": "Auditor"},
        ),
        threshold=5,
        evaluation_periods=3,
        datapoints_to_alarm=3,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    _attach_actions(_drift_alarm)

    # IntegrityHashMismatch=1 sustained for 6 hours = auditor sees
    # drift but autoheal isn't fixing it (e.g. AUTOHEAL=false, or
    # autoheal repeatedly losing race with new SSM changes).
    _integrity_alarm = cloudwatch.Alarm(
        scope,
        "SsmConfigSyncIntegrityMismatchAlarm",
        alarm_name=f"{_cluster_id}-SsmConfigSync-IntegrityMismatch",
        alarm_description=(
            "Auditor reports drift but the hash is not converging to "
            "match SSM. Either AUTOHEAL is disabled or healing is "
            "racing with live writes. Manual flush may be required."
        ),
        metric=cloudwatch.Metric(
            namespace="EDH/SsmConfigSync",
            metric_name="IntegrityHashMismatch",
            statistic="Maximum",
            period=Duration.hours(1),
            dimensions_map={**_alarm_dims, "Source": "Auditor"},
        ),
        threshold=1,
        evaluation_periods=6,
        datapoints_to_alarm=6,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    _attach_actions(_integrity_alarm)

    # Flush failures: any failure in the daily window. Flusher only
    # runs once a day so a single failure means we missed the
    # safety-net rebuild for ~24h. Fire promptly.
    _flush_fail_alarm = cloudwatch.Alarm(
        scope,
        "SsmConfigSyncFlushFailedAlarm",
        alarm_name=f"{_cluster_id}-SsmConfigSync-FlushFailed",
        alarm_description=(
            "ConfigFlusher could not complete the 24h atomic rebuild. "
            "Live and event-driven sync still operate, but the long-"
            "horizon safety net is offline. Investigate Lambda logs."
        ),
        metric=cloudwatch.Metric(
            namespace="EDH/SsmConfigSync",
            metric_name="FlushFailures",
            statistic="Sum",
            period=Duration.hours(1),
            dimensions_map={**_alarm_dims, "Source": "Flush"},
        ),
        threshold=1,
        evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    _attach_actions(_flush_fail_alarm)

    # Per-Lambda function-level Errors (covers cold-start failures,
    # OOM, init exceptions, etc. that may not surface as Source=*
    # metrics because the Lambda crashed before emitting them).
    for _lambda_obj, _name in (
        (_lambda, "ConfigSync"),
        (_auditor_lambda, "ConfigAuditor"),
        (_flusher_lambda, "ConfigFlusher"),
    ):
        _lambda_err_alarm = cloudwatch.Alarm(
            scope,
            f"SsmConfigSync{_name}LambdaErrorsAlarm",
            alarm_name=f"{_cluster_id}-SsmConfigSync-{_name}-LambdaErrors",
            alarm_description=(
                f"{_name} Lambda raised exceptions. "
                "May indicate IAM, networking, or code-level problems."
            ),
            metric=_lambda_obj.metric_errors(
                statistic="Sum",
                period=Duration.minutes(15),
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        _attach_actions(_lambda_err_alarm)

    # ----- Suppressor alarm (gates ops alarms below) -----

    # SuppressorActive=1 from EITHER auditor or flusher means a
    # scheduled sweep is in progress. We aggregate across both
    # sources via metric math (MAX). When the metric goes to 1 in
    # any single 1-min window, this alarm flips to ALARM. Composite
    # alarms below check this state to suppress ops alarms.
    _suppressor_alarm = cloudwatch.Alarm(
        scope,
        "SsmConfigSyncSuppressorActiveAlarm",
        alarm_name=f"{_cluster_id}-SsmConfigSync-SuppressorActive",
        alarm_description=(
            "Internal: ALARM while a scheduled sweep is publishing "
            "SuppressorActive=1. Used by composite alarms to suppress "
            "ops alarms during regular flush/audit windows. Not "
            "operator-actionable."
        ),
        metric=cloudwatch.MathExpression(
            expression="MAX([m1,m2])",
            using_metrics={
                "m1": cloudwatch.Metric(
                    namespace="EDH/SsmConfigSync",
                    metric_name="SuppressorActive",
                    statistic="Maximum",
                    period=Duration.minutes(1),
                    dimensions_map={**_alarm_dims, "Source": "Auditor"},
                ),
                "m2": cloudwatch.Metric(
                    namespace="EDH/SsmConfigSync",
                    metric_name="SuppressorActive",
                    statistic="Maximum",
                    period=Duration.minutes(1),
                    dimensions_map={**_alarm_dims, "Source": "Flush"},
                ),
            },
            period=Duration.minutes(1),
        ),
        threshold=0.5,  # any value > 0 = sweep in progress
        evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    # Suppressor itself does NOT page anyone -- it's wiring,
    # not a real signal.

    # ----- Ops alarms (composite-suppressed) -----

    # EventsFailed (Source=Live) spike: ConfigSync Lambda is failing
    # to process events. Suppressed during sweeps because aggressive
    # auto-heal during flush could push transient EventsFailed.
    _events_failed_metric_alarm = cloudwatch.Alarm(
        scope,
        "SsmConfigSyncEventsFailedAlarm",
        alarm_name=f"{_cluster_id}-SsmConfigSync-EventsFailed-Live",
        alarm_description=(
            "ConfigSync (live) is rejecting/failing on incoming SSM "
            "ParameterChange events at an elevated rate. Internal -- "
            "wrapped by composite to absorb sweep noise."
        ),
        metric=cloudwatch.Metric(
            namespace="EDH/SsmConfigSync",
            metric_name="EventsFailed",
            statistic="Sum",
            period=Duration.minutes(5),
            dimensions_map={**_alarm_dims, "Source": "Live"},
        ),
        threshold=5,
        evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    # Composite: fire only when EventsFailed alarms AND no sweep is running.
    _events_failed_composite = cloudwatch.CompositeAlarm(
        scope,
        "SsmConfigSyncEventsFailedCompositeAlarm",
        composite_alarm_name=f"{_cluster_id}-SsmConfigSync-EventsFailed",
        alarm_rule=cloudwatch.AlarmRule.all_of(
            cloudwatch.AlarmRule.from_alarm(
                _events_failed_metric_alarm,
                cloudwatch.AlarmState.ALARM,
            ),
            cloudwatch.AlarmRule.not_(
                cloudwatch.AlarmRule.from_alarm(
                    _suppressor_alarm,
                    cloudwatch.AlarmState.ALARM,
                )
            ),
        ),
        alarm_description=(
            "Live ConfigSync events are failing AND no scheduled sweep "
            "is in progress. Operator action required: check Lambda "
            "logs, IAM, and Valkey connectivity."
        ),
    )
    _attach_actions(_events_failed_composite)

    # EventLatencyMs (Source=Live) p99 elevated. Some latency growth
    # is expected during flush/audit (Valkey contention) so wrap.
    _latency_metric_alarm = cloudwatch.Alarm(
        scope,
        "SsmConfigSyncEventLatencyAlarm",
        alarm_name=f"{_cluster_id}-SsmConfigSync-EventLatency-Live",
        alarm_description=(
            "ConfigSync live event-processing latency p99 elevated "
            "above 500ms sustained 15min. Internal -- wrapped by "
            "composite to absorb sweep noise."
        ),
        metric=cloudwatch.Metric(
            namespace="EDH/SsmConfigSync",
            metric_name="EventLatencyMs",
            statistic="p99",
            period=Duration.minutes(5),
            dimensions_map={**_alarm_dims, "Source": "Live"},
        ),
        threshold=500,
        evaluation_periods=3,
        datapoints_to_alarm=3,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    _latency_composite = cloudwatch.CompositeAlarm(
        scope,
        "SsmConfigSyncEventLatencyCompositeAlarm",
        composite_alarm_name=f"{_cluster_id}-SsmConfigSync-EventLatency",
        alarm_rule=cloudwatch.AlarmRule.all_of(
            cloudwatch.AlarmRule.from_alarm(
                _latency_metric_alarm,
                cloudwatch.AlarmState.ALARM,
            ),
            cloudwatch.AlarmRule.not_(
                cloudwatch.AlarmRule.from_alarm(
                    _suppressor_alarm,
                    cloudwatch.AlarmState.ALARM,
                )
            ),
        ),
        alarm_description=(
            "Live ConfigSync latency p99 elevated AND no scheduled "
            "sweep in progress. Investigate Valkey health, Lambda "
            "cold-starts, and SecretsManager retrieval times."
        ),
    )
    _attach_actions(_latency_composite)

    logger.debug(
        f"SSM ElastiCache ConfigSync configured: hash={_hash_fqdn} "
        f"valkey={scope.soca_resources['elasticache'].attr_endpoint_address}"
    )


def _write_bulk_ssm_params(
    scope,
    cr_id: str,
    params: dict | None = None,
    resolved_params: dict | None = None,
    exclude_keys: set | None = None,
):
    """
    Create a CustomResource (CR) that bulk-writes SSM parameters.

    Two input channels are supported (both optional, at least one
    must contain data):

    params
        Synth-time-known name -> value pairs. These can be a large
        amount (hundreds) without hitting CFN property size limits
        because they are uploaded as a CDK Asset (S3 object).
    resolved_params
        name -> value pairs whose values are CDK tokens that only
        resolve at deploy time (e.g. ``vpc.vpc_id``,
        ``Fn.join(",", subnet_ids)``). These are passed inline via
        CustomResource properties so CloudFormation resolves the
        tokens before invoking the Lambda.

    The Lambda merges both sets; ``resolved_params`` wins on any key
    collision so a runtime value can override a static default.

    Args:
        cr_id: Logical CloudFormation ID for this CustomResource
            (e.g. ``"BulkSSMStaticParams"``). Must be unique per call
            site in the stack.
        params: Static or Synth-time-known parameter map, goes to S3.
        resolved_params: Deploy-time-resolved parameter map, goes
            into CR properties.

    Returns:
        The created CustomResource. The CR is added to
        ``scope._bulk_ssm_writers`` so downstream resources
        (e.g. ``cdk_completed`` signal parameter) can depend on all
        bulk writes completing.
    """
    params = params or {}
    resolved_params = resolved_params or {}
    # Model C: drop keys owned by the resource-mirror executor (it is the SOLE
    # writer of those SSM keys, so BulkSSMWriter must NOT write them — avoids a
    # write race on the s3|original repoint). See docs ResourceMirrorLambda D5/C.
    if exclude_keys:
        params = {k: v for k, v in params.items() if k not in exclude_keys}
        resolved_params = {k: v for k, v in resolved_params.items() if k not in exclude_keys}
    if not params and not resolved_params:
        raise ValueError(
            f"_write_bulk_ssm_params({cr_id}): at least one of "
            f"params or resolved_params must be non-empty"
        )

    _bulk_lambda = scope._get_bulk_ssm_lambda()

    # CR properties dict we will pass to CloudFormation.
    _cr_properties: dict = {}

    # Static params go to S3 as a CDK Asset.
    if params:
        # Stable JSON for content-hash (triggers Update when values change).
        _payload = json.dumps(params, sort_keys=True, default=str)
        _content_hash = hashlib.sha256(_payload.encode("utf-8")).hexdigest()

        _tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=f"_{cr_id}.json",
            delete=False,
            encoding="utf-8",
        )
        _tmp.write(_payload)
        _tmp.close()

        _asset = s3_assets.Asset(
            scope,
            f"{cr_id}Payload",
            path=_tmp.name,
        )
        # Least-privilege: grant read on this object only, not bucket-wide.
        _asset.grant_read(scope._bulk_ssm_lambda_role)

        _cr_properties["s3_bucket"] = _asset.s3_bucket_name
        _cr_properties["s3_key"] = _asset.s3_object_key
        _cr_properties["content_hash"] = _content_hash

    # Resolved (tokenized) params ride inline via CR properties. CFN
    # resolves the tokens before invoking the Lambda. No hash needed
    # because CFN already detects property changes natively.
    if resolved_params:
        _cr_properties["resolved_params"] = resolved_params

    # Forward stack-level cluster_tags so the Lambda can stamp each
    # SSM parameter via ssm:AddTagsToResource. See
    # docs/BulkSSMWriter.md §5.9 for the rationale (put_parameter
    # cannot accept Tags when Overwrite=True, so tagging must be a
    # discrete API call).
    if scope.cluster_tags:
        _cr_properties["tags"] = [
            {"Key": _t.get("Key"), "Value": _t.get("Value")}
            for _t in scope.cluster_tags
        ]

    _cr = CustomResource(
        scope,
        cr_id,
        service_token=_bulk_lambda.function_arn,
        properties=_cr_properties,
    )
    # Wait for the IAM policy to fully attach before the Lambda runs.
    _cr.node.add_dependency(scope._bulk_ssm_policy)
    scope._bulk_ssm_writers.append(_cr)

    logger.debug(
        f"Bulk SSM writer {cr_id}: "
        f"{len(params)} static (S3) + {len(resolved_params)} resolved (CR props)"
    )
    return _cr
