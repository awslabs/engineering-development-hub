# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
VDI pooling -- DynamoDB table provisioning for the DCV VDI pool feature.

Pooling pre-provisions DCV desktops (hot = running + broker-registered + idle;
warm = ASG warm pool / Stopped) so users get a desktop in ~0s / ~30s instead
of a full cold launch. The PRIMARY driver is UX (time-to-desktop); the cost
knobs exist to bound the added spend, not to save money.

This module owns the STATIC scaffolding (DDB tables) created at deploy time.
The pool AWS resources proper -- ASGs, warm pools, launch templates, scheduled
actions, alarms -- are created at RUNTIME by the PoolController (boto3), not
here, because pools are admin runtime config that changes far more often than
deploys.

Tables (all PAY_PER_REQUEST, mirroring the vdi_launch_history table pattern in
cdk_construct.py):
  * {cluster}-vdi-pool-config   -- admin per-(stack, instance_type) pool config
        pk = STACK#<software_stack_id>, sk = TYPE#<instance_type> | "META"
  * {cluster}-vdi-pool-ledger   -- per-member runtime state (atomic claim arbiter)
        pk = POOL#<stack_id>#<instance_type>, sk = <instance_id>
        TTL on expires_at to auto-reap terminal rows.
  * {cluster}-vdi-pool-summary  -- reconciler-stamped per-pool status + stats
        pk = POOL#<stack_id>#<instance_type>, sk = "SUMMARY"

Entry point:
  * setup() -- called from the thin SOCAInstall.vdi_pools() wrapper.

Applies ONLY to VDI (DCV) software stacks, never target-node software stacks.
"""

import logging

from aws_cdk import CustomResource, Duration, RemovalPolicy
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as aws_lambda
from aws_cdk import aws_logs as logs
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions

logger = logging.getLogger("soca_logger")


def _pool_table(scope, construct_id, table_name, *, ttl_attribute=None):
    """Create a pool DynamoDB table with the EDH-standard settings:
    on-demand billing (no RCU/WCU to manage at our bursty claim cadence),
    destroy-on-teardown, PITR off. Mirrors the vdi_launch_history table."""
    return dynamodb.Table(
        scope,
        construct_id,
        table_name=table_name,
        partition_key=dynamodb.Attribute(
            name="pk", type=dynamodb.AttributeType.STRING
        ),
        sort_key=dynamodb.Attribute(
            name="sk", type=dynamodb.AttributeType.STRING
        ),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        time_to_live_attribute=ttl_attribute,
        removal_policy=RemovalPolicy.DESTROY,
        point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
            point_in_time_recovery_enabled=False
        ),
    )


def _require_high_scale_for_pooling(get_config_key):
    """Synth-time precondition: VDI pooling REQUIRES DCV High Scale.

    Pooling depends on high-scale components (broker-managed sessions, the DCV
    event relay, event-driven readiness ingestion) and provisions additional
    always-on infrastructure (idle hot/warm EC2 + EBS, per-(stack, instance_type)
    ASGs, a reconciler Lambda). A misconfiguration must FAIL the synth with a
    clear message rather than silently enabling pooling or downgrading config.

    No-op when get_config_key is None (defensive; the wrapper always passes it).
    Raises plain ValueError (SocaError is runtime-only) per the EDH CDK
    convention, mirroring helpers/database.py + helpers/webshell.py.
    """
    if get_config_key is None:
        return
    _pool_enabled = get_config_key(
        key_name="Config.dcv.pool.enabled",
        expected_type=bool,
        default=False,
        required=False,
    )
    _high_scale = get_config_key(
        key_name="Config.dcv.high_scale",
        expected_type=bool,
        default=False,
        required=False,
    )
    if _pool_enabled and not _high_scale:
        raise ValueError(
            "Invalid DCV configuration: Config.dcv.pool.enabled is True but "
            "Config.dcv.high_scale is False. VDI pooling REQUIRES DCV High "
            "Scale -- it depends on broker-managed sessions, the DCV event "
            "relay, and event-driven readiness ingestion, all of which are "
            "high-scale components. Pooling also provisions additional "
            "always-on infrastructure (idle hot/warm EC2 + EBS, per-(stack, "
            "instance_type) ASGs, and a reconciler Lambda), so it is gated "
            "rather than silently enabled. Resolve by EITHER setting "
            "Config.dcv.high_scale: true (to use pooling) OR "
            "Config.dcv.pool.enabled: false (to disable pooling)."
        )


def setup(
    scope,
    soca_resources,
    user_specified_variables,
    lambda_runtime=None,
    get_config_key=None,
):
    """Provision the VDI pool DynamoDB tables (config / ledger / summary) and
    the runtime PoolController reconciler (Lambda + scoped role + schedule).

    Declarative and idempotent at the CDK level. Table references are stored
    in soca_resources so downstream wiring can reference them.

    Gate: VDI pooling REQUIRES DCV High Scale -- see
    _require_high_scale_for_pooling(). The synth fails fast (ValueError) on a
    pool-without-high-scale misconfiguration rather than silently enabling it.
    """
    # --- Synth-time precondition: pooling requires DCV High Scale ---------
    _require_high_scale_for_pooling(get_config_key)

    _cluster_id = user_specified_variables.cluster_id
    logger.debug("in vdi_pools.setup() -- creating VDI pool DDB tables")

    soca_resources["vdi_pool_config_table"] = _pool_table(
        scope, "VdiPoolConfigTable", f"{_cluster_id}-vdi-pool-config"
    )
    soca_resources["vdi_pool_ledger_table"] = _pool_table(
        scope,
        "VdiPoolLedgerTable",
        f"{_cluster_id}-vdi-pool-ledger",
        ttl_attribute="expires_at",
    )
    soca_resources["vdi_pool_summary_table"] = _pool_table(
        scope, "VdiPoolSummaryTable", f"{_cluster_id}-vdi-pool-summary"
    )

    setup_reconciler(
        scope=scope,
        soca_resources=soca_resources,
        user_specified_variables=user_specified_variables,
        lambda_runtime=lambda_runtime,
    )

    setup_tagger(
        scope=scope,
        soca_resources=soca_resources,
        user_specified_variables=user_specified_variables,
        lambda_runtime=lambda_runtime,
    )

    return soca_resources


def _table_arns(soca_resources):
    """ARNs (table + indexes) of the pool DDB tables the reconciler touches."""
    _keys = (
        "vdi_pool_config_table",
        "vdi_pool_ledger_table",
        "vdi_pool_summary_table",
        "vdi_launch_history_table",
    )
    _arns = []
    for _k in _keys:
        _t = soca_resources.get(_k)
        if _t is not None:
            _arns.append(_t.table_arn)
            _arns.append(f"{_t.table_arn}/index/*")
    return _arns


def setup_reconciler(scope, soca_resources, user_specified_variables, lambda_runtime):
    """Create the VdiPoolReconciler Lambda, its least-privilege role, and the
    EventBridge drift-sweep schedule.

    The reconciler manages pool AWS resources (ASGs, warm pools, launch
    templates, scheduled actions, alarms) at RUNTIME via boto3. Its role is
    scoped per-function (auditable in isolation): DDB on the pool tables;
    autoscaling/ec2 mutations tag-gated to this cluster; iam:PassRole limited
    to the EC2/ASG services.
    """
    _cid = user_specified_variables.cluster_id
    _runtime = lambda_runtime

    _role = iam.Role(
        scope,
        f"{_cid}-VdiPoolReconcilerRole",
        role_name=f"{_cid}-VdiPoolReconcilerRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
    )

    _cluster_tag_cond = {
        "StringEquals": {f"aws:ResourceTag/edh:ClusterId": _cid}
    }
    _cluster_requesttag_cond = {
        "StringEquals": {f"aws:RequestTag/edh:ClusterId": _cid}
    }

    _role.attach_inline_policy(
        iam.Policy(
            scope,
            f"{_cid}-VdiPoolReconcilerPolicy",
            statements=[
                # Pool DDB tables (config/ledger/summary) + launch history.
                iam.PolicyStatement(
                    actions=[
                        "dynamodb:GetItem",
                        "dynamodb:Query",
                        "dynamodb:Scan",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:BatchWriteItem",
                        "dynamodb:BatchGetItem",
                    ],
                    resources=_table_arns(soca_resources) or ["*"],
                ),
                # Discovery is read-only and unconditioned.
                iam.PolicyStatement(
                    actions=[
                        "autoscaling:Describe*",
                        "ec2:DescribeLaunchTemplates",
                        "ec2:DescribeLaunchTemplateVersions",
                        "ec2:DescribeInstances",
                    ],
                    resources=["*"],
                ),
                # Mutations on EXISTING ASGs -- gated to this cluster's tag.
                iam.PolicyStatement(
                    actions=[
                        "autoscaling:UpdateAutoScalingGroup",
                        "autoscaling:DeleteAutoScalingGroup",
                        "autoscaling:PutWarmPool",
                        "autoscaling:DeleteWarmPool",
                        "autoscaling:StartInstanceRefresh",
                        "autoscaling:PutScheduledUpdateGroupAction",
                        "autoscaling:BatchDeleteScheduledAction",
                        "autoscaling:DeleteScheduledAction",
                        "autoscaling:DetachInstances",
                        "autoscaling:SetInstanceHealth",
                        "autoscaling:PutLifecycleHook",
                        "autoscaling:DeleteLifecycleHook",
                    ],
                    resources=["*"],
                    conditions=_cluster_tag_cond,
                ),
                # Tagging ASGs (pool_id / managed_by / pool_status ACTIVE|
                # PARKED|DRAINING). UNCONDITIONAL on purpose: CreateOrUpdateTags/
                # DeleteTags do not reliably support the autoscaling:ResourceTag
                # condition key, and the pool_status-only update call carries no
                # cluster RequestTag -- gating either way 403s the update path.
                # Safe: this role only ever tags the pool ASGs it manages.
                iam.PolicyStatement(
                    actions=[
                        "autoscaling:CreateOrUpdateTags",
                        "autoscaling:DeleteTags",
                    ],
                    resources=["*"],
                ),
                # ASG creation + tagging -- gated on the request carrying the
                # cluster tag (the resource tag does not exist yet at create).
                iam.PolicyStatement(
                    actions=[
                        "autoscaling:CreateAutoScalingGroup",
                        "autoscaling:CreateOrUpdateTags",
                    ],
                    resources=["*"],
                    conditions=_cluster_requesttag_cond,
                ),
                # Session-less launch templates (rendered per stack at runtime).
                # ec2:RunInstances is required by CreateAutoScalingGroup's
                # launch-template authorization check (the real launches run via
                # the ASG service-linked role, not this role).
                iam.PolicyStatement(
                    actions=[
                        "ec2:CreateLaunchTemplate",
                        "ec2:CreateLaunchTemplateVersion",
                        "ec2:ModifyLaunchTemplate",
                        "ec2:DeleteLaunchTemplate",
                        "ec2:DeleteLaunchTemplateVersions",
                        "ec2:CreateTags",
                        "ec2:RunInstances",
                    ],
                    resources=["*"],
                ),
                # Advisory pool alarms (collision rate, claimed-Spot interrupts).
                iam.PolicyStatement(
                    actions=["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms"],
                    resources=["*"],
                ),
                # Cluster teardown: terminate detached/claimed pool desktops that
                # are no longer ASG members (ASG delete only reaps members). Gated
                # to this cluster's edh:ClusterId resource tag.
                iam.PolicyStatement(
                    actions=["ec2:TerminateInstances"],
                    resources=["*"],
                    conditions=_cluster_tag_cond,
                ),
                # Phase 3: per-pool depth gauges (ReadyNow/HotDepth/WarmDepth/
                # DesiredDepth) for the Pools dashboard. Namespace-scoped, mirrors
                # the relay's PutMetricData grant.
                iam.PolicyStatement(
                    actions=["cloudwatch:PutMetricData"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {"cloudwatch:namespace": "EDH/DCVHighScale"}
                    },
                ),
                # Cluster-wide launch inputs (SG, instance profile, subnets,
                # volume type, SSH key, region) read from /configuration/* at
                # reconcile time. Read-only; can be scoped to the cluster SSM
                # prefix once finalized.
                iam.PolicyStatement(
                    actions=[
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                    ],
                    resources=["*"],
                ),
                # Pass the VDI node instance role to EC2/ASG only.
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "iam:PassedToService": [
                                "ec2.amazonaws.com",
                                "autoscaling.amazonaws.com",
                            ]
                        }
                    },
                ),
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    resources=["*"],
                ),
            ],
        )
    )

    _recon_lg = scope.generate_log_group(name="VdiPoolReconcilerLambda")
    _fn = aws_lambda.Function(
        scope,
        f"{_cid}-VdiPoolReconciler",
        function_name=f"{_cid}-VdiPoolReconciler",
        description="Declarative reconciler for DCV VDI pools (ASGs/warm pools/LTs/alarms) -- runtime boto3, tag-managed.",
        memory_size=256,
        runtime=_runtime,
        timeout=Duration.minutes(15),
        log_group=_recon_lg,
        role=_role,
        handler="VdiPoolReconciler.lambda_handler",
        code=aws_lambda.Code.from_asset("../functions/VdiPoolReconciler"),
        layers=[_l for _l in [soca_resources.get("boto3_layer")] if _l] or None,
        environment={"EDH_CLUSTER_ID": _cid},
    )
    soca_resources["vdi_pool_reconciler_lambda"] = _fn

    # --- Lambda error visibility: log metric filters + alarms --------------
    # Caught-and-logged AWS errors (e.g. IAM AccessDenied in the reconciler's
    # per-pool try/except, or relay handler failures) do NOT increment the
    # built-in AWS/Lambda Errors metric, so they were historically invisible.
    # Surface them: a metric filter on each pool Lambda log group -> an
    # EDH/DCVHighScale error metric -> an alarm on the cluster SNS topic.
    _err_pattern = logs.FilterPattern.any_term(
        "[ERROR]", "Traceback", "AccessDenied", "ensure failed"
    )
    _alarm_topic = soca_resources.get("sns_cluster_topic")
    _err_targets = [("VdiPoolReconciler", _recon_lg)]
    _relay_lambda = soca_resources.get("dcv_event_relay_lambda")
    if _relay_lambda is not None:
        _err_targets.append(("DcvEventRelay", _relay_lambda.log_group))
    for _label, _lg in _err_targets:
        _metric_name = f"{_label}Errors"
        logs.MetricFilter(
            scope,
            f"{_cid}-{_label}ErrorMetricFilter",
            log_group=_lg,
            filter_pattern=_err_pattern,
            metric_namespace="EDH/DCVHighScale",
            metric_name=_metric_name,
            metric_value="1",
            default_value=0,
        )
        _alarm = cloudwatch.Alarm(
            scope,
            f"{_cid}-{_label}ErrorAlarm",
            alarm_name=f"{_cid}-vdipool-{_label.lower()}-errors",
            alarm_description=(
                f"{_label} logged an error (caught or uncaught) -- VDI pool. "
                "Caught errors don't hit AWS/Lambda Errors; this filter catches them."
            ),
            metric=cloudwatch.Metric(
                namespace="EDH/DCVHighScale",
                metric_name=_metric_name,
                statistic="Sum",
                period=Duration.minutes(5),
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        if _alarm_topic is not None:
            _alarm.add_alarm_action(cloudwatch_actions.SnsAction(_alarm_topic))

    # The DcvEventRelay Lambda writes the ledger AVAILABLE row on pool-ready
    # events (readiness ingestion), so grant it write on the ledger table.
    _relay_role = soca_resources.get("dcv_event_relay_role")
    if _relay_role is not None:
        soca_resources["vdi_pool_ledger_table"].grant_write_data(_relay_role)
        # ... and let it complete the launch lifecycle hook (Pending:Wait ->
        # InService) for a ready member. Kept OFF the end-user instance role on
        # purpose -- the relay is the single off-host readiness chokepoint.
        # CompleteLifecycleAction has no resource-level ARN, so scope by the
        # cluster's pool-managed ASG name pattern via a condition is not
        # supported; restrict to the action only (relay is trusted infra).
        _relay_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["autoscaling:CompleteLifecycleAction"],
                resources=["*"],
            )
        )

    # Let the web/API tier invoke the reconciler on config change (PUT) for
    # instant apply, and read/write the pool tables + run the claim path.
    _ctrl = soca_resources.get("controller_role")
    if _ctrl is not None:
        _fn.grant_invoke(_ctrl)
        for _k in (
            "vdi_pool_config_table",
            "vdi_pool_ledger_table",
            "vdi_pool_summary_table",
        ):
            _t = soca_resources.get(_k)
            if _t is not None:
                _t.grant_read_write_data(_ctrl)
        # Claim-path perms for the web-tier PoolAllocator: tag the claimed
        # instance, detach it (cluster-tag-scoped), emit claim metrics.
        _ctrl.attach_inline_policy(
            iam.Policy(
                scope,
                f"{_cid}-VdiPoolControllerClaimPolicy",
                statements=[
                    iam.PolicyStatement(
                        actions=["ec2:CreateTags"], resources=["*"]
                    ),
                    iam.PolicyStatement(
                        actions=["autoscaling:DetachInstances"],
                        resources=["*"],
                        conditions={
                            "StringEquals": {
                                "aws:ResourceTag/edh:ClusterId": _cid
                            }
                        },
                    ),
                    # Zombie-sweep: mark a broker-zombied AVAILABLE member
                    # Unhealthy so the ASG replaces it (cluster-tag scoped).
                    iam.PolicyStatement(
                        actions=["autoscaling:SetInstanceHealth"],
                        resources=["*"],
                        conditions={
                            "StringEquals": {
                                "aws:ResourceTag/edh:ClusterId": _cid
                            }
                        },
                    ),
                    iam.PolicyStatement(
                        actions=["cloudwatch:PutMetricData"],
                        resources=["*"],
                        conditions={
                            "StringEquals": {
                                "cloudwatch:namespace": "EDH/DCVHighScale"
                            }
                        },
                    ),
                ],
            )
        )

    # Periodic drift-sweep. Apply-on-config-change (API PUT -> invoke) is wired
    # in a later phase; the schedule alone keeps desired==actual.
    events.Rule(
        scope,
        f"{_cid}-VdiPoolReconcilerSchedule",
        rule_name=f"{_cid}-VdiPoolReconcilerSchedule",
        schedule=events.Schedule.rate(Duration.minutes(5)),
        targets=[events_targets.LambdaFunction(_fn)],
    )

    # Cluster-teardown hook. Pool ASGs/warm pools/LTs/alarms are runtime-created
    # and NOT in the CFN stack, so DeleteStack would orphan them. A stack-resident
    # custom resource fires _teardown() on Delete (Create/Update no-op); Delete
    # always returns SUCCESS so a cleanup hiccup can't wedge stack deletion.
    _teardown_cr = CustomResource(
        scope,
        f"{_cid}-VdiPoolTeardown",
        resource_type="Custom::VdiPoolTeardown",
        service_token=_fn.function_arn,
    )
    # The reconciler Lambda (and its IAM policy) must exist before the custom
    # resource invokes it, and must survive until the Delete handler runs.
    _teardown_cr.node.add_dependency(_fn)

    return _fn


def setup_tagger(scope, soca_resources, user_specified_variables, lambda_runtime):
    """Create the VdiPoolTagger Lambda, its least-privilege role, and the
    EventBridge rule that drives event-driven cosmetic re-tagging of pool
    instances (warm-pool member -> ``-warming``; promoted to live -> ``-hot``).

    Decoupled from VdiPoolReconciler on purpose: cosmetic tagging must never add
    latency or load to the reconcile loop, and a tagging failure must never
    affect pool reconciliation. Role is scoped per BSC6 least-privilege --
    ec2:CreateTags is gated to this cluster's edh:ClusterId resource tag.
    """
    _cid = user_specified_variables.cluster_id
    _runtime = lambda_runtime

    _role = iam.Role(
        scope,
        f"{_cid}-VdiPoolTaggerRole",
        role_name=f"{_cid}-VdiPoolTaggerRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
    )
    _role.attach_inline_policy(
        iam.Policy(
            scope,
            f"{_cid}-VdiPoolTaggerPolicy",
            statements=[
                # Cosmetic re-tag of pool instances -- gated to this cluster's
                # tag. The function only ever writes the Name + edh:pool_role
                # tags; reconciler discovery tags (edh:pool_id / managed_by /
                # instance_type / stack_id) are never touched.
                iam.PolicyStatement(
                    actions=["ec2:CreateTags"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {"aws:ResourceTag/edh:ClusterId": _cid}
                    },
                ),
                # DescribeTags has no resource-level scoping (AWS limitation).
                iam.PolicyStatement(
                    actions=["ec2:DescribeTags"],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    resources=["*"],
                ),
            ],
        )
    )

    _tagger_lg = scope.generate_log_group(name="VdiPoolTaggerLambda")
    _fn = aws_lambda.Function(
        scope,
        f"{_cid}-VdiPoolTagger",
        function_name=f"{_cid}-VdiPoolTagger",
        description="Event-driven cosmetic Name/role tagging for DCV VDI pool instances (warm -> -warming, promoted -> -hot).",
        memory_size=128,
        runtime=_runtime,
        timeout=Duration.minutes(1),
        log_group=_tagger_lg,
        role=_role,
        handler="VdiPoolTagger.lambda_handler",
        code=aws_lambda.Code.from_asset("../functions/VdiPoolTagger"),
        layers=[_l for _l in [soca_resources.get("boto3_layer")] if _l] or None,
        environment={"EDH_CLUSTER_ID": _cid},
    )
    soca_resources["vdi_pool_tagger_lambda"] = _fn

    # Fire on warm-pool lifecycle transitions for THIS cluster's pool ASGs only
    # (name prefix). Both event types carry Origin/Destination, letting the
    # function map warm-pool membership vs promotion to the -warming / -hot
    # suffix.
    events.Rule(
        scope,
        f"{_cid}-VdiPoolTaggerRule",
        rule_name=f"{_cid}-VdiPoolTaggerRule",
        event_pattern=events.EventPattern(
            source=["aws.autoscaling"],
            detail_type=[
                "EC2 Instance-launch Lifecycle Action",
                "EC2 Instance Launch Successful",
            ],
            detail={
                "AutoScalingGroupName": events.Match.prefix(f"{_cid}-vdipool-")
            },
        ),
        targets=[events_targets.LambdaFunction(_fn)],
    )

    return _fn
