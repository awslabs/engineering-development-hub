# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Owned-base AMI lineage reconciler -- CDK wiring.

In-VPC Lambda that copies AWS-published base AMIs into the account (owned lineage) and maintains
the base_image_registry Aurora table. Event-driven:
  * an "EC2 AMI State Change" rule flips copying -> active/failed on each copy completion;
  * a daily (per-cluster jittered) schedule drives the pending queue + refresh drift-poll.

Writes Aurora over 5432 (WRITER endpoint) via psycopg; reaches EC2/KMS/SSM/SecretsManager control
planes via VPC endpoints or NAT (BSC11 -- no public internet needed). Behavior is gated at runtime by
/configuration/BaseImageAcceleration/Enabled (handler no-ops when off). See docs/GoldenImageLineage-Design.md.
"""

import hashlib
import json
import logging

from aws_cdk import Aws, Duration
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda
from aws_cdk import aws_ssm as ssm
from aws_cdk import custom_resources as cr

from helpers import security_groups as security_groups_helper

logger = logging.getLogger("soca_logger")

FUNCTIONS_DIR = "../functions"  # asset path convention (from installer/resources/src)


def build_base_image_reconciler(
    scope,
    cluster_id: str,
    database_name: str,
    region: str,
    get_lambda_runtime_version,
):
    """Create the base image reconciler Lambda + EventBridge rules.

    Args:
        scope: the SOCAInstall construct (exposes soca_resources + generate_log_group).
        cluster_id: EDH cluster id (resource/SSM naming).
        database_name: Aurora default database name.
        region: cluster region (source/dest of copies, resolution key).
        get_lambda_runtime_version: shared runtime helper (keeps the fleet on one version).
    """
    vpc = scope.soca_resources["vpc"]
    database = scope.soca_resources["database"]
    database_secret = scope.soca_resources["database_secret"]
    database_sg = scope.soca_resources["database_sg"]
    _psycopg_layer = scope.soca_resources.get("psycopg_layer")

    # ---------- Lambda security group (egress to Aurora + AWS control planes) ----------
    sg = ec2.SecurityGroup(
        scope,
        f"{cluster_id}-BaseImageReconcilerSG",
        vpc=vpc,
        description="Base image reconciler Lambda -- egress to Aurora + EC2/KMS/SSM/SecretsManager",
        allow_all_outbound=True,
    )
    security_groups_helper.create_ingress_rule(
        security_group=database_sg,
        peer=sg,
        connection=ec2.Port.tcp(database.cluster_endpoint.port),
        description="Base image reconciler Lambda to Aurora",
    )

    # ---------- Execution role ----------
    role = iam.Role(
        scope,
        f"{cluster_id}-BaseImageReconcilerRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        description="Base image reconciler Lambda execution role",
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            ),
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
    )
    # secretsmanager:GetSecretValue + kms:Decrypt on the secret's CMK
    database_secret.grant_read(role)

    role.attach_inline_policy(
        iam.Policy(
            scope,
            f"{cluster_id}-BaseImageReconcilerPolicy",
            statements=[
                # AMI copy lifecycle -- these EC2 describe/copy actions are not resource-scopable
                iam.PolicyStatement(
                    actions=[
                        "ec2:DescribeImages",
                        "ec2:DescribeSnapshots",
                        "ec2:CopyImage",
                    ],
                    resources=["*"],
                ),
                # Tag only images/snapshots created by the CopyImage call
                iam.PolicyStatement(
                    actions=["ec2:CreateTags"],
                    resources=[
                        f"arn:{Aws.PARTITION}:ec2:{region}::image/*",
                        f"arn:{Aws.PARTITION}:ec2:{region}::snapshot/*",
                    ],
                    conditions={"StringEquals": {"ec2:CreateAction": "CopyImage"}},
                ),
                # Deregister only cluster-owned images (stale-copy cleanup on refresh)
                iam.PolicyStatement(
                    actions=["ec2:DeregisterImage"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {"aws:ResourceTag/edh:ClusterId": cluster_id}
                    },
                ),
                # Resolve SSM public AMI aliases + read the feature flag
                iam.PolicyStatement(
                    actions=["ssm:GetParameter"],
                    resources=[
                        f"arn:{Aws.PARTITION}:ssm:{region}::parameter/aws/service/*",
                        f"arn:{Aws.PARTITION}:ssm:{region}:{Aws.ACCOUNT_ID}:parameter/edh/{cluster_id}/configuration/*",
                    ],
                ),
                # Read the account-wide concurrent-copy quota to size MaxConcurrency
                iam.PolicyStatement(
                    actions=["servicequotas:GetServiceQuota"],
                    resources=["*"],
                ),
            ],
        )
    )

    # ---------- Reconciler Lambda (in-VPC; psycopg layer for Aurora writes) ----------
    fn = aws_lambda.Function(
        scope,
        f"{cluster_id}-BaseImageReconciler",
        function_name=f"{cluster_id}-BaseImageReconciler",
        description="Owned-base AMI lineage reconciler (CopyImage + base_image_registry).",
        runtime=get_lambda_runtime_version(),
        architecture=aws_lambda.Architecture.X86_64,
        handler="BaseImageReconciler.handler",
        code=aws_lambda.Code.from_asset(f"{FUNCTIONS_DIR}/BaseImageReconciler"),
        layers=[_l for _l in [_psycopg_layer, scope.soca_resources.get("boto3_layer")] if _l] or None,
        timeout=Duration.minutes(2),
        memory_size=256,
        log_group=scope.generate_log_group(name="BaseImageReconcilerLambda"),
        role=role,
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[sg],
        environment={
            "EDH_CLUSTER_ID": cluster_id,
            "REGION": region,
            # WRITER endpoint -- the reconciler mutates the registry
            "DB_HOST": database.cluster_endpoint.hostname,
            "DB_PORT": str(database.cluster_endpoint.port),
            "DB_NAME": database_name,
            "DB_SECRET_ARN": database_secret.secret_arn,
            "FF_KEY": f"/edh/{cluster_id}/configuration/BaseImageAcceleration/Enabled",
            "MANIFEST_KEY": f"/edh/{cluster_id}/configuration/BaseImageAcceleration/Manifest",
            "PRIORITY_KEY": f"/edh/{cluster_id}/configuration/BaseImageAcceleration/Priority",
            "COPY_PRIORITY": '{"x86_64": ["windows2025", "amazonlinux2023"], "arm64": ["amazonlinux2023"]}',
            "COPY_RESERVE": "1",
            "BASE_IMAGE_MAX_CONCURRENCY": "4",
        },
        retry_attempts=0,
    )

    # ---------- Completion: react to each copied AMI finishing ----------
    # Match source + detail-type only; the handler filters State (event field casing varies).
    events.Rule(
        scope,
        f"{cluster_id}-BaseImageReconcilerAmiState",
        description=f"{cluster_id} base image reconciler -- EC2 AMI State Change completion",
        enabled=True,
        event_pattern=events.EventPattern(
            source=["aws.ec2"],
            detail_type=["EC2 AMI State Change"],
        ),
        targets=[events_targets.LambdaFunction(fn)],
    )

    # ---------- Daily jittered drive + refresh drift-poll ----------
    # Per-cluster deterministic minute/hour (stable across synths; avoids fleet herd).
    _j = int(hashlib.sha256(cluster_id.encode()).hexdigest(), 16)
    events.Rule(
        scope,
        f"{cluster_id}-BaseImageReconcilerSchedule",
        description=f"{cluster_id} base image reconciler -- daily drive + refresh drift-poll",
        enabled=True,
        schedule=events.Schedule.cron(minute=str(_j % 60), hour=str(_j % 6)),
        targets=[
            events_targets.LambdaFunction(
                fn,
                event=events.RuleTargetInput.from_object({"trigger": "schedule"}),
            )
        ],
    )

    # ---------- Manifest: region_map-derived base set for the install region ----------
    # custom_ami_map is the already-merged region_map.d for this region: {arch: {base_os: ami|alias}}.
    # Write it as the reconciler's manifest; the handler reads it each run and seeds idempotently.
    _ami_map = scope.soca_resources.get("custom_ami_map", {}) or {}
    _manifest = []
    for _arch, _oses in _ami_map.items():
        for _base_os, _ami in (_oses or {}).items():
            if not _ami:
                continue
            _entry = {"base_os": _base_os, "arch": _arch}
            if str(_ami).startswith("/aws/service/"):
                _entry["source_alias"] = _ami
            else:
                _entry["source_ami_id"] = _ami
            _manifest.append(_entry)

    _manifest_param = ssm.StringParameter(
        scope,
        f"{cluster_id}-BaseImageManifest",
        parameter_name=f"/edh/{cluster_id}/configuration/BaseImageAcceleration/Manifest",
        string_value=json.dumps(_manifest),
        description="region_map-derived base AMI manifest consumed by the reconciler (seed source).",
    )

    # ---------- Install-time kick: invoke the reconciler once (async; no-op if FF off) ----------
    _kick = cr.AwsCustomResource(
        scope,
        f"{cluster_id}-BaseImageReconcilerKick",
        install_latest_aws_sdk=False,  # Lambda.invoke is in the built-in SDK; avoids the strict-synth warning
        on_update=cr.AwsSdkCall(
            service="Lambda",
            action="invoke",
            parameters={
                "FunctionName": fn.function_name,
                "InvocationType": "Event",
                "Payload": '{"trigger":"install"}',
            },
            physical_resource_id=cr.PhysicalResourceId.of(
                f"{cluster_id}-base-image-reconciler-kick"
            ),
        ),
        policy=cr.AwsCustomResourcePolicy.from_statements(
            [
                iam.PolicyStatement(
                    actions=["lambda:InvokeFunction"],
                    resources=[fn.function_arn],
                )
            ]
        ),
    )
    _kick.node.add_dependency(fn)
    # Ensure the manifest SSM param exists before the async install-kick reads it (avoids empty first seed)
    _kick.node.add_dependency(_manifest_param)

    scope.soca_resources["base_image_reconciler_lambda"] = fn
    logger.debug("Base image reconciler Lambda + EventBridge rules configured")
    return fn
