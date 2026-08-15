# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Spot Interruption Capture -- CDK wiring (Saved Desktops feature).

Deploys the EventBridge-triggered Lambda that auto-captures a Spot VDI on the
EC2 Spot Interruption Warning (2-min notice): NoReboot CreateImage + a
vdi_saved_images registry row so the desktop is resumable after reclaim.

Always deployed; behaviour is gated at runtime by the AllowSavedDesktops flag
(the Lambda reads it and no-ops when off), so the feature can be enabled
post-deployment via config alone -- no new infra. Mirrors the in-VPC, Aurora +
Secrets Manager pattern in usb_allowlist_resolver.py and the EventBridge->Lambda
pattern in vdi_pools.py. psycopg comes from the shared PsycopgLayer (x86_64).

Invoked from cdk_construct.py after the database + VPC exist.
"""

import logging

from aws_cdk import Aws, Duration
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda
from aws_cdk import aws_ssm as ssm

from helpers import security_groups as security_groups_helper

logger = logging.getLogger("soca_logger")

FUNCTIONS_DIR = "../functions"  # asset path convention (from installer/resources/src)


def build_spot_interruption_capture(
    scope,
    cluster_id: str,
    database_name: str,
    get_lambda_runtime_version,
):
    """Create the Spot interruption auto-capture Lambda + EventBridge rule.

    Args:
        scope: the SOCAInstall construct (exposes soca_resources + generate_log_group).
        cluster_id: EDH cluster id (for resource/SSM naming + tag scoping).
        database_name: Aurora default database name.
        get_lambda_runtime_version: shared runtime helper (keeps the fleet on one version).

    Returns:
        The created aws_lambda.Function.
    """
    vpc = scope.soca_resources["vpc"]
    database = scope.soca_resources["database"]
    database_secret = scope.soca_resources["database_secret"]
    database_sg = scope.soca_resources["database_sg"]

    # ---------- Lambda security group (egress to Aurora + AWS endpoints) ----------
    capture_sg = ec2.SecurityGroup(
        scope,
        f"{cluster_id}-SpotInterruptionCaptureSG",
        vpc=vpc,
        description="Spot interruption capture Lambda -- egress to Aurora + EC2/Secrets Manager",
        allow_all_outbound=True,
    )
    security_groups_helper.create_ingress_rule(
        security_group=database_sg,
        peer=capture_sg,
        connection=ec2.Port.tcp(database.cluster_endpoint.port),
        description="Spot interruption capture Lambda to Aurora (writes vdi_saved_images)",
    )

    # ---------- Execution role ----------
    capture_role = iam.Role(
        scope,
        f"{cluster_id}-SpotInterruptionCaptureRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        description="Spot interruption capture Lambda execution role",
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            ),
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
    )
    # secretsmanager:GetSecretValue + kms:Decrypt on the DB secret's CMK.
    database_secret.grant_read(capture_role)
    # EC2 describe (no resource scoping) + capture. The rule + the Lambda's own
    # edh:ClusterId tag filter constrain what it acts on; CreateImage/CreateTags
    # touch new image/snapshot resources that carry no pre-existing tag.
    capture_role.add_to_policy(
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["ec2:DescribeInstances", "ec2:DescribeVolumes"],
            resources=["*"],
        )
    )
    capture_role.add_to_policy(
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["ec2:CreateImage", "ec2:CreateTags", "ec2:DeregisterImage"],
            resources=["*"],
        )
    )
    # Runtime feature-flag read (AllowSavedDesktops), scoped to this cluster.
    capture_role.add_to_policy(
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["ssm:GetParameter"],
            resources=[
                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:"
                f"parameter/edh/{cluster_id}/configuration/FeatureFlags/VirtualDesktops/*"
            ],
        )
    )

    # ---------- Capture Lambda (in-VPC, writes Aurora) ----------
    _psycopg_layer = scope.soca_resources.get("psycopg_layer")
    capture_lambda = aws_lambda.Function(
        scope,
        f"{cluster_id}-SpotInterruptionCapture",
        function_name=f"{cluster_id}-SpotInterruptionCapture",
        description="Auto-capture a Spot VDI on EC2 Spot Interruption Warning (gated by AllowSavedDesktops)",
        runtime=get_lambda_runtime_version(),
        architecture=aws_lambda.Architecture.X86_64,
        handler="SpotInterruptionCapture.lambda_handler",
        code=aws_lambda.Code.from_asset(f"{FUNCTIONS_DIR}/SpotInterruptionCapture"),
        layers=[_l for _l in [_psycopg_layer, scope.soca_resources.get("boto3_layer")] if _l] or None,
        # create-image is initiated (not awaited) within the 2-min reclaim window;
        # allow headroom for the parallel ec2 calls + the DB writes.
        timeout=Duration.seconds(120),
        memory_size=256,
        log_group=scope.generate_log_group(name="SpotInterruptionCaptureLambda"),
        role=capture_role,
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        security_groups=[capture_sg],
        environment={
            # Writer endpoint -- the Lambda INSERTs the vdi_saved_images row.
            "DB_ENDPOINT": database.cluster_endpoint.hostname,
            "DB_PORT": str(database.cluster_endpoint.port),
            "DB_NAME": database_name,
            "DB_SECRET_ARN": database_secret.secret_arn,
            "EDH_CLUSTER_ID": cluster_id,
        },
        retry_attempts=0,
    )

    # ---------- EventBridge rule: Spot Interruption Warning -> Lambda ----------
    # The event detail carries only instance-id; the Lambda self-filters by the
    # instance's edh:ClusterId + dcv_node tags, so the rule is account-wide.
    events.Rule(
        scope,
        f"{cluster_id}-SpotInterruptionCaptureRule",
        rule_name=f"{cluster_id}-SpotInterruptionCaptureRule",
        description="Fire the capture Lambda on EC2 Spot Instance Interruption Warning",
        event_pattern=events.EventPattern(
            source=["aws.ec2"],
            detail_type=["EC2 Spot Instance Interruption Warning"],
        ),
        targets=[events_targets.LambdaFunction(capture_lambda)],
    )

    ssm.StringParameter(
        scope,
        f"{cluster_id}-SpotInterruptionCaptureLambdaArnParam",
        parameter_name=f"/edh/{cluster_id}/configuration/SpotInterruptionCaptureLambdaArn",
        string_value=capture_lambda.function_arn,
        description="ARN of the Spot interruption auto-capture Lambda",
    )

    scope.soca_resources["spot_interruption_capture_lambda"] = capture_lambda
    logger.debug("Spot interruption capture Lambda + EventBridge rule configured")
    return capture_lambda
