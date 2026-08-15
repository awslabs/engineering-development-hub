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
    RemovalPolicy,
    aws_dynamodb as dynamodb,
    aws_ec2 as ec2,
    aws_lambda as aws_lambda,
    aws_iam as iam,
    aws_sqs as sqs,
    aws_lambda_event_sources as lambda_event_sources,
    aws_ssm as ssm,
)


import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# VDI launch history DDB table

logger = logging.getLogger("soca_logger")


def vdi_launch_history(
    scope,
    *,
    user_specified_variables=None,
    get_lambda_runtime_version=None,
):
    """
    DDB table recording per-session launch checkpoint durations for
    the VDI launch-ETA feature. Controller writes inline on
    session-ready/failed; reads via helpers/vdi_eta to show
    "Typical: ~3:30" on VDI cards. 90-day TTL on expires_at.
    """
    _cluster_id = user_specified_variables.cluster_id

    _table = dynamodb.Table(
        scope,
        "VdiLaunchHistoryTable",
        table_name=f"{_cluster_id}-vdi-launch-history",
        partition_key=dynamodb.Attribute(
            name="pk", type=dynamodb.AttributeType.STRING
        ),
        sort_key=dynamodb.Attribute(
            name="sk", type=dynamodb.AttributeType.STRING
        ),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        time_to_live_attribute="expires_at",
        removal_policy=RemovalPolicy.DESTROY,
        point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
            point_in_time_recovery_enabled=False
        ),
    )
    scope.soca_resources["vdi_launch_history_table"] = _table

    # Controller reads + writes its own launch history.
    _controller_role = scope.soca_resources.get("controller_role")
    if _controller_role is not None:
        _controller_role.attach_inline_policy(
            iam.Policy(
                scope,
                "VdiLaunchHistoryTableAccess",
                statements=[
                    iam.PolicyStatement(
                        sid="VdiLaunchHistoryReadWrite",
                        actions=[
                            "dynamodb:PutItem",
                            "dynamodb:Query",
                            "dynamodb:GetItem",
                            "dynamodb:DescribeTable",
                        ],
                        resources=[_table.table_arn],
                    )
                ],
            )
        )

    logger.debug(
        f"VDI launch history table configured: {_table.table_name}"
    )

    # --- Notification Fabric: DDB event log + nonce dedup ---
    _notif_table = dynamodb.Table(
        scope,
        "DcvNotificationsTable",
        table_name=f"{_cluster_id}-notifications",
        partition_key=dynamodb.Attribute(
            name="scope", type=dynamodb.AttributeType.STRING
        ),
        sort_key=dynamodb.Attribute(
            name="id", type=dynamodb.AttributeType.STRING
        ),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        time_to_live_attribute="ttl",
        removal_policy=RemovalPolicy.DESTROY,
        point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
            point_in_time_recovery_enabled=False
        ),
    )
    scope.soca_resources["notifications_table"] = _notif_table

    _nonces_table = dynamodb.Table(
        scope,
        "DcvEventNoncesTable",
        table_name=f"{_cluster_id}-event-nonces",
        partition_key=dynamodb.Attribute(
            name="nonce_key", type=dynamodb.AttributeType.STRING
        ),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        time_to_live_attribute="ttl",
        removal_policy=RemovalPolicy.DESTROY,
        point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
            point_in_time_recovery_enabled=False
        ),
    )
    scope.soca_resources["event_nonces_table"] = _nonces_table

    if _controller_role is not None:
        _controller_role.attach_inline_policy(
            iam.Policy(
                scope,
                "NotificationFabricAccess",
                statements=[
                    iam.PolicyStatement(
                        sid="NotificationsReadWrite",
                        actions=[
                            "dynamodb:PutItem",
                            "dynamodb:Query",
                            "dynamodb:GetItem",
                            "dynamodb:DescribeTable",
                        ],
                        resources=[
                            _notif_table.table_arn,
                            _nonces_table.table_arn,
                        ],
                    )
                ],
            )
        )

    logger.debug(
        f"Notification fabric tables configured: "
        f"{_notif_table.table_name}, {_nonces_table.table_name}"
    )

    # --- Async Placement: SQS FIFO queues ---
    # FIFO + MessageGroupId=session_uuid preserves per-session ordering;
    # senders supply MessageDeduplicationId (nonce). Short retention (1h)
    # bounds backlog; DLQ catches poison messages after 5 receives.
    # visibility_timeout (360s) must exceed the Lambda timeout (60s).
    _placement_req_dlq = sqs.Queue(
        scope,
        "DcvPlacementRequestDlq",
        queue_name=f"{_cluster_id}-placement-request-dlq.fifo",
        fifo=True,
        content_based_deduplication=True,
        retention_period=Duration.days(14),
        encryption=sqs.QueueEncryption.SQS_MANAGED,
        enforce_ssl=True,
    )
    _placement_request_queue = sqs.Queue(
        scope,
        "DcvPlacementRequestQueue",
        queue_name=f"{_cluster_id}-placement-request.fifo",
        fifo=True,
        content_based_deduplication=True,
        retention_period=Duration.hours(1),
        visibility_timeout=Duration.seconds(360),
        encryption=sqs.QueueEncryption.SQS_MANAGED,
        enforce_ssl=True,
        dead_letter_queue=sqs.DeadLetterQueue(
            queue=_placement_req_dlq, max_receive_count=5
        ),
    )
    scope.soca_resources["placement_request_queue"] = _placement_request_queue

    _placement_res_dlq = sqs.Queue(
        scope,
        "DcvPlacementResultDlq",
        queue_name=f"{_cluster_id}-placement-result-dlq.fifo",
        fifo=True,
        content_based_deduplication=True,
        retention_period=Duration.days(14),
        encryption=sqs.QueueEncryption.SQS_MANAGED,
        enforce_ssl=True,
    )
    _placement_result_queue = sqs.Queue(
        scope,
        "DcvPlacementResultQueue",
        queue_name=f"{_cluster_id}-placement-result.fifo",
        fifo=True,
        content_based_deduplication=True,
        retention_period=Duration.hours(1),
        visibility_timeout=Duration.seconds(360),
        encryption=sqs.QueueEncryption.SQS_MANAGED,
        enforce_ssl=True,
        dead_letter_queue=sqs.DeadLetterQueue(
            queue=_placement_res_dlq, max_receive_count=5
        ),
    )
    scope.soca_resources["placement_result_queue"] = _placement_result_queue

    # --- Async Placement Lambdas: IAM roles ---
    # DcvPlacement: probes subnets, creates ODCR, emits to result queue
    _placement_role = iam.Role(
        scope,
        "DcvPlacementRole",
        role_name=f"{_cluster_id}-DcvPlacementRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        ],
    )
    _placement_role.attach_inline_policy(iam.Policy(
        scope, "DcvPlacementPolicy", statements=[
            iam.PolicyStatement(
                sid="EC2CapacityReservation",
                actions=[
                    "ec2:CreateCapacityReservation",
                    "ec2:CancelCapacityReservation",
                    "ec2:DescribeCapacityReservations",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeAvailabilityZones",
                    "ec2:DescribeImages",
                    "ec2:CreateTags",
                ],
                resources=["*"],
            ),
            iam.PolicyStatement(
                sid="SQSSendResult",
                actions=["sqs:SendMessage"],
                resources=[_placement_result_queue.queue_arn],
            ),
            iam.PolicyStatement(
                sid="SQSReceiveRequest",
                actions=["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                resources=[_placement_request_queue.queue_arn],
            ),
        ],
    ))
    scope.soca_resources["dcv_placement_role"] = _placement_role

    # CapacityExecutor: reads result queue, fetches context from DDB,
    # calls CreateStack with SNS notifications.
    _executor_role = iam.Role(
        scope,
        "CapacityExecutorRole",
        role_name=f"{_cluster_id}-CapacityExecutorRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        ],
    )
    _executor_role.attach_inline_policy(iam.Policy(
        scope, "CapacityExecutorPolicy", statements=[
            iam.PolicyStatement(
                sid="SQSReceiveResult",
                actions=["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                resources=[_placement_result_queue.queue_arn],
            ),
            iam.PolicyStatement(
                sid="SecretsManagerRelayKey",
                actions=["secretsmanager:GetSecretValue"],
                resources=[scope.soca_resources["dcv_event_relay_secret"].secret_arn],
            ),
            iam.PolicyStatement(
                sid="DDBReadContext",
                actions=["dynamodb:GetItem", "dynamodb:PutItem"],
                resources=[_notif_table.table_arn],
            ),
            iam.PolicyStatement(
                sid="CFNCreateStack",
                actions=[
                    "cloudformation:CreateStack",
                    "cloudformation:DescribeStacks",
                ],
                resources=[f"arn:{Aws.PARTITION}:cloudformation:{scope.region}:{scope.account}:stack/{_cluster_id}-*"],
            ),
            iam.PolicyStatement(
                sid="EC2ForCFN",
                actions=[
                    "ec2:CreateLaunchTemplate",
                    "ec2:DeleteLaunchTemplate",
                    "ec2:RunInstances",
                    "ec2:CreateTags",
                    "ec2:DescribeInstances",
                    "ec2:DescribeImages",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeLaunchTemplates",
                    "ec2:DescribeLaunchTemplateVersions",
                ],
                resources=["*"],
            ),
            iam.PolicyStatement(
                sid="IAMPassRole",
                actions=["iam:PassRole", "iam:GetRole"],
                resources=[f"arn:{Aws.PARTITION}:iam::{scope.account}:role/{_cluster_id}-*"],
            ),
            iam.PolicyStatement(
                sid="SNSPublish",
                actions=["sns:Publish"],
                resources=[f"arn:{Aws.PARTITION}:sns:{scope.region}:{scope.account}:{_cluster_id}-*"],
            ),
            iam.PolicyStatement(
                sid="LambdaInvoke",
                actions=["lambda:InvokeFunction"],
                resources=[f"arn:{Aws.PARTITION}:lambda:{scope.region}:{scope.account}:function:{_cluster_id}-*"],
            ),
            iam.PolicyStatement(
                sid="S3Bootstrap",
                actions=["s3:GetObject", "s3:GetBucketLocation"],
                resources=[
                    f"arn:{Aws.PARTITION}:s3:::{user_specified_variables.bucket}",
                    f"arn:{Aws.PARTITION}:s3:::{user_specified_variables.bucket}/*",
                ],
            ),
        ],
    ))
    scope.soca_resources["capacity_executor_role"] = _executor_role

    # --- Async Placement Lambdas: functions + SQS event sources ---
    # DcvPlacement probes capacity in parallel + reserves a real ODCR.
    # Calls only public AWS APIs (EC2, SQS) so it does NOT need VPC
    # attachment. FIFO event source with batch_size=1 preserves
    # per-session ordering; the handler never raises (emits
    # placement_failed on error), so no batch-item-failure reporting.
    _placement_lambda = aws_lambda.Function(
        scope,
        f"{_cluster_id}-DcvPlacement",
        function_name=f"{_cluster_id}-DcvPlacement",
        description="Async VDI placement: probe subnets in parallel, reserve a real ODCR, emit result",
        memory_size=256,
        runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        timeout=Duration.seconds(60),
        log_group=scope.generate_log_group(name="DcvPlacementLambda"),
        role=_placement_role,
        handler="DcvPlacement.lambda_handler",
        code=aws_lambda.Code.from_asset("../functions/DcvPlacement"),
        layers=[_l for _l in [scope.soca_resources.get("boto3_layer")] if _l] or None,
        environment={
            "EDH_CLUSTER_ID": _cluster_id,
            "EDH_PLACEMENT_RESULT_QUEUE_URL": _placement_result_queue.queue_url,
        },
        retry_attempts=0,
    )
    _placement_lambda.add_event_source(
        lambda_event_sources.SqsEventSource(
            _placement_request_queue, batch_size=1
        )
    )
    scope.soca_resources["dcv_placement_lambda"] = _placement_lambda

    # CapacityExecutor reads the placement result, fetches the parked
    # launch context from DDB, CreateStacks with the Lambda-probed
    # SubnetId + CapacityReservationId as CFN parameters, then POSTs a
    # 'placed' event to the controller (HMAC-signed with the shared
    # relay key) to flip placing->pending. VPC-attached + reusing the
    # DcvEventRelay SG (which already has controller :8443 egress/ingress)
    # since it makes the same RFC1918 controller hop.
    _executor_lambda = aws_lambda.Function(
        scope,
        f"{_cluster_id}-CapacityExecutor",
        function_name=f"{_cluster_id}-CapacityExecutor",
        description="Async VDI placement: CreateStack with probed subnet+ODCR, POST placed event to controller",
        memory_size=256,
        runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        timeout=Duration.seconds(60),
        log_group=scope.generate_log_group(name="CapacityExecutorLambda"),
        role=_executor_role,
        handler="CapacityExecutor.handler",
        code=aws_lambda.Code.from_asset("../functions/CapacityExecutor"),
        layers=[_l for _l in [scope.soca_resources.get("boto3_layer")] if _l] or None,
        environment={
            "EDH_CLUSTER_ID": _cluster_id,
            "CONTROLLER_API_URL": f"https://{scope.soca_resources['controller_instance'].attr_private_ip}:8443",
            "NOTIFICATIONS_TABLE": _notif_table.table_name,
            "RELAY_SECRET_ID": scope.soca_resources["dcv_event_relay_secret"].secret_arn,
        },
        retry_attempts=0,
        vpc=scope.soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[scope.soca_resources["dcv_event_relay_lambda_sg"]],
    )
    _executor_lambda.add_event_source(
        lambda_event_sources.SqsEventSource(
            _placement_result_queue, batch_size=1
        )
    )
    scope.soca_resources["capacity_executor_lambda"] = _executor_lambda

    # Controller enqueues placement requests (create_virtual_desktop ->
    # async_placement.enqueue_placement). Scoped send-only on the request
    # queue.
    _placement_request_queue.grant_send_messages(
        scope.soca_resources["controller_role"]
    )

    # SocaConfig SSM: controller reads this to find the request queue.
    ssm.StringParameter(
        scope,
        "DcvPlacementRequestQueueUrlParam",
        parameter_name=f"/edh/{_cluster_id}/configuration/PlacementRequestQueueUrl",
        string_value=_placement_request_queue.queue_url,
        description="SQS FIFO queue URL the controller enqueues async VDI placement requests to",
    )

    logger.debug("Async placement queues, Lambdas, and IAM roles configured")
