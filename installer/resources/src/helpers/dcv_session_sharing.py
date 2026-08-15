# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DCV Session Sharing -- CDK helper for DDB tables, expiry Lambda, and SSM config.

Provisions:
  * {cluster}-dcv-session-sharing-profiles  -- Admin-defined permission profile templates
        pk = profile_id (ULID), sk = "PROFILE"
  * {cluster}-dcv-session-sharing-grants    -- Per-session guest grants with expiry
        pk = grant_id (ULID), sk = "GRANT"
        GSI session-index: session_id + created_at (list grants per session)
        GSI guest-index:   guest_username + created_at (list "shared to me" tiles)
        GSI expiry-index:  status + expires_at (expiry Lambda scan; INCLUDE
                           session_id, owner_username)
  * Expiry Lambda -- fires every 15 min, revokes expired grants via broker API
  * SSM params   -- feature flag + allowed_sharing_modes

Entry point:
  * setup() -- called from SOCAInstall.session_sharing() wrapper.

Depends on: DCV High Scale (broker must be deployed).
"""

import json
import logging

from aws_cdk import Aws, Duration, RemovalPolicy
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as aws_lambda
from aws_cdk import aws_logs as logs
from aws_cdk import aws_ssm as ssm

logger = logging.getLogger("soca_logger")


def _sharing_table(scope, construct_id, table_name, *, gsis=None, ttl_attribute=None):
    """Create a sharing DDB table with EDH-standard settings."""
    table = dynamodb.Table(
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
    if gsis:
        for gsi in gsis:
            table.add_global_secondary_index(**gsi)
    return table


def setup(
    scope,
    soca_resources: dict,
    user_specified_variables,
    lambda_runtime,
    get_config_key,
):
    """Provision session sharing infrastructure (DDB tables + expiry Lambda)."""
    _cluster_id = user_specified_variables.cluster_id

    # --- DDB: Profiles table ---
    _profiles_table = _sharing_table(
        scope,
        "DcvSessionSharingProfilesTable",
        f"{_cluster_id}-dcv-session-sharing-profiles",
    )

    # --- DDB: Grants table with GSIs ---
    _grants_table = _sharing_table(
        scope,
        "DcvSessionSharingGrantsTable",
        f"{_cluster_id}-dcv-session-sharing-grants",
        ttl_attribute="ttl_expire",
        gsis=[
            {
                "index_name": "session-index",
                "partition_key": dynamodb.Attribute(
                    name="session_id", type=dynamodb.AttributeType.STRING
                ),
                "sort_key": dynamodb.Attribute(
                    name="created_at", type=dynamodb.AttributeType.STRING
                ),
                "projection_type": dynamodb.ProjectionType.ALL,
            },
            {
                "index_name": "guest-index",
                "partition_key": dynamodb.Attribute(
                    name="guest_username", type=dynamodb.AttributeType.STRING
                ),
                "sort_key": dynamodb.Attribute(
                    name="created_at", type=dynamodb.AttributeType.STRING
                ),
                "projection_type": dynamodb.ProjectionType.ALL,
            },
            {
                "index_name": "expiry-index",
                "partition_key": dynamodb.Attribute(
                    name="status", type=dynamodb.AttributeType.STRING
                ),
                "sort_key": dynamodb.Attribute(
                    name="expires_at", type=dynamodb.AttributeType.STRING
                ),
                # INCLUDE (not KEYS_ONLY): the expiry Lambda needs session_id +
                # owner_username from the index hit to rebuild each session .perm.
                "projection_type": dynamodb.ProjectionType.INCLUDE,
                "non_key_attributes": ["session_id", "owner_username"],
            },
        ],
    )

    # NOTE: the controller's DynamoDB access is granted cluster-wide
    # (edh-<cluster_id>-*) at the controller-role creation in helpers/iam.py,
    # so the sharing tables need no per-table controller grant here. The
    # expiry Lambda below stays per-table scoped (least privilege).

    # --- Expiry Lambda ---
    _lambda_role = iam.Role(
        scope,
        "DcvSessionSharingExpiryLambdaRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            ),
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
    )
    _grants_table.grant_read_write_data(_lambda_role)

    _expiry_lambda = aws_lambda.Function(
        scope,
        "DcvSessionSharingExpiryLambda",
        function_name=f"{_cluster_id}-DcvSessionSharingExpiry",
        runtime=lambda_runtime,
        handler="DcvSessionSharingExpiry.handler",
        code=aws_lambda.Code.from_asset("../functions/DcvSessionSharingExpiry"),
        layers=[_l for _l in [soca_resources.get("boto3_layer")] if _l] or None,
        role=_lambda_role,
        timeout=Duration.seconds(60),
        memory_size=256,
        log_group=scope.generate_log_group(name="DcvSessionSharingExpiryLambda"),
        environment={
            "CLUSTER_ID": _cluster_id,
            "GRANTS_TABLE": _grants_table.table_name,
            "BROKER_ENDPOINT": f"/edh/{_cluster_id}/dcv/backend_nlb_dns",
            "BROKER_PORT": f"/edh/{_cluster_id}/dcv/broker/client_port",
        },
        # The broker backend NLB is internal (private subnets), so the Lambda
        # must run in-VPC. Reuse the screenshot-poller SG, which dcv_backend_nlb_sg
        # already allows on TCP/8443 (see cluster_security_groups.py).
        vpc=soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[soca_resources["dcv_screenshot_lambda_sg"]],
    )

    _expiry_lambda.add_to_role_policy(
        iam.PolicyStatement(
            # The Lambda reads both keys via ssm.get_parameters (batch API),
            # which requires ssm:GetParameters (plural). Scope ARNs to this
            # partition/region/account, matching the controller role in iam.py.
            actions=["ssm:GetParameters"],
            resources=[
                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/edh/{_cluster_id}/dcv/backend_nlb_dns",
                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/edh/{_cluster_id}/dcv/broker/client_port",
            ],
        )
    )

    # EventBridge rule: fire at :00, :15, :30, :45
    _rule = events.Rule(
        scope,
        "DcvSessionSharingExpirySchedule",
        rule_name=f"{_cluster_id}-DcvSessionSharingExpirySchedule",
        schedule=events.Schedule.cron(minute="0/15"),
    )
    _rule.add_target(events_targets.LambdaFunction(_expiry_lambda))

    # Runtime SSM keys (controller reads these). Per the EDH two-layer
    # feature-flag convention: Config.dcv.session_sharing.enabled
    # gates construct deployment (CDK-time); these
    # /configuration/dcv/session_sharing/... SSM keys gate the controller
    # code paths (runtime).
    _allowed_modes = get_config_key(
        key_name="Config.dcv.session_sharing.allowed_sharing_modes",
        expected_type=list,
        default=["none", "secure"],
        required=False,
    )
    _allow_unsupervised = get_config_key(
        key_name="Config.dcv.session_sharing.allow_unsupervised_access",
        expected_type=bool,
        default=True,
        required=False,
    )
    _ssm_prefix = f"/edh/{_cluster_id}/configuration/dcv/session_sharing"
    ssm.StringParameter(
        scope,
        "DcvSessionSharingEnabledParam",
        parameter_name=f"{_ssm_prefix}/enabled",
        string_value="true",
    )
    ssm.StringParameter(
        scope,
        "DcvSessionSharingAllowedModesParam",
        parameter_name=f"{_ssm_prefix}/allowed_sharing_modes",
        string_value=json.dumps(_allowed_modes),
    )
    ssm.StringParameter(
        scope,
        "DcvSessionSharingAllowUnsupervisedParam",
        parameter_name=f"{_ssm_prefix}/allow_unsupervised_access",
        string_value="true" if _allow_unsupervised else "false",
    )

    # Store references for other constructs
    soca_resources["dcv_session_sharing_profiles_table"] = _profiles_table
    soca_resources["dcv_session_sharing_grants_table"] = _grants_table
    soca_resources["dcv_session_sharing_expiry_lambda"] = _expiry_lambda

    logger.info(
        f"Session sharing infrastructure provisioned: "
        f"{_profiles_table.node.id}, {_grants_table.node.id}, "
        f"{_expiry_lambda.node.id}"
    )
