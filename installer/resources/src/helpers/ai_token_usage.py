# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
AI Token Daily Usage -- CDK helper for the DynamoDB table that tracks
per-user daily token consumption for rate limiting.

Provisions:
  * {cluster}-Ai-Token-Daily-Usage
        pk = username (S), sk = date (S, YYYY-MM-DD)
        Attributes: total_tokens (N)
        TTL on `expires_at` to auto-purge old records after 90 days.
"""

import logging

from aws_cdk import RemovalPolicy
from aws_cdk import aws_dynamodb as dynamodb

logger = logging.getLogger("soca_logger")


def setup(scope, soca_resources: dict, user_specified_variables):
    """Provision the AI token usage DynamoDB table."""
    _cluster_id = user_specified_variables.cluster_id

    table = dynamodb.Table(
        scope,
        "AiTokenDailyUsageTable",
        table_name=f"{_cluster_id}-ai-assistant.token-daily-usage",
        partition_key=dynamodb.Attribute(
            name="username", type=dynamodb.AttributeType.STRING
        ),
        sort_key=dynamodb.Attribute(name="date", type=dynamodb.AttributeType.STRING),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        time_to_live_attribute="expires_at",
        removal_policy=RemovalPolicy.DESTROY,
        point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
            point_in_time_recovery_enabled=False
        ),
    )

    soca_resources["ai_token_usage_table"] = table
    return table
