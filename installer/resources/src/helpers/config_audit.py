# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Configuration Editor audit trail -- CDK helper for the append-only DDB table.

Provisions:
  * {cluster}-config-audit  -- one immutable row per applied config change
        pk = "{cluster_id}#{param_key}"   sk = ISO-8601 timestamp
        GSI activity-index:
            gsi_pk = "{cluster_id}#{YYYY-MM-DD}"   gsi_sk = ISO-8601 timestamp
        (powers the cluster-wide "Recent changes" feed)

The controller role already has cluster-wide (edh-<cluster_id>-*) DynamoDB
access via helpers/iam.py, so no per-table grant is needed here. The web tier
reads/writes this table through web_interface/helpers/config_audit_store.py.

Entry point: setup() -- called unconditionally from SOCAInstall. The
Configuration Editor is an always-on admin surface (admin-gated, no feature
flag), so its audit table is always provisioned.
"""

import logging

from aws_cdk import RemovalPolicy
from aws_cdk import aws_dynamodb as dynamodb

logger = logging.getLogger("soca_logger")


def setup(scope, user_specified_variables):
    """Provision the Configuration Editor audit trail DDB table + activity GSI."""
    _cluster_id = user_specified_variables.cluster_id

    _table = dynamodb.Table(
        scope,
        "ConfigEditorAuditTable",
        table_name=f"{_cluster_id}-config-audit",
        partition_key=dynamodb.Attribute(
            name="pk", type=dynamodb.AttributeType.STRING
        ),
        sort_key=dynamodb.Attribute(
            name="sk", type=dynamodb.AttributeType.STRING
        ),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        removal_policy=RemovalPolicy.DESTROY,
        point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
            point_in_time_recovery_enabled=False
        ),
    )

    _table.add_global_secondary_index(
        index_name="activity-index",
        partition_key=dynamodb.Attribute(
            name="gsi_pk", type=dynamodb.AttributeType.STRING
        ),
        sort_key=dynamodb.Attribute(
            name="gsi_sk", type=dynamodb.AttributeType.STRING
        ),
        projection_type=dynamodb.ProjectionType.ALL,
    )

    try:
        scope.soca_resources["config_editor_audit_table"] = _table
    except Exception:
        pass

    logger.info(f"Config Editor audit table provisioned: {_table.node.id}")
    return _table
