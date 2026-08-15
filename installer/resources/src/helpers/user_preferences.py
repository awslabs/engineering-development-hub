# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
User Preferences -- CDK helper for the generic WebUI user-preferences store.

Provisions:
  * {cluster}-user-preferences  -- one row per user, PK = username.
        Each preference is a TOP-LEVEL attribute (variant-2 sparse rows);
        no sort key. Read once at login, written on change. See
        docs/UserPreferences-Design.md and utils/user_pref_store.py.

No SSM seed: v1's only admin-default tier (vdi_tile_masking) reuses the existing
DCV screenshot privacy-mode knob (/dcv/screenshot/privacy_mode); a future pref
needing its own org default would seed it under
/configuration/user_preferences/defaults/<key>.

Entry point:
  * setup() -- called from SOCAInstall.user_preferences() wrapper.

IAM: the controller's DynamoDB access is granted cluster-wide
({cluster_id}-*) at controller-role creation in helpers/iam.py, so this table
needs no per-table grant here (mirrors the dcv_session_sharing note). No
Lambda, no GSI, no TTL (cleanup is the user-delete hook + reconciliation
sweep, not a timer).

At-rest encryption uses the DynamoDB default (AWS-owned key), matching every
other EDH table (notifications, vdi-launch-history, session-sharing). The data
is username + cosmetic display preferences (e.g. language, a client-honored
masking bool).
"""

import logging

from aws_cdk import RemovalPolicy
from aws_cdk import aws_dynamodb as dynamodb

logger = logging.getLogger("soca_logger")


def setup(scope, *, user_specified_variables=None):
    """Provision the user-preferences DDB table + SSM org-default seed keys."""
    _cluster_id = user_specified_variables.cluster_id

    # --- DDB: user preferences table (one row/user, sparse top-level attrs) ---
    _table = dynamodb.Table(
        scope,
        "UserPreferencesTable",
        table_name=f"{_cluster_id}-user-preferences",
        partition_key=dynamodb.Attribute(
            name="username", type=dynamodb.AttributeType.STRING
        ),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        removal_policy=RemovalPolicy.DESTROY,
        point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
            point_in_time_recovery_enabled=False
        ),
    )
    scope.soca_resources["user_preferences_table"] = _table

    # No SSM seed here. The only v1 admin-default tier (vdi_tile_masking) reuses
    # the existing DCV screenshot privacy-mode knob (/dcv/screenshot/privacy_mode),
    # owned by the DCV screenshot feature -- we don't duplicate or re-seed it.
    # A future pref needing its own org default would seed it under
    # /configuration/user_preferences/defaults/<key> here.

    logger.debug(
        f"User preferences table configured: {_table.table_name}"
    )
    return _table
