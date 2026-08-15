#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    aws_events as events,
    aws_backup as backup,
    aws_kms as kms,
)


import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# AWS Backup vault + plan provisioning. Extracted verbatim from cdk_construct.py.

logger = logging.getLogger("soca_logger")


def backups(
    scope,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    is_valid_backup_vault_arn=None,
):
    """
    Deploy AWS Backup vault. Controller EC2 instance and both EFS will be backup on a daily basis
    """
    logger.debug("Creating AWS Backup vault")
    _kms_key_id = get_kms_key_id(
        config_key_names=[
            "Config.services.aws_backup.kms_key_id",  # Current configuration parameter
        ],
        allow_global_default=True,
    )

    vault = backup.BackupVault(
        scope,
        "SOCABackupVault",
        backup_vault_name=f"{user_specified_variables.cluster_id}-BackupVault",
        removal_policy=RemovalPolicy.DESTROY,
        encryption_key=(
            kms.Key.from_key_arn(scope, id="BackupVaultKMSKey", key_arn=_kms_key_id)
            if _kms_key_id
            else None
        ),
    )  # removal policy won't apply if backup vault is not empty

    # Any additional copy destinations needed?
    _backup_copy_destinations: list = get_config_key(
        key_name="Config.services.aws_backup.additional_copy_destinations",
        expected_type=list,
        required=False,
        default=[],
    )

    _backup_copy_actions: list = []
    _seen_destinations: set = set()

    if _backup_copy_destinations:

        for _bu_destination in _backup_copy_destinations:
            if not is_valid_backup_vault_arn(arn=_bu_destination):
                logger.warning(
                    f"Invalid ARN for backup destination: {_bu_destination} (SKIPPING)"
                )
                continue

            if _bu_destination in _seen_destinations:
                logger.error(
                    f"Duplicate backup destination: {_bu_destination} . SKIPPING"
                )
                continue
            _seen_destinations.add(_bu_destination)

            # It looks like a proper ARN - resolve it
            logger.debug(f"Adding a new discrete backup dest: {_bu_destination}")
            _bu_vault = backup.BackupVault.from_backup_vault_arn(
                scope, f"BackupVault{_bu_destination}", _bu_destination
            )

            if _bu_vault:
                logger.debug(f"Vault copy being added - {_bu_destination}")
                # Looks unique - add it
                _backup_copy_actions.append(
                    backup.BackupPlanCopyActionProps(
                        destination_backup_vault=_bu_vault,
                    )
                )

            else:
                logger.error(
                    f"Unable to find backup vault for {_bu_destination} . SKIPPING"
                )
                continue

    plan = backup.BackupPlan(
        scope,
        "SOCABackupPlan",
        backup_plan_name=f"{user_specified_variables.cluster_id}-BackupPlan",
        backup_plan_rules=[
            backup.BackupPlanRule(
                backup_vault=vault,
                start_window=Duration.minutes(60),
                delete_after=Duration.days(
                    get_config_key(
                        key_name="Config.services.aws_backup.delete_after",
                        expected_type=int,
                        required=False,
                        default=7,
                    )
                ),
                schedule_expression=events.Schedule.expression("cron(0 5 * * ? *)"),
                copy_actions=_backup_copy_actions if _backup_copy_actions else None,
            )
        ],
    )
    # Backup EFS/EC2 resources with special tag: edh:BackupPlan, value: Current Cluster ID
    backup_selection = backup.BackupSelection(
        scope,
        "SOCABackupSelection",
        backup_plan=plan,
        role=scope.soca_resources["backup_role"],
        backup_selection_name=f"{user_specified_variables.cluster_id}-BackupSelection",
        resources=[
            backup.BackupResource(
                tag_condition=backup.TagCondition(
                    key="edh:BackupPlan",
                    value=user_specified_variables.cluster_id,
                    operation=backup.TagOperation.STRING_EQUALS,
                )
            )
        ],
    )
    # Depend on the backup role's inline policy so IAM propagates the role trust before AWS Backup validates AssumeRole (avoids intermittent "cannot be assumed")
    _backup_policy = scope.soca_resources.get("backup_policy")
    if _backup_policy is not None:
        backup_selection.node.add_dependency(_backup_policy)
