# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import logging
import boto3
from botocore.exceptions import ClientError

logging.getLogger().setLevel(logging.INFO)

"""
This function deletes orphaned EC2 Placement Groups requested via SOCA.
This function is managed by AWS StepFunction:
  - Triggered via EventBridge on CloudFormation stack state change
  - Also triggered via scheduled execution to clean orphaned Placement Groups
"""

ec2_client = boto3.client("ec2")
cfn_client = boto3.client("cloudformation")


class CleanupFailed(Exception):
    pass


def delete_placement_group(pg_name: str) -> bool:
    try:
        logging.info(f"Deleting Placement Group {pg_name}")
        ec2_client.delete_placement_group(GroupName=pg_name)
        logging.info(f"Placement Group {pg_name} deleted successfully.")
    except ClientError as e:
        _error_code = e.response["Error"]["Code"]
        if _error_code == "InvalidPlacementGroup.NotFound":
            logging.info(f"Placement Group {pg_name} not found, ignoring ...")
        elif _error_code == "InvalidPlacementGroup.InUse":
            logging.info(
                f"{pg_name} is still being used, SOCA will try again to remove it during the next cycle."
            )
        else:
            logging.fatal(f"Unable to delete placement group: {e}")
            return False

    return True


def clean_pg_assigned_to_stack(stack_name: str) -> bool:
    _success = True
    try:
        logging.info(
            f"Cleaning Placement Groups associated to tag:edh:AssociatedStackId = {stack_name}..."
        )

        response = ec2_client.describe_placement_groups(
            Filters=[
                {
                    "Name": "tag:edh:AssociatedStackId",
                    "Values": [stack_name],
                }
            ]
        )

        pgs = response.get("PlacementGroups", [])
        logging.info(
            f"Found {len(pgs)} Placement Groups with tag:edh:AssociatedStackId = {stack_name}"
        )
        for pg in pgs:
            pg_name = pg.get("GroupName")
            logging.info(f"Processing Placement Group {pg_name}")
            if not delete_placement_group(pg_name=pg_name):
                _success = False

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logging.fatal(
            f"Unable to delete Placement Group {stack_name}: {e}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
        )
        _success = False

    return _success


def clean_orphaned_pg_on_schedule() -> bool:
    _success = True
    try:
        _cluster_id = os.environ.get("EDH_CLUSTER_ID", None)
        if not _cluster_id:
            logging.fatal(
                "EDH_CLUSTER_ID is not defined, unable to proceed. Verify your configuration."
            )
            return False

        logging.info(f"Retrieving all Placement Groups for {_cluster_id}")
        response = ec2_client.describe_placement_groups(
            Filters=[
                {
                    "Name": "tag:edh:ClusterId",
                    "Values": [_cluster_id],
                }
            ]
        )

        pgs = response.get("PlacementGroups", [])

        logging.info(f"Found {len(pgs)} Placement Groups for {_cluster_id}")
        for pg in pgs:
            pg_name = pg.get("GroupName")
            tags = pg.get("Tags", [])

            _found_associated_stack_id = next(
                (
                    tag["Value"]
                    for tag in tags
                    if tag["Key"] == "edh:AssociatedStackId"
                ),
                None,
            )

            if not _found_associated_stack_id:
                logging.info(
                    f"Placement Group {pg_name} does NOT have tag 'edh:AssociatedStackId', skipping"
                )
                continue

            logging.info(
                f"Placement Group {pg_name} associated with stack {_found_associated_stack_id}"
            )

            try:
                stack = cfn_client.describe_stacks(StackName=_found_associated_stack_id)
                stack_status = stack["Stacks"][0]["StackStatus"]
                logging.debug(f"Stack status: {stack_status}")

                if stack_status in ["CREATE_COMPLETE", "CREATE_IN_PROGRESS"]:
                    logging.info(
                        "Associated CloudFormation stack is an active stack, skipping ..."
                    )
                    continue
                else:
                    logging.info(
                        f"Associated stack is not active ({stack_status}), deleting Placement Group"
                    )
                    if not delete_placement_group(pg_name=pg_name):
                        _success = False

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if (
                    error_code == "ValidationError"
                    and "does not exist" in e.response["Error"]["Message"]
                ):
                    logging.info(
                        f"Associated stack {_found_associated_stack_id} does not exist, deleting Placement Group {pg_name}"
                    )
                    if not delete_placement_group(pg_name=pg_name):
                        _success = False
                else:
                    logging.fatal(f"Error checking stack: {e}")
                    _success = False  # do not raise an error here
                    continue

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logging.fatal(f"Error: {e}, {exc_type}, {fname}, {exc_tb.tb_lineno}")
        _success = False

    return _success


def lambda_handler(event, context):
    _stack_id = event.get(
        "stack_id", None
    )  # EventBridge return the entire ARN e.g: arn:aws:cloudformation:us-west-1:123456789012:stack/stack_name/stack_uuid
    if _stack_id:
        _stack_name = _stack_id.split("/")[-2]  # get stack_name, not stack_uuid
        logging.info(f"Stack name is {_stack_name}")
    else:
        _stack_name = None

    _status = event.get("status", None)
    logging.info(f"Received event Stack name: {_stack_name}, Status: {_status}")

    if _status in ["CREATE_COMPLETE", "CREATE_IN_PROGRESS"]:
        # EventBridge EventPattern  does not include CREATE_COMPLETE / CREATE_IN_PROGRESS.
        logging.info(
            "CloudFormation stack is in active state, skipping Placement Group cleanup ..."
        )
    else:
        if _stack_name:
            logging.info(
                f"Triggered from EventBridge, cleaning Placement Groups for stack {_stack_name}"
            )
            if not clean_pg_assigned_to_stack(stack_name=_stack_name):
                raise CleanupFailed(
                    "Un-recoverable errors detected during clean_pg_assigned_to_stack"
                )
        else:
            logging.info("Triggered from schedule, cleaning orphaned Placement Groups")
            if not clean_orphaned_pg_on_schedule():
                raise CleanupFailed(
                    "Un-recoverable errors detected during clean_orphaned_pg_on_schedule"
                )

    logging.info("Lambda execution complete")
