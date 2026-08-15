# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
AsgCapacityBumper — Custom Resource Lambda that bumps an ASG's MinSize and
DesiredCapacity to target values once the cdk_completed sentinel has been
written.

Used to keep ASG-backed services (e.g. DCV broker, DCV gateway) at
desired=0 during initial stack create, so their instances launch only
after the SSM parameter tree is fully populated. Cleaner ops logs:
no SSM-poll-loop "WARNING ParameterNotFound" noise during normal
bootstrap.

Lifecycle:
    Create  - update_auto_scaling_group(MinSize, DesiredCapacity) to targets
    Update  - no-op. Operator may have manually scaled the ASG; do not override.
    Delete  - no-op. CFN tears down the ASG itself.

Idempotency: Create is safe to retry on the same ASG; AWS treats
identical UpdateAutoScalingGroup calls as no-ops.

Failure mode: if the bump fails on Create, this Lambda signals FAILED
back to CloudFormation, the stack rolls back, and the ASG stays at
min=0/desired=0 — no half-bootstrapped instances to triage.
"""

from __future__ import annotations

import logging
import os

import boto3
import cfnresponse


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    request_type = event.get("RequestType", "")
    props = event.get("ResourceProperties", {}) or {}
    asg_name = props.get("AsgName") or ""

    # Stable PhysicalResourceId — ties the CR's identity to the ASG it bumps,
    # so an ASG rename in a future template change creates a fresh CR rather
    # than mutating an existing one.
    physical_id = f"AsgCapacityBumper-{asg_name}" if asg_name else None

    response_data = {
        "AsgName": asg_name,
        "RequestType": request_type,
    }

    try:
        target_min = int(props.get("TargetMin", "0"))
        target_desired = int(props.get("TargetDesired", "0"))

        if request_type == "Create":
            if not asg_name:
                raise ValueError("AsgName property is required on Create")

            logger.info(
                f"Bumping ASG {asg_name} to MinSize={target_min}, "
                f"DesiredCapacity={target_desired}"
            )

            client = boto3.client(
                "autoscaling",
                region_name=os.environ.get("AWS_REGION"),
            )
            client.update_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                MinSize=target_min,
                DesiredCapacity=target_desired,
            )
            response_data["Action"] = "BumpedCapacity"
            response_data["MinSize"] = target_min
            response_data["DesiredCapacity"] = target_desired

        elif request_type in ("Update", "Delete"):
            # No-op:
            # - Update: operator may have scaled the ASG manually post-deploy;
            #   stack updates should preserve their changes, not clobber.
            # - Delete: CFN handles the ASG teardown; we have nothing to do.
            logger.info(
                f"{request_type} on AsgCapacityBumper for {asg_name}: no-op"
            )
            response_data["Action"] = "NoOp"

        else:
            raise ValueError(f"Unsupported RequestType: {request_type}")

        cfnresponse.send(
            event,
            context,
            cfnresponse.SUCCESS,
            response_data,
            physicalResourceId=physical_id,
        )

    except Exception as exc:  # pylint: disable=broad-except
        logger.exception(f"AsgCapacityBumper failed: {exc}")
        response_data["Reason"] = str(exc)
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED,
            response_data,
            physicalResourceId=physical_id,
            reason=str(exc),
        )
