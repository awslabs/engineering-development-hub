# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Async placement enqueue helper (Step 2 of the serverless placement pipeline).

Called by create_virtual_desktop.py when the async_placement feature flag is
enabled. Instead of probing ODCR inline (2.3s) and calling CreateStack, this:
  1. Parks the full launch context (template, tags, params) on the session row
  2. Writes the session to the DB with state=placing
  3. Enqueues a lightweight SQS message to the PLACEMENT_REQUEST_QUEUE
  4. Returns immediately (~50ms total)

The DcvPlacement Lambda (Step 1) picks up the SQS message, probes capacity
in parallel across subnets, creates a real ODCR with a short window, and
emits the result to PLACEMENT_RESULT_QUEUE.

The CapacityExecutor Lambda (Step 3) reads the result, fetches placement_context
from the DB row, and calls CreateStack.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone

from models import db, VirtualDesktopSessions
from utils.aws import boto3_wrapper as utils_boto3
from utils.aws.ec2_helper import describe_images
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

_CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")


def enqueue_placement(
    session_uuid: str,
    stack_name: str,
    template_body: str,
    cfn_tags: list,
    cfn_notification_arns: list,
    instance_type: str,
    ami_id: str,
    subnet_ids: list,
    tenancy: str,
    session_row: VirtualDesktopSessions,
    instance_platform: str = "",
    capacity_reservation_id: str = "",
    spot: bool = False,
) -> SocaResponse:
    """
    Park launch context on the session row + enqueue SQS placement request.

    Returns SocaResponse(success=True) or SocaError on failure -- intentionally
    WITHOUT .as_flask(). This is a utility helper, not a route handler; the
    caller in create_virtual_desktop.py inspects .get("success")/.get("message")
    directly and builds its own Flask response. Calling .as_flask() here would
    turn the return into a (dict, status_code) tuple and break that caller.
    """
    # 0. Resolve instance_platform from the AMI if not explicitly provided.
    if not instance_platform:
        _img_resp = describe_images(image_ids=[ami_id])
        if _img_resp.get("success"):
            _images = _img_resp.get("message", {}).get("Images", [])
            if _images:
                instance_platform = _images[0].get("PlatformDetails", "")
        if not instance_platform:
            logger.error(
                f"async_placement: cannot resolve InstancePlatform for AMI {ami_id}"
            )
            return SocaError.GENERIC_ERROR(
                helper=f"Cannot determine InstancePlatform for AMI {ami_id}"
            )

    # 1. Park the full launch context as JSON on the session row.
    #    Only IDs travel through SQS; passwords/template stay in the DB.
    placement_ctx = {
        "stack_name": stack_name,
        "template_body": template_body,
        "cfn_tags": cfn_tags,
        "cfn_notification_arns": cfn_notification_arns,
        # Retry context for spot AZ-fallback: DcvEventRelay reads this on a
        # terminal stack failure to re-enqueue the next candidate subnet.
        "retry": {
            "instance_type": instance_type,
            "ami_id": ami_id,
            "subnet_ids": subnet_ids,
            "tenancy": tenancy or "default",
            "instance_platform": instance_platform or "",
            "spot": bool(spot),
            "attempt": 1,
        },
    }
    session_row.placement_context = json.dumps(placement_ctx)
    session_row.session_state = "placing"
    session_row.session_state_latest_change_time = datetime.now(timezone.utc)

    try:
        db.session.add(session_row)
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        logger.error(f"async_placement: DB write failed: {err}")
        return SocaError.GENERIC_ERROR(helper=f"DB error: {err}")

    # 2. Enqueue a lightweight message to the PLACEMENT_REQUEST_QUEUE.
    #    The Lambda only needs enough to probe capacity — no secrets.
    _queue_url = os.environ.get("PLACEMENT_REQUEST_QUEUE_URL", "")
    if not _queue_url:
        # Fallback: read from SSM (cold path, only on first call)
        from utils.config import SocaConfig
        _resp = SocaConfig(
            key="/configuration/PlacementRequestQueueUrl"
        ).get_value(default="", allow_unknown_key=True)
        _queue_url = _resp.message if _resp.success else ""

    if not _queue_url:
        logger.error("async_placement: PLACEMENT_REQUEST_QUEUE_URL not configured")
        return SocaError.GENERIC_ERROR(helper="Queue URL not configured")

    # Resolve the cluster's custom tags so the ODCR the DcvPlacement Lambda
    # mints carries the same custom tag set as the instance it backs. The
    # Lambda cannot read SSM, so we resolve here and pass them in the body.
    try:
        from utils.aws.odcr_helper import get_cluster_custom_tags
        _custom_tags = get_cluster_custom_tags()
    except Exception as err:
        logger.warning(
            f"async_placement: custom tag resolve failed (non-fatal): {err}"
        )
        _custom_tags = []

    msg_body = {
        "session_uuid": session_uuid,
        "instance_type": instance_type,
        "ami_id": ami_id,
        "subnet_ids": subnet_ids,
        "tenancy": tenancy or "default",
        "instance_platform": instance_platform or "",
        "cluster_id": _CLUSTER_ID,
        "custom_tags": _custom_tags,
        # Admin-supplied ODCR (empty = auto-probe). When set, DcvPlacement
        # skips capacity probing and passes this id straight through so the
        # instance lands in the admin's reservation, not a fresh per-session one.
        "capacity_reservation_id": capacity_reservation_id or "",
        "spot": bool(spot),
        "attempt": 1,
        "nonce": uuid.uuid4().hex,
    }

    try:
        sqs = utils_boto3.get_boto(service_name="sqs").message
        sqs.send_message(
            QueueUrl=_queue_url,
            MessageBody=json.dumps(msg_body),
            MessageGroupId=session_uuid,
            MessageDeduplicationId=msg_body["nonce"],
        )
    except Exception as err:
        logger.error(f"async_placement: SQS send failed: {err}")
        return SocaError.AWS_API_ERROR(
            service_name="sqs", helper=f"SQS error: {err}"
        )

    # 3. Park placement_context in DDB (so executor Lambda can read it
    #    without controller DB access). Uses the notifications table with
    #    a special scope prefix.
    try:
        from utils.dcv_event_store import _ddb, _NOTIFICATIONS_TABLE
        import time as _time
        _ddb().put_item(
            TableName=_NOTIFICATIONS_TABLE,
            Item={
                "scope": {"S": f"placement_ctx#{session_uuid}"},
                "id": {"S": "context"},
                "envelope": {"S": json.dumps(placement_ctx)},
                "ttl": {"N": str(int(_time.time()) + 3600)},  # 1h expiry
            },
        )
    except Exception as err:
        logger.warning(f"async_placement: DDB context park failed (non-fatal): {err}")

    logger.info(
        f"async_placement: enqueued placement for {session_uuid} "
        f"({instance_type}, {len(subnet_ids)} subnets)"
    )
    return SocaResponse(success=True, message="Placement enqueued")
