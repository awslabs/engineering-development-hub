# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
DCV async capacity-placement Lambda.

Moves the slow ODCR capacity probe off the create_virtual_desktop API thread
so the WebUI returns immediately (state=placing). SQS-triggered, one message
per session.

Message body (JSON) enqueued by the create handler:
    {
      "session_uuid": "<uuid>",          # broker/SOCA session id
      "instance_type": "c8i.2xlarge",
      "instance_ami":  "ami-...",
      "subnet_ids":    ["subnet-a", ...], # candidates to probe in parallel
      "tenancy":       "default",
      "nonce":         "<hex>"            # replay dedup at controller
    }

Flow per message:
    1. Probe all candidate subnets IN PARALLEL (the latency win -- the old
       inline path probed serially, ~2.3s).
    2. Pick the first subnet with capacity, reserve a REAL short-window ODCR
       there (probe_capacity_only=False). ODCRs auto-expire (small end_date
       in odcr_helper) -- no reaper needed.
    3. POST the result to the controller:
         success -> {event_type:"placement_ready", subnet_id, capacity_reservation_id}
         failure -> {event_type:"placement_failed", reason}
       The controller advances the session (PLACED -> launches CFN with the
       known-good ODCR) or marks it failed and surfaces it on the timeline.

Stdlib + boto3 only (Lambda runtime provides boto3). HMAC-signed POST mirrors
DcvEventRelay so the controller trusts the placement result.
"""

import concurrent.futures
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_PROBE_WORKERS = int(os.environ.get("EDH_PLACEMENT_MAX_WORKERS", "8"))
RESULT_QUEUE_URL = os.environ["EDH_PLACEMENT_RESULT_QUEUE_URL"]

_sqs = boto3.client("sqs")
_ec2 = boto3.client("ec2")


def _emit_result(payload):
    """Send a placement result to the result queue."""
    _sqs.send_message(
        QueueUrl=RESULT_QUEUE_URL,
        MessageBody=json.dumps(payload),
        MessageGroupId=payload["session_uuid"],
        MessageDeduplicationId=payload["nonce"],
    )


def _probe_subnet(*, instance_type, instance_ami, subnet_id, tenancy, instance_platform):
    """Probe capacity in one subnet via DryRun CreateCapacityReservation."""
    logger.info(f"Probing capacity: {instance_type} platform={instance_platform} subnet={subnet_id}")
    try:
        _ec2.create_capacity_reservation(
            InstanceType=instance_type,
            InstancePlatform=instance_platform,
            AvailabilityZoneId=_get_az_for_subnet(subnet_id),
            InstanceCount=1,
            Tenancy=tenancy if tenancy != "default" else "default",
            DryRun=True,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "DryRunOperation":
            logger.info(f"Capacity available in subnet {subnet_id}")
            return subnet_id
        logger.info(f"No capacity in subnet {subnet_id}: {e.response['Error']['Code']}")
        return None
    return subnet_id


def _get_az_for_subnet(subnet_id):
    """Resolve subnet -> AZ."""
    resp = _ec2.describe_subnets(SubnetIds=[subnet_id])
    return resp["Subnets"][0]["AvailabilityZoneId"]


def _reserve_capacity(*, instance_type, instance_ami, subnet_id, tenancy, session_uuid, instance_platform, cluster_id="", custom_tags=None):
    """Create a real short-window ODCR (5 min expiry), tagged like the instance it backs."""
    from datetime import datetime, timedelta, timezone
    logger.info(f"Reserving capacity: {instance_type} platform={instance_platform} subnet={subnet_id} session={session_uuid}")
    end_time = datetime.now(timezone.utc) + timedelta(minutes=5)
    _tags = [{"Key": "edh:SessionUuid", "Value": session_uuid}]
    if cluster_id:
        _tags.append({"Key": "edh:ClusterId", "Value": cluster_id})
        _tags.append({"Key": "Name", "Value": f"{cluster_id}-dcv-odcr-{session_uuid[:8]}"})
    if custom_tags:
        # Skip custom keys colliding with reserved tags (AWS rejects duplicate keys).
        _reserved = {t["Key"] for t in _tags}
        _tags.extend(t for t in custom_tags if t.get("Key") not in _reserved)
    resp = _ec2.create_capacity_reservation(
        InstanceType=instance_type,
        InstancePlatform=instance_platform,
        AvailabilityZoneId=_get_az_for_subnet(subnet_id),
        InstanceCount=1,
        Tenancy=tenancy if tenancy != "default" else "default",
        EndDateType="limited",
        EndDate=end_time.isoformat(),
        InstanceMatchCriteria="targeted",
        TagSpecifications=[{
            "ResourceType": "capacity-reservation",
            "Tags": _tags,
        }],
    )
    return resp["CapacityReservation"]["CapacityReservationId"]


def _resolve_instance_platform(ami_id):
    """Derive the InstancePlatform value from the AMI's PlatformDetails.

    EC2 DescribeImages returns PlatformDetails such as "Linux/UNIX",
    "Red Hat Enterprise Linux", "Windows", "Windows with SQL Server Enterprise",
    etc.  The CreateCapacityReservation InstancePlatform enum collapses these
    into a smaller set.  We map known prefixes; anything unrecognised is left
    as-is (the API will reject it with a clear error rather than silently using
    the wrong platform).

    Returns None if the AMI cannot be described (deleted, cross-account, etc.).
    """
    logger.info(f"Resolving InstancePlatform from AMI {ami_id}")
    try:
        resp = _ec2.describe_images(ImageIds=[ami_id])
        images = resp.get("Images", [])
        if not images:
            logger.warning(f"No images returned for AMI {ami_id} (deleted or cross-account?)")
            return None
        platform_details = images[0].get("PlatformDetails", "")
    except ClientError as e:
        logger.error(f"DescribeImages failed for AMI {ami_id}: {e}")
        return None

    if not platform_details:
        logger.warning(f"AMI {ami_id} has no PlatformDetails")
        return None

    logger.info(f"Resolved InstancePlatform for AMI {ami_id}: {platform_details}")
    return platform_details


def _place_spot(subnets):
    """Spot is best-effort and cannot be reserved, so there is nothing to probe or
    rank -- return the first candidate subnet and let RunInstances draw from the spot
    pool (the builder skips the ODCR block entirely when spot=True).
    Returns (subnet_id, "", "spot")."""
    return subnets[0], "", "spot"


def _place_one(body):
    """Probe candidate subnets in parallel, reserve a real ODCR on the winner.
    Returns (subnet_id, capacity_reservation_id, source) or raises on no-capacity.

    source is "admin" when the caller supplied a capacity_reservation_id (the
    instance lands in the admin's reservation -- no probe, no fresh mint) or
    "auto" when this Lambda reserved a short-window per-session ODCR."""
    # Admin-supplied ODCR: AZ-locked and pre-validated by the controller, so
    # there is nothing to probe. Pass it straight through on its own subnet.
    admin_cr = body.get("capacity_reservation_id")
    if admin_cr and not body.get("spot"):
        return body["subnet_ids"][0], admin_cr, "admin"

    subnets = body["subnet_ids"]
    itype = body["instance_type"]
    ami = body["ami_id"]
    tenancy = body.get("tenancy", "default")
    platform = body.get("instance_platform")
    if platform:
        logger.info(f"Using caller-provided InstancePlatform: {platform}")
    else:
        platform = _resolve_instance_platform(ami)
    if not platform:
        raise RuntimeError(
            f"cannot determine InstancePlatform for AMI {ami} "
            f"(AMI not found or PlatformDetails empty)"
        )

    # Spot draws from a different pool than on-demand ODCR capacity and cannot be
    # reserved, so there is no ODCR to probe -- pick a candidate subnet best-effort.
    if body.get("spot"):
        return _place_spot(subnets)

    winner = None
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(MAX_PROBE_WORKERS, len(subnets))
    ) as pool:
        futures = {
            pool.submit(_probe_subnet, instance_type=itype, instance_ami=ami,
                        subnet_id=s, tenancy=tenancy, instance_platform=platform): s
            for s in subnets
        }
        for fut in concurrent.futures.as_completed(futures):
            if fut.result():
                winner = fut.result()
                break  # first subnet with capacity wins

    if not winner:
        raise RuntimeError(f"no capacity for {itype} across {len(subnets)} subnet(s)")

    # Reserve a REAL short-window ODCR on the winning subnet (auto-expires 5min).
    odcr_id = _reserve_capacity(
        instance_type=itype,
        instance_ami=ami,
        subnet_id=winner,
        tenancy=tenancy,
        session_uuid=body["session_uuid"],
        instance_platform=platform,
        cluster_id=body.get("cluster_id", ""),
        custom_tags=body.get("custom_tags") or [],
    )
    return winner, odcr_id, "auto"


def _handle_record(rec):
    body = json.loads(rec["body"])
    suid = body["session_uuid"]
    try:
        subnet_id, odcr_id, source = _place_one(body)
        logger.info(f"placement_ready session={suid} subnet={subnet_id} odcr={odcr_id} source={source}")
        _emit_result({
            "success": True,
            "event_type": "placement_ready",
            "session_uuid": suid,
            "subnet_id": subnet_id,
            "odcr_id": odcr_id,
            "capacity_reservation_source": source,
            "attempt": body.get("attempt", 1),
            "nonce": body["nonce"],
        })
    except Exception as e:
        logger.warning(f"placement_failed session={suid}: {e}")
        _emit_result({
            "success": False,
            "event_type": "placement_failed",
            "session_uuid": suid,
            "error": str(e),
            "nonce": body["nonce"],
        })


def lambda_handler(event, context):
    for rec in event.get("Records", []):
        try:
            _handle_record(rec)
        except Exception as e:
            # Never raise: a poison message must not block the queue. The
            # controller's own placement-timeout reconciler is the backstop.
            logger.exception(f"unhandled placement error: {e}")
    return {"ok": True}
