# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
DCV async capacity-placement Lambda.

Moves the slow ODCR capacity check off the create_virtual_desktop API thread
so the WebUI returns immediately (state=placing). SQS-triggered, one message
per session.

Message body (JSON) enqueued by the create handler:
    {
      "session_uuid": "<uuid>",          # broker/SOCA session id
      "instance_type": "c8i.2xlarge",
      "instance_ami":  "ami-...",
      "subnet_ids":    ["subnet-a", ...], # candidates, in preference order
      "tenancy":       "default",
      "nonce":         "<hex>"            # replay dedup at controller
    }

Flow per message:
    1. Collapse the candidate subnets to one per Availability Zone -- two
       subnets in one AZ draw from the same capacity pool, so reserving in
       both is wasted work. Order them by
       /configuration/dcv/placement/az_order: "random" (the default) spreads
       launches across the AZs, "ordered" walks the cluster's configured
       subnet order for an admin who prefers one AZ.
    2. Reserve a REAL short-window ODCR, walking the candidate AZs in waves of
       /configuration/dcv/placement/concurrent_az_attempts (read here, per
       invocation). A real CreateCapacityReservation is the only authoritative
       capacity test: DryRun checks permissions only and returns
       DryRunOperation regardless of capacity, so a DryRun probe reports every
       authorized AZ as available. Within a wave the highest-ranked success
       wins and the other reservations are canceled; if a whole wave is out of
       capacity the next wave runs, so one full AZ never blocks the launch.
       ODCRs auto-expire (5 min end_date) -- a cancel that does not land leaks
       for minutes, not forever.
    3. Emit the result to the placement result queue:
         success -> {event_type:"placement_ready", subnet_id, capacity_reservation_id}
         failure -> {event_type:"placement_failed", reason}
       CapacityExecutor consumes it and advances the session (PLACED -> launches
       CFN with the known-good ODCR) or marks it failed and surfaces it on the
       timeline.

Stdlib + boto3 only (Lambda runtime provides boto3). Every call this Lambda
makes is to a public AWS endpoint (EC2, SQS, SSM) and it never reaches the
controller directly, which is why it needs no VPC attachment -- the result
queue is the seam, and VPC-attached CapacityExecutor does the private leg.
"""

import concurrent.futures
import json
import logging
import os
import random
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Hard ceiling on concurrent reservation attempts. The per-launch
# concurrent_az_attempts setting is clamped to this.
MAX_PLACEMENT_WORKERS = int(os.environ.get("EDH_PLACEMENT_MAX_WORKERS", "8"))
# Width used whenever the setting cannot be read or cannot be used. Serial,
# because each attempt holds a real reservation.
DEFAULT_CONCURRENT_AZ_ATTEMPTS = 1
# AZ attempt order. Random by default so launches spread across the AZs
# instead of every one of them starting at whichever subnet the cluster
# happens to list first.
DEFAULT_AZ_ORDER = "random"
_AZ_ORDER_VALUES = frozenset({"random", "ordered"})
RESULT_QUEUE_URL = os.environ["EDH_PLACEMENT_RESULT_QUEUE_URL"]
CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")

# Error codes that will fail identically in every AZ, so the walk stops on
# them instead of spending the remaining AZs on the same answer. Anything NOT
# listed here is treated as a per-AZ shortage and moves to the next AZ: EC2
# has more than one capacity-shortage code and an unrecognized one costs a
# few hundred milliseconds, while mistaking a shortage for a terminal error
# is the failure this module exists to avoid.
_TERMINAL_ERROR_CODES = frozenset({
    # Authorization -- an SCP or IAM deny applies account-wide.
    "UnauthorizedOperation",
    "AccessDenied",
    "AccessDeniedException",
    # Account-level limits -- not AZ-specific.
    "InstanceLimitExceeded",
    "CapacityReservationLimitExceeded",
    "VcpuLimitExceeded",
    # Malformed request -- the next AZ rejects it the same way.
    "InvalidParameterValue",
    "InvalidParameterCombination",
    "MissingParameter",
    "InvalidAvailabilityZone",
})

# Transient -- retry the SAME AZ rather than moving on.
_THROTTLE_ERROR_CODES = frozenset({
    "RequestLimitExceeded",
    "Throttling",
    "ThrottlingException",
})

_THROTTLE_BACKOFF_SECONDS = 1.0
_THROTTLE_MAX_RETRIES = 2

_sqs = boto3.client("sqs")
_ec2 = boto3.client("ec2")
_ssm = boto3.client("ssm")
# Reservations go through their own client with retries OFF. EC2 answers
# InsufficientInstanceCapacity with HTTP 500, which botocore's default policy
# retries five times with exponential backoff: 9.5s per refusing AZ against
# 0.35s for one attempt, plus five junk failed-reservation records in the
# console. Re-asking one AZ is pointless here because the AZ walk IS the retry
# strategy; throttles are retried by _reserve_with_throttle_retry, which is
# now the only throttle protection on this call. total_max_attempts counts the
# initial request, so 1 means no retries -- max_attempts=1 would mean one
# RETRY, which is two attempts. Describes and cancels keep the default
# retries.
_ec2_reserve = boto3.client(
    "ec2", config=Config(retries={"total_max_attempts": 1, "mode": "standard"})
)


class TerminalPlacementError(Exception):
    """A reservation failure that will recur in every AZ (auth, quota, bad input)."""


def _emit_result(payload):
    """Send a placement result to the result queue."""
    _sqs.send_message(
        QueueUrl=RESULT_QUEUE_URL,
        MessageBody=json.dumps(payload),
        MessageGroupId=payload["session_uuid"],
        MessageDeduplicationId=payload["nonce"],
    )


def _candidate_azs(subnet_ids):
    """Collapse candidate subnets to one per AZ, in the caller's subnet order.

    That order is the CONFIGURED one, not necessarily the one attempted: the
    caller reorders the result per az_order. Subnets in the same AZ share one
    capacity pool, so reserving in both can only fail twice for the same
    reason. Resolves every subnet in ONE DescribeSubnets call, via a subnet-id
    FILTER rather than SubnetIds: the filter omits an id it cannot resolve,
    where SubnetIds raises InvalidSubnetID.NotFound for the whole call, so one
    stale id in the configured subnet list would fail every launch. The
    filter's result order is unspecified, which is why the order here comes
    from subnet_ids rather than from the response. Returns
    [(subnet_id, az_id), ...]."""
    resp = _ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": list(subnet_ids)}]
    )
    _az_by_subnet = {
        s["SubnetId"]: s["AvailabilityZoneId"] for s in resp.get("Subnets", [])
    }
    _candidates = []
    _seen_azs = set()
    for _subnet_id in subnet_ids:
        _az = _az_by_subnet.get(_subnet_id)
        if not _az:
            logger.warning(f"Subnet {_subnet_id} did not resolve to an AZ; skipping")
            continue
        if _az in _seen_azs:
            logger.info(f"Subnet {_subnet_id} shares AZ {_az} with an earlier candidate; skipping")
            continue
        _seen_azs.add(_az)
        _candidates.append((_subnet_id, _az))
    return _candidates


def _read_placement_setting(key, default):
    """Read /configuration/dcv/placement/<key> for this cluster.

    Read per invocation rather than cached, so an edhctl config set takes effect
    on the next launch. Returns None if the value cannot be read for any reason,
    which the caller resolves to its default: an advisory tuning read must never
    fail a launch, so a missing SSM endpoint or a timeout degrades to the
    default the same way an unset key does. `default` is used only to say in
    the log what the launch fell back to."""
    _name = f"/edh/{CLUSTER_ID}/configuration/dcv/placement/{key}"
    try:
        return _ssm.get_parameter(Name=_name)["Parameter"]["Value"]
    except ClientError as e:
        _code = e.response["Error"]["Code"]
        if _code == "ParameterNotFound":
            logger.info(f"{_name} is unset; using default {default!r}")
        else:
            logger.warning(
                f"Could not read {_name} ({_code}); using default {default!r}"
            )
        return None
    except Exception as e:  # noqa: BLE001 - no endpoint, timeout, odd response
        logger.warning(
            f"Could not read {_name} ({type(e).__name__}: {e}); "
            f"using default {default!r}"
        )
        return None


def _resolve_az_order(setting):
    """"random" or "ordered", anything else being the default.

    "ordered" walks the cluster's configured subnet order, which is what an
    admin wants when one AZ is preferred -- a single-AZ FSx file system, for
    instance, where placing away from the storage AZ costs cross-AZ latency on
    every read."""
    if setting is None:
        return DEFAULT_AZ_ORDER
    _value = str(setting).strip().lower()
    if _value in _AZ_ORDER_VALUES:
        return _value
    logger.warning(
        f"az_order={setting!r} is neither 'random' nor 'ordered'; "
        f"using {DEFAULT_AZ_ORDER}"
    )
    return DEFAULT_AZ_ORDER


def _order_candidates(candidates, az_order, session_uuid):
    """Return the candidates in the order they should be attempted.

    A random order is SEEDED BY SESSION, not by the clock: the spread across
    launches is what the setting is for, but one launch must be reproducible so
    a failure can be replayed in the order it actually used."""
    if az_order != "random":
        return candidates
    _ordered = list(candidates)
    random.Random(session_uuid).shuffle(_ordered)
    return _ordered


def _resolve_concurrency(setting, candidate_count):
    """How many AZs to reserve in at once, clamped to the candidate count.

    "all" means every candidate, and keeps meaning that as subnets are added.
    Anything unusable means serial, since each attempt holds a real
    reservation."""
    if setting is None:
        return DEFAULT_CONCURRENT_AZ_ATTEMPTS
    _setting = str(setting).strip()
    if _setting.lower() == "all":
        return min(candidate_count, MAX_PLACEMENT_WORKERS)
    try:
        _width = int(_setting)
    except (TypeError, ValueError):
        logger.warning(
            f"concurrent_az_attempts={setting!r} is neither 'all' nor an "
            f"integer; placing serially"
        )
        return DEFAULT_CONCURRENT_AZ_ATTEMPTS
    if _width < 1:
        logger.warning(
            f"concurrent_az_attempts={_width} is below 1; placing serially"
        )
        return DEFAULT_CONCURRENT_AZ_ATTEMPTS
    return min(_width, candidate_count, MAX_PLACEMENT_WORKERS)


def _reserve_capacity(*, instance_type, subnet_id, az_id, tenancy, session_uuid, instance_platform, cluster_id="", custom_tags=None):
    """Create a real short-window ODCR (5 min expiry), tagged like the instance it backs."""
    from datetime import datetime, timedelta, timezone
    logger.info(f"Reserving capacity: {instance_type} platform={instance_platform} subnet={subnet_id} az={az_id} session={session_uuid}")
    end_time = datetime.now(timezone.utc) + timedelta(minutes=5)
    _tags = [{"Key": "edh:SessionUuid", "Value": session_uuid}]
    if cluster_id:
        _tags.append({"Key": "edh:ClusterId", "Value": cluster_id})
        _tags.append({"Key": "Name", "Value": f"{cluster_id}-dcv-odcr-{session_uuid[:8]}"})
    if custom_tags:
        # Skip custom keys colliding with reserved tags (AWS rejects duplicate keys).
        _reserved = {t["Key"] for t in _tags}
        _tags.extend(t for t in custom_tags if t.get("Key") not in _reserved)
    resp = _ec2_reserve.create_capacity_reservation(
        InstanceType=instance_type,
        InstancePlatform=instance_platform,
        AvailabilityZoneId=az_id,
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


def _cancel_reservation(odcr_id):
    """Release a reservation this launch is not going to use. Best effort: the
    5-minute end_date set in _reserve_capacity is the backstop if it fails."""
    try:
        _ec2.cancel_capacity_reservation(CapacityReservationId=odcr_id)
        logger.info(f"Canceled unused reservation {odcr_id}")
    except ClientError as e:
        logger.warning(
            f"Could not cancel unused reservation {odcr_id} "
            f"({e.response['Error']['Code']}); it expires within 5 minutes"
        )


def _reserve_with_throttle_retry(**kwargs):
    """_reserve_capacity, retrying the same AZ on a throttle.

    A throttle says nothing about capacity, so moving to the next AZ on one
    would skip an AZ that was never actually asked. Retries here rather than in
    botocore because the reservation client has its retries disabled: that
    stops the pointless re-asking of an AZ that is out of capacity, and a
    throttle is the one case on this call that is worth asking again."""
    for _attempt in range(_THROTTLE_MAX_RETRIES + 1):
        try:
            return _reserve_capacity(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] not in _THROTTLE_ERROR_CODES:
                raise
            if _attempt == _THROTTLE_MAX_RETRIES:
                raise
            _delay = _THROTTLE_BACKOFF_SECONDS * (2 ** _attempt)
            logger.warning(
                f"Throttled reserving in {kwargs.get('az_id')}; retry "
                f"{_attempt + 1} of {_THROTTLE_MAX_RETRIES} after {_delay}s"
            )
            time.sleep(_delay)


def _resolve_instance_platform(ami_id):
    """Return the AMI's PlatformDetails for use as InstancePlatform.

    DescribeImages PlatformDetails values ("Linux/UNIX", "Red Hat Enterprise
    Linux", "Windows", ...) are passed through unchanged: the
    CreateCapacityReservation InstancePlatform enum accepts the same strings,
    and anything outside it is rejected by the API with a clear error rather
    than silently reserving the wrong platform.

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
    """Spot is best-effort and cannot be reserved, so there is nothing to test or
    rank -- return the first candidate subnet and let RunInstances draw from the spot
    pool (the builder skips the ODCR block entirely when spot=True).
    Returns (subnet_id, "", "spot")."""
    return subnets[0], "", "spot"


def _mint_wave(wave, *, reserve_kwargs):
    """Reserve concurrently across one wave of (subnet_id, az_id) candidates.

    Returns (winners, failures) where winners is [(rank, subnet_id, odcr_id)]
    sorted by rank -- the caller's candidate order, NOT completion order, so a
    faster-responding AZ cannot displace a preferred one. Raises
    TerminalPlacementError only after the wave has drained and any reservations
    it did win have been released."""
    _winners = []
    _failures = []
    _terminal = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(wave)) as pool:
        _futures = {
            pool.submit(
                _reserve_with_throttle_retry,
                subnet_id=_subnet_id,
                az_id=_az,
                **reserve_kwargs,
            ): (_rank, _subnet_id, _az)
            for _rank, (_subnet_id, _az) in enumerate(wave)
        }
        for _fut in concurrent.futures.as_completed(_futures):
            _rank, _subnet_id, _az = _futures[_fut]
            try:
                _winners.append((_rank, _subnet_id, _fut.result()))
            except ClientError as err:
                _code = err.response["Error"]["Code"]
                if _code in _TERMINAL_ERROR_CODES:
                    logger.warning(f"Terminal reservation error in {_az}: {_code}")
                    if _terminal is None:
                        _terminal = TerminalPlacementError(f"{_code} ({_az})")
                    continue
                logger.info(f"No capacity in {_az} ({_subnet_id}): {_code}")
                _failures.append((_az, _code))
            except Exception as err:  # noqa: BLE001 - one AZ must not sink the wave
                logger.warning(f"Unexpected reservation error in {_az}: {err}")
                _failures.append((_az, type(err).__name__))
    _winners.sort(key=lambda w: w[0])
    if _terminal is not None:
        # A terminal error means this launch cannot proceed, so release
        # anything the rest of the wave reserved before giving up.
        for _, _, _odcr_id in _winners:
            _cancel_reservation(_odcr_id)
        raise _terminal
    return _winners, _failures


def _place_one(body):
    """Reserve a real ODCR for this session, walking the candidate AZs in waves.
    Returns (subnet_id, capacity_reservation_id, source) or raises on no-capacity.

    source is "admin" when the caller supplied a capacity_reservation_id (the
    instance lands in the admin's reservation -- no reservation of our own) or
    "auto" when this Lambda reserved a short-window per-session ODCR."""
    # Admin-supplied ODCR: AZ-locked and pre-validated by the controller, so
    # there is nothing to reserve. Pass it straight through on its own subnet.
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
    # reserved, so there is no ODCR to place -- pick a candidate subnet best-effort.
    if body.get("spot"):
        return _place_spot(subnets)

    candidates = _candidate_azs(subnets)
    if not candidates:
        raise RuntimeError(
            f"none of the {len(subnets)} candidate subnet(s) resolved to an AZ"
        )
    az_order = _resolve_az_order(
        _read_placement_setting("az_order", DEFAULT_AZ_ORDER)
    )
    candidates = _order_candidates(candidates, az_order, body["session_uuid"])
    concurrent_az_attempts = _resolve_concurrency(
        _read_placement_setting(
            "concurrent_az_attempts", DEFAULT_CONCURRENT_AZ_ATTEMPTS
        ),
        len(candidates),
    )
    logger.info(
        f"Placing {itype}: {len(candidates)} candidate AZ(s), "
        f"az_order={az_order}, "
        f"concurrent_az_attempts={concurrent_az_attempts}, "
        f"attempt order {','.join(_az for _, _az in candidates)}"
    )

    reserve_kwargs = {
        "instance_type": itype,
        "tenancy": tenancy,
        "session_uuid": body["session_uuid"],
        "instance_platform": platform,
        "cluster_id": body.get("cluster_id", ""),
        "custom_tags": body.get("custom_tags") or [],
    }

    failures = []
    for _start in range(0, len(candidates), concurrent_az_attempts):
        _wave = candidates[_start:_start + concurrent_az_attempts]
        _winners, _wave_failures = _mint_wave(_wave, reserve_kwargs=reserve_kwargs)
        failures.extend(_wave_failures)
        if _winners:
            _, _subnet_id, _odcr_id = _winners[0]
            for _, _, _loser_odcr in _winners[1:]:
                _cancel_reservation(_loser_odcr)
            return _subnet_id, _odcr_id, "auto"
        logger.info(
            f"Wave {_start // concurrent_az_attempts + 1} found no capacity; "
            f"{len(candidates) - _start - len(_wave)} AZ(s) remaining"
        )

    # Every candidate AZ was asked and every one refused, so this message is
    # now literally true -- the DryRun version emitted it after one AZ.
    _detail = ", ".join(f"{_az}={_code}" for _az, _code in failures)
    raise RuntimeError(
        f"no capacity for {itype} in any of {len(candidates)} AZ(s): {_detail}"
    )


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
