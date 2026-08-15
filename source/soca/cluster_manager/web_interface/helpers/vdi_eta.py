# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
VDI launch ETA -- historical timing aggregation backed by DynamoDB.

Records per-session checkpoint durations at session-ready / session-failed
and computes per-stack/per-instance-type percentile bands so the WebUI
can show "Typical launch: 3-5 min" hints on VDI cards during launch.

Bucket precedence (highest to lowest confidence):
    Tier A: (stack_id, instance_type)  -- exact match
    Tier C: (stack_id)                 -- any instance type for this stack

Tier B (sizing-class normalized) deferred to a follow-up CR.

Sample size threshold N=5 below which no ETA is returned (UI shows
"building history..." instead of an unreliable estimate).
"""

from __future__ import annotations

import logging
import os
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cachetools import TTLCache, cached

import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Table name is deterministic from cluster_id so the controller and CDK
# agree without an extra config-key round-trip.
def _table_name() -> str:
    cluster_id = os.environ.get("EDH_CLUSTER_ID", "")
    return f"{cluster_id}-vdi-launch-history" if cluster_id else ""


# Sample-size floor below which we do not return an ETA (UI says
# "building history" instead of showing noise).
MIN_SAMPLE_SIZE = 5

# Lookback when querying. 90 day TTL on the table itself; this is the
# Query-time cap on rows scanned.
LOOKBACK_DAYS = 90

# Per-Query Limit. Picks the most recent K items via reverse SK scan.
# Large enough to give stable percentiles, small enough to keep RCU
# cost negligible at our scale.
QUERY_LIMIT = 200

# Cache the computed ETA per (stack_id, instance_type) for 5 minutes.
# Bursty page loads share a fetch; the data does not change at request
# cadence anyway.
_ETA_CACHE_TTL_SEC = 300
_eta_cache = TTLCache(maxsize=512, ttl=_ETA_CACHE_TTL_SEC)


# ---------------------------------------------------------------------------
# Lazy DDB client
# ---------------------------------------------------------------------------

_ddb_resource = None


def _get_ddb_table():
    """Lazily build a boto3 DynamoDB resource and return the launch
    history table. Cached at module scope so we share the underlying
    boto3 session across requests in the same worker."""
    global _ddb_resource
    if _ddb_resource is None:
        _ddb_resource = utils_boto3.get_boto(
            service_name="dynamodb", resource=True
        ).message
    return _ddb_resource.Table(_table_name())


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def record_launch_completion(
    session_uuid: str,
    software_stack_id: int,
    instance_type: str,
    os_family: str,
    state: str,
    created_on: datetime,
    completed_on: datetime,
    checkpoint_durations_ms: Dict[str, int],
) -> SocaResponse:
    """
    Write a single launch-completion item to the launch history table.

    Called from the event handler when a VDI reaches session-ready or
    session-failed. Failures are logged but never raised -- a write
    miss is a missed data point, not a session-blocking error.

    Args:
        session_uuid: VirtualDesktopSessions.session_uuid
        software_stack_id: SoftwareStacks.id
        instance_type: e.g. "m6i.xlarge"
        os_family: "linux" or "windows"
        state: "running" (became ready) or "failed"
        created_on: session creation timestamp (start of pending)
        completed_on: when state was reached
        checkpoint_durations_ms: {checkpoint_name: ms_since_pending}
            e.g. {"ec2-running": 9000, "session-ready": 110000}
    """
    table_name = _table_name()
    if not table_name:
        logger.warning("vdi_eta.record_launch: EDH_CLUSTER_ID empty, skip")
        return SocaResponse(success=False, message="cluster id missing")

    expires_at = int(
        (completed_on.replace(tzinfo=timezone.utc) + timedelta(days=LOOKBACK_DAYS))
        .timestamp()
    )
    pk = f"STACK#{software_stack_id}"
    # ISO-Z timestamp in SK gives natural reverse-chronological ordering
    # via ScanIndexForward=False on Query. Microsecond precision avoids
    # collisions when two sessions complete in the same second.
    sk = f"LAUNCH#{created_on.strftime('%Y-%m-%dT%H:%M:%S.%f')}Z#{session_uuid}"

    item = {
        "pk": pk,
        "sk": sk,
        "session_uuid": session_uuid,
        "stack_id": software_stack_id,
        "instance_type": instance_type,
        "os_family": os_family,
        "state": state,
        "created_on": created_on.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_on": completed_on.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_ms": int(
            (completed_on - created_on).total_seconds() * 1000
        ),
        "checkpoints": {k: int(v) for k, v in checkpoint_durations_ms.items()},
        "expires_at": expires_at,
    }

    try:
        _get_ddb_table().put_item(Item=item)
        logger.info(
            f"vdi_eta.record_launch: stack={software_stack_id} "
            f"instance={instance_type} state={state} "
            f"duration_ms={item['duration_ms']}"
        )
        return SocaResponse(success=True, message="recorded")
    except Exception as err:
        logger.warning(f"vdi_eta.record_launch failed: {err}")
        return SocaResponse(success=False, message=str(err))


# ---------------------------------------------------------------------------
# Reader: tiered bucket lookup + percentile compute
# ---------------------------------------------------------------------------


@cached(_eta_cache)
def get_eta(stack_id: int, instance_type: str) -> Optional[Dict[str, Any]]:
    """
    Compute an ETA bucket for a (stack, instance_type) pair by walking
    Tier A (exact match) then Tier C (stack-wide), each requiring at
    least MIN_SAMPLE_SIZE successful samples in the last LOOKBACK_DAYS.

    Returns None when no tier has enough samples (UI shows "building
    history...").

    Returns:
        {
          "tier": "A" | "C",
          "sample_size": int,
          "checkpoints": {
              "ec2-running": {"p25": ms, "p50": ms, "p75": ms, "p95": ms},
              "session-ready": {...},
              ...
          },
          "duration_ms": {"p25": ..., "p50": ..., "p75": ..., "p95": ...},
        }
    """
    if not _table_name():
        return None

    # Tier A: exact instance_type match
    items_all = _query_recent_for_stack(stack_id)
    items_a = [i for i in items_all if i.get("instance_type") == instance_type]
    if len(items_a) >= MIN_SAMPLE_SIZE:
        return _build_eta(items_a, tier="A")

    # Tier C: stack-wide, any instance_type
    if len(items_all) >= MIN_SAMPLE_SIZE:
        return _build_eta(items_all, tier="C")

    return None


def _query_recent_for_stack(stack_id: int) -> List[Dict[str, Any]]:
    """Query DDB for recent successful launches under this stack."""
    pk = f"STACK#{stack_id}"
    cutoff_iso = (
        datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    try:
        from boto3.dynamodb.conditions import Key, Attr

        resp = _get_ddb_table().query(
            KeyConditionExpression=(
                Key("pk").eq(pk) & Key("sk").gte(f"LAUNCH#{cutoff_iso}#")
            ),
            FilterExpression=Attr("state").eq("running"),
            ScanIndexForward=False,  # newest first
            Limit=QUERY_LIMIT,
        )
        return resp.get("Items", [])
    except Exception as err:
        logger.warning(
            f"vdi_eta.query stack={stack_id} failed: {err}; returning empty"
        )
        return []


def _build_eta(items: List[Dict[str, Any]], tier: str) -> Dict[str, Any]:
    """Compute p25/p50/p75/p95 across the sample for each checkpoint."""
    sample_size = len(items)

    # Aggregate checkpoint durations by name across all items
    by_checkpoint: Dict[str, List[int]] = {}
    durations: List[int] = []
    for it in items:
        cps = it.get("checkpoints") or {}
        for name, ms in cps.items():
            try:
                by_checkpoint.setdefault(name, []).append(int(ms))
            except (TypeError, ValueError):
                continue
        try:
            durations.append(int(it.get("duration_ms", 0)))
        except (TypeError, ValueError):
            continue

    checkpoints_eta = {
        name: _percentiles(values)
        for name, values in by_checkpoint.items()
        if len(values) >= MIN_SAMPLE_SIZE  # only show checkpoints with enough data
    }

    return {
        "tier": tier,
        "sample_size": sample_size,
        "duration_ms": _percentiles(durations) if durations else None,
        "checkpoints": checkpoints_eta,
    }


def _percentiles(values: List[int]) -> Dict[str, int]:
    """p25/p50/p75/p95 via statistics.quantiles."""
    if not values:
        return {"p25": 0, "p50": 0, "p75": 0, "p95": 0}
    # Sort once for both quantile + p95 paths.
    sorted_v = sorted(int(v) for v in values)
    n = len(sorted_v)

    if n == 1:
        only = sorted_v[0]
        return {"p25": only, "p50": only, "p75": only, "p95": only}

    # statistics.quantiles with n=4 returns the 3 cut points = p25, p50, p75
    quartiles = statistics.quantiles(sorted_v, n=4, method="inclusive")
    p25, p50, p75 = (int(q) for q in quartiles)

    # p95 from the sorted list (linear interpolation between adjacent
    # samples; statistics.quantiles(n=20) overcomputes for this single
    # need so we do it inline).
    rank = 0.95 * (n - 1)
    lo = int(rank)
    hi = min(lo + 1, n - 1)
    frac = rank - lo
    p95 = int(sorted_v[lo] + frac * (sorted_v[hi] - sorted_v[lo]))

    return {"p25": p25, "p50": p50, "p75": p75, "p95": p95}


# ---------------------------------------------------------------------------
# Test convenience -- callers can clear the cache between scenarios
# ---------------------------------------------------------------------------


def _clear_eta_cache() -> None:
    """Drop the ETA cache. Test-only helper; production should let the
    5-min TTL expire naturally."""
    _eta_cache.clear()
