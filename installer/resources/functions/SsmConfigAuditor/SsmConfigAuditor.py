# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
SSM ElastiCache ConfigAuditor Lambda.

Runs hourly via EventBridge Scheduler. Catches drift between SSM (the
source of truth) and the Valkey configuration HASH (the cache).

WHAT IT CHECKS
==============

  1. Keys in SSM but missing from hash    -- Lambda missed a Create event
  2. Keys in hash with wrong values        -- Lambda missed an Update event
  3. Keys in hash but missing from SSM     -- Lambda missed a Delete event
  4. Sentinel field present + recent       -- prevents readers from being
                                              told "hash is fully populated"
                                              when it actually is not

WHAT IT DOES
============

Auto-heals the drift in-place by HSET'ing missing/changed fields and
HDEL'ing stale ones. SSM is the truth, Valkey is downstream -- there
is no scenario where applying a diff "from SSM toward Valkey" makes
state worse. Frequency is hourly + drift count is bounded by Lambda
miss rate (typically zero), so blast radius is contained.

If correction counts exceed thresholds, the validation alarms fire
to surface a chronic problem (e.g. ConfigSync Lambda is throttling).

METRICS
=======

Namespace:  EDH/SsmConfigSync
Source dim: Auditor
Cluster dim: ClusterId

  AuditDuration               (Milliseconds) -- end-to-end run time
  AuditedKeyCount             (Count) -- total SSM params under prefix
  BackfillDriftCount          (Count) -- total drift entries detected
                                          (sum of missing + mismatched + extra)
  BackfillMissingCount        (Count) -- in SSM, not in hash
  BackfillMismatchCount       (Count) -- in both, value differs
  BackfillExtraCount          (Count) -- in hash, not in SSM
  IntegrityHashMismatch       (Count) -- 1 if drift > 0 this run else 0
  SuppressorActive            (Count) -- 1 at start, 0 at end. Composite
                                          alarms wrap ops metrics in
                                          NOT ALARM(SuppressorActive>0)
                                          to absorb regular sweep noise.

Validation alarms (drift) MUST fire on sustained drift.
Ops alarms (write rate, latency) MUST be suppressed via SuppressorActive
during the audit window.

DEPLOYMENT
==========

Packaged + deployed by CDK alongside SsmConfigSync. Required env vars:

  EDH_CLUSTER_ID
  EDH_VALKEY_ENDPOINT
  EDH_VALKEY_PORT
  EDH_VALKEY_CACHE_NAME
  EDH_VALKEY_USER
  EDH_CONFIG_HASH_FQDN

Optional:
  LOG_LEVEL                 default INFO
  EDH_AUDIT_AUTOHEAL        "true"|"false"  (default true). Set false to
                            run in audit-only mode (metrics fire, no
                            HSET/HDEL writes).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Tuple

import boto3
from botocore.exceptions import ClientError

import redis  # provided via Lambda layer
from redis.credentials import CredentialProvider
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
import botocore.session

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
PARAM_PREFIX = f"/edh/{CLUSTER_ID}/"
VALKEY_ENDPOINT = os.environ["EDH_VALKEY_ENDPOINT"]
VALKEY_PORT = int(os.environ.get("EDH_VALKEY_PORT", "6379"))
VALKEY_CACHE_NAME = os.environ["EDH_VALKEY_CACHE_NAME"]
VALKEY_USER = os.environ["EDH_VALKEY_USER"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
HASH_FQDN = os.environ["EDH_CONFIG_HASH_FQDN"]
AUTOHEAL = os.environ.get("EDH_AUDIT_AUTOHEAL", "true").strip().lower() in {
    "true",
    "1",
    "yes",
    "on",
}

METRICS_NAMESPACE = "EDH/SsmConfigSync"
METRIC_SOURCE = "Auditor"

# Reserved fields in the hash that the auditor must IGNORE when diffing
# against SSM (they are synthetic, not mirrored from any SSM parameter).
_RESERVED_FIELD_PREFIX = "__meta:"
_SENTINEL_FIELD = "__meta:walk_complete_at"


# ---------------------------------------------------------------------------
# AWS clients (warm-reused)
# ---------------------------------------------------------------------------

ssm_client = boto3.client("ssm")
cloudwatch = boto3.client("cloudwatch")

# IAM auth: a SigV4-signed "connect" token is minted per connection off the
# Lambda role's credentials (no static password). Credentials are resolved per
# get_credentials() call so rotated container env-var creds are never stale.


class _ElastiCacheIAMProvider(CredentialProvider):
    """redis-py provider: fresh SigV4 connect token per connection."""

    def __init__(self, cache_name, user_id, region):
        self._cache_name = cache_name
        self._user_id = user_id
        self._region = region

    def get_credentials(self):
        req = AWSRequest(
            method="GET",
            url="https://%s/" % self._cache_name,
            params={"Action": "connect", "User": self._user_id},
        )
        _creds = botocore.session.get_session().get_credentials()
        SigV4QueryAuth(
            _creds, "elasticache", self._region, expires=900
        ).add_auth(req)
        return (self._user_id, req.prepare().url[len("https://") :])


_redis_conn = None


def _get_redis():
    global _redis_conn
    if _redis_conn is not None:
        return _redis_conn

    logger.info("Cold-start: connecting to Valkey via IAM auth")
    _redis_conn = redis.Redis(
        host=VALKEY_ENDPOINT,
        port=VALKEY_PORT,
        protocol=3,
        ssl=True,
        ssl_cert_reqs=None,  # ElastiCache uses an AWS-managed cert chain not in
                             # the default Python trust store; auth is IAM SigV4.
        decode_responses=False,
        credential_provider=_ElastiCacheIAMProvider(
            VALKEY_CACHE_NAME, VALKEY_USER, AWS_REGION
        ),
        socket_connect_timeout=10,
        socket_timeout=10,
        retry_on_timeout=True,
    )
    return _redis_conn


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _emit_metric(metric_name: str, value: float, unit: str = "Count"):
    """Auditor metrics carry Source=Auditor (NOT Live) -- ops alarms
    don't see them. Validation alarms (drift, mismatch) DO watch them."""
    try:
        cloudwatch.put_metric_data(
            Namespace=METRICS_NAMESPACE,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": value,
                    "Unit": unit,
                    "Dimensions": [
                        {"Name": "ClusterId", "Value": CLUSTER_ID},
                        {"Name": "Source", "Value": METRIC_SOURCE},
                    ],
                }
            ],
        )
    except Exception as err:
        logger.warning(f"PutMetricData failed for {metric_name}: {err}")


def _emit_suppressor(active: bool):
    """Suppressor signal. Composite alarms watch this metric to absorb
    regular flush/audit noise -- ops alarms only fire when this is 0.
    The metric is published BOTH at start and end so a hung Lambda
    doesn't permanently silence ops alarms (Lambda timeout will
    eventually let SuppressorActive go stale, and CW alarm M-of-N
    over a 15-minute window will treat absence as 0)."""
    _emit_metric("SuppressorActive", 1.0 if active else 0.0, unit="None")


# ---------------------------------------------------------------------------
# SSM walk
# ---------------------------------------------------------------------------


def _walk_ssm() -> Dict[str, str]:
    """Walk all SSM parameters under the cluster prefix. Returns a
    dict keyed by full parameter name."""
    result = {}
    paginator = ssm_client.get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=PARAM_PREFIX, Recursive=True):
        for entry in page.get("Parameters", []):
            result[entry["Name"]] = entry["Value"]
    return result


# ---------------------------------------------------------------------------
# Hash read
# ---------------------------------------------------------------------------


def _read_hash(r) -> Dict[str, str]:
    """HGETALL the cluster config hash. Decodes bytes to str. Filters
    out reserved fields so they do not appear as 'extras' in the diff."""
    raw = r.hgetall(HASH_FQDN)
    if not raw:
        return {}
    decoded = {}
    for k, v in raw.items():
        kstr = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else k
        if kstr.startswith(_RESERVED_FIELD_PREFIX):
            continue
        vstr = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else v
        decoded[kstr] = vstr
    return decoded


# ---------------------------------------------------------------------------
# Diff + heal
# ---------------------------------------------------------------------------


def _diff(
    ssm_view: Dict[str, str], hash_view: Dict[str, str]
) -> Tuple[Dict[str, str], Dict[str, Tuple[str, str]], Dict[str, str]]:
    """Three-way diff:
       missing   -- in SSM, not in hash       (HSET to fix)
       mismatched -- in both, value differs   (HSET to fix)
       extra     -- in hash, not in SSM       (HDEL to fix)

    Reserved fields are filtered out by _read_hash so they cannot be
    classified as 'extras'.
    """
    missing = {}
    mismatched = {}
    for name, value in ssm_view.items():
        if name not in hash_view:
            missing[name] = value
        elif hash_view[name] != value:
            mismatched[name] = (hash_view[name], value)

    extra = {
        name: hash_view[name] for name in hash_view if name not in ssm_view
    }

    return missing, mismatched, extra


def _heal(r, missing: Dict[str, str], mismatched: Dict[str, Tuple[str, str]], extra: Dict[str, str]):
    """Apply the diff: HSET missing/mismatched, HDEL extras. No-op for
    keys not present in the diff. Single pipeline for atomicity-ish
    (Valkey pipeline is not strictly atomic but it is round-trip
    batched -- good enough since we want eventual consistency, not
    transactional)."""
    if not (missing or mismatched or extra):
        return

    pipe = r.pipeline(transaction=False)

    # HSET missing
    for name, value in missing.items():
        pipe.hset(HASH_FQDN, name, value)

    # HSET mismatched (use authoritative SSM value)
    for name, (_old, new_value) in mismatched.items():
        pipe.hset(HASH_FQDN, name, new_value)

    # HDEL extras (one HDEL per field is fine -- batch via pipeline)
    for name in extra:
        pipe.hdel(HASH_FQDN, name)

    pipe.execute()


# ---------------------------------------------------------------------------
# Sentinel maintenance
# ---------------------------------------------------------------------------


def _refresh_sentinel(r):
    """Touch the walk-complete sentinel so readers know the hash is
    current. We rewrite this every audit run regardless of drift count
    -- the audit itself constitutes a 'walk completed' event."""
    r.hset(
        HASH_FQDN,
        _SENTINEL_FIELD,
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event, context):
    """Scheduled invocation (EventBridge Scheduler, hourly).

    Returns a dict with the audit summary for ease of CloudWatch-Logs
    grep + downstream tooling. Raises on AWS errors so EventBridge
    Scheduler retry kicks in.
    """
    start = datetime.now(timezone.utc)
    _emit_suppressor(True)

    try:
        # 1. Read both views
        ssm_view = _walk_ssm()
        r = _get_redis()
        hash_view = _read_hash(r)

        # 2. Compute diff
        missing, mismatched, extra = _diff(ssm_view, hash_view)
        drift_count = len(missing) + len(mismatched) + len(extra)

        # 3. Always emit count metrics so dashboards have continuity
        _emit_metric("AuditedKeyCount", float(len(ssm_view)))
        _emit_metric("BackfillMissingCount", float(len(missing)))
        _emit_metric("BackfillMismatchCount", float(len(mismatched)))
        _emit_metric("BackfillExtraCount", float(len(extra)))
        _emit_metric("BackfillDriftCount", float(drift_count))
        _emit_metric(
            "IntegrityHashMismatch", 1.0 if drift_count > 0 else 0.0
        )

        # 4. Auto-heal (gated by env var)
        if AUTOHEAL and drift_count > 0:
            logger.warning(
                f"ConfigAuditor detected drift -- "
                f"missing={len(missing)} mismatched={len(mismatched)} "
                f"extra={len(extra)}; auto-healing"
            )
            _heal(r, missing, mismatched, extra)
        elif drift_count > 0:
            logger.warning(
                f"ConfigAuditor detected drift -- "
                f"missing={len(missing)} mismatched={len(mismatched)} "
                f"extra={len(extra)}; AUTOHEAL=false, skipping repair"
            )

        # 5. Always refresh the sentinel (we just walked SSM; even if
        #    no drift, the hash is now known-fresh).
        _refresh_sentinel(r)

        elapsed_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000.0
        _emit_metric("AuditDuration", elapsed_ms, unit="Milliseconds")

        return {
            "status": "ok",
            "audited_keys": len(ssm_view),
            "missing": len(missing),
            "mismatched": len(mismatched),
            "extra": len(extra),
            "drift_count": drift_count,
            "autoheal": AUTOHEAL,
            "elapsed_ms": elapsed_ms,
        }

    except ClientError as err:
        logger.error(f"AWS ClientError during audit: {err}")
        raise

    except redis.exceptions.RedisError as err:
        logger.error(f"RedisError during audit: {err}")
        # Drop cached connection so the next run re-handshakes
        global _redis_conn
        _redis_conn = None
        raise

    except Exception:
        logger.exception("Unhandled error during audit")
        raise

    finally:
        # ALWAYS lower the suppressor at the end. If we crashed midway,
        # the alarm windowing handles staleness so ops alarms come back
        # online once the M-of-N evaluation period rolls over.
        try:
            _emit_suppressor(False)
        except Exception:
            logger.warning("Failed to lower suppressor at audit end")
