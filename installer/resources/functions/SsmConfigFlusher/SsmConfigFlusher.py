# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
SSM ElastiCache ConfigFlusher Lambda.

Runs every 24 hours via EventBridge Scheduler. Performs an atomic
full rebuild of the cluster's Valkey configuration HASH from SSM
using a build-then-RENAME pattern.

WHY THIS EXISTS
===============

ConfigSync (event-driven) keeps the hash hot for individual changes.
ConfigAuditor (hourly) catches per-event drift the Lambda missed.
ConfigFlusher catches what BOTH may have missed:

  - Multi-hour Valkey outages where the SSM event queue eventually
    overflowed and was discarded by EventBridge
  - Auditor itself was down or throttled long enough that hours of
    drift accumulated without correction
  - Subtle field-level corruption that no single-key check catches
  - First-ever populate after a fresh CDK deploy (no events fired yet)

It is the belt-and-suspenders cheap insurance policy. Operator can
also invoke this on demand to force-refresh the cache.

ATOMIC SWAP PATTERN
===================

  1. DEL <hash_fqdn>:_new            (clean up any stale partial)
  2. Walk SSM by cluster prefix
  3. Pipeline HSET <hash_fqdn>:_new  field=name value=value (batched)
  4. HSET sentinel field on :_new
  5. RENAME <hash_fqdn>:_new -> <hash_fqdn>   (O(1), atomic)

Concurrent readers see EITHER the old hash (complete) OR the new
hash (complete). Never an empty hash, never a partial state. This
is the property that makes ConfigFlusher safe to run in production
during any time window.

If step 2-4 fails, RENAME never executes. The :_new key holds
partial state but no reader sees it -- they're still on the old
hash. Step 1 of the NEXT run cleans up the orphan.

If step 5 (RENAME) fails (Valkey error mid-command), the next run
also handles it idempotently: step 1 DELs whatever's at :_new, and
the next swap proceeds normally.

METRICS
=======

Namespace:  EDH/SsmConfigSync
Source dim: Flush
Cluster dim: ClusterId

  FlushedKeyCount        (Count) -- fields written to the new hash
  FlushDuration          (Milliseconds) -- end-to-end run time
  FlushFailures          (Count) -- crashed flush runs
  SuppressorActive       (None unit gauge) -- 1 at start, 0 at end

Suppressor follows the same pattern as ConfigAuditor: the composite
alarm watches SuppressorActive across both sources to silence ops
alarms during scheduled sweeps.

DEPLOYMENT
==========

Packaged + deployed by CDK alongside SsmConfigSync. Required env vars:

  EDH_CLUSTER_ID
  EDH_VALKEY_ENDPOINT
  EDH_VALKEY_PORT
  EDH_VALKEY_CACHE_NAME
  EDH_VALKEY_USER
  EDH_CONFIG_HASH_FQDN
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict

import boto3
from botocore.exceptions import ClientError

import redis
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

# Build-side key. Must NOT collide with the live hash key. We use a
# fixed suffix so the next run can always clean up if a previous run
# crashed mid-build.
HASH_FQDN_BUILD = f"{HASH_FQDN}:_new"

# Sentinel field marking "walk complete, hash is fresh". Read by
# SocaConfig path queries -- empty hash without sentinel triggers
# fall-through to SSM walk.
SENTINEL_FIELD = "__meta:walk_complete_at"

METRICS_NAMESPACE = "EDH/SsmConfigSync"
METRIC_SOURCE = "Flush"

# HSET batch size. redis-py pipeline can hold thousands of commands,
# but we cap at 100 per pipeline submit to keep memory + RTT bounded
# on very large clusters.
HSET_BATCH_SIZE = 100


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
        socket_timeout=15,
        retry_on_timeout=True,
    )
    return _redis_conn


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------


def _emit_metric(metric_name: str, value: float, unit: str = "Count"):
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
    _emit_metric("SuppressorActive", 1.0 if active else 0.0, unit="None")


# ---------------------------------------------------------------------------
# SSM walk
# ---------------------------------------------------------------------------


def _walk_ssm() -> Dict[str, str]:
    """Walk all SSM parameters under the cluster prefix."""
    result = {}
    paginator = ssm_client.get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=PARAM_PREFIX, Recursive=True):
        for entry in page.get("Parameters", []):
            result[entry["Name"]] = entry["Value"]
    return result


# ---------------------------------------------------------------------------
# Hash build + atomic swap
# ---------------------------------------------------------------------------


def _populate_build_hash(r, params: Dict[str, str]) -> int:
    """HSET every SSM field into the build-side key in pipelined batches.
    Adds the sentinel field at the end. Returns the count of fields
    written (sentinel excluded)."""
    written = 0
    pipe = r.pipeline(transaction=False)
    in_batch = 0

    for name, value in params.items():
        pipe.hset(HASH_FQDN_BUILD, name, value)
        in_batch += 1
        if in_batch >= HSET_BATCH_SIZE:
            pipe.execute()
            written += in_batch
            in_batch = 0
            pipe = r.pipeline(transaction=False)

    if in_batch:
        pipe.execute()
        written += in_batch

    # Sentinel: separate command so a flush rebuild always observably
    # bumps the timestamp even if there are zero params (edge case).
    r.hset(
        HASH_FQDN_BUILD,
        SENTINEL_FIELD,
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    return written


def _atomic_swap(r):
    """RENAME build -> live. Single Valkey command, O(1), atomic.
    Concurrent readers see EITHER the old hash (complete) OR the new
    hash (complete). Never partial."""
    r.rename(HASH_FQDN_BUILD, HASH_FQDN)


def _cleanup_build_hash(r):
    """Idempotent DEL of the build-side key. Run BEFORE every build
    to clean up any orphan from a prior crashed run. Safe even if the
    key does not exist."""
    r.delete(HASH_FQDN_BUILD)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event, context):
    """Scheduled invocation (EventBridge Scheduler, every 24h).

    Build-then-RENAME atomic full rebuild. Idempotent: safe to invoke
    on demand outside the schedule.
    """
    start = datetime.now(timezone.utc)
    _emit_suppressor(True)

    try:
        # 1. Walk SSM
        params = _walk_ssm()
        logger.info(f"Walked SSM: {len(params)} parameters under {PARAM_PREFIX}")

        # 2. Connect to Valkey
        r = _get_redis()

        # 3. Cleanup any stale build-side key from a prior crashed run
        _cleanup_build_hash(r)

        # 4. Populate build-side hash + sentinel
        written = _populate_build_hash(r, params)
        logger.info(
            f"Populated build hash {HASH_FQDN_BUILD}: "
            f"{written} fields + sentinel"
        )

        # 5. Atomic swap
        _atomic_swap(r)
        logger.info(f"RENAME {HASH_FQDN_BUILD} -> {HASH_FQDN} (atomic)")

        elapsed_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000.0
        _emit_metric("FlushedKeyCount", float(written))
        _emit_metric("FlushDuration", elapsed_ms, unit="Milliseconds")

        return {
            "status": "ok",
            "flushed_key_count": written,
            "elapsed_ms": elapsed_ms,
        }

    except ClientError as err:
        logger.error(f"AWS ClientError during flush: {err}")
        _emit_metric("FlushFailures", 1)
        raise

    except redis.exceptions.RedisError as err:
        logger.error(f"RedisError during flush: {err}")
        _emit_metric("FlushFailures", 1)
        global _redis_conn
        _redis_conn = None
        raise

    except Exception:
        logger.exception("Unhandled error during flush")
        _emit_metric("FlushFailures", 1)
        raise

    finally:
        try:
            _emit_suppressor(False)
        except Exception:
            logger.warning("Failed to lower suppressor at flush end")
