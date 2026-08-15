# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
SSM ElastiCache ConfigSync Lambda.

Mirrors SSM Parameter Store changes under /edh/<cluster>/ into the
cluster's Valkey configuration HASH so SocaConfig path queries hit O(1)
HGETALL instead of O(n) SSM walks.

ARCHITECTURE
============

    SSM Parameter Store Change
        |
        v
    EventBridge rule
        (filter: source=aws.ssm, detail.name prefix=/edh/<cluster>/)
        |
        v
    THIS Lambda
        - GetParameter (Create/Update) or skip (Delete)
        - HSET / HDEL the cluster's config hash
        - Emit metrics: EventsProcessed, EventsFailed, EventLatencyMs
          dimensions: ClusterId, Source=Live
        |
        v
    Valkey HASH `<cluster>:_cache_hashes/configuration`
    (read by controller via SocaConfig.get_value when feature flag is on)

CHAIN OF TRUST
==============

EventBridge events come from AWS-managed SSM service. We trust the
event payload's `name` field. The Lambda still validates that name
starts with the cluster's prefix to defend against cross-cluster
contamination if a rule is misconfigured.

Lambda runs in private subnets with SG egress to Valkey (custom port)
and to AWS APIs (443). Reads Valkey credentials from SecretsManager
at cold-start, caches the redis connection across warm invocations.

METRICS
=======

Namespace: EDH/SsmConfigSync
Dimensions: ClusterId, Source

  Source=Live    -- this Lambda (event-driven invocations)
  Source=Auditor -- ConfigAuditor Lambda (drift validator, future)
  Source=Flush   -- ConfigFlusher Lambda (24h sweep, future)

Live metrics drive ops alarms (write rate, latency, errors). Auditor
and Flush metrics drive validation alarms only -- ops alarms are
suppressed via composite-alarm SuppressorActive gauge while those
sources are running, to avoid alert storms during scheduled sweeps.

DEPLOYMENT
==========

Packaged + deployed by CDK (cdk_construct.py). Required env vars:

  EDH_CLUSTER_ID            cluster identifier (e.g. edh-dcvhs10b)
  EDH_VALKEY_ENDPOINT       Valkey hostname (host portion only)
  EDH_VALKEY_PORT           Valkey port (default 6379)
  EDH_VALKEY_CACHE_NAME     ElastiCache cache name (SigV4 IAM signing target)
  EDH_VALKEY_USER           ElastiCache IAM user id to authenticate as
  EDH_CONFIG_HASH_FQDN      full prefixed hash key, e.g.
                            /edh/<cluster>/_cache_hashes/configuration
                            (must match SocaCacheClient.key_fqdn output)

Optional:
  LOG_LEVEL                 logging verbosity, default INFO
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# redis-py provided via Lambda layer (see cdk_construct wiring).
import redis
from redis.credentials import CredentialProvider
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
import botocore.session

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
PARAM_PREFIX = f"/edh/{CLUSTER_ID}/"
VALKEY_ENDPOINT = os.environ["EDH_VALKEY_ENDPOINT"]
VALKEY_PORT = int(os.environ.get("EDH_VALKEY_PORT", "6379"))
VALKEY_CACHE_NAME = os.environ["EDH_VALKEY_CACHE_NAME"]
VALKEY_USER = os.environ["EDH_VALKEY_USER"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
HASH_FQDN = os.environ["EDH_CONFIG_HASH_FQDN"]

METRICS_NAMESPACE = "EDH/SsmConfigSync"
METRIC_SOURCE = "Live"

# Operations we respond to. LabelParameterVersion is intentionally
# excluded -- it doesn't change values, only labels.
WRITE_OPERATIONS = {"Create", "Update"}
DELETE_OPERATIONS = {"Delete"}


# ---------------------------------------------------------------------------
# AWS clients (warm-reused across invocations)
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


# Lazily initialized; reused across warm Lambda invocations.
_redis_conn = None


def _get_redis():
    """Connect to Valkey on demand. The connection is cached at module
    scope so subsequent warm invocations skip the SecretsManager round-
    trip and the TLS handshake. SocketTimeout caps tail latency on
    Valkey hiccups."""
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
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True,
    )
    return _redis_conn


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _emit_metric(metric_name: str, value: float, unit: str = "Count"):
    """Emit a CloudWatch metric with ClusterId + Source dimensions.
    Failures here are logged and swallowed -- a metric emit failure
    must not cascade into the actual sync work. The Lambda's own
    Errors metric will surface chronic problems."""
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


# ---------------------------------------------------------------------------
# Event handler
# ---------------------------------------------------------------------------


def lambda_handler(event, context):
    """
    EventBridge invocation handler.

    Expected event shape (SSM Parameter Store Change):
        {
            "source": "aws.ssm",
            "detail-type": "Parameter Store Change",
            "detail": {
                "name": "/edh/<cluster>/configuration/foo",
                "type": "String",
                "operation": "Create" | "Update" | "Delete" | "LabelParameterVersion"
            }
        }

    Returns a small dict for ease of CloudWatch-Logs filtering. Raises
    on AWS ClientError so Lambda retries / DLQ kicks in.
    """
    detail = event.get("detail", {})
    name = detail.get("name")
    operation = detail.get("operation")

    if not name or not operation:
        logger.warning(f"Malformed event (no name or operation): {event}")
        _emit_metric("EventsFailed", 1)
        return {"status": "skipped", "reason": "malformed-event"}

    # Defense-in-depth: even though EventBridge filters by prefix, verify
    # in-Lambda. Catches misconfigured rules + accidental cross-cluster
    # bleed.
    if not name.startswith(PARAM_PREFIX):
        logger.debug(
            f"Skipping out-of-prefix parameter {name} (expected {PARAM_PREFIX}*)"
        )
        return {"status": "skipped", "reason": "wrong-prefix"}

    if (
        operation not in WRITE_OPERATIONS
        and operation not in DELETE_OPERATIONS
    ):
        logger.debug(f"Skipping operation {operation} for {name}")
        return {"status": "skipped", "reason": f"operation-{operation}"}

    start = datetime.now(timezone.utc)

    try:
        r = _get_redis()

        if operation in WRITE_OPERATIONS:
            # GetParameter to fetch the new value. We do not trust event
            # payload to carry the value because EventBridge events do
            # not include parameter values for SSM by default.
            resp = ssm_client.get_parameter(Name=name)
            value = resp["Parameter"]["Value"]
            r.hset(HASH_FQDN, name, value)
            logger.info(f"HSET {HASH_FQDN} field={name}")

        else:  # operation in DELETE_OPERATIONS
            r.hdel(HASH_FQDN, name)
            logger.info(f"HDEL {HASH_FQDN} field={name}")

        elapsed_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000.0
        _emit_metric("EventsProcessed", 1)
        _emit_metric("EventLatencyMs", elapsed_ms, unit="Milliseconds")
        return {
            "status": "ok",
            "operation": operation,
            "name": name,
            "elapsed_ms": elapsed_ms,
        }

    except ClientError as err:
        # AWS-side problem (SSM throttle, SecretsManager hiccup,
        # permissions). Surface to Lambda retry/DLQ.
        logger.error(f"ClientError processing {operation} {name}: {err}")
        _emit_metric("EventsFailed", 1)
        raise

    except redis.exceptions.RedisError as err:
        # Valkey-side problem (connection drop, OOM, protocol). Same
        # retry semantics as ClientError.
        logger.error(f"RedisError processing {operation} {name}: {err}")
        _emit_metric("EventsFailed", 1)
        # Drop the cached connection so the next invocation re-handshakes.
        global _redis_conn
        _redis_conn = None
        raise

    except Exception as err:
        # Catch-all for unexpected exceptions. We still emit the
        # failure metric and re-raise to give Lambda a chance to retry.
        logger.exception(f"Unhandled error processing {operation} {name}: {err}")
        _emit_metric("EventsFailed", 1)
        raise
