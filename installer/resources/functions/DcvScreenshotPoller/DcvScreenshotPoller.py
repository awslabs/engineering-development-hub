# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DCV Screenshot Poller Lambda

Polls the DCV Session Manager Broker for session screenshots and stores them
in a dedicated S3 bucket.

Environment variables:
    EDH_CLUSTER_ID: Cluster identifier
    SCREENSHOTS_BUCKET: Dedicated bucket for screenshot storage (KMS-encrypted,
        BPA-locked, lifecycle-managed; created by CDK).
    BROKER_ENDPOINT: Backend NLB DNS for broker API
    BROKER_PORT: Broker client API port (default 8443)
    MAX_WIDTH: Screenshot max width (default 800)
    MAX_HEIGHT: Screenshot max height (default 600)

Bucket layout: keys are flat at the bucket root, "<session_id>.jpg".
The cluster id is no longer encoded in the path because the bucket itself
is per-cluster (named "<cluster>-dcv-screenshots-<account>").

Broker API contract (NICE DCV Session Manager Broker 2025.0):
- POST /describeSessions  body {} -> {RequestId, Sessions:[{Id, Owner, Type,
  State, Server:{...}, ...}]}
- POST /getSessionScreenshots  body [{SessionId, MaxWidth, MaxHeight}] ->
  {RequestId, SuccessfulList:[{SessionScreenshot:{...,
  SessionScreenshotImage:{Data: <base64>, Format: jpeg}}}], UnsuccessfulList}

Authorization is disabled at the broker (enable-authorization=false), so no
bearer/JWT is required. The broker validates that the requesting principal
matches the DCV server permission grant — see dcv_server.sh.j2 which writes
a default.perm granting `screenshot` to %any%.
"""

import base64
import json
import logging
import os
import time
import urllib3
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Disable SSL warnings for broker self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s3 = boto3.client("s3")
cloudwatch = boto3.client("cloudwatch")
http = urllib3.PoolManager(cert_reqs="CERT_NONE")

CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
# Backward-compatible env: prefer SCREENSHOTS_BUCKET, fall back to the
# legacy S3_BUCKET name during the migration window.
S3_BUCKET = os.environ.get("SCREENSHOTS_BUCKET") or os.environ["S3_BUCKET"]
BROKER_ENDPOINT = os.environ["BROKER_ENDPOINT"]
BROKER_PORT = os.environ.get("BROKER_PORT", "8443")
MAX_WIDTH = int(os.environ.get("MAX_WIDTH", "800"))
MAX_HEIGHT = int(os.environ.get("MAX_HEIGHT", "600"))
# Terminated-screenshot retention (days). Used only by the separate daily
# "expire" pass (run_expire), which a dedicated EventBridge schedule invokes
# for cluster/existing bucket modes. The poll cycle never deletes -- cleanup
# is a distinct, low-frequency process (S3 lifecycle for the dedicated bucket).
RETENTION_DAYS = int(os.environ.get("SCREENSHOT_RETENTION_DAYS", "0") or "0")
# Dedicated screenshot bucket -> flat key layout. If the legacy
# S3_BUCKET env var is in play (shared cluster bucket migration), keep
# the cluster-prefixed layout for back-compat. An explicit
# SCREENSHOTS_PREFIX (set by CDK per bucket_mode) always wins.
if os.environ.get("SCREENSHOTS_PREFIX") is not None:
    _p = os.environ["SCREENSHOTS_PREFIX"].strip().strip("/")
    SCREENSHOT_PREFIX = f"{_p}/" if _p else ""
elif os.environ.get("SCREENSHOTS_BUCKET"):
    SCREENSHOT_PREFIX = ""
else:
    SCREENSHOT_PREFIX = f"{CLUSTER_ID}/dcv/screenshots/"

BROKER_BASE = f"https://{BROKER_ENDPOINT}:{BROKER_PORT}"
COMMON_HEADERS = {"Content-Type": "application/json"}

# Custom CloudWatch namespace for SOCA/EDH DCV high-scale operational
# metrics. Per-cluster separation via ClusterId dimension. Read by the
# admin /admin/cluster_status/dcv_overview page.
METRICS_NAMESPACE = "EDH/DCVHighScale"


def _broker_post(path, body, timeout=15):
    """POST JSON to the broker, return parsed JSON dict on 2xx else None."""
    url = f"{BROKER_BASE}{path}"
    try:
        resp = http.request(
            "POST",
            url,
            body=json.dumps(body).encode("utf-8"),
            headers=COMMON_HEADERS,
            timeout=timeout,
        )
        if 200 <= resp.status < 300:
            return json.loads(resp.data.decode("utf-8"))
        logger.warning(
            "Broker POST %s returned HTTP %s: %s",
            path,
            resp.status,
            resp.data[:200].decode("utf-8", errors="replace"),
        )
    except Exception as e:
        logger.error("Broker POST %s failed: %s", path, e)
    return None


def describe_sessions():
    """List all sessions visible to the broker."""
    result = _broker_post("/describeSessions", {})
    if result is None:
        return []
    return result.get("Sessions", [])


def get_screenshots_batch(requests):
    """
    Fetch screenshots for one or more sessions in a single broker call.

    requests: list of dicts {"SessionId": str, "MaxWidth": int, "MaxHeight": int}
    returns: dict mapping SessionId -> (image_bytes, content_type)
    """
    if not requests:
        return {}
    result = _broker_post("/getSessionScreenshots", requests)
    out = {}
    if not result:
        return out

    successful = result.get("SuccessfulList", []) or []
    unsuccessful = result.get("UnsuccessfulList", []) or []

    for entry in successful:
        screenshot = entry.get("SessionScreenshot") or {}
        sid = screenshot.get("SessionId")
        # Newer broker versions return Images: [{Format, Data}]; older
        # versions returned SessionScreenshotImage: {Format, Data}. Accept
        # either shape.
        images = screenshot.get("Images") or []
        if not images and screenshot.get("SessionScreenshotImage"):
            images = [screenshot["SessionScreenshotImage"]]
        if not (sid and images):
            continue
        image = images[0]
        data_b64 = image.get("Data")
        fmt = (image.get("Format") or "jpeg").lower()
        content_type = "image/png" if fmt == "png" else "image/jpeg"
        if data_b64:
            try:
                out[sid] = (base64.b64decode(data_b64), content_type)
            except Exception as e:
                logger.warning("Failed to decode screenshot for %s: %s", sid, e)

    for entry in unsuccessful:
        req = entry.get("GetSessionScreenshotRequestData") or {}
        sid = req.get("SessionId", "<unknown>")
        reason = (entry.get("FailureReason") or "").strip()
        logger.warning("Screenshot failure for %s: %s", sid, reason)

    return out


def tag_s3_object(key, state):
    try:
        s3.put_object_tagging(
            Bucket=S3_BUCKET,
            Key=key,
            Tagging={"TagSet": [{"Key": "edh:session-state", "Value": state}]},
        )
    except s3.exceptions.NoSuchKey:
        # Expected: a session may transition through states (UNAVAILABLE,
        # CREATING, READY-but-blank, TERMINATED) without ever producing a
        # successful put_object. Tagging then has nothing to tag. This is
        # not an error -- log at DEBUG only to keep CW Logs quiet.
        logger.debug("Skipping tag for %s: object does not exist yet", key)
    except Exception as e:
        # Some SDK versions raise ClientError("NoSuchKey") instead of the
        # typed exception above; treat that the same way.
        msg = str(e)
        if "NoSuchKey" in msg or "does not exist" in msg:
            logger.debug("Skipping tag for %s (no object yet): %s", key, e)
        else:
            logger.warning("Failed to tag %s: %s", key, e)


def _key_for(sid):
    """Compose the S3 object key for a session id, handling both the
    flat layout (dedicated bucket, no prefix) and the prefixed layout
    (cluster/existing bucket). SCREENSHOT_PREFIX is "" or ends with "/"."""
    return f"{SCREENSHOT_PREFIX}{sid}.jpg"


def _list_prefix():
    """Return the prefix to pass to ListObjectsV2; empty string lists
    the whole bucket which is correct for the dedicated-bucket layout."""
    return SCREENSHOT_PREFIX


def _lifecycle_covers_screenshots():
    """Detect whether the bucket already has an enabled lifecycle
    Expiration rule covering our screenshot keys. Returns:
      True   -> a covering expiration rule exists (S3 handles cleanup; expire skips)
      False  -> no lifecycle (definitively uncovered; expire prunes by age)
      None   -> unknown (e.g. AccessDenied reading lifecycle); expire proceeds
                and prunes by age (cleaning up is the safe default).
    Lets the daily expire pass defer to a customer/operator lifecycle when one
    exists (cluster/existing modes) instead of double-cleaning."""
    try:
        resp = s3.get_bucket_lifecycle_configuration(Bucket=S3_BUCKET)
    except Exception as e:
        _code = ""
        if hasattr(e, "response"):
            _code = (e.response or {}).get("Error", {}).get("Code", "")
        if _code == "NoSuchLifecycleConfiguration":
            return False
        logger.warning("lifecycle detection inconclusive for %s: %s", S3_BUCKET, e)
        return None
    for rule in resp.get("Rules", []):
        if rule.get("Status") != "Enabled" or "Expiration" not in rule:
            continue
        # Rule prefix: legacy top-level Prefix, or Filter.Prefix / Filter.And.Prefix.
        _rp = rule.get("Prefix")
        if _rp is None:
            _f = rule.get("Filter", {}) or {}
            _rp = _f.get("Prefix")
            if _rp is None and "And" in _f:
                _rp = (_f.get("And") or {}).get("Prefix")
        _rp = _rp or ""
        # Covers us if the rule applies bucket-wide ("") or our keys fall
        # under the rule prefix.
        if _rp == "" or SCREENSHOT_PREFIX.startswith(_rp):
            return True
    return False


def list_existing_screenshots():
    """
    Enumerate all screenshot objects under the cluster's prefix.

    Returns: dict session_id -> {"key": str, "size": int, "last_modified": datetime}.
    The size + age fields are reused by the metric-publish path so we get
    bucket size / object count / max-age for free without a second listing.
    """
    out = {}
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=_list_prefix()):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith(".jpg"):
                session_id = obj["Key"].split("/")[-1].replace(".jpg", "")
                out[session_id] = {
                    "key": obj["Key"],
                    "size": obj.get("Size", 0),
                    "last_modified": obj.get("LastModified"),
                }
    return out


def _publish_metrics(metrics):
    """
    Best-effort publish of operational metrics to CloudWatch. Never raises;
    the screenshot capture path is the primary mission and metric publish
    is observability-only. Logs the metric set for offline inspection.
    """
    if not metrics:
        return
    try:
        now = datetime.now(timezone.utc)
        dims = [{"Name": "ClusterId", "Value": CLUSTER_ID}]
        metric_data = []
        for name, (value, unit) in metrics.items():
            if value is None:
                continue
            metric_data.append(
                {
                    "MetricName": name,
                    "Dimensions": dims,
                    "Timestamp": now,
                    "Value": float(value),
                    "Unit": unit,
                }
            )
        # CloudWatch put-metric-data accepts up to 1000 metric data items;
        # we publish at most ~10 per cycle.
        if metric_data:
            cloudwatch.put_metric_data(
                Namespace=METRICS_NAMESPACE, MetricData=metric_data
            )
            logger.info(
                "Published %d metrics to %s for %s",
                len(metric_data),
                METRICS_NAMESPACE,
                CLUSTER_ID,
            )
    except Exception as e:
        # Don't fail the poll cycle for a metrics-publish hiccup.
        logger.warning("PutMetricData failed: %s", e)


def run_expire():
    """Daily cleanup pass -- a SEPARATE, low-frequency process from the
    screenshot poll cycle. Deletes terminated-session screenshots older than
    RETENTION_DAYS, but only when no covering S3 lifecycle rule already
    handles expiry. A dedicated daily EventBridge schedule invokes this for
    cluster/existing bucket modes; the dedicated bucket has no expire schedule
    (its S3 lifecycle rule is the expiry mechanism)."""
    logger.info(
        "DCV Screenshot expire pass starting (cluster=%s bucket=%s prefix=%r)",
        CLUSTER_ID, S3_BUCKET, SCREENSHOT_PREFIX,
    )
    if RETENTION_DAYS <= 0:
        logger.info("RETENTION_DAYS<=0; nothing to expire")
        return {"statusCode": 200, "body": "retention disabled"}
    if _lifecycle_covers_screenshots() is True:
        logger.info("Bucket has a covering lifecycle rule; skipping poller expire")
        return {"statusCode": 200, "body": "lifecycle covers screenshots"}
    try:
        sessions = describe_sessions() or []
    except Exception as _e:
        # Can't confirm which sessions are active. Aged objects are still
        # safe to delete: active sessions are rewritten every poll cycle so
        # their last_modified stays recent (< retention).
        logger.warning("expire: describe_sessions failed (%s); pruning purely by age", _e)
        sessions = []
    active_session_ids = {s.get("Id") for s in sessions if s.get("Id")}
    now = datetime.now(timezone.utc)
    existing = list_existing_screenshots()
    pruned = 0
    for sid, obj in existing.items():
        if sid in active_session_ids:
            continue
        if obj.get("last_modified") and (now - obj["last_modified"]).total_seconds() > RETENTION_DAYS * 86400:
            try:
                s3.delete_object(Bucket=S3_BUCKET, Key=obj["key"])
                pruned += 1
            except Exception as _e:
                logger.warning("expire delete failed for %s: %s", obj["key"], _e)
    logger.info("DCV Screenshot expire pass complete: scanned=%d pruned=%d", len(existing), pruned)
    return {"statusCode": 200, "body": f"pruned={pruned}"}


def lambda_handler(event, context):
    if (event or {}).get("action") == "expire":
        return run_expire()

    logger.info("DCV Screenshot Poller starting for cluster %s", CLUSTER_ID)

    cycle_start = time.monotonic()
    broker_ok = False
    sessions = []
    updated = 0
    skipped = 0
    suppressed_blank = 0
    bucket_objects = 0
    bucket_bytes = 0
    max_age_seconds = 0

    try:
        sessions = describe_sessions()
        broker_ok = sessions is not None
        if not sessions:
            logger.info("No sessions returned from broker")
            return {"statusCode": 200, "body": "No sessions"}

        # Build screenshot request list for sessions in READY state.
        requests = []
        session_meta = {}
        for s in sessions:
            sid = s.get("Id")
            owner = s.get("Owner")
            state = s.get("State")
            if not sid or not owner:
                continue
            session_meta[sid] = {"owner": owner, "state": state}
            if state == "READY":
                requests.append(
                    {"SessionId": sid, "MaxWidth": MAX_WIDTH, "MaxHeight": MAX_HEIGHT}
                )

        screenshots = get_screenshots_batch(requests) if requests else {}

        active_session_ids = set(session_meta.keys())

        # Threshold (bytes) below which a returned image is treated as "blank"
        # (lock screen, no display, screensaver, disconnected) and we keep the
        # last known good thumbnail instead of overwriting. Empirically:
        #   * a fully-blank/all-uniform 400x300 PNG compresses to a few hundred bytes
        #   * a Linux GDM login screen (simple gradient) is 1-3 KB
        #   * a real desktop with windows/UI is 20-200 KB
        # We want to suppress the FIRST class while letting real (if simple)
        # screens through, including login screens -- otherwise users have no
        # visual feedback that "the VDI booted, just nobody's logged in yet".
        BLANK_IMAGE_BYTES_THRESHOLD = 1024

        # Sessions that already have a stored screenshot. The blank/small
        # suppression below only applies once a session has a prior shot --
        # the FIRST screenshot is always allowed through (even if tiny) so a
        # freshly-booted VDI shows something live instead of the default OS
        # icon placeholder.
        existing_ids = set(list_existing_screenshots().keys())

        for sid, meta in session_meta.items():
            s3_key = _key_for(sid)
            state = meta["state"]
            if state == "READY":
                entry = screenshots.get(sid)
                if entry:
                    data, content_type = entry
                    if len(data) < BLANK_IMAGE_BYTES_THRESHOLD and sid in existing_ids:
                        logger.info(
                            "Suppressing likely-blank screenshot for %s: %d bytes < threshold %d (lock screen / screensaver / no display)",
                            sid,
                            len(data),
                            BLANK_IMAGE_BYTES_THRESHOLD,
                        )
                        # Refresh the tag so the dashboard knows the session
                        # is still alive even though we kept the previous shot.
                        tag_s3_object(s3_key, "READY_BLANK_SUPPRESSED")
                        suppressed_blank += 1
                    else:
                        s3.put_object(
                            Bucket=S3_BUCKET,
                            Key=s3_key,
                            Body=data,
                            ContentType=content_type,
                            # Capture timestamp surfaces in the UI as "age"
                            # of the thumbnail. ISO-8601 UTC. Read by the
                            # SOCA list_virtual_desktops API via head_object
                            # then rendered under the card.
                            Metadata={
                                "captured-at": datetime.now(timezone.utc).isoformat(),
                                "size-bytes": str(len(data)),
                                "content-type": content_type,
                            },
                        )
                        tag_s3_object(s3_key, "READY")
                        updated += 1
                else:
                    # Broker reported READY but no image — likely permission issue
                    # on the DCV server, network blip, or transient mid-launch.
                    skipped += 1
            elif state in ("UNAVAILABLE",):
                # READY but no agent — keep prior shot, just refresh the tag.
                tag_s3_object(s3_key, "UNAVAILABLE")
                skipped += 1
            else:
                tag_s3_object(s3_key, state or "UNKNOWN")
                skipped += 1

        # Single bucket listing reused for two purposes: TERMINATED tagging
        # for vanished sessions, AND derivation of bucket-level stats
        # (object count / total bytes / oldest-shot age) which we publish
        # to CloudWatch so the admin status page doesn't need to re-list.
        existing = list_existing_screenshots()
        bucket_objects = len(existing)
        bucket_bytes = sum(o.get("size", 0) for o in existing.values())
        now = datetime.now(timezone.utc)
        # Only consider ACTIVE sessions when computing max-age, so stale
        # TERMINATED orphans don't permanently trip the MaxAge alarm.
        # The action signal is "session is alive but its shot isn't
        # refreshing", not "an old terminated shot is lingering".
        active_ages = [
            (now - o["last_modified"]).total_seconds()
            for sid, o in existing.items()
            if sid in active_session_ids and o.get("last_modified")
        ]
        max_age_seconds = int(max(active_ages)) if active_ages else 0

        # Tag (don't delete) orphans here -- cleanup is the separate daily
        # expire pass (run_expire). Tagging is cheap and surfaces TERMINATED
        # state on the status page each poll cycle.
        for sid, obj in existing.items():
            if sid not in active_session_ids:
                tag_s3_object(obj["key"], "TERMINATED")

        result = {
            "sessions": len(sessions),
            "updated": updated,
            "skipped": skipped,
            "suppressed_blank": suppressed_blank,
            "bucket_objects": bucket_objects,
            "bucket_bytes": bucket_bytes,
            "max_age_seconds": max_age_seconds,
        }
        logger.info("Screenshot poll complete: %s", result)
        return {"statusCode": 200, "body": json.dumps(result)}
    finally:
        # Always publish operational metrics, even on broker failure or
        # mid-cycle exception. Lets the admin page surface "broker
        # unreachable" via the BrokerErrors metric instead of going dark.
        cycle_ms = int((time.monotonic() - cycle_start) * 1000)
        _publish_metrics({
            "ScreenshotsCaptured": (updated, "Count"),
            "ScreenshotsSkipped": (skipped, "Count"),
            "ScreenshotsSuppressedBlank": (suppressed_blank, "Count"),
            "ScreenshotsActiveSessions": (len(sessions) if sessions else 0, "Count"),
            "ScreenshotsBucketObjects": (bucket_objects, "Count"),
            "ScreenshotsBucketBytes": (bucket_bytes, "Bytes"),
            "ScreenshotsMaxAgeSeconds": (max_age_seconds, "Seconds"),
            "ScreenshotPollerDuration": (cycle_ms, "Milliseconds"),
            "ScreenshotsBrokerErrors": (0 if broker_ok else 1, "Count"),
        })
