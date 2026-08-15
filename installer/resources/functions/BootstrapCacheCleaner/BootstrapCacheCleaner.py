# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
BootstrapCacheCleaner -- EventBridge-scheduled Lambda that ages out
old entries from the BootstrapTemplateCache.

The cluster S3 bucket is operator-supplied, so SOCA cannot install a
bucket-wide lifecycle policy. This Lambda runs on a weekly schedule
under SOCA-owned IAM (no bucket-config write permissions needed) and
deletes cache entries whose .stack_meta.json marker is older than
RETENTION_DAYS. Bodies under the entry prefix are deleted along with
the marker.

Trigger
-------
EventBridge cron rule: 0 3 ? * SUN * (every Sunday at 03:00 UTC).

Configuration
-------------
Driven by Lambda env vars set at CDK time:
    BUCKET           cluster S3 bucket name
    PREFIX           cache prefix (e.g. <cluster_id>/bootstrap/cache/)
    RETENTION_DAYS   integer; entries older than this are deleted.
                     Default 30 if env var is missing.

Idempotency
-----------
Re-running on the same input is safe: deleted entries don't reappear.
Concurrent runs are theoretically possible if EventBridge double-fires;
S3 DeleteObjects is idempotent so the worst case is one of the two
runs sees "object not found" warnings.

Observability
-------------
Returns a dict for CW Logs / EventBridge invocation history:
    {
        "entries_scanned": int,
        "entries_aged": int,           # passed retention check
        "objects_deleted": int,        # markers + bodies combined
        "retention_days": int,
        "prefix": str,
    }
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BUCKET = os.environ["BUCKET"]
PREFIX = os.environ["PREFIX"].rstrip("/") + "/"  # ensure trailing slash
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))

MARKER_NAME = ".stack_meta.json"


def _list_marker_keys(s3, bucket: str, prefix: str) -> list[dict[str, Any]]:
    """Yield every `.stack_meta.json` object under `prefix` (any depth).
    Returns dicts with `Key` and `LastModified` (datetime).
    """
    out: list[dict[str, Any]] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents") or []:
            if obj["Key"].endswith(f"/{MARKER_NAME}"):
                out.append(obj)
    return out


def _delete_entry(s3, bucket: str, entry_prefix: str) -> int:
    """Delete every object under `entry_prefix` (the cache entry's
    sub-prefix). Returns the number of objects deleted.
    """
    paginator = s3.get_paginator("list_objects_v2")
    deleted = 0
    for page in paginator.paginate(Bucket=bucket, Prefix=entry_prefix):
        keys = [{"Key": obj["Key"]} for obj in page.get("Contents") or []]
        if not keys:
            continue
        # delete_objects accepts up to 1000 per call; cache entries
        # have ~6 bodies + marker so we'll always be well under.
        s3.delete_objects(
            Bucket=bucket, Delete={"Objects": keys, "Quiet": True}
        )
        deleted += len(keys)
    return deleted


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    s3 = boto3.client("s3")
    cutoff = time.time() - (RETENTION_DAYS * 86400)
    logger.info(
        "BootstrapCacheCleaner sweep bucket=%s prefix=%s retention_days=%d",
        BUCKET,
        PREFIX,
        RETENTION_DAYS,
    )

    markers = _list_marker_keys(s3, BUCKET, PREFIX)
    aged_entries: list[str] = []
    objects_deleted = 0

    for marker in markers:
        if marker["LastModified"].timestamp() >= cutoff:
            continue
        # The entry prefix is the marker's parent folder.
        entry_prefix = marker["Key"].rsplit("/", 1)[0] + "/"
        logger.info(
            "BootstrapCacheCleaner aging entry %s (marker LastModified=%s)",
            entry_prefix,
            marker["LastModified"].isoformat(),
        )
        try:
            objects_deleted += _delete_entry(s3, BUCKET, entry_prefix)
            aged_entries.append(entry_prefix)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception(
                "Failed to delete entry %s: %s; skipping (will retry next run)",
                entry_prefix,
                exc,
            )

    summary = {
        "entries_scanned": len(markers),
        "entries_aged": len(aged_entries),
        "objects_deleted": objects_deleted,
        "retention_days": RETENTION_DAYS,
        "prefix": PREFIX,
    }
    logger.info("BootstrapCacheCleaner summary: %r", summary)
    return summary
