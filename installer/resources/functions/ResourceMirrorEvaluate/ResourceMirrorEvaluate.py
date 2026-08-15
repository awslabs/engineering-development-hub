# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource Mirror — EvaluateResults terminal state (D14 whole-step gate).

Receives the Inline Map output array + failure_mode, tallies per-status counts,
and enforces the gate: in `hard` mode any failed-class item (on_error=fail that
exhausted) raises -> SFN execution ends FAILED -> install-time custom resource
reports FAILED -> CFN rolls back. In `soft` mode it always returns a summary
(install proceeds; consumers fall back to the |original pipe-string).

Per the locked failure-class definition: ONLY `failed_caught` items count toward
the gate. `skipped`/`skipped_error`/`warn`/`mirrored` never trip it — `skip`/`warn`
are author-declared tolerable via the manifest's on_error.
"""

import logging

logger = logging.getLogger("ResourceMirrorEvaluate")
logger.setLevel(logging.INFO)

# Statuses that do NOT trip the hard gate.
NON_FATAL = {"mirrored", "skipped", "skipped_error", "warn"}


def handler(event, context):
    """
    event:
      {
        "results": [ <Map output items> ],   # each is {"result": {...}} or {"status": "failed_caught", ...}
        "failure_mode": "hard" | "soft"
      }
    """
    results = event.get("results", []) or []
    mode = (event.get("failure_mode") or "hard").lower()

    counts = {"mirrored": 0, "skipped": 0, "skipped_error": 0, "warn": 0, "failed": 0}
    failed_targets = []

    for item in results:
        # Caught failures arrive as a bare {"status": "failed_caught", ...} (from the
        # Map's Catch handler); normal item results are wrapped as {"result": {...}}.
        if item.get("status") == "failed_caught":
            counts["failed"] += 1
            failed_targets.append(item.get("s3_target", "<unknown>"))
            continue
        status = (item.get("result") or {}).get("status", "unknown")
        if status in counts:
            counts[status] += 1
        elif status not in NON_FATAL:
            # Defensive: an unrecognized non-NON_FATAL status is treated as a failure.
            counts["failed"] += 1
            failed_targets.append((item.get("result") or {}).get("s3_target", "<unknown>"))

    total = sum(counts.values())
    summary = {
        "total": total,
        "counts": counts,
        "failed_targets": failed_targets,
        "failure_mode": mode,
    }
    logger.info(f"EVALUATE: mode={mode} total={total} counts={counts}")

    if counts["failed"] > 0 and mode == "hard":
        msg = (
            f"HARD GATE FAILED: {counts['failed']} artifact(s) failed "
            f"(on_error=fail): {failed_targets}. Stack will roll back."
        )
        logger.error(msg)
        raise RuntimeError(msg)

    if counts["failed"] > 0:
        logger.warning(
            f"SOFT GATE: {counts['failed']} artifact(s) failed but mode=soft; "
            f"install proceeds, consumers fall back to |original: {failed_targets}"
        )

    summary["gate"] = "pass"
    return summary
