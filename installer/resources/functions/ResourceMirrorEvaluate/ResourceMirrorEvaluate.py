# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource Mirror -- EvaluateResults terminal state (D14 whole-step gate).

Receives the Inline Map output array + failure_mode, tallies per-status counts,
and enforces the gate.

GATE RULE. A failure is KEYED when the failing item carries a config_key -- a
named artifact some consumer resolves through SSM. A keyed failure trips the gate
in EITHER mode, because EDH never performs a CloudFormation stack update: the
trigger is a Create-only custom resource, so a cluster handed over with a
mirrored artifact missing has no in-place repair and stays broken for its whole
life. Rolling back is recoverable; shipping it is not.

An UNKEYED failure (config_key == "", the bulk-listed GPU driver objects consumed
by a `aws s3 cp --recursive`) trips the gate only in `hard` mode. There are
hundreds of those per cluster and one of them failing should not roll back an
install; it is reported by the trigger and recorded in the run record instead.

Recovery for either case, once the underlying cause is fixed, is
`edhctl mirror recover`, which re-invokes the trigger out of band. The executor is
idempotent and repoints on the SHA-skip path, so a re-run repairs a missing key
without re-downloading.

Per the locked failure-class definition, `mirrored`/`repointed`/`skipped`/
`skipped_error`/`warn` never trip the gate -- `skip`/`warn` are author-declared
tolerable via the manifest's on_error.
"""

import json
import logging

logger = logging.getLogger("ResourceMirrorEvaluate")
logger.setLevel(logging.INFO)

# A raised gate fails the execution, and a FAILED execution has no output -- only
# an error and a cause, where lambda:invoke puts this function's errorMessage. So
# the summary rides in the message after this marker, and the trigger parses it
# back out. Keep in step with GATE_SUMMARY_MARKER in ResourceMirrorTrigger.
GATE_SUMMARY_MARKER = "GATE_SUMMARY_JSON="

# Bounds on the embedded summary. The SFN cause is capped at 32768 characters and
# also carries the stack trace, and an unkeyed failure list can run to hundreds of
# GPU driver objects. failed_config_keys is never trimmed: keyed failures are the
# operator-actionable ones and there are at most a few dozen.
_EMBED_LIST_CAP = 25
_EMBED_ERROR_CHARS = 200


class GateFailed(RuntimeError):
    """The gate tripped. A RuntimeError subclass so existing handling is unchanged;
    the distinct name is what the execution reports as its error."""


def _gate_failure(msg, summary):
    """Build the GateFailed for `msg`, carrying a bounded copy of `summary`."""
    embedded = dict(summary)
    embedded["gate"] = "fail"
    for field in ("failed_keyed", "failed_unkeyed", "failed_targets"):
        values = embedded.get(field) or []
        if len(values) > _EMBED_LIST_CAP:
            embedded[field] = values[:_EMBED_LIST_CAP]
            embedded[f"{field}_truncated"] = (
                f"showing {_EMBED_LIST_CAP} of {len(values)}"
            )
    for field in ("failed_keyed", "failed_unkeyed"):
        embedded[field] = [
            {**r, "error": (r.get("error") or "")[:_EMBED_ERROR_CHARS]}
            for r in embedded.get(field) or []
        ]
    return GateFailed(f"{msg} {GATE_SUMMARY_MARKER}{json.dumps(embedded)}")

# Statuses that do NOT trip the gate. Every one of these is a value the executor
# actually returns -- keep this set in step with it.
#
#   mirrored       downloaded, verified and repointed
#   repointed      repoint_only item (a GPU bucket-path key, no bytes to fetch)
#   skipped        SHA already matched, or repoint_only with no config_key
#   skipped_error  on_error=skip and the download failed
#   warn           on_error=warn and the download failed
#
# `repointed` was absent from this set, so every repoint_only item -- one per GPU
# driver bucket-path key, present on any install with mirror_gpu_nvidia enabled --
# fell through to the unrecognised-status branch and was counted as a FAILURE. In
# soft mode that silently inflated the reported failure count, which is the exact
# number an operator reads when diagnosing a missing key; in hard mode it would
# have rolled back every GPU-enabled install.
NON_FATAL = {"mirrored", "repointed", "skipped", "skipped_error", "warn"}

# Statuses that DO trip it. `failed_caught` arrives from the Map's Catch handler
# (the executor raised and the Task's Retry was exhausted); `failed_permanent` is
# RETURNED by the executor for a condition retrying cannot clear, so it never
# reaches the Catch and must be recognised here by name.
FAILED_STATUSES = {"failed_caught", "failed_permanent"}


def handler(event, context):
    """
    event:
      {
        "results": [ <Map output items> ],
        "failure_mode": "hard" | "soft"
      }

    A Map output item is one of:
      {"result": {...}}                               normal executor return
      {"status": "failed_caught", "item": {...}, ...} the Catch handler's Pass
    """
    results = event.get("results", []) or []
    mode = (event.get("failure_mode") or "hard").lower()

    counts = {
        "mirrored": 0,
        "repointed": 0,
        "skipped": 0,
        "skipped_error": 0,
        "warn": 0,
        "failed": 0,
    }
    failed_keyed = []  # [{"s3_target":..., "config_key":..., "error":...}]
    failed_unkeyed = []

    for item in results:
        status, s3_target, config_key, error = _classify(item)

        if status in NON_FATAL:
            counts[status] += 1
            continue

        if status not in FAILED_STATUSES:
            # Defensive: an unrecognised status counts as a failure rather than being
            # silently ignored, which is how a newly added executor return value would
            # otherwise slip past the gate. It is logged so the omission is findable.
            logger.warning(
                f"Unrecognised item status {status!r} for {s3_target}; counting as "
                f"failed. Add it to NON_FATAL or FAILED_STATUSES."
            )

        counts["failed"] += 1
        record = {
            "s3_target": s3_target,
            "config_key": config_key,
            "status": status,
            "error": error,
        }
        (failed_keyed if config_key else failed_unkeyed).append(record)

    total = sum(counts.values())
    summary = {
        "total": total,
        "counts": counts,
        "failed_keyed": failed_keyed,
        "failed_unkeyed": failed_unkeyed,
        # Retained for any consumer of the previous shape.
        "failed_targets": [
            r["s3_target"] for r in (failed_keyed + failed_unkeyed)
        ],
        "failed_config_keys": [r["config_key"] for r in failed_keyed],
        "failure_mode": mode,
    }
    logger.info(
        f"EVALUATE: mode={mode} total={total} counts={counts} "
        f"keyed_failures={len(failed_keyed)} unkeyed_failures={len(failed_unkeyed)}"
    )

    # A keyed failure is fatal in BOTH modes: there is no stack update to repair it.
    if failed_keyed:
        msg = (
            f"GATE FAILED: {len(failed_keyed)} artifact(s) with a config_key could "
            f"not be mirrored, so those SSM keys hold an upstream URL instead of the "
            f"mirror and cluster nodes will fetch them over the internet or not at "
            f"all. Config keys: {[r['config_key'] for r in failed_keyed]}. "
            f"Stack will roll back (mode={mode}; a keyed failure is fatal in either "
            f"mode because there is no in-place repair after handover)."
        )
        logger.error(msg)
        raise _gate_failure(msg, summary)

    if failed_unkeyed and mode == "hard":
        _shown = [r["s3_target"] for r in failed_unkeyed[:_EMBED_LIST_CAP]]
        _more = len(failed_unkeyed) - len(_shown)
        msg = (
            f"HARD GATE FAILED: {len(failed_unkeyed)} unkeyed artifact(s) failed: "
            f"{_shown}{f' and {_more} more' if _more else ''}. Stack will roll back."
        )
        logger.error(msg)
        raise _gate_failure(msg, summary)

    if failed_unkeyed:
        logger.warning(
            f"SOFT GATE: {len(failed_unkeyed)} unkeyed artifact(s) failed and "
            f"mode=soft, so the install proceeds. These carry no config_key and are "
            f"consumed by a recursive copy of the mirror prefix, so that prefix is "
            f"now INCOMPLETE -- run `edhctl mirror recover` once the cause is fixed: "
            f"{[r['s3_target'] for r in failed_unkeyed]}"
        )

    summary["gate"] = "pass"
    return summary


def _classify(item):
    """Return (status, s3_target, config_key, error) for one Map output item.

    Reads the whole failing item rather than individual JSONPaths, because the Catch
    handler passes the item through wholesale: a per-field JSONPath in that Pass
    state would itself fail on an item missing the field, and a failure inside the
    Pass state has no Catch above it, so it would fail the entire Map. That is
    exactly the shape a malformed manifest item produces.
    """
    if item.get("status") in FAILED_STATUSES:
        # Catch handler's Pass: {"status", "item", "error"}
        inner = item.get("item") or {}
        return (
            item["status"],
            inner.get("s3_target") or item.get("s3_target") or "<unknown>",
            inner.get("config_key") or item.get("config_key") or "",
            _stringify(item.get("error")),
        )
    result = item.get("result") or {}
    return (
        result.get("status", "unknown"),
        result.get("s3_target", "<unknown>"),
        result.get("config_key", ""),
        _stringify(result.get("error")),
    )


def _stringify(error):
    """The Catch handler hands over the whole error object because `$.error.Cause`
    is not present on every SFN error shape (a States.Timeout has no Cause), and a
    missing JSONPath in the Pass state would fail the Map."""
    if error is None:
        return ""
    if isinstance(error, str):
        return error[:1000]
    if isinstance(error, dict):
        return str(error.get("Cause") or error.get("Error") or error)[:1000]
    return str(error)[:1000]
