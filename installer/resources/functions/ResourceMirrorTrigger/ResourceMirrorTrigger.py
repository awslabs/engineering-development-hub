# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource Mirror Trigger -- CDK Custom Resource Lambda, and the out-of-band
recovery entry point.

Reads the manifest from S3 (boto3, region from the installer's BucketRegion hint --
the bucket may be in a different region than the install cluster, D15), parses it,
and fires the SFN with the items array passed INLINE (no SFN-native getObject, which
is region-pinned). BLOCKS until the execution reaches a terminal state, then maps
the result to the CFN custom-resource response.

The trigger reads only the small manifest LIST -- the heavy per-artifact downloads
still fan out one-executor-Lambda-per-item under the SFN Inline Map (D1, unchanged).

TWO INVOCATION SHAPES:

1. CloudFormation custom resource (the event carries RequestType).
   - Delete: no-op SUCCESS (mirror artifacts retained; idempotent for re-install).
   - MirroringMethod=install-host (D10): no-op SUCCESS (cloud executor skipped).
   - Create/Update: read manifest -> start execution (items inline) -> poll ->
     SUCCESS iff SUCCEEDED.

2. Direct invoke (no RequestType), used by `edhctl mirror recover`. EDH never
   performs a CloudFormation stack update, so this custom resource fires exactly
   once in a cluster's life and its Update branch is unreachable in practice --
   which means a CFN-driven re-run is NOT a repair path. This is. It takes the
   same manifest and state machine from the environment, so an operator supplies
   nothing but an optional list of config keys to retry.

REPORTING. A terminal run always leaves two records behind: the failure detail is
logged at ERROR (not swallowed into a SUCCESS with no detail), and a run record is
written to SSM at RUN_RECORD_KEY. That key is the only artifact that outlives the
SFN's own execution history, which sits in a vendedlogs group retained for two
weeks.

Bounded by the Lambda timeout. For the 2-4 GB / dozens-of-artifacts catalog this
finishes in minutes. A future thousands-scale catalog would switch to Distributed
Map (S3 ItemReader) + the async SFN-terminal -> CFN response-URL callback.
"""

import json
import logging
import os
import time
import uuid

import boto3
import cfnresponse
from botocore.exceptions import ClientError

logger = logging.getLogger("ResourceMirrorTrigger")
logger.setLevel(logging.INFO)

sfn = boto3.client("stepfunctions")
ssm = boto3.client("ssm")

POLL_INTERVAL_SEC = 10
SAFETY_MARGIN_MS = 30_000  # respond to CFN before the Lambda times out
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}

# Populated by the CDK construct. Duplicated from the CustomResource properties so
# the recovery path, which has no ResourceProperties, needs no operator input.
CLUSTER_ID = os.environ.get("CLUSTER_ID", "")
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")
MANIFEST_BUCKET = os.environ.get("MANIFEST_BUCKET", "")
MANIFEST_KEY = os.environ.get("MANIFEST_KEY", "")
BUCKET_REGION = os.environ.get("BUCKET_REGION", "") or None
FAILURE_MODE = os.environ.get("FAILURE_MODE", "hard")
MIRRORING_METHOD = os.environ.get("MIRRORING_METHOD", "cloud-no-vpc")
RUN_RECORD_KEY = os.environ.get("RUN_RECORD_KEY", "")


def handler(event, context):
    """Dispatch on invocation shape. A CFN custom-resource event always carries
    RequestType; anything else is an out-of-band recovery invoke and must NOT reach
    cfnresponse, which would POST to a response URL that is not there."""
    if event.get("RequestType"):
        return _handle_cloudformation(event, context)
    try:
        return _handle_recovery(event, context)
    except Exception as e:
        # Guards the whole recovery body, not only the run: a malformed manifest
        # raises ValueError from _load_manifest, and start_execution can raise
        # before _run_mirror writes anything. Returned rather than raised so
        # edhctl reports it as an error instead of an unhandled FunctionError.
        logger.error(f"Recovery error: {e}")
        _write_error_record("recovery", MIRRORING_METHOD, FAILURE_MODE, e)
        return {"status": "ERROR", "error": str(e)[:1000]}


# ---------------------------------------------------------------------------
# CloudFormation custom resource
# ---------------------------------------------------------------------------


def _handle_cloudformation(event, context):
    request_type = event["RequestType"]
    props = event["ResourceProperties"]
    state_machine_arn = props["StateMachineArn"]
    method = props.get("MirroringMethod", "cloud-no-vpc")
    failure_mode = props.get("FailureMode", "hard")
    manifest_bucket = props.get("ManifestBucket", "")
    manifest_key = props.get("ManifestKey", "")
    bucket_region = props.get("BucketRegion") or None  # installer header-probe hint

    try:
        if request_type == "Delete":
            logger.info("Delete -- no-op, mirror artifacts retained.")
            return _respond(event, context, True, {"Message": "Delete no-op"})

        if method == "install-host":
            logger.info("MirroringMethod=install-host -- cloud executor skipped (D10).")
            return _respond(event, context, True,
                            {"Message": "Skipped: install-host method"})

        # Read + parse the manifest (small list) using a region-aware client.
        try:
            items = _load_manifest(manifest_bucket, manifest_key, bucket_region)
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404", "NoSuchBucket"):
                msg = (f"Manifest absent: s3://{manifest_bucket}/{manifest_key}")
                if failure_mode == "soft":
                    logger.warning(f"{msg}; failure_mode=soft -- no-op SUCCESS, "
                                   f"cluster proceeds unmirrored.")
                    _write_run_record({
                        "status": "MANIFEST_ABSENT",
                        "trigger": request_type,
                        "message": msg,
                        "note": ("Every mirrored config key is left holding its "
                                 "upstream URL; no artifact was mirrored."),
                    })
                    return _respond(event, context, True,
                                    {"Message": "Manifest absent; soft no-op"})
                logger.error(f"{msg}; failure_mode=hard -- failing.")
                _write_run_record({
                    "status": "MANIFEST_ABSENT",
                    "trigger": request_type,
                    "message": msg,
                })
                return _respond(event, context, False, {"Error": msg})
            raise
        logger.info(f"Manifest loaded: {len(items)} item(s) from "
                    f"s3://{manifest_bucket}/{manifest_key} (region={bucket_region})")

        outcome = _run_mirror(
            state_machine_arn=state_machine_arn,
            items=items,
            failure_mode=failure_mode,
            trigger_type={"Create": "install", "Update": "update"}.get(
                request_type, request_type.lower()
            ),
            method=method,
            context=context,
        )

        data = {
            "ExecutionArn": outcome["execution_arn"],
            "Status": outcome["status"],
            "ItemCount": str(len(items)),
            # Surfaced on the CFN resource itself so a soft-gated run that shipped
            # with missing artifacts is visible without opening a log group.
            "FailedCount": str(outcome["failed_count"]),
            "FailedConfigKeys": ",".join(outcome["failed_config_keys"])[:900] or "none",
        }

        if outcome["status"] == "SUCCEEDED":
            logger.info(f"Mirror SUCCEEDED: {outcome['execution_arn']}")
            return _respond(event, context, True, data,
                            physical_id=outcome["execution_arn"])

        logger.error(f"Mirror did not succeed ({outcome['status']}): "
                     f"{outcome['cause']}")
        data["Cause"] = (outcome["cause"] or "")[:1000]
        return _respond(event, context, False, data,
                        physical_id=outcome["execution_arn"])

    except Exception as e:
        logger.error(f"Trigger error: {e}")
        if request_type != "Delete":
            _write_error_record(request_type, method, failure_mode, e)
        return _respond(event, context, False, {"Error": str(e)})


# ---------------------------------------------------------------------------
# Out-of-band recovery (edhctl mirror recover)
# ---------------------------------------------------------------------------


def _handle_recovery(event, context):
    """Re-run the mirror without CloudFormation.

    event (all optional):
      {
        "action": "recover",
        "config_keys": ["/edh/<cluster>/system/openmpi/url", "/system/cjson/url"],
        "failure_mode": "soft" | "hard",
        "dry_run": false
      }

    config_keys selects which manifest items to retry; an entry matches an item
    whose config_key is equal to it or ends with it, so an operator can pass either
    the full SSM name or the cluster-relative suffix. Omitted means every item --
    which is cheap, because the executor skips any artifact whose SHA already
    matches and still repoints its key on that path.
    """
    action = event.get("action", "recover")
    if action != "recover":
        return {"status": "ERROR", "error": f"Unsupported action {action!r}"}

    if not STATE_MACHINE_ARN or not MANIFEST_BUCKET or not MANIFEST_KEY:
        return {
            "status": "ERROR",
            "error": ("This function predates the recovery path: STATE_MACHINE_ARN / "
                      "MANIFEST_BUCKET / MANIFEST_KEY are not in its environment."),
        }

    if MIRRORING_METHOD == "install-host":
        return {
            "status": "SKIPPED",
            "error": ("Cluster was installed with method=install-host, so no cloud "
                      "mirror ran and there is nothing to recover. Those keys are "
                      "written directly by the installer."),
        }

    try:
        items = _load_manifest(MANIFEST_BUCKET, MANIFEST_KEY, BUCKET_REGION)
    except ClientError as ce:
        # Recorded like the ValueError path that handler() catches, so either
        # kind of unreadable manifest replaces the previous run's record.
        _err = (f"Cannot read manifest s3://{MANIFEST_BUCKET}/{MANIFEST_KEY}: "
                f"{ce}")
        logger.error(f"Recovery error: {_err}")
        _write_error_record("recovery", MIRRORING_METHOD, FAILURE_MODE, _err)
        return {"status": "ERROR", "error": _err}

    requested = event.get("config_keys") or []
    selected = _select_items(items, requested)
    if not selected:
        return {
            "status": "ERROR",
            "error": (f"No manifest item matched {requested}. The manifest holds "
                      f"{len(items)} item(s)."),
            "available_config_keys": sorted(
                {i.get("config_key", "") for i in items if i.get("config_key")}
            ),
        }

    failure_mode = (event.get("failure_mode") or FAILURE_MODE).lower()

    if event.get("dry_run"):
        return {
            "status": "DRY_RUN",
            "selected_count": len(selected),
            "manifest_count": len(items),
            "failure_mode": failure_mode,
            "selected_config_keys": [
                i.get("config_key", "") for i in selected if i.get("config_key")
            ],
        }

    logger.info(f"RECOVERY: re-running {len(selected)} of {len(items)} manifest "
                f"item(s), failure_mode={failure_mode}")

    outcome = _run_mirror(
        state_machine_arn=STATE_MACHINE_ARN,
        items=selected,
        failure_mode=failure_mode,
        trigger_type="recovery",
        method=MIRRORING_METHOD,
        context=context,
    )

    return {
        "status": outcome["status"],
        "execution_arn": outcome["execution_arn"],
        "item_count": len(selected),
        "manifest_count": len(items),
        "failed_count": outcome["failed_count"],
        "failed_config_keys": outcome["failed_config_keys"],
        "summary": outcome["summary"],
        "cause": (outcome["cause"] or "")[:1000],
    }


def _select_items(items, requested):
    """Items whose config_key matches any requested key exactly or by suffix.

    An empty request selects everything. A requested key that matches nothing is
    reported by the caller rather than silently dropped, because a typo would
    otherwise look like a successful no-op recovery.
    """
    if not requested:
        return list(items)
    wanted = [r for r in (s.strip() for s in requested) if r]
    out = []
    for item in items:
        key = item.get("config_key") or ""
        if not key:
            continue
        if any(key == w or key.endswith(w) for w in wanted):
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Shared run path
# ---------------------------------------------------------------------------


def _run_mirror(state_machine_arn, items, failure_mode, trigger_type, method,
                context):
    """Stamp the items, start the execution, block to terminal, then report.

    Returns a dict with status, execution_arn, cause, summary, failed_count and
    failed_config_keys. Always logs a terminal failure at ERROR and always writes
    the run record, so neither caller can report a clean result over a dirty run.
    """
    # Pre-generate the execution name so we can stamp it onto each item BEFORE
    # starting (the executor records sfn_execution_id from the item for provenance).
    # Passing it as the execution `name` keeps the ARN and the stamped id consistent.
    execution_name = f"mirror-{uuid.uuid4()}"
    for _item in items:
        _item["sfn_execution_id"] = execution_name
        _item["trigger_type"] = trigger_type

    execution_arn = sfn.start_execution(
        stateMachineArn=state_machine_arn,
        name=execution_name,
        input=json.dumps({"items": items, "failure_mode": failure_mode}),
    )["executionArn"]
    logger.info(f"Started execution: {execution_arn} "
                f"(failure_mode={failure_mode}, trigger={trigger_type})")

    status, cause, output = _poll_to_terminal(execution_arn, context)
    summary = _extract_summary(output)
    if not summary and status == "FAILED":
        # A tripped gate fails the execution, so there is no output to read; the
        # gate carried its summary in the cause instead. Without this a gate
        # failure reported Failed 0 with no keys -- on the run that failed.
        summary, cause = _summary_from_cause(cause)

    failed_keyed = summary.get("failed_keyed") or []
    failed_unkeyed = summary.get("failed_unkeyed") or []
    failed_config_keys = summary.get("failed_config_keys")
    if not isinstance(failed_config_keys, list):
        failed_config_keys = [
            r.get("config_key", "") for r in failed_keyed if r.get("config_key")
        ]
    # counts["failed"] is the true total; the lists may be trimmed when the
    # summary arrived through the cause.
    failed_count = (summary.get("counts") or {}).get("failed")
    if not isinstance(failed_count, int):
        failed_count = len(failed_keyed) + len(failed_unkeyed)

    # A SUCCEEDED execution can still carry per-item failures: the Map's Catch keeps
    # one bad artifact from cancelling its siblings, and the gate tolerates an
    # unkeyed failure in soft mode. Reporting only the execution status would hand
    # back a clean SUCCESS over a run that did not mirror everything.
    if failed_count:
        logger.error(
            f"MIRROR INCOMPLETE: {failed_count} artifact(s) failed "
            f"(execution status {status}). "
            f"Keyed: {[r.get('config_key') for r in failed_keyed]}. "
            f"Unkeyed: {[r.get('s3_target') for r in failed_unkeyed]}. "
            f"Re-run with `edhctl mirror recover` once the cause is fixed."
        )
    elif status == "SUCCEEDED":
        logger.info(f"Mirror complete: {summary.get('counts')}")

    _write_run_record({
        "status": status,
        "trigger": trigger_type,
        "method": method,
        "failure_mode": failure_mode,
        "execution_arn": execution_arn,
        "item_count": len(items),
        "failed_count": failed_count,
        "failed_config_keys": failed_config_keys,
        "failed_targets": summary.get("failed_targets") or [],
        "counts": summary.get("counts") or {},
        "cause": (cause or "")[:500],
    })

    return {
        "status": status,
        "execution_arn": execution_arn,
        "cause": cause,
        "summary": summary,
        "failed_count": failed_count,
        "failed_config_keys": failed_config_keys,
    }


def _load_manifest(bucket, key, region):
    """Read + parse the manifest JSON from S3. Region-aware (D15) -- the bucket may
    be in a different region than this Lambda. Accepts either a bare items array
    or an object with an "items" key."""
    s3 = boto3.client("s3", region_name=region) if region else boto3.client("s3")
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    data = json.loads(body)
    items = data["items"] if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError(f"Manifest must be a list or {{items:[...]}}, got {type(items)}")
    return items


def _poll_to_terminal(execution_arn, context):
    """Poll DescribeExecution until terminal or until the Lambda is about to time
    out. Returns (status, cause, output). A poll-timeout returns
    ('TIMED_OUT_POLL', msg, None).

    `output` is the EvaluateResults payload and is present only on SUCCEEDED -- a
    FAILED execution carries cause/error instead, because the gate raised.
    """
    while True:
        desc = sfn.describe_execution(executionArn=execution_arn)
        status = desc["status"]
        if status in TERMINAL:
            return status, desc.get("cause", ""), desc.get("output")
        if context.get_remaining_time_in_millis() < SAFETY_MARGIN_MS:
            msg = (f"Lambda timeout approaching; execution still {status}. "
                   f"Aborting wait -- treating as failure for safety.")
            logger.error(msg)
            return "TIMED_OUT_POLL", msg, None
        time.sleep(POLL_INTERVAL_SEC)


def _extract_summary(output):
    """Pull the EvaluateResults summary out of the execution output.

    The state machine's last state wraps it as {"summary": {...}} via ResultSelector,
    and the whole output is absent on a FAILED execution. Every unwrap step is
    tolerant because a malformed or missing output must not turn a reportable run
    into an exception in the reporting code itself.
    """
    if not output:
        return {}
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError) as err:
        logger.warning(f"Could not parse execution output: {err}")
        return {}
    if not isinstance(parsed, dict):
        return {}
    summary = parsed.get("summary")
    return summary if isinstance(summary, dict) else {}


# Keep in step with GATE_SUMMARY_MARKER in ResourceMirrorEvaluate.
GATE_SUMMARY_MARKER = "GATE_SUMMARY_JSON="


def _summary_from_cause(cause):
    """Recover the gate's summary from a FAILED execution's cause.

    lambda:invoke sets the cause to the function's error payload as a JSON string,
    {"errorMessage", "errorType", "stackTrace", ...}, and the gate appends its
    summary to errorMessage after GATE_SUMMARY_MARKER. Returns (summary, cause)
    where cause is the human-readable message without the embedded JSON, or
    ({}, cause) unchanged when the failure was not the gate. Tolerant throughout:
    the reporting path must not raise over a cause it cannot read.
    """
    text = cause or ""
    try:
        payload = json.loads(text)
        if isinstance(payload, dict) and isinstance(payload.get("errorMessage"), str):
            text = payload["errorMessage"]
    except (TypeError, ValueError):
        pass
    head, sep, tail = text.partition(GATE_SUMMARY_MARKER)
    if not sep:
        return {}, cause
    try:
        summary = json.loads(tail)
    except (TypeError, ValueError) as err:
        logger.warning(f"Could not parse the gate summary from the cause: {err}")
        return {}, cause
    if not isinstance(summary, dict):
        return {}, cause
    return summary, head.rstrip()


# A Standard-tier SSM parameter value is capped at 4096 bytes. An unkeyed failure
# list can run to hundreds of GPU driver objects, so the record is trimmed to fit
# rather than being rejected at PutParameter time -- a run record that fails to
# write is exactly the silence this key exists to remove. Keyed failures are the
# operator-actionable ones, so they are trimmed last.
_RUN_RECORD_MAX_BYTES = 3800
_RUN_RECORD_LIST_CAP = 25


def _write_error_record(trigger, method, failure_mode, err):
    """Run record for a run that ended in an exception rather than a terminal
    execution state, so `edhctl mirror status` never shows an older run's record
    over one that failed. No counts are recorded because none are known."""
    _write_run_record({
        "status": "ERROR",
        "trigger": trigger,
        "method": method,
        "failure_mode": failure_mode,
        "cause": str(err)[:500],
    })


def _write_run_record(record):
    """Persist the run outcome to SSM.

    Best-effort by design: a failure to write the record must not change the
    install's outcome, and swallowing it here is safe precisely because the same
    detail was already logged at ERROR by the caller. Without this key the only
    record of a run is the Lambda log group and a vendedlogs SFN group retained for
    two weeks, so an older install leaves nothing an operator can read.
    """
    if not RUN_RECORD_KEY:
        logger.warning("RUN_RECORD_KEY not set; skipping run record.")
        return
    record["cluster_id"] = CLUSTER_ID
    record["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        ssm.put_parameter(
            Name=RUN_RECORD_KEY,
            Value=_bounded_record_json(record),
            Type="String",
            Overwrite=True,
        )
        logger.info(f"RUN RECORD: {RUN_RECORD_KEY} status={record.get('status')} "
                    f"failed={record.get('failed_count')}")
    except Exception as err:
        logger.warning(f"Could not write run record to {RUN_RECORD_KEY}: {err}")


def _bounded_record_json(record):
    """Serialise the record, trimming its list fields until it fits the parameter
    value limit. The counts always survive, so `failed_count` remains the true
    total even when the enumerated names were truncated -- a reader must not
    mistake a trimmed list for the whole picture, hence the explicit
    `*_truncated` markers.
    """
    trimmed = dict(record)
    # Least actionable first: unkeyed targets, then the cause text, then keys.
    for field in ("failed_targets", "failed_config_keys"):
        values = trimmed.get(field) or []
        if len(values) > _RUN_RECORD_LIST_CAP:
            trimmed[field] = values[:_RUN_RECORD_LIST_CAP]
            trimmed[f"{field}_truncated"] = (
                f"showing {_RUN_RECORD_LIST_CAP} of {len(values)}"
            )

    payload = json.dumps(trimmed, default=str)
    if len(payload.encode("utf-8")) <= _RUN_RECORD_MAX_BYTES:
        return payload

    for field in ("failed_targets", "cause", "failed_config_keys"):
        if field in trimmed:
            trimmed[field] = [] if isinstance(trimmed[field], list) else ""
            trimmed[f"{field}_omitted"] = "too large for the parameter value limit"
        payload = json.dumps(trimmed, default=str)
        if len(payload.encode("utf-8")) <= _RUN_RECORD_MAX_BYTES:
            return payload

    # Nothing left to drop that is not load-bearing: keep the counts, which are the
    # part a reader needs to know a run was incomplete at all.
    return json.dumps(
        {
            "status": trimmed.get("status"),
            "cluster_id": trimmed.get("cluster_id"),
            "completed_at": trimmed.get("completed_at"),
            "execution_arn": trimmed.get("execution_arn"),
            "failed_count": trimmed.get("failed_count"),
            "counts": trimmed.get("counts"),
            "record_truncated": "detail exceeded the parameter value limit",
        },
        default=str,
    )


def _respond(event, context, success, data, physical_id=None):
    status = cfnresponse.SUCCESS if success else cfnresponse.FAILED
    cfnresponse.send(event, context, status, data, physicalResourceId=physical_id)
    return data
