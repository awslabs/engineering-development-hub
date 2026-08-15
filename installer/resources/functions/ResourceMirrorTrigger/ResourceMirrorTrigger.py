# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource Mirror Trigger — CDK Custom Resource Lambda (install-time gate).

Reads the manifest from S3 (boto3, region from the installer's BucketRegion hint —
the bucket may be in a different region than the install cluster, D15), parses it,
and fires the SFN with the items array passed INLINE (no SFN-native getObject, which
is region-pinned). BLOCKS until the execution reaches a terminal state, then maps
the result to the CFN custom-resource response.

The trigger reads only the small manifest LIST — the heavy per-artifact downloads
still fan out one-executor-Lambda-per-item under the SFN Inline Map (D1, unchanged).

- Delete: no-op SUCCESS (mirror artifacts retained; idempotent for re-install).
- MirroringMethod=install-host (D10): no-op SUCCESS (cloud executor skipped).
- Create/Update: read manifest -> start execution (items inline) -> poll -> SUCCESS iff SUCCEEDED.

Bounded by the Lambda timeout. For the 2–4 GB / dozens-of-artifacts catalog this
finishes in minutes. A future thousands-scale catalog would switch to Distributed
Map (S3 ItemReader) + the async SFN-terminal -> CFN response-URL callback.
"""

import json
import logging
import time
import uuid

import boto3
import cfnresponse
from botocore.exceptions import ClientError

logger = logging.getLogger("ResourceMirrorTrigger")
logger.setLevel(logging.INFO)

sfn = boto3.client("stepfunctions")

POLL_INTERVAL_SEC = 10
SAFETY_MARGIN_MS = 30_000  # respond to CFN before the Lambda times out
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}


def handler(event, context):
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
            logger.info("Delete — no-op, mirror artifacts retained.")
            return _respond(event, context, True, {"Message": "Delete no-op"})

        if method == "install-host":
            logger.info("MirroringMethod=install-host — cloud executor skipped (D10).")
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
                    logger.warning(f"{msg}; failure_mode=soft — no-op SUCCESS, "
                                   f"cluster proceeds unmirrored.")
                    return _respond(event, context, True,
                                    {"Message": "Manifest absent; soft no-op"})
                logger.error(f"{msg}; failure_mode=hard — failing.")
                return _respond(event, context, False, {"Error": msg})
            raise
        logger.info(f"Manifest loaded: {len(items)} item(s) from "
                    f"s3://{manifest_bucket}/{manifest_key} (region={bucket_region})")

        # Pre-generate the execution name so we can stamp it onto each item BEFORE
        # starting (the executor records sfn_execution_id from the item for provenance).
        # Passing it as the execution `name` keeps the ARN and the stamped id consistent.
        execution_name = f"mirror-{uuid.uuid4()}"
        _trigger_type = {"Create": "install", "Update": "update"}.get(
            request_type, request_type.lower()
        )
        for _item in items:
            _item["sfn_execution_id"] = execution_name
            _item["trigger_type"] = _trigger_type

        # Fire the SFN with items INLINE — fan-out happens in the Map (unchanged).
        execution_arn = sfn.start_execution(
            stateMachineArn=state_machine_arn,
            name=execution_name,
            input=json.dumps({"items": items, "failure_mode": failure_mode}),
        )["executionArn"]
        logger.info(f"Started execution: {execution_arn} (failure_mode={failure_mode})")

        status, cause = _poll_to_terminal(execution_arn, context)

        if status == "SUCCEEDED":
            logger.info(f"Mirror SUCCEEDED: {execution_arn}")
            return _respond(event, context, True,
                            {"ExecutionArn": execution_arn, "Status": status,
                             "ItemCount": str(len(items))},
                            physical_id=execution_arn)

        logger.error(f"Mirror did not succeed ({status}): {cause}")
        return _respond(event, context, False,
                        {"ExecutionArn": execution_arn, "Status": status,
                         "Cause": (cause or "")[:1000]},
                        physical_id=execution_arn)

    except Exception as e:
        logger.error(f"Trigger error: {e}")
        return _respond(event, context, False, {"Error": str(e)})


def _load_manifest(bucket, key, region):
    """Read + parse the manifest JSON from S3. Region-aware (D15) — the bucket may
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
    out. Returns (status, cause). A poll-timeout returns ('TIMED_OUT_POLL', msg)."""
    while True:
        desc = sfn.describe_execution(executionArn=execution_arn)
        status = desc["status"]
        if status in TERMINAL:
            return status, desc.get("cause", "")
        if context.get_remaining_time_in_millis() < SAFETY_MARGIN_MS:
            msg = (f"Lambda timeout approaching; execution still {status}. "
                   f"Aborting wait — treating as failure for safety.")
            logger.error(msg)
            return "TIMED_OUT_POLL", msg
        time.sleep(POLL_INTERVAL_SEC)


def _respond(event, context, success, data, physical_id=None):
    status = cfnresponse.SUCCESS if success else cfnresponse.FAILED
    cfnresponse.send(event, context, status, data, physicalResourceId=physical_id)
    return data
