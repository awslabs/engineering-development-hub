# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0     

"""
DCV event relay Lambda (SQS-backed).

Receives messages from the per-cluster SQS queue
<ClusterId>-dcv-session-events via the AWS-managed event source mapping
(long-poll, sub-second latency, no polling cost). Pre-screens each
message and forwards valid ones to the controller's session-event
endpoint over a private VPC path.

ARCHITECTURE
============

    VDI  --aws sqs send-message-->  SQS queue  --(SenderId attached)-->  this Lambda
                                                                              |
                                                          extract SenderId,   |
                                                          validate vs body    |
                                                          and HMAC-bind into  |
                                                          canonical string    |
                                                                              v
                                                                       Controller HTTPS

PRE-SCREEN: cheap rejections happen here so the controller doesn't see
malformed traffic. Anything that gets through to the controller is then
re-validated authoritatively (defense in depth).

  Cheap-fail in this Lambda:
    1. Schema check (REQUIRED_FIELDS in body)
    2. event_type allowlist
    3. Format checks (UUID, instance ID, nonce length)
    4. Freshness (5 min window)
    5. SenderId attestation -- AWS-attested instance ID extracted from
       SQS message attributes; must match body.instance_id.

  Forward to controller (which re-validates everything plus DB checks):
    - Sign canonical-string HMAC with relay key from SecretsManager
    - Set X-EDH-Attested-Instance: <i-XXX> header (bound into HMAC)
    - POST to https://<controller_ip>:8443/api/dcv/session-event

CHAIN OF TRUST
==============

  1. VDI->SQS:        SigV4 signed by IMDS-issued STS creds. AWS verifies
                      the signature and attaches role-id:i-XXX as SenderId
                      to the delivered message.
  2. SQS->Lambda:     ESM delivers the message with the SenderId attribute.
                      We trust AWS's internal delivery integrity.
  3. Lambda->ctrl:    HMAC-SHA-256 over a canonical string that binds
                      method + path + attested-instance header + body.
                      Tampering with any of these (in flight or by a
                      compromised Lambda) invalidates the signature.

The relay key in SecretsManager is auto-rotated every 90 days by the
DcvEventRelayRotation Lambda with AWSCURRENT/AWSPREVIOUS overlap so
neither side sees a brittle cutover.

DEPLOYMENT
==========

CDK (cdk_construct.dcv_event_relay) wires:
  - SQS queue + dead-letter queue
  - This Lambda + SQS event source mapping (batch=10)
  - SecretsManager secret (auto-rotation 90d)
  - IAM: GetSecretValue scoped to AWSCURRENT only (Lambda); AWSCURRENT +
         AWSPREVIOUS for the controller role
  - SSM SocaConfig params:
      /configuration/ControllerWebUIUrl     -- where to POST
      /configuration/DcvSessionEventsQueueUrl
      /configuration/DcvEventRelaySecretArn
  - CW alarms: Rejected sum >=5/5min; missing-attested >=1/1min (forgery)

This file uses stdlib only -- no cryptography, no requests. SOCA Lambdas
are loaded via aws_lambda.Code.from_asset() with no bundler, so we must
stick to what's in the Python 3.x Lambda runtime.
"""

import base64
import hmac
import http.client
import json
import logging
import os
import re
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Optional

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ----- constants -----------------------------------------------------------

FRESHNESS_WINDOW_SEC = 300
MAX_BODY_BYTES = 16384
MAX_NONCE_LEN = 128
MIN_NONCE_LEN = 16

# Launch lifecycle hook on the pool ASGs (set by VdiPoolReconciler). The relay
# completes it with CONTINUE once a member announces readiness, so the ASG only
# counts truly-ready members as InService. A member that never announces is
# ABANDONed at the hook timeout (terminated + relaunched) -- see reconciler.
LIFECYCLE_HOOK_NAME = "vdipool-ready"

KNOWN_EVENT_TYPES = {
    "session-ready",
    "session-resumed",
    "session-failed",
    "session-heartbeat",
    "bootstrap-checkpoint",
    "bootstrap-status",
}

REQUIRED_FIELDS = {
    "event_type",
    "session_uuid",
    "instance_id",
    "event_timestamp",
    "nonce",
}

UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")

# Env vars set by CDK on Lambda definition.
CONTROLLER_URL = os.environ.get("EDH_CONTROLLER_URL", "")
RELAY_SECRET_ARN = os.environ.get("EDH_RELAY_SECRET_ARN", "")

# Lazy-init clients.
_sm_client = None
_cw_client = None

# In-process relay-key cache (single-key here -- Lambda only ever signs with
# AWSCURRENT, never with AWSPREVIOUS; that's why GetSecretValue IAM is
# scoped tighter on the Lambda role than on the controller role).
_relay_key_cache: dict = {"key": None, "fetched_at": None}
_RELAY_KEY_CACHE_TTL = timedelta(minutes=5)


# ----- relay key fetch -----------------------------------------------------

def _get_relay_key() -> Optional[bytes]:
    """
    Return the AWSCURRENT relay HMAC key, fetching from SecretsManager if
    the in-process cache is stale or empty. Cache keeps cold-start cost
    bounded; a Lambda container handles many invocations per warm period.
    """
    global _sm_client
    now = datetime.now(timezone.utc)
    fetched = _relay_key_cache.get("fetched_at")
    if (
        _relay_key_cache.get("key")
        and fetched
        and (now - fetched) < _RELAY_KEY_CACHE_TTL
    ):
        return _relay_key_cache["key"]

    if not RELAY_SECRET_ARN:
        logger.error("EDH_RELAY_SECRET_ARN not set; cannot sign requests")
        return None
    try:
        if _sm_client is None:
            _sm_client = boto3.client("secretsmanager")
        resp = _sm_client.get_secret_value(
            SecretId=RELAY_SECRET_ARN, VersionStage="AWSCURRENT"
        )
        key = resp.get("SecretBinary") or resp.get("SecretString", "").encode()
        _relay_key_cache["key"] = key
        _relay_key_cache["fetched_at"] = now
        return key
    except Exception as err:
        logger.error(f"GetSecretValue failed: {err}")
        return None


# ----- CloudWatch metric for rejections -----------------------------------

def _emit_rejected(reason: str) -> None:
    """Emit EDH/DCVEventRelay::Rejected{Reason=...} for alarm wiring + log it."""
    logger.warning("relay rejected event: reason=%s", reason)
    global _cw_client
    try:
        if _cw_client is None:
            _cw_client = boto3.client("cloudwatch")
        _cw_client.put_metric_data(
            Namespace="EDH/DCVEventRelay",
            MetricData=[
                {
                    "MetricName": "Rejected",
                    "Dimensions": [
                        {"Name": "Reason", "Value": reason.split(":", 1)[0]}
                    ],
                    "Value": 1.0,
                    "Unit": "Count",
                }
            ],
        )
    except Exception:
        pass  # never let metric publish mask the rejection


# ----- handler ------------------------------------------------------------

# Cluster ID env var, used by the EC2 / CFN paths to filter events to
# our cluster only -- a single Lambda may serve multiple sources but we
# only forward events that match this cluster's edh:ClusterId tag.
EDH_CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")

# Spot AZ-fallback (Option 1): on a dcv_node stack launch failure, re-drive the
# next candidate subnet via the placement request queue. Bounded by SPOT_MAX_ATTEMPTS.
PLACEMENT_REQUEST_QUEUE_URL = os.environ.get("PLACEMENT_REQUEST_QUEUE_URL", "")
NOTIFICATIONS_TABLE = os.environ.get("NOTIFICATIONS_TABLE", f"{EDH_CLUSTER_ID}-notifications")
SPOT_MAX_ATTEMPTS = int(os.environ.get("EDH_SPOT_MAX_ATTEMPTS", "3"))

# Lazy-init EC2 + CFN clients for tag lookups (only used by the EventBridge
# / SNS paths).
_ec2_client = None
_cfn_client = None

def _get_ec2_client():
    global _ec2_client
    if _ec2_client is None:
        _ec2_client = boto3.client("ec2")
    return _ec2_client

def _get_cfn_client():
    global _cfn_client
    if _cfn_client is None:
        _cfn_client = boto3.client("cloudformation")
    return _cfn_client

_asg_client = None

def _get_asg_client():
    global _asg_client
    if _asg_client is None:
        _asg_client = boto3.client("autoscaling")
    return _asg_client

_sqs_client = None

def _get_sqs_client():
    global _sqs_client
    if _sqs_client is None:
        _sqs_client = boto3.client("sqs")
    return _sqs_client


def handler(event, context):
    """
    Multi-source dispatcher.

    Three input shapes are accepted:

      1. SQS event source mapping (existing VDI path):
           event["Records"][i]["eventSource"] == "aws:sqs"
         Each record has body+SenderId; messages are pre-screened
         (SenderId attestation, freshness, schema) and forwarded.

      2. EventBridge direct invocation (EC2 state-change):
           event["source"] == "aws.ec2"
           event["detail-type"] == "EC2 Instance State-change Notification"
         Only `state == "running"` is forwarded, gated on
         edh:ClusterId tag matching this cluster. Emits the
         `ec2-running` bootstrap-checkpoint.

      3. SNS subscription (CFN stack lifecycle):
           event["Records"][i]["EventSource"] == "aws:sns"
         CFN events arrive as plain key=value text in the SNS message.
         We forward CREATE_IN_PROGRESS for the stack itself (filtered
         to AWS::CloudFormation::Stack resource type, ignoring nested
         resources) as the `stack-launching` checkpoint.

    Partial-batch failures are returned only for the SQS path -- the
    other paths are single-event invocations.
    """
    if not isinstance(event, dict):
        logger.warning(f"unexpected event type: {type(event)}")
        return {}

    # EventBridge direct invocation
    if event.get("source") == "aws.ec2" and \
       event.get("detail-type") == "EC2 Instance State-change Notification":
        try:
            _process_eventbridge_ec2(event)
        except Exception as err:
            logger.error(f"EventBridge EC2 handler error: {err}")
        return {}

    # Records[]-wrapped sources (SQS or SNS)
    records = event.get("Records", [])
    if not records:
        return {"batchItemFailures": []}

    # SNS sources have EventSource (capital E S) == "aws:sns".
    # SQS sources have eventSource (lowercase) == "aws:sqs".
    first = records[0]
    if first.get("EventSource") == "aws:sns" or "Sns" in first:
        for rec in records:
            try:
                _process_sns_cfn(rec)
            except Exception as err:
                logger.error(f"SNS CFN handler error: {err}")
        return {}

    # Default: SQS-from-VDI path.
    failures = []
    for rec in records:
        msg_id = rec.get("messageId", "?")
        try:
            ok = _process_one(rec)
            if not ok:
                pass  # already logged + metric'd
        except Exception as err:
            logger.error(f"unhandled error on msg {msg_id}: {err}")
            failures.append({"itemIdentifier": msg_id})

    return {"batchItemFailures": failures}


def _process_one(rec: dict) -> bool:
    """
    Pre-screen one SQS record and forward to controller on success.
    Returns False on rejection (logged + metric'd; message is dropped).
    Raises on unexpected errors so SQS will retry via batchItemFailures.
    """
    raw_body_str = rec.get("body", "") or ""
    raw_body = raw_body_str.encode("utf-8")
    if len(raw_body) > MAX_BODY_BYTES:
        _emit_rejected("body_too_large")
        return False

    # 1. Extract AWS-attested instance from SenderId.
    # SenderId format: "<RoleId>:<RoleSessionName>". For an EC2 instance
    # role, AWS sets RoleSessionName = instance ID (i-XXXXXXXX).
    sender_id = rec.get("attributes", {}).get("SenderId", "")
    if not sender_id or ":" not in sender_id:
        _emit_rejected("sender_id_missing")
        logger.warning(f"missing/malformed SenderId: {sender_id!r}")
        return False
    attested_instance = sender_id.split(":", 1)[1].strip()
    if not INSTANCE_ID_RE.match(attested_instance):
        _emit_rejected("sender_id_format")
        logger.warning(
            f"SenderId session-name is not an instance ID: {attested_instance!r}"
        )
        return False

    # 2. Body parse + schema check.
    try:
        body = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _emit_rejected("body_parse")
        return False
    if not isinstance(body, dict):
        _emit_rejected("body_not_object")
        return False

    # Pool-ready: a session-less idle pool member announcing readiness. Different
    # schema (no session_uuid) and a different sink (the pool ledger, written
    # here) -- it does NOT forward to the controller. instance_id is SenderId-
    # attested; pool identity is read from the instance's own tags.
    if body.get("event_type") == "pool-ready":
        return _handle_pool_ready(body, attested_instance)

    if not (REQUIRED_FIELDS <= body.keys()):
        _emit_rejected("missing_field")
        return False

    if body["event_type"] not in KNOWN_EVENT_TYPES:
        _emit_rejected("unknown_event_type")
        return False
    if not (isinstance(body["session_uuid"], str) and UUID_RE.match(body["session_uuid"])):
        _emit_rejected("session_uuid_format")
        return False
    if not (isinstance(body["instance_id"], str) and INSTANCE_ID_RE.match(body["instance_id"])):
        _emit_rejected("instance_id_format")
        return False
    nonce = body["nonce"]
    if not (isinstance(nonce, str) and MIN_NONCE_LEN <= len(nonce) <= MAX_NONCE_LEN):
        _emit_rejected("nonce_format")
        return False

    # 3. Cross-check body.instance_id vs AWS-attested SenderId.
    # This is the core anti-forgery gate: a VDI cannot publish events
    # claiming to be a different VDI because SQS won't let it lie about
    # SenderId. Anything that mismatches here is forgery and is alarmed.
    if body["instance_id"] != attested_instance:
        _emit_rejected("body_instance_mismatch")
        logger.warning(
            f"instance mismatch: body={body['instance_id']!r} "
            f"sender={attested_instance!r}"
        )
        return False

    # 4. Freshness window (cheap reject before forwarding).
    try:
        event_ts = datetime.fromisoformat(
            body["event_timestamp"].replace("Z", "+00:00")
        )
    except (TypeError, ValueError, AttributeError):
        _emit_rejected("timestamp_format")
        return False
    skew = abs((datetime.now(timezone.utc) - event_ts).total_seconds())
    if skew > FRESHNESS_WINDOW_SEC:
        _emit_rejected("timestamp_skew")
        return False

    # 5. Sign canonical and forward.
    return _post_to_controller(raw_body, attested_instance)


# ----- forward to controller ----------------------------------------------

def _build_canonical(raw_body: bytes, attested_instance: str) -> bytes:
    """
    Build the canonical string the relay HMAC is computed over. MUST stay
    byte-for-byte identical to session_event._build_canonical on the
    controller side. See controller docstring for the threat model.
    """
    return (
        b"POST\n"
        b"/api/dcv/session-event\n"
        b"x-edh-attested-instance:" + attested_instance.encode("ascii") + b"\n"
        b"\n"
        + raw_body
    )


def _post_to_controller(raw_body: bytes, attested_instance: str) -> bool:
    """
    Sign canonical-string HMAC with the AWSCURRENT relay key and POST to
    the controller's session-event endpoint. Returns True on 2xx.
    """
    if not CONTROLLER_URL:
        _emit_rejected("controller_url_missing")
        logger.error("EDH_CONTROLLER_URL not set; dropping event")
        return False

    key = _get_relay_key()
    if key is None:
        _emit_rejected("relay_key_unavailable")
        return False

    canonical = _build_canonical(raw_body, attested_instance)
    sig = hmac.new(key, canonical, sha256).digest()
    sig_b64 = base64.b64encode(sig).decode("ascii")

    parsed = urllib.parse.urlparse(CONTROLLER_URL)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = "/api/dcv/session-event"

    # The controller's TLS cert is self-signed (per-cluster) and reachable
    # only over a private VPC path. We disable verification because the
    # HMAC is the authentication boundary, not TLS. Defense-in-depth only.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=5)
        conn.request(
            "POST",
            path,
            body=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-EDH-DcvRelay-HMAC": sig_b64,
                "X-EDH-Attested-Instance": attested_instance,
            },
        )
        resp = conn.getresponse()
        status = resp.status
        resp.read()  # drain
        conn.close()
        if 200 <= status < 300:
            return True
        logger.warning(
            f"controller POST returned {status} for instance {attested_instance}"
        )
        _emit_rejected(f"controller_{status}")
        return False
    except Exception as err:
        logger.error(f"controller POST failed: {err}")
        _emit_rejected("controller_io")
        return False


# ----- EventBridge: EC2 state-change ---------------------------------------

def _process_eventbridge_ec2(event: dict) -> None:
    """
    EventBridge invocation for EC2 state-change events.

    Filters:
      - state == "running" only (we don't track stop/terminate via this dot)
      - EC2 must carry edh:ClusterId == EDH_CLUSTER_ID
      - EC2 must carry edh:SessionUuid (= UUID this controller knows)

    On match, builds a canonical bootstrap-checkpoint=ec2-running event
    body and forwards via the standard HMAC path. The Lambda's IAM role
    is the trust anchor (same as the SQS path's SenderId attestation --
    the controller doesn't need to distinguish between sources).
    """
    detail = event.get("detail", {}) or {}
    state = (detail.get("state") or "").lower()
    instance_id = detail.get("instance-id") or ""

    if state != "running":
        return  # only the running transition fires the dot
    if not INSTANCE_ID_RE.match(instance_id):
        logger.warning(f"ec2-running: malformed instance-id {instance_id!r}")
        return

    tags = _describe_instance_tags(instance_id)
    if tags is None:
        return  # describe failed; logged inside helper

    cluster = tags.get("edh:ClusterId", "")
    session_uuid = tags.get("edh:SessionUuid", "")
    if not cluster or cluster != EDH_CLUSTER_ID:
        # Not our cluster -- drop silently. Lambda may receive events
        # for the whole account/region.
        return
    if not session_uuid or not UUID_RE.match(session_uuid):
        logger.info(
            f"ec2-running: instance {instance_id} has no edh:SessionUuid tag; "
            f"likely not a VDI -- dropping"
        )
        return

    body = _build_infra_event_body(
        event_type="bootstrap-checkpoint",
        checkpoint="ec2-running",
        sub_status="EC2 instance running",
        session_uuid=session_uuid,
        instance_id=instance_id,
    )
    raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    if _post_to_controller(raw_body, instance_id):
        logger.info(
            f"ec2-running forwarded for session={session_uuid} instance={instance_id}"
        )


def _describe_instance_tags(instance_id: str) -> Optional[dict]:
    """Return {tag_key: tag_value} for the instance, or None on failure."""
    try:
        ec2 = _get_ec2_client()
        resp = ec2.describe_instances(InstanceIds=[instance_id])
    except Exception as err:
        logger.warning(f"DescribeInstances({instance_id}) failed: {err}")
        return None
    reservations = resp.get("Reservations", [])
    if not reservations:
        return {}
    instances = reservations[0].get("Instances", [])
    if not instances:
        return {}
    return {t["Key"]: t["Value"] for t in instances[0].get("Tags", [])}


# ----- pool readiness ingestion (VDI pools) --------------------------------

_ddb_resource = None


def _ddb():
    global _ddb_resource
    if _ddb_resource is None:
        _ddb_resource = boto3.resource("dynamodb")
    return _ddb_resource


def _handle_pool_ready(body: dict, attested_instance: str) -> bool:
    """Write the ledger AVAILABLE row for a session-less pool member that has
    announced readiness (DCV up, broker-registered, no session).

    Trust model: instance_id is the SenderId-attested instance (same anchor as
    the session path). Pool identity (edh:pool_id) and the ASG name come from
    the instance's OWN tags (authoritative), not the event body. This opens the
    claim gate -- PoolAllocator.try_claim_hot pops AVAILABLE rows.
    """
    nonce = body.get("nonce")
    if not (isinstance(nonce, str) and MIN_NONCE_LEN <= len(nonce) <= MAX_NONCE_LEN):
        _emit_rejected("nonce_format")
        return False
    try:
        event_ts = datetime.fromisoformat(
            str(body.get("event_timestamp", "")).replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        _emit_rejected("timestamp_format")
        return False
    if abs((datetime.now(timezone.utc) - event_ts).total_seconds()) > FRESHNESS_WINDOW_SEC:
        _emit_rejected("timestamp_skew")
        return False

    tags = _describe_instance_tags(attested_instance)
    if not tags:
        _emit_rejected("pool_ready_no_tags")
        return False
    if tags.get("edh:ClusterId") != EDH_CLUSTER_ID:
        logger.info(
            "pool-ready: instance %s edh:ClusterId=%r != %r; dropping (not our cluster)",
            attested_instance,
            tags.get("edh:ClusterId"),
            EDH_CLUSTER_ID,
        )
        return False  # not our cluster
    pool_id = tags.get("edh:pool_id")
    if not pool_id:
        _emit_rejected("pool_ready_no_pool_id")
        return False

    table_name = (
        f"{EDH_CLUSTER_ID}-vdi-pool-ledger" if EDH_CLUSTER_ID else ""
    )
    if not table_name:
        logger.error(
            "pool-ready: EDH_CLUSTER_ID unset; cannot resolve ledger table (instance=%s)",
            attested_instance,
        )
        return False
    try:
        _ddb().Table(table_name).put_item(
            Item={
                "pk": pool_id,
                "sk": attested_instance,
                "status": "AVAILABLE",
                "instance_id": attested_instance,
                # Canonical ASG name (auto-added tag), NOT the "<asg>-hot" Name
                # tag -- the claim path detaches by this exact ASG name.
                "asg_name": tags.get("aws:autoscaling:groupName")
                or tags.get("Name", ""),
                "registered_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
        )
    except Exception as err:
        logger.error(
            "pool-ready ledger write failed for %s/%s: %s",
            pool_id,
            attested_instance,
            err,
        )
        return False
    logger.info(
        "pool-ready: %s AVAILABLE (instance=%s)", pool_id, attested_instance
    )

    # Complete the launch lifecycle hook so the ASG promotes the member from
    # Pending:Wait -> InService now that it is genuinely ready (DCV up,
    # broker-registered) and has its AVAILABLE ledger row. This keeps the ASG
    # InService count == ready count and makes the instance detachable by the
    # claim path. Canonical ASG name comes from the auto-added
    # aws:autoscaling:groupName tag (fall back to the propagated Name tag).
    # Best-effort: a failure here does not undo the AVAILABLE row -- the hook
    # will otherwise ABANDON at its timeout, recycling the member.
    asg_name = tags.get("aws:autoscaling:groupName") or tags.get("Name")
    if asg_name:
        try:
            _get_asg_client().complete_lifecycle_action(
                LifecycleHookName=LIFECYCLE_HOOK_NAME,
                AutoScalingGroupName=asg_name,
                InstanceId=attested_instance,
                LifecycleActionResult="CONTINUE",
            )
            logger.info(
                "pool-ready: lifecycle CONTINUE for %s on %s",
                attested_instance,
                asg_name,
            )
        except Exception as err:
            # Already-completed / no-active-action is benign (idempotent retry).
            logger.warning(
                "pool-ready: complete_lifecycle_action skipped for %s on %s: %s",
                attested_instance,
                asg_name,
                err,
            )
    else:
        logger.warning(
            "pool-ready: no ASG name tag for %s; cannot complete lifecycle hook",
            attested_instance,
        )
    return True


# ----- SNS: CFN stack lifecycle --------------------------------------------

def _read_placement_ctx(session_uuid: str) -> Optional[dict]:
    """Read the parked placement_context (includes retry block) from DDB."""
    try:
        item = _ddb().Table(NOTIFICATIONS_TABLE).get_item(
            Key={"scope": f"placement_ctx#{session_uuid}", "id": "context"}
        ).get("Item")
        if item and item.get("envelope"):
            return json.loads(item["envelope"])
    except Exception as err:
        logger.warning(f"placement_ctx read failed for {session_uuid}: {err}")
    return None


def _put_placement_ctx(session_uuid: str, ctx: dict) -> None:
    """Re-park placement_context with an updated retry block."""
    import time as _t
    try:
        _ddb().Table(NOTIFICATIONS_TABLE).put_item(Item={
            "scope": f"placement_ctx#{session_uuid}",
            "id": "context",
            "envelope": json.dumps(ctx),
            "ttl": int(_t.time()) + 3600,
        })
    except Exception as err:
        logger.warning(f"placement_ctx update failed for {session_uuid}: {err}")


def _stack_subnet(stack_name: str) -> Optional[str]:
    """Read the SubnetId parameter of the (failed) stack -- the AZ that failed."""
    try:
        resp = _get_cfn_client().describe_stacks(StackName=stack_name)
        for p in resp["Stacks"][0].get("Parameters", []):
            if p.get("ParameterKey") == "SubnetId":
                return p.get("ParameterValue")
    except Exception as err:
        logger.warning(f"SubnetId read failed for {stack_name}: {err}")
    return None


def _post_control_plane(session_uuid: str, event_type: str, sub_status: str) -> bool:
    """POST a control-plane event (placement_failed) attested as dcv-event-relay."""
    import secrets
    body = {
        "event_type": event_type,
        "session_uuid": session_uuid,
        "sub_status": sub_status[:256],
        "event_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": secrets.token_hex(16),
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    return _post_to_controller(raw, "dcv-event-relay")


def _reenqueue_next_az(session_uuid: str, stack_name: str, ctx: dict, reason: str) -> bool:
    """Re-drive placement to the next candidate subnet. Returns True if a retry was
    enqueued (caller must NOT surface failure), False if exhausted."""
    retry = ctx.get("retry") or {}
    attempt = int(retry.get("attempt", 1) or 1)
    if attempt >= SPOT_MAX_ATTEMPTS or not PLACEMENT_REQUEST_QUEUE_URL:
        return False
    failed_subnet = _stack_subnet(stack_name)
    remaining = [s for s in retry.get("subnet_ids", []) if s != failed_subnet]
    if not remaining:
        return False
    import secrets
    next_attempt = attempt + 1
    msg = {
        "session_uuid": session_uuid,
        "instance_type": retry.get("instance_type"),
        "ami_id": retry.get("ami_id"),
        "subnet_ids": remaining,
        "tenancy": retry.get("tenancy", "default"),
        "instance_platform": retry.get("instance_platform", "Linux/UNIX"),
        "cluster_id": EDH_CLUSTER_ID,
        "capacity_reservation_id": "",
        "spot": True,
        "attempt": next_attempt,
        "nonce": secrets.token_hex(16),
    }
    try:
        _get_sqs_client().send_message(
            QueueUrl=PLACEMENT_REQUEST_QUEUE_URL,
            MessageBody=json.dumps(msg),
            MessageGroupId=session_uuid,
            MessageDeduplicationId=msg["nonce"],
        )
    except Exception as err:
        logger.error(f"spot AZ-fallback re-enqueue failed for {session_uuid}: {err}")
        return False
    retry["attempt"] = next_attempt
    retry["subnet_ids"] = remaining
    ctx["retry"] = retry
    _put_placement_ctx(session_uuid, ctx)
    # Non-terminal UX signal so the user sees progress, not a vanish.
    placeholder = "i-" + session_uuid.replace("-", "")[:16]
    body = _build_infra_event_body(
        event_type="bootstrap-checkpoint",
        checkpoint="spot-retry",
        sub_status=f"Spot capacity unavailable in one AZ; retrying (attempt {next_attempt})",
        session_uuid=session_uuid,
        instance_id=placeholder,
    )
    _post_to_controller(json.dumps(body, separators=(",", ":")).encode("utf-8"), placeholder)
    logger.info(f"spot AZ-fallback: re-enqueued {session_uuid} attempt={next_attempt} remaining={remaining}")
    return True


def _handle_launch_failure(fields: dict) -> None:
    """A dcv_node instance failed to launch (e.g. Spot ICE). For spot, re-drive
    the next candidate subnet. Terminal surfacing is handled by the stack-level
    backstop (_handle_stack_failure) so any failure class -- not just an
    instance ICE -- surfaces instead of vanishing, with no double-fire."""
    stack_id = fields.get("StackId", "")
    if not stack_id:
        return
    stack_name = stack_id.rsplit("/", 2)[-2] if "/" in stack_id else stack_id
    reason = (fields.get("ResourceStatusReason") or "").strip() or "Instance launch failed"
    tags = _describe_stack_tags(stack_name)
    if tags is None:
        return
    if tags.get("edh:ClusterId", "") != EDH_CLUSTER_ID:
        return
    if tags.get("edh:NodeType", "") != "dcv_node":
        return
    session_uuid = tags.get("edh:SessionUuid", "")
    if not session_uuid or not UUID_RE.match(session_uuid):
        return
    ctx = _read_placement_ctx(session_uuid)
    if ctx and (ctx.get("retry") or {}).get("spot"):
        # Try the next candidate subnet. If a retry is enqueued, the stale stack's
        # rollback is ignored by the backstop (older attempt number). If not
        # (exhausted), the stack-rollback backstop surfaces placement_failed.
        _reenqueue_next_az(session_uuid, stack_name, ctx, reason)


def _handle_stack_failure(fields: dict) -> None:
    """Terminal backstop: any dcv_node CFN stack that reaches ROLLBACK_COMPLETE
    / CREATE_FAILED surfaces placement_failed (so the tile shows a reason
    instead of silently vanishing), UNLESS a newer attempt is already in
    flight (this is a stale prior-attempt rollback that an AZ-retry replaced)."""
    stack_id = fields.get("StackId", "")
    if not stack_id:
        return
    stack_name = stack_id.rsplit("/", 2)[-2] if "/" in stack_id else stack_id
    tags = _describe_stack_tags(stack_name)
    if tags is None:
        return
    if tags.get("edh:ClusterId", "") != EDH_CLUSTER_ID:
        return
    if tags.get("edh:NodeType", "") != "dcv_node":
        return
    session_uuid = tags.get("edh:SessionUuid", "")
    if not session_uuid or not UUID_RE.match(session_uuid):
        return
    # Attempt number of the failing stack (base = 1, "-rN" = N).
    _m = re.search(r"-r(\d+)$", stack_name)
    stack_attempt = int(_m.group(1)) if _m else 1
    ctx = _read_placement_ctx(session_uuid)
    cur_attempt = int(((ctx or {}).get("retry") or {}).get("attempt", 1) or 1)
    if stack_attempt < cur_attempt:
        return  # a newer AZ-retry is already in flight; ignore stale rollback
    reason = (fields.get("ResourceStatusReason") or "").strip() or "Launch failed during stack creation"
    if _post_control_plane(session_uuid, "placement_failed", reason):
        logger.info(
            f"placement_failed surfaced (stack rollback) for {session_uuid} "
            f"attempt={stack_attempt}: {reason[:120]}"
        )


def _process_sns_cfn(record: dict) -> None:
    """
    SNS subscription delivers CFN stack lifecycle events. Forward only
    the AWS::CloudFormation::Stack CREATE_IN_PROGRESS event (start of
    stack creation) as the `stack-launching` checkpoint. Nested resource
    events are dropped to keep the dot semantic clean.
    """
    sns = record.get("Sns", {}) or {}
    raw_message = sns.get("Message", "") or ""
    fields = _parse_cfn_sns_message(raw_message)

    # dcv_node instance launch failure (e.g. Spot ICE): re-drive next AZ.
    if (fields.get("ResourceType") == "AWS::EC2::Instance"
            and fields.get("ResourceStatus", "") == "CREATE_FAILED"):
        _handle_launch_failure(fields)
        return

    # dcv_node stack terminal failure (any cause): surface placement_failed
    # unless a newer AZ-retry already superseded this attempt.
    if (fields.get("ResourceType") == "AWS::CloudFormation::Stack"
            and fields.get("ResourceStatus", "") in ("ROLLBACK_COMPLETE", "CREATE_FAILED")):
        _handle_stack_failure(fields)
        return

    if fields.get("ResourceType") != "AWS::CloudFormation::Stack":
        return  # nested resources -- ignore
    status = fields.get("ResourceStatus", "")
    if status != "CREATE_IN_PROGRESS":
        return  # not the start; rollbacks/completes go through other dots

    stack_id = fields.get("StackId", "")
    if not stack_id:
        return

    # Parse stack name out of the ARN; describe to read tags.
    stack_name = stack_id.rsplit("/", 2)[-2] if "/" in stack_id else stack_id

    tags = _describe_stack_tags(stack_name)
    if tags is None:
        return
    cluster = tags.get("edh:ClusterId", "")
    session_uuid = tags.get("edh:SessionUuid", "")
    if not cluster or cluster != EDH_CLUSTER_ID:
        return
    if not session_uuid or not UUID_RE.match(session_uuid):
        logger.info(f"stack-launching: stack {stack_name} has no edh:SessionUuid -- dropping")
        return

    # No EC2 instance ID exists yet at stack-creation time. The controller
    # validates X-EDH-Attested-Instance == body.instance_id; for stack
    # events we use the eventual VDI's expected instance_id once it's
    # known. Since we don't know it yet, set instance_id=session_uuid for
    # the canonical bind and add an explicit hint to the body so the
    # controller can recognize this as a synthetic stack-event.
    #
    # Trade-off: the controller-side code already keys events on
    # session_uuid AND validates the attestation header. For infra events
    # without a real EC2 yet, we use a placeholder of the form
    # "i-stack" + first-12-chars-of-session-uuid so the regex still
    # matches.
    placeholder_instance = "i-" + session_uuid.replace("-", "")[:16]

    body = _build_infra_event_body(
        event_type="bootstrap-checkpoint",
        checkpoint="stack-launching",
        sub_status="CloudFormation stack create in progress",
        session_uuid=session_uuid,
        instance_id=placeholder_instance,
    )
    raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    if _post_to_controller(raw_body, placeholder_instance):
        logger.info(
            f"stack-launching forwarded for session={session_uuid} stack={stack_name}"
        )


def _parse_cfn_sns_message(text: str) -> dict:
    """
    CFN-via-SNS messages are plain text with one `Key='Value'` per line.
    Quotes around values, escaped single quotes inside as `\'`.
    """
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip("'")
        out[k] = v
    return out


def _describe_stack_tags(stack_name: str) -> Optional[dict]:
    try:
        cfn = _get_cfn_client()
        resp = cfn.describe_stacks(StackName=stack_name)
    except Exception as err:
        logger.warning(f"DescribeStacks({stack_name}) failed: {err}")
        return None
    stacks = resp.get("Stacks", [])
    if not stacks:
        return {}
    return {t["Key"]: t["Value"] for t in stacks[0].get("Tags", [])}


# ----- shared body builder for infra-sourced events ------------------------

def _build_infra_event_body(
    event_type: str,
    checkpoint: str,
    sub_status: str,
    session_uuid: str,
    instance_id: str,
) -> dict:
    """
    Build a canonical event body for infra-sourced events (EventBridge,
    SNS) so they ride the same /api/dcv/session-event path as VDI events.

    nonce: 32 hex chars from os.urandom; freshness window is 5 min so a
    fresh nonce per call is ample.
    """
    import secrets
    return {
        "event_type": event_type,
        "checkpoint": checkpoint,
        "sub_status": sub_status,
        "session_uuid": session_uuid,
        "instance_id": instance_id,
        "event_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": secrets.token_hex(16),
    }
