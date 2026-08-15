# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DcvEventRelayRotation -- AWS-standard 4-step Secrets Manager rotation
Lambda for the dcv-event-relay-key.

Steps (per AWS rotation contract):

  createSecret  - generate a new 64-byte random and stage it as AWSPENDING
  setSecret     - apply the secret to its consumer system. For an HMAC key
                  the secret IS the value, so this is a no-op.
  testSecret    - verify the new key works end-to-end. We send a synthetic
                  health-probe event signed with the AWSPENDING key to the
                  controller's /api/dcv/session-event-rotation-test endpoint.
                  Controller confirms the new key validates AND that the old
                  one still works (rotation overlap), returns 204.
  finishSecret  - move staging labels: AWSPENDING -> AWSCURRENT, old
                  AWSCURRENT -> AWSPREVIOUS. Done by SM itself when we
                  return success here.

If any step fails the rotation aborts and SM keeps the old AWSCURRENT --
no service interruption.
"""

import base64
import hmac
import json
import logging
import os
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from hashlib import sha256

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ----- environment --------------------------------------------------------

CONTROLLER_URL_PARAM = os.environ["CONTROLLER_URL_PARAM"]
EDH_CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
HTTP_TIMEOUT_SEC = int(os.environ.get("HTTP_TIMEOUT_SEC", "10"))

# 64 bytes (512 bits) per design doc -- exceeds NIST SP 800-107 minimum
# and fully utilises the SHA-256 block size after pre-hashing.
SECRET_LENGTH_BYTES = 64

_sm = boto3.client("secretsmanager")
_ssm = boto3.client("ssm")

CONTROLLER_URL: str = _ssm.get_parameter(Name=CONTROLLER_URL_PARAM)["Parameter"][
    "Value"
].rstrip("/")


def handler(event, context):
    """
    Standard SM rotation handler. Event shape:
        { "Step": "createSecret"|"setSecret"|"testSecret"|"finishSecret",
          "SecretId": "<arn>",
          "Token": "<version uuid>" }
    """
    step = event["Step"]
    arn = event["SecretId"]
    token = event["Token"]

    # Verify rotation is enabled and this token corresponds to AWSPENDING
    # before doing any work. SM occasionally fires duplicate events.
    meta = _sm.describe_secret(SecretId=arn)
    if not meta.get("RotationEnabled", False):
        raise ValueError(f"rotation not enabled on {arn}")
    versions = meta.get("VersionIdsToStages", {})
    if token not in versions:
        # Already moved; AWS will retry, idempotent.
        logger.info(f"token {token} not in VersionIdsToStages, idempotent return")
        return
    if "AWSCURRENT" in versions[token]:
        logger.info(f"version {token} already AWSCURRENT; nothing to do")
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError(f"version {token} not staged AWSPENDING")

    if step == "createSecret":
        _create(arn, token)
    elif step == "setSecret":
        _set(arn, token)
    elif step == "testSecret":
        _test(arn, token)
    elif step == "finishSecret":
        _finish(arn, token)
    else:
        raise ValueError(f"unknown step: {step}")


# ----- step implementations -----------------------------------------------

def _create(arn: str, token: str) -> None:
    """Generate a fresh 64-byte CSPRNG secret and stage it as AWSPENDING."""
    try:
        _sm.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: AWSPENDING already exists, idempotent return")
        return
    except _sm.exceptions.ResourceNotFoundException:
        pass

    new_key = secrets.token_bytes(SECRET_LENGTH_BYTES)
    _sm.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretBinary=new_key,
        VersionStages=["AWSPENDING"],
    )
    logger.info(
        f"createSecret: new {SECRET_LENGTH_BYTES}-byte key staged as "
        f"AWSPENDING (token={token[:8]}...)"
    )


def _set(arn: str, token: str) -> None:
    """
    For an HMAC key, the secret value IS the credential -- no external
    consumer to push it to. Verifiers (controller, Lambda) read directly
    from SM by VersionStage at runtime. No-op step.
    """
    logger.info("setSecret: HMAC key has no external consumer (no-op)")


def _test(arn: str, token: str) -> None:
    """
    Synthetic round-trip: sign a health-probe event with AWSPENDING and
    POST to controller's rotation-test endpoint. Controller confirms the
    new key validates AND that AWSCURRENT still works (so rotation
    overlap is intact). 2xx -> proceed; non-2xx -> rotation aborts.

    Uses the same canonical-string HMAC scheme as the live relay so the
    rotation probe exercises identical code paths on the controller. The
    attested-instance value is the sentinel "i-rotationprobe" -- it is
    the only "instance ID" the rotation-test endpoint accepts; the live
    endpoint rejects it via INSTANCE_ID_RE which requires hex digits.
    """
    pending = _sm.get_secret_value(
        SecretId=arn, VersionId=token, VersionStage="AWSPENDING"
    )
    pending_key = pending.get("SecretBinary") or pending.get(
        "SecretString", ""
    ).encode()

    probe_body = json.dumps(
        {
            "probe": "rotation-test",
            "cluster_id": EDH_CLUSTER_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version_token": token,
        },
        sort_keys=True, separators=(",", ":")
    ).encode()

    # Canonical string MUST byte-match the controller's rotation-test
    # _build_canonical-equivalent in DcvSessionEventRotationTest.post().
    attested = "i-rotationprobe"
    canonical = (
        b"POST\n"
        b"/api/dcv/session-event-rotation-test\n"
        b"x-edh-attested-instance:" + attested.encode("ascii") + b"\n"
        b"\n"
        + probe_body
    )
    sig = base64.b64encode(hmac.new(pending_key, canonical, sha256).digest()).decode()
    url = f"{CONTROLLER_URL}/api/dcv/session-event-rotation-test"

    req = urllib.request.Request(
        url,
        data=probe_body,
        headers={
            "Content-Type": "application/json",
            "X-EDH-DcvRelay-HMAC": sig,
            "X-EDH-Attested-Instance": attested,
            "User-Agent": f"DcvEventRelayRotation/{EDH_CLUSTER_ID}",
        },
        method="POST",
    )
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC, context=ctx) as resp:
            if 200 <= resp.status < 300:
                logger.info(f"testSecret: rotation probe ok ({resp.status})")
                return
            raise RuntimeError(f"rotation probe HTTP {resp.status}")
    except urllib.error.HTTPError as err:
        raise RuntimeError(f"rotation probe HTTP {err.code}: {err.reason}")


def _finish(arn: str, token: str) -> None:
    """
    Move AWSCURRENT to point at the new version. SM auto-relabels the
    old AWSCURRENT to AWSPREVIOUS as part of this swap.
    """
    meta = _sm.describe_secret(SecretId=arn)
    current_version = None
    for ver, stages in meta.get("VersionIdsToStages", {}).items():
        if "AWSCURRENT" in stages:
            current_version = ver
            break
    if current_version == token:
        logger.info("finishSecret: already AWSCURRENT, idempotent return")
        return

    _sm.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(
        f"finishSecret: AWSCURRENT={token[:8]}... AWSPREVIOUS={current_version[:8] if current_version else 'none'}..."
    )
