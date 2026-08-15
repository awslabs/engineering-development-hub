# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
USB Allowlist Resolver -- boot-time Lambda behind an IAM-auth HTTP API route
(the shared EDH internal API).

A VDI's boot hook calls this route SigV4-signed with its instance role.
The function reads the caller's instance-id ONLY from the AWS-attested caller
ARN (assumed-role session name == instance-id; a guest cannot forge it), maps
it to the instance's effective Hardware Profile, and returns the rendered DCV
`usb-devices.conf` body (one 8-field filter string per line).

Resolution (Project binding overrides Stack binding):
    instance_id -> virtual_desktop_sessions
                -> software_stacks.hardware_profile_id             (stack bind)
                -> projects.hardware_profile_id (by project name)  (project bind)
    effective   = COALESCE(project bind, stack bind)
                -> hardware_profiles.usb_profile_id
                -> usb_profile_entries -> filter lines

Data access is IN-VPC and read-only: the Lambda runs in the cluster private
subnets and connects to the Aurora READER endpoint over 5432 with psycopg,
using credentials from DatabaseAdminSecret. The query path never leaves the
VPC (no RDS Data API / public control-plane endpoint).

The allowlist is a DCV device compatibility filter, NOT a security boundary
(AWS documents this). This resolver's guarantee is that a user cannot cause
their instance to receive a *different* instance's profile -- the instance-id
is taken from the attested caller ARN, never from the request.
"""

import base64
import json
import logging
import os
import re

import boto3
import psycopg

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Attested EC2 instance-id: "i-" + >=8 hex chars.
_INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,}$")

# Per-field validators for defense-in-depth at render time (entries are already
# validated on write; this re-checks before emitting a line to usb-devices.conf).
_CLASS_RE = re.compile(r"^(\*|\d{1,3})$")   # base/sub/protocol: 0-255 or *
_ID_RE = re.compile(r"^(\*|\d{1,5})$")      # vid/pid: 0-65535 or *
_LABEL_BAD_RE = re.compile(r"[,\r\n\x00-\x1f]")  # no comma/newline/control chars

# Named-parameter (pyformat) SQL -- psycopg binds safely, no string interpolation.
_RESOLVE_SQL = """
SELECT e.device_label, e.base_class, e.sub_class, e.protocol,
       e.vid, e.pid, e.support_autoshare, e.skip_reset
FROM virtual_desktop_sessions s
JOIN software_stacks st ON st.id = s.software_stack_id
LEFT JOIN projects p
       ON p.project_name = s.session_project AND p.is_active = true
JOIN hardware_profiles hp
       ON hp.id = COALESCE(p.hardware_profile_id, st.hardware_profile_id)
      AND hp.is_active = true
JOIN usb_profiles up ON up.id = hp.usb_profile_id AND up.is_active = true
JOIN usb_profile_entries e ON e.usb_profile_id = up.id
WHERE s.instance_id = %(instance_id)s AND s.is_active = true
  AND e.enabled = true
ORDER BY e.id
"""

_DB_HOST = os.environ["DB_HOST"]          # Aurora reader endpoint hostname
_DB_PORT = int(os.environ.get("DB_PORT", "5432"))
_DB_NAME = os.environ["DB_NAME"]
_DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]

# Roles permitted to resolve an EXPLICIT target instance (controller API/CLI
# preview). VDIs are NOT in this set: a vdi_node_role caller can only ever
# resolve its own attested instance-id, never a target it supplies.
_TRUSTED_ROLES = {
    r.strip()
    for r in os.environ.get("TRUSTED_RESOLVER_ROLES", "").split(",")
    if r.strip()
}

_secrets = boto3.client("secretsmanager")

# Cache creds across warm invocations (secret is stable; refetched only on cold
# start or if a connection attempt fails auth).
_creds_cache = None


def _get_creds():
    global _creds_cache
    if _creds_cache is None:
        resp = _secrets.get_secret_value(SecretId=_DB_SECRET_ARN)
        secret = json.loads(resp["SecretString"])
        _creds_cache = (secret["username"], secret["password"])
    return _creds_cache


def _connect():
    user, password = _get_creds()
    return psycopg.connect(
        host=_DB_HOST,
        port=_DB_PORT,
        dbname=_DB_NAME,
        user=user,
        password=password,
        sslmode="require",   # Aurora enforces TLS
        connect_timeout=5,
    )


def _caller_identity(event):
    """Return (role_name, session_name) from the attested IAM caller ARN.

    HTTP API AWS_IAM auth (payload format 2.0) places the SigV4 caller ARN at
    requestContext.authorizer.iam.userArn, e.g.
        arn:aws:sts::<acct>:assumed-role/<role_name>/<session_name>
    For an EC2 instance role the session_name IS the instance-id.
    """
    try:
        user_arn = event["requestContext"]["authorizer"]["iam"]["userArn"]
    except (KeyError, TypeError):
        return (None, None)
    tail = user_arn.split(":assumed-role/", 1)[-1]
    if "/" not in tail:
        return (None, None)
    role_name, session_name = tail.split("/", 1)
    return (role_name, session_name)


def _body_instance_id(event):
    """Extract a validated target instance-id from a trusted caller's request body."""
    raw = event.get("body")
    if not raw:
        return None
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(raw).decode("utf-8")
        except Exception:
            return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    val = data.get("instance_id")
    return val if isinstance(val, str) and _INSTANCE_ID_RE.match(val) else None


def _resolve_target_instance_id(event):
    """Determine which instance-id to resolve, enforcing the trust boundary.

    - Trusted caller (controller role): may resolve an explicit instance_id
      from the request body (API/CLI preview).
    - Any other caller (VDI): may ONLY resolve its own attested instance-id
      (the caller ARN session name). It cannot specify a target.
    Returns the instance-id string, or None.
    """
    role_name, session_name = _caller_identity(event)
    if role_name is None:
        return None
    if role_name in _TRUSTED_ROLES:
        target = _body_instance_id(event)
        if not target:
            logger.warning("Trusted caller %s supplied no valid instance_id", role_name)
        return target
    # VDI path: attested identity only.
    if session_name and _INSTANCE_ID_RE.match(session_name):
        return session_name
    logger.warning("Untrusted caller with no attested instance-id (role=%s)", role_name)
    return None


def _render_line(row):
    """Render one DB row as a validated DCV filter string, or None if invalid."""
    label, base_class, sub_class, protocol, vid, pid, autoshare, skip_reset = row
    label = "" if label is None else str(label)
    base_class = "" if base_class is None else str(base_class)
    sub_class = "" if sub_class is None else str(sub_class)
    protocol = "" if protocol is None else str(protocol)
    vid = "" if vid is None else str(vid)
    pid = "" if pid is None else str(pid)

    if not label or _LABEL_BAD_RE.search(label):
        logger.warning("Skipping entry with invalid label")
        return None
    for field in (base_class, sub_class, protocol):
        if not _CLASS_RE.match(field):
            logger.warning("Skipping entry with invalid class field: %s", field)
            return None
    for field in (vid, pid):
        if not _ID_RE.match(field):
            logger.warning("Skipping entry with invalid id field: %s", field)
            return None

    auto = "1" if autoshare else "0"
    reset = "1" if skip_reset else "0"
    return f"{label},{base_class},{sub_class},{protocol},{vid},{pid},{auto},{reset}"


def _text_response(status, body):
    return {
        "statusCode": status,
        "headers": {"content-type": "text/plain; charset=utf-8"},
        "body": body,
    }


def handler(event, context):
    instance_id = _resolve_target_instance_id(event)
    if not instance_id:
        # No resolvable target -> empty allowlist (DCV defaults). Return 200 so
        # the boot hook writes an empty file rather than treating non-200 as an
        # error and leaving a stale file.
        return _text_response(200, "")

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_RESOLVE_SQL, {"instance_id": instance_id})
                rows = cur.fetchall()
    except Exception:
        logger.exception("DB query failed for %s", instance_id)
        return _text_response(500, "")

    lines = [line for line in (_render_line(r) for r in rows) if line is not None]
    logger.info("Resolved %d USB allowlist entries for %s", len(lines), instance_id)

    body = "\n".join(lines)
    if body:
        body += "\n"
    return _text_response(200, body)
