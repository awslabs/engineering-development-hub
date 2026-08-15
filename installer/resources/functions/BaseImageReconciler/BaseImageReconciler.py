# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BaseImageReconciler -- owned-base AMI lineage copy engine.

Event-driven, idempotent reconciler over the base_image_registry Aurora table:
  * schedule / CR invoke -> refresh drift-check + drive pending copies (<= MaxConcurrency)
  * "EC2 AMI State Change" -> flip copying->active/failed, then drive the queue

CopyImage is async (returns immediately), so completion arrives as an EventBridge event and
the Lambda never blocks on the ~30-min copy. No-op when the feature flag is off. Copyability is
decided by attempting CopyImage and handling the real error (failed -> resolver falls back to source).
"""

import datetime
import json
import logging
import os

import boto3
import botocore

import psycopg

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ["REGION"]
CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
DB_HOST = os.environ["DB_HOST"]
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ["DB_NAME"]
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]
FF_KEY = os.environ["FF_KEY"]
MANIFEST_KEY = os.environ.get("MANIFEST_KEY", "")
PRIORITY_KEY = os.environ.get("PRIORITY_KEY", "")
DEFAULT_PRIORITY = os.environ.get(
    "COPY_PRIORITY", '{"x86_64": ["windows2025", "amazonlinux2023"], "arm64": ["amazonlinux2023"]}'
)
QUOTA_SERVICE = os.environ.get("COPY_QUOTA_SERVICE", "ebs")
QUOTA_CODE = os.environ.get("COPY_QUOTA_CODE", "L-39BD5252")
RESERVE = int(os.environ.get("COPY_RESERVE", "1"))
DEFAULT_MAX = int(os.environ.get("BASE_IMAGE_MAX_CONCURRENCY", "4"))
COPY_CMK_ARN = os.environ.get("COPY_CMK_ARN", "")
STUCK_COPY_MINUTES = int(os.environ.get("STUCK_COPY_MINUTES", "10"))  # reset copying+no-AMI rows older than this

_ec2 = boto3.client("ec2", region_name=REGION)
_ssm = boto3.client("ssm", region_name=REGION)
_sm = boto3.client("secretsmanager", region_name=REGION)
_sq = boto3.client("service-quotas", region_name=REGION)
_sts = boto3.client("sts", region_name=REGION)

_ACCOUNT = None


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _account():
    global _ACCOUNT
    if _ACCOUNT is None:
        _ACCOUNT = _sts.get_caller_identity()["Account"]
    return _ACCOUNT


def _enabled():
    try:
        return str(_ssm.get_parameter(Name=FF_KEY)["Parameter"]["Value"]).lower() == "true"
    except Exception:
        return False


def _max_concurrency():
    try:
        live = int(
            _sq.get_service_quota(ServiceCode=QUOTA_SERVICE, QuotaCode=QUOTA_CODE)["Quota"]["Value"]
        )
        return max(1, live - RESERVE)  # leave headroom for non-EDH copies
    except Exception:
        return DEFAULT_MAX


def _priority_map():
    """{ arch: [ordered base_os, ...] } copied first within each arch. SSM-tunable JSON, env fallback."""
    _val = DEFAULT_PRIORITY
    if PRIORITY_KEY:
        try:
            _v = _ssm.get_parameter(Name=PRIORITY_KEY)["Parameter"]["Value"]
            if _v:
                _val = _v
        except Exception:
            pass
    try:
        _m = json.loads(_val)
        return {
            str(a).lower(): [str(b).lower() for b in (lst or [])]
            for a, lst in _m.items()
        }
    except Exception:
        return {}


def _rank(base_os, arch, pmap):
    """Rank = base_os position within its arch's list; unlisted -> sorts after all prioritized."""
    _lst = pmap.get((arch or "").lower(), [])
    _b = (base_os or "").lower()
    return _lst.index(_b) if _b in _lst else 9999


def _conn():
    _s = json.loads(_sm.get_secret_value(SecretId=DB_SECRET_ARN)["SecretString"])
    return psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=_s["username"],
        password=_s["password"],
        connect_timeout=10,
    )


def _resolve_alias(alias):
    try:
        _v = _ssm.get_parameter(Name=alias)["Parameter"]["Value"]
        return _v if _v.startswith("ami-") else None
    except Exception:
        return None


def _describe(ami_id):
    try:
        _imgs = _ec2.describe_images(ImageIds=[ami_id]).get("Images", [])
        if not _imgs:
            return None, None
        return _imgs[0].get("OwnerId"), _imgs[0].get("DeprecationTime")
    except botocore.exceptions.ClientError:
        return None, None


def _read_manifest():
    """Load the region_map-derived manifest written to SSM at install."""
    if not MANIFEST_KEY:
        return []
    try:
        return json.loads(_ssm.get_parameter(Name=MANIFEST_KEY)["Parameter"]["Value"])
    except Exception:
        return []


def handler(event, context):
    if not _enabled():
        logger.info("BaseImageAcceleration disabled; no-op")
        return {"ok": True, "disabled": True}
    with _conn() as conn:
        if isinstance(event, dict) and event.get("detail-type") == "EC2 AMI State Change":
            _on_state_change(conn, event.get("detail", {}) or {})
        else:
            if isinstance(event, dict) and event.get("retry_failed"):
                # Operational re-drive: reset failed rows to pending (terminal failures
                # like unsubscribed marketplace bases simply fail again, fast).
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE base_image_registry SET status='pending', last_error=NULL "
                        "WHERE region=%s AND status='failed'",
                        (REGION,),
                    )
                conn.commit()
            _manifest = (event or {}).get("manifest") if isinstance(event, dict) else None
            if not _manifest:
                _manifest = _read_manifest()
            if _manifest:
                _seed(conn, _manifest)
            _refresh(conn)
        _drive(conn)
    return {"ok": True}


def _seed(conn, manifest):
    """Discovery: resolve alias -> concrete id, DescribeImages OwnerId; upsert a pending row for
    each foreign-owned base. Idempotent on (source_ami_id, region); already-owned bases are skipped."""
    for _e in manifest:
        _base_os = _e.get("base_os")
        _arch = _e.get("arch")
        _src = _e.get("source_alias") or _e.get("source_ami_id")
        if not _src:
            continue
        _alias = _src if _src.startswith("/aws/service/") else None
        _ami_id = _resolve_alias(_src) if _alias else _src
        if not _ami_id:
            continue
        _owner, _dep = _describe(_ami_id)
        if _owner is None or _owner == _account():
            continue  # undescribable or already owned in-account -> nothing to copy
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO base_image_registry
                     (base_os, arch, region, origin, source_alias, source_ami_id, source_region,
                      source_owner, source_deprecation_time, status, auto_refresh, ref_count,
                      source_resolved_at, created_on)
                   VALUES (%s,%s,%s,'aws-base',%s,%s,%s,%s,%s,'pending', true, 1, %s, %s)
                   ON CONFLICT (source_ami_id, region)
                   DO UPDATE SET source_resolved_at = EXCLUDED.source_resolved_at""",
                (_base_os, _arch, REGION, _alias, _ami_id, REGION, _owner, _dep, _now(), _now()),
            )
        conn.commit()


def _refresh(conn):
    """Re-resolve alias-backed auto_refresh rows; on drift, seed a fresh pending row."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT source_alias, source_ami_id, base_os, arch FROM base_image_registry "
            "WHERE region=%s AND auto_refresh AND source_alias IS NOT NULL",
            (REGION,),
        )
        _rows = cur.fetchall()
    for _alias, _cur_id, _base_os, _arch in _rows:
        _new = _resolve_alias(_alias)
        if _new and _new != _cur_id:
            _seed(conn, [{"base_os": _base_os, "arch": _arch, "source_alias": _alias}])


def _drive(conn):
    _maxc = _max_concurrency()
    _prio = _priority_map()
    _claimed = []
    # Recover rows stuck in 'copying' with no AMI (invocation died mid-claim) back to pending
    _stale = _now() - datetime.timedelta(minutes=STUCK_COPY_MINUTES)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE base_image_registry SET status='pending', copying_since=NULL "
            "WHERE region=%s AND status='copying' AND owned_ami_id IS NULL AND copying_since < %s",
            (REGION, _stale),
        )
    conn.commit()
    # Atomic claim under FOR UPDATE SKIP LOCKED so concurrent invocations never double-claim a row
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM base_image_registry WHERE region=%s AND status='copying'",
            (REGION,),
        )
        _slots = _maxc - cur.fetchone()[0]
        if _slots <= 0:
            return
        cur.execute(
            "SELECT id, source_ami_id, source_region, base_os, arch, created_on "
            "FROM base_image_registry WHERE region=%s AND status='pending' FOR UPDATE SKIP LOCKED",
            (REGION,),
        )
        _pending = cur.fetchall()
        # Priority-ordered: base_os position within its arch's list first, then FIFO by created_on
        _pending.sort(key=lambda r: (_rank(r[3], r[4], _prio), r[5]))
        for _row in _pending[:_slots]:
            cur.execute(
                "UPDATE base_image_registry SET status='copying', copying_since=%s WHERE id=%s",
                (_now(), _row[0]),
            )
            _claimed.append(_row)
    conn.commit()  # release locks; claimed rows are now 'copying' so peers won't repick them
    for _rid, _src_id, _src_region, _base_os, _arch, _ in _claimed:
        _start_copy(conn, _rid, _src_id, _src_region or REGION, _base_os, _arch)


def _start_copy(conn, rid, src_id, src_region, base_os, arch):
    _name = f"{CLUSTER_ID}-{base_os}-{arch}-{src_id}"  # CLUSTER_ID already carries the edh- prefix
    _tags = [
        {"Key": "edh:ClusterId", "Value": CLUSTER_ID},
        {"Key": "Name", "Value": _name},
    ]
    _owned = None
    try:
        _kwargs = {
            "Name": _name,
            "SourceImageId": src_id,
            "SourceRegion": src_region,
            # Tag on create so the ec2:CreateAction=CopyImage IAM condition is satisfied
            "TagSpecifications": [{"ResourceType": "image", "Tags": _tags}],
        }
        if COPY_CMK_ARN:
            _kwargs["Encrypted"] = True
            _kwargs["KmsKeyId"] = COPY_CMK_ARN
        _owned = _ec2.copy_image(**_kwargs)["ImageId"]
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE base_image_registry SET status='copying', owned_ami_id=%s, last_error=NULL WHERE id=%s",
                (_owned, rid),
            )
        conn.commit()
        logger.info(f"CopyImage started {src_id} -> {_owned}")
    except Exception as e:
        # Attempt-then-handle. If copy_image already returned an id, persist it (keep 'copying') so the
        # state-change rule can still advance it; otherwise fail so the resolver falls back to source.
        _msg = str(e)[:900]
        with conn.cursor() as cur:
            if _owned:
                cur.execute(
                    "UPDATE base_image_registry SET owned_ami_id=%s, last_error=%s WHERE id=%s",
                    (_owned, _msg, rid),
                )
            else:
                cur.execute(
                    "UPDATE base_image_registry SET status='failed', last_error=%s WHERE id=%s",
                    (_msg, rid),
                )
        conn.commit()
        logger.warning(f"CopyImage failed for {src_id}: {_msg}")


def _on_state_change(conn, detail):
    _ami_id = detail.get("ImageId")
    _state = str(detail.get("State", "")).lower()  # event field casing varies; normalize
    if not _ami_id:
        return
    with conn.cursor() as cur:
        if _state == "available":
            cur.execute(
                "UPDATE base_image_registry SET status='active', copied_at=%s, last_error=NULL "
                "WHERE owned_ami_id=%s AND status='copying'",
                (_now(), _ami_id),
            )
        elif _state in ("failed", "invalid", "error", "deregistered"):
            cur.execute(
                "UPDATE base_image_registry SET status='failed', last_error=%s "
                "WHERE owned_ami_id=%s AND status='copying'",
                (f"AMI state={_state}", _ami_id),
            )
    conn.commit()
