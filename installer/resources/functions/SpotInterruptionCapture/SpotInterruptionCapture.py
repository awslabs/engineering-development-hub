# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
SpotInterruptionCapture -- EventBridge-triggered Lambda that auto-captures a
Spot VDI when the EC2 Spot Interruption Warning (2-min notice) fires.

Trigger: EventBridge rule on source=aws.ec2, detail-type="EC2 Spot Instance
Interruption Warning". The instance-id is in detail.instance-id.

Action (same primitives as the web-tier Save & Park, but fire-and-forget from
a Lambda in the 2-min reclaim window):
  1. Describe the instance; verify it's our cluster + dcv_node + Spot.
  2. Arm the resume-heal Scheduled Task on the instance (SSM, fire-and-forget).
  3. Tag edh:PreserveAdObject=true (ADComputerCleaner skip-guard).
  4. create-image (NoReboot=true) with cluster + custom tags on image + snapshot.
  5. Write the vdi_saved_images registry row (source='interrupt', state='capturing').

The instance will be reclaimed ~2 min after the event fires. create-image is
initiated (not completed) within seconds; EBS snapshots finish asynchronously
even after the instance terminates. The web-tier's Gap A promote pass flips the
row to 'available' once the AMI is ready.

Idempotency: if a saved-image row already exists for this session_uuid with
state != 'consumed', skip (duplicate event or a manual Save & Park already ran).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
import psycopg

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "")
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]
DB_ENDPOINT = os.environ["DB_ENDPOINT"]
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "edh")


def _get_db_conn():
    sm = boto3.client("secretsmanager", region_name=REGION)
    sec = json.loads(sm.get_secret_value(SecretId=DB_SECRET_ARN)["SecretString"])
    return psycopg.connect(
        host=DB_ENDPOINT, port=DB_PORT, dbname=DB_NAME,
        user=sec.get("username") or sec.get("user"),
        password=sec.get("password"), sslmode="require", autocommit=True,
    )


def _instance_info(ec2, instance_id: str) -> tuple[dict[str, str], str]:
    """Returns (tags_dict, instance_type)."""
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in (i.get("Tags") or [])}
            return tags, i.get("InstanceType", "")
    return {}, ""


def _saved_desktops_enabled() -> bool:
    # Runtime gate: the Lambda + EventBridge rule are always deployed, but capture
    # only fires when AllowSavedDesktops is on. Defaults False (ships dark).
    try:
        _ssm = boto3.client("ssm", region_name=REGION)
        _v = _ssm.get_parameter(
            Name=f"/edh/{CLUSTER_ID}/configuration/FeatureFlags/VirtualDesktops/AllowSavedDesktops"
        )["Parameter"]["Value"]
        return str(_v).strip().lower() == "true"
    except Exception:
        return False


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    if not _saved_desktops_enabled():
        return {"action": "ignored", "reason": "saved_desktops_disabled"}

    detail = event.get("detail") or {}
    instance_id = detail.get("instance-id")
    if not instance_id:
        return {"action": "ignored", "reason": "no_instance_id"}

    ec2 = boto3.client("ec2", region_name=REGION)
    tags, instance_type = _instance_info(ec2, instance_id)

    if tags.get("edh:ClusterId") != CLUSTER_ID:
        return {"action": "ignored", "reason": "different_cluster"}
    if tags.get("edh:NodeType") != "dcv_node":
        return {"action": "ignored", "reason": "not_dcv_node"}

    session_uuid = tags.get("edh:DCVSessionUUID")
    session_owner = tags.get("edh:JobOwner")
    ad_name = tags.get("edh:ADComputerName", "")
    base_os = tags.get("edh:DCVSystem", "")

    if not session_uuid:
        return {"action": "ignored", "reason": "no_session_uuid"}

    # Idempotency: skip if already captured for this session
    conn = _get_db_conn()
    cur = conn.cursor()
    # Self-heal the idempotency index on DBs created before it (fresh installs get it via the model).
    try:
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_vdi_saved_active_session "
            "ON vdi_saved_images (origin_session_uuid) "
            "WHERE state != 'consumed' AND is_active = true"
        )
    except Exception as _ix_err:
        logger.warning(f"idempotency index ensure failed: {_ix_err}")
    cur.execute(
        "SELECT id FROM vdi_saved_images WHERE origin_session_uuid=%s AND state != 'consumed' AND is_active=true",
        (session_uuid,),
    )
    if cur.fetchone():
        cur.close()
        conn.close()
        return {"action": "skipped", "reason": "already_captured", "session_uuid": session_uuid}

    logger.info(f"Spot ITN capture for {instance_id} session={session_uuid} owner={session_owner}")

    # --- Parallel execution: arm-task, preserve-tag, create-image, describe-volumes ---
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ts = int(datetime.now(timezone.utc).timestamp())
    name = f"edh-savedvdi-{session_uuid}-{ts}"
    img_tags = [
        {"Key": "Name", "Value": name},
        {"Key": "edh:ClusterId", "Value": CLUSTER_ID},
        {"Key": "edh:SavedVdiOwner", "Value": session_owner or ""},
        {"Key": "edh:OriginSessionUuid", "Value": session_uuid},
        {"Key": "edh:SavedVdiName", "Value": tags.get("edh:JobName", "")},
    ]

    image_id = None
    root_bytes = 0

    def _do_preserve():
        try:
            ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "edh:PreserveAdObject", "Value": "true"}])
        except Exception as err:
            logger.warning(f"Preserve tag failed: {err}")

    def _do_create_image():
        return ec2.create_image(
            InstanceId=instance_id, Name=name, NoReboot=True,
            Description=f"EDH auto-capture on Spot interruption ({session_uuid})",
            TagSpecifications=[
                {"ResourceType": "image", "Tags": img_tags},
                {"ResourceType": "snapshot", "Tags": img_tags},
            ],
        )

    def _do_describe_volumes():
        vols = ec2.describe_volumes(Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}])
        return sum(int(v.get("Size", 0)) for v in vols.get("Volumes", [])) * 1073741824

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_preserve = pool.submit(_do_preserve)
        f_image = pool.submit(_do_create_image)
        f_vols = pool.submit(_do_describe_volumes)

    # Collect results
    try:
        img_resp = f_image.result()
        image_id = img_resp["ImageId"]
    except Exception as err:
        logger.error(f"create-image failed: {err}")
        cur.close()
        conn.close()
        return {"action": "failed", "reason": "create_image_failed", "error": str(err)}

    try:
        root_bytes = f_vols.result()
    except Exception:
        pass

    # --- DB writes (serial, need image_id) ---
    software_stack_id = None
    try:
        cur.execute(
            "SELECT software_stack_id FROM virtual_desktop_sessions "
            "WHERE session_uuid=%s ORDER BY created_on DESC LIMIT 1",
            (session_uuid,),
        )
        _sid_row = cur.fetchone()
        if _sid_row:
            software_stack_id = _sid_row[0]
    except Exception as err:
        logger.warning(f"software_stack_id lookup failed: {err}")

    _duplicate = False
    try:
        cur.execute(
            """INSERT INTO vdi_saved_images
               (image_id, origin_session_uuid, session_name, os_family, base_os,
                instance_type, root_bytes, software_stack_label, created_by, owner,
                source, state, pinned, is_active, created_on, software_stack_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (origin_session_uuid)
               WHERE state != 'consumed' AND is_active = true
               DO NOTHING""",
            (image_id, session_uuid, tags.get("edh:JobName", "spot-captured"),
             "windows" if "windows" in base_os.lower() else "linux", base_os,
             instance_type, root_bytes, "",
             session_owner or "", session_owner or "",
             "interrupt", "capturing", False, True, datetime.now(timezone.utc),
             software_stack_id),
        )
        _duplicate = cur.rowcount == 0
    except Exception as err:
        logger.error(f"DB insert failed: {err}")

    if _duplicate:
        # A concurrent delivery already registered this capture; drop our orphan AMI.
        logger.info(f"Duplicate capture for {session_uuid}; deregistering orphan {image_id}")
        try:
            ec2.deregister_image(ImageId=image_id)
        except Exception as _dder:
            logger.warning(f"orphan image deregister failed: {_dder}")
        cur.close()
        conn.close()
        return {"action": "skipped", "reason": "already_captured", "session_uuid": session_uuid}

    # Mark the VDI session 'interrupting' (spot reclaim in progress; distinct from a
    # user-initiated 'stopping'). session_state_enum includes 'interrupting'.
    try:
        cur.execute(
            "UPDATE virtual_desktop_sessions SET session_state='interrupting', "
            "session_state_latest_change_time=NOW() "
            "WHERE session_uuid=%s AND is_active=true",
            (session_uuid,),
        )
    except Exception as err:
        logger.warning(f"Could not set session to interrupting: {err}")

    cur.close()
    conn.close()

    logger.info(f"Spot ITN capture initiated: {image_id} for {session_uuid}")
    return {
        "action": "captured",
        "image_id": image_id,
        "instance_id": instance_id,
        "session_uuid": session_uuid,
    }
