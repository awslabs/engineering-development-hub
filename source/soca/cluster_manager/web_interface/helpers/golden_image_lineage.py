# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Golden Image Lineage — Background CopyImage for account ownership.

After a golden image is published, this module copies the AMI into
account ownership so that:
  1. Downstream VDI saves produce fast incremental snapshots (delta)
  2. The snapshot becomes FSR-eligible (cannot FSR AWS-owned snapshots)

The copy runs asynchronously. The stack is immediately active with the
source AMI. When CopyImage completes, the stack's active_ami_id is
swapped to the owned copy.

If CopyImage fails (e.g. Marketplace AMI, access denied), the publish
succeeds regardless — the admin gets an advisory notification and the
version record is stamped copy_failed.
"""

import logging
import threading
import time
from typing import Optional

import utils.aws.boto3_wrapper as utils_boto3
from models import db, SoftwareStacks, SoftwareStackVersion
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

# How long to wait for CopyImage to complete (seconds)
_COPY_WAIT_TIMEOUT = 1800  # 30 min max for large images
_COPY_POLL_INTERVAL = 30


def trigger_lineage_copy(
    app,
    stack_id: int,
    version_id: int,
    ami_id: str,
    source_ami_id: str,
) -> SocaResponse:
    """Fire-and-forget background CopyImage.

    `app` is the real Flask app object (captured in the request/parent context)
    so the daemon thread can push its own app_context for DB access.
    """
    _thread = threading.Thread(
        target=_lineage_copy_worker,
        args=(app, stack_id, version_id, ami_id, source_ami_id),
        daemon=True,
        name=f"golden-lineage-{stack_id}-v{version_id}",
    )
    _thread.start()
    logger.info(
        f"Golden lineage: background CopyImage started for stack {stack_id} "
        f"version {version_id} (ami={ami_id})"
    )
    # Programmatic dispatch ack -- consumed in-process, never an HTTP response (no .as_flask()).
    return SocaResponse(
        success=True,
        message=f"Lineage copy started for stack {stack_id} version {version_id}",
    )


def _lineage_copy_worker(
    app, stack_id: int, version_id: int, ami_id: str, source_ami_id: str
) -> None:
    """Background worker: copy AMI into account ownership."""
    with app.app_context():
        try:
            _do_copy(stack_id, version_id, ami_id, source_ami_id)
        except Exception as err:
            logger.error(
                f"Golden lineage: CopyImage failed for stack {stack_id} "
                f"version {version_id}: {err}"
            )
            _mark_copy_failed(version_id, str(err))


def _cleanup_ami(client_ec2, ami_id: str) -> None:
    """Best-effort deregister an AMI and delete its backing snapshots."""
    _snap_ids = []
    try:
        _desc = client_ec2.describe_images(ImageIds=[ami_id])
        for _img in _desc.get("Images", []):
            for _bdm in _img.get("BlockDeviceMappings", []):
                _sid = (_bdm.get("Ebs") or {}).get("SnapshotId")
                if _sid:
                    _snap_ids.append(_sid)
    except Exception as err:
        logger.warning(f"Golden lineage: describe for cleanup of {ami_id} failed: {err}")
    try:
        client_ec2.deregister_image(ImageId=ami_id)
    except Exception as err:
        logger.warning(f"Golden lineage: deregister {ami_id} failed: {err}")
    for _sid in _snap_ids:
        try:
            client_ec2.delete_snapshot(SnapshotId=_sid)
        except Exception as err:
            logger.warning(f"Golden lineage: delete_snapshot {_sid} failed: {err}")


def _do_copy(stack_id: int, version_id: int, ami_id: str, source_ami_id: str) -> None:
    """Execute the CopyImage and update records on success."""
    _ec2_resp = utils_boto3.get_boto(service_name="ec2")
    if _ec2_resp.get('success') is False:
        raise RuntimeError("Failed to get boto3 ec2 client")
    client_ec2 = _ec2_resp.get("message")
    _sts_resp = utils_boto3.get_boto(service_name="sts")
    if _sts_resp.get('success') is False:
        raise RuntimeError("Failed to get boto3 sts client")
    client_sts = _sts_resp.get("message")

    # Check if the AMI is already owned by this account
    _account_id = client_sts.get_caller_identity()["Account"]
    _image_info = client_ec2.describe_images(ImageIds=[ami_id])
    if not _image_info.get("Images"):
        raise RuntimeError(f"AMI {ami_id} not found")

    _owner = _image_info["Images"][0].get("OwnerId", "")
    if _owner == _account_id:
        # Already account-owned — no copy needed
        logger.info(f"Golden lineage: {ami_id} already owned by {_account_id}, skip copy")
        _mark_copy_complete(stack_id, version_id, ami_id)
        return

    # Mark version as copying
    _update_lineage_status(version_id, "copying")

    # Execute CopyImage
    _copy_name = f"edh-golden-owned-{int(time.time())}"
    try:
        _resp = client_ec2.copy_image(
            SourceImageId=ami_id,
            SourceRegion=_get_region(client_ec2),
            Name=_copy_name,
            Description=f"Account-owned copy of golden image {ami_id} (source: {source_ami_id})",
            TagSpecifications=[
                {
                    "ResourceType": "image",
                    "Tags": [
                        {"Key": "Name", "Value": _copy_name},
                        {"Key": "edh:GoldenImage", "Value": "true"},
                        {"Key": "edh:SourceAmi", "Value": source_ami_id},
                        {"Key": "edh:LineageCopy", "Value": "true"},
                    ],
                }
            ],
        )
        _new_ami_id = _resp["ImageId"]
    except Exception as err:
        # CopyImage can fail for Marketplace AMIs, access denied, etc.
        raise RuntimeError(f"CopyImage call failed: {err}")

    logger.info(f"Golden lineage: CopyImage initiated → {_new_ami_id}")

    # Wait for the copy to complete
    _deadline = time.time() + _COPY_WAIT_TIMEOUT
    while time.time() < _deadline:
        try:
            _desc = client_ec2.describe_images(ImageIds=[_new_ami_id])
            _state = _desc["Images"][0]["State"]
            if _state == "available":
                logger.info(f"Golden lineage: {_new_ami_id} available")
                _mark_copy_complete(stack_id, version_id, _new_ami_id)
                return
            if _state == "failed":
                _cleanup_ami(client_ec2, _new_ami_id)
                raise RuntimeError(f"CopyImage {_new_ami_id} failed")
        except client_ec2.exceptions.ClientError as ce:
            # Image might not be visible yet immediately after copy_image
            if "InvalidAMIID.NotFound" not in str(ce):
                raise
        time.sleep(_COPY_POLL_INTERVAL)

    _cleanup_ami(client_ec2, _new_ami_id)
    raise TimeoutError(f"CopyImage {_new_ami_id} did not complete within {_COPY_WAIT_TIMEOUT}s")


def _mark_copy_complete(stack_id: int, version_id: int, owned_ami_id: str) -> None:
    """Update the version record and swap the stack's active AMI."""
    _version = SoftwareStackVersion.query.filter_by(id=version_id).first()
    if _version:
        _version.owned_ami_id = owned_ami_id
        _version.lineage_status = "owned"

    # Only swap the stack AMI if this version is still the active one
    _stack = SoftwareStacks.query.filter_by(id=stack_id, is_active=True).first()
    if _stack and _version and _version.is_active:
        _stack.ami_id = owned_ami_id
        logger.info(
            f"Golden lineage: swapped stack {stack_id} AMI to owned copy {owned_ami_id}"
        )

    try:
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        logger.error(f"Golden lineage: DB commit failed: {err}")


def _mark_copy_failed(version_id: int, error_msg: str) -> None:
    """Stamp the version record as copy_failed."""
    try:
        _version = SoftwareStackVersion.query.filter_by(id=version_id).first()
        if _version:
            _version.lineage_status = "copy_failed"
            db.session.commit()
    except Exception as err:
        db.session.rollback()
        logger.error(f"Golden lineage: failed to mark copy_failed: {err}")


def _update_lineage_status(version_id: int, status: str) -> None:
    """Update the lineage_status field on a version record."""
    try:
        _version = SoftwareStackVersion.query.filter_by(id=version_id).first()
        if _version:
            _version.lineage_status = status
            db.session.commit()
    except Exception as err:
        db.session.rollback()
        logger.error(f"Golden lineage: failed to update status to {status}: {err}")


def _get_region(client_ec2) -> str:
    """Get the current region from the EC2 client's session."""
    return client_ec2.meta.region_name
