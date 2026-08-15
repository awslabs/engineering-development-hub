# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Owned-base AMI lineage: launch-time resolver + feature gate.

Hot-path contract: resolve_launch_ami() is a cheap registry read that returns the owned copy of
a base when one is active, else the unchanged source AMI id. It never calls DescribeImages
(ownership/copyability is decided at discovery time by the reconciler) and is a strict
passthrough when the feature flag is off or anything errors (fail-safe).
"""

import logging

from extensions import db
from models import BaseImageRegistry
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

_FF_KEY = "/configuration/BaseImageAcceleration/Enabled"
_REGION_KEY = "/configuration/Region"


def _is_enabled() -> bool:
    """Cluster-wide feature gate. Default off; passthrough when off. Internal helper (raw bool)."""
    try:
        _v = (
            SocaConfig(key=_FF_KEY)
            .get_value(default="false", allow_unknown_key=True)
            .get("message", "false")
        )
        return (
            SocaCastEngine(_v).cast_as(expected_type=str).get("message", "false").lower()
            == "true"
        )
    except Exception:
        return False


def _cluster_region() -> str:
    try:
        return (
            SocaConfig(key=_REGION_KEY)
            .get_value(default="", allow_unknown_key=True)
            .get("message", "")
        )
    except Exception:
        return ""


def resolve_launch_ami(source_ami_id: str, region: str = None) -> SocaResponse:
    """Return the active owned copy of source_ami_id in region, else source_ami_id unchanged.

    region defaults to the cluster's home region (`/configuration/Region`). Cheap registry read,
    no AWS calls. Fail-safe: FF-off or any error passes through the input. Callers read `.get("message")`.
    """
    if not Validators.exist(source_ami_id) or not _is_enabled():
        return SocaResponse(success=True, message=source_ami_id)
    region = region or _cluster_region()
    if not region:
        return SocaResponse(success=True, message=source_ami_id)
    try:
        _row = (
            db.session.query(BaseImageRegistry)
            .filter(
                BaseImageRegistry.source_ami_id == source_ami_id,
                BaseImageRegistry.region == region,
                BaseImageRegistry.status == "active",
            )
            .first()
        )
        if _row and _row.owned_ami_id:
            logger.info(
                f"BaseImageAcceleration: resolved {source_ami_id} -> owned {_row.owned_ami_id} in {region}"
            )
            return SocaResponse(success=True, message=_row.owned_ami_id)
    except Exception as e:
        # Fail-safe: structured-log the error but still pass through to source so launches never break
        SocaError.DB_ERROR(helper=f"resolve_launch_ami query failed for {source_ami_id} in {region}: {e}")
    return SocaResponse(success=True, message=source_ami_id)


def _jsonsafe(row: dict) -> dict:
    """Coerce datetime/enum column values to JSON-serializable strings."""
    out = {}
    for k, v in row.items():
        out[k] = v.isoformat() if hasattr(v, "isoformat") else v
    return out


def list_status(region: str = None) -> SocaResponse:
    """Admin status view ('Local Acceleration Mirror'): feature state + registry rows for the region."""
    region = region or _cluster_region()
    out = {"enabled": _is_enabled(), "region": region, "rows": []}
    try:
        _q = db.session.query(BaseImageRegistry)
        if region:
            _q = _q.filter(BaseImageRegistry.region == region)
        out["rows"] = [
            _jsonsafe(r.as_dict())
            for r in _q.order_by(
                BaseImageRegistry.base_os.asc(), BaseImageRegistry.arch.asc()
            ).all()
        ]
    except Exception as e:
        return SocaError.DB_ERROR(helper=f"BaseImageAcceleration status query failed: {e}")
    return SocaResponse(success=True, message=out)
