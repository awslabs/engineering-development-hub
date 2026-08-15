# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
from flask import request, session
import logging
import os
from datetime import datetime, timezone
import utils.aws.boto3_wrapper as utils_boto3
from decorators import private_api
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.error import SocaError

logger = logging.getLogger("soca_logger")


def _is_active_shared_guest(broker_session_id, username):
    """True when `username` holds an active, unexpired session-sharing grant on
    the broker session `broker_session_id`. Lets a guest view the shared
    session's screenshot thumbnail (the owner is always allowed separately)."""
    if not broker_session_id or not username:
        return False
    try:
        # Cluster policy gate: guest thumbnails default on; owner-only when off.
        from utils.config import SocaConfig
        from utils.cast import SocaCastEngine
        _raw = SocaConfig(
            key="/configuration/dcv/session_sharing/guest_screenshot_enabled"
        ).get_value().message
        _cast = SocaCastEngine(_raw).cast_as(bool)
        if _cast.success and not _cast.message:
            return False
    except Exception:
        pass
    try:
        from helpers import dcv_session_sharing_store
        svc = dcv_session_sharing_store.get_grant_service()
        if not svc:
            return False
        _now = datetime.now(timezone.utc)
        for _g in svc.list_grants_for_session(broker_session_id, status="ACTIVE"):
            if _g.get("guest_username", "").lower() != username.lower():
                continue
            _exp = _g.get("expires_at")
            if _exp:
                try:
                    _exp_dt = datetime.fromisoformat(_exp)
                except ValueError:
                    continue  # unparseable expiry -> treat as invalid (fail closed)
                if _exp_dt.tzinfo is None:
                    _exp_dt = _exp_dt.replace(tzinfo=timezone.utc)
                if _exp_dt <= _now:
                    continue
            return True
        return False
    except Exception as err:
        logger.warning(f"shared-guest screenshot authz check failed: {err}")
        return False


def _session_thumbnail(session_uuid):
    """Return the session's software-stack thumbnail (base64 data-URI) or None."""
    if not session_uuid:
        return None
    try:
        from models import VirtualDesktopSessions
        _row = VirtualDesktopSessions.query.filter_by(
            session_uuid=session_uuid, is_active=True
        ).first()
        return _row.session_thumbnail if _row else None
    except Exception:
        return None


# Lazily created so we do not open a boto3 client at import time. Under gevent
# (uwsgi), creating the client during module import can run before the workers
# fork, and a client built in the parent is unsafe to share across forked
# greenlet workers. Build it on first use inside the request instead.
_client_s3 = None


def _get_s3_client():
    global _client_s3
    if _client_s3 is None:
        _resp = utils_boto3.get_boto(service_name="s3")
        if _resp.get("success") is False:
            logger.error(f"Failed to get boto3 client for s3: {_resp.get('message')}")
            return None
        _client_s3 = _resp.get("message")
    return _client_s3


class VirtualDesktopScreenshot(Resource):
    @private_api
    def get(self):
        r"""
        Return a pre-signed S3 URL for a session screenshot
        ---
        openapi: 3.1.0
        operationId: getVirtualDesktopScreenshot
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
          - name: session_id
            in: query
            schema:
              type: string
            required: true
            description: UUID of the DCV session to retrieve the screenshot for
        responses:
          '200':
            description: Screenshot lookup result (success=true with URL, or success=false if unavailable)
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      oneOf:
                        - type: object
                          description: Pre-signed URL (when success is true)
                          properties:
                            url:
                              type: string
                              format: uri
                              description: Pre-signed S3 URL for the screenshot (expires in 5 minutes)
                        - type: string
                          description: Error message (when success is false, e.g. "No screenshot available")
          '401':
            description: Authentication required
          '403':
            description: Not authorized to view the screenshot for this session
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_id", type=str, required=True, location="args")
        args = parser.parse_args()

        cluster_id = os.environ.get("EDH_CLUSTER_ID")
        # Prefer the dedicated screenshot bucket if CDK published it.
        # Falls back to the legacy shared cluster bucket so older
        # deployments keep working without rotation.
        screenshot_bucket = (
            SocaConfig(key="/dcv/screenshot/s3_bucket").get_value().get("message")
        )
        if screenshot_bucket and screenshot_bucket != "CACHE_MISS":
            bucket = screenshot_bucket
            use_dedicated_bucket = True
        else:
            bucket = SocaConfig(key="/configuration/S3Bucket").get_value().get("message")
            use_dedicated_bucket = False

        # Determine the right S3 key. In high-scale mode, screenshots are
        # named by the broker session Id (DcvScreenshotPoller saves
        # `<broker_session_id>.jpg`), but the frontend passes our SOCA
        # session_uuid as `session_id`. Resolve the broker handle from DB
        # via `authentication_token` (reused column) when HS is enabled.
        # In non-HS mode, the local DCV session id == SOCA session_uuid,
        # so the input is already correct.
        is_high_scale = (
            str(
                SocaConfig(key="/dcv/high_scale_enabled")
                .get_value()
                .get("message", "false")
            )
            .lower()
            == "true"
        )
        s3_session_id = args["session_id"]
        if is_high_scale:
            try:
                from models import VirtualDesktopSessions
                _row = VirtualDesktopSessions.query.filter_by(
                    session_uuid=args["session_id"], is_active=True
                ).first()
                if _row and _row.authentication_token:
                    s3_session_id = _row.authentication_token
                # Ownership check: the session owner, or a user holding an
                # active sharing grant on this session, may view its screenshot.
                _requesting_user = request.headers.get("X-EDH-USER", "") or session.get("user", "")
                if (
                    _row
                    and _row.session_owner != _requesting_user
                    and not _is_active_shared_guest(_row.authentication_token, _requesting_user)
                ):
                    return SocaError.VIRTUAL_DESKTOP_AUTHENTICATION_ERROR(
                        helper="Not authorized to view this screenshot",
                        status_code=403,
                    ).as_flask()
            except Exception as err:
                logger.warning(
                    f"VirtualDesktopScreenshot: lookup of broker session id failed: {err}"
                )
        else:
            # Non-HS: still enforce ownership.
            try:
                from models import VirtualDesktopSessions
                _row = VirtualDesktopSessions.query.filter_by(
                    session_uuid=args["session_id"], is_active=True
                ).first()
                _requesting_user = request.headers.get("X-EDH-USER", "") or session.get("user", "")
                if (
                    _row
                    and _row.session_owner != _requesting_user
                    and not _is_active_shared_guest(_row.authentication_token, _requesting_user)
                ):
                    return SocaError.VIRTUAL_DESKTOP_AUTHENTICATION_ERROR(
                        helper="Not authorized to view this screenshot",
                        status_code=403,
                    ).as_flask()
            except Exception:
                pass  # fail-open on lookup error (legacy clusters may not have the column)

        # Dedicated bucket has flat keys (no prefix). Legacy shared
        # bucket nests under <cluster>/dcv/screenshots/.
        # Explicit prefix (cluster/existing modes) wins when published.
        try:
            _ss_prefix = (
                SocaConfig(key="/dcv/screenshot/s3_prefix").get_value().get("message", "")
            )
        except Exception:
            _ss_prefix = ""
        if _ss_prefix in ("CACHE_MISS", None, "~"):
            _ss_prefix = ""
        if _ss_prefix:
            s3_key = f"{_ss_prefix}{s3_session_id}.jpg"
        elif use_dedicated_bucket:
            s3_key = f"{s3_session_id}.jpg"
        else:
            s3_key = f"{cluster_id}/dcv/screenshots/{s3_session_id}.jpg"

        try:
            # Discover bucket region so we sign for it. The helper's
            # default S3 client now auto-applies SigV4 + virtual-hosted
            # + regional endpoint when called with the right
            # region_name (see utils/aws/boto3_wrapper.py).
            try:
                _bucket_region = (
                    _get_s3_client().head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPHeaders"]
                    .get("x-amz-bucket-region", "us-east-1")
                )
            except Exception:
                _bucket_region = "us-east-1"
            _signing_resp = utils_boto3.get_boto(
                service_name="s3", region_name=_bucket_region
            )
            if _signing_resp.get("success") is False:
                logger.error(
                    f"Failed to get boto3 client for s3: {_signing_resp.get('message')}"
                )
                return SocaResponse(
                    success=False, message="Unable to create S3 client for screenshot"
                ).as_flask()
            _signing_s3 = _signing_resp.get("message")

            # Check if screenshot exists
            _signing_s3.head_object(Bucket=bucket, Key=s3_key)

            # Generate pre-signed URL (5 min expiry)
            url = _signing_s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": s3_key},
                ExpiresIn=300,
            )

            return SocaResponse(
                success=True,
                message={"url": url, "is_placeholder": False},
            ).as_flask()

        except _signing_s3.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return SocaResponse(
                    success=True,
                    message={"url": _session_thumbnail(args["session_id"]), "is_placeholder": True},
                ).as_flask()
            raise
