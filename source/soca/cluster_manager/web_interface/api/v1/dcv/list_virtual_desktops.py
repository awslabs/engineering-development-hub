######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

from flask_restful import Resource, reqparse
from flask import request
import logging
import json
from decorators import private_api, feature_flag
import os
import sys
from models import db, VirtualDesktopSessions, SoftwareStacks, VirtualDesktopProfiles, SessionState
import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message


# ----- Per-request perf caches -----------------------------------------------
#
# SocaConfig caching here used to be required because path queries
# bypassed the Valkey cache (the upstream "/" walk fanned out into ~390
# SSM API calls, costing 1.5-1.9s per /virtual_desktops render). That
# bug is now fixed properly by the SSM ElastiCache ConfigSync feature
# (services.ssm_elasticache_config_sync.enabled): SocaConfig.get_value()
# routes path queries through HGETALL on the cluster config hash, which
# is sub-millisecond. The local SocaConfig cache that lived here is
# therefore deleted.
#
# What remains in this block: head_bucket region resolution and per-region
# s3 client reuse. These are not SocaConfig-related -- they cache an AWS
# API response (bucket -> region) and a Boto3 session/credential
# resolution (region -> client). Both are immutable for the life of the
# controller process and have no relationship to ConfigSync.

import time as _time
import threading as _threading

_perf_cache_lock = _threading.Lock()
_bucket_region_cache: dict = {}           # bucket -> (region, fetched_at)
_s3_client_by_region: dict = {}           # region -> s3 client (lifetime)


def _get_bucket_region_cached(bucket: str) -> str:
    """head_bucket once per bucket (region is immutable for the bucket's life)."""
    if not bucket:
        return "us-east-1"
    now = _time.time()
    with _perf_cache_lock:
        cached = _bucket_region_cache.get(bucket)
        # Bucket region never changes after creation, so we only re-fetch
        # if we somehow lost it. Use a long TTL (1 hour) just in case the
        # cluster is migrated to a new bucket.
        if cached is not None and now - cached[1] < 3600.0:
            return cached[0]
    try:
        s3 = utils_boto3.get_boto(service_name="s3").message
        region = (
            s3.head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPHeaders"]
            .get("x-amz-bucket-region", "us-east-1")
        )
    except Exception:
        region = "us-east-1"
    with _perf_cache_lock:
        _bucket_region_cache[bucket] = (region, now)
    return region


def _get_s3_client_for_region(region: str):
    """Reuse a single s3 client per region across requests."""
    with _perf_cache_lock:
        cached = _s3_client_by_region.get(region)
        if cached is not None:
            return cached
    client = utils_boto3.get_boto(service_name="s3", region_name=region).message
    with _perf_cache_lock:
        _s3_client_by_region[region] = client
    return client


def _prewarm_perf_caches() -> None:
    """
    Pre-warm now intentionally a no-op. The SocaConfig pre-warm that
    used to live here was deleted alongside the SocaConfig caches when
    the SSM ElastiCache ConfigSync feature shipped (path queries hit
    HGETALL on the cluster config hash, no walk). Bucket region and
    s3 client caches that remain self-warm on first request and there
    is nothing left worth pre-fetching at module import.

    Kept as a stub so any external module that may still call it
    (defensive) does not crash; remove entirely in a follow-up cleanup
    once we've grepped the worktree to confirm no callers.
    """
    return None


_prewarm_perf_caches()


# Cap on the per-session recent-events strip embedded in the grid card.
# The full event log lives on the detail page; this is just a peek.
_RECENT_EVENTS_LIMIT = 4


def _get_recent_events_for_session(session_uuid: str) -> list:
    """
    Return the most recent N events from DDB for `session_uuid`,
    serialized as plain dicts for the JSON response.
    Order: oldest-first (chronological).
    """
    from utils.dcv_event_store import recent_events as ddb_recent_events
    try:
        events = ddb_recent_events(f"dcv#{session_uuid}", limit=_RECENT_EVENTS_LIMIT)
    except Exception:
        events = []
    return [
        {
            "id": e["id"],
            "event_type": e.get("payload", {}).get("event_type", ""),
            "checkpoint": e.get("payload", {}).get("checkpoint", ""),
            "sub_status": e.get("payload", {}).get("sub_status", ""),
            "received_at": e.get("ts", ""),
        }
        for e in events
    ]


def _get_eta_for_session(session_info) -> dict:
    """Return the launch-ETA bucket for pending/running sessions, or None.

    Only pending and running sessions get an ETA -- a stopped or
    long-running session has nothing to estimate. None when history is
    too thin (UI shows "building history"). Best-effort: never raises.
    """
    if session_info.session_state not in ("pending", "placing", "running"):
        return None
    try:
        from helpers.vdi_eta import get_eta
        return get_eta(
            stack_id=session_info.software_stack_id,
            instance_type=session_info.instance_type,
        )
    except Exception as err:
        logger.warning(
            f"eta lookup failed for {session_info.session_uuid}: {err}"
        )
        return None


class ListVirtualDesktops(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        """
        List DCV desktop sessions for a given user
        ---
        openapi: 3.1.0
        operationId: listVirtualDesktops
        tags:
          - Virtual Desktops
        summary: List user's virtual desktop sessions
        description: Retrieves DCV desktop sessions for the authenticated user with optional filtering
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
          - name: is_active
            in: query
            required: true
            schema:
              type: string
              enum: ["true", "false"]
            description: Filter sessions by active status
            example: "true"
          - name: session_uuid
            in: query
            required: false
            schema:
              type: string
              format: uuid
            description: Filter by specific session UUID
            example: "550e8400-e29b-41d4-a716-446655440000"
          - name: state
            in: query
            required: false
            schema:
              type: string
              enum: ["pending", "running", "stopped", "stopping", "terminated"]
            description: Filter by session state
            example: "running"
        responses:
          '200':
            description: Successfully retrieved virtual desktop sessions
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      additionalProperties:
                        type: object
                        required:
                          - session_uuid
                          - session_name
                          - session_state
                          - instance_type
                          - connection_string
                        properties:
                          session_uuid:
                            type: string
                            format: uuid
                            example: "550e8400-e29b-41d4-a716-446655440000"
                          session_name:
                            type: string
                            example: "my-desktop"
                          session_state:
                            type: string
                            enum: ["pending", "running", "stopped", "stopping", "terminated"]
                            example: "running"
                          instance_type:
                            type: string
                            example: "m5.large"
                          connection_string:
                            type: string
                            format: uri
                            example: "https://dcv.example.com/ip-10-0-1-100/?authToken=token123#session1"
                          session_owner:
                            type: string
                            example: "john.doe"
                          os_family:
                            type: string
                            enum: ["linux", "windows"]
                            example: "linux"
                          instance_private_ip:
                            type: string
                            format: ipv4
                            nullable: true
                            example: "10.0.1.100"
                          url:
                            type: string
                            format: uri
                            example: "https://dcv.example.com/ip-10-0-1-100/"
          '400':
            description: Bad request - missing or invalid parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "Missing required parameter: is_active"
          '401':
            description: Unauthorized - invalid user/token pair
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 401
                    message:
                      type: string
                      example: "Missing required header: X-EDH-USER"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 500
                    message:
                      type: string
                      example: "Unable to retrieve SOCA Parameters"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("is_active", type=str, location="args")
        parser.add_argument("session_uuid", type=str, location="args")
        parser.add_argument("state", type=str, location="args")
        args = parser.parse_args()
        logger.debug(f"Received parameter for listing DCV desktop: {args}")

        user = request.headers.get("X-EDH-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        if args["is_active"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="is_active").as_flask()

        _check_active = SocaCastEngine(args["is_active"]).cast_as(expected_type=bool)
        if not _check_active.success:
            return SocaError.CLIENT_INVALID_PARAMETER(
                parameter="is_active", helper="is_active must be true or false"
            ).as_flask()
        else:
            _is_active = _check_active.message

        # Retrieve sessions
        logger.info(f"Retrieving DCV sessions for {user}")
        _all_dcv_sessions = (
            VirtualDesktopSessions.query.join(
                SoftwareStacks,
                SoftwareStacks.id == VirtualDesktopSessions.software_stack_id,
            )
            .join(
                VirtualDesktopProfiles,
                VirtualDesktopProfiles.id == SoftwareStacks.virtual_desktop_profile_id,
            )
            .filter(
                VirtualDesktopSessions.session_owner == f"{user}",
                VirtualDesktopSessions.is_active == _is_active,
            )
            .add_columns(
                SoftwareStacks.virtual_desktop_profile_id,
                SoftwareStacks.ami_arch,
                VirtualDesktopProfiles.allowed_instance_types,
            )
            # Stable, deterministic tile order so cards don't reshuffle between refreshes.
            .order_by(VirtualDesktopSessions.created_on.asc())
        )

        if args["state"]:
            if args["state"] not in SessionState.enums:
                return SocaError.CLIENT_INVALID_PARAMETER(
                    parameter="state",
                    helper=f"state must be one of {SessionState.enums}",
                ).as_flask()
            logger.debug(f"Adding filter for session_state to {args['state']}")
            _all_dcv_sessions = _all_dcv_sessions.filter(
                VirtualDesktopSessions.session_state == args["state"]
            )

        if args["session_uuid"] is not None:
            logger.debug(f"Adding filter for session_uuid to {args['session_uuid']}")
            _all_dcv_sessions = _all_dcv_sessions.filter(
                VirtualDesktopSessions.session_uuid == args["session_uuid"]
            )

        logger.debug(f"Found all DCV sessions {_all_dcv_sessions.all()}")

        user_sessions = {}
        logger.info("Getting Session information for all session")

        _get_soca_parameters = SocaConfig(key="/").get_value(return_as=dict)
        if _get_soca_parameters.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve SOCA Parameters: {_get_soca_parameters.get('message')}"
            ).as_flask()
        else:
            _soca_parameters = _get_soca_parameters.get("message")

        _thumbnails = {}

        # Session sharing: build the grant service once (per request) so the
        # tile badge can show the active-share count. None when not enabled.
        # Resolve the cluster flags via SocaCastEngine (safe bool coercion).
        _sharing_enabled = SocaCastEngine(
            _soca_parameters.get("/configuration/dcv/session_sharing/enabled", "false")
        ).cast_as(bool)
        _sharing_enabled = bool(_sharing_enabled.success and _sharing_enabled.message)
        _allow_unsup = SocaCastEngine(
            _soca_parameters.get("/configuration/dcv/session_sharing/allow_unsupervised_access", "true")
        ).cast_as(bool)
        _allow_unsup = _allow_unsup.message if _allow_unsup.success else True

        _sharing_grant_svc = None
        if _sharing_enabled:
            try:
                from helpers import dcv_session_sharing_store
                _sharing_grant_svc = dcv_session_sharing_store.get_grant_service()
            except Exception as _e:
                logger.warning(f"session-sharing grant service unavailable: {_e}")

        for (
            session_info,
            virtual_desktop_profile_id,
            ami_arch,
            allowed_instance_types,
        ) in _all_dcv_sessions.all():
            try:
                # build connection string
                # console session Windows -> do not user external authenticator and rely on DCV login page
                # Linux -> use external authenticator
                if _soca_parameters.get("/configuration/UserDirectory/provider") in [
                    "existing_active_directory",
                    "aws_ds_managed_activedirectory",
                ]:
                    if session_info.os_family == "windows":
                        _username = f"{_soca_parameters.get('/configuration/UserDirectory/short_name')}\\{session_info.session_owner}"
                    else:
                        # no need to specify domain on Linux
                        _username = session_info.session_owner
                else:
                    _username = session_info.session_owner

                # DCV High-Scale: route through gateway instead of direct to host
                _is_high_scale = str(_soca_parameters.get("/dcv/high_scale_enabled", "false")).lower() == "true"

                if _is_high_scale:
                    _frontend_nlb = _soca_parameters.get("/dcv/frontend_nlb_dns", "")
                    # Fetch a fresh ConnectionToken from the broker each time
                    # the list is rendered. Token TTL is ~1h, scoped to
                    # (broker_session_id, owner). The watcher persists the
                    # broker session Id in `authentication_token` (reused
                    # column); see session_state_watcher.py HS branch.
                    _broker_session_id = session_info.authentication_token
                    if not _broker_session_id:
                        # Watcher hasn't registered with broker yet (still
                        # pending). Render a placeholder URL; UI will hide
                        # the Connect button anyway when state != running.
                        _connection_string = f"https://{_frontend_nlb}/?#{session_info.session_id}"
                    else:
                        try:
                            from utils.dcv_broker_client import DcvBrokerClient
                            _broker = DcvBrokerClient()
                            _conn_resp = _broker.get_session_connection_data(
                                session_id=_broker_session_id,
                                user=session_info.session_owner,
                            )
                            if _conn_resp.success:
                                _conn_token = (_conn_resp.message or {}).get("ConnectionToken", "")
                                _connection_string = (
                                    f"https://{_frontend_nlb}/?authToken={_conn_token}"
                                    f"&username={_username}"
                                    f"#{_broker_session_id}"
                                )
                            else:
                                logger.warning(
                                    f"broker.get_session_connection_data failed for "
                                    f"{session_info.session_uuid} ({_broker_session_id}): "
                                    f"{_conn_resp.message}"
                                )
                                _connection_string = f"https://{_frontend_nlb}/?#{_broker_session_id}"
                        except Exception as _err:
                            logger.error(
                                f"DcvBrokerClient.get_session_connection_data raised: {_err}"
                            )
                            _connection_string = f"https://{_frontend_nlb}/?#{_broker_session_id}"
                else:
                    if session_info.session_type == "console":
                        # use system auth authenticator
                        _connection_string = f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{session_info.instance_private_dns}/?username={_username}#{session_info.session_id}"
                    else:
                        # use external authenticator
                        _connection_string = f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{session_info.instance_private_dns}/?authToken={session_info.authentication_token}#{session_info.session_id}"

                _session_data = {
                    "session_uuid": session_info.session_uuid,
                    "session_name": session_info.session_name,
                    "session_owner": session_info.session_owner,
                    "session_state": session_info.session_state,
                    "session_project": session_info.session_project,
                    "session_type": session_info.session_type,
                    "created_on": session_info.created_on.isoformat() + "Z" if session_info.created_on else None,
                    "session_state_latest_change_time": session_info.session_state_latest_change_time.isoformat() + "Z" if session_info.session_state_latest_change_time else None,
                    "session_local_admin_password": session_info.session_local_admin_password,
                    "schedule": session_info.schedule,
                    "session_thumbnail": session_info.session_thumbnail,
                    "session_screenshot_url": None,
                    "session_id": session_info.session_id,
                    "session_token": session_info.session_token,
                    "authentication_token": session_info.authentication_token,
                    "instance_private_dns": session_info.instance_private_dns,
                    "instance_private_ip": session_info.instance_private_ip,
                    "instance_id": session_info.instance_id,
                    "instance_type": session_info.instance_type,
                    "instance_base_os": session_info.instance_base_os,
                    "os_family": session_info.os_family,
                    "ssm_ping_status": session_info.ssm_ping_status or "Unknown",
                    "last_event_type": session_info.last_event_type,
                    "last_checkpoint": session_info.last_checkpoint,
                    "recent_events": _get_recent_events_for_session(session_info.session_uuid),
                    "eta": _get_eta_for_session(session_info),
                    "support_hibernation": session_info.support_hibernation,
                    "is_spot": session_info.is_spot,
                    "stack_name": session_info.stack_name,
                    "software_stack_id": session_info.software_stack_id,
                    "ami_arch": ami_arch,  # joined
                    "virtual_desktop_profile_id": virtual_desktop_profile_id,  # joined
                    "allowed_instance_types": sorted(
                        json.loads(allowed_instance_types).get(ami_arch)
                    ),  # joined
                    "url": f"https://{_frontend_nlb}/" if _is_high_scale else f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{session_info.instance_private_dns}/",
                    "connection_string": _connection_string,
                    "sharing_enabled": bool(_is_high_scale) and _sharing_enabled,
                    # Cluster policy: when false the owner share modal greys out
                    # the "allow without me" toggle (the API forces supervised
                    # regardless, but the UI should reflect it). Defaults true.
                    "allow_unsupervised_access": _allow_unsup,
                    "active_grants_count": (
                        _sharing_grant_svc.count_active_grants_for_session(
                            session_info.authentication_token
                        )
                        if _sharing_grant_svc and session_info.authentication_token
                        else 0
                    ),
                    "broker_session_id": session_info.authentication_token or "",
                    # DCV session sharing scope inherited from the session's
                    # software stack ('none'|'project'|'cluster'); NULL -> cluster.
                    "share_scope": (
                        getattr(session_info.software_stack, "share_scope", None) or "cluster"
                    ),
                }

                user_sessions[session_info.session_uuid] = _session_data
                logger.debug(f"Session Info {user_sessions[session_info.session_uuid]}")

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return SocaError.GENERIC_ERROR(
                    helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                ).as_flask()

        logger.debug(f"Complete User Sessions details to return: {user_sessions}")

        # Inject S3 screenshot pre-signed URLs when high-scale screenshots are enabled.
        #
        # The bucket region may differ from the cluster region (the SOCA
        # installer accepts an existing S3 bucket from any region). SigV4
        # signatures are region-bound — signing a us-east-1 bucket with a
        # us-east-2 client returns HTTP 301 PermanentRedirect to the browser.
        # We discover the bucket region once via head_bucket (cheap, idempotent)
        # and create a region-correct signing client.
        #
        # Block Public Access on the bucket is fully compatible with this
        # pattern: presigned URLs use the controller role's IAM credentials
        # via SigV4, not anonymous access. BPA only blocks bucket-level
        # ACLs/policies granting public access.
        _dcv_screenshots_enabled = (
            SocaConfig(key="/dcv/high_scale_enabled")
            .get_value()
            .get("message", "false")
        )
        if str(_dcv_screenshots_enabled).lower() == "true":
            # Prefer the dedicated screenshot bucket (CDK-published).
            # Fall back to the legacy shared cluster bucket so older
            # deployments keep rendering thumbnails during migration.
            _ss_bucket = (
                SocaConfig(key="/dcv/screenshot/s3_bucket")
                .get_value()
                .get("message", "")
            )
            if _ss_bucket and _ss_bucket != "CACHE_MISS":
                _bucket = _ss_bucket
                _flat_keys = True
            else:
                _bucket = (
                    SocaConfig(key="/configuration/S3Bucket")
                    .get_value()
                    .get("message", "")
                )
                _flat_keys = False
            _cluster_id = os.environ.get("EDH_CLUSTER_ID")
            # Optional key prefix published by CDK for cluster/existing bucket
            # modes. Absent (or empty) -> fall back to the flat/legacy layout.
            _ss_prefix = (
                SocaConfig(key="/dcv/screenshot/s3_prefix")
                .get_value()
                .get("message", "")
            )
            if _ss_prefix in ("CACHE_MISS", None, "~"):
                _ss_prefix = ""
            # Cached bucket-region lookup (head_bucket called once per
            # bucket lifetime, not once per request).
            _bucket_region = _get_bucket_region_cached(_bucket)
            # Cached s3 client per region.
            _s3 = _get_s3_client_for_region(_bucket_region)
            for _uuid, _session in user_sessions.items():
                # In high-scale mode, screenshots are keyed by the broker
                # session Id (which DcvScreenshotPoller learns via
                # describeSessions). The watcher persists that handle in
                # `authentication_token`. In single-VDI (non-HS) mode the
                # local DCV session id == SOCA session_uuid, which is what
                # `session_id` already holds. Pick the right field per mode.
                _sid = (
                    _session.get("authentication_token")
                    if _is_high_scale
                    else _session.get("session_id", "")
                ) or _session.get("session_id", "")
                if _sid and _session.get("session_state") in (
                    "running",
                    "stopping",
                    "stopped",
                ):
                    # Explicit prefix (cluster/existing modes) wins; else
                    # dedicated bucket = flat keys; legacy = nested under
                    # <cluster>/dcv/screenshots/.
                    if _ss_prefix:
                        _key = f"{_ss_prefix}{_sid}.jpg"
                    elif _flat_keys:
                        _key = f"{_sid}.jpg"
                    else:
                        _key = f"{_cluster_id}/dcv/screenshots/{_sid}.jpg"
                    try:
                        _head = _s3.head_object(Bucket=_bucket, Key=_key)
                        _session["session_screenshot_url"] = _s3.generate_presigned_url(
                            "get_object",
                            Params={"Bucket": _bucket, "Key": _key},
                            ExpiresIn=300,
                        )
                        # Surface capture age in the UI. The Lambda writes
                        # `captured-at` metadata when it puts a fresh
                        # screenshot; fall back to S3's own LastModified.
                        _meta = _head.get("Metadata") or {}
                        _captured_at = _meta.get("captured-at") or (
                            _head.get("LastModified").isoformat()
                            if _head.get("LastModified")
                            else None
                        )
                        if _captured_at:
                            _session["session_screenshot_captured_at"] = _captured_at
                    except Exception:
                        pass

        return SocaResponse(success=True, message=user_sessions).as_flask()
