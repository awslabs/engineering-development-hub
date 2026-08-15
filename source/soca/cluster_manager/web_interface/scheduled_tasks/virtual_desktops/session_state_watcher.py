# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from extensions import db
from models import VirtualDesktopSessions, VdiSavedImages
import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.aws.cloudformation_client import SocaCfnClient
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse
from utils.error import SocaError
from botocore.exceptions import ClientError
import config
from cryptography.fernet import Fernet
import json
from sqlalchemy.orm import Session
import base64
from typing import Iterator, List, Literal, Iterable, TypeVar
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from itertools import islice
import time
from flask import Flask


logger = logging.getLogger("scheduled_tasks_virtual_desktops_session_state_watcher")

# Lazy, cached boto3 clients. Deferred to first use with a success guard.
# Raises on failure (rather than returning None) so a transient get_boto error
# surfaces as a catchable exception at the call site instead of an opaque
# AttributeError on a None client -- and preserves the original module-level
# fail-loud semantics.
_CLIENT_CACHE = {}


def _client(service_name):
    if service_name not in _CLIENT_CACHE:
        _resp = utils_boto3.get_boto(service_name=service_name)
        if _resp.get("success") is False:
            logger.warning(
                f"session_state_watcher: failed to get boto3 {service_name} client"
            )
            raise RuntimeError(f"Unable to create boto3 {service_name} client")
        _CLIENT_CACHE[service_name] = _resp.get("message")
    return _CLIENT_CACHE[service_name]


def is_high_scale_enabled() -> bool:
    """
    True if the cluster is running in DCV high-scale (broker) mode.

    Reads /dcv/high_scale_enabled from SSM via SocaConfig -- the canonical
    persisted flag (matches create_virtual_desktop.py, list_virtual_desktops.py,
    views/virtual_desktops.py, virtual_desktop_screenshot.py, and
    start_virtual_desktop.py's resume handler). /configuration/DcvHighScale
    is a render-only variable that is never persisted to SSM -- reading it
    here always fell through to the "false" default, permanently caching
    False and letting the legacy Stage-1 push-promotion path run on every
    high-scale cluster. That caused resumed sessions to be marked "running"
    in the DB with no real broker session (WebUI shows ready, connect fails
    with "requested dcvSession does not exist" -- broker has zero sessions).
    Cached at the module level for the lifetime of the process; the value
    cannot change without redeploying CDK, so a stale read is impossible
    in practice.

    Used to gate the watcher's session-health check: in single-VDI mode
    we run an SSM `dcv list-sessions` against the host; in high-scale
    mode the broker is the source of truth so we query it directly via
    DcvBrokerClient and avoid the SSM round-trip entirely.
    """
    if not hasattr(is_high_scale_enabled, "_cached"):
        try:
            _resp = SocaConfig(key="/dcv/high_scale_enabled").get_value(
                default="false", allow_unknown_key=True
            )
            _val = _resp.message if _resp.success else "false"
            _cast = SocaCastEngine(_val).cast_as(bool)
            is_high_scale_enabled._cached = _cast.message if _cast.success else False
        except Exception as _err:
            logger.warning(
                f"is_high_scale_enabled: could not read /dcv/high_scale_enabled, "
                f"defaulting to False: {_err}"
            )
            is_high_scale_enabled._cached = False
    return is_high_scale_enabled._cached


def chunked_iterable(iterable: Iterable[TypeVar], chunk_size: int) -> Iterator[List]:
    iterator = iter(iterable)
    for first in iterator:
        yield [first] + list(islice(iterator, chunk_size - 1))


def process_chunk(
    sessions: list[VirtualDesktopSessions],
    instance_ids_by_state: dict,
) -> SocaResponse:
    _db_scoped_session = db.session
    """
    This function is responsible to retrieve all active VDI desktops and ensure the status displayed on the Web Interface match the state of the process running on the EC2 machine
    """
    try:
        logger.info(f"Processing chunk {sessions}")

        _get_soca_parameters = SocaConfig(key="/").get_value(return_as=dict)
        if _get_soca_parameters.get("success") is False:
            logger.critical(
                f"Unable to retrieve SOCA Parameters: {_get_soca_parameters.get('message')}"
            )
            return SocaResponse(
                success=False,
                message=f"Unable to retrieve SOCA Parameters: {_get_soca_parameters.get('message')}",
            )
        else:
            _soca_parameters = _get_soca_parameters.get("message")

        logger.info(
            "Finding VDI sessions with no registered EC2 Instance on DB, or "
            "(high-scale mode) no broker session registration yet ..."
        )
        _is_high_scale_mode = is_high_scale_enabled()
        _sessions_with_no_ec2_instance = [
            session
            for session in sessions
            if session.instance_private_dns is None
            or session.instance_private_ip is None
            or session.instance_id is None
            # Also re-run for sessions whose EC2 identity is already known
            # but whose broker session (authentication_token) has not been
            # (re-)created yet. Covers two cases: (1) a first launch whose
            # early stamp/ec2-running event raced ahead of broker
            # registration -- without this the early stamp would drop it
            # from this filter before create_session ever succeeds; (2) a
            # resumed session -- start_virtual_desktop.py's resume handler
            # clears authentication_token to signal "needs re-registration"
            # since the broker's prior Session for this UUID does not
            # survive a stop. Both retry via the same broker.create_session()
            # loop below until the (re)started instance's DCV server
            # registers with the broker.
            or (
                _is_high_scale_mode
                and session.authentication_token is None
                and session.session_state in ("pending", "placing")
            )
        ]
        if _sessions_with_no_ec2_instance:
            logger.info(
                f"Found Sessions with no EC2 Instance: {_sessions_with_no_ec2_instance}"
            )
            update_ec2_info(
                sessions=_sessions_with_no_ec2_instance,
                cluster_id=_soca_parameters.get("/configuration/ClusterId"),
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("All VDI sessions have active EC2 instance on DB")

        logger.info(
            "Finding VDI sessions with invalid or terminated Instance ID. Deleting associated CloudFormation stack if needed ..."
        )
        _inactive_sessions = [
            session
            for session in sessions
            if instance_ids_by_state.get(session.instance_id) in [None, "terminated"]
        ]

        if _inactive_sessions:
            logger.info(
                f"Found Sessions that can be deactivated {_inactive_sessions} depending on the CloudFormation stack status"
            )
            delete_inactive_instances(
                sessions=_inactive_sessions,
                instance_ids_state=instance_ids_by_state,
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No inactive session found")

        # Update stopping sessions (EC2 instance transitioning, e.g. Windows
        # shutdown mid-flight -- keep the WebUI honest instead of claiming
        # "stopped" before the instance actually is)
        logger.info(
            "Finding VDI Sessions with EC2 Instance stopping but DB state not yet stopping"
        )
        _sync_stopping_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state.get(session.instance_id).lower() == "stopping"
            and session.session_state.lower() != "stopping"
        ]
        if _sync_stopping_sessions:
            logger.info(
                f"Found Sessions to update state to stopping: {_sync_stopping_sessions}"
            )
            update_virtual_desktop_state(
                sessions=_sync_stopping_sessions,
                new_state="stopping",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to stopping")

        # Update stopped sessions -- only once EC2 itself reports "stopped"
        # (not "stopping"; that transitional state is handled above and
        # kept distinct so the WebUI doesn't claim "stopped" while the
        # instance -- especially Windows -- is still mid-shutdown, e.g: if
        # you stop the instance from AWS Console)
        logger.info(
            "Finding VDI Sessions with stopped EC2 Instance but DB state is not stopped"
        )

        _sync_stopped_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state.get(session.instance_id).lower() == "stopped"
            and session.session_state.lower() != "stopped"
        ]
        logger.info(
            f"Found stopped EC2 instances not in sync with DB session_state {_sync_stopped_sessions}"
        )
        if _sync_stopped_sessions:
            logger.info(
                f"Found Sessions to update state to stopped: {_sync_stopped_sessions}"
            )
            update_virtual_desktop_state(
                sessions=_sync_stopped_sessions,
                new_state="stopped",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to stopped")

        # Retrieve all non-running VDI session with a running Instance ID.
        logger.info(
            "Finding non-running VDI Sessions but associated EC2 instance is running, check if DCV is up and running and change the state to running"
        )

        _sync_running_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state[session.instance_id].lower() == "running"
            and session.session_state.lower() not in ("running", "interrupting", "interrupted")
        ]

        _running_sessions_to_validate = []
        if _sync_running_sessions:
            logger.info(
                f"Found running EC2 instances but session_state are not running {_sync_running_sessions}, checking if DCV is healthy on these machine"
            )
            for _session in _sync_running_sessions:
                # In high-scale mode, skip direct HTTP probe (gateway doesn't support path-based routing)
                # Trust SSM Agent ping status instead
                if str(_soca_parameters.get("/dcv/high_scale_enabled", "false")).lower() == "true":
                    _running_sessions_to_validate.append(_session)
                    continue

                _dcv_https_url = f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{_session.instance_private_dns}/"
                try:
                    _check_dcv_state = SocaHttpClient(
                        endpoint=_dcv_https_url, allow_redirects=False, timeout=5
                    ).get()
                    logger.info(
                        f"LoadBalancer Result {_dcv_https_url} -> {_check_dcv_state}"
                    )
                    # We change status to 200 only if DCVEntryPointDNSName returns 200 and if we can get `dcv` as part of  returned headers
                    if _check_dcv_state.get("status_code") == 200:
                        _response_headers = _check_dcv_state.get("request").headers
                        logger.info(
                            f"Headers response for {_session.id=} {_session.session_uuid=}: {_response_headers}"
                        )
                        if "Server" in _response_headers:
                            if _response_headers.get("Server") == "dcv":
                                # We will also validate if DCV is responding correctly before changing the status to running
                                _running_sessions_to_validate.append(_session)
                    else:
                        update_virtual_desktop_state(
                            sessions=[_session],
                            new_state="pending",
                            db_scoped_session=_db_scoped_session,
                        )
                except Exception as err:
                    logger.warning(
                        f"Unable to query {_dcv_https_url} due to {err}. This is normal is the session is still being provisioned"
                    )
        else:
            logger.info("No VDI sessions to be changed to running")

        if _running_sessions_to_validate:
            logger.info(
                f"Found EC2 running and DCV listening for {_running_sessions_to_validate}, will verify if dcv describe-session is correct and update status to running"
            )
            validate_dcv_session(
                sessions=_running_sessions_to_validate,
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to running")

        # Update pending sessions
        logger.info(
            "Finding VDI Session with running EC2 instance type but stopped state. updating them to pending"
        )
        _sync_pending_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state.get(session.instance_id).lower() == "running"
            and session.session_state.lower() == "stopped"
        ]
        if _sync_pending_sessions:
            logger.info(f"Found sessions to update to pending {_sync_pending_sessions}")
            update_virtual_desktop_state(
                sessions=_sync_pending_sessions,
                new_state="pending",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to pending")

        # Update SSM Agent ping status for all sessions with instance IDs
        _sessions_with_instances = [
            s for s in sessions if s.instance_id is not None
        ]
        if _sessions_with_instances:
            update_ssm_ping_status(
                sessions=_sessions_with_instances,
                db_scoped_session=_db_scoped_session,
            )

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(f"Process Chunk error due to {err} at line {exc_tb.tb_lineno}")

    # Close current thread
    return SocaResponse(success=True, message="Chunk processed")


def update_ssm_ping_status(sessions, db_scoped_session: Session):
    """Batch-query SSM Agent ping status and update DB for all sessions."""
    instance_ids = [s.instance_id for s in sessions if s.instance_id]
    if not instance_ids:
        return

    ping_map = {}
    try:
        paginator = _client("ssm").get_paginator("describe_instance_information")
        for page in paginator.paginate(
            Filters=[{"Key": "InstanceIds", "Values": instance_ids}]
        ):
            for info in page.get("InstanceInformationList", []):
                ping_map[info["InstanceId"]] = info.get("PingStatus", "Unknown")
    except ClientError as err:
        logger.warning(f"SSM describe_instance_information failed: {err}")
        return

    for s in sessions:
        status = ping_map.get(s.instance_id, "Unknown")
        if s.ssm_ping_status != status:
            logger.info(
                f"SSM ping status for {s.session_uuid} ({s.instance_id}): "
                f"{s.ssm_ping_status} -> {status}"
            )
            s.ssm_ping_status = status

    try:
        db_scoped_session.commit()
    except Exception as err:
        logger.warning(f"Failed to commit SSM ping status: {err}")
        db_scoped_session.rollback()


def ssm_get_command_info(os_family: Literal["linux", "windows"]) -> SocaResponse:
    """
    Returns the SSM command & document name to run as a COLD-SESSION PROBE.

    This is a read-only check: "is the local DCV session alive?". Returns 0
    if alive, 1 if not. We DO NOT restart any service here -- the original
    'restart dcvserver' branch was harmful (it killed in-flight broker
    createSessionRequests and caused 'session not reachable' WebUI blips).
    Recovery is a separate explicit operator action.

    The cold-session probe is invoked by the watcher only when the session
    is running AND the push channel has gone stale (last_seen_event_at >
    10 min or never set). Healthy sessions emit session-resumed/heartbeat
    events that keep last_seen_event_at fresh, so the SSM probe rarely
    fires in a working cluster.
    """

    if os_family not in ["linux", "windows"]:
        logger.critical(f"os_family must be linux or windows, detected {os_family}")

    if os_family == "windows":
        # Pure describe; no restart. Windows DCV resolves by name OR id.
        _ssm_commands = [
            f"Invoke-Expression \"& 'C:\\Program Files\\NICE\\DCV\\Server\\bin\\dcv' describe-session $env:EDH_DCV_SESSION_ID\"",
            "if ($?) { exit 0 } else { exit 1 }",
        ]
        _ssm_document_name = "AWS-RunPowerShellScript"
    else:
        # Linux DCV strictly looks up by id; SOCA passes UUID as session
        # NAME, so we have to grep the list-sessions output for `name: <uuid>`.
        _ssm_commands = [
            "export EDH_DCV_SESSION_ID=$(grep '^export EDH_DCV_SESSION_ID=' /etc/environment | head -1 | awk -F'=' '{print $2}')",
            "if dcv list-sessions 2>/dev/null | grep -F \"name: ${EDH_DCV_SESSION_ID}\" >/dev/null; then",
            "  exit 0",
            "else",
            "  exit 1",
            "fi",
        ]
        _ssm_document_name = "AWS-RunShellScript"

    return SocaResponse(
        success=True,
        message={
            "ssm_commands": _ssm_commands,
            "ssm_document_name": _ssm_document_name,
        },
    )


def ssm_get_list_command_status(command_id: str) -> SocaResponse:
    """
    Returns the status of the SSM command ID.
    Valid status are either Success or Failed (this means the SSM command has completed successfully)

    """
    try:
        _max_ssm_loop_attempts = 10
        _ssm_attempt = 1
        while True:
            _check_command_status = _client("ssm").list_commands(CommandId=command_id)[
                "Commands"
            ][0]["Status"]
            logger.info(f"Status command for {command_id}: {_check_command_status}")
            if _check_command_status in ["Success", "Failed"]:
                return SocaResponse(
                    success=True,
                    message=f"Command {command_id} has completed, checking each instance results",
                )
            else:
                if _check_command_status in ["InProgress", "Pending"]:
                    if _ssm_attempt == _max_ssm_loop_attempts:
                        logger.critical(
                            f"Unable to determine status SSM responses after timeout for {command_id}"
                        )
                        return SocaResponse(
                            success=False,
                            message=f"Unable to determine status SSM responses after timeout for {command_id}",
                        )
                    else:
                        time.sleep(5)
                        _ssm_attempt += 1
                else:
                    logger.critical(
                        f"SSM command {command_id} exited with invalid status {_check_command_status=}"
                    )
                    return SocaResponse(
                        success=False,
                        message=f"SSM command {command_id} exited with invalid status {_check_command_status=}",
                    )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"ssm_get_list_command_status error due to {err} at line {exc_tb.tb_lineno}"
        )


def _validate_dcv_sessions_via_broker(
    sessions: list, db_scoped_session: Session
) -> SocaResponse:
    """
    High-scale mode session-health check.

    The broker is authoritative for session lifecycle in high-scale mode.
    Instead of round-tripping an SSM `dcv list-sessions` against each VDI
    (which is expensive, slow, and racy with broker-driven create flows),
    we ask the broker for its view of every session and promote each one
    whose broker state is READY (or any *_CREATING substate) to "running".

    Single broker REST call per chunk (describe_sessions), then in-memory
    lookup by name -- no per-session network cost.

    States we treat as healthy: READY only (CREATING is not yet connectable).
    States we leave alone: any other -- session_error_watcher.py is the
    component responsible for marking sessions as error/deleted.
    """
    try:
        from utils.dcv_broker_client import DcvBrokerClient

        _broker = DcvBrokerClient()
        _describe = _broker.describe_sessions()
        if not _describe.success:
            logger.warning(
                f"broker.describe_sessions failed: {_describe.message}; "
                f"skipping this cycle (will retry next minute)"
            )
            return SocaResponse(
                success=False,
                message=f"broker.describe_sessions failed: {_describe.message}",
            )

        _broker_sessions = (_describe.message or {}).get("Sessions") or []
        # The broker's describeSessions list can carry more than one
        # record for the same Name (a terminal DELETED/DELETING record
        # left over from a prior cycle, plus a newly-created live one).
        # A plain dict comprehension would let iteration order decide
        # which wins; prefer a live (non-terminal) record over a terminal
        # one so a fresh session is never shadowed by its own predecessor.
        _TERMINAL_BROKER_STATES = {"DELETING", "DELETED"}

        def _prefer_live(existing: dict, candidate: dict) -> dict:
            if existing is None:
                return candidate
            _existing_state = (existing.get("State") or "").upper()
            _candidate_state = (candidate.get("State") or "").upper()
            if _existing_state in _TERMINAL_BROKER_STATES and _candidate_state not in _TERMINAL_BROKER_STATES:
                return candidate
            return existing

        _by_name: dict = {}
        _by_id: dict = {}
        for bs in _broker_sessions:
            _name_key = bs.get("Name")
            if _name_key:
                _by_name[_name_key] = _prefer_live(_by_name.get(_name_key), bs)
            _id_key = bs.get("Id")
            if _id_key:
                _by_id[_id_key] = _prefer_live(_by_id.get(_id_key), bs)

        # READY only; CREATING can still die (reboot mid-placement) -> wedge.
        _healthy_states = {"READY"}

        for _session in sessions:
            _broker_view = _by_name.get(_session.session_uuid) or _by_id.get(
                _session.session_uuid
            )
            if not _broker_view:
                logger.info(
                    f"broker has no session for {_session.session_uuid} "
                    f"({_session.session_name}); leaving in current state "
                    f"-- session_error_watcher will reconcile if persistent"
                )
                continue

            _state = (_broker_view.get("State") or "").upper()
            if _state in _healthy_states:
                logger.info(
                    f"DCV Session healthy via broker for {_session.session_uuid} "
                    f"(broker state={_state}); changing state to running"
                )
                update_virtual_desktop_state(
                    sessions=[_session],
                    new_state="running",
                    db_scoped_session=db_scoped_session,
                )
            elif _state in _TERMINAL_BROKER_STATES:
                logger.warning(
                    f"DCV Session {_session.session_uuid} reported by broker in "
                    f"terminal state {_state}; self-healing by clearing stale "
                    f"authentication_token and resetting to pending so "
                    f"ensure_broker_session re-registers on next cycle"
                )
                _session.authentication_token = None
                update_virtual_desktop_state(
                    sessions=[_session],
                    new_state="pending",
                    db_scoped_session=db_scoped_session,
                )
                db_scoped_session.commit()
            else:
                logger.warning(
                    f"DCV Session {_session.session_uuid} reported by broker in "
                    f"non-healthy state {_state}; leaving alone -- "
                    f"session_error_watcher will reconcile"
                )

        return SocaResponse(
            success=True, message="DCV sessions validated via broker"
        )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"_validate_dcv_sessions_via_broker error: {err} at line {exc_tb.tb_lineno}"
        )
        return SocaResponse(success=False, message=err)


def validate_dcv_session(
    sessions: VirtualDesktopSessions, db_scoped_session: Session
) -> SocaResponse:
    """
    Validate DCV session health for a chunk of sessions.

    In DCV high-scale (broker) mode, this delegates to
    _validate_dcv_sessions_via_broker() which queries the broker for
    session state -- no SSM round-trip needed.

    In single-VDI (legacy) mode this now uses a 2-stage strategy:

      Stage 1 (push-driven, fast path, no SSM): if a session has
              session_ready_pushed_at set in the DB, the VDI itself
              already published a session-ready event through the
              SNS->Lambda relay. We promote pending->running directly.

      Stage 2 (cold-session probe): for sessions still pending OR running
              sessions whose last_seen_event_at is stale (>10 min) OR
              never set (legacy clusters that don't publish), fall through
              to a single read-only SSM probe (no restart). The probe
              runs once per session per 10-minute window; healthy sessions
              that emit heartbeats keep last_seen_event_at fresh and bypass
              SSM entirely.

    SSM ssm.send_command takes up to 50 InstanceIDs -- chunk size cap.
    """
    if is_high_scale_enabled():
        logger.info(
            "High-scale mode -- delegating session validation to broker "
            "(skipping SSM dcv-list-sessions check)"
        )
        return _validate_dcv_sessions_via_broker(
            sessions=list(sessions), db_scoped_session=db_scoped_session
        )

    # ----- Stage 1: push-driven fast path (legacy mode) -------------------
    # If a session_ready_pushed_at is set, the VDI has confirmed via SNS
    # that bootstrap finished and the local DCV session exists. Promote
    # immediately -- no SSM needed.
    _push_promoted = []
    for _session in list(sessions):
        if (
            _session.session_state not in ("running", "interrupting", "interrupted")
            and getattr(_session, "session_ready_pushed_at", None) is not None
        ):
            logger.info(
                f"DCV Session {_session.session_uuid}: push-driven promotion "
                f"to running (session_ready_pushed_at={_session.session_ready_pushed_at})"
            )
            update_virtual_desktop_state(
                sessions=[_session],
                new_state="running",
                db_scoped_session=db_scoped_session,
            )
            _push_promoted.append(_session.id)

    # ----- Stage 2: cold-session SSM probe filter -------------------------
    # Drop sessions that just got promoted (we already trust the push).
    # Drop sessions whose push channel is fresh (last_seen_event_at within
    # 10 min) -- those are healthy and don't need an SSM round-trip.
    from datetime import datetime, timedelta, timezone

    _cold_threshold = datetime.now(timezone.utc) - timedelta(minutes=10)
    _sessions_to_probe = []
    for _session in list(sessions):
        if _session.id in _push_promoted:
            continue
        if (getattr(_session, "session_state", "") or "").lower() in ("interrupting", "interrupted"):
            continue  # spot reclaim in progress / interrupted-saved card; never probe/promote back to running
        _last_seen = getattr(_session, "last_seen_event_at", None)
        if _last_seen is not None and _last_seen.replace(tzinfo=timezone.utc) > _cold_threshold:
            # Push channel is hot; no SSM needed.
            continue
        _sessions_to_probe.append(_session)

    if not _sessions_to_probe:
        logger.info(
            f"All sessions covered by push channel; "
            f"push_promoted={len(_push_promoted)}; SSM probe skipped"
        )
        return SocaResponse(
            success=True,
            message=f"DCV sessions validated via push (no SSM). "
            f"promoted={len(_push_promoted)}, hot={len(list(sessions))-len(_sessions_to_probe)}",
        )

    logger.info(
        f"Cold-session SSM probe firing for {len(_sessions_to_probe)} sessions "
        f"(push hot for {len(list(sessions))-len(_sessions_to_probe)-len(_push_promoted)}, "
        f"push promoted {len(_push_promoted)})"
    )
    sessions = _sessions_to_probe  # narrow downstream SSM scope

    try:
        _linux_sessions_instance_ids = [
            session.instance_id for session in sessions if session.os_family == "linux"
        ]

        logger.info(
            f"Found Linux Sessions to validate DCV: {_linux_sessions_instance_ids}"
        )
        _windows_sessions_instance_ids = [
            session.instance_id
            for session in sessions
            if session.os_family == "windows"
        ]
        logger.info(
            f"Found Windows Sessions to validate DCV: {_windows_sessions_instance_ids}"
        )
        _linux_ssm_info = ssm_get_command_info(os_family="linux")
        if _linux_ssm_info.get("success") is False:
            logger.critical(
                f"Unable to retrieve SSM command info for linux due to {_linux_ssm_info.get('message')}"
            )
            return SocaResponse(success=False, message=_linux_ssm_info.get("message"))
        _windows_ssm_info = ssm_get_command_info(os_family="windows")

        if _windows_ssm_info.get("success") is False:
            logger.critical(
                f"Unable to retrieve SSM command info for Windows due to {_windows_ssm_info.get('message')}"
            )
            return SocaResponse(success=False, message=_windows_ssm_info.get("message"))

        # Run SSM for Linux and Windows hosts
        if _linux_sessions_instance_ids:
            _check_dcv_session_linux = _client("ssm").send_command(
                InstanceIds=_linux_sessions_instance_ids,
                DocumentName=_linux_ssm_info.get("message").get("ssm_document_name"),
                Parameters={
                    "commands": _linux_ssm_info.get("message").get("ssm_commands")
                },
                TimeoutSeconds=30,
            )
            _ssm_command_id_linux = _check_dcv_session_linux["Command"]["CommandId"]

        else:
            logger.info("No Linux instances to check")
            _ssm_command_id_linux = False

        if _windows_sessions_instance_ids:
            _check_dcv_session_windows = _client("ssm").send_command(
                InstanceIds=_windows_sessions_instance_ids,
                DocumentName=_windows_ssm_info.get("message").get("ssm_document_name"),
                Parameters={
                    "commands": _windows_ssm_info.get("message").get("ssm_commands")
                },
                TimeoutSeconds=30,
            )
            _ssm_command_id_windows = _check_dcv_session_windows["Command"]["CommandId"]

        else:
            logger.info("No Windows instances to check")
            _ssm_command_id_windows = False

        # Wait until the Commands have completed.
        # Succeed => All instances succeeded
        # Failed => At least 1 instance failed, but other may have succeeded
        # All others return code => SSM command was not executed for various reason (Quota, Rate Exceeded etc ..)

        _skip_linux = False
        _skip_windows = False

        if _ssm_command_id_linux is False:
            _skip_linux = True
        else:
            _check_linux_command_status = ssm_get_list_command_status(
                command_id=_ssm_command_id_linux
            )
            if _check_linux_command_status.get("success") is False:
                logger.error(
                    f"Unable to determine status SSM responses for linux instances due to {_check_linux_command_status}"
                )
                _skip_linux = True

        if _ssm_command_id_windows is False:
            _skip_windows = True
        else:
            _check_windows_command_status = ssm_get_list_command_status(
                command_id=_ssm_command_id_windows
            )
            if _check_windows_command_status.get("success") is False:
                logger.error(
                    f"Unable to determine status SSM responses for windows instances due to {_check_windows_command_status}"
                )
                _skip_windows = True

        # Check all linux hosts individually
        if not _skip_linux:
            for _session in [
                session for session in sessions if session.os_family == "linux"
            ]:
                _ssm_output = _client("ssm").get_command_invocation(
                    CommandId=_ssm_command_id_linux, InstanceId=_session.instance_id
                )
                _status = _ssm_output.get("Status")
                logger.info(f"Validating {_session}, received ssm output {_status}")
                if _status.lower() != "success":
                    logger.warning(
                        f"DCV Session not running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, this may be because system has just started. DCV Error state will be checked by session_error_watcher.py"
                    )

                else:
                    logger.info(
                        f"DCV Session running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, changing state to running"
                    )
                    update_virtual_desktop_state(
                        sessions=[_session],
                        new_state="running",
                        db_scoped_session=db_scoped_session,
                    )
        # Check all Windows hosts individually
        if not _skip_windows:
            for _session in [
                session for session in sessions if session.os_family == "windows"
            ]:
                _ssm_output = _client("ssm").get_command_invocation(
                    CommandId=_ssm_command_id_windows, InstanceId=_session.instance_id
                )
                _status = _ssm_output.get("Status")
                logger.info(f"Validating {_session}, received ssm output {_status}")
                if _status.lower() != "success":
                    logger.warning(
                        f"DCV Session not running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, this may be because system has just started. DCV Error state will be checked by session_error_watcher.py"
                    )

                else:
                    logger.info(
                        f"DCV Session running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, changing state to running"
                    )
                    update_virtual_desktop_state(
                        sessions=[_session],
                        new_state="running",
                        db_scoped_session=db_scoped_session,
                    )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"validate_dcv_session error due to {err} at line {exc_tb.tb_lineno}"
        )
        return SocaResponse(success=False, message=err)

    return SocaResponse(success=True, message="DCV Session validated successfully")


def encrypt(message: base64) -> SocaResponse:
    """
    This function create the DCV Authentication Code
    """
    try:
        key = config.Config.DCV_TOKEN_SYMMETRIC_KEY
        cipher_suite = Fernet(key)
        return SocaResponse(
            success=True, message=cipher_suite.encrypt(message.encode("utf-8"))
        )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(f"encrypt error due to {err} at line {exc_tb.tb_lineno}")
        return SocaResponse(success=False, message=err)


def update_ec2_info(
    sessions: VirtualDesktopSessions, cluster_id: str, db_scoped_session: Session
) -> None:
    """
    Find details for VDI session with no active EC2 Instance registered on the database (e.g: desktop that just launched).
    If EC2 capacity is provisioned, retrieve private IP/DNS, generate authentication token and update DB
    If EC2 capacity is not yet provisioned, we verify if the CloudFormation stack associated to the vdi session is in progress.
    """

    for _session in sessions:
        try:
            _session_uuid = _session.session_uuid
            _base_os = _session.instance_base_os
            _owner = _session.session_owner
            logger.info(
                f"Checking get_ec2_host_info for VDI Session {_session.id} with tag:edh:DCVSessionUUID: {_session_uuid}, tag:edh:ClusterId {cluster_id}, tag:edh:JobOwner {_owner} and tag:edh:DCVSystem {_base_os}"
            )
            _host_info = {}

            _find_instance = _client("ec2").describe_instances(
                Filters=[
                    {
                        "Name": "tag:edh:DCVSessionUUID",
                        "Values": [_session.session_uuid],
                    },
                    {"Name": "tag:edh:ClusterId", "Values": [cluster_id]},
                    {"Name": "tag:edh:DCVSystem", "Values": [_base_os]},
                    {"Name": "tag:edh:JobOwner", "Values": [_owner]},
                ],
            )

            if not _find_instance["Reservations"]:
                logger.warning(
                    f"No instance found for tag:edh:DCVSessionUUID: {_session_uuid}, checking if the associated CloudFormation stack is healthy"
                )
            else:
                logger.debug(f"Found Instance: {_find_instance}")
                for reservation in _find_instance["Reservations"]:
                    for instance in reservation["Instances"]:
                        if instance["PrivateDnsName"].split(".")[0]:
                            _host_private_dns = instance["PrivateDnsName"].split(".")[
                                0
                            ]  # ip-192-168-1-10.ec2.internal -> we only get the first part
                            _host_private_ip_address = instance["PrivateIpAddress"]
                            _host_instance_id = instance["InstanceId"]
                            _host_status = instance["State"]["Name"]

                            logger.info(
                                f"EC2 instance found for {_session.id=} {_session.session_uuid=}, creating authentication token"
                            )

                            # Stamp EC2 identity IMMEDIATELY (decoupled from
                            # broker registration) so instance_id/private_ip/
                            # private_dns appear on the row as soon as the
                            # instance is found -- an admin can correlate to the
                            # AWS console while the session is still
                            # provisioning, instead of waiting minutes for the
                            # broker to register. Idempotent (no-op once set);
                            # pass the already-resolved values to avoid a second
                            # describe_instances call.
                            from helpers.dcv_broker_session import (
                                stamp_ec2_identity as _stamp_ec2_identity,
                            )
                            _stamp_ec2_identity(
                                _session,
                                _host_instance_id,
                                db_scoped_session,
                                private_ip=_host_private_ip_address,
                                private_dns=_host_private_dns,
                            )

                            # In DCV high-scale mode, the broker is the
                            # authoritative authenticator: the DCV server's
                            # auth-token-verifier points at the broker (see
                            # https://docs.aws.amazon.com/dcv/latest/sm-admin/configure-dcv-server.html).
                            # We register the session with the broker via
                            # /createSessions, which is asynchronous -- the
                            # response is the broker session Id (State=CREATING,
                            # Substate=SESSION_PLACING). The broker then tells
                            # the SM Agent to run `dcv create-session`, which
                            # requires the DCV server to be configured with
                            # create-session=false (no auto console session) --
                            # handled in dcv_server.sh.j2 and
                            # dcv_session_setup.ps.j2 when DcvHighScale is set.
                            #
                            # The connection token used to actually attach to
                            # the session is *not* returned at create time. It
                            # is fetched fresh on every Connect via
                            # `broker.get_session_connection_data` (see
                            # list_virtual_desktops.py). We persist only the
                            # broker session Id here, in the
                            # `authentication_token` column (reused as an
                            # opaque handle for the broker round-trip).
                            _is_high_scale = (
                                str(
                                    SocaConfig(key="/dcv/high_scale_enabled")
                                    .get_value()
                                    .get("message", "false")
                                )
                                .lower()
                                == "true"
                            )
                            if _is_high_scale:
                                from utils.dcv_broker_client import DcvBrokerClient

                                _broker_client = DcvBrokerClient()

                                # Idempotent recovery: if a previous watcher
                                # cycle already registered this session with
                                # the broker but lost the Id (e.g. uwsgi
                                # restart between create + DB commit, or
                                # broker reports SERVER_FULL because our
                                # session is the one filling it), reuse it.
                                _existing = _broker_client.find_session_by_name(
                                    _session.session_uuid
                                )
                                # Ignore terminal-state broker records. A
                                # DELETED/DELETING session lingers in
                                # describeSessions briefly after teardown;
                                # recovering its dead Id would wedge the
                                # session (it never re-registers). Treat
                                # terminal states as "no existing session" so
                                # we create a fresh one.
                                _state_cast = SocaCastEngine(
                                    (_existing or {}).get("State", "")
                                ).cast_as(expected_type=str)
                                _state_str = (
                                    _state_cast.get("message")
                                    if _state_cast.get("success") is True
                                    else ""
                                ).upper()
                                if _existing and _state_str in ("DELETING", "DELETED"):
                                    logger.info(
                                        f"Ignoring terminal-state broker session for "
                                        f"{_session.session_uuid}: state={_existing.get('State')!r}; "
                                        f"will create a fresh session"
                                    )
                                    _existing = None
                                if _existing:
                                    _broker_session_id = _existing.get("Id")
                                    logger.info(
                                        f"Recovered existing broker session for {_session.session_uuid}: "
                                        f"id={_broker_session_id} state={_existing.get('State')!r}"
                                    )
                                else:
                                    # Allow operators to raise the per-session collaborator
                                    # cap via SSM (defaults to 10 -- the broker's stock
                                    # default). Stress-testing benefits from a much higher
                                    # value; production should leave at 10 unless explicitly
                                    # increased. Read fresh on each create so config changes
                                    # take effect for new sessions without a restart.
                                    #
                                    # `default="10"` + `allow_unknown_key=True` keeps the
                                    # missing-key path silent: SocaConfig.get_value() will
                                    # otherwise raise AWS_API_ERROR + dump a stack trace
                                    # for every poll on every active session, swamping
                                    # the web_interface log and burning SSM API budget
                                    # under load.
                                    _max_collab_resp = (
                                        SocaConfig(key="/dcv/max_concurrent_clients")
                                        .get_value(default="10", allow_unknown_key=True)
                                    )
                                    _max_collab_raw = (
                                        _max_collab_resp.message
                                        if _max_collab_resp.success
                                        else "10"
                                    )
                                    _collab_cast = SocaCastEngine(
                                        _max_collab_raw
                                    ).cast_as(expected_type=int)
                                    if _collab_cast.get("success") is True:
                                        _max_collab = _collab_cast.get("message")
                                    else:
                                        logger.warning(
                                            f"/dcv/max_concurrent_clients={_max_collab_raw!r} not "
                                            f"parseable as int; falling back to broker default."
                                        )
                                        _max_collab = None

                                    _stype_cast = SocaCastEngine(
                                        _session.session_type or "console"
                                    ).cast_as(expected_type=str)
                                    _session_type = (
                                        _stype_cast.get("message")
                                        if _stype_cast.get("success") is True
                                        else "console"
                                    ).upper()

                                    # Pass storage-root so the broker-created
                                    # session enables file transfer (upload/
                                    # download). In high-scale mode the auto-
                                    # console session is disabled, so the
                                    # automatic-console-session/storage-root
                                    # registry/dcv.conf value never applies --
                                    # the broker must hand --storage-root to the
                                    # agent's `dcv create-session`. Without it
                                    # DCV reports "filestorage backend not
                                    # available". Path must match the folder the
                                    # bootstrap created per-OS or DCV silently
                                    # disables storage.
                                    _storage_cfg = SocaConfig(
                                        key="/system/dcv/session_storage"
                                    ).get_value(
                                        default="dcv_session_storage",
                                        allow_unknown_key=True,
                                    )
                                    _storage_name = (
                                        _storage_cfg.message
                                        if _storage_cfg.success
                                        else "dcv_session_storage"
                                    )
                                    # %home% -> C:\Users\<user>\ (Windows) / $HOME/ (Linux); keeps storage off the C:\ root (V2169683758)
                                    _storage_root = f"%home%/{_storage_name}"

                                    _broker_resp = _broker_client.create_session(
                                        name=_session.session_uuid,
                                        owner=_session.session_owner,
                                        session_type=_session_type,
                                        instance_id=_host_instance_id,
                                        max_concurrent_clients=_max_collab,
                                        storage_root=_storage_root,
                                    )
                                    if not _broker_resp.success:
                                        logger.info(
                                            f"broker.create_session deferred for {_session.session_uuid}: {_broker_resp.message}"
                                        )
                                        continue

                                    _session_obj = _broker_resp.message or {}
                                    _broker_session_id = _session_obj.get("Id")
                                    if not _broker_session_id:
                                        logger.error(
                                            f"broker.create_session succeeded but returned no Id for {_session.session_uuid}: {_session_obj}"
                                        )
                                        continue
                                    logger.info(
                                        f"Registered session {_session.session_uuid} with broker as {_broker_session_id} "
                                        f"(state={_session_obj.get('State')!r}, substate={_session_obj.get('Substate')!r})"
                                    )

                                # Reuse the authentication_token column to
                                # store the broker session Id (an opaque
                                # handle, not a token). The actual
                                # ConnectionToken is fetched per-Connect via
                                # broker.get_session_connection_data() at
                                # render time in list_virtual_desktops.
                                _session.authentication_token = _broker_session_id
                            else:
                                # Single-VDI mode: SOCA controller is the
                                # authenticator (DCV server's
                                # auth-token-verifier points at
                                # /api/dcv/authenticator). Generate a Fernet
                                # token containing the session metadata.
                                _authentication_data = json.dumps(
                                    {
                                        "system": _session.instance_base_os,
                                        "instance_id": _host_instance_id,
                                        "session_token": _session.session_token,
                                        "session_user": _session.session_owner,
                                    }
                                )
                                try:
                                    if (
                                        generate_auth_token := encrypt(
                                            message=_authentication_data
                                        )
                                    ).get("success") is False:
                                        logger.error(
                                            f"Unable to generate authentication token because of {generate_auth_token.get('message')}"
                                        )
                                        continue
                                    else:
                                        session_authentication_token = base64.b64encode(
                                            generate_auth_token.get("message")
                                        ).decode("utf-8")
                                        _session.authentication_token = (
                                            session_authentication_token
                                        )
                                except Exception as err:
                                    logger.error(
                                        f"Unable to update dcv auth token for {_session.id=} {_session.session_uuid=} in DB due to {err}"
                                    )
                                    continue

                            try:
                                logger.info(
                                    f"New EC2 instance detected for {_session.id=} {_session.session_uuid=}, adding {_host_instance_id=}, {_host_private_dns=}, {_host_private_ip_address=} to DB"
                                )
                                _session.instance_id = _host_instance_id
                                _session.instance_private_ip = _host_private_ip_address
                                _session.instance_private_dns = _host_private_dns
                                try:
                                    db_scoped_session.commit()
                                    logger.info("Changes commited successfully")
                                except Exception as e:
                                    db_scoped_session.rollback()
                                    logger.critical(
                                        f"Error trying to run the following commits on update_virtual_desktop_state because of: {e}"
                                    )
                                    queries = [
                                        str(statement)
                                        for statement in db_scoped_session._logger.handlers[
                                            0
                                        ].baseFilename
                                    ]
                                    logger.critical(f"Failed SQL query: {queries}")

                            except Exception as err:
                                logger.error(
                                    f"Unable to update host info for {_session.id=} {_session.session_uuid=} because of {err}"
                                )
                                continue
                        else:
                            logger.info(
                                "No Host information for session, will try again in the next run"
                            )
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.critical(
                f"update_ec2_info error due to {err} at line {exc_tb.tb_lineno}"
            )
            return SocaResponse(success=False, message=err)


def find_instance_ids_instance_state(
    all_sessions: VirtualDesktopSessions,
) -> SocaResponse:
    """
    Returns a dictionary of instance ID -> Instance State. Returns None if Instance ID does not exist anymore
    """
    try:
        logger.info(
            f"Finding instance state name for each instance ID for list of VDI {all_sessions}"
        )

        _instance_ids_state = {}

        # First, we get all Instance IDs, and we confirm they still exist.
        _all_instance_ids = [
            session.instance_id
            for session in all_sessions
            if session.instance_id is not None
        ]

        batch_size = 100  # max number of Instances IDs we can pass as part of describe_instance_status
        for i in range(0, len(_all_instance_ids), batch_size):
            _instance_ids_batch = _all_instance_ids[i : i + batch_size]
            logger.info(
                f"Verifying if EC2 instance still exist. Processing batch {(i // batch_size) + 1}: {_instance_ids_batch}"
            )
            try:
                response = _client("ec2").describe_instance_status(
                    InstanceIds=_instance_ids_batch,
                    IncludeAllInstances=True,  # required to also display instance not in Running state
                )

                # The response contains a list of statuses
                instance_statuses = response.get("InstanceStatuses", [])
                # Iterate through the returned statuses and print details
                for status in instance_statuses:
                    _instance_ids_state[status.get("InstanceId")] = status.get(
                        "InstanceState", {}
                    ).get("Name")

                    logger.debug(
                        f"Instance {status.get('InstanceId')} is in state: {status.get('InstanceState')}"
                    )
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code in [
                    "InvalidInstanceID.NotFound",
                ]:
                    logger.warning(
                        f"Error encountered in batch. Processing each instance individually to isolate invalid IDs."
                    )
                    for _instance_id in _instance_ids_batch:
                        try:
                            individual_response = _client("ec2").describe_instance_status(
                                InstanceIds=[_instance_id]
                            )
                            statuses = individual_response.get("InstanceStatuses", [])
                            if statuses:
                                for status in statuses:
                                    _instance_ids_state[_instance_id] = status.get(
                                        "InstanceState", {}
                                    ).get("Name")
                            else:
                                logger.error(
                                    f"Instance {_instance_id} returned no status (might be stopped or not yet checked)"
                                )
                        except ClientError as inner_e:
                            if inner_e.response["Error"]["Code"] in [
                                "InvalidInstanceID.NotFound"
                            ]:
                                logger.error(
                                    f"Instance ID {_instance_id} not found. Skipping..."
                                )
                                _instance_ids_state[_instance_id] = None
                            else:
                                logger.error(
                                    f"Unable to check {_instance_id}: {inner_e}"
                                )
                else:
                    logger.error(f"Unable to batch check instance state: {e}")

        return SocaResponse(success=True, message=_instance_ids_state)

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"find_instance_ids_instance_state error due to {err} at line {exc_tb.tb_lineno}"
        )
        return SocaResponse(
            success=False,
            message=f"find_instance_ids_instance_state error due to {err} at line {exc_tb.tb_lineno}",
        )


def _describe_all_stack_statuses() -> SocaResponse:
    """Single paginated account-level DescribeStacks -> {stack_name: status}.  """
    _statuses: dict = {}
    try:
        _paginator = _client("cloudformation").get_paginator("describe_stacks")
        for _page in _paginator.paginate():
            for _stack in _page.get("Stacks", []):
                _statuses[_stack["StackName"]] = _stack["StackStatus"]
        return SocaResponse(success=True, message=_statuses)
    except Exception as err:
        logger.error(f"Batch DescribeStacks failed: {err}")
        return SocaError.AWS_API_ERROR(
            service_name="cloudformation",
            helper=f"Batch DescribeStacks failed: {err}",
        )


def delete_inactive_instances(
    sessions: VirtualDesktopSessions,
    instance_ids_state: dict,
    db_scoped_session: Session,
):
    """

    If an session does not have any associated instance id, it means:
    1 - the session was just initiated and the CloudFormation stack has not created the EC2 capacity yet
    2 - the EC2 machine and/or CloudFormation Stack has been either removed from AWS console/CLI

    If 2), we don't try to delete the Cloudformation stack if needed and we updated the is_active flag for the session to False
    """

    logger.info(
        f"Finding inactive instances & Deleting Associated Stack for the following list: {sessions}"
    )

    # Batch the per-cycle CFN status read into ONE paginated call. If it fails
    # (throttle/transient), skip the reap this cycle and retry next pass -- never
    # delete a session on an inconclusive stack read (was the 128-scale mass-reap bug).
    _stack_statuses_resp = _describe_all_stack_statuses()
    if _stack_statuses_resp.get("success") is False:
        logger.warning(
            "Skipping inactive-instance reap this cycle: batch DescribeStacks failed "
            f"({_stack_statuses_resp.get('message')}). Refusing to delete sessions on an "
            "inconclusive stack read; will retry next cycle."
        )
        return
    _stack_statuses = _stack_statuses_resp.get("message")

    for _session in sessions:
        _stack_name = _session.stack_name
        _session_uuid = _session.session_uuid
        _session_instance_id = _session.instance_id

        _stack_deleted = False
        logger.info(f"Checking CFN stack {_stack_name} for session {_session_uuid}")

        _instance_id_current_state = instance_ids_state.get(_session_instance_id)

        if _instance_id_current_state == "terminated":
            logger.info(
                f"{_session_instance_id=} is terminated, deleting stack if it exist"
            )
            _delete_stack = SocaCfnClient(stack_name=_stack_name).delete_stack()
            if _delete_stack.get("success") is False:
                logger.error(
                    f"Unable to delete stack {_stack_name}: {_delete_stack.get('message')}"
                )
            else:
                logger.info(f"{_stack_name=} deleted")
                _stack_deleted = True
        else:
            logger.info(
                f"{_session_instance_id=} exist {_session.id=} {_session.session_uuid=}, checking CFN stack status, ensuring it's still being provisioned"
            )
            # Look up the batch-resolved status. Absent from the map == stack no longer
            # exists (DELETE_COMPLETE is excluded from an unfiltered DescribeStacks), so
            # treat as STACK_UNKNOWN -> reap. A transient throttle can no longer land here:
            # it fails the batch read above and skips the whole cycle.
            _stack_status = _stack_statuses.get(_stack_name, "STACK_UNKNOWN")

            logger.info(f"CloudFormation Stack {_stack_name} status: {_stack_status}")

            if _stack_status in [
                "STACK_UNKNOWN",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            ]:
                logger.info(
                    f"CloudFormation Stack associated does not exist or is being deleted, removing this session from the database"
                )

                _delete_stack = SocaCfnClient(stack_name=_stack_name).delete_stack()
                if _delete_stack.get("success") is False:
                    logger.error(
                        f"Unable to delete stack {_stack_name}: {_delete_stack.get('message')}"
                    )
                else:
                    logger.info(f"{_stack_name=} deleted")
                    _stack_deleted = True

            else:
                logger.info(
                    f"CloudFormation Stack exist and is in valid state, capacity will be provisioned soon ... "
                )

        if _stack_deleted:
            # Spot-interrupt hand-off: the reclaimed instance's stack is gone,
            # but instead of deactivating we hold the tile as a terminal
            # "interrupted -> saved" card (is_active=True). The interrupted-card
            # reaper (below) owns its resolution: retire on saved-image available,
            # or hold a failure card. Fires once (interrupting -> interrupted);
            # on later ticks it is already interrupted and we just skip.
            if getattr(_session, "is_spot", False) and _session.session_state in (
                "interrupting",
                "interrupted",
            ):
                if _session.session_state != "interrupted":
                    _session.session_state = "interrupted"
                    _session.session_state_latest_change_time = datetime.now(
                        timezone.utc
                    )
                    try:
                        db_scoped_session.commit()
                        logger.info(
                            f"Session {_session.id} {_session.session_uuid=} "
                            f"interrupting -> interrupted (spot reclaim; holding terminal card)"
                        )
                    except Exception as e:
                        db_scoped_session.rollback()
                        logger.critical(
                            f"Error committing interrupted transition: {e}"
                        )
                continue
            try:
                logger.info("Updating is_active flag to False")
                _session.is_active = False
                _session.deactivated_on = datetime.now(timezone.utc)
                _session.deactivated_by = "SCHEDULED_TASK"
                _session.session_state_latest_change_time = datetime.now(timezone.utc)
                # A pre-instance session whose stack rolled back / was deleted
                # never launched -> surface as error (not left at placing/pending)
                # so the tile shows a failure card instead of a stuck spinner.
                # Guarded so a running/stopped session is never mislabeled.
                if _session.session_state in ("placing", "pending"):
                    _session.session_state = "error"
                    logger.info(
                        f"Session {_session.id} {_session.session_uuid=} "
                        f"-> error (stack deleted before instance launch)"
                    )
                try:
                    db_scoped_session.commit()
                    logger.info(
                        f"Session {_session.id} {_session.session_uuid=} has been deactivated successfully on the database"
                    )
                except Exception as e:
                    db_scoped_session.rollback()
                    logger.critical(
                        f"Error trying to run the following commits on update_virtual_desktop_state because of: {e}"
                    )
                    queries = [
                        str(statement)
                        for statement in db_scoped_session._logger.handlers[
                            0
                        ].baseFilename
                    ]
                    logger.critical(f"Failed SQL query: {queries}")

            except Exception as err:
                logger.error(f"Unable to update is_active flag to False: {err}")
                continue


def update_virtual_desktop_state(
    sessions: VirtualDesktopSessions, new_state: str, db_scoped_session: Session
):
    for _session in sessions:
        try:
            logger.info(
                f"Updating state for session {_session.id=} {_session.session_uuid=} to {new_state} in the database, current state is {_session.session_state}"
            )
            if _session.session_state != new_state:
                _session.session_state = new_state
                _session.session_state_latest_change_time = datetime.now(timezone.utc)
                try:
                    db_scoped_session.commit()
                    logger.info(
                        f"Success: state for session {_session.id=} {_session.session_uuid=} to {new_state=} in the database"
                    )
                except Exception as e:
                    db_scoped_session.rollback()
                    logger.critical(
                        f"Error trying to run the following commits on update_virtual_desktop_state because of: {e}"
                    )
                    queries = [
                        str(statement)
                        for statement in db_scoped_session._logger.handlers[
                            0
                        ].baseFilename
                    ]
                    logger.critical(f"Failed SQL query: {queries}")

            else:
                logger.info(
                    f"Session {_session.id=} {_session.session_uuid=} already in state {new_state=}"
                )

        except Exception as err:
            logger.error(
                f"Unable to update state for session {_session.session_uuid} to {new_state}: {err}"
            )
            continue


# main
def _sweep_zombie_available_members():
    """Reap pool members that are AVAILABLE in the ledger but no longer
    broker-registered (fell out of DCV while idle): drop the stale row and mark
    the instance Unhealthy so the ASG relaunches it. Safety: one describe_servers
    per cycle (skip entirely if the broker is unreachable -- never mass-reap on a
    blip); a registered_at grace window avoids racing broker consistency.
    """
    try:
        from helpers.vdi_pool_allocator import _ledger_table_name
        from utils.dcv_broker_client import DcvBrokerClient
        from boto3.dynamodb.conditions import Attr
    except Exception as _imp_err:
        logger.warning(f"zombie sweep: import failed; skipping: {_imp_err}")
        return

    _tname = _ledger_table_name()
    if not _tname:
        return

    _grace_sec = 180
    try:
        _servers = DcvBrokerClient().describe_servers()
    except Exception as _e:
        logger.warning(f"zombie sweep: describe_servers error; skipping (no reap): {_e}")
        return
    if not getattr(_servers, "success", False):
        logger.warning(
            "zombie sweep: describe_servers failed; skipping (no reap on broker blip)"
        )
        return

    _ready = set()
    for _s in (_servers.message or {}).get("Servers", []) or []:
        if _s.get("Availability") != "AVAILABLE":
            continue
        _tags = {t.get("Key"): t.get("Value") for t in (_s.get("Tags") or [])}
        _iid = _tags.get("instance") or (
            (_s.get("Host") or {}).get("Aws") or {}
        ).get("EC2InstanceId")
        if _iid:
            _ready.add(_iid)

    try:
        _ddb_resp = utils_boto3.get_boto(service_name="dynamodb", resource=True)
        if _ddb_resp.get("success") is False:
            logger.warning("zombie sweep: failed to get DynamoDB resource; skipping")
            return
        _ddb = _ddb_resp.get("message")
        _table = _ddb.Table(_tname)
        _rows = []
        _scan_kwargs = {"FilterExpression": Attr("status").eq("AVAILABLE")}
        while True:
            _resp = _table.scan(**_scan_kwargs)
            _rows.extend(_resp.get("Items", []))
            if "LastEvaluatedKey" not in _resp:
                break
            _scan_kwargs["ExclusiveStartKey"] = _resp["LastEvaluatedKey"]
    except Exception as _e:
        logger.warning(f"zombie sweep: ledger scan failed; skipping: {_e}")
        return

    _now = datetime.now(timezone.utc)
    _asg_resp = utils_boto3.get_boto(service_name="autoscaling")
    _ec2_resp = utils_boto3.get_boto(service_name="ec2")
    if _asg_resp.get("success") is False or _ec2_resp.get("success") is False:
        logger.warning("zombie sweep: failed to get EC2/ASG client; skipping")
        return
    _asg = _asg_resp.get("message")
    _ec2 = _ec2_resp.get("message")

    # Candidate rows: AVAILABLE, not broker-ready, past the grace window.
    _candidates = []
    for _row in _rows:
        _iid = _row.get("instance_id") or _row.get("sk")
        if not _iid or _iid in _ready:
            continue
        _reg = _row.get("registered_at")
        if _reg:
            try:
                _rt = datetime.strptime(_reg, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
                if (_now - _rt).total_seconds() < _grace_sec:
                    continue  # too fresh; broker may still be catching up
            except Exception:
                pass
        _candidates.append((_iid, _row))
    if not _candidates:
        return

    # Resolve EC2 run state so we don't terminate a legitimate Stopped warm
    # member (stale AVAILABLE row, but a parked reserve). Only a RUNNING member
    # the broker can't serve is a true zombie -> recycle it.
    _state = {}
    try:
        _pg = _ec2.get_paginator("describe_instances")
        for _pager in _pg.paginate(
            Filters=[{"Name": "instance-id", "Values": [c[0] for c in _candidates]}]
        ):
            for _r in _pager.get("Reservations", []):
                for _i in _r.get("Instances", []):
                    _state[_i["InstanceId"]] = (_i.get("State") or {}).get("Name", "")
    except Exception as _e:
        logger.warning(f"zombie sweep: describe_instances failed; skipping: {_e}")
        return

    _reaped = 0
    _cleaned = 0
    for _iid, _row in _candidates:
        _st = _state.get(_iid, "")
        if _st in ("stopped", "stopping"):
            # Legitimate Stopped warm reserve with a STALE AVAILABLE row -- just
            # drop the row so a claim never picks a stopped member. Do NOT
            # terminate (that would churn the warm pool).
            try:
                _table.delete_item(Key={"pk": _row["pk"], "sk": _row["sk"]})
                _cleaned += 1
                logger.info(
                    f"zombie sweep: dropped stale AVAILABLE row for stopped warm "
                    f"member {_iid} (left the warm reserve intact)"
                )
            except Exception as _e:
                logger.warning(f"zombie sweep: stale-row delete failed for {_iid}: {_e}")
        elif _st == "running":
            # True zombie: running + AVAILABLE but the broker can't serve it.
            # Drop the row and mark Unhealthy so the ASG recycles it.
            logger.warning(
                f"zombie sweep: {_iid} is RUNNING + AVAILABLE but NOT broker-ready; "
                f"dropping row + marking Unhealthy so the ASG replaces it"
            )
            try:
                _table.delete_item(Key={"pk": _row["pk"], "sk": _row["sk"]})
            except Exception as _e:
                logger.warning(f"zombie sweep: ledger delete failed for {_iid}: {_e}")
            try:
                _asg.set_instance_health(
                    InstanceId=_iid,
                    HealthStatus="Unhealthy",
                    ShouldRespectGracePeriod=False,
                )
            except Exception as _e:
                logger.warning(f"zombie sweep: set_instance_health failed for {_iid}: {_e}")
            _reaped += 1
        else:
            # pending/shutting-down/terminated/unknown: drop the row (not
            # claimable), don't touch the instance.
            try:
                _table.delete_item(Key={"pk": _row["pk"], "sk": _row["sk"]})
                _cleaned += 1
            except Exception as _e:
                logger.warning(f"zombie sweep: row delete ({_st}) failed for {_iid}: {_e}")
    if _reaped or _cleaned:
        logger.info(
            f"zombie sweep: recycled {_reaped} running zombie(s), "
            f"cleaned {_cleaned} stale row(s)"
        )


def _reap_orphaned_session_stacks(cluster_id: str):
    """Delete per-session VDI CloudFormation stacks left standing after their
    instance died outside the Delete-Desktop path (Spot interruption auto-capture,
    Save & Shut Down, manual/FIS terminate). The active-session reaper
    (delete_inactive_instances) only fires while a session is still
    is_active=True; capture flows deactivate the session before the stack is
    torn down, so the stack orphans and never re-enters that reaper. This sweep
    catches every death path by reaping any per-session stack (tagged
    edh:NodeType=dcv_node for this cluster) that no ACTIVE session still owns.
    The saved-desktop AMI/snapshots are independent of the stack and are never
    touched. Best-effort and idempotent -- an inconclusive DescribeStacks skips
    the sweep this cycle rather than risk a wrong delete."""
    if not cluster_id:
        return

    # Stacks owned by a live (is_active=True) session must never be reaped --
    # includes running AND stopped/resumable desktops.
    _protected = {
        s.stack_name
        for s in VirtualDesktopSessions.query.filter(
            VirtualDesktopSessions.is_active.is_(True)
        ).all()
        if s.stack_name
    }

    # Also protect a stopped box that is mid-capture (Save & Shut Down deferred its
    # CreateImage to create_images_for_stopped_captures): the session is already
    # deactivated, so without this the reaper could delete the stack -- terminating
    # the box -- before it is imaged, losing the capture. Once imaged, the row
    # leaves 'pending_capture' and the stack drops out of protection.
    _protected |= {
        r.capture_stack_name
        for r in VdiSavedImages.query.filter_by(
            state="pending_capture", is_active=True
        ).all()
        if r.capture_stack_name
    }

    _reapable_status = {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_ROLLBACK_FAILED",
    }

    _orphans = []
    try:
        _paginator = _client("cloudformation").get_paginator("describe_stacks")
        for _page in _paginator.paginate():
            for _stack in _page.get("Stacks", []):
                _tags = {t["Key"]: t["Value"] for t in _stack.get("Tags", [])}
                # Scope strictly to per-session VDI stacks for THIS cluster. This
                # tag pair excludes the main cluster stack, nested stacks, other
                # clusters, and any non-EDH stack.
                if _tags.get("edh:NodeType") != "dcv_node":
                    continue
                if _tags.get("edh:ClusterId") != cluster_id:
                    continue
                _name = _stack["StackName"]
                if _name in _protected:
                    continue
                if _stack["StackStatus"] not in _reapable_status:
                    continue
                _orphans.append(_name)
    except Exception as err:
        logger.warning(
            f"orphan-stack sweep: DescribeStacks failed ({err}); skipping this cycle"
        )
        return

    if not _orphans:
        return

    logger.info(
        f"orphan-stack sweep: reaping {len(_orphans)} orphaned VDI stack(s): {_orphans}"
    )
    for _name in _orphans:
        _res = SocaCfnClient(stack_name=_name).delete_stack()
        if _res.get("success") is False:
            logger.warning(
                f"orphan-stack sweep: delete_stack({_name}) failed: {_res.get('message')}"
            )
        else:
            logger.info(f"orphan-stack sweep: deleted orphaned stack {_name}")


def virtual_desktops_session_state_watcher(app: Flask):
    with app.app_context():
        logger.info("Scheduled Task: virtual_desktops_session_state_watcher")

        # Reliability sweep (high-scale only): reap AVAILABLE pool members that
        # have zombied out of the DCV broker while idle, so claims never serve a
        # dead member. Best-effort; never breaks the watcher.
        if is_high_scale_enabled():
            try:
                _sweep_zombie_available_members()
            except Exception as _sw_err:
                logger.warning(f"zombie sweep failed (non-fatal): {_sw_err}")

        # Orphan-stack reaper: reap per-session VDI stacks whose instance died
        # outside Delete-Desktop (Spot interrupt, Save & Shut Down, manual terminate)
        # and whose session is no longer active. Best-effort; never breaks the watcher.
        try:
            _reap_orphaned_session_stacks(
                SocaConfig(key="/configuration/ClusterId").get_value().get("message")
            )
        except Exception as _reap_err:
            logger.warning(f"orphan-stack sweep failed (non-fatal): {_reap_err}")

        _start_time = time.time()

        # --- Resume-From: consume saved images whose resumed session is now running ---
        # Single-use invariant: once a resumed session reaches 'running', deregister its
        # source AMI. Idempotent -- consume flips the image to 'consumed' so the filter
        # below stops matching on the next cycle. Catches all promotion paths (broker
        # validate, placing->running, push) since it keys off the final 'running' state.
        try:
            from utils.resume_orchestration import consume_on_success as _consume_on_success
            from utils.resume_orchestration import promote_ready_captures as _promote_ready_captures
            from utils.resume_orchestration import reap_recycled_images as _reap_recycled_images
            from utils.resume_orchestration import (
                create_images_for_stopped_captures as _create_images_for_stopped_captures,
            )

            # Stop-then-image: image any 'pending_capture' box that has now stopped
            # (Save & Shut Down deferred CreateImage here for a clean snapshot), then
            # terminate it. Creates the 'capturing' row that promote picks up below.
            _create_images_for_stopped_captures()

            # Flip finished captures capturing->available so the Resume button appears.
            _promote_ready_captures()

            # Hard-delete recycled saved images whose recovery TTL has elapsed.
            _reap_recycled_images()

            _resumed_running = VirtualDesktopSessions.query.filter(
                VirtualDesktopSessions.is_active.is_(True),
                VirtualDesktopSessions.session_state == "running",
                VirtualDesktopSessions.resume_saved_image_id.isnot(None),
            ).all()
            for _rs in _resumed_running:
                _img = VdiSavedImages.query.filter_by(
                    id=_rs.resume_saved_image_id, state="resuming"
                ).first()
                if _img:
                    logger.info(
                        f"Resume-From: session {_rs.session_uuid} is running; consuming "
                        f"saved image id={_img.id} ({_img.image_id})"
                    )
                    _consume_on_success(_img.id)
        except Exception as _consume_err:
            logger.warning(f"Resume-From consume pass failed (non-fatal): {_consume_err}")

        # --- Resume-From: auto-revert saved images whose resumed session FAILED ---
        # If the resumed session was deactivated (CFN rollback, terminated, error) while
        # the saved-image row is still 'resuming', revert to 'available' so the user can
        # retry. Without this, a failed resume strands the image in 'resuming' forever.
        try:
            from utils.resume_orchestration import revert_resume_lease as _revert_resume_lease

            _stale_resuming = VdiSavedImages.query.filter_by(
                state="resuming", is_active=True
            ).all()
            for _sr in _stale_resuming:
                _linked = VirtualDesktopSessions.query.filter_by(
                    resume_saved_image_id=_sr.id, is_active=True
                ).first()
                if _linked is None:
                    logger.warning(
                        f"Resume-From: saved image id={_sr.id} is 'resuming' but has no "
                        f"active session -- reverting to available (resume failed/deactivated)"
                    )
                    _revert_resume_lease(_sr.id)
        except Exception as _revert_err:
            logger.warning(f"Resume-From revert pass failed (non-fatal): {_revert_err}")

        # Get all current active VDI (exclude 'placing' — no EC2 instance yet)
        # --- Placing-state promotion + timeout backstop ---
        # The /session-event endpoint is instance-attested, so it structurally
        # cannot accept the executor's 'placed'/'placement_failed' events (no
        # instance exists yet at placement time). We therefore drive the
        # placing-state transitions HERE, from the durable event store:
        #   session-ready  -> running   (bootstrap finished — Connect appears)
        #   placed         -> pending   (stack created; bootstrapping)
        #   none after 5m  -> error     (placement pipeline never responded)
        _placing_timeout_min = 5
        _now = datetime.now(timezone.utc)
        _placing = VirtualDesktopSessions.query.filter(
            VirtualDesktopSessions.is_active.is_(True),
            VirtualDesktopSessions.session_state == "placing",
        ).all()
        _placing_changed = False
        for _s in _placing:
            try:
                from utils.dcv_event_store import recent_events as _recent_events
                _seen = {(_e.get("payload") or {}).get("event_type")
                         for _e in _recent_events(f"dcv#{_s.session_uuid}", limit=50)}
            except Exception as _ev_err:
                logger.warning(f"placing guard event read failed for {_s.session_uuid}: {_ev_err}")
                continue
            # Event-driven promotion (event store is the source of truth here).
            if _seen & {"session-ready", "session-resumed"}:
                _s.session_state = "running"
                _s.session_state_latest_change_time = _now
                _placing_changed = True
                logger.info(f"Promoted placing->running (session-ready) for {_s.session_uuid}")
                continue
            if "placement_failed" in _seen:
                # Terminal failure wins over an earlier 'placed' (async spot
                # AZ-fallback emits placed on each attempt, then placement_failed
                # on exhaustion). Checked before 'placed' so a same-tick
                # placed+failed resolves to error, not a stuck 'pending'.
                _s.session_state = "error"
                _s.session_state_latest_change_time = _now
                _placing_changed = True
                logger.info(f"Promoted placing->error (placement_failed) for {_s.session_uuid}")
                continue
            if "placed" in _seen:
                _s.session_state = "pending"
                _s.session_state_latest_change_time = _now
                _placing_changed = True
                logger.info(f"Promoted placing->pending (placed) for {_s.session_uuid}")
                continue
            # Broker-state backstop (Option 1): pool hot-claimed sessions never
            # emit session-ready/placed events (the instance was already running
            # when the broker session was created). Ask the broker directly if
            # the session is READY; if so, promote placing->running. This also
            # rescues any cold VDI whose events were lost.
            try:
                from utils.dcv_broker_client import DcvBrokerClient
                _broker_session = DcvBrokerClient().find_session_by_name(_s.session_uuid)
                if _broker_session and str(_broker_session.get("State", "")).upper() == "READY":
                    _s.session_state = "running"
                    _s.session_state_latest_change_time = _now
                    _placing_changed = True
                    logger.info(f"Promoted placing->running (broker READY backstop) for {_s.session_uuid}")
                    continue
            except Exception as _broker_err:
                logger.debug(f"Broker backstop check failed for {_s.session_uuid}: {_broker_err}")
            # Backstop: only when the pipeline never responded AND we're past
            # the grace window (genuine Lambda death — no placed/ready event).
            # Normalize tz-awareness: session_state_latest_change_time comes back
            # from the DB offset-naive while _now is offset-aware (UTC), and a
            # naive>=aware compare raises TypeError -- which crashed the whole
            # watcher every cycle and stranded pool hot-claim sessions (the first
            # consumers to reach this backstop with no placed/ready event) in
            # 'placing' forever. Treat stored times as UTC.
            _last_change = _s.session_state_latest_change_time
            if _last_change is not None and _last_change.tzinfo is None:
                _last_change = _last_change.replace(tzinfo=timezone.utc)
            _grace_cutoff = _now
            if _grace_cutoff.tzinfo is None:
                _grace_cutoff = _grace_cutoff.replace(tzinfo=timezone.utc)
            if _last_change is not None and _last_change >= (
                _grace_cutoff - timedelta(minutes=_placing_timeout_min)
            ):
                continue
            # Atomic single-fire across concurrent watcher workers (conditional
            # PutItem); without this the guard fired 2–3x in the same instant.
            try:
                from utils.dcv_event_store import record_nonce_or_reject as _nonce
                if not _nonce(_s.session_uuid, "placement_timeout", "backstop"):
                    continue
            except Exception as _nonce_err:
                logger.warning(f"placing-timeout nonce guard failed: {_nonce_err}")
            logger.warning(
                f"Placing timeout: session {_s.session_uuid} stuck in 'placing' "
                f">{_placing_timeout_min}min with no placement response; marking as error"
            )
            _s.session_state = "error"
            _s.session_state_latest_change_time = _now
            _placing_changed = True
            try:
                from utils.dcv_event_store import append_event, build_envelope, new_event_id
                _eid = new_event_id()
                _env = build_envelope(
                    _eid, "placement_failed", _s.session_uuid,
                    "timeout",
                    f"Placement pipeline did not respond within "
                    f"{_placing_timeout_min} min (session never left 'placing')",
                    owner=_s.session_owner,
                )
                append_event(f"dcv#{_s.session_uuid}", _eid, _env)
            except Exception as _evt_err:
                logger.warning(f"Could not emit placement_failed event: {_evt_err}")
        if _placing_changed:
            db.session.commit()
        # --- End placing-state promotion + backstop ---

        # --- Interrupted-card reaper (spot interrupt -> saved hand-off) ---
        # An 'interrupted' session is a terminal card held (is_active=True) after
        # a Spot reclaim so the user keeps a reference until the auto-save is
        # resumable. Resolution is derived from the linked interrupt saved image
        # (VdiSavedImages.origin_session_uuid). Reap triggers (locked design):
        #   * saved image 'available'  -> retire the card (Saved Desktop now
        #     stands on its own, carries the "interrupted spot" identifier).
        #   * capture failed / stuck past the soft TTL -> the card renders a
        #     failure ("auto-save did not complete"); it is retained so the user
        #     sees the data-loss signal, and only hard-reaped past the long TTL.
        #   * manual dismiss is handled by delete_virtual_desktop (is_active=False).
        _interrupted = VirtualDesktopSessions.query.filter(
            VirtualDesktopSessions.is_active.is_(True),
            VirtualDesktopSessions.session_state == "interrupted",
        ).all()
        _interrupted_changed = False
        _hard_ttl = timedelta(hours=24)  # backstop reap for a lingering failure card
        for _s in _interrupted:
            _img = (
                VdiSavedImages.query.filter_by(
                    origin_session_uuid=_s.session_uuid, source="interrupt"
                )
                .order_by(VdiSavedImages.id.desc())
                .first()
            )
            _img_state = (_img.state if _img else None)
            _changed_at = _s.session_state_latest_change_time
            if _changed_at is not None and _changed_at.tzinfo is None:
                _changed_at = _changed_at.replace(tzinfo=timezone.utc)
            _age = (_now - _changed_at) if _changed_at is not None else timedelta(0)
            if _img_state == "available":
                # Hand-off complete: the saved desktop is resumable. Retire card.
                _s.is_active = False
                _s.deactivated_on = _now
                _s.deactivated_by = "interrupted_card_reaper"
                _s.session_state_latest_change_time = _now
                _interrupted_changed = True
                logger.info(
                    f"Interrupted card retired (saved image {_img.id} available) "
                    f"for {_s.session_uuid}"
                )
            elif _age >= _hard_ttl:
                # Failure card lingered past the hard backstop -> reap.
                _s.is_active = False
                _s.deactivated_on = _now
                _s.deactivated_by = "interrupted_card_reaper"
                _s.session_state_latest_change_time = _now
                _interrupted_changed = True
                logger.info(
                    f"Interrupted card hard-reaped (age {_age}, image state "
                    f"{_img_state}) for {_s.session_uuid}"
                )
            # else: still capturing within TTL, or a failure card within the hard
            # TTL -> keep it. Success/failure rendering is derived from _img_state
            # by the tile/API (available=save ok; failed/None+past soft TTL=failure).
        if _interrupted_changed:
            db.session.commit()
        # --- End interrupted-card reaper ---

        _all_dcv_sessions = VirtualDesktopSessions.query.filter(
            VirtualDesktopSessions.is_active.is_(True),
            VirtualDesktopSessions.session_state != "placing",
        ).all()
        if _all_dcv_sessions:

            # First, we get the latest status for all the instances IDs registered.
            # We create batch requests of up to 100 instance ids.
            _instance_ids_by_state = find_instance_ids_instance_state(
                all_sessions=_all_dcv_sessions
            )

            logger.debug(f"Instance ID by State: {_instance_ids_by_state}")

            if _instance_ids_by_state.get("success") is False:
                logger.critical(
                    f"Unable to retrieve instance state for all instances due to {_instance_ids_by_state.get('message')}"
                )

            # Start by creating chunk of 50 VDI sessions maximum (this is the max number of InstanceIds we can pass to some boto3 API call)
            # Keep this limit below 50.
            _chunk_size = 50

            # Create chunk of 50 sessions max
            _chunks_of_sessions = chunked_iterable(_all_dcv_sessions, _chunk_size)

            # Provision 3 workers to run concurrently
            _workers = 3

            use_multi_threads = False  # for future usage

            if use_multi_threads:
                with ThreadPoolExecutor(max_workers=_workers) as executor:
                    # Submit each chunk to the executor for parallel processing
                    futures = [
                        executor.submit(
                            process_chunk, chunk, _instance_ids_by_state.get("message")
                        )
                        for chunk in _chunks_of_sessions
                    ]

                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            logger.info(result)
                        except Exception as e:
                            logger.error(f"Chunk processing failed: {e}")
            else:
                # No concurrency, create chunk and process them
                for _chunk in _chunks_of_sessions:
                    process_chunk(_chunk, _instance_ids_by_state.get("message"))

            _end_time = time.time()
            logger.info(
                f"Scheduled task completed in {_end_time - _start_time:.2f} seconds for {len(_all_dcv_sessions)} sessions"
            )

        else:
            logger.info("No active virtual desktops found")
