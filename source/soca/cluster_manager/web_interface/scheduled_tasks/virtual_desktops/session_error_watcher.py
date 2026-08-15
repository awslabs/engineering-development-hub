# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from extensions import db
from models import VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
import config
from sqlalchemy.orm import Session
from typing import Iterator, List, Literal, Iterable, TypeVar
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from itertools import islice
import time
from flask import Flask

logger = logging.getLogger("scheduled_tasks_virtual_desktops_session_error_watcher")

client_ssm = utils_boto3.get_boto(service_name="ssm").message


def is_high_scale_enabled() -> bool:
    """
    True if the cluster is running in DCV high-scale (broker) mode.

    In broker mode, session_state_watcher.py validates session health
    by querying the broker every 1 minute -- which is more frequent than
    this 5-minute error watcher anyway. Running a parallel SSM-based
    check from this watcher would be (a) redundant, (b) hostile (SSM
    timeouts can cause spurious "session not reachable" blips in the
    WebUI), so we skip this watcher entirely in high-scale mode.

    Reads /dcv/high_scale_enabled -- the canonical persisted flag (matches
    create_virtual_desktop.py, list_virtual_desktops.py, session_state_watcher.py,
    etc). /configuration/DcvHighScale is a render-only variable that is
    never persisted to SSM -- reading it here always fell through to the
    "false" default, permanently caching False and letting this watcher's
    SSM-probe path run on every high-scale cluster (exactly the "hostile"
    behavior the docstring above says this function exists to prevent).
    """
    if not hasattr(is_high_scale_enabled, "_cached"):
        try:
            # Canonical persisted flag is /dcv/high_scale_enabled (matches
            # create/list/render). /configuration/DcvHighScale is a render-only
            # var, never persisted -> defaulted false -> this watcher never
            # skipped and false-errored console broker sessions.
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
) -> SocaResponse:
    """
    This function will retrieve all running DCV instances and check if DCV Session ID is healthy on the machine
    If not, status will be updated to "error"
    """
    _db_scoped_session = db.session
    try:
        logger.info(f"Processing chunk {sessions}")

        if is_high_scale_enabled():
            logger.info(
                "High-scale mode -- skipping session_error_watcher SSM check "
                "(state_watcher validates session health via broker every 1 min)"
            )
            return SocaResponse(
                success=True,
                message="Skipped in high-scale mode (broker is source of truth)",
            )

        if config.Config.DCV_VERIFY_SESSION_HEALTH is True:
            validate_dcv_session(
                sessions=sessions,
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.warning(
                "config.Config.DCV_VERIFY_SESSION_HEALTH is not True, skipping this check"
            )

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(f"Process Chunk error due to {err} at line {exc_tb.tb_lineno}")

    # Close current thread
    return SocaResponse(success=True, message="Chunk processed")


def ssm_get_command_info(os_family: Literal["linux", "windows"]) -> SocaResponse:
    """
    Returns the SSM command & document name to run based on the operating system

    Run dcv describe-session command
    - Return 0 is the command exists
    - Return 1 for any error
    """

    if os_family not in ["linux", "windows"]:
        logger.critical(f"os_family must be linux or windows, detected {os_family}")

    if os_family == "windows":
        _ssm_commands = [
            f"Invoke-Expression \"& 'C:\\Program Files\\NICE\\DCV\\Server\\bin\\dcv' describe-session $env:EDH_DCV_SESSION_ID\"",
            "if ($?) { exit 0 }",
            "Restart-Service -Name dcvserver -Force",
            "Start-Sleep -Seconds 5",
            f"Invoke-Expression \"& 'C:\\Program Files\\NICE\\DCV\\Server\\bin\\dcv' describe-session $env:EDH_DCV_SESSION_ID\"",
            "if ($?) { exit 0 } else { exit 1 }",
        ]

        _ssm_document_name = "AWS-RunPowerShellScript"

    else:
        _ssm_commands = [
            "export EDH_DCV_SESSION_ID=$(cat /etc/environment | grep EDH_DCV_SESSION_ID= | awk -F'=' '{print $2}')", # ssm.send_command() cannot use source",
            f"if dcv describe-session $EDH_DCV_SESSION_ID; then",
            " exit 0",
            "fi",
            " ",
            "systemctl restart socadcv;",
            "sleep 5",
            "",
            f"if dcv describe-session $EDH_DCV_SESSION_ID; then",
            "exit 0",
            "else",
            "exit 1 ",
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
            _check_command_status = client_ssm.list_commands(CommandId=command_id)[
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


def validate_dcv_session(
    sessions: VirtualDesktopSessions, db_scoped_session: Session
) -> SocaResponse:
    """
    ssm.send_command takes up to 50 InstanceIDs. Make sure the maximum chunk size is not greater than 50
    """
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
            _check_dcv_session_linux = client_ssm.send_command(
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
            _check_dcv_session_windows = client_ssm.send_command(
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
                _ssm_output = client_ssm.get_command_invocation(
                    CommandId=_ssm_command_id_linux, InstanceId=_session.instance_id
                )
                _status = _ssm_output.get("Status")
                if _status.lower() != "success":
                    logger.info(
                        f"DCV Session not running properly on {_session.instance_id} for DCV Session {_session.session_uuid}. Changing state to error"
                    )
                    update_virtual_desktop_state(
                        sessions=[_session],
                        new_state="error",
                        db_scoped_session=db_scoped_session,
                    )

        # Check all Windows hosts individually
        if not _skip_windows:
            for _session in [
                session for session in sessions if session.os_family == "windows"
            ]:
                _ssm_output = client_ssm.get_command_invocation(
                    CommandId=_ssm_command_id_windows, InstanceId=_session.instance_id
                )
                _status = _ssm_output.get("Status")
                if _status.lower() != "success":
                    logger.info(
                        f"DCV Session not running properly on {_session.instance_id} for DCV Session {_session.session_uuid}. Changing state to error"
                    )
                    update_virtual_desktop_state(
                        sessions=[_session],
                        new_state="error",
                        db_scoped_session=db_scoped_session,
                    )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"validate_dcv_session error due to {err} at line {exc_tb.tb_lineno}"
        )
        return SocaResponse(success=False, message=err)

    return SocaResponse(success=True, message="DCV Session validated successfully")


def update_virtual_desktop_state(
    sessions: VirtualDesktopSessions, new_state: str, db_scoped_session: Session
):
    for _session in sessions:
        try:
            logger.info(
                f"Updating state for session {_session.id=} to {new_state} in the database, current state is {_session.session_state}"
            )
            if _session.session_state != new_state:
                _session.session_state = new_state
                _session.session_state_latest_change_time = datetime.now(timezone.utc)
                try:
                    db_scoped_session.commit()
                    logger.info(
                        f"Success: state for session {_session.id=} to {new_state=} in the database"
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
                logger.info(f"Session {_session.id=} already in state {new_state=}")

        except Exception as err:
            logger.error(
                f"Unable to update state for session {_session.session_uuid} to {new_state}: {err}"
            )
            continue


# main
def virtual_desktops_session_error_watcher(app: Flask):
    with app.app_context():
        logger.info("Scheduled Task: virtual_desktops_session_error_watcher")

        _start_time = time.time()

        # Get all current active VDI
        _all_dcv_sessions = VirtualDesktopSessions.query.filter(
            VirtualDesktopSessions.is_active.is_(True),
            VirtualDesktopSessions.session_state == "running",
        ).all()
        if _all_dcv_sessions:

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
                        executor.submit(process_chunk, chunk)
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
                    process_chunk(_chunk)

            _end_time = time.time()
            logger.info(
                f"Scheduled task completed in {_end_time - _start_time:.2f} seconds for {len(_all_dcv_sessions)} sessions"
            )

        else:
            logger.info("No active virtual desktops found")
