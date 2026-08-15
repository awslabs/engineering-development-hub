# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import config
from dateutil.parser import parse
from extensions import db
from models import VirtualDesktopSessions
from utils.error import SocaError
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.validators import Validators
import utils.aws.boto3_wrapper as utils_boto3
import utils.aws.odcr_helper as odcr_helper
from utils.aws.cloudformation_client import SocaCfnClient
from utils.config import SocaConfig
import time
from datetime import datetime, timedelta, timezone
import pytz
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
from typing import Literal, Union
import math
import os
from flask import Flask

logger = logging.getLogger("scheduled_tasks_virtual_desktops_schedule_management")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message


def ssm_get_command_info(
    os_family: Literal["linux", "windows"],
) -> Union[SocaResponse, SocaError]:
    """
    Returns the SSM command & document name to run based on the operating system
    """

    if os_family not in ["linux", "windows"]:
        return SocaError.GENERIC_ERROR(
            success=False,
            message=f"os_family must be linux or windows, detected {os_family}",
        )

    if os_family == "windows":
        _ssm_commands = [
            # Powershell in Python - syntax highlighting may get crazy!
            """
            $Instance_Type = (Get-EC2InstanceMetadata -Category InstanceType)
            $GPU = (aws ec2 describe-instance-types --instance-types $Instance_Type --query 'InstanceTypes[*].GpuInfo.Gpus[*].Manufacturer' --output=text)
            if ($GPU -eq "NVIDIA") {
                $GPU_Usage_Level = (nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits)
            } elseif ($GPU -eq "AMD") {
                $GPU_Usage_Level = 0
            } else {
                $GPU_Usage_Level = 0
            }
            """,
            "$DCV_Sessions = Invoke-Expression \"& 'C:\\Program Files\\NICE\\DCV\\Server\\bin\\dcv' list-sessions -j\" | ConvertFrom-Json",
            '$CPUAveragePerformanceLast10Secs = (GET-COUNTER -Counter "\\Processor(_Total)\\% Processor Time" -SampleInterval 2 -MaxSamples 5 |select -ExpandProperty countersamples | select -ExpandProperty cookedvalue | Measure-Object -Average).average',
            # RDP sessions in state "Active" mean a user is actively connected over RDP,
            # independent of any DCV session. Match SESSIONNAME "rdp-tcp#N" only -- the
            # local "console" session (session 1, the physical/virtual display) is also
            # reported "Active" by `query user` whenever a user is logged in, even with
            # no RDP client attached (e.g. DCV-only usage), which would otherwise false-
            # positive and permanently block idle-stop. "Disc" RDP sessions are excluded,
            # matching DCV's num-of-connections semantics (0 when nobody is watching).
            '$RDPActiveConnections = (query user 2>$null | Select-String "^\\s*\\S+\\s+rdp-tcp#\\d+\\s+\\d+\\s+Active" | Measure-Object).Count',
            "$output = @{}",
            '$output["CPUAveragePerformanceLast10Secs"] = $CPUAveragePerformanceLast10Secs',
            '$output["GPUUsageLevel"] = $GPU_Usage_Level',
            '$output["DCVSessions"] = $DCV_Sessions',
            '$output["RDPActiveConnections"] = $RDPActiveConnections',
            "$output | ConvertTo-Json -Depth 10",
        ]
        _ssm_document_name = "AWS-RunPowerShellScript"

    else:
        # Linux BaseOS
        _ssm_commands = [
            """
            TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
            INSTANCE_TYPE=$(curl -s -H "X-aws-ec2-metadata-token: ${TOKEN}" http://169.254.169.254/latest/meta-data/instance-type)
            GPU=$(aws ec2 describe-instance-types --instance-types ${INSTANCE_TYPE} --query 'InstanceTypes[*].GpuInfo.Gpus[*].Manufacturer' --output=text)
            if [ "${GPU}" == "NVIDIA" ]; then
                GPU_USAGE_LEVEL=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits)
            else
                GPU_USAGE_LEVEL=0
            fi
            """,
            "DCV_Sessions=$(dcv list-sessions -j)",
            'echo "${DCV_Sessions:-[]}" | jq --arg GPUUsageLevel "${GPU_USAGE_LEVEL}" --arg CPUAveragePerformanceLast10Secs "$(top -d 5 -b -n2 | grep \'Cpu(s)\' | tail -n 1 | awk \'{print $2 + $4}\')" \'{"DCVSessions": ., "CPUAveragePerformanceLast10Secs": $CPUAveragePerformanceLast10Secs, "GPUUsageLevel": $GPUUsageLevel}\'',
        ]
        _ssm_document_name = "AWS-RunShellScript"

    return SocaResponse(
        success=True,
        message={
            "ssm_commands": _ssm_commands,
            "ssm_document_name": _ssm_document_name,
        },
    )


def ssm_get_list_command_status(command_id: str) -> Union[SocaResponse, SocaError]:
    """
    Returns the status of the SSM command ID.
    Valid status are either Success or Failed (this means the SSM command has completed successfully)
    All other SSM status code will return a SocaError
    """
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
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to determine status SSM responses after timeout for {command_id}"
                    )
                else:
                    time.sleep(5)
                    _ssm_attempt += 1
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"SSM command {command_id} exited with invalid status {_check_command_status=}"
                )


def _handle_odcr_remediation(session, instance_id: str) -> bool:
    """Attempt to fix ODCR for a stopped instance that failed to start due to capacity.

    Returns True if remediation succeeded (caller should retry start), False otherwise.
    """
    try:
        _describe = client_ec2.describe_instances(InstanceIds=[instance_id])
        _instance_info = _describe["Reservations"][0]["Instances"][0]
    except Exception as err:
        logger.warning(f"Unable to describe {instance_id} for ODCR remediation: {err}")
        return False

    _cr_spec = _instance_info.get("CapacityReservationSpecification") or {}
    _targeted_cr = (_cr_spec.get("CapacityReservationTarget") or {}).get(
        "CapacityReservationId"
    )

    if not _targeted_cr:
        logger.info(f"{instance_id} has no targeted CR; nothing to remediate")
        return False

    _tags = {t.get("Key"): t.get("Value") for t in _instance_info.get("Tags", [])}
    _cr_source = _tags.get("edh:CapacityReservationSource")
    if _cr_source is None:
        try:
            _cr_info = odcr_helper.get_reservation_info_soca_capacity_reservation(
                capacity_reservation_id=_targeted_cr
            )
            _cr_source = (
                "admin"
                if (_cr_info.reservation_exist and _cr_info.state == "active")
                else "auto"
            )
        except Exception:
            _cr_source = "auto"

    if _cr_source == "admin":
        logger.info(
            f"ODCR remediation: {instance_id} uses admin-supplied CR "
            f"({_targeted_cr}); cannot remediate"
        )
        return False

    logger.info(
        f"ODCR remediation: {instance_id} has expired auto CR ({_targeted_cr}), "
        f"attempting fresh ODCR"
    )
    _max_odcr_attempts = 2
    for _attempt in range(1, _max_odcr_attempts + 1):
        if _attempt > 1:
            logger.info(
                f"ODCR retry {_attempt}/{_max_odcr_attempts} for {instance_id}"
            )
        _cr_result = odcr_helper.create_capacity_reservation(
            probe_capacity_only=False,
            instance_type=_instance_info.get("InstanceType"),
            capacity_reservation_name=session.stack_name,
            desired_capacity=1,
            subnet_id=_instance_info.get("SubnetId"),
            instance_ami=_instance_info.get("ImageId"),
            tenancy=_instance_info.get("Placement", {}).get("Tenancy"),
        )

        if not (
            _cr_result.get("success") is True
            and getattr(_cr_result.message, "reservation_exist", False)
        ):
            break

        _new_cr_id = _cr_result.message.reservation_id
        logger.info(f"Fresh ODCR {_new_cr_id} reserved; retargeting {instance_id}")

        _retarget = odcr_helper.retarget_instance_to_capacity_reservation(
            instance_id=instance_id,
            capacity_reservation_id=_new_cr_id,
        )
        if _retarget.get("success") is True:
            return True

        _retarget_err = _retarget.get("message", "")
        logger.warning(
            f"Retarget failed for {instance_id} to {_new_cr_id} "
            f"(attempt {_attempt}/{_max_odcr_attempts}): {_retarget_err}"
        )

    # Fresh ODCR failed or retarget failed after retries — check ResumeODCRFallback flag
    _od_fallback_val = (
        SocaConfig(key="/configuration/FeatureFlags/VirtualDesktops/ResumeODCRFallback")
        .get_value(default="true", allow_unknown_key=True)
        .get("message", "true")
    )
    _od_fallback = SocaCastEngine(_od_fallback_val).cast_as(bool)
    _od_fallback_enabled = _od_fallback.message if _od_fallback.success else True

    if _od_fallback_enabled:
        logger.warning(
            f"No reserved capacity for {_instance_info.get('InstanceType')} "
            f"in {_instance_info.get('SubnetId')}; detaching CR and resuming "
            f"{instance_id} On-Demand"
        )
        try:
            client_ec2.modify_instance_capacity_reservation_attributes(
                InstanceId=instance_id,
                CapacityReservationSpecification={
                    "CapacityReservationPreference": "open"
                },
            )
            return True
        except Exception as err:
            logger.error(f"On-Demand fallback modify failed for {instance_id}: {err}")
            return False

    logger.error(
        f"No capacity for {_instance_info.get('InstanceType')} in "
        f"{_instance_info.get('SubnetId')} and On-Demand fallback is "
        f"disabled; skipping {instance_id}"
    )
    return False


def start_instances(
    sessions_info: list[VirtualDesktopSessions],
) -> None:
    """
    Start EC2 instances
    Important, start_instances and stop_instances can take up to 50 Instance IDs. Make sure session_info chunk size is max 50.
    """
    if not isinstance(sessions_info, list):
        logger.critical(
            f"Unable to start instances, sessions_info must be a list of VirtualDesktopSessions objects"
        )
        return

    logger.info(f"Starting instances: {sessions_info}")
    _successful_sessions = list(sessions_info)

    # Try to start all instances first. If the ODCR is still valid, this
    # succeeds immediately. Only on failure do we attempt ODCR remediation.
    try:
        client_ec2.start_instances(
            InstanceIds=[session.instance_id for session in _successful_sessions]
        )
    except Exception as err:
        logger.warning(
            f"Batch start failed: {err}. Trying instances one-by-one with ODCR handling."
        )
        # Start each instance individually; on capacity errors, attempt ODCR fix and retry.
        _failed_sessions = []
        for _session in list(_successful_sessions):
            _instance_id = _session.instance_id
            try:
                client_ec2.start_instances(InstanceIds=[_instance_id])
            except Exception as start_err:
                _err_msg = str(start_err).lower()
                _is_capacity_error = (
                    "does not have sufficient compatible and available capacity"
                    in _err_msg
                )
                if not _is_capacity_error:
                    logger.error(f"Unable to start {_instance_id}: {start_err}")
                    _failed_sessions.append(_session)
                    continue

                # Capacity error — attempt ODCR remediation
                logger.info(
                    f"Capacity error for {_instance_id}, attempting ODCR fix"
                )
                if not _handle_odcr_remediation(_session, _instance_id):
                    _failed_sessions.append(_session)
                    continue

                # Retry start after ODCR fix
                try:
                    client_ec2.start_instances(InstanceIds=[_instance_id])
                except Exception as retry_err:
                    logger.error(
                        f"Start failed for {_instance_id} even after ODCR fix: {retry_err}"
                    )
                    _failed_sessions.append(_session)

        for _s in _failed_sessions:
            _successful_sessions.remove(_s)

    # High-scale broker: clear stale session handles so session_state_watcher
    # re-registers resumed instances with the broker (same as start_virtual_desktop API).
    _is_high_scale_cast = SocaCastEngine(
        SocaConfig(key="/dcv/high_scale_enabled")
        .get_value(default="false", allow_unknown_key=True)
        .get("message", "false")
    ).cast_as(bool)
    _is_high_scale = (
        _is_high_scale_cast.message if _is_high_scale_cast.success else False
    )

    for _session in _successful_sessions:
        try:
            if _is_high_scale:
                _session.authentication_token = None
            _session.session_state = "pending"
            _session.session_state_latest_change_time = datetime.now(timezone.utc)
            db.session.commit()
            logger.info(f"Started {_session} successfully {_session.instance_id=}")
        except Exception as err:
            logger.error(
                f"{_session.instance_id} from {_session} was started successfully but unable to update DB entry due to {err}, updating it back to stopped"
            )
            try:
                client_ec2.stop_instances(InstanceIds=[_session.instance_id])
            except Exception as err:
                logger.error(
                    f"Unable to stop {_session} instance {_session.instance_id} due to {err}"
                )


def find_inactive_sessions(sessions_info: list[VirtualDesktopSessions]) -> None:
    """
    Identify Linux or Windows instances that should be stopped and execute an SSM command to check for any ongoing activity.
    """

    _windows_sessions_instance_ids = [
        session.instance_id
        for session in sessions_info
        if session.os_family == "windows"
    ]

    _linux_sessions_instance_ids = [
        session.instance_id for session in sessions_info if session.os_family == "linux"
    ]

    if (
        get_idle_time_windows := SocaCastEngine(
            data=config.Config.DCV_WINDOWS_STOP_IDLE_SESSION
        ).cast_as(int)
    ).get("success") is True:
        _stop_instance_after_idle_time_windows = get_idle_time_windows.get("message")
    else:
        logger.critical(
            "DCV_WINDOWS_STOP_IDLE_SESSION does not seems to be a valid integer"
        )
        return

    if (
        get_idle_time_linux := SocaCastEngine(
            data=config.Config.DCV_LINUX_STOP_IDLE_SESSION
        ).cast_as(int)
    ).get("success") is True:
        _stop_instance_after_idle_time_linux = get_idle_time_linux.get("message")
    else:
        logger.critical(
            "DCV_LINUX_STOP_IDLE_SESSION does not seems to be a valid integer"
        )
        return

    # Do not run checks unless all SSM commands succeeded
    _skip_linux = True
    _skip_windows = True

    # Validate Linux SSM
    if _linux_sessions_instance_ids:
        logger.info(
            f"Detected the following Linux VDI running on {_linux_sessions_instance_ids=}"
        )
        _linux_ssm_info = ssm_get_command_info(os_family="linux")
        if _linux_ssm_info.get("success") is False:
            logger.critical(
                f"Unable to retrieve SSM command info for linux due to {_linux_ssm_info.get('message')}"
            )
        else:
            try:
                _check_dcv_session_linux = client_ssm.send_command(
                    InstanceIds=_linux_sessions_instance_ids,
                    DocumentName=_linux_ssm_info.get("message").get(
                        "ssm_document_name"
                    ),
                    Parameters={
                        "commands": _linux_ssm_info.get("message").get("ssm_commands")
                    },
                    TimeoutSeconds=30,
                )
                _ssm_command_id_linux = _check_dcv_session_linux["Command"]["CommandId"]
                if (
                    ssm_get_list_command_status(command_id=_ssm_command_id_linux).get(
                        "success"
                    )
                    is False
                ):
                    logger.error(
                        f"Unable to determine status SSM responses for linux instances {_ssm_command_id_linux=}"
                    )
                else:
                    logger.info("Running SSM Command on Linux hosts succeeded")
                    _skip_linux = False
            except Exception as err:
                logger.error(
                    f"SSM send_command failed for Linux instances {_linux_sessions_instance_ids}: {err}"
                )
    else:
        logger.info("No Linux instances to check for schedule")
    # Validate Windows SSM
    if _windows_sessions_instance_ids:
        logger.info(
            f"Detected the following Windows VDI running on {_windows_sessions_instance_ids=}"
        )
        _windows_ssm_info = ssm_get_command_info(os_family="windows")
        if _windows_ssm_info.get("success") is False:
            logger.critical(
                f"Unable to retrieve SSM command info for Windows due to {_windows_ssm_info.get('message')}"
            )
        else:
            try:
                _check_dcv_session_windows = client_ssm.send_command(
                    InstanceIds=_windows_sessions_instance_ids,
                    DocumentName=_windows_ssm_info.get("message").get(
                        "ssm_document_name"
                    ),
                    Parameters={
                        "commands": _windows_ssm_info.get("message").get("ssm_commands")
                    },
                    TimeoutSeconds=30,
                )
                _ssm_command_id_windows = _check_dcv_session_windows["Command"][
                    "CommandId"
                ]
                if (
                    ssm_get_list_command_status(command_id=_ssm_command_id_windows).get(
                        "success"
                    )
                    is False
                ):
                    logger.error(
                        f"Unable to determine status SSM responses for windows instances {_ssm_command_id_windows=}"
                    )
                else:
                    logger.info("Running SSM Command on Windows hosts succeeded")
                    _skip_windows = False
            except Exception as err:
                logger.error(
                    f"SSM send_command failed for Windows instances {_windows_sessions_instance_ids}: {err}"
                )
    else:
        logger.info("No Windows instances to check for schedule")
    # Wait until the Commands have completed.
    # Succeed => All instances succeeded
    # Failed => At least 1 instance failed, but other may have succeeded
    # All others return code => SSM command was not executed for various reason (Quota, Rate Exceeded etc ..)
    if not _skip_linux:
        for _session in [
            session for session in sessions_info if session.os_family == "linux"
        ]:
            try:
                stop_instance_if_inactive(
                    ssm_command_id=_ssm_command_id_linux,
                    stop_instance_after_idle_time=_stop_instance_after_idle_time_linux,
                    session=_session,
                )
            except Exception as err:
                logger.error(
                    f"Error processing idle check for Linux session {_session.instance_id}: {err}"
                )

    # Check all Windows hosts individually
    if not _skip_windows:
        for _session in [
            session for session in sessions_info if session.os_family == "windows"
        ]:
            try:
                stop_instance_if_inactive(
                    ssm_command_id=_ssm_command_id_windows,
                    stop_instance_after_idle_time=_stop_instance_after_idle_time_windows,
                    session=_session,
                )
            except Exception as err:
                logger.error(
                    f"Error processing idle check for Windows session {_session.instance_id}: {err}"
                )


def stop_instance_if_inactive(
    ssm_command_id: str,
    stop_instance_after_idle_time: int,
    session: VirtualDesktopSessions,
) -> Union[SocaResponse, SocaError]:
    """
    Check if the instance is inactive and can be stopped, update the associated VirtualDesktopSessions if needed
    """

    _session_id = session.id
    _instance_id = session.instance_id
    _session_uuid = session.session_uuid
    _hibernate = session.support_hibernation

    #
    # TODO - try/except for boto3 call
    #
    _ssm_output = client_ssm.get_command_invocation(
        CommandId=ssm_command_id, InstanceId=_instance_id
    )
    _status = _ssm_output.get("Status", "")

    logger.info(
        f"Checking if {_instance_id=} is inactive and can be stopped for DCV Session {_session_id=} ({_status=}): {_ssm_output}"
    )

    #
    # The resources we are concerned with monitoring on the instance
    #
    # TODO - there should probably be a difference for fallback_value and something like unknown_value?
    #
    _resource_usage_thresholds: dict = {
        "dcv_connections": {
            "enabled": True,
            "element": "DCVCurrentConnections",
            "min": 1,
            "fallback_value": 1,
            "cast_as": int,
        },
        "rdp_connections": {
            # Windows-only: an active RDP console session (independent of DCV)
            # is evidence of user activity and must block the idle-stop, same
            # as an active DCV connection. Not applicable to Linux hosts.
            "enabled": session.os_family == "windows",
            "element": "RDPActiveConnections",
            "min": 1,
            "fallback_value": 1,
            "cast_as": int,
        },
        "cpu_usage": {
            "enabled": True,
            "element": "CPUAveragePerformanceLast10Secs",
            "min": config.Config.DCV_IDLE_CPU_THRESHOLD,
            "fallback_value": 100.0,
            "cast_as": float,
        },
        "gpu_usage": {
            "enabled": True,
            "element": "GPUUsageLevel",
            "min": 10.0,
            "fallback_value": 100.0,
            "cast_as": float,
        },
        "memory_usage": {
            "enabled": False,
            "element": "MemoryUsage",
            "min": 1.0,
            "fallback_value": 1.0,
            "cast_as": float,
        },
    }

    # Where we put our resource values that we find
    _resource_values: dict = {}
    #
    # _resource_idle_results tells us if the resource is "Idle" - that is - under the min for the resource.
    # This is used to determine if the instance can be paused.
    _resource_idle_results: dict = {}

    if _status not in {"Success"}:
        logger.error(
            f"SSM command {ssm_command_id} on {_instance_id=} failed with error: {_ssm_output.get('StandardErrorContent', '')}"
        )
        return

    logger.info(
        f"SSM output for {_instance_id} succeeded, checking current resource usage"
    )
    _raw_resp = SocaCastEngine(
        _ssm_output.get("StandardOutputContent", "") or "{}"
    ).as_json()
    if _raw_resp.success is not True:
        logger.error(
            f"Unable to parse DCV info JSON for {_instance_id=}: {_ssm_output}"
        )
        return
    _raw = _raw_resp.message

    if not _raw:
        logger.error(f"Unable to read DCV info for {_instance_id=}: {_ssm_output}")
        return

    # Match THIS VDI row to its DCV session on the host. `dcv list-sessions`
    # returns every session on the node; the session's `name` is the EDH
    # session_uuid in BOTH legacy and high-scale modes (high-scale `id` is the
    # broker-assigned id). Matching by name is mode-agnostic and
    # multi-session-safe; we also accept an id match (session_uuid for legacy,
    # authentication_token for the high-scale broker id) as a fallback.
    _raw_sessions = _raw.get("DCVSessions")
    if Validators.is_dict(_raw_sessions):
        # Normalize to a list across shapes: Windows PowerShell ConvertTo-Json
        # serializes a collection as {"value": [...], "Count": N}; some DCV
        # builds use {"sessions": [...]}; a lone session may arrive as a single
        # object. Linux jq already yields a bare array (handled below).
        if Validators.is_list(_raw_sessions.get("value")):
            _host_sessions = _raw_sessions["value"]
        elif Validators.is_list(_raw_sessions.get("sessions")):
            _host_sessions = _raw_sessions["sessions"]
        else:
            _host_sessions = [_raw_sessions]
    elif Validators.is_list(_raw_sessions):
        _host_sessions = _raw_sessions
    else:
        _host_sessions = []

    def _as_str(_v):
        # Safe string coercion via the cast engine (handles None/unexpected
        # types without the str(None) -> "None" false-match footgun).
        _c = SocaCastEngine(_v).cast_as(str)
        return _c.message if _c.success else None

    _uuid_str = _as_str(_session_uuid)
    _candidate_ids = {
        _as_str(_x)
        for _x in (_session_uuid, session.authentication_token)
        if _x and _as_str(_x) is not None
    }
    _dcv_session = next(
        (
            s
            for s in _host_sessions
            if (_uuid_str is not None and _as_str(s.get("name")) == _uuid_str)
            or _as_str(s.get("id")) in _candidate_ids
        ),
        None,
    )
    if _dcv_session is None:
        logger.info(
            f"No DCV session on {_instance_id=} matching desktop {_session_uuid=} "
            f"(host sessions: {[s.get('name') for s in _host_sessions]}); skipping idle check this cycle"
        )
        return

    # Normalize to the keys the threshold logic below expects. Host-level
    # CPU/GPU come from the wrapper (shared across sessions on the host).
    _dcv_info = {
        "DCVCurrentConnections": _dcv_session.get("num-of-connections"),
        "DCVCreationTime": _dcv_session.get("creation-time"),
        "DCVLastDisconnectTime": _dcv_session.get("last-disconnection-time"),
        "CPUAveragePerformanceLast10Secs": _raw.get("CPUAveragePerformanceLast10Secs"),
        "GPUUsageLevel": _raw.get("GPUUsageLevel"),
        # Host-level (not per-DCV-session) count of Active RDP consoles. Only
        # present in the Windows SSM payload; absent on Linux, where the
        # rdp_connections threshold is disabled above.
        "RDPActiveConnections": _raw.get("RDPActiveConnections"),
    }

    # last-disconnection-time is "" if never disconnected -> fall back to
    # creation-time. Guard against missing/None so we never parse(None).
    _last_disconnect_raw = _dcv_info.get("DCVLastDisconnectTime") or _dcv_info.get(
        "DCVCreationTime"
    )
    if not _last_disconnect_raw:
        logger.info(
            f"No DCV creation/disconnect time for {_instance_id=} {_session_uuid=}; skipping idle check this cycle"
        )
        return
    last_dcv_disconnect = parse(_last_disconnect_raw)

    #
    # Scan our resources
    #
    for _resource_name, _resource_config in _resource_usage_thresholds.items():
        logger.info(f"Considering {_resource_name=} for thresholds")

        _resource_key_name: str = _resource_config.get("element", "")
        _resource_cast_as = _resource_config.get("cast_as")

        if not _resource_config.get("enabled", False) or not _resource_key_name:
            logger.info(
                f"Skipping {_resource_name=} for thresholds - disabled or no element name available"
            )
            continue

        # If there is no fallback - fallback to 100 for safety

        _raw_resource_value = _dcv_info.get(
            _resource_key_name, _resource_config.get("fallback_value", 100)
        )

        # Run it via the Casting Engine to make sure it is what we expect
        if (
            _resource_value_caster := SocaCastEngine(data=_raw_resource_value).cast_as(
                _resource_cast_as
            )
        ).get("success"):
            _resource_value = _resource_value_caster.get(
                "message", _resource_config.get("fallback_value")
            )
        else:
            logger.error(
                f"Unable to determine {_resource_name=} for thresholds - Casting failure"
            )
            return

        logger.info(
            f"Found resource {_resource_name=} at {_resource_key_name=} with a value of {_resource_value=}"
        )

        _resource_values[_resource_name] = _resource_value
        #
        # TODO - Should the min be sent via Caster as well?
        #
        _resource_min_value = _resource_config.get(
            "min", _resource_config.get("fallback_value", 100)
        )

        #
        # If the resource_value is below our min_value - the resource is Idle. Else it is Not-Idle.
        #
        if _resource_value < _resource_min_value:
            logger.info(
                f"Resource {_resource_name=} is {_resource_value=} - threshold is {_resource_min_value=} - Setting resource to Idle"
            )
            _resource_idle_results[_resource_name] = True
        else:
            logger.info(
                f"Resource {_resource_name=} is {_resource_value=} - threshold is {_resource_min_value=} - Setting resource to Non-Idle"
            )
            _resource_idle_results[_resource_name] = False

    # We should now have _resource_values populated with the information
    logger.debug(f"Resources for session: {_resource_values=}")

    #
    # Logic for Idle can now take place.
    # If all resources are Idle=False, then this is an easy-button
    #
    if True not in _resource_idle_results.values():
        logger.debug(f"Resources for session: {_resource_values=}")
        logger.info("All resources are active - skipping")
        return

    # How many resources?
    # NOTE - do not compare to _resource_usage_thresholds - as it has enabled/disabled settings
    # must compare to our _enabled_ and _collected_ resources
    _resource_count: int = len(_resource_idle_results)

    # How many True-ly idle resources?
    # Python allows us to do this since True=1 and False=0.
    # So we just need to sum() up the dict values() for a count of our True
    _idle_resources: int = sum(_resource_idle_results.values())

    logger.info(f"Resources for session: {_resource_values=}")
    logger.info(f"At least one resource is idle: {_resource_idle_results=}")

    if _idle_resources != _resource_count:
        logger.info(f"Resources for session: {_resource_values=}")
        logger.info(
            f"At least one resource is non-idle - skipping: {_resource_idle_results=}"
        )
        return

    # If we are here - then our idle resources matches our resource count
    logger.info(f"Session has all idle resources - {_idle_resources=}")

    current_time = parse(datetime.now(timezone.utc).replace(microsecond=0).isoformat())

    if (
        last_dcv_disconnect + timedelta(hours=stop_instance_after_idle_time)
    ) > current_time:
        logger.info(
            f"{_instance_id=} NOT ready to be stopped/hibernated, last access time {last_dcv_disconnect}, stop after idle time (hours): {stop_instance_after_idle_time}, current time is {current_time} Desktop UUID {_session_uuid}"
        )
        return

    # All checks pass - idle and able to be stopped
    logger.info(
        f"{_instance_id} is ready to be stopped/hibernated {_hibernate=}, last access time {last_dcv_disconnect}, stop after idle time (hours): {stop_instance_after_idle_time}, current time is {current_time}"
    )
    try:
        #
        # TODO - check return value?
        #
        client_ec2.stop_instances(
            InstanceIds=[_instance_id],
            Hibernate=_hibernate,
        )
    except Exception as err:
        logger.critical(
            f"Unable to stop/hibernate instance {_instance_id=} due to {err} {_hibernate=}. Desktop UUID {_session_uuid}"
        )

    try:
        session.session_state = "stopping"
        session.session_state_latest_change_time = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"{session} stopping")

    except Exception as err:
        logger.error(
            f"Unable to update DB entry for {_instance_id=} due to {err}. Desktop UUID {_session_uuid}"
        )
        # TODO - why was this here? Restart in case of DB commit failure?
        # try:
        #     client_ec2.start_instances(
        #         InstanceIds=[session.instance_id]
        #     )
        # except Exception as err:
        #     logger.error(
        #         f"Unable to start {session} instance {session.instance_id} due to {err}"
        #     )


def _safe_get_day_schedule(session, day):
    """Parse session schedule JSON and return the day's dict, or None on error."""
    try:
        return json.loads(session.schedule).get(day, {})
    except Exception:
        logger.warning(
            f"Unable to parse schedule for session {session.instance_id}: {session.schedule!r}"
        )
        return None


def process_chunk(vdi_sessions: list[VirtualDesktopSessions]):
    logger.info(f"Processing chunk: {vdi_sessions}")
    # Grace Period
    # - Will not stop a desktop if it was started within the grace period
    # - Will not start a desktop if it was stopped within the grace period
    # In other words, even if your schedule is stopped all day, but you manually start your desktop, it will stays up and running for 1 hour)
    _grace_period = config.Config.DCV_SCHEDULE_GRACE_PERIOD_IN_HOURS

    try:
        _tz = pytz.timezone(config.Config.TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        logger.error(
            f"Timezone {config.Config.TIMEZONE} configured by the admin does not exist. Defaulting to UTC. Refer to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for a full list of supported timezones"
        )
        _tz = pytz.timezone("UTC")

    _now = datetime.now(_tz)
    _day = _now.strftime("%A").lower()
    _now_in_minutes = _now.hour * 60 + _now.minute

    # Filter the sessions where _now is greater than or equal to session_state_latest_change_time + grace period
    _sessions_outside_of_grace_period = []
    for session in vdi_sessions:
        try:
            if _now >= _tz.localize(
                session.session_state_latest_change_time
            ) + timedelta(hours=_grace_period):
                _sessions_outside_of_grace_period.append(session)
            else:
                logger.info(
                    f"Session {session.instance_id} (state={session.session_state}) is within grace period "
                    f"(last change: {session.session_state_latest_change_time}, grace expires: "
                    f"{_tz.localize(session.session_state_latest_change_time) + timedelta(hours=_grace_period)})"
                )
        except Exception as err:
            logger.error(
                f"Error evaluating grace period for session {session.instance_id}: {err}"
            )

    logger.info(
        f"List of VDI outside of Grace Period: {_sessions_outside_of_grace_period}"
    )
    if _sessions_outside_of_grace_period:
        logger.info(f"Today is {_day=}, {_now_in_minutes=}, {_now=}")

        # Starting instance is instant, so we begin with them
        logger.info(
            f"Checking sessions supposed to be started all-day but not running, starting them (if any)."
        )
        _sessions_running_all_day = []
        for session in _sessions_outside_of_grace_period:
            _sched_day = _safe_get_day_schedule(session, _day)
            if _sched_day is None:
                continue
            try:
                if (
                    _sched_day.get("stop") == 1440
                    and _sched_day.get("start") == 1440
                    and session.session_state != "running"
                ):
                    _sessions_running_all_day.append(session)
            except Exception as err:
                logger.error(
                    f"Error evaluating all-day start for session {session.instance_id}: {err}"
                )
        if _sessions_running_all_day:
            logger.info(f"List of Sessions: {_sessions_running_all_day=}")
            start_instances(sessions_info=_sessions_running_all_day)
        else:
            logger.info("No Sessions found")

        logger.info(
            f"Checking sessions supposed to be running at this time but state is not running, starting them (if any)."
        )
        # Only restart a stopped session if it was stopped BEFORE the current
        # schedule window opened (i.e., it was off overnight and the schedule
        # says "on" now). If it was stopped DURING the current window, it was
        # idle-stopped and should stay stopped until the user manually starts
        # it or the next schedule boundary.
        _sessions_schedule_start = []
        for session in _sessions_outside_of_grace_period:
            try:
                _sched = _safe_get_day_schedule(session, _day)
                if _sched is None:
                    continue
                _sched_start = _sched.get("start", 0)
                _sched_stop = _sched.get("stop", 0)
                if not (_sched_start < _now_in_minutes < _sched_stop):
                    continue
                if session.session_state == "running":
                    continue
                _sessions_schedule_start.append(session)
            except Exception as err:
                logger.error(
                    f"Error evaluating schedule start for session {session.instance_id}: {err}"
                )

        if _sessions_schedule_start:
            logger.info(f"List of Sessions: {_sessions_schedule_start=}")
            start_instances(sessions_info=_sessions_schedule_start)
        else:
            logger.info("No Sessions found")

        # Stopping session take a little longer as we need to compute the current CPU percentage on each machine, so we move them at the end
        logger.info(
            f"Checking sessions supposed to be stopped all-day but currently running, stopping them if inactive (if any)"
        )
        _sessions_stopped_all_day = []
        for session in _sessions_outside_of_grace_period:
            _sched_day = _safe_get_day_schedule(session, _day)
            if _sched_day is None:
                continue
            if (
                _sched_day.get("stop") == 0
                and _sched_day.get("start") == 0
                and session.session_state == "running"
            ):
                _sessions_stopped_all_day.append(session)
        if _sessions_stopped_all_day:
            logger.info(f"List of Sessions: {_sessions_stopped_all_day=}")
            find_inactive_sessions(sessions_info=_sessions_stopped_all_day)
        else:
            logger.info("No Sessions found")

        logger.info(
            f"Checking sessions supposed to be stopped at this time but state is running, stopping them if inactive (if any)"
        )
        _sessions_schedule_stop = []
        for session in _sessions_outside_of_grace_period:
            _sched_day = _safe_get_day_schedule(session, _day)
            if _sched_day is None:
                continue
            if session.session_state == "running" and (
                _now_in_minutes < _sched_day.get("start", 0)
                or _now_in_minutes > _sched_day.get("stop", 0)
            ):
                _sessions_schedule_stop.append(session)
        if _sessions_schedule_stop:
            logger.info(f"List of Sessions: {_sessions_schedule_stop=}")
            find_inactive_sessions(sessions_info=_sessions_schedule_stop)
        else:
            logger.info("No Sessions found")

        # Idle-stop for sessions that are currently within their scheduled
        # running window. The schedule says "on", but if the user has been
        # disconnected longer than DCV_*_STOP_IDLE_SESSION hours, stop them
        # to save cost. A value of 0 in config disables this behaviour.
        logger.info("Checking in-schedule running sessions for idle activity")
        try:
            _idle_linux_val = int(config.Config.DCV_LINUX_STOP_IDLE_SESSION)
        except (ValueError, TypeError):
            _idle_linux_val = 0
        try:
            _idle_windows_val = int(config.Config.DCV_WINDOWS_STOP_IDLE_SESSION)
        except (ValueError, TypeError):
            _idle_windows_val = 0

        _sessions_in_schedule_running = []
        for session in _sessions_outside_of_grace_period:
            if session.session_state != "running":
                continue
            if not (
                (session.os_family == "linux" and _idle_linux_val > 0)
                or (session.os_family == "windows" and _idle_windows_val > 0)
            ):
                continue
            _sched_day = _safe_get_day_schedule(session, _day)
            if _sched_day is None:
                continue
            if (_sched_day.get("start") == 1440 and _sched_day.get("stop") == 1440) or (
                _sched_day.get("start", 0) < _now_in_minutes < _sched_day.get("stop", 0)
            ):
                _sessions_in_schedule_running.append(session)
        if _sessions_in_schedule_running:
            logger.info(
                f"Found {len(_sessions_in_schedule_running)} in-schedule running sessions to check for idle: {_sessions_in_schedule_running}"
            )
            find_inactive_sessions(sessions_info=_sessions_in_schedule_running)
        else:
            logger.info(
                "No in-schedule running sessions to idle-stop (feature disabled or none matched)"
            )
    else:
        logger.info(
            "No VDI info subject to Schedule Update as they are all within grace time"
        )


def chunked_iterable(iterable: VirtualDesktopSessions, chunk_size: int):
    """Utility function to create chunks of the iterable using islice."""
    # Iterate over the iterable and yield chunks of the specified size
    iterator = iter(iterable)
    for first in iterator:
        yield [first] + list(islice(iterator, chunk_size - 1))


def virtual_desktops_schedule_management(app: Flask):
    with app.app_context():
        logger.info("Scheduled Task: virtual_desktops_schedule_management")

        _start_time = time.time()

        # Get all current active VDI
        _all_dcv_sessions = VirtualDesktopSessions.query.filter(
            VirtualDesktopSessions.is_active.is_(True),
            VirtualDesktopSessions.is_spot.isnot(True),
        ).all()
        if _all_dcv_sessions:
            # Start by creating chunk of 50 VDI sessions maximum (this is the max number of InstanceIds we can pass to some boto3 API call)
            # Keep this limit below 50.
            _chunk_size = 50

            _chunks_of_sessions = chunked_iterable(_all_dcv_sessions, _chunk_size)

            for _chunk in _chunks_of_sessions:
                try:
                    process_chunk(_chunk)
                except Exception as err:
                    logger.error(
                        f"Error processing chunk {[s.instance_id for s in _chunk]}: {err}"
                    )

        else:
            logger.info("No active virtual desktops found")

        _end_time = time.time()
        logger.info(
            f"Scheduled task completed in {_end_time - _start_time:.2f} seconds for {len(_all_dcv_sessions)} sessions"
        )


def auto_terminate_stopped_instance(app: Flask):
    with app.app_context():
        logger.info("Scheduled Task: auto_terminate_stopped_instance")
        try:
            _terminate_stopped_windows_instance_after = int(
                config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION
            )
            _terminate_stopped_linux_instance_after = int(
                config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION
            )
        except ValueError as err:
            return SocaError.GENERIC_ERROR(
                helper=f"_terminate_stopped_instance_after does not seems to be a valid integer Script will not proceed to auto-termination. Error: {err}, DCV_WINDOWS_TERMINATE_STOPPED_SESSION={config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION}, DCV_LINUX_TERMINATE_STOPPED_SESSION={config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION} ."
            )

        _all_stopped_dcv_sessions = []
        if _terminate_stopped_windows_instance_after > 0:
            logger.info(
                f"Windows instance will be terminated after {_terminate_stopped_windows_instance_after} hours"
            )
            _all_stopped_windows_dcv_sessions = VirtualDesktopSessions.query.filter(
                VirtualDesktopSessions.is_active == True,
                VirtualDesktopSessions.session_state == "stopped",
                VirtualDesktopSessions.os_family == "windows",
            ).all()
            _all_stopped_dcv_sessions.extend(_all_stopped_windows_dcv_sessions)

        if _terminate_stopped_linux_instance_after > 0:
            logger.info(
                f"Linux instance will be terminated after {_terminate_stopped_windows_instance_after} hours"
            )
            _all_stopped_linux_dcv_sessions = VirtualDesktopSessions.query.filter(
                VirtualDesktopSessions.is_active == True,
                VirtualDesktopSessions.session_state == "stopped",
                VirtualDesktopSessions.os_family == "linux",
            ).all()
            _all_stopped_dcv_sessions.extend(_all_stopped_linux_dcv_sessions)

        if _all_stopped_dcv_sessions:
            for session_info in _all_stopped_dcv_sessions:
                try:
                    logger.info(
                        f"Checking stopped session {session_info.session_name} owned by {session_info.session_owner}"
                    )

                    _stack_name = session_info.stack_name
                    _os_family = session_info.os_family
                    _session_state_latest_change_time = (
                        session_info.session_state_latest_change_time
                    )

                    if _os_family == "windows":
                        _terminate_stopped_instance_after = (
                            _terminate_stopped_windows_instance_after
                        )
                    else:
                        _terminate_stopped_instance_after = (
                            _terminate_stopped_linux_instance_after
                        )

                    if _terminate_stopped_instance_after == 0:
                        logger.info(
                            "_terminate_stopped_instance_after is disabled, skipping"
                        )
                        continue

                    if (
                        _session_state_latest_change_time
                        + timedelta(hours=_terminate_stopped_instance_after)
                    ) < datetime.now(timezone.utc):
                        logger.info(
                            f"Desktop {session_info.session_uuid} is ready to be terminated, last access time {_session_state_latest_change_time}, stop after idle time (hours): {_terminate_stopped_instance_after}"
                        )

                        _delete_stack = SocaCfnClient(
                            stack_name=_stack_name
                        ).delete_stack()
                        if _delete_stack.get("success") is False:
                            logger.error(f"Unable to terminate instance {_stack_name}")
                            continue

                        session_info.is_active = False
                        session_info.deactivated_on = datetime.now(timezone.utc)
                        session_info.deactivated_by = "auto_terminate_stopped_instance"
                        session_info.session_state_latest_change_time = datetime.now(
                            timezone.utc
                        )
                        db.session.commit()
                        logger.info(f"Terminated {_stack_name} successfully")

                except Exception as err:
                    logger.error(
                        f"Error processing auto-terminate for session {session_info.session_uuid}: {err}"
                    )
        else:
            logger.info(
                f"No stopped sessions found or feature is disabled (0). {config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION=} {config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION=}"
            )
