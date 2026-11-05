# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import config
from dateutil.parser import parse
from extensions import db
from models import TargetNodeSessions
from utils.error import SocaError
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ec2_helper import ec2_quota_headroom
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


logger = logging.getLogger("scheduled_tasks_target_nodes_schedule_management")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message


def new_quota_budget() -> dict:
    """
    A per-PASS quota budget, threaded through every start decision in one run of
    target_nodes_schedule_management().

    This exists because plan_starts_within_quota() alone is not enough. It reads
    headroom and decrements locally, but a scheduler pass calls start_instances()
    several times: process_chunk() calls it once for the all-day sessions and again
    for the scheduled-start sessions, and the pass iterates 50-session chunks. If
    each call re-read headroom and threw its decrement away, every call would be
    admitted against the same allowance and the batch could over-admit by a multiple
    of the quota -- the exact failure the planner exists to prevent, moved up one
    level from the session boundary to the call boundary.

    Re-reading would not save it either. An instance started earlier in the same
    pass takes time to appear in describe_instances, so a fresh read mid-pass can
    still report the pre-start usage. The measurement taken once at the start of the
    pass, minus what this pass has admitted since, is the only figure that stays
    correct for the whole pass.

    Two maps:
      headroom  quota_name    -> vcpus still available in this pass
      per_type  instance_type -> (quota_name, vcpus_per_instance), or None to skip
    """
    return {"headroom": {}, "per_type": {}}


def plan_starts_within_quota(
    sessions_info: list[TargetNodeSessions],
    quota_budget: dict = None,
) -> tuple[list[TargetNodeSessions], list[TargetNodeSessions]]:
    """
    Split a start batch into (admitted, deferred) on remaining vCPU headroom.

    A STOPPED instance does not consume the running-vCPU quota, so starting one
    consumes quota again. This task starts up to 50 in a single call, on a schedule,
    with nobody watching -- so an exhausted quota otherwise shows up as instances
    that silently fail to come up.

    Two things make a naive check wrong here:

      - Calling validate_ec2_quota_for_instance() per session re-measures account
        usage every time (a describe_instances paginate plus a reservation list),
        paying that cost 50 times to learn one number.
      - Worse, every one of those calls sees the SAME usage, because nothing has
        started yet. All 50 are admitted when only 10 fit. That is worse than no
        check, because it looks like one.

    So headroom is read ONCE per distinct instance type and then decremented locally
    as instances are admitted. Sessions that do not fit are deferred, not failed:
    they stay stopped and the next scheduler pass reconsiders them, by which time
    capacity may have been freed.

    Pass `quota_budget` from new_quota_budget() to carry that accounting across
    every start decision in one scheduler pass; see new_quota_budget() for why a
    per-call budget is not sufficient. Omitting it scopes the budget to this call
    alone, which is correct only when the call is the whole pass.

    Ordering is preserved, so the batch fills deterministically rather than by
    whichever session happens to be cheapest.
    """
    if not sessions_info:
        return [], []

    if quota_budget is None:
        quota_budget = new_quota_budget()

    _admitted, _deferred = [], []
    _headroom = quota_budget["headroom"]  # quota_name -> vcpus still available
    _per_type = quota_budget["per_type"]  # instance_type -> resolved, or None to skip

    for _session in sessions_info:
        _instance_type = getattr(_session, "instance_type", None)
        if not _instance_type:
            # Nothing to check against; let the start proceed as it did before.
            logger.warning(
                f"{_session} has no instance_type recorded, starting without a quota check"
            )
            _admitted.append(_session)
            continue

        if _instance_type not in _per_type:
            _quota = ec2_quota_headroom(instance_type=_instance_type)
            if _quota.get("success") is False:
                # Could not read the quota. Do NOT hold the fleet down over it: this
                # runs unattended, and a schedule that stops starting nodes because
                # an API call failed is a worse outcome than a start that fails.
                logger.warning(
                    f"Unable to read quota headroom for {_instance_type} "
                    f"({_quota.get('message')}), starting without a quota check"
                )
                _per_type[_instance_type] = None
            elif (_quota.get("message") or {}).get("skipped"):
                logger.info(
                    f"Quota check skipped for {_instance_type}: "
                    f"{(_quota.get('message') or {}).get('skipped')}"
                )
                _per_type[_instance_type] = None
            else:
                _info = _quota.get("message")
                _per_type[_instance_type] = (
                    _info["quota_name"],
                    _info["vcpus_per_instance"],
                )
                # First type to reach this quota seeds its headroom. A second type
                # sharing the same quota must NOT reseed it, or the two would each
                # spend the full allowance.
                _headroom.setdefault(_info["quota_name"], _info["available"])
                logger.info(
                    f"Quota {_info['quota_name']}: {_info['in_use']} of "
                    f"{_info['limit']} vcpus in use, {_info['available']} available"
                )

        _resolved = _per_type[_instance_type]
        if _resolved is None:
            _admitted.append(_session)
            continue

        _quota_name, _vcpus = _resolved
        if _headroom.get(_quota_name, 0) >= _vcpus:
            _headroom[_quota_name] -= _vcpus
            _admitted.append(_session)
        else:
            _deferred.append(_session)
            # Debug, not warning: a large batch against a full quota would otherwise
            # emit one warning per instance on every scheduler pass. The summary
            # below is the operator-facing line.
            logger.debug(
                f"Deferring start of {_session.instance_id} ({_instance_type}, "
                f"{_vcpus} vcpus): only {_headroom.get(_quota_name, 0)} vcpus left "
                f"against {_quota_name}"
            )

    if _deferred:
        _by_type = {}
        for _session in _deferred:
            _by_type[getattr(_session, "instance_type", "unknown")] = (
                _by_type.get(getattr(_session, "instance_type", "unknown"), 0) + 1
            )
        logger.warning(
            f"Quota deferred {len(_deferred)} of {len(sessions_info)} scheduled "
            f"starts ({_by_type}). They stay stopped and are reconsidered next pass. "
            f"Raise the relevant quota or reduce scheduled capacity."
        )

    return _admitted, _deferred


def start_instances(
    sessions_info: list[TargetNodeSessions],
    quota_budget: dict = None,
) -> None:
    """
    Start EC2 instances
    Important, start_instances and stop_instances can take up to 50 Instance IDs. Make sure session_info chunk size is max 50.
    """
    if not isinstance(sessions_info, list):
        logger.critical(
            f"Unable to start instances, sessions_info must be a list of TargetNodeSessions objects"
        )
        return

    # Quota gate for the batch. See plan_starts_within_quota() for why this cannot
    # be a per-instance call to validate_ec2_quota_for_instance().
    sessions_info, _deferred_by_quota = plan_starts_within_quota(
        sessions_info, quota_budget=quota_budget
    )
    if not sessions_info:
        logger.warning(
            f"Every scheduled start in this chunk was deferred by the quota check "
            f"({len(_deferred_by_quota)} sessions), nothing to start"
        )
        return

    logger.info(f"Starting instances: {sessions_info}")
    _successful_sessions = sessions_info
    try:
        client_ec2.start_instances(
            InstanceIds=[session.instance_id for session in sessions_info]
        )

    except Exception as err:
        logger.warning(
            f"Unable to start instance from this chunk {sessions_info} due to {err}, trying to proceed one by one"
        )
        for _session in sessions_info:
            try:
                client_ec2.start_instances(InstanceIds=[_session.instance_id])
            except Exception as err:
                logger.error(
                    f"Unable to start instance {_session.instance_id} due to {err}"
                )
                _successful_sessions.remove(_session)

    for _session in _successful_sessions:
        try:
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


def stop_instances(
    sessions_info: TargetNodeSessions,
) -> Union[SocaResponse, SocaError]:
    """
    Check if the instance is inactive and can be stopped, update the associated TargetNodeSessions if needed
    """
    for session in sessions_info:
        _session_id = session.id
        _instance_id = session.instance_id
        _session_uuid = session.session_uuid

        logger.info(f"Stopping {_instance_id=} target node {_session_id=}")

        try:
            client_ec2.stop_instances(
                InstanceIds=[_instance_id],
            )
        except Exception as err:
            logger.critical(
                f"Unable to stop instance {_instance_id=} due to {err} . Desktop UUID {_session_uuid}"
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
            try:
                client_ec2.start_instances(InstanceIds=[session.instance_id])
            except Exception as err:
                logger.error(
                    f"Unable to start {session} instance {session.instance_id} due to {err}"
                )


def process_chunk(
    target_nodes_sessions: list[TargetNodeSessions], quota_budget: dict = None
):
    logger.info(f"Processing chunk: {target_nodes_sessions}")
    # Grace Period
    # - Will not stop a desktop if it was started within the grace period
    # - Will not start a desktop if it was stopped within  the grace period
    # In other word, even if your schedule is stopped all day, but you manually start your desktop, it will stays up and running for 1 hour)
    _grace_period = config.Config.TARGET_NODE_GRACE_PERIOD_IN_HOURS

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
    _sessions_outside_of_grace_period = [
        session
        for session in target_nodes_sessions
        if _now
        >= _tz.localize(session.session_state_latest_change_time)
        + timedelta(hours=_grace_period)
    ]

    logger.info(
        f"List of target node outside of Grace Period: {_sessions_outside_of_grace_period}"
    )
    if _sessions_outside_of_grace_period:
        logger.info(f"Today is {_day=}, {_now_in_minutes=}, {_now=}")

        # Starting instance is instant, so we begin with them
        logger.info(
            f"Checking sessions supposed to be started all-day but not running, starting them (if any)."
        )
        _sessions_running_all_day = [
            session
            for session in _sessions_outside_of_grace_period
            if json.loads(session.schedule).get(_day).get("stop") == 1440
            and json.loads(session.schedule).get(_day).get("start") == 1440
            and session.session_state != "running"
        ]
        if _sessions_running_all_day:
            logger.info(f"List of Sessions: {_sessions_running_all_day=}")
            start_instances(
                sessions_info=_sessions_running_all_day, quota_budget=quota_budget
            )
        else:
            logger.info("No Sessions found")

        logger.info(
            f"Checking sessions supposed to be running at this time but state is not running, starting them (if any)."
        )
        _sessions_schedule_start = [
            session
            for session in _sessions_outside_of_grace_period
            if json.loads(session.schedule).get(_day).get("start")
            < _now_in_minutes
            < json.loads(session.schedule).get(_day).get("stop")
            and session.session_state != "running"
        ]

        if _sessions_schedule_start:
            logger.info(f"List of Sessions: {_sessions_schedule_start=}")
            start_instances(
                sessions_info=_sessions_schedule_start, quota_budget=quota_budget
            )
        else:
            logger.info("No Sessions found")

        # Stopping session take a little longer as we need to compute the current CPU percentage on each machine, so we move them at the end
        logger.info(
            f"Checking sessions supposed to be stopped all-day but currently running, stopping them if inactive (if any)"
        )
        _sessions_stopped_all_day = [
            session
            for session in _sessions_outside_of_grace_period
            if json.loads(session.schedule).get(_day).get("stop") == 0
            and json.loads(session.schedule).get(_day).get("start") == 0
            and session.session_state == "running"
        ]
        if _sessions_stopped_all_day:
            logger.info(f"List of Sessions: {_sessions_stopped_all_day=}")
            stop_instances(sessions_info=_sessions_stopped_all_day)
        else:
            logger.info("No Sessions found")

        logger.info(
            f"Checking sessions supposed to be stopped at this time but state is running, stopping them if inactive (if any)"
        )

        _sessions_schedule_stop = [
            session
            for session in _sessions_outside_of_grace_period
            if (
                _now_in_minutes < json.loads(session.schedule).get(_day).get("start")
                or _now_in_minutes > json.loads(session.schedule).get(_day).get("stop")
            )
            and session.session_state == "running"
        ]
        if _sessions_schedule_stop:
            logger.info(f"List of Sessions: {_sessions_schedule_stop=}")
            stop_instances(sessions_info=_sessions_schedule_stop)
        else:
            logger.info("No Sessions found")
    else:
        logger.info(
            "No target node info subject to Schedule Update as they are all within grace time"
        )


def chunked_iterable(iterable: TargetNodeSessions, chunk_size: int):
    """Utility function to create chunks of the iterable using islice."""
    # Iterate over the iterable and yield chunks of the specified size
    iterator = iter(iterable)
    for first in iterator:
        yield [first] + list(islice(iterator, chunk_size - 1))


def target_nodes_schedule_management(app: Flask):
    with app.app_context():
        logger.info("Scheduled Task: target_nodes_schedule_management")

        _start_time = time.time()

        # Get all current active target node
        _all_dcv_sessions = TargetNodeSessions.query.filter(
            TargetNodeSessions.is_active.is_(True)
        ).all()
        if _all_dcv_sessions:
            # Start by creating chunk of 50 target node sessions maximum (this is the max number of InstanceIds we can pass to some boto3 API call)
            # Keep this limit below 50.
            _chunk_size = 50

            _chunks_of_sessions = chunked_iterable(_all_dcv_sessions, _chunk_size)

            # ONE budget for the whole pass. Every chunk, and both start calls
            # within a chunk, draw from and decrement the same headroom -- see
            # new_quota_budget(). A budget per chunk would let each chunk spend
            # the full quota over again.
            _quota_budget = new_quota_budget()

            for _chunk in _chunks_of_sessions:
                process_chunk(_chunk, quota_budget=_quota_budget)

        else:
            logger.info("No active target nodes  found")

        _end_time = time.time()
        logger.info(
            f"Scheduled task completed in {_end_time - _start_time:.2f} seconds for {len(_all_dcv_sessions)} sessions"
        )
