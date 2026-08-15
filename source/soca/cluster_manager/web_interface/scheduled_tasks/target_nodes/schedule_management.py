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


def start_instances(
    sessions_info: list[TargetNodeSessions],
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


def process_chunk(target_nodes_sessions: list[TargetNodeSessions]):
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
            start_instances(sessions_info=_sessions_running_all_day)
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
            start_instances(sessions_info=_sessions_schedule_start)
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

            for _chunk in _chunks_of_sessions:
                process_chunk(_chunk)

        else:
            logger.info("No active target nodes  found")

        _end_time = time.time()
        logger.info(
            f"Scheduled task completed in {_end_time - _start_time:.2f} seconds for {len(_all_dcv_sessions)} sessions"
        )
