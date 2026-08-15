# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from extensions import db
from models import TargetNodeSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.aws.cloudformation_client import SocaCfnClient
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse
from botocore.exceptions import ClientError
import config
from cryptography.fernet import Fernet
import json
from sqlalchemy.orm import Session
import base64
from typing import Iterator, List, Literal, Iterable, TypeVar
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from itertools import islice
import time
from flask import Flask


logger = logging.getLogger("scheduled_tasks_target_nodes_session_state_watcher")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


def chunked_iterable(iterable: Iterable[TypeVar], chunk_size: int) -> Iterator[List]:
    iterator = iter(iterable)
    for first in iterator:
        yield [first] + list(islice(iterator, chunk_size - 1))


def process_chunk(
    sessions: list[TargetNodeSessions],
    instance_ids_by_state: dict,
) -> SocaResponse:
    _db_scoped_session = db.session
    """
    This function is responsible to retrieve all active target nodes and ensure the status displayed on the Web Interface match the state of the process running on the EC2 machine
    """

    _ec2_state_to_soca_mapping = {
        "pending": "pending",
        "running": "running",
        "shutting-down": "stopped",
        "terminated": "stopped",
        "stopping": "stopped",
        "stopped": "stopped",
    }
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

        logger.info("Finding Target sessions with no registered EC2 Instance on DB ...")
        _sessions_with_no_ec2_instance = [
            session
            for session in sessions
            if session.instance_private_dns is None
            or session.instance_private_ip is None
            or session.instance_id is None
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
            logger.info("All Target Nodes sessions have active EC2 instance on DB")

        logger.info(
            "Finding Target Nodes sessions with invalid or terminated Instance ID. Deleting associated CloudFormation stack if needed ..."
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
            "Finding Target Nodes Sessions with EC2 Instance stopping but DB state not yet stopping"
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
            update_target_node_state(
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
            "Finding Target Nodes Sessions with stopped EC2 Instance but DB state is not stopped"
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
            update_target_node_state(
                sessions=_sync_stopped_sessions,
                new_state="stopped",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to stopped")

        # Retrieve all non-running target node session with a running Instance ID.
        logger.info(
            "Finding non-running  target node Sessions but associated EC2 instance is running, change the state to running"
        )

        _sync_running_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state[session.instance_id].lower() == "running"
            and session.session_state.lower() != "running"
        ]

        if _sync_running_sessions:
            logger.info(
                f"Found running EC2 instances but session_state are not running {_sync_running_sessions}"
            )
            update_target_node_state(
                sessions=_sync_running_sessions,
                new_state="running",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No target node sessions to be changed to running")

        # Update pending sessions
        logger.info(
            "Finding target node Session with running EC2 instance type but stopped state. updating them to pending"
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
            update_target_node_state(
                sessions=_sync_pending_sessions,
                new_state="pending",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to pending")

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(f"Process Chunk error due to {err} at line {exc_tb.tb_lineno}")

    # Close current thread
    return SocaResponse(success=True, message="Chunk processed")


def update_ec2_info(
    sessions: TargetNodeSessions, cluster_id: str, db_scoped_session: Session
) -> None:
    """
    Find details for  target node  session with no active EC2 Instance registered on the database (e.g:  target node  that just launched).
    If EC2 capacity is provisioned, retrieve private IP/DNS, generate authentication token and update DB
    If EC2 capacity is not yet provisioned, we verify if the CloudFormation stack associated to the  target node  session is in progress.
    """

    for _session in sessions:
        try:
            _session_uuid = _session.session_uuid
            _owner = _session.session_owner
            logger.info(
                f"Checking get_ec2_host_info for target nodes Session {_session.id} with tag:edh:TargetNodeSessionUUID: {_session_uuid}, tag:edh:ClusterId {cluster_id}, tag:edh:JobOwner {_owner}"
            )
            _host_info = {}

            _find_instance = client_ec2.describe_instances(
                Filters=[
                    {
                        "Name": "tag:edh:TargetNodeSessionUUID",
                        "Values": [_session.session_uuid],
                    },
                    {"Name": "tag:edh:ClusterId", "Values": [cluster_id]},
                    {"Name": "tag:edh:NodeType", "Values": ["target_node"]},
                    {"Name": "tag:edh:JobOwner", "Values": [_owner]},
                ],
            )

            if not _find_instance["Reservations"]:
                logger.warning(
                    f"No instance found for tag:edh:TargetNodeSessionUUID: {_session_uuid}, checking if the associated CloudFormation stack is healthy"
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
                                f"EC2 instance found for {_session.id=} {_session.session_uuid=}"
                            )

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
                                        f"Error trying to run the following commits on update_target_node_state because of: {e}"
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
    all_sessions: TargetNodeSessions,
) -> SocaResponse:
    """
    Returns a dictionary of instance ID -> Instance State. Returns None if Instance ID does not exist anymore
    """
    try:
        logger.info(
            f"Finding instance state name for each instance ID for list of  target node  {all_sessions}"
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
                response = client_ec2.describe_instance_status(
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
                            individual_response = client_ec2.describe_instance_status(
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


def delete_inactive_instances(
    sessions: TargetNodeSessions,
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
            try:
                check_stack = client_cfn.describe_stacks(StackName=_stack_name)
                _stack_status = check_stack["Stacks"][0]["StackStatus"]
            except Exception as err:
                _stack_status = "STACK_UNKNOWN"  # handle case where CFN has been removed via AWS Console/APIs
                logger.error(
                    f"Error Retrieving {_stack_name=} due to {err}, deleting record from database"
                )

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
            try:
                logger.info("Updating is_active flag to False")
                _session.is_active = False
                _session.deactivated_on = datetime.now(timezone.utc)
                _session.deactivated_by = "SCHEDULED_TASK"
                _session.session_state_latest_change_time = datetime.now(timezone.utc)
                try:
                    db_scoped_session.commit()
                    logger.info(
                        f"Session {_session.id} {_session.session_uuid=} has been deactivated successfully on the database"
                    )
                except Exception as e:
                    db_scoped_session.rollback()
                    logger.critical(
                        f"Error trying to run the following commits on update_target_node_state because of: {e}"
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


def update_target_node_state(
    sessions: TargetNodeSessions, new_state: str, db_scoped_session: Session
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
                        f"Error trying to run the following commits on update_target_node_state because of: {e}"
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
def target_nodes_session_state_watcher(app: Flask):
    with app.app_context():
        logger.info("Scheduled Task: target_nodes_session_state_watcher")

        _start_time = time.time()

        # Get all current active  target node
        _all_target_nodes_sessions = TargetNodeSessions.query.filter(
            TargetNodeSessions.is_active.is_(True)
        ).all()
        if _all_target_nodes_sessions:

            # First, we get the latest status for all the instances IDs registered.
            # We create batch requests of up to 100 instance ids.
            _instance_ids_by_state = find_instance_ids_instance_state(
                all_sessions=_all_target_nodes_sessions
            )

            logger.debug(f"Instance ID by State: {_instance_ids_by_state}")

            if _instance_ids_by_state.get("success") is False:
                logger.critical(
                    f"Unable to retrieve instance state for all instances due to {_instance_ids_by_state.get('message')}"
                )

            # Start by creating chunk of 50  target node  sessions maximum (this is the max number of InstanceIds we can pass to some boto3 API call)
            # Keep this limit below 50.
            _chunk_size = 50

            # Create chunk of 50 sessions max
            _chunks_of_sessions = chunked_iterable(
                _all_target_nodes_sessions, _chunk_size
            )

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
                f"Scheduled task completed in {_end_time - _start_time:.2f} seconds for {len(_all_target_nodes_sessions)} sessions"
            )

        else:
            logger.info("No active target node found")
