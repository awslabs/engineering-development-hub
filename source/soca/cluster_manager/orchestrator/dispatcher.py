# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import socket
import os
import pathlib
import re
import shlex
import stat
import sys
import yaml
from yaml.nodes import MappingNode
from yaml.loader import SafeLoader
import logging

from typing import Union, Any, Dict, List

from utils.error import SocaError
from utils.logger import SocaLogger
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.subprocess_client import SocaSubprocessClient

from utils.aws.ec2_helper import validate_instance_ri_coverage

from utils.datamodels.hpc.queue import SocaHpcQueue
from utils.datamodels.hpc.shared.job_resources import (
    SocaHpcJobState,
    SocaHpcJobProvisioningState,
)
from utils.datamodels.hpc.shared.job import SocaHpcJob
from utils.datamodels.hpc.scheduler import get_schedulers

from utils.hpc.job_fetcher import SocaHpcJobFetcher
from utils.hpc.job_controller import SocaHpcJobController
from utils.hpc.license_check import SocaLicenseQuery


def get_logger(log_file_rotation: str, logger_name: str = "soca_logger"):

    # use soca_logger otherwise you may loose other utils logging
    logger = logging.getLogger(logger_name)

    # Remove existing handlers (prevents duplicates as we create logger per job)
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create one logger
    return SocaLogger(name="soca_logger").timed_rotating_file_handler(
        file_path=log_file_rotation
    )


def get_lock(process_name: str) -> Union[bool, str]:
    """
    Attempts to acquire a lock using a UNIX socket.

    This function ensures that only one instance of a process with the given name
    can run at a time by binding to an abstract namespace socket.
    """
    get_lock._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.getpid()
    try:
        get_lock._lock_socket.bind(f"\0{process_name}")
        return True
    except (OSError, socket.error) as e:
        sys.exit(
            f"Lock for {process_name} already exists. Exiting PID {pid}. Error: {str(e).replace('\n', ' ').replace('\r', ' ')}"
        )
    except Exception as err:
        sys.exit(f"Unknown error trying to get socket: {err}")


class LicenseMappingSafeLoader(SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._key_path: List[str] = []


def no_duplicates_and_validate_daemons(
    loader: LicenseMappingSafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> Dict[Any, Any]:
    mapping: Dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)

        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key ({key})",
                key_node.start_mark,
            )

        # 🔍 Validate keys under `daemons`
        if loader._key_path == ["daemons"]:
            if not isinstance(key, str) or not re.compile(r"^.+_lic_.+$").match(key):
                raise yaml.constructor.ConstructorError(
                    "while constructing 'daemons'",
                    node.start_mark,
                    f"invalid daemon key '{key}' "
                    "(must match '<something>_lic_<something>')",
                    key_node.start_mark,
                )

        loader._key_path.append(key)
        value = loader.construct_object(value_node, deep=deep)
        loader._key_path.pop()

        mapping[key] = value

    return mapping


LicenseMappingSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    no_duplicates_and_validate_daemons,
)


def load_queue_configuration(queue_config_file: str, queue_type: str) -> SocaHpcQueue:
    """
    Load and validate queue configuration from YAML file.
    Returns a SocaQueue object if successful, otherwise exits the program.
    """
    logger_dispatcher.debug(
        f"Getting Queue Information from {queue_config_file=} for {queue_type=}"
    )
    try:
        with open(queue_config_file, "r") as stream_resource_mapping:
            docs = yaml.safe_load_all(stream_resource_mapping)
            for doc in docs:
                for items in doc.values():
                    for _type, info in items.items():
                        if _type == queue_type:
                            queue_cfg = SocaHpcQueue.model_construct()
                            for key, value in info.items():
                                if hasattr(queue_cfg, key):
                                    logger_dispatcher.debug(
                                        f"Queue Value found {key=} with {value=}"
                                    )
                                    setattr(queue_cfg, key, value)

                            if (is_config_valid := queue_cfg.validate_queue()).get(
                                "success"
                            ) is False:
                                sys.exit(
                                    f"{queue_cfg} has config errors: {is_config_valid.get('message')}"
                                )
                            return queue_cfg
    except Exception as err:
        sys.exit(
            f"Unable to read queue settings file ({queue_config_file}) with error: {err}"
        )

    sys.exit(f"Unable to find queues information for queue type {queue_type}")


def load_license_mapping(license_mapping_file: str) -> dict:
    try:
        with open(license_mapping_file, "r") as f:
            return yaml.load(f, Loader=LicenseMappingSafeLoader)
    except Exception as err:
        sys.exit(
            f"Unable to read license file ({license_mapping_file}) with error: {err}"
        )


def query_license_script(
    script_command: str, minus: int = 0, timeout: int = 30
) -> SocaResponse:
    """
    provider: "script". Run a customer command (absolute script path followed by
    its arguments, no shell) whose stdout is a single integer: the number of
    licenses currently AVAILABLE. A non-zero exit code or any other output is an
    error, so the job stays queued rather than being dispatched on a guess.
    """
    logger.info(f"Checking Script-based licenses, executing {script_command=}")
    try:
        _command_parts = shlex.split(script_command)
    except ValueError as _err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to parse script_command {script_command!r}: {_err}"
        )
    if not _command_parts:
        return SocaError.GENERIC_ERROR(helper="script_command is empty")
    _script_path = pathlib.Path(_command_parts[0])

    # Runs on every dispatcher cycle with the dispatcher's privileges, so
    # refuse anything another user could swap the contents of.
    if not _script_path.is_absolute():
        return SocaError.GENERIC_ERROR(
            helper=f"script_command must start with an absolute path, received {_script_path}"
        )
    if not _script_path.is_file():
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to find license script, {_script_path} does not seem to exist or is not a file"
        )
    if not os.access(_script_path, os.X_OK):
        return SocaError.GENERIC_ERROR(
            helper=f"{_script_path} is not executable. Run chmod +x {_script_path}"
        )
    _stat = _script_path.stat()
    if _stat.st_uid not in (0, os.geteuid()):
        return SocaError.GENERIC_ERROR(
            helper=f"{_script_path} must be owned by root or by the user running the dispatcher"
        )
    if _stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return SocaError.GENERIC_ERROR(
            helper=f"{_script_path} must not be group or world writable. Run chmod go-w {_script_path}"
        )

    _script_output = SocaSubprocessClient(run_command=script_command).run(
        timeout=timeout
    )
    logger.debug("License script output: %s", _script_output)
    if _script_output.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run license script {_script_path}: {_script_output.get('message')}"
        )

    _output = _script_output.get("message").get("stdout", "").strip()
    logger.debug("Received license script output: %s", _output)
    _licenses_available = SocaCastEngine(data=_output).cast_as(int)
    if _licenses_available.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"License script {_script_path} must print a single integer, received {_output!r}"
        )
    _licenses_available = _licenses_available.get("message")
    if _licenses_available < 0:
        return SocaError.GENERIC_ERROR(
            helper=f"License script {_script_path} returned a negative count ({_licenses_available})"
        )

    return SocaResponse(success=True, message=_licenses_available - (minus or 0))


def verify_job_licenses_requirements(
    job_info: SocaHpcJob,
    license_mapping: dict,
    override_license_count_for_pending_jobs: dict,
    concurrent_subjobs: int = 1,
) -> SocaResponse:

    _license_error = False
    if job_info.licenses:
        logger.info(
            f"Found license requirement {job_info.licenses} for this job {job_info.job_id}, checking availability ..."
        )
        for _license in job_info.licenses:
            if _license_error:
                break

            _lmutil_path = license_mapping.get("settings", {}).get(
                "flexlm_lmutil_path", None
            )
            _license_daemons = license_mapping.get("daemons", {})
            if _license.name in _license_daemons.keys():
                _requested_license_name = _license.name
                # The scheduler reports an array parent's license request per
                # SUBJOB, like nodes and cpus, so the raw count is what one subjob
                # takes. concurrent_subjobs is 1 for an ordinary job.
                _license_count = SocaCastEngine(data=_license.count).cast_as(int)
                if _license_count.success is False:
                    logger.error(
                        f"Unable to read the license count {_license.count!r} for "
                        f"{_license.name} on {job_info.job_id}"
                    )
                    _license_error = True
                    break
                _requested_license_count = (
                    _license_count.get("message") * concurrent_subjobs
                )
                _license_server = _license_daemons[_license.name].get("server", None)
                _license_port = _license_daemons[_license.name].get("port", None)
                _license_feature = _license_daemons[_license.name].get("feature", None)
                _license_minus = _license_daemons[_license.name].get(
                    "minus", 0
                )  # default to 0 if not set
                _license_provider = _license_daemons[_license.name].get(
                    "provider", None
                )
                logger.info(
                    f"{_requested_license_name=} {_requested_license_count=} {_license_server=} {_license_port=} {_license_feature=} {_license_minus=} {_license_provider=}"
                )
                if _license_provider == "flexlm":
                    logger.info(f"Checking FlexLM licenses for {_license.name}")
                    if _lmutil_path is None:
                        logger.error(
                            f"Requested FlexLM checks for {_license.name} but flexlm_lmutil_path is not set in the license mapping file"
                        )
                        _license_error = True
                        break
                    else:
                        _license_query = SocaLicenseQuery(
                            server=_license_server,
                            port=_license_port,
                            feature=_license_feature,
                            minus=_license_minus,
                        ).flexlm(lmutil_path=_lmutil_path)
                elif _license_provider == "script":
                    _script_command = _license_daemons[_license.name].get(
                        "script_command", None
                    )
                    logger.info(
                        f"Checking Script-based licenses for {_license.name}, executing {_script_command=}"
                    )

                    if not _script_command:
                        logger.error(
                            f"Requested script checks for {_license.name} but script_command is not set in the license mapping file"
                        )
                        _license_error = True
                        break
                    _script_timeout = SocaCastEngine(
                        data=_license_daemons[_license.name].get("timeout", 30)
                    ).cast_as(int)
                    if _script_timeout.success is False:
                        logger.error(
                            f"Invalid timeout for {_license.name} in the license mapping file, must be an integer (seconds)"
                        )
                        _license_error = True
                        break
                    _license_query = query_license_script(
                        script_command=str(_script_command),
                        minus=_license_minus,
                        timeout=_script_timeout.get("message"),
                    )
                    logger.info(
                        f"Script-based license check for {_license.name} completed successfully"
                    )
                    logger.debug(f"Script-based license check output: {_license_query}")
                else:
                    _provider_hint = ""
                    if _license_provider is None:
                        _provider_hint = " The provider key is missing."
                    elif str(_license_provider).startswith("/"):
                        # Common mistake: script path set as the provider
                        _provider_hint = (
                            f' It looks like a path: set provider: "script" and '
                            f'script_command: "{_license_provider}" instead.'
                        )
                    logger.error(
                        f"Invalid license provider {_license_provider!r} for "
                        f"{_license.name} in the license mapping file. "
                        f'Supported values: "flexlm", "script".{_provider_hint} '
                        f"Job {job_info.job_id} stays queued until this is fixed."
                    )
                    _license_error = True
                    break

                if _license_query.get("success") is True:
                    _license_available = _license_query.get("message")
                    logger.info(
                        f"Successfully querying license server: {_license_available=} for {_license_feature}"
                    )
                    if (
                        _requested_license_name
                        in override_license_count_for_pending_jobs.keys()
                    ):
                        _license_available = (
                            _license_available
                            - override_license_count_for_pending_jobs[
                                _requested_license_name
                            ]
                        )
                        logger.info(
                            f"{_requested_license_name} already in override_license_count_for_pending_jobs, {override_license_count_for_pending_jobs[_requested_license_name]}"
                        )

                    logger.info(f"{_license_available=} for {_requested_license_name=}")
                    # _license_minus is NOT subtracted again here: SocaLicenseQuery
                    # returns (issued - minus) - in_use.
                    if _license_available >= _requested_license_count:
                        logger.info(
                            f"License Ask OK for {_requested_license_name}. Requested {_requested_license_count}, available {_license_available}"
                        )
                        # Accumulate what this cycle has RESERVED, not
                        # available-plus-requested.
                        override_license_count_for_pending_jobs[
                            _requested_license_name
                        ] = (
                            override_license_count_for_pending_jobs.get(
                                _requested_license_name, 0
                            )
                            + _requested_license_count
                        )
                    else:
                        logger.error(
                            f"Requested {_requested_license_count}*{_requested_license_name} but only {_license_available} are available"
                        )
                        _license_error = True
                        break
                else:
                    logger.error(
                        f"Unable to query {_license_provider} for {_requested_license_name} due to {_license_query.get('message')}"
                    )
                    _license_error = True
                    break
            else:
                logger.warning(
                    f"Requested {_license} but this key has not been found on {license_mapping}"
                )
                _license_error = True
                break

        if _license_error:
            return SocaError.GENERIC_ERROR(
                helper="Unable to validate License Requirements for this job. See logs for more details.",
            )
        else:
            return SocaResponse(
                success=True, message=override_license_count_for_pending_jobs
            )
    else:
        logger.info("No license needed, continuing with capacity provisioning")
        return SocaResponse(
            success=True, message=override_license_count_for_pending_jobs
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", nargs="?", required=True, help="Path to a configuration file"
    )
    parser.add_argument(
        "-t",
        "--type",
        nargs="?",
        required=True,
        help="queue type - ex: compute .. Open YML file for more info",
    )
    arg = parser.parse_args()
    queue_config_file = arg.config
    queue_type = arg.type
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message

    # Try to get a lock; if another dispatcher for the same queue is running, this instance will exit
    get_lock(process_name=f"{__file__} {queue_type}")

    # Create dispatcher logger, note a custom <queue_log> will be created for each queue
    # use soca_logger otherwise you may loose other utils logging
    logger_dispatcher = logging.getLogger("soca_logger")
    if logger_dispatcher.hasHandlers():
        logger_dispatcher.handlers.clear()

    logger_dispatcher = SocaLogger(name="soca_logger").timed_rotating_file_handler(
        file_path=f"/opt/edh/{_cluster_id}/cluster_manager/orchestrator/logs/dispatcher.log"
    )

    # Retrieve Default parameters for the queues
    _queues_configuration = load_queue_configuration(
        queue_config_file=queue_config_file, queue_type=queue_type
    )

    # Retrieve License mapping
    _license_mapping = load_license_mapping(
        license_mapping_file=f"/opt/edh/{_cluster_id}/cluster_manager/orchestrator/settings/licenses_mapping.yml"
    )

    # Track Future EC2 quota usage across multiple jobs.
    # Example: If we plan to launch 2 c6i.24xlarge instances, the first one (96 vCPUs) may not be running yet,
    # but we still need to count its vCPUs when scheduling the second job. This ensures we don’t exceed
    # account quotas by ignoring pending (yet-to-be-provisioned) capacity.
    _override_vcpus_quotas_for_pending_instances = {}

    # Track FUTURE EC2 RI usage across multiple jobs.
    # Example: If we plan to launch 2 c6i.24xlarge instances the first one may not be running yet,
    # but we still need to count its capacity (2 nodes) when scheduling the second job. This ensures we don’t exceed
    # account RI by ignoring pending (yet-to-be-provisioned) capacity.
    _override_pending_instances_count = 0

    # Track Future License Usage across multiple jobs.
    # Example: If we plan to launch 2 jobs that will need mylic1=5, the first one may not be running yet,
    # but we still need to count the 5 licenses to be used when scheduling the second job. This ensures we don’t exceed
    # licenses count by ignoring pending (yet-to-be-provisioned) capacity.
    _override_license_count_for_pending_jobs = {}

    # SOCA will automatically try to re-create the CloudFormation stack associated to the job if the
    # CloudFormation stack is `CREATE_COMPLETE` but job has not started within the grace period configured
    if (
        _check_grace_period := SocaConfig(
            key="/system/orchestration/stack_grace_period_in_minutes"
        ).get_value(return_as=int)
    ).get("success"):
        _stack_grace_period_in_minutes = _check_grace_period.get("message")
    else:
        logger_dispatcher.error(
            f"{_check_grace_period} is not a valid integer, default to 45"
        )
        _stack_grace_period_in_minutes = 45

    # Retrieve all configured/enabled schedulers
    _schedulers_to_query = get_schedulers()
    for _scheduler in _schedulers_to_query:
        if _scheduler.soca_managed_nodes_provisioning is False:
            logger_dispatcher.info(
                f"Skipping scheduler {_scheduler.identifier} as soca_managed_nodes_provisioning is set to False"
            )
            continue

        logger_dispatcher.info(f"Fetching jobs for {_scheduler.identifier}")

        # Process all queues
        for queue in _queues_configuration.queues:

            logger = get_logger(
                log_file_rotation=f"/opt/edh/{_cluster_id}/cluster_manager/orchestrator/logs/{_scheduler.identifier}/queues/{queue}.log"
            )
            logger.info(f"Retrieving jobs for {queue=}")
            logger.debug(f"Scheduler Configuration: {_scheduler}")
            logger.debug(f"Queues Configuration: {_queues_configuration}")

            if (
                get_jobs_response := SocaHpcJobFetcher(
                    scheduler_info=_scheduler
                ).by_queue(queue=queue)
            ).get("success"):
                get_jobs = get_jobs_response.get("message")
                if not get_jobs:
                    logger.info(f"No jobs found for {queue=}")
                    continue
                else:
                    # This gets really noisy in a busy environment
                    logger.debug(f"Retrieved jobs: {get_jobs=}")
            else:
                logger.error(
                    f"Unable to retrieve jobs for {queue=} due to {str(get_jobs_response.get('message', '')).replace('\n', ' ').replace('\r', ' ')}"
                )
                continue

            # Checking if we don't already have hit the queue limit in term of running jobs
            _current_running_jobs = sum(
                1
                for job in get_jobs
                if job.job_provisioning_state
                in [
                    SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_IN_PROGRESS,
                    SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_COMPLETE,
                    SocaHpcJobProvisioningState.RUNNING,
                ]
            )
            logger.info(
                f"Detected {_current_running_jobs=} running jobs in {queue=}, max_running_job is {_queues_configuration.max_running_jobs=}"
            )
            if (
                _queues_configuration.max_running_jobs is not None
                and _current_running_jobs >= _queues_configuration.max_running_jobs
            ):
                logger.info(
                    f"Maximum number of running jobs reached for {queue=}, skipping queue ..."
                )
                continue

            # Checking if we don't already have hit the queue limit for concurrent provisioned nodes
            _current_provisioned_instances = sum(
                job.nodes
                for job in get_jobs
                if job.job_provisioning_state
                in [
                    SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_IN_PROGRESS,
                    SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_COMPLETE,
                    SocaHpcJobProvisioningState.RUNNING,
                ]
            )
            logger.info(
                f"Detected {_current_provisioned_instances=} provisioned nodes in {queue=}, max_provisioned_instances is {_queues_configuration.max_provisioned_instances=}"
            )
            if (
                _queues_configuration.max_provisioned_instances is not None
                and _current_provisioned_instances
                >= _queues_configuration.max_provisioned_instances
            ):
                logger.info(
                    f"Maximum number of instances reached for {queue=}, skipping queue ..."
                )
                continue

            # Process all queued jobs in this queue
            for job in get_jobs:
                logger = get_logger(
                    log_file_rotation=f"/opt/edh/{_cluster_id}/cluster_manager/orchestrator/logs/{_scheduler.identifier}/jobs/{job.job_id}.log"
                )

                if (
                    job.job_provisioning_state
                    == SocaHpcJobProvisioningState.MAX_RETRY_ATTEMPTS_REACHED
                ):
                    logger.warning(
                        f"{job.job_id=} has reached max retry attempts ({job.job_failed_provisioning_retry_count}), skipping it"
                    )

                else:

                    if job.job_state == SocaHpcJobState.QUEUED:

                        logger.info(f"Processing queued {job.job_id=}")
                        logger.debug(f"{job.job_id=} Info: {job}")

                        # Check if job has unset resources
                        # If yes, we try to inherit them from the default value specified for the queue
                        logger.info(
                            f"Checking if {job.job_id=} has unset fields and replace them with default queue values if available"
                        )
                        if job.job_compute_node in ["tbd", "-1"]:
                            # only apply resource if the compute_node is not defined, otherwise it means the default_queue_values have already been applied
                            # tbd = OpenPBS/PBSPro
                            # -1 = LSF (as you cannot use String for RES_REQ)
                            job.apply_default_queue_values(
                                queue_configuration=_queues_configuration,
                                scheduler_info=job.job_scheduler_info,
                            )

                        if (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.PENDING
                        ):

                            logger.info(
                                f"{job.job_id=} is currently queued and no CloudFormation Stack is set, trying to provision compute for this job"
                            )

                            logger.info(
                                f"Checking if {job.job_id=} has license requirements {job.licenses=}"
                            )
                            _check_license = verify_job_licenses_requirements(
                                job_info=job,
                                license_mapping=_license_mapping,
                                override_license_count_for_pending_jobs=_override_license_count_for_pending_jobs,
                                # Same concurrency figure capacity sizing uses, so
                                # licenses and nodes are reserved for the same
                                # number of simultaneous subjobs.
                                concurrent_subjobs=job.array_concurrency(
                                    max_running_subjobs=_queues_configuration.max_running_subjobs
                                ).get("message"),
                            )
                            if _check_license.get("success") is False:
                                SocaHpcJobController(job=job).set_error_message(
                                    errors=[_check_license.get("message")]
                                )
                                logger.error(
                                    f"License ask for job {job.job_id=} has been rejected"
                                )
                                continue
                            else:
                                logger.info(
                                    f"License ask for job {job.job_id=} has been validated successfully"
                                )
                                _override_license_count_for_pending_jobs = (
                                    _check_license.get("message")
                                )

                            logger.info(
                                f"Validating all resources associated to {job.job_id=}"
                            )
                            _is_job_config_valid = job.validate()
                            if _is_job_config_valid.get("success") is False:
                                # note: error_message is automatically updated via is_valid(), no need to call SocaHpcJobController here
                                logger.error(
                                    f"Unable to validate job {job.job_id=}: {_is_job_config_valid.get('message')}"
                                )
                                continue
                            else:
                                logger.info(f"Validated Job Data: {job=}")

                            logger.info(
                                f"Queued Job {job.job_id=} has valid config, trying to see if we can provision compute for it. Provisioning state is {job.job_provisioning_state}"
                            )

                            # validate() will verify the setup and change the job provisioning state to  COMPUTE_PROVISIONING_BLOCKED if job error is detected
                            if (
                                job.job_provisioning_state
                                == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_BLOCKED
                            ):
                                logger.error(
                                    f"{job.job_id=} is currently in {job.job_provisioning_state=} due to {job.error_message=}."
                                )
                                continue
                            else:
                                # An array parent reports nodes/cpus per subjob.
                                # Runs after validate(), which checks nodes
                                # against cpus per subjob. Gated on is_array
                                # rather than the subjob count, so an array the
                                # parser could not size is refused below instead
                                # of provisioning one subjob's worth.
                                if job.is_array:
                                    _array_plan = job.array_capacity_plan(
                                        max_running_subjobs=_queues_configuration.max_running_subjobs,
                                        node_vcpus=job.node_vcpus,
                                        node_mem_mib=job.node_mem_mib,
                                    )
                                    if _array_plan.get("success") is False:
                                        logger.error(
                                            f"Refusing job array {job.job_id=}: {_array_plan.get('message')}"
                                        )
                                        SocaHpcJobController(job=job).set_error_message(
                                            errors=[_array_plan.get("message")]
                                        )
                                        continue

                                    _plan = _array_plan.get("message")
                                    logger.info(
                                        f"Job array {job.job_id=} sizing: "
                                        f"{_plan.get('subjobs')} subjobs, "
                                        f"concurrency {_plan.get('concurrent_subjobs')}"
                                        f"{' (capped by max_running_subjobs)' if _plan.get('capped') else ''}, "
                                        f"{_plan.get('subjobs_per_node')} per node "
                                        f"({_plan.get('density_basis')}-bound) "
                                        f"-> provisioning {_plan.get('nodes_to_provision')} node(s)"
                                    )
                                    job.nodes = _plan.get("nodes_to_provision")

                                # Verify job provisioning won't hit the maximum number of concurrent running jobs allowed for the queue
                                if (
                                    _queues_configuration.max_running_jobs is not None
                                    and _current_running_jobs + 1
                                    > _queues_configuration.max_running_jobs
                                ):
                                    logger.info(
                                        f"{job.job_id} will provision {job.nodes} additional nodes. This will hit the maximum number of concurrent running jobs for this {queue=} which is {_queues_configuration.max_running_jobs=}, job won't be provisioned until other jobs finish"
                                    )
                                    break  # exit the loop entirely as no other jobs on this queue can be provisioned at this time
                                else:
                                    _current_running_jobs += 1

                                # Verify job provisioning won't hit the maximum number of concurrent provisioned instances allowed for the queue
                                if (
                                    _queues_configuration.max_provisioned_instances
                                    is not None
                                    and _current_provisioned_instances + job.nodes
                                    > _queues_configuration.max_provisioned_instances
                                ):
                                    logger.info(
                                        f"{job.job_id} will provision {job.nodes} additional nodes. This will hit the aximum number of instances reached for this {queue=} which is {_queues_configuration.max_provisioned_instances=}, job won't be provisioned until other jobs finish"
                                    )
                                    continue
                                else:
                                    _current_provisioned_instances += job.nodes

                                if job.force_ri:
                                    _ri_validated = True
                                    for _instance_type in job.instance_types:
                                        logger.info(
                                            f"force_ri detected, validating current Reserved Instance coverage for {_instance_type}"
                                        )
                                        if (
                                            validate_instance_ri_coverage(
                                                instance_type=_instance_type,
                                                desired_capacity=job.nodes,
                                                override_pending_instances_count=_override_pending_instances_count,
                                            ).get("success")
                                            is False
                                        ):
                                            logger.error(
                                                f"Unable to get RI for {_instance_type}"
                                            )
                                            _ri_validated = False
                                            break
                                        else:
                                            _override_pending_instances_count += (
                                                job.nodes
                                            )

                                    if not _ri_validated:
                                        SocaHpcJobController(job=job).set_error_message(
                                            errors=[
                                                "Unable to validate ReservedInstances"
                                            ]
                                        )
                                        continue

                                    logger.info(
                                        f"Reserved Instance coverage validated for {job.job_id=}"
                                    )

                                logger.info(
                                    "All check passed, provisioning capacity via CloudFormation"
                                )

                                _capacity_provisioning = job.provision_capacity(
                                    cluster_id=_cluster_id,
                                    stack_name=f"{_cluster_id}-job-{job.job_id}-{_scheduler.identifier}",
                                    keep_forever=False,
                                    terminate_when_idle=0,
                                    override_vcpus_quotas_for_pending_instances=_override_vcpus_quotas_for_pending_instances,
                                )
                                if _capacity_provisioning.get("success") is False:
                                    logger.error(
                                        f"Unable to provision capacity for {job.job_id=} due to {_capacity_provisioning.get('message')}"
                                    )
                                    continue
                                else:

                                    _provisioning_result_message = (
                                        _capacity_provisioning.get("message")
                                    )
                                    # Automatically increment vcpus that will be provisioned for quota check
                                    _override_vcpus_quotas_for_pending_instances = _provisioning_result_message.get(
                                        "override_vcpus_quotas_for_pending_instances"
                                    )
                                    logger.info(
                                        f"Successfully provisioned capacity for {job.job_id=} via CloudFormation Stack {_provisioning_result_message.get('stack_name')}"
                                    )

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_COMPLETE
                        ):
                            logger.info(
                                f"{job.job_id=} is currently queued, has a valid CloudFormation and SocaHpcJobProvisioningState is COMPUTE_PROVISIONING_COMPLETE, checking grace period, if the job has been submitted more than {_stack_grace_period_in_minutes} minutes ago"
                            )

                            _refresh_stack = SocaHpcJobController(
                                job=job
                            ).reset_cloudformation_stack_creation()

                            if _refresh_stack.get("success") is True:
                                # stack cannot be rebuild simply because it's still in the grace period, ignoring
                                if _refresh_stack.get("status_code") == 201:
                                    logger.info(
                                        f"{job.job_id=} associated capacity stack has been created less than {_stack_grace_period_in_minutes} minutes ago, skipping for now ..."
                                    )
                                else:
                                    logger.info(
                                        f"Stack for {job.job_id=} needs to be refreshed and retry_attempt counter incremented successfully"
                                    )
                            else:
                                logger.error(
                                    f"Unable to refresh stack for {job.job_id=} due to {_refresh_stack.get('message')}"
                                )
                                SocaHpcJobController(job=job).set_error_message(
                                    errors=[_refresh_stack.get("message")],
                                )
                                continue

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_ERROR
                        ):
                            logger.info(
                                f"{job.job_id=} is currently queued and SocaHpcJobProvisioningState is in COMPUTE_PROVISIONING_ERROR, CloudFormation Stack is being deleted automatically and job will be re-processed shortly ..."
                            )

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_IN_PROGRESS
                        ):
                            logger.info(
                                f"{job.job_id=} is currently queued and SocaHpcJobProvisioningState is still COMPUTE_PROVISIONING_IN_PROGRESS, waiting for all capacity to be provisioned which should happen shortly."
                            )
                            continue

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_DELETE
                        ):
                            logger.info(
                                f"{job.job_id} capacity is currently being deleted, skipping job ... "
                            )
                            continue

                        else:
                            logger.error(
                                f"Unsupported {job.job_provisioning_state} for {job.job_id=}, skipping job ... "
                            )
                            continue
                    else:
                        logger.info(
                            f"{job.job_id=} is not queued. Current State {job.job_state=}, skipping job ...."
                        )
