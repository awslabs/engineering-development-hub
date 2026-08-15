# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import logging
import re
import os
import sys
from datetime import datetime

from typing import Optional
from utils.response import SocaResponse
from utils.subprocess_client import SocaSubprocessClient
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.datamodels.hpc.shared.job_resources import (
    SocaHpcJobLicense,
    SocaHpcJobState,
    SocaHpcJobOrchestrationMethod,
)

from utils.aws.odcr_helper import get_reservation_info_soca_capacity_reservation
from utils.datamodels.hpc.scheduler import SocaHpcScheduler, SocaHpcSchedulerProvider
from utils.datamodels.hpc.lsf.job import SocaHpcJobLSF
from utils.datamodels.hpc.pbs.job import SocaHpcJobPBS
from utils.datamodels.hpc.slurm.job import SocaHpcJobSlurm

from utils.hpc.scheduler_command_builder import (
    SocaHpcPBSJobCommandBuilder,
    SocaHpcLSFJobCommandBuilder,
    SocaHpcSlurmJobCommandBuilder,
)

logger = logging.getLogger("soca_logger")


def _parse_pbs_time(value) -> Optional[int]:
    # PBS times are formatted strings ("Wed Mar 18 20:23:04 2026"); some fields (obittime) may be epoch ints
    if value is None:
        return None
    _cast_int = SocaCastEngine(data=value).cast_as(int)
    if _cast_int.get("success") is True:
        return _cast_int.get("message")
    _cast_str = SocaCastEngine(data=value).cast_as(str)
    if _cast_str.get("success") is True:
        try:
            return int(datetime.strptime(_cast_str.get("message"), "%a %b %d %H:%M:%S %Y").timestamp())
        except (TypeError, ValueError):
            return None
    return None


def get_job_orchestration_mapping(value: str) -> SocaHpcJobOrchestrationMethod:
    # translate user-specified value into SocaHpcJobOrchestrationMethod

    if value is None:
        logger.warning(
            f"No value specified, will use the default orchestration method configured"
        )
        value = "default"

    if not isinstance(value, str):
        logger.warning(
            f"Invalid str value for job orchestration method: {value}, will use the default orchestration method configured"
        )
        value = "default"

    if value.lower() in ["autoscaling", "autoscaling-group", "asg", "legacy"]:
        return SocaHpcJobOrchestrationMethod.ASG
    elif value.lower() in ["ec2fleet", "ec2-fleet", "fleet", "default"]:
        return SocaHpcJobOrchestrationMethod.FLEET
    else:
        logger.warning(
            f"Invalid value for job orchestration method: {value}. Defaulting to FLEET"
        )
        return SocaHpcJobOrchestrationMethod.FLEET


def job_state_mapping(
    state: str, scheduler_provider: SocaHpcSchedulerProvider
) -> SocaHpcJobState:

    # force state to be lowercase
    state = state.lower().strip()

    # https://github.com/openpbs/openpbs/blob/master/src/include/job.h
    _pbs_mapping = {
        "b": SocaHpcJobState.OTHER,  # begun
        "e": SocaHpcJobState.EXITING,  # exiting
        "f": SocaHpcJobState.FINISHED,  # finished
        "h": SocaHpcJobState.STOPPED,  # held
        "m": SocaHpcJobState.OTHER,  # moved
        "r": SocaHpcJobState.RUNNING,  # running
        "q": SocaHpcJobState.QUEUED,  # queued
        "s": SocaHpcJobState.STOPPED,  # suspended
        "t": SocaHpcJobState.OTHER,  # transit
        "u": SocaHpcJobState.STOPPED,  # usersuspended
        "w": SocaHpcJobState.OTHER,  # waiting
        "x": SocaHpcJobState.OTHER,  # expired
    }

    # https://www.ibm.com/docs/en/spectrum-lsf/10.1.0?topic=execution-about-job-states
    _lsf_mapping = {
        "pend": SocaHpcJobState.QUEUED,  # waiting in a queue
        "run": SocaHpcJobState.RUNNING,  # dispatched and running
        "psusp": SocaHpcJobState.STOPPED,  # suspended (pending)
        "ususp": SocaHpcJobState.STOPPED,  # suspended (user)
        "ssusp": SocaHpcJobState.STOPPED,  # suspended (system)
        "done": SocaHpcJobState.FINISHED,  # finished normally
        "unkwn": SocaHpcJobState.OTHER,  # unknown
    }

    # https://slurm.schedmd.com/job_state_codes.html
    _slurm_mapping = {
        # Job States
        "boot_fail": SocaHpcJobState.FINISHED,  # terminated due to node boot failure
        "cancelled": SocaHpcJobState.FINISHED,  # cancelled by user or administrator
        "completed": SocaHpcJobState.FINISHED,  # completed execution successfully; finished with an exit code of zero on all nodes
        "deadline": SocaHpcJobState.FINISHED,  # terminated due to reaching the latest acceptable start time specified for the job
        "failed": SocaHpcJobState.FINISHED,  # completed execution unsuccessfully; non-zero exit code or other failure condition
        "node_fail": SocaHpcJobState.FINISHED,  # terminated due to node failure
        "out_of_memory": SocaHpcJobState.FINISHED,  # experienced out of memory error
        "pending": SocaHpcJobState.QUEUED,  # queued and waiting for initiation
        "preempted": SocaHpcJobState.OTHER,  # terminated due to preemption; may transition to another state based on the configured PreemptMode and job characteristics
        "running": SocaHpcJobState.RUNNING,  # allocated resources and executing
        "suspended": SocaHpcJobState.STOPPED,  # allocated resources but execution suspended, such as from preemption or a direct request from an authorized user
        "timeout": SocaHpcJobState.FINISHED,  # terminated due to reaching the time limit
        # Job Flags
        # "completing": SocaHpcJobState.OTHER,       # job has finished or been cancelled and is performing cleanup tasks, including the epilog script if present
        # "configuring": SocaHpcJobState.OTHER,      # job has been allocated nodes and is waiting for them to boot or reboot
        # "launch_failed": SocaHpcJobState.OTHER,    # failed to launch on the chosen node(s); includes prolog failure and other failure conditions
        # "power_up_node": SocaHpcJobState.OTHER,    # job has been allocated powered down nodes and is waiting for them to boot
        # "reconfig_fail": SocaHpcJobState.OTHER,    # node configuration for job failed
        # "requeued": SocaHpcJobState.OTHER,         # job is being requeued, such as from preemption or a direct request from an authorized user
        # "requeue_fed": SocaHpcJobState.OTHER,      # requeued due to conditions of its sibling job in a federated setup
        # "requeue_hold": SocaHpcJobState.OTHER,     # same as REQUEUED but will not be considered for scheduling until it is released
        # "resizing": SocaHpcJobState.OTHER,         # the size of the job is changing; prevents conflicting job changes from taking place
        # "resv_del_hold": SocaHpcJobState.OTHER,    # held due to deleted reservation
        # "revoked": SocaHpcJobState.OTHER,          # revoked due to conditions of its sibling job in a federated setup
        # "signaling": SocaHpcJobState.OTHER,        # outgoing signal to job is pending
        # "special_exit": SocaHpcJobState.OTHER,     # same as REQUEUE_HOLD but used to identify a special situation that applies to this job
        # "stage_out": SocaHpcJobState.OTHER,        # staging out data (burst buffer)
        # "stopped": SocaHpcJobState.OTHER,          # received SIGSTOP to suspend the job without releasing resources
        # "updated_db": SocaHpcJobState.OTHER,       # sending an update about the job to the database
    }

    #  https://docs.aws.amazon.com/batch/latest/userguide/job_states.html
    # _aws_batch_mapping = {
    #    "submitted": SocaHpcJobState.QUEUED,   # A job that's submitted to the queue, and has not yet been evaluated by the scheduler
    #    "pending": SocaHpcJobState.QUEUED,     # A job that resides in the queue and isn't yet able to run due to a dependency on another job or resource
    #    "runnable": SocaHpcJobState.QUEUED,    # A job that resides in the queue, has no outstanding dependencies, and is therefore ready to be scheduled to a host
    #    "starting": SocaHpcJobState.RUNNING,   # These jobs have been scheduled to a host and the relevant container initiation operations are underway
    #    "running": SocaHpcJobState.RUNNING,    # The job is running as a container job on an Amazon ECS container instance within a compute environment.
    #    "suceeded": SocaHpcJobState.FINISHED,  # The job has successfully completed with an exit code of 0.
    #    "failed": SocaHpcJobState.FINISHED,    # The job has failed all available attempts.
    # }

    _provider_state_map = {
        SocaHpcSchedulerProvider.OPENPBS: _pbs_mapping,
        SocaHpcSchedulerProvider.PBSPRO: _pbs_mapping,
        SocaHpcSchedulerProvider.LSF: _lsf_mapping,
        SocaHpcSchedulerProvider.SLURM: _slurm_mapping,
        # SocaHpcSchedulerProvider.AWS_PCS: _slurm_mapping,
        # SocaHpcSchedulerProvider.AWS_BATCH: _aws_batch_mapping
    }

    _job_state = _provider_state_map.get(scheduler_provider).get(state, None)

    if _job_state is None:
        logger.error(
            f"{state=} does not seem to be a valid node state for provider {scheduler_provider}"
        )
        return SocaHpcJobState.UNKNOWN

    return _job_state


class SocaHpcJobFetcher:

    def __init__(self, scheduler_info: SocaHpcScheduler):

        self.scheduler_info = scheduler_info
        logger.info(
            f"SocaHpcJobFetcher: About to fetch jobs for Scheduler: {self.scheduler_info.identifier=}"
        )

    def by_user(self, user: str) -> SocaResponse:
        logger.info(f"Retrieving all HPC job for {user=}")
        if user is None:
            return SocaError.GENERIC_ERROR(
                helper="Unable to get job info for user when args user is not specified"
            )

        _jobs_info = self.get_all_jobs(user=user)
        if _jobs_info.get("success"):
            return SocaResponse(success=True, message=_jobs_info.get("message"))

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get job info for user {user} due to {_jobs_info.get('message')}"
            )

    def by_job_id(self, job_id: str) -> SocaResponse:
        logger.info(f"Retrieving HPC job for {job_id=}")
        if job_id is None:
            return SocaError.GENERIC_ERROR(
                helper="Unable to get job info for job id when args job_id is not specified"
            )

        _jobs_info = self.get_all_jobs(job_id=str(job_id))
        if _jobs_info.get("success"):
            return SocaResponse(success=True, message=_jobs_info.get("message"))

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get job info for id {job_id} due to {_jobs_info.get('message')}"
            )

    def by_queue(self, queue: str) -> SocaResponse:
        logger.info(f"Retrieving HPC job for {queue=}")
        if queue is None:
            return SocaError.GENERIC_ERROR(
                helper="Unable to get job info for queue  when args queue is not specified"
            )

        _jobs_info = self.get_all_jobs(queue=queue)
        if _jobs_info.get("success"):
            return SocaResponse(success=True, message=_jobs_info.get("message"))

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get job info for queue {queue} due to {_jobs_info.get('message')}"
            )

    def get_all_jobs(
        self,
        queue: Optional[str] = None,
        user: Optional[str] = None,
        job_id: Optional[str] = None,
        include_finished: bool = False,
    ) -> SocaResponse:

        logger.debug(
            f"Received get_all_jobs request with {queue=} / {user=} / {job_id=} / {include_finished=}"
        )

        # Scheduler generic filters

        # Build commands to get job details. Add scheduler specific filters if needed
        if self.scheduler_info.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:

            # PBS does not natively have a flag to list only jobs in a specific queue / users then output as json. Post-processing will be done automatically
            # -x includes finished/historical jobs (bounded by the scheduler's job_history_duration)
            _job_id_option = f"{job_id}" if job_id else ""
            _history_option = "-x" if include_finished else ""
            _run_command = SocaHpcPBSJobCommandBuilder(
                scheduler_info=self.scheduler_info
            ).qstat(args=f"{_history_option} -f -F json {_job_id_option}")

        elif self.scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
            _queue_option = f"-q {queue}" if queue else ""
            _job_id_option = f"{job_id}" if job_id else ""
            _user_option = "-u all" if not user else f"-u {user}"
            _run_command = SocaHpcLSFJobCommandBuilder(
                scheduler_info=self.scheduler_info
            ).bjobs(
                args=f'{_queue_option} {_user_option} -o "all" -json {_job_id_option}'
            )

        elif self.scheduler_info.provider == SocaHpcSchedulerProvider.SLURM:
            _queue_option = f"--partition {queue}" if queue else ""
            _user_option = f"--user {user}" if user else ""
            _job_id_option = f"--job {job_id}" if job_id else ""
            _run_command = SocaHpcSlurmJobCommandBuilder(
                scheduler_info=self.scheduler_info
            ).squeue(args=f"{_queue_option} {_user_option} {_job_id_option} --json")

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"{self.scheduler_info.provider=} is not a recognized scheduler on SOCA, must be openpbs, slurm or lsf"
            )

        if not _run_command:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build run command for {self.scheduler_info.provider=}, see logs for additional details"
            )
        logger.info(
            f"Fetching all HPC jobs for scheduler {self.scheduler_info.identifier}"
        )

        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self.scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self.scheduler_info.binary_folder_paths}:{_current_path}"
            )

        _job_data = SocaSubprocessClient(run_command=_run_command).run(env=_current_env)

        if _job_data.get("success"):
            _get_output_as_json = SocaCastEngine(
                data=_job_data.get("message").get("stdout")
            ).as_json()
            if _get_output_as_json.get("success"):
                if self.scheduler_info.provider in [
                    SocaHpcSchedulerProvider.OPENPBS,
                    SocaHpcSchedulerProvider.PBSPRO,
                ]:
                    # PBS does not natively have a flag to list only jobs in a specific queue, so some post-processing is needed

                    _qstat_output = _get_output_as_json.get("message")

                    _jobs_list = self.__pbs_parser(
                        qstat_output=_qstat_output,
                    )

                    if queue:
                        _jobs_list = [
                            job for job in _jobs_list if job.job_queue == queue
                        ]

                    if user:
                        _jobs_list = [
                            job for job in _jobs_list if job.job_owner == user
                        ]

                elif self.scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
                    _jobs_list = self.__lsf_parser(
                        bjobs_output=_get_output_as_json.get("message")
                    )

                elif self.scheduler_info.provider == SocaHpcSchedulerProvider.SLURM:
                    _jobs_list = self.__slurm_parser(
                        squeue_output=_get_output_as_json.get("message")
                    )

            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"{_run_command} succeeded but output was not a valid json"
                )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to run {_run_command} due to {_job_data.get('message')}"
            )

        logger.debug(
            f"Received jobs list for  {self.scheduler_info.identifier} {_jobs_list=}"
        )
        return SocaResponse(success=True, message=_jobs_list)

    def __lsf_parser(self, bjobs_output: dict) -> list[SocaHpcJobLSF]:
        """
        Parser for LSF
        """
        logger.debug(f"Received LSF parser with bjobs output {bjobs_output=}")
        _jobs_list = []
        if bjobs_output.get("JOBS", 0) == 0:
            logger.debug("No jobs found")
            return _jobs_list
        try:
            _jobs_count = bjobs_output.get("JOBS")
            logger.debug(f"Processing {_jobs_count} job")
            for _job_data in bjobs_output.get("RECORDS"):
                # when using bjobs -o "all", all attributes will be returned. Unset attributes will return an empty string ""

                logger.debug(f"Processing LSF Job: {_job_data}")
                _job_lsf = SocaHpcJobLSF.model_construct()

                # Required Attributes from SocaHpcJob
                _job_lsf.job_id = _job_data.get("JOBID")
                _job_lsf.job_scheduler_info = self.scheduler_info
                _job_lsf.job_name = _job_data.get("JOB_NAME")
                _job_lsf.job_owner = _job_data.get("USER")
                _job_lsf.job_queue = _job_data.get("QUEUE")
                _job_lsf.job_error_log_path = _job_data.get("ERROR_FILE")
                _job_lsf.job_output_log_path = _job_data.get("OUTPUT_FILE")
                _job_lsf.job_project = _job_data.get("PROJ_NAME")
                if _job_data.get("SLOTS"):
                    try:
                        _job_lsf.cpus = int(_job_lsf.get("SLOTS"))
                    except Exception as err:
                        # note: validate() will reject the job if cpus is incorrect
                        logger.error(
                            f'Unable to cast SLOTS {_job_data.get("SLOTS")} as integer due to {err}'
                        )
                else:
                    _job_lsf.cpus = 1

                if _job_data.get("SUBMIT_TIME"):
                    current_year = (
                        datetime.now().year
                    )  # note: SUBMIT_TIME does not contain year, eg:  "SUBMIT_TIME":"Oct  1 15:40",
                    _dt = datetime.strptime(
                        f"{_job_data.get('SUBMIT_TIME')} {current_year}",
                        "%b %d %H:%M %Y",
                    )
                    _job_lsf.job_queue_time = int(_dt.timestamp())

                if _job_data.get("STAT"):
                    _job_lsf.job_state = job_state_mapping(
                        state=_job_data.get("STAT"),
                        scheduler_provider=self.scheduler_info.provider,
                    )  # SOCA specific, used for logic
                    _job_lsf.job_scheduler_state = _job_data.get("STAT")

                # Transform RES_REQ (-R)
                # Received format:  "select[type == local] order[r15s:pg] ...."
                # Output: [{'select': 'type == local'}, {'order': 'r15s:pg'}]
                _job_request = _job_data.get("COMBINED_RESREQ")
                _res_request = []
                if _job_request:
                    matches = re.findall(r"(\w+)\[([^\]]+)\]", _job_request)
                    _res_request = [{k: v for k, v in matches}]

                logger.debug(f"Found {_res_request=} for {_job_lsf.job_id}")
                for _res in _res_request:
                    for res_name, res_data in _res.items():
                        if res_name == "select":
                            _find_compute_node = re.search(
                                r"compute_node==([^\)&\s]+)", res_data
                            )
                            if _find_compute_node:
                                _job_lsf.job_compute_node = str(
                                    _find_compute_node.group(1)
                                )

                # Note: LSF does not allow string for compute_node, so a non-existing compute_node is flagged as compute_node==-1
                if not _job_lsf.job_compute_node or _job_lsf.job_compute_node == "-1":
                    _job_lsf.job_compute_node == "tbd"  # default to tbd if not found

                _job_lsf.job_working_directory = _job_data.get("SUB_CWD")
                # Required SocaHpcJobLSF attributes
                # On LSF, SOCA specific resources -instance_ami, root_disk.- are configured via the Job Description field
                _job_description_variables = {}
                _job_lsf.lsf_job_description = _job_data.get("JOB_DESCRIPTION", "")

                # received as string with space delimiters : "JOB_DESCRIPTION":"scratch_size=50 instance_types=m5.xlarge"
                # convert to list ["scratch_size=50", "instance_types=m5.xlarge"] then as dict: {"scratch_size": "50", "instance_types": "m5.xlarge" }
                for part in _job_lsf.lsf_job_description.split(" "):
                    part = part.strip()  # remove l/r strip
                    if not part:  # skip empty
                        continue

                    if "=" not in part:  # skip resources that don't watch key=value
                        logger.warning(f"Skipping {part}, not a SOCA managed resource")
                        continue

                    # Track all key=value resource. SOCA validation will be performed by _job_resource_mapping
                    k, v = part.split("=", 1)

                    if k.strip() in _job_description_variables:
                        logger.warning(
                            f"Skipping {part}, {k} already exist in {_job_description_variables}, ignoring ... "
                        )
                        continue
                    else:
                        _job_description_variables[k.strip()] = v.strip()
                logger.debug(
                    f"Found LSF {_job_lsf.job_id=} Job Description: {_job_description_variables}"
                )
                _job_resource_mapping = {
                    # LSF resource name : SocaHpcJob attr
                    "base_os": "base_os",
                    "nodes": "nodes",
                    "instance_profile": "instance_profile",
                    "instance_ami": "instance_ami",
                    "instance_type": "instance_types",  # rewrite singular (legacy) to plural (new) if present
                    "instance_types": "instance_types",
                    "root_size": "root_size",
                    "scratch_iops": "scratch_iops",
                    "fsx_lustre": "fsx_lustre",
                    "fsx_lustre_size": "fsx_lustre_size",
                    "fsx_lustre_deployment_type": "fsx_lustre_deployment_type",
                    "fsx_lustre_per_unit_throughput": "fsx_lustre_per_unit_throughput",
                    "scratch_size": "scratch_size",
                    "security_groups": "security_groups",
                    "spot_allocation_count": "spot_allocation_count",
                    "spot_price": "spot_price",
                    "subnet_id": "subnet_ids",  # rewrite singular (legacy) to plural (new) if present
                    "subnet_ids": "subnet_ids",
                    "spot_allocation_strategy": "spot_allocation_strategy",
                    "keep_ebs": "keep_ebs",
                    "placement_group": "placement_group",
                    "efa_support": "efa_support",
                    "force_ri": "force_ri",
                    "ht_support": "ht_support",
                    "nested_virtualization": "nested_virtualization",
                    "retry_attempt": "job_failed_provisioning_retry_count",
                    "stack_id": "stack_id",
                    "capacity_reservation_id": "capacity_reservation_id",
                    "error_message": "error_message",
                    "x_soca_aws_orchestration_method": "job_orchestration_method",
                }

                for _resource, attr in _job_resource_mapping.items():
                    _resource_value = _job_description_variables.get(_resource)
                    if _resource_value is not None:
                        if (
                            _resource == "retry_attempt"
                        ):  # retry_attempt must be an integer
                            setattr(_job_lsf, attr, int(_resource_value))
                        elif re.match(r"^(?!_lic_).+_lic_.+", _resource):
                            # Handle Licenses
                            _job_lsf.licenses.append(
                                SocaHpcJobLicense(name=_resource, count=_resource_value)
                            )
                        elif _resource == "error_message":
                            _job_lsf.error_message = re.findall(
                                r"ERROR_(.*?)_END_OF_ERROR", _resource_value
                            )
                        elif _resource == "x_soca_aws_orchestration_method":
                            _job_lsf.job_orchestration_method = (
                                get_job_orchestration_mapping(value=_resource_value)
                            )
                        elif _resource == "capacity_reservation_id":
                            _job_lsf.capacity_reservation_id = (
                                get_reservation_info_soca_capacity_reservation(
                                    capacity_reservation_id=_resource_value
                                )
                            )
                        elif _resource == "stack_id":
                            _job_lsf.stack_id = _resource_value
                        elif _resource == "nodes":
                            try:
                                _job_lsf.nodes = int(_resource_value)
                            except Exception as err:
                                logger.error(
                                    f"Unable to cast {attr} {_resource_value} as integer due to {err}"
                                )
                                setattr(_job_lsf, attr, None)
                        else:
                            setattr(_job_lsf, attr, _resource_value)

                # Special Cases
                if _job_lsf.nodes is None:
                    logger.warning(
                        f"No 'nodes' found on {_job_lsf.job_id=}, default to 1 node for this simulation"
                    )
                    _job_lsf.nodes = 1

                # Optional SocaHpcJobLSF attributes
                _job_lsf.lsf_jobid = _job_data.get("JOBID", None)
                _job_lsf.lsf_state = _job_data.get("STAT", None)
                _job_lsf.lsf_user = _job_data.get("USER", None)
                _job_lsf.lsf_queue = _job_data.get("QUEUE", None)
                _job_lsf.lsf_job_name = _job_data.get("JOB_NAME", None)
                _job_lsf.lsf_proj_name = _job_data.get("PROJ_NAME", None)
                _job_lsf.lsf_application = _job_data.get("APPLICATION", None)
                _job_lsf.lsf_service_class = _job_data.get("SERVICE_CLASS", None)
                _job_lsf.lsf_user_group = _job_data.get("USER_GROUP", None)
                _job_lsf.lsf_job_group = _job_data.get("JOB_GROUP", None)
                _job_lsf.lsf_job_priority = _job_data.get("JOB_PRIORITY", None)
                _job_lsf.lsf_job_dependency = _job_data.get("DEPENDENCY", None)
                _job_lsf.lsf_aps = _job_data.get("APS", None)
                _job_lsf.lsf_immediate_orphan_term = _job_data.get(
                    "IMMEDIATE_ORPHAN_TERM", None
                )
                _job_lsf.lsf_exclusive = _job_data.get("EXCLUSIVE", None)
                _job_lsf.lsf_interactive = _job_data.get("INTERACTIVE", None)
                _job_lsf.lsf_pendstate = _job_data.get("PENDSTATE", None)
                _job_lsf.lsf_pend_reason = _job_data.get("PEND_REASON", None)
                _job_lsf.lsf_plimit_remain = _job_data.get("PLIMIT_REMAIN", None)
                _job_lsf.lsf_eplimit_remain = _job_data.get("EPLIMIT_REMAIN", None)
                _job_lsf.lsf_charged_saap = _job_data.get("CHARGED_SAAP", None)
                _job_lsf.lsf_jobindex = _job_data.get("JOBINDEX", None)
                _job_lsf.lsf_rsvid = _job_data.get("RSVID", None)
                _job_lsf.lsf_command = _job_data.get("COMMAND", None)
                _job_lsf.lsf_pre_exec_command = _job_data.get("PRE_EXEC_COMMAND", None)
                _job_lsf.lsf_post_exec_command = _job_data.get(
                    "POST_EXEC_COMMAND", None
                )
                _job_lsf.lsf_resize_notification_command = _job_data.get(
                    "RESIZE_NOTIFICATION_COMMAND", None
                )
                _job_lsf.lsf_pids = _job_data.get("PIDS", None)
                _job_lsf.lsf_exit_code = _job_data.get("EXIT_CODE", None)
                _job_lsf.lsf_exit_reason = _job_data.get("EXIT_REASON", None)
                _job_lsf.lsf_from_host = _job_data.get("FROM_HOST", None)
                _job_lsf.lsf_first_host = _job_data.get("FIRST_HOST", None)
                _job_lsf.lsf_exec_host = _job_data.get("EXEC_HOST", None)
                _job_lsf.lsf_nexec_host = _job_data.get("NEXEC_HOST", None)
                _job_lsf.lsf_ask_host = _job_data.get("ASK_HOSTS", None)
                _job_lsf.lsf_submit_time = _job_data.get("SUBMIT_TIME", None)
                _job_lsf.lsf_start_time = _job_data.get("START_TIME", None)
                _job_lsf.lsf_estimated_start_time = _job_data.get(
                    "ESTIMATED_START_TIME", None
                )
                _job_lsf.lsf_specified_start_time = _job_data.get(
                    "SPECIFIED_START_TIME", None
                )
                _job_lsf.lsf_specified_terminate_time = _job_data.get(
                    "SPECIFIED_TERMINATE_TIME", None
                )
                _job_lsf.lsf_time_left = _job_data.get("TIME_LEFT", None)
                _job_lsf.lsf_finish_time = _job_data.get("FINISH_TIME", None)
                _job_lsf.lsf_pctcomplete = _job_data.get("%COMPLETE", None)
                _job_lsf.lsf_warning_action = _job_data.get("WARNING_ACTION", None)
                _job_lsf.lsf_action_warning_time = _job_data.get(
                    "ACTION_WARNING_TIME", None
                )
                _job_lsf.lsf_estimated_sim_start_time = _job_data.get(
                    "ESTIMATED_SIM_START_TIME", None
                )
                _job_lsf.lsf_pend_time = _job_data.get("PEND_TIME", None)
                _job_lsf.lsf_ependtime = _job_data.get("EPENDTIME", None)
                _job_lsf.lsf_ipendtime = _job_data.get("IPENDTIME", None)
                _job_lsf.lsf_estimated_run_time = _job_data.get(
                    "ESTIMATED_RUN_TIME", None
                )
                _job_lsf.lsf_ru_utime = _job_data.get("RU_UTIME", None)
                _job_lsf.lsf_ru_stime = _job_data.get("RU_STIME", None)
                _job_lsf.lsf_cpu_used = _job_data.get("CPU_USED", None)
                _job_lsf.lsf_run_time = _job_data.get("RUN_TIME", None)
                _job_lsf.lsf_idle_factor = _job_data.get("IDLE_FACTOR", None)
                _job_lsf.lsf_exception_status = _job_data.get("EXCEPTION_STATUS", None)
                _job_lsf.lsf_slots = _job_data.get("SLOTS", None)
                _job_lsf.lsf_mem = _job_data.get("MEM", None)
                _job_lsf.lsf_max_mem = _job_data.get("MAX_MEM", None)
                _job_lsf.lsf_avg_mem = _job_data.get("AVG_MEM", None)
                _job_lsf.lsf_memlimit = _job_data.get("MEMLIMIT", None)
                _job_lsf.lsf_swap = _job_data.get("SWAP", None)
                _job_lsf.lsf_swaplimit = _job_data.get("SWAPLIMIT", None)
                _job_lsf.lsf_min_req_proc = _job_data.get("MIN_REQ_PROC", None)
                _job_lsf.lsf_max_req_proc = _job_data.get("MAX_REQ_PROC", None)
                _job_lsf.lsf_effective_resreq = _job_data.get("EFFECTIVE_RESREQ", None)
                _job_lsf.lsf_network_req = _job_data.get("NETWORK_REQ", None)
                _job_lsf.lsf_combined_resreq = _job_data.get("COMBINED_RESREQ", None)
                _job_lsf.lsf_file_limit = _job_data.get("FILELIMIT", None)
                _job_lsf.lsf_corelimit = _job_data.get("CORELIMIT", None)
                _job_lsf.lsf_stacklimit = _job_data.get("STACKLIMIT", None)
                _job_lsf.lsf_processlimit = _job_data.get("PROCESSLIMIT", None)
                _job_lsf.lsf_runtimelimit = _job_data.get("RUNTIMELIMIT", None)
                _job_lsf.lsf_effective_plimit = _job_data.get("EFFECTIVE_PLIMIT", None)
                _job_lsf.lsf_effective_eplimit = _job_data.get(
                    "EFFECTIVE_EPLIMIT", None
                )
                _job_lsf.lsf_plimit = _job_data.get("PLIMIT", None)
                _job_lsf.lsf_eplimit = _job_data.get("EPLIMIT", None)
                _job_lsf.lsf_input_file = _job_data.get("INPUT_FILE", None)
                _job_lsf.lsf_output_file = _job_data.get("OUTPUT_FILE", None)
                _job_lsf.lsf_error_file = _job_data.get("ERROR_FILE", None)
                _job_lsf.lsf_output_dir = _job_data.get("OUTPUT_DIR", None)
                _job_lsf.lsf_sub_cwd = _job_data.get("SUB_CWD", None)
                _job_lsf.lsf_exec_home = _job_data.get("EXEC_HOME", None)
                _job_lsf.lsf_exec_cwd = _job_data.get("EXEC_CWD", None)
                _job_lsf.lsf_forward_cluster = _job_data.get("FORWARD_CLUSTER", None)
                _job_lsf.lsf_forward_time = _job_data.get("FORWARD_TIME", None)
                _job_lsf.lsf_source_cluster = _job_data.get("SOURCE_CLUSTER", None)
                _job_lsf.lsf_srcjobid = _job_data.get("SRCJOBID", None)
                _job_lsf.lsf_dstjobid = _job_data.get("DSTJOBID", None)
                _job_lsf.lsf_host_file = _job_data.get("HOST_FILE", None)
                _job_lsf.lsf_nalloc_slot = _job_data.get("NALLOC_SLOT", None)
                _job_lsf.lsf_alloc_slot = _job_data.get("ALLOC_SLOT", None)
                _job_lsf.lsf_hrusage = _job_data.get("HRUSAGE", [])
                _job_lsf.lsf_nthreads = _job_data.get("NTHREADS", None)
                _job_lsf.lsf_licproject = _job_data.get("LICPROJECT", None)
                _job_lsf.lsf_esub = _job_data.get("ESUB", None)
                _job_lsf.lsf_image = _job_data.get("IMAGE", None)
                _job_lsf.lsf_ctxuser = _job_data.get("CTXUSER", None)
                _job_lsf.lsf_container_name = _job_data.get("CONTAINER_NAME", None)
                _job_lsf.lsf_energy = _job_data.get("ENERGY", None)
                _job_lsf.lsf_gpfsio = _job_data.get("GPFSIO", None)
                _job_lsf.lsf_killreason = _job_data.get("KILL_REASON", None)
                _job_lsf.lsf_nreq_slot = _job_data.get("NREQ_SLOT", None)
                _job_lsf.lsf_suspendreason = _job_data.get("SUSPEND_REASON", None)
                _job_lsf.lsf_resumereason = _job_data.get("RESUME_REASON", None)
                _job_lsf.lsf_kill_issue_host = _job_data.get("KILL_ISSUE_HOST", None)
                _job_lsf.lsf_suspend_issue_host = _job_data.get(
                    "SUSPEND_ISSUE_HOST", None
                )
                _job_lsf.lsf_resume_issue_host = _job_data.get(
                    "RESUME_ISSUE_HOST", None
                )
                _job_lsf.lsf_j_exclusive = _job_data.get("J_EXCLUSIVE", None)
                _job_lsf.lsf_gpu_mode = _job_data.get("GPU_MODE", None)
                _job_lsf.lsf_gpu_num = _job_data.get("GPU_NUM", None)
                _job_lsf.lsf_gpu_alloc = _job_data.get("GPU_ALLOC", None)
                _job_lsf.lsf_longjobid = _job_data.get("LONGJOBID", None)
                _job_lsf.lsf_k8s = _job_data.get("K8S", None)
                _job_lsf.lsf_plan_start_time = _job_data.get("PLAN_START_TIME", None)
                _job_lsf.lsf_block = _job_data.get("BLOCK", None)
                _job_lsf.lsf_cpu_peak = _job_data.get("CPU_PEAK", None)
                _job_lsf.lsf_cpu_peak_efficiency = _job_data.get(
                    "CPU_PEAK_EFFICIENCY", None
                )
                _job_lsf.lsf_mem_efficiency = _job_data.get("MEM_EFFICIENCY", None)
                _job_lsf.lsf_average_cpu_efficiency = _job_data.get(
                    "AVERAGE_CPU_EFFICIENCY", None
                )
                _job_lsf.lsf_cpu_peak_reached_duration = _job_data.get(
                    "CPU_PEAK_REACHED_DURATION", None
                )

                # Retrieve the current job provisioning state
                _job_lsf.job_provisioning_state = _job_lsf.get_job_provisioning_state()

                logger.debug(f"Found LSF Job {_job_lsf}")
                # Add job to jobs list
                _jobs_list.append(_job_lsf)

            logger.debug(f"LSFParser: {_jobs_list}")
            return _jobs_list
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            f"__lsf_parser: Error trying to parse bjobs output due to {err} {exc_type} {fname} {exc_tb.tb_lineno}"
        return _jobs_list

    def __slurm_parser(self, squeue_output: dict) -> list[SocaHpcJobSlurm]:
        """
        Parser for Slurm
        """
        logger.debug(f"Received Slurm parser with squeue output {squeue_output=}")
        _jobs_list = []
        if not squeue_output.get("jobs", []):
            logger.debug("No jobs found")
            return _jobs_list
        try:
            _jobs_count = len(squeue_output.get("jobs"))
            logger.debug(f"Processing {_jobs_count} job")
            for _job_data in squeue_output.get("jobs"):
                logger.debug(f"Processing Slurm Job: {_job_data}")
                _job_slurm = SocaHpcJobSlurm.model_construct()

                # Required Attributes from SocaHpcJob
                _job_slurm.job_id = _job_data.get("job_id")
                _job_slurm.job_scheduler_info = self.scheduler_info
                _job_slurm.job_name = _job_data.get("name")
                _job_slurm.job_owner = _job_data.get("user_name")
                _job_slurm.job_queue = _job_data.get("partition")
                _job_slurm.job_error_log_path = _job_data.get("stderr_expanded")
                _job_slurm.job_output_log_path = _job_data.get("stdout_expanded")
                _job_slurm.job_project = _job_data.get("account")
                _job_slurm.cpus = _job_data.get("tasks", {}).get("number", None)
                _job_slurm.job_queue_time = _job_data.get("submit_time", {}).get(
                    "number", None
                )
                _job_slurm.nodes = _job_data.get("node_count", {}).get("number", None)
                # Slurm keeps track of all the entire job lifecycle. Latest status are first in the array
                # "job_state": [
                #    "RUNNING", <-- Current state
                #    "CONFIGURING", <-- Previous state
                #    "POWER_UP_NODE" <-- Previous state
                # ]
                _job_slurm.job_state = job_state_mapping(
                    state=_job_data.get("job_state")[0],
                    scheduler_provider=self.scheduler_info.provider,
                )  # SOCA specific, used for logic
                _job_slurm.job_scheduler_state = _job_data.get("job_state")[0]

                # Retrieve the current job provisioning state
                _job_slurm.job_provisioning_state = (
                    _job_slurm.get_job_provisioning_state()
                )

                # Optional Slurm job parameters
                _job_slurm.account = _job_data.get("account", None)
                _job_slurm.accrue_time = _job_data.get("accrue_time", None)
                _job_slurm.admin_comment = _job_data.get("admin_comment", None)
                _job_slurm.allocating_node = _job_data.get("allocating_node", None)
                _job_slurm.array_job_id = _job_data.get("array_job_id", None)
                _job_slurm.array_max_tasks = _job_data.get("array_max_tasks", None)
                _job_slurm.array_task_string = _job_data.get("array_task_string", None)
                _job_slurm.association_id = _job_data.get("association_id", None)
                _job_slurm.batch_features = _job_data.get("batch_features", None)
                _job_slurm.batch_flag = _job_data.get("batch_flag", None)
                _job_slurm.batch_host = _job_data.get("batch_host", None)
                _job_slurm.flags = _job_data.get("flags", None)
                _job_slurm.burst_buffer = _job_data.get("burst_buffer", None)
                _job_slurm.burst_buffer_state = _job_data.get(
                    "burst_buffer_state", None
                )
                _job_slurm.cluster = _job_data.get("cluster", None)
                _job_slurm.cluster_features = _job_data.get("cluster_features", None)
                _job_slurm.command = _job_data.get("command", None)
                _job_slurm.comment = _job_data.get("comment", None)
                _job_slurm.container = _job_data.get("container", None)
                _job_slurm.container_id = _job_data.get("container_id", None)
                _job_slurm.contiguous = _job_data.get("contiguous", None)
                _job_slurm.core_spec = _job_data.get("core_spec", None)
                _job_slurm.thread_spec = _job_data.get("thread_spec", None)
                _job_slurm.cores_per_socket = _job_data.get("cores_per_socket", None)
                _job_slurm.billable_tres = _job_data.get("billable_tres", None)
                _job_slurm.cpus_per_task = _job_data.get("cpus_per_task", None)
                _job_slurm.cpu_frequency_minimum = _job_data.get(
                    "cpu_frequency_minimum", None
                )
                _job_slurm.cpu_frequency_maximum = _job_data.get(
                    "cpu_frequency_maximum", None
                )
                _job_slurm.cpu_frequency_governor = _job_data.get(
                    "cpu_frequency_governor", None
                )
                _job_slurm.cpus_per_tres = _job_data.get("cpus_per_tres", None)
                _job_slurm.cron = _job_data.get("cron", None)
                _job_slurm.deadline = _job_data.get("deadline", None)
                _job_slurm.delay_boot = _job_data.get("delay_boot", None)
                _job_slurm.dependency = _job_data.get("dependency", None)
                _job_slurm.derived_exit_code = _job_data.get("derived_exit_code", None)
                _job_slurm.eligible_time = _job_data.get("eligible_time", None)
                _job_slurm.end_time = _job_data.get("end_time", None)
                _job_slurm.excluded_nodes = _job_data.get("excluded_nodes", None)
                _job_slurm.exit_code = _job_data.get("exit_code", None)
                _job_slurm.extra = _job_data.get("extra", None)
                _job_slurm.failed_node = _job_data.get("failed_node", None)
                _job_slurm.features = _job_data.get("features", None)
                _job_slurm.federation_origin = _job_data.get("federation_origin", None)
                _job_slurm.federation_siblings_active = _job_data.get(
                    "federation_siblings_active", None
                )
                _job_slurm.federation_siblings_viable = _job_data.get(
                    "federation_siblings_viable", None
                )
                _job_slurm.gres_detail = _job_data.get("gres_detail", None)
                _job_slurm.group_id = _job_data.get("group_id", None)
                _job_slurm.group_name = _job_data.get("group_name", None)
                _job_slurm.het_job_id = _job_data.get("het_job_id", None)
                _job_slurm.het_job_id_set = _job_data.get("het_job_id_set", None)
                _job_slurm.het_job_offset = _job_data.get("het_job_offset", None)
                _job_slurm.job_id = _job_data.get("job_id", None)
                _job_slurm.job_resources = _job_data.get("job_resources", None)
                _job_slurm.job_size_str = _job_data.get("job_size_str", None)
                _job_slurm.last_sched_evaluation = _job_data.get(
                    "last_sched_evaluation", None
                )
                _job_slurm.licenses_allocated = _job_data.get(
                    "licenses_allocated", None
                )
                _job_slurm.mail_type = _job_data.get("mail_type", None)
                _job_slurm.mail_user = _job_data.get("mail_user", None)
                _job_slurm.max_cpus = _job_data.get("max_cpus", None)
                _job_slurm.max_nodes = _job_data.get("max_nodes", None)
                _job_slurm.mcs_label = _job_data.get("mcs_label", None)
                _job_slurm.memory_per_tres = _job_data.get("memory_per_tres", None)
                _job_slurm.name = _job_data.get("name", None)
                _job_slurm.network = _job_data.get("network", None)
                _job_slurm.nice = _job_data.get("nice", None)
                _job_slurm.tasks_per_core = _job_data.get("tasks_per_core", None)
                _job_slurm.tasks_per_tres = _job_data.get("tasks_per_tres", None)
                _job_slurm.tasks_per_node = _job_data.get("tasks_per_node", None)
                _job_slurm.tasks_per_socket = _job_data.get("tasks_per_socket", None)
                _job_slurm.tasks_per_board = _job_data.get("tasks_per_board", None)
                _job_slurm.node_count = _job_data.get("node_count", None)
                _job_slurm.tasks = _job_data.get("tasks", None)
                _job_slurm.partition = _job_data.get("partition", None)
                _job_slurm.prefer = _job_data.get("prefer", None)
                _job_slurm.memory_per_cpu = _job_data.get("memory_per_cpu", None)
                _job_slurm.memory_per_node = _job_data.get("memory_per_node", None)
                _job_slurm.minimum_cpus_per_node = _job_data.get(
                    "minimum_cpus_per_node", None
                )
                _job_slurm.minimum_tmp_disk_per_node = _job_data.get(
                    "minimum_tmp_disk_per_node", None
                )
                _job_slurm.power = _job_data.get("power", None)
                _job_slurm.preempt_time = _job_data.get("preempt_time", None)
                _job_slurm.preemptable_time = _job_data.get("preemptable_time", None)
                _job_slurm.pre_sus_time = _job_data.get("pre_sus_time", None)
                _job_slurm.hold = _job_data.get("hold", None)
                _job_slurm.priority = _job_data.get("priority", None)
                _job_slurm.priority_by_partition = _job_data.get(
                    "priority_by_partition", None
                )
                _job_slurm.profile = _job_data.get("profile", None)
                _job_slurm.qos = _job_data.get("qos", None)
                _job_slurm.reboot = _job_data.get("reboot", None)
                _job_slurm.required_nodes = _job_data.get("required_nodes", None)
                _job_slurm.required_switches = _job_data.get("required_switches", None)
                _job_slurm.requeue = _job_data.get("requeue", None)
                _job_slurm.resize_time = _job_data.get("resize_time", None)
                _job_slurm.restart_cnt = _job_data.get("restart_cnt", None)
                _job_slurm.resv_name = _job_data.get("resv_name", None)
                _job_slurm.scheduled_nodes = _job_data.get("scheduled_nodes", None)
                _job_slurm.segment_size = _job_data.get("segment_size", None)
                _job_slurm.selinux_context = _job_data.get("selinux_context", None)
                _job_slurm.shared = _job_data.get("shared", None)
                _job_slurm.sockets_per_board = _job_data.get("sockets_per_board", None)
                _job_slurm.sockets_per_node = _job_data.get("sockets_per_node", None)
                _job_slurm.start_time = _job_data.get("start_time", None)
                _job_slurm.state_description = _job_data.get("state_description", None)
                _job_slurm.state_reason = _job_data.get("state_reason", None)
                _job_slurm.standard_input = _job_data.get("standard_input", None)
                _job_slurm.standart_output = _job_data.get("standart_output", None)
                _job_slurm.standard_error = _job_data.get("standard_error", None)
                _job_slurm.stdin_expanded = _job_data.get("stdin_expanded", None)
                _job_slurm.stdout_expanded = _job_data.get("stdout_expanded", None)
                _job_slurm.stderr_expanded = _job_data.get("stderr_expanded", None)
                _job_slurm.submit_time = _job_data.get("submit_time", None)
                _job_slurm.suspend_time = _job_data.get("suspend_time", None)
                _job_slurm.system_comment = _job_data.get("system_comment", None)
                _job_slurm.time_limit = _job_data.get("time_limit", None)
                _job_slurm.time_minimum = _job_data.get("time_minimum", None)
                _job_slurm.threads_per_core = _job_data.get("threads_per_core", None)
                _job_slurm.tres_bind = _job_data.get("tres_bind", None)
                _job_slurm.tres_freq = _job_data.get("tres_freq", None)
                _job_slurm.tres_per_job = _job_data.get("tres_per_job", None)
                _job_slurm.tres_per_node = _job_data.get("tres_per_node", None)
                _job_slurm.tres_per_socket = _job_data.get("tres_per_socket", None)
                _job_slurm.tres_per_task = _job_data.get("tres_per_task", None)
                _job_slurm.tres_req_str = _job_data.get("tres_req_str", None)
                _job_slurm.tres_alloc_str = _job_data.get("tres_alloc_str", None)
                _job_slurm.user_id = _job_data.get("user_id", None)
                _job_slurm.user_name = _job_data.get("user_name", None)
                _job_slurm.maximum_switch_wait_time = _job_data.get(
                    "maximum_switch_wait_time", None
                )
                _job_slurm.wckey = _job_data.get("wckey", None)
                _job_slurm.current_working_directory = _job_data.get(
                    "current_working_directory", None
                )

                _job_resource_mapping = {
                    # Slurm resource name : SocaHpcJob attr
                    "base_os": "base_os",
                    "nodes": "nodes",
                    "instance_profile": "instance_profile",
                    "instance_ami": "instance_ami",
                    "instance_type": "instance_types",  # rewrite singular (legacy) to plural (new) if present
                    "instance_types": "instance_types",
                    "root_size": "root_size",
                    "scratch_iops": "scratch_iops",
                    "fsx_lustre": "fsx_lustre",
                    "fsx_lustre_size": "fsx_lustre_size",
                    "fsx_lustre_deployment_type": "fsx_lustre_deployment_type",
                    "fsx_lustre_per_unit_throughput": "fsx_lustre_per_unit_throughput",
                    "scratch_size": "scratch_size",
                    "security_groups": "security_groups",
                    "spot_allocation_count": "spot_allocation_count",
                    "spot_price": "spot_price",
                    "subnet_id": "subnet_ids",  # rewrite singular (legacy) to plural (new) if present
                    "subnet_ids": "subnet_ids",
                    "spot_allocation_strategy": "spot_allocation_strategy",
                    "keep_ebs": "keep_ebs",
                    "placement_group": "placement_group",
                    "efa_support": "efa_support",
                    "force_ri": "force_ri",
                    "ht_support": "ht_support",
                    "nested_virtualization": "nested_virtualization",
                    "retry_attempt": "job_failed_provisioning_retry_count",
                    "stack_id": "stack_id",
                    "capacity_reservation_id": "capacity_reservation_id",
                    "error_message": "error_message",
                    "x_soca_aws_orchestration_method": "job_orchestration_method",
                }

                _job_comment_variables = {}
                # received as string with space delimiters : "comment":"scratch_size=50 instance_types=m5.xlarge"
                # convert to list ["scratch_size=50", "instance_type=m5.xlarge"] then as dict: {"scratch_size": "50", "instance_types": "m5.xlarge" }
                for part in _job_slurm.comment.split(" "):
                    part = part.strip()  # remove l/r strip

                    if not part:  # skip empty
                        continue

                    if "=" not in part:  # skip resources that don't watch key=value
                        logger.warning(f"Skipping {part}, not a SOCA managed resource")
                        continue

                    # Track all key=value resource. SOCA validation will be performed by _job_resource_mapping
                    k, v = part.split("=", 1)

                    if k.strip() in _job_comment_variables:
                        logger.warning(
                            f"Skipping {part}, {k} already exist in {_job_comment_variables}, ignoring ... "
                        )
                        continue
                    else:
                        _job_comment_variables[k.strip()] = v.strip()

                logger.debug(
                    f"Found Slurm {_job_slurm.job_id=} Job Comment: {_job_comment_variables}"
                )

                for _resource, attr in _job_resource_mapping.items():
                    _resource_value = _job_comment_variables.get(_resource)
                    if _resource_value is not None:
                        if (
                            _resource == "retry_attempt"
                        ):  # retry_attempt must be an integer
                            setattr(_job_slurm, attr, int(_resource_value))
                        elif _resource == "error_message":
                            _job_slurm.error_message = re.findall(
                                r"ERROR_(.*?)_END_OF_ERROR", _resource_value
                            )
                        elif _resource == "x_soca_aws_orchestration_method":
                            _job_slurm.job_orchestration_method = (
                                get_job_orchestration_mapping(value=_resource_value)
                            )
                        elif _resource == "capacity_reservation_id":
                            _job_slurm.capacity_reservation_id = (
                                get_reservation_info_soca_capacity_reservation(
                                    capacity_reservation_id=_resource_value
                                )
                            )
                        elif re.match(r"^(?!_lic_).+_lic_.+", _resource):
                            # Handle Licenses
                            _job_slurm.licenses.append(
                                SocaHpcJobLicense(name=_resource, count=_resource_value)
                            )
                        elif _resource == "stack_id":
                            _job_slurm.stack_id = _resource_value
                        else:
                            setattr(_job_slurm, attr, _resource_value)

                logger.debug(f"Found Slurm Job {_job_slurm}")
                # Add job to jobs list
                _jobs_list.append(_job_slurm)

            logger.debug(f"SlurmParser: {_jobs_list}")
            return _jobs_list
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error(
                f"__slurm_parser: Error trying to parse squeue output due to {err} {exc_type} {fname} {exc_tb.tb_lineno}"
            )
        return _jobs_list

    def __pbs_parser(
        self,
        qstat_output: dict,
    ) -> list[SocaHpcJobPBS]:
        """
        Parser for PBSPro and OpenPBS
        """
        logger.debug(f"Received PBS parser with qstat output {qstat_output=}")
        _jobs_list = []

        if not "Jobs" in qstat_output.keys():
            return _jobs_list

        try:
            _jobs_count = len(qstat_output.get("Jobs"))
            logger.debug(f"Processing {_jobs_count} job")
            for _k, _v in qstat_output.get("Jobs").items():
                _job_pbs = SocaHpcJobPBS.model_construct()

                # Required Attributes from SocaHpcJob
                _job_pbs.job_id = _k.split(".")[0]
                _job_pbs.job_scheduler_info = self.scheduler_info
                _job_pbs.job_name = _v.get("Job_Name", None)
                _job_pbs.job_owner = (
                    _v.get("Job_Owner").split("@")[0] if _v.get("Job_Owner") else None
                )
                _job_pbs.job_queue = _v.get("queue", None)
                _job_pbs.job_error_log_path = (
                    _v.get("Error_Path").split(":")[-1]
                    if _v.get("Error_Path")
                    else None
                )
                _job_pbs.job_output_log_path = (
                    _v.get("Output_Path").split(":")[-1]
                    if _v.get("Output_Path")
                    else None
                )
                _job_pbs.job_working_directory = _v.get("Variable_List", {}).get(
                    "PBS_O_WORKDIR", None
                )
                _job_pbs.stack_id = _v.get("Resource_List", {}).get("stack_id", None)

                if _v.get("qtime", None) is not None:
                    _job_pbs.job_queue_time = _parse_pbs_time(_v.get("qtime"))

                # Normalized start/end (D3 timeline). stime appears once running; obittime on completion (-x)
                _job_pbs.job_start_time = _parse_pbs_time(_v.get("stime"))
                _end_time = _v.get("obittime")
                _state_cast = SocaCastEngine(data=_v.get("job_state", "")).cast_as(str)
                _state_str = (
                    _state_cast.get("message").lower()
                    if _state_cast.get("success") is True
                    else ""
                )
                if _end_time is None and _state_str in ("f", "e"):
                    _end_time = _v.get("mtime")
                _job_pbs.job_end_time = _parse_pbs_time(_end_time)

                _job_pbs.job_project = _v.get("Project", None)
                if _v.get("job_state", None) is not None:
                    _job_pbs.job_state = job_state_mapping(
                        state=_v.get("job_state"),
                        scheduler_provider=self.scheduler_info.provider,
                    )  # SOCA specific, used for logic
                    _job_pbs.job_scheduler_state = _v.get(
                        "job_state"
                    )  # Tracking as raw actual scheduler job state

                # Map SocaHpcJobResourceModel

                _resource_mapping = {
                    # PBS resource name : SocaHpcJobPbs attr
                    "nodect": "nodes",
                    "ncpus": "cpus",
                    "base_os": "base_os",
                    "instance_profile": "instance_profile",
                    "instance_ami": "instance_ami",
                    "instance_type": "instance_types",  # rewrite singular (legacy) to plural (new) if present
                    "instance_types": "instance_types",
                    "root_size": "root_size",
                    "scratch_iops": "scratch_iops",
                    "fsx_lustre": "fsx_lustre",
                    "fsx_lustre_size": "fsx_lustre_size",
                    "fsx_lustre_deployment_type": "fsx_lustre_deployment_type",
                    "fsx_lustre_per_unit_throughput": "fsx_lustre_per_unit_throughput",
                    "scratch_size": "scratch_size",
                    "security_groups": "security_groups",
                    "spot_allocation_count": "spot_allocation_count",
                    "spot_price": "spot_price",
                    "subnet_id": "subnet_ids",  # rewrite singular (legacy) to plural (new) if present
                    "subnet_ids": "subnet_ids",
                    "spot_allocation_strategy": "spot_allocation_strategy",
                    "keep_ebs": "keep_ebs",
                    "placement_group": "placement_group",
                    "efa_support": "efa_support",
                    "force_ri": "force_ri",
                    "ht_support": "ht_support",
                    "nested_virtualization": "nested_virtualization",
                    "select": "",
                    "retry_attempt": "job_failed_provisioning_retry_count",
                    "capacity_reservation_id": "capacity_reservation_id",
                    "error_message": "error_message",
                    "x_soca_aws_orchestration_method": "job_orchestration_method",
                }

                for _resource in _v.get("Resource_List", {}).keys():
                    _resource_value = _v.get("Resource_List", {}).get(_resource)
                    # Handle Licenses
                    if re.match(r"^(?!_lic_).+_lic_.+", _resource):
                        logger.debug(f"Found License {_resource}={_resource_value}")
                        _job_pbs.licenses.append(
                            SocaHpcJobLicense(name=_resource, count=_resource_value)
                        )

                    if _resource in _resource_mapping.keys():
                        attr = _resource_mapping.get(_resource)
                        if _resource_value is not None:
                            if (
                                _resource == "retry_attempt"
                            ):  # retry_attempt must be an integer
                                setattr(_job_pbs, attr, int(_resource_value))
                            elif _resource == "error_message":
                                _job_pbs.error_message = re.findall(
                                    r"ERROR_(.*?)_END_OF_ERROR", _resource_value
                                )
                            elif _resource == "x_soca_aws_orchestration_method":
                                _job_pbs.job_orchestration_method = (
                                    get_job_orchestration_mapping(value=_resource_value)
                                )
                            elif _resource == "capacity_reservation_id":
                                _job_pbs.capacity_reservation_id = (
                                    get_reservation_info_soca_capacity_reservation(
                                        capacity_reservation_id=_resource_value
                                    )
                                )
                            elif _resource == "select":
                                # select need a little bit of parsing to retrieve the compute_node
                                _resource_value = str(
                                    _resource_value
                                )  # force to string in case select value is just an integer (e.g: select=1 if there is no ncpus/ppn specified )
                                if "compute_node=" in _resource_value:
                                    _pattern = r"compute_node=([^:]+)(?::|$)"
                                    _match = re.search(_pattern, _resource_value)
                                    if _match:
                                        _job_pbs.job_compute_node = _match.group(1)
                                    else:
                                        logger.error(
                                            f"Unable to find the compute_node in {_resource_value} using regex {_pattern}"
                                        )
                                        _job_pbs.job_compute_node = "tbd"
                                else:
                                    _job_pbs.job_compute_node = "tbd"
                            else:
                                setattr(_job_pbs, attr, _resource_value)

                # Optional Attributes from SocaHpcJobPBS
                _job_pbs.pbs_job_name = _v.get("Job_Name", None)
                _job_pbs.pbs_job_owner = _v.get("Job_Owner", None).split("@")[0]
                _job_pbs.pbs_job_state = _v.get("job_state", None)
                _job_pbs.pbs_queue = _v.get("queue", None)
                _job_pbs.pbs_server = _v.get("server", None)
                _job_pbs.pbs_checkpoint = _v.get("Checkpoint", None)
                _job_pbs.pbs_ctime = _v.get("ctime", None)
                _job_pbs.pbs_hold_types = _v.get("Hold_Types", None)
                _job_pbs.pbs_error_path = _v.get("Error_Path", None)
                _job_pbs.pbs_output_path = _v.get("Output_Path", None)
                _job_pbs.pbs_join_path = _v.get("Join_Path", None)
                _job_pbs.pbs_keep_files = _v.get("Keep_Files", None)
                _job_pbs.pbs_mail_points = _v.get("Mail_Points", None)
                _job_pbs.pbs_mtime = _v.get("mtime", None)
                _job_pbs.pbs_priority = _v.get("Priority", None)
                _job_pbs.pbs_qtime = _v.get("qtime", None)
                _job_pbs.pbs_rerunable = _v.get("Rerunable", None)
                _job_pbs.pbs_resource_list = _v.get("Resource_List", {})
                _job_pbs.pbs_substate = _v.get("substate", None)
                _job_pbs.pbs_schedselect = _v.get("schedselect", None)
                _job_pbs.pbs_variable_list = _v.get("Variable_List", {})
                _job_pbs.pbs_euser = _v.get("euser", None)
                _job_pbs.pbs_egroup = _v.get("egroup", None)
                _job_pbs.pbs_queue_rank = _v.get("queue_rank", None)
                _job_pbs.pbs_queue_type = _v.get("queue_type", None)
                _job_pbs.pbs_comment = _v.get("comment", None)
                _job_pbs.pbs_etime = _v.get("etime", None)
                _job_pbs.pbs_submit_arguments = _v.get("Submit_arguments", None)
                _job_pbs.pbs_executable = _v.get("executable", None)
                _job_pbs.pbs_argument_list = _v.get("argument_list", None)
                _job_pbs.pbs_project = _v.get("project", None)
                _job_pbs.pbs_submit_host = _v.get("Submit_Host", None)

                # Retrieve the current job provisioning state
                _job_pbs.job_provisioning_state = _job_pbs.get_job_provisioning_state()

                logger.debug(f"Found PBS Job {_job_pbs}")
                # Add job to jobs list
                _jobs_list.append(_job_pbs)
            logger.debug(f"PBSParser: {_jobs_list}")
            return _jobs_list
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error(
                f"__pbs_parser: Error trying to parse qstat output due to {err} {exc_type} {fname} {exc_tb.tb_lineno}"
            )
        return _jobs_list
