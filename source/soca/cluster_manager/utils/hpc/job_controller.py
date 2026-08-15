# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
import re
import time
import logging
import os
from utils.response import SocaResponse
from utils.subprocess_client import SocaSubprocessClient
from utils.error import SocaError
from utils.config import SocaConfig
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider
from utils.aws.cloudformation_client import SocaCfnClient
from utils.cast import SocaCastEngine
from typing import Any, Optional, Literal
from utils.hpc.scheduler_command_builder import (
    SocaHpcPBSJobCommandBuilder,
    SocaHpcLSFJobCommandBuilder,
    SocaHpcSlurmJobCommandBuilder,
)
from utils.datamodels.hpc.shared.job_resources import SocaHpcJobProvisioningState

import re

logger = logging.getLogger("soca_logger")


class SocaHpcJobController:

    def __init__(
        self,
        job: "SocaHpcJobLSF" | "SocaHpcJobPBS" | "SocaHpcJobSlurm",
    ):

        self._job = job
        self._scheduler_info = self._job.job_scheduler_info

    def set_error_message(self, errors: list) -> SocaResponse:
        # for openpbs, we assign all errors in the error_message resource
        # only alphanumeric chars are allowed, replace space with _
        logger.debug(
            f"Receive set_error_message for Job {self._job.job_id} with errors {errors}"
        )
        _sanitized_errors = []
        for error in errors:
            _sanitized_error = f"ERROR_{re.sub(r'[^a-zA-Z0-9_ ]', '', str(error)).replace(' ', '_')}_END_OF_ERROR"
            if _sanitized_error not in _sanitized_errors:
                _sanitized_errors.append(_sanitized_error)

        _errors_list = "_".join(_sanitized_errors)

        if self._scheduler_info.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:
            _update_error_message = self.pbs_update_resource(
                resource_name="error_message",
                resource_value=_errors_list,
            )

        elif self._scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
            _update_error_message = self.lsf_update_job_description(
                resource_name="error_message",
                resource_value=_errors_list,
            )

        elif self._scheduler_info.provider == SocaHpcSchedulerProvider.SLURM:
            _update_error_message = self.slurm_update_comment(
                resource_name="error_message",
                resource_value=_errors_list,
            )

        logging.info(
            "Error detected, setting job provisioning state to COMPUTE_PROVISIONING_BLOCKED"
        )
        self._job.job_provisioning_state = (
            SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_BLOCKED
        )

        if _update_error_message.get("success") is True:
            return SocaResponse(
                success=True, message="error_message updated successfully"
            )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to update error_message due to {_update_error_message.get('message')}"
            )

    def lsf_update_job_description(
        self,
        resource_name: str,
        resource_value: Optional[str] = "",
    ) -> SocaResponse:
        logger.info(
            f"Received LSF Update Job Description {resource_name=} / {resource_value=}"
        )
        # For LSF, SOCA parameters (instance_ami, instance_type, root_size etc ..) are specified via the job description (JOB_DESCRIPTION) and are soft request, not used by LSF but SOCA to provision relevant capacity based on job requirements
        # Use lsf_update_resource() to update compute_node
        if self._scheduler_info.provider != SocaHpcSchedulerProvider.LSF:
            return SocaError.GENERIC_ERROR(
                f"lsf_update_job_description is only available if the scheduler is LSF, found {self._scheduler_info}"
            )

        # Updates to -Jd are not reflecting instantly, giving some time to make sure LSF is updated correctly
        time.sleep(5)

        # get current job description (do not use lsf_job_description as it may be not have been refreshed by the dispatcher)
        _run_command = SocaHpcLSFJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).bjobs(args=f'-o "JOB_DESCRIPTION" -json {self._job.job_id}')
        if not _run_command:
            return SocaError.GENERIC_ERROR(
                helper="Unable to build bjobs command to retrieve current job description"
            )
        _get_current_job_description = SocaSubprocessClient(
            run_command=_run_command
        ).run()
        logger.debug(
            f"Retrieved current job description: {_get_current_job_description}"
        )
        if _get_current_job_description.get("success"):
            _get_output_as_json = SocaCastEngine(
                data=_get_current_job_description.get("message").get("stdout")
            ).as_json()
            if _get_output_as_json.get("success"):
                _current_job_description = (
                    _get_output_as_json.get("message")
                    .get("RECORDS")[0]
                    .get("JOB_DESCRIPTION")
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse {self._job.job_id=} description due to {_get_output_as_json.get('message')} - output received {_get_output_as_json.get('message')}"
                )

        logger.debug(f"{_current_job_description=}")
        if not _current_job_description:
            if resource_value:
                _new_job_description = f"{resource_name}={resource_value}"
            else:
                _new_job_description = ""
        else:
            # Regex to handle key=value, key = value, key==value
            # Match: key [=]+ [optional spaces] value
            _pattern = rf"(?<!\S){re.escape(resource_name)}\s*=+\s*[^ ]*"
            if resource_value == "":
                # remove resource_name if resource_value is set to ''
                _new_job_description = re.sub(
                    _pattern, "", _current_job_description
                ).strip()
            else:
                if re.search(_pattern, _current_job_description):
                    # replace if resource_name is already set
                    _new_job_description = re.sub(
                        _pattern,
                        f"{resource_name}={resource_value}",
                        _current_job_description,
                    )
                else:
                    # add new resource_name if not already there. Append any other values from the job description
                    _new_job_description = (
                        (
                            _current_job_description.strip()
                            + f" {resource_name}={resource_value}"
                        )
                        if _current_job_description.strip()
                        else f"{resource_name}={resource_value}"
                    )

        # Remove potential double space
        _new_job_description = re.sub(r"\s{2,}", " ", _new_job_description).strip()

        logger.debug(f"{_new_job_description=}")
        if _new_job_description == "":
            logger.info(f"{_new_job_description} is empty, ignoring ...")
            return SocaResponse(
                success=True, message="job_description is empty, no need to update it"
            )

        _run_command = SocaHpcLSFJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).bmod(args=f'-Jd "{_new_job_description}" {self._job.job_id}')
        if not _run_command:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build bmod command for {resource_name} to {resource_value} for job {self._job.job_id}"
            )

        _job_data = SocaSubprocessClient(run_command=_run_command).run()
        if _job_data.get("success") is True:
            logger.info(
                f"LSF Update Job Description for {resource_name=} / {resource_value=} updated successfully. New Description {_new_job_description=}"
            )
            return SocaResponse(
                success=True, message=_job_data.get("message").get("stdout")
            )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"LSF Unable to Update Job Description {resource_name} to {resource_value} for job {self._job.job_id} due to {_job_data.get('message')}"
            )

    def slurm_update_comment(
        self,
        resource_name: str,
        resource_value: Optional[str] = "",
    ) -> SocaResponse:
        logger.info(
            f"Received Slurm Update Comment {resource_name=} / {resource_value=}"
        )
        # For Slurm, SOCA parameters (instance_ami, instance_type, root_size etc ..) are specified via the --comment field and are soft request, not used by Slurm but SOCA to provision relevant capacity based on job requirements
        if self._scheduler_info.provider != SocaHpcSchedulerProvider.SLURM:
            return SocaError.GENERIC_ERROR(
                f"slurm_update_comment is only available if the scheduler is Slurm, found {self._scheduler_info}"
            )

        # Updates to -comment are not reflecting instantly, giving some time to make sure LSF is updated correctly
        time.sleep(5)

        # get current job comment (do not use  _job.comment as it may be not have been refreshed by the dispatcher)
        _run_command = SocaHpcSlurmJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).scontrol(args=f'-o "comment" -json {self._job.job_id}')
        if not _run_command:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build scontrol command for {resource_name} to {resource_value} for job {self._job.job_id}"
            )
        _get_current_job_comment = SocaSubprocessClient(run_command=_run_command).run()
        logger.debug(f"Retrieved current job comment: {_get_current_job_comment}")
        if _get_current_job_comment.get("success"):
            _get_output_as_json = SocaCastEngine(
                data=_get_current_job_comment.get("message").get("stdout")
            ).as_json()
            if _get_output_as_json.get("success"):
                _current_job_comment = (
                    _get_output_as_json.get("message")
                    .get("RECORDS")[0]
                    .get("JOB_DESCRIPTION")
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse {self._job.job_id=} comment due to {_get_output_as_json.get('message')} - output received {_get_output_as_json.get('message')}"
                )

        logger.debug(f"{_current_job_comment=}")
        if not _current_job_comment:
            if resource_value:
                _new_job_comment = f"{resource_name}={resource_value}"
            else:
                _new_job_comment = ""
        else:
            # Regex to handle key=value, key = value, key==value
            # Match: key [=]+ [optional spaces] value
            _pattern = rf"(?<!\S){re.escape(resource_name)}\s*=+\s*[^ ]*"
            if resource_value == "":
                # remove resource_name if resource_value is set to ''
                _new_job_comment = re.sub(_pattern, "", _current_job_comment).strip()
            else:
                if re.search(_pattern, _current_job_comment):
                    # replace if resource_name is already set
                    _new_job_comment = re.sub(
                        _pattern,
                        f"{resource_name}={resource_value}",
                        _current_job_comment,
                    )
                else:
                    # add new resource_name if not already there. Append any other values from the job description
                    _new_job_comment = (
                        (
                            _current_job_comment.strip()
                            + f" {resource_name}={resource_value}"
                        )
                        if _current_job_comment.strip()
                        else f"{resource_name}={resource_value}"
                    )

        # Remove potential double space
        _new_job_comment = re.sub(r"\s{2,}", " ", _new_job_comment).strip()

        logger.debug(f"{_new_job_comment=}")
        if _new_job_comment == "":
            logger.info(f"{_new_job_comment} is empty, ignoring ...")
            return SocaResponse(
                success=True, message="job_description is empty, no need to update it"
            )

        _run_command = (
            f"scontrol update job={self._job.job_id} comment='{_new_job_comment}'"
        )

        _job_data = SocaSubprocessClient(run_command=_run_command).run()
        if _job_data.get("success") is True:
            logger.info(
                f"Slurm Update Job Comment for {resource_name=} / {resource_value=} updated successfully. New Comment {_new_job_comment=}"
            )
            return SocaResponse(
                success=True, message=_job_data.get("message").get("stdout")
            )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Slurm Unable to Update Job Comment {resource_name} to {resource_value} for job {self._job.job_id} due to {_job_data.get('message')}"
            )

    def lsf_update_resource(
        self,
        resource_name: str,
        resource_value: Any,
        resource_type: Literal["String", "Numeric", "Boolean"] = "String",
    ) -> SocaResponse:
        logger.info(
            f"Received LSF Update Resource for {resource_name=} / {resource_value=}"
        )
        # For LSF, resource configured via -R or RES_REQ is limited to only `compute_node`.
        # Note: only NUMERIC/Boolean resources can be added to RES_REQ. String will be attach to the nodes but can't be used as RES_REQ
        #  These are hard request, meaning LSF will provision capacity only on hosts that have the same associated compute_node
        # For SOCA parameters (instance_ami, instance_type, root_size etc ..) use lsf_update_job_description
        if self._scheduler_info.provider != SocaHpcSchedulerProvider.LSF:
            return SocaError.GENERIC_ERROR(
                f"lsf_update_resource is only available if the scheduler is LSF, found {self._scheduler_info}"
            )

        if resource_type == "String":
            _select = f"'select[{resource_name}=='{resource_value}']'"
        elif resource_type == "Numeric":
            _select = f"'select[{resource_name}=={resource_value}]'"
        elif resource_type == "Boolean":
            _select = f"'select[{resource_name}]'"
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"resource_type must be String, Numeric or Boolean, received {resource_type=}"
            )

        _run_command = SocaHpcLSFJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).bmod(args=f"-R {_select} {self._job.job_id}")
        if not _run_command:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build bmod command for {resource_name} to {resource_value} for job {self._job.job_id}"
            )
        _job_data = SocaSubprocessClient(run_command=_run_command).run()
        if _job_data.get("success") is True:
            logger.info(
                f"LSF Update Resource for {resource_name=} / {resource_value=} updated successfully"
            )
            return SocaResponse(
                success=True, message=_job_data.get("message").get("stdout")
            )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to update LSF resource {resource_name} to {resource_value} for job {self._job.job_id} due to {_job_data.get('message')}"
            )

    def pbs_update_resource(
        self, resource_name: str, resource_value: Any
    ) -> SocaResponse:
        logger.info(
            f"Received PBS Update Resource for {resource_name=} / {resource_value=}"
        )
        if not self._scheduler_info.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:
            return SocaError.GENERIC_ERROR(
                f"pbs_update_resource is only available if the scheduler is PBS, found {self._scheduler_info}"
            )

        if resource_value is None or resource_value == "":
            logger.info(
                f"Found empty value for {resource_name=}, removing it from job resource requirement"
            )
            _run_command = SocaHpcPBSJobCommandBuilder(
                scheduler_info=self._scheduler_info
            ).qalter(args=f"-l {resource_name} {self._job.job_id}")
        else:
            _run_command = SocaHpcPBSJobCommandBuilder(
                scheduler_info=self._scheduler_info
            ).qalter(args=f"-l {resource_name}={resource_value} {self._job.job_id}")

        if not _run_command:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build qalter command for {resource_name} to {resource_value} for job {self._job.job_id}"
            )

        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self._scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self._scheduler_info.binary_folder_paths}:{_current_path}"
            )

        _job_data = SocaSubprocessClient(run_command=_run_command).run(env=_current_env)
        if _job_data.get("success") is True:
            logger.info(
                f"PBS Update Resource for {resource_name=} / {resource_value=} updated successfully"
            )
            return SocaResponse(
                success=True, message=_job_data.get("message").get("stdout")
            )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to update resource {resource_name} to {resource_value} for job {self._job.job_id} due to {_job_data.get('message')}"
            )

    def reset_cloudformation_stack_creation(
        self,
    ) -> SocaResponse:
        """
        This function reset job.compute_node and delete the current associated cloudformation stack id for SOCA to create a new one for the job in the next cycle
        """
        if (
            _check_grace_period := SocaConfig(
                key="/system/orchestration/stack_grace_period_in_minutes"
            ).get_value(return_as=int)
        ).get("success"):
            stack_grace_period_in_minutes = _check_grace_period.get("message")
        else:
            logger.error(f"{_check_grace_period} is not a valid integer, default to 45")
            stack_grace_period_in_minutes = 45

        _current_retry_count = self._job.job_failed_provisioning_retry_count
        logger.info(
            f"Current retry Count for {self._job.job_id=} is {_current_retry_count}"
        )
        # Note: Grace priod does not apply if the stack state is in error. (e.g: no point in waiting 30 minutes if the stack is already CREATE_FAILED)
        # Grace period only apply if the capacity is being/has been provisioned correctly
        if (
            self._job.job_provisioning_state
            and self._job.job_provisioning_state
            not in (
                SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_BLOCKED,
                SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_ERROR,
            )
        ):

            _stack_older_than = SocaCfnClient(
                stack_name=self._job.stack_id
            ).is_stack_older_than(minutes=stack_grace_period_in_minutes)
            if _stack_older_than.get("success") is False:
                # Return HTTP 201. The stack cannot be rebuilt, but this is considered a non-blocking rewrite
                # see dispatcher.py
                return SocaResponse(
                    success=True,
                    status_code=201,
                    message=f"Stack for job {self._job.job_id} won't be rebuilt because it was created less than {stack_grace_period_in_minutes} minutes ago.{_stack_older_than.get('message')}",
                )

        logger.info(
            f"Stack is outside of the grace period, received Job CloudFormation Stack Rebuild for {self._job.job_id}, ({_current_retry_count=})"
        )

        _delete_stack = SocaCfnClient(stack_name=self._job.stack_id).delete_stack(
            ignore_missing_stack=True
        )
        if _delete_stack.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete stack {self._job.stack_id} for job {self._job.job_id} due to {_delete_stack.get('message')}"
            )
        else:
            logger.info(
                f"Successfully deleted stack {self._job.stack_id} for job {self._job.job_id}"
            )

        if self._job.job_scheduler_info.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:
            logger.info("Detected OpenPBS/PBSPro job, updating select resource")
            _resource_selector_name = "select"
            # remove compute_node if there
            _select_clean = re.sub(r':?compute_node=[^:\s]*', '', self._job.pbs_resource_list.get('select'))
            _resource_selector_value = f"{_select_clean}:compute_node=tbd"

        elif self._scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
            logger.info("Detected LSF job, updating RES_REQ resource")
            _resource_selector_name = "compute_node"
            _resource_selector_value = "tbd"

        elif self._scheduler_info.provider == SocaHpcSchedulerProvider.Slurm:
            logger.info("Detected Slurm job, updating Constraint resource")
            _resource_selector_name = "compute_node"
            _resource_selector_value = "tbd"

        logger.info(
            f"Updating {_resource_selector_name=} to {_resource_selector_value=}"
        )
        _resources_to_update = {
            _resource_selector_name: _resource_selector_value,
            "stack_id": "",
            "retry_attempt": _current_retry_count + 1,
        }

        for resource_name, resource_value in _resources_to_update.items():
            if self._scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
                _update_resource = SocaHpcJobController(
                    job=self._job
                ).lsf_update_resource(
                    resource_name=resource_name,
                    resource_value=resource_value,
                    resource_type=(
                        "Numeric"
                        if resource_name == _resource_selector_name
                        else "String"
                    ),
                )
            else:
                _update_resource = SocaHpcJobController(
                    job=self._job
                ).pbs_update_resource(
                    resource_name=resource_name, resource_value=resource_value
                )

            if _update_resource.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to update resource {resource_name} to {resource_value} for job {self._job.job_id} due to {_update_resource.get('message')}"
                )
            else:
                logger.info(
                    f"Successfully updated resource {resource_name} to {resource_value} for job {self._job.job_id}"
                )
        return SocaResponse(success=True, message="Stack Refreshed")

    def delete_job(self) -> SocaResponse:
        if self._scheduler_info.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:
            _run_command = SocaHpcPBSJobCommandBuilder(
                scheduler_info=self._scheduler_info
            ).qdel(args=f"{self._job.job_id} -W force")
        elif self._scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
            _run_command = SocaHpcLSFJobCommandBuilder(
                scheduler_info=self._scheduler_info
            ).bkill(args=f"{self._job.job_id}")
        elif self._scheduler_info.provider == SocaHpcSchedulerProvider.SLURM:
            _run_command = SocaHpcSlurmJobCommandBuilder(
                scheduler_info=self._scheduler_info
            ).scancel(args=f"{self._job.job_id}")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete job {self._job.job_id} due to unsupported scheduler {self._scheduler_info.provider}"
            )

        if not _run_command:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build run command for {self._scheduler_info.provider=}, see logs for additional details"
            )
        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self._scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self._scheduler_info.binary_folder_paths}:{_current_path}"
            )
        _delete_job = SocaSubprocessClient(run_command=_run_command).run(
            env=_current_env
        )
        if _delete_job.get("success") is True:
            return SocaResponse(success=True, message=_delete_job.get("message"))
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete job {self._job.job_id} due to {_delete_job.get('message')}"
            )
