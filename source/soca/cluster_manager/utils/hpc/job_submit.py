# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
import sys
import pathlib
from typing import Optional
import random
import string
import shutil
from utils.response import SocaResponse
from utils.subprocess_client import SocaSubprocessClient
from utils.datamodels.hpc.scheduler import get_schedulers
from utils.user_filesystems_acls import check_user_permission, Permissions
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider
from utils.hpc.scheduler_command_builder import (
    SocaHpcPBSJobCommandBuilder,
    SocaHpcLSFJobCommandBuilder,
    SocaHpcSlurmJobCommandBuilder,
)
import shlex
import pwd

from utils.error import SocaError
import base64

logger = logging.getLogger("soca_logger")


class SocaHpcJobSubmit:
    """
    Handles submission of High-Performance Computing (HPC) batch jobs to supported schedulers
    (Slurm, LSF, or PBS).

    This class provides a unified interface for submitting HPC jobs on behalf of a specified user.
    The submitted job will be owned and executed under the user account provided in the request.

    Supported submission methods:
        - **submit_script_path**: Submit a job using the filesystem path to a valid Slurm/LSF/PBS script.
        - **submit_encoded_payload**: Submit a job using a base64-encoded version of the job script.

    Notes:
        - The scheduler is automatically validated before submission.
        - The user must have appropriate permissions to read the script file.
        - All submissions are logged and executed with user context isolation.
        - Job submission commands are constructed based on the scheduler provider (e.g., `sbatch`, `bsub`, or `qsub`).

    Example:
        ```python
        response = SocaHpcJobSubmit(scheduler_id="default-openpbs", user="alice", cwd="/data/home/alice").submit_script_path(
            script_path="/data/home/alice/my_job.pbs"
        )

        encoded_payload = base64.b64encode(b"#!/bin/bash\n#PBS -N myjob........").decode("utf-8")
        response = SocaHpcJobSubmit(scheduler_id="default-openpbs", user="alice", cwd="/data/home/alice").submit_encoded_payload(
            payload=encoded_payload
        )

        if response.success:
            print(f"Job submitted successfully: {response.message}")
        else:
            print(f"Job submission failed: {response.message}")
        ```
    """

    def __init__(self, scheduler_id: str, user: str, cwd: Optional[str] = None):
        self._user = user
        self._all_schedulers = get_schedulers()
        self._scheduler = None
        self._cwd = cwd

        for _sched in self._all_schedulers:
            if _sched.identifier == scheduler_id:
                self._scheduler = _sched
                break

    def submit_script_path(self, script_path: str) -> SocaResponse:
        logger.info(
            f"Received SocaHpcJobSubmit submit_script_path request for {self._user} on {self._scheduler} via script path: {script_path}"
        )

        if not self._scheduler:
            return SocaError.GENERIC_ERROR(
                f"specified scheduler_id is invalid, must be one of {[s.identifier for s in self._all_schedulers]}"
            )

        _file_path = pathlib.Path(script_path)
        if not _file_path.exists():
            return SocaError.GENERIC_ERROR(
                helper=f"Script path {script_path=} does not exist"
            )
        logger.debug(f"Checking if {self._user} has READ permissions on {_file_path}")
        if (
            check_user_permission(
                user=self._user, permissions=Permissions.READ, path=_file_path
            )
            is True
        ):

            if self._scheduler.provider in [
                SocaHpcSchedulerProvider.OPENPBS,
                SocaHpcSchedulerProvider.PBSPRO,
            ]:
                _run_command = SocaHpcPBSJobCommandBuilder(
                    scheduler_info=self._scheduler
                ).qsub(args=f"{shlex.quote(_file_path.as_posix())}")

            elif self._scheduler.provider == SocaHpcSchedulerProvider.LSF:
                _run_command = SocaHpcLSFJobCommandBuilder(
                    scheduler_info=self._scheduler
                ).bsub(args=f"{shlex.quote(_file_path.as_posix())}")

            elif self._scheduler.provider == SocaHpcSchedulerProvider.SLURM:
                _run_command = SocaHpcSlurmJobCommandBuilder(
                    scheduler_info=self._scheduler
                ).sbatch(args=f"{shlex.quote(_file_path.as_posix())}")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"{self._scheduler.provider=} is not a recognized scheduler on SOCA, must be openpbs, slurm or lsf"
                )

            if not _run_command:
                return SocaError.GENERIC_ERROR(
                    helper="Unable to build run command for job submission"
                )

            # Extend the PATH to include potential binary_folder_paths
            _current_env = os.environ.copy()
            if self._scheduler.binary_folder_paths:
                _current_path = _current_env.get("PATH", "")
                _current_env["PATH"] = (
                    f"{self._scheduler.binary_folder_paths}:{_current_path}"
                )

            # remove SOCA specific environment variables
            for _key in list(_current_env.keys()):
                if _key.startswith("SOCA_"):
                    _current_env.pop(_key)

            _submit_job = SocaSubprocessClient(
                run_command=_run_command, run_as=self._user
            ).run(env=_current_env, timeout=10, cwd=self._cwd)
            if _submit_job.get("success") is True:
                _stdout = _submit_job.get("message").get("stdout")
                return SocaResponse(success=True, message=_stdout)
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to submit job due to {_submit_job.get('message')}"
                )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"User {self._user} does not have permission to read {script_path=}"
            )

    def submit_encoded_payload(
        self,
        payload: base64,
        submit_directory: Optional[str] = None,
    ) -> SocaResponse:
        logger.info(
            f"Received SocaHpcJobSubmit submit_encoded_payload request for {self._user} on {self._scheduler} via encoded payload"
        )
        if not self._scheduler:
            return SocaError.GENERIC_ERROR(
                f"specified scheduler_id is invalid, must be one of {[s.identifier for s in self._all_schedulers]}"
            )

        try:
            _plain_payload = base64.b64decode(payload).decode()
        except KeyError:
            return SocaError.GENERIC_ERROR(helper="Missing payload")
        except UnicodeError:
            return SocaError.GENERIC_ERROR(
                helper="payload (str) does not seems to be a valid base64 encoded string"
            )
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unknown error trying to read base64 payload {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )

        logger.debug(f"Job payload: {_plain_payload}")

        try:
            _random_id = "".join(
                random.choice(string.ascii_letters + string.digits) for _i in range(20)
            )
            _job_submit_file = f"job_submit_{_random_id}.sh"

            try:
                _user_info = pwd.getpwnam(self._user)
            except Exception as err:
                logger.error(
                    f"Unable to get {self._user} info because of {err}. Validate sssd.conf."
                )
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to get user info for {self._user}. Check logs for more details."
                )

            if submit_directory is None:
                _user_home = _user_info.pw_dir
                _job_submit_folder = f"{_user_home}/soca_job_output"
                _job_submit_script_path = f"{_job_submit_folder}/{_job_submit_file}"
                logger.info(
                    f"submit_directory not specified. Job script path will be stored on {_job_submit_script_path}, creating it ... "
                )
                os.makedirs(_job_submit_folder, exist_ok=True)
                logger.debug(
                    f"Applying 0o700 permission to {_job_submit_folder} and correct chown"
                )
                os.chmod(_job_submit_folder, 0o700)
                shutil.chown(
                    _job_submit_folder, user=_user_info.pw_name, group=_user_info.pw_gid
                )
            else:
                logger.info(
                    f"Using {submit_directory=}, checking if {self._user} has write permissions"
                )
                if (
                    check_user_permission(
                        path=submit_directory,
                        permissions=Permissions.WRITE,
                        user=self._user,
                    )
                    is False
                ):
                    return SocaError.GENERIC_ERROR(
                        helper=f"User {self._user} does not have WRITE permission on {submit_directory=}"
                    )
                else:
                    _job_submit_folder = f"{submit_directory}"
                    _job_submit_script_path = f"{_job_submit_folder}/{_job_submit_file}"

            logger.info(
                f"Job Submit Script Path: {_job_submit_script_path}, creating file "
            )

            _fd = os.open(
                _job_submit_script_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700
            )
            with os.fdopen(_fd, "w") as text_file:
                text_file.write(_plain_payload)
                # fchown/fchmod on the fd, not the path -- a symlink swapped in after close can't redirect the root op.
                os.fchown(text_file.fileno(), _user_info.pw_uid, _user_info.pw_gid)
                os.fchmod(text_file.fileno(), 0o700)

            logger.info(
                f"{_job_submit_script_path} created successfully, applying correct permissions"
            )

            logger.info(f"About to submit job via {_job_submit_script_path}")
            _submit_request = self.submit_script_path(
                script_path=_job_submit_script_path
            )
            if _submit_request.get("success") is True:
                return SocaResponse(
                    success=True, message=_submit_request.get("message")
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to submit job due to {_submit_request.get('message')}"
                )

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to submit job due to {err} on line {exc_tb.tb_lineno}"
            )


class SocaShellScriptSubmit:
    """
    Handles the submission of ad-hoc HPC jobs using a user-provided shell script payload.

    This class allows users to submit custom shell scripts to supported HPC environments
    (e.g., Slurm, LSF, PBS) by providing either a base64-encoded script payload.
    The submitted job runs under the ownership of the specified user account.

    The `submit_encoded_payload()` method is primarily intended for API-based submissions
    where a script is uploaded as base64 text and executed by the selected interpreter
    (e.g., `/bin/bash`, `/usr/bin/python`).

    Example:
        ```python
        encoded_script = base64.b64encode(b"#!/bin/bash\nwill_execute_custom_logic...").decode("utf-8")

        response = SocaShellScriptSubmit(scheduler_id="/bin/bash", user="alice", cwd="/data/home/alice").submit_encoded_payload(
            payload=encoded_script
        )

        if response.success:
            print(f"Script executed successfully: {response.message}")
        else:
            print(f"Script execution failed: {response.message}")
        ```
    """

    def __init__(self, interpreter: str, user: str, cwd: Optional[str] = None):
        self._interpreter = interpreter
        self._user = user
        self._cwd = cwd

    def submit_encoded_payload(
        self,
        payload: base64,
        submit_directory: Optional[str] = None,
    ) -> SocaResponse:
        logger.info(
            f"Received Submit SocaShellScriptSubmit request for {self._user} with interpreter {self._interpreter} via encoded payload"
        )
        try:
            _plain_payload = base64.b64decode(payload).decode()
        except KeyError:
            return SocaError.GENERIC_ERROR(helper="Missing payload")
        except UnicodeError:
            return SocaError.GENERIC_ERROR(
                helper="payload (str) does not seems to be a valid base64 encoded string"
            )
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unknown error trying to read base64 payload {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )

        logger.debug(f"Script payload: {_plain_payload}")

        try:
            _random_id = "".join(
                random.choice(string.ascii_letters + string.digits) for _i in range(20)
            )
            _job_submit_file = f"script_submit_{_random_id}.sh"

            try:
                _user_info = pwd.getpwnam(self._user)
            except Exception as err:
                logger.error(
                    f"Unable to get {self._user} info because of {err}. Validate sssd.conf."
                )
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to get user info for {self._user}. Check logs for more details."
                )

            if submit_directory is None:
                _user_home = _user_info.pw_dir
                _job_submit_folder = f"{_user_home}/soca_job_output"
                _job_submit_script_path = f"{_job_submit_folder}/{_job_submit_file}"
                logger.info(
                    f"submit_directory not specified. Job script path will be stored on {_job_submit_script_path}, creating it ... "
                )
                os.makedirs(_job_submit_folder, exist_ok=True)
                logger.debug(
                    f"Applying 0o700 permission to {_job_submit_folder} and correct chown"
                )
                os.chmod(_job_submit_folder, 0o700)
                shutil.chown(
                    _job_submit_folder, user=_user_info.pw_name, group=_user_info.pw_gid
                )
            else:
                logger.info(
                    f"Using {submit_directory=}, checking if {self._user} has write permissions"
                )
                if (
                    check_user_permission(
                        path=submit_directory,
                        permissions=Permissions.WRITE,
                        user=self._user,
                    )
                    is False
                ):
                    return SocaError.GENERIC_ERROR(
                        helper=f"User {self._user} does not have WRITE permission on {submit_directory=}"
                    )
                else:
                    _job_submit_folder = f"{submit_directory.rstrip('/')}"
                    _job_submit_script_path = f"{_job_submit_folder}/{_job_submit_file}"

            logger.info(
                f"Job Submit Script Path: {_job_submit_script_path}, creating file "
            )

            _fd = os.open(
                _job_submit_script_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700
            )
            with os.fdopen(_fd, "w") as text_file:
                text_file.write(_plain_payload)
                # fchown/fchmod on the fd, not the path -- a symlink swapped in after close can't redirect the root op.
                os.fchown(text_file.fileno(), _user_info.pw_uid, _user_info.pw_gid)
                os.fchmod(text_file.fileno(), 0o700)

            logger.info(
                f"{_job_submit_script_path} created successfully, applying correct permissions"
            )

            logger.info(f"About to submit script via {_job_submit_script_path}")
            _submit_request = SocaSubprocessClient(
                run_command=f"{self._interpreter} {shlex.quote(_job_submit_script_path)}",
                run_as=self._user,
            ).run(cwd=self._cwd, timeout=5)
            if _submit_request.get("success") is True:
                return SocaResponse(
                    success=True, message=_submit_request.get("message")
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to submit script due to {_submit_request.get('message')}"
                )

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to submit job due to {err} on line {exc_tb.tb_lineno}"
            )
