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
    SocaHpcPCSJobCommandBuilder
)
from utils.hpc.job_dependencies import (
    SocaJobDependencyType,
    build_dependency_arg,
    client_error,
    coerce_dependency_type,
    find_cycle,
    max_chain_stages,
    max_parents_per_stage,
    short_job_id,
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

    def submit_script_path(
        self,
        script_path: str,
        depends_on: Optional[list] = None,
        dependency_type=SocaJobDependencyType.AFTER_OK,
        hold: bool = False,
    ) -> SocaResponse:
        """
        Submit `script_path` as `self._user`.

        depends_on       job ids this submission must wait for, or None
        dependency_type  when the wait is satisfied, see SocaJobDependencyType
        hold             submit held, so the job cannot start until released.
                         Used by submit_chain to wire a whole graph before any
                         part of it runs.
        """
        logger.info(
            f"Received SocaHpcJobSubmit submit_script_path request for {self._user} on {self._scheduler} via script path: {script_path}"
        )

        if not self._scheduler:
            return SocaError.GENERIC_ERROR(
                f"specified scheduler_id is invalid, must be one of {[s.identifier for s in self._all_schedulers]}"
            )

        # Built before the permission check so an invalid dependency is refused
        # without touching the filesystem.
        _extra_args = []
        if hold:
            _extra_args.append(self._hold_flag())
        if depends_on:
            _dependency_arg = build_dependency_arg(
                provider=self._scheduler.provider,
                dependency_type=dependency_type,
                job_ids=depends_on,
            )
            if _dependency_arg.get("success") is False:
                return _dependency_arg
            _extra_args.append(_dependency_arg.get("message"))
        _prefix = (" ".join(_arg for _arg in _extra_args if _arg) + " ") if _extra_args else ""

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
                ).qsub(args=f"{_prefix}{shlex.quote(_file_path.as_posix())}")

            elif self._scheduler.provider == SocaHpcSchedulerProvider.LSF:
                _run_command = SocaHpcLSFJobCommandBuilder(
                    scheduler_info=self._scheduler
                ).bsub(args=f"{_prefix}{shlex.quote(_file_path.as_posix())}")

            elif self._scheduler.provider == SocaHpcSchedulerProvider.SLURM:
                _run_command = SocaHpcSlurmJobCommandBuilder(
                    scheduler_info=self._scheduler
                ).sbatch(args=f"{_prefix}{shlex.quote(_file_path.as_posix())}")
            
            elif self._scheduler.provider == SocaHpcSchedulerProvider.AWS_PCS:
                _run_command = SocaHpcPCSJobCommandBuilder(
                    scheduler_info=self._scheduler
                ).sbatch(args=f"{_prefix}{shlex.quote(_file_path.as_posix())}")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"{self._scheduler.provider=} is not a recognized scheduler on SOCA, must be openpbs, aws_pcs, slurm or lsf"
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
        depends_on: Optional[list] = None,
        dependency_type=SocaJobDependencyType.AFTER_OK,
        hold: bool = False,
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
                script_path=_job_submit_script_path,
                depends_on=depends_on,
                dependency_type=dependency_type,
                hold=hold,
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


    def _hold_flag(self) -> str:
        """The submit flag that queues a job without letting it start."""
        if self._scheduler.provider in (
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ):
            return "-h"
        if self._scheduler.provider in (
            SocaHpcSchedulerProvider.SLURM,
            SocaHpcSchedulerProvider.AWS_PCS,
        ):
            return "--hold"
        if self._scheduler.provider == SocaHpcSchedulerProvider.LSF:
            return "-H"
        return ""

    def _is_pbs(self) -> bool:
        return self._scheduler.provider in (
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        )

    def _run_as_user(self, run_command: str, timeout: int = 15) -> SocaResponse:
        """Run a prebuilt scheduler command as the submitting user."""
        _current_env = os.environ.copy()
        if self._scheduler.binary_folder_paths:
            _current_env["PATH"] = (
                f"{self._scheduler.binary_folder_paths}:{_current_env.get('PATH', '')}"
            )
        for _key in list(_current_env.keys()):
            if _key.startswith("SOCA_"):
                _current_env.pop(_key)

        return SocaSubprocessClient(run_command=run_command, run_as=self._user).run(
            env=_current_env, timeout=timeout, cwd=self._cwd
        )

    def _pbs_delete_jobs(self, job_ids: list) -> None:
        """
        Best effort removal, used to roll back a chain that failed part way.

        Deleted newest first: deleting a parent while a dependent is still
        registered against it leaves the dependent behind, so dependents go
        first.
        """
        _builder = SocaHpcPBSJobCommandBuilder(scheduler_info=self._scheduler)
        for _job_id in reversed(job_ids):
            _delete = self._run_as_user(
                _builder.qdel(args=f"{shlex.quote(str(_job_id))}")
            )
            if _delete.get("success") is False:
                logger.error(
                    f"Unable to roll back chain job {_job_id}: {_delete.get('message')}"
                )

    def submit_chain(
        self,
        stages: list,
        submit_directory: Optional[str] = None,
        dependency_type=SocaJobDependencyType.AFTER_OK,
    ) -> SocaResponse:
        """
        Submit several jobs as one dependency graph, or submit none of them.

        `stages` is an ordered list of dicts:

            {
              "payload":         base64 job script (required),
              "depends_on":      [index, ...] into `stages`, default [] (a root),
              "dependency_type": overrides the graph default for this stage,
              "name":            label echoed back, for the caller's display
            }

        Message on success is a list of
        {"index", "name", "job_id", "depends_on": [job_id, ...]}.

        On PBS every stage is submitted HELD, the edges are wired with qalter,
        and only then are the holds released. Three reasons it is done that
        way rather than passing the dependency at submit time:

        - a stage cannot start, and so cannot finish, before the graph it
          belongs to is complete;
        - a failure part way leaves nothing running to clean up around, so the
          rollback is just a delete of what was submitted;
        - the graph is validated for cycles first, which the scheduler itself
          does not do. It accepts a cycle and the jobs then wait on each other
          with no timeout.

        Releasing clears only the user hold placed here. A stage whose
        dependency is still unsatisfied keeps the scheduler's own hold and
        stays queued, which is the desired end state.
        """
        logger.info(
            f"Received submit_chain request for {self._user} on {self._scheduler} with {len(stages or [])} stage(s)"
        )

        if not self._scheduler:
            return client_error(
                f"specified scheduler_id is invalid, must be one of {[s.identifier for s in self._all_schedulers]}"
            )

        if not stages:
            return client_error("A job chain needs at least one stage")

        _count = len(stages)
        _max_stages = max_chain_stages()
        if _count > _max_stages:
            return client_error(
                (
                    f"A job chain is limited to {_max_stages} stage(s), received {_count}. "
                    f"Raise /configuration/HPC/JobChain/MaxStages to allow more."
                )
            )
        _max_parents = max_parents_per_stage()

        # Validate shape and edges before anything is written or submitted.
        _prerequisites = {}
        for _index, _stage in enumerate(stages):
            if not isinstance(_stage, dict) or not _stage.get("payload"):
                return client_error(
                    f"Chain stage {_index} is missing its payload"
                )
            # Checked before any falsy-to-empty coercion: `depends_on: 0` is a
            # bare index rather than a list, and 0 is falsy, so coercing first
            # would silently turn "depends on stage 0" into "depends on
            # nothing" and let the stage run immediately.
            _depends_on = _stage.get("depends_on")
            if _depends_on is None:
                _depends_on = []
            if not isinstance(_depends_on, (list, tuple)):
                return client_error(
                    f"Chain stage {_index} depends_on must be a list of stage indexes"
                )
            _parents = set()
            for _parent in _depends_on:
                if not isinstance(_parent, int) or isinstance(_parent, bool):
                    return client_error(
                        f"Chain stage {_index} depends_on must contain stage indexes, received {_parent!r}"
                    )
                if _parent == _index:
                    return client_error(
                        f"Chain stage {_index} cannot depend on itself"
                    )
                if _parent < 0 or _parent >= _count:
                    return client_error(
                        f"Chain stage {_index} depends on stage {_parent}, which is not in this chain"
                    )
                _parents.add(_parent)

            # 0 means no separate fan-in limit; the stage count already bounds it.
            if _max_parents and len(_parents) > _max_parents:
                return client_error(
                    (
                        f"Chain stage {_index} waits on {len(_parents)} parents, which is "
                        f"more than the {_max_parents} allowed. Raise "
                        f"/configuration/HPC/JobChain/MaxParentsPerStage to allow more, "
                        f"or set it to 0 to bound fan-in only by the stage count."
                    )
                )
            _prerequisites[_index] = _parents

            if _stage.get("dependency_type") is not None:
                _coerced = coerce_dependency_type(_stage.get("dependency_type"))
                if _coerced.get("success") is False:
                    return _coerced

        _cycle = find_cycle(_prerequisites)
        if _cycle:
            return client_error(
                (
                    "Job chain contains a circular dependency through stage(s) "
                    f"{' -> '.join(str(_node) for _node in _cycle)}. The scheduler "
                    "would accept it and the jobs would wait on each other forever."
                )
            )

        # Parents before children, so a parent's real job id is known by the
        # time its child is wired.
        _order = []
        _placed = set()
        while len(_order) < _count:
            _progressed = False
            for _index in range(_count):
                if _index in _placed:
                    continue
                if _prerequisites[_index] <= _placed:
                    _order.append(_index)
                    _placed.add(_index)
                    _progressed = True
            if not _progressed:
                # find_cycle already covers this; kept so the loop cannot spin.
                return client_error(
                    "Job chain dependencies cannot be ordered"
                )

        _hold_for_wiring = self._is_pbs()
        _job_ids = {}
        _submitted = []

        for _index in _order:
            _stage = stages[_index]
            _stage_type = _stage.get("dependency_type") or dependency_type
            _parent_ids = [_job_ids[_parent] for _parent in sorted(_prerequisites[_index])]

            # On PBS the edge is attached afterwards, so nothing can start
            # mid-build. Elsewhere the parents are already submitted, so the
            # dependency goes on at submit time.
            _submit = self.submit_encoded_payload(
                payload=_stage.get("payload"),
                submit_directory=submit_directory,
                depends_on=None if _hold_for_wiring else (_parent_ids or None),
                dependency_type=_stage_type,
                hold=_hold_for_wiring,
            )
            if _submit.get("success") is False:
                if _hold_for_wiring:
                    self._pbs_delete_jobs(_submitted)
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Chain stage {_index} failed to submit, "
                        f"{len(_submitted)} earlier stage(s) rolled back: {_submit.get('message')}"
                    )
                )

            _stdout = str(_submit.get("message") or "").strip()
            _job_id = _stdout.split()[0] if _stdout else ""
            if not _job_id:
                if _hold_for_wiring:
                    self._pbs_delete_jobs(_submitted)
                return SocaError.GENERIC_ERROR(
                    helper=f"Chain stage {_index} returned no job id from the scheduler"
                )

            _job_ids[_index] = _job_id
            _submitted.append(_job_id)

        if _hold_for_wiring:
            _builder = SocaHpcPBSJobCommandBuilder(scheduler_info=self._scheduler)

            for _index in _order:
                _parents = sorted(_prerequisites[_index])
                if not _parents:
                    continue
                _stage_type = stages[_index].get("dependency_type") or dependency_type
                _dependency_arg = build_dependency_arg(
                    provider=self._scheduler.provider,
                    dependency_type=_stage_type,
                    job_ids=[_job_ids[_parent] for _parent in _parents],
                )
                if _dependency_arg.get("success") is False:
                    self._pbs_delete_jobs(_submitted)
                    return _dependency_arg

                _alter = self._run_as_user(
                    _builder.qalter(
                        args=f"{_dependency_arg.get('message')} {shlex.quote(_job_ids[_index])}"
                    )
                )
                if _alter.get("success") is False:
                    self._pbs_delete_jobs(_submitted)
                    return SocaError.GENERIC_ERROR(
                        helper=(
                            f"Unable to attach dependency to chain stage {_index} "
                            f"({_job_ids[_index]}), whole chain rolled back: {_alter.get('message')}"
                        )
                    )

            # Release only the hold placed above. An unsatisfied dependency
            # keeps its own hold and the stage correctly stays queued.
            for _index in _order:
                _release = self._run_as_user(
                    _builder.qrls(args=f"-h u {shlex.quote(_job_ids[_index])}")
                )
                if _release.get("success") is False:
                    self._pbs_delete_jobs(_submitted)
                    return SocaError.GENERIC_ERROR(
                        helper=(
                            f"Unable to release chain stage {_index} "
                            f"({_job_ids[_index]}), whole chain rolled back: {_release.get('message')}"
                        )
                    )

        _result = []
        for _index in range(_count):
            _result.append(
                {
                    "index": _index,
                    "name": stages[_index].get("name"),
                    "job_id": _job_ids[_index],
                    "short_job_id": short_job_id(_job_ids[_index]),
                    "depends_on": [
                        _job_ids[_parent] for _parent in sorted(_prerequisites[_index])
                    ],
                }
            )

        _chain_job_ids = [_stage.get("job_id") for _stage in _result]
        logger.info(
            f"Job chain submitted: {len(_result)} stage(s), job ids {_chain_job_ids}"
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Job chain stage detail: {_result}")
        return SocaResponse(success=True, message=_result)


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
