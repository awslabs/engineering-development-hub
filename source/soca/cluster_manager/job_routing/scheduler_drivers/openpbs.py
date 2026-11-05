######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
The OpenPBS and PBS Pro driver.

Built on the shipped HPC helpers rather than on raw subprocess calls, which is a
correction to the first revision of this change:

  SocaHpcPBSJobCommandBuilder  builds every scheduler command. It sources pbs.conf
                               and sets PATH explicitly, because EDH installs PBS
                               under a per-cluster prefix that is on no default
                               PATH. My own version guessed that path.
  SocaHpcJobSubmit             submits. It writes the script with O_EXCL and 0o700,
                               fixes ownership, and runs qsub as the submitting user.
  SocaSubprocessClient         runs the command, and carries `run_as` so the
                               privilege drop is not hand-rolled here.
  SocaCastEngine               parses the JSON that PBS returns.

This module is allowed to reach Flask, unlike `base.py` beside it. The driver only
ever runs inside the web process: the routing daemon and the PBS queuejob hook use
the vocabulary in `base.py` and never this file. The first revision applied the
Flask-free pin to the whole package by reflex, which is why it reimplemented PBS
path resolution and skipped job-name sanitizing entirely.

One thing is still decided here rather than delegated. A JobSpec arrives from another
cluster, and `attributes["owner"]` is whatever that cluster put there, so the local
account a job runs as is chosen by THIS cluster and never read from the spec. The
reference implementation read it from the spec and then dropped privileges to it,
which let a peer name any local user. The requester is still recorded, as a job
comment, because who asked and what to run as are different questions.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shlex
from typing import Dict, List, Optional

from utils.cast import SocaCastEngine
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider, get_schedulers
from utils.hpc.job_submit import SocaHpcJobSubmit
from utils.hpc.scheduler_command_builder import SocaHpcPBSJobCommandBuilder
from utils.subprocess_client import SocaSubprocessClient

from .base import (
    QUEUE_PARKING,
    JobSpec,
    JobView,
    NormalizedState,
)

logger = logging.getLogger("soca_logger")

DEFAULT_SUBMIT_USER = "edhadmin"
DEFAULT_TIMEOUT_SECONDS = 30

# PBS reports job_state as a single character. Mapped to one vocabulary so a state
# means the same thing whichever cluster reports it.
#
# The held and suspended states all map to PARKED because that is what a delegated
# job looks like locally: present, not running, and waiting on something that is not
# local resources.
_PBS_STATE = {
    "t": NormalizedState.ROUTING,  # transit
    "q": NormalizedState.SUBMITTED,  # queued
    "h": NormalizedState.PARKED,  # held
    "s": NormalizedState.PARKED,  # suspended
    "u": NormalizedState.PARKED,  # user-suspended
    "w": NormalizedState.SUBMITTED,  # waiting
    "r": NormalizedState.ACTIVE,  # running
    "e": NormalizedState.EXITING,  # exiting
    "b": NormalizedState.ACTIVE,  # begun, job array
    "m": NormalizedState.ROUTING,  # moved
    "f": NormalizedState.COMPLETED,  # finished, exit status refines this
    "x": NormalizedState.COMPLETED,  # expired, subjob finished
}

_TRUE_WORDS = frozenset({"true", "1", "yes"})

# A POSIX environment variable name. Anything else is refused rather than escaped,
# because an assignment's left-hand side is not a place quoting can protect: the shell
# parses `export A=1; cmd` as two statements before any quoting on the value applies.
# The name arrives from another cluster like everything else in a JobSpec.
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Any control character, which is refused in anything emitted onto a `#PBS` line.
#
# A directive is a shell COMMENT, and `#` comments out only its own physical line. The
# shell does no quote tracking inside a comment, so `shlex.quote` is inert there: a value
# carrying a newline ends the comment and whatever follows becomes a command. Refusing is
# the only option, because there is no escaping that survives a line break in a comment.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _reject_control_characters(field: str, value: str) -> str:
    """
    Return `value` unchanged, or refuse it if it carries a control character.

    Used for every value emitted onto a `#PBS` directive line. See `_CONTROL_CHARS` for
    why quoting cannot substitute for this.
    """
    if _CONTROL_CHARS.search(value):
        raise ValueError(
            f"{field} carries a control character, which cannot appear on a #PBS "
            "directive line: a directive is a shell comment, so a newline ends it and "
            "the next line would be executed. Refusing rather than escaping."
        )
    return value

_PBS_PROVIDERS = (
    SocaHpcSchedulerProvider.OPENPBS,
    SocaHpcSchedulerProvider.PBSPRO,
)


class PBSCommandError(RuntimeError):
    """
    A scheduler command failed, or its output could not be read.

    Raised rather than returned because this is the driver layer, whose protocol is
    declared in the Flask-free `base.py` and returns plain values. The endpoint that
    calls a driver is where a `SocaResponse` is built, which is the layer the return
    type standard is written for.
    """


def submit_user() -> str:
    """
    The local account a routed job runs as.

    Read from this cluster's own environment, never from the incoming spec. PBS
    refuses to run a job as root, so something has to be chosen, and the receiving
    cluster is the only party that can safely choose it.
    """
    return (os.environ.get("EDH_REMOTE_SUBMIT_USER") or "").strip() or DEFAULT_SUBMIT_USER


def build_job_script(spec: JobSpec, *, job_name: Optional[str] = None) -> str:
    """
    The submission script for a spec, as PBS directives plus the command.

    Every command element is quoted with `shlex.quote`. The reference joined them
    with a space, so an element containing whitespace became several arguments and one
    containing `;` or a backtick became additional commands. The elements arrive from
    another cluster, so this is the boundary where that has to be got right.

    Resources and the queue are emitted as `#PBS` directives rather than qsub flags,
    because the shipped submit path takes a script and lets the script speak for
    itself. `job_name` is passed in already normalized, since sanitizing it is the
    builder's job.

    Two kinds of refusal, both because quoting has a limit and this is where untrusted
    fields meet a shell. An environment variable NAME is validated because the shell
    splits `export A=1; cmd` into statements before quoting the value matters. Anything
    emitted onto a `#PBS` line is checked for control characters because a directive is
    a shell COMMENT, and `#` comments out only its own physical line: a value carrying a
    newline ends the comment and the next line runs. `shlex.quote` is inert inside a
    comment, so there is nothing to escape with.
    """
    if not spec.command:
        raise ValueError("a job spec must carry a command")

    lines = ["#!/bin/sh"]
    if spec.target_queue:
        queue = _reject_control_characters("target_queue", spec.target_queue)
        lines.append(f"#PBS -q {shlex.quote(queue)}")
    if job_name:
        # Already restricted to PBS's own character set by the shipped builder's
        # normalize_job_name, so it cannot carry a control character. Checked anyway,
        # so this function's guarantee does not depend on a caller having done it.
        lines.append(
            f"#PBS -N {shlex.quote(_reject_control_characters('job name', job_name))}"
        )
    for key, value in sorted(spec.resources.items()):
        _reject_control_characters(f"resource name {key!r}", key)
        _reject_control_characters(f"resource {key!r}", value)
        lines.append(f"#PBS -l {shlex.quote(f'{key}={value}')}")

    requested_by = (spec.attributes.get("owner") or "").strip()
    if requested_by:
        _reject_control_characters("owner", requested_by)
        lines.append(f"#PBS -W {shlex.quote(f'comment=requested by {requested_by}')}")

    for key, value in sorted(spec.environment.items()):
        # The NAME is validated, not quoted. `shlex.quote` protects a value, but the
        # left-hand side of an assignment is not a value: the shell splits
        # `export A=1; cmd` into two statements before quoting on the right-hand side
        # means anything. A peer supplying a name containing `;` would therefore run
        # its own commands, which is what happened before this check existed.
        if not _ENV_NAME.match(key):
            raise ValueError(
                f"environment variable name {key!r} is not a POSIX name; refusing "
                "rather than escaping, since an assignment's left-hand side cannot "
                "be protected by quoting"
            )
        lines.append(f"export {key}={shlex.quote(value)}")

    lines.append(" ".join(shlex.quote(part) for part in spec.command))
    return "\n".join(lines) + "\n"


class OpenPBSDriver:
    """
    The PBS-family driver.

    `scheduler_id` names which registered scheduler to drive, the same identifier
    `SocaHpcJobSubmit` and `SocaHpcJobFetcher` take, so a controller with more than
    one scheduler configured is addressed the same way here as everywhere else.
    """

    engine_name = "openpbs"

    def __init__(self, scheduler_id: str, *, run_as: Optional[str] = None):
        self._scheduler_id = scheduler_id
        self._run_as = run_as or submit_user()
        self._scheduler_info = None

    # ------------------------------------------------------------------ helpers

    def _scheduler(self):
        """The registered scheduler this driver drives, resolved once."""
        if self._scheduler_info is not None:
            return self._scheduler_info

        for scheduler in get_schedulers():
            if scheduler.identifier == self._scheduler_id:
                if scheduler.provider not in _PBS_PROVIDERS:
                    raise PBSCommandError(
                        f"scheduler {self._scheduler_id!r} is a "
                        f"{scheduler.provider} scheduler, not PBS"
                    )
                self._scheduler_info = scheduler
                return scheduler

        raise PBSCommandError(f"no scheduler registered as {self._scheduler_id!r}")

    def _builder(self) -> SocaHpcPBSJobCommandBuilder:
        return SocaHpcPBSJobCommandBuilder(scheduler_info=self._scheduler())

    def _run(self, command: str, *, as_user: Optional[str] = None) -> str:
        """
        Run one built command and return its stdout.

        `command` must come from the builder, which is what puts PBS on PATH. A
        failure becomes `PBSCommandError` carrying whatever the scheduler said,
        because the callers above need to tell "the scheduler said no" from "the
        scheduler is not answering" and both are ordinary conditions.
        """
        if not command:
            # The builder returns an empty string when asked for a command for the
            # wrong provider. Running that would be running nothing and reading
            # success into it.
            raise PBSCommandError(
                f"no command was built for scheduler {self._scheduler_id!r}; the "
                "builder rejects a provider mismatch"
            )

        result = SocaSubprocessClient(run_command=command, run_as=as_user).run(
            timeout=DEFAULT_TIMEOUT_SECONDS
        )
        if not result.get("success"):
            raise PBSCommandError(str(result.get("message")))
        return str((result.get("message") or {}).get("stdout") or "")

    def _run_json(self, command: str) -> dict:
        out = self._run(command)
        parsed = SocaCastEngine(data=out).as_json()
        if not parsed.get("success"):
            raise PBSCommandError(
                f"the scheduler returned output that is not JSON: {parsed.get('message')}"
            )
        return parsed.get("message") or {}

    # ------------------------------------------------------------------ protocol

    def submit(self, spec: JobSpec) -> str:
        """
        Submit the job and return the PBS job id.

        Delegated to `SocaHpcJobSubmit`, which writes the script with O_EXCL and
        0o700, sets ownership, and runs qsub as the submitting user. Reimplementing
        that here, as the first revision did, meant hand-rolling both the temporary
        file and the privilege drop.

        The job name is sanitized by the builder, because PBS rejects characters
        outside its own set for `-N` and the name arrives from another cluster. The
        first revision passed it through untouched.
        """
        raw_name = (spec.attributes.get("name") or "").strip()
        job_name = (
            self._builder().normalize_job_name(raw_name) if raw_name else None
        )

        script = build_job_script(spec, job_name=job_name)
        payload = base64.b64encode(script.encode()).decode()

        response = SocaHpcJobSubmit(
            scheduler_id=self._scheduler_id, user=self._run_as
        ).submit_encoded_payload(payload=payload)

        if not response.success:
            raise PBSCommandError(f"submit failed: {response.message}")

        job_id = str(response.message or "").strip()
        if not job_id:
            raise PBSCommandError("submit reported success but returned no job id")
        return job_id

    def get(self, job_id: str) -> JobView:
        """
        One job's normalized state.

        A finished job with a non-zero exit status is reported FAILED rather than
        COMPLETED, because PBS says only that the job finished and the distinction is
        what the origin cluster needs.
        """
        data = self._run_json(
            self._builder().qstat(args=f"-x -f -F json {shlex.quote(job_id)}")
        )
        jobs = data.get("Jobs", {}) or {}
        raw = jobs.get(job_id) or (next(iter(jobs.values())) if jobs else {})

        state = _PBS_STATE.get(
            str(raw.get("job_state", "")).lower().strip(), NormalizedState.UNKNOWN
        )

        exit_code = raw.get("Exit_status")
        if exit_code is not None:
            cast = SocaCastEngine(data=exit_code).cast_as(int)
            if cast.get("success"):
                exit_code = cast.get("message")
            else:
                # Reported but unreadable. Better an unknown exit code on a real
                # state than discarding the whole view.
                logger.warning(
                    "job %s reported an unreadable Exit_status %r", job_id, exit_code
                )
                exit_code = None

        if state == NormalizedState.COMPLETED and exit_code not in (None, 0):
            state = NormalizedState.FAILED

        return JobView(
            job_id=job_id,
            state=state,
            queue=str(raw.get("queue", "")),
            annotation=raw.get("comment"),
            exit_code=exit_code,
        )

    def cancel(self, job_id: str) -> None:
        self._run(self._builder().qdel(args=shlex.quote(job_id)))

    def annotate(self, job_id: str, note: str) -> None:
        self._run(
            self._builder().qalter(
                args=f"-W {shlex.quote(f'comment={note}')} {shlex.quote(job_id)}"
            )
        )

    def is_accepting(self) -> bool:
        """
        Whether a real job would be taken AND run now, without creating one.

        A queue must be enabled, started, and of Execution type. All three matter, and
        `started` is the one the first revision omitted: the parking queue that
        `ensure_queues` creates on every routing-enabled cluster is enabled and
        Execution but deliberately never started, so without that check a cluster
        whose only enabled execution queue was the parking queue advertised itself as
        able to run work, and everything routed to it parked forever.

        False on any failure, including the scheduler not answering, because the
        question is whether work can be placed here and an unanswerable question is
        not a yes.
        """
        try:
            data = self._run_json(self._builder().qstat(args="-Q -f -F json"))
        except PBSCommandError as exc:
            logger.warning("cannot tell whether PBS is accepting work: %s", exc)
            return False

        for queue in (data.get("Queue", {}) or {}).values():
            enabled = str(queue.get("enabled", "")).lower() in _TRUE_WORDS
            started = str(queue.get("started", "")).lower() in _TRUE_WORDS
            is_execution = str(queue.get("queue_type", "")).lower().startswith("exec")
            if enabled and started and is_execution:
                return True
        return False

    def ensure_queues(self, parking: str = QUEUE_PARKING) -> None:
        """
        Create the parking queue if it is absent. Idempotent.

        The parking queue is an Execution queue that is deliberately never started, so
        a job placed there is held and never scheduled. That is what holds a delegated
        job locally while a peer runs the real one, which keeps the delegation visible
        to qstat and cancellable from the origin.

        Execution queues proper are managed by the existing queue mapping bootstrap;
        this adds only the one queue routing needs.
        """
        builder = self._builder()
        safe = shlex.quote(parking)
        try:
            self._run(builder.qstat(args=f"-Q -f {safe}"))
            return
        except PBSCommandError:
            pass
        for directive in (
            f"-c {shlex.quote(f'create queue {parking} queue_type=Execution')}",
            f"-c {shlex.quote(f'set queue {parking} enabled=True')}",
            f"-c {shlex.quote(f'set queue {parking} started=False')}",
        ):
            self._run(builder.qmgr(args=directive))

    def install_intake_handler(self) -> None:
        """
        Nothing to do at runtime.

        The queuejob hook is installed by the bootstrap template via a qmgr hook
        import, so this exists to satisfy the protocol rather than to act.
        """
        return None
