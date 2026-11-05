######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Scheduler-agnostic contract for cross-cluster job routing.

Nothing above this layer knows about PBS, Slurm or LSF. A driver translates the
generic JobSpec, JobView and NormalizedState vocabulary into its native scheduler,
and the driver is the lowest layer where engine-specific code is allowed.

"queue" is the universal job-grouping term here. A driver maps it to whatever its
engine calls the same idea, a PBS queue or a Slurm partition.

This module imports stdlib only, deliberately, and that pin is enforced by a test.
The routing daemon runs from a systemd unit and the PBS queuejob hook runs inside
pbs_server's own stripped embedded Python; both import `JobSpec` and
`NormalizedState` from here, and `utils.config`, `utils.error` and `utils.response`
all import Flask at module scope.

The pin applies to THIS module, not to the drivers beside it. A driver that shells
out to a scheduler only ever runs inside the web process, so it uses the shipped
`SocaHpcPBSJobCommandBuilder` and `SocaSubprocessClient` and is not held to this
constraint. Applying it to the whole package, as I first did, meant reimplementing
PBS path resolution and job-name sanitizing that the shipped helpers already do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Protocol, runtime_checkable


class NormalizedState(str, Enum):
    """
    Engine job states mapped to one vocabulary, so a job's state means the same
    thing whichever cluster is reporting it. Each driver owns its own mapping.

    The distinction that matters for routing is PARKED. A delegated job is held
    locally while a peer runs the real one, so it is neither waiting for local
    resources nor running, and reporting it as either would make a delegated job
    indistinguishable from an ordinary one.
    """

    SUBMITTED = "submitted"
    ROUTING = "routing"
    PARKED = "parked"
    ACTIVE = "active"
    EXITING = "exiting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class SchedulerEngine(str, Enum):
    """
    The engines a driver can be requested for.

    Values match `SocaHpcSchedulerProvider` in `utils/datamodels/hpc/scheduler.py`,
    which is the shipped vocabulary for this and the one `edhctl schedulers` already
    validates against. They are restated rather than imported because that module
    imports `utils.config` and pydantic, and `utils.config` reaches Flask, which
    this package cannot take on.

    A test asserts the two stay in agreement, so adding an engine there without
    adding it here fails rather than diverging silently.
    """

    OPENPBS = "openpbs"
    PBSPRO = "pbspro"
    LSF = "lsf"
    SLURM = "slurm"
    AWS_PCS = "aws_pcs"


# The reserved queue role for delegated work. A job routed to a peer stays here
# locally, held, for as long as the peer is running the real one: that is what
# makes the delegation visible to `qstat` and cancellable from the origin cluster
# rather than existing only in a database.
#
# There is deliberately no intake "route" queue. A PBS queuejob hook fires before
# routing happens, so a later hook such as validate_job_submit has to be able to
# see the resolved execution queue; the hook sets the destination directly instead.
QUEUE_PARKING = "parking"


@dataclass(frozen=True)
class JobSpec:
    """
    A scheduler-agnostic job description, as it crosses the mesh.

    Every field arrives from another cluster over the network, so a driver must
    treat all of it as untrusted input. In particular `attributes` carries the
    requesting owner, which must never be used to choose the local account the job
    runs as: the receiving cluster decides that, because the alternative lets a
    peer name any local user.
    """

    command: List[str]
    environment: Dict[str, str] = field(default_factory=dict)
    # cpu, mem, gpu, walltime, instance_type
    resources: Dict[str, str] = field(default_factory=dict)
    # owner, name, project
    attributes: Dict[str, str] = field(default_factory=dict)
    target_queue: Optional[str] = None


@dataclass(frozen=True)
class JobView:
    """A normalized snapshot of one job's state, independent of the engine."""

    job_id: str
    state: NormalizedState
    queue: str
    annotation: Optional[str] = None
    submit_ts: Optional[int] = None
    start_ts: Optional[int] = None
    end_ts: Optional[int] = None
    exit_code: Optional[int] = None


@runtime_checkable
class SchedulerDriver(Protocol):
    """
    The lowest layer where engine-specific code is allowed.

    `is_accepting` exists so a routing decision can be made without submitting
    anything: a probe asks whether a real job would be taken now, and must never
    create one to find out.

    `hold`, `release` and `move` are deliberately absent. The parking flow will need
    them, but nothing calls them yet, and the shipped `SocaHpcPBSJobCommandBuilder`
    covers qsub, qstat, qalter, qdel, qmgr and pbsnodes rather than qhold, qrls and
    qmove. Declaring them here would either mean bypassing that builder for three
    commands or shipping surface with no caller. They arrive with the change that
    parks a delegated job, which is where extending the builder can be justified on
    its own terms.
    """

    engine_name: str

    def submit(self, spec: JobSpec) -> str: ...

    def get(self, job_id: str) -> JobView: ...

    def cancel(self, job_id: str) -> None: ...

    def annotate(self, job_id: str, note: str) -> None: ...

    def is_accepting(self) -> bool: ...

    def ensure_queues(self, parking: str) -> None: ...

    def install_intake_handler(self) -> None: ...
