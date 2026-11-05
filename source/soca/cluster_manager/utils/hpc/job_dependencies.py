# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Job dependencies: one vocabulary for "run this job after that one".

Only the `after*` family is exposed. PBS also accepts `before*`, but a
`before*` dependency is rejected by the target unless that target was itself
submitted with `depend=on:N`, and a rejected registration kills the submitted
job with no exit status and no comment. Emitting `after*` on the dependent
needs no cooperation from the target, so the `before*` spelling is deliberately
not reachable from here.

PBS records both directions on its own: a child submitted with
`afterok:<parent>` causes the parent to gain `beforeok:<child>`. So the live
graph is readable from either end and nothing here keeps a second copy of it.

PBS also CLEARS a satisfied edge off the dependent's `depend` attribute, so a
finished chain cannot be reconstructed from `depend` alone. The submit
arguments retain the original spelling for as long as the scheduler keeps job
history, which is what `parse_dependency_arg` is for.
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Iterable, Optional

from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider
from utils.error import SocaError
from utils.validators import Validators
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

# Chain size limits, read from cluster configuration so a site can change them
# without a code change. Both are read on every call, so an edhctl config set
# takes effect on the next submission.
#
# MaxStages default: a chain costs three scheduler calls per stage (submit,
# attach the edge, release the hold), each paying the PBS environment load, so
# the binding constraint is how long one HTTP request stays open rather than
# anything the scheduler refuses. 50 keeps the worst case within the web tier's
# own request budget. Raise it for a site that submits chains from a script.
#
# MaxParentsPerStage default 0 means "no separate limit": a stage can only
# reference other stages in the same chain, so fan-in is already bounded by
# MaxStages. It exists so a site can allow long chains while forbidding wide
# fan-in. OpenPBS 23.06.06 itself accepted a 60-parent afterok list (a
# 2766-character argument) without complaint, so this bound is a site policy
# choice and not a scheduler constraint.
_MAX_STAGES_KEY = "/configuration/HPC/JobChain/MaxStages"
_MAX_PARENTS_KEY = "/configuration/HPC/JobChain/MaxParentsPerStage"
_MAX_STAGES_DEFAULT = 50
_MAX_PARENTS_DEFAULT = 0


def client_error(helper: str) -> SocaResponse:
    """
    A refusal caused by what the caller asked for, not by a fault here.

    Status 400 rather than the 500 default, so an HTTP caller can tell "fix
    your request" from "the cluster failed". Every graph and request-shape
    refusal in this module and in the chain submitter uses this.
    """
    return SocaError.GENERIC_ERROR(helper=helper, status_code=400)


def _config_int(key: str, default: int, minimum: int) -> int:
    """
    A non-negative int from cluster configuration, falling back to `default`.

    A missing, unparseable or out-of-range value falls back rather than
    failing the submission: a chain should not become unsubmittable because a
    config key was typed wrongly, and the fallback is the shipped default.
    """
    try:
        _resp = SocaConfig(key=key).get_value(return_as=int, default=default)
        _value = _resp.get("message") if _resp.get("success") is True else default
    except Exception as err:
        logger.warning(f"Unable to read {key}, using {default}: {err}")
        return default

    if not Validators.is_int(_value) or _value < minimum:
        logger.warning(
            f"{key} is {_value!r}, which is not an integer >= {minimum}; using {default}"
        )
        return default
    return _value


def max_chain_stages() -> int:
    """Most stages one chain may carry."""
    return _config_int(_MAX_STAGES_KEY, _MAX_STAGES_DEFAULT, minimum=1)


def max_parents_per_stage() -> int:
    """
    Most parents one stage may wait on, or 0 for no limit beyond the stage count.
    """
    return _config_int(_MAX_PARENTS_KEY, _MAX_PARENTS_DEFAULT, minimum=0)


class SocaJobDependencyType(str, Enum):
    """
    When a dependent becomes eligible to run, in terms of its parents.

    AFTER_OK      every parent finished with exit status 0
    AFTER_NOT_OK  every parent finished with a non-zero exit status
    AFTER_ANY     every parent finished, whatever the exit status
    AFTER_START   every parent has started
    """

    AFTER_OK = "afterok"
    AFTER_NOT_OK = "afternotok"
    AFTER_ANY = "afterany"
    AFTER_START = "after"


# PBS spells these the same way. Slurm and LSF do not, so each provider gets
# its own spelling rather than a shared string.
_PBS_KEYWORD = {
    SocaJobDependencyType.AFTER_OK: "afterok",
    SocaJobDependencyType.AFTER_NOT_OK: "afternotok",
    SocaJobDependencyType.AFTER_ANY: "afterany",
    SocaJobDependencyType.AFTER_START: "after",
}

_SLURM_KEYWORD = {
    SocaJobDependencyType.AFTER_OK: "afterok",
    SocaJobDependencyType.AFTER_NOT_OK: "afternotok",
    SocaJobDependencyType.AFTER_ANY: "afterany",
    SocaJobDependencyType.AFTER_START: "after",
}

# LSF expresses dependencies as a condition expression over job names or ids,
# not as a keyword list. "done" is exit 0, "exit" is non-zero, "ended" is
# either, and "started" is the running equivalent.
_LSF_CONDITION = {
    SocaJobDependencyType.AFTER_OK: "done",
    SocaJobDependencyType.AFTER_NOT_OK: "exit",
    SocaJobDependencyType.AFTER_ANY: "ended",
    SocaJobDependencyType.AFTER_START: "started",
}

# A scheduler job id as it may legally arrive: a plain number, a PBS array
# parent ("6[]"), a PBS subjob ("6[7]"), any of those with a server suffix
# ("6.host" or "6.host@host"), or a Slurm/LSF numeric id. Anything else is
# refused rather than quoted, because a job id reaches this module from a web
# form and is interpolated into a scheduler command line.
_JOB_ID = re.compile(r"^[A-Za-z0-9]+(\[[0-9]*\])?(\.[A-Za-z0-9._-]+)?(@[A-Za-z0-9._-]+)?$")

# The leading job number of a fully qualified id, keeping array brackets.
_SHORT_ID = re.compile(r"^(?P<short>[A-Za-z0-9]+(\[[0-9]*\])?)")

# One PBS `depend` clause: "<type>:<id>[:<id>...]". Clauses are comma separated.
_PBS_ON_COUNT = re.compile(r"^on:(?P<count>[0-9]+)$")

# PBS hold types. "s" is the system hold a scheduler places for an unsatisfied
# dependency; "u" is a user hold from `qsub -h` or `qhold`; "o" is an operator
# hold. A dependency-held job carries "s", and a job held for both reasons
# carries both letters.
_DEPENDENCY_HOLD_LETTER = "s"

# PBS job substates, as observed on OpenPBS 23.06.06.
#
# A job removed by a delete request lands on 91, and one the server itself
# finished or removed lands on 92. Both reach state F with no exit status, so
# without this a dependent DELETED while it waited is indistinguishable from
# one the server removed because its dependency became unsatisfiable, and the
# first gets reported as the second.
#
# Measured over 18 finished dependents: every scheduler-removed one reported
# 92 (an afterok parent that exited non-zero, a dependency on a job id that
# does not exist, a before* registration the target refused, and a dependent
# whose parent was deleted out from under it), and every one removed by qdel
# reported 91.
_SUBSTATE_TERMINATED_BY_DELETE = 91
_SUBSTATE_FINISHED = 92


def short_job_id(job_id) -> str:
    """
    The leading job number of `job_id`, with any server suffix removed.

    "6.host@host" yields "6" and "6[].host" yields "6[]". A value that does not
    start with a job number is returned unchanged, because the only caller that
    sees one is a display path.
    """
    if job_id is None:
        return ""
    _match = _SHORT_ID.match(str(job_id).strip())
    if not _match:
        return str(job_id).strip()
    return _match.group("short")


def validate_job_ids(job_ids: Iterable) -> SocaResponse:
    """
    Message is the job ids as a list of str when every one of them is a legal
    scheduler job id.

    Refuses rather than escapes. These ids are interpolated into a scheduler
    command line, and a value that is not a job id has no correct quoting.
    """
    _ids = []
    for _job_id in job_ids or []:
        _candidate = str(_job_id).strip()
        if not _candidate:
            return SocaError.GENERIC_ERROR(helper="Dependency job id must not be empty")
        if not _JOB_ID.match(_candidate):
            return SocaError.GENERIC_ERROR(
                helper=f"Dependency job id {_candidate!r} is not a valid scheduler job id"
            )
        _ids.append(_candidate)

    if not _ids:
        return SocaError.GENERIC_ERROR(helper="At least one dependency job id is required")

    return SocaResponse(success=True, message=_ids)


def coerce_dependency_type(dependency_type) -> SocaResponse:
    """Message is a SocaJobDependencyType for any accepted spelling of one."""
    if isinstance(dependency_type, SocaJobDependencyType):
        return SocaResponse(success=True, message=dependency_type)

    _candidate = str(dependency_type or "").strip().lower()
    for _member in SocaJobDependencyType:
        if _candidate == _member.value:
            return SocaResponse(success=True, message=_member)

    return SocaError.GENERIC_ERROR(
        helper=(
            f"{dependency_type!r} is not a supported dependency type, must be one of "
            f"{[m.value for m in SocaJobDependencyType]}"
        )
    )


def build_dependency_arg(
    provider: SocaHpcSchedulerProvider,
    dependency_type,
    job_ids: Iterable,
) -> SocaResponse:
    """
    Message is the scheduler argument that makes a job wait on `job_ids`.

    PBS and Slurm take a keyword list; LSF takes a condition expression. The
    returned string is ready to concatenate into the submit command built by
    utils.hpc.scheduler_command_builder.
    """
    _type = coerce_dependency_type(dependency_type)
    if _type.get("success") is False:
        return _type
    _type = _type.get("message")

    _ids = validate_job_ids(job_ids)
    if _ids.get("success") is False:
        return _ids
    _ids = _ids.get("message")

    if provider in (
        SocaHpcSchedulerProvider.OPENPBS,
        SocaHpcSchedulerProvider.PBSPRO,
    ):
        _keyword = _PBS_KEYWORD[_type]
        return SocaResponse(
            success=True, message=f"-W depend={_keyword}:{':'.join(_ids)}"
        )

    if provider in (
        SocaHpcSchedulerProvider.SLURM,
        SocaHpcSchedulerProvider.AWS_PCS,
    ):
        _keyword = _SLURM_KEYWORD[_type]
        return SocaResponse(
            success=True, message=f"--dependency={_keyword}:{':'.join(_ids)}"
        )

    if provider == SocaHpcSchedulerProvider.LSF:
        _condition = _LSF_CONDITION[_type]
        _expression = " && ".join(f'{_condition}("{_id}")' for _id in _ids)
        return SocaResponse(success=True, message=f"-w '{_expression}'")

    return SocaError.GENERIC_ERROR(
        helper=f"{provider=} does not have a known job dependency spelling"
    )


def parse_pbs_depend(depend: Optional[str]) -> SocaResponse:
    """
    Message is the PBS `depend` attribute as a list of
    {"type": str, "job_ids": [str], "short_job_ids": [str]}.

    Both directions appear in this attribute, so a `beforeok` clause on a
    parent is returned as readily as an `afterok` clause on a child. The
    `on:<count>` form carries a count rather than job ids and is returned with
    an empty id list and the count under "count".

    An unreadable clause is skipped rather than failing the whole parse: this
    feeds a display path, and one malformed clause should not blank the rest.
    """
    _edges = []
    if not depend:
        return SocaResponse(success=True, message=_edges)

    for _clause in str(depend).split(","):
        _clause = _clause.strip()
        if not _clause:
            continue

        _on_count = _PBS_ON_COUNT.match(_clause)
        if _on_count:
            _edges.append(
                {
                    "type": "on",
                    "count": int(_on_count.group("count")),
                    "job_ids": [],
                    "short_job_ids": [],
                }
            )
            continue

        _parts = _clause.split(":")
        if Validators.is_list_length_lower_than(_parts, 2):
            logger.debug("Skipping unreadable PBS depend clause %r", _clause)
            continue

        _type = _parts[0].strip()
        _ids = [_part.strip() for _part in _parts[1:] if _part.strip()]
        if not _type or not _ids:
            logger.debug("Skipping unreadable PBS depend clause %r", _clause)
            continue

        _edges.append(
            {
                "type": _type,
                "job_ids": _ids,
                "short_job_ids": [short_job_id(_id) for _id in _ids],
            }
        )

    return SocaResponse(success=True, message=_edges)


def parse_dependency_arg(submit_arguments: Optional[str]) -> SocaResponse:
    """
    Message is the dependency spelling found in a job's submit arguments, or an
    empty list when it carries none.

    This is the only durable record of what a job was SUBMITTED to wait on.
    PBS clears a satisfied edge from the live `depend` attribute, so a chain
    that has already run reads as having had no dependencies at all unless the
    submit arguments are consulted.
    """
    if not submit_arguments:
        return SocaResponse(success=True, message=[])

    for _token in str(submit_arguments).split():
        if _token.startswith("depend="):
            return parse_pbs_depend(_token[len("depend=") :])

    return SocaResponse(success=True, message=[])


def is_dependency_hold(hold_types: Optional[str]) -> bool:
    """
    True when `hold_types` carries the scheduler's system hold.

    This is what separates "waiting for another job" from "someone suspended
    it". A job held for both reasons carries both letters and is reported here
    as a dependency hold, because that is the hold a user cannot clear.
    """
    if not hold_types:
        return False
    return _DEPENDENCY_HOLD_LETTER in str(hold_types).strip().lower()


def is_dependency_casualty(
    job_state: Optional[str],
    exit_status,
    hold_types: Optional[str],
    depend: Optional[str],
    substate=None,
) -> bool:
    """
    True when a job was removed because its dependency could not be satisfied.

    A job whose `afterok` parent fails is removed by the scheduler, and that
    removal is quiet: the job lands in the finished state with NO exit status,
    keeps the system hold, and keeps the unsatisfied edge on `depend`. Without
    this test such a job is indistinguishable from one that completed
    normally, which is how a stage of a chain appears to vanish.

    `substate` is what separates it from a job a USER deleted while it was
    waiting. That case reaches the same state, the same absent exit status and
    the same retained hold and edge, so the first four tests alone report it
    as a dependency failure it never suffered. A delete request leaves 91 and
    the server's own removal leaves 92.

    Passing no substate keeps the older, looser behavior rather than silently
    reclassifying every deleted job, so a caller that cannot supply it is no
    worse off than before.
    """
    if str(job_state or "").strip().upper() not in ("F", "FINISHED"):
        return False
    if exit_status is not None and str(exit_status).strip() != "":
        return False
    if not is_dependency_hold(hold_types):
        return False

    if substate is not None and str(substate).strip() != "":
        _cast = SocaCastEngine(data=substate).cast_as(int)
        if _cast.get("success") is True:
            if _cast.get("message") == _SUBSTATE_TERMINATED_BY_DELETE:
                return False

    _edges = parse_pbs_depend(depend).get("message")
    return any(_edge.get("type", "").startswith("after") for _edge in _edges)


def find_cycle(prerequisites: dict) -> Optional[list]:
    """
    A cycle in `prerequisites` as the list of nodes forming it, or None.

    `prerequisites` maps a node to the nodes that must finish before it. The
    scheduler does NOT reject a cyclic dependency: it accepts the registration
    and the jobs involved then wait on each other forever. So any caller that
    builds a graph has to run this before submitting anything.
    """
    _visiting = set()
    _done = set()
    _stack = []

    def _walk(_node) -> Optional[list]:
        if _node in _done:
            return None
        if _node in _visiting:
            _start = _stack.index(_node) if _node in _stack else 0
            return _stack[_start:] + [_node]

        _visiting.add(_node)
        _stack.append(_node)
        for _parent in prerequisites.get(_node, ()) or ():
            _found = _walk(_parent)
            if _found:
                return _found
        _stack.pop()
        _visiting.discard(_node)
        _done.add(_node)
        return None

    for _node in list(prerequisites.keys()):
        _found = _walk(_node)
        if _found:
            return _found
    return None


def validate_chain_request(body, scheduler_ids) -> SocaResponse:
    """
    Validate a job chain request body, independent of any web framework.

    Message on success is
    {"interpreter": str, "dependency_type": str, "stages": [dict]}.

    Lives here rather than in the API resource so it is reachable without
    flask_restful, which this repository declares in no requirements file.
    The resource is a thin adapter over this function; everything it refuses,
    it refuses here.

    Only the shape of the REQUEST is checked. The graph itself (cycles,
    indexes, fan-in) is checked by the submitter, which is also the authority
    for a caller that does not arrive over HTTP.
    """
    if not Validators.is_dict(body):
        return client_error("Request body must be a JSON object")

    _interpreter = body.get("interpreter")
    if not _interpreter:
        return client_error("interpreter is required")

    _known = list(scheduler_ids or [])
    if _interpreter not in _known:
        return client_error(
            helper=(
                f"interpreter is invalid, detected {_interpreter}, must be one of "
                f"{_known}. A job chain requires a scheduler, so the shell "
                f"interpreters accepted for a single job are not valid here."
            )
        )

    _stages = body.get("stages")
    if not Validators.is_list_not_empty(_stages):
        return client_error(
            helper="stages must be a non-empty list of chain stages"
        )

    _max_stages = max_chain_stages()
    if Validators.is_list_length_greater_than(_stages, _max_stages):
        return client_error(
            helper=(
                f"A job chain is limited to {_max_stages} stage(s), received "
                f"{len(_stages)}. Raise {_MAX_STAGES_KEY} to allow more."
            )
        )

    for _index, _stage in enumerate(_stages):
        if not Validators.is_dict(_stage):
            return client_error(
                helper=f"Chain stage {_index} must be an object"
            )

    _dependency_type = body.get("dependency_type") or SocaJobDependencyType.AFTER_OK
    _coerced = coerce_dependency_type(_dependency_type)
    if _coerced.get("success") is False:
        return client_error(str(_coerced.get("message")))

    return SocaResponse(
        success=True,
        message={
            "interpreter": _interpreter,
            "dependency_type": _coerced.get("message").value,
            "stages": _stages,
        },
    )


def describe_wait_reason(
    job_state: Optional[str],
    hold_types: Optional[str],
    depend: Optional[str],
    submit_arguments: Optional[str] = None,
    exit_status=None,
    substate=None,
) -> SocaResponse:
    """
    Message is a display summary of why a job is not running, as
    {"blocked": bool, "casualty": bool, "dependency_type": str|None,
     "waiting_on": [str], "label": str}.

    Built for a jobs list, so every field is safe to render directly and
    `label` is already a sentence.
    """
    _summary = {
        "blocked": False,
        "casualty": False,
        "dependency_type": None,
        "waiting_on": [],
        "label": "",
    }

    _casualty = is_dependency_casualty(
        job_state=job_state,
        exit_status=exit_status,
        hold_types=hold_types,
        depend=depend,
        substate=substate,
    )

    # A satisfied edge is gone from `depend`, so fall back to what the job was
    # submitted with before concluding it never had a dependency.
    _edges = parse_pbs_depend(depend).get("message")
    if not _edges and submit_arguments:
        _edges = parse_dependency_arg(submit_arguments).get("message")

    _waiting = []
    _type = None
    for _edge in _edges:
        if not _edge.get("type", "").startswith("after"):
            continue
        _type = _type or _edge.get("type")
        _waiting.extend(_edge.get("short_job_ids", []))

    _summary["dependency_type"] = _type
    _summary["waiting_on"] = _waiting

    if _casualty:
        _summary["casualty"] = True
        _summary["label"] = (
            "Cancelled: dependency could not be satisfied"
            + (f" ({_type} on job {', '.join(_waiting)})" if _waiting else "")
        )
        return SocaResponse(success=True, message=_summary)

    if is_dependency_hold(hold_types) and _waiting:
        _summary["blocked"] = True
        _summary["label"] = f"Waiting on job {', '.join(_waiting)} ({_type})"
        return SocaResponse(success=True, message=_summary)

    if is_dependency_hold(hold_types):
        _summary["blocked"] = True
        _summary["label"] = "Waiting on a job dependency"
        return SocaResponse(success=True, message=_summary)

    return SocaResponse(success=True, message=_summary)
