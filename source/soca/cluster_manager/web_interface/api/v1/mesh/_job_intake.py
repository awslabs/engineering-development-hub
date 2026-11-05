######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

"""
What a dispatched job has to satisfy, and which local scheduler receives it.

Separate from `jobs_dispatch.py` for one reason: THAT MODULE IMPORTS
`flask_restful`, WHICH IS DECLARED IN NO REQUIREMENTS FILE IN THIS REPOSITORY, so
a test cannot import it and can only assert against its source text. The decisions
below are the ones worth testing behaviourally - which payloads are refused, and
which scheduler a peer's job lands on - so they live where a test can call them.

That is not only a testing convenience. Validating a payload and choosing a
scheduler are not route concerns, and the route is the one part of this that has
to be read rather than run.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

from utils.validators import Validators

logger = logging.getLogger("soca_logger")

# The modes a peer may ask for.
#
# Named rather than compared inline. The prototype branched `if mode == "probe"`
# and fell through to a submit for anything else, so a typo, a future third mode,
# or a peer sending nothing recognisable queued a real job while the caller
# believed it had only asked a question.
MODE_SUBMIT = "submit"
MODE_PROBE = "probe"
MODES = (MODE_SUBMIT, MODE_PROBE)


class DriverUnavailable(Exception):
    """No local scheduler driver could be resolved to act on.

    Distinct from a driver that failed, because the answers differ: this cluster
    cannot take work at all and the origin should route elsewhere, rather than
    retrying against a peer whose scheduler is merely busy or briefly unreachable.
    """


def load_local_driver():
    """
    The driver for this cluster's scheduler.

    THE SCHEDULER IS RESOLVED LOCALLY AND NEVER TAKEN FROM THE REQUEST. A
    controller can have several schedulers registered, and letting a peer name one
    would hand a peer the choice of which of this cluster's engines runs its work.

    A controller with exactly one enabled scheduler routes to it. More than one is
    REFUSED rather than defaulted: taking the first of several would send a peer's
    job to whichever scheduler happened to be listed first, which is a silent
    decision about somebody else's work made by list order. Configuring which
    scheduler receives routed jobs is a real feature and it is not this change.
    """
    from utils.datamodels.hpc.scheduler import get_schedulers
    from job_routing.scheduler_drivers import UnsupportedEngineError, load_driver

    schedulers = get_schedulers()
    # `is_list_not_empty` rather than a truthiness test, and it is deliberately the
    # first gate: the length check below refuses only a value it can measure as a
    # list, so anything that is not one would fall past it and be indexed at [0].
    # Requiring the list shape here means a non-list reaches the refusal rather
    # than the subscript.
    if not Validators.is_list_not_empty(schedulers):
        raise DriverUnavailable(
            "no enabled scheduler is registered on this cluster, so there is "
            "nothing to route a job to"
        )
    if Validators.is_list_length_greater_than(schedulers, 1):
        names = ", ".join(sorted(str(s.identifier) for s in schedulers))
        raise DriverUnavailable(
            f"this cluster has more than one enabled scheduler ({names}) and no "
            "configured choice of which receives routed work. Refusing rather than "
            "picking one on the peer's behalf."
        )

    scheduler = schedulers[0]
    # `lsf` and `slurm` are shipped values of the provider vocabulary and this build
    # drives the PBS family only, so a cluster can be configured into an engine that
    # has no driver. That is a permanent condition rather than a fault, which is what
    # DriverUnavailable means here and why the handlers answer it with 503 -- route
    # elsewhere rather than retry. UnsupportedEngineError left as it comes escapes
    # them, because they catch DriverUnavailable alone.
    #
    # Deliberately narrow. A blanket `except Exception` would also report a genuine
    # defect inside a driver as "this cluster cannot take work", telling the origin
    # to route away permanently from a cluster that is merely broken.
    provider = getattr(scheduler.provider, "value", scheduler.provider)
    try:
        return load_driver(scheduler.provider, scheduler_id=scheduler.identifier)
    except UnsupportedEngineError as e:
        raise DriverUnavailable(
            f"the scheduler on this cluster ({scheduler.identifier}) runs "
            f"{provider}, which this build has no driver for, so it cannot accept "
            "routed work"
        ) from e


def job_spec_from(job: Any) -> Tuple[Optional[Any], Optional[str]]:
    """
    Build a JobSpec from a dispatch request's `job` object.

    Returns (spec, why_not), exactly one of which is meaningful.

    THE CHECKS HERE ARE ABOUT SHAPE, NOT CONTENT. Every field arrived from another
    cluster, and the driver is written against that: it validates an environment
    variable name against a POSIX pattern, refuses control characters on a `#PBS`
    directive line, and quotes each command element. Repeating that here would
    duplicate a defence that has to live where the shell is, and a weaker copy in
    front of a strong one reads as the protection.

    What is checked is what would otherwise fail confusingly or silently. A
    `command` that is a string rather than a list is the one that matters: the
    prototype tested only `job.get("command")` for truthiness, so "rm -rf /" as a
    bare string passed, and `list(...)` of it would have become a command of
    single characters.
    """
    from job_routing.scheduler_drivers.base import JobSpec

    if not Validators.is_dict(job):
        return None, "submit requires a 'job' object"

    command = job.get("command")
    if Validators.is_string(command):
        return None, (
            "'job.command' must be a list of arguments, not a string; a string "
            "would be split into one argument per character"
        )
    if not Validators.is_list_not_empty(command):
        return None, "submit requires 'job.command' as a non-empty list"
    if not all(Validators.is_string(part) for part in command):
        return None, "every element of 'job.command' must be a string"

    for field_name in ("environment", "resources", "attributes"):
        value = job.get(field_name)
        if value is not None and not Validators.is_dict(value):
            return None, f"'job.{field_name}' must be an object when present"

    target_queue = job.get("target_queue")
    if target_queue is not None and not Validators.is_string(target_queue):
        return None, "'job.target_queue' must be a string when present"

    return (
        JobSpec(
            command=list(command),
            environment=dict(job.get("environment") or {}),
            resources=dict(job.get("resources") or {}),
            attributes=dict(job.get("attributes") or {}),
            target_queue=target_queue,
        ),
        None,
    )
