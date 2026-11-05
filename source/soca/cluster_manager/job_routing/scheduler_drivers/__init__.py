######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Scheduler driver factory.

`load_driver` requires both the engine name and the scheduler id rather than
resolving either itself, which is a departure from the reference implementation.

The engine name is required because the reference defaulted to openpbs on any value
it could not read, including a configuration error, so a misconfigured cluster would
submit PBS syntax to Slurm and fail somewhere far less obvious than the point of
misconfiguration.

The scheduler id is required because a controller can have more than one scheduler
registered, and it is the same identifier `SocaHpcJobSubmit` and `SocaHpcJobFetcher`
take. A driver is therefore addressed the way the rest of the HPC layer is addressed.

Only `.base` is imported at module scope here, and the driver is imported inside the
function. That keeps importing the vocabulary free of the shipped HPC helpers, which
reach Flask: the routing daemon and the PBS queuejob hook need `JobSpec` and
`NormalizedState` without them.
"""

from __future__ import annotations

import logging
from typing import Union

from .base import SchedulerDriver, SchedulerEngine

logger = logging.getLogger("soca_logger")

# Aliases accepted for the PBS family, because /etc/pbs.conf and operators both use
# the bare name while the shipped provider vocabulary spells it out.
_PBS_ALIASES = frozenset({"pbs", "openpbs", "pbspro"})


class UnsupportedEngineError(ValueError):
    """
    Raised for an engine this build has no driver for.

    A subclass of ValueError so existing handlers still contain it, the same
    reasoning as `DDBBallotIncompleteError` subclassing `DDBQueryError`.
    """


def load_driver(
    engine: Union[str, SchedulerEngine], *, scheduler_id: str
) -> SchedulerDriver:
    """
    Return a driver for `engine`, driving the scheduler registered as `scheduler_id`.

    Only the PBS family has a driver today. LSF and Slurm are named in the engine
    vocabulary because the shipped provider enum lists them and `edhctl schedulers`
    accepts them, so they are configurable states a cluster can genuinely be in.
    Asking for one raises rather than falling back to PBS.
    """
    name = (
        engine.value if isinstance(engine, SchedulerEngine) else str(engine or "")
    ).strip().lower()

    if not name:
        raise UnsupportedEngineError(
            "no scheduler engine named; the caller must resolve it rather than "
            "letting this default, so a misconfiguration cannot silently submit to "
            "the wrong engine"
        )

    if not (scheduler_id or "").strip():
        raise UnsupportedEngineError(
            "no scheduler id named; a controller can have several schedulers "
            "registered, so the one to drive has to be said"
        )

    if name in _PBS_ALIASES:
        from .openpbs import OpenPBSDriver

        return OpenPBSDriver(scheduler_id=scheduler_id)

    known = ", ".join(sorted(e.value for e in SchedulerEngine))
    raise UnsupportedEngineError(
        f"no driver for scheduler engine {name!r}; this build drives the PBS family "
        f"only. Configurable engines are: {known}"
    )
