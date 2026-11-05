######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
The delegation ledger's row model.

A delegation records that a job submitted HERE is being run by a peer. It is the
cross-region system of record, and it exists because the schedulers cannot be
one: PBS keeps finished jobs for 72 hours, so once local history has rolled over
the only evidence that a job ran at all is this row. Retention is therefore
measured against the audit question ("which cluster ran this user's work, and
when") rather than against the scheduler's.

Kept in its own module, holding nothing but the dataclass and its vocabulary, so
that reading a delegation costs no more than stdlib. Three consumers need that:
the reconciler and the routing daemon both run from systemd units, and the WebUI
Routed Jobs view reads the same rows from inside uwsgi. Only the last of those
could take Flask, and a model shared by all three must satisfy the strictest.

`state` is a `NormalizedState` rather than a string. A delegation's state is the
REMOTE job's state, reported by a cluster that may be running a different
scheduler, so the one vocabulary the drivers already normalize to is exactly the
right type: storing a free string here would let one cluster's "R" and another's
"RUNNING" both land in the ledger and mean nothing to the view that reads them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .scheduler_drivers.base import NormalizedState

# The states in which a delegation needs nothing further from the reconciler.
#
# Derived from NormalizedState rather than spelled out, so a state added there
# cannot silently become one the reconciler polls forever.
TERMINAL_STATES = frozenset(
    {
        NormalizedState.COMPLETED,
        NormalizedState.FAILED,
        NormalizedState.CANCELLED,
    }
)


@dataclass(frozen=True)
class Delegation:
    """
    One locally submitted job that a peer cluster is running.

    Frozen for the same reason `JobSpec` is: the row is read by the reconciler,
    the daemon and the WebUI view, and a mutable model invites one of them to
    adjust a field locally and act on a value the ledger does not hold.

    `local_job_id` is the scheduler id of the PARKED STUB on this cluster, not of
    anything on the peer. The stub is what makes a delegated job visible to
    `qstat` and cancellable by its owner, and it is what `stub_released` tracks.
    """

    mesh_id: str
    # The parked stub's scheduler id on THIS cluster. Sort key.
    local_job_id: str
    local_cluster_id: str
    remote_cluster_id: str
    # The real job's scheduler id on the peer.
    remote_job_id: str
    owner: str
    state: NormalizedState
    submitted_ts: int
    updated_ts: int
    completed_ts: Optional[int] = None
    # Whether the local parked stub has been taken out of the queue. Tracked
    # separately from `state` because the two can disagree, and the disagreement
    # is the state that needs recovering: the remote job can be finished while
    # the local release failed. Collapsing them into one field is what makes such
    # a stub unrecoverable, since a ledger that calls the delegation finished has
    # no reason to look at it again.
    stub_released: bool = False
    expires_at: Optional[int] = None
    schema_version: int = 1
    min_compatible_version: int = 1

    @property
    def is_terminal(self) -> bool:
        """Whether the remote job has reached a state that will not change."""
        return self.state in TERMINAL_STATES

    @property
    def needs_reconciliation(self) -> bool:
        """
        Whether the reconciler still has work to do on this delegation.

        Not the negation of `is_terminal`. A delegation whose remote job has
        finished but whose local stub is still queued needs one more pass, and
        asking only about the remote state is what leaves that stub parked for
        the rest of the cluster's life.
        """
        return not self.is_terminal or not self.stub_released
