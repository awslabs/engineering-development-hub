######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Delegation reconciler.

One pass walks the delegations this cluster originated that still need work, asks
each peer what the real job is doing, records it, and once a remote job has
finished releases the local parked stub so the job leaves the queue and enters
local history.

`reconcile_once` is a single pass and takes every dependency as an argument: the
ledger, the state query, the scheduler driver and the clock. A caller supplies a
sleep loop. That split is deliberate - it is what lets the ordering rule below be
tested against a driver that fails, which is the case the rule exists for and the
case a live cluster reaches by itself.

THE ORDERING RULE, which is the whole reason this module is not three lines:

    1. record the remote state, because the ledger should reflect what the peer
       says as soon as it says it
    2. then try to release the local stub
    3. and record the release ONLY if it succeeded

The reference did (1) and (2) and had nowhere to put (3), because its ledger had
one state field. A failed release was therefore indistinguishable from a
successful one, and since a delegation that reads as finished is never listed
again, a single transient qdel failure parked that stub in the queue for the rest
of the cluster's life. Splitting the release into its own recorded fact is what
makes the next pass pick it up.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, Optional

from . import delegation_store, dispatch_client
from .models import Delegation
from .scheduler_drivers.base import NormalizedState

logger = logging.getLogger("soca_logger")

# The states from which a vanished remote job is understood as having finished
# its work rather than never having started it.
_OBSERVED_RUNNING = frozenset(
    {NormalizedState.ACTIVE, NormalizedState.EXITING}
)


@dataclass(frozen=True)
class ReconcileCounts:
    """What one pass did. A dataclass rather than a dict so a caller cannot read a
    counter that was never incremented and see None."""

    checked: int = 0
    state_changed: int = 0
    unreachable: int = 0
    stubs_released: int = 0
    stubs_release_failed: int = 0

    def plus(self, **deltas: int) -> "ReconcileCounts":
        fields = {
            "checked": self.checked,
            "state_changed": self.state_changed,
            "unreachable": self.unreachable,
            "stubs_released": self.stubs_released,
            "stubs_release_failed": self.stubs_release_failed,
        }
        for name, delta in deltas.items():
            fields[name] += delta
        return ReconcileCounts(**fields)


def state_from_view(view: dict, *, previous: NormalizedState) -> NormalizedState:
    """
    What a peer's answer means for the delegation, given what it last said.

    Pure, and separate from the pass, so the one judgement in this module can be
    enumerated per prior state rather than reached through a network call.

    AN ABSENT REMOTE JOB IS NOT AUTOMATICALLY A COMPLETED ONE. The reference read
    any absence as COMPLETED, which is right for the case it had in mind - the
    peer's scheduler prunes finished jobs, so a job delegated long enough ago is
    simply gone - but wrong for the case that matters more: a delegation still
    sitting at SUBMITTED whose remote job is absent has most likely never run at
    all, because the dispatch failed, the peer was rebuilt, or the id was never
    valid. Reporting that as COMPLETED tells a user their work succeeded and
    produced no output, which is the single worst answer available. Absence is read
    as completion only when this cluster previously saw the job running.
    """
    if view.get("absent"):
        if previous in _OBSERVED_RUNNING:
            return NormalizedState.COMPLETED
        return NormalizedState.FAILED
    raw = view.get("state")
    try:
        return NormalizedState(str(raw))
    except ValueError:
        # A peer reporting a state outside the shared vocabulary is a peer this
        # cluster cannot interpret. UNKNOWN keeps the delegation open so the next
        # pass asks again, where guessing a terminal state would release the stub
        # on the strength of a value nobody understands.
        logger.warning(
            "delegation_sync: peer reported an unrecognized state %r; holding the "
            "delegation open",
            raw,
        )
        return NormalizedState.UNKNOWN


def reconcile_once(
    *,
    mesh_id: str,
    self_cluster_id: str,
    token: str,
    resolve_base_url: Callable[[str], Optional[str]],
    driver,
    store=delegation_store,
    query_state: Callable[..., dict] = dispatch_client.query_state,
    now: Optional[int] = None,
) -> ReconcileCounts:
    """
    Reconcile every delegation that still needs work, once.

    A peer that cannot be reached is counted and skipped, not failed: the
    delegation stays open and the next pass tries again. That is the correct
    direction here, because the alternative - concluding anything about a job on
    the strength of a cluster being unreachable - is how a running job gets
    reported as finished.
    """
    stamp = int(time.time()) if now is None else int(now)
    counts = ReconcileCounts()

    for delegation in store.list_needing_reconciliation(
        local_cluster_id=self_cluster_id
    ):
        counts = counts.plus(checked=1)

        # Reading the remote state needs the peer. RELEASING THE LOCAL STUB DOES
        # NOT, and keeping the two under one reachability gate is what made the
        # recovery case unreachable: a delegation already terminal in the ledger
        # with an unreleased stub has nothing left to ask anyone, and gating it on
        # the peer meant a cluster that had gone away kept that stub parked
        # forever. Worse than a transient outage, because a DECOMMISSIONED peer is
        # filtered out of the route table permanently, so the gate never reopens
        # and every pass for the life of the cluster spends a turn on a delegation
        # it refuses to finish.
        state = delegation.state
        if not delegation.is_terminal:
            state = _observe_remote_state(
                delegation,
                mesh_id=mesh_id,
                token=token,
                resolve_base_url=resolve_base_url,
                query_state=query_state,
                store=store,
                driver=driver,
                stamp=stamp,
            )
            if state is None:
                counts = counts.plus(unreachable=1)
                continue
            if state != delegation.state:
                counts = counts.plus(state_changed=1)

        if state in delegation_store.TERMINAL_STATES and not delegation.stub_released:
            counts = counts.plus(
                **_release_stub(driver, store, delegation, mesh_id, stamp)
            )

    return counts


def _observe_remote_state(
    delegation: Delegation,
    *,
    mesh_id: str,
    token: str,
    resolve_base_url: Callable[[str], Optional[str]],
    query_state: Callable[..., dict],
    store,
    driver,
    stamp: int,
) -> Optional[NormalizedState]:
    """
    Ask the peer what the job is doing and record any change.

    Returns the delegation's state as it now stands, or None when nothing could be
    established - an unreachable peer, or a ledger write that did not land. None
    means the caller must not act on a state, which is the whole reason it is
    distinct from returning the unchanged state: acting on an unchanged state after
    a failed read would treat silence as evidence.
    """
    base_url = resolve_base_url(delegation.remote_cluster_id)
    if not base_url:
        logger.info(
            "delegation_sync: %s is not currently reachable, so %s stays open",
            delegation.remote_cluster_id,
            delegation.local_job_id,
        )
        return None

    try:
        view = query_state(
            base_url=base_url,
            token=token,
            remote_job_id=delegation.remote_job_id,
        )
    except dispatch_client.DispatchError as e:
        logger.info(
            "delegation_sync: could not read %s on %s (%s); %s stays open",
            delegation.remote_job_id,
            delegation.remote_cluster_id,
            e,
            delegation.local_job_id,
        )
        return None

    state = state_from_view(view, previous=delegation.state)
    if state == delegation.state:
        return state

    try:
        store.update_state(
            mesh_id=mesh_id,
            local_job_id=delegation.local_job_id,
            state=state,
            now=stamp,
        )
    except delegation_store.DelegationError:
        logger.warning(
            "delegation_sync: could not record %s as %s; leaving it for the next "
            "pass",
            delegation.local_job_id,
            state.value,
            exc_info=True,
        )
        return None

    _annotate(driver, delegation, state)
    return state


def _release_stub(driver, store, delegation: Delegation, mesh_id: str, stamp: int) -> dict:
    """
    Take the local parked stub out of the queue, and record that only if it worked.

    Returns the counter deltas rather than mutating a counter, so the caller holds
    the only copy. A failure here is deliberately NOT fatal to the pass - the other
    delegations are unaffected - and deliberately NOT recorded as a release, which
    is what leaves the retry possible.
    """
    try:
        driver.cancel(delegation.local_job_id)
    except Exception:
        logger.warning(
            "delegation_sync: could not release the parked stub %s for the finished "
            "remote job %s on %s. The ledger keeps it unreleased, so the next pass "
            "retries; until then the stub stays in the local queue.",
            delegation.local_job_id,
            delegation.remote_job_id,
            delegation.remote_cluster_id,
            exc_info=True,
        )
        return {"stubs_release_failed": 1}

    try:
        store.mark_stub_released(
            mesh_id=mesh_id, local_job_id=delegation.local_job_id, now=stamp
        )
    except delegation_store.DelegationError:
        # The stub IS out of the queue; only the record failed. Counted as a
        # failure so the next pass tries again, and a second cancel of an
        # already-cancelled job is harmless.
        logger.warning(
            "delegation_sync: released the stub %s but could not record it; the next "
            "pass will retry the record",
            delegation.local_job_id,
            exc_info=True,
        )
        return {"stubs_release_failed": 1}
    return {"stubs_released": 1}


def _annotate(driver, delegation: Delegation, state: NormalizedState) -> None:
    """
    Put the delegation's current state on the local stub, so `qstat -f` explains
    where the job actually is.

    Best effort, because an annotation is a convenience and must not cost the
    reconciliation. It is LOGGED on failure rather than discarded: the reference
    swallowed this with a bare `except Exception: pass`, which makes a driver whose
    annotate is broken for every job on the cluster completely invisible.
    """
    note = (
        f"delegated to {delegation.remote_cluster_id}:{delegation.remote_job_id} "
        f"({state.value})"
    )
    try:
        driver.annotate(delegation.local_job_id, note)
    except Exception:
        logger.warning(
            "delegation_sync: could not annotate %s; reconciliation continues",
            delegation.local_job_id,
            exc_info=True,
        )
