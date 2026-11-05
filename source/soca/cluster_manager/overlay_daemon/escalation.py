######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Turning sustained unreachability into a quorum proposal.

The reference prototype's `maybe_auto_decommission` writes DECOMMISSIONED directly
from one observer's row, with a comment admitting the multi-observer read is a TODO.
That is one possibly-partitioned cluster removing a healthy peer, and it predates the
quorum mechanism so it bypasses the agreement the peer API requires.

Here the same evidence raises a PROPOSAL instead. The other clusters vote from their
own observations, which is the corroboration a single observer cannot supply, and a
partition that isolates one cluster can never reach quorum.

Pure: `plan_escalation` takes the observations and the peers and returns a decision.
The caller writes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional

from .models import (
    FenceOperation,
    Health,
    HealthObservation,
    Lifecycle,
    Peer,
)

logger = logging.getLogger("soca_logger")

# Separate observers that must independently report a peer unavailable before its
# removal is proposed. Two, not one: one observer reporting unavailable is as likely
# to be its own partition as the peer's absence, and that is precisely the reference's
# defect. Not higher, because a mesh of three ACTIVE peers removing one has only two
# possible observers, and a threshold above two would make the smallest quorum-bearing
# mesh unable to ever escalate.
MIN_CORROBORATING_OBSERVERS = 2

# How long a peer must have been unreachable before removal is proposed at all. Days
# rather than minutes: the tunnel already stops carrying traffic to an UNAVAILABLE peer
# without anything being decommissioned, so there is no urgency, and a cluster being
# rebuilt or a region being unreachable for an afternoon must not cost it its
# membership.
DEFAULT_UNREACHABLE_DAYS = 7
MIN_UNREACHABLE_DAYS = 1


@dataclass(frozen=True)
class Escalation:
    """One peer whose removal should be proposed, and the evidence for it."""

    target: str
    observers: List[str]
    unreachable_since: int
    reason: str


def unreachable_threshold_seconds(days: Optional[int]) -> Optional[int]:
    """
    The configured threshold in seconds, or None when escalation is switched off.

    None means off, and off is the DEFAULT for the caller to choose: automatic
    escalation of a destructive operation should be opted into, not inherited.
    """
    if days is None:
        return None
    return max(MIN_UNREACHABLE_DAYS, days) * 86400


def active_observer_ids(peers: Iterable[Peer]) -> set:
    """
    The clusters whose observations count as evidence.

    Only an ACTIVE cluster is running a daemon that probes, so only an ACTIVE cluster
    can corroborate anything. This matters because decommissioning sets a peer's
    lifecycle rather than deleting its row, and nothing reaps `overlay_health`: a
    cluster removed from the mesh a year ago still has UNAVAILABLE rows in the table,
    naming peers it can no longer reach because it is gone.

    Counting those rows lets a ghost act as a corroborating observer. One live observer
    plus one dead cluster reaches MIN_CORROBORATING_OBSERVERS, which is enough to pull a
    healthy peer out of the rendered tunnel and enough to raise a decommission proposal
    against it. The corroboration requirement exists to make a single cluster's view
    insufficient, and an unfiltered count quietly returns it to one.
    """
    return {peer.cluster_id for peer in peers if peer.lifecycle == Lifecycle.ACTIVE}


def unavailable_observers_by_peer(
    observations: Iterable[HealthObservation], *, active_cluster_ids: set
) -> dict:
    """
    Which ACTIVE clusters report each peer UNAVAILABLE, as observed cluster to the set
    of observers.

    The single place this counting happens. It had been written out three times, in the
    tunnel's health map, the escalation planner and the admin view, and the peer-set
    filter was missing from all three. Two of them act on the count, so a divergence
    between them is not a display bug.
    """
    by_observed: dict = {}
    for observation in observations:
        if observation.health != Health.UNAVAILABLE:
            continue
        if observation.observer == observation.observed:
            # A cluster cannot corroborate its own unreachability. Nothing should
            # write such a row, and counting one would let a single cluster
            # manufacture a second observer.
            continue
        if observation.observer not in active_cluster_ids:
            continue
        if observation.observed not in active_cluster_ids:
            # A row about a cluster that is no longer ACTIVE is not evidence about the
            # mesh. Leaving it in produced a count for a peer with no row in the admin
            # matrix, which is the view appearing to contradict itself.
            continue
        by_observed.setdefault(observation.observed, set()).add(observation.observer)
    return by_observed


def plan_escalation(
    *,
    peers: Iterable[Peer],
    observations: Iterable[HealthObservation],
    threshold_seconds: Optional[int],
    now: Optional[int] = None,
) -> List[Escalation]:
    """
    Which peers have been unreachable long enough, by enough observers, to propose
    removing.

    Rules, each of which exists to stop a specific wrong removal:

      - only ACTIVE peers. Anything else is already out of the tunnel or already
        being decided.
      - at least MIN_CORROBORATING_OBSERVERS distinct observers reporting UNAVAILABLE.
        A missing or unreadable observation can only lower that count, so incomplete
        health data delays an escalation and can never cause one.
      - every corroborating observer must have last reached the peer longer ago than
        the threshold. Taking the OLDEST would let one stale observer carry a peer
        that everyone else reached minutes ago.
      - a peer no observer has ever reached is escalated on its join time instead, so
        a tunnel that never came up is not exempt forever.
    """
    if threshold_seconds is None:
        return []
    if now is None:
        now = int(time.time())

    observations = list(observations)
    corroborated = unavailable_observers_by_peer(
        observations, active_cluster_ids=active_observer_ids(peers)
    )

    escalations: List[Escalation] = []
    for peer in peers:
        if peer.lifecycle != Lifecycle.ACTIVE:
            continue

        # Distinct ACTIVE observers, because two rows from one observer are one
        # opinion and a decommissioned cluster's leftover rows are none.
        observers = sorted(corroborated.get(peer.cluster_id, set()))
        if len(observers) < MIN_CORROBORATING_OBSERVERS:
            continue

        corroborating = set(observers)
        reporting = [
            o
            for o in observations
            if o.observed == peer.cluster_id and o.observer in corroborating
        ]

        # The most recent success across the corroborating observers. If ANY of them
        # reached this peer recently, it has not been unreachable for the threshold,
        # whatever the others say.
        last_seen_values = [
            o.last_ok_ts if o.last_ok_ts is not None else peer.joined_at
            for o in reporting
        ]
        most_recent = max(last_seen_values)
        if (now - most_recent) < threshold_seconds:
            continue

        escalations.append(
            Escalation(
                target=peer.cluster_id,
                observers=observers,
                unreachable_since=most_recent,
                reason=(
                    f"unreachable from {len(observers)} clusters "
                    f"({', '.join(observers)}) since "
                    f"{(now - most_recent) // 86400} days ago; proposing "
                    f"decommission for the mesh to decide"
                ),
            )
        )
    return escalations


def already_proposed(
    escalation: Escalation, open_proposals: Iterable
) -> bool:
    """
    Whether a live proposal already covers this peer's removal.

    Checked so a peer unreachable for a month does not accumulate one proposal per
    probe round. Matches on target and operation only, and ignores who proposed it:
    every daemon plans the same escalation from the same shared rows, so without this
    an N-cluster mesh would raise N proposals for one peer.
    """
    from . import fence

    for proposal in open_proposals:
        if proposal.state in fence.TERMINAL_STATES:
            continue
        if (
            proposal.target == escalation.target
            and proposal.operation == FenceOperation.DECOMMISSION
        ):
            return True
    return False
