######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Quorum decisions for the operations the mesh API refuses to take alone.

CR-304228329 shipped a transition table that refuses decommission, tombstone and
reclaim on any mesh with more than two ACTIVE peers, with the outcome NEEDS_QUORUM
and a message saying the action must go through a quorum proposal. Nothing in the
tree could create one, so those three actions were unreachable on a real mesh.
This module is the decision half of making them reachable.

What quorum here is, and is not
-------------------------------
It is a two-person rule. It stops one administrator acting alone on an operation
whose blast radius is a whole cluster, and it stops a mistake becoming a fact
before anyone else has seen it.

It is NOT a defence against a hostile mesh member, and it is worth being blunt
about that because the opposite is easy to assume from the word quorum. Every
mesh member holds the participant role, and helpers/cdk/cross_region's
mesh_write_actions grants that role PutItem, UpdateItem and, on overlay_config
specifically, DeleteItem. Peer lifecycle rows live in overlay_config. So a member
that wanted a cluster decommissioned could write that lifecycle directly and never
touch a proposal. Vote tampering would be a strictly weaker move than one the same
credential already permits, so hardening the ballot while the ballot's subject
stays writable would buy nothing.

The consequence for reading this module: the tally is honest arithmetic among
cooperating peers, not a consensus protocol that survives a liar.

Storage
-------
Proposals and votes live in overlay_config under namespaced sort keys,
"fence#<proposal_id>" and "vote#<proposal_id>#<voter>". The shipped reader is
already built for that: query_mesh skips those prefixes rather than validating
them as peers, and its tests cover them. Nothing accumulates forever, because the
daemon reaps finalised proposals on its own cycle; overlay_config declares no TTL
attribute and adding one would put every row in the table under a reaper, which is
too blunt for a table that also holds peer lifecycle.

Imports
-------
Standard library and relative modules only. This module is loaded by the daemon's
serve loop, and CR-304228329's round six found that a single outside import here
turns a packaging change into total daemon failure rather than one broken query. A
test pins the dependency set.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, replace
from typing import Iterable, List, Optional

from .models import (
    FenceOperation,
    FenceProposal,
    FenceVote,
    Lifecycle,
    Peer,
    ProposalState,
    VoteValue,
)

logger = logging.getLogger("soca_logger")

# Sort-key namespaces inside overlay_config. Named here and used everywhere, so
# the reader in ddb_client and the writer in this module cannot disagree about
# what a fence row looks like.
PROPOSAL_PREFIX = "fence#"
VOTE_PREFIX = "vote#"

# How long a proposal collects votes for by default.
DEFAULT_VOTING_WINDOW_SECONDS = 15 * 60

# Bounds on a caller-supplied window. The floor exists because a window shorter
# than a daemon sync interval closes before peers have plausibly seen the
# proposal, which would manufacture stalls; the ceiling exists because an open
# proposal is a pending destructive action and should not outlive an operator's
# attention.
MIN_VOTING_WINDOW_SECONDS = 60
MAX_VOTING_WINDOW_SECONDS = 24 * 60 * 60

# States a proposal can no longer move out of. SUPERSEDED is here so an operation
# that stopped being applicable becomes reapable like any other finished proposal:
# leaving it open meant it re-decided every cycle, failed to apply every cycle, and
# was never eligible for the reaper, so it logged forever and accumulated.
TERMINAL_STATES = frozenset(
    {
        ProposalState.COMMITTED,
        ProposalState.REJECTED,
        ProposalState.STALLED,
        ProposalState.SUPERSEDED,
        ProposalState.CANCELLED,
    }
)


def proposal_sort_key(proposal_id: str) -> str:
    """The overlay_config sort key for a proposal row."""
    return f"{PROPOSAL_PREFIX}{proposal_id}"


def vote_sort_key(proposal_id: str, voter: str) -> str:
    """
    The overlay_config sort key for one peer's vote on one proposal.

    Keyed on the pair so a peer changing its mind rewrites its own row.
    """
    return f"{VOTE_PREFIX}{proposal_id}#{voter}"


def clamp_voting_window(requested: Optional[int]) -> int:
    """
    A usable voting window, from whatever the caller asked for.

    Clamped rather than refused: an out-of-range window is a caller being
    careless with a number, not a reason to block a destructive operation from
    being proposed at all. The value actually used is stored on the proposal, so
    what was applied is visible afterwards rather than inferred from the request.
    """
    if requested is None:
        return DEFAULT_VOTING_WINDOW_SECONDS
    return max(MIN_VOTING_WINDOW_SECONDS, min(MAX_VOTING_WINDOW_SECONDS, requested))


def active_cluster_ids(peers: Iterable[Peer]) -> set:
    """The cluster ids currently ACTIVE, which is the electorate."""
    return {peer.cluster_id for peer in peers if peer.lifecycle == Lifecycle.ACTIVE}


def required_quorum(active_count: int) -> int:
    """
    Votes needed to decide, as a simple majority of the ACTIVE peers.

    floor(N/2) + 1. Two properties follow and both are relied on elsewhere, so
    they are stated here rather than rediscovered.

    A majority always exceeds half the electorate, so yes and no can never both
    reach quorum on the same proposal. evaluate_proposal checks no before yes
    without needing to worry about the order being load-bearing, and a test
    asserts the exclusivity across mesh sizes rather than trusting this comment.

    On an empty electorate this is 0. That is a degenerate mesh with nothing to
    decide about, and evaluate_proposal refuses rather than treating 0 as met.
    """
    if active_count <= 0:
        return 0
    return active_count // 2 + 1


@dataclass(frozen=True)
class Tally:
    """
    The count, and everything a caller needs to explain it.

    Carries active_count and quorum alongside the votes so a message can say
    "1 of 2 needed" without recomputing the electorate and risking a different
    answer than the one the decision used.
    """

    yes: int
    no: int
    abstain: int
    active_count: int
    quorum: int
    counted_voters: frozenset
    silent_voters: frozenset
    votes_besides_proposer: int

    @property
    def yes_quorum_reached(self) -> bool:
        return self.quorum > 0 and self.yes >= self.quorum

    @property
    def no_quorum_reached(self) -> bool:
        return self.quorum > 0 and self.no >= self.quorum

    @property
    def anyone_else_responded(self) -> bool:
        """
        Whether any ACTIVE peer other than the proposer expressed a view.

        This is the difference between a window that closed on silence and one
        that closed on disagreement, which is the difference between STALLED and
        REJECTED. It counts votes rather than voters deliberately: an abstention
        is a response, so a mesh that looked at a proposal and declined to back it
        is not treated as a mesh that never answered.
        """
        return self.votes_besides_proposer > 0


def tally(
    proposal: FenceProposal,
    votes: Iterable[FenceVote],
    peers: Iterable[Peer],
) -> Tally:
    """
    Count a proposal's votes against the current electorate.

    Three rules, each of which changes an outcome:

    The proposer carries an implicit yes, because proposing is supporting. It
    counts ONLY while the proposer is still ACTIVE: a cluster that decommissions
    itself mid-window stops voting, so its proposal does not keep a supporter it
    no longer has.

    Votes from peers that are no longer ACTIVE are dropped, for the same reason
    in the other direction. The electorate is who is active now, not who was
    active when the proposal opened, so a mesh that shrinks mid-window has its
    quorum recomputed rather than measured against a stale roll.

    A voter appearing twice is counted once, taking the later vote by timestamp.
    The sort key makes that unreachable through this module, but a duplicate row
    is not the only way two rows could arrive, and silently double-counting a
    voter would inflate a tally toward committing.
    """
    active = active_cluster_ids(peers)
    counted: dict = {}

    for vote in votes:
        if vote.voter not in active:
            continue
        existing = counted.get(vote.voter)
        if existing is None or vote.voted_at >= existing.voted_at:
            counted[vote.voter] = vote

    yes = 0
    no = 0
    abstain = 0

    proposer_is_active = proposal.proposer in active
    if proposer_is_active:
        yes += 1
        # An explicit vote from the proposer is not counted twice. It also does
        # not override the implicit yes: a proposer that wants to withdraw
        # support cancels the proposal rather than voting against it, which is a
        # clearer record than a proposal whose own author voted no.
        counted.pop(proposal.proposer, None)

    for vote in counted.values():
        if vote.vote == VoteValue.YES:
            yes += 1
        elif vote.vote == VoteValue.NO:
            no += 1
        else:
            abstain += 1

    counted_voters = set(counted)
    if proposer_is_active:
        counted_voters.add(proposal.proposer)

    return Tally(
        yes=yes,
        no=no,
        abstain=abstain,
        active_count=len(active),
        quorum=required_quorum(len(active)),
        counted_voters=frozenset(counted_voters),
        silent_voters=frozenset(active - counted_voters),
        votes_besides_proposer=len(counted),
    )


@dataclass(frozen=True)
class Decision:
    """
    What a proposal's state should be, and why.

    `state` is only ever a state the caller may write. `reason` is operator-facing
    and names the numbers, because "not enough votes" sends someone to read the
    table while "1 yes of 2 needed, 1 peer silent" does not.
    """

    state: ProposalState
    tally: Tally
    reason: str

    @property
    def is_final(self) -> bool:
        return self.state in TERMINAL_STATES


def _why_inapplicable(proposal: FenceProposal, peers: Iterable[Peer]) -> Optional[str]:
    """
    Why this operation can no longer be applied to its target, or None.

    Consulted before the votes, because no tally makes an inapplicable operation
    applicable. A proposal raised while its target was ACTIVE can still be open
    after that peer has moved, and the operation is then moot rather than pending.

    A target already IN the operation's intended lifecycle is NOT inapplicable: the
    end state the proposal asked for holds, so the apply step treats it as done and
    the votes still decide whether it is recorded as committed. Only a target that
    can never be moved by this operation is superseded.
    """
    target = next(
        (p for p in peers if p.cluster_id == proposal.target), None
    )
    if target is None:
        return (
            f"superseded: {proposal.target} has no peer row in this mesh, so "
            f"{proposal.operation.value} has nothing to apply to"
        )
    if target.lifecycle == proposal.operation.target_lifecycle:
        return None
    if target.lifecycle not in proposal.operation.permitted_from:
        return (
            f"superseded: {proposal.target} is now {target.lifecycle.value}, and "
            f"{proposal.operation.value} is only permitted from "
            f"{', '.join(sorted(s.value for s in proposal.operation.permitted_from))}"
        )
    return None


def evaluate_proposal(
    proposal: FenceProposal,
    votes: Iterable[FenceVote],
    peers: Iterable[Peer],
    *,
    now: Optional[int] = None,
) -> Decision:
    """
    Decide the state a proposal should be in, from its votes and the clock.

    THE ORDER OF THE CHECKS BELOW IS THE DEFINITION of REJECTED versus STALLED.
    Those two overlap in prose, since both can describe a window that closed
    without enough support, and the reference this was ported from defined them
    ambiguously in one docstring and disambiguated them only by the order of an
    if-chain. Rather than repeat that, the order is stated here and a test asserts
    each branch is reachable.

      1. A proposal already finalised is returned unchanged. Re-evaluating is
         normal, because every daemon on every cycle does it.
      2. An empty electorate refuses. Quorum of zero is not quorum met.
      3. An operation that can no longer be applied to its target is SUPERSEDED,
         checked before the votes are consulted because no tally makes an
         inapplicable operation applicable. The alternative was a proposal that
         reached quorum, failed to apply every cycle forever, and was never
         reapable because it never reached a terminal state.
      4. A recorded override commits, whatever the votes say.
      5. Explicit no reaching quorum rejects, at any time. A decided no does not
         wait for a window to close.
      6. Yes reaching quorum commits, at any time, PROVIDED at least one peer
         besides the proposer voted. Waiting once real support exists would leave
         a decided proposal pending for no reason, but the proviso is not
         optional: the electorate is recomputed each evaluation, so a mesh that
         shrinks to a lone ACTIVE proposer has required_quorum(1) == 1, which the
         proposer's own implicit yes satisfies. Without the proviso a cluster
         could decommission a peer entirely on its own decision the moment it
         became the last one standing, which is precisely the unilateral action
         this whole mechanism exists to prevent. It only ever bites when quorum
         is 1, because reaching a quorum above 1 on the implicit yes alone is
         arithmetically impossible.
      7. Window still open: stays open.
      8. Window closed and nobody but the proposer said anything: STALLED.
         Silence is not consent. This is the case the reference documented
         backwards, claiming a two-peer mesh "commits unless the other peer
         rejects"; its own implementation stalled, and stalling is right, because
         an unreachable peer must not be read as agreement to decommission a
         cluster.
      9. Window closed with responses but not enough support: REJECTED. The mesh
         looked and declined.

    The caller writes the state conditionally. Two daemons evaluating the same
    proposal in the same second must not both commit it, and that is enforced at
    the write rather than here, because this function is pure.
    """
    if now is None:
        now = int(time.time())

    counted = tally(proposal, votes, peers)

    if proposal.state in TERMINAL_STATES:
        return Decision(proposal.state, counted, "already finalised")

    if counted.active_count == 0:
        return Decision(
            ProposalState.OPEN,
            counted,
            "no ACTIVE peers, so there is no electorate and nothing to decide",
        )

    superseded = _why_inapplicable(proposal, peers)
    if superseded is not None:
        return Decision(ProposalState.SUPERSEDED, counted, superseded)

    if proposal.committed_by_override:
        return Decision(
            ProposalState.COMMITTED,
            counted,
            "committed by recorded operator override rather than by quorum",
        )

    if counted.no_quorum_reached:
        return Decision(
            ProposalState.REJECTED,
            counted,
            f"rejected: {counted.no} no of {counted.quorum} needed",
        )

    # The second condition is load-bearing, not a belt-and-braces check. See rule 6
    # in the docstring: a mesh that has shrunk to a lone ACTIVE proposer needs a
    # quorum of one, which its own implicit yes meets, so without this a cluster
    # could decommission a peer on nobody's decision but its own.
    if counted.yes_quorum_reached and counted.votes_besides_proposer > 0:
        return Decision(
            ProposalState.COMMITTED,
            counted,
            f"committed: {counted.yes} yes of {counted.quorum} needed",
        )

    if now < proposal.expires_at:
        return Decision(
            ProposalState.OPEN,
            counted,
            f"open: {counted.yes} yes and {counted.no} no of {counted.quorum} "
            f"needed, {len(counted.silent_voters)} peer(s) yet to answer",
        )

    if not counted.anyone_else_responded:
        return Decision(
            ProposalState.STALLED,
            counted,
            f"stalled: the voting window closed with no peer besides the "
            f"proposer having answered, and silence is not consent. "
            f"{len(counted.silent_voters)} peer(s) were silent",
        )

    return Decision(
        ProposalState.REJECTED,
        counted,
        f"rejected: the voting window closed with {counted.yes} yes of "
        f"{counted.quorum} needed",
    )


def new_proposal_id(now_ms: Optional[int] = None) -> str:
    """
    A proposal id that sorts chronologically, for the same reason audit ids do.

    Proposals share overlay_config with peer rows, so they are not read by a
    range query the way audit events are, and nothing today depends on their
    order. They are built sortable anyway because CR-304228329 shipped an audit
    sort key that was a random UUID under a comment claiming it was ordered, and
    the cost of getting this right now is one function call.
    """
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return f"{now_ms:020d}#{uuid.uuid4()}"


def create_proposal(
    *,
    mesh_id: str,
    proposer: str,
    operation: FenceOperation,
    target: str,
    reason: str,
    voting_window_seconds: Optional[int] = None,
    committed_by_override: bool = False,
    now: Optional[int] = None,
    metadata: Optional[dict] = None,
) -> FenceProposal:
    """
    Build a proposal row. Pure: the caller writes it.

    `committed_by_override` is accepted here and stored, so a bypass is a property
    of the record rather than a fact about one request that nothing keeps. The
    authorisation question it raises is settled at the endpoint, and settled
    honestly: there is no permission in this architecture a proposer cannot
    self-grant, so the override is justified by being recorded and attributable
    rather than by being gated.
    """
    if now is None:
        now = int(time.time())
    window = clamp_voting_window(voting_window_seconds)
    return FenceProposal(
        mesh_id=mesh_id,
        proposal_id=new_proposal_id(now * 1000),
        proposer=proposer,
        operation=operation,
        target=target,
        reason=reason,
        proposed_at=now,
        expires_at=now + window,
        state=ProposalState.OPEN,
        committed_by_override=committed_by_override,
        metadata=dict(metadata or {}),
    )


def create_vote(
    *,
    mesh_id: str,
    proposal_id: str,
    voter: str,
    vote: VoteValue,
    reason: str = "",
    now: Optional[int] = None,
) -> FenceVote:
    """Build a vote row. Pure: the caller writes it."""
    if now is None:
        now = int(time.time())
    return FenceVote(
        mesh_id=mesh_id,
        proposal_id=proposal_id,
        voter=voter,
        vote=vote,
        voted_at=now,
        reason=reason,
    )


def with_state(proposal: FenceProposal, state: ProposalState) -> FenceProposal:
    """The same proposal in a new state, for the caller to write conditionally."""
    return replace(proposal, state=state)


def is_reapable(
    proposal: FenceProposal,
    *,
    now: Optional[int] = None,
    retain_seconds: int = 7 * 24 * 60 * 60,
) -> bool:
    """
    Whether a finalised proposal is old enough to delete.

    The daemon reaps rather than DynamoDB expiring rows, and that is a deliberate
    choice with a reason worth keeping. overlay_config declares no TTL attribute,
    and adding one would put every row in the table under a reaper, including the
    peer lifecycle rows and the mesh metadata row. A per-row decision made by code
    that knows which rows are proposals is narrower than a table-wide rule that
    trusts every writer never to set the attribute by accident.

    Only finalised proposals are reapable: an open one is a pending destructive
    action and deleting it would silently drop a decision in progress. Retention
    is generous because a proposal is the record of why a cluster was removed, and
    the audit log holds the event but not the vote breakdown.
    """
    if now is None:
        now = int(time.time())
    if proposal.state not in TERMINAL_STATES:
        return False
    decided_at = max(proposal.proposed_at, proposal.expires_at)
    return now - decided_at >= retain_seconds
