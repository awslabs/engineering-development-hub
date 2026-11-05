######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Whether a proposal may be raised, and whether a vote may be cast.

Imports no Flask, for the same reason `lifecycle.py` does not: `flask_restful` is
declared in no requirements file in this repository, so a module that imports it
cannot be imported by a test at all. Keeping the decisions here means every refusal
can be enumerated against every mesh state without a web stack, and `fence.py` is
left mapping HTTP onto a decision.

The refusals are the substance. Three of the four exist because the alternative is
not an error but a trap: a proposal that can never reach quorum, a proposal for a
transition that can never be applied, and a vote that is stored and then ignored.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from overlay_daemon import fence
from overlay_daemon.models import FenceOperation, Lifecycle

from api.v1.mesh import lifecycle as lifecycle_rules


class ProposalOutcome:
    """Why a planner answered as it did. Values are stable for the UI."""

    OK = "ok"
    NO_SUCH_PEER = "no_such_peer"
    QUORUM_NOT_REQUIRED = "quorum_not_required"
    TRANSITION_NOT_PERMITTED = "transition_not_permitted"
    DUPLICATE_PROPOSAL = "duplicate_proposal"
    PROPOSAL_CLOSED = "proposal_closed"
    VOTER_IS_TARGET = "voter_is_target"
    BAD_VOTING_WINDOW = "bad_voting_window"


# A refusal is a conflict rather than a client error wherever the request was well
# formed and the mesh's state is what makes it inapplicable. Only a missing peer is
# a 404, because that one names something that does not exist, and only the voting
# window is a 400, because that one is a malformed request rather than a state
# conflict.
OUTCOME_STATUS = {
    ProposalOutcome.NO_SUCH_PEER: 404,
    ProposalOutcome.QUORUM_NOT_REQUIRED: 409,
    ProposalOutcome.TRANSITION_NOT_PERMITTED: 409,
    ProposalOutcome.DUPLICATE_PROPOSAL: 409,
    ProposalOutcome.PROPOSAL_CLOSED: 409,
    ProposalOutcome.VOTER_IS_TARGET: 409,
    ProposalOutcome.BAD_VOTING_WINDOW: 400,
}


@dataclass(frozen=True)
class ProposalDecision:
    """
    Whether to proceed, and what to say when not.

    `reason` is operator-facing and names the way forward, because a refusal that
    only says no leaves someone guessing which endpoint to call instead.
    """

    allowed: bool
    outcome: str
    reason: str = ""

    @property
    def status_code(self) -> int:
        return OUTCOME_STATUS.get(self.outcome, 409)


def plan_proposal(
    *,
    operation: FenceOperation,
    target: str,
    peers: Iterable,
    existing_proposals: Iterable,
) -> ProposalDecision:
    """
    Whether a proposal for this operation may be raised now.

    Ordered deliberately, and the order is part of the answer: mesh size is checked
    before the transition, so a two-peer mesh is told to use the direct endpoint
    rather than being told its transition needs quorum, which would be true and
    useless.
    """
    peers = list(peers)
    peer = next((p for p in peers if p.cluster_id == target), None)
    if peer is None:
        return ProposalDecision(
            allowed=False,
            outcome=ProposalOutcome.NO_SUCH_PEER,
            reason=f"No peer {target} in this mesh.",
        )

    active_count = sum(1 for p in peers if p.lifecycle == Lifecycle.ACTIVE)
    threshold = lifecycle_rules.ADMIN_DECIDES_UP_TO_ACTIVE_PEERS
    if active_count <= threshold:
        # Refused rather than accepted, because a proposal here is a trap: the peer
        # API already lets one administrator perform the action directly, and
        # required_quorum(2) is 2, so a proposal raised at this size can never reach
        # quorum on the proposer's own vote. It would sit open until somebody used
        # the single-cluster override, which is a worse outcome than not offering it.
        return ProposalDecision(
            allowed=False,
            outcome=ProposalOutcome.QUORUM_NOT_REQUIRED,
            reason=(
                f"This mesh has {active_count} active peers, and quorum is not "
                f"required at or below {threshold}. Use "
                f"POST /api/v1/mesh/peers/{target}/{operation.value} directly. "
                f"Agreement among {active_count} clusters needs all of them, so a "
                f"proposal could not reach quorum here without the single-cluster "
                f"override."
            ),
        )

    # The same table the direct endpoint consults, so a proposal cannot be raised for
    # a transition that could never be applied. Above the threshold, a permitted
    # action answers NEEDS_QUORUM, which is precisely the case this exists to serve;
    # anything else is a real refusal.
    planned = lifecycle_rules.plan_transition(
        action=operation.value,
        current=peer.lifecycle,
        active_peer_count=active_count,
    )
    if planned.outcome != lifecycle_rules.Outcome.NEEDS_QUORUM:
        return ProposalDecision(
            allowed=False,
            outcome=ProposalOutcome.TRANSITION_NOT_PERMITTED,
            reason=(
                f"{operation.value} cannot be proposed for {target}: {planned.reason}"
            ),
        )

    duplicate = next(
        (
            p
            for p in existing_proposals
            if p.target == target
            and p.operation == operation
            and p.state not in fence.TERMINAL_STATES
        ),
        None,
    )
    if duplicate is not None:
        # BEST EFFORT, not atomic, and the comment says so because the code cannot.
        # This reads the proposals and then writes, and `put_fence_proposal` conditions
        # only on its own timestamp-derived id, so two concurrent creates for the same
        # target and operation can both pass here and both be stored. It catches what
        # actually happens, which is an operator clicking twice or two operators
        # looking at the same page minutes apart.
        #
        # The residual race is left rather than closed because its outcome is benign
        # and closing it is not free. If both proposals reach quorum, the first to
        # commit is applied and the second finds the peer already in the intended
        # lifecycle, which the apply step treats as done, so exactly one mutation
        # happens either way. Making it atomic would mean either a deterministic key
        # per target and operation, which then collides with a FINISHED proposal for
        # the same pair until the reaper clears it a week later, or a separate lock row
        # with its own cleanup failure modes.
        return ProposalDecision(
            allowed=False,
            outcome=ProposalOutcome.DUPLICATE_PROPOSAL,
            reason=(
                f"Proposal {duplicate.proposal_id} already proposes "
                f"{operation.value} for {target} and is still "
                f"{duplicate.state.value}. Vote on that one, or let it expire."
            ),
        )

    return ProposalDecision(allowed=True, outcome=ProposalOutcome.OK)


def plan_vote(*, proposal, voter: str) -> ProposalDecision:
    """Whether this cluster may vote on this proposal."""
    if proposal.state in fence.TERMINAL_STATES:
        return ProposalDecision(
            allowed=False,
            outcome=ProposalOutcome.PROPOSAL_CLOSED,
            reason=(
                f"Proposal {proposal.proposal_id} is {proposal.state.value} and is "
                f"no longer taking votes."
            ),
        )

    if proposal.target == voter:
        # Refused because the subject of a decision does not get a vote on it, and
        # the vote would carry real weight rather than none: `active_cluster_ids` is
        # every ACTIVE peer with no exclusion for the target, so a peer facing
        # decommission is in its own electorate and a NO from it counts toward the
        # quorum that would reject its removal.
        #
        # An earlier version of this comment claimed the opposite, that the tally
        # excluded the target so the vote would be stored and then ignored. That was
        # false, and measurably so: with a three-peer mesh and the target voting yes,
        # the tally reports yes=2 with the target among counted_voters. The refusal
        # was right and the reason was backwards.
        #
        # The target counting toward a quorum it cannot contribute to makes quorum
        # stricter than the majority it describes: at four ACTIVE peers, quorum is 3
        # and only 3 peers may vote, so agreement has to be unanimous. That is left
        # as it is because erring toward more agreement is the safe direction for a
        # destructive operation, and it is recorded here so it is a choice rather
        # than a surprise.
        return ProposalDecision(
            allowed=False,
            outcome=ProposalOutcome.VOTER_IS_TARGET,
            reason=(
                f"This cluster is the target of proposal {proposal.proposal_id}, so "
                f"it does not vote on it."
            ),
        )

    return ProposalDecision(allowed=True, outcome=ProposalOutcome.OK)


def check_voting_window(window: int) -> ProposalDecision:
    """
    Whether an explicitly requested voting window is within bounds.

    Takes an int the caller has already converted, because reading and converting a
    request body belongs at the endpoint where `SocaCastEngine` is available: that
    reaches Flask through `utils.error`, and this module stays importable without a
    web stack. The bounds are the rule, so they live here.
    """
    if not (
        fence.MIN_VOTING_WINDOW_SECONDS
        <= window
        <= fence.MAX_VOTING_WINDOW_SECONDS
    ):
        return ProposalDecision(
            allowed=False,
            outcome=ProposalOutcome.BAD_VOTING_WINDOW,
            reason=(
                f"voting_window_seconds must be between "
                f"{fence.MIN_VOTING_WINDOW_SECONDS} and "
                f"{fence.MAX_VOTING_WINDOW_SECONDS}, and {window} is outside that. "
                f"The lower bound exists because the other clusters have to be able "
                f"to see the proposal and answer it."
            ),
        )
    return ProposalDecision(allowed=True, outcome=ProposalOutcome.OK)
