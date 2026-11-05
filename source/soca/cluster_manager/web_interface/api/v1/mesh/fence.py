######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Quorum proposals and votes for fenced mesh operations. Admin-only.

This is what makes decommission, tombstone and reclaim reachable. The peer API
refuses all three on a mesh with more than two active peers, and until now nothing
could create a proposal, so those refusals were dead ends.

### A cluster's vote is the cluster the request arrived at, never a body field

The proposer and the voter are both taken from `resolve_self_cluster_id`, and there
is deliberately no way to name either in the request. If the voter came from the
body, an administrator on one cluster could cast another cluster's vote, and the
whole point of quorum is that the clusters agree separately. This is the same
mistake the audit actor had in CR-304228329, where the recorded identity came from
a header the caller controlled.

The human who clicked is recorded too, in the audit row rather than on the ballot:
the vote belongs to the cluster, and which administrator cast it is accountability
information. CR-304228329's actor fix is what makes that trustworthy.

### What quorum here is, and is not

It is a two-person rule against mistakes and unilateral action by cooperating
peers. It is NOT a defence against a hostile mesh member: `mesh_write_actions`
grants PutItem, UpdateItem and, on overlay_config specifically, DeleteItem, and
peer lifecycle rows live in that table, so any cluster holding the mesh write role
can write the outcome directly without voting at all. Hardening the ballot while
the ballot's subject stays writable would buy nothing.

### The override is recorded, not authorised

`single_cluster_override` lets a proposer commit without quorum, and what follows is
the accurate account of when it is reachable, because an earlier revision of this
docstring gave a wrong one that review caught.

It said the override was necessary because a two-peer mesh whose other cluster was
down would otherwise deadlock. **That state cannot occur.** `plan_proposal` refuses
any proposal at or below `ADMIN_DECIDES_UP_TO_ACTIVE_PEERS` with
`QUORUM_NOT_REQUIRED`, so a two-active-peer mesh cannot create a proposal at all, and
it does not need to: `plan_transition` permits the direct action at that size. So the
override is only ever reachable on a mesh ABOVE the threshold.

What it actually does there is let one administrator commit a decommission, tombstone
or reclaim with no agreement from two or more other ACTIVE clusters. That is a
unilateral destructive action, and describing it as a deadlock-breaker understated it.

The reason it still exists is narrower than the old rationale and real. The electorate
is computed from `lifecycle == ACTIVE`, not from reachability, so a peer that is
partitioned or dead but has not been decommissioned still counts toward quorum and
cannot vote. A mesh of five ACTIVE peers with three unreachable needs a quorum of 3
and has 2 able to answer, so every proposal stalls and no amount of waiting fixes it.
Without an override the mesh could not remove anything until somebody edited peer
rows directly, which is the outcome quorum exists to make unnecessary.

**Nothing verifies that the silent clusters are genuinely unreachable**, and nothing
can: a partition looks identical from both sides, and the proposer is the only party
present to ask. That is exactly why this is accountability rather than permission, and
why IAM-gating it is close to unimplementable here: the proposer is administrator of
its own cluster and no central authority exists. The reference prototype's docstring
claims it is IAM-gated while its implementation gates it with a typed confirmation in
the same request body, so the claim was dropped and the mechanism kept, justified by
being visible instead:

- stored as `committed_by_override` on the proposal row, so a bypass is a property of
  the record rather than a fact about one request that nothing keeps
- named in the decision reason
- attributable, because CR-304228329 fixed the audit actor to come from
  `g.authenticated_user` rather than a header the caller controls
- logged at warning level when the proposal is raised
- rendered on the admin page as a bypassed proposal
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional, Tuple

from flask_restful import Resource
from flask import request

from decorators import admin_api
from api.v1.mesh._actor import actor_from_request
from api.v1.mesh._context import (
    MeshContextError,
    mesh_endpoint,
    resolve_mesh_id,
    resolve_self_cluster_id,
)
from api.v1.mesh import _proposal_rules
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

from overlay_daemon import ddb_client, fence
from overlay_daemon.models import (
    AuditEvent,
    FenceOperation,
    Lifecycle,
    VoteValue,
    new_event_id,
)

logger = logging.getLogger("soca_logger")


def _audit(
    *,
    mesh_id: str,
    action: str,
    target: str,
    reason: str,
    actor: str,
    metadata: dict,
) -> None:
    """
    Record what happened, and never fail the request because recording failed.

    The write this describes has already happened by the time this runs, so raising
    would report a failure for something that succeeded. Logged at exception level
    so a gap in the audit trail stays discoverable.

    `source_cluster_id` is set, which peers.py did not do. AuditEvent documents why
    the field exists: an actor of "edhadmin" is ambiguous across a mesh of N
    clusters because every cluster has one. That ambiguity is worse here than
    anywhere else, because the single-cluster override is justified by being
    attributable and an unattributable override is just an unchecked one.
    """
    now_ms = int(time.time() * 1000)
    try:
        source = resolve_self_cluster_id()
    except MeshContextError:
        # Tolerated rather than raised: this cluster is bound to a mesh, since the
        # operation being audited just succeeded against it. An empty source is a
        # less precise audit row, not a reason to lose one.
        source = ""
    try:
        ddb_client.append_audit_event(
            AuditEvent(
                mesh_id=mesh_id,
                event_id=new_event_id(now_ms, str(uuid.uuid4())),
                action=action,
                target_cluster_id=target,
                actor=actor,
                reason=reason,
                ts=now_ms // 1000,
                metadata=metadata,
                source_cluster_id=source,
            )
        )
    except Exception:
        logger.exception(
            "mesh audit write failed for %s on %s; the operation itself succeeded",
            action,
            target,
        )


def _proposal_to_json(proposal, decision=None) -> dict:
    """
    One proposal as the UI needs it.

    The live decision is included when the caller has the votes to compute it, so a
    page can show "1 yes of 2 needed" without reimplementing the tally in
    JavaScript. `committed_by_override` is always present, including when false,
    because a field that appears only on bypassed proposals is one a reader can
    mistake for absent rather than negative.
    """
    payload = {
        "proposal_id": proposal.proposal_id,
        "proposer": proposal.proposer,
        "operation": proposal.operation.value,
        "target": proposal.target,
        "reason": proposal.reason,
        "proposed_at": proposal.proposed_at,
        "expires_at": proposal.expires_at,
        "state": proposal.state.value,
        "committed_by_override": proposal.committed_by_override,
    }
    if decision is not None:
        payload["tally"] = {
            "yes": decision.tally.yes,
            "no": decision.tally.no,
            "abstain": decision.tally.abstain,
            "quorum_needed": decision.tally.quorum,
            "active_peers": decision.tally.active_count,
            # Named rather than counted, because "2 clusters have not answered" sends
            # an administrator looking for which ones, and the page can chase them.
            "silent": sorted(decision.tally.silent_voters),
        }
        payload["would_become"] = decision.state.value
        payload["decision_reason"] = decision.reason
    return payload


def _vote_to_json(vote) -> dict:
    return {
        "voter": vote.voter,
        "vote": vote.vote.value,
        "voted_at": vote.voted_at,
        "reason": vote.reason,
    }


def _read_body() -> dict:
    """
    The request body as a dict, never None.

    `get_json(silent=True)` answers None both for a malformed body and for no body
    at all, and every caller here treats a missing field the same way, so the
    distinction would only add a branch nothing acts on differently.
    """
    body = request.get_json(silent=True)
    return body if Validators.is_dict(body) else {}


def _read_override(body: dict):
    """
    Whether the caller asked to bypass quorum, or the refusal to return.

    This was `bool(body.get("single_cluster_override", False))`, which is a genuine
    defect rather than a style problem, because `bool` of a non-empty string is True:
    a body carrying `"false"`, `"False"`, `"no"` or `"0"` would have switched quorum
    OFF while plainly saying otherwise. That is the most consequential flag in this
    module, so it is the last one that should guess.

    `SocaCastEngine` reads all four of those as False, and refuses a value it cannot
    read rather than defaulting either way. Refusing is right here: for a flag that
    disables the agreement of every other cluster, an unreadable value must not
    resolve to the permissive answer, and it must not silently resolve to the safe one
    either, because the caller believes they asked for something.
    """
    if "single_cluster_override" not in body:
        return False, None

    cast = SocaCastEngine(body.get("single_cluster_override")).cast_as(bool)
    if not cast.success:
        return None, SocaError.GENERIC_ERROR(
            helper=(
                "single_cluster_override must be a boolean. Send true or false, or "
                "leave it out, which means false. It bypasses the agreement of every "
                "other cluster in the mesh, so a value that cannot be read as a "
                "boolean is refused rather than guessed."
            ),
            status_code=400,
        ).as_flask()
    return cast.message, None


def _read_voting_window(body: dict):
    """
    The requested voting window, or the refusal to return.

    Parsed here rather than in `_proposal_rules`, because reading a request body is
    not a mesh rule and `SocaCastEngine` reaches Flask through `utils.error`, which
    that module deliberately does not. The bounds themselves are the rule and stay
    there.

    Refused rather than clamped: silently granting a fifteen-minute window to
    somebody who asked for ten seconds is a substitution they would not discover
    until it mattered. `fence.create_proposal` still clamps, which keeps the stored
    value sane for any caller that does not come through here.
    """
    if "voting_window_seconds" not in body:
        return None, None

    cast = SocaCastEngine(body.get("voting_window_seconds")).cast_as(int)
    if not cast.success:
        return None, SocaError.GENERIC_ERROR(
            helper=(
                f"voting_window_seconds must be a whole number of seconds between "
                f"{fence.MIN_VOTING_WINDOW_SECONDS} and "
                f"{fence.MAX_VOTING_WINDOW_SECONDS}."
            ),
            status_code=400,
        ).as_flask()

    window = cast.message
    decision = _proposal_rules.check_voting_window(window)
    if not decision.allowed:
        return None, SocaError.GENERIC_ERROR(
            helper=decision.reason,
            status_code=decision.status_code,
        ).as_flask()
    return window, None


class MeshProposalList(Resource):
    @admin_api
    @mesh_endpoint
    def get(self):
        """Every proposal, with a live tally on the ones still open."""
        try:
            mesh_id = resolve_mesh_id()
        except MeshContextError as e:
            return SocaError.GENERIC_ERROR(
                helper=str(e), status_code=e.status_code
            ).as_flask()

        try:
            proposals = ddb_client.read_fence_proposals(mesh_id)
            peers, _meta = ddb_client.query_mesh(mesh_id)
        except ddb_client.DDBQueryError as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Could not read proposals for mesh {mesh_id}: {e}",
                status_code=503,
            ).as_flask()

        rows = []
        for proposal in proposals:
            decision = None
            if proposal.state not in fence.TERMINAL_STATES:
                try:
                    votes = ddb_client.read_fence_votes(
                        mesh_id, proposal.proposal_id
                    )
                except ddb_client.DDBBallotIncompleteError as e:
                    # Distinguished from a transient read because it needs a person:
                    # the row stays malformed until somebody repairs it, so this is an
                    # error rather than a warning even though the page still renders.
                    logger.error(
                        "proposal %s has an unreadable vote row and is listed "
                        "without a tally: %s",
                        proposal.proposal_id,
                        e,
                    )
                    votes = None
                except ddb_client.DDBQueryError as e:
                    # One unreadable proposal must not blank the whole list, which is
                    # the page an administrator uses to see what is waiting on them.
                    logger.warning(
                        "could not read votes for proposal %s: %s",
                        proposal.proposal_id,
                        e,
                    )
                    votes = None
                if votes is not None:
                    decision = fence.evaluate_proposal(proposal, votes, peers)
            rows.append(_proposal_to_json(proposal, decision))

        return SocaResponse(
            success=True,
            message={
                "mesh_id": mesh_id,
                "self_cluster_id": _self_cluster_id_or_none(),
                "proposals": rows,
                "count": len(rows),
            },
        ).as_flask()

    @admin_api
    @mesh_endpoint
    def post(self):
        """Raise a proposal for an operation this cluster cannot perform alone."""
        try:
            mesh_id = resolve_mesh_id()
            proposer = resolve_self_cluster_id()
        except MeshContextError as e:
            return SocaError.GENERIC_ERROR(
                helper=str(e), status_code=e.status_code
            ).as_flask()

        body = _read_body()

        operation, complaint = _read_operation(body)
        if complaint is not None:
            return complaint

        # Type-checked before it is normalised, because a non-string target otherwise
        # becomes its repr and then fails the peer lookup with a 404 naming something
        # like "{'a': 1}". That reads as a peer that is missing rather than a field
        # that is the wrong type. `SocaCastEngine.cast_as(str)` would not help here: it
        # is behaviourally identical to `str()` for every input, including dicts and
        # None, so it refuses nothing.
        if "target" in body and not Validators.is_string(body.get("target")):
            return SocaError.GENERIC_ERROR(
                helper="target must be a string, the cluster_id of the peer.",
                status_code=400,
            ).as_flask()
        target = str(body.get("target") or "").strip()
        if not target:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="target",
                helper="The cluster_id of the peer the operation applies to.",
                status_code=400,
            ).as_flask()

        reason = str(body.get("reason") or "").strip()
        if not reason:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="reason",
                helper=(
                    "A reason is required to raise a proposal. The other clusters "
                    "vote on it, so it is what they are deciding against, and it is "
                    "recorded against your identity."
                ),
                status_code=400,
            ).as_flask()

        window, complaint = _read_voting_window(body)
        if complaint is not None:
            return complaint

        override, complaint = _read_override(body)
        if complaint is not None:
            return complaint

        try:
            peers, _meta = ddb_client.query_mesh(mesh_id)
            existing = ddb_client.read_fence_proposals(mesh_id)
        except ddb_client.DDBQueryError as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Could not read mesh {mesh_id}: {e}",
                status_code=503,
            ).as_flask()

        decision = _proposal_rules.plan_proposal(
            operation=operation,
            target=target,
            peers=peers,
            existing_proposals=existing,
        )
        if not decision.allowed:
            return SocaError.GENERIC_ERROR(
                helper=decision.reason,
                status_code=decision.status_code,
            ).as_flask()

        active_count = sum(1 for p in peers if p.lifecycle == Lifecycle.ACTIVE)

        proposal = fence.create_proposal(
            mesh_id=mesh_id,
            proposer=proposer,
            operation=operation,
            target=target,
            reason=reason,
            voting_window_seconds=window,
            committed_by_override=override,
        )
        try:
            ddb_client.put_fence_proposal(proposal)
        except ddb_client.DDBConditionFailedError:
            return SocaError.GENERIC_ERROR(
                helper=(
                    "A proposal with that identifier already exists. Retry: the "
                    "identifier carries a timestamp, so a fresh one will differ."
                ),
                status_code=409,
            ).as_flask()
        except ddb_client.DDBQueryError as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Could not store the proposal: {e}",
                status_code=503,
            ).as_flask()

        actor = actor_from_request()
        _audit(
            mesh_id=mesh_id,
            action="quorum_proposed",
            target=target,
            reason=reason,
            actor=actor,
            metadata={
                "proposal_id": proposal.proposal_id,
                "operation": operation.value,
                "proposer": proposer,
                "expires_at": proposal.expires_at,
                "single_cluster_override": override,
                # Named so the audit trail carries the electorate the proposal was
                # raised against, which is what its quorum was computed from.
                "active_peers": active_count,
            },
        )
        if override:
            # Deliberately its own line at warning level. The override is acceptable
            # because it is visible, so it has to actually be visible.
            logger.warning(
                "proposal %s was raised with the single-cluster override by %s, so "
                "it will commit without agreement from the other clusters in mesh %s",
                proposal.proposal_id,
                actor,
                mesh_id,
            )

        return SocaResponse(
            success=True,
            message=_proposal_to_json(proposal),
        ).as_flask()


class MeshProposalDetail(Resource):
    @admin_api
    @mesh_endpoint
    def get(self, proposal_id: str):
        """One proposal with its votes and its live tally."""
        try:
            mesh_id = resolve_mesh_id()
        except MeshContextError as e:
            return SocaError.GENERIC_ERROR(
                helper=str(e), status_code=e.status_code
            ).as_flask()

        proposal, error = _load_proposal(mesh_id, proposal_id)
        if error is not None:
            return error

        try:
            votes = ddb_client.read_fence_votes(mesh_id, proposal_id)
            peers, _meta = ddb_client.query_mesh(mesh_id)
        except ddb_client.DDBBallotIncompleteError as e:
            # Caught before the retryable case, and answered 200 with no tally rather
            # than 503. A malformed vote row does not clear on its own, so a retryable
            # status would have a client retry forever, and this endpoint previously
            # did exactly that while the list endpoint rendered the same proposal
            # without a tally. The two now agree, and the honest answer is the
            # proposal with its ballot marked uncounted.
            logger.error(
                "proposal %s has an unreadable vote row, so it is shown without a "
                "tally until that row is repaired: %s",
                proposal_id,
                e,
            )
            payload = _proposal_to_json(proposal)
            payload["votes"] = []
            payload["tally_unavailable"] = str(e)
            payload["self_cluster_id"] = _self_cluster_id_or_none()
            return SocaResponse(success=True, message=payload).as_flask()
        except ddb_client.DDBQueryError as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Could not read votes for proposal {proposal_id}: {e}",
                status_code=503,
            ).as_flask()

        decision = fence.evaluate_proposal(proposal, votes, peers)
        payload = _proposal_to_json(proposal, decision)
        payload["votes"] = [_vote_to_json(v) for v in votes]
        payload["self_cluster_id"] = _self_cluster_id_or_none()
        return SocaResponse(success=True, message=payload).as_flask()


class MeshProposalVote(Resource):
    @admin_api
    @mesh_endpoint
    def post(self, proposal_id: str):
        """
        Cast this cluster's vote.

        The voter is this cluster, resolved from its own configuration. There is no
        way to name a voter in the request, because a vote naming its own caster is
        not a vote.
        """
        try:
            mesh_id = resolve_mesh_id()
            voter = resolve_self_cluster_id()
        except MeshContextError as e:
            return SocaError.GENERIC_ERROR(
                helper=str(e), status_code=e.status_code
            ).as_flask()

        body = _read_body()
        value, complaint = _read_vote_value(body)
        if complaint is not None:
            return complaint
        reason = str(body.get("reason") or "").strip()

        proposal, error = _load_proposal(mesh_id, proposal_id)
        if error is not None:
            return error

        decision = _proposal_rules.plan_vote(proposal=proposal, voter=voter)
        if not decision.allowed:
            return SocaError.GENERIC_ERROR(
                helper=decision.reason,
                status_code=decision.status_code,
            ).as_flask()

        vote = fence.create_vote(
            mesh_id=mesh_id,
            proposal_id=proposal_id,
            voter=voter,
            vote=value,
            reason=reason,
        )
        try:
            ddb_client.put_fence_vote(vote)
        except ddb_client.DDBQueryError as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Could not record the vote: {e}",
                status_code=503,
            ).as_flask()

        _audit(
            mesh_id=mesh_id,
            action="quorum_voted",
            target=proposal.target,
            reason=reason or f"voted {value.value}",
            actor=actor_from_request(),
            metadata={
                "proposal_id": proposal_id,
                "operation": proposal.operation.value,
                "voter": voter,
                "vote": value.value,
            },
        )

        # Read back rather than reporting the vote alone, so the caller sees where the
        # proposal now stands. The daemon applies it, not this request: a decision
        # that took effect only when an administrator happened to be looking at the
        # page would not resolve for a mesh whose proposer is the cluster being
        # removed.
        try:
            votes = ddb_client.read_fence_votes(mesh_id, proposal_id)
            peers, _meta = ddb_client.query_mesh(mesh_id)
        except ddb_client.DDBQueryError as e:
            logger.warning(
                "vote on %s was stored but the tally could not be read back: %s",
                proposal_id,
                e,
            )
            return SocaResponse(
                success=True,
                message={
                    "proposal_id": proposal_id,
                    "voter": voter,
                    "vote": value.value,
                },
            ).as_flask()

        decision = fence.evaluate_proposal(proposal, votes, peers)
        payload = _proposal_to_json(proposal, decision)
        payload["votes"] = [_vote_to_json(v) for v in votes]
        payload["your_vote"] = value.value
        return SocaResponse(success=True, message=payload).as_flask()


def _load_proposal(mesh_id: str, proposal_id: str) -> Tuple[Optional[object], object]:
    """
    One proposal by id, or the refusal to return.

    Reads the mesh's proposals and selects, because the row's sort key is derived
    and there is no single-item read for it in ddb_client. The list is bounded by
    the reaper, which deletes finalised proposals after their retention window.
    """
    try:
        proposals = ddb_client.read_fence_proposals(mesh_id)
    except ddb_client.DDBQueryError as e:
        return None, SocaError.GENERIC_ERROR(
            helper=f"Could not read proposals for mesh {mesh_id}: {e}",
            status_code=503,
        ).as_flask()

    proposal = next(
        (p for p in proposals if p.proposal_id == proposal_id), None
    )
    if proposal is None:
        return None, SocaError.GENERIC_ERROR(
            helper=f"No proposal {proposal_id} in mesh {mesh_id}.",
            status_code=404,
        ).as_flask()
    return proposal, None


def _read_operation(body: dict):
    """The operation, or the refusal to return. Names the permitted values."""
    raw = str(body.get("operation") or "").strip()
    if not raw:
        return None, SocaError.CLIENT_MISSING_PARAMETER(
            parameter="operation",
            helper=(
                "One of: "
                + ", ".join(sorted(op.value for op in FenceOperation))
                + "."
            ),
            status_code=400,
        ).as_flask()
    try:
        return FenceOperation(raw), None
    except ValueError:
        return None, SocaError.GENERIC_ERROR(
            helper=(
                f"{raw} is not an operation that goes through quorum. Permitted: "
                + ", ".join(sorted(op.value for op in FenceOperation))
                + "."
            ),
            status_code=400,
        ).as_flask()


def _read_vote_value(body: dict):
    """The vote, or the refusal to return."""
    raw = str(body.get("vote") or "").strip()
    if not raw:
        return None, SocaError.CLIENT_MISSING_PARAMETER(
            parameter="vote",
            helper=(
                "One of: " + ", ".join(sorted(v.value for v in VoteValue)) + "."
            ),
            status_code=400,
        ).as_flask()
    try:
        return VoteValue(raw), None
    except ValueError:
        return None, SocaError.GENERIC_ERROR(
            helper=(
                f"{raw} is not a vote. Permitted: "
                + ", ".join(sorted(v.value for v in VoteValue))
                + "."
            ),
            status_code=400,
        ).as_flask()


def _self_cluster_id_or_none() -> Optional[str]:
    """
    This cluster's id for display, or None.

    Reported so the UI can mark which row is this cluster's own vote without
    guessing. Absence is not an error on a read: the list is still useful without
    it, and every write path resolves it strictly and refuses.
    """
    try:
        return resolve_self_cluster_id()
    except MeshContextError:
        return None
