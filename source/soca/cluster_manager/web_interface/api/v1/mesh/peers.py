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
Mesh peer management. Admin-only.

This is the surface that makes a joining cluster routable: CR3 writes it as
PENDING and has nothing that can promote it.

### The transition table is the whole design, and it lives next door

Every action is a move between lifecycle states, and the rules live in
`lifecycle.py`, which imports no Flask. This module maps an HTTP request onto a
decision from `lifecycle.plan_transition` and maps the decision back onto a
status code. It makes no lifecycle judgements of its own, so a test can enumerate
every action against every state without a web stack, which matters because
`flask_restful` is declared in no requirements file in this repository.

The prototype had six near-identical endpoint bodies with the state check missing
from all six in the same way, which is why the rules are declared once and
performed once here.

### Concurrency

Each action reads the peer, plans the transition against what it read, then writes
gated on that row's revision. A conflict is reported rather than retried: the
state the decision was made against is gone, so the decision has to be made again
by whoever is looking at the mesh.
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
from api.v1.mesh import lifecycle as lifecycle_rules
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse

from overlay_daemon import ddb_client
from overlay_daemon.models import AuditEvent, Lifecycle, Peer, new_event_id

logger = logging.getLogger("soca_logger")

# Decision outcomes mapped to the status code each should produce. A refusal is a
# conflict rather than a client error, because the request was well formed and the
# mesh's state is what makes it inapplicable.
_OUTCOME_STATUS = {
    lifecycle_rules.Outcome.UNKNOWN_ACTION: 400,
    lifecycle_rules.Outcome.WRONG_STATE: 409,
    lifecycle_rules.Outcome.NEEDS_QUORUM: 409,
}


def _peer_to_json(peer: Peer, active_peer_count: int) -> dict:
    """
    One peer as the UI needs it.

    `revision` is included because an action REQUIRES it back as expected_revision,
    which is how a click acts on the state the administrator was looking at rather
    than on whatever the row says by the time the request lands.

    `permitted_actions` comes from the shared table so the UI can disable what
    cannot be done without reimplementing the rules in JavaScript.
    """
    return {
        "cluster_id": peer.cluster_id,
        "cluster_name": peer.cluster_name,
        "region": peer.region,
        "account_id": peer.account_id,
        "site_seq": peer.site_seq,
        "lifecycle": peer.lifecycle.value,
        "endpoint": peer.endpoint,
        "ula_prefix": peer.ula_prefix,
        "cgn_prefix": peer.cgn_prefix,
        "joined_at": peer.joined_at,
        "joined_by": peer.joined_by,
        # Sent back on an action as expected_revision, so a click from a stale
        # page is refused rather than applied to a state nobody saw.
        "revision": peer.revision,
        "permitted_actions": lifecycle_rules.permitted_actions(peer.lifecycle),
        # Which of those actions this mesh is too large to perform directly.
        # `permitted_actions` ignores quorum by design, so on a mesh above the
        # threshold it lists three actions the API then refuses, and the page was
        # rendering a button for each that could only ever fail. Computed from
        # `plan_transition` rather than by naming the actions and the threshold
        # again here, so the page can label them without carrying a copy of the
        # rule in JavaScript.
        "actions_requiring_quorum": [
            action
            for action in lifecycle_rules.permitted_actions(peer.lifecycle)
            if lifecycle_rules.plan_transition(
                action=action,
                current=peer.lifecycle,
                active_peer_count=active_peer_count,
            ).outcome
            == lifecycle_rules.Outcome.NEEDS_QUORUM
        ],
    }


def _read_action_request() -> Tuple[str, Optional[int], Optional[str]]:
    """
    The reason and the revision the caller is acting on, or a complaint.

    Both are required. The reason because a lifecycle transition with no stated
    reason is close to useless afterwards: the row shows what changed and not why
    anyone decided it should.

    `expected_revision` because otherwise the concurrency check is nearly
    worthless. Reading the row here and writing it gated on what was just read
    only protects the microseconds between this request's own read and write. What
    needs protecting is the administrator's decision: they are looking at a page
    that may be minutes old, and if the peer has changed since it rendered, the
    click applies to a state they never saw. Requiring the revision they were shown
    is what makes "changed while you were deciding" detectable.

    Required rather than optional for the reason this CR keeps running into: an
    optional check is one that gets omitted, and the prototype's own
    `expected_revision` was optional and passed by nobody.
    """
    payload = request.get_json(silent=True) or {}
    reason = (payload.get("reason") or request.form.get("reason") or "").strip()
    if not reason:
        return "", None, "reason"

    raw = payload.get("expected_revision")
    if raw is None:
        raw = request.form.get("expected_revision")
    if raw is None or str(raw).strip() == "":
        return reason, None, "expected_revision"
    # Through the cast engine here, unlike the tolerant row casts in
    # observability, because these two cases are genuinely different. This value
    # arrives in a request body, so a non-numeric one is a client error that the
    # caller is told about and that is worth a log line with a Request ID. An
    # absent heartbeat timestamp is instead the ordinary state of a peer approved a
    # moment ago, and logging it as an error would be reporting a fault.
    cast = SocaCastEngine(raw).cast_as(int)
    if not cast.success:
        return reason, None, "expected_revision_not_a_number"
    return reason, cast.message, None


def _find_peer(mesh_id: str, cluster_id: str) -> Tuple[Optional[Peer], int]:
    """
    One peer, and how many peers in its mesh are ACTIVE.

    Returned together because this already reads the whole mesh, and the count is
    what says whether an action on this peer needs quorum. Querying again for it
    would let the two answers disagree across the gap.
    """
    peers, _meta = ddb_client.query_mesh(mesh_id)
    return (
        next((p for p in peers if p.cluster_id == cluster_id), None),
        sum(1 for p in peers if p.lifecycle == Lifecycle.ACTIVE),
    )


def _audit(
    *,
    mesh_id: str,
    action: str,
    target: str,
    reason: str,
    actor: str,
    metadata: Optional[dict] = None,
) -> None:
    """
    Record the transition, and never fail the request because recording failed.

    The transition has already happened by the time this runs, so raising here
    would report a failure for an action that succeeded, which is worse than an
    audit gap: the operator would retry, the retry would be refused by the
    transition table, and they would be left unsure which state the row is in.
    Logged at exception level so it stays discoverable.

    `source_cluster_id` is set because AuditEvent documents why it exists: an actor
    of "edhadmin" is ambiguous across a mesh of N clusters, since every cluster has
    one. This was left empty when these endpoints landed, so peer-lifecycle rows
    carried an actor that could not be attributed to a cluster.
    """
    now_ms = int(time.time() * 1000)
    try:
        source = resolve_self_cluster_id()
    except MeshContextError:
        # Tolerated rather than raised. The transition being audited just succeeded
        # against this mesh, so a less precise row beats losing one.
        source = ""
    event = AuditEvent(
        mesh_id=mesh_id,
        event_id=new_event_id(now_ms, str(uuid.uuid4())),
        action=action,
        target_cluster_id=target,
        actor=actor,
        reason=reason,
        ts=now_ms // 1000,
        metadata=metadata or {},
        source_cluster_id=source,
    )
    try:
        ddb_client.append_audit_event(event)
    except Exception:
        logger.exception(
            "mesh audit append failed for action=%s target=%s; the transition "
            "itself succeeded",
            action,
            target,
        )


def _perform(action: str, cluster_id: str):
    """Every lifecycle action, in one place, over the shared decision rules."""
    try:
        mesh_id = resolve_mesh_id()
    except MeshContextError as e:
        return SocaError.GENERIC_ERROR(
            helper=str(e), status_code=e.status_code
        ).as_flask()

    reason, expected_revision, complaint = _read_action_request()
    if complaint == "reason":
        return SocaError.CLIENT_MISSING_PARAMETER(
            parameter="reason",
            helper=(
                f"A reason is required to {action} a peer. It is recorded in the "
                f"mesh audit log against your identity."
            ),
            status_code=400,
        ).as_flask()
    if complaint == "expected_revision_not_a_number":
        # Distinct from the absent case, because the two need different things from
        # the caller. This one sent the field and it could not be parsed, so telling
        # them to read it from the peer's row reads as though nothing arrived and
        # sends them looking for a value they already have.
        return SocaError.GENERIC_ERROR(
            helper=(
                f"expected_revision must be a whole number, and the value sent with "
                f"this {action} could not be read as one. It is the revision your "
                f"view of the mesh was showing, which GET /api/v1/mesh/peers reports "
                f"as an integer on each peer's row."
            ),
            status_code=400,
        ).as_flask()
    if complaint is not None:
        return SocaError.CLIENT_MISSING_PARAMETER(
            parameter="expected_revision",
            helper=(
                f"It must be the revision your view of the mesh was showing, and it "
                f"is how a click on a stale page is rejected instead of applied to a "
                f"state you never saw. Read it from the peer's row in "
                f"GET /api/v1/mesh/peers."
            ),
            status_code=400,
        ).as_flask()

    try:
        peers, _meta = ddb_client.query_mesh(mesh_id)
    except ddb_client.DDBQueryError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Could not read mesh {mesh_id} to {action} {cluster_id}: {e}",
            status_code=503,
            ).as_flask()

    peer = next((p for p in peers if p.cluster_id == cluster_id), None)
    if peer is None:
        return SocaError.GENERIC_ERROR(
            helper=f"No peer {cluster_id} in mesh {mesh_id}.",
            status_code=404,
            ).as_flask()

    decision = lifecycle_rules.plan_transition(
        action=action,
        current=peer.lifecycle,
        active_peer_count=sum(1 for p in peers if p.lifecycle == Lifecycle.ACTIVE),
    )
    if not decision.allowed:
        return SocaError.GENERIC_ERROR(
            helper=decision.reason,
            status_code=_OUTCOME_STATUS[decision.outcome],
            ).as_flask()

    # Checked against what the caller was shown, not against what we just read, so
    # a click on a page that has gone stale is refused rather than applied to a
    # state the administrator never saw.
    if expected_revision != peer.revision:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"Peer {cluster_id} has changed since your view of the mesh was "
                f"rendered: you are acting on revision {expected_revision} and it "
                f"is now at {peer.revision}. Reload the mesh and decide again "
                f"against its current state."
            ),
            status_code=409,
        ).as_flask()

    actor = actor_from_request()
    try:
        ddb_client.update_peer_lifecycle(
            mesh_id=mesh_id,
            cluster_id=cluster_id,
            new_lifecycle=decision.target,
            actor=actor,
            reason=reason,
            expected_revision=expected_revision,
        )
    except ddb_client.DDBConditionFailedError:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"Peer {cluster_id} changed while you were deciding, so the "
                f"{action} was not applied. Reload the mesh and decide again "
                f"against its current state."
            ),
            status_code=409,
        ).as_flask()
    except ddb_client.DDBQueryError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Could not {action} peer {cluster_id}: {e}",
            status_code=503,
            ).as_flask()

    _audit(
        mesh_id=mesh_id,
        action=action,
        target=cluster_id,
        reason=reason,
        actor=actor,
        metadata={"severity": "critical"} if action == "revoke" else {},
    )
    return SocaResponse(
        success=True,
        message={
            "cluster_id": cluster_id,
            "action": action,
            "lifecycle": decision.target.value,
            "from": peer.lifecycle.value,
        },
    ).as_flask()


class MeshPeerList(Resource):
    @admin_api
    @mesh_endpoint
    def get(self):
        try:
            mesh_id = resolve_mesh_id()
        except MeshContextError as e:
            return SocaError.GENERIC_ERROR(
                helper=str(e), status_code=e.status_code
            ).as_flask()
        try:
            peers, _meta = ddb_client.query_mesh(mesh_id)
        except ddb_client.DDBQueryError as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Could not read mesh {mesh_id}: {e}",
                status_code=503,
                ).as_flask()
        active_peer_count = sum(
            1 for p in peers if p.lifecycle == Lifecycle.ACTIVE
        )
        return SocaResponse(
            success=True,
            message={
                "mesh_id": mesh_id,
                "peers": [_peer_to_json(p, active_peer_count) for p in peers],
                "active_peer_count": active_peer_count,
            },
        ).as_flask()


class MeshPeerDetail(Resource):
    @admin_api
    @mesh_endpoint
    def get(self, cluster_id: str):
        try:
            mesh_id = resolve_mesh_id()
        except MeshContextError as e:
            return SocaError.GENERIC_ERROR(
                helper=str(e), status_code=e.status_code
            ).as_flask()
        try:
            peer, active_peer_count = _find_peer(mesh_id, cluster_id)
        except ddb_client.DDBQueryError as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Could not read mesh {mesh_id}: {e}",
                status_code=503,
                ).as_flask()
        if peer is None:
            return SocaError.GENERIC_ERROR(
                helper=f"No peer {cluster_id} in mesh {mesh_id}.",
                status_code=404,
                ).as_flask()
        return SocaResponse(
            success=True,
            message=_peer_to_json(peer, active_peer_count),
        ).as_flask()


class MeshPeerApprove(Resource):
    @admin_api
    @mesh_endpoint
    def post(self, cluster_id: str):
        return _perform("approve", cluster_id)


class MeshPeerReject(Resource):
    @admin_api
    @mesh_endpoint
    def post(self, cluster_id: str):
        return _perform("reject", cluster_id)


class MeshPeerDecommission(Resource):
    @admin_api
    @mesh_endpoint
    def post(self, cluster_id: str):
        return _perform("decommission", cluster_id)


class MeshPeerTombstone(Resource):
    @admin_api
    @mesh_endpoint
    def post(self, cluster_id: str):
        return _perform("tombstone", cluster_id)


class MeshPeerReclaim(Resource):
    @admin_api
    @mesh_endpoint
    def post(self, cluster_id: str):
        return _perform("reclaim", cluster_id)


class MeshPeerRevoke(Resource):
    """Emergency key revoke. The peer leaves routing within one sync interval."""

    @admin_api
    @mesh_endpoint
    def post(self, cluster_id: str):
        return _perform("revoke", cluster_id)
