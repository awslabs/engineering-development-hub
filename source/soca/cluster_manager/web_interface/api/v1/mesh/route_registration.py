# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Which process exposes which half of the mesh API.

The mesh API has two kinds of route and they have never had two kinds of exposure.

  ADMIN routes are operator-facing. They authenticate a human or an API key
  through `admin_api`, they are reached through the load balancer, and they are
  what the /admin/mesh page calls.

  P2P routes are cluster-facing. They authenticate another cluster's reconciler
  presenting the shared mesh token, they carry no operator identity, and their only
  legitimate caller is a peer controller reaching this one over the WireGuard mesh.

WHAT THIS CHANGES, and it is a narrowing rather than a refactor. CR-307548143
registered the three job endpoints on the main web application, beside the admin
ones, because that was the only application there was. That left them reachable
through the public load balancer with the shared token as the ONLY barrier in
front of code execution on this cluster's scheduler. After this change the main
application registers the admin surface alone and the sidecar registers the P2P
surface alone, so a P2P route is reachable only from inside the mesh tunnel and a
caller has to hold the token AND be on the overlay.

There is deliberately no switch to put them back together. A toggle that
re-exposed a P2P route on the ALB would be a one-line configuration change away
from undoing the narrowing, and nothing would look wrong.

WHY THE IMPORTS ARE INSIDE THE FUNCTIONS. These modules pull in overlay_daemon,
which pulls in boto3 and the daemon's model and access layers. At module scope a
failure anywhere in that chain would take down the whole web interface on every
cluster, including the ones with services.cross_region.enabled false. app.py has
guarded that since CR3; keeping the imports inside these two functions is what
lets the guard stay a try around one call rather than a try around a list of
imports that each new CR has to remember to extend.

The P2P importer is also deliberately kept clear of the admin modules. Those reach
`decorators`, and through it the web tier's SQLAlchemy session and Flask config
globals, which the sidecar process has no reason to construct.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("soca_logger")


def register_admin_routes(api: Any) -> int:
    """
    Register the operator-facing mesh routes and return how many were added.

    Raises whatever the imports raise. The caller is expected to guard the call:
    see app.py, whose guard exists so an unimportable mesh package costs the mesh
    feature rather than the whole web interface.

    Registered unconditionally rather than behind the feature flag, which is CR3's
    decision and is kept here. Every one of these resolves the mesh id per request
    and answers 409 with a message naming the unbound cluster, so an unconfigured
    cluster gets a diagnosis. Gating registration instead would mean enabling the
    feature needed a uwsgi restart before the routes existed at all, which is a
    harder failure to read than the 409.
    """
    from api.v1.mesh.audit import MeshAudit
    from api.v1.mesh.fence import (
        MeshProposalDetail,
        MeshProposalList,
        MeshProposalVote,
    )
    from api.v1.mesh.health import MeshHealth
    from api.v1.mesh.peers import (
        MeshPeerApprove,
        MeshPeerDecommission,
        MeshPeerDetail,
        MeshPeerList,
        MeshPeerReclaim,
        MeshPeerReject,
        MeshPeerRevoke,
        MeshPeerTombstone,
    )

    api.add_resource(MeshPeerList, "/api/v1/mesh/peers")
    api.add_resource(MeshPeerDetail, "/api/v1/mesh/peers/<string:cluster_id>")
    api.add_resource(MeshPeerApprove, "/api/v1/mesh/peers/<string:cluster_id>/approve")
    api.add_resource(MeshPeerReject, "/api/v1/mesh/peers/<string:cluster_id>/reject")
    api.add_resource(
        MeshPeerDecommission, "/api/v1/mesh/peers/<string:cluster_id>/decommission"
    )
    api.add_resource(
        MeshPeerTombstone, "/api/v1/mesh/peers/<string:cluster_id>/tombstone"
    )
    api.add_resource(MeshPeerReclaim, "/api/v1/mesh/peers/<string:cluster_id>/reclaim")
    api.add_resource(MeshPeerRevoke, "/api/v1/mesh/peers/<string:cluster_id>/revoke")

    api.add_resource(MeshHealth, "/api/v1/mesh/health")
    api.add_resource(MeshAudit, "/api/v1/mesh/audit")

    api.add_resource(MeshProposalList, "/api/v1/mesh/proposals")
    api.add_resource(MeshProposalDetail, "/api/v1/mesh/proposals/<string:proposal_id>")
    api.add_resource(
        MeshProposalVote, "/api/v1/mesh/proposals/<string:proposal_id>/vote"
    )

    logger.info("mesh routes: registered the ADMIN surface, 13 resources")
    return 13


def register_p2p_routes(api: Any) -> int:
    """
    Register the cluster-facing mesh routes and return how many were added.

    Called by the mesh sidecar and by nothing else. The main web application must
    never call this: doing so would put these routes back on the load balancer,
    which is the exposure this split exists to remove. An invariant asserts app.py
    does not reference it.
    """
    from api.v1.mesh.jobs_dispatch import (
        MeshJobCancel,
        MeshJobDispatch,
        MeshJobState,
    )

    api.add_resource(MeshJobDispatch, "/api/v1/mesh/jobs/dispatch")
    api.add_resource(MeshJobState, "/api/v1/mesh/jobs/<string:job_id>/state")
    api.add_resource(MeshJobCancel, "/api/v1/mesh/jobs/<string:job_id>/cancel")

    logger.info("mesh routes: registered the P2P surface, 3 resources")
    return 3
