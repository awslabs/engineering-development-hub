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
Cross-region overlay mesh API.

Fourth of eight CRs. CR3 shipped the daemon that registers a cluster in the mesh
and reconciles its tunnel; a cluster that JOINS an existing mesh is written as
PENDING and nothing in CR3 can promote it. This package is what makes approval
reachable, so it is the CR that turns a joining cluster into a routable one.

Endpoints in this CR, all admin-only:

  GET    /api/v1/mesh/peers                          the mesh's peer rows
  GET    /api/v1/mesh/peers/<cluster_id>             one peer row
  POST   /api/v1/mesh/peers/<cluster_id>/approve     PENDING becomes ACTIVE
  POST   /api/v1/mesh/peers/<cluster_id>/reject      PENDING becomes REJECTED
  POST   /api/v1/mesh/peers/<cluster_id>/decommission ACTIVE becomes DECOMMISSIONED
  POST   /api/v1/mesh/peers/<cluster_id>/tombstone   DECOMMISSIONED becomes TOMBSTONED
  POST   /api/v1/mesh/peers/<cluster_id>/reclaim     TOMBSTONED becomes reclaimable
  POST   /api/v1/mesh/peers/<cluster_id>/revoke      emergency key revoke
  GET    /api/v1/mesh/health                         per-peer heartbeat rollup
  GET    /api/v1/mesh/audit                          paginated audit log
  GET    /api/v1/mesh/proposals                      quorum proposals with tallies
  POST   /api/v1/mesh/proposals                      raise a quorum proposal
  GET    /api/v1/mesh/proposals/<proposal_id>        one proposal with its votes
  POST   /api/v1/mesh/proposals/<proposal_id>/vote   cast this cluster's vote

Job routing, added later and NOT admin-only:

  POST   /api/v1/mesh/jobs/dispatch                  take a routed job, or probe
  GET    /api/v1/mesh/jobs/<job_id>/state            a delegated job's state
  POST   /api/v1/mesh/jobs/<job_id>/cancel           cancel a delegated job

Those three are the first endpoints in this package that do not authenticate an
operator. Their caller is a peer cluster's reconciler and it presents the shared
mesh credential, so they are wrapped by `job_auth.authenticate_peer` rather than by
`admin_api`. Because the credential is shared mesh-wide it proves membership and
not identity, and an invariant test asserts the two authentication paths never meet:
no admin endpoint accepts the mesh token, since every member holds it and an admin
endpoint that took it would let any cluster approve peers.

Deliberately NOT here, each arriving with its own CR: peer health probing and
the capacity endpoints, the fence protocol with its freeze, diff-approval,
participant and replica surfaces, and the mesh sidecar with its source-address
authentication and route registration. Importing this package pulls in none of them.

### Why the imports below are allowed to reach the daemon

The endpoints read and write the mesh Global Tables through
`overlay_daemon.ddb_client`, which is a plain import rather than a duplicated
access layer. That is legitimate here and was not in CR3: `edhwebui.sh` exports
PYTHONPATH=/opt/edh/<cluster>/cluster_manager, and both `web_interface` and
`overlay_daemon` live under that directory, so they are one deployment artifact
from the interpreter's point of view.

CR3 duplicated `SHORT_NAMES` between the daemon and the installer's CDK for the
opposite reason: those two really are separate artifacts with no import path.
The distinction matters, so a test asserts the launcher still exports that
PYTHONPATH. Nothing else would catch its removal, because the tests supply their
own import path and would keep passing while every endpoint failed at runtime.
"""
