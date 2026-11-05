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
GET /api/v1/mesh/health

Per-cluster daemon liveness for the mesh. Admin-only.

### What this reports, and what it does not

Liveness derived from the heartbeat rows CR3's daemon writes every sync cycle, and
which nothing read until now. It is NOT reachability: a cluster whose daemon is
running and whose tunnel is down reports `live`, because its heartbeat is current.
The field is named `daemon_liveness` rather than `health` so that is not misread.

The pairwise probe matrix from `overlay_health` is now served too, under
`reachability`, because the probing subsystem that writes that table exists. It is
kept separate from `daemon_liveness` rather than merged into one verdict, and it
carries `probing_active`: false there means nothing has ever written an observation,
which is a different statement from every pair being fine. That distinction is why
this view was withheld until something wrote the table, since an operator reads "no
observations" as "nothing wrong".

A peer with no heartbeat row at all is reported as `unknown`, not omitted. A peer
missing from a health view reads as a peer that does not exist, and the difference
between a cluster that never checked in and a cluster that is not in the mesh is
the whole question an operator is asking.
"""

from __future__ import annotations

import logging
import time

from flask_restful import Resource

from decorators import admin_api
from api.v1.mesh._context import (
    MeshContextError,
    mesh_endpoint,
    resolve_mesh_id,
    resolve_self_cluster_id,
)
from api.v1.mesh import observability as obs
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse

from overlay_daemon import ddb_client
from overlay_daemon import escalation

logger = logging.getLogger("soca_logger")


def _sync_interval_seconds() -> int:
    """
    The configured sync interval, which the staleness thresholds are counted in.

    Read from configuration rather than assumed, because a cluster configured to
    sync slowly would otherwise be reported stale for syncing exactly on schedule.
    Falls back to the daemon's own default when unset, which is the same value the
    daemon would be using.
    """
    from utils.config import SocaConfig

    # Passes a default, unlike resolve_mesh_id, and the difference is deliberate.
    # Every failure mode here wants the same answer, the daemon's own default, so
    # collapsing an absent key and an unreachable store is correct rather than a
    # loss. A default also makes get_value substitute it instead of returning an
    # error string in `message`, which is what the previous version fed into the
    # cast: a config failure produced a warning claiming the configured interval
    # was the text of the error, on every health request.
    #
    # There is deliberately no success check, because with a default get_value
    # cannot report failure and a check that cannot fail provides nothing.
    result = SocaConfig(
        key="/configuration/services/cross_region/overlay/sync_interval_seconds"
    ).get_value(default="")
    value = result.get("message")
    if value in (None, "", "CACHE_MISS"):
        return obs.DEFAULT_SYNC_INTERVAL_SECONDS
    # Through the cast engine because a configured value that is not a number is a
    # misconfiguration worth surfacing, unlike the row casts in observability where
    # an absent field is the normal state. The warning below is kept as well: it
    # names the value and the fallback, which is what an operator needs to fix it.
    cast = SocaCastEngine(value).cast_as(int)
    if not cast.success:
        logger.warning(
            "sync_interval_seconds is %r, which is not a number; using %d for "
            "liveness thresholds",
            value,
            obs.DEFAULT_SYNC_INTERVAL_SECONDS,
        )
        return obs.DEFAULT_SYNC_INTERVAL_SECONDS
    parsed = cast.message
    return parsed if parsed > 0 else obs.DEFAULT_SYNC_INTERVAL_SECONDS


class MeshHealth(Resource):
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
            heartbeats = ddb_client.read_cluster_state_heartbeats(mesh_id)
        except ddb_client.DDBQueryError as e:
            logger.exception("mesh health read failed for mesh %s", mesh_id)
            return SocaError.GENERIC_ERROR(
                helper=f"Could not read the state of mesh {mesh_id}: {e}",
                status_code=503,
                ).as_flask()

        # Reachability, which is a separate question from daemon liveness and which
        # this endpoint could not answer until the probing subsystem existed. Read in
        # its own guard: a health table that cannot be read must not cost the caller
        # the liveness view it has always been able to serve.
        reachability_error = None
        observations = []
        try:
            observations = ddb_client.read_health_observations(mesh_id)
        except ddb_client.DDBQueryError as e:
            logger.warning("could not read reachability for mesh %s: %s", mesh_id, e)
            reachability_error = str(e)

        interval = _sync_interval_seconds()
        now = int(time.time())
        by_cluster = {
            str(row.get("cluster_id") or ""): row
            for row in heartbeats
            if row.get("cluster_id")
        }

        entries = []
        readings = []
        for peer in peers:
            row = by_cluster.get(peer.cluster_id)
            # A peer with no heartbeat is reported as unknown rather than omitted:
            # absence from this view would read as absence from the mesh.
            reading = obs.classify_heartbeat(
                row if row is not None else {"cluster_id": peer.cluster_id},
                now=now,
                sync_interval_seconds=interval,
            )
            readings.append(reading)
            entries.append(
                {
                    "cluster_id": peer.cluster_id,
                    "cluster_name": peer.cluster_name,
                    "region": peer.region,
                    "lifecycle": peer.lifecycle.value,
                    "daemon_liveness": reading.daemon_liveness,
                    "age_seconds": reading.age_seconds,
                    "last_sync_ts": reading.last_sync_ts,
                    "last_sync_ok": reading.last_sync_ok,
                    "peer_count_seen": reading.peer_count,
                    "daemon_version": reading.daemon_version,
                    "has_heartbeat": row is not None,
                }
            )

        # Heartbeat rows for clusters that are not in the peer set. Surfaced rather
        # than dropped: a heartbeat from a cluster with no peer row means either a
        # row was deleted under a running daemon or a daemon is writing to a mesh
        # it was never admitted to, and both are worth an operator seeing.
        orphaned = sorted(
            cluster_id
            for cluster_id in by_cluster
            if cluster_id not in {peer.cluster_id for peer in peers}
        )

        return SocaResponse(
            success=True,
            message={
                "mesh_id": mesh_id,
                "self_cluster_id": resolve_self_cluster_id(),
                "sync_interval_seconds": interval,
                "observed_at": now,
                "summary": obs.summarise(readings),
                "peers": entries,
                "heartbeats_without_a_peer_row": orphaned,
                # Two different questions, kept separately named so neither is read
                # as the other. Liveness is heartbeat freshness: a cluster whose
                # daemon runs and whose tunnel is down reports live. Reachability is
                # who can actually reach whom.
                "liveness_basis": "daemon heartbeat freshness, not reachability",
                "reachability": _reachability_view(
                    peers, observations, error=reachability_error
                ),
            },
        ).as_flask()


def _reachability_view(peers, observations, *, error) -> dict:
    """
    The pairwise probe matrix, which this endpoint deliberately did not offer until
    something wrote it.

    The previous docstring said shipping an empty matrix and labelling it health would
    be worse than not offering the view, because an operator reads "no observations" as
    "nothing wrong". So `probing_active` is reported explicitly: false means nothing has
    written an observation, which is a different statement from every pair being fine.

    A pair with no observation is `unknown`, never `healthy`, for the same reason a peer
    with no heartbeat is unknown rather than omitted.
    """
    cluster_ids = sorted(peer.cluster_id for peer in peers)
    by_pair = {(o.observer, o.observed): o for o in observations}

    matrix = []
    for observer in cluster_ids:
        row = {"observer": observer, "observed": {}}
        for observed in cluster_ids:
            if observer == observed:
                continue
            observation = by_pair.get((observer, observed))
            if observation is None:
                row["observed"][observed] = {"health": "unknown", "observed_at": None}
                continue
            row["observed"][observed] = {
                "health": observation.health.value,
                "observed_at": observation.last_attempt_ts,
                "last_ok_ts": observation.last_ok_ts,
                "last_rtt_ms": observation.last_rtt_ms,
                "consecutive_failures": observation.consecutive_failures,
                "recent_rtt_ms": list(observation.recent_rtt_ms),
            }
        matrix.append(row)

    # How many separate observers call each peer unavailable. This is the number the
    # tunnel and the escalation both act on, so showing the count rather than a verdict
    # lets an operator see a one-sided partition, which is the case a single verdict
    # would hide.
    # The same count the daemon acts on, from the same function, so the page cannot
    # report a corroboration the tunnel does not see or miss one it does. Only an ACTIVE
    # cluster counts: decommissioning sets a lifecycle rather than deleting a row and
    # nothing reaps overlay_health, so a departed cluster's rows would otherwise both
    # contradict the matrix and overstate the corroboration.
    unavailable_observers = escalation.unavailable_observers_by_peer(
        observations, active_cluster_ids=escalation.active_observer_ids(peers)
    )

    return {
        # False means nothing has ever written an observation, which is not the same
        # as every pair being reachable.
        "probing_active": bool(observations),
        "unreadable": error,
        "matrix": matrix,
        "unavailable_observer_counts": {
            cluster_id: sorted(observers)
            for cluster_id, observers in unavailable_observers.items()
        },
    }
