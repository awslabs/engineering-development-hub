# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Source-IP peer authentication, for the P2P routes the mesh sidecar exposes.

WHY THIS EXISTS. The shared mesh token proves MEMBERSHIP and nothing more: every
cluster in the mesh holds the same secret, so no comparison against it can tell
one peer from another. `job_auth.authenticate_peer` says so and returns an auth
path rather than a cluster id for that reason. This module is the only thing in
the mesh API that can name WHICH peer is calling, and it can do so because the
sidecar binds directly to the WireGuard interface: the WG kernel module
authenticates every packet by Curve25519 before the socket sees it, so
`request.remote_addr` there is the sending cluster's mesh address rather than a
claim in a header or a body.

It is therefore ONLY meaningful inside the sidecar process, which sets
SOCA_MESH_SIDECAR=1. In the main web tier the P2P routes are not registered at
all and `remote_addr` is the ALB's address, so `trust_wg_source_ip_enabled()`
answers no there and nothing else in this module runs.

HOW A PEER IS IDENTIFIED, and it is not what the prototype did. That version
queried the `cluster_state` table for a row whose `mesh_ip` equals the source
address and whose `status` is "active". Neither field exists: `cluster_state`
rows carry mesh_id, cluster_id, last_sync_ts, peer_count, daemon_version and
last_sync_ok (see ddb_client.write_cluster_state_heartbeat), and the
administrator-controlled state lives on the peer row in `overlay_config` as
`lifecycle`. The lookup would have matched nothing on any real cluster and every
request would have fallen through to bearer, which is the shape that looks like
it works because the fallback answers.

What a peer actually owns is a PREFIX. `Peer.ula_prefix` is its /64 and
`Peer.cgn_prefix` its /24, both allocated from the mesh address plan by site_seq,
so identification is prefix containment rather than an equality match on a single
address. That is also more correct than an equality match would have been: a
controller may source from any address inside its own allocation, and an equality
match against one recorded address would refuse the others.

CACHING. Keyed on the source address with a short TTL, because this runs on every
P2P request and the alternative is a mesh read per request. Only a POSITIVE
resolution is cached. Caching a miss is the defect review found on CR-307548143
revision 1 in this subsystem's token read: a peer approved a moment ago would be
unidentifiable for the rest of the TTL, and the operator would see it resolve by
itself later with nothing to point at.

WHAT A FAILURE MEANS HERE. A mesh read that fails is not a peer that is absent,
and the two must not collapse - the same distinction `job_auth.read_token_pair`
is built around, and the same one its ARN read got wrong at revision 4. This
module reports the difference by raising `PeerLookupUnavailable` rather than
answering None, so a caller can refuse a request it could not evaluate instead of
silently demoting it to the bearer path. `None` means one thing only: the read
succeeded and this address belongs to no active peer in this mesh.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("soca_logger")

# The environment variable the sidecar sets at startup. Compared against the
# exact string "1" rather than tested for truthiness, so an inherited empty value
# cannot enable a trust path.
SIDECAR_ENV_VAR = "SOCA_MESH_SIDECAR"

# Short deliberately. This is an authentication input, so the window in which a
# revoked peer still resolves is the window in which it is still trusted.
CACHE_TTL_SECONDS = 60

# source address -> (cluster_id, expires_at). Only successful resolutions land
# here; see the module docstring.
_CACHE: Dict[str, Tuple[str, int]] = {}


class PeerLookupUnavailable(Exception):
    """
    The mesh could not be read, so which peer owns this address is unknown.

    Deliberately not the same answer as "no peer owns it". A caller that cannot
    tell the two apart reports a transient DynamoDB failure as an unrecognised
    peer, which is a permanent-sounding claim about a peer that is fine.
    """


def trust_wg_source_ip_enabled() -> bool:
    """
    True only inside the mesh sidecar process.

    The sidecar sets SOCA_MESH_SIDECAR=1 before it registers any route. Nothing
    else in the tree sets it, so this is False in the main web tier, in the
    overlay daemon, and under test unless a test sets it.
    """
    return os.environ.get(SIDECAR_ENV_VAR) == "1"


def _owns(peer, address) -> bool:
    """
    Whether `address` falls inside either prefix allocated to `peer`.

    Both prefixes are checked because the mesh assigns each cluster one of each,
    a ULA /64 and a CGN /24, and which one a controller sources from depends on
    the route the sender picked. A malformed prefix on a row is skipped rather
    than raising: one corrupt peer row must not make every other peer
    unidentifiable, which is the same posture `ddb_client.query_mesh` takes on a
    row it cannot validate.
    """
    for prefix in (peer.ula_prefix, peer.cgn_prefix):
        if not prefix:
            continue
        try:
            network = ipaddress.ip_network(str(prefix), strict=False)
        except ValueError:
            logger.warning(
                "peer auth: cluster_id=%s carries an unparseable prefix %r, skipping it",
                peer.cluster_id,
                prefix,
            )
            continue
        # No address-family guard before this. `in` across families answers False
        # rather than raising - measured on CPython 3.14, IPv4Address in
        # IPv6Network is False - so a version check here would be dead code that
        # reads as protection. An earlier draft had one; a probe showed removing
        # it changed no behaviour, which is what says it was never doing anything.
        if address in network:
            return True
    return False


def peer_cluster_for_source_ip(source_ip: Optional[str]) -> Optional[str]:
    """
    The cluster_id of the ACTIVE peer whose address plan contains `source_ip`.

    Returns None when the mesh was read successfully and no active peer owns the
    address. Raises PeerLookupUnavailable when the mesh could not be read or this
    cluster's own mesh binding could not be resolved, so those never read as an
    unrecognised peer.

    An unparseable `source_ip` is None rather than an exception: it is an input
    from the socket, so it is a caller-facing fact and not an outage.
    """
    if not source_ip:
        return None
    try:
        address = ipaddress.ip_address(str(source_ip).strip())
    except ValueError:
        logger.warning("peer auth: source address %r is not an IP", source_ip)
        return None

    now = int(time.time())
    cached = _CACHE.get(str(address))
    if cached and cached[1] > now:
        return cached[0]

    # The one copy of this resolution, and the one that distinguishes an unbound
    # cluster from an unreadable config store. A local copy is what drifted in
    # the prototype and what an invariant in this package now forbids.
    from api.v1.mesh._context import MeshContextError, resolve_mesh_id

    try:
        mesh_id = resolve_mesh_id()
    except MeshContextError as e:
        raise PeerLookupUnavailable(
            f"cannot resolve this cluster's mesh binding, so the source address "
            f"cannot be attributed to a peer: {e}"
        ) from e

    # Through the daemon's typed layer rather than a boto3 resource of our own.
    # That module pins a region and can carry a cross-account assumed role, and
    # its own docstring records what building a client here instead would cost:
    # region_name=None resolves from instance metadata and can read a different
    # region's copy of a Global Table, which on THIS path would mean
    # authenticating a peer from another region's view of the mesh.
    from overlay_daemon import ddb_client

    try:
        peers, _meta = ddb_client.query_mesh(mesh_id)
    except ddb_client.DDBQueryError as e:
        raise PeerLookupUnavailable(
            f"cannot read the mesh peer rows, so the source address cannot be "
            f"attributed to a peer: {e}"
        ) from e

    from overlay_daemon.models import Lifecycle

    for peer in peers:
        if peer.lifecycle != Lifecycle.ACTIVE:
            continue
        if not _owns(peer, address):
            continue
        _CACHE[str(address)] = (peer.cluster_id, now + CACHE_TTL_SECONDS)
        logger.info(
            "peer auth: source address %s resolved to active peer cluster_id=%s",
            address,
            peer.cluster_id,
        )
        return peer.cluster_id

    # Not cached. See the module docstring: a peer approved a moment from now
    # must be identifiable on its next request rather than after a TTL.
    logger.warning(
        "peer auth: source address %s belongs to no ACTIVE peer in mesh %s",
        address,
        mesh_id,
    )
    return None


def reset_cache() -> None:
    """Drop every cached resolution. For tests, and for a rotation hook."""
    _CACHE.clear()
