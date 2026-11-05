######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Reachability probing, and the rules that turn probe results into health.

### The split in this module is the design

`classify` and `next_observation` are pure: they take a probe result and the previous
observation and return the next one. `probe_peer` is the only function that runs a
subprocess. That boundary exists because the interesting behaviour is entirely in the
classification, and a rule that can only be tested by pinging something is a rule
that does not get tested across the states that matter.

### What a probe measures, and what it cannot

An ICMP echo to the peer's overlay address over the WireGuard tunnel. Reaching that
address IS the test, which is why no probe token or mTLS is involved: an unauthorised
party cannot be inside the tunnel's address space. The reference prototype has a
separate token subsystem for its capacity probes, which carry a request an endpoint
must trust; liveness needs nothing of the kind.

It measures ONE DIRECTION from ONE observer. That is the whole reason observations are
stored per pair rather than as a single verdict per peer: a partition is often
asymmetric, and a cluster that cannot reach a peer has learned something about itself
as much as about the peer.

### Why unreachable does not mean decommission

`models.Health` states it: "an unreachable peer must not be un-approved just because a
probe failed". The reference prototype ignores that, and its `maybe_auto_decommission`
writes DECOMMISSIONED directly from ONE observer's row, with a comment admitting the
multi-observer read is a TODO. That is a single possibly-partitioned cluster taking a
destructive action against a healthy peer, and it also predates the quorum mechanism,
so it bypasses the agreement the peer API now requires. It calls
`update_peer_lifecycle` without `expected_revision`, which the current signature
requires, so it cannot even run against this tree.

What replaces it is in `escalation.py`: sustained unreachability, corroborated by
enough separate observers, raises a quorum PROPOSAL. The other clusters then vote on
the evidence of their own observations, which is exactly the corroboration a single
observer cannot supply, and a partition that isolates one cluster can never reach
quorum.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from .models import Health, HealthObservation, Peer

logger = logging.getLogger("soca_logger")

# Seconds between probe rounds. Deliberately longer than the sync interval: the mesh
# does not change fast enough for a tighter loop to tell an operator anything, and
# every round costs one subprocess per peer.
DEFAULT_PROBE_INTERVAL_SECONDS = 60
MIN_PROBE_INTERVAL_SECONDS = 15
MAX_PROBE_INTERVAL_SECONDS = 3600

# Per-probe parameters. Three echoes rather than one so a single dropped packet is
# not read as a failure, which on a WAN tunnel it frequently is not.
DEFAULT_PROBE_COUNT = 3
DEFAULT_PROBE_TIMEOUT_SECONDS = 3

# Consecutive failed rounds before a peer is called degraded, then unavailable. Both
# count ROUNDS rather than packets, so a peer has to be unreachable across separate
# probe cycles spread over minutes before its classification moves.
DEGRADED_AFTER_FAILURES = 2
UNAVAILABLE_AFTER_FAILURES = 5

# How many recent round trips to keep on the row. Short: the value of the window is
# showing a trend at a glance, and a long history belongs in metrics rather than in a
# row every daemon rewrites every round.
RTT_WINDOW = 10

# Loss at or above this within a single round counts the round as failed even though
# some packets arrived. A tunnel losing half its packets is not usable.
FAILED_ROUND_LOSS_PCT = 50


@dataclass(frozen=True)
class ProbeResult:
    """
    What one probe round measured. Pure data, so the classifier can be tested
    without a network.
    """

    sent: int
    received: int
    rtt_ms: Optional[int] = None

    @property
    def loss_pct(self) -> int:
        if self.sent <= 0:
            return 100
        return int(round(100 * (self.sent - self.received) / self.sent))

    @property
    def is_failure(self) -> bool:
        """
        Whether this round counts as a failure.

        Total loss is obviously one. Partial loss at or above the threshold is too,
        because a tunnel dropping half its packets carries neither PBS traffic nor a
        useful measurement, and treating it as success would leave a peer classified
        healthy while nothing worked across it.
        """
        return self.received <= 0 or self.loss_pct >= FAILED_ROUND_LOSS_PCT


def clamp_probe_interval(requested: Optional[int]) -> int:
    """
    A usable probe interval, from whatever was configured.

    Clamped rather than refused because this comes from cluster configuration read at
    startup, not from a request: refusing would mean the daemon declining to probe at
    all over a careless number, which loses the subsystem to protect a bound.
    """
    if requested is None:
        return DEFAULT_PROBE_INTERVAL_SECONDS
    return max(
        MIN_PROBE_INTERVAL_SECONDS, min(MAX_PROBE_INTERVAL_SECONDS, requested)
    )


def classify(consecutive_failures: int, *, has_ever_succeeded: bool) -> Health:
    """
    The health a failure streak implies.

    THE ORDER AND THE BOUNDARIES ARE THE DEFINITION, so they are stated here rather
    than left to be read off the comparisons:

      - a peer that has never been reached and is failing is UNKNOWN until the streak
        reaches the degraded threshold, not HEALTHY. Zero failures for a peer nobody
        has ever reached means no probe has completed yet, and calling that healthy
        would report a mesh as fine before it has been tested at all.
      - zero failures for a peer that HAS been reached is HEALTHY.
      - at or above DEGRADED_AFTER_FAILURES: DEGRADED. Still configured in the
        tunnel, because handshake state surviving a transient fault is what lets
        recovery need no administrator.
      - at or above UNAVAILABLE_AFTER_FAILURES: UNAVAILABLE, which is the only value
        that removes a peer from the rendered tunnel and hosts file.

    A single failed round is deliberately NOT degraded. One lost round on a WAN
    tunnel is normal, and a classification that moved on it would flap.
    """
    if consecutive_failures >= UNAVAILABLE_AFTER_FAILURES:
        return Health.UNAVAILABLE
    if consecutive_failures >= DEGRADED_AFTER_FAILURES:
        return Health.DEGRADED
    if not has_ever_succeeded:
        return Health.UNKNOWN
    return Health.HEALTHY


def next_observation(
    *,
    previous: Optional[HealthObservation],
    result: ProbeResult,
    mesh_id: str,
    observer: str,
    observed: str,
    now: Optional[int] = None,
) -> HealthObservation:
    """
    The observation to store after one probe round.

    Pure, and takes the previous row rather than reading it, so every transition can
    be enumerated: first success, first failure, recovery, and a streak crossing each
    threshold.

    A success resets the failure streak to zero rather than decrementing it. A tunnel
    that is working is working, and a decaying counter would keep a recovered peer
    classified as degraded for several rounds after it recovered.
    """
    if now is None:
        now = int(time.time())

    previous_failures = previous.consecutive_failures if previous else 0
    previous_ok = previous.last_ok_ts if previous else None
    window = list(previous.recent_rtt_ms) if previous else []

    if result.is_failure:
        failures = previous_failures + 1
        last_ok = previous_ok
        rtt = None
    else:
        failures = 0
        last_ok = now
        rtt = result.rtt_ms
        if rtt is not None:
            window = (window + [rtt])[-RTT_WINDOW:]

    return HealthObservation(
        mesh_id=mesh_id,
        observer=observer,
        observed=observed,
        last_attempt_ts=now,
        health=classify(failures, has_ever_succeeded=last_ok is not None),
        last_ok_ts=last_ok,
        last_rtt_ms=rtt,
        consecutive_failures=failures,
        recent_rtt_ms=window,
    )


def probe_peer(
    address: str,
    *,
    count: int = DEFAULT_PROBE_COUNT,
    timeout: int = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> ProbeResult:
    """
    One ICMP probe round against an overlay address.

    Uses the ping binary rather than a raw socket because a raw socket needs
    CAP_NET_RAW and this daemon runs unprivileged, while ping is installed setuid and
    handles that itself.

    Every failure mode returns a total-loss result rather than raising: a missing
    binary, a timeout, and an unreachable peer are all "this observer could not reach
    that peer this round", and the classifier's streak logic is what decides whether
    that matters. A raise here would make one unreachable peer abort the round for
    every other peer.
    """
    args = ["ping", "-c", str(count), "-W", str(timeout), address]
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            # Bounded above the per-packet wait so a hung ping cannot stall the
            # probe round indefinitely.
            timeout=timeout * count + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("probe of %s timed out after %ds", address, timeout * count + 5)
        return ProbeResult(sent=count, received=0)
    except (FileNotFoundError, OSError) as e:
        # Logged at error because unlike an unreachable peer this does not clear on
        # its own: without the binary no peer will ever be probed, and every peer
        # would otherwise be reported unreachable with no indication why.
        logger.error(
            "cannot probe %s because the ping binary is unusable, so no peer can be "
            "probed this round: %s",
            address,
            e,
        )
        return ProbeResult(sent=count, received=0)

    return parse_ping_output(completed.stdout, expected_sent=count)


_STATS_RE = re.compile(
    r"(?P<sent>\d+)\s+packets transmitted,\s+(?P<received>\d+)\s+(?:packets\s+)?received"
)
_RTT_RE = re.compile(
    r"(?:rtt|round-trip)\s+min/avg/max(?:/(?:mdev|stddev))?\s*=\s*"
    r"[\d.]+/(?P<avg>[\d.]+)/"
)


def parse_ping_output(stdout: str, *, expected_sent: int) -> ProbeResult:
    """
    Read a ping summary, and report total loss when it cannot be read.

    Separate from `probe_peer` and public so the parsing can be tested against real
    output from both BSD and GNU ping without running either. The two differ: BSD
    says "round-trip min/avg/max/stddev" and GNU says "rtt min/avg/max/mdev", and a
    parser that only knew one would silently report no round trip on the other.

    Unparseable output is total loss rather than an exception, for the same reason
    `probe_peer` swallows its errors: the streak logic decides what a bad round means,
    and one peer's odd output must not abort the round for the rest.
    """
    stats = _STATS_RE.search(stdout)
    if not stats:
        logger.warning("could not read a packet count from ping output")
        return ProbeResult(sent=expected_sent, received=0)

    sent = int(stats.group("sent"))
    received = int(stats.group("received"))

    rtt: Optional[int] = None
    rtt_match = _RTT_RE.search(stdout)
    if rtt_match:
        rtt = int(round(float(rtt_match.group("avg"))))

    return ProbeResult(sent=sent, received=received, rtt_ms=rtt)


def peers_to_probe(
    peers: Iterable[Peer], *, self_cluster_id: str
) -> List[Tuple[str, str]]:
    """
    The (cluster_id, address) pairs this cluster should probe, and nothing else.

    Excludes this cluster: probing its own overlay address measures nothing and would
    store a row claiming a cluster observed itself.

    Uses the peer's own `is_routable` and `controller_v4` rather than deciding either
    here. `is_routable` is lifecycle only, and its docstring says why health must not
    feed into it: a peer that is administratively active but unreachable stays
    configured so it recovers without an administrator. Probing exactly the routable
    set means this never disagrees with what the tunnel was rendered for, and it also
    means an UNAVAILABLE peer keeps being probed, which is what lets it recover.

    Skips a peer whose address plan cannot be used, asking `address_plan_error` rather
    than re-deriving that judgement, since the overlay address is the thing being
    probed and a peer without a usable prefix has none to reach.

    IPv4 is probed rather than IPv6 because `controller_v4` is derived from the CGN
    prefix every peer carries, while an IPv6 underlay endpoint is optional in this
    mesh. Probing the address that always exists keeps the observation comparable
    across peers.
    """
    targets: List[Tuple[str, str]] = []
    for peer in peers:
        if peer.cluster_id == self_cluster_id:
            continue
        if not peer.is_routable:
            continue
        if peer.address_plan_error is not None:
            logger.debug(
                "not probing %s: %s", peer.cluster_id, peer.address_plan_error
            )
            continue
        targets.append((peer.cluster_id, peer.controller_v4))
    return targets
