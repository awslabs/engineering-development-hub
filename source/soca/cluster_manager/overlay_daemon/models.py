######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Data classes for the overlay daemon.

Immutable dataclasses only. Conversion to and from DynamoDB item dicts lives in
ddb_client.py, and validation of a raw item into one of these models lives in
schema.py, so this module has no dependencies beyond the standard library.

Every row carries schema_version and min_compatible_version so a reader can
dispatch on version; see schema.py for how that dispatch works. Mutable rows
also carry a revision used for optimistic concurrency on conditional writes.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from typing import List, Optional

# The suffix every overlay hostname carries. Defined here, beside the property
# that builds a peer's name, and imported by hosts_writer rather than repeated
# there. It was written out in both places, which is two sources of truth for the
# name peers resolve each other by: changing one would have left the rendered
# hosts block and Peer.hostname disagreeing, with nothing to catch it.
DOMAIN_SUFFIX = "edh-mesh"

# Width of the timestamp prefix in an audit event_id. Wide enough that every
# value is the same length for the next several thousand years, which is what
# makes lexical order equal chronological order: DynamoDB compares a string sort
# key bytewise, so "9999" sorts above "10000" unless both are padded.
_EVENT_ID_TS_WIDTH = 20


def new_event_id(ts_ms: int, unique: str) -> str:
    """
    Build an audit event_id that sorts chronologically.

    The overlay_audit table's sort key is event_id, and the reader queries it with
    ScanIndexForward=False to get newest-first. DynamoDB orders by the sort key's
    value rather than by insertion time, so a random identifier here makes "newest
    first" mean "in reverse order of a random string": the audit page would look
    shuffled, and cursor paging over it would skip and repeat rows.

    The CDK that declares this table carried a comment claiming event_id was a
    KSUID, which would have sorted correctly, but no KSUID generator has ever
    existed in this repository. This is that claim made true without adding a
    dependency: a zero-padded millisecond timestamp, then a uniqueness suffix so
    two events in the same millisecond stay distinct rather than one losing the
    append-only conditional write.

    ts_ms is milliseconds rather than seconds because approving several peers is a
    handful of clicks and second granularity would put them in an arbitrary order
    within the same second.
    """
    return f"{ts_ms:0{_EVENT_ID_TS_WIDTH}d}#{unique}"


def event_id_ts_ms(event_id: str) -> Optional[int]:
    """
    The millisecond timestamp encoded in an event_id, or None if it carries none.

    Tolerant on purpose: it is used to present a row, and a row written by some
    future writer that formats the id differently should still display rather than
    breaking the page it appears on.
    """
    prefix, _, _ = event_id.partition("#")
    if not prefix.isdigit():
        return None
    return int(prefix)



class Lifecycle(str, Enum):
    """
    A peer's administrator-controlled state.

    This is deliberately separate from observed health: an administrator
    approving or revoking a cluster is a different fact from whether that
    cluster's tunnel currently passes traffic.
    """

    PENDING = "pending"
    ACTIVE = "active"
    DECOMMISSIONED = "decommissioned"
    TOMBSTONED = "tombstoned"
    AVAILABLE_FOR_RECLAIM = "available_for_reclaim"
    TAKEOVER_PENDING = "takeover_pending"
    REVOKED = "revoked"
    REJECTED = "rejected"


class Health(str, Enum):
    """
    A peer's observed reachability, as distinct from its lifecycle.

    Deliberately orthogonal to Lifecycle: an administratively approved peer can
    be unreachable, and an unreachable peer must not be un-approved just because
    a probe failed. Only UNAVAILABLE removes a peer from the rendered tunnel and
    hosts file; DEGRADED peers stay configured so that handshake state survives
    and recovery needs no administrator action.
    """

    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Peer:
    """One cluster's peer row in the overlay_config table."""

    mesh_id: str
    cluster_id: str
    cluster_name: str
    region: str
    account_id: str
    site_seq: int
    pubkey: str
    pubkey_next: Optional[str]
    endpoint: str
    ula_prefix: str  # for example "fd92:af:1234:1::/64"
    cgn_prefix: str  # for example "100.64.1.0/24"
    lifecycle: Lifecycle
    joined_at: int
    joined_by: str  # IAM principal ARN
    decommissioned_at: Optional[int] = None
    tombstoned_at: Optional[int] = None
    lifecycle_history: List[dict] = field(default_factory=list)
    # Optional IPv6 underlay endpoint, for example "[2001:db8::1]:51820".
    # Most peers leave this None, because the mesh underlay is IPv4 by default.
    endpoint_ipv6: Optional[str] = None
    schema_version: int = 1
    min_compatible_version: int = 1
    # Optimistic-concurrency revision. 0 means never written.
    revision: int = 0

    @property
    def address_plan_error(self) -> Optional[str]:
        """
        Why this peer's address plan cannot be used, or None when it is usable.

        The one predicate both render paths ask, replacing the emptiness checks
        they each carried. Emptiness was never the property that mattered: the
        rows come from an admin-editable Global Table and the schema validator
        defaults a missing prefix to the empty string but never rejects a
        malformed one, so a hand-edited ':3::/64' passed both guards. In the
        tunnel that emitted `AllowedIPs = :3::/64` and wg syncconf rejected the
        whole file, failing the entire apply rather than skipping one peer, which
        is the exact failure those guards exist to prevent. In the hosts block
        controller_v6 raised and aborted the render, dropping the names of every
        other peer.

        Returns a reason rather than a bool so each caller can log which peer was
        skipped and why, which is the only way an operator finds the bad row.
        """
        for value, family, label in (
            (self.ula_prefix, ipaddress.IPv6Network, "IPv6"),
            (self.cgn_prefix, ipaddress.IPv4Network, "IPv4"),
        ):
            if not value or not str(value).strip():
                return f"no {label} prefix on its row"
            try:
                family(str(value).strip(), strict=False)
            except ValueError as e:
                return f"its {label} prefix {value!r} is not a valid network ({e})"
        return None

    @property
    def controller_v6(self) -> str:
        """
        The controller's IPv6 address, always ::1 within the cluster's prefix.

        Derived through the ipaddress module rather than by string surgery.
        The obvious string form, stripping trailing colons and appending "1",
        is wrong for every prefix this system generates: cluster prefixes are
        always "::"-terminated, so stripping consumes both colons and appends
        the 1 onto the last group, turning fd00:0:0:1::/64 into
        "fd00:0:0:11" - not a different address but not an address at all,
        since it has four groups and no "::".
        """
        network = ipaddress.IPv6Network(self.ula_prefix, strict=False)
        return str(network.network_address + 1)

    @property
    def controller_v4(self) -> str:
        """The controller's IPv4 address, always .1 within the cluster's prefix."""
        network = ipaddress.IPv4Network(self.cgn_prefix, strict=False)
        return str(network.network_address + 1)

    @property
    def is_routable(self) -> bool:
        """
        Whether this peer should appear in the rendered WireGuard config.

        Lifecycle alone decides this. Health gates traffic separately, so a
        peer that is administratively active but currently unreachable stays
        configured and recovers without an administrator action.
        """
        return self.lifecycle == Lifecycle.ACTIVE

    @property
    def hostname(self) -> str:
        return f"{self.cluster_id}.{DOMAIN_SUFFIX}"


@dataclass(frozen=True)
class MeshMeta:
    """
    The mesh's metadata row, stored in overlay_config under the _meta sort key.

    One row per mesh. It holds the address plan the whole mesh derives from and
    the allocator for site sequence numbers, which is why creating it is the
    operation that decides which cluster created the mesh.
    """

    mesh_id: str
    mesh_ula_prefix: str  # /48, subdivided per cluster
    mesh_cgn_prefix: str  # /16, subdivided per cluster
    next_site_seq: int
    created_at: int
    created_by: str
    key_rotation_days: int = 90
    auto_decommission_days: Optional[int] = 90
    decommission_to_tombstone_days: int = 30
    schema_version: int = 1
    min_compatible_version: int = 1
    revision: int = 0


@dataclass(frozen=True)
class AuditEvent:
    """
    One row in the overlay_audit table.

    The table is append-only, enforced both by IAM policy and by a conditional
    write on event_id, so these rows are never updated in place and carry no
    revision field.

    event_id is the table's sort key and MUST sort chronologically. Build it with
    new_event_id rather than assigning a bare identifier: the reader queries with
    ScanIndexForward=False and promises newest-first, and DynamoDB orders by the
    sort key's own value, not by when the row arrived.
    """

    mesh_id: str
    event_id: str
    action: str  # for example "approve", "reject", "decommission", "revoke"
    target_cluster_id: str
    actor: str  # IAM principal
    reason: str
    ts: int
    metadata: dict = field(default_factory=dict)
    # Which mesh member originated the event. Without these, an actor of
    # "edhadmin" is ambiguous across a mesh of N clusters in M accounts,
    # because every cluster has an edhadmin. They default to empty strings so
    # a row written before they existed still validates.
    source_cluster_id: str = ""
    source_region: str = ""
    source_account_id: str = ""
    schema_version: int = 1
    min_compatible_version: int = 1


# ---------------------------------------------------------------------------
# Quorum-gated operations
# ---------------------------------------------------------------------------


class FenceOperation(str, Enum):
    """
    An operation that must carry a quorum decision before it is applied.

    Deliberately only the three the mesh API already refuses without quorum:
    lifecycle.QUORUM_ACTIONS names decommission, tombstone and reclaim, and
    those refusals are currently unreachable outcomes because nothing can
    create a proposal. This enum is the set that becomes reachable.

    The reference prototype also lists takeover, site_seq_reassign and
    wg_key_rotate. They are left out because none of them is reachable in this
    tree: takeover writes TAKEOVER_PENDING, which lifecycle.py records as not
    produced by any current code path, and the other two have no caller at all.
    Adding an operation nothing can propose would mean shipping a value the UI
    offers and the API cannot honour.
    """

    DECOMMISSION = "decommission"
    TOMBSTONE = "tombstone"
    RECLAIM = "reclaim"

    @property
    def target_lifecycle(self) -> "Lifecycle":
        """The lifecycle this operation moves a peer to."""
        return _FENCE_OPERATION_EFFECT[self][0]

    @property
    def permitted_from(self) -> frozenset:
        """
        The lifecycles this operation may be applied from.

        This mapping is the single source of truth for the three quorum-gated
        transitions, and the web interface's transition table derives its entries
        for them from here rather than repeating the values. That direction is
        deliberate: the rule is knowledge about a peer's lifecycle, Lifecycle lives
        in this module, and the daemon cannot import the web interface while the
        web interface already imports this one.

        It matters because both sides need it. The API refuses an illegal
        transition when an operator asks for one, and the daemon has to refuse the
        same transition when it applies a proposal that reached quorum, since a
        proposal raised while its target was ACTIVE can commit after that peer has
        already moved. The reference applied committed operations with no such
        check, so quorum was a way to write any lifecycle over any other.
        """
        return _FENCE_OPERATION_EFFECT[self][1]


# Read through FenceOperation's properties rather than directly. Defined after the
# enum because it refers to its members.
_FENCE_OPERATION_EFFECT = {
    FenceOperation.DECOMMISSION: (
        Lifecycle.DECOMMISSIONED,
        frozenset({Lifecycle.ACTIVE}),
    ),
    FenceOperation.TOMBSTONE: (
        Lifecycle.TOMBSTONED,
        frozenset({Lifecycle.DECOMMISSIONED}),
    ),
    FenceOperation.RECLAIM: (
        Lifecycle.AVAILABLE_FOR_RECLAIM,
        frozenset({Lifecycle.TOMBSTONED}),
    ),
}


class ProposalState(str, Enum):
    """
    Where a proposal has got to.

    The transitions are defined by fence.evaluate_proposal in ONE ordered pass,
    and the order is the definition rather than these descriptions. That matters
    because REJECTED and STALLED otherwise overlap: both can describe a window
    that closed without enough yes votes. The reference's own docstring defined
    them ambiguously, so a reader picking either description would be right half
    the time.

    Read fence.evaluate_proposal for the authority. In summary:

    - OPEN      the window is still running and nothing decisive has happened.
    - COMMITTED enough yes votes, or a recorded override.
    - REJECTED  enough explicit no votes, at any time; or the window closed with
                some support but not enough.
    - STALLED   the window closed with nobody having expressed a view, or with
                only the proposer's own implicit yes. Silence is not consent.
    - SUPERSEDED the operation can no longer be applied to its target, because
                that peer has moved to a lifecycle the operation is not permitted
                from, or its row is gone. Distinct from every state above on
                purpose: COMMITTED would claim the operation took effect, REJECTED
                and STALLED describe what the mesh decided, and CANCELLED says a
                person withdrew it. This one says nobody decided anything and the
                question stopped being answerable.
    - CANCELLED withdrawn rather than decided.
    """

    OPEN = "open"
    COMMITTED = "committed"
    REJECTED = "rejected"
    STALLED = "stalled"
    SUPERSEDED = "superseded"
    CANCELLED = "cancelled"


class VoteValue(str, Enum):
    """
    A peer's answer.

    ABSTAIN is a real answer and not a missing one: it says the peer saw the
    proposal and declined to support or block it. It counts toward nobody having
    been silent, so a window closing on abstentions is REJECTED rather than
    STALLED, because the peers did respond.
    """

    YES = "yes"
    NO = "no"
    ABSTAIN = "abstain"


@dataclass(frozen=True)
class FenceProposal:
    """
    One proposal, stored in overlay_config with sort key "fence#<proposal_id>".

    That table is shared with peer rows on purpose, and the shipped reader is
    already built for it: query_mesh skips sort keys prefixed fence#, vote# and
    control# rather than trying to validate them as peers, and its tests cover
    those prefixes. Using a separate table would mean deleting working code.

    `committed_by_override` records that quorum was bypassed rather than met. It
    is a permanent property of the row, not a request flag, because the reason
    the bypass is acceptable is that it is visible afterwards: there is no
    authority in this architecture that a proposer cannot self-grant, so the
    control is accountability rather than permission.
    """

    mesh_id: str
    proposal_id: str
    proposer: str
    operation: FenceOperation
    target: str
    reason: str
    proposed_at: int
    expires_at: int
    state: ProposalState = ProposalState.OPEN
    committed_by_override: bool = False
    paused_total_seconds: int = 0
    metadata: dict = field(default_factory=dict)
    schema_version: int = 1
    min_compatible_version: int = 1
    revision: int = 0


@dataclass(frozen=True)
class FenceVote:
    """
    One peer's vote, stored with sort key "vote#<proposal_id>#<voter>".

    Keyed on the pair so a peer changing its mind rewrites its own row rather
    than adding a second. The tally is defensive about duplicates anyway, since
    a key collision is not the only way two rows could appear.
    """

    mesh_id: str
    proposal_id: str
    voter: str
    vote: VoteValue
    voted_at: int
    reason: str = ""
    schema_version: int = 1
    min_compatible_version: int = 1


# ---------------------------------------------------------------------------
# Observed reachability
# ---------------------------------------------------------------------------


def health_pair_id(observer: str, observed: str) -> str:
    """
    The overlay_health sort key for one directed observation.

    The CDK defines this key as "<observer_cluster_id>:<observed_cluster_id>", so
    the separator is fixed by the table rather than chosen here. Directed on
    purpose: A reaching B and B reaching A are different facts, and a partition
    is frequently asymmetric, so collapsing them would hide the case an operator
    most needs to see.

    No parser is offered for the reverse direction. Both cluster ids are stored as
    their own attributes on the row, so a reader never needs to split this key,
    and a parser nothing calls is how CR-304562137 shipped a function that
    corrupted every real key for two revisions before review caught it.
    """
    return f"{observer}:{observed}"


@dataclass(frozen=True)
class HealthObservation:
    """
    One cluster's view of whether it can reach another, a row in overlay_health.

    Overwrite-only, and that is why it carries no `revision` where peer rows do.
    The key is the (observer, observed) pair, so a write can only replace that
    observer's own previous view of that peer. There is no lost update to protect
    against: two writers for one row would mean one cluster running two daemons,
    which is a different fault.

    `health` is this observer's classification, not the mesh's. The mesh-wide
    answer is a function of every observer's row and is computed by whoever reads
    them, because a single cluster cannot distinguish "the peer is down" from "I
    cannot reach the peer".
    """

    mesh_id: str
    observer: str
    observed: str
    last_attempt_ts: int
    health: Health
    # None until the observer has ever succeeded, which is different from a peer
    # that was reachable and stopped: the first says the tunnel may never have
    # come up, the second says it broke.
    last_ok_ts: Optional[int] = None
    last_rtt_ms: Optional[int] = None
    consecutive_failures: int = 0
    # A short window of recent round trips, newest last, kept so a reader can see
    # a trend rather than one sample. Bounded by the prober.
    recent_rtt_ms: List[int] = field(default_factory=list)
    schema_version: int = 1
    min_compatible_version: int = 1

    @property
    def pair_id(self) -> str:
        return health_pair_id(self.observer, self.observed)

    @property
    def has_ever_succeeded(self) -> bool:
        """
        Whether this observer has ever reached this peer.

        Named rather than left to callers comparing `last_ok_ts` to None, because
        the two failure stories need different operator responses and the
        distinction is easy to drop: a peer that never answered is usually a
        configuration or key problem, and a peer that stopped answering is usually
        a network or host problem.
        """
        return self.last_ok_ts is not None
