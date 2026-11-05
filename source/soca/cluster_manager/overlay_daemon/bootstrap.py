######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
First-run bootstrap: create the overlay mesh, or join one that exists.

The decision is made from what the mesh's Global Table already holds:

    query the mesh
      |
      +-- succeeded, rows returned    -> JOIN, allocating the next site_seq
      |
      +-- succeeded, no rows          -> CREATE, as site_seq 1
      |
      +-- failed                      -> ABORT

The ABORT path carries the weight here. A query that fails is not the same as a
query that found nothing, and treating them alike is how two clusters both
decide they are first. During a transient outage both would read "no rows" and
both would create the mesh, leaving two clusters with conflicting address plans
and no way to reconcile them. So an unreadable mesh stops the install.

CREATE is race-protected independently of that, because two clusters can reach
it legitimately at the same moment on a genuinely empty mesh. The metadata row
is written with a condition that it does not already exist, so exactly one
creator wins; the loser re-reads and joins the winner's mesh rather than failing.

See docs/cross_region/README.md for the mesh model and
docs/cross_region/MultiAccount.md for the cross-account case.
"""

from __future__ import annotations
import ipaddress
import logging
import secrets
import subprocess
import time
from typing import Optional

from . import ddb_client, table_names
from .models import Lifecycle, MeshMeta, Peer

logger = logging.getLogger("soca_logger")

# The mesh address plan. The IPv6 side is a randomly generated ULA /48 divided
# into a /64 per cluster; the IPv4 side is a fixed shared-address-space /16
# divided into a /24 per cluster.
DEFAULT_MESH_CGN_PREFIX = "100.64.0.0/16"

# Fallbacks for the mesh-wide lifecycle policy the creator writes into the
# metadata row. Named DEFAULT_ and passed in on the command line for the same
# reason the listen port is: all three ship as configurable keys, and the write
# happens exactly once at mesh creation with no update path in this change, so a
# literal here would override the operator's configuration for the life of the
# mesh rather than merely until the next restart.
DEFAULT_KEY_ROTATION_DAYS = 90
DEFAULT_AUTO_DECOMMISSION_DAYS = 90
DEFAULT_DECOMMISSION_TO_TOMBSTONE_DAYS = 30

# A /16 split into /24s leaves the third octet as the only degree of freedom, so
# the IPv4 plan is what caps mesh size rather than the IPv6 plan.
MAX_SITE_SEQ_V4 = 254
MAX_SITE_SEQ_V6 = 0xFFFF

# The address plan's prefix lengths, declared once. Every piece of the carve is
# derived from these rather than written as a literal: the shift, the output
# length, and the number of site_seq values that fit.
#
# The previous version hardcoded `site_seq << 64` and an octet rsplit, both of
# which are correct only for a /48 and a /16 respectively, and _parsed_prefix
# used strict=False and never checked the length. A /56 mesh prefix therefore
# passed validation and carved COLLIDING slots: site_seq 1, 257 and 513 all
# produced the same /64, which is two clusters handed one prefix, the exact
# collision this feature exists to prevent. A /24 CGN prefix produced slots
# outside the mesh prefix entirely.
MESH_ULA_PREFIXLEN = 48
CLUSTER_ULA_PREFIXLEN = 64
MESH_CGN_PREFIXLEN = 16
CLUSTER_CGN_PREFIXLEN = 24

# What an operator can actually re-run after a failed bootstrap.
#
# These messages used to say "retry the install", which is not possible on the
# controller they are printed on: 03_setup.sh.j2 writes its completion lock
# BEFORE the cross-region block runs, and its own top guard exits when that lock
# exists, so re-running the bootstrap script aborts immediately. The overlay
# installer is separately idempotent and reads its inputs from /etc/environment,
# which is already populated by the time this code runs, so re-running that one
# script is the remedy that works. A test asserts no operator message promises
# the unreachable one.
RETRY_HINT = (
    "the overlay installer directly: "
    "/opt/edh/$EDH_CLUSTER_ID/cluster_manager/overlay_daemon/scripts/"
    "install-overlay-daemon.sh (idempotent). Re-running the controller "
    "bootstrap will not work: its completion lock is already written"
)


class BootstrapError(Exception):
    """Any condition that should abort the install rather than be retried here."""


def _read_mesh(mesh_id: str, *, context: str):
    """
    Read the mesh, translating any operational failure into BootstrapError.

    Every mesh read in this module goes through here. Written as one helper
    rather than three copies of the same try block because the defect it closes
    was exactly that: the translation existed at the first read and not at the
    other two, and cmd_bootstrap catches only BootstrapError, so a failure at
    either of the others ended the install in a traceback rather than the clean
    exit and operator message this step exists to give. A helper means a fourth
    read cannot be added without the translation, and a test asserts this module
    makes no direct query_mesh call.

    `context` names what the read was for, so the operator message says which
    step failed rather than only that a read did.

    The metadata row's address plan is validated here as well, so every path that
    holds a meta holds a usable one. That is the other half of the same lesson:
    the emptiness guards were added for peer rows and then for the self row, and
    the prefixes every one of those slots is carved from were never checked.
    """
    try:
        peers, meta = ddb_client.query_mesh(mesh_id)
    except ddb_client.DDBQueryError as e:
        raise BootstrapError(
            f"{context} Resolve connectivity or permissions and re-run "
            f"{RETRY_HINT}. Underlying error: {e}"
        ) from e
    if meta is not None:
        _assert_usable_address_plan(meta)
    return peers, meta


def _assert_usable_address_plan(meta: MeshMeta) -> None:
    """
    Refuse a metadata row whose prefixes cannot define an address plan.

    Raised at the read rather than at the carve so the message names the row and
    the operator learns of it during bootstrap, where it is diagnosable, instead
    of at render time on every later cycle.
    """
    _parsed_prefix(
        meta.mesh_ula_prefix,
        ipaddress.IPv6Network,
        kind="IPv6 /48",
        expected_prefixlen=MESH_ULA_PREFIXLEN,
    )
    _parsed_prefix(
        meta.mesh_cgn_prefix,
        ipaddress.IPv4Network,
        kind="IPv4 /16",
        expected_prefixlen=MESH_CGN_PREFIXLEN,
    )


# ------------------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------------------


def bootstrap(
    *,
    mesh_id: str,
    cluster_id: str,
    cluster_name: str,
    region: str,
    account_id: str,
    endpoint: str,
    private_key_secret_arn: str,
    iam_principal: str,
    key_rotation_days: int = DEFAULT_KEY_ROTATION_DAYS,
    auto_decommission_days: int = DEFAULT_AUTO_DECOMMISSION_DAYS,
    decommission_to_tombstone_days: int = DEFAULT_DECOMMISSION_TO_TOMBSTONE_DAYS,
) -> Peer:
    """
    Register this cluster in the mesh and return its peer row.

    Raises BootstrapError on anything unrecoverable. The caller exits non-zero
    on that, so the install records a failure rather than leaving a controller
    that believes it is meshed when it is not.
    """
    logger.info("Starting overlay bootstrap for cluster=%s mesh=%s", cluster_id, mesh_id)

    peers, meta = _read_mesh(
        mesh_id,
        context=(
            f"Cannot verify the state of mesh {mesh_id}, so refusing to proceed. "
            f"Continuing without an authoritative answer risks two clusters each "
            f"creating it independently."
        ),
    )

    # The refusal below has to happen BEFORE any key is generated or persisted.
    # Generating first meant that on the path where the stored secret is invalid
    # and this cluster's row carries a different pubkey, a fresh key was written
    # to Secrets Manager and the bootstrap then refused. Every retry read that
    # now-valid key, derived the same non-matching pubkey and refused again, so
    # the install was permanently stuck until an operator reconciled the secret
    # against the row by hand. Deriving without generating keeps a refusal free
    # of side effects and therefore recoverable.
    existing_self = next((p for p in peers if p.cluster_id == cluster_id), None)
    current_public_key = _current_public_key(private_key_secret_arn)

    if existing_self is not None and existing_self.pubkey:
        if (
            current_public_key is not None
            and existing_self.pubkey == current_public_key
        ):
            logger.info(
                "Cluster %s is already registered with this public key; nothing to do",
                cluster_id,
            )
            return existing_self
        raise BootstrapError(
            f"Cluster {cluster_id} already has a row in mesh {mesh_id} carrying a "
            f"different public key. Overwriting it would let a host that holds a "
            f"new key take over an approved cluster's identity, so this is "
            f"refused. Nothing has been written, so the secret and the row are "
            f"still consistent. If the key was rotated or the controller was "
            f"rebuilt, revoke the existing peer and approve the new key from the "
            f"mesh console."
        )

    # Past this point the cluster will create, join or claim a row, so it needs a
    # usable key and generating one is the right thing to do.
    public_key = _ensure_wg_keypair(private_key_secret_arn)

    if meta is None and not peers:
        peer = _create_mesh(
            mesh_id=mesh_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            region=region,
            account_id=account_id,
            endpoint=endpoint,
            pubkey=public_key,
            iam_principal=iam_principal,
            key_rotation_days=key_rotation_days,
            auto_decommission_days=auto_decommission_days,
            decommission_to_tombstone_days=decommission_to_tombstone_days,
        )
        logger.info(
            "Created mesh %s with cluster %s as site_seq=%d",
            mesh_id,
            cluster_id,
            peer.site_seq,
        )
        return peer

    if meta is None:
        # Peer rows without a metadata row means the address plan is missing
        # while clusters are already using addresses derived from it. Deriving a
        # replacement would hand out prefixes that collide with the ones in use.
        raise BootstrapError(
            f"Mesh {mesh_id} has peer rows but no metadata row, so the address "
            f"plan those peers derived their prefixes from is gone. This cannot "
            f"be reconstructed safely and needs an operator. Inspect the table "
            f"with: aws dynamodb query --table-name "
            f"{_table_name_hint('overlay_config')} "
            f"--key-condition-expression 'mesh_id = :m' "
            f"--expression-attribute-values '{{\":m\":{{\"S\":\"{mesh_id}\"}}}}'"
        )

    existing_self = next((p for p in peers if p.cluster_id == cluster_id), None)
    if existing_self is not None:
        # Only the pre-registered case can reach here: a row carrying a pubkey
        # was already answered above, either as a no-op or as a refusal.
        return _adopt_existing_row(
            mesh_id=mesh_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            region=region,
            account_id=account_id,
            endpoint=endpoint,
            pubkey=public_key,
            iam_principal=iam_principal,
            meta=meta,
            existing_self=existing_self,
        )

    if not peers and meta.created_by == iam_principal:
        # Interrupted creation, resumed rather than joined.
        #
        # _create_mesh writes the metadata row and then its own peer row. When
        # the second write failed the mesh existed with no members, and this
        # function used to fall through to _join_mesh: the cluster registered
        # itself as PENDING at a freshly allocated site_seq, became the mesh's
        # only member, and could never be approved, because approval requires an
        # ACTIVE peer and there was none. That is a permanent deadlock with no
        # in-band recovery, reached by the operator doing the obvious thing.
        #
        # Guarded on created_by matching this principal so it cannot be used to
        # claim someone else's empty mesh. site_seq 1 is free by construction:
        # next_site_seq starts at 2, so no joiner is ever handed slot 1, and
        # rewriting it is idempotent rather than a second allocation.
        logger.warning(
            "Mesh %s has an address plan but no members and was created by this "
            "principal, so a previous install failed after creating it. "
            "Repopulating this cluster's own row as site_seq=1 rather than "
            "joining as a new site, which could never be approved.",
            mesh_id,
        )
        peer = _creator_peer(
            mesh_id=mesh_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            region=region,
            account_id=account_id,
            endpoint=endpoint,
            pubkey=public_key,
            iam_principal=iam_principal,
            ula_prefix=meta.mesh_ula_prefix,
            cgn_prefix=meta.mesh_cgn_prefix,
        )
        _translated(
            lambda: ddb_client.put_peer(peer),
            context=(
                f"Recovering the interrupted creation of mesh {mesh_id} failed "
                f"while rewriting this cluster's own peer row."
            ),
        )
        logger.info(
            "Recovered mesh %s with cluster %s as site_seq=%d",
            mesh_id,
            cluster_id,
            peer.site_seq,
        )
        return peer

    if not peers:
        # An address plan with no members that this principal did not create.
        # Joining would make this cluster the only member and PENDING, so it
        # could never be approved. Refusing says so instead of deadlocking.
        raise BootstrapError(
            f"Mesh {mesh_id} has an address plan but no member clusters, and it "
            f"was created by {meta.created_by} rather than by this cluster's "
            f"principal ({iam_principal}). Joining would register this cluster "
            f"as PENDING with no ACTIVE peer able to approve it, which cannot be "
            f"resolved from inside the mesh. Have the creating cluster complete "
            f"its own install first, or remove the orphaned metadata row."
        )

    peer = _join_mesh(
        mesh_id=mesh_id,
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        region=region,
        account_id=account_id,
        endpoint=endpoint,
        pubkey=public_key,
        iam_principal=iam_principal,
        meta=meta,
    )
    logger.info(
        "Joined mesh %s as cluster %s site_seq=%d", mesh_id, cluster_id, peer.site_seq
    )
    return peer


# ------------------------------------------------------------------------------
# CREATE
# ------------------------------------------------------------------------------


def _create_mesh(
    *,
    mesh_id: str,
    cluster_id: str,
    cluster_name: str,
    region: str,
    account_id: str,
    endpoint: str,
    pubkey: str,
    iam_principal: str,
    key_rotation_days: int = DEFAULT_KEY_ROTATION_DAYS,
    auto_decommission_days: int = DEFAULT_AUTO_DECOMMISSION_DAYS,
    decommission_to_tombstone_days: int = DEFAULT_DECOMMISSION_TO_TOMBSTONE_DAYS,
) -> Peer:
    """Create the mesh's address plan and register this cluster as site_seq 1."""
    ula_prefix = _generate_ula_48()
    cgn_prefix = DEFAULT_MESH_CGN_PREFIX

    meta = MeshMeta(
        mesh_id=mesh_id,
        mesh_ula_prefix=ula_prefix,
        mesh_cgn_prefix=cgn_prefix,
        # This cluster takes 1, so the next joiner takes 2.
        next_site_seq=2,
        created_at=int(time.time()),
        created_by=iam_principal,
        key_rotation_days=key_rotation_days,
        auto_decommission_days=auto_decommission_days,
        decommission_to_tombstone_days=decommission_to_tombstone_days,
    )
    try:
        _translated(
            lambda: ddb_client.put_meta_conditional(meta),
            context=f"Creating the address plan for mesh {mesh_id} failed.",
        )
    except ddb_client.DDBConditionFailedError:
        # Another cluster created the mesh between the read and this write. Its
        # address plan is now authoritative, so discard the one generated above
        # and join instead. This is an expected outcome, not an error.
        logger.warning(
            "Another cluster created mesh %s first; joining it instead of creating",
            mesh_id,
        )
        _peers, meta_now = _read_mesh(
            mesh_id,
            context=(
                f"Lost the race to create mesh {mesh_id}, and re-reading it to "
                f"join the winner failed, so this cluster's place in the mesh is "
                f"unknown."
            ),
        )
        if meta_now is None:
            raise BootstrapError(
                f"Lost the race to create mesh {mesh_id}, but the winner's "
                f"metadata row is not visible yet. This is most likely Global "
                f"Table replication lag; re-run {RETRY_HINT}."
            )
        return _join_mesh(
            mesh_id=mesh_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            region=region,
            account_id=account_id,
            endpoint=endpoint,
            pubkey=pubkey,
            iam_principal=iam_principal,
            meta=meta_now,
        )

    peer = _creator_peer(
        mesh_id=mesh_id,
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        region=region,
        account_id=account_id,
        endpoint=endpoint,
        pubkey=pubkey,
        iam_principal=iam_principal,
        ula_prefix=ula_prefix,
        cgn_prefix=cgn_prefix,
    )
    _translated(
        lambda: ddb_client.put_peer(peer),
        context=(
            f"Registered the address plan for mesh {mesh_id} but writing this "
            f"cluster's own peer row failed, so the mesh exists with no members. "
            f"Re-running the install recovers this: the creator's row is "
            f"repopulated rather than joined as a new site."
        ),
    )
    return peer


def _creator_peer(
    *,
    mesh_id: str,
    cluster_id: str,
    cluster_name: str,
    region: str,
    account_id: str,
    endpoint: str,
    pubkey: str,
    iam_principal: str,
    ula_prefix: str,
    cgn_prefix: str,
) -> Peer:
    """
    The mesh creator's own peer row: site_seq 1, ACTIVE, prefixes from slot 1.

    Shared by _create_mesh and the interrupted-creation recovery below so the two
    cannot disagree about what the creator's row looks like. Writing it in both
    places is how the recovery path would silently drift into allocating a fresh
    site_seq or a PENDING lifecycle.
    """
    return Peer(
        mesh_id=mesh_id,
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        region=region,
        account_id=account_id,
        site_seq=1,
        pubkey=pubkey,
        pubkey_next=None,
        endpoint=endpoint,
        ula_prefix=_slot_ula(ula_prefix, site_seq=1),
        cgn_prefix=_slot_cgn(cgn_prefix, site_seq=1),
        # The cluster that creates the mesh is approved by definition: there is
        # no one else yet who could approve it.
        lifecycle=Lifecycle.ACTIVE,
        joined_at=int(time.time()),
        joined_by=iam_principal,
    )


# ------------------------------------------------------------------------------
# JOIN
# ------------------------------------------------------------------------------


def _join_mesh(
    *,
    mesh_id: str,
    cluster_id: str,
    cluster_name: str,
    region: str,
    account_id: str,
    endpoint: str,
    pubkey: str,
    iam_principal: str,
    meta: MeshMeta,
) -> Peer:
    """Claim a site_seq and register this cluster as awaiting approval."""
    site_seq = _translated(
        lambda: ddb_client.allocate_site_seq(mesh_id),
        context=(
            f"Could not claim a site sequence number in mesh {mesh_id}, so this "
            f"cluster has no address plan of its own."
        ),
    )

    peer = Peer(
        mesh_id=mesh_id,
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        region=region,
        account_id=account_id,
        site_seq=site_seq,
        pubkey=pubkey,
        pubkey_next=None,
        endpoint=endpoint,
        ula_prefix=_slot_ula(meta.mesh_ula_prefix, site_seq=site_seq),
        cgn_prefix=_slot_cgn(meta.mesh_cgn_prefix, site_seq=site_seq),
        # A joining cluster is inert until an administrator approves it. Peers
        # will not route to it, and it will not route to them.
        lifecycle=Lifecycle.PENDING,
        joined_at=int(time.time()),
        joined_by=iam_principal,
    )
    _translated(
        lambda: ddb_client.put_peer(peer),
        context=(
            f"Claimed site sequence {peer.site_seq} in mesh {mesh_id} but writing "
            f"this cluster's peer row failed, so the sequence is consumed and the "
            f"cluster is not registered."
        ),
    )
    return peer


# ------------------------------------------------------------------------------
# Adopting a row that already exists
# ------------------------------------------------------------------------------


def _adopt_existing_row(
    *,
    mesh_id: str,
    cluster_id: str,
    cluster_name: str,
    region: str,
    account_id: str,
    endpoint: str,
    pubkey: str,
    iam_principal: str,
    meta: MeshMeta,
    existing_self: Peer,
) -> Peer:
    """
    Claim a row this mesh already carries for this cluster id.

    Only the pre-registered case reaches here. A row that already carries a
    public key is answered in bootstrap() before any key is generated, either as
    a no-op when it matches or as a refusal when it does not, so that a refusal
    cannot leave a freshly written secret behind. The matching and mismatching
    branches used to live here, after generation, which is what made a refused
    bootstrap unrecoverable.
    """
    if existing_self.pubkey:
        raise BootstrapError(
            f"_adopt_existing_row was reached for cluster {cluster_id} with a "
            f"populated public key, which bootstrap() is meant to have answered "
            f"already. Refusing rather than deciding it twice."
        )

    logger.info(
        "Cluster %s has a pre-registered row (lifecycle=%s); claiming it",
        cluster_id,
        existing_self.lifecycle.value,
    )
    peer = _populate_pre_registered_row(
        mesh_id=mesh_id,
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        region=region,
        account_id=account_id,
        endpoint=endpoint,
        pubkey=pubkey,
        iam_principal=iam_principal,
        meta=meta,
        existing_self=existing_self,
    )
    logger.info(
        "Claimed pre-registered row for %s: lifecycle=%s site_seq=%d",
        cluster_id,
        peer.lifecycle.value,
        peer.site_seq,
    )
    return peer


def _populate_pre_registered_row(
    *,
    mesh_id: str,
    cluster_id: str,
    cluster_name: str,
    region: str,
    account_id: str,
    endpoint: str,
    pubkey: str,
    iam_principal: str,
    meta: MeshMeta,
    existing_self: Peer,
) -> Peer:
    """
    Fill in a pre-registered row's key and addressing, preserving its lifecycle.

    An administrator can register a cluster before it exists so that approval
    happens during the deploy window rather than after it. Such a row may
    already have been approved by the time the controller boots, so the
    lifecycle is deliberately left alone: resetting it to PENDING would discard
    an approval that has already been given.
    """
    # The pre-registration row carries no usable site_seq, so allocate one now.
    site_seq = _translated(
        lambda: ddb_client.allocate_site_seq(mesh_id),
        context=(
            f"Could not claim a site sequence number for the pre-registered row "
            f"of cluster {cluster_id} in mesh {mesh_id}."
        ),
    )

    _translated(
        lambda: ddb_client.populate_pre_registered_peer(
            mesh_id=mesh_id,
            cluster_id=cluster_id,
            site_seq=site_seq,
            pubkey=pubkey,
            endpoint=endpoint,
            ula_prefix=_slot_ula(meta.mesh_ula_prefix, site_seq=site_seq),
            cgn_prefix=_slot_cgn(meta.mesh_cgn_prefix, site_seq=site_seq),
            # Fall back to the name the administrator registered, so a cluster
            # that cannot resolve its own name does not blank out a reviewed
            # value.
            cluster_name=cluster_name or existing_self.cluster_name,
            region=region,
            account_id=account_id,
            actor=iam_principal,
        ),
        context=(
            f"Could not fill in the pre-registered row for cluster {cluster_id} "
            f"in mesh {mesh_id}."
        ),
    )

    # Re-read rather than constructing the result locally: the lifecycle may
    # have been changed by an administrator while this was running, and the
    # caller needs the row as it now stands.
    peers, _meta = _read_mesh(
        mesh_id,
        context=(
            f"Claimed the pre-registered row for cluster {cluster_id} in mesh "
            f"{mesh_id}, but re-reading it failed, so its lifecycle after the "
            f"claim is unknown. The claim itself succeeded."
        ),
    )
    self_now = next((p for p in peers if p.cluster_id == cluster_id), None)
    if self_now is None:
        raise BootstrapError(
            f"The row for cluster {cluster_id} disappeared while it was being "
            f"populated, so it was most likely deleted concurrently. Aborting "
            f"rather than recreating it, because the deletion may have been "
            f"deliberate."
        )
    return self_now


# ------------------------------------------------------------------------------
# Address plan
# ------------------------------------------------------------------------------


def _generate_ula_48() -> str:
    """
    Generate a random unique-local /48 for a new mesh, per RFC 4193.

    The RFC calls for fd00::/8 followed by 40 random bits, which is what makes
    two independently created meshes overwhelmingly unlikely to collide even
    though neither consults any registry.
    """
    random_hex = secrets.token_bytes(5).hex()  # 40 bits, 10 hex characters
    return f"fd{random_hex[:2]}:{random_hex[2:6]}:{random_hex[6:10]}::/48"


def _slot_ula(mesh_prefix_48: str, *, site_seq: int) -> str:
    """Return one cluster's /64, carved out of the mesh /48 by site_seq."""
    if site_seq < 1 or site_seq > MAX_SITE_SEQ_V6:
        raise BootstrapError(
            f"site_seq {site_seq} is out of range for a /48 to /64 split "
            f"(1 to {MAX_SITE_SEQ_V6})"
        )
    return _carve_slot(
        mesh_prefix_48,
        site_seq=site_seq,
        family=ipaddress.IPv6Network,
        bits=128,
        mesh_prefixlen=MESH_ULA_PREFIXLEN,
        cluster_prefixlen=CLUSTER_ULA_PREFIXLEN,
        kind="IPv6 /48",
    )


def _slot_cgn(mesh_prefix_16: str, *, site_seq: int) -> str:
    """Return one cluster's /24, carved out of the mesh /16 by site_seq."""
    if site_seq < 1 or site_seq > MAX_SITE_SEQ_V4:
        raise BootstrapError(
            f"site_seq {site_seq} is out of range for a /16 to /24 split "
            f"(1 to {MAX_SITE_SEQ_V4}), which is the limit on how many clusters "
            f"one mesh can hold"
        )
    return _carve_slot(
        mesh_prefix_16,
        site_seq=site_seq,
        family=ipaddress.IPv4Network,
        bits=32,
        mesh_prefixlen=MESH_CGN_PREFIXLEN,
        cluster_prefixlen=CLUSTER_CGN_PREFIXLEN,
        kind="IPv4 /16",
    )


def _carve_slot(
    mesh_prefix: str,
    *,
    site_seq: int,
    family,
    bits: int,
    mesh_prefixlen: int,
    cluster_prefixlen: int,
    kind: str,
) -> str:
    """
    Carve one cluster's slot out of a mesh prefix, for either address family.

    One implementation for both families, because the two diverging is how the
    IPv6 side came to do string surgery while the IPv4 side derived from the
    parsed object, and how the IPv6 side alone shipped a defect the IPv4 side was
    immune to.

    Everything is derived: the shift from `cluster_prefixlen`, the room available
    from the difference between the two lengths. Nothing is a literal, so a plan
    with a different split cannot silently produce overlapping slots.

    There is deliberately NO runtime assertion that the carved slot is inside the
    mesh prefix. One was written and then removed: probing showed it could not fire,
    because a masked network address ORed with a value that fits the available bits
    is always inside the prefix once the length is validated, and the no-room guard
    below covers the only inconsistent-declaration case. An assertion that cannot
    fail is not a guard, it just reads like one. The property is enforced by
    test_every_carved_slot_is_inside_the_mesh_prefix and
    test_no_two_site_seqs_share_a_slot, both of which were confirmed to fail when
    the shift is hardcoded again.
    """
    if cluster_prefixlen <= mesh_prefixlen:
        raise BootstrapError(
            f"The address plan declares a mesh /{mesh_prefixlen} and a cluster "
            f"/{cluster_prefixlen}, which leaves no room to carve per-cluster "
            f"slots. This is a programming error in the plan's declared lengths, "
            f"not a problem with the stored row."
        )
    network = _parsed_prefix(
        mesh_prefix, family, kind=kind, expected_prefixlen=mesh_prefixlen
    )
    room = cluster_prefixlen - mesh_prefixlen
    if site_seq >= (1 << room):
        raise BootstrapError(
            f"site_seq {site_seq} does not fit in the {room} bits between "
            f"/{mesh_prefixlen} and /{cluster_prefixlen}, so it would collide with "
            f"another cluster's slot."
        )
    slot = family(
        (
            int(network.network_address) | (site_seq << (bits - cluster_prefixlen)),
            cluster_prefixlen,
        )
    )
    return str(slot)


def _parsed_prefix(value: str, constructor, *, kind: str, expected_prefixlen: int):
    """
    Parse a mesh prefix, refusing anything unusable with an operator message.

    The single place a stored prefix becomes a network object, so every slot is
    carved from something that parsed. Guarding here rather than at each call site
    is deliberate: the same predicate was applied to peer rows in one revision and
    the self row in the next, and the metadata row's own prefixes, which every
    slot derives from, were never covered at all.

    `expected_prefixlen` is required, not optional. strict=False accepts a valid
    network of ANY length, so a /56 stored where a /48 belongs parsed cleanly and
    then carved colliding slots. An optional check would have been left off at
    some call site, which is the shape of most of this CR's review findings, so
    there is no default to omit.
    """
    if not value or not str(value).strip():
        # Not load-bearing for the refusal: ipaddress rejects "" and "   " on its
        # own, verified. This branch exists only so the operator reads "carries no
        # IPv6 prefix", which names the actual state of the row, rather than
        # "'' is not a valid network". A test asserts the distinct wording, so the
        # branch cannot be deleted as dead while the message it produces is
        # relied on.
        raise BootstrapError(
            f"The mesh metadata row carries no {kind} prefix, so no cluster "
            f"address plan can be derived from it. This row was created or edited "
            f"outside bootstrap, which always writes both prefixes. Inspect the "
            f"_meta row in {_table_name_hint('overlay_config')} before retrying."
        )
    try:
        network = constructor(str(value).strip(), strict=False)
    except ValueError as e:
        raise BootstrapError(
            f"The mesh metadata row's {kind} prefix {value!r} is not a valid "
            f"network, so the address plan it defines cannot be used. Inspect the "
            f"_meta row in {_table_name_hint('overlay_config')}. Underlying "
            f"error: {e}"
        ) from e
    if network.prefixlen != expected_prefixlen:
        raise BootstrapError(
            f"The mesh metadata row's {kind} prefix {value!r} is a "
            f"/{network.prefixlen}, but the address plan requires a "
            f"/{expected_prefixlen}. Carving cluster slots out of a different "
            f"length would hand two clusters the same addresses or hand one "
            f"cluster addresses outside the mesh. Inspect the _meta row in "
            f"{_table_name_hint('overlay_config')}."
        )
    return network


# ------------------------------------------------------------------------------
# WireGuard key material
# ------------------------------------------------------------------------------


def _translated(operation, *, context: str):
    """
    Run a ddb_client call, translating an operational failure into BootstrapError.

    The counterpart to _read_mesh, and added for the same reason one revision
    later: the reads were swept through a translating helper and nothing else
    was, so the writes and the Secrets Manager reads still raised DDBQueryError.
    cmd_bootstrap catches only BootstrapError, so any of them ended the install
    in a traceback rather than the clean exit and operator message it is
    documented to produce.

    DDBConditionFailedError is deliberately NOT translated. It is not an
    operational failure but a race outcome the callers act on: losing the
    creation race converts to a join, and a claimed pre-registered row is a
    refusal with its own message.
    """
    try:
        return operation()
    except ddb_client.DDBQueryError as e:
        raise BootstrapError(
            f"{context} Resolve connectivity or permissions and re-run "
            f"{RETRY_HINT}. Underlying error: {e}"
        ) from e


def _current_public_key(secret_arn: str) -> Optional[str]:
    """
    The public key of the stored private key, or None when there is no usable one.

    Reads only. Deliberately separate from _ensure_wg_keypair so the caller can
    answer "does the stored key match this row" without the act of asking having
    written anything: a refusal that had already replaced the secret left the
    install unable to succeed on any retry.
    """
    privkey = _translated(
        lambda: ddb_client.read_private_key_secret(secret_arn),
        context=(
            f"Could not read the WireGuard key secret {secret_arn}, so this "
            f"cluster's mesh identity cannot be established."
        ),
    )
    if privkey is None or not _is_valid_wg_private_key(privkey):
        return None
    return (
        subprocess.check_output(["wg", "pubkey"], input=privkey.encode())
        .decode()
        .strip()
    )


def _ensure_wg_keypair(secret_arn: str) -> str:
    """
    Ensure the cluster holds a usable WireGuard private key, and return the
    matching public key.

    Secrets Manager is the source of truth, so a re-run reuses the existing key
    and does not disturb peers that already trust it.

    MAY WRITE. Call this only once the caller has decided the cluster is going to
    create, join or claim a row; use _current_public_key when the answer is only
    being compared.

    The stored value is validated rather than merely checked for presence,
    because CDK's Secret generates a random alphanumeric string when no
    generator is configured. That value is non-empty but is not a Curve25519
    key, so a presence check accepts it and the daemon then fails on its first
    use of the key. Validating covers that case along with manual edits and
    partial writes.
    """
    privkey = _translated(
        lambda: ddb_client.read_private_key_secret(secret_arn),
        context=f"Could not read the WireGuard key secret {secret_arn}.",
    )

    if privkey is None or not _is_valid_wg_private_key(privkey):
        if privkey is None:
            logger.info("No WireGuard private key stored yet; generating one")
        else:
            logger.warning(
                "The stored WireGuard secret is not a valid private key, which "
                "usually means it still holds the value generated at deploy "
                "time. Generating a real key and overwriting it."
            )
        privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
        _translated(
            lambda: ddb_client.write_private_key_secret(secret_arn, privkey),
            context=(
                f"Generated a WireGuard key but could not store it in "
                f"{secret_arn}, so it would be lost and the cluster's identity "
                f"would change on the next run."
            ),
        )

    return (
        subprocess.check_output(["wg", "pubkey"], input=privkey.encode())
        .decode()
        .strip()
    )


def _is_valid_wg_private_key(value: str) -> bool:
    """
    Whether a stored value is a usable WireGuard private key.

    Decided by asking wg to derive a public key from it, rather than by checking
    length or character set, because those accept values wg then rejects.
    """
    try:
        subprocess.run(
            ["wg", "pubkey"],
            input=value.encode(),
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ):
        return False


def _table_name_hint(short_name: str) -> str:
    """
    Resolve a table name for an operator-facing message, best effort.

    An error message must not raise while being built, and the case this appears
    in is already a broken mesh, so an unresolvable name degrades to the short
    name rather than replacing the real error with a resolution failure.
    """
    try:
        return table_names.resolve(short_name)
    except Exception:  # noqa: BLE001 - a hint must never mask the real error
        return f"<edh_(prefix)_{short_name}>"
