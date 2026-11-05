######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Render and apply the WireGuard configuration for this cluster's mesh peers.

The load-bearing decision here is that peer changes are applied with
`wg syncconf` rather than by taking the interface down and up. wg-quick's
down/up cycle would reconfigure everything correctly and also drop every
in-flight connection across the tunnel, which for this mesh means killing PBS
protocol traffic every time an unrelated cluster joins, is approved, or rotates
a key. syncconf reconciles the peer set in place instead, so the interface never
bounces.

That choice has a consequence this module has to make up for: wg-quick installs
ip routes as well as configuring WireGuard, and syncconf does not. Cryptokey
routing (the AllowedIPs filter) is not the same thing as the kernel knowing to
send a packet at the interface, so route reconciliation lives here.
"""

from __future__ import annotations
import hashlib
import logging
import os
import re
import subprocess
import tempfile
from typing import List, Optional

from .models import Health, Lifecycle, Peer

logger = logging.getLogger("soca_logger")

INTERFACE_NAME = "edh-mesh0"
KEEPALIVE_SECONDS = 25

# Fallbacks only. The listen port and MTU are configurable through
# /configuration/services/cross_region/overlay/, and the interface script and
# the advertised peer endpoint both honour the configured value, so a constant
# used in their place does not merely differ, it fights them: the interface comes
# up on the configured port and a reconcile cycle then resets it to this one
# while every peer keeps dialling the port the mesh advertises. These are named
# DEFAULT_ so a value that should have been plumbed cannot read as settled.
DEFAULT_LISTEN_PORT = 51820
DEFAULT_MTU = 1280

# Every Peer attribute that _render_peer_block interpolates into a value line and
# that WireGuard rejects when empty. A peer row missing any of them is skipped
# rather than rendered, because wg syncconf refuses the whole file and one bad
# row would take the mesh down instead of itself.
#
# tests/cross_region/test_daemon_invariants.py derives the attributes the block
# actually reads and asserts this list covers them, so adding a field to the
# block without adding it here fails rather than shipping.
PEER_BLOCK_REQUIRED_FIELDS = ("pubkey", "endpoint", "ula_prefix", "cgn_prefix")

# Change-detection marker. This holds a HASH of the last applied configuration
# rather than the configuration itself, because the rendered configuration
# contains this cluster's WireGuard private key and nothing here ever needs to
# read the old text back, only to know whether it differs.
_LAST_APPLIED_PATH = "/var/lib/edh-overlay-daemon/last_applied.sha256"


# ------------------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------------------


def render(
    *,
    self_peer: Peer,
    self_privkey: str,
    peers: List[Peer],
    health_by_cluster: Optional[dict] = None,
    listen_port: int = DEFAULT_LISTEN_PORT,
    mtu: int = DEFAULT_MTU,
) -> str:
    """
    Render this cluster's WireGuard configuration from the mesh peer set.

    Only peers whose lifecycle is ACTIVE are included, so a pending, revoked or
    decommissioned cluster is absent from the tunnel entirely.

    Health, when supplied, drops only UNAVAILABLE peers. A DEGRADED peer stays
    configured on purpose: PBS retries on its own, and keeping the peer means
    handshake state survives a transient problem instead of the mesh having to
    rediscover it. health_by_cluster is empty until the health subsystem exists,
    which leaves every ACTIVE peer configured.
    """
    health_by_cluster = health_by_cluster or {}
    # Guarded before the [Interface] block, not just inside the peer loop. The
    # interface lines dereference this cluster's own controller addresses, and
    # the validator defaults a missing prefix to the empty string, so an own row
    # without an address plan raised here and abandoned the whole render. Unlike
    # a peer in that state, this one cannot be skipped: without our own
    # addresses there is no configuration to write, so it is reported.
    #
    # Asked through the same predicate the peer loop and the hosts block use, so
    # the self row is held to the same standard. The emptiness form this replaced
    # accepted a malformed non-empty prefix, which then raised out of
    # controller_v6 with a message about a leading colon instead of this one.
    self_plan_error = self_peer.address_plan_error
    if self_plan_error is not None:
        raise ValueError(
            f"cluster {self_peer.cluster_id} has an unusable address plan on its "
            f"own mesh row ({self_plan_error}), so no interface configuration can "
            f"be rendered. bootstrap assigns the plan, so this row was created or "
            f"edited outside it."
        )
    lines: List[str] = [
        "# Auto-generated by edh-overlay-daemon. Do not edit.",
        f"# Mesh: {self_peer.mesh_id}",
        f"# Self: {self_peer.cluster_id} (site_seq={self_peer.site_seq})",
        "",
        "[Interface]",
        f"PrivateKey = {self_privkey}",
        f"ListenPort = {listen_port}",
        f"Address = {self_peer.controller_v6}/64, {self_peer.controller_v4}/24",
        f"MTU = {mtu}",
        "",
    ]

    for peer in peers:
        if peer.cluster_id == self_peer.cluster_id:
            continue
        if peer.lifecycle != Lifecycle.ACTIVE:
            continue
        if health_by_cluster.get(peer.cluster_id) == Health.UNAVAILABLE:
            continue
        # Every field the peer block emits must be non-empty, checked from one
        # list rather than as separate conditions. The guards used to name pubkey
        # and the address plan and not endpoint, and the validator defaults a
        # missing endpoint to the empty string, so an ACTIVE row without one
        # emitted "Endpoint = " with nothing after it. wg syncconf rejects that
        # file, which fails the whole apply rather than one peer, which is the
        # failure every guard here exists to prevent. Deriving the list from
        # PEER_BLOCK_REQUIRED_FIELDS means a field added to the block has to be
        # added here too, and a test asserts the two agree.
        missing = [f for f in PEER_BLOCK_REQUIRED_FIELDS if not getattr(peer, f, None)]
        if missing:
            logger.warning(
                "skipping peer %s in the tunnel: its row is missing %s",
                peer.cluster_id,
                ", ".join(missing),
            )
            continue
        # Emptiness is not the property that matters for the prefixes. A
        # non-empty but malformed value passes the check above and reaches
        # AllowedIPs, and wg syncconf then rejects the file, so one hand-edited
        # row costs the whole apply. Peer.address_plan_error is the same predicate
        # the hosts block asks, so the two cannot disagree about which rows are
        # usable.
        plan_error = peer.address_plan_error
        if plan_error is not None:
            logger.warning(
                "skipping peer %s in the tunnel: %s", peer.cluster_id, plan_error
            )
            continue

        lines.extend(_render_peer_block(peer, peer.pubkey))

        # pubkey_next is deliberately NOT rendered as a second peer block.
        # WireGuard requires AllowedIPs to be unique across the peers on an
        # interface and moves an overlapping prefix to whichever peer was
        # configured last, so two blocks carrying this peer's same prefixes do
        # not accept both keys: the second silently takes the routing from the
        # first, which is the cutover gap the overlap was meant to remove.
        # A rotating peer keeps its current key in `pubkey` until it has
        # switched, so reading `pubkey` alone is what actually spans a rotation.
        # Publishing and retiring `pubkey_next` belongs to the key-rotation
        # subsystem, which arrives with its own change.

    return "\n".join(lines) + "\n"


def _render_peer_block(peer: Peer, pubkey: str, label_suffix: str = "") -> List[str]:
    return [
        f"[Peer]{label_suffix}",
        f"# {peer.cluster_id} ({peer.region})",
        f"PublicKey = {pubkey}",
        f"AllowedIPs = {peer.ula_prefix}, {peer.cgn_prefix}",
        f"Endpoint = {peer.endpoint}",
        f"PersistentKeepalive = {KEEPALIVE_SECONDS}",
        "",
    ]


# ------------------------------------------------------------------------------
# Applying
# ------------------------------------------------------------------------------


def apply_config(rendered: str, *, dry_run: bool = False) -> bool:
    """
    Apply a rendered configuration. Returns True when the configuration changed.

    The sequence is: reconcile routes, then `wg syncconf` the peer sections if the
    configuration differs from the last applied one, then re-assert the interface
    settings and check for drift in the startup-only ones.

    Routes AND the interface settings are applied on EVERY call, including when
    the configuration is unchanged, because both can be mutated from outside this
    daemon and an unchanged peer set is no guarantee the kernel still agrees with
    it. Only syncconf is gated on the hash, because it is the one step whose work
    is proportional to the peer set.

    That per-cycle assertion is a correction. The interface settings used to sit
    inside the hash-gated branch, so INTERFACE_KEYS_APPLIED_EACH_CYCLE named a
    guarantee the code did not give: an operator running `ip link set dev
    edh-mesh0 mtu 1200` by hand was never corrected, because the rendered config
    had not changed. That is exactly the drift case the route rationale above is
    written about.

    syncconf takes a peer-only file, so the interface settings are re-applied
    separately afterwards with `wg set`. That ordering matters: syncconf given a
    file with no [Interface] section can clear interface-level fields, and if the
    listen port is lost WireGuard picks an ephemeral one while every peer is
    still sending to 51820. The settings are therefore applied after the syncconf
    block rather than before it, so a cycle that runs syncconf still ends with
    them asserted.
    """
    if dry_run:
        logger.info(
            "dry run: would apply a configuration of %d lines",
            len(rendered.splitlines()),
        )
        return False

    try:
        _reconcile_peer_routes(rendered)
    except Exception:
        # A routing problem must not stop the peer set being applied; the tunnel
        # is still worth configuring, and the next cycle retries the routes.
        logger.exception("peer route reconciliation failed")

    changed = _config_changed(rendered)
    if changed:
        peer_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".conf", delete=False
            ) as peer_file:
                peer_file.write(_strip_interface_section(rendered))
                peer_path = peer_file.name

            subprocess.run(
                ["wg", "syncconf", INTERFACE_NAME, peer_path],
                check=True,
                capture_output=True,
            )
            _save_last_applied(rendered)
        finally:
            # In a finally block so a syncconf failure does not leave the file
            # behind on every retry.
            if peer_path is not None:
                try:
                    os.unlink(peer_path)
                except OSError:
                    pass

    _apply_interface_settings(rendered)
    _warn_on_startup_only_drift(rendered)
    return changed


def _apply_interface_settings(rendered: str) -> None:
    """
    Assert the [Interface] settings that this daemon owns onto the link.

    Called on every cycle, and always after any syncconf, because syncconf given
    a peer-only file can clear interface-level fields.

    Everything here is read from the rendered configuration rather than from a
    module constant, so the value written into [Interface] and the value set on
    the link cannot disagree. A constant here reset a configured port back to the
    default on the first cycle while peers kept dialling the port the mesh
    advertises.

    Each call is idempotent: setting the same key, port or MTU that is already in
    place is a no-op, which is what makes running this every cycle cheap enough to
    be the default rather than an optimisation to gate.
    """
    privkey = _extract_privkey(rendered)
    listen_port = _extract_listen_port(rendered)
    settings: List[str] = []
    if listen_port is not None:
        settings += ["listen-port", str(listen_port)]
    if privkey:
        subprocess.run(
            ["wg", "set", INTERFACE_NAME] + settings + [
                "private-key", "/dev/stdin",
            ],
            input=privkey.encode(),
            check=True,
            capture_output=True,
        )
    elif settings:
        subprocess.run(
            ["wg", "set", INTERFACE_NAME] + settings,
            check=True,
            capture_output=True,
        )

    _apply_mtu(rendered)


# Every key rendered into [Interface], partitioned by how it reaches the link.
#
# The partition is the point. `_config_changed` hashes the WHOLE rendered file,
# so any [Interface] value that is rendered but never applied is marked converged
# the moment it changes: the hash is saved, the next cycle matches, and the drift
# is masked permanently. That is exactly what happened to MTU, which was rendered
# and hashed while only ensure-interface.sh ever set it, so a configured MTU
# change silently never took effect on a running daemon. The listen port had the
# same shape and was fixed for the port alone three revisions earlier.
#
# A test in test_daemon_invariants.py derives the keys `render` actually emits
# into [Interface] and asserts each one appears in exactly one of these two sets,
# so a field added to the section cannot be left silently unapplied again.
INTERFACE_KEYS_APPLIED_EACH_CYCLE = frozenset(
    {"PrivateKey", "ListenPort", "MTU"}
)

INTERFACE_KEYS_SET_AT_STARTUP_ONLY = {
    "Address": (
        "Renumbering means removing the old prefixes as well as adding the new "
        "ones, which drops every tunnel on the interface, so ensure-interface.sh "
        "assigns the addresses when it creates the link and a change needs the "
        "unit restarted. Not applied here, and therefore warned about on every "
        "cycle rather than hashed away."
    ),
}


def _apply_mtu(rendered: str) -> None:
    """
    Apply the rendered MTU to the link.

    Neither `wg syncconf` nor `wg set` touches MTU: it is a link property, and
    ensure-interface.sh sets it with the same `ip link set` call at startup. It
    has to be re-applied here for the same reason the listen port does, because
    the rendered value is what the hash records as applied.
    """
    mtu = _extract_mtu(rendered)
    if mtu is None:
        return
    try:
        subprocess.run(
            ["ip", "link", "set", "dev", INTERFACE_NAME, "mtu", str(mtu)],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError) as e:
        # Logged rather than raised: the peer set has already been applied and is
        # worth keeping, and the next cycle retries. Raising here would also
        # skip _save_last_applied and re-run syncconf every cycle.
        logger.warning("could not set the MTU on %s to %s: %s", INTERFACE_NAME, mtu, e)


def _extract_mtu(config: str) -> Optional[int]:
    """The MTU from the rendered [Interface] section, or None when absent."""
    match = re.search(r"^\s*MTU\s*=\s*(\d+)\s*$", config, re.MULTILINE)
    return int(match.group(1)) if match else None


def _extract_addresses(config: str) -> List[str]:
    """The addresses from the rendered [Interface] section, in order."""
    match = re.search(r"^\s*Address\s*=\s*(.+)$", config, re.MULTILINE)
    if not match:
        return []
    return [part.strip() for part in match.group(1).split(",") if part.strip()]


def _warn_on_startup_only_drift(rendered: str) -> None:
    """
    Log when a startup-only [Interface] value no longer matches the link.

    Read from the interface rather than from remembered state, because the
    last-applied marker deliberately stores only a hash and the kernel is the
    authority anyway. Without this the hash would record a renumbering as applied
    and no cycle would ever mention it again.
    """
    wanted = _extract_addresses(rendered)
    if not wanted:
        return
    try:
        result = subprocess.run(
            ["ip", "-o", "addr", "show", "dev", INTERFACE_NAME],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, OSError) as e:
        logger.debug("could not read the addresses on %s: %s", INTERFACE_NAME, e)
        return
    on_link = result.stdout
    missing = [address for address in wanted if address not in on_link]
    if missing:
        logger.warning(
            "%s is missing the rendered address(es) %s. %s Restart "
            "edh-overlay-daemon to reassign them.",
            INTERFACE_NAME,
            ", ".join(missing),
            INTERFACE_KEYS_SET_AT_STARTUP_ONLY["Address"],
        )


def _strip_interface_section(config: str) -> str:
    """
    Return the configuration with the [Interface] section removed.

    syncconf rejects a file carrying an [Interface] section, and this also keeps
    the private key out of the temporary file written to disk.
    """
    out: List[str] = []
    in_interface = False
    for line in config.splitlines():
        stripped = line.strip()
        if stripped == "[Interface]":
            in_interface = True
            continue
        if in_interface and stripped.startswith("[Peer]"):
            in_interface = False
        if not in_interface:
            out.append(line)
    return "\n".join(out)


def _extract_privkey(config: str) -> Optional[str]:
    for line in config.splitlines():
        if line.startswith("PrivateKey = "):
            return line.split(" = ", 1)[1].strip()
    return None


def _extract_listen_port(config: str) -> Optional[int]:
    """
    The listen port the rendered configuration declares, or None.

    None means the re-assertion is skipped rather than guessed, leaving whatever
    the interface script set. Guessing would reintroduce the defect this replaced.
    """
    for line in config.splitlines():
        if line.startswith("ListenPort = "):
            value = line.split(" = ", 1)[1].strip()
            try:
                return int(value)
            except ValueError:
                logger.warning(
                    "rendered ListenPort %r is not a number; leaving the port "
                    "the interface script set",
                    value,
                )
                return None
    return None


def _config_changed(rendered: str) -> bool:
    try:
        with open(_LAST_APPLIED_PATH, "r") as f:
            last = f.read().strip()
    except FileNotFoundError:
        return True
    return _hash(rendered) != last


def _save_last_applied(rendered: str) -> None:
    """
    Record the hash of the applied configuration.

    Only the hash is stored. The rendered configuration contains the cluster's
    WireGuard private key, and change detection needs nothing more than a
    comparison, so there is no reason for the key to be on disk here as well as
    in Secrets Manager and in the kernel.
    """
    os.makedirs(os.path.dirname(_LAST_APPLIED_PATH), mode=0o700, exist_ok=True)
    with open(_LAST_APPLIED_PATH, "w") as f:
        f.write(_hash(rendered) + "\n")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ------------------------------------------------------------------------------
# Route reconciliation
# ------------------------------------------------------------------------------


def _reconcile_peer_routes(rendered: str) -> None:
    """
    Bring the ip routes on the mesh interface into line with the peer set.

    Idempotent, and reconciling in both directions: a peer that has just been
    approved needs its route added, and a peer that has been decommissioned
    needs its route removed, or traffic keeps being handed to an interface that
    will no longer carry it.

    The desired set is derived from the rendered configuration's AllowedIPs
    rather than from the peer list, so the routes cannot disagree with what
    WireGuard was actually told.
    """
    desired_v4: set = set()
    desired_v6: set = set()

    in_peer = False
    for line in rendered.splitlines():
        stripped = line.strip()
        if stripped.startswith("[Interface]"):
            in_peer = False
            continue
        if stripped.startswith("[Peer]"):
            in_peer = True
            continue
        if not in_peer or not stripped.startswith("AllowedIPs"):
            continue
        _, _, value = stripped.partition("=")
        for cidr in (candidate.strip() for candidate in value.split(",")):
            if not cidr:
                continue
            (desired_v6 if ":" in cidr else desired_v4).add(cidr)

    for family, desired in (("-4", desired_v4), ("-6", desired_v6)):
        current = _list_managed_routes(family)
        if current is None:
            # The listing failed, so what is on the interface is unknown. Adding
            # would be harmless but removing would not: acting on an unknown as
            # though it were empty is what silently stopped stale routes being
            # removed. Skip the family and let the next cycle try again.
            logger.warning(
                "skipping %s route reconciliation this cycle: the current routes "
                "on %s could not be read",
                family,
                INTERFACE_NAME,
            )
            continue
        for cidr in sorted(desired - current):
            result = subprocess.run(
                ["ip", family, "route", "add", cidr, "dev", INTERFACE_NAME],
                capture_output=True,
            )
            # An existing route is the desired end state, so treat it as success.
            if result.returncode != 0 and b"File exists" not in result.stderr:
                logger.warning(
                    "ip %s route add %s dev %s failed (rc=%d): %s",
                    family, cidr, INTERFACE_NAME, result.returncode,
                    result.stderr.decode(errors="replace").strip(),
                )
            else:
                logger.info("added route %s dev %s", cidr, INTERFACE_NAME)
        for cidr in sorted(current - desired):
            result = subprocess.run(
                ["ip", family, "route", "del", cidr, "dev", INTERFACE_NAME],
                capture_output=True,
            )
            if result.returncode != 0:
                logger.warning(
                    "ip %s route del %s dev %s failed (rc=%d): %s",
                    family, cidr, INTERFACE_NAME, result.returncode,
                    result.stderr.decode(errors="replace").strip(),
                )
            else:
                logger.info("removed stale route %s dev %s", cidr, INTERFACE_NAME)


def _list_managed_routes(family: str) -> Optional[set]:
    """
    Return the CIDRs on the mesh interface that this daemon owns, or None.

    Kernel-installed routes are excluded. The kernel adds a route for the
    interface's own address as a side effect of configuring it, and deleting
    that would break this cluster's own overlay addressing, so the "proto
    kernel" marker is what separates our routes from the kernel's.

    None means the listing FAILED, which is not the same as the interface having
    no routes. The return code used to be ignored, so a non-zero exit with empty
    stdout, which is what happens before ensure-interface.sh has brought the link
    up, was read as an empty set: `current - desired` was then empty and no stale
    route was ever removed, while the cycle reported a successful reconcile. The
    caller skips that family rather than acting on an unknown.
    """
    result = subprocess.run(
        ["ip", family, "route", "show", "dev", INTERFACE_NAME],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.warning(
            "ip %s route show dev %s failed (rc=%d): %s",
            family,
            INTERFACE_NAME,
            result.returncode,
            (result.stderr or "").strip(),
        )
        return None
    routes: set = set()
    for line in result.stdout.splitlines():
        if not line.strip() or "proto kernel" in line:
            continue
        cidr = line.split(None, 1)[0]
        if cidr:
            routes.add(cidr)
    return routes
