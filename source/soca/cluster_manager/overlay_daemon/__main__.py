######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Command-line entry point for the overlay daemon.

Two subcommands:

  bootstrap   Register this cluster in the mesh once. Run by the controller
              install, which fails if this fails.
  serve       Run the reconcile loop. Run as a systemd unit.

Identity is passed in on the command line rather than read back out of
configuration. The installer already knows the cluster's id, region, account and
endpoint at the point it invokes this, so re-reading them through a
configuration cache would add a staleness question to answer nothing.

The two subcommands handle failure in opposite ways, deliberately. Bootstrap
fails loudly: it decides whether this cluster creates or joins a mesh, and
guessing when the answer is unavailable risks two clusters each creating one.
The serve loop does the opposite and keeps going, because it is reconciling a
desired state that has not changed just because one poll failed, and a daemon
that exits on a transient DynamoDB error takes the tunnel down with it.
"""

from __future__ import annotations
import argparse
import logging
import os
import signal
import sys
import time
import uuid
from typing import Iterable, List, Optional

from . import __version__, bootstrap as bootstrap_mod, ddb_client, hosts_writer, schema, wg_config
from .models import (
    AuditEvent,
    HealthObservation,
    FenceOperation,
    Health,
    Lifecycle,
    Peer,
    ProposalState,
    new_event_id,
)

logger = logging.getLogger("soca_logger")

DEFAULT_SYNC_INTERVAL_SECONDS = 30
METRIC_NAMESPACE = "MeshControlPlane"

# Set by the signal handlers so the loop finishes its current cycle and stops at
# a clean point rather than being interrupted mid-apply.
_stop_requested = False


def _request_stop(signum, _frame) -> None:
    global _stop_requested
    _stop_requested = True
    logger.info("received signal %s; stopping after the current cycle", signum)


# ------------------------------------------------------------------------------
# bootstrap
# ------------------------------------------------------------------------------


def cmd_bootstrap(args: argparse.Namespace) -> int:
    """
    Register this cluster in the mesh. Returns a process exit code.

    Any BootstrapError becomes a non-zero exit so the install records a failure
    rather than leaving a controller that believes it is meshed when it is not.
    """
    ddb_client.configure(
        mesh_role_arn=args.mesh_role_arn,
        external_id=args.mesh_role_external_id,
        region=args.region,
    )

    try:
        peer = bootstrap_mod.bootstrap(
            mesh_id=args.mesh_id,
            cluster_id=args.cluster_id,
            cluster_name=args.cluster_name,
            region=args.region,
            account_id=args.account_id,
            endpoint=args.endpoint,
            private_key_secret_arn=args.private_key_secret_arn,
            iam_principal=args.iam_principal,
            key_rotation_days=args.key_rotation_days,
            auto_decommission_days=args.auto_decommission_days,
            decommission_to_tombstone_days=args.decommission_to_tombstone_days,
        )
    except bootstrap_mod.BootstrapError as e:
        logger.error("bootstrap failed: %s", e)
        return 1
    except Exception:
        # The boundary invariant: NOTHING escapes this call as a traceback.
        #
        # Four review rounds each found the same shape, a translation applied to
        # the sites I could enumerate and missing the ones I could not: reads but
        # not writes, DDBQueryError but not DDBConditionFailedError, neither the
        # wg subprocess calls nor a bare KeyError from a secret with no value.
        # Enumerating raisable types cannot be finished from the inside, so the
        # contract is enforced here instead, where it is one branch: this step is
        # documented to fail the install with an operator-facing message and a
        # non-zero exit, and that is now true whatever any inner path raises.
        #
        # The per-site translations in bootstrap.py are still worth having,
        # because a BootstrapError carries a message written for the operator
        # while this branch can only say which step failed. They are no longer
        # what makes the contract hold.
        logger.exception(
            "bootstrap failed with an unexpected error. The cluster may be "
            "partially registered in mesh %s; inspect it before retrying.",
            args.mesh_id,
        )
        return 1

    logger.info(
        "registered cluster %s in mesh %s: site_seq=%d lifecycle=%s",
        peer.cluster_id,
        peer.mesh_id,
        peer.site_seq,
        peer.lifecycle.value,
    )

    if args.wait_for_approval > 0 and peer.lifecycle is Lifecycle.PENDING:
        _wait_for_approval(
            mesh_id=args.mesh_id,
            cluster_id=args.cluster_id,
            timeout_seconds=args.wait_for_approval,
        )

    return 0


def _wait_for_approval(*, mesh_id: str, cluster_id: str, timeout_seconds: int) -> None:
    """
    Wait briefly for an administrator to approve this cluster.

    Cosmetic by design, which is why it never fails the install. A cluster left
    PENDING is not broken: it is registered, and the serve loop brings its
    tunnel up within one sync interval of approval whenever that happens. This
    only buys a nicer install transcript when the approval is quick.
    """
    deadline = time.monotonic() + timeout_seconds
    logger.info(
        "waiting up to %ds for %s to be approved", timeout_seconds, cluster_id
    )
    while time.monotonic() < deadline:
        time.sleep(min(5, max(1, timeout_seconds // 10)))
        try:
            peers, _meta = ddb_client.query_mesh(mesh_id)
        except Exception as e:
            # Every exception, for the same reason _write_heartbeat catches
            # every exception. This function is documented as never failing the
            # install, and it runs AFTER the cluster is already registered, so
            # anything escaping here fails an install whose work is already
            # done. Catching only DDBQueryError left that contract false.
            logger.warning("could not check approval state: %s", e)
            continue
        current = next((p for p in peers if p.cluster_id == cluster_id), None)
        if current is not None and current.lifecycle is Lifecycle.ACTIVE:
            logger.info("cluster %s was approved", cluster_id)
            return
    logger.info(
        "cluster %s is still awaiting approval; the install continues and the "
        "daemon will bring the tunnel up once an administrator approves it in "
        "Admin -> Mesh",
        cluster_id,
    )


# ------------------------------------------------------------------------------
# serve
# ------------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the reconcile loop until stopped."""
    ddb_client.configure(
        mesh_role_arn=args.mesh_role_arn,
        external_id=args.mesh_role_external_id,
        region=args.region,
    )

    if args.emit_metrics:
        schema.set_metric_emitter(
            schema.make_cloudwatch_emitter(
                namespace=METRIC_NAMESPACE,
                cluster_id=args.cluster_id,
                region=args.region,
            )
        )

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    logger.info(
        "serving mesh %s as %s, reconciling every %ds (version %s)",
        args.mesh_id,
        args.cluster_id,
        args.sync_interval,
        __version__,
    )

    while True:
        _run_one_cycle(args)
        if args.once or _stop_requested:
            break
        # Interruptible sleep, so a stop signal is honoured within a second
        # rather than after a whole interval.
        for _ in range(args.sync_interval):
            if _stop_requested:
                break
            time.sleep(1)
        if _stop_requested:
            break

    logger.info("stopped")
    return 0


# When each mesh was last probed, so the probe round is rate-limited independently of
# the sync cycle. Process-local on purpose: it is a rate limit, not state, and losing
# it on a restart costs one extra probe round rather than correctness.
_LAST_PROBE_ROUND: dict = {}


def _run_one_cycle(args: argparse.Namespace) -> bool:
    """
    Reconcile local state against the mesh once. Returns whether it succeeded.

    Every failure here is caught and reported rather than raised. The loop's
    contract is that one bad cycle costs one interval, not the tunnel: the
    WireGuard interface keeps carrying traffic with the peer set it already has
    while this retries.
    """
    peers: List[Peer] = []
    observations: List[HealthObservation] = []
    ok = False
    try:
        peers, _meta = ddb_client.query_mesh(args.mesh_id)
        self_peer = next(
            (p for p in peers if p.cluster_id == args.cluster_id), None
        )
        # Read before the self_peer check, not inside it. The probe round runs whenever
        # there are peers, including when this cluster has no row of its own, and it
        # needs the prior observations to carry each peer's failure streak. Reading
        # only on the render path meant a cluster whose own row was absent probed
        # forever with an empty streak, so no peer could ever reach DEGRADED or
        # UNAVAILABLE and escalation was silently dead for as long as the row was gone.
        observations = _read_observations_once(args)

        if self_peer is None:
            # Not fatal: an administrator can remove a row, and the tunnel
            # should keep running on its existing configuration rather than
            # tearing itself down on one absent read.
            logger.error(
                "cluster %s has no row in mesh %s, so there is nothing to "
                "render from. Leaving the current configuration in place.",
                args.cluster_id,
                args.mesh_id,
            )
        else:
            # Read before rendering, so the tunnel is rendered against the health
            # the mesh currently agrees on. wg_config and hosts_writer have excluded
            # UNAVAILABLE peers since the daemon CR, with wg_config recording that
            # its health map "is empty until the health subsystem exists". This is
            # what fills it, and a read failure falls back to an empty map, which is
            # the previous behaviour: every ACTIVE peer stays configured.
            health_by_cluster = _mesh_health_from(observations, peers=peers)
            _apply_desired_state(
                args,
                self_peer=self_peer,
                peers=peers,
                health_by_cluster=health_by_cluster,
            )
            ok = True
    except ddb_client.DDBQueryError as e:
        logger.error("mesh query failed, retrying next cycle: %s", e)
    except Exception:
        logger.exception("reconcile cycle failed, retrying next cycle")

    # Deliberately after the tunnel work and in its own guard, for the same reason
    # the proposal sweep is: a probe round that fails is repeated next cycle, whereas
    # a tunnel that does not get reconciled stops carrying traffic. It also does not
    # set `ok`, because the heartbeat's flag means the sync succeeded and a failed
    # probe round is not a failed sync.
    if peers:
        try:
            _run_probe_round(args, peers=peers, observations=observations)
        except Exception:
            logger.exception("probe round failed, retrying next cycle")

    # Separate from the probe round above and gated only on its own flag. Escalation
    # decides from what every cluster has observed, so a cluster that does not probe
    # can still evaluate one, and a cluster that does probe should not have to wait for
    # its next probe round to notice a week of unreachability. Its own guard for the
    # usual reason: an escalation that cannot be evaluated is evaluated next cycle,
    # whereas a tunnel that is not reconciled stops carrying traffic. It does not set
    # `ok` either.
    if peers and getattr(args, "auto_decommission_days", None) is not None:
        try:
            _escalate_unreachable_peers(
                args, peers=peers, observations=observations
            )
        except Exception:
            logger.exception("could not evaluate escalations, retrying next cycle")

    # Deliberately after the tunnel work and in its own guard. A proposal that
    # cannot be evaluated this cycle is evaluated next cycle, whereas a tunnel that
    # does not get reconciled stops carrying traffic, so this must never be able to
    # cost the tunnel a cycle. It also does not set `ok`: the heartbeat's ok flag
    # means the sync succeeded, and a proposal sweep that failed is not a sync
    # failure. It is logged instead.
    if peers:
        try:
            _process_quorum_proposals(args, peers=peers)
        except Exception:
            logger.exception(
                "quorum proposal sweep failed, retrying next cycle"
            )

    _write_heartbeat(args, peer_count=len(peers), ok=ok)
    return ok


def _read_observations_once(args: argparse.Namespace) -> List[HealthObservation]:
    """
    The mesh's health rows, read ONCE per cycle and passed to everything that needs
    them.

    Three separate consumers want this data in a cycle where a probe round is due: the
    tunnel's health map, the previous-observation lookup that carries each peer's
    failure streak, and the escalation check. Each reading it independently meant three
    full paginated queries of the whole mesh's health table every cycle, which review
    caught.

    A consequence worth naming: the escalation check therefore evaluates the rows as
    they were BEFORE this round's probes were written, so this cluster's newest
    observation counts towards escalation one cycle later. That is immaterial against a
    threshold measured in days, and the alternative is re-reading the table to gain a
    few seconds of freshness on a decision that needs a week of evidence.

    Never raises. An unreadable table yields no rows, which leaves the tunnel rendered
    for every ACTIVE peer, exactly as before this subsystem existed.
    """
    try:
        return ddb_client.read_health_observations(args.mesh_id)
    except Exception:
        logger.exception(
            "could not read mesh health, so the tunnel is rendered for every active "
            "peer this cycle and no escalation is evaluated"
        )
        return []


def _mesh_health_from(
    observations: Iterable[HealthObservation], *, peers: Iterable[Peer]
) -> dict:
    """
    The mesh's agreed health per cluster.

    A peer is UNAVAILABLE to this cluster only when MIN_CORROBORATING_OBSERVERS
    separate ACTIVE observers say so. One observer is not enough to pull a peer out of
    the tunnel, because that observer may be the partitioned one, and pulling the peer
    would then destroy the tunnel that was working for everyone else.

    `peers` is required rather than optional because the observer filter is what makes
    the corroboration requirement mean anything: decommissioning sets a lifecycle
    rather than deleting a row and nothing reaps `overlay_health`, so without it a
    departed cluster's stale rows corroborate alongside one live observer and remove a
    healthy peer from the tunnel.
    """
    from . import escalation as _escalation

    corroborated = _escalation.unavailable_observers_by_peer(
        observations, active_cluster_ids=_escalation.active_observer_ids(peers)
    )
    return {
        cluster_id: Health.UNAVAILABLE
        for cluster_id, observers in corroborated.items()
        if len(observers) >= _escalation.MIN_CORROBORATING_OBSERVERS
    }


def _run_probe_round(
    args: argparse.Namespace,
    *,
    peers: List[Peer],
    observations: Iterable[HealthObservation],
) -> None:
    """
    Probe every routable peer once and store what was seen.

    Rate-limited independently of the sync cycle. The sync interval is about how fast
    the mesh reacts to a configuration change; the probe interval is about how often
    it is worth spending one subprocess per peer to ask whether a tunnel is up. Tying
    them together would mean a cluster configured to sync every 15 seconds pinging
    every peer four times a minute for no additional information.

    Probing is off when no interval is configured, which is how a caller that does not
    want it avoids paying for it. Each peer is probed and written inside its own guard,
    so one unreachable or unwritable peer costs that peer's observation rather than the
    whole round.

    Escalation deliberately does NOT live here. It ran at the end of this function and
    so inherited both of the early returns above, which meant `--auto-decommission-days`
    on its own did nothing at all and said nothing about it. Escalation reads the
    observations of every cluster in the mesh, not this cluster's probes, so it has no
    reason to wait on this cluster's probe cadence.
    """
    from . import escalation as _escalation, health as _health

    interval = getattr(args, "probe_interval_seconds", None)
    if interval is None:
        return

    now = int(time.time())
    due_at = _LAST_PROBE_ROUND.get(args.mesh_id, 0) + _health.clamp_probe_interval(
        interval
    )
    if now < due_at:
        return
    _LAST_PROBE_ROUND[args.mesh_id] = now

    targets = _health.peers_to_probe(peers, self_cluster_id=args.cluster_id)
    previous = {
        o.observed: o for o in observations if o.observer == args.cluster_id
    }

    for cluster_id, address in targets:
        try:
            result = _health.probe_peer(address)
            observation = _health.next_observation(
                previous=previous.get(cluster_id),
                result=result,
                mesh_id=args.mesh_id,
                observer=args.cluster_id,
                observed=cluster_id,
            )
            ddb_client.put_health_observation(observation)
        except Exception:
            logger.exception(
                "could not probe or record %s this round; other peers are "
                "unaffected",
                cluster_id,
            )



def _escalate_unreachable_peers(
    args: argparse.Namespace,
    *,
    peers: List[Peer],
    observations: Iterable[HealthObservation],
) -> None:
    """
    Raise a decommission PROPOSAL for peers the mesh agrees are gone.

    Not a direct lifecycle write, which is what the reference prototype does from a
    single observer's row. The other clusters vote from their own observations, which
    is the corroboration one observer cannot supply, and a partition isolating this
    cluster can never reach quorum.
    """
    from . import escalation as _escalation, fence as _fence

    open_proposals = ddb_client.read_fence_proposals(args.mesh_id)

    escalations = _escalation.plan_escalation(
        peers=peers,
        observations=observations,
        threshold_seconds=_escalation.unreachable_threshold_seconds(
            args.auto_decommission_days
        ),
    )

    for escalation in escalations:
        if _escalation.already_proposed(escalation, open_proposals):
            continue

        proposal = _fence.create_proposal(
            mesh_id=args.mesh_id,
            proposer=args.cluster_id,
            operation=FenceOperation.DECOMMISSION,
            target=escalation.target,
            reason=escalation.reason,
            metadata={
                "raised_by": "health_escalation",
                "observers": escalation.observers,
                "unreachable_since": escalation.unreachable_since,
            },
        )
        try:
            ddb_client.put_fence_proposal(proposal)
        except ddb_client.DDBConditionFailedError:
            continue
        # Warning, not info: a destructive operation has been proposed without a
        # person asking for it, and that should be visible in the log even though
        # the mesh still has to agree before anything happens.
        logger.warning(
            "proposed decommissioning %s after sustained unreachability: %s",
            escalation.target,
            escalation.reason,
        )
        _audit_escalation(args, proposal=proposal, escalation=escalation)


def _audit_escalation(args: argparse.Namespace, *, proposal, escalation) -> None:
    """Record who raised it and on what evidence. Never fails the round."""
    now_ms = int(time.time() * 1000)
    try:
        ddb_client.append_audit_event(
            AuditEvent(
                mesh_id=args.mesh_id,
                event_id=new_event_id(now_ms, str(uuid.uuid4())),
                action="health_escalation_proposed",
                target_cluster_id=escalation.target,
                actor=f"daemon:{args.cluster_id}",
                reason=escalation.reason,
                ts=now_ms // 1000,
                metadata={
                    "proposal_id": proposal.proposal_id,
                    "observers": escalation.observers,
                    "unreachable_since": escalation.unreachable_since,
                },
                source_cluster_id=args.cluster_id,
            )
        )
    except Exception:
        logger.exception(
            "could not record the audit event for the escalation of %s; the "
            "proposal itself was written",
            escalation.target,
        )


def _process_quorum_proposals(
    args: argparse.Namespace, *, peers: List[Peer]
) -> None:
    """
    Evaluate every open proposal, apply the ones that reached quorum, reap old ones.

    Every daemon in the mesh runs this, which is deliberate: a proposal must still
    resolve when the cluster that raised it is the one being removed, or is simply
    offline. Concurrency is handled at the two writes rather than by electing one
    daemon, because electing one puts the outcome behind that daemon being alive.

    ORDER: apply the operation first, then record the decision. That is the opposite
    of the reference, which recorded COMMITTED and then applied, and whose own
    comment admitted the operation might not have been applied while claiming the
    next cycle would notice. It would not: a committed proposal evaluates to
    "already finalised", so nothing retries and the mesh keeps a decision that never
    took effect. Applying first means a failure between the two steps leaves the
    proposal OPEN, so the next cycle re-evaluates, finds quorum again, sees the peer
    already in the target lifecycle, and records the decision. That heals.
    """
    from . import fence

    for proposal in ddb_client.read_fence_proposals(args.mesh_id):
        # Guarded per proposal, around the WHOLE body rather than around one call
        # inside it. An earlier revision wrapped only the vote read, which review
        # pointed out was asymmetric: `evaluate_proposal` can raise on unexpected
        # stored data, and anything other than the two DDB errors escaping the apply
        # or the transition write would propagate to the single broad guard in
        # `_run_one_cycle` and abandon every proposal after this one. That is exactly
        # the outcome the vote-read guard was added to prevent, so it belongs here
        # where it covers all of them. The narrower excepts inside stay, because they
        # distinguish expected cases that are not failures.
        try:
            _process_one_proposal(args, proposal=proposal, peers=peers)
        except Exception:
            logger.exception(
                "proposal %s could not be processed this cycle, so it is left for "
                "the next one",
                proposal.proposal_id,
            )


def _process_one_proposal(
    args: argparse.Namespace, *, proposal, peers: List[Peer]
) -> None:
    """
    Reap, evaluate, apply and record one proposal. Raises rather than reporting, so
    the caller's per-proposal guard is the single place a failure is contained.
    """
    from . import fence

    if fence.is_reapable(proposal):
        try:
            ddb_client.delete_fence_proposal(args.mesh_id, proposal.proposal_id)
        except ddb_client.DDBQueryError as e:
            logger.warning(
                "could not reap finalised proposal %s: %s",
                proposal.proposal_id,
                e,
            )
        return

    if proposal.state in fence.TERMINAL_STATES:
        return

    try:
        votes = ddb_client.read_fence_votes(args.mesh_id, proposal.proposal_id)
    except ddb_client.DDBBallotIncompleteError as e:
        # Separated from the transient case because retrying will not help: the row is
        # malformed and stays malformed, so this proposal cannot be decided until
        # somebody repairs or cancels it. Logged at error and left alone, which is the
        # right trade against the alternative of deciding a destructive operation on a
        # ballot known to be incomplete.
        logger.error(
            "proposal %s cannot be decided because a vote row is unreadable, and "
            "this will not clear without intervention: %s",
            proposal.proposal_id,
            e,
        )
        return
    except ddb_client.DDBQueryError as e:
        # Guarded per proposal, not for the sweep as a whole. The only other
        # guard is the broad one around this call in _run_one_cycle, so an escape
        # here would abandon every proposal after this one in the list, and one
        # transient read would stall decisions on all of them. The mesh API's
        # list endpoint wraps the same call for the same reason.
        logger.warning(
            "could not read votes for proposal %s, so it is left for the next "
            "cycle: %s",
            proposal.proposal_id,
            e,
        )
        return

    decision = fence.evaluate_proposal(proposal, votes, peers)
    if not decision.is_final:
        return

    if decision.state == ProposalState.COMMITTED:
        if not _apply_quorum_operation(
            args, proposal=proposal, peers=peers
        ):
            # Left OPEN, and this is now only the RETRYABLE case. A target that
            # can never be moved by this operation is decided SUPERSEDED by
            # evaluate_proposal before it ever reaches here, so what arrives is a
            # write that failed or a peer that moved mid-cycle, both of which the
            # next cycle re-reads and re-decides. Warning rather than error for
            # the same reason: it is expected to clear on its own.
            logger.warning(
                "proposal %s reached quorum but its operation could not be "
                "applied this cycle, so it is left open and retried: %s",
                proposal.proposal_id,
                decision.reason,
            )
            return

    try:
        ddb_client.transition_fence_proposal(
            mesh_id=args.mesh_id,
            proposal_id=proposal.proposal_id,
            new_state=decision.state,
            expected_state=proposal.state,
        )
    except ddb_client.DDBConditionFailedError:
        # Another daemon decided it first. Normal, not an error: every daemon
        # evaluates every proposal, so exactly one wins this write and the rest
        # arrive here.
        logger.info(
            "proposal %s was already decided by another cluster",
            proposal.proposal_id,
        )
        return
    except ddb_client.DDBQueryError as e:
        logger.error(
            "could not record the decision on proposal %s: %s",
            proposal.proposal_id,
            e,
        )
        return

    logger.info(
        "proposal %s is now %s: %s",
        proposal.proposal_id,
        decision.state.value,
        decision.reason,
    )
    _audit_proposal_decision(args, proposal=proposal, decision=decision)


def _apply_quorum_operation(
    args: argparse.Namespace, *, proposal, peers: List[Peer]
) -> bool:
    """
    Move the target peer to the lifecycle the operation intends.

    Returns whether the target is now in that lifecycle, which includes the case
    where it already was. Idempotent for that reason: the caller may retry after a
    failure between applying and recording, and a second attempt must not report a
    failure just because the work was already done.

    Refuses an illegal transition. A proposal raised while its target was ACTIVE can
    reach quorum after that peer has moved, and applying regardless would write a
    lifecycle over one the state machine forbids: quorum would become a way around
    the rule the API enforces. The reference applied committed operations with no
    such check.
    """
    target = next((p for p in peers if p.cluster_id == proposal.target), None)
    if target is None:
        logger.error(
            "proposal %s targets %s, which has no row in mesh %s",
            proposal.proposal_id,
            proposal.target,
            args.mesh_id,
        )
        return False

    intended = proposal.operation.target_lifecycle
    if target.lifecycle == intended:
        logger.info(
            "proposal %s: %s is already %s, so there is nothing to apply",
            proposal.proposal_id,
            proposal.target,
            intended.value,
        )
        return True

    if target.lifecycle not in proposal.operation.permitted_from:
        logger.error(
            "proposal %s cannot be applied: %s is %s, and %s is only permitted "
            "from %s",
            proposal.proposal_id,
            proposal.target,
            target.lifecycle.value,
            proposal.operation.value,
            sorted(state.value for state in proposal.operation.permitted_from),
        )
        return False

    try:
        ddb_client.update_peer_lifecycle(
            mesh_id=args.mesh_id,
            cluster_id=proposal.target,
            new_lifecycle=intended,
            actor=f"quorum:{proposal.proposal_id}",
            reason=f"quorum reached on {proposal.operation.value}",
            expected_revision=target.revision,
        )
    except ddb_client.DDBConditionFailedError:
        # The peer moved between the mesh read at the top of this cycle and now.
        # Not applied, and not recorded: the next cycle re-reads and decides again.
        logger.info(
            "proposal %s: %s changed while applying, retrying next cycle",
            proposal.proposal_id,
            proposal.target,
        )
        return False
    except ddb_client.DDBQueryError as e:
        logger.error(
            "proposal %s: could not apply %s to %s: %s",
            proposal.proposal_id,
            proposal.operation.value,
            proposal.target,
            e,
        )
        return False
    return True


def _audit_proposal_decision(
    args: argparse.Namespace, *, proposal, decision
) -> None:
    """
    Record the decision, and never fail the sweep because recording failed.

    The decision is already written by the time this runs, so raising would report a
    failure for something that happened. Same reasoning as the mesh API's audit
    write, and logged at exception level so an audit gap stays discoverable.
    """
    from .models import AuditEvent, new_event_id

    now_ms = int(time.time() * 1000)
    try:
        ddb_client.append_audit_event(
            AuditEvent(
                mesh_id=args.mesh_id,
                event_id=new_event_id(now_ms, str(uuid.uuid4())),
                action=f"quorum_{decision.state.value}",
                target_cluster_id=proposal.target,
                actor=f"quorum:{proposal.proposal_id}",
                reason=decision.reason,
                ts=now_ms // 1000,
                metadata={
                    "proposal_id": proposal.proposal_id,
                    "operation": proposal.operation.value,
                    "proposer": proposal.proposer,
                    "yes": decision.tally.yes,
                    "no": decision.tally.no,
                    "abstain": decision.tally.abstain,
                    "quorum": decision.tally.quorum,
                    "active_peers": decision.tally.active_count,
                    "committed_by_override": proposal.committed_by_override,
                },
                source_cluster_id=args.cluster_id,
            )
        )
    except Exception:
        logger.exception(
            "could not record the audit event for proposal %s; the decision "
            "itself was written",
            proposal.proposal_id,
        )


def _apply_desired_state(
    args: argparse.Namespace,
    *,
    self_peer: Peer,
    peers: List[Peer],
    health_by_cluster: Optional[dict] = None,
) -> None:
    """
    Render and apply the tunnel and the peer hostnames.

    `health_by_cluster` excludes UNAVAILABLE peers, which both renderers have
    supported since the daemon CR while nothing supplied it. An empty or absent map
    keeps every ACTIVE peer configured, which is the behaviour that shipped.
    """
    privkey = ddb_client.read_private_key_secret(args.private_key_secret_arn)
    if not privkey:
        raise RuntimeError(
            f"no WireGuard private key in {args.private_key_secret_arn}; the "
            f"bootstrap subcommand generates it, so this cluster has not "
            f"completed bootstrap"
        )

    rendered = wg_config.render(
        self_peer=self_peer,
        self_privkey=privkey,
        peers=peers,
        health_by_cluster=health_by_cluster,
        listen_port=args.listen_port,
        mtu=args.mtu,
    )
    if wg_config.apply_config(rendered, dry_run=args.dry_run):
        logger.info(
            "applied a new WireGuard configuration (%d routable peers)",
            sum(1 for p in peers if p.is_routable and p.cluster_id != self_peer.cluster_id),
        )

    # Isolated from the tunnel: a hosts-file problem must not stop the mesh
    # carrying traffic, since addresses work whether or not names resolve.
    try:
        if hosts_writer.write_for_peers(
            mesh_id=args.mesh_id,
            peers=peers,
            hosts_path=args.hosts_path,
            health_by_cluster=health_by_cluster,
            dry_run=args.dry_run,
        ):
            logger.info("updated the peer hostnames in %s", args.hosts_path)
    except Exception:
        logger.exception(
            "writing peer hostnames to %s failed; the tunnel is unaffected",
            args.hosts_path,
        )


def _write_heartbeat(args: argparse.Namespace, *, peer_count: int, ok: bool) -> None:
    """
    Record that this cluster completed a cycle, and whether it worked.

    Written even when the cycle failed, because a heartbeat that only appears on
    success cannot distinguish a cluster whose syncs are failing from one that
    has stopped running, and those need different operator responses.
    """
    try:
        ddb_client.write_cluster_state_heartbeat(
            mesh_id=args.mesh_id,
            cluster_id=args.cluster_id,
            last_sync_ts=int(time.time()),
            peer_count=peer_count,
            daemon_version=__version__,
            last_sync_ok=ok,
        )
    except Exception as e:
        # Deliberately every exception, not just DDBQueryError. The heartbeat is
        # observability, and this call is the FIRST thing in a cycle to resolve
        # the cluster_state table name: that is a separate cache entry from
        # overlay_config, so on a cluster whose table prefix cannot be resolved
        # it raises TableNameResolutionError here, which is a RuntimeError and
        # not a DDBQueryError. Catching only the latter let it escape into the
        # serve loop, which has no handler, and killed the daemon over a failure
        # to write a status row.
        logger.warning("could not write the heartbeat: %s", e)


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="edh-overlay-daemon",
        description="Cross-region WireGuard overlay mesh agent.",
    )
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))
    sub = parser.add_subparsers(dest="command", required=True)

    def add_mesh_role_arguments(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--mesh-role-arn",
            default="",
            help=(
                "role to assume before reaching the mesh tables, for a mesh "
                "spanning AWS accounts. Empty means same-account, which issues "
                "no STS calls."
            ),
        )
        target.add_argument(
            "--mesh-role-external-id",
            default="",
            help="ExternalId required by the mesh role's trust policy, if set.",
        )

    boot = sub.add_parser("bootstrap", help="register this cluster in the mesh once")
    boot.add_argument("--mesh-id", required=True)
    boot.add_argument("--cluster-id", required=True)
    boot.add_argument("--cluster-name", required=True)
    boot.add_argument("--region", required=True)
    boot.add_argument("--account-id", required=True)
    boot.add_argument(
        "--endpoint", required=True, help="host:port reachable by mesh peers"
    )
    boot.add_argument("--private-key-secret-arn", required=True)
    boot.add_argument("--iam-principal", required=True)
    boot.add_argument(
        "--key-rotation-days",
        type=int,
        default=bootstrap_mod.DEFAULT_KEY_ROTATION_DAYS,
        help=(
            "mesh-wide WireGuard key rotation cadence, written into the mesh "
            "metadata row. Only the cluster that CREATES the mesh sets it, and "
            "there is no update path yet, so it is passed in rather than "
            "defaulted in the daemon."
        ),
    )
    boot.add_argument(
        "--auto-decommission-days",
        type=int,
        default=bootstrap_mod.DEFAULT_AUTO_DECOMMISSION_DAYS,
        help="mesh-wide days of unreachability before a peer is decommissioned.",
    )
    boot.add_argument(
        "--decommission-to-tombstone-days",
        type=int,
        default=bootstrap_mod.DEFAULT_DECOMMISSION_TO_TOMBSTONE_DAYS,
        help="mesh-wide days from decommissioned to permanently tombstoned.",
    )
    boot.add_argument(
        "--wait-for-approval",
        type=int,
        default=0,
        help=(
            "seconds to wait for an administrator to approve this cluster. "
            "Cosmetic: 0 returns immediately and the serve loop brings the "
            "tunnel up whenever approval arrives."
        ),
    )
    add_mesh_role_arguments(boot)
    boot.set_defaults(func=cmd_bootstrap)

    serve = sub.add_parser("serve", help="run the reconcile loop")
    serve.add_argument("--mesh-id", required=True)
    serve.add_argument("--cluster-id", required=True)
    serve.add_argument("--private-key-secret-arn", required=True)
    serve.add_argument(
        "--region",
        default=os.environ.get("EDH_REGION") or None,
        required=not os.environ.get("EDH_REGION"),
        help=(
            "The region this cluster runs in. Pins every AWS client the daemon "
            "builds, so none of them resolves a region from instance metadata and "
            "reaches one this cluster was never configured for. Required, "
            "defaulting to EDH_REGION when the unit has baked it in: an optional "
            "pin is not a pin, because the None it falls back to is what let a "
            "client resolve its own region."
        ),
    )
    serve.add_argument(
        "--sync-interval", type=int, default=DEFAULT_SYNC_INTERVAL_SECONDS
    )
    serve.add_argument(
        "--probe-interval",
        type=int,
        default=None,
        dest="probe_interval_seconds",
        help=(
            "Seconds between reachability probe rounds. Separate from the sync "
            "interval because syncing is about reacting to configuration changes "
            "and probing costs one subprocess per peer. Omitted means no probing, "
            "which leaves every ACTIVE peer configured in the tunnel as before "
            "this subsystem existed."
        ),
    )
    serve.add_argument(
        "--auto-decommission-days",
        type=int,
        default=None,
        help=(
            "Days a peer must be unreachable, corroborated by at least two other "
            "clusters, before its removal is PROPOSED for the mesh to vote on. "
            "Never decommissions anything directly. Omitted means no automatic "
            "escalation, which is the default because a destructive operation "
            "raised without a person asking should be opted into. Independent of "
            "--probe-interval: this decides from what every cluster has observed, so "
            "it works on a cluster that does not probe at all."
        ),
    )
    serve.add_argument(
        "--listen-port",
        type=int,
        default=wg_config.DEFAULT_LISTEN_PORT,
        help=(
            "UDP port this cluster listens on. Must match the port the mesh "
            "advertises as this peer's endpoint, so it is passed in rather than "
            "defaulted here: the interface script and the advertised endpoint "
            "both take it from configuration."
        ),
    )
    serve.add_argument(
        "--mtu",
        type=int,
        default=wg_config.DEFAULT_MTU,
        help="MTU written into the rendered interface configuration.",
    )
    serve.add_argument(
        "--hosts-path",
        default=hosts_writer.HOSTS_FILE,
        help="hosts file to publish peer names into.",
    )
    serve.add_argument(
        "--emit-metrics",
        action="store_true",
        help="publish schema-compatibility metrics to CloudWatch.",
    )
    serve.add_argument(
        "--dry-run",
        action="store_true",
        help="render and report without applying anything.",
    )
    serve.add_argument(
        "--once",
        action="store_true",
        help="run a single cycle and exit, for diagnosis.",
    )
    add_mesh_role_arguments(serve)
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
