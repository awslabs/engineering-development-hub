# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import sys
from datetime import datetime
from datetime import timezone

from utils.datamodels.soca_node import (
    SocaNode,
)
from utils.datamodels.hpc.shared.scheduler_node_resources import SocaSchedulerNodeState
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider
from utils.cast import SocaCastEngine
from utils.validators import Validators
from utils.hpc.job_identity import capacity_key

# Providers whose manager consumes `reclaim_idle_scheduler_nodes`, i.e. can
# terminate one idle node and leave its stack up. Only PBS implements it, via
# SocaSchedulerPBSNodesManager.terminate_node_capacity.
#
# This function is scheduler-agnostic, so without this gate it would emit the
# action, and an INFO line announcing the reclaim, on every provider -- while
# lsf.py and slurm.py silently drop the action. The idle instances would keep
# running and billing behind a log that said they had been reclaimed.
#
# Adding a provider here requires giving its manager a terminate_node_capacity
# equivalent AND a consumer for the action; the log is derived from this set,
# so it cannot drift from what the managers actually do.
_PROVIDERS_WITH_PER_NODE_RECLAIM = frozenset(
    {
        SocaHpcSchedulerProvider.OPENPBS,
        SocaHpcSchedulerProvider.PBSPRO,
    }
)

logger = logging.getLogger("soca_logger")


def sync_scheduler_config(
    scheduler_registered_nodes: list[SocaHpcPBSNode],
    provisioned_ec2_nodes: list[SocaNode],
    jobs_in_queues: list[SocaHpcJobPBS | SocaHpcJobLSF],
    unparseable_scheduler_nodes: list[dict] | None = None,
) -> dict:
    # This functions must be called from the relevant utils.hpc.schedulers_managers scheduler class:
    # - SocaSchedulerPBSNodesManager

    logger.debug(f"Registered nodes on scheduler {scheduler_registered_nodes}")
    logger.debug(f"Jobs in Queues: {jobs_in_queues}")
    logger.debug(
        f"Provisioned EC2 Nodes including KeepForever instances: {provisioned_ec2_nodes}"
    )

    _unparseable_scheduler_nodes = unparseable_scheduler_nodes or []
    if _unparseable_scheduler_nodes:
        logger.error(
            f"{len(_unparseable_scheduler_nodes)} registered node(s) could not be parsed into a node model: {_unparseable_scheduler_nodes}"
        )

    _scheduler_sync_actions = {
        "register_soca_nodes_to_scheduler": [],
        "deregister_scheduler_nodes_no_associated_ec2_capacity": [],
        "deregister_scheduler_nodes_finished_jobs": [],
        # Stacks whose every node is idle, as ONE entry per stack:
        #   {"stack_id": str, "nodes": [node, ...]}
        #
        # Per stack, not per node, because the consumer deletes a
        # CloudFormation stack. The previous shape was a flat node list, which
        # left every consumer looping nodes and issuing one DeleteStack per
        # node of the same stack -- and was the reason one idle node could
        # delete a stack its busy siblings were still using.
        "delete_idle_capacity_per_stack": [],
        # Individually idle nodes to drain and terminate, leaving their stack
        # and its busy siblings in place. A flat node list is right here: the
        # unit of work really is one node.
        "reclaim_idle_scheduler_nodes": [],
        "deregister_unparseable_scheduler_nodes": [],
    }

    # Compare capacity keys, not raw job ids. A scheduler node's job_id is read
    # from its edh:JobId tag, which carries the capacity_key spelling ("4-7" for
    # subjob "4[7]"), while qstat reports the raw id. See utils.hpc.job_identity.
    # Hoisted out of the finished-jobs block below because the unparseable-node
    # path applies the same test.
    _active_job_ids = [
        capacity_key(job.job_id).get("message") for job in jobs_in_queues
    ]

    if not provisioned_ec2_nodes:
        try:
            # Begin - De-register all nodes since there is no provisioned EC2 capacity
            logger.info("No EC2 nodes provisioned for this scheduler")
            if scheduler_registered_nodes:
                logger.debug(
                    "Removing all registered nodes since there is no associated EC2 capacity"
                )
                for _scheduler_node in scheduler_registered_nodes:
                    _scheduler_sync_actions.get(
                        "deregister_scheduler_nodes_no_associated_ec2_capacity"
                    ).append(_scheduler_node)
            # Same reasoning for a node no model could be built for: with no EC2
            # capacity at all there is nothing its registration can be protecting.
            for _unparseable_node in _unparseable_scheduler_nodes:
                if _unparseable_node.get("pbs_mom"):
                    _scheduler_sync_actions.get(
                        "deregister_unparseable_scheduler_nodes"
                    ).append(_unparseable_node)
        except Exception as err:
            logger.error(
                f"Error while building deregister_scheduler_nodes_no_associated_ec2_capacity because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End - De-register all nodes since there is no provisioned EC2 capacity
    else:

        # Begin: Find AlwaysOn hosts
        _alwayson_scheduler_nodes = [
            _scheduler_node
            for _scheduler_node in scheduler_registered_nodes
            if _scheduler_node.keep_forever is True
            and _scheduler_node.terminate_when_idle == 0
        ]
        for _alwayson_host in _alwayson_scheduler_nodes:
            logger.info(
                f"Found AlwaysOn EC2 nodes: {_alwayson_host} with no terminate_when_idle configured. This host can only be removed manually via socactl"
            )

        # End: Find alwayson host and output debug info message for troubleshooting purpose

        # Begin: Register EC2 nodes to the scheduler
        try:
            _scheduler_nodes_registered_mapped_by_instance_id = {
                sched_node.instance_id: sched_node
                for sched_node in scheduler_registered_nodes
            }

            # An unparseable node is registered in the scheduler even though no
            # model exists for it, so its instance must appear in this map.
            _unparseable_instance_ids = {
                _node.get("instance_id")
                for _node in _unparseable_scheduler_nodes
                if _node.get("instance_id")
            }

            _missing_ec2_nodes_to_register = [
                soca_node
                for soca_node in provisioned_ec2_nodes
                if soca_node.instance_id
                not in _scheduler_nodes_registered_mapped_by_instance_id
                and soca_node.instance_id not in _unparseable_instance_ids
            ]

            logger.debug(
                f"Missing EC2 nodes to register: {_missing_ec2_nodes_to_register}"
            )
            if _missing_ec2_nodes_to_register:
                for _ec2_node in _missing_ec2_nodes_to_register:
                    _scheduler_sync_actions.get(
                        "register_soca_nodes_to_scheduler"
                    ).append(_ec2_node)
            else:
                logger.debug("No missing EC2 nodes to register")
        except Exception as err:
            logger.error(
                f"Error while building register_soca_nodes_to_scheduler because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End: Register EC2 nodes to PBS

        # Begin: De-register EC2 Always-On nodes assigned to finished jobs
        try:
            _scheduler_nodes_assigned_to_finished_jobs = [
                _scheduler_node
                for _scheduler_node in scheduler_registered_nodes
                if capacity_key(_scheduler_node.job_id).get("message")
                not in _active_job_ids
                and _scheduler_node.keep_forever is False
            ]
            logger.debug(
                f"De-registering EC2 nodes with KeepForever set to False assigned to finished jobs: {_scheduler_nodes_assigned_to_finished_jobs}: {_active_job_ids=}"
            )
            for _scheduler_node in _scheduler_nodes_assigned_to_finished_jobs:
                _scheduler_sync_actions.get(
                    "deregister_scheduler_nodes_finished_jobs"
                ).append(_scheduler_node)
        except Exception as err:
            logger.error(
                f"Error while building deregister_scheduler_nodes_finished_jobs because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End: De-register EC2 nodes assigned to finished jobs

        # Begin: De-Register Nodes assigned to removed EC2 instances, whether it's ondemand or alwayson
        # example: If you remove the EC2 instance manually from the AWS console
        try:
            _scheduler_node_assigned_to_removed_ec2_instance = [
                _sched_node
                for _sched_node in scheduler_registered_nodes
                if _sched_node.instance_id
                not in [soca_node.instance_id for soca_node in provisioned_ec2_nodes]
            ]

            for _scheduler_node in _scheduler_node_assigned_to_removed_ec2_instance:
                logger.debug(
                    f"De-registering {_scheduler_node} since it is not associated to any EC2 instance"
                )
                _scheduler_sync_actions.get(
                    "deregister_scheduler_nodes_no_associated_ec2_capacity"
                ).append(_scheduler_node)
        except Exception as err:
            logger.error(
                f"Error while building deregister_scheduler_nodes_no_associated_ec2_capacity because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End: De-Register PBS Nodes assigned to removed EC2 instance

        # Begin De-Register instance with an expired terminate_when_idle
        #
        # Reclaim is PER NODE, which is what the legacy orchestrator did
        # (orchestrator/legacy/nodes_manager.py, remove_offline_nodes_*): an
        # idle node is drained and its instance terminated while its busy
        # siblings keep running. Waiting for a whole stack to fall idle would
        # keep paying for every node in it until its last job finished.
        #
        # Eligibility is per node: AlwaysOn, an idle timer set, idle now, and
        # idle for longer than its OWN threshold.
        #
        # The outcome is then decided per stack, because there are two ways to
        # reclaim and they are not interchangeable:
        #
        #   every node eligible  -> delete the CloudFormation stack, which
        #                           takes its instances with it. One API call
        #                           instead of N, and it leaves no empty stack
        #                           behind. Requires a COMPLETE view (see
        #                           below), since deleting a stack while a
        #                           sibling is still booting would take that
        #                           sibling too.
        #   some nodes eligible  -> terminate just those instances and leave
        #                           the stack alone. Safe on an incomplete
        #                           view: a node that is idle past its own
        #                           threshold is reclaimable regardless of
        #                           what else the scheduler cannot see yet.
        #
        # A complete view means every live EC2 instance in the stack is
        # registered with the scheduler. A sibling still booting is absent
        # from scheduler_registered_nodes, so without this check an
        # incomplete view reads as "no other nodes here".
        #
        # Per-node termination is only safe because AlwaysOn capacity is an
        # EC2 Fleet of Type="instant", which does not backfill a terminated
        # instance. Spot capacity (Type="maintain") and capacity-block
        # reservations (ASG) would replace it and churn forever, so
        # create_alwayson refuses an idle timer in combination with those.
        # Lifting that restriction needs a capacity-reduction path that does
        # not exist outside legacy/ yet.
        try:
            _now_epoch = int(datetime.now(timezone.utc).timestamp())

            # Live instance IDS per stack, not just a count: the count reveals an
            # unregistered sibling, and the ids let a per-node reclaim confirm the
            # instance it is about to terminate actually exists. A registered node
            # with no live instance belongs to the no-associated-capacity path,
            # which removes it; terminating from here would duplicate that with an
            # instance id EC2 does not have.
            _ec2_ids_per_stack = {}
            for _ec2_node in provisioned_ec2_nodes:
                if not _ec2_node.stack_id:
                    continue
                if _ec2_node.instance_state_name not in ("running", "pending"):
                    continue
                _ec2_ids_per_stack.setdefault(_ec2_node.stack_id, set()).add(
                    _ec2_node.instance_id
                )

            # A node with no stack id is skipped rather than grouped: grouping
            # them would treat unrelated nodes as one stack.
            _registered_per_stack = {}
            for _sched_node in scheduler_registered_nodes:
                if not _sched_node.stack_id:
                    continue
                _registered_per_stack.setdefault(_sched_node.stack_id, []).append(
                    _sched_node
                )

            logger.debug(
                "Checking AlwaysOn nodes idle past their own terminate_when_idle"
            )
            for _stack_id, _stack_nodes in _registered_per_stack.items():
                if not any(
                    _node.keep_forever is True and _node.terminate_when_idle > 0
                    for _node in _stack_nodes
                ):
                    continue

                _live_ec2_ids = _ec2_ids_per_stack.get(_stack_id, set())
                _eligible = []
                _idle_minutes = []
                for _node in _stack_nodes:
                    if _node.keep_forever is not True or _node.terminate_when_idle <= 0:
                        logger.debug(
                            "Keeping %s: no idle timer, so it is reclaimed only "
                            "when its stack is deleted",
                            _node.instance_id,
                        )
                        continue
                    if _node.node_state != SocaSchedulerNodeState.IDLE:
                        # .value, not the member: SocaSchedulerNodeState subclasses
                        # str but Enum.__str__ still wins, so an f-string of the
                        # member renders "SocaSchedulerNodeState.ACTIVE" in an
                        # operator-facing log line instead of "active".
                        logger.debug(
                            "Keeping %s: it is %s, not idle",
                            _node.instance_id,
                            _node.node_state.value,
                        )
                        continue
                    # Through the cast engine, not a bare int(): this value is
                    # read off a scheduler payload, so it is exactly the
                    # untrusted-input case the cast engine exists for -- and it
                    # matches how is_dependency_casualty() converts the substate
                    # it reads from the same source.
                    _cast = SocaCastEngine(
                        data=_node.last_state_change_timestamp
                    ).cast_as(int)
                    if _cast.get("success") is not True:
                        # Kept, not reclaimed: without a readable timestamp
                        # there is no evidence it has been idle at all, and
                        # guessing in the reclaim direction terminates a node
                        # that might be seconds old.
                        logger.warning(
                            "Keeping %s: unreadable last_state_change_timestamp %r",
                            _node.instance_id,
                            _node.last_state_change_timestamp,
                        )
                        continue
                    _idle_seconds = _now_epoch - _cast.get("message")
                    if _idle_seconds <= _node.terminate_when_idle * 60:
                        logger.debug(
                            "Keeping %s: idle %.1f of its %s minutes",
                            _node.instance_id,
                            _idle_seconds / 60,
                            _node.terminate_when_idle,
                        )
                        continue
                    if _node.instance_id not in _live_ec2_ids:
                        logger.debug(
                            "Keeping %s: idle past its threshold but no live EC2 "
                            "instance for it, so the no-associated-capacity path "
                            "owns this node",
                            _node.instance_id,
                        )
                        continue
                    _eligible.append(_node)
                    _idle_minutes.append(_idle_seconds / 60)

                if not _eligible:
                    continue

                _idle_summary = ", ".join(f"{_m:.1f}" for _m in _idle_minutes)
                _live_ec2 = len(_live_ec2_ids)
                # Both halves compare a count against the stack's node list, so
                # both go through the same Validators length helper: every node
                # is eligible, AND every live instance is registered.
                _whole_stack = Validators.is_list_length_equal_of(
                    _stack_nodes, len(_eligible)
                ) and Validators.is_list_length_equal_of(_stack_nodes, _live_ec2)

                # INFO on both paths, not debug: each one terminates instances
                # an operator is paying for. Someone asking why capacity
                # disappeared should find the reason in the ordinary log rather
                # than having to enable debug and wait for it to recur. The
                # per-node "Keeping ..." lines above stay at debug because they
                # run every minute for every node.
                if _whole_stack:
                    logger.info(
                        f"De-registering all {len(_stack_nodes)} node(s) of {_stack_id} and "
                        f"deleting its capacity: every node is idle past its "
                        f"terminate_when_idle (idle minutes: {_idle_summary})"
                    )
                    _scheduler_sync_actions.get(
                        "delete_idle_capacity_per_stack"
                    ).append({"stack_id": _stack_id, "nodes": _eligible})
                else:
                    # Either a sibling is still working, or the scheduler's view
                    # of this stack is incomplete. Both mean the stack has to
                    # survive, so the idle instances are terminated on their own.
                    if len(_eligible) == len(_stack_nodes):
                        _why = (
                            f"{_live_ec2} live EC2 instance(s) against "
                            f"{len(_stack_nodes)} registered node(s), so a sibling is "
                            f"not registered yet and the stack must survive"
                        )
                    else:
                        _why = (
                            f"{len(_stack_nodes) - len(_eligible)} of "
                            f"{len(_stack_nodes)} node(s) still in use"
                        )

                    _provider = _stack_nodes[0].scheduler_info.provider
                    if _provider not in _PROVIDERS_WITH_PER_NODE_RECLAIM:
                        # Say nothing was reclaimed, because nothing will be:
                        # this provider's manager does not consume the action.
                        # Debug, not info -- it recurs every sync for as long as
                        # the stack has a node in use.
                        logger.debug(
                            "Not reclaiming %s idle node(s) of %s: %s does not "
                            "implement per-node reclaim, so the stack is only "
                            "released once every node in it is idle (%s)",
                            len(_eligible),
                            _stack_id,
                            _provider.value,
                            _why,
                        )
                        continue

                    logger.info(
                        f"Reclaiming {len(_eligible)} idle node(s) of {_stack_id} "
                        f"individually, leaving the stack in place: {_why} "
                        f"(idle minutes: {_idle_summary})"
                    )
                    for _node in _eligible:
                        _scheduler_sync_actions.get(
                            "reclaim_idle_scheduler_nodes"
                        ).append(_node)

        except Exception as err:
            logger.error(
                f"Error while building the idle-capacity actions because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End De-Register KeepForever instance with custom terminate_when_idle

        # Begin: Reclaim unparseable nodes whose job has left the queue
        #
        # Deliberately narrow. The only unparseable node reclaimed here is one
        # where the raw compute_node value is still READABLE and its job is no
        # longer in any queue -- the same test the finished-jobs path applies,
        # just read off the pbsnodes payload instead of a model. Every other
        # unparseable node is reported and left alone, because a validator that
        # rejects a field unrelated to job identity would otherwise let this path
        # delete capacity out from under a running job.
        try:
            for _unparseable_node in _unparseable_scheduler_nodes:
                _raw_compute_node = _unparseable_node.get("compute_node")
                if not _raw_compute_node:
                    logger.error(
                        f"Unparseable node {_unparseable_node.get('node_name')} has no readable compute_node, so whether its job is still queued cannot be determined. Left in place -- it will keep its EC2 capacity until an operator removes it"
                    )
                    continue

                if _unparseable_node.get("keep_forever") is True:
                    logger.error(
                        f"Unparseable node {_unparseable_node.get('node_name')} is keep_forever, left in place"
                    )
                    continue

                if (
                    capacity_key(str(_raw_compute_node)).get("message")
                    in _active_job_ids
                ):
                    logger.error(
                        f"Unparseable node {_unparseable_node.get('node_name')} belongs to queued job {_raw_compute_node}, left in place. Its subjobs cannot be scheduled while it is unparseable"
                    )
                    continue

                if not _unparseable_node.get("pbs_mom"):
                    logger.error(
                        f"Unparseable node {_unparseable_node.get('node_name')} has no readable Mom, so it cannot be deregistered. Left in place"
                    )
                    continue

                logger.error(
                    f"Reclaiming unparseable node {_unparseable_node.get('node_name')}: its job {_raw_compute_node} is no longer queued"
                )
                _scheduler_sync_actions.get(
                    "deregister_unparseable_scheduler_nodes"
                ).append(_unparseable_node)
        except Exception as err:
            logger.error(
                f"Error while building deregister_unparseable_scheduler_nodes because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End: Reclaim unparseable nodes whose job has left the queue

    logger.debug(f"Sync actions: {_scheduler_sync_actions}")
    return _scheduler_sync_actions
