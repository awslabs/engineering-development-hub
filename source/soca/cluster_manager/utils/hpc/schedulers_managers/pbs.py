# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import ValidationError
import logging
import os
import sys
from typing import Optional
from datetime import datetime

from utils.subprocess_client import SocaSubprocessClient
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse

from utils.datamodels.hpc.scheduler import SocaHpcScheduler
from utils.datamodels.hpc.shared.scheduler_node_resources import SocaSchedulerNodeState
import utils.hpc.schedulers_managers.common_sync as common_sync
from utils.datamodels.soca_node import (
    SocaNode,
)
from utils.datamodels.hpc.pbs.node import SocaHpcNodePBS
from utils.aws.cloudformation_client import SocaCfnClient
from utils.aws.boto3_wrapper import get_boto
from utils.hpc.scheduler_command_builder import SocaHpcPBSJobCommandBuilder

logger = logging.getLogger("soca_logger")


class SocaSchedulerPBSNodesManager:

    def __init__(self, scheduler_info: SocaHpcScheduler):

        self._scheduler_info = scheduler_info
        logger.info(
            f"SocaSchedulerPBSNodesManager: About to sync Scheduler: {self._scheduler_info}"
        )

    @staticmethod
    def delete_associated_capacity(stack_name: str) -> SocaResponse:
        logger.info(f"About to delete {stack_name=}")
        _delete_stack_request = SocaCfnClient(stack_name=stack_name).delete_stack(
            ignore_missing_stack=True
        )
        if not _delete_stack_request.get("success"):
            return SocaError.GENERIC_ERROR(
                helper=f"Capacity removed from scheduler but Unable to delete stack {stack_name} due to {_delete_stack_request.get('message')}"
            )
        else:
            return SocaResponse(
                success=True, message=f"{stack_name=} deleted successfully"
            )

    @staticmethod
    def terminate_node_capacity(instance_id: str) -> SocaResponse:
        """
        Terminate ONE instance, leaving its CloudFormation stack in place.

        Used to reclaim an idle AlwaysOn node while its siblings keep running.
        Deleting the stack is not an option there: it would take the siblings
        and their jobs with it.

        Safe because AlwaysOn capacity is an EC2 Fleet of Type="instant",
        which provisions once and does not backfill. A spot fleet
        (Type="maintain") or a capacity-block ASG would replace the instance,
        so create_alwayson refuses an idle timer alongside those rather than
        letting this churn.

        The stack is left holding a fleet resource whose instance is gone.
        That is inert for an instant fleet, and deleting the stack later still
        succeeds: terminating an already-terminated instance is not an error.
        """
        if not instance_id:
            return SocaError.GENERIC_ERROR(
                helper="Unable to terminate capacity: no instance id"
            )

        logger.info(f"About to terminate idle instance {instance_id=}")
        _ec2_client = get_boto(service_name="ec2")
        if not _ec2_client.get("success"):
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get EC2 client to terminate {instance_id} due to {_ec2_client.get('message')}"
            )

        try:
            _ec2_client.get("message").terminate_instances(InstanceIds=[instance_id])
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Capacity removed from scheduler but unable to terminate instance {instance_id} due to {err}"
            )

        return SocaResponse(
            success=True, message=f"{instance_id=} terminated successfully"
        )

    @staticmethod
    def get_pbs_node_mom_attribute(soca_node: SocaNode) -> str:
        # PBS Client Node will be registered via their Private IP\
        # You can change that if needed, but make sure whatever value you select (DNS, IP) must be routable/resolvable by the system
        return soca_node.private_ip_address

    def sync_config(
        self, provisioned_ec2_nodes: list[SocaNode], jobs_in_queues: list[SocaHpcJob]
    ):
        """
        Synchronizes the PBS scheduler configuration with the current state of EC2 nodes and jobs.

        Uses common_sync.sync_scheduler_config to generate synchronization actions by comparing:
        - Currently registered PBS nodes
        - Provisioned EC2 nodes
        - Jobs in queues
        - Scheduler information

        The sync_scheduler_config returns a dictionary with the following structure:
        {
            "register_soca_nodes_to_scheduler": [SocaNode],  # EC2 Nodes to be registered in PBS
            "deregister_scheduler_nodes_no_associated_ec2_capacity": [PbsNode],  # PBS Nodes without associated EC2 instances
            "deregister_scheduler_nodes_finished_jobs": [PbsNode],  # PBS Nodes associated to completed jobs
            "delete_idle_capacity_per_stack": [{"stack_id": str, "nodes": [PbsNode]}]  # one entry per stack whose EVERY node is idle past its terminate_when_idle
            "reclaim_idle_scheduler_nodes": [PbsNode]  # individually idle nodes to drain and terminate, leaving their stack up
            "deregister_unparseable_scheduler_nodes": [dict]  # raw pbsnodes records for nodes no model could be built from, whose job has left the queue
        }

        Each action list is then processed to either register new nodes or deregister existing ones.

        Args:
            provisioned_ec2_nodes (list[SocaNode]): List of currently provisioned EC2 nodes
            jobs_in_queues (list[SocaHpcJob]): List of jobs currently in the PBS queues
        """
        if not (_registered_nodes := self.get_registered_nodes()).get("success"):
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve registered nodes due to {_registered_nodes.get('message')}"
            )

        _nodes_payload = _registered_nodes.get("message")
        _sync_actions = common_sync.sync_scheduler_config(
            scheduler_registered_nodes=_nodes_payload.get("nodes"),
            provisioned_ec2_nodes=provisioned_ec2_nodes,
            jobs_in_queues=jobs_in_queues,
            unparseable_scheduler_nodes=_nodes_payload.get("unparseable_nodes"),
        )

        logger.info(
            f"{self._scheduler_info.identifier}: Received PBS sync actions: {_sync_actions=}"
        )

        _register_soca_nodes_to_scheduler = _sync_actions.get(
            "register_soca_nodes_to_scheduler"
        )
        if _register_soca_nodes_to_scheduler:
            logger.info("Registering missing SocaNodes to PBS configuration")
            for _soca_nodes in _register_soca_nodes_to_scheduler:
                _register_node = self.register_node(soca_node=_soca_nodes)
                if _register_node.get("success") is False:
                    logger.error(
                        f"Unable to register node {_soca_nodes.instance_id} due to {_register_node.get('message')}"
                    )

        _deregister_scheduler_nodes_no_associated_ec2_capacity = _sync_actions.get(
            "deregister_scheduler_nodes_no_associated_ec2_capacity"
        )
        if _deregister_scheduler_nodes_no_associated_ec2_capacity:
            logger.info(
                "De-registering SocaPbsNode without valid associated EC2 capacity from PBS configuration"
            )
            for _pbs_nodes in _deregister_scheduler_nodes_no_associated_ec2_capacity:
                _deregister_node = self.deregister_node(pbs_node=_pbs_nodes)
                if _deregister_node.get("success") is False:
                    logger.error(
                        f"Unable to deregister node {_pbs_nodes.instance_id} due to {_deregister_node.get('message')}"
                    )
                else:
                    _delete_associated_capacity = self.delete_associated_capacity(
                        stack_name=_pbs_nodes.stack_id
                    )
                    if _delete_associated_capacity.get("success") is False:
                        logger.error(
                            f"Unable to delete associated capacity {_pbs_nodes.stack_id} due to {_delete_associated_capacity.get('message')}"
                        )
                    else:
                        logger.info(
                            f"Associated capacity {_pbs_nodes.stack_id} deleted successfully"
                        )

        _deregister_scheduler_nodes_finished_jobs = _sync_actions.get(
            "deregister_scheduler_nodes_finished_jobs"
        )
        if _deregister_scheduler_nodes_finished_jobs:
            logger.info(
                "De-registering SocaPbsNode + delete cloudformation_capacity assigned to finished jobs from PBS configuration"
            )
            for _pbs_nodes in _deregister_scheduler_nodes_finished_jobs:
                _deregister_node = self.deregister_node(pbs_node=_pbs_nodes)
                if _deregister_node.get("success") is False:
                    logger.error(
                        f"Unable to deregister node {_pbs_nodes.instance_id} due to {_deregister_node.get('message')}"
                    )
                else:
                    _delete_associated_capacity = self.delete_associated_capacity(
                        stack_name=_pbs_nodes.stack_id
                    )
                    if _delete_associated_capacity.get("success") is False:
                        logger.error(
                            f"Unable to delete associated capacity {_pbs_nodes.stack_id} due to {_delete_associated_capacity.get('message')}"
                        )
                    else:
                        logger.info(
                            f"Associated capacity {_pbs_nodes.stack_id} deleted successfully"
                        )

        _delete_idle_capacity_per_stack = _sync_actions.get(
            "delete_idle_capacity_per_stack"
        )
        if _delete_idle_capacity_per_stack:
            logger.info(
                "De-registering SocaPbsNode + delete cloudformation_capacity with expired terminate_when_idle flag"
            )
            for _entry in _delete_idle_capacity_per_stack:
                _stack_id = _entry.get("stack_id")
                for _pbs_node in _entry.get("nodes", []):
                    _deregister_node = self.deregister_node(pbs_node=_pbs_node)
                    if _deregister_node.get("success") is False:
                        # Logged and carried on rather than skipping the delete.
                        # The stack is going either way, so stopping here would
                        # leave capacity running that nothing is going to use. A
                        # node left registered against a terminated instance is
                        # picked up by the no-associated-capacity path.
                        logger.error(
                            f"Unable to deregister node {_pbs_node.instance_id} due to {_deregister_node.get('message')}, "
                            f"continuing to delete {_stack_id} anyway"
                        )

                # Once per stack, not once per node.
                _delete_associated_capacity = self.delete_associated_capacity(
                    stack_name=_stack_id
                )
                if _delete_associated_capacity.get("success") is False:
                    logger.error(
                        f"Unable to delete associated capacity {_stack_id} due to {_delete_associated_capacity.get('message')}"
                    )
                else:
                    logger.info(
                        f"Associated capacity {_stack_id} deleted successfully"
                    )

        _reclaim_idle_scheduler_nodes = _sync_actions.get("reclaim_idle_scheduler_nodes")
        if _reclaim_idle_scheduler_nodes:
            logger.info(
                "De-registering SocaPbsNode + terminating the instance for idle nodes "
                "whose stack must survive because a sibling is still in use"
            )
            for _pbs_node in _reclaim_idle_scheduler_nodes:
                _deregister_node = self.deregister_node(pbs_node=_pbs_node)
                if _deregister_node.get("success") is False:
                    # Not terminated: an instance whose node is still registered
                    # would keep being offered work it can no longer run.
                    logger.error(
                        f"Unable to deregister node {_pbs_node.instance_id} due to {_deregister_node.get('message')}, "
                        f"leaving its instance running"
                    )
                    continue
                _terminate = self.terminate_node_capacity(
                    instance_id=_pbs_node.instance_id
                )
                if _terminate.get("success") is False:
                    logger.error(
                        f"Unable to terminate idle instance {_pbs_node.instance_id} due to {_terminate.get('message')}"
                    )
                else:
                    logger.info(
                        f"Idle instance {_pbs_node.instance_id} of {_pbs_node.stack_id} terminated successfully"
                    )

        _deregister_unparseable_scheduler_nodes = _sync_actions.get(
            "deregister_unparseable_scheduler_nodes"
        )
        if _deregister_unparseable_scheduler_nodes:
            logger.error(
                "De-registering nodes that could not be parsed into a node model and whose job has left the queue"
            )
            # Addressed with plain strings read off the pbsnodes payload, because
            # building the node model is exactly what failed for these.
            for _unparseable_node in _deregister_unparseable_scheduler_nodes:
                _deregister_node = self.deregister_node(
                    pbs_mom=_unparseable_node.get("pbs_mom")
                )
                if _deregister_node.get("success") is False:
                    logger.error(
                        f"Unable to deregister unparseable node {_unparseable_node.get('node_name')} due to {_deregister_node.get('message')}"
                    )
                    continue

                _stack_id = _unparseable_node.get("stack_id")
                if not _stack_id:
                    logger.error(
                        f"Unparseable node {_unparseable_node.get('node_name')} deregistered but it has no readable stack_id, so its EC2 capacity cannot be deleted from here. Instance {_unparseable_node.get('instance_id')} needs an operator"
                    )
                    continue

                _delete_associated_capacity = self.delete_associated_capacity(
                    stack_name=_stack_id
                )
                if _delete_associated_capacity.get("success") is False:
                    logger.error(
                        f"Unable to delete associated capacity {_stack_id} due to {_delete_associated_capacity.get('message')}"
                    )
                else:
                    logger.info(
                        f"Associated capacity {_stack_id} deleted successfully"
                    )

    def get_registered_nodes(
        self,
    ):
        logger.info("Retrieving all PBS nodes registered in the scheduler")

        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self._scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self._scheduler_info.binary_folder_paths}:{_current_path}"
            )

        _run_command = SocaHpcPBSJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).pbsnodes(f"-q -a -F json -s {self._scheduler_info.endpoint}")

        # Note: pbsnodes will return 1 if there is no nodes registered
        _nodes_data = SocaSubprocessClient(run_command=_run_command).run(
            env=_current_env, non_fatal_rcs=[0, 1]
        )

        _registered_nodes_on_scheduler = []
        # Nodes pbsnodes reported that could not be turned into a SocaHpcNodePBS.
        _unparseable_nodes_on_scheduler = []

        if _nodes_data.get("success"):
            if _nodes_data.get("message").get("returncode") == 1:
                logger.info(
                    f"Scheduler {self._scheduler_info.identifier} does not have any nodes registered"
                )
            else:
                _get_output_as_json = SocaCastEngine(
                    data=_nodes_data.get("message").get("stdout")
                ).as_json()

                if _get_output_as_json.get("success") is False:
                    logger.error(
                        f"Unable to parse pbsnodes output due to {_get_output_as_json.get('message')}"
                    )
                    return SocaError.GENERIC_ERROR(
                        helper=f"{_run_command} succeeded but output was not a valid json"
                    )

                _pbsnodes_output = _get_output_as_json.get("message")
                logger.debug(
                    f"Received PBS parser with pbsnodes output {_pbsnodes_output}"
                )

                for _node_name, node_info in _pbsnodes_output.get("nodes", {}).items():
                    try:

                        if node_info.get("state") in [
                            "active",
                            "job-busy",
                            "job-exclusive",
                            "job-sharing",
                            "busy",
                            "time-shared",
                        ]:
                            _node_state = SocaSchedulerNodeState.ACTIVE
                        elif node_info.get("state") in ["free", "up"]:
                            _node_state = SocaSchedulerNodeState.IDLE
                        elif node_info.get("state") in [
                            "offline"
                        ] or "down" in node_info.get(
                            "state"
                        ):  # state-unknown,down -> will be flagged as down
                            _node_state = SocaSchedulerNodeState.DOWN
                        else:
                            # "state-unknown"
                            _node_state = SocaSchedulerNodeState.OTHER

                        # last_state_change_time only exist after the first state change
                        # key won't exist during the registration and until the remote pbs_mom is active
                        if node_info.get("last_state_change_time", None) is None:
                            # default to current timestamp
                            _last_state_change_timestamp = int(
                                datetime.now().timestamp()
                            )
                        else:
                            _last_state_change_timestamp = node_info.get(
                                "last_state_change_time"
                            )

                        _node = SocaHpcNodePBS(
                            # required attributes from SocaSchedulerNodeResourceModel
                            job_id=str(
                                node_info.get("resources_available", {}).get(
                                    "compute_node", None
                                )
                            ),  # same as compute_node
                            stack_id=node_info.get("resources_available", {}).get(
                                "stack_id", None
                            ),
                            instance_id=node_info.get("resources_available", {}).get(
                                "instance_id", None
                            ),
                            scheduler_info=self._scheduler_info,
                            keep_forever=(
                                True
                                if node_info.get("resources_available", {})
                                .get("keep_forever", "false")
                                .lower()
                                == "true"
                                else False
                            ),
                            terminate_when_idle=node_info.get(
                                "resources_available", {}
                            ).get("terminate_when_idle", 0),
                            node_state=_node_state,
                            compute_node=node_info.get("resources_available", {}).get(
                                "compute_node", "tbd"
                            ),
                            last_state_change_timestamp=_last_state_change_timestamp,
                            # Required attributes from SocaHpcNodePBS
                            pbs_mom=node_info.get("Mom"),  # note: case sensitive
                            # Optional Attributes from SocaHpcNodePBS
                            pbs_port=node_info.get("Port", None),  # case_sensitive
                            pbs_pbs_version=node_info.get("pbs_version", None),
                            pbs_ntype=node_info.get("ntype", None),
                            pbs_state=node_info.get("state", None),
                            pbs_pcpus=node_info.get("pcpus", None),
                            pbs_jobs=node_info.get("jobs", []),
                            pbs_resources_available=node_info.get(
                                "resources_available", {}
                            ),
                            pbs_resources_assigned=node_info.get(
                                "resources_assigned", {}
                            ),
                            pbs_queue=node_info.get("queue", None),
                            pbs_resv_enable=node_info.get("resv_enable", None),
                            pbs_sharing=node_info.get("sharing", None),
                            pbs_license=node_info.get("license", None),
                            pbs_last_state_change_time=node_info.get(
                                "last_state_change_time", None
                            ),
                        )

                        logger.debug(f"Found {_node} on pbsnodes")
                        _registered_nodes_on_scheduler.append(_node)

                    except ValidationError as ve:
                        # This will give detailed info about what fields failed
                        logger.error(
                            f"Pydantic validation failed for node_info={node_info}: {ve.json()}"
                        )
                        _unparseable_nodes_on_scheduler.append(
                            self.unparseable_node_record(
                                node_name=_node_name,
                                node_info=node_info,
                                error=ve.json(),
                            )
                        )
                        continue

                    except Exception as err:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        # error, not info: a node that cannot be parsed is capacity
                        # EDH is paying for and can no longer see. The generic case
                        # is the one nobody anticipated, so it is the louder of the
                        # two, not the quieter.
                        logger.error(
                            f"Unable to parse PBS node {_node_name} {node_info=} due to {err} on line {exc_tb.tb_lineno}, skipping"
                        )
                        _unparseable_nodes_on_scheduler.append(
                            self.unparseable_node_record(
                                node_name=_node_name,
                                node_info=node_info,
                                error=str(err),
                            )
                        )
                        continue

            if _unparseable_nodes_on_scheduler:
                logger.error(
                    f"{len(_unparseable_nodes_on_scheduler)} node(s) registered in the scheduler could not be parsed and are excluded from node management: {[_n.get('node_name') for _n in _unparseable_nodes_on_scheduler]}"
                )

            return SocaResponse(
                success=True,
                message={
                    "nodes": _registered_nodes_on_scheduler,
                    "unparseable_nodes": _unparseable_nodes_on_scheduler,
                },
            )

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to run {_run_command} due to {_nodes_data.get('message')}"
            )

    @staticmethod
    def unparseable_node_record(
        node_name: str, node_info: dict, error: str
    ) -> dict:
        """
        What is still usable about a node whose model construction failed.

        Read straight from the pbsnodes payload rather than from a model, since
        building the model is what failed. Every value is optional: the point is
        to carry whatever identifies the node and its capacity so an operator,
        and the safe teardown path in common_sync, can act on it.
        """
        _resources_available = node_info.get("resources_available", {}) or {}
        return {
            "node_name": node_name,
            "pbs_mom": node_info.get("Mom"),  # note: case sensitive
            "instance_id": _resources_available.get("instance_id"),
            "stack_id": _resources_available.get("stack_id"),
            "compute_node": _resources_available.get("compute_node"),
            "keep_forever": str(
                _resources_available.get("keep_forever", "false")
            ).lower()
            == "true",
            "state": node_info.get("state"),
            "error": error,
        }

    def register_node(self, soca_node: SocaNode) -> SocaResponse:
        """
        Register a new SocaNode to the scheduler
        """
        _pbs_mom = self.get_pbs_node_mom_attribute(soca_node=soca_node)
        logger.info(f"Registering EC2 nodes with {_pbs_mom=}")
        logger.debug(f"Registering node {soca_node}")

        if soca_node.job_id is None:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to register node {_pbs_mom} due to missing JobId tag"
            )

        if soca_node.job_queue is None:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to register node {_pbs_mom} due to missing JobQueue tag"
            )

        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self._scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self._scheduler_info.binary_folder_paths}:{_current_path}"
            )

        _run_command_create_node = SocaHpcPBSJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).qmgr(f"-c 'create node {_pbs_mom} queue={soca_node.job_queue}'")
        if not _run_command_create_node:
            return SocaError.GENERIC_ERROR(
                helper="Unable to build qmgr _run_command_create_node command. See log for details "
            )
        _register_node = SocaSubprocessClient(run_command=_run_command_create_node).run(
            env=_current_env
        )
        if _register_node.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to register node {_pbs_mom} due to {_register_node.get('message')}"
            )
        else:

            _node_resources_available = [
                f"resources_available.keep_forever={soca_node.keep_forever}",  # mandatory
                f"resources_available.terminate_when_idle={soca_node.terminate_when_idle}",  # mandatory
                f"resources_available.stack_id={soca_node.stack_id}",  # mandatory
                f"resources_available.compute_node={soca_node.job_id}",  # mandatory
                f"resources_available.instance_id={soca_node.instance_id}",  # mandatory
                f"resources_available.instance_type={soca_node.instance_type}",  # mandatory
                f"resources_available.availability_zone={soca_node.availability_zone}",
                f"resources_available.subnet_id={soca_node.subnet_id}",
            ]

            logger.info(
                f"Node {_pbs_mom} successfully registered, adding custom node_resources: {_node_resources_available} "
            )

            _run_command_set_node = SocaHpcPBSJobCommandBuilder(
                scheduler_info=self._scheduler_info
            ).qmgr(f"-c 'set node {_pbs_mom} {','.join(_node_resources_available)}'")
            if not _run_command_set_node:
                return SocaError.GENERIC_ERROR(
                    helper="Unable to build qmgr _run_command_set_node command. See log for details "
                )
            _configure_node = SocaSubprocessClient(
                run_command=_run_command_set_node
            ).run(env=_current_env)

            if _configure_node.get("success") is True:
                logger.info(
                    f"Node {_pbs_mom} successfully configured with job {soca_node.job_id=}"
                )
                return SocaResponse(
                    success=True, message=_configure_node.get("message")
                )
            else:
                logger.error(
                    f"Unable to configure node {soca_node.private_ip_address} due to {_configure_node.get('message')}, removing {soca_node} from qmgr"
                )

                self.deregister_node(pbs_mom=_pbs_mom)

                return SocaError.GENERIC_ERROR(
                    helper=f"Node {_pbs_mom} created successfully but unable to configure it due to {_configure_node.get('message')}"
                )

    def deregister_node(
        self, pbs_mom: Optional[str] = None, pbs_node: Optional[SocaHpcNodePBS] = None
    ) -> SocaResponse:
        """
        Deregister a node from the scheduler
        """
        if not pbs_mom and not pbs_node:
            return SocaError.GENERIC_ERROR(
                helper="'pbs_mom' or 'pbs_node' must be specified"
            )

        _pbs_mom = pbs_mom if pbs_mom else pbs_node.pbs_mom

        logger.info(f"About to de-register SocaPbsNode with {_pbs_mom=}")
        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self._scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self._scheduler_info.binary_folder_paths}:{_current_path}"
            )
        _run_command_delete_node = SocaHpcPBSJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).qmgr(f"-c 'delete node {_pbs_mom}'")
        if not _run_command_delete_node:
            return SocaError.GENERIC_ERROR(
                helper="Unable to build qmgr _run_command_delete_node command. See log for details "
            )
        _node_data = SocaSubprocessClient(run_command=_run_command_delete_node).run(
            env=_current_env
        )
        if _node_data.get("success") is True:
            return SocaResponse(
                success=True,
                message=f"{_pbs_mom} de-registered and successfully",
            )
        else:
            if "unknown node" in _node_data.get("message").get("stderr").lower():
                return SocaResponse(
                    success=True,
                    message="Node not found, may have already been deleted",
                )

            return SocaError.GENERIC_ERROR(
                helper=f"Unable to deregister node {_pbs_mom} due to {_node_data.get('message')}"
            )
