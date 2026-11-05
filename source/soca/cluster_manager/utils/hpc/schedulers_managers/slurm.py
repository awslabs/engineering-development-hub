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


logger = logging.getLogger("soca_logger")


class SocaSchedulerSlurmNodesManager:

    def __init__(self, scheduler_info: SocaHpcScheduler):

        self._scheduler_info = scheduler_info
        logger.info(
            f"SocaSchedulerSlurmNodesManager: About to sync Scheduler: {self._scheduler_info}"
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
    def get_nodename(soca_node: SocaNode) -> str:
        # Slurm NodeName will be the default private DNS of the instance
        return soca_node.private_dns_name

    def sync_config(
        self, provisioned_ec2_nodes: list[SocaNode], jobs_in_queues: list[SocaHpcJob]
    ):
        """
        WIP -
        """
        if not (_registered_nodes := self.get_registered_nodes()).get("success"):
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve registered nodes due to {_registered_nodes.get('message')}"
            )

        _sync_actions = common_sync.sync_scheduler_config(
            scheduler_registered_nodes=_registered_nodes.get("message"),
            provisioned_ec2_nodes=provisioned_ec2_nodes,
            jobs_in_queues=jobs_in_queues,
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
                for _pbs_nodes in _entry.get("nodes", []):
                    _deregister_node = self.deregister_node(pbs_node=_pbs_nodes)
                    if _deregister_node.get("success") is False:
                        # Logged and carried on rather than skipping the delete:
                        # the stack is going either way, and a node left
                        # registered against a terminated instance is picked up
                        # by the no-associated-capacity path.
                        logger.error(
                            f"Unable to deregister node {_pbs_nodes.instance_id} due to {_deregister_node.get('message')}, "
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

        # NOTE: reclaim_idle_scheduler_nodes (terminate ONE idle node, leaving
        # its stack and busy siblings in place) is implemented for PBS only.
        # Slurm therefore keeps the stricter behaviour: capacity is reclaimed
        # only when every node in the stack is idle. Implementing it here needs
        # a Slurm equivalent of terminate_node_capacity.

    def get_registered_nodes(
        self,
    ):
        """WIP  
        """
        

    def register_node(self, soca_node: SocaNode) -> SocaResponse:
        """
        WIP - Register a new SocaNode to the scheduler
        """
        _nodename = self.get_nodename(soca_node=soca_node)
        logger.debug(f"Registering node {soca_node}")

        if soca_node.job_id is None:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to register node {_nodename} due to missing JobId tag"
            )

        if soca_node.job_queue is None:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to register node {_nodename} due to missing JobQueue tag"
            )

        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self._scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self._scheduler_info.binary_folder_paths}:{_current_path}"
            )

        _register_node = SocaSubprocessClient(
            run_command=f"scontrol update NodeName={_nodename} Features='compute_node={soca_node.job_id}'"
        ).run(env=_current_env)
        if _register_node.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to register node {_nodename} due to {_register_node.get('message')}"
            )
        else:
            return SocaResponse(
                success=True, message=f"Node {_nodename} successfully registered"
            )

    def deregister_node(
        self, slurm_nodename: Optional[str] = None, slurm_node: Optional[SocaHpcNodeSlurm] = None
    ) -> SocaResponse:
        """
        WIP
        """
        if not slurm_nodename and not slurm_node:
            return SocaError.GENERIC_ERROR(
                helper="'slurm_nodename' or 'slurm_node' must be specified"
            )

        _slurm_nodename = slurm_nodename if slurm_nodename else slurm_node.name

        logger.info(f"About to de-register SocaHpcNodeSlurm with {slurm_nodename=}")
        
        # Extend the PATH to include potential binary_folder_paths
        _current_env = os.environ.copy()
        if self._scheduler_info.binary_folder_paths:
            _current_path = _current_env.get("PATH", "")
            _current_env["PATH"] = (
                f"{self._scheduler_info.binary_folder_paths}:{_current_path}"
            )

        _run_command = f"scontrol delete NodeName={_slurm_nodename}"
        _node_data = SocaSubprocessClient(run_command=_run_command).run(
            env=_current_env
        )
        if _node_data.get("success") is True:
            return SocaResponse(
                success=True,
                message=f"{_slurm_nodename} de-registered and successfully"
            )
        else:
            if "not found" in _node_data.get("message").get("stderr").lower():
                return SocaResponse(
                    success=True,
                    message="Node not found, may have already been deleted",
                )

            return SocaError.GENERIC_ERROR(
                helper=f"Unable to deregister node {_slurm_nodename} due to {_node_data.get('message')}"
            )
