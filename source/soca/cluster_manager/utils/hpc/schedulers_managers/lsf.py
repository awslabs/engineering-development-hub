# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import sys
import re
from datetime import datetime
from pydantic import ValidationError
from collections import defaultdict

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
from utils.datamodels.hpc.lsf.node import (
    SocaHpcNodeLSF,
    SocaHpcNodeLSFBhostsOutput,
    SocaHpcNodeLSFLshostsOutput,
)
from utils.hpc.scheduler_command_builder import SocaHpcLSFJobCommandBuilder

from utils.aws.cloudformation_client import SocaCfnClient

logger = logging.getLogger("soca_logger")


class SocaSchedulerLSFNodesManager:

    def __init__(self, scheduler_info: SocaHpcScheduler):

        self._scheduler_info = scheduler_info
        logger.info(
            f"SocaSchedulerLSFNodesManager: About to sync Scheduler: {self._scheduler_info}"
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

    def sync_config(
        self, provisioned_ec2_nodes: list[SocaNode], jobs_in_queues: list[SocaHpcJobLSF]
    ):
        """
        Synchronizes the LSF scheduler configuration with the current state of EC2 nodes and jobs.

        Uses common_sync.sync_scheduler_config to generate synchronization actions by comparing:
        - Currently registered LSF nodes
        - Provisioned EC2 nodes
        - Jobs in queues
        - Scheduler information

        The sync_scheduler_config returns a dictionary with the following structure:
        {
            "register_soca_nodes_to_scheduler": [SocaNode],  # EC2 Nodes to be registered in LSF
            "deregister_scheduler_nodes_no_associated_ec2_capacity": [SocaHpcNodeLSF],  # LSF Nodes without associated EC2 instances
            "deregister_scheduler_nodes_finished_jobs": [SocaHpcNodeLSF],  # LSF Nodes associated to completed jobs
            "delete_idle_capacity_per_stack": [{"stack_id": str, "nodes": [SocaHpcNodeLSF]}]  # one entry per stack whose EVERY node is idle past its terminate_when_idle
            "reclaim_idle_scheduler_nodes": [SocaHpcNodeLSF]  # individually idle nodes, PBS only for now
        }

        Each action list is then processed to either register new nodes or deregister existing ones.

        Args:
            provisioned_ec2_nodes (list[SocaNode]): List of currently provisioned EC2 nodes
            jobs_in_queues (list[SocaHpcJobLSF]): List of jobs currently in the LSF queues
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
            f"{self._scheduler_info.identifier}: Received LSF sync actions: {_sync_actions=}"
        )

        _deregister_scheduler_nodes_finished_jobs = _sync_actions.get(
            "deregister_scheduler_nodes_finished_jobs"
        )
        if _deregister_scheduler_nodes_finished_jobs:
            logger.info(
                "De-registering SocaHpcNodeLSF + delete cloudformation_capacity assigned to finished jobs from LSF configuration"
            )
            for _lsf_node in _deregister_scheduler_nodes_finished_jobs:
                _deregister_node = self.deregister_node(lsf_node=_lsf_node)
                if _deregister_node.get("success") is False:
                    logger.error(
                        f"Unable to deregister node {_lsf_node.instance_id} due to {_deregister_node.get('message')}"
                    )
                else:
                    _delete_associated_capacity = self.delete_associated_capacity(
                        stack_name=_lsf_node.stack_id
                    )
                    if _delete_associated_capacity.get("success") is False:
                        logger.error(
                            f"Unable to delete associated capacity {_lsf_node.stack_id} due to {_delete_associated_capacity.get('message')}"
                        )
                    else:
                        logger.info(
                            f"Associated capacity {_lsf_node.stack_id} deleted successfully"
                        )

        _delete_idle_capacity_per_stack = _sync_actions.get(
            "delete_idle_capacity_per_stack"
        )
        if _delete_idle_capacity_per_stack:
            logger.info(
                "De-registering SocaLSFNode + delete cloudformation_capacity with expired terminate_when_idle flag"
            )
            for _entry in _delete_idle_capacity_per_stack:
                _stack_id = _entry.get("stack_id")
                for _lsf_node in _entry.get("nodes", []):
                    _deregister_node = self.deregister_node(lsf_node=_lsf_node)
                    if _deregister_node.get("success") is False:
                        # Logged and carried on rather than skipping the delete:
                        # the stack is going either way, and a node left
                        # registered against a terminated instance is picked up
                        # by the no-associated-capacity path.
                        logger.error(
                            f"Unable to deregister node {_lsf_node.instance_id} due to {_deregister_node.get('message')}, "
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
        # LSF therefore keeps the stricter behaviour: capacity is reclaimed only
        # when every node in the stack is idle. Implementing it here needs an
        # LSF equivalent of terminate_node_capacity.

    def get_registered_nodes(
        self,
    ):
        logger.info("Retrieving all LSF nodes registered in the scheduler")

        _registered_nodes_on_scheduler = []

        # note: all commands only return string
        _run_command_lshosts = SocaHpcLSFJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).lshosts(
            args='-o "HOST_NAME type model cpuf ncpus maxmem maxswp server RESOURCES ndisks maxtmp rexpri nprocs ncores nthreads RUN_WINDOWS" -json'
        )
        _run_command_lshosts_string_resources = SocaHpcLSFJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).lshosts(args="-sl")
        _run_command_bhosts = SocaHpcLSFJobCommandBuilder(
            scheduler_info=self._scheduler_info
        ).bhosts(args='-o "all" -json')

        if not _run_command_bhosts:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build _run_command_lshosts command for {self._scheduler_info.provider=}, see logs for additional details"
            )

        if not _run_command_lshosts:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build _run_command_lshosts command for {self._scheduler_info.provider=}, see logs for additional details"
            )

        if not _run_command_lshosts_string_resources:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build _run_command_lshosts_string_resources command for {self._scheduler_info.provider=}, see logs for additional details"
            )

        _nodes_data_lshosts = SocaSubprocessClient(
            run_command=_run_command_lshosts
        ).run()

        _nodes_data_bhosts = SocaSubprocessClient(run_command=_run_command_bhosts).run()
        if _nodes_data_lshosts.get("success"):
            if data := SocaCastEngine(
                data=_nodes_data_lshosts.get("message").get("stdout")
            ).as_json():
                _lshosts_data = data.get("message")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"{_run_command_lshosts} succeeded but output was not a valid json"
                )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve lshost data due to {_nodes_data_lshosts.get('message')}"
            )

        if _nodes_data_bhosts.get("success"):
            if data := SocaCastEngine(
                data=_nodes_data_bhosts.get("message").get("stdout")
            ).as_json():
                _bhosts_data = data.get("message")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"{_nodes_data_bhosts} succeeded but output was not a valid json"
                )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve lshost data due to {_nodes_data_bhosts.get('message')}"
            )

        if _bhosts_data.get("HOSTS") == 0:
            logger.debug(
                f"Scheduler {self._scheduler_info.identifier} does not have any nodes registered"
            )
            return SocaResponse(success=True, message=_registered_nodes_on_scheduler)
        else:

            _nodes_data_lshosts_string_resources = SocaSubprocessClient(
                run_command=_run_command_lshosts_string_resources
            ).run()
            if _nodes_data_lshosts_string_resources.get("success"):
                """
                convert lshosts -ls output to dictionary
                RESOURCE
                    compute_node
                        VALUE: 12
                        LOCATION: ip-147-0-106-3.us-east-2.compute.internal
                        NAMES: -
                    compute_node
                        VALUE: 13
                        LOCATION: ip-147-0-97-139.us-east-2.compute.internal
                        NAMES: -
                    availability_zone
                        VALUE: us-east-2c
                        LOCATION: ip-147-0-219-126.us-east-2.compute.internal
                        NAMES: -
                    instance_id
                        VALUE: i-03f968b3e275e8cc4
                        LOCATION: ip-147-0-219-126.us-east-2.compute.internal
                        NAMES: -
                    ....
                """
                hosts = defaultdict(dict)
                current_resource = None
                value = None

                lines = (
                    _nodes_data_lshosts_string_resources.get("message")
                    .get("stdout")
                    .strip()
                    .splitlines()
                )
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Resource line (not starting with VALUE, LOCATION, NAMES)
                    if not line.startswith(("VALUE:", "LOCATION:", "NAMES:")):
                        current_resource = line
                        continue

                    if line.startswith("VALUE:"):
                        value = line.split(":", 1)[1].strip()
                    elif line.startswith("LOCATION:"):
                        ip = line.split(":", 1)[1].strip()
                        hosts[ip][current_resource] = value
                    elif line.startswith("NAMES:"):
                        names = line.split(":", 1)[1].strip()
                        if names != "-":
                            hosts[ip].setdefault(f"{current_resource}_names", names)

                _lshosts_string_resources = dict(hosts)
                logger.info(f"Found LSF string resources: {_lshosts_string_resources}")
            else:
                logger.error("Unable to determine string resources")
                _lshosts_string_resources = {}

            logger.debug(
                f"Received LSF parser with bhost output {_bhosts_data} and lshost output: {_lshosts_data}"
            )

            # merge lshosts and bhosts output into a single dictionary:
            # key: hostname: {"bhosts": {//bhosts output}, "lshosts": {//lshost output} }
            _nodes_info = {}
            for record in _lshosts_data.get("RECORDS", []):
                host = record["HOST_NAME"]
                if host not in _nodes_info:
                    _nodes_info[host] = {}
                _nodes_info[host]["lshosts"] = record

            for record in _bhosts_data.get("RECORDS", []):
                host = record["HOST_NAME"]
                if host not in _nodes_info:
                    _nodes_info[host] = {}
                _nodes_info[host]["bhosts"] = record

            for _node_hostname, _node_data in _nodes_info.items():
                try:
                    if (
                        _node_data.get("bhosts").get("STATUS") == "ok"
                        and _node_data.get("bhosts").get("NJOBS") == "0"
                    ):
                        _node_state = (
                            SocaSchedulerNodeState.IDLE
                        )  # node is available but not serving any jobs
                    elif (
                        _node_data.get("bhosts").get("STATUS") == "ok"
                        and _node_data.get("bhosts").get("NJOBS") != "0"
                    ):
                        _node_state = (
                            SocaSchedulerNodeState.ACTIVE
                        )  # node is available and actively serving jobs
                    elif (
                        "closed" in _node_data.get("bhosts").get("STATUS")
                        or "unavail" in _node_data.get("bhosts").get("STATUS")
                        or "unreach" in _node_data.get("bhosts").get("STATUS")
                    ):
                        # addition info can be appended, e.g: closed_Adm, closed_Cu_excl
                        _node_state = SocaSchedulerNodeState.DOWN
                    else:
                        _node_state = SocaSchedulerNodeState.OTHER

                    # Not available on LSF
                    _last_state_change_timestamp = int(datetime.now().timestamp())

                    # Find required SOCA parameters associated to the LSF node via the lshosts string resource
                    _compute_node = _lshosts_string_resources.get(
                        _node_hostname, {}
                    ).get("compute_node", None)
                    _stack_id = _lshosts_string_resources.get(_node_hostname, {}).get(
                        "stack_id", None
                    )
                    _instance_id = _lshosts_string_resources.get(
                        _node_hostname, {}
                    ).get("instance_id", None)
                    _keep_forever = _lshosts_string_resources.get(
                        _node_hostname, {}
                    ).get("keep_forever", False)
                    _terminate_when_idle = _lshosts_string_resources.get(
                        _node_hostname, {}
                    ).get("terminate_when_idle", 0)

                    if not _compute_node and not _instance_id and not _stack_id:
                        logger.warning(
                            f"{_node_hostname=} does not have  compute_node / instance_id and stack_id resources associated to it. It's probably not a SOCA node, ignoring node ..."
                        )
                        continue

                    _lsf_node = SocaHpcNodeLSF(
                        node_state=_node_state,
                        scheduler_info=self._scheduler_info,
                        last_state_change_timestamp=_last_state_change_timestamp,
                        keep_forever=_keep_forever,
                        terminate_when_idle=_terminate_when_idle,
                        instance_id=_instance_id,
                        stack_id=_stack_id,
                        job_id=(
                            _compute_node if _compute_node != "tbd" else None
                        ),  # same as compute node if compute_node
                        compute_node=_compute_node,
                        lshosts=SocaHpcNodeLSFLshostsOutput(
                            string_resources=_lshosts_string_resources,
                            host_name=_node_data.get("lshosts").get("HOST_NAME", None),
                            resources=_node_data.get("lshosts").get("RESOURCES", None),
                            type=_node_data.get("lshosts").get("type", None),
                            model=_node_data.get("lshosts").get("model", None),
                            cpuf=_node_data.get("lshosts").get("cpuf", None),
                            ncpus=_node_data.get("lshosts").get("ncpus", None),
                            maxmem=_node_data.get("lshosts").get("maxmem", None),
                            maxswp=_node_data.get("lshosts").get("maxswp", None),
                            server=_node_data.get("lshosts").get("server", None),
                            ndisks=_node_data.get("lshosts").get("ndisks", None),
                            maxtmp=_node_data.get("lshosts").get("maxtmp", None),
                            rexpri=_node_data.get("lshosts").get("rexpri", None),
                            nprocs=_node_data.get("lshosts").get("nprocs", None),
                            ncores=_node_data.get("lshosts").get("ncores", None),
                            nthreads=_node_data.get("lshosts").get("nthreads", None),
                            run_windows=_node_data.get("lshosts").get(
                                "RUN_WINDOWS", None
                            ),
                        ),
                        bhosts=SocaHpcNodeLSFBhostsOutput(
                            host_name=_node_data.get("bhosts").get("HOST_NAME", None),
                            status=_node_data.get("bhosts").get("STATUS", None),
                            cpuf=_node_data.get("bhosts").get("CPUF", None),
                            jl_u=_node_data.get("bhosts").get("JL_U", None),
                            max=_node_data.get("bhosts").get("MAX", None),
                            njobs=_node_data.get("bhosts").get("NJOBS", None),
                            run=_node_data.get("bhosts").get("RUN", None),
                            ssusp=_node_data.get("bhosts").get("SSUSP", None),
                            ususp=_node_data.get("bhosts").get("USUSP", None),
                            rsv=_node_data.get("bhosts").get("RSV", None),
                            dispatch_window=_node_data.get("bhosts").get(
                                "DISPATCH_WINDOW", None
                            ),
                            slots=_node_data.get("bhosts").get("SLOTS", None),
                            slots_alloc=_node_data.get("bhosts").get(
                                "SLOTS_ALLOC", None
                            ),
                            ngpus=_node_data.get("bhosts").get("NGPUS", None),
                            ngpus_alloc=_node_data.get("bhosts").get(
                                "NGPUS_ALLOC", None
                            ),
                            ngpus_excl_alloc=_node_data.get("bhosts").get(
                                "NGPUS_EXCL_ALLOC", None
                            ),
                            ngpus_shared_alloc=_node_data.get("bhosts").get(
                                "NGPUS_SHARED_ALLOC", None
                            ),
                            ngpus_shared_jexcl_alloc=_node_data.get("bhosts").get(
                                "NGPUS_SHARED_JEXCL_ALLOC", None
                            ),
                            ngpus_excl_avail=_node_data.get("bhosts").get(
                                "NGPUS_EXCL_AVAIL", None
                            ),
                            ngpus_shared_avail=_node_data.get("bhosts").get(
                                "NGPUS_SHARED_AVAIL", None
                            ),
                            attribute=_node_data.get("bhosts").get("ATTRIBUTE", None),
                            comments=_node_data.get("bhosts").get("COMMENTS", None),
                            mig_alloc=_node_data.get("bhosts").get("MIG_ALLOC", None),
                            total_mem=_node_data.get("bhosts").get("TOTAL_MEM", None),
                            reserved_mem=_node_data.get("bhosts").get(
                                "RESERVED_MEM", None
                            ),
                            available_mem=_node_data.get("bhosts").get(
                                "AVAILABLE_MEM", None
                            ),
                        ),
                    )

                    logger.debug(f"Found LSF node {_lsf_node}")
                    _registered_nodes_on_scheduler.append(_lsf_node)
                except ValidationError as ve:
                    # This will give detailed info about what fields failed
                    logger.error(
                        f"Pydantic validation failed for node_info={_node_data}: {ve.json()}"
                    )
                    continue

                except Exception as err:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    logger.info(
                        f"Unable to parse LSF node {_node_hostname=} / {_node_data=} due to {err} on line  {exc_tb.tb_lineno}, skipping"
                    )
                    continue

            return SocaResponse(success=True, message=_registered_nodes_on_scheduler)

    def register_node(self, soca_node: SocaNode) -> SocaResponse:
        """
        There is no need to register a node manually to LSF.
        Node registration happens automatically when the LSF daemons are started on the compute nodes
        """
        return SocaResponse(success=True, message="")

    def deregister_node(self, lsf_node: SocaHpcNodeLSF) -> SocaResponse:
        """
        There is no need to de-register a node manually from LSF

        Instead, SOCA does configure LSF_DYNAMIC_HOST_TIMEOUT=60m which will automatically remove the idle nodes from LSF configuration
        https://www.ibm.com/docs/en/spectrum-lsf/10.1.0?topic=cluster-removing-dynamic-hosts

        Note: EC2 Capacity removal is still manual via SocaSchedulerLSFNodesManager.delete_associated_capacity
        """
        return SocaResponse(success=True, message="")
