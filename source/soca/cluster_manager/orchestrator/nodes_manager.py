# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from utils.response import SocaResponse
from utils.error import SocaError
from utils.logger import SocaLogger

from utils.datamodels.hpc.scheduler import (
    get_schedulers,
    SocaHpcScheduler,
    SocaHpcSchedulerProvider,
)

from utils.aws.boto3_wrapper import get_boto
from utils.aws.ec2_helper import describe_instances_as_soca_nodes
from utils.aws.cloudformation_client import SocaCfnClient
from utils.config import SocaConfig
from utils.hpc.schedulers_managers.pbs import SocaSchedulerPBSNodesManager
from utils.hpc.schedulers_managers.lsf import SocaSchedulerLSFNodesManager
from utils.hpc.schedulers_managers.slurm import SocaSchedulerSlurmNodesManager

from utils.hpc.job_fetcher import SocaHpcJobFetcher


def get_failed_cloudformation_stacks_assigned_to_scheduler(
    scheduler_info: SocaHpcScheduler,
) -> SocaResponse:
    logger.info(
        f"Retrieving all failed CloudFormation Stack assigned to {scheduler_info=}"
    )
    _stacks = {}

    # list_stacks has no cluster/tag filter, so it returns every failed stack in the
    # account/region. Resolve our ClusterId up front to (a) scope by stack-name prefix
    # before logging/describing anything, and (b) make the edh:ClusterId tag comparison
    # below actually work (it previously referenced an undefined _cluster_id).
    _cluster_id_resp = SocaConfig(key="/configuration/ClusterId").get_value()
    _cluster_id = (
        _cluster_id_resp.get("message")
        if _cluster_id_resp.get("success") is True
        else None
    )
    if not _cluster_id:
        return SocaError.GENERIC_ERROR(
            helper="Unable to resolve /configuration/ClusterId for failed-stack scan"
        )

    try:
        cf_client = get_boto(service_name="cloudformation").message

        paginator = cf_client.get_paginator("list_stacks")

        for page in paginator.paginate(
            StackStatusFilter=["CREATE_FAILED", "ROLLBACK_FAILED", "DELETE_FAILED"]
        ):
            for summary in page["StackSummaries"]:
                try:
                    _stack_name = summary["StackName"]
                    _stack_status = summary["StackStatus"]

                    # Scope to THIS cluster's stacks up front. Skip foreign stacks
                    # silently -- never log another cluster's failed stack here, it
                    # causes needless operator alarm.
                    if not _stack_name.startswith(f"{_cluster_id}-"):
                        continue

                    _stack_data = SocaCfnClient(stack_name=_stack_name)
                    logger.debug(
                        f"{_stack_name} found in status {_stack_status}, checking if stack should be deleted"
                    )
                    if (
                        _stack_data.is_stack_older_than(minutes=60).get("success")
                        is True
                    ):
                        _fetch_tags = _stack_data.get_tags()
                        if _fetch_tags.get("success") is False:
                            logger.error(
                                f"Unable to fetch tags for {_stack_name} due to {_fetch_tags.get('message')}"
                            )
                            continue
                        else:
                            _tags = _fetch_tags.get("message")

                        logger.info(f"Found all tags for {_stack_name}: {_tags=}")

                        if _tags.get("edh:ClusterId") != _cluster_id:
                            logger.debug("edh:ClusterId not there, ignoring ... ")
                            continue

                        if (
                            _tags.get("edh:SchedulerIdentifier")
                            != scheduler_info.identifier
                        ):
                            logger.debug(
                                f"edh:SchedulerIdentifier not matching {scheduler_info.identifier}, ignoring ... "
                            )
                            continue

                        job_id = _tags.get(
                            "edh:JobId",
                        )
                        if not job_id:
                            logger.debug("edh:JobId not there, ignoring ... ")
                            continue

                        _stacks[_stack_name] = job_id

                    else:
                        logger.warning(
                            "Stack last update happened less than 60 minutes ago, ignoring ... "
                        )
                        continue

                except Exception as err:
                    logger.error(f"Unable to process {_stack_name} due to {err}")
                    continue

    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to list failed CloudFormation stacks due to {err}"
        )

    logger.debug(f"Found Failed Stacks: {_stacks}")
    return SocaResponse(success=True, message=_stacks)


def get_provisioned_ec2_nodes_assigned_to_scheduler(
    scheduler_info: SocaHpcScheduler,
) -> SocaResponse[list[SocaNode]]:
    logger.info(f"Retrieving all provisioned EC2 Nodes assigned to {scheduler_info=}")
    # Notes
    #  - Additional Scheduler Specific filters will be automatically added to the _filters as we pass a SocaHpcScheduler object on describe_instances_as_soca_nodes
    #  - We must retrieve KeepForever nodes as well
    _filters = [
        {
            "Name": "instance-state-name",
            "Values": ["running", "pending"],
        },
        {"Name": "tag:edh:NodeType", "Values": ["compute_node"]},
        {
            "Name": "tag:edh:KeepForever",
            "Values": ["false", "False", "true", "True"],
        },
        {"Name": "tag:edh:ClusterId", "Values": [_cluster_id]},
    ]
    logger.debug(f"Fetching EC2 instances using {_filters=}")
    _fetch_all_ec2_nodes_for_scheduler = describe_instances_as_soca_nodes(
        filters=_filters, scheduler_info=scheduler_info
    )
    if _fetch_all_ec2_nodes_for_scheduler.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 nodes due to {_fetch_all_ec2_nodes_for_scheduler.get('message')}"
        )
    else:
        # Note: this is a list of SocaNode as we use describe_instances_as_soca_nodes
        _provisioned_ec2_nodes = _fetch_all_ec2_nodes_for_scheduler.get("message")

        logger.debug(
            f"List of EC2 Node associated to {scheduler_info.identifier}: {_provisioned_ec2_nodes}"
        )
        return SocaResponse(success=True, message=_provisioned_ec2_nodes)


if __name__ == "__main__":
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message

    logger = SocaLogger(name="soca_logger").timed_rotating_file_handler(
        file_path=f"/opt/edh/{_cluster_id}/cluster_manager/orchestrator/logs/nodes_manager.log"
    )

    _all_schedulers = get_schedulers()
    logger.debug(f"About to fetch nodes for {_all_schedulers=} with {_cluster_id=}")

    for _scheduler in _all_schedulers:
        logger.debug(f"Processing {_scheduler}")
        # List of SocaHpcJob found in all queues assigned to the scheduler
        _jobs_in_queues: list[SocaHpcJobLSF | SocaHpcJobPBS | SocaHpcJobSlurm] = []

        # List of SocaNode provisioned on EC2 and attached to this scheduler
        _provisioned_ec2_nodes: list[SocaNode] = []

        if _scheduler.soca_managed_nodes_provisioning is False:
            logger.info(
                f"Skipping scheduler {_scheduler.identifier} as soca_managed_nodes_provisioning is set to False"
            )
            continue

        # 1 - Get the list of EC2 Provisioned nodes assigned to the scheduler
        logger.info(f"Syncing provisioned EC2 nodes for {_scheduler.identifier}")
        if not (
            _get_provisioned_nodes := get_provisioned_ec2_nodes_assigned_to_scheduler(
                scheduler_info=_scheduler
            )
        ).get("success"):
            logger.error(
                f"Unable to fetch EC2 nodes due to {_get_provisioned_nodes.get('message')}"
            )
            continue
        else:
            _provisioned_ec2_nodes = _get_provisioned_nodes.get("message")

        # 2 - Get all jobs submitted
        logger.info(f"Syncing jobs in queue for {_scheduler.identifier}")
        if not (
            _get_submitted_jobs := SocaHpcJobFetcher(_scheduler).get_all_jobs()
        ).get("success"):
            logger.error(
                f"Unable to fetch jobs in queues due to {_get_submitted_jobs.get('message')}"
            )
            continue
        else:
            _jobs_in_queues = _get_submitted_jobs.get("message")

        # 3 - Find any failed stacks and delete them if assigned jobs are not in the queue anymore
        logger.info(
            f"Checking Failed CloudFormation stacks for {_scheduler.identifier}"
        )
        _get_failed_stacks = get_failed_cloudformation_stacks_assigned_to_scheduler(
            scheduler_info=_scheduler
        )
        if _get_failed_stacks.get("success") is False:
            logger.error(
                f"Unable to fetch failed stacks due to {_get_failed_stacks.get('message')}, skipping"
            )
        else:
            for _stack_name, _job_id in _get_failed_stacks.get("message").items():
                if _job_id in [job.job_id for job in _jobs_in_queues]:
                    logger.info(
                        f"Job {_job_id} is still in queue, skipping deletion of failed stack {_stack_name}"
                    )
                else:
                    logger.info(
                        f"Deleting failed stack {_stack_name} for {_job_id=} as job is not in the queue anymore "
                    )
                    if (
                        SocaCfnClient(stack_name=_stack_name)
                        .delete_stack()
                        .get("success")
                        is False
                    ):
                        logger.error(f"Unable to delete failed stack {_stack_name}")
                    else:
                        logger.info(f"{_stack_name=} deleted successfully")

        logger.debug(f"{_scheduler.provider}: Found {_provisioned_ec2_nodes=}")
        logger.debug(f"{_scheduler.provider}: Found {_jobs_in_queues=}")

        # 4 - Sync configuration with respective scheduler information
        if _scheduler.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:
            # errors/warnings are automatically forwarded to nodes_manager.log
            SocaSchedulerPBSNodesManager(scheduler_info=_scheduler).sync_config(
                provisioned_ec2_nodes=_provisioned_ec2_nodes,
                jobs_in_queues=_jobs_in_queues,
            )
        elif _scheduler.provider == SocaHpcSchedulerProvider.LSF:
            # errors/warnings are automatically forwarded to nodes_manager.log
            SocaSchedulerLSFNodesManager(scheduler_info=_scheduler).sync_config(
                provisioned_ec2_nodes=_provisioned_ec2_nodes,
                jobs_in_queues=_jobs_in_queues,
            )

        elif _scheduler.provider == SocaHpcSchedulerProvider.SLURM:
            # errors/warnings are automatically forwarded to nodes_manager.log
            SocaSchedulerSlurmNodesManager(scheduler_info=_scheduler).sync_config(
                provisioned_ec2_nodes=_provisioned_ec2_nodes,
                jobs_in_queues=_jobs_in_queues,
            )

        else:
            logger.error(f"{_scheduler.provider} is not supported yet")
