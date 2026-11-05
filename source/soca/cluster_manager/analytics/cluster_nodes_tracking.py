#!/usr/bin/python

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
import json
import datetime
from utils.config import SocaConfig
from utils.analytics_client import SocaAnalyticsClient
from utils.subprocess_client import (
    SocaSubprocessClient,
    subprocess_message_as_dict,
)
from utils.logger import SocaLogger
from utils.datamodels.hpc.scheduler import get_schedulers, SocaHpcSchedulerProvider
from utils.hpc.scheduler_command_builder import SocaHpcPBSJobCommandBuilder


if __name__ == "__main__":
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message
    _log_file_location = f"/opt/edh/{_cluster_id}/cluster_manager/analytics/logs/cluster_nodes_tracking.log"
    logger = SocaLogger(name="analytics_cluster_nodes_tracking").rotating_file_handler(
        file_path=_log_file_location
    )

    logger.debug(f"Tracking active SOCA HPC compute nodes. Log: {_log_file_location}")
    _analytics_client = SocaAnalyticsClient(
        endpoint=SocaConfig(key="/configuration/Analytics/endpoint")
        .get_value()
        .get("message"),
        engine=SocaConfig(key="/configuration/Analytics/engine")
        .get_value()
        .get("message"),
    )

    if _analytics_client.is_enabled().success is False:
        logger.info("Analytics is not enabled, exiting")
        sys.exit(1)
    else:
        _analytics_client.initialize()
        logger.info("Analytics client initialized")

    _schedulers_to_query = get_schedulers()
    for _scheduler in _schedulers_to_query:
        if _scheduler.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:

            _run_command = SocaHpcPBSJobCommandBuilder(
                scheduler_info=_scheduler
            ).pbsnodes(args="-a -F json")
            logger.info(
                f"Scheduler detected: {_scheduler.provider}, proceeding with parsing command {_run_command} to retrieve cluster nodes information"
            )

            _index_name = f"edh_nodes_{_scheduler.identifier}_{_cluster_id}"

            # pbsnodes exits with rc==1 when there is no nodes in the pbsnodes list.
            # This is not a fatal problem for dynamic clusters that are cloud native
            # nodes come and go - and there may be times when there are simply no nodes yet.
            _command = SocaSubprocessClient(
                run_command=_run_command,
            ).run(non_fatal_rcs=[1])

            # SocaResponse.message is a dict on success but a STRING on failure, because
            # SocaError.return_error formats it into one. Normalise before reading keys.
            _message = subprocess_message_as_dict(_command.message)

            if _command.success is False:
                if "server has no node list" in (_message.get("stderr") or "").lower():
                    logger.info(
                        f"No nodes found for scheduler {_scheduler.identifier}, skipping ..."
                    )
                    continue
                else:
                    logger.error(
                        f"Error querying scheduler {_scheduler.identifier}: {_command.message}"
                    )
                    continue

            else:
                # A non-fatal rc==1 lands here with success=True and an EMPTY stdout, which
                # is the ordinary "no nodes yet" case rather than an error. Treat it as such
                # instead of handing "" to json.loads.
                _stdout = (_message.get("stdout") or "").strip()
                if not _stdout:
                    logger.info(
                        f"No nodes reported by scheduler {_scheduler.identifier}, skipping ..."
                    )
                    continue

                # Compute Nodes detected
                try:
                    pbsnodes_output = json.loads(_stdout)
                except json.JSONDecodeError as err:
                    logger.error(
                        f"Unable to parse pbsnodes output for scheduler "
                        f"{_scheduler.identifier} as JSON: {err}"
                    )
                    continue
                for hostname, data in pbsnodes_output["nodes"].items():

                    try:
                        data["timestamp"] = datetime.datetime.fromtimestamp(
                            pbsnodes_output["timestamp"]
                        ).isoformat()
                    except Exception as err:
                        logger.error(
                            f"Unable to process record: {hostname=} / {data=} / {pbsnodes_output=} due to {err}"
                        )
                        continue

                    _index_data = _analytics_client.index(index=_index_name, body=data)
                    if _index_data.success:
                        logger.info(f"RECORD INDEXED SUCCESSFULLY > {data}")
                    else:
                        logger.error(f"Error while indexing {data}")
        else:
            logger.info(
                f"Scheduler detected: {_scheduler.identifier} ({_scheduler.provider}), skipping as not supported yet (only PBSPro/OpenPBS supported currently)"
            )
