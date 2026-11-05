# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import sys
from datetime import datetime, timedelta, timezone

import click

from commands.db.common import (
    _cast_str,
    _echo_json,
    _resolve_client,
    _resolve_db_cluster_identifier,
    get_cloudwatch_client,
)

logger = logging.getLogger("soca_logger")


@click.command()
@click.option("--hours", type=int, default=6, help="Number of hours of history to display")
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def capacity(hours, output):
    """Show Aurora Serverless ACU utilization over time."""
    _cluster_id = _resolve_db_cluster_identifier()
    _cloudwatch = _resolve_client(get_cloudwatch_client())

    _end = datetime.now(timezone.utc)
    _start = _end - timedelta(hours=hours)
    _period = 900 if hours <= 24 else 3600
    logger.debug(f"Fetching ACU metrics for {_cluster_id} over {hours}h at {_period}s")

    try:
        _response = _cloudwatch.get_metric_statistics(
            Namespace="AWS/RDS",
            MetricName="ServerlessDatabaseCapacity",
            Dimensions=[{"Name": "DBClusterIdentifier", "Value": _cluster_id}],
            StartTime=_start,
            EndTime=_end,
            Period=_period,
            Statistics=["Average", "Maximum"],
        )
    except Exception as err:
        logger.error(f"Failed to fetch ACU metrics for {_cluster_id}: {err}")
        click.echo(f"Error: failed to fetch ACU metrics: {err}", err=True)
        sys.exit(1)

    _datapoints = sorted(_response.get("Datapoints", []), key=lambda x: x["Timestamp"])

    if output == "json":
        _echo_json(
            {
                "cluster": _cluster_id,
                "hours": hours,
                "datapoints": [
                    {
                        "timestamp": _cast_str(d.get("Timestamp"))[:16],
                        "avg_acu": round(d.get("Average"), 2),
                        "max_acu": round(d.get("Maximum"), 2),
                    }
                    for d in _datapoints
                ],
            }
        )
        return

    click.echo(
        f"ACU utilization for {_cluster_id} (last {hours}h, {_period}s intervals):\n"
    )
    click.echo(f"{'Time':<18s} {'Avg ACU':>8s} {'Max ACU':>8s}")
    click.echo("-" * 36)
    for d in _datapoints:
        _ts = _cast_str(d.get("Timestamp"))[11:16]
        _avg = d.get("Average")
        _max = d.get("Maximum")
        _flag = " <- burst" if _max > _avg * 1.5 else ""
        click.echo(f"{_ts:<18s} {_avg:>8.2f} {_max:>8.2f}{_flag}")

    if _datapoints:
        _overall_avg = sum(d.get("Average") for d in _datapoints) / len(_datapoints)
        _overall_max = max(d.get("Maximum") for d in _datapoints)
        click.echo("-" * 36)
        click.echo(f"{'Period avg:':<18s} {_overall_avg:>8.2f}")
        click.echo(f"{'Period max:':<18s} {_overall_max:>8.2f}")
