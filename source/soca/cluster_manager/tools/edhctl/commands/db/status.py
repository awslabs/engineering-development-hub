# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import sys

import click

from commands.db.common import (
    _cast_str,
    _echo_json,
    _format_bytes,
    _resolve_client,
    _resolve_db_cluster_identifier,
    db_connection,
    get_rds_client,
)

logger = logging.getLogger("soca_logger")


@click.command()
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def status(output):
    """Show Aurora cluster status and database summary."""
    _cluster_id = _resolve_db_cluster_identifier()
    _rds = _resolve_client(get_rds_client())
    logger.debug(f"Retrieving status for RDS cluster {_cluster_id}")

    try:
        _cluster = _rds.describe_db_clusters(DBClusterIdentifier=_cluster_id)["DBClusters"][0]
        _instances = _rds.describe_db_instances(
            Filters=[{"Name": "db-cluster-id", "Values": [_cluster_id]}]
        ).get("DBInstances", [])
    except Exception as err:
        logger.error(f"Failed to describe RDS cluster {_cluster_id}: {err}")
        click.echo(f"Error: failed to describe RDS cluster {_cluster_id}: {err}", err=True)
        sys.exit(1)

    _scaling = _cluster.get("ServerlessV2ScalingConfiguration", {})

    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT pg_database_size(current_database())")
        _db_size = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'")
        _total_conn = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM pg_stat_user_tables")
        _table_count = cur.fetchone()[0]

    _info = {
        "cluster_identifier": _cluster_id,
        "status": _cluster.get("Status"),
        "engine": f"{_cluster.get('Engine')} {_cluster.get('EngineVersion')}",
        "writer_endpoint": _cluster.get("Endpoint"),
        "reader_endpoint": _cluster.get("ReaderEndpoint", "N/A"),
        "acu_min": _scaling.get("MinCapacity", "N/A"),
        "acu_max": _scaling.get("MaxCapacity", "N/A"),
        "deletion_protection": _cluster.get("DeletionProtection", False),
        "encrypted": _cluster.get("StorageEncrypted", False),
        "backup_retention_days": _cluster.get("BackupRetentionPeriod", 0),
        "pitr_earliest": _cast_str(_cluster.get("EarliestRestorableTime", "N/A"))[:19],
        "pitr_latest": _cast_str(_cluster.get("LatestRestorableTime", "N/A"))[:19],
        "database_size_bytes": _db_size,
        "database_size_human": _format_bytes(_db_size),
        "active_connections": _total_conn,
        "table_count": _table_count,
        "instances": [
            {
                "id": i.get("DBInstanceIdentifier"),
                "class": i.get("DBInstanceClass"),
                "az": i.get("AvailabilityZone"),
                "status": i.get("DBInstanceStatus"),
            }
            for i in _instances
        ],
    }

    if output == "json":
        _echo_json(_info)
        return

    click.echo(f"Cluster:          {_info['cluster_identifier']}")
    click.echo(f"Status:           {_info['status']}")
    click.echo(f"Engine:           {_info['engine']}")
    click.echo(f"Writer:           {_info['writer_endpoint']}")
    click.echo(f"Reader:           {_info['reader_endpoint']}")
    click.echo(f"ACU range:        {_info['acu_min']} - {_info['acu_max']}")
    click.echo(f"Deletion prot:    {'enabled' if _info['deletion_protection'] else 'disabled'}")
    click.echo(f"Encrypted:        {'yes' if _info['encrypted'] else 'no'}")
    click.echo(f"Backup retention: {_info['backup_retention_days']} days")
    click.echo(f"PITR window:      {_info['pitr_earliest']} -> {_info['pitr_latest']}")
    click.echo(f"Database size:    {_info['database_size_human']}")
    click.echo(f"Connections:      {_info['active_connections']}")
    click.echo(f"Tables:           {_info['table_count']}")
    if _info["instances"]:
        click.echo("Instances:")
        for _inst in _info["instances"]:
            click.echo(
                f"  {_inst['id']}  {_inst['class']}  {_inst['az']}  {_inst['status']}"
            )
