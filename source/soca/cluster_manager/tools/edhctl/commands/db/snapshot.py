# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import sys
from datetime import datetime, timezone

import click

from commands.common import confirm
from commands.db.common import (
    _cast_str,
    _echo_json,
    _resolve_client,
    _resolve_db_cluster_identifier,
    get_rds_client,
)
from utils.error import SocaError

logger = logging.getLogger("soca_logger")


@click.group()
def snapshot():
    """Manage Aurora cluster snapshots."""
    pass


@snapshot.command("create")
@click.option("--name", required=True, help="Snapshot identifier suffix (alphanumeric + hyphens)")
@click.option("--wait/--no-wait", default=True, help="Wait for snapshot to become available")
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def snapshot_create(name, wait, output):
    """Create a manual DB cluster snapshot."""
    _cluster_id = _resolve_db_cluster_identifier()
    _rds = _resolve_client(get_rds_client())

    _snapshot_id = f"{_cluster_id}-{name}" if not name.startswith(_cluster_id) else name
    logger.debug(f"Creating snapshot {_snapshot_id} from cluster {_cluster_id}")

    click.echo(f"Creating snapshot {_snapshot_id}...")
    try:
        _snap = _rds.create_db_cluster_snapshot(
            DBClusterIdentifier=_cluster_id,
            DBClusterSnapshotIdentifier=_snapshot_id,
        )["DBClusterSnapshot"]
    except Exception as err:
        _error = SocaError.AWS_API_ERROR(
            service_name="rds",
            helper=f"Failed to create snapshot '{_snapshot_id}': {err}",
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    if wait:
        click.echo("Waiting for snapshot to become available...", nl=False)
        try:
            _rds.get_waiter("db_cluster_snapshot_available").wait(
                DBClusterSnapshotIdentifier=_snapshot_id
            )
        except Exception as err:
            click.echo("")
            _error = SocaError.AWS_API_ERROR(
                service_name="rds",
                helper=f"Snapshot '{_snapshot_id}' did not become available: {err}",
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)
        click.echo(" done.")

    _status = "available" if wait else _snap.get("Status")
    logger.info(f"Snapshot {_snapshot_id} created for cluster {_cluster_id}, status {_status}")

    if output == "json":
        _echo_json(
            {
                "snapshot_id": _snapshot_id,
                "status": _status,
                "cluster": _cluster_id,
                "created": _cast_str(_snap.get("SnapshotCreateTime", ""))[:19],
            }
        )
        return

    click.echo(f"Snapshot: {_snapshot_id}")
    click.echo(f"Status:   {_status}")
    click.echo(f"Cluster:  {_cluster_id}")


@snapshot.command("list")
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def snapshot_list(output):
    """List available cluster snapshots."""
    _cluster_id = _resolve_db_cluster_identifier()
    _rds = _resolve_client(get_rds_client())
    logger.debug(f"Listing snapshots for cluster {_cluster_id}")

    try:
        _response = _rds.describe_db_cluster_snapshots(DBClusterIdentifier=_cluster_id)
    except Exception as err:
        _error = SocaError.AWS_API_ERROR(
            service_name="rds",
            helper=f"Failed to list snapshots for '{_cluster_id}': {err}",
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    # tz-aware default: snapshots still creating have no SnapshotCreateTime
    _epoch = datetime.min.replace(tzinfo=timezone.utc)
    _snaps = sorted(
        _response.get("DBClusterSnapshots", []),
        key=lambda s: s.get("SnapshotCreateTime") or _epoch,
    )

    _results = [
        {
            "id": s.get("DBClusterSnapshotIdentifier"),
            "type": s.get("SnapshotType"),
            "status": s.get("Status"),
            "created": _cast_str(s.get("SnapshotCreateTime", ""))[:19],
            "engine": s.get("EngineVersion", ""),
        }
        for s in _snaps
    ]

    if output == "json":
        _echo_json(_results)
        return

    if not _results:
        click.echo("No snapshots found.")
        return

    click.echo(f"{'Snapshot ID':<55s} {'Type':<10s} {'Created':<20s} {'Status':<10s}")
    click.echo("-" * 98)
    for r in _results:
        click.echo(
            f"{r['id']:<55s} {r['type']:<10s} {r['created']:<20s} {r['status']:<10s}"
        )
    click.echo(f"\nTotal: {len(_results)} snapshot(s)")


@snapshot.command("delete")
@click.option("--name", required=True, help="Snapshot identifier to delete")
@click.option(
    "--confirm",
    "skip_confirm",
    is_flag=True,
    default=False,
    help="Skip confirmation prompt",
)
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def snapshot_delete(name, skip_confirm, output):
    """Delete a manual cluster snapshot."""
    _rds = _resolve_client(get_rds_client())

    if not skip_confirm:
        if not confirm(f"Delete snapshot '{name}'?"):
            click.echo("Aborted.")
            return

    logger.debug(f"Deleting snapshot {name}")
    try:
        _rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=name)
    except _rds.exceptions.DBClusterSnapshotNotFoundFault:
        _error = SocaError.AWS_API_ERROR(
            service_name="rds",
            helper=f"Snapshot '{name}' not found",
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)
    except Exception as err:
        if "InvalidDBClusterSnapshotState" in _cast_str(err):
            _helper = (
                f"Cannot delete snapshot '{name}'. Only manual snapshots can be deleted, "
                f"automated snapshots are managed by the backup retention policy"
            )
        else:
            _helper = f"Failed to delete snapshot '{name}': {err}"
        _error = SocaError.AWS_API_ERROR(service_name="rds", helper=_helper)
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    logger.info(f"Snapshot {name} deleted")

    if output == "json":
        _echo_json({"deleted": name, "status": "ok"})
        return

    click.echo(f"Deleted snapshot: {name}")
