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
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


@click.group()
def pitr():
    """Point-in-time recovery for the Aurora cluster."""
    pass


def _describe_source(rds, cluster_id: str) -> dict:
    """Describe the source cluster or abort. Internal to this module."""
    try:
        _clusters = rds.describe_db_clusters(DBClusterIdentifier=cluster_id).get(
            "DBClusters", []
        )
    except Exception as err:
        _error = SocaError.AWS_API_ERROR(
            service_name="rds",
            helper=f"Failed to describe source cluster '{cluster_id}': {err}",
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    if not Validators.is_list_not_empty(_clusters):
        _error = SocaError.AWS_API_ERROR(
            service_name="rds", helper=f"Source cluster '{cluster_id}' not found"
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    return _clusters[0]


def _source_writer_class(rds, source: dict) -> str:
    """Resolve the source cluster writer's instance class, defaulting to db.serverless."""
    _writer_id = None
    for _member in source.get("DBClusterMembers", []):
        if _member.get("IsClusterWriter") is True:
            _writer_id = _member.get("DBInstanceIdentifier")
            break

    if not Validators.exist(_writer_id):
        logger.warning("Source cluster has no writer member, defaulting to db.serverless")
        return "db.serverless"

    try:
        _instances = rds.describe_db_instances(DBInstanceIdentifier=_writer_id).get(
            "DBInstances", []
        )
    except Exception as err:
        logger.warning(
            f"Unable to describe source writer {_writer_id} ({err}), "
            f"defaulting to db.serverless"
        )
        return "db.serverless"

    if not Validators.is_list_not_empty(_instances):
        return "db.serverless"
    return _instances[0].get("DBInstanceClass", "db.serverless")


def _parse_restore_time(value: str) -> datetime:
    """Parse an ISO-8601 restore timestamp, assuming UTC when no offset is given."""
    try:
        _parsed = datetime.fromisoformat(value)
    except ValueError as err:
        _error = SocaError.GENERIC_ERROR(
            helper=(
                f"'{value}' is not a valid ISO-8601 timestamp ({err}). "
                f"Expected e.g. 2026-08-26T14:30:00 or 2026-08-26T14:30:00+00:00"
            )
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    if _parsed.tzinfo is None:
        _parsed = _parsed.replace(tzinfo=timezone.utc)
    return _parsed


@pitr.command("window")
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def pitr_window(output):
    """Show the restorable time window for the cluster."""
    _cluster_id = _resolve_db_cluster_identifier()
    _rds = _resolve_client(get_rds_client())
    _cluster = _describe_source(_rds, _cluster_id)

    _earliest = _cluster.get("EarliestRestorableTime")
    _latest = _cluster.get("LatestRestorableTime")
    _retention = _cluster.get("BackupRetentionPeriod")

    _span_hours = None
    if Validators.exist(_earliest) and Validators.exist(_latest):
        _span = (_latest - _earliest).total_seconds() / 3600
        _cast = SocaCastEngine(round(_span, 1)).cast_as(float)
        _span_hours = _cast.get("message") if _cast.get("success") else None

    _payload = {
        "cluster": _cluster_id,
        "earliest_restorable_time": _cast_str(_earliest)[:19],
        "latest_restorable_time": _cast_str(_latest)[:19],
        "backup_retention_days": _retention,
        "window_hours": _span_hours,
    }

    if output == "json":
        _echo_json(_payload)
        return

    click.echo(f"Cluster:            {_cluster_id}")
    click.echo(f"Retention:          {_retention} day(s)")
    click.echo(f"Earliest restore:   {_payload['earliest_restorable_time']} UTC")
    click.echo(f"Latest restore:     {_payload['latest_restorable_time']} UTC")
    if Validators.exist(_span_hours):
        click.echo(f"Window:             {_span_hours} hour(s)")
    click.echo(
        "\nAny second within this window is restorable. Use "
        "'edhctl db pitr restore' to restore to a new cluster."
    )


@pitr.command("restore")
@click.option(
    "--name",
    required=True,
    help="Suffix for the restored cluster identifier (alphanumeric + hyphens)",
)
@click.option(
    "--to",
    "restore_to",
    default=None,
    help="ISO-8601 restore target, e.g. 2026-08-26T14:30:00 (UTC assumed). Omit with --latest",
)
@click.option(
    "--latest",
    "use_latest",
    is_flag=True,
    default=False,
    help="Restore to the latest restorable time",
)
@click.option(
    "--restore-type",
    default="full-copy",
    type=click.Choice(["full-copy", "copy-on-write"]),
    help="full-copy is an independent volume, copy-on-write shares the source volume",
)
@click.option(
    "--wait/--no-wait", default=True, help="Wait for the restored cluster to be available"
)
@click.option(
    "--confirm",
    "skip_confirm",
    is_flag=True,
    default=False,
    help="Skip confirmation prompt",
)
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def pitr_restore(name, restore_to, use_latest, restore_type, wait, skip_confirm, output):
    """Restore the cluster to a point in time as a NEW cluster.

    Aurora cannot restore in place. This creates a separate cluster alongside
    the running one and leaves the live cluster untouched.
    """
    if use_latest and Validators.exist(restore_to):
        _error = SocaError.GENERIC_ERROR(helper="--to and --latest are mutually exclusive")
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    if not use_latest and not Validators.exist(restore_to):
        _error = SocaError.GENERIC_ERROR(helper="Specify either --to <timestamp> or --latest")
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    _cluster_id = _resolve_db_cluster_identifier()
    _rds = _resolve_client(get_rds_client())
    _source = _describe_source(_rds, _cluster_id)

    _target_id = f"{_cluster_id}-{name}" if not name.startswith(_cluster_id) else name

    _restore_time = None
    if not use_latest:
        _restore_time = _parse_restore_time(restore_to)
        _earliest = _source.get("EarliestRestorableTime")
        _latest = _source.get("LatestRestorableTime")
        if Validators.exist(_earliest) and _restore_time < _earliest:
            _error = SocaError.GENERIC_ERROR(
                helper=(
                    f"Requested restore time {_restore_time.isoformat()} is before the "
                    f"earliest restorable time {_earliest.isoformat()}"
                )
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)
        if Validators.exist(_latest) and _restore_time > _latest:
            _error = SocaError.GENERIC_ERROR(
                helper=(
                    f"Requested restore time {_restore_time.isoformat()} is after the "
                    f"latest restorable time {_latest.isoformat()}"
                )
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)

    _target_desc = "latest restorable time" if use_latest else _restore_time.isoformat()

    click.echo(f"Source cluster:  {_cluster_id}")
    click.echo(f"Restored as:     {_target_id}")
    click.echo(f"Restore point:   {_target_desc}")
    click.echo(f"Restore type:    {restore_type}")
    click.echo(
        "\nThe live cluster is not modified. The restored cluster is billed separately\n"
        "and is NOT tagged with this cluster's edh:ClusterId, so edhctl db commands\n"
        "continue to target the live cluster."
    )

    if not skip_confirm:
        if not confirm(f"Restore '{_cluster_id}' into new cluster '{_target_id}'?"):
            click.echo("Aborted.")
            return

    # Inherit placement and networking from the source rather than hardcoding
    _params = {
        "DBClusterIdentifier": _target_id,
        "SourceDBClusterIdentifier": _cluster_id,
        "RestoreType": restore_type,
        "DBSubnetGroupName": _source.get("DBSubnetGroup"),
        "VpcSecurityGroupIds": [
            sg.get("VpcSecurityGroupId") for sg in _source.get("VpcSecurityGroups", [])
        ],
        "CopyTagsToSnapshot": _source.get("CopyTagsToSnapshot", False),
        "Port": _source.get("Port"),
        # deliberately omit edh:ClusterId so the tag lookup cannot resolve to this clone
        "Tags": [
            {"Key": "Name", "Value": _target_id},
            {"Key": "edh:RestoredFrom", "Value": _cluster_id},
            {"Key": "edh:RestorePoint", "Value": _target_desc},
        ],
    }

    _serverless = _source.get("ServerlessV2ScalingConfiguration")
    if Validators.is_dict(_serverless):
        _params["ServerlessV2ScalingConfiguration"] = {
            "MinCapacity": _serverless.get("MinCapacity"),
            "MaxCapacity": _serverless.get("MaxCapacity"),
        }

    if use_latest:
        _params["UseLatestRestorableTime"] = True
    else:
        _params["RestoreToTime"] = _restore_time

    logger.info(f"Restoring {_cluster_id} to {_target_desc} as {_target_id}")
    click.echo(f"\nRestoring cluster {_target_id}...")
    try:
        _restored = _rds.restore_db_cluster_to_point_in_time(**_params)["DBCluster"]
    except Exception as err:
        _error = SocaError.AWS_API_ERROR(
            service_name="rds",
            helper=f"Failed to restore '{_cluster_id}' into '{_target_id}': {err}",
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    # A restored Aurora cluster has no instances; the writer must be added explicitly
    _writer_id = f"{_target_id}-writer"
    _writer_class = _source_writer_class(_rds, _source)

    click.echo(f"Creating writer instance {_writer_id} ({_writer_class})...")
    try:
        _rds.create_db_instance(
            DBInstanceIdentifier=_writer_id,
            DBClusterIdentifier=_target_id,
            DBInstanceClass=_writer_class,
            Engine=_source.get("Engine"),
            PubliclyAccessible=False,
        )
    except Exception as err:
        _error = SocaError.AWS_API_ERROR(
            service_name="rds",
            helper=(
                f"Cluster '{_target_id}' was restored but the writer instance "
                f"'{_writer_id}' could not be created: {err}. The cluster exists with "
                f"no instance and must be completed or deleted manually"
            ),
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    _endpoint = _restored.get("Endpoint")
    if wait:
        click.echo("Waiting for the writer instance to become available...", nl=False)
        try:
            _rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=_writer_id)
        except Exception as err:
            click.echo("")
            _error = SocaError.AWS_API_ERROR(
                service_name="rds",
                helper=f"Writer '{_writer_id}' did not become available: {err}",
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)
        click.echo(" done.")
        _refreshed = _describe_source(_rds, _target_id)
        _endpoint = _refreshed.get("Endpoint")

    logger.info(f"Restored cluster {_target_id} endpoint {_endpoint}")

    _payload = {
        "restored_cluster": _target_id,
        "writer_instance": _writer_id,
        "source_cluster": _cluster_id,
        "restore_point": _target_desc,
        "restore_type": restore_type,
        "endpoint": _endpoint,
        "port": _source.get("Port"),
        "status": "available" if wait else _restored.get("Status"),
    }

    if output == "json":
        _echo_json(_payload)
        return

    click.echo("")
    click.echo(f"Restored cluster: {_target_id}")
    click.echo(f"Writer:           {_writer_id}")
    click.echo(f"Endpoint:         {_endpoint}:{_source.get('Port')}")
    click.echo(f"Status:           {_payload['status']}")
    click.echo(
        f"\nThe restored cluster uses the same DatabaseAdminSecret credentials as "
        f"{_cluster_id}.\nIt is not wired into this cluster. To promote it, repoint the "
        f"cluster's database\nendpoint configuration at the new cluster and restart the "
        f"web interface.\n\nRemember to delete '{_target_id}' when you are finished with it."
    )
