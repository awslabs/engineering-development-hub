# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import click

from commands.db.common import _echo_json, db_connection

logger = logging.getLogger("soca_logger")


@click.command()
@click.option(
    "--idle-threshold",
    type=int,
    default=0,
    help="Only show connections idle longer than N seconds",
)
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def connections(idle_threshold, output):
    """Show active database connections grouped by state and user."""
    logger.debug(f"Listing client connections, idle_threshold={idle_threshold}")
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT state, usename, count(*),
                   max(extract(epoch from now()-state_change))::int as max_idle_s
            FROM pg_stat_activity
            WHERE backend_type='client backend'
            GROUP BY state, usename
            ORDER BY count DESC
            """
        )
        _rows = cur.fetchall()

        cur.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'"
        )
        _total = cur.fetchone()[0]

    _results = [
        {
            "state": r[0] or "NULL",
            "user": r[1] or "N/A",
            "count": r[2],
            "max_idle_seconds": r[3] or 0,
        }
        for r in _rows
    ]

    if idle_threshold > 0:
        _results = [r for r in _results if r["max_idle_seconds"] >= idle_threshold]

    if output == "json":
        _echo_json({"connections": _results, "total": _total})
        return

    click.echo(f"{'STATE':<12s} {'USER':<16s} {'COUNT':>5s} {'MAX_IDLE':>10s}")
    click.echo("-" * 48)
    for r in _results:
        click.echo(
            f"{r['state']:<12s} {r['user']:<16s} {r['count']:>5d} {r['max_idle_seconds']:>8d}s"
        )
    click.echo("-" * 48)
    click.echo(f"Total connections: {_total}")
