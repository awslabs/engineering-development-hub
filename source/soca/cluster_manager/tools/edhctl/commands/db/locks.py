# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import click

from commands.db.common import _echo_json, db_connection

logger = logging.getLogger("soca_logger")


@click.command()
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def locks(output):
    """Show blocking lock chains (if any)."""
    logger.debug("Querying blocking lock chains")
    with db_connection() as conn:
        cur = conn.cursor()
        # ORDER BY before LIMIT so the longest waiters are never dropped
        cur.execute(
            """
            SELECT
                blocked.pid AS blocked_pid,
                blocked.usename AS blocked_user,
                substring(blocked.query, 1, 80) AS blocked_query,
                blocked.wait_event_type,
                blocking.pid AS blocking_pid,
                blocking.usename AS blocking_user,
                substring(blocking.query, 1, 80) AS blocking_query,
                extract(epoch from now() - blocked.state_change)::int AS wait_seconds
            FROM pg_stat_activity AS blocked
            JOIN pg_locks AS bl ON bl.pid = blocked.pid
            JOIN pg_locks AS kl
                ON kl.locktype = bl.locktype
                AND kl.relation = bl.relation
                AND kl.pid != bl.pid
                AND kl.granted
            JOIN pg_stat_activity AS blocking ON blocking.pid = kl.pid
            WHERE NOT bl.granted
            ORDER BY wait_seconds DESC
            LIMIT 20
            """
        )
        _rows = cur.fetchall()

    _results = [
        {
            "blocked_pid": r[0],
            "blocked_user": r[1],
            "blocked_query": r[2],
            "wait_event_type": r[3],
            "blocking_pid": r[4],
            "blocking_user": r[5],
            "blocking_query": r[6],
            "wait_seconds": r[7],
        }
        for r in _rows
    ]

    if output == "json":
        _echo_json(_results)
        return

    if not _results:
        click.echo("No blocking locks.")
        return

    logger.info(f"{len(_results)} blocking lock chain(s) detected")
    click.echo(
        f"{'Blocked PID':<12s} {'User':<12s} {'By PID':<8s} {'By User':<12s} {'Wait':>6s} Query"
    )
    click.echo("-" * 80)
    for r in _results:
        click.echo(
            f"{r['blocked_pid']:<12d} {r['blocked_user']:<12s} "
            f"{r['blocking_pid']:<8d} {r['blocking_user']:<12s} "
            f"{r['wait_seconds']:>5d}s {r['blocked_query'][:40]}"
        )
