# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import click

from commands.db.common import _echo_json, _format_bytes, db_connection
from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")


@click.command("table-sizes")
@click.option("--top", type=int, default=15, help="Number of tables to show")
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def table_sizes(top, output):
    """Show largest tables by total size."""
    logger.debug(f"Listing top {top} tables by total relation size")
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT schemaname, relname, n_live_tup, n_dead_tup,
                   pg_total_relation_size(quote_ident(schemaname)||'.'||quote_ident(relname)) as total_bytes
            FROM pg_stat_user_tables
            ORDER BY pg_total_relation_size(quote_ident(schemaname)||'.'||quote_ident(relname)) DESC
            LIMIT %s
            """,
            (top,),
        )
        _rows = cur.fetchall()

    _results = [
        {
            "schema": r[0],
            "table": r[1],
            "live_tuples": r[2],
            "dead_tuples": r[3],
            "total_bytes": r[4],
            "total_human": _format_bytes(r[4]),
        }
        for r in _rows
    ]

    if output == "json":
        _echo_json(_results)
        return

    click.echo(f"{'Table':<35s} {'Live':>8s} {'Dead':>6s} {'Size':>10s}")
    click.echo("-" * 62)
    for r in _results:
        click.echo(
            f"{r['table']:<35s} {r['live_tuples']:>8d} {r['dead_tuples']:>6d} {r['total_human']:>10s}"
        )


@click.command()
@click.option("--top", type=int, default=10, help="Number of tables to show")
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def bloat(top, output):
    """Show tables with dead tuples (bloat candidates for VACUUM)."""
    logger.debug(f"Listing top {top} tables by dead tuple count")
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT relname, n_live_tup, n_dead_tup,
                   CASE WHEN n_live_tup > 0
                        THEN round(100.0 * n_dead_tup / n_live_tup, 1)
                        ELSE 0 END as dead_pct
            FROM pg_stat_user_tables
            WHERE n_dead_tup > 0
            ORDER BY n_dead_tup DESC
            LIMIT %s
            """,
            (top,),
        )
        _rows = cur.fetchall()

    _results = []
    for r in _rows:
        _cast = SocaCastEngine(r[3]).cast_as(float)
        _results.append(
            {
                "table": r[0],
                "live_tuples": r[1],
                "dead_tuples": r[2],
                "dead_pct": _cast.get("message") if _cast.get("success") else 0.0,
            }
        )

    if output == "json":
        _echo_json(_results)
        return

    if not _results:
        click.echo("No dead tuples detected. Database is clean.")
        return

    click.echo(f"{'Table':<35s} {'Live':>8s} {'Dead':>6s} {'Ratio':>8s}")
    click.echo("-" * 60)
    for r in _results:
        click.echo(
            f"{r['table']:<35s} {r['live_tuples']:>8d} {r['dead_tuples']:>6d} {r['dead_pct']:>7.1f}%"
        )
    click.echo("\nRun 'edhctl db vacuum' to clean up dead tuples.")
