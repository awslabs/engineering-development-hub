# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import click

from commands.common import confirm
from commands.db.common import _cast_str, _echo_json, db_connection

logger = logging.getLogger("soca_logger")


@click.command()
@click.option("--table", default=None, help="Specific table to vacuum (default: all)")
@click.option(
    "--full",
    is_flag=True,
    default=False,
    help="Run VACUUM FULL (reclaims disk, locks table)",
)
@click.option(
    "--analyze/--no-analyze",
    default=True,
    help="Update planner statistics (default: yes)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be vacuumed without doing it",
)
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def vacuum(table, full, analyze, dry_run, output):
    """Run VACUUM on database tables to reclaim dead tuples."""
    with db_connection() as conn:
        conn.autocommit = True
        cur = conn.cursor()

        if table:
            _targets = [table]
        else:
            cur.execute(
                """
                SELECT relname FROM pg_stat_user_tables
                WHERE n_dead_tup > 0
                ORDER BY n_dead_tup DESC
                """
            )
            _targets = [r[0] for r in cur.fetchall()]

        if not _targets:
            click.echo("No tables with dead tuples. Nothing to vacuum.")
            return

        logger.debug(
            f"Vacuum targets={len(_targets)} full={full} analyze={analyze} dry_run={dry_run}"
        )

        if full and not dry_run:
            click.echo("WARNING: VACUUM FULL locks each table exclusively during operation.")
            if not confirm("Proceed with VACUUM FULL?"):
                click.echo("Aborted.")
                return

        _results = []
        for _table in _targets:
            _parts = ["VACUUM"]
            if full:
                _parts.append("FULL")
            if analyze:
                _parts.append("ANALYZE")
            _parts.append(f'"{_table}"')
            _sql = " ".join(_parts)

            if dry_run:
                _results.append({"table": _table, "sql": _sql, "status": "dry-run"})
                if output == "text":
                    click.echo(f"  [dry-run] {_sql}")
                continue

            logger.debug(f"Executing: {_sql}")
            try:
                cur.execute(_sql)
                _results.append({"table": _table, "sql": _sql, "status": "ok"})
                logger.info(f"Vacuumed table {_table} (full={full}, analyze={analyze})")
                if output == "text":
                    click.echo(f"  OK {_sql}")
            except Exception as err:
                logger.error(f"Vacuum failed on table {_table}: {err}")
                _results.append(
                    {"table": _table, "sql": _sql, "status": "error", "error": _cast_str(err)}
                )
                if output == "text":
                    click.echo(f"  FAILED {_sql}: {err}")

    if output == "json":
        _echo_json({"vacuumed": _results, "dry_run": dry_run})
        return

    if not dry_run:
        _ok_count = sum(1 for r in _results if r["status"] == "ok")
        click.echo(f"\nVacuumed {_ok_count}/{len(_targets)} table(s).")
