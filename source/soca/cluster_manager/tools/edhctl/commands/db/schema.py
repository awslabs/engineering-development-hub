# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import click

from commands.db.common import _echo_json, db_connection

logger = logging.getLogger("soca_logger")


@click.command()
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def schema(output):
    """Show database schema summary (tables, version)."""
    logger.debug("Retrieving database schema summary")
    with db_connection() as conn:
        cur = conn.cursor()

        cur.execute(
            """
            SELECT tablename FROM pg_tables
            WHERE schemaname = 'public'
            ORDER BY tablename
            """
        )
        _tables = [r[0] for r in cur.fetchall()]

        _version = None
        try:
            cur.execute("SELECT version_num FROM alembic_version LIMIT 1")
            _row = cur.fetchone()
            if _row:
                _version = _row[0]
        except Exception as err:
            # alembic_version is absent on clusters not using alembic migrations
            logger.debug(f"alembic_version not readable: {err}")
            conn.rollback()

        cur.execute("SELECT version()")
        _pg_version = cur.fetchone()[0]

    _info = {
        "postgres_version": _pg_version,
        "schema_version": _version,
        "table_count": len(_tables),
        "tables": _tables,
    }

    if output == "json":
        _echo_json(_info)
        return

    click.echo(f"PostgreSQL: {_pg_version}")
    if _version:
        click.echo(f"Schema version (alembic): {_version}")
    else:
        click.echo("Schema version: N/A (no alembic_version table)")
    click.echo(f"Tables ({len(_tables)}):")
    for i in range(0, len(_tables), 4):
        click.echo(f"  {', '.join(_tables[i : i + 4])}")
