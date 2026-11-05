# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Table-level export and import for cluster migration.

pg_dump is deliberately not used: the controller ships a PostgreSQL 15 client
while Aurora runs 17.x, and pg_dump hard-refuses a newer server. These commands
use psycopg COPY, which is version tolerant, and CSV, which merges into an
existing cluster instead of replacing its schema.
"""

import csv
import logging
import os
import sys
from datetime import datetime, timezone

import click
import psycopg
from psycopg import sql

from commands.common import confirm, get_cluster_id
from commands.db.common import (
    _cast_str,
    _echo_json,
    db_connection,
)
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.error import SocaError
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1

# Tables whose rows carry region-scoped AMI identifiers. Importing these into a
# different region leaves dangling image references.
_AMI_BEARING_TABLES = ("software_stacks", "base_image_registry", "vdi_saved_images")


def _list_tables(conn) -> list:
    """Return all base table names in the public schema."""
    with conn.cursor() as _cur:
        _cur.execute(
            """
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            ORDER BY table_name
            """
        )
        return [r[0] for r in _cur.fetchall()]


def _table_columns(conn, table: str) -> list:
    """Return ordered column names for a table."""
    with conn.cursor() as _cur:
        _cur.execute(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table,),
        )
        return [r[0] for r in _cur.fetchall()]


def _table_primary_key(conn, table: str) -> list:
    """Return the primary key column names for a table, in key order."""
    with conn.cursor() as _cur:
        _cur.execute(
            """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON kcu.constraint_name = tc.constraint_name
             AND kcu.table_schema = tc.table_schema
            WHERE tc.table_schema = 'public'
              AND tc.table_name = %s
              AND tc.constraint_type = 'PRIMARY KEY'
            ORDER BY kcu.ordinal_position
            """,
            (table,),
        )
        return [r[0] for r in _cur.fetchall()]


def _table_row_count(conn, table: str) -> int:
    """Return the exact row count for a table."""
    with conn.cursor() as _cur:
        _cur.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table)))
        return _cur.fetchone()[0]


def _resolve_tables(conn, tables: str, exclude: str) -> list:
    """Resolve the effective table set from --tables and --exclude."""
    _all = _list_tables(conn)

    if Validators.exist(tables):
        _requested = [t.strip() for t in tables.split(",") if Validators.exist(t.strip())]
        _unknown = [t for t in _requested if t not in _all]
        if Validators.is_list_not_empty(_unknown):
            _error = SocaError.GENERIC_ERROR(
                helper=f"Unknown table(s): {', '.join(_unknown)}"
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)
        _selected = _requested
    else:
        _selected = _all

    if Validators.exist(exclude):
        _excluded = [t.strip() for t in exclude.split(",") if Validators.exist(t.strip())]
        _selected = [t for t in _selected if t not in _excluded]

    return _selected


def _edh_version() -> str:
    """Best-effort EDH version for the manifest."""
    _version = SocaConfig(key="/configuration/Version").get_value()
    if _version.get("success") is True:
        return _cast_str(_version.get("message"))
    logger.debug("Unable to resolve /configuration/Version for the export manifest")
    return "unknown"


def _current_region() -> str:
    """Best-effort region for the manifest region guard."""
    _region = SocaConfig(key="/configuration/Region").get_value()
    if _region.get("success") is True:
        return _cast_str(_region.get("message"))
    return _cast_str(os.environ.get("AWS_DEFAULT_REGION", "unknown"))


def _write_manifest(path: str, payload: dict) -> None:
    """Serialize the manifest to disk."""
    _serialized = SocaCastEngine(payload).serialize_json(indent=2)
    if _serialized.get("success") is False:
        _error = SocaError.GENERIC_ERROR(
            helper=f"Unable to serialize the export manifest: {_serialized.get('message')}"
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)
    try:
        _fd_num = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(_fd_num, "w", encoding="utf-8") as _fd:
            _fd.write(_serialized.get("message"))
    except OSError as err:
        _error = SocaError.GENERIC_ERROR(helper=f"Unable to write {path}: {err}")
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)


def _read_manifest(path: str) -> dict:
    """Load and validate an export manifest."""
    if not os.path.isfile(path):
        _error = SocaError.GENERIC_ERROR(
            helper=f"No {MANIFEST_NAME} found at {path}. Is this an edhctl db export directory?"
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as _fd:
        _raw = _fd.read()

    _parsed = SocaCastEngine(_raw).as_json()
    if _parsed.get("success") is False:
        _error = SocaError.GENERIC_ERROR(
            helper=f"{MANIFEST_NAME} is not valid JSON: {_parsed.get('message')}"
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    _manifest = _parsed.get("message")
    if not Validators.is_dict(_manifest):
        _error = SocaError.GENERIC_ERROR(helper=f"{MANIFEST_NAME} is not a JSON object")
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    _version = SocaCastEngine(_manifest.get("manifest_version")).cast_as(int)
    if _version.get("success") is False or _version.get("message") > MANIFEST_VERSION:
        _error = SocaError.GENERIC_ERROR(
            helper=(
                f"{MANIFEST_NAME} declares manifest_version "
                f"{_manifest.get('manifest_version')}, this edhctl supports up to "
                f"{MANIFEST_VERSION}. Upgrade edhctl on this cluster before importing"
            )
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    return _manifest


@click.command("export")
@click.option(
    "--dest",
    default=None,
    help=(
        "Destination directory. Defaults to a controller-local path under "
        "/opt/edh/<cluster_id>/cluster_manager/web_interface/db_exports/<timestamp>"
    ),
)
@click.option(
    "--tables",
    default=None,
    help="Comma-separated table list. Default is every table in the database",
)
@click.option(
    "--exclude", default=None, help="Comma-separated tables to omit from the export"
)
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def db_export(dest, tables, exclude, output):
    """Export cluster tables to CSV for migration.

    Exports every table by default, including session history and single-use
    tokens, so a restored cluster is a faithful copy. Primary key values are
    preserved verbatim; the schema has no foreign keys, so the integer ids in
    the join tables are the only thing tying related rows together.
    """
    _cluster_id = get_cluster_id()

    if not Validators.exist(dest):
        _stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # controller-local, not the shared filesystem: the export carries token
        # hashes and audit history, and a cross-cluster import cannot read this
        # cluster's /apps anyway, so sharing bought exposure and nothing else
        dest = (
            f"/opt/edh/{_cluster_id}/cluster_manager/web_interface/db_exports/{_stamp}"
        )

    try:
        os.makedirs(dest, exist_ok=True)
        # chmod after creation because makedirs' mode is umask-masked and is
        # ignored entirely when the directory already exists
        os.chmod(dest, 0o700)
    except OSError as err:
        _error = SocaError.GENERIC_ERROR(
            helper=f"Unable to create export directory {dest}: {err}"
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    _results = []
    _total_rows = 0

    with db_connection() as _conn:
        _selected = _resolve_tables(_conn, tables, exclude)
        if not Validators.is_list_not_empty(_selected):
            _error = SocaError.GENERIC_ERROR(
                helper="No tables selected for export after applying --tables/--exclude"
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)

        click.echo(f"Exporting {len(_selected)} table(s) from {_cluster_id} to {dest}")

        _sequences = {}
        for _table in _selected:
            _columns = _table_columns(_conn, _table)
            _pk = _table_primary_key(_conn, _table)
            _rows = _table_row_count(_conn, _table)
            _csv_path = os.path.join(dest, f"{_table}.csv")

            try:
                with _conn.cursor() as _cur:
                    # mode set atomically at creation: a mid-write failure must
                    # never leave token hashes readable at the default mode
                    _fd_num = os.open(
                        _csv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                    )
                    with open(_fd_num, "wb") as _fd:
                        _copy = sql.SQL(
                            "COPY {} TO STDOUT WITH (FORMAT csv, HEADER true)"
                        ).format(sql.Identifier(_table))
                        with _cur.copy(_copy) as _stream:
                            for _chunk in _stream:
                                _fd.write(_chunk)
            except psycopg.Error as err:
                _error = SocaError.DB_ERROR(
                    query=f"COPY {_table} TO STDOUT",
                    helper=f"Failed to export table '{_table}': {err}",
                )
                click.echo(f"Error: {_error.get('message')}", err=True)
                sys.exit(1)
            except OSError as err:
                _error = SocaError.GENERIC_ERROR(
                    helper=(
                        f"Unable to write {_csv_path}: {err}. A partial export may "
                        f"remain in {dest}"
                    )
                )
                click.echo(f"Error: {_error.get('message')}", err=True)
                sys.exit(1)

            # capture sequence positions so an import can report drift
            for _column in _columns:
                with _conn.cursor() as _cur:
                    _cur.execute(
                        """
                        SELECT s.schemaname || '.' || s.sequencename, s.last_value
                        FROM pg_sequences s
                        WHERE s.schemaname || '.' || s.sequencename
                              = pg_get_serial_sequence(%s, %s)
                        """,
                        (_table, _column),
                    )
                    _row = _cur.fetchone()
                    if Validators.exist(_row):
                        _sequences[_row[0]] = {
                            "table": _table,
                            "column": _column,
                            "last_value": _row[1],
                        }

            _total_rows += _rows
            _results.append(
                {
                    "table": _table,
                    "rows": _rows,
                    "columns": _columns,
                    "primary_key": _pk,
                    "file": f"{_table}.csv",
                    "bytes": os.path.getsize(_csv_path),
                }
            )
            click.echo(f"  {_table:<45s} {_rows:>8d} row(s)")

        _engine_version = ""
        with _conn.cursor() as _cur:
            _cur.execute("SHOW server_version")
            _engine_version = _cast_str(_cur.fetchone()[0])

    _manifest = {
        "manifest_version": MANIFEST_VERSION,
        "cluster_id": _cluster_id,
        "region": _current_region(),
        "edh_version": _edh_version(),
        "postgres_version": _engine_version,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_rows": _total_rows,
        "tables": _results,
        "sequences": _sequences,
    }
    _write_manifest(os.path.join(dest, MANIFEST_NAME), _manifest)

    logger.info(
        f"Exported {len(_results)} table(s) / {_total_rows} row(s) "
        f"from {_cluster_id} to {dest}"
    )

    if output == "json":
        _echo_json(_manifest)
        return

    click.echo("")
    click.echo(f"Tables:   {len(_results)}")
    click.echo(f"Rows:     {_total_rows}")
    click.echo(f"Location: {dest}")
    click.echo(f"Manifest: {os.path.join(dest, MANIFEST_NAME)}")
    click.echo(
        f"\nImport into another cluster with:\n"
        f"  edhctl db import --src {dest}"
    )


def _csv_header(path: str) -> list:
    """Read the column header from an exported CSV."""
    with open(path, "r", encoding="utf-8", newline="") as _fd:
        _reader = csv.reader(_fd)
        try:
            return next(_reader)
        except StopIteration:
            return []


def _column_types(conn, table: str) -> dict:
    """Map column name to its formatted PostgreSQL type for explicit casting."""
    with conn.cursor() as _cur:
        _cur.execute(
            """
            SELECT a.attname, format_type(a.atttypid, a.atttypmod)
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = %s
              AND a.attnum > 0 AND NOT a.attisdropped
            """,
            (table,),
        )
        return {r[0]: r[1] for r in _cur.fetchall()}


def _import_table(conn, table: str, csv_path: str, mode: str, pk: list) -> dict:
    """Load one CSV into a table, preserving primary key values. Returns a report."""
    _source_columns = _csv_header(csv_path)
    if not Validators.is_list_not_empty(_source_columns):
        return {"table": table, "loaded": 0, "skipped": "empty file"}

    _target_columns = _table_columns(conn, table)
    _types = _column_types(conn, table)

    _shared = [c for c in _source_columns if c in _target_columns]
    _dropped = [c for c in _source_columns if c not in _target_columns]
    _added = [c for c in _target_columns if c not in _source_columns]

    if not Validators.is_list_not_empty(_shared):
        return {
            "table": table,
            "loaded": 0,
            "skipped": "no columns in common with the target schema",
        }

    # Stage into a text-typed temp table so schema drift between versions is
    # tolerated: only the intersecting columns are projected into the target.
    _staging = f"_edh_import_{table}"
    with conn.cursor() as _cur:
        _cur.execute(
            sql.SQL("CREATE TEMP TABLE {} ({}) ON COMMIT DROP").format(
                sql.Identifier(_staging),
                sql.SQL(", ").join(
                    sql.SQL("{} text").format(sql.Identifier(c)) for c in _source_columns
                ),
            )
        )

        _copy = sql.SQL("COPY {} FROM STDIN WITH (FORMAT csv, HEADER true)").format(
            sql.Identifier(_staging)
        )
        with open(csv_path, "rb") as _fd:
            with _cur.copy(_copy) as _stream:
                while True:
                    _chunk = _fd.read(1024 * 256)
                    if not _chunk:
                        break
                    _stream.write(_chunk)

        if mode == "replace":
            _cur.execute(
                sql.SQL("TRUNCATE TABLE {} RESTART IDENTITY").format(sql.Identifier(table))
            )

        _projection = sql.SQL(", ").join(
            sql.SQL("{}::{}").format(sql.Identifier(c), sql.SQL(_types.get(c, "text")))
            for c in _shared
        )
        _insert = sql.SQL("INSERT INTO {} ({}) SELECT {} FROM {}").format(
            sql.Identifier(table),
            sql.SQL(", ").join(sql.Identifier(c) for c in _shared),
            _projection,
            sql.Identifier(_staging),
        )

        _conflict_target = [c for c in pk if c in _shared]
        if mode == "upsert" and Validators.is_list_not_empty(_conflict_target):
            _updatable = [c for c in _shared if c not in _conflict_target]
            if Validators.is_list_not_empty(_updatable):
                _insert = sql.SQL("{} ON CONFLICT ({}) DO UPDATE SET {}").format(
                    _insert,
                    sql.SQL(", ").join(sql.Identifier(c) for c in _conflict_target),
                    sql.SQL(", ").join(
                        sql.SQL("{} = EXCLUDED.{}").format(
                            sql.Identifier(c), sql.Identifier(c)
                        )
                        for c in _updatable
                    ),
                )
            else:
                _insert = sql.SQL("{} ON CONFLICT ({}) DO NOTHING").format(
                    _insert,
                    sql.SQL(", ").join(sql.Identifier(c) for c in _conflict_target),
                )
        elif mode == "upsert":
            # no usable primary key in the payload, fall back to skip-on-conflict
            _insert = sql.SQL("{} ON CONFLICT DO NOTHING").format(_insert)

        _cur.execute(_insert)
        _loaded = _cur.rowcount

    return {
        "table": table,
        "loaded": _loaded,
        "columns_ignored": _dropped,
        "columns_defaulted": _added,
    }


def _reset_sequences(conn, tables: list) -> list:
    """Realign every serial sequence to max(column) so new inserts do not collide."""
    _reset = []
    for _table in tables:
        for _column in _table_columns(conn, _table):
            with conn.cursor() as _cur:
                _cur.execute("SELECT pg_get_serial_sequence(%s, %s)", (_table, _column))
                _seq = _cur.fetchone()[0]
                if not Validators.exist(_seq):
                    continue
                _cur.execute(
                    sql.SQL(
                        "SELECT setval(%s, GREATEST(COALESCE(max({}), 0), 1), "
                        "max({}) IS NOT NULL) FROM {}"
                    ).format(
                        sql.Identifier(_column),
                        sql.Identifier(_column),
                        sql.Identifier(_table),
                    ),
                    (_seq,),
                )
                _reset.append({"sequence": _seq, "value": _cur.fetchone()[0]})
    return _reset


@click.command("import")
@click.option("--src", required=True, help="Export directory produced by 'edhctl db export'")
@click.option(
    "--tables",
    default=None,
    help="Comma-separated table list. Default is every table present in the export",
)
@click.option("--exclude", default=None, help="Comma-separated tables to skip")
@click.option(
    "--mode",
    default="upsert",
    type=click.Choice(["upsert", "replace"]),
    help="upsert merges on primary key, replace truncates the target table first",
)
@click.option(
    "--allow-region-mismatch",
    is_flag=True,
    default=False,
    help="Import even when the export came from a different region (AMI ids will dangle)",
)
@click.option("--dry-run", is_flag=True, default=False, help="Report the plan and exit")
@click.option(
    "--confirm",
    "skip_confirm",
    is_flag=True,
    default=False,
    help="Skip confirmation prompt",
)
@click.option("--output", default="text", type=click.Choice(["text", "json"]))
def db_import(src, tables, exclude, mode, allow_region_mismatch, dry_run, skip_confirm, output):
    """Import an export produced by 'edhctl db export'.

    Primary key values are preserved so the join tables keep pointing at the
    right rows, and every serial sequence is realigned afterwards. Columns
    present in the export but absent from the target schema are ignored, and
    new columns take their schema default, so an export from an older EDH
    version imports into a newer one.
    """
    _cluster_id = get_cluster_id()
    _manifest = _read_manifest(os.path.join(src, MANIFEST_NAME))

    _source_cluster = _cast_str(_manifest.get("cluster_id"))
    _source_region = _cast_str(_manifest.get("region"))
    _target_region = _current_region()

    _manifest_tables = _manifest.get("tables", [])
    if not Validators.is_list_not_empty(_manifest_tables):
        _error = SocaError.GENERIC_ERROR(helper=f"{MANIFEST_NAME} lists no tables")
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    _by_name = {t.get("table"): t for t in _manifest_tables}
    _selected = list(_by_name.keys())

    if Validators.exist(tables):
        _requested = [t.strip() for t in tables.split(",") if Validators.exist(t.strip())]
        _missing = [t for t in _requested if t not in _by_name]
        if Validators.is_list_not_empty(_missing):
            _error = SocaError.GENERIC_ERROR(
                helper=f"Table(s) not present in the export: {', '.join(_missing)}"
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)
        _selected = _requested

    if Validators.exist(exclude):
        _excluded = [t.strip() for t in exclude.split(",") if Validators.exist(t.strip())]
        _selected = [t for t in _selected if t not in _excluded]

    if not Validators.is_list_not_empty(_selected):
        _error = SocaError.GENERIC_ERROR(
            helper="No tables selected for import after applying --tables/--exclude"
        )
        click.echo(f"Error: {_error.get('message')}", err=True)
        sys.exit(1)

    _region_mismatch = (
        Validators.exist(_source_region)
        and Validators.exist(_target_region)
        and not Validators.is_string_equal(_source_region, _target_region)
        and not Validators.is_string_equal(_source_region, "unknown")
        and not Validators.is_string_equal(_target_region, "unknown")
    )
    _ami_tables = [t for t in _selected if t in _AMI_BEARING_TABLES]

    click.echo(f"Source export:  {_source_cluster} ({_source_region})")
    click.echo(f"Target cluster: {_cluster_id} ({_target_region})")
    click.echo(f"EDH version:    {_cast_str(_manifest.get('edh_version'))} -> {_edh_version()}")
    click.echo(f"Mode:           {mode}")
    click.echo(f"Tables:         {len(_selected)}")

    if _region_mismatch:
        click.echo("")
        click.echo(
            f"Region mismatch: the export was taken in {_source_region}, this cluster is "
            f"in {_target_region}."
        )
        if Validators.is_list_not_empty(_ami_tables):
            click.echo(
                f"AMI ids in {', '.join(_ami_tables)} are region scoped and will not "
                f"resolve here."
            )
        if not allow_region_mismatch and not dry_run:
            _error = SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to import a {_source_region} export into {_target_region}. "
                    f"Re-run with --allow-region-mismatch to proceed anyway, or exclude "
                    f"the AMI bearing tables with "
                    f"--exclude {','.join(_AMI_BEARING_TABLES)}"
                )
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)
        if dry_run and not allow_region_mismatch:
            # a dry run writes nothing, so report the plan and let the guard fire
            # on the real invocation instead
            click.echo(
                "A real import would be refused without --allow-region-mismatch."
            )
        elif allow_region_mismatch:
            logger.warning(
                f"Importing a {_source_region} export into {_target_region} with "
                f"--allow-region-mismatch"
            )

    if dry_run:
        _plan = [
            {
                "table": t,
                "rows_in_export": _by_name.get(t, {}).get("rows"),
                "file": _by_name.get(t, {}).get("file"),
            }
            for t in _selected
        ]
        if output == "json":
            _echo_json({"dry_run": True, "mode": mode, "plan": _plan})
            return
        click.echo("")
        for _entry in _plan:
            click.echo(f"  {_entry['table']:<45s} {_cast_str(_entry['rows_in_export']):>8s} row(s)")
        click.echo("\nDry run, nothing was written.")
        return

    if mode == "replace":
        click.echo(
            f"\n'replace' TRUNCATEs each target table before loading. Existing rows in "
            f"{len(_selected)} table(s) on {_cluster_id} will be destroyed."
        )

    if not skip_confirm:
        if not confirm(f"Import {len(_selected)} table(s) into '{_cluster_id}'?"):
            click.echo("Aborted.")
            return

    _reports = []
    _loaded_total = 0

    with db_connection() as _conn:
        _existing = _list_tables(_conn)
        for _table in _selected:
            if _table not in _existing:
                logger.warning(f"Table {_table} is in the export but not in the target schema")
                _reports.append(
                    {"table": _table, "loaded": 0, "skipped": "not present in target schema"}
                )
                continue

            _csv_path = os.path.join(src, _by_name.get(_table, {}).get("file", f"{_table}.csv"))
            if not os.path.isfile(_csv_path):
                _reports.append({"table": _table, "loaded": 0, "skipped": "csv file missing"})
                continue

            _pk = _table_primary_key(_conn, _table)
            try:
                _report = _import_table(_conn, _table, _csv_path, mode, _pk)
            except psycopg.Error as err:
                _conn.rollback()
                _error = SocaError.DB_ERROR(
                    query=f"COPY {_table} FROM STDIN",
                    helper=(
                        f"Failed to import table '{_table}': {err}. The transaction was "
                        f"rolled back and no tables were modified"
                    ),
                )
                click.echo(f"Error: {_error.get('message')}", err=True)
                sys.exit(1)

            _reports.append(_report)
            _loaded_total += _report.get("loaded", 0)
            _detail = ""
            if Validators.is_list_not_empty(_report.get("columns_ignored", [])):
                _detail = f"  (ignored: {', '.join(_report['columns_ignored'])})"
            click.echo(f"  {_table:<45s} {_report.get('loaded', 0):>8d} row(s){_detail}")

        # sequences must be realigned or the next insert collides with an imported id
        _processed = [r["table"] for r in _reports if not Validators.exist(r.get("skipped"))]
        try:
            _sequences = _reset_sequences(_conn, _processed)
            _conn.commit()
        except psycopg.Error as err:
            _conn.rollback()
            _error = SocaError.DB_ERROR(
                query="setval(pg_get_serial_sequence(...))",
                helper=(
                    f"Failed to finalize the import: {err}. The transaction was "
                    f"rolled back and no tables were modified"
                ),
            )
            click.echo(f"Error: {_error.get('message')}", err=True)
            sys.exit(1)

    logger.info(
        f"Imported {_loaded_total} row(s) across {len(_reports)} table(s) into {_cluster_id} "
        f"from {src} in {mode} mode"
    )

    _payload = {
        "target_cluster": _cluster_id,
        "source_cluster": _source_cluster,
        "mode": mode,
        "rows_loaded": _loaded_total,
        "tables": _reports,
        "sequences_reset": len(_sequences),
    }

    if output == "json":
        _echo_json(_payload)
        return

    click.echo("")
    click.echo(f"Rows loaded:      {_loaded_total}")
    click.echo(f"Sequences reset:  {len(_sequences)}")
    click.echo(
        "\nRestart the web interface so cached configuration reflects the imported rows."
    )
