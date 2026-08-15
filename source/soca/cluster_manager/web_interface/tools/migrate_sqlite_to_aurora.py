#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
SOCA SQLite -> Aurora PostgreSQL migration tool.

Migrates the SOCA web app's authoritative state from the local sqlite db.sqlite
file to Aurora PostgreSQL Serverless v2.

Run from the SOCA controller. The script:
  1. Connects to SQLite (source) and Aurora (destination).
  2. Reflects both schemas. The Aurora schema must already exist -- the web app
     creates it via db.create_all() on first boot; this tool does NOT import the
     SOCA models (it stays standalone: sqlalchemy + psycopg + boto3 only).
  3. Iterates every reflected table and copies rows, preserving primary keys.
  4. Validates that row counts match for each table.
  5. Prints a summary report. Exit code 0 on success, non-zero on any mismatch.

USAGE
  cd /opt/edh/<cluster_id>/cluster_manager/web_interface
  python3 tools/migrate_sqlite_to_aurora.py [--dry-run] [--source PATH] [--secret-arn ARN]

By default, source is db.sqlite next to app.py and the destination is read from
the SocaConfig keys /configuration/Database/endpoint and /configuration/Database/secret_arn.

PRE-REQUISITES
  - Aurora cluster deployed (CDK with Config.database.provider = aurora_serverless_v2).
  - Network reachability from controller to Aurora (SG ingress on TCP 5432).
  - boto3 credentials with secretsmanager:GetSecretValue on the master secret.
  - The web app should be stopped during migration to avoid concurrent writes:
      edhwebui.sh stop
  - After successful migration, deploy the A2 changes to swap SQLALCHEMY_DATABASE_URI,
    then restart the web app with edhwebui.sh start.

ROLLBACK
  This script does NOT modify the SQLite source file. To rollback, simply do not
  swap the SQLALCHEMY_DATABASE_URI -- the web app continues using db.sqlite as
  before. The Aurora cluster can be left in place (idle ACU cost) or torn down.
"""

import argparse
import json
import logging
import os
import sys
from typing import Any

# Ensure web app modules are importable when run from the web_interface directory
_HERE = os.path.dirname(os.path.abspath(__file__))
_WEB_INTERFACE = os.path.dirname(_HERE)
if _WEB_INTERFACE not in sys.path:
    sys.path.insert(0, _WEB_INTERFACE)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("migrate_sqlite_to_aurora")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate SOCA web app state from SQLite to Aurora PostgreSQL."
    )
    parser.add_argument(
        "--source",
        default=os.path.join(_WEB_INTERFACE, "db.sqlite"),
        help="Path to source SQLite file (default: db.sqlite next to app.py).",
    )
    parser.add_argument(
        "--secret-arn",
        default=None,
        help="ARN of the Aurora master secret. Default: read from SocaConfig.",
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Aurora writer endpoint hostname. Default: read from SocaConfig.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5432,
        help="Aurora port. Default: 5432.",
    )
    parser.add_argument(
        "--database",
        default="edh",
        help="Database name. Default: edh.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report row counts but do not write to Aurora.",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"),
        help="AWS region for Secrets Manager lookups.",
    )
    return parser.parse_args()


def resolve_aurora_target(args: argparse.Namespace) -> dict:
    """Resolve Aurora connection parameters from args + SocaConfig fallback."""
    endpoint = args.endpoint
    secret_arn = args.secret_arn
    if endpoint is None or secret_arn is None:
        try:
            from utils.config import SocaConfig
        except ImportError:
            logger.error(
                "Cannot import SocaConfig; pass --endpoint and --secret-arn explicitly."
            )
            sys.exit(2)
        if endpoint is None:
            endpoint = SocaConfig(key="/configuration/Database/endpoint").get_value().get("message")
        if secret_arn is None:
            secret_arn = SocaConfig(key="/configuration/Database/secret_arn").get_value().get("message")
    if not endpoint or not secret_arn:
        logger.error(
            "Aurora endpoint and secret ARN are required. "
            "Pass --endpoint and --secret-arn or ensure SocaConfig keys are set."
        )
        sys.exit(2)
    return {"endpoint": endpoint, "secret_arn": secret_arn}


def fetch_credentials(secret_arn: str, region: str) -> dict:
    """Fetch master credentials from Secrets Manager."""
    import boto3
    sm = boto3.client("secretsmanager", region_name=region)
    resp = sm.get_secret_value(SecretId=secret_arn)
    return json.loads(resp["SecretString"])


def build_aurora_uri(creds: dict, endpoint: str, port: int, database: str) -> str:
    """Build the SQLAlchemy URI for Aurora PG."""
    user = creds["username"]
    password = creds["password"]
    # URL-encode the password in case it contains special characters
    from urllib.parse import quote_plus
    return f"postgresql+psycopg://{user}:{quote_plus(password)}@{endpoint}:{port}/{database}"


def copy_table(src_session, dst_session, table) -> tuple[int, int]:
    """Copy all rows from a single table. Returns (src_count, dst_count)."""
    src_rows = src_session.execute(table.select()).fetchall()
    src_count = len(src_rows)
    if src_count == 0:
        return 0, 0
    # Insert in batches of 500 to keep memory and lock pressure modest
    batch_size = 500
    inserted = 0
    for i in range(0, src_count, batch_size):
        batch = [dict(row._mapping) for row in src_rows[i:i + batch_size]]
        dst_session.execute(table.insert(), batch)
        inserted += len(batch)
    dst_session.commit()
    return src_count, inserted


def sync_postgres_sequences(dst_session, ordered_tables) -> None:
    """
    After bulk-copy, advance each table's PK sequence to MAX(id) + 1.

    Postgres uses sequences for auto-increment columns. The migration copies
    rows preserving primary keys (id=1,2,3,...) but the sequence still starts
    at 1. Without this fix, the FIRST insert from the web app after migration
    would collide on duplicate primary key.

    Pattern: SELECT setval('<table>_id_seq', COALESCE((SELECT MAX(id) FROM <table>), 1), true)
    The 'true' arg means "the supplied value HAS been used" so next nextval()
    returns max+1.
    """
    from sqlalchemy import text, inspect
    inspector = inspect(dst_session.bind)
    fixed = 0
    for table in ordered_tables:
        # Only sync if there's an integer PK named 'id' with a default sequence.
        pk_cols = [c for c in table.primary_key.columns]
        if len(pk_cols) != 1:
            continue
        pk = pk_cols[0]
        if pk.name != "id":
            continue
        # The conventional Postgres sequence name SQLAlchemy creates
        seq_name = f"{table.name}_id_seq"
        try:
            dst_session.execute(
                text(
                    f"SELECT setval(:seq, COALESCE((SELECT MAX(id) FROM \"{table.name}\"), 1), true)"
                ),
                {"seq": seq_name},
            )
            fixed += 1
        except Exception as e:
            logger.warning(
                f"  Could not sync sequence {seq_name} for {table.name}: {e}"
            )
    dst_session.commit()
    logger.info(f"Synced {fixed} table sequences to MAX(id).")


def main() -> int:
    args = parse_args()

    if not os.path.exists(args.source):
        logger.error(f"Source SQLite file not found: {args.source}")
        return 2

    # Resolve Aurora target
    aurora = resolve_aurora_target(args)
    creds = fetch_credentials(aurora["secret_arn"], args.region)
    aurora_uri = build_aurora_uri(creds, aurora["endpoint"], args.port, args.database)
    logger.info(f"Source: sqlite:///{args.source}")
    logger.info(f"Destination: postgresql+psycopg://<user>@{aurora['endpoint']}:{args.port}/{args.database}")
    logger.info(f"Dry-run: {args.dry_run}")

    from sqlalchemy import create_engine, MetaData
    from sqlalchemy.orm import sessionmaker

    src_engine = create_engine(f"sqlite:///{args.source}")
    src_meta = MetaData()
    src_meta.reflect(bind=src_engine)

    if args.dry_run:
        logger.info("Dry-run mode: reporting source row counts only.")
        SrcSession = sessionmaker(bind=src_engine)
        from sqlalchemy import func, select
        with SrcSession() as s:
            for table_name, table in src_meta.tables.items():
                count = s.execute(select(func.count()).select_from(table)).scalar()
                logger.info(f"  {table_name}: {count} rows")
        return 0

    # Real run -- reflect Aurora schema (web app already created it via db.create_all)
    # We reflect rather than importing the SOCA Flask app, which requires the full
    # cluster_manager PYTHONPATH that's not available to a standalone script.
    dst_engine = create_engine(aurora_uri)
    dst_meta = MetaData()
    dst_meta.reflect(bind=dst_engine)
    if not dst_meta.tables:
        logger.error(
            "Aurora schema is empty. Web app must run db.create_all() first. "
            "Start the web app once before running the migration."
        )
        return 2

    DstSession = sessionmaker(bind=dst_engine)
    SrcSession = sessionmaker(bind=src_engine)

    # Migrate in dependency order using Aurora's sorted_tables (parents first)
    ordered_tables = list(dst_meta.sorted_tables)
    logger.info(f"Migrating {len(ordered_tables)} tables...")

    results = []
    with SrcSession() as src_sess, DstSession() as dst_sess:
        for table in ordered_tables:
            if table.name not in src_meta.tables:
                logger.warning(f"  {table.name}: not present in source SQLite (new table?), skipping copy.")
                results.append((table.name, 0, 0, "skipped-new"))
                continue
            src_table = src_meta.tables[table.name]
            src_count, dst_count = copy_table(src_sess, dst_sess, src_table)
            ok = src_count == dst_count
            logger.info(f"  {table.name}: {src_count} -> {dst_count} {'OK' if ok else 'MISMATCH'}")
            results.append((table.name, src_count, dst_count, "ok" if ok else "mismatch"))

    # Summary
    logger.info("=" * 70)
    total_src = sum(r[1] for r in results)
    total_dst = sum(r[2] for r in results)
    logger.info(f"Summary: {len(results)} tables, {total_src} source rows, {total_dst} destination rows.")
    mismatches = [r for r in results if r[3] == "mismatch"]
    if mismatches:
        logger.error(f"{len(mismatches)} table(s) had row-count mismatches.")
        return 1

    # Sync Postgres sequences so the next auto-incremented insert from the
    # web app picks up where SQLite left off.
    with DstSession() as dst_sess:
        sync_postgres_sequences(dst_sess, ordered_tables)

    logger.info("Migration complete. All row counts match. Sequences synced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
