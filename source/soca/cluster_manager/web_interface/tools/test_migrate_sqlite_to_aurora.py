#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Synthetic test for the SQLite -> Aurora PostgreSQL migration tool
(migrate_sqlite_to_aurora.py).

It builds a synthetic SQLite source whose schema deliberately mirrors the
migration's risk surface, runs the tool's REAL functions to migrate into a
Postgres target, and asserts correctness the tool itself does NOT check
(value integrity, PK preservation, post-migration sequence state).

What it validates
-----------------
1. Row-count parity per table (what the tool checks).
2. Primary-key preservation (ids copied verbatim).
3. Text-value integrity round-trip -- a >255-char authentication_token and
   >500-char profile fields survive the copy byte-for-byte. This is the
   REGRESSION GUARD: if a Text-widened column were reverted to String(255)/(500),
   the Postgres dest column would be varchar(N) and the copy would raise
   "value too long for type character varying(N)".
4. FK dependency order -- a child table (FK to a parent) migrates after its
   parent without a constraint violation (tool uses dst sorted_tables).
5. Batching -- a 1200-row table is copied via the tool's 500-row batches.
6. Sequence sync -- after migration, the next auto-increment insert gets
   MAX(id)+1 (no PK collision), and a non-'id' PK table is skipped gracefully.

Running it
----------
The synthetic migration test needs a scratch Postgres. Point MIGRATION_TEST_PG_DSN
at any throwaway database (it DROPs/CREATEs the synthetic tables, so use a
scratch DB, never a real one). Without the env var, the integration test is
skipped; the build_aurora_uri unit test always runs.

Option A -- local ephemeral Postgres via Docker:
    docker run -d --rm -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16
    MIGRATION_TEST_PG_DSN="postgresql+psycopg://postgres:test@127.0.0.1:55432/postgres" \
        python3 -m pytest tools/test_migrate_sqlite_to_aurora.py -v

Option B -- a scratch database on the controller's Aurora (run on the controller):
    # create a throwaway DB first (do NOT use the live 'edh' database):
    #   psql "host=<endpoint> user=edh_admin dbname=edh sslmode=require" -c 'CREATE DATABASE migtest;'
    MIGRATION_TEST_PG_DSN="postgresql+psycopg://edh_admin:<pw>@<endpoint>:5432/migtest?sslmode=require" \
        python3 -m pytest tools/test_migrate_sqlite_to_aurora.py -v
"""

import importlib.util
import os
import uuid

import pytest
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    func,
    insert,
    select,
    text,
)
from sqlalchemy.orm import sessionmaker

# ---- import the migration tool by path (no SOCA app/config required) ----
_TOOL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrate_sqlite_to_aurora.py")
_spec = importlib.util.spec_from_file_location("migrate_sqlite_to_aurora_under_test", _TOOL_PATH)
migrate_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(migrate_tool)

PG_DSN = os.environ.get("MIGRATION_TEST_PG_DSN")

# Edge-case payloads that mirror the Text-widened columns in models.py.
LONG_TOKEN = "tok-" + "A" * 400  # >255 chars: mirrors VirtualDesktopSessions.authentication_token (Fernet blob)
LONG_TYPES = ",".join(f"m5.{i}xlarge" for i in range(80))  # >500 chars: pattern_allowed_instance_types
LONG_SUBNETS = ",".join(f"subnet-{uuid.uuid4().hex[:17]}" for _ in range(25))  # >500 chars: allowed_subnet_ids
UNICODE_NAME = "proj-\u00e9\u00fc\u4e2d\u6587-\U0001f680"  # accents + CJK + emoji


def _synthetic_metadata() -> MetaData:
    """A small schema mirroring the real migration's risk shapes."""
    md = MetaData()
    Table(
        "projects", md,
        Column("id", Integer, primary_key=True),
        Column("name", String(64), nullable=False),
    )
    Table(
        "project_memberships", md,
        Column("id", Integer, primary_key=True),
        Column("project_id", Integer, ForeignKey("projects.id"), nullable=False),
        Column("user", String(64), nullable=False),
    )
    Table(
        "vdi_sessions", md,
        Column("id", Integer, primary_key=True),
        Column("name", String(36), nullable=False),
        # Text (NOT String(255)) -- the regression-guard column
        Column("authentication_token", Text),
    )
    Table(
        "vdi_profiles", md,
        Column("id", Integer, primary_key=True),
        # Text (NOT String(500)) -- regression-guard columns
        Column("pattern_allowed_instance_types", Text, nullable=False),
        Column("allowed_subnet_ids", Text, nullable=False),
    )
    Table(
        "bulk", md,
        Column("id", Integer, primary_key=True),
        Column("payload", String(32)),
    )
    Table(
        "kv", md,
        # non-'id' string PK -> sequence-sync must SKIP this table without error
        Column("k", String(40), primary_key=True),
        Column("v", Text),
    )
    return md


def _populate_source(src_engine, md: MetaData) -> None:
    with src_engine.begin() as c:
        c.execute(insert(md.tables["projects"]),
                  [{"id": 1, "name": UNICODE_NAME}, {"id": 2, "name": "proj2"}, {"id": 3, "name": "proj3"}])
        c.execute(insert(md.tables["project_memberships"]),
                  [{"id": i, "project_id": ((i - 1) % 3) + 1, "user": f"user{i}"} for i in range(1, 6)])
        c.execute(insert(md.tables["vdi_sessions"]),
                  [{"id": 1, "name": "s1", "authentication_token": LONG_TOKEN},
                   {"id": 2, "name": "s2", "authentication_token": None}])  # NULL round-trip
        c.execute(insert(md.tables["vdi_profiles"]),
                  [{"id": 1, "pattern_allowed_instance_types": LONG_TYPES, "allowed_subnet_ids": LONG_SUBNETS}])
        c.execute(insert(md.tables["bulk"]),
                  [{"id": i, "payload": f"row{i}"} for i in range(1, 1201)])  # 1200 rows -> 3 copy batches
        c.execute(insert(md.tables["kv"]),
                  [{"k": "alpha", "v": "x"}, {"k": "beta", "v": "y"}])


# ---------------------------------------------------------------------------
# Always-run unit test (no database required)
# ---------------------------------------------------------------------------
def test_build_aurora_uri_url_encodes_password():
    """Passwords with URL-special chars must be percent-encoded in the URI."""
    creds = {"username": "edh_admin", "password": "p@ss/w:rd #1"}
    uri = migrate_tool.build_aurora_uri(creds, "db.example.com", 5432, "edh")
    assert uri.startswith("postgresql+psycopg://edh_admin:")
    assert "@db.example.com:5432/edh" in uri
    # quote_plus: @->%40 /->%2F :->%3A space->+ #->%23
    assert "p%40ss%2Fw%3Ard+%231" in uri
    assert "p@ss/w:rd #1" not in uri  # raw password must not leak into the URI


# ---------------------------------------------------------------------------
# Synthetic end-to-end migration test (needs a scratch Postgres)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not PG_DSN,
    reason="set MIGRATION_TEST_PG_DSN to a scratch Postgres DSN to run the synthetic migration test",
)
def test_synthetic_sqlite_to_postgres_migration(tmp_path):
    md = _synthetic_metadata()
    src_engine = create_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")
    dst_engine = create_engine(PG_DSN)

    # Idempotent dest: drop any leftovers, recreate the schema (simulates the
    # web app's db.create_all() having run on Aurora first).
    md.drop_all(dst_engine)
    md.create_all(dst_engine)
    md.create_all(src_engine)
    _populate_source(src_engine, md)

    try:
        # Reflect both sides exactly as the tool's main() does.
        src_meta = MetaData(); src_meta.reflect(bind=src_engine)
        dst_meta = MetaData(); dst_meta.reflect(bind=dst_engine)
        SrcSession = sessionmaker(bind=src_engine)
        DstSession = sessionmaker(bind=dst_engine)
        ordered = list(dst_meta.sorted_tables)  # parents before children

        results = {}
        with SrcSession() as src_sess, DstSession() as dst_sess:
            for t in ordered:
                src_t = src_meta.tables[t.name]
                src_count, dst_count = migrate_tool.copy_table(src_sess, dst_sess, src_t)
                results[t.name] = (src_count, dst_count)

        # (1) row-count parity for every table
        for name, (sc, dc) in results.items():
            assert sc == dc, f"row-count mismatch on {name}: src={sc} dst={dc}"
        # (5) batching: 1200 rows fully copied; FK child copied
        assert results["bulk"] == (1200, 1200)
        assert results["project_memberships"] == (5, 5)

        with DstSession() as d:
            dsess = dst_meta.tables["vdi_sessions"]
            dprof = dst_meta.tables["vdi_profiles"]
            dproj = dst_meta.tables["projects"]

            # (2) PK preservation
            ids = sorted(r[0] for r in d.execute(select(dsess.c.id)).all())
            assert ids == [1, 2]
            # (3) Text-value integrity (regression guard) + NULL round-trip
            tok = d.execute(select(dsess.c.authentication_token).where(dsess.c.id == 1)).scalar()
            assert tok == LONG_TOKEN and len(tok) > 255
            assert d.execute(select(dsess.c.authentication_token).where(dsess.c.id == 2)).scalar() is None
            pat = d.execute(select(dprof.c.pattern_allowed_instance_types)).scalar()
            assert pat == LONG_TYPES and len(pat) > 500
            sub = d.execute(select(dprof.c.allowed_subnet_ids)).scalar()
            assert sub == LONG_SUBNETS and len(sub) > 500
            # unicode round-trip on the FK parent
            assert d.execute(select(dproj.c.name).where(dproj.c.id == 1)).scalar() == UNICODE_NAME

        # (6) sequence sync: must run without error (incl. skipping the kv string-PK table)
        with DstSession() as d:
            migrate_tool.sync_postgres_sequences(d, ordered)

        # next auto-increment insert (no id supplied) must land at MAX(id)+1 = 4,
        # proving the sequence was advanced past the copied PKs (no collision).
        with dst_engine.begin() as c:
            new_id = c.execute(
                text('INSERT INTO projects (name) VALUES (:n) RETURNING id'), {"n": "after-migration"}
            ).scalar()
        assert new_id == 4, f"sequence not synced: next id={new_id}, expected 4"

        # sanity: dest total rows == source total rows
        with SrcSession() as s, DstSession() as d:
            for name in ("projects", "project_memberships", "vdi_sessions", "vdi_profiles", "bulk", "kv"):
                sc = s.execute(select(func.count()).select_from(src_meta.tables[name])).scalar()
                dc = d.execute(select(func.count()).select_from(dst_meta.tables[name])).scalar()
                # projects gained 1 row from the post-sync insert above
                expected = sc + 1 if name == "projects" else sc
                assert dc == expected, f"{name}: dst={dc} expected={expected}"
    finally:
        md.drop_all(dst_engine)


if __name__ == "__main__":
    raise SystemExit(pytest.main([os.path.abspath(__file__), "-v"]))
