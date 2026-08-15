# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()
scheduler = BackgroundScheduler()


# ---------------------------------------------------------------------------
# SQLite tuning -- applied to every new SQLite connection.
#
# These PRAGMAs are required to scale to ~1000 concurrent SSE-connected
# users without writer-lock contention freezing readers. WAL mode lets
# readers proceed concurrently with the single writer. busy_timeout=5000
# caps the rare contention wait at 5 seconds. cache_size=-65536 grants
# the connection 64 MB of page cache (negative value = KB).
#
# When SOCA migrates to Aurora PostgreSQL Serverless v2 (feature/crossregion
# branch), this listener becomes a no-op because the dialect check filters
# non-SQLite engines. No removal needed.
# ---------------------------------------------------------------------------

@event.listens_for(Engine, "connect")
def _apply_sqlite_pragmas(dbapi_connection, connection_record) -> None:
    # Filter to SQLite only. The dbapi_connection class is sqlite3.Connection
    # for SQLite engines; psycopg2.extensions.connection for PostgreSQL.
    if type(dbapi_connection).__module__ != "sqlite3":
        return
    cursor = dbapi_connection.cursor()
    try:
        # journal_mode is database-scoped (persists across connections) but
        # safe to set every time -- the call is cheap.
        cursor.execute("PRAGMA journal_mode = WAL")
        # synchronous=NORMAL is safe under WAL and faster than FULL. SOCA's
        # data is recoverable from cluster state if a write is lost on power
        # cut (rare on EC2; never on Aurora).
        cursor.execute("PRAGMA synchronous = NORMAL")
        # Auto-checkpoint every 1000 pages (~4 MB). Caps WAL file growth.
        cursor.execute("PRAGMA wal_autocheckpoint = 1000")
        # 64 MB page cache per connection (negative = KB).
        cursor.execute("PRAGMA cache_size = -65536")
        # 5-second wait on writer-lock contention before raising. Long enough
        # to absorb burst writes during a provisioning wave; short enough
        # that an SSE greenlet doesn't appear hung from the user's POV.
        cursor.execute("PRAGMA busy_timeout = 5000")
    finally:
        cursor.close()
