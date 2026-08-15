# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scheduled task: refresh API path latency statistics.

Maintains two structures:
  1. Materialized view `api_path_stats` -- rolling 24h baseline per path+method.
     Used by the audit log API to flag abnormal latency in real-time.
  2. History table `api_path_stats_history` -- hourly snapshots for long-term
     trending on long-running clusters.

Refresh cadence: every 60 seconds (matview), hourly append (history).
"""

import logging
import time
from datetime import datetime, timezone

from extensions import db
from sqlalchemy import text

from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")

_MATVIEW_NAME = "api_path_stats"
_HISTORY_TABLE = "api_path_stats_history"
_last_history_append = 0


def get_cached_stats():
    """Return path latency stats keyed by (path, method), read from the matview (worker-consistent)."""
    try:
        # Independent read-only connection: never touch the caller's request ORM session.
        with db.engine.connect() as conn:
            rows = conn.execute(text(
                f"SELECT path, method, p50_ms, p95_ms, p99_ms FROM {_MATVIEW_NAME}"
            )).fetchall()
        return SocaResponse(success=True, message={
            (r[0], r[1]): {"p50": _num(r[2]), "p95": _num(r[3]), "p99": _num(r[4])}
            for r in rows
        })
    except Exception as err:
        logger.debug(f"get_cached_stats matview read failed (pre-refresh?): {err}")
        return SocaError.GENERIC_ERROR(
            helper=f"get_cached_stats matview read failed: {err}"
        )


def _num(v):
    if v is None:
        return None
    _c = SocaCastEngine(v).cast_as(float)
    return _c.get("message") if _c.get("success") is True else None


def _ensure_matview(conn):
    """Create the matview + unique index if they don't exist."""
    exists = conn.execute(text(
        "SELECT 1 FROM pg_matviews WHERE matviewname = :name"
    ), {"name": _MATVIEW_NAME}).fetchone()
    if not exists:
        conn.execute(text(f"""
            CREATE MATERIALIZED VIEW {_MATVIEW_NAME} AS
            SELECT
                path,
                method,
                COUNT(*) as cnt,
                ROUND(AVG(duration_ms)::numeric, 1) as avg_ms,
                ROUND((PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms))::numeric, 1) as p50_ms,
                ROUND((PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms))::numeric, 1) as p95_ms,
                ROUND((PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms))::numeric, 1) as p99_ms
            FROM api_audit_log
            WHERE duration_ms IS NOT NULL
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY path, method
        """))
        conn.execute(text(
            f"CREATE UNIQUE INDEX ON {_MATVIEW_NAME} (path, method)"
        ))
        conn.commit()
        logger.info("Created materialized view api_path_stats")


def _ensure_history_table(conn):
    """Create the history table if it doesn't exist."""
    conn.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {_HISTORY_TABLE} (
            id SERIAL PRIMARY KEY,
            captured_at TIMESTAMP NOT NULL DEFAULT NOW(),
            path VARCHAR(512) NOT NULL,
            method VARCHAR(10) NOT NULL,
            cnt INTEGER NOT NULL,
            avg_ms NUMERIC(10,1),
            p50_ms NUMERIC(10,1),
            p95_ms NUMERIC(10,1),
            p99_ms NUMERIC(10,1)
        )
    """))
    conn.execute(text(f"""
        CREATE INDEX IF NOT EXISTS idx_path_stats_history_time
        ON {_HISTORY_TABLE} (captured_at)
    """))
    conn.execute(text(f"""
        CREATE INDEX IF NOT EXISTS idx_path_stats_history_path
        ON {_HISTORY_TABLE} (path, captured_at)
    """))
    conn.commit()


def _refresh_matview(conn):
    """Refresh the matview concurrently (non-blocking)."""
    conn.execute(text(
        f"REFRESH MATERIALIZED VIEW CONCURRENTLY {_MATVIEW_NAME}"
    ))
    conn.commit()


def _append_history(conn):
    """Snapshot current matview stats into the history table."""
    conn.execute(text(f"""
        INSERT INTO {_HISTORY_TABLE} (captured_at, path, method, cnt, avg_ms, p50_ms, p95_ms, p99_ms)
        SELECT NOW(), path, method, cnt, avg_ms, p50_ms, p95_ms, p99_ms
        FROM {_MATVIEW_NAME}
    """))
    conn.commit()
    logger.debug("Appended path stats history snapshot")


def refresh_api_path_stats(app) -> SocaResponse:
    """
    Main entry point called by APScheduler every 60 seconds.
    Refreshes the matview on every call; appends history hourly.
    """
    global _last_history_append

    with app.app_context():
        try:
            with db.engine.connect() as conn:
                _ensure_matview(conn)
                _ensure_history_table(conn)
                _refresh_matview(conn)

                now = time.time()
                if now - _last_history_append >= 3600:
                    _append_history(conn)
                    _last_history_append = now

            return SocaResponse(success=True, message="refreshed")

        except Exception as err:
            logger.error(f"refresh_api_path_stats failed: {err}")
            return SocaError.GENERIC_ERROR(
                helper=f"refresh_api_path_stats failed: {err}"
            )
