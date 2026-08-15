# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Server-Sent Events (SSE) endpoint for the DCV event-relay path.

Two routes:

  GET /api/dcv/events/stream
      Multiplexed stream for the WebUI grid view. ONE connection per
      browser session, multiplexes events for ALL the user's owned
      sessions onto the wire. Browser JS demuxes on session_uuid and
      routes into the right grid card.

  GET /api/dcv/events/stream/<session_uuid>
      Focused stream for the WebUI detail page. Includes a recent-history
      replay (last N events from DcvSessionEventLog) on connect, then
      live updates.

Architecture:

  - SQLite + WAL mode + 5-second poll cadence. Sized for ~1000
    concurrent SSE-connected users; switches to Redis pub/sub at the
    Aurora migration cutover.
  - gevent monkey-patched uwsgi -- each connection is one greenlet,
    blocking calls (DB queries, gevent.sleep) yield cooperatively.
  - 30-second SSE comment-line keepalive so any LB / proxy idle timeout
    (default NLB 350s, ALB 60s) cannot drop the connection.
  - per-user authorization: stream filters on session_owner == X-EDH-USER
    enforced server-side so a malicious client cannot read another user's
    events even by guessing UUIDs.
  - Last-Event-ID resume: on EventSource auto-reconnect the browser sends
    Last-Event-ID and the stream replays only events with id > that.

Failure modes:

  - DB unreachable: handler logs the error, sends one SSE comment line
    indicating the failure, then returns. Browser reconnects after its
    EventSource retry interval (default 3 seconds).
  - Client disconnect: gevent surfaces a GreenletExit when the WSGI
    layer detects the closed socket; the generator stops cleanly.
  - Greenlet starvation: detected externally via uwsgi --stats and
    elevated p99 connection latency. No mitigation in this file.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Generator, List, Optional, Set

from flask import Response, request, stream_with_context
from flask_restful import Resource

from decorators import private_api, feature_flag
from models import db, DcvSessionEventLog, VirtualDesktopSessions
from utils.cast import SocaCastEngine
from utils.dcv_event_store import query_events_since as ddb_query_events
from utils.error import SocaError

logger = logging.getLogger("soca_logger")

# Tunables. Defaults sized for ~1000 connected users on SQLite.
POLL_INTERVAL_SEC = 5            # DB scan cadence per greenlet
KEEPALIVE_INTERVAL_SEC = 30      # SSE comment line cadence
MAX_BATCH_SIZE = 100             # rows per query iteration
HISTORY_REPLAY_LIMIT = 50        # detail-page initial replay rows
ADMIN_STREAM_CONCURRENCY = 5     # cap on simultaneous admin wildcard streams

# UUID validation -- mirrors session_event.py to reject path-injection
# attempts before they reach the DB.
import re
_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


def _resolve_user_session_uuids(user: str) -> Set[str]:
    """
    Return the set of session_uuid values owned by the given user.
    Resolved once per stream open, cached in-memory for the connection's
    lifetime. The grid view auto-reconnects on session add/remove via
    a separate signaling channel (page nav or explicit refresh).
    """
    rows = (db.session.query(VirtualDesktopSessions.session_uuid)
            .filter(VirtualDesktopSessions.session_owner == user)
            .filter(VirtualDesktopSessions.is_active.is_(True))
            .all())
    return {r[0] for r in rows if r[0]}


def _row_to_sse_payload(row: DcvSessionEventLog) -> dict:
    """Serialize a DcvSessionEventLog row into the SSE data dict."""
    return {
        "id": row.id,
        "session_uuid": row.session_uuid,
        "event_type": row.event_type,
        "checkpoint": row.checkpoint,
        "sub_status": row.sub_status,
        "event_timestamp": row.event_timestamp.isoformat() + "Z"
        if row.event_timestamp else None,
    }


def _format_sse(payload: dict, event_id: int, event_name: Optional[str] = None) -> str:
    """
    Build a single SSE message frame. Format per WHATWG spec:
        id: 12345
        event: bootstrap-checkpoint
        data: {...}
        \n
    """
    lines: List[str] = [f"id: {event_id}"]
    if event_name:
        lines.append(f"event: {event_name}")
    lines.append(f"data: {json.dumps(payload, separators=(',', ':'))}")
    return "\n".join(lines) + "\n\n"


def _normalize_event_timestamp(ts) -> Optional[str]:
    """
    Normalize a notification-envelope ``ts`` to an ISO-8601 string the
    browser's ``Date.parse()`` can read.

    Two producers write the envelope with DIFFERENT ts formats: the
    controller's ``dcv_event_store.build_envelope`` emits ISO-8601, while
    the CapacityExecutor Lambda's inline envelope emits an epoch-seconds
    float string (e.g. ``"1781069974.666"``). The detail-page timeline
    parses this value as a date, so an epoch string is unparseable -> the
    row shows a blank "Received" time and sinks to the bottom of the log.
    Convert epoch values to ISO; pass ISO values through unchanged.
    """
    if not ts:
        return None
    _ts = SocaCastEngine(ts).cast_as(expected_type=str)
    if _ts.get("success") is not True:
        return None
    _s = _ts.get("message").strip()
    if not _s:
        return None
    # ISO-8601 carries a date/time 'T' separator; epoch values are purely
    # numeric, so a missing 'T' marks a legacy epoch-seconds string.
    if "T" in _s:
        return _s
    _epoch = SocaCastEngine(_s).cast_as(expected_type=float)
    if _epoch.get("success") is not True:
        return _s  # unrecognized format -- surface it rather than drop it
    return datetime.fromtimestamp(_epoch.get("message"), tz=timezone.utc).isoformat()


def _envelope_to_sse_payload(evt: dict) -> dict:
    """
    Build the SSE ``data:`` dict the timeline JS consumes from a stored
    notification envelope.

    The browser reads ``id``, ``event_timestamp``, ``event_type``,
    ``checkpoint``, ``sub_status`` and ``session_uuid``. The envelope keeps
    ``id`` and ``ts`` at the TOP level while the per-event fields live under
    ``payload`` -- so flatten the two together and surface a parseable ISO
    ``event_timestamp``. Without this, the payload sub-dict alone has no id
    and no timestamp, breaking row ordering and the T+/D+ columns.
    """
    _sse = (evt.get("payload") or {}).copy()
    _sse["id"] = evt.get("id")
    _sse["event_timestamp"] = _normalize_event_timestamp(evt.get("ts"))
    return _sse


def _stream_events(
    session_uuids: Set[str],
    last_event_id: int,
) -> Generator[str, None, None]:
    """
    Common generator body for both stream routes. Yields SSE-formatted
    strings until the client disconnects (greenlet exits) or DB errors.

    session_uuids: set of UUIDs to filter on. Empty set means "no
    accessible sessions" -- generator yields one comment-line and exits.
    last_event_id: starting id (exclusive). Use 0 for full replay.
    """
    if not session_uuids:
        # Nothing to stream. Send one comment so the browser EventSource
        # opens cleanly, then close.
        yield ": no accessible sessions\n\n"
        return

    # Force HTTP response status + headers to flush immediately so the
    # browser's EventSource fires onopen right away. Without this, when
    # the session has no events yet (fresh VDI), the generator sits in
    # the polling loop for up to 30s (KEEPALIVE_INTERVAL_SEC) before any
    # bytes go on the wire -- the response stays in "connecting" the
    # whole time and the badge never flips to "connected".
    yield ": stream-open\n\n"

    last_keepalive = time.monotonic()

    while True:
        # Poll DDB for new events across all watched sessions.
        all_events = []
        try:
            for _uuid in session_uuids:
                evts = ddb_query_events(
                    f"dcv#{_uuid}", last_event_id, limit=MAX_BATCH_SIZE
                )
                all_events.extend(evts)
        except Exception as err:
            logger.warning(f"SSE stream DDB error (cursor={last_event_id}): {err}")
            yield f": stream error -- closing\n\n"
            return

        # Sort merged events by id (ULID = time-ordered)
        all_events.sort(key=lambda e: e["id"])

        for evt in all_events:
            _sse = _envelope_to_sse_payload(evt)
            yield _format_sse(
                _sse,
                event_id=evt["id"],
                event_name=_sse.get("event_type", "event"),
            )
            last_event_id = evt["id"]

        # If the batch was full, immediately query again -- we're catching
        # up. Otherwise sleep for POLL_INTERVAL_SEC, with periodic keepalive.
        if len(all_events) >= MAX_BATCH_SIZE:
            continue

        # Cooperative sleep that wakes for keepalives. gevent.sleep yields
        # the greenlet back to the event loop so other connections run.
        try:
            import gevent
            sleeper = gevent.sleep
        except ImportError:
            sleeper = time.sleep

        sleeper(POLL_INTERVAL_SEC)

        now = time.monotonic()
        if now - last_keepalive >= KEEPALIVE_INTERVAL_SEC:
            yield ": keepalive\n\n"
            last_keepalive = now


def _last_event_id_from_request() -> str:
    """
    Resolve the resume cursor from either Last-Event-ID header (set by
    EventSource auto-reconnect) or ?last_id= query param. Defaults to ""
    (= full replay subject to the route's history cap).

    The cursor is a ULID string (opaque to the client).
    """
    raw = (request.headers.get("Last-Event-ID")
           or request.args.get("last_id")
           or "")
    return raw.strip()


def _build_sse_response(generator) -> Response:
    """Wrap a generator in a Flask SSE Response with the standard headers."""
    resp = Response(stream_with_context(generator), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    resp.headers["Connection"] = "keep-alive"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


# ---------------------------------------------------------------------------
# Auth-agnostic stream builders.
#
# Both the API (header-auth) Resources below and the WebUI (cookie-auth)
# view routes in views/virtual_desktops.py call these. The decorators and
# user-resolution differ between the two callers, but the streaming work
# is identical -- so it lives here in one place.
# ---------------------------------------------------------------------------


def build_grid_stream_response(user: str) -> Response:
    """
    Build the multiplexed grid-view SSE response for the authenticated user.
    Streams events for every session_uuid owned by `user`.

    Caller is responsible for authentication. Authorization (filter to
    user's own sessions) is enforced inside this function.
    """
    if not user:
        return ({"error": "missing_user"}, 400)

    session_uuids = _resolve_user_session_uuids(user)
    last_id = _last_event_id_from_request()

    logger.info(
        f"SSE grid stream open: user={user} "
        f"sessions={len(session_uuids)} resume_from={last_id}"
    )
    return _build_sse_response(_stream_events(session_uuids, last_id))


def build_session_stream_response(user: str, session_uuid: str):
    """
    Build the focused detail-page SSE response for `session_uuid`.

    Validates the session UUID format, then enforces ownership
    (user must own the session). Streams events for ONLY this session,
    starting with a bounded historical replay (HISTORY_REPLAY_LIMIT
    most-recent rows) followed by live updates.
    """
    if not user:
        return ({"error": "missing_user"}, 400)

    if not _UUID_RE.match(session_uuid or ""):
        return (
            SocaError.CLIENT_INVALID_PARAMETER(parameter="session_uuid").as_flask()
            if hasattr(SocaError, "CLIENT_INVALID_PARAMETER")
            else ({"error": "session_uuid_format"}, 400)
        )

    # Ownership gate: user must own this session.
    owned = (db.session.query(VirtualDesktopSessions.session_uuid)
             .filter(VirtualDesktopSessions.session_uuid == session_uuid)
             .filter(VirtualDesktopSessions.session_owner == user)
             .filter(VirtualDesktopSessions.is_active.is_(True))
             .first())
    if not owned:
        # Same shape as a missing session so probing for foreign UUIDs
        # cannot distinguish "not yours" from "doesn't exist".
        return ({"error": "session_unknown"}, 404)

    # Resolve last-event-id from header or query, falling back to a
    # bounded historical replay window.
    last_id = _last_event_id_from_request()
    # DDB-backed: no tail query needed; query_events_since with empty
    # cursor returns the most recent events (limited by MAX_BATCH_SIZE).

    logger.info(
        f"SSE detail stream open: user={user} "
        f"session={session_uuid} resume_from={last_id}"
    )
    return _build_sse_response(_stream_events({session_uuid}, last_id))


# ---------------------------------------------------------------------------
# Resources -- API (header-auth) entry points.
# WebUI (cookie-auth) entry points live in views/virtual_desktops.py and
# call the same build_*_stream_response helpers above.
# ---------------------------------------------------------------------------

class DcvEventStream(Resource):
    """
    GET /api/dcv/events/stream

    Multiplexed grid-view stream. Returns events for every session_uuid
    owned by the authenticated user. Browser JS routes by session_uuid.
    """

    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        Multiplexed SSE event stream for all sessions owned by the authenticated user
        ---
        openapi: 3.1.0
        operationId: getDcvEventStreamGrid
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
          - name: Last-Event-ID
            in: header
            schema:
              type: string
            required: false
            description: Resume cursor for EventSource reconnect (ULID string)
          - name: last_id
            in: query
            schema:
              type: string
            required: false
            description: Alternative resume cursor (used when Last-Event-ID header is not available)
        responses:
          '200':
            description: SSE stream opened successfully
            content:
              text/event-stream:
                schema:
                  type: string
                  description: Server-Sent Events stream with session lifecycle events
          '400':
            description: Missing required X-EDH-USER header
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        user = request.headers.get("X-EDH-USER")
        if not user:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()
        return build_grid_stream_response(user)


class DcvEventStreamSession(Resource):
    """
    GET /api/dcv/events/stream/<session_uuid>

    Focused detail-page stream. Validates the session is owned by the
    caller, then streams events for ONLY this session_uuid. On connect,
    replays up to HISTORY_REPLAY_LIMIT recent events for the timeline UI;
    then transitions to live updates.
    """

    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self, session_uuid: str):
        r"""
        Focused SSE event stream for a single session with history replay
        ---
        openapi: 3.1.0
        operationId: getDcvEventStreamSession
        tags:
          - Virtual Desktops
        parameters:
          - name: session_uuid
            in: path
            schema:
              type: string
              pattern: ^[0-9a-fA-F-]{36}$
            required: true
            description: UUID of the DCV session to stream events for
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
          - name: Last-Event-ID
            in: header
            schema:
              type: string
            required: false
            description: Resume cursor for EventSource reconnect (ULID string)
          - name: last_id
            in: query
            schema:
              type: string
            required: false
            description: Alternative resume cursor (used when Last-Event-ID header is not available)
        responses:
          '200':
            description: SSE stream opened successfully with history replay followed by live updates
            content:
              text/event-stream:
                schema:
                  type: string
                  description: Server-Sent Events stream with session lifecycle events
          '400':
            description: Missing required header or invalid session_uuid format
          '401':
            description: Authentication required
          '404':
            description: Session not found or not owned by the authenticated user
          '500':
            description: Server error
        """
        user = request.headers.get("X-EDH-USER")
        if not user:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()
        return build_session_stream_response(user, session_uuid)
