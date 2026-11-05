######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

"""
Reading rules for the mesh's audit log and liveness view.

Flask-free, for the same reason `lifecycle.py` is: `flask_restful` is declared in
no requirements file here, so logic that must be tested cannot live in a module
that imports it.

### What liveness means in this release

CR3's daemon writes a heartbeat row every sync cycle carrying `last_sync_ts`,
`last_sync_ok` and the peer count it saw. Nothing read those rows until now, and
they are the only liveness signal that exists: the pairwise probe matrix the
prototype's health endpoint rendered comes from the peer-probing subsystem, which
is a later CR, so an endpoint reading it today would return an empty matrix
forever and call it health.

So liveness here is derived from heartbeat age against the sync interval, which is
a weaker claim than reachability and is labelled as such. A peer whose daemon is
running and whose tunnel is down reports LIVE, because its heartbeat is current.
That is honest for what this release can observe, and the field names say
`daemon_liveness` rather than `health` so nothing reads it as more.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Callable, Optional

# Validators is stdlib-only (typing, datetime, logging), so it does not pull flask
# in the way utils.response and utils.error do. That is what makes it usable here,
# in a module whose whole point is being importable from a checkout.
from utils.validators import Validators


class Liveness:
    """Values are stable, because the UI renders them and the tests assert them."""

    LIVE = "live"
    STALE = "stale"
    DEAD = "dead"
    FAILING = "failing"
    UNKNOWN = "unknown"


# A heartbeat older than this many sync intervals is stale, and older than the
# second is dead. Expressed in intervals rather than seconds so a cluster
# configured with a slow sync is not reported dead for syncing on schedule, which
# is the mistake a fixed threshold would make.
STALE_AFTER_INTERVALS = 3
DEAD_AFTER_INTERVALS = 10

# Used when a heartbeat row carries no usable interval, so the arithmetic still
# has a basis. Matches the daemon's own default.
DEFAULT_SYNC_INTERVAL_SECONDS = 30


@dataclass(frozen=True)
class HeartbeatReading:
    """One cluster's liveness, with the numbers the judgement was made from."""

    cluster_id: str
    daemon_liveness: str
    age_seconds: Optional[int]
    last_sync_ts: Optional[int]
    last_sync_ok: Optional[bool]
    peer_count: Optional[int]
    daemon_version: str


def _as_int(value, default: Optional[int] = None) -> Optional[int]:
    """
    A tolerant int, because an absent value here is a normal state and not an error.

    Hand-written rather than SocaCastEngine for two measured reasons. The first is
    structural: utils/cast.py imports utils.error, which imports flask at module
    scope, so adopting it would make this module unimportable without flask. That
    matters because this module is imported by its unit tests directly from a
    checkout, where flask is not installed: Flask and Flask-RESTful are pinned in
    the controller's bootstrap requirements template, which soca_python.sh.j2
    renders and installs on a running controller, so they are present there and
    absent here.

    The second reason is behavioural, and it is the stronger one. A peer that has
    never heartbeated has no last_sync_ts, which is the ordinary state of a peer
    approved a moment ago. Passing that None through cast_as(int) emits eight log
    lines at ERROR level carrying a full frame walk and a minted Request ID. On a
    mesh health page that is eight error lines per never-heartbeated peer per page
    load, describing a condition the page then renders as "unknown" on purpose.
    Refusing to convert is not the same as failing, and only one of the two
    mechanisms can say so.
    """
    """
    Coerce a DynamoDB numeric without raising.

    Rows come from a Global Table an administrator can edit, so a value that will
    not convert must degrade to unknown rather than failing the whole view. The
    prototype's `int(item.get("ts", 0))` turned a malformed row into a 500 for
    every peer at once, which is the same one-bad-row-costs-everything shape the
    hosts block had in CR3.
    """
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_display_dict(value, default: Optional[dict] = None) -> dict:
    """
    A tolerant dict, for a stored field that is presented rather than acted on.

    The sibling of _as_int, and it exists because the audit row shaper coerced
    every other field through a degrading helper and this one field through a bare
    dict(). Audit rows come from a Global Table and outlive schema changes, so the
    shaper's whole contract is that one unreadable field renders blank instead of
    failing the page. A scalar reaching dict() raises TypeError or ValueError, and
    that exception left the shaper, left the endpoint, and turned one malformed row
    into a 500 for the entire audit page.

    Written with try/except rather than a type check so a DynamoDB map arrives as a
    dict, anything unconvertible degrades, and there is one mechanism for tolerance
    in this module rather than two.
    """
    if default is None:
        default = {}
    if value is None:
        return dict(default)
    try:
        return dict(value)
    except (TypeError, ValueError):
        return dict(default)


def classify_heartbeat(
    row: dict,
    *,
    now: int,
    sync_interval_seconds: int = DEFAULT_SYNC_INTERVAL_SECONDS,
) -> HeartbeatReading:
    """
    Turn one heartbeat row into a liveness reading.

    A row whose timestamp is missing or unreadable is UNKNOWN, never LIVE. Failing
    open here would report a cluster as healthy on the strength of a row nobody
    could parse.

    A future timestamp is treated as an age of zero rather than a negative one.
    Clock skew across regions is expected, and a skewed clock should not make a
    peer look more alive than any other peer, nor produce a negative age in the
    response for the UI to render.
    """
    cluster_id = str(row.get("cluster_id") or "")
    last_sync_ts = _as_int(row.get("last_sync_ts"))
    last_sync_ok = row.get("last_sync_ok")
    if last_sync_ok is not None:
        last_sync_ok = bool(last_sync_ok)

    interval = sync_interval_seconds
    if interval <= 0:
        interval = DEFAULT_SYNC_INTERVAL_SECONDS

    if last_sync_ts is None:
        liveness = Liveness.UNKNOWN
        age = None
    else:
        age = max(0, now - last_sync_ts)
        if age > DEAD_AFTER_INTERVALS * interval:
            liveness = Liveness.DEAD
        elif age > STALE_AFTER_INTERVALS * interval:
            liveness = Liveness.STALE
        elif last_sync_ok is False:
            # Current heartbeat, but the cycle it reports failed. Distinct from
            # STALE: the daemon is alive and telling us it cannot converge, which
            # is a different problem from a daemon nobody has heard from.
            liveness = Liveness.FAILING
        else:
            liveness = Liveness.LIVE

    return HeartbeatReading(
        cluster_id=cluster_id,
        daemon_liveness=liveness,
        age_seconds=age,
        last_sync_ts=last_sync_ts,
        last_sync_ok=last_sync_ok,
        peer_count=_as_int(row.get("peer_count")),
        daemon_version=str(row.get("daemon_version") or ""),
    )


def summarise(readings) -> dict:
    """
    Counts by liveness, with every value present even at zero.

    Every key always appears so the UI does not have to distinguish absent from
    zero, and so a chart does not silently drop a category the moment it empties.
    """
    counts = {
        Liveness.LIVE: 0,
        Liveness.FAILING: 0,
        Liveness.STALE: 0,
        Liveness.DEAD: 0,
        Liveness.UNKNOWN: 0,
    }
    for reading in readings:
        if reading.daemon_liveness in counts:
            counts[reading.daemon_liveness] += 1
        else:
            counts[Liveness.UNKNOWN] += 1
    return counts


# Filters the audit endpoint accepts, mapped to the row field each compares.
# Declared so the endpoint cannot accept a filter this module does not apply, and
# so a test can enumerate them rather than trusting a list in a docstring.
EXACT_MATCH_FILTERS = {
    "cluster_id": "target_cluster_id",
    "action": "action",
    "actor": "actor",
}


class MalformedCursor(Exception):
    """
    A pagination cursor that did not decode.

    Raised rather than ignored. The prototype logged a warning and fell back to the
    first page, so a caller advancing through pages with a corrupted cursor was
    silently handed page one again, which in a UI is a Next button that never
    advances and shows no error. Refusing makes the caller's mistake visible.
    """


# Keys a cursor is permitted to carry. Restricted so a hand-crafted cursor cannot
# smuggle arbitrary query state, such as a different mesh's partition, into a
# request that has already been authorised for this mesh.
_CURSOR_KEYS = frozenset({"mesh_id", "event_id"})


def encode_cursor(last_key: Optional[dict]) -> Optional[str]:
    """The key to resume from, as an opaque string, or None at the end of a scan."""
    if not last_key:
        return None
    trimmed = {key: str(last_key[key]) for key in sorted(_CURSOR_KEYS) if key in last_key}
    if not trimmed:
        return None
    raw = json.dumps(trimmed, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor: Optional[str], *, expected_mesh_id: str) -> Optional[dict]:
    """
    A cursor back into a resume key, refusing anything that is not one.

    The mesh id inside the cursor must match the mesh the request is for. Without
    that check a cursor from one mesh could be replayed against another, and the
    query would happily page through a partition the caller did not ask about,
    which the endpoint would then present as this mesh's audit log.
    """
    if not cursor:
        return None
    try:
        decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
    except Exception as e:
        raise MalformedCursor(f"The pagination cursor could not be decoded: {e}")
    if not Validators.is_dict(decoded):
        raise MalformedCursor("The pagination cursor is not an object.")
    unknown = sorted(set(decoded) - _CURSOR_KEYS)
    if unknown:
        raise MalformedCursor(
            f"The pagination cursor carries unexpected keys: {unknown}."
        )
    missing = sorted(_CURSOR_KEYS - set(decoded))
    if missing:
        raise MalformedCursor(
            f"The pagination cursor is missing {missing}."
        )
    if str(decoded["mesh_id"]) != expected_mesh_id:
        raise MalformedCursor(
            "The pagination cursor belongs to a different mesh than this request."
        )
    return {key: str(value) for key, value in decoded.items()}


def audit_matcher(
    *,
    cluster_id: Optional[str] = None,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    start_ts: Optional[int] = None,
    end_ts: Optional[int] = None,
) -> Callable[[dict], bool]:
    """
    Build the predicate the paginating read applies while walking pages.

    Returned as a predicate rather than applied to a fetched page, because the
    prototype filtered one page of `Limit=limit` after the fact: asking for fifty
    approvals returned however many approvals happened to fall in the newest fifty
    rows of any kind, and a filter matching nothing on the first page looked like
    no matching events existed. The caller pages until it has `limit` matches.

    An unreadable timestamp on a row excludes it from a time-bounded query rather
    than including it, because a row that cannot be placed in time cannot be
    asserted to fall inside the window the operator asked for.
    """
    wanted = {
        field: value
        for filter_name, field in EXACT_MATCH_FILTERS.items()
        for value in [{"cluster_id": cluster_id, "action": action, "actor": actor}[filter_name]]
        if value
    }

    def matches(row: dict) -> bool:
        for field, value in wanted.items():
            if str(row.get(field) or "") != value:
                return False
        if start_ts is not None or end_ts is not None:
            ts = _as_int(row.get("ts"))
            if ts is None:
                return False
            if start_ts is not None and ts < start_ts:
                return False
            if end_ts is not None and ts > end_ts:
                return False
        return True

    return matches
