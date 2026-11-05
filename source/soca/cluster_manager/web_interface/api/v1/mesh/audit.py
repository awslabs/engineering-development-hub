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
GET /api/v1/mesh/audit

The mesh's audit log, newest first, with filters and a cursor. Admin-only.

Thin over `observability.audit_matcher` and `ddb_client.query_audit_events`: this
module reads query arguments and shapes a response, and makes no decisions about
what matches or how paging works, so both can be tested without a web stack.

`limit` means what it says. The read pages until it has that many MATCHING rows or
the partition is exhausted, where the prototype fetched one page of `Limit=limit`
and filtered afterwards, so a request for fifty approvals returned however many
approvals happened to fall in the newest fifty rows of any kind. When the page
budget runs out first, the response says so rather than presenting a partial answer
as complete.

The table name is resolved per request through the daemon's resolver, not cached at
import with a fallback to a bare `edh_overlay_audit`. That fallback is the default
CR3 removed: the pre-namespacing version of this feature created exactly those
names, so such a table can exist holding another mesh's stale data.
"""

from __future__ import annotations

import logging
from typing import Optional

from flask_restful import Resource, reqparse

from decorators import admin_api
from api.v1.mesh._context import MeshContextError, mesh_endpoint, resolve_mesh_id
from api.v1.mesh import lifecycle as lifecycle_rules
from api.v1.mesh import observability as obs
from utils.error import SocaError
from utils.response import SocaResponse

from overlay_daemon import ddb_client

logger = logging.getLogger("soca_logger")

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def _clamp_limit(requested: Optional[int]) -> int:
    """
    A usable page size from whatever arrived.

    Clamped rather than rejected, because a limit outside the range is a caller
    being imprecise about presentation and not a reason to refuse to show an
    audit log. A non-positive value falls back to the default rather than
    returning nothing, which would read as an empty audit trail.
    """
    if requested is None or requested < 1:
        return DEFAULT_LIMIT
    return min(requested, MAX_LIMIT)


class MeshAudit(Resource):
    @admin_api
    @mesh_endpoint
    def get(self):
        try:
            mesh_id = resolve_mesh_id()
        except MeshContextError as e:
            return SocaError.GENERIC_ERROR(
                helper=str(e), status_code=e.status_code
            ).as_flask()

        parser = reqparse.RequestParser()
        for name in ("cluster_id", "action", "actor", "cursor"):
            parser.add_argument(name, type=str, location="args")
        for name in ("limit", "start_ts", "end_ts"):
            parser.add_argument(name, type=int, location="args")
        args = parser.parse_args(strict=False)

        limit = _clamp_limit(args.get("limit"))

        try:
            start_key = obs.decode_cursor(
                args.get("cursor"), expected_mesh_id=mesh_id
            )
        except obs.MalformedCursor as e:
            # Refused rather than ignored. Falling back to the first page would
            # give a caller paging forward the same page again, with no error.
            return SocaError.GENERIC_ERROR(helper=str(e), status_code=400).as_flask()

        filters = {
            "cluster_id": args.get("cluster_id"),
            "action": args.get("action"),
            "actor": args.get("actor"),
            "start_ts": args.get("start_ts"),
            "end_ts": args.get("end_ts"),
        }

        try:
            rows, next_key, budget_exhausted = ddb_client.query_audit_events(
                mesh_id=mesh_id,
                limit=limit,
                start_key=start_key,
                matches=obs.audit_matcher(**filters),
            )
        except ddb_client.DDBQueryError as e:
            logger.exception("mesh audit query failed for mesh %s", mesh_id)
            return SocaError.GENERIC_ERROR(
                helper=f"Could not read the audit log for mesh {mesh_id}: {e}",
                status_code=503,
                ).as_flask()

        return SocaResponse(
            success=True,
            message={
                "mesh_id": mesh_id,
                "events": [_row_to_event(row) for row in rows],
                "next_cursor": obs.encode_cursor(next_key),
                "filters_applied": dict(filters, limit=limit),
                # Every action the log can contain, so a client can offer a
                # historical filter for all of them. Deliberately NOT the peers'
                # permitted_actions, which is what can be done to a peer NOW: those
                # two sets are different questions and the page had been answering
                # the wrong one. approve is permitted only from PENDING, so once
                # every peer was ACTIVE an operator could no longer filter the audit
                # log for approvals, which is the query an audit log exists for.
                "filterable_actions": sorted(lifecycle_rules.TRANSITIONS),
                # True when paging stopped because the scan budget ran out rather
                # than because the limit was met or the log ended. The caller has
                # a partial answer and a cursor to continue from, and saying so is
                # the difference between "no more matches" and "we stopped looking".
                "search_incomplete": budget_exhausted,
            },
        ).as_flask()


def _row_to_event(row: dict) -> dict:
    """
    One audit row as the UI reads it.

    Every field defaults rather than being required, because these rows outlive
    schema changes: the source-context fields were added after the first ones were
    written, so a mesh in service has rows without them, and a missing field must
    render as blank rather than failing the whole page.
    """
    return {
        "event_id": str(row.get("event_id") or ""),
        "action": str(row.get("action") or ""),
        "target_cluster_id": str(row.get("target_cluster_id") or ""),
        "actor": str(row.get("actor") or ""),
        "reason": str(row.get("reason") or ""),
        "ts": obs._as_int(row.get("ts"), default=0),
        "metadata": obs.as_display_dict(row.get("metadata")),
        "source_cluster_id": str(row.get("source_cluster_id") or ""),
        "source_region": str(row.get("source_region") or ""),
        "source_account_id": str(row.get("source_account_id") or ""),
    }
