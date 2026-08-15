# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from datetime import datetime

from sqlalchemy import or_, not_

from flask import request
from flask_restful import Resource
from flask_babel import gettext as _

from decorators import admin_api, feature_flag
from models import ApiAuditLog
from extensions import db
from utils.response import SocaResponse
from utils.validators import Validators
from scheduled_tasks.refresh_api_path_stats import get_cached_stats

logger = logging.getLogger("soca_logger")


class AdminAuditLog(Resource):
    @admin_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def get(self):
        """
        Query the API audit log (admin)
        ---
        openapi: 3.1.0
        operationId: adminGetAuditLog
        tags:
          - Token (Admin)
        summary: Query the token API audit log
        description: |
          Returns paginated audit log entries for scoped token API usage. Supports
          filtering by user, token_id, path, method, status, and time range.
          Requires admin (sudo) privileges.
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
            description: Admin username
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
            description: Admin authentication token
          - name: user
            in: query
            required: false
            schema:
              type: string
            description: Filter by username
          - name: token_id
            in: query
            required: false
            schema:
              type: integer
            description: Filter by token ID
          - name: path
            in: query
            required: false
            schema:
              type: string
            description: "Filter by API path (supports wildcard suffix, e.g. /api/user/*)"
          - name: method
            in: query
            required: false
            schema:
              type: string
              enum: ["GET", "POST", "PUT", "DELETE"]
            description: Filter by HTTP method
          - name: status
            in: query
            required: false
            schema:
              type: string
              enum: ["success", "denied", "error"]
            description: Filter by response status category
          - name: from
            in: query
            required: false
            schema:
              type: string
              format: date-time
            description: Start of time range (ISO 8601)
          - name: to
            in: query
            required: false
            schema:
              type: string
              format: date-time
            description: End of time range (ISO 8601)
          - name: limit
            in: query
            required: false
            schema:
              type: integer
              default: 100
              maximum: 1000
            description: Maximum number of entries to return
          - name: offset
            in: query
            required: false
            schema:
              type: integer
              default: 0
            description: Number of entries to skip (pagination)
        responses:
          '200':
            description: Audit log entries retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      properties:
                        total:
                          type: integer
                          description: Total number of matching entries
                        entries:
                          type: array
                          items:
                            type: object
                            properties:
                              id:
                                type: integer
                              timestamp:
                                type: string
                                format: date-time
                              user:
                                type: string
                              token_id:
                                type: integer
                                nullable: true
                              token_name:
                                type: string
                                nullable: true
                              token_type:
                                type: string
                              method:
                                type: string
                              path:
                                type: string
                              status_code:
                                type: integer
                              ip:
                                type: string
                              user_agent:
                                type: string
                                nullable: true
                              duration_ms:
                                type: integer
                                nullable: true
                              denied_reason:
                                type: string
                                nullable: true
          '401':
            description: Not authorized (requires admin privileges)
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
        """
        filter_user = request.args.get("user")
        filter_token_id = request.args.get("token_id", type=int)
        filter_path = request.args.get("path")
        filter_method = request.args.get("method")
        filter_status = request.args.get("status")
        filter_actor = request.args.get("actor")
        filter_source = request.args.get("source")
        filter_ip = request.args.get("ip")
        filter_reason = request.args.get("reason")
        filter_from = request.args.get("from")
        filter_to = request.args.get("to")
        filter_include_obo = request.args.get("include_obo", "true").lower() != "false"
        limit = min(request.args.get("limit", 100, type=int), 1000)
        offset = request.args.get("offset", 0, type=int)

        query = ApiAuditLog.query

        def _split_pos_neg(raw):
            pos, neg = [], []
            for tok in (raw or "").split(","):
                tok = tok.strip()
                if not tok:
                    continue
                if tok.startswith("!"):
                    _t = tok[1:].strip()
                    if _t:
                        neg.append(_t)
                else:
                    pos.append(tok)
            return pos, neg

        def _path_cond(p):
            return ApiAuditLog.path.contains(p.strip("*"), autoescape=True)

        def _apply_substr(q, col, raw):
            _pos, _neg = _split_pos_neg(raw)
            if _pos:
                q = q.filter(or_(*[col.contains(p.strip("*"), autoescape=True) for p in _pos]))
            for _n in _neg:
                q = q.filter(or_(col.is_(None), not_(col.contains(_n.strip("*"), autoescape=True))))
            return q

        # User: "!" negates. When include_obo, also match rows where the user is the on_behalf_of principal.
        _u_pos, _u_neg = _split_pos_neg(filter_user)
        if _u_pos:
            if filter_include_obo:
                query = query.filter(or_(ApiAuditLog.user.in_(_u_pos), ApiAuditLog.on_behalf_of.in_(_u_pos)))
            else:
                query = query.filter(ApiAuditLog.user.in_(_u_pos))
        if _u_neg:
            if filter_include_obo:
                query = query.filter(
                    ApiAuditLog.user.notin_(_u_neg),
                    or_(ApiAuditLog.on_behalf_of.is_(None), ApiAuditLog.on_behalf_of.notin_(_u_neg)),
                )
            else:
                query = query.filter(ApiAuditLog.user.notin_(_u_neg))

        if filter_token_id:
            query = query.filter(ApiAuditLog.token_id == filter_token_id)

        # Path: comma-separated, "!" negates, substring/contains match per token.
        _p_pos, _p_neg = _split_pos_neg(filter_path)
        if _p_pos:
            query = query.filter(or_(*[_path_cond(p) for p in _p_pos]))
        for _pn in _p_neg:
            query = query.filter(not_(_path_cond(_pn)))

        # Method: tri-state — "!" prefix excludes. include -> in_, exclude -> notin_.
        _m_pos, _m_neg = _split_pos_neg(filter_method)
        _m_pos = [m.upper() for m in _m_pos]
        _m_neg = [m.upper() for m in _m_neg]
        if _m_pos:
            query = query.filter(ApiAuditLog.method.in_(_m_pos))
        if _m_neg:
            query = query.filter(ApiAuditLog.method.notin_(_m_neg))

        # Status: tri-state buckets. include -> OR of bucket conds; exclude -> AND NOT each.
        def _status_cond(s):
            if Validators.is_string_equal(s, "success"):
                return ApiAuditLog.status_code < 400
            if Validators.is_string_equal(s, "denied"):
                return ApiAuditLog.status_code == 403
            if Validators.is_string_equal(s, "error"):
                return ApiAuditLog.status_code >= 500
            return None
        _s_pos, _s_neg = _split_pos_neg(filter_status)
        _pos_conds = [c for s in _s_pos if (c := _status_cond(s)) is not None]
        if _pos_conds:
            query = query.filter(or_(*_pos_conds))
        for s in _s_neg:
            _c = _status_cond(s)
            if _c is not None:
                query = query.filter(not_(_c))

        # Actor: tri-state — "!" prefix excludes.
        _a_pos, _a_neg = _split_pos_neg(filter_actor)
        if _a_pos:
            query = query.filter(ApiAuditLog.actor_type.in_(_a_pos))
        if _a_neg:
            query = query.filter(ApiAuditLog.actor_type.notin_(_a_neg))

        # Source / IP / Reason: substring chips with "!" negation.
        query = _apply_substr(query, ApiAuditLog.source_ref, filter_source)
        query = _apply_substr(query, ApiAuditLog.ip, filter_ip)
        query = _apply_substr(query, ApiAuditLog.denied_reason, filter_reason)

        if filter_from:
            try:
                from_dt = datetime.fromisoformat(filter_from.replace("Z", "+00:00"))
                query = query.filter(ApiAuditLog.timestamp >= from_dt)
            except ValueError:
                pass
        if filter_to:
            try:
                to_dt = datetime.fromisoformat(filter_to.replace("Z", "+00:00"))
                query = query.filter(ApiAuditLog.timestamp <= to_dt)
            except ValueError:
                pass

        filter_since_id = request.args.get("since_id", type=int)
        if filter_since_id:
            query = query.filter(ApiAuditLog.id > filter_since_id)

        total = query.count()
        entries = (
            query.order_by(ApiAuditLog.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        # Path latency stats read from the api_path_stats matview (worker-consistent).
        _stats_resp = get_cached_stats()
        _path_stats = _stats_resp.get("message") if _stats_resp.get("success") is True else {}

        result = []
        for e in entries:
            entry = {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat() + "Z",
                    "user": e.user,
                    "actor_type": e.actor_type,
                    "source_ref": e.source_ref,
                    "on_behalf_of": e.on_behalf_of,
                    "via_ip": e.via_ip,
                    "token_id": e.token_id,
                    "token_name": e.token_name,
                    "token_type": e.token_type,
                    "method": e.method,
                    "path": e.path,
                    "status_code": e.status_code,
                    "ip": e.ip,
                    "user_agent": e.user_agent,
                    "duration_ms": e.duration_ms,
                    "denied_reason": e.denied_reason,
                }
            stats = _path_stats.get((e.path, e.method))
            if stats and e.duration_ms is not None:
                entry["path_p95"] = stats["p95"]
                entry["path_p99"] = stats["p99"]
            result.append(entry)

        return SocaResponse(
            success=True,
            message={"total": total, "entries": result},
        ).as_flask()
