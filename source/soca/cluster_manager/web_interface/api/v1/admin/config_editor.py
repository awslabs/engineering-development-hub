# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Admin Configuration Editor API (read slice).

Thin flask_restful handlers over services.config_editor_service. Admin-only
(@admin_api requires sudo). All handlers return .as_flask() (web-tier contract).
Write endpoints (batch apply) land in a later slice.
"""

import logging
import json

from flask import request, session
from flask_restful import Resource, reqparse

from decorators import admin_api, feature_flag
from utils.error import SocaError
from utils.cast import SocaCastEngine
import utils.config_editor_service as cfg_svc

logger = logging.getLogger("soca_logger")


class ConfigTree(Resource):
    """/api/admin/config/tree -- nested path-segment tree of visible params."""

    @admin_api
    @feature_flag(flag_name="CONFIG_EDITOR", mode="api")
    def get(self):
        r"""
        Get nested path-segment tree of visible configuration parameters
        ---
        openapi: 3.1.0
        operationId: getConfigTree
        tags:
          - Admin
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
        responses:
          '200':
            description: Nested tree structure of configuration parameters
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '401':
            description: Authentication required or not an admin
          '403':
            description: CONFIG_EDITOR feature flag is disabled
          '500':
            description: Failed to build configuration tree
        """
        return cfg_svc.build_tree().as_flask()


class ConfigParams(Resource):
    """/api/admin/config/params?prefix=/configuration/... -- flat list under a prefix."""

    @admin_api
    @feature_flag(flag_name="CONFIG_EDITOR", mode="api")
    def get(self):
        r"""
        List configuration parameters under a given prefix
        ---
        openapi: 3.1.0
        operationId: getConfigParams
        tags:
          - Admin
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
          - name: prefix
            in: query
            schema:
              type: string
              default: /
            required: false
            description: Parameter path prefix to list under (e.g. /configuration/...)
          - name: direct
            in: query
            schema:
              type: string
              enum: ["true", "false", "1", "0", "yes", "no"]
            required: false
            description: If true, only return direct children of the prefix
        responses:
          '200':
            description: Flat list of parameters under the specified prefix
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '401':
            description: Authentication required or not an admin
          '403':
            description: CONFIG_EDITOR feature flag is disabled
          '500':
            description: Failed to list configuration parameters
        """
        parser = reqparse.RequestParser()
        parser.add_argument("prefix", type=str, location="args")
        parser.add_argument("direct", type=str, location="args")
        args = parser.parse_args()
        _dc = SocaCastEngine(args.get("direct") or "").cast_as(str)
        _direct = (_dc.message if _dc.success else "").lower() in ("1", "true", "yes")
        return cfg_svc.list_params(prefix=args.get("prefix") or "/", direct=_direct).as_flask()


class ConfigParamDetail(Resource):
    """/api/admin/config/param?key=/configuration/... -- one param + policy."""

    @admin_api
    @feature_flag(flag_name="CONFIG_EDITOR", mode="api")
    def get(self):
        r"""
        Get a single configuration parameter with its policy metadata
        ---
        openapi: 3.1.0
        operationId: getConfigParamDetail
        tags:
          - Admin
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
          - name: key
            in: query
            schema:
              type: string
            required: true
            description: Full parameter key path (e.g. /configuration/...)
        responses:
          '200':
            description: Parameter value and associated policy
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '400':
            description: Missing required key parameter
          '401':
            description: Authentication required or not an admin
          '403':
            description: CONFIG_EDITOR feature flag is disabled
          '500':
            description: Failed to retrieve parameter detail
        """
        parser = reqparse.RequestParser()
        parser.add_argument("key", type=str, required=True, location="args")
        args = parser.parse_args()
        return cfg_svc.get_param(args["key"]).as_flask()


class ConfigSearch(Resource):
    """/api/admin/config/search?q=&scope=key|value|both -- hidden redacted."""

    @admin_api
    @feature_flag(flag_name="CONFIG_EDITOR", mode="api")
    def get(self):
        r"""
        Search configuration parameters by key, value, or both
        ---
        openapi: 3.1.0
        operationId: searchConfigParams
        tags:
          - Admin
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
          - name: q
            in: query
            schema:
              type: string
            required: true
            description: Search query string
          - name: scope
            in: query
            schema:
              type: string
              enum: [key, value, both]
              default: both
            required: false
            description: Search scope - match against key, value, or both (hidden params are redacted)
        responses:
          '200':
            description: List of matching configuration parameters
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '400':
            description: Missing required query parameter q
          '401':
            description: Authentication required or not an admin
          '403':
            description: CONFIG_EDITOR feature flag is disabled
          '500':
            description: Search operation failed
        """
        parser = reqparse.RequestParser()
        parser.add_argument("q", type=str, required=True, location="args")
        parser.add_argument("scope", type=str, location="args")
        args = parser.parse_args()
        return cfg_svc.search(args["q"], scope=args.get("scope") or "both").as_flask()


class ConfigHistory(Resource):
    """/api/admin/config/history?key=/configuration/... -- SSM version history."""

    @admin_api
    @feature_flag(flag_name="CONFIG_EDITOR", mode="api")
    def get(self):
        r"""
        Get SSM parameter version history for a configuration key
        ---
        openapi: 3.1.0
        operationId: getConfigParamHistory
        tags:
          - Admin
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
          - name: key
            in: query
            schema:
              type: string
            required: true
            description: Full parameter key path (e.g. /configuration/...)
        responses:
          '200':
            description: Version history of the specified parameter
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '400':
            description: Missing required key parameter
          '401':
            description: Authentication required or not an admin
          '403':
            description: CONFIG_EDITOR feature flag is disabled
          '500':
            description: Failed to retrieve parameter history
        """
        parser = reqparse.RequestParser()
        parser.add_argument("key", type=str, required=True, location="args")
        args = parser.parse_args()
        return cfg_svc.get_history(args["key"]).as_flask()


class ConfigBatch(Resource):
    """/api/admin/config/batch -- best-effort batch write (staged 'Apply').

    Body: changes_json = JSON array of {key, value}. Returns per-param status.
    Editor policy (hidden/readonly) + SocaConfig value validation both apply.
    """

    @admin_api
    @feature_flag(flag_name="CONFIG_EDITOR", mode="api")
    def post(self):
        r"""
        Batch apply configuration parameter changes
        ---
        openapi: 3.1.0
        operationId: batchSetConfigParams
        tags:
          - Admin
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
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - changes_json
                properties:
                  changes_json:
                    type: string
                    description: JSON array of objects with key and value fields
        responses:
          '200':
            description: Per-parameter status of the batch write operation
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '400':
            description: changes_json is missing or not valid JSON
          '401':
            description: Authentication required or not an admin
          '403':
            description: CONFIG_EDITOR feature flag is disabled
          '500':
            description: Batch write operation failed
        """
        parser = reqparse.RequestParser()
        parser.add_argument("changes_json", type=str, required=True, location="form")
        args = parser.parse_args()
        try:
            items = json.loads(args["changes_json"])
        except (ValueError, TypeError) as e:
            return SocaError.GENERIC_ERROR(
                helper=f"changes_json must be a valid JSON array: {e}", status_code=400
            ).as_flask()
        _actor = request.headers.get("X-EDH-USER") or session.get("user") or "unknown-user"
        return cfg_svc.batch_set(items, actor=_actor).as_flask()


class ConfigActivity(Resource):
    """/api/admin/config/activity?days=&limit= -- cluster-wide recent-change feed."""

    @admin_api
    @feature_flag(flag_name="CONFIG_EDITOR", mode="api")
    def get(self):
        r"""
        Get cluster-wide recent configuration change activity feed
        ---
        openapi: 3.1.0
        operationId: getConfigActivity
        tags:
          - Admin
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
          - name: days
            in: query
            schema:
              type: integer
              default: 7
            required: false
            description: Number of days of history to retrieve
          - name: limit
            in: query
            schema:
              type: integer
              default: 200
            required: false
            description: Maximum number of activity entries to return
        responses:
          '200':
            description: Recent configuration change activity
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '401':
            description: Authentication required or not an admin
          '403':
            description: CONFIG_EDITOR feature flag is disabled
          '500':
            description: Failed to retrieve activity feed
        """
        parser = reqparse.RequestParser()
        parser.add_argument("days", type=int, location="args")
        parser.add_argument("limit", type=int, location="args")
        args = parser.parse_args()
        return cfg_svc.list_activity(days=args.get("days") or 7, limit=args.get("limit") or 200).as_flask()
