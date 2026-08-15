# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
GET /api/dcv/virtual_desktops/connection_file

Returns the same .dcv connection-file payload that the WebUI route
/virtual_desktops/client serves, but authenticated via the standard
SOCA API headers (X-EDH-USER + X-EDH-TOKEN). Lets non-browser clients
(load harnesses, native DCV launchers, automation) fetch a session's
connection file without driving the HTML form login flow.

Both this resource and the WebUI route call the shared
build_dcv_session_file() helper in views/virtual_desktops.py so the
two can never drift.
"""

import logging

from flask import Response, request
from flask_restful import Resource, reqparse

from decorators import private_api, feature_flag
from views.virtual_desktops import build_dcv_session_file

logger = logging.getLogger("soca_logger")


class GetVirtualDesktopConnectionFile(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        """
        Get a virtual desktop's .dcv connection file.
        ---
        openapi: 3.1.0
        operationId: getVirtualDesktopConnectionFile
        tags:
          - Virtual Desktops
        summary: Fetch the .dcv connection file for a session
        description: |
          Returns the .dcv connection file (as text/plain attachment)
          for the specified session. The caller must be the session owner
          or hold the admin token. Same payload as the WebUI route.
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema: {type: string}
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema: {type: string}
          - name: session_uuid
            in: query
            required: true
            schema: {type: string}
            description: Session UUID
          - name: owner
            in: query
            required: false
            schema: {type: string}
            description: |
              Session owner. Defaults to X-EDH-USER. Only the admin token
              may pass an owner different from itself; other tokens that
              attempt this get a 403.
        responses:
          '200':
            description: .dcv connection file (text/plain attachment)
          '400':
            description: Missing session_uuid
          '403':
            description: Non-admin caller requested another user's session
          '404':
            description: Session not found or not owned by user
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, required=True, location="args")
        parser.add_argument("owner", type=str, required=False, location="args")
        args = parser.parse_args()

        _caller = request.headers.get("X-EDH-USER", "")
        _token = request.headers.get("X-EDH-TOKEN", "")
        _owner = args.get("owner") or _caller

        # Cross-user fetch is admin-only. private_api has already validated
        # that _token is either the admin root key OR a per-user key for
        # _caller — so if _owner != _caller we need to confirm it's the
        # admin path.
        if _owner != _caller:
            import config
            if _token != config.Config.API_ROOT_KEY:
                return {
                    "success": False,
                    "message": "Only the admin token may fetch another user's session",
                }, 403

        result = build_dcv_session_file(
            owner=_owner, session_uuid=args["session_uuid"]
        )

        if not result["success"]:
            return {
                "success": False,
                "message": str(result.get("message", "")),
            }, result.get("status", 500)

        return Response(
            result["body"],
            mimetype="text/plain",
            headers={
                "Content-disposition": f"attachment; filename={result['filename']}",
            },
        )
