# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Caller-scoped user preferences API.

Registered (see app.py) at two URLs:
    GET    /api/user/preferences            -> resolve ALL prefs (value + metadata)
    GET    /api/user/preferences/<key>      -> resolve ONE pref
    PUT    /api/user/preferences/<key>      -> set ONE pref       (body: value=...)
    DELETE /api/user/preferences            -> reset ALL (delete the user's row)
    DELETE /api/user/preferences/<key>      -> reset ONE (delete the attribute)

Authorization (see docs/UserPreferences-Design.md, decision 8): every operation
acts on the AUTHENTICATED CALLER's own row only. The target username is derived
from the @private_api-authenticated identity (server-signed session cookie, or
the token-validated X-EDH-USER header) -- NEVER from the request body or query.
There is no client-supplied user/object id to tamper with, so there is no
cross-user (IDOR) surface.

Responses are inherently JSON-safe: the store decodes every DynamoDB attribute
to a native python scalar (no Decimal escapes the store layer).
"""

import logging

from flask import request, session
from flask_restful import Resource

from decorators import private_api
from utils.response import SocaResponse
from utils import user_pref_store as prefs
from utils import user_pref_catalog as catalog

logger = logging.getLogger("soca_logger")


def _caller():
    """
    The authenticated caller's username under @private_api: the server-signed
    session user (browser path) or the token-validated X-EDH-USER header (CLI
    path). Returns None for the root-API-key path, which has no associated user
    and therefore cannot manage "its own" preferences.
    """
    return session.get("user") or request.headers.get("X-EDH-USER")


class UserPreferences(Resource):
    """Self-scoped CRUD over the calling user's preferences."""

    @private_api
    def get(self, key=None):
        r"""
        Get user preferences (all or a single key)
        ---
        openapi: 3.1.0
        operationId: getUserPreferences
        tags:
          - User
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
            in: path
            schema:
              type: string
            required: false
            description: Specific preference key to retrieve. If omitted, all preferences are returned.
        responses:
          '200':
            description: Success
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      description: Resolved preference(s) with value and metadata
          '400':
            description: No authenticated user
          '404':
            description: Unknown preference key
        """
        _user = _caller()
        if not _user:
            return SocaResponse(
                success=False,
                message="No authenticated user for preferences",
                status_code=400,
            ).as_flask()

        if key is None:
            _result = prefs.resolve_all(_user)
            if not _result.success:
                return _result.as_flask()
            return SocaResponse(
                success=True, message=_result.message
            ).as_flask()

        if not catalog._is_known(key):
            return SocaResponse(
                success=False,
                message=f"unknown preference key '{key}'",
                status_code=404,
            ).as_flask()
        _resolved = prefs.resolve_pref(_user, key)
        if not _resolved.success:
            return _resolved.as_flask()
        return SocaResponse(
            success=True, message=_resolved.message
        ).as_flask()

    @private_api
    def put(self, key=None):
        r"""
        Set a user preference value
        ---
        openapi: 3.1.0
        operationId: updateUserPreference
        tags:
          - User
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
            in: path
            schema:
              type: string
            required: true
            description: Preference key to set
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - value
                properties:
                  value:
                    description: The value to set for the preference (type depends on the preference catalog definition)
        responses:
          '200':
            description: Preference set successfully, returns the resolved preference with metadata
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      description: Resolved preference with value, metadata, and source
          '400':
            description: No authenticated user, missing key in URL, missing value in body, or validation error
          '401':
            description: Authentication required
        """
        _user = _caller()
        if not _user:
            return SocaResponse(
                success=False,
                message="No authenticated user for preferences",
                status_code=400,
            ).as_flask()
        if key is None:
            return SocaResponse(
                success=False,
                message="preference key is required in the URL",
                status_code=400,
            ).as_flask()

        _body = request.get_json(silent=True)
        if _body is None:
            _body = request.form
        if not _body or "value" not in _body:
            return SocaResponse(
                success=False,
                message="missing 'value' in request body",
                status_code=400,
            ).as_flask()

        # set_pref validates + coerces against the catalog; on bad key/type/
        # range it returns a failed SocaResponse (status 400), which we surface.
        _result = prefs.set_pref(_user, key, _body.get("value"))
        if not _result.success:
            return _result.as_flask()

        # Return the freshly-resolved pref (value + metadata) so the UI updates
        # its is_set/source without a second round-trip.
        _resolved = prefs.resolve_pref(_user, key)
        if not _resolved.success:
            return _resolved.as_flask()
        return SocaResponse(
            success=True, message=_resolved.message
        ).as_flask()

    @private_api
    def delete(self, key=None):
        r"""
        Reset user preferences (all or a single key)
        ---
        openapi: 3.1.0
        operationId: deleteUserPreferences
        tags:
          - User
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
            in: path
            schema:
              type: string
            required: false
            description: Specific preference key to reset. If omitted, all preferences are cleared.
        responses:
          '200':
            description: Preference(s) reset successfully (values fall back to defaults)
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: string
          '400':
            description: No authenticated user or unknown preference key
          '401':
            description: Authentication required
        """
        _user = _caller()
        if not _user:
            return SocaResponse(
                success=False,
                message="No authenticated user for preferences",
                status_code=400,
            ).as_flask()

        # No key -> reset the entire row (every pref falls back to its default).
        if key is None:
            return prefs.clear_all(_user).as_flask()

        # Single-key reset -> delete the attribute (unknown key -> 400).
        return prefs.clear_pref(_user, key).as_flask()
