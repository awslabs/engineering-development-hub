# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
USB profile admin API (Hardware Profile feature, Phase 1).

Thin flask_restful handlers over services.usb_profile_service. Admin-only.
All handlers return .as_flask() (web-tier contract); the service functions
return SocaResponse/SocaError which are serialized here.
"""

import logging
import json

from flask import request, session
from flask_restful import Resource, reqparse

from decorators import admin_api, feature_flag
from utils.error import SocaError
import utils.usb_profile_service as usb_svc

logger = logging.getLogger("soca_logger")


def _actor():
    """Acting admin username. @admin_api authorizes via X-EDH header pair,
    root key, OR the browser session cookie -- so resolve the header first,
    then the session (browser AJAX), matching the session-sharing handlers."""
    return request.headers.get("X-EDH-USER") or session.get("user") or "admin"


class UsbProfilesManager(Resource):
    """/api/dcv/usb_profiles -- list + create USB device allowlists."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        List USB profiles
        ---
        openapi: 3.1.0
        operationId: listUsbProfiles
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
          - name: include_inactive
            in: query
            schema:
              type: string
            required: false
            description: Include inactive profiles (1, true, or yes to enable)
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
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("include_inactive", type=str, location="args")
        args = parser.parse_args()
        _include = str(args.get("include_inactive") or "").lower() in ("1", "true", "yes")
        return usb_svc.list_usb_profiles(include_inactive=_include).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        r"""
        Create a USB profile
        ---
        openapi: 3.1.0
        operationId: createUsbProfile
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
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - profile_name
                properties:
                  profile_name:
                    type: string
                    description: Name for the new USB profile
                  description:
                    type: string
                    description: Optional description
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
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        _user = _actor()
        parser = reqparse.RequestParser()
        parser.add_argument("profile_name", type=str, required=True, location="form")
        parser.add_argument("description", type=str, location="form")
        args = parser.parse_args()
        return usb_svc.create_usb_profile(
            profile_name=args["profile_name"],
            description=args.get("description"),
            created_by=_user,
        ).as_flask()


class UsbProfileDetail(Resource):
    """/api/dcv/usb_profiles/<id> -- get, update, deactivate one profile."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self, profile_id):
        r"""
        Get a USB profile by ID
        ---
        openapi: 3.1.0
        operationId: getUsbProfile
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
          - name: profile_id
            in: path
            schema:
              type: integer
            required: true
            description: USB profile ID
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
          '401':
            description: Authentication required
          '404':
            description: USB profile not found
          '500':
            description: Server error
        """
        return usb_svc.get_usb_profile(profile_id).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def put(self, profile_id):
        r"""
        Update a USB profile
        ---
        openapi: 3.1.0
        operationId: updateUsbProfile
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
          - name: profile_id
            in: path
            schema:
              type: integer
            required: true
            description: USB profile ID
        requestBody:
          required: false
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                properties:
                  profile_name:
                    type: string
                    description: Updated profile name
                  description:
                    type: string
                    description: Updated description
                  is_active:
                    type: string
                    description: Active state (1/true/yes or 0/false/no)
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
          '401':
            description: Authentication required
          '404':
            description: USB profile not found
          '500':
            description: Server error
        """
        _user = _actor()
        parser = reqparse.RequestParser()
        parser.add_argument("profile_name", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("is_active", type=str, location="form")
        args = parser.parse_args()
        _fields = {}
        if args.get("profile_name") is not None:
            _fields["profile_name"] = args["profile_name"]
        if args.get("description") is not None:
            _fields["description"] = args["description"]
        if args.get("is_active") is not None:
            _fields["is_active"] = str(args["is_active"]).lower() in ("1", "true", "yes")
        return usb_svc.update_usb_profile(
            profile_id, updated_by=_user, **_fields
        ).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def delete(self, profile_id):
        r"""
        Deactivate a USB profile
        ---
        openapi: 3.1.0
        operationId: deleteUsbProfile
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
          - name: profile_id
            in: path
            schema:
              type: integer
            required: true
            description: USB profile ID to deactivate
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
          '401':
            description: Authentication required
          '404':
            description: USB profile not found
          '500':
            description: Server error
        """
        _user = _actor()
        return usb_svc.deactivate_usb_profile(
            profile_id, deactivated_by=_user
        ).as_flask()


class UsbProfileEntriesManager(Resource):
    """/api/dcv/usb_profiles/<id>/entries -- add an allowlist entry.

    Accepts either a raw `filter_string` (paste-to-parse) or the discrete
    8 fields (device_label, base_class, sub_class, protocol, vid, pid,
    support_autoshare, skip_reset).
    """

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self, profile_id):
        r"""
        Add an allowlist entry to a USB profile
        ---
        openapi: 3.1.0
        operationId: createUsbProfileEntry
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
          - name: profile_id
            in: path
            schema:
              type: integer
            required: true
            description: USB profile ID to add the entry to
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                properties:
                  filter_string:
                    type: string
                    description: Raw DCV USB filter string (paste-to-parse; alternative to discrete fields)
                  device_label:
                    type: string
                    description: Human-readable device label
                  base_class:
                    type: string
                    description: USB base class code
                  sub_class:
                    type: string
                    description: USB sub-class code
                  protocol:
                    type: string
                    description: USB protocol code
                  vid:
                    type: string
                    description: Vendor ID
                  pid:
                    type: string
                    description: Product ID
                  support_autoshare:
                    type: string
                    description: Whether to auto-share this device
                  skip_reset:
                    type: string
                    description: Whether to skip USB reset
                  enabled:
                    type: string
                    description: Whether this entry is enabled
                  admin_comment:
                    type: string
                    description: Optional admin comment
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
          '400':
            description: Invalid filter string or entry fields
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        _user = _actor()
        parser = reqparse.RequestParser()
        parser.add_argument("filter_string", type=str, location="form")
        parser.add_argument("device_label", type=str, location="form")
        parser.add_argument("base_class", type=str, location="form")
        parser.add_argument("sub_class", type=str, location="form")
        parser.add_argument("protocol", type=str, location="form")
        parser.add_argument("vid", type=str, location="form")
        parser.add_argument("pid", type=str, location="form")
        parser.add_argument("support_autoshare", type=str, location="form")
        parser.add_argument("skip_reset", type=str, location="form")
        parser.add_argument("enabled", type=str, location="form")
        parser.add_argument("admin_comment", type=str, location="form")
        args = parser.parse_args()

        if args.get("filter_string"):
            _parsed = usb_svc.parse_filter_string(args["filter_string"])
            if not _parsed.success:
                return _parsed.as_flask()
            _fields = _parsed.message
        else:
            _fields = {
                "device_label": args.get("device_label"),
                "base_class": args.get("base_class"),
                "sub_class": args.get("sub_class"),
                "protocol": args.get("protocol"),
                "vid": args.get("vid"),
                "pid": args.get("pid"),
                "support_autoshare": args.get("support_autoshare"),
                "skip_reset": args.get("skip_reset"),
            }
        if args.get("enabled") is not None:
            _fields["enabled"] = args["enabled"]
        if args.get("admin_comment") is not None:
            _fields["admin_comment"] = args["admin_comment"]
        return usb_svc.add_entry(profile_id, created_by=_user, **_fields).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def put(self, profile_id):
        r"""
        Batch-reconcile USB profile entries to the posted desired set
        ---
        openapi: 3.1.0
        operationId: batchUpdateUsbProfileEntries
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
          - name: profile_id
            in: path
            schema:
              type: integer
            required: true
            description: USB profile ID
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - entries_json
                properties:
                  entries_json:
                    type: string
                    description: JSON array of entry objects (each optionally carrying an existing integer id)
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
          '400':
            description: Invalid JSON in entries_json
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        _user = _actor()
        parser = reqparse.RequestParser()
        parser.add_argument("entries_json", type=str, required=True, location="form")
        args = parser.parse_args()
        try:
            desired = json.loads(args["entries_json"])
        except (ValueError, TypeError) as e:
            return SocaError.GENERIC_ERROR(
                helper=f"entries_json must be a valid JSON array: {e}", status_code=400
            ).as_flask()
        return usb_svc.set_entries(profile_id, actor=_user, desired=desired).as_flask()


class UsbProfileEntryDetail(Resource):
    """/api/dcv/usb_profiles/entries/<entry_id> -- delete one entry."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def delete(self, entry_id):
        r"""
        Delete a USB profile entry
        ---
        openapi: 3.1.0
        operationId: deleteUsbProfileEntry
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
          - name: entry_id
            in: path
            schema:
              type: integer
            required: true
            description: ID of the USB allowlist entry to delete
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
          '401':
            description: Authentication required
          '404':
            description: Entry not found
          '500':
            description: Server error
        """
        return usb_svc.remove_entry(entry_id).as_flask()


class UsbFilterStringParse(Resource):
    """/api/dcv/usb_profiles/parse -- validate/normalize a pasted filter string
    without storing it (WebUI paste-to-parse preview)."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        r"""
        Parse and validate a USB filter string without storing it
        ---
        openapi: 3.1.0
        operationId: parseUsbFilterString
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
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - filter_string
                properties:
                  filter_string:
                    type: string
                    description: Raw DCV USB filter string to validate and normalize
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
          '400':
            description: Invalid filter string
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("filter_string", type=str, required=True, location="form")
        args = parser.parse_args()
        return usb_svc.parse_filter_string(args["filter_string"]).as_flask()
