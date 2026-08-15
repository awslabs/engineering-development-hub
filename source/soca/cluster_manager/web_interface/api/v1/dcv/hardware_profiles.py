# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Hardware profile admin API (Hardware Profile feature, Phase 1).

Thin flask_restful handlers over services.hardware_profile_service. Admin-only.
Covers container CRUD, USB sub-profile linking (via usb_profile_id on
create/update), Project-over-Stack bindings, and a resolve+render preview.
"""

import logging

from flask import request, session
from flask_restful import Resource, reqparse

from decorators import admin_api, feature_flag
from utils.error import SocaError
from utils.cast import SocaCastEngine
import utils.hardware_profile_service as hp_svc

logger = logging.getLogger("soca_logger")


def _actor():
    """Acting admin username: X-EDH-USER header (CLI/service) or the browser
    session cookie (AJAX). @admin_api has already authorized the caller."""
    return request.headers.get("X-EDH-USER") or session.get("user") or "admin"


def _optional_int(value):
    """Cast an optional str id to int (None stays None). Returns (ok, value)."""
    if value is None or str(value).strip() == "":
        return True, None
    _cast = SocaCastEngine(value).cast_as(int)
    if not _cast.success:
        return False, None
    return True, _cast.message


class HardwareProfilesManager(Resource):
    """/api/dcv/hardware_profiles -- list + create Hardware Profiles."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        List hardware profiles
        ---
        openapi: 3.1.0
        operationId: listHardwareProfiles
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
        return hp_svc.list_hardware_profiles(include_inactive=_include).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        r"""
        Create a hardware profile
        ---
        openapi: 3.1.0
        operationId: createHardwareProfile
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
                    description: Name for the new hardware profile
                  description:
                    type: string
                    description: Optional description
                  usb_profile_id:
                    type: string
                    description: Optional USB profile ID to link
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
            description: Invalid input (e.g. usb_profile_id not an integer)
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        _user = _actor()
        parser = reqparse.RequestParser()
        parser.add_argument("profile_name", type=str, required=True, location="form")
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("usb_profile_id", type=str, location="form")
        args = parser.parse_args()
        _ok, _usb_id = _optional_int(args.get("usb_profile_id"))
        if not _ok:
            return SocaError.GENERIC_ERROR(
                helper="usb_profile_id must be an integer", status_code=400
            ).as_flask()
        return hp_svc.create_hardware_profile(
            profile_name=args["profile_name"],
            description=args.get("description"),
            created_by=_user,
            usb_profile_id=_usb_id,
        ).as_flask()


class HardwareProfileDetail(Resource):
    """/api/dcv/hardware_profiles/<id> -- get, update, deactivate."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self, hp_id):
        r"""
        Get a hardware profile by ID
        ---
        openapi: 3.1.0
        operationId: getHardwareProfile
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
          - name: hp_id
            in: path
            schema:
              type: integer
            required: true
            description: Hardware profile ID
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
            description: Hardware profile not found
          '500':
            description: Server error
        """
        return hp_svc.get_hardware_profile(hp_id).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def put(self, hp_id):
        r"""
        Update a hardware profile
        ---
        openapi: 3.1.0
        operationId: updateHardwareProfile
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
          - name: hp_id
            in: path
            schema:
              type: integer
            required: true
            description: Hardware profile ID
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
                  usb_profile_id:
                    type: string
                    description: USB profile ID to link (empty string clears the link)
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
          '400':
            description: Invalid input (e.g. usb_profile_id not an integer)
          '401':
            description: Authentication required
          '404':
            description: Hardware profile not found
          '500':
            description: Server error
        """
        _user = _actor()
        parser = reqparse.RequestParser()
        parser.add_argument("profile_name", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        # usb_profile_id: present-and-empty clears the link; absent leaves it.
        parser.add_argument("usb_profile_id", type=str, location="form")
        parser.add_argument("is_active", type=str, location="form")
        args = parser.parse_args()
        _fields = {}
        if args.get("profile_name") is not None:
            _fields["profile_name"] = args["profile_name"]
        if args.get("description") is not None:
            _fields["description"] = args["description"]
        if args.get("is_active") is not None:
            _fields["is_active"] = str(args["is_active"]).lower() in ("1", "true", "yes")
        if "usb_profile_id" in request.form or "usb_profile_id" in request.args:
            _ok, _usb_id = _optional_int(args.get("usb_profile_id"))
            if not _ok:
                return SocaError.GENERIC_ERROR(
                    helper="usb_profile_id must be an integer or empty", status_code=400
                ).as_flask()
            _fields["usb_profile_id"] = _usb_id
        return hp_svc.update_hardware_profile(hp_id, updated_by=_user, **_fields).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def delete(self, hp_id):
        r"""
        Deactivate a hardware profile
        ---
        openapi: 3.1.0
        operationId: deleteHardwareProfile
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
          - name: hp_id
            in: path
            schema:
              type: integer
            required: true
            description: Hardware profile ID to deactivate
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
            description: Hardware profile not found
          '500':
            description: Server error
        """
        _user = _actor()
        return hp_svc.deactivate_hardware_profile(hp_id, deactivated_by=_user).as_flask()


class HardwareProfileBinding(Resource):
    """/api/dcv/hardware_profiles/bind -- bind (or clear) a profile on a
    Software Stack or Project. Body: target_type=stack|project, target_id,
    hardware_profile_id (empty to clear)."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        r"""
        Bind or clear a hardware profile on a Software Stack or Project
        ---
        openapi: 3.1.0
        operationId: bindHardwareProfile
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
                  - target_type
                  - target_id
                properties:
                  target_type:
                    type: string
                    enum:
                      - stack
                      - project
                    description: Type of target to bind (stack or project)
                  target_id:
                    type: string
                    description: Integer ID of the target stack or project
                  hardware_profile_id:
                    type: string
                    description: Hardware profile ID to bind (empty to clear)
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
            description: Invalid input (bad target_type, target_id, or hardware_profile_id)
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        _user = _actor()
        parser = reqparse.RequestParser()
        parser.add_argument("target_type", type=str, required=True, location="form")
        parser.add_argument("target_id", type=str, required=True, location="form")
        parser.add_argument("hardware_profile_id", type=str, location="form")
        args = parser.parse_args()

        _tt = str(args["target_type"]).lower()
        _ok_t, _target_id = _optional_int(args["target_id"])
        if not _ok_t or _target_id is None:
            return SocaError.GENERIC_ERROR(
                helper="target_id must be an integer", status_code=400
            ).as_flask()
        _ok_h, _hp_id = _optional_int(args.get("hardware_profile_id"))
        if not _ok_h:
            return SocaError.GENERIC_ERROR(
                helper="hardware_profile_id must be an integer or empty", status_code=400
            ).as_flask()

        if _tt == "stack":
            return hp_svc.bind_to_stack(_target_id, _hp_id, updated_by=_user).as_flask()
        if _tt == "project":
            return hp_svc.bind_to_project(_target_id, _hp_id, updated_by=_user).as_flask()
        return SocaError.GENERIC_ERROR(
            helper="target_type must be 'stack' or 'project'", status_code=400
        ).as_flask()


class HardwareProfileSubProfileTypes(Resource):
    """/api/dcv/hardware_profiles/sub_profile_types -- registry of enabled
    sub-profile types (usb today; disk/cpu later). Drives the admin detail
    pane's registry-based section rendering."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        List enabled sub-profile types
        ---
        openapi: 3.1.0
        operationId: listHardwareSubProfileTypes
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
        return hp_svc.list_sub_profile_types().as_flask()


class HardwareProfileBindingsList(Resource):
    """/api/dcv/hardware_profiles/bindings -- read-only rollup of every active
    Software Stack / Project that currently binds a Hardware Profile. Bindings
    are set/cleared on the Stack or Project edit page, not here."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        List all hardware profile bindings
        ---
        openapi: 3.1.0
        operationId: listHardwareProfileBindings
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
        return hp_svc.list_all_bindings().as_flask()


class HardwareProfilePreview(Resource):
    """/api/dcv/hardware_profiles/preview -- resolve the effective profile for a
    Software Stack (+ optional Project) and render its USB allowlist lines."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        Preview the resolved USB allowlist for a Software Stack and optional Project
        ---
        openapi: 3.1.0
        operationId: previewHardwareProfileAllowlist
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
          - name: software_stack_id
            in: query
            schema:
              type: string
            required: true
            description: Integer ID of the software stack to resolve
          - name: project_id
            in: query
            schema:
              type: string
            required: false
            description: Optional integer ID of the project override
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
            description: Invalid input (bad software_stack_id or project_id)
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("software_stack_id", type=str, required=True, location="args")
        parser.add_argument("project_id", type=str, location="args")
        args = parser.parse_args()
        _ok_s, _stack_id = _optional_int(args["software_stack_id"])
        if not _ok_s or _stack_id is None:
            return SocaError.GENERIC_ERROR(
                helper="software_stack_id must be an integer", status_code=400
            ).as_flask()
        _ok_p, _project_id = _optional_int(args.get("project_id"))
        if not _ok_p:
            return SocaError.GENERIC_ERROR(
                helper="project_id must be an integer or empty", status_code=400
            ).as_flask()
        return hp_svc.preview_allowlist_for_stack_project(
            _stack_id, project_id=_project_id
        ).as_flask()
