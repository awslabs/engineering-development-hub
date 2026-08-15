# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DCV Session Sharing API endpoints.

Routes (registered in app.py):
    GET    /api/dcv/session_sharing/profiles          - List profiles
    POST   /api/dcv/session_sharing/profiles          - Create profile (admin)
    PUT    /api/dcv/session_sharing/profiles/<id>     - Update profile (admin)
    DELETE /api/dcv/session_sharing/profiles/<id>     - Delete profile (admin)
    POST   /api/dcv/session_sharing/grants            - Create grant
    DELETE /api/dcv/session_sharing/grants/<id>       - Revoke grant
    GET    /api/dcv/session_sharing/grants            - List grants (filterable)
    GET    /api/dcv/session_sharing/shared_to_me      - Guest's shared sessions
    GET    /api/dcv/session_sharing/users/search      - AD/LDAP typeahead
    GET    /api/dcv/session_sharing/sessions          - Admin: running sessions
    GET/PUT /api/dcv/session_sharing/settings         - Admin: cluster settings
"""

import logging

from flask import request, session
from flask_restful import Resource

from decorators import private_api, admin_api
from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

_NOT_ENABLED_HELPER = "Session sharing not enabled"


def _get_profile_service():
    """Lazy-init profile service."""
    from helpers import dcv_session_sharing_store
    return dcv_session_sharing_store.get_profile_service()


def _get_grant_service():
    """Lazy-init grant service."""
    from helpers import dcv_session_sharing_store
    return dcv_session_sharing_store.get_grant_service()


def _user_groups(username):
    """POSIX group names for an AD/local user (matches the resources_permissions
    pattern). Returns [] if the user is not resolvable on the controller."""
    import pwd
    import grp
    import os
    groups = []
    try:
        _pw = pwd.getpwnam(username)
        for _gid in os.getgrouplist(username, _pw.pw_gid):
            try:
                groups.append(grp.getgrgid(_gid).gr_name)
            except KeyError:
                continue
    except KeyError:
        logger.warning(f"_user_groups: user {username} not resolvable; no groups")
    return groups


def _session_owner(session_id):
    """Return the AD owner of the VDI session whose broker id == session_id,
    or None if the session row cannot be resolved. Used to verify a non-admin
    caller actually owns the session they are sharing."""
    from models import db, VirtualDesktopSessions
    try:
        _vds = (
            db.session.query(VirtualDesktopSessions)
            .filter(VirtualDesktopSessions.authentication_token == session_id)
            .first()
        )
        return _vds.session_owner if _vds is not None else None
    except Exception as err:
        logger.warning(f"session owner lookup failed for {session_id}: {err}")
        return None


def _resolve_share_scope(session_id, owner_username, guest_username):
    """
    Resolve the session's share_scope from its VDI software stack and, when
    scope == 'project', the owner/guest allowed-project-ID sets so the grant
    service can enforce overlap.

    In high_scale mode the broker session id is stored on
    VirtualDesktopSessions.authentication_token. NULL/unknown scope defaults to
    'cluster' (permissive) so legacy stacks keep working.

    Returns: (share_scope, owner_projects, guest_projects)
    """
    from models import db, VirtualDesktopSessions, Projects

    share_scope = "cluster"
    try:
        _vds = (
            db.session.query(VirtualDesktopSessions)
            .filter(VirtualDesktopSessions.authentication_token == session_id)
            .first()
        )
        if _vds is not None and _vds.software_stack is not None:
            share_scope = (_vds.software_stack.share_scope or "cluster").lower()
    except Exception as err:
        logger.warning(
            f"share_scope lookup failed for session {session_id}: {err}; defaulting to cluster"
        )
        return "cluster", None, None

    owner_projects = guest_projects = None
    if share_scope == "project":
        try:
            owner_projects = list(
                Projects.get_allowed_projects_for_user(
                    db_session=db.session,
                    user_name=owner_username,
                    groups=_user_groups(owner_username),
                )
            )
            guest_projects = list(
                Projects.get_allowed_projects_for_user(
                    db_session=db.session,
                    user_name=guest_username,
                    groups=_user_groups(guest_username),
                )
            )
        except Exception as err:
            logger.error(f"project membership resolution failed: {err}")
            # Empty sets -> validator denies (fail-closed for scope=project).
            owner_projects = owner_projects or []
            guest_projects = guest_projects or []
    return share_scope, owner_projects, guest_projects


class DcvSessionSharingProfiles(Resource):
    """CRUD for permission profiles (admin-only for mutations)."""

    @private_api
    def get(self):
        r"""
        List all session sharing profiles
        ---
        openapi: 3.1.0
        operationId: listSessionSharingProfiles
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
          - name: all
            in: query
            schema:
              type: string
              enum:
                - "true"
                - "false"
            required: false
            description: When true, include disabled profiles (admin use)
        responses:
          '200':
            description: List of session sharing profiles
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: array
                      items:
                        type: object
          '503':
            description: Session sharing not enabled
        """
        svc = _get_profile_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()
        try:
            svc.seed_defaults()
        except Exception as e:
            logger.warning(f"default profile seeding skipped: {e}")
        _profiles = svc.list_profiles()
        profiles = _profiles.message if _profiles.success else []
        # Default to ENABLED-only so the owner/admin share dropdowns never
        # offer a disabled profile. The admin Permission Profiles management
        # tab passes ?all=true to see (and re-enable) disabled profiles.
        want_all = request.args.get("all", "").lower() == "true"
        if not want_all:
            profiles = [p for p in profiles if p.get("enabled", True)]
        return SocaResponse(success=True, message=profiles).as_flask()

    @admin_api
    def post(self):
        r"""
        Create a new session sharing profile
        ---
        openapi: 3.1.0
        operationId: createSessionSharingProfile
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
            application/json:
              schema:
                type: object
                required:
                  - profile_name
                  - permissions
                properties:
                  profile_name:
                    type: string
                    description: Name of the sharing profile
                  permissions:
                    type: array
                    items:
                      type: string
                    description: List of permission strings for this profile
        responses:
          '200':
            description: Profile created successfully
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
            description: Missing required fields
          '503':
            description: Session sharing not enabled
        """
        svc = _get_profile_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()

        data = request.get_json(force=True)
        profile_name = data.get("profile_name")
        permissions = data.get("permissions", [])
        if not Validators.is_string_not_empty(profile_name) or not Validators.is_list_not_empty(permissions):
            return SocaError.GENERIC_ERROR(
                helper="profile_name and permissions are required", status_code=400
            ).as_flask()

        return svc.create_profile(
            profile_name=profile_name,
            permissions=permissions,
            admin_username=session.get("user", "admin"),
        ).as_flask()


class DcvSessionSharingProfileDetail(Resource):
    """Single profile operations."""

    @admin_api
    def put(self, profile_id):
        r"""
        Update a session sharing profile
        ---
        openapi: 3.1.0
        operationId: updateSessionSharingProfile
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
              type: string
            required: true
            description: ID of the profile to update
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                properties:
                  profile_name:
                    type: string
                    description: New name for the profile (not allowed on default profiles)
                  permissions:
                    type: array
                    items:
                      type: string
                    description: Updated permissions list (not allowed on default profiles)
                  enabled:
                    type: boolean
                    description: Enable or disable the profile
        responses:
          '200':
            description: Profile updated successfully
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
            description: Invalid request (e.g. editing default profile name/permissions)
          '503':
            description: Session sharing not enabled
        """
        svc = _get_profile_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()

        data = request.get_json(force=True)
        # Default profiles may only be enabled/disabled -- never renamed or
        # re-permissioned. The enable/disable toggle (data has only 'enabled')
        # is still allowed; name/permission edits are rejected.
        _existing = svc.get_profile(profile_id)
        if not _existing.success:
            return _existing.as_flask()
        if _existing.message.get("is_default") and any(
            k in data for k in ("profile_name", "permissions")
        ):
            return SocaError.GENERIC_ERROR(
                helper="Default profiles cannot be edited; only enable/disable is allowed",
                status_code=400,
            ).as_flask()
        return svc.update_profile(
            profile_id=profile_id,
            admin_username=session.get("user", "admin"),
            **{k: v for k, v in data.items() if k in ("profile_name", "permissions", "enabled")},
        ).as_flask()

    @admin_api
    def delete(self, profile_id):
        r"""
        Delete a session sharing profile
        ---
        openapi: 3.1.0
        operationId: deleteSessionSharingProfile
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
              type: string
            required: true
            description: ID of the profile to delete
        responses:
          '200':
            description: Profile deleted successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: string
          '409':
            description: Profile is in use by active shares
          '503':
            description: Session sharing not enabled
        """
        svc = _get_profile_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()

        grant_svc = _get_grant_service()
        if grant_svc and grant_svc.is_profile_in_use(profile_id):
            return SocaError.GENERIC_ERROR(
                helper="Profile is in use by active shares -- revoke them first",
                status_code=409,
            ).as_flask()

        return svc.delete_profile(profile_id).as_flask()


class DcvSessionSharingGrants(Resource):
    """Create and list grants."""

    @private_api
    def get(self):
        r"""
        List session sharing grants
        ---
        openapi: 3.1.0
        operationId: listSessionSharingGrants
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
          - name: all
            in: query
            schema:
              type: string
              enum:
                - "true"
                - "false"
            required: false
            description: When true, return all grants (admin only)
          - name: session_id
            in: query
            schema:
              type: string
            required: false
            description: Filter grants by broker session ID
          - name: guest_username
            in: query
            schema:
              type: string
            required: false
            description: Filter grants by guest username
          - name: status
            in: query
            schema:
              type: string
              default: ACTIVE
            required: false
            description: Filter by grant status (ACTIVE, ALL, etc.)
        responses:
          '200':
            description: List of grants
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: array
                      items:
                        type: object
          '400':
            description: Missing required filter parameter
          '403':
            description: Admin privileges required for all=true
          '503':
            description: Session sharing not enabled
        """
        svc = _get_grant_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()

        session_id = request.args.get("session_id")
        guest = request.args.get("guest_username")
        status = request.args.get("status", "ACTIVE")
        want_all = request.args.get("all", "").lower() == "true"

        if want_all:
            if not session.get("sudoers", False):
                return SocaError.GENERIC_ERROR(helper="Admin only", status_code=403).as_flask()
            # status=ALL returns every grant (history/audit); otherwise filter
            # to the given status (default ACTIVE).
            items = svc.list_all_grants(status=None if status.upper() == "ALL" else status)
        elif session_id:
            items = svc.list_grants_for_session(session_id, status=status)
        elif guest:
            items = svc.list_grants_for_guest(guest, status=status)
        else:
            return SocaError.GENERIC_ERROR(
                helper="session_id, guest_username, or all=true is required", status_code=400
            ).as_flask()

        return SocaResponse(success=True, message=items).as_flask()

    @private_api
    def post(self):
        r"""
        Create a session sharing grant
        ---
        openapi: 3.1.0
        operationId: createSessionSharingGrant
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
            application/json:
              schema:
                type: object
                required:
                  - session_id
                  - guest_username
                  - profile_id
                  - expires_at
                properties:
                  session_id:
                    type: string
                    description: Broker session ID of the session to share
                  guest_username:
                    type: string
                    description: Username of the guest to grant access to
                  profile_id:
                    type: string
                    description: ID of the permission profile to apply
                  expires_at:
                    type: string
                    description: ISO 8601 expiration timestamp for the grant
                  owner_username:
                    type: string
                    description: Session owner username (admin override only)
                  unsupervised:
                    type: boolean
                    description: Whether to allow unsupervised access
        responses:
          '200':
            description: Grant created successfully
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
            description: Missing required fields
          '403':
            description: Not authorized to share this session
          '503':
            description: Session sharing not enabled
        """
        svc = _get_grant_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()

        data = request.get_json(force=True)
        required = ("session_id", "guest_username", "profile_id", "expires_at")
        missing = [f for f in required if not Validators.is_string_not_empty(data.get(f))]
        if missing:
            return SocaError.GENERIC_ERROR(
                helper=f"Missing required fields: {missing}", status_code=400
            ).as_flask()

        username = session.get("user", "")
        is_admin = session.get("sudoers", False) is True

        # Authorization + actor role. A non-admin may only share sessions they
        # own. actor_role reflects WHOSE session it is, not the caller's
        # privilege: 'owner' whenever the caller is the session's real owner
        # (including a sudoers admin sharing their own desktop), 'admin' only
        # when an admin shares someone else's session. This keeps a self-share
        # revocable from the owner tile and off the "By Admin" badge.
        real_owner = _session_owner(data["session_id"])
        if is_admin and real_owner is not None and real_owner != username:
            actor_role = "admin"
            owner_username = data.get("owner_username") or real_owner
        else:
            if not is_admin and real_owner is not None and real_owner != username:
                return SocaError.GENERIC_ERROR(
                    helper="Only the session owner or an admin can create shares",
                    status_code=403,
                ).as_flask()
            actor_role = "owner"
            owner_username = username

        # Resolve the session's share_scope (from its software stack) and, for
        # scope=project, the owner/guest project sets.
        share_scope, owner_projects, guest_projects = _resolve_share_scope(
            data["session_id"], owner_username, data["guest_username"],
        )

        # Coerce the JSON-supplied unsupervised flag safely (a string "true"
        # must not be silently treated as truthy).
        _unsup = SocaCastEngine(data.get("unsupervised", False)).cast_as(bool)
        # create_grant returns SocaResponse/SocaError directly (status codes set).
        return svc.create_grant(
            session_id=data["session_id"],
            owner_username=owner_username,
            guest_username=data["guest_username"],
            profile_id=data["profile_id"],
            expires_at=data["expires_at"],
            created_by=username,
            actor_role=actor_role,
            unsupervised=_unsup.message if _unsup.success else False,
            share_scope=share_scope,
            owner_projects=owner_projects,
            guest_projects=guest_projects,
        ).as_flask()


class DcvSessionSharingGrantDetail(Resource):
    """Single grant operations (revoke)."""

    @private_api
    def delete(self, grant_id):
        r"""
        Revoke a session sharing grant
        ---
        openapi: 3.1.0
        operationId: revokeSessionSharingGrant
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
          - name: grant_id
            in: path
            schema:
              type: string
            required: true
            description: ID of the grant to revoke
        responses:
          '200':
            description: Grant revoked successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: string
          '403':
            description: Not authorized to revoke this grant
          '404':
            description: Grant not found
          '503':
            description: Session sharing not enabled
        """
        svc = _get_grant_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()

        username = session.get("user", "")
        is_admin = session.get("sudoers", False) is True

        # Authorization: fetch the grant and verify the caller is entitled.
        # Admins may revoke any grant; the session owner and the guest may
        # revoke their own. (404 rather than 403 for a non-existent id so we
        # don't leak which grant IDs exist to an enumerating caller.)
        grant = svc.get_grant(grant_id)
        if not grant:
            return SocaError.GENERIC_ERROR(
                helper="Grant not found", status_code=404
            ).as_flask()
        if not (
            is_admin
            or username == grant.get("owner_username")
            or username == grant.get("guest_username")
        ):
            return SocaError.GENERIC_ERROR(
                helper="Only the session owner, the guest, or an admin can revoke this share",
                status_code=403,
            ).as_flask()

        return svc.revoke_grant(grant_id, revoked_by=username).as_flask()


class DcvSessionSharingSharedToMe(Resource):
    """Guest's view: sessions shared to the current user."""

    @private_api
    def get(self):
        r"""
        List sessions shared to the current user
        ---
        openapi: 3.1.0
        operationId: listSessionsSharedToMe
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
            description: List of active grants where current user is the guest
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: array
                      items:
                        type: object
                        properties:
                          grant_id:
                            type: string
                          session_id:
                            type: string
                          owner_username:
                            type: string
                          session_uuid:
                            type: string
                          base_os:
                            type: string
          '503':
            description: Session sharing not enabled
        """
        svc = _get_grant_service()
        if not svc:
            return SocaError.GENERIC_ERROR(helper=_NOT_ENABLED_HELPER, status_code=503).as_flask()

        username = session.get("user", "")
        items = svc.list_grants_for_guest(username, status="ACTIVE")

        # Enrich each grant with the VDI's session_uuid (+ base OS) so the guest
        # tile can fetch the screenshot thumbnail. Grants key on the broker
        # session id (stored on VirtualDesktopSessions.authentication_token); the
        # screenshot endpoint keys on session_uuid. Skipped when the cluster
        # guest_screenshot policy is disabled.
        if _read_guest_screenshot_enabled():
            try:
                from models import db, VirtualDesktopSessions
                _bsids = {g.get("session_id") for g in items if g.get("session_id")}
                if _bsids:
                    _rows = (
                        db.session.query(VirtualDesktopSessions)
                        .filter(VirtualDesktopSessions.authentication_token.in_(_bsids))
                        .filter(VirtualDesktopSessions.is_active == True)  # noqa: E712
                        .all()
                    )
                    _uuid_by_bsid = {
                        r.authentication_token: r.session_uuid for r in _rows
                    }
                    _os_by_bsid = {
                        r.authentication_token: getattr(r, "instance_base_os", "")
                        for r in _rows
                    }
                    for g in items:
                        g["session_uuid"] = _uuid_by_bsid.get(g.get("session_id"))
                        g["base_os"] = _os_by_bsid.get(g.get("session_id"), "")
            except Exception as err:
                logger.warning(f"shared_to_me session_uuid enrichment failed: {err}")

        return SocaResponse(success=True, message=items).as_flask()


class DcvSessionSharingUserSearch(Resource):
    """AD/LDAP typeahead for finding shareable users."""

    @private_api
    def get(self):
        r"""
        Search cluster users for session sharing
        ---
        openapi: 3.1.0
        operationId: searchSessionSharingUsers
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
          - name: q
            in: query
            schema:
              type: string
              minLength: 2
            required: true
            description: Search query substring (minimum 2 characters)
          - name: exclude
            in: query
            schema:
              type: string
            required: false
            description: Username to exclude from results (defaults to current user)
        responses:
          '200':
            description: Matching users (max 10)
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: array
                      items:
                        type: object
                        properties:
                          username:
                            type: string
                          display_name:
                            type: string
          '503':
            description: User directory unavailable
        """
        import config
        from utils.identity_provider_client import SocaIdentityProviderClient

        q = request.args.get("q", "").strip()
        if not Validators.is_string_length_greater_equal_than(q, 2):
            return SocaResponse(success=True, message=[]).as_flask()

        # Who to omit from results. The owner modal omits the caller (you can't
        # share a session to yourself). The admin Create-Share modal passes an
        # explicit `exclude` (the chosen session's OWNER) -- admin is not the
        # owner, so admin should be able to find themselves, but never the
        # session owner. When `exclude` is absent we default to the caller, so
        # the owner modal keeps working unchanged.
        exclude_param = request.args.get("exclude")
        exclude = (
            exclude_param.strip().lower()
            if exclude_param is not None
            else (session.get("user") or "").lower()
        )

        # Provider-aware base filter + login attribute, mirroring
        # /api/ldap/users. We additionally request givenName/sn so the picker
        # can show and match real names, not just the dotted login.
        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _base = "(objectClass=person)"
            _attr_name = "uid"
        elif config.Config.DIRECTORY_AUTH_PROVIDER == "aws_ds_managed_activedirectory":
            _base = "(&(objectClass=user)(!(sAMAccountName=Admin))(!(sAMAccountName=krbtgt))(!(sAMAccountName=AWS_*)))"
            _attr_name = "sAMAccountName"
        else:
            _base = "(&(objectClass=user)(!(sAMAccountName=Administrator))(!(sAMAccountName=krbtgt))(!(sAMAccountName=AWS_*)))"
            _attr_name = "sAMAccountName"

        # Tokenize on whitespace and AND the tokens, each token matching the
        # login attr / given name / surname / displayName as a substring
        # (server-side, case-insensitive). So "ryan" or "peterson" find
        # ryan.peterson, AND a full-name query like "Anna Martin" matches
        # (token "Anna" hits givenName, "Martin" hits sn). RFC 4515-escape
        # each token.
        def _esc_term(_t):
            return (
                _t.replace("\\", "\\5c").replace("*", "\\2a")
                  .replace("(", "\\28").replace(")", "\\29").replace("\x00", "\\00")
            )

        _tokens = [t for t in q.split() if t]
        if not _tokens:
            return SocaResponse(success=True, message=[]).as_flask()
        _groups = "".join(
            f"(|({_attr_name}=*{_e}*)(givenName=*{_e}*)(sn=*{_e}*)(displayName=*{_e}*))"
            for _e in (_esc_term(t) for t in _tokens)
        )
        _filter = f"(&{_base}{_groups})"

        try:
            _client = SocaIdentityProviderClient()
            _client.initialize()
            _client.bind_as_service_account()
            _res = _client.search(
                base=config.Config.DIRECTORY_PEOPLE_SEARCH_BASE,
                filter=_filter,
                attr_list=[_attr_name, "givenName", "sn"],
                # Typeahead only renders [:10]; cap the candidate pool to a
                # single bounded page so a broad short query (e.g. "an") does
                # not page through thousands of matches.
                page_size=200,
                max_results=200,
            )
            if not _res.success:
                return SocaError.GENERIC_ERROR(
                    helper="User directory unavailable", status_code=503
                ).as_flask()

            # search() returns already-UTF-8-decoded attrs: (dn, {attr: [str]}).
            # Build {username, display_name="First Last"} rows; fall back to the
            # bare login when given/surname are unpopulated. The frontend
            # esc()-escapes display_name before render.
            results = []
            for _entry in (_res.message or []):
                _attrs = _entry[1] or {}
                _uname = (_attrs.get(_attr_name) or [""])[0]
                if not _uname or _uname.lower() == exclude:
                    continue
                _first = (_attrs.get("givenName") or [""])[0]
                _last = (_attrs.get("sn") or [""])[0]
                _display = f"{_first} {_last}".strip() or _uname
                results.append({"username": _uname, "display_name": _display})

            results.sort(key=lambda r: r["username"].lower())
            return SocaResponse(success=True, message=results[:10]).as_flask()
        except Exception as e:
            logger.error(f"User search failed: {e}")
            return SocaError.GENERIC_ERROR(
                helper="User search unavailable", status_code=503
            ).as_flask()


class DcvSessionSharingAdminSessions(Resource):
    """Admin: list active VDI sessions cluster-wide for the Create-Share
    picker. Returns each session's broker session id + owner so an admin can
    create a share on behalf of any owner (D5 admin override)."""

    @admin_api
    def get(self):
        r"""
        List active VDI sessions for admin sharing
        ---
        openapi: 3.1.0
        operationId: listAdminSessionSharingSessions
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
            description: List of running VDI sessions with sharing metadata
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      properties:
                        sessions:
                          type: array
                          items:
                            type: object
                            properties:
                              broker_session_id:
                                type: string
                              session_uuid:
                                type: string
                              owner:
                                type: string
                              state:
                                type: string
                              base_os:
                                type: string
                        allow_unsupervised_access:
                          type: boolean
          '503':
            description: Unable to list sessions
        """
        from models import db, VirtualDesktopSessions
        try:
            # Only RUNNING sessions are shareable: is_active just means the row
            # is not deleted, so it also matches stopped/pending/placing rows
            # whose broker session does not exist. Sharing one of those makes
            # the broker UpdateSessionPermissions fail -> 502. Restrict to running.
            rows = (
                db.session.query(VirtualDesktopSessions)
                .filter(VirtualDesktopSessions.is_active == True)  # noqa: E712
                .filter(VirtualDesktopSessions.session_state == "running")
                .all()
            )
        except Exception as e:
            logger.error(f"admin sessions list failed: {e}")
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to list sessions: {e}", status_code=503
            ).as_flask()

        sessions = []
        for r in rows:
            # The broker session id is stored in authentication_token (the
            # state watcher writes the broker's session Id there on register).
            bsid = getattr(r, "authentication_token", None)
            if not bsid:
                continue  # not yet broker-registered; cannot be shared
            sessions.append({
                "broker_session_id": bsid,
                "session_uuid": r.session_uuid,
                "owner": r.session_owner,
                "state": str(getattr(r, "session_state", "")),
                "base_os": getattr(r, "instance_base_os", ""),
            })
        # Cluster policy so the admin Create-Share modal can grey out the
        # unsupervised toggle (the API forces supervised regardless). Defaults true.
        _allow_unsup = _read_allow_unsupervised()
        return SocaResponse(
            success=True,
            message={"sessions": sessions, "allow_unsupervised_access": _allow_unsup},
        ).as_flask()


def _read_allow_unsupervised() -> bool:
    """Read the cluster allow_unsupervised_access policy from SSM (default True)."""
    from utils.config import SocaConfig
    try:
        _raw = SocaConfig(
            key="/configuration/dcv/session_sharing/allow_unsupervised_access"
        ).get_value().message
        _cast = SocaCastEngine(_raw).cast_as(bool)
        return _cast.message if _cast.success else True
    except Exception:
        return True


def _read_guest_screenshot_enabled() -> bool:
    """Read the cluster guest_screenshot_enabled policy from SSM (default True).
    When True, a guest holding an active grant sees the shared session's
    screenshot thumbnail. When False, thumbnails are owner-only."""
    from utils.config import SocaConfig
    try:
        _raw = SocaConfig(
            key="/configuration/dcv/session_sharing/guest_screenshot_enabled"
        ).get_value().message
        _cast = SocaCastEngine(_raw).cast_as(bool)
        return _cast.message if _cast.success else True
    except Exception:
        return True


class DcvSessionSharingSettings(Resource):
    """Admin: read/write cluster-level sharing settings. Backed by SSM so the
    grant service + CDK gate read the same source of truth."""

    _ALLOWED_MODES_KEY = "/configuration/dcv/session_sharing/allowed_sharing_modes"
    _ALLOW_UNSUP_KEY = "/configuration/dcv/session_sharing/allow_unsupervised_access"
    _GUEST_SCREENSHOT_KEY = "/configuration/dcv/session_sharing/guest_screenshot_enabled"

    @staticmethod
    def _read(key, default):
        from utils.config import SocaConfig
        try:
            _v = SocaConfig(key=key).get_value().message
            return _v if _v is not None else default
        except Exception:
            return default

    @admin_api
    def get(self):
        r"""
        Get cluster-level session sharing settings
        ---
        openapi: 3.1.0
        operationId: getSessionSharingSettings
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
            description: Current session sharing settings
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      properties:
                        allowed_sharing_modes:
                          type: array
                          items:
                            type: string
                        allow_unsupervised_access:
                          type: boolean
                        guest_screenshot_enabled:
                          type: boolean
        """
        modes_raw = self._read(self._ALLOWED_MODES_KEY, '["none", "secure"]')
        if Validators.is_list(modes_raw):
            modes = modes_raw
        else:
            _cast = SocaCastEngine(modes_raw).as_json()
            modes = _cast.message if _cast.success else ["none", "secure"]
        return SocaResponse(success=True, message={
            "allowed_sharing_modes": modes,
            "allow_unsupervised_access": _read_allow_unsupervised(),
            "guest_screenshot_enabled": _read_guest_screenshot_enabled(),
        }).as_flask()

    @admin_api
    def put(self):
        r"""
        Update cluster-level session sharing settings
        ---
        openapi: 3.1.0
        operationId: updateSessionSharingSettings
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
            application/json:
              schema:
                type: object
                properties:
                  allow_unsupervised_access:
                    type: boolean
                    description: Whether to allow unsupervised sharing access
                  guest_screenshot_enabled:
                    type: boolean
                    description: Whether guests can see session screenshots
                  allowed_sharing_modes:
                    type: array
                    items:
                      type: string
                    description: List of allowed sharing modes (e.g. none, secure, link)
        responses:
          '200':
            description: Settings updated successfully
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
            description: Invalid request (bad format or no recognized settings)
        """
        from utils.config import SocaConfig
        data = request.get_json(force=True)
        results = {}
        if "allow_unsupervised_access" in data:
            _cast = SocaCastEngine(data["allow_unsupervised_access"]).cast_as(bool)
            val = "true" if (_cast.success and _cast.message) else "false"
            r = SocaConfig(key=self._ALLOW_UNSUP_KEY).set_value(value=val)
            results["allow_unsupervised_access"] = getattr(r, "success", bool(r))
        if "guest_screenshot_enabled" in data:
            _cast = SocaCastEngine(data["guest_screenshot_enabled"]).cast_as(bool)
            val = "true" if (_cast.success and _cast.message) else "false"
            r = SocaConfig(key=self._GUEST_SCREENSHOT_KEY).set_value(value=val)
            results["guest_screenshot_enabled"] = getattr(r, "success", bool(r))
        if "allowed_sharing_modes" in data:
            modes = data["allowed_sharing_modes"]
            if not Validators.is_list(modes):
                return SocaError.GENERIC_ERROR(
                    helper="allowed_sharing_modes must be a list", status_code=400
                ).as_flask()
            _ser = SocaCastEngine(modes).serialize_json()
            if not _ser.success:
                return SocaError.GENERIC_ERROR(
                    helper="Unable to serialize allowed_sharing_modes", status_code=400
                ).as_flask()
            r = SocaConfig(key=self._ALLOWED_MODES_KEY).set_value(value=_ser.message)
            results["allowed_sharing_modes"] = getattr(r, "success", bool(r))
        if not results:
            return SocaError.GENERIC_ERROR(
                helper="No recognized settings in request", status_code=400
            ).as_flask()
        return SocaResponse(success=True, message=results).as_flask()
