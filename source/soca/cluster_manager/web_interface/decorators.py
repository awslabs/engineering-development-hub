# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import urllib
from functools import wraps
import config
from flask import request, redirect, session, flash, abort, g
from flask_babel import gettext as _
from requests import get, post
import logging
from typing import Optional
from utils.http_client import SocaHttpClient
import feature_flags
from utils.token_service import validate_token as _validate_token_v2, get_or_rotate_session_token

logger = logging.getLogger("soca_logger")


def validate_api_key(
    user: Optional[str] = None, token: Optional[str] = None, check_sudo: bool = False
) -> bool:
    """Validate a legacy API key (plain hex token from the ApiKeys table)."""
    logger.debug(
        "Validate if token supplied is used by Flask or if the pair of username/api_key is valid"
    )
    if token == config.Config.API_ROOT_KEY:
        return True

    if user is None or token is None:
        logger.debug("No user or token supplied")
        return False

    from models import ApiKeys
    record = ApiKeys.query.filter_by(user=user, token=token, is_active=True).first()
    if not record:
        return False
    if check_sudo:
        _sudo_check = SocaHttpClient(
            endpoint="/api/ldap/sudo",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).get(params={"user": user})
        if not _sudo_check.get("success"):
            return False
    return True


def validate_api_token(
    user: Optional[str] = None, token: Optional[str] = None, check_sudo: bool = False
) -> bool:
    """Validate a scoped API token (edh_ prefix, stored as hash in ApiTokens table)."""
    logger.debug(
        "Validate if pair of username/api_token is valid"
    )
    if token == config.Config.API_ROOT_KEY:
        return True

    if user is None or token is None:
        logger.debug("No user or token supplied")
        return False

    path = request.path if request else "/api/unknown"
    method = request.method if request else "GET"

    authorized, reason = _validate_token_v2(
        user=user, token=token, path=path, method=method, check_sudo=check_sudo
    )

    if not authorized:
        logger.debug(f"Token validation failed for {user=}: {reason}")
        g.auth_denied_reason = reason

    return authorized


def validate_token(
    user: Optional[str] = None, token: Optional[str] = None, check_sudo: bool = False
) -> bool:
    """Dispatch to validate_api_token or validate_api_key based on the token prefix."""
    if token == config.Config.API_ROOT_KEY:
        return True
    if user is None or token is None:
        return False
    if token.startswith("edh_"):
        return validate_api_token(user=user, token=token, check_sudo=check_sudo)
    return validate_api_key(user=user, token=token, check_sudo=check_sudo)


def validate_password(
    user: Optional[str] = None, password: Optional[str] = None
) -> bool:
    logger.debug(f"Validate if pair or username/password is valid for {user}")
    if user is None or password is None:
        return False
    else:
        # password are not stored in DB. We determine successfully login via LDAP bind
        check_auth = SocaHttpClient(
            endpoint="/api/ldap/authenticate",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).post(data={"user": user, "password": password})

        if check_auth.get("success") is True:
            logger.debug(f"Valid login received for {user}")
            return True
        else:
            logger.error(f"Invalid login received for {user}")
            return False


from utils.validators import Validators


def _feature_flag_member_of_any(login, group_refs):
    """True if `login` resolves as a member of ANY ref in `group_refs`.

    Group refs resolve via utils.group_resolver.resolve_membership (sudoers
    today; ldap:/posix: are documented fail-closed extension points). FAIL
    CLOSED: a resolver error, an unwired ref, or a non-member verdict all
    count as NOT a member -- a lookup blip never falls open to grant access.
    """
    if not login or not group_refs:
        return False
    from utils.group_resolver import resolve_membership

    for _group_ref in group_refs:
        _member = resolve_membership(login, _group_ref)
        if _member.get("success") is True and _member.get("message") is True:
            return True
    return False


# Enable/Disable feature
def feature_flag(flag_name, mode):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):

            def _deny_access(message):
                if mode == "view":
                    flash(message, "error")
                    return redirect("/")
                return {"success": False, "message": message}, 400

            _ff = feature_flags.get_flag(flag_name)
            if _ff.get("success") is not True:
                return _deny_access(_("Invalid feature flag configuration"))
            _feature = _ff.get("message")
            _current_user = session.get("user") or request.headers.get("X-EDH-USER")
            logger.debug(f"Checking {_current_user} permission to {_feature}")

            if not Validators.is_dict(_feature):
                return _deny_access(_("Invalid feature flag configuration"))

            # Global flag
            if not _feature.get("enabled", False):
                return _deny_access(_("Feature not available on this EDH cluster. Please contact your Administrator to enable it."))

            # Dependency chain. A feature may declare `depends_on` in
            # FEATURE_FLAGS as either:
            #   * a single string:  "depends_on": "FILE_BROWSER"
            #   * a list of strings: "depends_on": ["FILE_BROWSER", "HPC"]
            # ALL listed parents must be enabled (AND semantics) for the
            # dependent feature to be accessible. Each parent's own
            # depends_on is walked transitively. Cycle-protected.
            def _as_dep_list(_dep):
                if _dep is None:
                    return []
                if Validators.is_string(_dep):
                    return [_dep]
                if Validators.is_list(_dep):
                    return [_d for _d in _dep if Validators.is_string(_d)]
                return []

            _visited = {flag_name}
            _deps_to_check = [
                d for d in _as_dep_list(_feature.get("depends_on"))
                if d not in _visited
            ]
            while _deps_to_check:
                _parent_name = _deps_to_check.pop(0)
                if _parent_name in _visited:
                    continue
                _visited.add(_parent_name)
                _pff = feature_flags.get_flag(_parent_name)
                _parent = _pff.get("message") if _pff.get("success") is True else None
                if not Validators.is_dict(_parent):
                    logger.warning(f"feature_flag: parent flag {_parent_name} is not a dict; denying {flag_name}")
                    return _deny_access(_("Feature not available on this EDH cluster. Please contact your Administrator to enable it."))
                if not _parent.get("enabled", False):
                    logger.debug(f"feature_flag: {flag_name} denied because parent flag {_parent_name} is disabled")
                    return _deny_access(_("Feature not available on this EDH cluster. Please contact your Administrator to enable it."))
                # Enqueue any transitive deps this parent has, eagerly
                # filtering out anything we've already visited. This
                # bounds queue growth for repeated references (e.g. a
                # large depends_on list that names the same parent many
                # times, or a diamond where two branches meet).
                _deps_to_check.extend(
                    d for d in _as_dep_list(_parent.get("depends_on"))
                    if d not in _visited
                )

            _denied_users = _feature.get("denied_users", []) or []
            _allowed_users = _feature.get("allowed_users", []) or []
            _denied_groups = _feature.get("denied_groups", []) or []
            _allowed_groups = _feature.get("allowed_groups", []) or []

            # Explicit deny by user (deny always wins over any allow)
            if _current_user in _denied_users:
                return _deny_access(
                    _("Feature not available for you on this EDH cluster. Please contact your Administrator to enable it.")
                )

            # Explicit deny by group membership (fail-closed resolver)
            if _feature_flag_member_of_any(_current_user, _denied_groups):
                return _deny_access(
                    _("Feature not available for you on this EDH cluster. Please contact your Administrator to enable it.")
                )

            # Allow-list gate. Open to everyone ONLY when BOTH allow lists are
            # empty; otherwise the user must be named in allowed_users OR be a
            # member of one of allowed_groups.
            if _allowed_users or _allowed_groups:
                _permitted = (
                    _current_user in _allowed_users
                    or _feature_flag_member_of_any(_current_user, _allowed_groups)
                )
                if not _permitted:
                    return _deny_access(
                        _("Feature not available for you on this EDH cluster. Please contact your Administrator to enable it.")
                    )

            # All other use cases, return True
            return f(*args, **kwargs)

        return wrapped

    return decorator


# Restricted API can only be accessed using Flask Root API key
# In other words, @restricted_api can only be triggered by the web application
def restricted_api(f):
    @wraps(f)
    def restricted_resource(*args, **kwargs):
        token = request.headers.get("X-EDH-TOKEN", None)
        if validate_token("", token):
            g.authenticated_user = "_root"
            return f(*args, **kwargs)
        else:
            return {"success": False, "message": _("Not authorized")}, 401

    return restricted_resource


# Admin API: same auth paths as private_api, but every path additionally
# requires sudo. Accepts (0) the Flask root API key, (1) an X-EDH-USER +
# X-EDH-TOKEN pair belonging to a sudoer (validated via /api/ldap/sudo), or
# (2) a server-signed Flask session cookie whose "sudoers" flag is True
# (browser admin pages). The session path mirrors private_api so browser AJAX
# works; the sudo gate keeps it admin-only. Before this, admin_api only
# honored the token-header path, so browser fetches (cookie, no token header)
# always 401'd -- forcing admin AJAX endpoints onto private_api + a hand-rolled
# session["sudoers"] check, which silently grants every authenticated user if
# the manual check is ever omitted.
def admin_api(f):
    @wraps(f)
    def admin_resource(*args, **kwargs):
        _token = request.headers.get("X-EDH-TOKEN", None)

        # Path 0: root API key (internal service-to-service, admin-equivalent)
        if _token == config.Config.API_ROOT_KEY:
            g.authenticated_user = "_root"
            return f(*args, **kwargs)

        # Path 1: explicit user + token header, must be a sudoer
        _user = request.headers.get("X-EDH-USER", None)
        if _user and _token:
            if validate_token(user=_user, token=_token, check_sudo=True):
                g.authenticated_user = _user
                return f(*args, **kwargs)
            return {"success": False, "message": _("Not authorized")}, 401

        # Path 2: Flask session cookie (browser AJAX, same-origin). The session
        # is server-signed (itsdangerous/SECRET_KEY), so the "sudoers" flag set
        # at login is cryptographically verified -- same trust model as
        # private_api's api_key path, just additionally gated on sudo.
        if (
            session.get("user")
            and session.get("api_key")
            and session.get("sudoers") is True
        ):
            _sess_user = session["user"]
            _sess_token = session["api_key"]
            if validate_token(user=_sess_user, token=_sess_token, check_sudo=True):
                g.authenticated_user = _sess_user
                return f(*args, **kwargs)
            return {"success": False, "message": _("Not authorized")}, 401

        return {"success": False, "message": _("Not authorized")}, 401

    return admin_resource


# This is the only decorator that accept X-EDH-PASSWORD.
#  Used to query /api/user/api_key
def retrieve_api_key(f):
    @wraps(f)
    def get_key(*args, **kwargs):
        user = request.headers.get("X-EDH-USER", None)
        password = request.headers.get("X-EDH-PASSWORD", None)
        token = request.headers.get("X-EDH-TOKEN", None)
        if token == config.Config.API_ROOT_KEY:
            g.authenticated_user = "_root"
            return f(*args, **kwargs)

        # Ensure requester can only retrieve her/his own key
        get_key_for_user = request.args.get("user", None)
        if get_key_for_user != user:
            logger.error(f"{user=} is not authorized to retrieve {get_key_for_user=} key")
            return {"success": False, "message": _("Not authorized")}, 401
        else:
            if validate_password(user, password):
                return f(*args, **kwargs)

        return {"success": False, "message": _("Not authorized")}, 401

    return get_key


# Private API can only be accessed with a valid pair of token
def private_api(f):
    @wraps(f)
    def private_resource(*args, **kwargs):
        _token = request.headers.get("X-EDH-TOKEN", None)

        # Path 0: root API key (internal service-to-service calls, no user needed)
        if _token == config.Config.API_ROOT_KEY:
            g.authenticated_user = "_root"
            return f(*args, **kwargs)

        # Path 1: explicit user + token header (CLI, programmatic callers)
        _user = request.headers.get("X-EDH-USER", None)
        if _user and _token:
            if validate_token(user=_user, token=_token, check_sudo=False):
                g.authenticated_user = _user
                return f(*args, **kwargs)
            return {"success": False, "message": _("Not authorized")}, 401

        # Path 2: Flask session cookie (browser AJAX with credentials: 'same-origin').
        # The session is server-signed (itsdangerous/SECRET_KEY) so the values
        # are cryptographically verified — not blindly trusted.
        if session.get("user") and session.get("api_key"):
            _sess_user = session["user"]
            _sess_token = session["api_key"]
            if validate_token(user=_sess_user, token=_sess_token, check_sudo=False):
                g.authenticated_user = _sess_user
                return f(*args, **kwargs)
            return {"success": False, "message": _("Not authorized")}, 401

        return {"success": False, "message": _("Not authorized")}, 401

    return private_resource


# Views require a valid login
def login_required(f):
    @wraps(f)
    def validate_account(*args, **kwargs):

        if "user" in session:
            # Use the new session token system: get or rotate on expiry
            get_or_rotate_session_token(session, session["user"])

            # Sync sudoers status from LDAP
            if "sudoers" not in session:
                session["sudoers"] = False
            _sudo_check = SocaHttpClient(
                endpoint="/api/ldap/sudo",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).get(params={"user": session["user"]})
            if _sudo_check.get("success") is True:
                session["sudoers"] = True
            else:
                session["sudoers"] = False

            return f(*args, **kwargs)
        else:
            if config.Config.ENABLE_SSO:
                data = {
                    "redirect_uri": config.Config.COGNITO_CALLBACK_URL,
                    "client_id": config.Config.COGNITO_APP_ID,
                    "response_type": "code",
                    "state": request.path,
                }
                oauth_url = (
                    config.Config.COGNITO_OAUTH_AUTHORIZE_ENDPOINT
                    + "?"
                    + urllib.parse.urlencode(data)
                )
                return redirect(oauth_url)
            else:
                request_to_forward = request.path
                if request_to_forward == "/":
                    return redirect("/login")
                else:
                    return redirect("/login?fwd=" + request_to_forward)

    return validate_account


# Views restricted to admin
def admin_only(f):
    @wraps(f)
    def check_admin(*args, **kwargs):
        if "sudoers" in session:
            if session["sudoers"] is True:
                return f(*args, **kwargs)
            else:
                flash(_("Sorry this page requires admin privileges."), "error")
                return redirect("/")
        else:
            return redirect("/login")

    return check_admin


# To be removed, used feature_flag instead https://awslabs.github.io/engineering-development-hub-documentation/documentation/web-interface/feature-flags/ 
def disabled(f):
    @wraps(f)
    def disable_feature(*args, **kwargs):
        if "api" in request.path:
            return {
                "success": False,
                "message": _("This API has been disabled by your Administrator"),
            }, 401
        else:
            flash(_("Sorry this feature has been disabled by your Administrator."), "error")
            return redirect("/")

    return disable_feature
