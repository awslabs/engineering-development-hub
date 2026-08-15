# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import secrets
import string
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from flask import request, g
from extensions import db
from models import ApiTokens, ApiAuditLog
import config

logger = logging.getLogger("soca_logger")

SESSION_TOKEN_LIFETIME_HOURS = 24
TOKEN_PREFIX = "edh_"
TOKEN_RANDOM_BYTES = 48
TOKEN_CHARS = string.ascii_letters + string.digits + "!@#$%^&*-_=+"

DEFAULT_POLICY = {
    "max_tokens_per_user": 5,
    "max_lifetime_hours": 720,
    "default_lifetime_hours": 24,
    "max_renewals": 1000,
    "renewal_allowed": True,
    "require_expiration": False,
    "global_deny": {
        # "/api/admin/*": ["*"],
    },
}


_policy_cache = {"policy": None, "expires": 0}
_POLICY_CACHE_TTL = 60


def load_token_policy() -> dict:
    import time

    now = time.monotonic()
    if _policy_cache["policy"] and now < _policy_cache["expires"]:
        return _policy_cache["policy"]

    from utils.http_client import SocaHttpClient

    try:
        resp = SocaHttpClient(
            endpoint="/api/admin/config/param",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).get(params={"key": "/configuration/Security/api_token_policy"})
        if resp.success and resp.message:
            policy = (
                json.loads(resp.message)
                if isinstance(resp.message, str)
                else resp.message
            )
            merged = {**DEFAULT_POLICY, **policy}
            _policy_cache["policy"] = merged
            _policy_cache["expires"] = now + _POLICY_CACHE_TTL
            return merged
    except Exception:
        logger.debug("Could not load token policy from config, using defaults")

    result = DEFAULT_POLICY.copy()
    _policy_cache["policy"] = result
    _policy_cache["expires"] = now + _POLICY_CACHE_TTL
    return result


def _generate_token() -> str:
    random_part = "".join(
        secrets.choice(TOKEN_CHARS) for _ in range(TOKEN_RANDOM_BYTES)
    )
    return f"{TOKEN_PREFIX}{random_part}"


def _make_hint(token: str) -> str:
    return f"{token[:8]}...{token[-3:]}"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def _path_method_matches(path: str, method: str, rules: dict) -> bool:
    for pattern, methods in rules.items():
        if _path_matches(path, pattern):
            if "*" in methods or method.upper() in methods:
                return True
    return False


def _path_matches_any(path: str, rules: dict) -> bool:
    return any(_path_matches(path, pattern) for pattern in rules)


def validate_token(
    user: Optional[str] = None,
    token: Optional[str] = None,
    path: Optional[str] = None,
    method: Optional[str] = None,
    check_sudo: bool = False,
) -> Tuple[bool, str]:
    """
    Validate a token against path+method permissions.
    Returns (authorized, reason).
    Sets g.token_id, g.token_name, g.token_type for audit logging.
    """
    if token == config.Config.API_ROOT_KEY:
        g.token_id = None
        g.token_name = "_root"
        g.token_type = "root"
        return True, "root"

    if user is None or token is None:
        return False, "missing_credentials"

    token_hash = _hash_token(token)
    record = ApiTokens.query.filter_by(token_hash=token_hash, user=user).first()

    if not record:
        return False, "invalid_token"
    if record.revoked_at:
        return False, "revoked"
    if record.is_expired:
        return False, "expired"

    g.token_id = record.id
    g.token_name = record.name
    g.token_type = record.token_type

    permissions = json.loads(record.permissions)

    # Global deny — skipped for session tokens (web UI acting as user)
    if record.token_type != "session":
        policy = load_token_policy()
        if _path_method_matches(path, method, policy.get("global_deny", {})):
            return False, "global_deny"

        # Sudo check for admin endpoints
        if check_sudo:
            from utils.http_client import SocaHttpClient

            _validate_sudo = SocaHttpClient(
                endpoint="/api/ldap/sudo",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).get(params={"user": user})
            if not _validate_sudo.get("success"):
                return False, "not_sudoer"

    # Token deny
    deny_rules = permissions.get("deny", {})
    if deny_rules and _path_method_matches(path, method, deny_rules):
        return False, "path_denied"

    # Token allow — must match at least one entry
    allow_rules = permissions.get("allow", {})
    if not _path_method_matches(path, method, allow_rules):
        if _path_matches_any(path, allow_rules):
            return False, "method_not_allowed"
        return False, "path_not_allowed"

    # Mark token_id on g so after_request can update last_used
    g._authorized_token_id = record.id

    return True, "ok"


def create_token(
    user: str,
    name: str,
    permissions: dict,
    lifetime_hours: int,
    created_by: str,
    renewable: bool = True,
    max_renewals: Optional[int] = None,
    token_type: str = "user",
) -> Tuple[str, ApiTokens]:
    """
    Create a new API token. Returns (plaintext_token, record).
    The plaintext is only available at creation time.
    """
    plaintext = _generate_token()
    now = datetime.now(timezone.utc)

    if lifetime_hours > 0:
        expires_at = now + timedelta(hours=lifetime_hours)
    else:
        expires_at = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    record = ApiTokens(
        user=user,
        name=name,
        token_type=token_type,
        token_hint=_make_hint(plaintext),
        token_hash=_hash_token(plaintext),
        permissions=json.dumps(permissions),
        expires_at=expires_at,
        renewable=renewable,
        max_renewals=max_renewals,
        renewal_count=0,
        created_at=now,
        created_by=created_by,
    )

    db.session.add(record)
    db.session.commit()

    return plaintext, record


def create_session_token(user: str) -> Tuple[str, ApiTokens]:
    """Create a session token for the web UI (full access, 1h lifetime)."""
    permissions = {"allow": {"/api/*": ["*"]}}
    return create_token(
        user=user,
        name="_session",
        permissions=permissions,
        lifetime_hours=SESSION_TOKEN_LIFETIME_HOURS,
        created_by="_system",
        renewable=False,
        token_type="session",
    )


def get_or_rotate_session_token(flask_session: dict, user: str) -> str:
    """Return a valid session token, rotating if expired or missing."""
    token_id = flask_session.get("session_token_id")

    if token_id:
        record = db.session.get(ApiTokens, token_id)
        if record and not record.revoked_at and not record.is_expired:
            existing_key = flask_session.get("api_key")
            if existing_key:
                return existing_key
            # api_key missing from session — fall through to create a new one

        # Revoke the old one
        if record and not record.revoked_at:
            record.revoked_at = datetime.now(timezone.utc)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

    # Create new session token
    plaintext, new_record = create_session_token(user)
    flask_session["api_key"] = plaintext
    flask_session["session_token_id"] = new_record.id
    return plaintext


def revoke_all_user_tokens(user: str, token_type: Optional[str] = None):
    """Revoke all active tokens for a user. Optionally filter by type."""
    now = datetime.now(timezone.utc)
    query = ApiTokens.query.filter_by(user=user).filter(ApiTokens.revoked_at.is_(None))
    if token_type:
        query = query.filter_by(token_type=token_type)

    tokens = query.all()
    for t in tokens:
        t.revoked_at = now

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def count_active_user_tokens(user: str) -> int:
    """Count active (non-revoked, non-expired) user tokens (excludes session tokens)."""
    now = datetime.now(timezone.utc)
    return (
        ApiTokens.query.filter_by(user=user, token_type="user")
        .filter(ApiTokens.revoked_at.is_(None))
        .filter(ApiTokens.expires_at > now)
        .count()
    )


def write_audit_log(
    user: str,
    status_code: int,
    denied_reason: Optional[str] = None,
):
    """Write an audit log entry for the current request and update last_used on authorized tokens."""
    try:
        # Update last_used for the token that authorized this request
        authorized_token_id = g.get("_authorized_token_id")
        if authorized_token_id:
            record = db.session.get(ApiTokens, authorized_token_id)
            if record:
                record.last_used_at = datetime.now(timezone.utc)
                record.last_used_ip = request.remote_addr or None

        _actor_type = g.get("actor_type")
        if not _actor_type:
            if user == "_root" or g.get("token_type") == "root":
                _actor_type = "service"
            elif user and user != "anonymous":
                _actor_type = "user"
            else:
                _actor_type = "anonymous"
        _source_ref = g.get("source_ref")
        if not _source_ref:
            _tt = g.get("token_type")
            if _tt == "session":
                _source_ref = "webui"
            elif user == "_root" or _tt == "root":
                _source_ref = "internal"
            elif user and user != "anonymous":
                _source_ref = "api"
        _on_behalf_of = g.get("on_behalf_of")
        if not _on_behalf_of and (_actor_type == "service" or user == "_root"):
            _obo = request.headers.get("X-EDH-USER") or request.values.get("user")
            if _obo and _obo != "_root":
                _on_behalf_of = _obo[:255]
        _xff = request.headers.get("X-Forwarded-For")
        _client_ip = _xff.split(",")[-1].strip() if _xff else (request.remote_addr or "unknown")
        entry = ApiAuditLog(
            timestamp=datetime.now(timezone.utc),
            user=user or "anonymous",
            token_id=g.get("token_id"),
            token_name=g.get("token_name"),
            token_type=g.get("token_type"),
            method=request.method,
            path=request.path,
            status_code=status_code,
            ip=_client_ip,
            user_agent=(request.headers.get("User-Agent", "") or "")[:512],
            request_id=g.get("request_id"),
            duration_ms=g.get("request_duration_ms"),
            denied_reason=denied_reason,
            actor_type=_actor_type,
            source_ref=_source_ref,
            on_behalf_of=_on_behalf_of,
            via_ip=request.remote_addr or None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.debug("Failed to write audit log entry")


def validate_permissions_structure(permissions: dict) -> Tuple[bool, str]:
    """Validate that a permissions dict has the expected structure."""
    if not isinstance(permissions, dict):
        return False, "permissions must be a JSON object"

    allow = permissions.get("allow")
    if not allow or not isinstance(allow, dict):
        return False, "permissions.allow is required and must be a non-empty object"

    valid_methods = {"GET", "POST", "PUT", "DELETE", "*"}

    for path, methods in allow.items():
        if not isinstance(path, str) or not path.startswith("/api/"):
            return False, f"Invalid allow path: {path} (must start with /api/)"
        if not isinstance(methods, list) or not methods:
            return False, f"Methods for path {path} must be a non-empty list"
        for m in methods:
            if m not in valid_methods:
                return False, f"Invalid method '{m}' for path {path}"

    deny = permissions.get("deny")
    if deny is not None:
        if not isinstance(deny, dict):
            return False, "permissions.deny must be an object if provided"
        for path, methods in deny.items():
            if not isinstance(path, str) or not path.startswith("/api/"):
                return False, f"Invalid deny path: {path} (must start with /api/)"
            if not isinstance(methods, list) or not methods:
                return False, f"Methods for deny path {path} must be a non-empty list"
            for m in methods:
                if m not in valid_methods:
                    return False, f"Invalid method '{m}' for deny path {path}"

    return True, "ok"
