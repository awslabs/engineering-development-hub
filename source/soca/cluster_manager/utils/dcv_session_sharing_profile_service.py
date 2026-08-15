# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DcvSessionSharingProfileService -- CRUD for session-sharing permission profiles.

Profiles are admin-defined named templates (e.g. "Full Control", "View Only")
that map to DCV permission flags. Stored in DDB, managed via admin WebUI/API.

Public methods return SocaResponse/SocaError (the message carries the profile
dict / list on success), per the web-tier contract.
"""

import logging
from datetime import datetime, timezone

import uuid as _uuid_mod

from utils.response import SocaResponse
from utils.error import SocaError
from utils.datamodels.soca_session_sharing import SocaSessionSharingProfile


def _new_id() -> str:
    """Opaque unique id for profiles. uuid4 (avoids ulid-package API drift)."""
    return str(_uuid_mod.uuid4())

logger = logging.getLogger("soca_logger")

# DCV permission flags (complete set)
VALID_PERMISSIONS = frozenset({
    "display", "keyboard", "mouse", "pointer",
    "audio-in", "audio-out",
    "clipboard-copy", "clipboard-paste",
    "file-download", "file-upload",
    "keyboard-sas", "printer", "screenshot",
    "smartcard", "stylus", "touch", "usb",
    "webcam", "gamepad", "unsupervised-access",
    "webauthn-redirection", "extensions-client", "extensions-server",
    "builtin",
})

DEFAULT_PROFILES = [
    {
        "profile_name": "Full Control",
        "permissions": ["builtin"],
        "is_default": True,
    },
    {
        "profile_name": "Collaborate",
        "permissions": [
            "display", "pointer", "keyboard", "mouse",
            "clipboard-copy", "clipboard-paste",
            "file-download", "file-upload",
            "audio-in", "audio-out", "webcam",
        ],
        "is_default": True,
    },
    {
        "profile_name": "View Only",
        "permissions": ["display", "pointer", "audio-out"],
        "is_default": True,
    },
]


class DcvSessionSharingProfileService:
    """CRUD operations for sharing permission profiles."""

    def __init__(self, table):
        """
        Args:
            table: boto3 DynamoDB Table resource for sharing-profiles.
        """
        self._table = table

    def seed_defaults(self, admin_username: str = "system") -> SocaResponse:
        """Idempotently seed default profiles if table is empty."""
        resp = self._table.scan(Limit=1)
        if resp.get("Items"):
            return SocaResponse(success=True, message="already seeded")

        now = datetime.now(timezone.utc).isoformat()
        for profile_def in DEFAULT_PROFILES:
            profile = SocaSessionSharingProfile(
                pk=_new_id(),
                profile_name=profile_def["profile_name"],
                permissions=profile_def["permissions"],
                is_default=profile_def["is_default"],
                enabled=True,
                created_by=admin_username,
                created_at=now,
                updated_by=admin_username,
                updated_at=now,
                actor_role="admin",
            )
            self._table.put_item(Item=profile.model_dump())
        logger.info(f"Seeded {len(DEFAULT_PROFILES)} default sharing profiles")
        return SocaResponse(success=True, message=f"seeded {len(DEFAULT_PROFILES)}")

    def list_profiles(self) -> SocaResponse:
        """Return all profiles. Profiles created before the `enabled` field
        existed are treated as enabled (default True)."""
        resp = self._table.scan()
        items = resp.get("Items", [])
        for it in items:
            it.setdefault("enabled", True)
        return SocaResponse(success=True, message=items)

    def get_profile(self, profile_id: str) -> SocaResponse:
        """Get a single profile by ID. message=item on success; SocaError 404 if absent."""
        resp = self._table.get_item(Key={"pk": profile_id, "sk": "PROFILE"})
        item = resp.get("Item")
        if item is None:
            return SocaError.GENERIC_ERROR(
                helper=f"Profile {profile_id} not found", status_code=404
            )
        item.setdefault("enabled", True)
        return SocaResponse(success=True, message=item)

    def create_profile(self, profile_name: str, permissions: list, admin_username: str) -> SocaResponse:
        """Create a new profile. message=created item on success."""
        _valid = self._validate_permissions(permissions)
        if not _valid.success:
            return _valid
        now = datetime.now(timezone.utc).isoformat()
        profile = SocaSessionSharingProfile(
            pk=_new_id(),
            profile_name=profile_name,
            permissions=permissions,
            is_default=False,
            enabled=True,
            created_by=admin_username,
            created_at=now,
            updated_by=admin_username,
            updated_at=now,
            actor_role="admin",
        )
        item = profile.model_dump()
        self._table.put_item(Item=item)
        return SocaResponse(success=True, message=item)

    def update_profile(self, profile_id: str, admin_username: str, **kwargs) -> SocaResponse:
        """Update profile fields. message=updated item; SocaError 404 if not found."""
        _existing = self.get_profile(profile_id)
        if not _existing.success:
            return _existing
        existing = _existing.message

        if "permissions" in kwargs:
            _valid = self._validate_permissions(kwargs["permissions"])
            if not _valid.success:
                return _valid

        now = datetime.now(timezone.utc).isoformat()
        update_fields = {k: v for k, v in kwargs.items() if k in ("profile_name", "permissions", "enabled")}
        update_fields["updated_by"] = admin_username
        update_fields["updated_at"] = now

        expr_parts = []
        expr_names = {}
        expr_values = {}
        for i, (k, v) in enumerate(update_fields.items()):
            expr_parts.append(f"#f{i} = :v{i}")
            expr_names[f"#f{i}"] = k
            expr_values[f":v{i}"] = v

        self._table.update_item(
            Key={"pk": profile_id, "sk": "PROFILE"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )
        return SocaResponse(success=True, message={**existing, **update_fields})

    def delete_profile(self, profile_id: str) -> SocaResponse:
        """Delete a profile. message='Deleted'; SocaError 404 if not found."""
        _existing = self.get_profile(profile_id)
        if not _existing.success:
            return _existing
        self._table.delete_item(Key={"pk": profile_id, "sk": "PROFILE"})
        return SocaResponse(success=True, message="Deleted")

    @staticmethod
    def _validate_permissions(permissions: list) -> SocaResponse:
        """SocaError if permissions isn't a list or any flag is invalid, else success."""
        from utils.validators import Validators

        if not Validators.is_list(permissions):
            return SocaError.GENERIC_ERROR(
                helper="permissions must be a list", status_code=400
            )
        invalid = set(permissions) - VALID_PERMISSIONS
        if invalid:
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid DCV permission flags: {sorted(invalid)}",
                status_code=400,
            )
        return SocaResponse(success=True, message="valid")
