# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DcvSessionSharingGrantService -- create, revoke, list session-sharing grants.

A grant represents: "guest_username has permission_profile access to session_id,
expiring at expires_at, created by actor (owner or admin)."

On create: writes DDB + calls broker UpdateSessionPermissions + issues guest token.
On revoke: calls broker UpdateSessionPermissions (remove guest) + updates DDB.
"""

import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

import uuid as _uuid_mod

from utils.response import SocaResponse
from utils.error import SocaError
from utils.datamodels.soca_session_sharing import SocaSessionSharingGrant


def _new_id() -> str:
    """Opaque unique id for grants/profiles. uuid4 (sortability not required;
    ordering uses created_at + GSIs). Avoids ulid-package API drift."""
    return str(_uuid_mod.uuid4())


def _jsonsafe(obj):
    """Recursively convert DynamoDB Decimal (e.g. connect_count) to int/float
    so flask jsonify does not raise 'Object of type Decimal is not JSON
    serializable'. boto3 returns every Number attribute as Decimal."""
    if isinstance(obj, list):
        return [_jsonsafe(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _jsonsafe(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    return obj

logger = logging.getLogger("soca_logger")

# Rate limits (bound .perm file size and blast radius)
MAX_ACTIVE_GRANTS_PER_SESSION = 10
MAX_ACTIVE_GRANTS_PER_GUEST = 20


class DcvSessionSharingGrantService:
    """Grant lifecycle operations."""

    def __init__(self, grants_table, profiles_table, broker_client, get_config_key=None):
        """
        Args:
            grants_table: boto3 DDB Table for dcv-session-sharing-grants.
            profiles_table: boto3 DDB Table for dcv-session-sharing-profiles.
            broker_client: DcvBrokerClient instance.
            get_config_key: Config resolver for scope/mode validation.
        """
        self._grants = grants_table
        self._profiles = profiles_table
        self._broker = broker_client
        self._get_config_key = get_config_key

    def create_grant(
        self,
        *,
        session_id: str,
        owner_username: str,
        guest_username: str,
        profile_id: str,
        expires_at: str,
        created_by: str,
        actor_role: str = "owner",
        unsupervised: bool = False,
        share_scope: str = "cluster",
        owner_projects: Optional[list[str]] = None,
        guest_projects: Optional[list[str]] = None,
    ) -> SocaResponse:
        """
        Create a sharing grant: validate scope, apply permissions via broker,
        issue guest token, write DDB.

        Args:
            session_id: Broker session ID.
            owner_username: Session owner AD username.
            guest_username: Guest AD username.
            profile_id: Permission profile ID to apply.
            expires_at: ISO-8601 expiry (quarter-hour boundary).
            created_by: Username of the actor creating the grant.
            actor_role: "owner" or "admin".
            unsupervised: If True, guest can connect without owner present.
            share_scope: "none", "project", or "cluster" from VDI Profile.
            owner_projects: Project IDs the owner belongs to.
            guest_projects: Project IDs the guest belongs to.

        Returns: SocaResponse(success=True, message=<grant dict + connection_token>)
                 on success; SocaError on validation/profile/scope failure or a
                 broker failure.
        """
        # A session cannot be shared with its own owner.
        if guest_username.lower() == owner_username.lower():
            return SocaError.GENERIC_ERROR(
                helper="Cannot share a session with its owner", status_code=400
            )

        # Scope validation (admin bypasses)
        if actor_role != "admin":
            _scope = self._validate_scope(
                share_scope, owner_projects, guest_projects, guest_username
            )
            if not _scope.success:
                return _scope

        # Validate sharing mode at cluster level
        _mode = self._validate_cluster_mode()
        if not _mode.success:
            return _mode

        # Cluster policy: if unsupervised (owner-less) access is disabled
        # cluster-wide, force every grant to supervised regardless of the
        # requested per-share toggle OR the profile. The .perm build then writes
        # an explicit `deny unsupervised-access`, which overrides even Full
        # Control's `builtin`.
        if unsupervised and not self._cluster_allows_unsupervised():
            logger.info(
                "unsupervised requested but disabled cluster-wide; forcing "
                f"supervised (guest={guest_username} session={session_id})"
            )
            unsupervised = False

        # Rate limits
        if len(self.list_grants_for_session(session_id)) >= MAX_ACTIVE_GRANTS_PER_SESSION:
            return SocaError.GENERIC_ERROR(
                helper=f"Session has reached the maximum of {MAX_ACTIVE_GRANTS_PER_SESSION} active shares",
                status_code=400,
            )
        if len(self.list_grants_for_guest(guest_username)) >= MAX_ACTIVE_GRANTS_PER_GUEST:
            return SocaError.GENERIC_ERROR(
                helper=f"{guest_username} has reached the maximum of {MAX_ACTIVE_GRANTS_PER_GUEST} active shares",
                status_code=400,
            )

        # One active grant per (session, guest). A duplicate would emit a second
        # .perm line for the same guest -- redundant at best, and with mixed
        # supervision the explicit `deny unsupervised-access` silently wins,
        # producing confusing DCV behavior and ambiguous revoke semantics.
        # Reject; the owner/admin must revoke the existing share to change it.
        if any(
            g.get("guest_username", "").lower() == guest_username.lower()
            for g in self.list_grants_for_session(session_id)
        ):
            return SocaError.GENERIC_ERROR(
                helper=f"{guest_username} already has an active share on this session "
                "-- revoke it first to change the permissions",
                status_code=409,
            )

        # Resolve profile
        profile = self._profiles.get_item(
            Key={"pk": profile_id, "sk": "PROFILE"}
        ).get("Item")
        if not profile:
            return SocaError.GENERIC_ERROR(
                helper=f"Profile {profile_id} not found", status_code=404
            )
        # A disabled profile must not be usable even if a stale dropdown still
        # offers it. Profiles created before the `enabled` field default to on.
        if not profile.get("enabled", True):
            return SocaError.GENERIC_ERROR(
                helper=f"Profile '{profile.get('profile_name', profile_id)}' is disabled",
                status_code=400,
            )

        # Build .perm file content: existing active guests + the new guest,
        # so adding a 2nd+ guest never drops earlier ones.
        perm_content = self._rebuild_session_perm(
            session_id=session_id, owner=owner_username
        )
        new_flags = " ".join(profile["permissions"])
        if unsupervised and "unsupervised-access" not in profile["permissions"]:
            new_flags += " unsupervised-access"
        perm_content = perm_content.rstrip("\n") + f"\n{guest_username} allow {new_flags}\n"
        # Arm supervised auto-disconnect for this new guest (see _rebuild_session_perm):
        # an explicit deny is required; omission does not arm it.
        if not unsupervised:
            perm_content += f"{guest_username} deny unsupervised-access\n"

        # Apply permissions via broker (synchronous)
        result = self._broker.update_session_permissions(
            session_id=session_id,
            owner=owner_username,
            permissions_content=perm_content,
        )
        if not result.success:
            return SocaError.GENERIC_ERROR(
                helper=f"Broker permission update failed: {result.message}",
                status_code=502,
            )

        # Issue guest auth token
        token_result = self._broker.get_session_connection_data(
            session_id=session_id, user=guest_username
        )
        if not token_result.success:
            return SocaError.GENERIC_ERROR(
                helper=f"Broker token generation failed: {token_result.message}",
                status_code=502,
            )

        connection_token = (token_result.message or {}).get("ConnectionToken", "")

        # Write grant to DDB (shape defined by the SocaSessionSharingGrant model)
        now = datetime.now(timezone.utc).isoformat()
        grant_id = _new_id()
        grant = SocaSessionSharingGrant(
            pk=grant_id,
            session_id=session_id,
            owner_username=owner_username,
            guest_username=guest_username,
            profile_id=profile_id,
            profile_name=profile["profile_name"],
            permissions=profile["permissions"],
            status="ACTIVE",
            expires_at=expires_at,
            created_at=now,
            created_by=created_by,
            actor_role=actor_role,
            unsupervised=unsupervised,
        )
        item = grant.model_dump()
        self._grants.put_item(Item=item)

        logger.info(
            f"Grant created: {grant_id} guest={guest_username} "
            f"session={session_id} profile={profile['profile_name']} "
            f"expires={expires_at} actor={created_by}({actor_role})"
        )

        return SocaResponse(
            success=True,
            message={**item, "connection_token": connection_token},
            status_code=201,
        )

    def revoke_grant(self, grant_id: str, revoked_by: str) -> SocaResponse:
        """
        Revoke an active grant: rebuild the session .perm from the REMAINING
        active grants (so other guests keep their access), update DDB.

        Returns SocaResponse(success=True, message=<updated grant>), or
        SocaError if the grant is not found / already revoked.
        """
        resp = self._grants.get_item(Key={"pk": grant_id, "sk": "GRANT"})
        grant = _jsonsafe(resp.get("Item"))
        if not grant or grant.get("status") != "ACTIVE":
            return SocaError.GENERIC_ERROR(
                helper="Grant not found or already revoked", status_code=404
            )

        # Rebuild .perm from all OTHER active grants on this session
        perm_content = self._rebuild_session_perm(
            session_id=grant["session_id"],
            owner=grant["owner_username"],
            exclude_grant_id=grant_id,
        )
        # Remove the revoked guest's access on the live session. We deliberately
        # do NOT abort the DDB flip on broker failure: a terminated/gone session
        # legitimately fails here and revoke must stay idempotent. But a failure
        # on a LIVE session means the guest still holds access, so surface it
        # loudly for operators rather than discarding the result silently.
        _perm_result = self._broker.update_session_permissions(
            session_id=grant["session_id"],
            owner=grant["owner_username"],
            permissions_content=perm_content,
        )
        if not (_perm_result and _perm_result.success):
            logger.warning(
                f"Broker permission removal failed during revoke of grant "
                f"{grant_id} (session={grant['session_id']}): "
                f"{getattr(_perm_result, 'message', 'no response')} -- guest may "
                f"retain live access if the session is still running"
            )

        now = datetime.now(timezone.utc).isoformat()
        self._grants.update_item(
            Key={"pk": grant_id, "sk": "GRANT"},
            UpdateExpression="SET #s = :revoked, revoked_at = :now, revoked_by = :by",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":revoked": "REVOKED",
                ":now": now,
                ":by": revoked_by,
            },
        )

        logger.info(f"Grant revoked: {grant_id} by {revoked_by}")
        return SocaResponse(
            success=True,
            message={**grant, "status": "REVOKED", "revoked_at": now, "revoked_by": revoked_by},
        )

    def _rebuild_session_perm(
        self, *, session_id: str, owner: str, exclude_grant_id: Optional[str] = None
    ) -> str:
        """
        Build a complete .perm file for a session from its currently-active
        grants. Always includes the owner with full control. Each remaining
        active guest is added with their stored permission flags.

        exclude_grant_id lets a revoke/expiry caller drop the grant being
        terminated before the DDB status flip is visible.
        """
        active = self.list_grants_for_session(session_id, status="ACTIVE")
        lines = ["[permissions]", "%owner% allow builtin"]
        for g in active:
            if exclude_grant_id and g["pk"] == exclude_grant_id:
                continue
            flags = " ".join(g.get("permissions", []))
            if g.get("unsupervised") and "unsupervised-access" not in g.get("permissions", []):
                flags += " unsupervised-access"
            if flags:
                lines.append(f"{g['guest_username']} allow {flags}")
            # Supervised guests MUST be EXPLICITLY denied unsupervised-access to
            # arm DCV's supervised auto-disconnect: a user explicitly denied
            # unsupervised-access cannot connect while the owner is absent and is
            # dropped when no connected user holds it (the owner holds it via
            # 'builtin'). This REQUIRES the DCV host to run with
            # [security] supervision-control=enforced; with the default
            # ('disabled') DCV ignores unsupervised-access entirely.
            if not g.get("unsupervised"):
                lines.append(f"{g['guest_username']} deny unsupervised-access")
        return "\n".join(lines) + "\n"

    def list_grants_for_session(self, session_id: str, status: str = "ACTIVE") -> list[dict]:
        """List grants for a specific session."""
        resp = self._grants.query(
            IndexName="session-index",
            KeyConditionExpression="session_id = :sid",
            FilterExpression="#s = :status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":sid": session_id, ":status": status},
        )
        return _jsonsafe(resp.get("Items", []))

    def list_grants_for_guest(self, guest_username: str, status: str = "ACTIVE") -> list[dict]:
        """List grants shared TO a specific user (for 'shared to me' tiles)."""
        resp = self._grants.query(
            IndexName="guest-index",
            KeyConditionExpression="guest_username = :user",
            FilterExpression="#s = :status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":user": guest_username, ":status": status},
        )
        return _jsonsafe(resp.get("Items", []))

    def get_grant(self, grant_id: str) -> Optional[dict]:
        """Get a single grant by ID."""
        resp = self._grants.get_item(Key={"pk": grant_id, "sk": "GRANT"})
        return _jsonsafe(resp.get("Item"))

    def count_active_grants_for_session(self, session_id: str) -> int:
        """Count active grants on a session (drives the 'Shared (N)' tile badge)."""
        return len(self.list_grants_for_session(session_id, status="ACTIVE"))

    def list_all_active_grants(self) -> list[dict]:
        """Scan all ACTIVE grants cluster-wide (admin Active Shares view)."""
        items, kwargs = [], {
            "FilterExpression": "#s = :active",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":active": "ACTIVE"},
        }
        while True:
            resp = self._grants.scan(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return _jsonsafe(items)

    def list_all_grants(self, status: Optional[str] = None) -> list[dict]:
        """Scan ALL grants cluster-wide (admin history/audit view). When
        `status` is given (e.g. REVOKED, EXPIRED, ACTIVE) filter to it;
        otherwise return every grant regardless of status."""
        items = []
        kwargs = {}
        if status:
            kwargs = {
                "FilterExpression": "#s = :st",
                "ExpressionAttributeNames": {"#s": "status"},
                "ExpressionAttributeValues": {":st": status},
            }
        while True:
            resp = self._grants.scan(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return _jsonsafe(items)

    def record_connection(self, grant_id: str, connected_by: str) -> None:
        """Audit: stamp a successful (identity-verified) nonce consume on the
        grant -- when the guest actually connected, who, and a running count.
        Best-effort; never raises into the connect flow."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            self._grants.update_item(
                Key={"pk": grant_id, "sk": "GRANT"},
                UpdateExpression=(
                    "SET last_connected_at = :now, last_connected_by = :who "
                    "ADD connect_count :one"
                ),
                ExpressionAttributeValues={":now": now, ":who": connected_by, ":one": 1},
            )
        except Exception as err:
            logger.warning(f"record_connection failed for grant {grant_id}: {err}")

    def revoke_all_for_session(self, session_id: str, revoked_by: str) -> int:
        """
        Revoke every active grant on a session. Called when a session is
        terminated (user delete, pool recycle, admin kill) so guest access
        does not outlive the session. Returns count revoked.

        No broker .perm rewrite is attempted -- the session is going away, so
        there is nothing to update. DDB records are flipped to REVOKED for the
        audit trail and to keep 'shared to me' tiles accurate.
        """
        active = self.list_grants_for_session(session_id, status="ACTIVE")
        now = datetime.now(timezone.utc).isoformat()
        for g in active:
            self._grants.update_item(
                Key={"pk": g["pk"], "sk": "GRANT"},
                UpdateExpression="SET #s = :revoked, revoked_at = :now, revoked_by = :by",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":revoked": "REVOKED",
                    ":now": now,
                    ":by": revoked_by,
                },
            )
        if active:
            logger.info(
                f"Revoked {len(active)} active grant(s) on terminated session {session_id}"
            )
        return len(active)

    def is_profile_in_use(self, profile_id: str) -> bool:
        """True if any ACTIVE grant references this profile (blocks hard-delete)."""
        # Paginate: a FilterExpression scan with Limit caps items EVALUATED, not
        # matched -- Limit=1 could miss an active grant on a later page and let a
        # still-in-use profile be deleted. Walk all pages until a match or EOF.
        _kwargs = {
            "FilterExpression": "profile_id = :pid AND #s = :active",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":pid": profile_id, ":active": "ACTIVE"},
            "ProjectionExpression": "pk",
        }
        while True:
            resp = self._grants.scan(**_kwargs)
            if resp.get("Items"):
                return True
            if "LastEvaluatedKey" not in resp:
                return False
            _kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    @staticmethod
    def _validate_scope(
        share_scope: str,
        owner_projects: Optional[list],
        guest_projects: Optional[list],
        guest_username: str,
    ) -> SocaResponse:
        """Enforce share_scope from the session's VDI Profile."""
        if share_scope == "none":
            return SocaError.GENERIC_ERROR(
                helper="Sharing is disabled for this session's VDI profile",
                status_code=403,
            )
        if share_scope == "project":
            if not owner_projects or not guest_projects:
                return SocaError.GENERIC_ERROR(
                    helper=f"Cannot share to {guest_username}: project membership unknown",
                    status_code=403,
                )
            if not set(owner_projects) & set(guest_projects):
                return SocaError.GENERIC_ERROR(
                    helper=f"Cannot share to {guest_username}: not in a shared project "
                    "(scope=project requires overlapping project membership)",
                    status_code=403,
                )
        return SocaResponse(success=True, message="scope ok")

    def _validate_cluster_mode(self) -> SocaResponse:
        """Check cluster-level allowed_sharing_modes includes a non-none mode."""
        if not self._get_config_key:
            return SocaResponse(success=True, message="no config resolver")
        allowed = self._get_config_key(
            key_name="Config.dcv.session_sharing.allowed_sharing_modes",
            expected_type=list,
            default=["none", "secure"],
            required=False,
        )
        active_modes = [m for m in allowed if m != "none"]
        if not active_modes:
            return SocaError.GENERIC_ERROR(
                helper="Session sharing is disabled cluster-wide (allowed_sharing_modes=[none])",
                status_code=403,
            )
        return SocaResponse(success=True, message="mode ok")

    def _cluster_allows_unsupervised(self) -> bool:
        """Cluster-wide policy: may a share grant owner-less (unsupervised)
        access at all? Default True (preserves per-share/per-profile control).
        When False, all grants are forced supervised regardless of request."""
        if not self._get_config_key:
            return True
        return bool(self._get_config_key(
            key_name="Config.dcv.session_sharing.allow_unsupervised_access",
            expected_type=bool,
            default=True,
            required=False,
        ))
