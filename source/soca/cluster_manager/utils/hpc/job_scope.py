# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import logging
from typing import Optional

from utils.response import SocaResponse
from utils.datamodels.hpc.job_scope_result import SocaJobScopeResult

logger = logging.getLogger("soca_logger")

# Admin-configurable visibility ceiling for the My HPC Jobs listing.
VALID_POSTURES = ("all", "project", "owner_only")
DEFAULT_POSTURE = "all"


def resolve_job_scope(
    caller: str,
    is_admin: bool,
    posture: str,
    requested_user: Optional[str] = None,
    project_peers: Optional[set] = None,
) -> SocaResponse:
    """
    Decide which owners' jobs the caller is allowed to see.

    Returns SocaResponse whose message is {"effective_user": str|None, "allowed_owners": set|None}
      effective_user: value to pass as the API 'user' filter (None = no single-user filter)
      allowed_owners: owners to post-filter on (None = unrestricted)

    Admins always see everything; posture only constrains non-admins.
    """
    posture = (posture or DEFAULT_POSTURE).strip().lower()
    if posture not in VALID_POSTURES:
        logger.warning(f"Invalid job visibility posture {posture!r}, defaulting to {DEFAULT_POSTURE}")
        posture = DEFAULT_POSTURE

    requested_user = (requested_user or "").strip() or None

    if is_admin or posture == "all":
        return SocaResponse(success=True, message=SocaJobScopeResult(effective_user=requested_user, allowed_owners=None))

    if posture == "owner_only":
        # Non-admin can only ever see their own jobs, regardless of what was requested.
        return SocaResponse(success=True, message=SocaJobScopeResult(effective_user=caller, allowed_owners={caller}))

    # posture == "project": limit to owners in the caller's shared projects (+ self)
    _peers = set(project_peers or set())
    _peers.add(caller)
    if requested_user:
        # Honor a requested user only if within the peer set; otherwise fall back to self.
        if requested_user in _peers:
            return SocaResponse(success=True, message=SocaJobScopeResult(effective_user=requested_user, allowed_owners=_peers))
        return SocaResponse(success=True, message=SocaJobScopeResult(effective_user=caller, allowed_owners={caller}))
    return SocaResponse(success=True, message=SocaJobScopeResult(effective_user=None, allowed_owners=_peers))
