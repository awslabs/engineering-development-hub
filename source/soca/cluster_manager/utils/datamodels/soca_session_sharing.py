# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Pydantic datamodels for DCV Session Sharing DDB records.

Used at construction time by the profile/grant services so the persisted
item shape is defined in one place (instead of ad-hoc dicts). Call
.model_dump() to get the plain dict written to DynamoDB / returned via the API.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


class SocaSessionSharingProfile(BaseModel):
    """A permission profile template (pk=profile_id, sk='PROFILE')."""

    pk: str
    sk: str = "PROFILE"
    profile_name: str
    permissions: List[str] = Field(default_factory=list)
    is_default: bool = False
    enabled: bool = True
    actor_role: str = "admin"
    created_by: str = "system"
    created_at: Optional[str] = None
    updated_by: Optional[str] = None
    updated_at: Optional[str] = None


class SocaSessionSharingGrant(BaseModel):
    """A per-session guest grant (pk=grant_id, sk='GRANT')."""

    pk: str
    sk: str = "GRANT"
    session_id: str
    owner_username: str
    guest_username: str
    profile_id: str
    profile_name: str
    permissions: List[str] = Field(default_factory=list)
    unsupervised: bool = False
    status: str = "ACTIVE"
    expires_at: Optional[str] = None
    created_at: Optional[str] = None
    created_by: str = ""
    actor_role: str = "owner"
    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None
    last_connected_at: Optional[str] = None
    last_connected_by: Optional[str] = None
    connect_count: int = 0
