# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, List, Optional

from pydantic import BaseModel


class ResolvedPrefMeta(BaseModel):
    """
    Structured payload for a single resolved user preference (see
    web_interface/utils/user_pref_store.py). Built by ``_with_meta`` and
    serialized to a plain dict at the store's public SocaResponse boundary, so
    the REST API, views, and templates consume a stable, typed shape.

    Fields:
      value   -- the resolved value (tier 1 user / tier 2 admin / tier 3 code).
      is_set  -- True only when the value came from the user's stored row.
      source  -- "user" | "admin" | "default" | None (unknown key).
      allowed -- enum allowed-values list (None for non-enum).
      min/max -- inclusive int bounds (None when not an int pref / unbounded).
    """

    value: Any = None
    is_set: bool = False
    source: Optional[str] = None
    allowed: Optional[List[Any]] = None
    min: Optional[int] = None
    max: Optional[int] = None


class ResolvedPrefView(ResolvedPrefMeta):
    """
    ResolvedPrefMeta plus the catalog ``key`` and ``type`` -- the per-row shape
    the My Account Preferences panel renders (one control per preference).
    """

    key: str
    type: Optional[str] = None
