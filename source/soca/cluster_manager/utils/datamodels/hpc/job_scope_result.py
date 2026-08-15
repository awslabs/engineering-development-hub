# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Optional, Set

from pydantic import BaseModel


class SocaJobScopeResult(BaseModel):
    """Resolved visibility scope for the My HPC Jobs listing."""

    # Value to pass as the API 'user' filter (None = no single-user filter)
    effective_user: Optional[str] = None

    # Owners to post-filter on (None = unrestricted)
    allowed_owners: Optional[Set[str]] = None
