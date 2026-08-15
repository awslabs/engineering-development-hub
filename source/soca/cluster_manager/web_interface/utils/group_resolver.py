# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Group membership resolver for feature-flag authorization.

feature_flags.allowed_groups / denied_groups carry group references that this
module resolves to a live boolean "is <login> a member of <group_ref>". Group
refs are namespaced by prefix:

    "sudoers"        -> cluster sudoers, via GET /api/ldap/sudo (the same source
                        of truth @admin_api uses). REAL / wired today.
    "ldap:<dn>"      -> arbitrary LDAP group by DN. EXTENSION POINT -- not wired
                        yet (no dedicated VDI-admin group exists); fails closed.
    "posix:<name>"   -> POSIX group. EXTENSION POINT -- not wired yet; fails
                        closed.

resolve_membership() is the single public entry point (called from the
feature_flag decorator, a different module) so it returns a SocaResponse whose
`message` is the boolean verdict and whose `success` indicates the lookup itself
completed. Callers treat (success is True AND message is True) as "is a member";
anything else -- including lookup failure -- is fail-closed (NOT a member).
"""

import logging

from utils.response import SocaResponse
from utils.error import SocaError
from utils.http_client import SocaHttpClient
from utils.validators import Validators
from utils.cache.decorator import soca_cache
import config

logger = logging.getLogger("soca_logger")

def _resolve_sudoers(login: str) -> SocaResponse:
    """Definitive sudoer verdict for `login` via GET /api/ldap/sudo (root-key) --
    the same authority @admin_api and login_required rely on.

    Returns SocaResponse(success=True, message=<bool>) ONLY for a DEFINITIVE
    answer: HTTP 200 => sudoer (message=True), HTTP 403 => not a sudoer
    (message=False). Any lookup failure (identity-provider error / HTTP 500,
    timeout or transport error => status_code 500/None) returns a SocaError, so
    the caller -- and @soca_cache -- never records a transient failure as
    'not a member' (which would deny a real sudoer for the whole cache TTL).
    """
    _resp = SocaHttpClient(
        endpoint="/api/ldap/sudo",
        headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
    ).get(params={"user": login})
    if _resp.get("success") is True:
        return SocaResponse(success=True, message=True)
    if _resp.get("status_code") == 403:
        return SocaResponse(success=True, message=False)
    return SocaError.IDENTITY_PROVIDER_ERROR(
        helper=f"sudo lookup for {login!r} was not definitive "
        f"(status={_resp.get('status_code')}): {_resp.get('message')}"
    )


@soca_cache(prefix="group_resolver", ttl=60)
def resolve_membership(login: str, group_ref: str) -> SocaResponse:
    """Resolve whether `login` is a member of `group_ref`.

    Returns SocaResponse(success=True, message=<is_member bool>) for a
    DEFINITIVE verdict, or a SocaError when the lookup itself failed. Callers
    treat (success is True AND message is True) as 'is a member'; anything else
    -- including a SocaError -- is fail-closed (NOT a member).

    Programmatic dispatch: consumed IN-PROCESS by the feature_flag decorator
    (via .get("success")/.get("message")), never returned as an HTTP response,
    so these SocaResponse/SocaError returns are intentionally NOT wrapped with
    .as_flask().

    Caching: @soca_cache (SocaCacheClient / ElastiCache, shared across workers,
    60s TTL) caches ONLY successful SocaResponses, so definitive member /
    non-member verdicts are cached but a transient lookup failure (SocaError) is
    not -- it re-checks on the next call rather than denying a real member for
    the whole TTL. If the cache is unavailable the decorator transparently
    recomputes (calls this function), so a cache outage degrades to a live
    lookup, never to a denial.
    """
    if not Validators.is_string_not_empty(login) or not Validators.is_string_not_empty(group_ref):
        return SocaResponse(success=True, message=False)

    try:
        if group_ref == "sudoers":
            return _resolve_sudoers(login)

        # Extension points -- deliberately not wired until a dedicated group
        # (e.g. vdi-admins) exists. Fail closed and make the gap explicit.
        if group_ref.startswith("ldap:") or group_ref.startswith("posix:"):
            logger.warning(
                f"group_resolver: group ref {group_ref!r} is not wired yet; "
                f"denying membership for {login} (fail-closed)"
            )
            return SocaError.GENERIC_ERROR(
                helper=f"Group resolver for {group_ref!r} not implemented"
            )

        logger.warning(
            f"group_resolver: unknown group ref {group_ref!r}; denying "
            f"membership for {login} (fail-closed)"
        )
        return SocaError.GENERIC_ERROR(
            helper=f"Unknown group ref {group_ref!r}"
        )
    except Exception as err:
        logger.warning(
            f"group_resolver: membership lookup failed for {login} in "
            f"{group_ref!r}: {err}; denying (fail-closed)"
        )
        return SocaError.GENERIC_ERROR(
            helper=f"Membership lookup failed for {group_ref!r}: {err}"
        )
