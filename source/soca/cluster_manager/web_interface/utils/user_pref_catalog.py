# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Code-side catalog of EDH WebUI user preferences.

The catalog is the SINGLE contract for what a preference is. DynamoDB is dumb
storage with no schema; this module declares every valid pref key, its value
type, constraints, and how its default resolves. Adding a preference = adding
one entry here, in the same CR as the feature that introduces it. No DDB
migration, no ALTER, no backfill.

Authority model (see docs/UserPreferences-Design.md, decision 4):
  Every preference is a user-owned, client-honored display preference. NONE are
  access controls. The admin's only lever is the org default -- declared per
  key via ``default_ssm`` -- which the resolver reads when the user has not set
  the pref. There is no clamp and no server-side enforcement in v1.

Value types (v1, decision 14): scalars only.
  - ``bool``                       true / false
  - ``int``    + optional min/max  integer with an inclusive range
  - ``string`` + optional maxlen/pattern
  - ``enum``   + ``values``        membership in an allowed set
``list`` / ``map`` are deferred -- a catalog-validation-only extension later
(variant-2 top-level DDB attributes already store them natively; no migration).

Spec shape per key::

    "<key>": {
        "type":        "bool" | "int" | "string" | "enum",   # required
        "default":     <scalar>,                              # required (code baseline)
        "default_ssm": "/configuration/.../<leaf>",           # optional admin org default
        # type-specific constraints:
        "values":      [...] | callable -> list,              # enum only
        "min": <int>, "max": <int>,                           # int only (inclusive)
        "maxlen": <int>, "pattern": r"...",                   # string only
    }

``values`` (and only ``values``) may be a zero-arg callable returning the list,
so a pref can source its allowed set from elsewhere at runtime without a hard
import cycle. ``default`` is always a plain scalar.
"""

import logging
import re
from typing import Any, Callable, Optional, Union

from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

# Python type each catalog ``type`` coerces to via SocaCastEngine.
_TYPE_PY = {
    "bool": bool,
    "int": int,
    "string": str,
    "enum": str,
}


# ---------------------------------------------------------------------------
# language allowed-values resolver
#
# The selectable languages are owned by ``app.LANGUAGES`` -- the same set
# ``get_locale()`` validates against. Resolve them lazily so the catalog stays
# the single contract without a hard import cycle (utils <- app). In-process
# (a live Flask worker) ``app`` is already imported, so this is a cheap
# sys.modules hit. Off-cluster (unit tests where ``app`` is not importable) it
# falls back to a static mirror of the current ``app.LANGUAGES`` keys.
# ---------------------------------------------------------------------------
_LANGUAGE_FALLBACK = (
    "en", "es", "es_MX", "de", "ja", "ko", "fr", "pt", "zh", "zh_TW", "hi", "it",
)


def _language_values() -> list:
    try:
        from app import LANGUAGES  # deferred; app already loaded in-process

        return sorted(LANGUAGES.keys())
    except Exception:
        return sorted(_LANGUAGE_FALLBACK)


# ---------------------------------------------------------------------------
# The catalog. One entry per preference.
# ---------------------------------------------------------------------------
PREFERENCES: dict[str, dict] = {
    # User's UI language. Allowed set tracks app.LANGUAGES at runtime. Org
    # baseline is the static "en"; not admin-tunable in v1 (no default_ssm) --
    # add one later if an org-wide default language is ever wanted.
    "language": {
        "type": "enum",
        "values": _language_values,
        "default": "en",
    },
    # Cosmetic accidental-leak masking of VDI tile previews (screen recording /
    # Zoom / training capture), like API-key masking. Client-honored bool; the
    # user owns the content. Admin sets the org default (default-on/off) via the
    # SSM key below. No clamp, no server-side enforcement.
    "vdi_tile_masking": {
        "type": "bool",
        "default": False,
        # Reuse the EXISTING DCV screenshot privacy-mode admin knob as the org
        # default tier -- this pref is the persistent form of that same feature
        # (the privacy-blur toggle on the virtual desktops page). Reusing the
        # key preserves any admin's current setting and avoids a duplicate.
        "default_ssm": "/dcv/screenshot/privacy_mode",
    },
    # Where the user lands after login. The index ("/") view redirects to the
    # chosen page; "home" (default) stays on the dashboard, so there is no
    # redirect loop. Values map to real routes (see views/index.py).
    "default_landing_page": {
        "type": "enum",
        "values": ["home", "virtual_desktops", "file_browser", "jobs", "my_account"],
        "default": "home",
    },
    # How many VDI cards per row on the virtual desktops page. Client-honored:
    # the page sets a data attribute on the card grid and a CSS rule overrides
    # the Bootstrap column width for all cards (server-rendered + live-streamed).
    "vdi_cards_per_row": {
        "type": "int",
        "default": 3,
        "min": 1,
        "max": 6,
    },
    # Show a faded short session-uuid under the VDI tile name so identically
    # named desktops (now possible after stack-name decoupling) stay visually
    # distinguishable. Client-honored display bool; default off. Purely cosmetic
    # per-user choice -- no org-default/SSM tier.
    "show_session_uuid_tile": {
        "type": "bool",
        "default": False,
    },
}


# ---------------------------------------------------------------------------
# Read helpers (internal to the preferences subsystem -- ``_`` prefixed so they
# are not "public" functions under the SOCA return-type guideline; ``validate``
# below is the public SocaResponse-returning facade).
# ---------------------------------------------------------------------------
def _all_keys() -> list:
    """Every known preference key."""
    return list(PREFERENCES.keys())


def _is_known(key: str) -> bool:
    """True if ``key`` is a declared preference."""
    return key in PREFERENCES


def _spec(key: str) -> Optional[dict]:
    """The raw spec dict for ``key``, or None if unknown."""
    return PREFERENCES.get(key)


def _default_for(key: str) -> Any:
    """The static code default (tier 3) for ``key``, or None if unknown."""
    _s = PREFERENCES.get(key)
    return _s.get("default") if _s else None


def _allowed_values(key: str) -> Optional[list]:
    """
    Resolved allowed-value list for an enum pref (resolving a callable
    ``values`` if present). None for non-enum or unknown keys.
    """
    _s = PREFERENCES.get(key)
    if not _s or _s.get("type") != "enum":
        return None
    return _resolve_values(_s.get("values"))


def _resolve_values(values: Union[list, tuple, Callable, None]) -> list:
    if callable(values):
        try:
            return list(values())
        except Exception as err:  # pragma: no cover - defensive
            logger.error(f"user_pref_catalog: values callable failed: {err}")
            return []
    return list(values or [])


# ---------------------------------------------------------------------------
# Validation / coercion
# ---------------------------------------------------------------------------
def validate(key: str, value: Any) -> SocaResponse:
    """
    Validate + coerce ``value`` for preference ``key`` against the catalog.

    Returns a SocaResponse:
      - success=True,  message=<coerced value>   when valid
      - success=False, message=<reason str>, status_code=400  when invalid
        (unknown key, wrong type, out of range, not an allowed enum member).

    This is the SINGLE validator, used at both write time and read time (the
    read path uses it for self-healing -- an invalid stored value is treated as
    absent rather than raising).
    """
    _spec = PREFERENCES.get(key)
    if _spec is None:
        return SocaResponse(
            success=False,
            message=f"unknown preference key '{key}'",
            status_code=400,
        )

    _ptype = _spec.get("type")
    _py = _TYPE_PY.get(_ptype)
    if _py is None:  # pragma: no cover - guards a malformed catalog entry
        return SocaResponse(
            success=False,
            message=f"preference '{key}' has unsupported type '{_ptype}'",
            status_code=400,
        )

    # Coerce to the declared scalar python type.
    _cast = SocaCastEngine(value).cast_as(expected_type=_py)
    if _cast.get("success") is not True:
        return SocaResponse(
            success=False,
            message=f"preference '{key}' expects {_ptype}, got {value!r}",
            status_code=400,
        )
    _coerced = _cast.get("message")

    # Type-specific constraints.
    if _ptype == "enum":
        _allowed = _resolve_values(_spec.get("values"))
        if _coerced not in _allowed:
            return SocaResponse(
                success=False,
                message=(
                    f"preference '{key}' value {_coerced!r} not in allowed "
                    f"values {_allowed}"
                ),
                status_code=400,
            )
    elif _ptype == "int":
        if "min" in _spec and _coerced < _spec["min"]:
            return SocaResponse(
                success=False,
                message=f"preference '{key}' value {_coerced} below min {_spec['min']}",
                status_code=400,
            )
        if "max" in _spec and _coerced > _spec["max"]:
            return SocaResponse(
                success=False,
                message=f"preference '{key}' value {_coerced} above max {_spec['max']}",
                status_code=400,
            )
    elif _ptype == "string":
        if "maxlen" in _spec and not Validators.is_string_length_lower_equal_than(
            _coerced, _spec["maxlen"]
        ):
            return SocaResponse(
                success=False,
                message=f"preference '{key}' exceeds maxlen {_spec['maxlen']}",
                status_code=400,
            )
        if "pattern" in _spec and not re.fullmatch(_spec["pattern"], _coerced):
            return SocaResponse(
                success=False,
                message=f"preference '{key}' does not match required pattern",
                status_code=400,
            )

    return SocaResponse(success=True, message=_coerced)
