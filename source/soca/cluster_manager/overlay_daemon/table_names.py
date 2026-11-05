######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Runtime resolver for the mesh DynamoDB Global Table names.

The tables are namespaced per mesh so two meshes can coexist in one account.
Physical names are:

    edh_<mesh_table_prefix>_<short_name>

The prefix is derived at install time from the mesh id by
helpers/cdk/cross_region/mesh_table_naming.py and published to SSM as
/configuration/Overlay/mesh_table_prefix.

The short-name list below duplicates TABLE_SCHEMAS in
helpers/cdk/cross_region/ddb_global_tables.py, which is the source of truth.
The duplication is deliberate and unavoidable: that module ships in the
installer artifact while this one runs on the controller, so there is no import
path between them. tests/cross_region/test_daemon_table_names.py imports both
and asserts they agree, so the two cannot drift silently.

Resolution order, highest priority first:
  1. EDH_TABLE_<SHORT> environment variable, for a caller whose table name is
     injected directly rather than derived (a Lambda handed table.table_name
     by CDK).
  2. EDH_MESH_TABLE_PREFIX environment variable, set by controller bootstrap.
  3. SocaConfig key /configuration/Overlay/mesh_table_prefix, for callers
     running under uwsgi where SocaConfig is already wired.

When none of the three resolves, resolution RAISES. There is deliberately no
fallback to a bare `edh_<short_name>`. Such a name is not merely wrong, it is
wrong in a way that can succeed: the pre-namespacing version of this feature
created exactly those bare table names, so on the upgrade path the fallback was
written to protect, a bare-named table plausibly exists and holds stale
pre-mesh data. The daemon would then read a real table and report a mesh that
does not reflect reality, which is far harder to diagnose than a refusal to
start.
"""

from __future__ import annotations
import logging
import os
import threading
from typing import Optional

logger = logging.getLogger("soca_logger")

# Mirrors TABLE_SCHEMAS in helpers/cdk/cross_region/ddb_global_tables.py.
# Guarded against drift by tests/cross_region/test_daemon_table_names.py.
SHORT_NAMES = (
    "overlay_config",
    "overlay_health",
    "overlay_audit",
    "cluster_state",
    "routing_history",
    "routing_policy",
    "routing_evaluations",
    "delegations",
)

PREFIX_ENV_VAR = "EDH_MESH_TABLE_PREFIX"
PREFIX_CONFIG_KEY = "/configuration/Overlay/mesh_table_prefix"

_lock = threading.Lock()
_cached: dict = {}  # short_name -> physical table name


class TableNameResolutionError(RuntimeError):
    """Raised when the mesh table prefix cannot be resolved from any source."""


def _resolve_prefix() -> tuple[Optional[str], Optional[str]]:
    """
    Resolve the mesh table prefix.

    Returns (prefix, unreachable_reason). Exactly one is meaningful. A None
    prefix with a None reason means no source supplied a value; a None prefix
    with a reason means a source existed but could not be consulted. Those are
    different operator problems - an unconfigured mesh against an unreachable
    configuration store - so they are reported separately rather than collapsed
    into a single "not set".
    """
    from_env = os.environ.get(PREFIX_ENV_VAR)
    if from_env:
        return from_env, None
    # SocaConfig is imported lazily so this module stays usable in plain
    # scripts that do not carry the web-tier dependencies.
    try:
        from utils.config import SocaConfig  # type: ignore

        result = SocaConfig(key=PREFIX_CONFIG_KEY).get_value()
        message = result.get("message")
        if message and message != "CACHE_MISS":
            return str(message), None
        return None, None
    except ImportError as exc:
        # No web-tier dependencies here, so the key simply has no reader.
        logger.debug("table_names: SocaConfig unavailable in this context: %s", exc)
        return None, None
    except Exception as exc:  # noqa: BLE001 - the store itself failed
        return None, f"{type(exc).__name__}: {exc}"


def resolve(short_name: str) -> str:
    """
    Return the physical table name for a mesh table short name.

    Cached per short name after first resolution, so callers can resolve on
    every operation rather than binding names at import time. Thread-safe.

    Raises TableNameResolutionError when the prefix cannot be resolved.
    """
    if short_name not in SHORT_NAMES:
        raise ValueError(
            f"resolve(): unknown short_name {short_name!r}; expected one of {SHORT_NAMES}"
        )
    with _lock:
        cached = _cached.get(short_name)
        if cached:
            return cached

        per_table = os.environ.get(f"EDH_TABLE_{short_name.upper()}")
        if per_table:
            _cached[short_name] = per_table
            return per_table

        prefix, unreachable_reason = _resolve_prefix()
        if not prefix:
            if unreachable_reason:
                raise TableNameResolutionError(
                    f"Cannot resolve the physical name of mesh table {short_name!r}: "
                    f"the {PREFIX_ENV_VAR} environment variable is unset and the "
                    f"{PREFIX_CONFIG_KEY} configuration key could not be read "
                    f"({unreachable_reason}). The prefix may well be configured; "
                    f"the configuration store could not be consulted to find out."
                )
            raise TableNameResolutionError(
                f"Cannot resolve the physical name of mesh table {short_name!r}: "
                f"neither the {PREFIX_ENV_VAR} environment variable nor the "
                f"{PREFIX_CONFIG_KEY} configuration key is set. The controller "
                f"bootstrap sets the environment variable and the installer "
                f"publishes the configuration key, so one of those two did not "
                f"run for this cluster."
            )

        full = f"edh_{prefix}_{short_name}"
        _cached[short_name] = full
        return full


def reset_cache() -> None:
    """Clear the resolution cache. For tests that mutate the environment."""
    with _lock:
        _cached.clear()
