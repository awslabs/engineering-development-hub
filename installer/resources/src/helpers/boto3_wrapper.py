# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Shared boto3 Session + client factory for the SOCA installer.

Centralizes boto3 client/resource creation so that a single
``boto3.session.Session`` is reused (per profile) across every caller
in the installer process. Without this, every caller pays the cost of
re-running the credential provider chain -- which on Isengard / profile-
based dev setups means spawning a ``credential_process`` subprocess on
every client build (observed: ~500-600 ms per call, ~6s for the
installer's 10-client warmup batch).

Behaviour is gated by the ``SOCA_BOTO3_SHARED_SESSION`` env var (default
``"1"``). Accepts any of ``1 / true / yes / on`` (case-insensitive) to
enable, anything else to disable and fall back to per-call
``boto3.Session()``. Kept as an opt-out for:

    * A/B benchmarking of the optimization vs the legacy path
    * Safety valve in case a future feature genuinely needs fresh
      credential resolution per client

Measured win on a typical Isengard developer setup (installer 10-client
warmup batch):

    SOCA_BOTO3_SHARED_SESSION=1  ->   0.16 s total (~16 ms/client)
    SOCA_BOTO3_SHARED_SESSION=0  ->   6.11 s total (~611 ms/client)

    ~38x speedup.

Every client build emits a DEBUG log with per-call timing
(session_ms + client_ms) so a future refactor that accidentally
regresses this will be immediately visible in the installer logs.
"""

import logging
import os
import time

import boto3
from typing import Any, Optional


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared-session cache (Option A).
#
# Process-local; not thread-safe by design (the installer is
# single-threaded for the client-warmup phase). Cache key is the
# profile name (``None`` for default credentials).
# ---------------------------------------------------------------------------
_SHARED_SESSION_CACHE: dict = {}
_SHARED_SESSION_CACHE_HITS: dict = {}
# Built-client/resource cache. The session cache above avoids re-resolving
# credentials, but session.client()/resource() still builds a fresh object on
# every call. Cache the built objects too, keyed by everything that affects
# their identity (service/region/endpoint/profile/kind).
_CLIENT_CACHE: dict = {}


def _use_shared_session() -> bool:
    """True unless SOCA_BOTO3_SHARED_SESSION is explicitly turned off."""
    _raw = os.environ.get("SOCA_BOTO3_SHARED_SESSION", "1").strip().lower()
    return _raw in ("1", "true", "yes", "on", "")


def get_shared_session(profile_name: Optional[str] = None) -> boto3.session.Session:
    """
    Return (creating if necessary) a cached ``boto3.session.Session``
    for the given profile. Reusing a Session avoids re-running the
    credential provider chain on every client build.

    When ``SOCA_BOTO3_SHARED_SESSION`` is turned off, falls back to a
    fresh ``Session`` each call.
    """
    if not _use_shared_session():
        logger.debug(
            f"boto3 shared-session DISABLED via env -- creating fresh "
            f"Session for profile={profile_name if profile_name else '<default>'}"
        )
        return (
            boto3.session.Session(profile_name=profile_name)
            if profile_name
            else boto3.session.Session()
        )

    _key = profile_name  # None or str
    _SHARED_SESSION_CACHE_HITS[_key] = _SHARED_SESSION_CACHE_HITS.get(_key, 0) + 1
    if _key not in _SHARED_SESSION_CACHE:
        logger.debug(
            f"boto3 shared-session cache MISS for profile="
            f"{_key if _key is not None else '<default>'} -- "
            f"creating new Session (credentials will be resolved now)"
        )
        _SHARED_SESSION_CACHE[_key] = (
            boto3.session.Session(profile_name=profile_name)
            if profile_name
            else boto3.session.Session()
        )
    else:
        logger.debug(
            f"boto3 shared-session cache HIT for profile="
            f"{_key if _key is not None else '<default>'}"
        )
    return _SHARED_SESSION_CACHE[_key]


def _session_was_hit(profile_name: Optional[str]) -> bool:
    """Report whether the most recent get_shared_session() for this
    profile was a cache hit (i.e. not the first call). Used for
    logging only."""
    return _SHARED_SESSION_CACHE_HITS.get(profile_name, 0) > 1


# ---------------------------------------------------------------------------
# Legacy helpers -- preserved for backwards compatibility.
# ---------------------------------------------------------------------------


def get_boto_session_credentials():
    try:
        return get_shared_session().get_credentials()
    except Exception as err:
        raise RuntimeError(f"Unable to get boto3 credentials because of {err}") from err


def get_boto_session_region():
    try:
        return get_shared_session().region_name
    except Exception as err:
        raise RuntimeError(f"Unable to get boto3 region because of {err}") from err


def get_boto(
    service_name: str,
    region_name: Optional[str] = None,
    profile_name: Optional[str] = None,
    resource: Optional[bool] = False,
    endpoint_url: Optional[str] = None,
) -> Any:
    """
    Legacy factory. Now routes through the shared-session cache rather
    than creating a fresh Session per call. Callers outside the
    installer that want the classic per-call Session behaviour can set
    ``SOCA_BOTO3_SHARED_SESSION=0``.
    """

    if not region_name:
        region_name = get_boto_session_region()

    _boto3_params = {
        "service_name": service_name,
        "region_name": region_name,
        "endpoint_url": endpoint_url,
    }

    _cache_key = (service_name, region_name, endpoint_url, profile_name, bool(resource))
    if _use_shared_session() and _cache_key in _CLIENT_CACHE:
        logger.debug(
            f"boto3 client cache HIT for service={service_name} resource={resource}"
        )
        return _CLIENT_CACHE[_cache_key]

    _t0 = time.monotonic()
    _session = get_shared_session(profile_name)
    _t_session = time.monotonic()

    try:
        if not resource:
            _result = _session.client(**_boto3_params)
        else:
            _result = _session.resource(**_boto3_params)
    except Exception as err:
        raise RuntimeError(
            f"Unable to create boto3 {'resource' if resource else 'client'} for {service_name} because of {err}"
        ) from err

    _t_done = time.monotonic()
    logger.debug(
        f"boto3 build timing: service={service_name} "
        f"resource={resource} "
        f"session={'shared' if _use_shared_session() else 'fresh'} "
        f"{'(hit)' if _session_was_hit(profile_name) else '(miss)'} "
        f"session_ms={(_t_session - _t0) * 1000:.0f} "
        f"client_ms={(_t_done - _t_session) * 1000:.0f} "
        f"total_ms={(_t_done - _t0) * 1000:.0f}"
    )
    if _use_shared_session():
        _CLIENT_CACHE[_cache_key] = _result

    return _result
