# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
BootstrapTemplateCache -- content-addressable cache for rendered SOCA
bootstrap templates.

Eliminates the redundant Jinja2 render + S3 PUT round-trip that
otherwise dominates VDI/HPC create latency. The big bootstrap templates
(02_setup.sh, 03_setup_post_reboot.sh, install_required_packages.sh,
filesystems_automount.sh, etc.) are rendered once per
(stack_relevant_soca_parameters, .j2 content tree), keyed by a SHA256
hash, and stored in the cluster S3 bucket. Per-session values are
surfaced via a separate small env file (00_session_env.sh) that is
sourced by the worker before the cached big bootstrap runs.

See docs/BootstrapTemplateCache.md for the full design.

Configuration
-------------
Driven by SocaConfig keys (with the standard /configuration prefix
auto-applied):

    /configuration/feature_flags/BootstrapTemplateCache/enabled
        default True. When False, get_or_render() short-circuits to the
        render_fn and uploads bodies fresh on every call (today's
        behavior, no cache).
    /configuration/feature_flags/BootstrapTemplateCache/ttl_minutes
        default 120. Cache entries older than this trigger re-render
        even when content addressing says "hit". Safety net for inputs
        that don't surface in the cache key (e.g. underlying AMI
        fingerprint changes).

Cache layout in S3
------------------
    s3://<bucket>/<prefix>/<stack_cache_key>/
        <one body per template>
        .stack_meta.json           # atomic completion marker, written LAST

Failure modes (per docs/BootstrapTemplateCache.md section 5)
------------------------------------------------------------
- Cold-cache race: last-write-wins. Acceptable.
- Partial render: marker is written LAST, after all bodies. HEAD on
  marker. Marker missing -> miss.
- Body deleted but marker present: S3 lifecycle policy expires the
  whole prefix together; worker stub retries.
- HEAD timeout / 5xx: treat as MISS. WARNING-logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

logger = logging.getLogger("soca_logger")


# Per-session SocaConfig keys that MUST be excluded from the stack cache
# key. Adding more per-session keys here is the safe direction; the only
# cost is recomputing the cache (which then de-duplicates on the next
# create). Forgetting to add one would cause a stack-level cache entry
# to embed per-session content -- which is exactly the bug we're trying
# to prevent.
EXCLUDE_PER_SESSION_PREFIXES: tuple[str, ...] = (
    "/job/JobId",
    "/job/JobName",
    "/job/JobOwner",
    "/job/JobProject",
    "/job/JobQueue",
    "/job/SessionOwner",
    "/job/StackId",
    "/job/Session",  # catches /job/SessionIr, /job/SessionId, /job/Session*
    "/job/BootstrapPath",
    "/job/BootstrapScripts",
    "/job/ScratchSize",
    "/job/KeepForever",
    "/job/TerminateWhenIdle",
    "/dcv/Session",  # catches /dcv/SessionId, /dcv/SessionName, /dcv/SessionOwner, /dcv/SessionType
)


# Shorter is fine for our scale (clusters have <100 distinct stack
# configs in practice, well below the 64-bit collision floor) but
# longer is harmless. 16 hex = 64 bits is the sweet spot for log
# readability.
CACHE_KEY_HEX_LEN: int = 16


@dataclass(frozen=True)
class _CacheLookupResult:
    """Outcome of a HEAD on the cache marker."""

    hit: bool
    reason: str  # one of: "hit_fresh", "hit_ttl_expired", "miss", "head_failed"
    age_seconds: int | None = None


def _is_per_session_key(key: str) -> bool:
    """True if `key` is a per-session SocaConfig key that must be excluded
    from the cache hash. Whitespace-trimmed; case-sensitive (matches
    SOCA's existing key conventions).
    """
    return any(key.startswith(prefix) for prefix in EXCLUDE_PER_SESSION_PREFIXES)


def _filter_stack_relevant(soca_parameters: dict) -> dict:
    """Return only the keys from `soca_parameters` that should affect the
    stack-level cache key. Per-session keys are excluded.
    """
    return {k: v for k, v in soca_parameters.items() if not _is_per_session_key(k)}


def _hash_template_tree(bootstrap_root: Path) -> dict[str, str]:
    """Walk `bootstrap_root` recursively, hashing every `.j2` file by
    content. Returns a dict of relative-path -> sha256-hex.

    The walk is over-pessimistic on purpose: any .j2 edit anywhere
    under bootstrap_root busts the cache. The trade-off is rare
    spurious cache misses (cheap) vs the risk of serving stale content
    after a partial template edit (correctness bug). Always-correct
    wins.
    """
    if not bootstrap_root.is_dir():
        raise ValueError(
            f"bootstrap_root {bootstrap_root!s} is not a directory; "
            "cache key cannot be computed"
        )
    out: dict[str, str] = {}
    for j2_path in sorted(bootstrap_root.rglob("*.j2")):
        rel = str(j2_path.relative_to(bootstrap_root))
        out[rel] = hashlib.sha256(j2_path.read_bytes()).hexdigest()
    return out


def compute_stack_cache_key(
    soca_parameters: dict, bootstrap_root: Path | str
) -> str:
    """
    Compute a deterministic content-addressable cache key for the
    bootstrap template render of a given (stack-config, .j2 tree)
    combination.

    The key is the first `CACHE_KEY_HEX_LEN` hex chars of:
        sha256(canonical_json({
            "params": <soca_parameters with per-session keys excluded>,
            "templates": <relative_path -> sha256 of every .j2>
        }))

    Same inputs -> same key. Any change in the included soca_parameters
    OR in the content of any .j2 file -> different key. Per-session
    keys (instance/owner/session ids etc) are excluded so 100 sessions
    against the same software stack collapse to one cache entry.
    """
    bootstrap_root = Path(bootstrap_root)
    payload = {
        "params": _filter_stack_relevant(soca_parameters),
        "templates": _hash_template_tree(bootstrap_root),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:CACHE_KEY_HEX_LEN]


# Module-level LRU caches the .j2 tree hash for a given (root, mtime-ish
# bucket) so back-to-back create requests within the same uwsgi worker
# don't re-hash the whole tree. 60s window is short enough that hot-
# patches are picked up promptly.
@lru_cache(maxsize=8)
def _hash_template_tree_cached(bootstrap_root_str: str, bucket: int) -> str:
    """Cached `_hash_template_tree`. The `bucket` argument is a quantized
    timestamp (current_time // 60) -- inputs landing in the same bucket
    return the same cached value, while a new bucket forces a re-hash.
    Callers should pass `bucket = int(time.time() // 60)`.
    """
    payload = _hash_template_tree(Path(bootstrap_root_str))
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class BootstrapCache:
    """
    Cache facade. Construct once per controller process, call
    `get_or_render(cache_key, render_fn)` per template-bundle render.

    Parameters
    ----------
    s3_client:
        boto3 S3 client. Caller-supplied so we don't carry a global
        boto session here (and so unit tests can pass a moto-backed
        client trivially).
    bucket:
        S3 bucket name (typically the cluster's S3Bucket SocaConfig
        value).
    prefix:
        S3 key prefix under which to store cache entries. Each cache
        entry is a sub-prefix `<prefix>/<stack_cache_key>/`. Conventional
        layout is `<cluster_id>/bootstrap/cache`.
    enabled:
        When False, `get_or_render` always calls `render_fn` and
        uploads bodies fresh. Used to wire the `BootstrapTemplateCache.
        enabled` SocaConfig flag.
    ttl_seconds:
        Cache entries older than this are treated as miss even when the
        content-addressable key matches. 7200 seconds (2 hours) is the
        documented default.

    Thread safety
    -------------
    No internal mutable state -- safe to share an instance across
    threads. The boto3 S3 client is itself thread-safe.
    """

    MARKER_NAME: str = ".stack_meta.json"

    def __init__(
        self,
        s3_client: Any,
        bucket: str,
        prefix: str,
        enabled: bool = True,
        ttl_seconds: int = 7200,
    ) -> None:
        if not bucket:
            raise ValueError("BootstrapCache requires a non-empty `bucket`")
        if not prefix:
            raise ValueError("BootstrapCache requires a non-empty `prefix`")
        self._s3 = s3_client
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._enabled = bool(enabled)
        if ttl_seconds < 0:
            raise ValueError(f"ttl_seconds must be >= 0, got {ttl_seconds}")
        self._ttl_seconds = int(ttl_seconds)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def cache_prefix_for(self, cache_key: str) -> str:
        """Return the S3 prefix (with trailing slash) for a cache entry."""
        return f"{self._prefix}/{cache_key}/"

    def cache_uri_for(self, cache_key: str) -> str:
        """Return the s3:// URI for a cache entry's prefix."""
        return f"s3://{self._bucket}/{self.cache_prefix_for(cache_key)}"

    def _marker_key(self, cache_key: str) -> str:
        return f"{self.cache_prefix_for(cache_key)}{self.MARKER_NAME}"

    def _check_marker(self, cache_key: str) -> _CacheLookupResult:
        """HEAD the marker; classify the outcome."""
        marker_key = self._marker_key(cache_key)
        try:
            head = self._s3.head_object(Bucket=self._bucket, Key=marker_key)
        except self._s3.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("404", "NoSuchKey", "NotFound"):
                return _CacheLookupResult(hit=False, reason="miss")
            logger.warning(
                "BootstrapCache HEAD on s3://%s/%s failed (%s); treating as MISS",
                self._bucket,
                marker_key,
                code or repr(exc),
            )
            return _CacheLookupResult(hit=False, reason="head_failed")
        # Pull build_ts out of either the user metadata or the body.
        build_ts: int | None = None
        meta = head.get("Metadata") or {}
        raw = meta.get("build-ts")
        if raw:
            try:
                build_ts = int(raw)
            except (TypeError, ValueError):
                logger.debug(
                    "BootstrapCache: marker %s has unparseable build-ts metadata=%r",
                    marker_key,
                    raw,
                )
        if build_ts is None:
            # Fall back to LastModified (timestamp granularity is fine for
            # the 2h TTL safety net).
            last_mod = head.get("LastModified")
            if last_mod is not None:
                build_ts = int(last_mod.timestamp())
        if build_ts is None:
            # We have a marker but no usable timestamp -- conservative:
            # treat as fresh (favor cache hit over wasted re-render).
            return _CacheLookupResult(hit=True, reason="hit_fresh", age_seconds=None)
        age = int(time.time() - build_ts)
        if age > self._ttl_seconds:
            return _CacheLookupResult(
                hit=False, reason="hit_ttl_expired", age_seconds=age
            )
        return _CacheLookupResult(hit=True, reason="hit_fresh", age_seconds=age)

    def get_or_render(
        self,
        cache_key: str,
        render_fn: Callable[[], Iterable[tuple[str, bytes | str]]],
    ) -> str:
        """
        Return the cached cache_uri for `cache_key`. If absent or
        TTL-expired, call `render_fn()` (which returns an iterable of
        (filename, body) pairs), upload each, then upload the marker.

        When the cache is disabled (constructor flag) or the call
        otherwise has to render, the bodies are PUT to the same
        `<prefix>/<cache_key>/` location -- so the worker UserData
        stub doesn't have to know whether the cache was warm or cold.
        Subsequent calls with the same `cache_key` will then hit the
        cache.

        Parameters
        ----------
        cache_key:
            The content-addressable key produced by
            `compute_stack_cache_key`.
        render_fn:
            Zero-arg callable returning an iterable of `(filename, body)`
            pairs. `body` may be `bytes` or `str` (encoded UTF-8). The
            callable is only invoked on miss/TTL-expired/disabled paths.
        """
        if not cache_key:
            raise ValueError("cache_key must be non-empty")
        if not self._enabled:
            logger.debug(
                "BootstrapCache disabled; rendering and uploading without HEAD probe"
            )
            self._render_and_upload(cache_key, render_fn)
            return self.cache_uri_for(cache_key)
        outcome = self._check_marker(cache_key)
        if outcome.hit:
            logger.info(
                "BootstrapCache HIT cache_key=%s age=%ss",
                cache_key,
                outcome.age_seconds,
            )
            return self.cache_uri_for(cache_key)
        logger.info(
            "BootstrapCache MISS cache_key=%s reason=%s; rendering",
            cache_key,
            outcome.reason,
        )
        self._render_and_upload(cache_key, render_fn)
        return self.cache_uri_for(cache_key)

    def _render_and_upload(
        self,
        cache_key: str,
        render_fn: Callable[[], Iterable[tuple[str, bytes | str]]],
    ) -> None:
        """Run the render callback, upload each body, then upload the
        atomic completion marker LAST.

        On exception during render or any body upload, the marker is
        NOT written -- so the next call sees a miss and tries again.
        Orphan body objects under the prefix are reaped by the S3
        lifecycle policy on the cache prefix.
        """
        rendered = list(render_fn())
        if not rendered:
            raise ValueError(
                f"render_fn for cache_key {cache_key!r} returned no bodies"
            )
        for fname, body in rendered:
            if not fname or fname == self.MARKER_NAME or "/" in fname:
                raise ValueError(
                    f"render_fn returned invalid filename {fname!r}; "
                    "filenames must be a single basename and must not "
                    f"collide with the marker {self.MARKER_NAME!r}"
                )
            body_bytes = body.encode("utf-8") if isinstance(body, str) else body
            self._s3.put_object(
                Bucket=self._bucket,
                Key=f"{self.cache_prefix_for(cache_key)}{fname}",
                Body=body_bytes,
                ContentType="text/x-shellscript",
            )
        # Marker LAST -- atomic "this entry is complete" signal.
        marker_body = json.dumps(
            {
                "stack_cache_key": cache_key,
                "rendered_at": int(time.time()),
                "body_count": len(rendered),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self._s3.put_object(
            Bucket=self._bucket,
            Key=self._marker_key(cache_key),
            Body=marker_body,
            ContentType="application/json",
            Metadata={"build-ts": str(int(time.time()))},
        )

    def refresh_all(self) -> int:
        """Force every cache entry to be re-rendered on next access by
        deleting all marker files under the configured prefix.

        Body files are left in place (next render's PUT will overwrite
        them; the S3 lifecycle policy on the prefix will reap any
        orphans that never get re-rendered).

        Returns the number of markers deleted. Surfaced via the admin
        "Refresh bootstrap cache" button on the admin status page.
        """
        deleted = 0
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(
            Bucket=self._bucket, Prefix=f"{self._prefix}/"
        ):
            keys_to_delete = [
                {"Key": obj["Key"]}
                for obj in page.get("Contents") or []
                if obj["Key"].endswith(f"/{self.MARKER_NAME}")
            ]
            if not keys_to_delete:
                continue
            self._s3.delete_objects(
                Bucket=self._bucket,
                Delete={"Objects": keys_to_delete, "Quiet": True},
            )
            deleted += len(keys_to_delete)
        logger.info(
            "BootstrapCache.refresh_all: deleted %d markers under s3://%s/%s/",
            deleted,
            self._bucket,
            self._prefix,
        )
        return deleted
