# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
High-level helper that ties BootstrapCache + SocaJinja2Generator
together so both the VDI create path
(api/v1/dcv/create_virtual_desktop.py) and the HPC dispatcher
(orchestrator/cloudformation_builder.py) call into one shared
implementation.

bootstrap_cache.py stays pure cache logic with no Jinja2 dependency
(easy to unit-test with moto). This module is the integration point
that knows about both halves.

See docs/BootstrapTemplateCache.md for the design.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from utils.bootstrap_cache import (
    BootstrapCache,
    compute_stack_cache_key,
)
from utils.aws.s3_helper import s3_join
from utils.config import SocaConfig
from utils.jinjanizer import SocaJinja2Generator

logger = logging.getLogger("soca_logger")


@dataclass(frozen=True)
class BootstrapRenderResult:
    """Outcome of `render_bootstrap_bundle`.

    Both `bootstrap_scripts_s3` and `session_env_s3` are S3 directory
    URIs WITHOUT a trailing slash, so callers (Linux + Windows worker
    stubs, log lines, sync targets) can append `/<filename>` once
    without producing a `//`. S3 keys are exact-match -- a `//` is a
    different key from a `/` and HeadObject 404s on the wrong one.

    Both fields are produced via `utils.aws.s3_helper.s3_join(...)`,
    which is idempotent on slashes -- callers don't have to worry
    about whether their pieces had trailing slashes.

    `session_env_s3` may be empty when the cache feature is disabled
    AND there is no per-session env file to fetch -- the worker stub
    skips the download step in that case. (In the current
    implementation it is always non-empty, but the sentinel is
    preserved for forward compatibility.)
    """

    bootstrap_scripts_s3: str
    session_env_s3: str
    cache_hit: bool
    cache_key: str


def _render_to_string(
    template_relpath: str,
    bootstrap_root: str,
    soca_parameters: dict,
) -> str:
    """Render a single .j2 to a string, raising on failure."""
    resp = SocaJinja2Generator(
        get_template=f"{template_relpath}.j2",
        template_dirs=[bootstrap_root],
        variables=soca_parameters,
    ).to_stdout(autocast_values=True)
    if not resp.get("success"):
        raise RuntimeError(
            f"Jinja render failed for {template_relpath}.j2: "
            f"{resp.get('message')}"
        )
    return resp.get("message", "")


def render_bootstrap_bundle(
    *,
    soca_parameters: dict,
    bootstrap_root: Path | str,
    s3_client,
    bucket: str,
    cluster_id: str,
    per_session_prefix: str,
    cache_prefix: str,
    big_templates: list[str],
    session_env_template: str,
    session_env_filename: str,
    cache_bypass: bool = False,
) -> BootstrapRenderResult:
    """
    Render the bootstrap bundle for one VDI or HPC create.

    Cache-state semantics
    ---------------------
    There are three orthogonal switches:

    1. The cluster-wide config flag `Config.feature_flags.
       BootstrapTemplateCache.enabled` (read from SocaConfig). When
       false, this function ALWAYS uses the legacy per-session render
       path -- the `cache_bypass` arg is ignored because there's
       nothing to bypass.
    2. The per-request `cache_bypass=True` arg. When the cluster flag
       is enabled BUT this request asked to bypass, render to the
       per-session S3 prefix and do NOT consult or mutate the cache.
       Other in-flight creates against the cache are unaffected.
    3. The TTL safety net inside BootstrapCache itself. Independent of
       1 and 2.

    When the cluster flag is enabled and `cache_bypass=False`:
        - The big_templates are rendered via the content-addressable
          BootstrapCache (no-op on cache hit, full render+upload on
          miss). The result lives at `s3://bucket/<cache_prefix>/<key>/`.
        - The session_env_template is rendered fresh and uploaded to
          `s3://bucket/<per_session_prefix>/`.

    When disabled OR `cache_bypass=True`:
        - All templates (big + env) are rendered to the per-session
          prefix as if the cache didn't exist.
        - `session_env_s3` is still set to the per-session prefix so
          the worker stub sources the env file.

    Parameters
    ----------
    cache_bypass:
        Per-request override. Defaults False. When True, forces this
        single render to skip the cache regardless of the cluster flag
        (as long as the cluster flag is enabled -- if disabled, this
        arg is a no-op since legacy render is already in effect).

    Parameters
    ----------
    soca_parameters:
        Full SocaConfig dict including per-session keys. The cache key
        derivation strips per-session keys; the session_env render needs
        them. Pass as-is.
    bootstrap_root:
        Path to source/soca/cluster_node_bootstrap on the controller.
    s3_client:
        boto3 S3 client (caller-supplied).
    bucket:
        Cluster S3 bucket name (`/configuration/S3Bucket` value).
    cluster_id:
        Used in log messages only.
    per_session_prefix:
        S3 key prefix (no leading or trailing slash) where per-session
        renders go. E.g. `<cluster_id>/.../<session_uuid>`.
    cache_prefix:
        S3 key prefix for cache entries. E.g. `<cluster_id>/bootstrap/cache`.
    big_templates:
        Template paths relative to bootstrap_root, WITHOUT `.j2` suffix
        (e.g. `compute_node/02_setup.sh`). Same convention as the
        existing `_templates_to_render` lists.
    session_env_template:
        Template path for the per-session env file, relative to
        bootstrap_root, WITHOUT `.j2`. e.g.
        `templates/linux/00_session_env.sh` or
        `windows_virtual_desktop/00_session_env.ps1`.
    session_env_filename:
        On-S3 filename for the rendered per-session env file (e.g.
        `00_session_env.sh` or `00_session_env.ps1`).
    """
    bootstrap_root = str(bootstrap_root)

    enabled = (
        SocaConfig(
            key="/configuration/feature_flags/BootstrapTemplateCache/enabled"
        )
        .get_value(default=True, allow_unknown_key=True, return_as=bool)
        .get("message", True)
    )
    ttl_minutes = (
        SocaConfig(
            key="/configuration/feature_flags/BootstrapTemplateCache/ttl_minutes"
        )
        .get_value(default=120, allow_unknown_key=True, return_as=int)
        .get("message", 120)
    )

    per_session_prefix = per_session_prefix.strip("/")
    cache_prefix = cache_prefix.strip("/")

    # ---------- DISABLED or BYPASS path: legacy per-session render ----------
    if not enabled or cache_bypass:
        reason = "disabled" if not enabled else "request-level cache_bypass"
        logger.info(
            "BootstrapTemplateCache %s for cluster_id=%s; rendering all "
            "templates to the per-session prefix",
            reason,
            cluster_id,
        )
        for tpath in big_templates:
            body = _render_to_string(tpath, bootstrap_root, soca_parameters)
            fname = tpath.split("/")[-1]
            # Strip the final file extension only -- the original code
            # uses `.split('/')[-1]` which keeps the extension. Match that.
            s3_client.put_object(
                Bucket=bucket,
                Key=f"{per_session_prefix}/{fname}",
                Body=body.encode("utf-8"),
                ContentType="text/x-shellscript",
            )
        # In the disabled path the session_env_s3 is intentionally empty
        # so the worker stub does NOT try to source a file that doesn't
        # exist. The big templates still have per-session ${EDH_*} refs
        # but those resolve to empty strings on the worker -- which is
        # the SAME behavior we get when /etc/environment is missing
        # those vars (existing behavior pre-cache). Cluster operators
        # should leave the cache enabled to actually benefit from the
        # refactor.
        #
        # However: we still need the EDH_* env vars set on the worker
        # for the cached templates to function correctly when they get
        # cached LATER (after re-enabling). So we render the env file
        # to the per-session prefix and return its s3 path. This way
        # the disabled path is also forward-compatible.
        env_body = _render_to_string(
            session_env_template, bootstrap_root, soca_parameters
        )
        s3_client.put_object(
            Bucket=bucket,
            Key=f"{per_session_prefix}/{session_env_filename}",
            Body=env_body.encode("utf-8"),
            ContentType="text/x-shellscript",
        )
        return BootstrapRenderResult(
            bootstrap_scripts_s3=s3_join(
                f"s3://{bucket}", per_session_prefix
            ),
            # Even when disabled, expose the env file so cached
            # templates work on the worker. Worker stub skips the source
            # step when this is empty -- so we KEEP it set here.
            session_env_s3=s3_join(f"s3://{bucket}", per_session_prefix),
            cache_hit=False,
            cache_key="",
        )

    # ---------- ENABLED path ----------
    cache_key = compute_stack_cache_key(soca_parameters, bootstrap_root)
    cache = BootstrapCache(
        s3_client=s3_client,
        bucket=bucket,
        prefix=cache_prefix,
        enabled=True,
        ttl_seconds=ttl_minutes * 60,
    )

    def _render_all_big() -> Iterable[tuple[str, bytes]]:
        for tpath in big_templates:
            body = _render_to_string(tpath, bootstrap_root, soca_parameters)
            fname = tpath.split("/")[-1]
            yield (fname, body.encode("utf-8"))

    # Probe-then-render. The probe is internal to BootstrapCache; the
    # closure here only runs on miss/TTL-expired/disabled paths.
    pre_check_marker = cache._check_marker(cache_key)  # internal probe for telemetry only
    cache_uri = cache.get_or_render(cache_key, _render_all_big)
    cache_hit = pre_check_marker.hit
    logger.info(
        "render_bootstrap_bundle cluster_id=%s cache_key=%s cache_hit=%s "
        "ttl_minutes=%d",
        cluster_id,
        cache_key,
        cache_hit,
        ttl_minutes,
    )

    # Always render + upload the per-session env file fresh.
    env_body = _render_to_string(
        session_env_template, bootstrap_root, soca_parameters
    )
    s3_client.put_object(
        Bucket=bucket,
        Key=f"{per_session_prefix}/{session_env_filename}",
        Body=env_body.encode("utf-8"),
        ContentType="text/x-shellscript",
    )

    return BootstrapRenderResult(
        bootstrap_scripts_s3=cache_uri,
        session_env_s3=s3_join(f"s3://{bucket}", per_session_prefix),
        cache_hit=cache_hit,
        cache_key=cache_key,
    )
