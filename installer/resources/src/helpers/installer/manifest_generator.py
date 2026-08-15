# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Manifest generator for the Resource Mirror Executor.

Walks the SOCA install config Parameters tree (the same discovery logic the
legacy install-host path uses) and produces a manifest JSON suitable for the
SFN Inline Map. Writes the manifest to S3 for the state machine to consume.
"""

import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger("ManifestGenerator")

MIRROR_EXCLUDE_URLS = [
    "https://us.download.nvidia.com/tesla",
    "https://repo.radeon.com/amdgpu",
    # ec2-*-drivers s3_bucket_url (https://<bucket>.s3.amazonaws.com) are NOT artifacts and
    # are no longer consumed by anything: the GPU driver scripts dropped the region-probe
    # HEAD and let `aws s3 cp` self-resolve the bucket region. Exclude them so they are
    # neither mirrored nor repointed -- BulkSSMWriter leaves the original value (a harmless
    # dead key). Only s3_bucket_path is repointed (see _gpu_repoint_kind).
    "https://ec2-linux-nvidia-drivers.s3.amazonaws.com",
    "https://ec2-windows-nvidia-drivers.s3.amazonaws.com",
    "https://ec2-amd-linux-drivers.s3.amazonaws.com",
    "https://ec2-amd-windows-drivers.s3.amazonaws.com",
]

# D16: GPU driver buckets mirrored by expanding selected prefixes. AWS-published,
# region us-east-1. Per-vendor toggles (D16a): NVIDIA default ON, AMD default OFF (AMD GPU
# offerings are old/rarely used). AMD can be re-enabled for a deployed cluster via a
# manifest-refresh re-run.
GPU_DRIVER_BUCKETS = {
    "nvidia": ["ec2-linux-nvidia-drivers", "ec2-windows-nvidia-drivers"],
    "amd": ["ec2-amd-linux-drivers", "ec2-amd-windows-drivers"],
}
# Prefixes to mirror per bucket. `latest/` tracks newest; the pinned grid-N/ prefixes MUST
# match the versions the consumer templates hardcode, because the consumer pulls
# `<s3_bucket_path>/<GridVersion>/` -- Windows has NO cross-version fallback, Linux falls
# back to latest/. Keep in sync with the consumer pins:
#   windows/gpu/nvidia_drivers.ps.j2   WS2019=grid-18.0, WS2022/2025=grid-19.4
#   linux/gpu/install_drivers.sh.j2    grid-17.1, grid-19.4
# A non-existent prefix lists empty and is skipped, so an over-broad list is harmless.
# AMD s3_bucket_path config already points at `.../latest/`, so AMD needs latest/ only.
GPU_DRIVER_PREFIXES = {
    "ec2-linux-nvidia-drivers":   ["latest/", "grid-17.1/", "grid-19.4/"],
    "ec2-windows-nvidia-drivers": ["latest/", "grid-18.0/", "grid-19.4/"],
    "ec2-amd-linux-drivers":      ["latest/"],
    "ec2-amd-windows-drivers":    ["latest/"],
}
GPU_DRIVER_DEFAULT_PREFIXES = ["latest/"]
GPU_DRIVER_REGION = "us-east-1"

# D16b: buckets KNOWN to deny server-side CopyObject (EULA-gated; GetObject works, copy
# doesn't). Pin these to s3_method=getput so the executor skips the wasted copy attempt.
# Verified: ec2-linux-nvidia-drivers denies CopyObject; the others copy fine.
KNOWN_GETPUT_BUCKETS = {"ec2-linux-nvidia-drivers"}


def expand_gpu_driver_prefixes(cluster_name, nvidia=True, amd=False, s3_client=None):
    """D16: list each enabled GPU driver vendor's bucket `latest/` prefix and emit one
    s3-copy manifest item per object. Handles single- (NVIDIA) or multi-file (AMD)
    uniformly, no version-pinning (tracks current `latest/`).

    Per-vendor toggles (D16a): nvidia default on, amd default off. AMD is re-enabled
    for a deployed cluster simply by re-running the mirror (D9) with amd=True — the
    manifest is regenerated per run, so the refresh picks up the new vendor set."""
    import boto3
    s3 = s3_client or boto3.client("s3", region_name=GPU_DRIVER_REGION)
    s3_base_prefix = f"{cluster_name}/resources_mirroring"
    enabled = ([] + (GPU_DRIVER_BUCKETS["nvidia"] if nvidia else [])
               + (GPU_DRIVER_BUCKETS["amd"] if amd else []))
    items = []
    for bucket in enabled:
        prefixes = GPU_DRIVER_PREFIXES.get(bucket, GPU_DRIVER_DEFAULT_PREFIXES)
        for prefix in prefixes:
            try:
                paginator = s3.get_paginator("list_objects_v2")
                count = 0
                for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        key = obj["Key"]
                        if key.endswith("/") or obj["Size"] == 0:
                            continue
                        if key.rsplit("/", 1)[-1] in (".DS_Store",):
                            continue  # junk that appears in some upstream prefixes
                        items.append({
                            "urls": [f"s3://{bucket}/{key}"],
                            "expected_sha256": None,
                            "s3_target": f"{s3_base_prefix}/{bucket}/{key}",
                            "config_key": "",  # consumed via bootstrap `aws s3 cp`, no SSM repoint
                            "on_error": "fail",
                            "s3_method": "getput" if bucket in KNOWN_GETPUT_BUCKETS else "auto",
                        })
                        count += 1
                logger.info(f"GPU driver bucket {bucket}/{prefix}: {count} object(s)")
            except Exception as err:
                logger.warning(f"Could not list GPU driver bucket {bucket}/{prefix}: {err}")
    return items


def generate_manifest(
    parameters: dict,
    cluster_name: str,
    ssm_prefix: str,
    mirror_s3_sources: bool = True,
    mirror_gpu_nvidia: bool = True,
    mirror_gpu_amd: bool = False,
    s3_client=None,
) -> list[dict]:
    """Walk the Parameters tree and produce manifest items.

    Args:
        parameters: the install config Parameters dict (same input as resources_mirroring())
        cluster_name: cluster name for S3 prefix
        ssm_prefix: SSM parameter prefix (e.g. "/edh/mycluster")
        mirror_s3_sources: D11 flag — include s3:// sources in the manifest
        mirror_gpu_nvidia: D16a — expand NVIDIA GPU driver `latest/` prefixes (default on)
        mirror_gpu_amd: D16a — expand AMD GPU driver `latest/` prefixes (default off; AMD
            offerings are old/rare. Re-enable for a deployed cluster via a manifest-refresh
            re-run with amd=True)
        s3_client: optional boto3 S3 client for GPU prefix listing (defaults to us-east-1)

    Returns:
        List of manifest items ready for JSON serialization + SFN Map input.
    """
    s3_base_prefix = f"{cluster_name}/resources_mirroring"
    items = []

    def _should_skip(url: str) -> bool:
        if url.startswith("s3://") and not mirror_s3_sources:
            return True
        if "%region%" in url or "%os%" in url or "%architecture%" in url:
            return True
        if url.endswith(".git") or url.startswith("git://"):
            return True
        for excluded in MIRROR_EXCLUDE_URLS:
            if url.startswith(excluded):
                return True
        return False

    def _gpu_repoint_kind(config_key: str):
        """GPU driver s3_bucket_path keys are repoint-only (consumer does a raw `aws s3 cp`),
        not downloadable artifacts. Returns 's3_path' | None. s3_bucket_url is intentionally
        NOT handled here -- it is excluded (MIRROR_EXCLUDE_URLS) and left at its original
        value, because the driver scripts no longer read it (cp self-resolves the region)."""
        if "/gpu/gpu_settings/" not in config_key:
            return None
        if config_key.endswith("/s3_bucket_path"):
            return "s3_path"
        return None

    def _url_to_s3_key(url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https"):
            domain = parsed.netloc
            path = parsed.path.lstrip("/")
            key = f"{domain}/{path}" if path else domain
        elif parsed.scheme == "s3":
            bucket = parsed.netloc
            path = parsed.path.lstrip("/")
            key = f"{bucket}/{path}" if path else bucket
        else:
            key = url.replace("://", "/")
        return f"{s3_base_prefix}/{key}"

    def _walk(node, key_path: str):
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = f"{key_path}/{key}" if key_path else key
                if isinstance(value, str) and value.startswith(("http://", "https://", "s3://")):
                    config_key = f"{ssm_prefix}/{child_path}" if ssm_prefix else ""
                    # GPU driver s3_bucket_path: repoint-only (no download). The driver
                    # scripts do a raw `aws s3 cp` on s3_bucket_path (region self-resolves),
                    # so this gets a PLAIN mirror value. Family-gated: only repoint a family
                    # we actually mirror -- a disabled family (e.g. AMD default-off) is left
                    # untouched so BulkSSMWriter keeps the original AWS value and those nodes
                    # still pull from AWS.
                    gpu_kind = _gpu_repoint_kind(config_key)
                    if gpu_kind:
                        fam = "amd" if "/amd/" in config_key else "nvidia"
                        enabled = (fam == "nvidia" and mirror_gpu_nvidia) or (
                            fam == "amd" and mirror_gpu_amd)
                        if not enabled:
                            continue  # leave original; not excluded from BulkSSMWriter
                        items.append({
                            "repoint_only": True,
                            "repoint_kind": gpu_kind,
                            # s3_path target preserves the original path shape (nvidia=bucket
                            # root, amd=.../latest/).
                            "s3_target": _url_to_s3_key(value),
                            "config_key": config_key,
                            "on_error": "fail",
                        })
                        continue
                    if _should_skip(value):
                        continue
                    expected_sha256 = node.get("sha256")
                    s3_key = _url_to_s3_key(value)
                    items.append({
                        "urls": [value],
                        "expected_sha256": expected_sha256,
                        "s3_target": s3_key,
                        "config_key": config_key,
                        "on_error": "fail",
                    })
                else:
                    _walk(value, child_path)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                _walk(item, f"{key_path}[{i}]")

    _walk(parameters, "")
    if mirror_gpu_nvidia or mirror_gpu_amd:
        items.extend(expand_gpu_driver_prefixes(
            cluster_name, nvidia=mirror_gpu_nvidia, amd=mirror_gpu_amd,
            s3_client=s3_client))
    return items


def write_manifest_to_s3(items: list[dict], s3_client, bucket: str, key: str):
    """Serialize and upload the manifest to S3."""
    body = json.dumps(items, indent=2)
    s3_client.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json")
    logger.info(f"Manifest written: s3://{bucket}/{key} ({len(items)} items)")
