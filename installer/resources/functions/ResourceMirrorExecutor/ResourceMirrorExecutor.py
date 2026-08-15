# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource Mirror Executor — per-artifact Lambda invoked by SFN Inline Map.

Processes ONE manifest item: walks urls[] in order, streams to S3 with
server-side SHA256 integrity, records immutable provenance as S3 metadata and
mutable ops state as S3 tags, then rewrites the config key with the
s3|original pipe-string only after checksum verification passes.
"""

import base64
import hashlib
import logging
import os
import time
import urllib.request
import ssl

import boto3

logger = logging.getLogger("ResourceMirrorExecutor")
logger.setLevel(logging.INFO)

MIRROR_BUCKET = os.environ.get("MIRROR_BUCKET", "")
CLUSTER_ID = os.environ.get("CLUSTER_ID", "")
MIRROR_S3_SOURCES = os.environ.get("MIRROR_S3_SOURCES", "true").lower() == "true"
MIRROR_REGION = os.environ.get("MIRROR_REGION", "") or None  # bucket region (D15)
MIRROR_ENGINE = "ResourceMirrorExecutor/1.0"
METADATA_SCHEMA_VERSION = "1"

# S3 does NOT support ChecksumType=FULL_OBJECT with SHA256 on MULTIPART uploads
# (CreateMultipartUpload rejects it -- only CRC gets full-object multipart; SHA256
# multipart is always COMPOSITE). So we cannot make S3's native checksum a whole-object
# SHA256 for large objects. Instead, Option A computes the authoritative whole-object
# SHA256 in-stream (hashlib), independent of S3's checksum behavior.
_UPLOAD_EXTRA_ARGS = {"ChecksumAlgorithm": "SHA256"}


class _HashingReader:
    """File-like wrapper that computes a SHA256 over every byte read. s3transfer reads
    a non-seekable stream sequentially (it cannot parallelize reads from a network/
    StreamingBody source), so the digest is the true whole-object SHA256 even when the
    upload is multipart. This is the authoritative integrity gate, immune to S3's
    multipart COMPOSITE-checksum behavior and independent of the transfer method."""

    def __init__(self, fileobj):
        self._f = fileobj
        self._h = hashlib.sha256()

    def read(self, amt=-1):
        chunk = self._f.read(amt) if amt is not None else self._f.read()
        if chunk:
            self._h.update(chunk)
        return chunk

    def hexdigest(self):
        return self._h.hexdigest()


# Region-explicit S3 client (the mirror bucket may be in a different region than
# this Lambda, D15). Falls back to the Lambda's region if no hint supplied.
s3 = boto3.client("s3", region_name=MIRROR_REGION) if MIRROR_REGION else boto3.client("s3")
ssm = boto3.client("ssm")


def handler(event, context):
    # GPU bucket-path repoint (no download). The driver scripts consume s3_bucket_path
    # via a raw `aws s3 cp --recursive` and let the CLI self-resolve the bucket region
    # (no region-probe HEAD), so this key takes a PLAIN mirror value (NOT the s3|original
    # pipe-string the file-URL consumers parse). The per-object latest/ items (emitted
    # separately) carry the actual bytes. s3_bucket_url is no longer repointed.
    if event.get("repoint_only"):
        ck = event.get("config_key", "")
        if not ck:
            logger.info("REPOINT(prefix): skipped (no config_key)")
            return {"status": "skipped", "reason": "repoint_only without config_key"}
        # Only s3_path is emitted today; default keeps the branch tolerant if reused.
        value = f"s3://{MIRROR_BUCKET}/{event.get('s3_target', '')}"
        ssm.put_parameter(Name=ck, Value=value, Type="String", Overwrite=True)
        logger.info(f"REPOINT(prefix): {ck} -> {value}")
        return {"status": "repointed", "config_key": ck, "value": value}

    # Validate required manifest fields up front (clear error vs opaque KeyError).
    missing = [f for f in ("urls", "s3_target") if not event.get(f)]
    if missing:
        msg = f"Malformed manifest item: missing/empty required field(s) {missing}"
        logger.error(msg)
        raise ValueError(msg)

    urls = event["urls"]
    expected_sha256 = event.get("expected_sha256")
    s3_target = event["s3_target"]
    config_key = event.get("config_key", "")
    on_error = event.get("on_error", "fail")
    trigger_type = event.get("trigger_type", "unknown")
    sfn_execution_id = event.get("sfn_execution_id", "")
    s3_method = event.get("s3_method", "auto")  # D16b: auto|copy|getput
    original_url = urls[0] if urls else ""

    # D4: SHA-skip — object already mirrored. Still (a) ensure the SSM repoint is
    # in place (idempotent, D9 repair) and (b) refresh the LastVerifiedAt tag —
    # both WITHOUT re-downloading or rewriting the object.
    if expected_sha256 and _s3_sha_matches(s3_target, expected_sha256):
        logger.info(f"SKIP (SHA match): s3://{MIRROR_BUCKET}/{s3_target}")
        _repoint(config_key, s3_target, original_url)
        _write_tags(s3_target, trigger_type)
        return {"status": "skipped", "s3_target": s3_target}

    # Walk urls[] in order until one succeeds.
    last_error = None
    for url_idx, url in enumerate(urls):
        attempt = url_idx + 1
        logger.info(f"ATTEMPT [{attempt}/{len(urls)}]: {url} -> {s3_target}")
        t0 = time.time()
        try:
            method, src_etag, src_lastmod, fell_back, computed_sha = _stream_to_s3(url, s3_target, s3_method)
            duration_ms = round((time.time() - t0) * 1000)
            logger.info(f"UPLOADED in {duration_ms}ms via {method}"
                        + (" (copy->getput fallback)" if fell_back else "")
                        + f": s3://{MIRROR_BUCKET}/{s3_target}")

            # Integrity SHA256: prefer the in-stream whole-object hash (Option A);
            # for server-side copies (no local bytes) fall back to the S3-native
            # checksum, which is a whole-object FULL_OBJECT hash for a single copy.
            actual_sha = computed_sha or _get_s3_checksum(s3_target)
            logger.info(f"SHA256 ({'in-stream' if computed_sha else 'S3-native'}): {actual_sha}")

            if expected_sha256 and actual_sha != expected_sha256:
                logger.error(
                    f"SHA256 MISMATCH: expected={expected_sha256} actual={actual_sha}. "
                    f"SSM repoint BLOCKED."
                )
                raise ValueError(
                    f"SHA256 mismatch: expected {expected_sha256}, got {actual_sha}"
                )

            # Immutable provenance -> S3 metadata; mutable ops state -> S3 tags.
            _store_provenance(
                s3_target, url, method, duration_ms, attempt, src_etag,
                src_lastmod, sfn_execution_id, actual_sha, fell_back,
            )
            _write_tags(s3_target, trigger_type)

            # D5: SSM repoint — only after integrity verified.
            _repoint(config_key, s3_target, original_url)

            return {"status": "mirrored", "s3_target": s3_target, "source": url,
                    "sha256": actual_sha, "duration_ms": duration_ms,
                    "transfer_method": method, "attempt_count": attempt,
                    "copy_fallback": fell_back}

        except Exception as e:
            last_error = str(e)
            logger.warning(f"FAILED url={url}: {last_error}")
            continue

    msg = f"All URLs failed for {s3_target}: {last_error}"
    # Model C: this executor is the SOLE writer of config_key (excluded from
    # BulkSSMWriter). On a soft-mode failure we MUST still write the key — to the
    # original URL — so the consumer keeps an internet fallback instead of an
    # absent key. (Hard mode raises -> stack rollback, so no key is ever orphaned.)
    if on_error in ("skip", "warn") and config_key and original_url:
        ssm.put_parameter(Name=config_key, Value=original_url, Type="String", Overwrite=True)
        logger.warning(f"REPOINT(original-fallback): {config_key} -> {original_url}")
    if on_error == "skip":
        logger.warning(f"SKIP (on_error=skip): {msg}")
        return {"status": "skipped_error", "s3_target": s3_target, "error": msg}
    elif on_error == "warn":
        logger.warning(f"WARN: {msg}")
        return {"status": "warn", "s3_target": s3_target, "error": msg}
    else:
        logger.error(f"FATAL: {msg}")
        raise RuntimeError(msg)


def _s3_sha_matches(key: str, expected_sha256: str) -> bool:
    """Check if the mirrored object already matches expected_sha256. Prefers the
    stored content_sha256 metadata (authoritative whole-object hash -- correct even
    for multipart objects). Falls back to the S3-native checksum, which is only the
    true file hash for single-part/FULL_OBJECT objects (multipart COMPOSITE will not
    match -- a legacy object would then be re-mirrored, which is safe)."""
    try:
        head = s3.head_object(Bucket=MIRROR_BUCKET, Key=key)
        stored_meta = (head.get("Metadata") or {}).get("content_sha256", "")
        if stored_meta:
            return stored_meta == expected_sha256
        resp = s3.get_object_attributes(
            Bucket=MIRROR_BUCKET, Key=key, ObjectAttributes=["Checksum"],
        )
        stored = resp.get("Checksum", {}).get("ChecksumSHA256", "")
        stored_hex = base64.b64decode(stored).hex() if stored else ""
        return stored_hex == expected_sha256
    except Exception:
        return False


def _get_s3_checksum(key: str) -> str:
    """Retrieve the S3-native SHA256 checksum (base64 -> hex)."""
    resp = s3.get_object_attributes(
        Bucket=MIRROR_BUCKET, Key=key, ObjectAttributes=["Checksum"],
    )
    b64 = resp.get("Checksum", {}).get("ChecksumSHA256", "")
    if not b64:
        raise RuntimeError(f"No ChecksumSHA256 on s3://{MIRROR_BUCKET}/{key}")
    return base64.b64decode(b64).hex()


def _stream_to_s3(url: str, s3_key: str, s3_method: str = "auto"):
    """Stream URL to S3 with server-side SHA256. Returns (method, src_etag, src_last_modified, fell_back)."""
    if url.startswith("s3://"):
        if not MIRROR_S3_SOURCES:
            raise ValueError(f"S3 source mirroring disabled, skipping {url}")
        return _copy_s3_to_s3(url, s3_key, s3_method)

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "EDH-ResourceMirror/2.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        src_etag = (resp.headers.get("ETag") or "").strip('"')
        src_lastmod = resp.headers.get("Last-Modified") or ""
        hashing = _HashingReader(resp)  # Option A: whole-object SHA256 in-stream
        s3.upload_fileobj(
            hashing, MIRROR_BUCKET, s3_key, ExtraArgs=_UPLOAD_EXTRA_ARGS,
        )
    return ("http-stream", src_etag, src_lastmod, False, hashing.hexdigest())


def _copy_s3_to_s3(source_uri: str, dest_key: str, s3_method: str = "auto"):
    """Copy from remote S3 bucket into mirror bucket. Returns (method, src_etag, src_last_modified, fell_back).

    s3_method (D16b): 'auto' (default) tries server-side CopyObject then falls back to
    streaming GET->PUT on any failure; 'copy' forces CopyObject (no fallback); 'getput'
    forces streaming GET->PUT (skips the wasted copy attempt for KNOWN copy-restricted
    buckets — EULA-gated AWS driver buckets like ec2-linux-nvidia-drivers grant
    GetObject/download but DENY server-side copy). GET->PUT is how AWS docs fetch these
    (`aws s3 cp`). `fell_back`=True only when an auto copy was attempted and failed."""
    parts = source_uri.replace("s3://", "").split("/", 1)
    src_bucket, src_key = parts[0], parts[1] if len(parts) > 1 else ""
    src_etag, src_lastmod = "", ""
    try:  # source headers are best-effort
        h = s3.head_object(Bucket=src_bucket, Key=src_key)
        src_etag = (h.get("ETag") or "").strip('"')
        lm = h.get("LastModified")
        src_lastmod = lm.strftime("%Y-%m-%dT%H:%M:%SZ") if lm else ""
    except Exception as e:
        logger.warning(f"Could not head S3 source {source_uri}: {e}")

    def _getput():
        body = s3.get_object(Bucket=src_bucket, Key=src_key)["Body"]
        hashing = _HashingReader(body)  # Option A: whole-object SHA256 in-stream
        s3.upload_fileobj(hashing, MIRROR_BUCKET, dest_key,
                          ExtraArgs=_UPLOAD_EXTRA_ARGS)
        return hashing.hexdigest()

    if s3_method == "getput":  # forced, not a fallback
        computed_sha = _getput()
        return ("s3-getput", src_etag, src_lastmod, False, computed_sha)

    try:
        s3.copy_object(
            Bucket=MIRROR_BUCKET, Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": src_key},
            ChecksumAlgorithm="SHA256",
        )
        # Server-side copy: bytes never transit the Lambda, so no in-stream hash.
        # A single CopyObject (<5GB) yields a FULL_OBJECT S3 checksum, so the native
        # checksum IS the whole-object SHA256 -> handler falls back to it for copies.
        return ("s3-copy", src_etag, src_lastmod, False, None)
    except Exception as e:
        if s3_method == "copy":  # forced copy, no fallback
            raise
        logger.warning(f"CopyObject denied/failed for {source_uri} ({e}); "
                       f"falling back to streaming GET->PUT")
        computed_sha = _getput()
        return ("s3-getput", src_etag, src_lastmod, True, computed_sha)


def _repoint(config_key: str, s3_target: str, original_url: str):
    """Write the s3|original pipe-string to the config key (idempotent). No-op if
    no config_key. Called on both fresh-mirror and SHA-skip paths so a re-run can
    repair a missing/purged SSM key without re-downloading (D9)."""
    if not config_key:
        logger.info("REPOINT: skipped (no config_key)")
        return
    pipe_value = f"s3://{MIRROR_BUCKET}/{s3_target}|{original_url}"
    ssm.put_parameter(Name=config_key, Value=pipe_value, Type="String", Overwrite=True)
    logger.info(f"REPOINT: {config_key} -> {pipe_value}")


def _store_provenance(key, source_url, method, duration_ms, attempt, src_etag,
                      src_lastmod, sfn_execution_id, content_sha256, fell_back=False):
    """Immutable provenance as S3 user metadata (set once at upload via self-copy).
    content_sha256 is the authoritative whole-object SHA256 (in-stream for http/getput,
    S3-native for copy) -- the skip-path reads it so multipart objects match on re-run."""
    meta = {
        "metadata_schema_version": METADATA_SCHEMA_VERSION,
        "source_url": source_url,
        "transfer_method": method,
        "copy_fallback": "true" if fell_back else "false",
        "content_sha256": content_sha256 or "",
        "source_etag": src_etag,
        "source_last_modified": src_lastmod,
        "mirrored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "download_duration_ms": str(duration_ms),
        "attempt_count": str(attempt),
        "sfn_execution_id": sfn_execution_id,
        "mirror_engine": MIRROR_ENGINE,
    }
    s3.copy_object(
        Bucket=MIRROR_BUCKET, Key=key,
        CopySource={"Bucket": MIRROR_BUCKET, "Key": key},
        Metadata=meta, MetadataDirective="REPLACE",
        ChecksumAlgorithm="SHA256",
    )


def _write_tags(key, trigger_type):
    """Mutable ops state as S3 object tags — updatable via PutObjectTagging with
    NO object rewrite. LastVerifiedAt refreshes on every mirror AND skip."""
    s3.put_object_tagging(
        Bucket=MIRROR_BUCKET, Key=key,
        Tagging={"TagSet": [
            {"Key": "edh:TriggerType", "Value": trigger_type or "unknown"},
            {"Key": "edh:ClusterId", "Value": CLUSTER_ID or "unknown"},
            {"Key": "edh:LastVerifiedAt",
             "Value": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        ]},
    )
    logger.info(f"TAGS: {key} trigger={trigger_type} verified=now")
