# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""S3 path/URI string helpers.

This module is intentionally narrow. It contains string-shape utilities
for S3 keys, prefixes, and ``s3://`` URIs -- it does NOT call boto3.

Why a dedicated module?
-----------------------
S3 keys are matched exactly. ``"prefix/"`` and ``"prefix"`` are
different keys; ``"prefix/file"`` and ``"prefix//file"`` are different
keys; HeadObject on the wrong one returns a 404 even when the "right"
one exists. Hand-built path concatenations (f-strings, ``+``, Jinja2
``${var}/file``) routinely produce the wrong shape when one side
disagrees with the other on whether trailing slashes are present.

Use ``s3_join(...)`` whenever you build an S3 path/URI string from two
or more pieces. It normalizes both inputs and outputs the same way:

* No trailing slash on the result.
* No double slashes anywhere.
* ``s3://`` scheme preserved if the first part begins with ``s3:``.

Convention for any string returned from this codebase that represents
an S3 path or URI: NO trailing slash. Callers that need a trailing
slash (e.g. ``Boto3 ListObjectsV2(Prefix=...)``) add it at the call
site, locally.

Companion regression tests live in
``tests/bootstrap_cache/test_s3_helper.py``.
"""

from __future__ import annotations


def s3_join(*parts: str) -> str:
    """Join S3 path/URI segments with exactly one ``/`` between each.

    Idempotent on trailing/leading slashes -- callers don't need to
    sanitize their inputs first. Empty/None parts are skipped.
    Returns ``""`` when no non-empty parts are given.

    The first part is allowed to begin with ``s3://`` (or ``s3:/`` /
    ``s3:`` after stripping). The scheme is preserved on the way out.

    Examples
    --------
    >>> s3_join("s3://bucket", "prefix", "file.ps1")
    's3://bucket/prefix/file.ps1'
    >>> s3_join("s3://bucket/prefix/", "/file.ps1")
    's3://bucket/prefix/file.ps1'
    >>> s3_join("prefix/", "/sub/", "/file.sh")
    'prefix/sub/file.sh'
    >>> s3_join("only-one")
    'only-one'
    >>> s3_join("", "", "")
    ''
    >>> s3_join("s3://bucket")
    's3://bucket'
    """
    cleaned: list[str] = []
    for raw in parts:
        if not raw:
            continue
        # Strip both leading and trailing slashes so neither side of
        # any concatenation can introduce a double slash.
        stripped = raw.strip("/")
        if not stripped:
            continue
        cleaned.append(stripped)

    if not cleaned:
        return ""

    head, *tail = cleaned
    # Re-prepend the s3:// scheme if the first part started with one.
    # (After strip("/"), "s3://bucket" becomes "s3:bucket" -- restore.)
    if head.startswith("s3:") and not head.startswith("s3://"):
        head = f"s3://{head[3:]}"

    return f"{head}/{'/'.join(tail)}" if tail else head
