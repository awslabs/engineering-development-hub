# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Optional S3-bucket picker for the interactive installer (V1294129659).

Backs the '?' affordance at the "enter an S3 bucket" prompt: list the buckets
the account owns and let the user search-and-select instead of typing a name
from memory. Opt-in only -- the plain free-text entry is unchanged and stays
the default path, so accounts with many buckets are never forced to build a
list.

`list_buckets` returns only buckets the account owns (exactly the valid set the
installer needs) and, since the 2024 API update, each bucket's region directly
in the response -- so region display costs no per-bucket get_bucket_location
calls and pagination is native via ContinuationToken.

`order_buckets_for_picker` is pure (stdlib only) and unit-tested; the questionary
import is deferred into `build_bucket_choices` so the ordering logic imports
without the TUI dependencies.
"""

from typing import Any, List, Optional

_UNKNOWN_REGION = "unknown"


def list_owned_buckets(s3_client) -> List[dict]:
    """Return ``[{"Name", "BucketRegion"}]`` for every bucket the account owns,
    following ContinuationToken pagination. ``BucketRegion`` is populated
    directly by list_buckets; falls back to ``""`` when absent (older API)."""
    _buckets: List[dict] = []
    _token: Optional[str] = None
    while True:
        _kwargs: dict[str, Any] = {"MaxBuckets": 1000}
        if _token:
            _kwargs["ContinuationToken"] = _token
        _resp = s3_client.list_buckets(**_kwargs)
        for _b in _resp.get("Buckets", []):
            _buckets.append(
                {
                    "Name": _b.get("Name", ""),
                    "BucketRegion": _b.get("BucketRegion", ""),
                }
            )
        _token = _resp.get("ContinuationToken")
        if not _token:
            break
    return _buckets


def order_buckets_for_picker(
    buckets: List[dict], install_region: str
) -> List[dict]:
    """Pure ordering for the picker. Returns a flat list of row dicts:

        {"kind": "separator", "region": <label>}
        {"kind": "bucket", "name": <name>, "region": <label>}

    Group order: ``install_region`` first, then the remaining regions
    alphabetically, then a trailing group for buckets with no region. Names are
    alpha-sorted within each group. Empty/nameless input is skipped; empty
    overall yields an empty list."""
    _by_region: dict[str, List[str]] = {}
    for _b in buckets:
        _name = (_b.get("Name") or "").strip()
        if not _name:
            continue
        _region = (_b.get("BucketRegion") or "").strip() or _UNKNOWN_REGION
        _by_region.setdefault(_region, []).append(_name)

    _install = (install_region or "").strip()
    _ordered_regions: List[str] = []
    if _install and _install in _by_region:
        _ordered_regions.append(_install)
    _ordered_regions.extend(
        sorted(r for r in _by_region if r not in (_install, _UNKNOWN_REGION))
    )
    if _UNKNOWN_REGION in _by_region:
        _ordered_regions.append(_UNKNOWN_REGION)

    _rows: List[dict] = []
    for _region in _ordered_regions:
        _rows.append({"kind": "separator", "region": _region})
        for _name in sorted(_by_region[_region]):
            _rows.append({"kind": "bucket", "name": _name, "region": _region})
    return _rows


def build_bucket_choices(buckets: List[dict], install_region: str) -> list:
    """Convert ordered rows into questionary Choice/Separator entries. The
    questionary import is deferred so ``order_buckets_for_picker`` stays
    importable without the TUI dependencies (unit tests)."""
    from questionary import Choice, Separator

    _choices: list = []
    for _row in order_buckets_for_picker(buckets, install_region):
        if _row["kind"] == "separator":
            _choices.append(Separator(f"\u2500\u2500 {_row['region']} \u2500\u2500"))
        else:
            _choices.append(
                Choice(
                    title=f"{_row['name']}   [{_row['region']}]",
                    value=_row["name"],
                )
            )
    return _choices
