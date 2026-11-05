# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
One safe spelling of a scheduler job id, for the places a raw job id cannot go.

A PBS array parent's job id is "4[]" and its subjobs "4[1]". The brackets are
legal in PBS but rejected by AWS tag values, EC2 launch template names and S3
prefixes. The same value is written as the edh:JobId tag, the compute_node pin,
the node's registered compute_node resource and the bootstrap log folder, so
all four must use this one spelling. Anything already safe passes through
unchanged.
"""

from __future__ import annotations

import re

from utils.cast import SocaCastEngine
from utils.response import SocaResponse

# Characters kept as-is. Anything else is DROPPED, not substituted.
#
# Deletion matches what EDH already does to the CloudFormation stack name in
# provision_capacity:
#
#     stack_name = re.sub(r"[^A-Za-z0-9-]", "", stack_name)
#
# so array parent "6[]" yields a stack name ending "-job-6-openpbs-default",
# and using the same rule here keeps the tag and the stack name in agreement.
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_-]")

# A PBS subjob id: parent number, then the index in brackets ("6[7]").
_SUBJOB_ID = re.compile(r"^(?P<parent>\d+)\[(?P<index>\d+)\]$")


def _as_int(value) -> int | None:
    """Cast to int, or None when the value is not a number."""
    _cast = SocaCastEngine(data=value).cast_as(int)
    if _cast.success:
        return _cast.message
    return None


def capacity_key(job_id) -> SocaResponse:
    """
    Return `job_id` in the one spelling that every capacity-correlation site
    accepts, as the message of a successful SocaResponse.

    Examples:
        "6"                   -> "6"      (unchanged)
        "alwayson-<uuid4>"    -> unchanged
        "6[]"                 -> "6"      (array parent)
        "6[7]"                -> "6-7"    (subjob)

    An array PARENT collapses to its bare job number, and that is unambiguous
    rather than lossy: PBS issues job numbers from ONE sequence shared by arrays
    and ordinary jobs, so a given number is either an array or a plain job and
    never both.

    A SUBJOB keeps its index behind a hyphen rather than losing it. Deleting the
    brackets there WOULD collide: "6[1]" would become "61", which is a different
    valid job number. "6-1" cannot collide with any plain job id, because those
    are all digits. Nothing provisions per subjob today, but the id reaches this
    helper from paths that may, so the safe spelling is defined now.

    An empty or None job id yields "" -- callers already treat a missing job id
    as an error, and inventing a placeholder here would hide it. There is no
    failure mode, so the response is always successful.
    """
    if job_id is None:
        return SocaResponse(success=True, message="")

    _job_id = str(job_id)

    _subjob = _SUBJOB_ID.match(_job_id)
    if _subjob:
        return SocaResponse(
            success=True,
            message=f"{_subjob.group('parent')}-{_subjob.group('index')}",
        )

    return SocaResponse(success=True, message=_UNSAFE_CHARS.sub("", _job_id))


def is_array_parent_job_id(job_id) -> SocaResponse:
    """
    Message is True when `job_id` is a PBS array PARENT ("4[]"), not a subjob
    ("4[7]").

    Read the `array` attribute off the job when you have it; this is for the
    paths that only carry an id.
    """
    return SocaResponse(
        success=True, message=str(job_id or "").endswith("[]")
    )


# One index range as the scheduler spells it: "1-100", "0-999:10", or a bare "7".
_INDEX_RANGE = re.compile(
    r"^\s*(?P<start>\d+)\s*(?:-\s*(?P<end>\d+)\s*(?::\s*(?P<step>\d+)\s*)?)?$"
)


def count_array_indices(array_indices: str) -> SocaResponse:
    """
    Number of subjobs an index specification yields, as the message.

    This is the figure capacity must be sized against. The scheduler reports a
    job array's resource request per SUBJOB, so the parent's nodes/cpus describe
    one execution and say nothing about how many there are.

    Accepts what PBS accepts in `array_indices_submitted`:

        "1-100"     -> 100
        "0-999:10"  -> 100   (0,10,...,990 -- step, not contiguous)
        "7"         -> 1     (single index)
        "1-4,9-10"  -> 6     (comma-separated list of ranges)
        "-"         -> 0     (PBS's "nothing remaining" sentinel)

    The message is 0 for anything unparseable rather than a guess, so a caller
    that cannot determine the size refuses to provision instead of provisioning
    a wrong amount. The response itself is always successful: an unparseable
    specification is a valid answer of 0, not a failure to compute one.
    """
    if not array_indices:
        return SocaResponse(success=True, message=0)

    _total = 0
    for _part in str(array_indices).split(","):
        _part = _part.strip()
        if not _part or _part == "-":
            continue
        _match = _INDEX_RANGE.match(_part)
        if not _match:
            # An unrecognized spelling. Refuse the whole specification rather
            # than returning a partial count that looks authoritative.
            return SocaResponse(success=True, message=0)
        _start = _as_int(_match.group("start"))
        if _start is None:
            return SocaResponse(success=True, message=0)
        _end = _match.group("end")
        if _end is None:
            _total += 1
            continue
        _end = _as_int(_end)
        if _end is None or _end < _start:
            return SocaResponse(success=True, message=0)
        _step = _as_int(_match.group("step") or 1)
        if _step is None or _step < 1:
            return SocaResponse(success=True, message=0)
        _total += ((_end - _start) // _step) + 1

    return SocaResponse(success=True, message=_total)


def parse_array_state_count(state_count: str) -> SocaResponse:
    """
    A scheduler array state tally as lowercased name -> int, in the message.

        "Queued:4 Running:12 Exiting:0 Expired:0"
        -> {"queued": 4, "running": 12, "exiting": 0, "expired": 0}

    Unparseable fragments are skipped rather than failing the whole read: this
    tally is advisory (it refines a reap decision) and a scheduler that adds a
    new state name must not break job parsing. An empty tally yields a
    successful response carrying an empty dict.
    """
    _counts = {}
    if not state_count:
        return SocaResponse(success=True, message=_counts)
    for _token in str(state_count).split():
        if ":" not in _token:
            continue
        _name, _, _value = _token.partition(":")
        _name = _name.strip().lower()
        _value = _value.strip()
        if not _name or not _value.isdigit():
            continue
        _parsed = _as_int(_value)
        if _parsed is None:
            continue
        _counts[_name] = _parsed
    return SocaResponse(success=True, message=_counts)
