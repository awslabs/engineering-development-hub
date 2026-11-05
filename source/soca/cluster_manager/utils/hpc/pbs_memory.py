# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
PBS memory sizes, normalized to MiB.

PBS expresses a memory size as a number with an optional unit suffix ("6gb",
"512mb", "16086124kb"), and a bare number means BYTES. Everything inside EDH
works in MiB, which is also the unit describe_instance_types reports
(MemoryInfo.SizeInMiB).

PBS's units are BINARY: "kb" is 1024 bytes, not 1000.
"""

from __future__ import annotations

import logging
import re

from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

# Multiplier to MiB for each suffix PBS accepts. PBS also accepts the
# single-letter forms (k, m, g, t) and treats a bare number as bytes.
_SUFFIX_TO_MIB = {
    "b": 1.0 / (1024 * 1024),
    "kb": 1.0 / 1024,
    "k": 1.0 / 1024,
    "mb": 1.0,
    "m": 1.0,
    "gb": 1024.0,
    "g": 1024.0,
    "tb": 1024.0 * 1024,
    "t": 1024.0 * 1024,
    "pb": 1024.0 * 1024 * 1024,
    "p": 1024.0 * 1024 * 1024,
}

# A PBS size: digits, optional decimal part, optional unit. Case-insensitive.
_SIZE = re.compile(r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<suffix>[a-zA-Z]*)\s*$")


def _cast_as(value, expected_type):
    """Cast `value`, or None when it will not convert."""
    _cast = SocaCastEngine(data=value).cast_as(expected_type)
    if _cast.success:
        return _cast.message
    return None


def _parse_to_mib(value) -> int | None:
    """
    Whole MiB, or None when `value` cannot be read.

    None rather than 0 for unreadable input, because 0 would read as "no memory
    needed" and silently pass a validation this value is meant to feed.

    A bare number genuinely is bytes in PBS, so a small one legitimately rounds
    to 0 MiB. That is not an error and is returned as 0.
    """
    if value is None:
        return None

    # An int/float arriving here is already MiB: it came from our own model,
    # not from the scheduler's string form.
    if Validators.is_bool(value):
        return None
    if Validators.is_int(value) or Validators.is_float(value):
        if value < 0:
            return None
        return _cast_as(value, int)

    _match = _SIZE.match(str(value))
    if not _match:
        logger.warning(f"Unable to parse PBS memory size {value!r}")
        return None

    _number = _cast_as(_match.group("value"), float)
    if _number is None:
        logger.warning(f"Unable to parse PBS memory size {value!r}")
        return None

    _suffix = (_match.group("suffix") or "b").lower()

    _multiplier = _SUFFIX_TO_MIB.get(_suffix)
    if _multiplier is None:
        logger.warning(
            f"Unknown PBS memory unit {_suffix!r} in {value!r}; "
            f"accepted units: {sorted(_SUFFIX_TO_MIB)}"
        )
        return None

    return _cast_as(_number * _multiplier, int)


def parse_pbs_memory_to_mib(value) -> SocaResponse:
    """
    `value` as whole MiB, in the message.

    Examples:
        "6gb"        -> 6144
        "512mb"      -> 512
        "16086124kb" -> 15709
        "2048"       -> 0      (bare number is BYTES, so 2048 B rounds to 0 MiB)
        "1.5gb"      -> 1536
        6144         -> 6144   (an int is already MiB, from our own model)

    A size that cannot be read yields a failed response rather than 0, because 0
    would read as "no memory needed" and silently pass a validation this value is
    meant to feed. A caller that gets a failure must say it could not read the
    request.
    """
    _mib = _parse_to_mib(value)
    if _mib is None:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to read {value!r} as a PBS memory size"
        )
    return SocaResponse(success=True, message=_mib)


def format_mib_as_pbs(mib) -> SocaResponse:
    """
    Whole MiB as a PBS size string ("6144mb"), in the message.

    Always emits mb rather than converting to gb: PBS accepts it, and an exact
    integer MiB avoids a rounding step that could request slightly more memory
    than the caller computed.

    A size that cannot be read yields a failed response, so a caller cannot
    interpolate an empty string into a resource request.
    """
    _mib = _parse_to_mib(mib)
    if _mib is None:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to read {mib!r} as a PBS memory size"
        )
    return SocaResponse(success=True, message=f"{_mib}mb")
