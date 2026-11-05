# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resolve the root EBS volume (size, type, IOPS, throughput) for a VDI launch.

Every VDI launch path (on-demand launch, saved-desktop resume, pool launch
spec) calls resolve_vdi_root_volume() so there
is one source of truth for the root volume defaults and one place that knows
the per-type EBS limits.

Precedence for each field:

    requested value (the launch form, or the saved AMI's root device)
        then the cluster default under /configuration/dcv/root_volume/
        then the literal floor in _FALLBACK

A per-stack or per-project override slots in between the first two steps
when one exists; nothing supplies it today.

Per-type rules (AWS EBS limits):

    gp2  size only. EBS rejects Iops and Throughput for gp2, so they are
         dropped.
    gp3  IOPS 3000..80000 and at most 500 per GiB (3000 is always allowed).
         Throughput 125..2000 MiB/s and at most 0.25 MiB/s per IOPS.
         First-generation AWS Outposts racks support gp2 only;
         second-generation racks support gp3 up to 16 TiB, 16000 IOPS and
         1000 MiB/s. Those lower limits are not applied here.
    io1  IOPS required, 100..64000 and at most 50 per GiB.
    io2  IOPS required, 100..256000 and at most 1000 per GiB.

An IOPS or throughput value of 0 means "use the default for the volume
type", which is how io1/io2 get a generated IOPS value without the operator
having to pick one. A configured value outside what the volume type and size
allow is clamped (and logged) rather than failing the launch, because the
same cluster default has to work across every disk size a user can pick.
A requested SIZE outside the type's limits is an error: that is a bad
request, not a default that needs adjusting.
"""

import logging
import math
from dataclasses import dataclass
from typing import Any, Dict, Optional

from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

KEY_PREFIX = "/configuration/dcv/root_volume"

# Used when a key is missing or unreadable, so a launch can never be built
# with an empty or zero-sized volume.
_FALLBACK: Dict[str, Any] = {
    "default_size_linux": 100,
    "default_size_windows": 100,
    "min_size_linux": 100,
    "min_size_windows": 100,
    "volume_type": "gp3",
    "iops": 0,
    "throughput": 0,
}

# Sizes in GiB, IOPS, throughput in MiB/s.
_LIMITS: Dict[str, Dict[str, Any]] = {
    "gp2": {"min_size": 1, "max_size": 16384},
    "gp3": {
        "min_size": 1,
        "max_size": 65536,
        "min_iops": 3000,
        "max_iops": 80000,
        "iops_per_gib": 500,
        "default_iops": 3000,
        "min_throughput": 125,
        "max_throughput": 2000,
        "throughput_per_iops": 0.25,
        "default_throughput": 125,
    },
    "io1": {
        "min_size": 4,
        "max_size": 16384,
        "min_iops": 100,
        "max_iops": 64000,
        "iops_per_gib": 50,
        "default_iops": 3000,
    },
    "io2": {
        "min_size": 4,
        "max_size": 65536,
        "min_iops": 100,
        "max_iops": 256000,
        "iops_per_gib": 1000,
        "default_iops": 3000,
    },
}

SUPPORTED_VOLUME_TYPES = tuple(_LIMITS.keys())


@dataclass(frozen=True)
class RootVolume:
    size: int
    volume_type: str
    iops: Optional[int]
    throughput: Optional[int]

    def as_launch_parameters(self) -> Dict[str, Any]:
        """Keys consumed by dcv_cloudformation_builder and create_capacity_dry_run."""
        return {
            "disk_size": self.size,
            "volume_type": self.volume_type,
            "volume_iops": self.iops,
            "volume_throughput": self.throughput,
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "size": self.size,
            "volume_type": self.volume_type,
            "iops": self.iops,
            "throughput": self.throughput,
        }


def _is_windows(base_os: Optional[str]) -> bool:
    return "windows" in str(base_os or "").lower()


def _as_int(value: Any, field: str) -> SocaResponse:
    """SocaResponse(message=int) for a setting or request value.

    The string form is cast because cast_as(int) passes a bool through as-is
    (bool is an int subclass) and truncates a float, so True and 12.5 would
    otherwise be accepted.
    """
    _cast = SocaCastEngine(str(value).strip()).cast_as(int)
    if not _cast.success:
        return SocaError.GENERIC_ERROR(helper=f"{field} must be an integer, got {value!r}")
    return _cast


def _int_or_zero(value: Any, field: str) -> int:
    """An optional size: empty or unreadable counts as not set (0)."""
    if value is None or str(value).strip() == "":
        return 0
    _cast = _as_int(value, field)
    return _cast.message if _cast.success else 0


def load_root_volume_settings(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read the /configuration/dcv/root_volume/* keys.

    `params` is the SocaConfig("/") dump most launch paths already hold; when it
    is not supplied each key is read individually. A missing key falls back to
    _FALLBACK so a cluster without the keys still launches.
    """
    _settings: Dict[str, Any] = {}
    for _name, _default in _FALLBACK.items():
        _key = f"{KEY_PREFIX}/{_name}"
        if params is not None:
            _value = params.get(_key)
        else:
            _resp = SocaConfig(key=_key).get_value(default=None, allow_unknown_key=True)
            _value = _resp.message if _resp.success else None
        if _value is None or str(_value).strip() == "":
            _value = _default
        _settings[_name] = _value
    return _settings


def _resolve_iops(volume_type: str, size: int, configured: int) -> Optional[int]:
    _limits = _LIMITS[volume_type]
    if "min_iops" not in _limits:
        return None
    _wanted = configured if configured > 0 else _limits["default_iops"]
    # gp3 always allows its 3000 baseline regardless of size; the provisioned
    # types scale strictly with size.
    _size_cap = size * _limits["iops_per_gib"]
    if volume_type == "gp3":
        _size_cap = max(_size_cap, _limits["min_iops"])
    _upper = min(_limits["max_iops"], _size_cap)
    _lower = min(_limits["min_iops"], _upper)
    _resolved = max(_lower, min(_wanted, _upper))
    if _resolved != _wanted:
        logger.warning(
            f"Root volume IOPS {_wanted} is outside {_lower}..{_upper} for a "
            f"{size} GiB {volume_type} volume, using {_resolved}"
        )
    return _resolved


def _resolve_throughput(volume_type: str, iops: Optional[int], configured: int) -> Optional[int]:
    _limits = _LIMITS[volume_type]
    if "min_throughput" not in _limits or iops is None:
        return None
    _wanted = configured if configured > 0 else _limits["default_throughput"]
    _upper = max(
        _limits["min_throughput"],
        min(_limits["max_throughput"], math.floor(iops * _limits["throughput_per_iops"])),
    )
    _resolved = max(_limits["min_throughput"], min(_wanted, _upper))
    if _resolved != _wanted:
        logger.warning(
            f"Root volume throughput {_wanted} MiB/s is outside "
            f"{_limits['min_throughput']}..{_upper} for {iops} IOPS on "
            f"{volume_type}, using {_resolved}"
        )
    return _resolved


def ami_root_snapshot_size(image: Optional[Dict[str, Any]]) -> SocaResponse:
    """SocaResponse(message=GiB or None): root snapshot size of one describe_images() entry.

    EBS rejects a root volume smaller than the AMI's root snapshot, so this is
    the floor for any launch from that AMI. The message is None when it cannot
    be determined, which leaves the launch without an AMI floor.
    """
    _size = None
    if image:
        _root_device = image.get("RootDeviceName")
        for _mapping in image.get("BlockDeviceMappings") or []:
            if _mapping.get("DeviceName") == _root_device:
                _size = _int_or_zero(
                    (_mapping.get("Ebs") or {}).get("VolumeSize"), "AMI root VolumeSize"
                ) or None
                break
    return SocaResponse(success=True, message=_size)


def effective_min_size(
    base_os: Optional[str],
    stack_min: Any = None,
    ami_min: Any = None,
    params: Optional[Dict[str, Any]] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> SocaResponse:
    """SocaResponse(message=GiB): smallest root size allowed for a launch.

    The software stack's own minimum when it is above 0; at 0 the stack uses
    the per-OS cluster minimum (/configuration/dcv/root_volume/min_size_*).
    The AMI root snapshot size is always a floor on top of either.
    """
    if settings is None:
        settings = load_root_volume_settings(params=params)
    _stack_min = _int_or_zero(stack_min, "software stack root size")
    if _stack_min <= 0:
        _key = "min_size_windows" if _is_windows(base_os) else "min_size_linux"
        _cluster_min = _as_int(settings.get(_key), f"{KEY_PREFIX}/{_key}")
        _stack_min = _cluster_min.message if _cluster_min.success else _FALLBACK[_key]
    _ami_min = _int_or_zero(ami_min, "AMI root snapshot size")
    return SocaResponse(success=True, message=max(_stack_min, _ami_min))


def root_size_defaults(
    params: Optional[Dict[str, Any]] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> SocaResponse:
    """Per-OS cluster default and minimum root sizes shown in the WebUI.

    SocaResponse(message={"linux", "windows", "min_linux", "min_windows"}), or
    an error naming the first key that is not an integer.
    """
    if settings is None:
        settings = load_root_volume_settings(params=params)
    _defaults: Dict[str, int] = {}
    for _name, _key in (
        ("linux", "default_size_linux"),
        ("windows", "default_size_windows"),
        ("min_linux", "min_size_linux"),
        ("min_windows", "min_size_windows"),
    ):
        _cast = _as_int(settings.get(_key), f"{KEY_PREFIX}/{_key}")
        if not _cast.success:
            return _cast
        _defaults[_name] = _cast.message
    return SocaResponse(success=True, message=_defaults)


def resolve_vdi_root_volume(
    base_os: Optional[str],
    requested_size: Any = None,
    params: Optional[Dict[str, Any]] = None,
    settings: Optional[Dict[str, Any]] = None,
    min_size: Optional[int] = None,
) -> SocaResponse:
    """Return SocaResponse(message=RootVolume) or an error SocaResponse.

    `requested_size` is what the caller asked for (form value, saved AMI root
    size); None or "" means "use the cluster default for this OS".
    `min_size` is the smallest size allowed for this launch, normally from
    effective_min_size().message (stack minimum, or the cluster minimum when the stack
    is 0, and the AMI root snapshot size). A default below it
    is raised to it; an explicit request below it is rejected.
    `settings` bypasses config reads entirely and exists for tests.
    """
    if settings is None:
        settings = load_root_volume_settings(params=params)

    _volume_type = str(settings.get("volume_type") or _FALLBACK["volume_type"]).strip().lower()
    if _volume_type not in _LIMITS:
        return SocaError.GENERIC_ERROR(
            helper=f"{KEY_PREFIX}/volume_type is {_volume_type!r}; supported types are "
            f"{', '.join(SUPPORTED_VOLUME_TYPES)}"
        )
    _limits = _LIMITS[_volume_type]

    _use_default = requested_size is None or str(requested_size).strip() == ""
    if _use_default:
        _size_key = "default_size_windows" if _is_windows(base_os) else "default_size_linux"
        _size_resp = _as_int(settings.get(_size_key), f"{KEY_PREFIX}/{_size_key}")
    else:
        _size_resp = _as_int(requested_size, "disk_size")
    _iops_resp = _as_int(settings.get("iops") or 0, f"{KEY_PREFIX}/iops")
    _throughput_resp = _as_int(settings.get("throughput") or 0, f"{KEY_PREFIX}/throughput")
    for _resp in (_size_resp, _iops_resp, _throughput_resp):
        if not _resp.success:
            return _resp
    _size = _size_resp.message
    _configured_iops = _iops_resp.message
    _configured_throughput = _throughput_resp.message

    _min = _int_or_zero(min_size, "min_size")
    if _min and _size < _min:
        if not _use_default:
            return SocaError.GENERIC_ERROR(
                helper=f"Root volume size {_size} GiB is below the {_min} GiB minimum "
                f"for this software stack"
            )
        logger.info(
            f"Default root volume size {_size} GiB is below the {_min} GiB minimum, using {_min} GiB"
        )
        _size = _min

    if not _limits["min_size"] <= _size <= _limits["max_size"]:
        return SocaError.GENERIC_ERROR(
            helper=f"Root volume size {_size} GiB is outside the "
            f"{_limits['min_size']}..{_limits['max_size']} GiB range for {_volume_type}"
        )

    _iops = _resolve_iops(_volume_type, _size, _configured_iops)
    _throughput = _resolve_throughput(_volume_type, _iops, _configured_throughput)

    return SocaResponse(
        success=True,
        message=RootVolume(
            size=_size,
            volume_type=_volume_type,
            iops=_iops,
            throughput=_throughput,
        ),
    )
