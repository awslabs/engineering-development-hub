# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Single source of truth for parsing EC2 instance-type hardware specs.

Both the admin instance-type typeahead (api/v1/dcv/instance_type_search.py) and
the end-user launch-modal specs endpoint (api/v1/dcv/instance_type_specs.py)
call parse_instance_specs() so the spec dict shape -- and therefore the spec
line rendered in the WebUI -- is identical on the admin and end-user surfaces.

Do NOT add a second parser. If a spec field changes shape here, bump the
catalog cache-key version suffix in instance_type_search.py (:v6 -> :v7) so the
stale Valkey-cached catalog isn't served past the change.

The companion client-side formatter is static/js/edh_instance_specs.js
(edhFormatInstanceSpecs); keep the two in sync (fields produced here must be
the fields the formatter reads).
"""

from fractions import Fraction


def parse_instance_specs(info: dict) -> dict:
    """Extract spec facts from a describe_instance_types entry.

    Returns a dict with: type, vcpu, mem_mib, mem_gib, hibernation_supported,
    gpu, gpu_name, gpu_mem_gib, gpu_frac, arch, clock_ghz, cpu_mfr, disk.
    Fields the caller doesn't render (e.g. arch on the end-user modal) are
    harmless extras.
    """
    _vcpu = (info.get("VCpuInfo") or {}).get("DefaultVCpus")
    _mem_mib = (info.get("MemoryInfo") or {}).get("SizeInMiB")
    _mem_gib = round(_mem_mib / 1024) if _mem_mib else None

    _gpu = 0
    _gpu_name = ""
    _gpu_manufacturer = ""
    _gpu_mem_gib = None
    _gpu_frac = None  # exact partition fraction string for fractional GPUs (e.g. "1/8")
    _gi = info.get("GpuInfo")
    if _gi:
        _gpus = _gi.get("Gpus") or []
        # Fractional/partitioned GPUs (e.g. g6f) report Count=0 but
        # LogicalGpuCount>=1 -- fall back so they still register as GPU types.
        _gpu = sum((_g.get("Count") or _g.get("LogicalGpuCount") or 0) for _g in _gpus)
        if _gpus:
            _g0 = _gpus[0]
            _gpu_manufacturer = _g0.get("Manufacturer", "") or ""
            _gpu_name = f"{_g0.get('Manufacturer', '')} {_g0.get('Name', '')}".strip()
            # GpuPartitionSize is AWS-authoritative (no derivation): g6f.xlarge
            # = 0.125 (1/8 of an L4), g6f.2xlarge = 0.25, full GPUs = 1.0. When
            # < 1, surface the exact fraction so "GPU x1" isn't misread as a
            # whole card. Fraction(...).limit_denominator keeps it clean (1/8).
            _part = _g0.get("GpuPartitionSize")
            if _part and _part < 1:
                _fr = Fraction(_part).limit_denominator(16)
                _gpu_frac = f"{_fr.numerator}/{_fr.denominator}"
        _tot = _gi.get("TotalGpuMemoryInMiB")
        if _tot:
            _gpu_mem_gib = round(_tot / 1024)

    _store = info.get("InstanceStorageInfo")
    _disk = (
        f"{_store.get('TotalSizeInGB')} GB SSD"
        if _store and _store.get("TotalSizeInGB")
        else "EBS"
    )
    _arch = ",".join(
        (info.get("ProcessorInfo") or {}).get("SupportedArchitectures") or []
    )
    _clock = (info.get("ProcessorInfo") or {}).get("SustainedClockSpeedInGhz")
    _mfr = (info.get("ProcessorInfo") or {}).get("Manufacturer") or ""
    return {
        "type": info.get("InstanceType"),
        "vcpu": _vcpu,
        "mem_mib": _mem_mib,
        "mem_gib": _mem_gib,
        # None when the API omits the field -> callers fail OPEN (never block on
        # a data gap); only an explicit False means "hibernation unsupported".
        "hibernation_supported": info.get("HibernationSupported"),
        "gpu": _gpu,
        "gpu_name": _gpu_name,
        "gpu_manufacturer": _gpu_manufacturer,
        "gpu_mem_gib": _gpu_mem_gib,
        "gpu_frac": _gpu_frac,
        "arch": _arch,
        "clock_ghz": _clock,
        "cpu_mfr": _mfr,
        "disk": _disk,
    }
