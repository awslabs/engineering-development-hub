# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
VDI pool launch_spec convergence.

The VdiPoolReconciler reads the launch_spec from DynamoDB, NOT from the
bootstrap templates at apply time. So when a render input changes -- the
bootstrap .j2 templates, cluster /configuration values, or a software stack's
AMI / base_os / root_size -- WITHOUT an admin pool save (PUT), the stored
launch_spec silently goes stale and the reconciler keeps applying old bytes.
(That is exactly how a fixed template can fail to take effect.)

This module re-renders the launch_spec and writes it back only when its
content input-hash (spec_input_hash, stamped by vdi_pool_render.build_launch_spec)
has drifted from the stored stamp. It is driven by two callers:

  * the periodic convergence sweep (scheduled_tasks/refresh_pool_specs.py), and
  * the software-stack edit hook (api/v1/dcv/software_stacks.py).

Both go through vdi_pool_store.cas_update_launch_spec, whose compare-and-set on
the stored stamp guarantees two racing callers cannot double-apply -- the first
flips the hash, the second's condition fails and no-ops. The sweep additionally
takes a best-effort DDB lease so only one controller host renders per cycle on a
multi-host web tier (the CAS remains the correctness backstop if the lease ever
overlaps).

Note on the input-hash pre-gate: the expensive part of build_launch_spec (the
big 02/03 bundle render + S3 upload) is short-circuited by the content-addressed
BootstrapTemplateCache, so a no-drift cycle does not pay it. We compute the
freshly-rendered spec_input_hash via the SAME code path that stamps it (so the
two always agree) and only issue the CAS write when it differs from the stored
stamp -- avoiding write/PENDING_APPLY churn when nothing changed.
"""

import logging
import os
import socket

from utils.response import SocaResponse

from helpers import vdi_pool_render
from helpers import vdi_pool_store

logger = logging.getLogger("soca_logger")

# Lease longer than the sweep interval (10 min) so one cycle holds it with
# slack; a host that dies mid-sweep auto-releases when the lease expires.
DEFAULT_SWEEP_LEASE_SECONDS = 900


def refresh_pool_spec(stack) -> SocaResponse:
    """Re-render one VDI software stack's launch_spec and CAS-write it to DDB
    only when its render input-hash drifted from the stored stamp.

    message is one of: "no_config" (no pool config for the stack), "disabled"
    (pool not enabled), "unchanged" (stamp matches; no write), "applied" (drift
    detected, re-rendered + CAS-written), "raced" (drift detected but another
    writer won the CAS). success=False only on a real render/store error.
    """
    _sid = getattr(stack, "id", None)

    _meta = vdi_pool_store.get_pool_input_hash(_sid)
    if _meta.get("success") is not True:
        return SocaResponse(success=False, message=_meta.get("message"))
    _meta_msg = _meta.get("message")
    if not _meta_msg:
        return SocaResponse(success=True, message="no_config")
    if not _meta_msg.get("enabled"):
        return SocaResponse(success=True, message="disabled")
    _stored_hash = _meta_msg.get("spec_input_hash")

    # Expensive bundle render is cache-gated inside build_launch_spec; this
    # also computes the authoritative spec_input_hash via the same path that
    # stamps it, so the comparison below is parity-safe by construction.
    _spec, _err = vdi_pool_render.build_launch_spec(stack)
    if _err:
        return SocaResponse(success=False, message=_err)
    _new_hash = (_spec or {}).get("spec_input_hash")

    if _stored_hash and _new_hash == _stored_hash:
        return SocaResponse(success=True, message="unchanged")

    _put = vdi_pool_store.cas_update_launch_spec(
        stack_id=_sid,
        launch_spec=_spec,
        expected_input_hash=_stored_hash,
        updated_by="spec-convergence",
    )
    if _put.get("success") is True:
        logger.info(
            "pool spec converged: stack=%s re-rendered on input drift "
            "(stored=%s new=%s)",
            _sid,
            _stored_hash,
            _new_hash,
        )
        return SocaResponse(success=True, message="applied")
    if _put.get("message") == "raced":
        return SocaResponse(success=True, message="raced")
    return SocaResponse(success=False, message=_put.get("message"))


def refresh_all_enabled_pools(
    lease_ttl_seconds: int = DEFAULT_SWEEP_LEASE_SECONDS,
    bypass_lease: bool = False,
) -> SocaResponse:
    """Convergence sweep entry point. Unless bypass_lease is set, acquires the
    best-effort singleton lease (skips cleanly if another host holds it), then
    refreshes every ENABLED pool whose render input-hash has drifted. Returns a
    per-outcome count summary.

    bypass_lease=True is for the explicit admin "refresh now" endpoint -- it runs
    regardless of the periodic sweep's lease; the cas_update_launch_spec CAS is
    the race backstop so an overlap with the scheduled sweep cannot double-apply.
    """
    if not bypass_lease:
        _owner = f"{socket.gethostname()}:{os.getpid()}"
        _lease = vdi_pool_store.acquire_spec_sweep_lease(
            ttl_seconds=lease_ttl_seconds, owner=_owner
        )
        if _lease.get("success") is not True:
            # 'held' (another host owns the lease this cycle) or a store error --
            # either way there is nothing for this host to do. Not an error.
            logger.debug(
                "pool spec convergence sweep skipped: %s", _lease.get("message")
            )
            return SocaResponse(
                success=True, message={"skipped": _lease.get("message")}
            )

    _enabled = vdi_pool_store.get_enabled_pool_configs()
    if _enabled.get("success") is not True:
        return SocaResponse(success=False, message=_enabled.get("message"))
    _pools = _enabled.get("message") or []

    # Imported here (not at module load) so this helper stays importable by the
    # CLI / tests without the full Flask model stack.
    from models import SoftwareStacks

    _counts = {
        "applied": 0,
        "unchanged": 0,
        "raced": 0,
        "no_config": 0,
        "disabled": 0,
        "missing_stack": 0,
        "error": 0,
    }
    for _p in _pools:
        _sid = _p.get("stack_id")
        _stack = SoftwareStacks.query.filter_by(id=_sid).first()
        if _stack is None:
            _counts["missing_stack"] += 1
            logger.warning(
                "pool spec convergence: enabled pool stack=%s has no "
                "SoftwareStacks row; skipping",
                _sid,
            )
            continue
        _r = refresh_pool_spec(_stack)
        if _r.get("success") is not True:
            _counts["error"] += 1
            logger.warning(
                "pool spec convergence: refresh error stack=%s: %s",
                _sid,
                _r.get("message"),
            )
            continue
        _outcome = _r.get("message")
        _counts[_outcome] = _counts.get(_outcome, 0) + 1

    logger.info("pool spec convergence sweep complete: %s", _counts)
    return SocaResponse(success=True, message=_counts)
