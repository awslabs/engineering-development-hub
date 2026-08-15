# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scheduled task: VDI pool launch_spec convergence sweep.

The VdiPoolReconciler applies the launch_spec stored in DynamoDB, which is only
(re)written on an admin pool save (PUT). Bootstrap template changes, cluster
/configuration changes, and software-stack AMI edits therefore do NOT propagate
to running pools on their own -- the stored launch_spec drifts from the current
render and the reconciler keeps applying stale bytes.

This task periodically re-renders each ENABLED pool and CAS-writes the
launch_spec back only when its content input-hash drifted, converging the stored
state to the current render. It is the catch-all for every drift source; the
software-stack edit hook handles the low-latency AMI-edit case immediately.

Runs on the APScheduler IntervalTrigger registered in app.py with
max_instances=1 (per-process overlap guard). A DDB lease inside
refresh_all_enabled_pools provides the cross-host singleton on a multi-host web
tier; the compare-and-set write is the correctness backstop either way.
"""

import logging

from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


def refresh_pool_specs(app) -> SocaResponse:
    """Re-render + CAS-write drifted pool launch_specs. Never raises into the
    scheduler -- a sweep failure is logged and retried next cycle. Returns the
    sweep outcome as a SocaResponse (the scheduler ignores the return; the typed
    response keeps this public entry point consistent with the SOCA contract)."""
    with app.app_context():
        try:
            from helpers import vdi_pool_refresh

            _resp = vdi_pool_refresh.refresh_all_enabled_pools()
            if _resp.success:
                logger.info(f"refresh_pool_specs sweep: {_resp.message}")
            else:
                logger.warning(
                    f"refresh_pool_specs sweep returned error: {_resp.message}"
                )
            return _resp
        except Exception as err:
            logger.exception(f"refresh_pool_specs sweep failed: {err}")
            return SocaResponse(
                success=False,
                message=f"refresh_pool_specs sweep failed: {err}",
            )
