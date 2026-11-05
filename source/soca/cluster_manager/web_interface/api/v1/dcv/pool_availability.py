# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
End-user read API for VDI pool availability (drives the launch modal).

Route (registered in app.py):
    GET /api/dcv/virtual_desktops/pool_availability[?software_stack_id=<id>]

Returns, per pool-enabled (stack, instance_type), the data the launch modal
needs to decorate the size list and the "ready now" quick-launch zone:

    {
      "<stack_id>": {
        "<instance_type>": {
            "ready_now":       <int>,   # AVAILABLE hot members -> instant claim
            "warming":         <int>,   # MEASURED promotable warm members
            "warming_up":      <int>,   # warm members still booting in
            "warm_measured":   <bool>,  # False -> depth unknown, promise nothing
            "warm_configured": <int>,   # what the admin asked for
            "label":           "<str>"  # optional admin display tag, may be ""
        }, ...
      }, ...
    }

`warming` is a measurement taken by the reconciler, not the admin's configured
warm_count. The two differ whenever a warm pool is still filling, failed to
fill, or has been partly consumed -- which is exactly when the modal must not
promise warm capacity.

This is intentionally a thin, cheap, end-user-safe read (one ledger COUNT
query per enabled entry, plus one scan of the one-row-per-pool summary table)
so the modal can poll it (~15s) without touching the heavier software-stacks
list API. Admin-only pool mutation lives in pool.py.

VDI software stacks only.
"""

import logging

from flask import request
from flask_restful import Resource

from decorators import private_api, feature_flag
from utils.error import SocaError
from utils.response import SocaResponse

from helpers import vdi_pool_store
from helpers import vdi_pool_allocator

logger = logging.getLogger("soca_logger")


class VdiPoolAvailability(Resource):
    """Live per-(stack, type) pool availability for the end-user launch modal."""

    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        Get live pool availability counts per (stack, instance_type) for the launch modal
        ---
        openapi: 3.1.0
        operationId: getVdiPoolAvailability
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
          - name: software_stack_id
            in: query
            schema:
              type: string
            required: false
            description: Scope results to a single software stack (omit for all enabled pools)
        responses:
          '200':
            description: Success
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      additionalProperties:
                        type: object
                        additionalProperties:
                          type: object
                          properties:
                            ready_now:
                              type: integer
                              description: Available hot members for instant claim
                            warming:
                              type: integer
                              description: Measured warm members parked and promotable
                            warming_up:
                              type: integer
                              description: Measured warm members still booting into the warm pool
                            warm_measured:
                              type: boolean
                              description: False when warm depth is unknown (unstamped pool or describe failure)
                            warm_configured:
                              type: integer
                              description: Admin-configured warm_count, for comparison only
                            label:
                              type: string
                              description: Optional admin display tag
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        _sid = request.args.get("software_stack_id")

        # Resolve the set of enabled pools to report on: one stack (when the
        # modal scopes to a selected stack) or all enabled pools.
        _configs = []
        if _sid:
            _resp = vdi_pool_store.get_pool_config(_sid)
            if _resp.get("success") is not True:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to read pool config: {_resp.get('message')}"
                ).as_flask()
            _meta = _resp.get("message")
            if _meta and _meta.get("enabled"):
                _configs = [
                    {
                        "stack_id": _meta.get("stack_id", _sid),
                        "entries": _meta.get("entries", []),
                    }
                ]
        else:
            _resp = vdi_pool_store.get_enabled_pool_configs()
            if _resp.get("success") is not True:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to read pool configs: {_resp.get('message')}"
                ).as_flask()
            _configs = _resp.get("message") or []

        # Broker's live AVAILABLE set (one call per request), so ready_now is the
        # true claim-now count -- not stale ledger rows. None -> ledger fallback.
        _ready_ids = vdi_pool_allocator.broker_ready_instance_ids()

        # Reconciler-stamped per-pool depth. `warming` used to report the
        # admin's CONFIGURED warm_count, which never moves: it did not drop as
        # warm members were consumed, did not go to zero when a warm pool
        # failed to fill or was still filling, and was never compared against
        # the ASG. A type with hot_count=0 and warm_count=5 was therefore
        # badged as pre-warmed and pinned at the top of the size list while
        # being unable to serve anybody. Report what the reconciler measured.
        #
        # One DDB scan of a one-row-per-pool table, so the endpoint stays
        # cheap enough for the modal to poll. A read failure leaves
        # _summaries empty and `warming` reports 0 with warm_measured false,
        # which is honest: we do not know, so do not promise.
        _summary_resp = vdi_pool_store.get_pool_summaries()
        _summaries = (
            _summary_resp.get("message") or {}
            if _summary_resp.get("success") is True
            else {}
        )

        _out = {}
        for _cfg in _configs:
            _stack_id = _cfg.get("stack_id")
            _types = {}
            for _entry in _cfg.get("entries", []):
                _it = (_entry.get("instance_type") or "").strip()
                if not _it:
                    continue
                # Parked (disabled) entries have no running/warm capacity --
                # don't surface them as a pool tier; they appear as normal
                # cold-launchable sizes like any non-pooled type.
                if _entry.get("enabled", True) is False:
                    continue
                _sum = _summaries.get(f"POOL#{_stack_id}#{_it}") or {}
                _types[_it] = {
                    "ready_now": vdi_pool_allocator.available_count(
                        _stack_id, _it, _ready_ids
                    ),
                    # Promotable now: parked warm members a desired-capacity
                    # bump can start. Excludes members still booting into the
                    # warm pool, which are reported separately so the UI can
                    # distinguish "ready in ~30s" from "not yet".
                    "warming": int(_sum.get("warm_promotable") or 0),
                    "warming_up": int(_sum.get("warm_warming_up") or 0),
                    # False when the reconciler has not stamped this pool yet,
                    # or its warm describe failed. The UI must not promise warm
                    # capacity on an unmeasured pool.
                    "warm_measured": bool(_sum.get("warm_measured")),
                    # What the admin asked for, kept for the admin view and for
                    # telling "not filled yet" apart from "not configured".
                    "warm_configured": int(_entry.get("warm_count") or 0),
                    "label": _entry.get("label") or "",
                }
            _out[str(_stack_id)] = _types

        return SocaResponse(success=True, message=_out).as_flask()
