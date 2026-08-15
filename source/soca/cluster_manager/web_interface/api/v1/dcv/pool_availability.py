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
            "ready_now": <int>,   # AVAILABLE hot members -> instant claim
            "warming":   <int>,   # warm capacity (starts in ~30s)
            "label":     "<str>"  # optional admin display tag, may be ""
        }, ...
      }, ...
    }

This is intentionally a thin, cheap, end-user-safe read (one ledger COUNT
query per enabled entry) so the modal can poll it (~15s) without touching the
heavier software-stacks list API. Admin-only pool mutation lives in pool.py.

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
                              description: Warm capacity starting up
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
                _types[_it] = {
                    "ready_now": vdi_pool_allocator.available_count(
                        _stack_id, _it, _ready_ids
                    ),
                    "warming": int(_entry.get("warm_count") or 0),
                    "label": _entry.get("label") or "",
                }
            _out[str(_stack_id)] = _types

        return SocaResponse(success=True, message=_out).as_flask()
