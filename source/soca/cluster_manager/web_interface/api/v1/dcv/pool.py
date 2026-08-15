# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Admin API for VDI (DCV) software-stack pooling config.

Routes (registered in app.py):
    GET /api/dcv/virtual_desktops/software_stacks/<software_stack_id>/pool
    PUT /api/dcv/virtual_desktops/software_stacks/<software_stack_id>/pool

The WebUI admin form is a thin client of this API: validation
(helpers/vdi_pool_config) and persistence (helpers/vdi_pool_store) are shared,
so the two entry points cannot diverge. PUT is declarative (desired state) and
stamps the pool PENDING_APPLY; the PoolController reconcile (later phase)
translates desired state to AWS.

VDI software stacks only -- never target-node software stacks.
"""

import logging

from flask import request
from flask_restful import Resource

from decorators import admin_api, feature_flag
from models import SoftwareStacks
from utils.error import SocaError
from utils.response import SocaResponse

from helpers import vdi_pool_config
from helpers import vdi_pool_store
from helpers import vdi_pool_render
import json
import os
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")


class VdiPoolManager(Resource):
    """Read/replace the pooling config attached to a VDI software stack."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self, software_stack_id):
        r"""
        Return the saved pool config for a VDI software stack (or null)
        ---
        openapi: 3.1.0
        operationId: getVdiPoolConfig
        tags:
          - Virtual Desktops
        parameters:
          - name: software_stack_id
            in: path
            schema:
              type: string
            required: true
            description: ID of the VDI software stack
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
                      description: Pool configuration object or null if not configured
          '401':
            description: Authentication required
          '403':
            description: Admin privileges required
          '404':
            description: Software stack not found
          '500':
            description: Server error
        """
        _stack = SoftwareStacks.query.filter_by(id=software_stack_id).first()
        if _stack is None:
            return SocaError.GENERIC_ERROR(
                helper=f"VDI software stack {software_stack_id} not found"
            ).as_flask()

        _resp = vdi_pool_store.get_pool_config(software_stack_id)
        if _resp.get("success") is not True:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to read pool config: {_resp.get('message')}"
            ).as_flask()

        return SocaResponse(success=True, message=_resp.get("message")).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def put(self, software_stack_id):
        r"""
        Validate and declaratively persist the pool config for a VDI software stack
        ---
        openapi: 3.1.0
        operationId: putVdiPoolConfig
        tags:
          - Virtual Desktops
        parameters:
          - name: software_stack_id
            in: path
            schema:
              type: string
            required: true
            description: ID of the VDI software stack
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
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                description: Desired pool configuration state
                properties:
                  pool_state:
                    type: string
                    description: Desired pool state (e.g. Hibernated)
                  entries:
                    type: array
                    items:
                      type: object
                      properties:
                        instance_type:
                          type: string
                        enabled:
                          type: boolean
                        warm_count:
                          type: integer
                        label:
                          type: string
            application/x-www-form-urlencoded:
              schema:
                type: object
                properties:
                  pool_config:
                    type: string
                    description: JSON-encoded pool configuration
        responses:
          '200':
            description: Pool config saved and reconcile triggered
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
          '400':
            description: Invalid pool config or unknown instance types
          '401':
            description: Authentication required
          '403':
            description: Admin privileges required
          '404':
            description: Software stack not found
          '500':
            description: Server error
        """
        _stack = SoftwareStacks.query.filter_by(id=software_stack_id).first()
        if _stack is None:
            return SocaError.GENERIC_ERROR(
                helper=f"VDI software stack {software_stack_id} not found"
            ).as_flask()

        _payload = request.get_json(silent=True)
        if _payload is None:
            # The WebUI proxies the config as a `pool_config` JSON form field
            # (SocaHttpClient sends form-encoded), so fall back to parsing it.
            _raw = request.form.get("pool_config")
            if _raw:
                try:
                    _payload = json.loads(_raw)
                except (TypeError, ValueError):
                    return SocaError.GENERIC_ERROR(
                        helper="pool_config is not valid JSON"
                    ).as_flask()

        _normalized, _errors = vdi_pool_config.validate_pool_config(_payload)
        if _errors:
            return SocaError.GENERIC_ERROR(
                helper="Invalid pool config: " + "; ".join(_errors)
            ).as_flask()

        # Reject non-existent instance types at save time (catches typos AND
        # future/API callers that bypass the form typeahead). Backed by the
        # cached EC2 catalog; is_known_instance_type fails OPEN if the catalog
        # can't load, so a transient EC2/IAM hiccup never blocks a save.
        from api.v1.dcv.instance_type_search import is_known_instance_type

        _bad_types = sorted(
            {
                _e.get("instance_type")
                for _e in (_normalized.get("entries") or [])
                if _e.get("instance_type")
                and not is_known_instance_type(_e["instance_type"])
            }
        )
        if _bad_types:
            return SocaError.GENERIC_ERROR(
                helper="Unknown instance type(s): " + ", ".join(_bad_types)
            ).as_flask()

        # Architecture guard (authoritative): a stack's AMI is a single
        # architecture (x86_64/arm64) and an instance of a different arch simply
        # won't boot it -- so a pool must never mix archs. Reject any entry whose
        # instance type doesn't support the stack's AMI arch. Covers the form AND
        # any API caller; the typeahead hard-filter is just UX on top of this.
        # instance_type_arch_ok fails OPEN on unknown types / missing arch data
        # (unknown types are already reported above).
        from api.v1.dcv.instance_type_search import instance_type_arch_ok

        _ami_arch = getattr(_stack, "ami_arch", None)
        if _ami_arch:
            _arch_bad = sorted(
                {
                    _e.get("instance_type")
                    for _e in (_normalized.get("entries") or [])
                    if _e.get("instance_type")
                    and not instance_type_arch_ok(_e["instance_type"], _ami_arch)
                }
            )
            if _arch_bad:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Instance type(s) {', '.join(_arch_bad)} do not support "
                        f"this stack's AMI architecture ({_ami_arch})"
                    )
                ).as_flask()

        # Hibernation guard (V1587014009): a "Hibernated" pool keeps its members
        # in hibernation, which fails at launch when an instance type either
        # doesn't support hibernation or exceeds the OS-specific RAM ceiling.
        # Reject such entries at save with a clear message instead of letting the
        # reconciler hit a launch error every cycle. instance_type_hibernation_ok
        # fails OPEN on catalog/data gaps (unknown types are reported above).
        if _normalized.get("pool_state") == "Hibernated":
            from api.v1.dcv.instance_type_search import instance_type_hibernation_ok

            _hib_base_os = getattr(_stack, "ami_base_os", None)
            _hib_bad = []
            for _e in _normalized.get("entries") or []:
                _it = _e.get("instance_type")
                if not _it:
                    continue
                _ok, _reason = instance_type_hibernation_ok(_it, _hib_base_os)
                if _ok is False:
                    _hib_bad.append(f"{_it} ({_reason})")
            if _hib_bad:
                return SocaError.GENERIC_ERROR(
                    helper="Hibernated pool cannot use "
                    + "; ".join(sorted(_hib_bad))
                ).as_flask()

        # Authenticated principal -> audit actor (RBAC-ready for the future
        # VDI-admin persona). admin_api guarantees the header is present.
        _updated_by = request.headers.get("X-EDH-USER", "unknown")

        # Render the session-less bootstrap + denormalize the launch inputs
        # (AMI, instance profile, SG, subnets, user_data) so the reconciler is
        # fully self-contained. Reuses the VDI render path (cached big bootstrap).
        _launch_spec, _spec_err = vdi_pool_render.build_launch_spec(_stack)
        if _spec_err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build launch spec for stack "
                f"{software_stack_id}: {_spec_err}"
            ).as_flask()

        _resp = vdi_pool_store.put_pool_config(
            stack_id=software_stack_id,
            normalized=_normalized,
            updated_by=_updated_by,
            launch_spec=_launch_spec,
        )
        if _resp.get("success") is not True:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to save pool config: {_resp.get('message')}"
            ).as_flask()

        # Trigger an immediate reconcile for this stack (instant apply). Best
        # effort -- the periodic schedule applies it regardless.
        try:
            _lambda = utils_boto3.get_boto(service_name="lambda").message
            _lambda.invoke(
                FunctionName=f"{os.environ.get('EDH_CLUSTER_ID', '')}-VdiPoolReconciler",
                InvocationType="Event",
                Payload=json.dumps(
                    {"action": "reconcile", "stack_id": software_stack_id}
                ).encode("utf-8"),
            )
        except Exception as _inv_err:
            logger.warning(
                "pool reconcile invoke failed (will reconcile on schedule): %s",
                _inv_err,
            )

        # Persisted as desired state; the PoolController reconcile applies it.
        # NOTE: as_flask() already returns a (body, status) tuple -- do NOT
        # append another status here or Flask serializes the body as a JSON
        # list and SocaHttpClient (.get on the result) breaks.
        return SocaResponse(success=True, message=_resp.get("message")).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self, software_stack_id):
        r"""
        Trigger a pool recycle (instance refresh) for all pool members of a stack
        ---
        openapi: 3.1.0
        operationId: recycleVdiPool
        tags:
          - Virtual Desktops
        parameters:
          - name: software_stack_id
            in: path
            schema:
              type: string
            required: true
            description: ID of the VDI software stack whose pool members to recycle
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
        responses:
          '200':
            description: Recycle triggered successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: string
          '401':
            description: Authentication required
          '403':
            description: Admin privileges required
          '404':
            description: Software stack not found
          '500':
            description: Server error or unable to trigger recycle
        """
        _stack = SoftwareStacks.query.filter_by(id=software_stack_id).first()
        if _stack is None:
            return SocaError.GENERIC_ERROR(
                helper=f"VDI software stack {software_stack_id} not found"
            ).as_flask()
        try:
            _lambda = utils_boto3.get_boto(service_name="lambda").message
            _lambda.invoke(
                FunctionName=f"{os.environ.get('EDH_CLUSTER_ID', '')}-VdiPoolReconciler",
                InvocationType="Event",
                Payload=json.dumps(
                    {"action": "recycle", "stack_id": software_stack_id}
                ).encode("utf-8"),
            )
        except Exception as _inv_err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to trigger pool recycle: {_inv_err}"
            ).as_flask()
        return SocaResponse(
            success=True,
            message=f"Recycle triggered for stack {software_stack_id} pools",
        ).as_flask()


class VdiPoolSpecRefresh(Resource):
    """Admin: force the VDI pool launch_spec convergence sweep on demand.

    The periodic APScheduler sweep (every 10 min) re-renders and CAS-writes any
    ENABLED pool whose render input-hash drifted from the stored snapshot. This
    endpoint runs that same sweep immediately -- the operator cure for a stale
    stored launch_spec (e.g. after a bootstrap template or AMI change) without
    waiting for the next cycle. Bypasses the singleton lease (explicit admin
    action); the compare-and-set write remains the race backstop.
    """

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        r"""
        Force an immediate VDI pool launch_spec convergence sweep for all enabled pools
        ---
        openapi: 3.1.0
        operationId: refreshVdiPoolSpecs
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
        responses:
          '200':
            description: Spec refresh completed
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      description: Summary of pools refreshed
          '401':
            description: Authentication required
          '403':
            description: Admin privileges required
          '500':
            description: Server error or refresh failed
        """
        from helpers import vdi_pool_refresh

        _resp = vdi_pool_refresh.refresh_all_enabled_pools(bypass_lease=True)
        if _resp.get("success") is not True:
            return SocaError.GENERIC_ERROR(
                helper=f"pool spec refresh failed: {_resp.get('message')}"
            ).as_flask()
        return SocaResponse(
            success=True, message=_resp.get("message")
        ).as_flask()
