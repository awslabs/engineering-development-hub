# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
End-user read API for instance-type hardware specs (drives the launch modal).

Route (registered in app.py):
    GET /api/dcv/virtual_desktops/instance_type_specs?instance_types=t1,t2,...

Returns, per requested instance type, the facts the launch modal renders on
the "Start instantly" chips and the all-sizes list rows. The spec dict is
produced by the SHARED parser (utils/aws/instance_type_specs.parse_instance_specs),
the exact same one the admin typeahead uses, so the spec line is identical on
the admin and end-user surfaces. Instance-type specs are immutable, so results
are cached in-process for the worker's lifetime -- the modal fetches this ONCE
per AMI selection (NOT on the ~15s availability poll, which only refreshes
ready-now counts).

    {
      "<instance_type>": {
          "type":        "<str>",
          "vcpu":        <int|None>,
          "mem_gib":     <int|None>,
          "gpu":         <int>,        # 0 for non-GPU types
          "gpu_name":    "<str>",
          "gpu_mem_gib": <int|None>,
          "gpu_frac":    "<str|None>", # e.g. "1/8" for fractional GPUs
          "arch":        "<str>",
          "clock_ghz":   <float|None>,
          "cpu_mfr":     "<str>",
          "disk":        "<str>"       # "<N> GB SSD" (instance store) or "EBS"
      }, ...
    }

VDI software stacks only.
"""

import logging

from flask import request
from flask_restful import Resource

from decorators import private_api, feature_flag
from utils.error import SocaError
from utils.response import SocaResponse
from utils.aws.ec2_helper import describe_instance_types
from utils.aws.instance_type_specs import parse_instance_specs

logger = logging.getLogger("soca_logger")

# Instance-type specs never change -> cache parsed specs per type for the
# worker lifetime. Only types missing from the cache trigger an EC2 describe.
_SPEC_CACHE: dict = {}


class VdiInstanceTypeSpecs(Resource):
    """Cached vCPU/RAM/GPU/disk specs for the requested instance types."""

    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        Get hardware specs for requested EC2 instance types (drives the launch modal)
        ---
        openapi: 3.1.0
        operationId: getVdiInstanceTypeSpecs
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
          - name: instance_types
            in: query
            schema:
              type: string
            required: true
            description: Comma-separated list of EC2 instance type names (e.g. m5.large,c5.xlarge)
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
                        properties:
                          type:
                            type: string
                          vcpu:
                            type: integer
                          mem_mib:
                            type: integer
                            nullable: true
                          mem_gib:
                            type: integer
                          hibernation_supported:
                            type: boolean
                            nullable: true
                          gpu:
                            type: integer
                          gpu_name:
                            type: string
                          gpu_mem_gib:
                            type: integer
                          gpu_frac:
                            type: string
                          arch:
                            type: string
                          clock_ghz:
                            type: number
                          cpu_mfr:
                            type: string
                          disk:
                            type: string
          '401':
            description: Authentication required
          '500':
            description: Server error
        """
        _raw = request.args.get("instance_types") or ""
        _types = sorted({t.strip() for t in _raw.split(",") if t.strip()})
        if not _types:
            return SocaResponse(success=True, message={}).as_flask()

        _out = {}
        _missing = []
        for _t in _types:
            if _t in _SPEC_CACHE:
                _out[_t] = _SPEC_CACHE[_t]
            else:
                _missing.append(_t)

        # describe_instance_types rejects >100 types per call.
        for _i in range(0, len(_missing), 100):
            _batch = _missing[_i : _i + 100]
            _resp = describe_instance_types(instance_types=_batch)
            if _resp.get("success") is not True:
                # Degrade gracefully: skip specs for this batch (modal still
                # renders without them) but surface the reason in logs.
                logger.warning(
                    "instance_type_specs: describe failed for %s: %s",
                    _batch,
                    _resp.get("message"),
                )
                continue
            for _info in (_resp.get("message") or {}).get("InstanceTypes", []):
                _name = _info.get("InstanceType")
                if not _name:
                    continue
                _spec = parse_instance_specs(_info)
                _SPEC_CACHE[_name] = _spec
                _out[_name] = _spec

        return SocaResponse(success=True, message=_out).as_flask()
