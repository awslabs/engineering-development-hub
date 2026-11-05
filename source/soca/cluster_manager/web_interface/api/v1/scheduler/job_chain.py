# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Submit several jobs as one dependency graph.

Separate from the single-job resource because the unit of success differs: a
chain either goes in whole or not at all, so a partial result is a failure
here and the stages already submitted are removed before returning.
"""

import logging
import os
import sys

import config
from flask import request
from flask_restful import Resource
from decorators import private_api, feature_flag
from utils.datamodels.hpc.scheduler import get_schedulers
from utils.error import SocaError
from utils.hpc.job_dependencies import validate_chain_request
from utils.hpc.job_submit import SocaHpcJobSubmit
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class JobChain(Resource):
    @private_api
    @feature_flag(flag_name="JOB_CHAIN_SUBMIT_API", mode="api")
    def post(self):
        """
        Submit a dependency graph of jobs as one unit
        ---
        openapi: 3.1.0
        operationId: submitJobChain
        tags:
          - Scheduler
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA authentication token
            example: abc123token
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - interpreter
                  - stages
                properties:
                  interpreter:
                    type: string
                    description: Scheduler identifier to submit against
                    example: openpbs-default
                  dependency_type:
                    type: string
                    enum: [afterok, afternotok, afterany, after]
                    default: afterok
                    description: Default edge type for every stage in the chain
                  stages:
                    type: array
                    minItems: 1
                    description: Ordered stages. A stage with no depends_on is a root.
                    items:
                      type: object
                      required:
                        - payload
                      properties:
                        payload:
                          type: string
                          description: Base64 encoded job script
                        name:
                          type: string
                          description: Label echoed back in the response
                        depends_on:
                          type: array
                          items:
                            type: integer
                          description: Indexes of earlier stages in this chain
                        dependency_type:
                          type: string
                          enum: [afterok, afternotok, afterany, after]
                          description: Overrides dependency_type for this stage
        responses:
          '200':
            description: Every stage submitted and wired
          '400':
            description: Invalid chain, for example a circular dependency
          '401':
            description: Authentication required
          '500':
            description: Chain submission failed and was rolled back
        """
        # Every request-shape rule lives in validate_chain_request so it is
        # testable without flask_restful, which this repository declares in no
        # requirements file. The graph itself is validated by submit_chain,
        # which stays the authority for callers that do not arrive over HTTP.
        _validated = validate_chain_request(
            body=request.get_json(silent=True),
            scheduler_ids=[scheduler.identifier for scheduler in get_schedulers()],
        )
        if _validated.get("success") is False:
            return _validated.as_flask()

        _request = _validated.get("message")
        _interpreter = _request["interpreter"]
        _stages = _request["stages"]
        _dependency_type = _request["dependency_type"]

        try:
            _user = request.headers.get("X-EDH-USER")
            if _user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

            logger.info(
                f"Received job chain submission for {_user} on {_interpreter} "
                f"with {len(_stages)} stage(s)"
            )

            _submit_chain = SocaHpcJobSubmit(
                scheduler_id=_interpreter,
                user=_user,
                cwd=f"{config.Config.USER_HOME}/{_user}",
            ).submit_chain(stages=_stages, dependency_type=_dependency_type)

            if _submit_chain.get("success") is True:
                return SocaResponse(
                    success=True, message=_submit_chain.get("message")
                ).as_flask()

            # Returned as-is rather than re-wrapped: wrapping it in another
            # GENERIC_ERROR would reset a 400 to 500 and nest a second request
            # id inside the message a caller reads.
            return _submit_chain.as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to submit job chain because of {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
