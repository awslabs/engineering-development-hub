# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import config
import subprocess
from flask import request
from flask_babel import gettext as _
from flask_restful import Resource, reqparse
import logging
import base64
from decorators import private_api, feature_flag
import sys
import os
import re
import random
import string
import shutil
import grp
import pwd
import json
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.datamodels.hpc.scheduler import get_schedulers
from utils.hpc.job_fetcher import SocaHpcJobFetcher
from utils.hpc.job_controller import SocaHpcJobController
from utils.hpc.job_submit import SocaHpcJobSubmit, SocaShellScriptSubmit

logger = logging.getLogger("soca_logger")


class Job(Resource):
    @private_api
    @feature_flag(flag_name="HPC", mode="api")
    def get(self):
        r"""
        Get information for a specific job
        ---
        openapi: 3.1.0
        operationId: getJob
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
          - name: scheduler_id
            in: query
            schema:
              type: string
              pattern: '^[a-zA-Z0-9_.-]+$'
              minLength: 1
            required: false
            description: ID of scheduler. Optional if only one scheduler is configured
            example: "openpbs-soca-default"
          - name: serialize
            in: query
            schema:
              type: string
              enum: ["true", "false"]
              minLength: 1
            required: false
            description: Choose whether to serialize output. Recommended to set to true
            example: "true"
          - name: job_id
            in: query
            schema:
              type: string
              pattern: '^[0-9]+\.[a-zA-Z0-9_.-]+$'
              minLength: 1
            required: true
            description: ID of the job to retrieve
            example: "123.scheduler"
        responses:
          '200':
            description: Job information retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      properties:
                        Job_Name:
                          type: string
                          example: my_job
                        Job_Owner:
                          type: string
                          example: john.doe@cluster
                        job_state:
                          type: string
                          enum: [Q, R, H, S, E, F]
                          example: R
                        queue:
                          type: string
                          example: normal
          '400':
            description: Missing job_id parameter
          '401':
            description: Authentication required
          '210':
            description: Job may have terminated
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_id", type=str, location="args")
        parser.add_argument("scheduler_id", type=str, location="args")
        parser.add_argument("serialize", type=str, location="args")
        args = parser.parse_args()
        _job_id = args.get("job_id", "")
        _scheduler_id = args.get("scheduler_id", "")
        logger.info(f"Get job information for job_id: {_job_id=} {_scheduler_id=}")
        if not _job_id:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_id").as_flask()

        _scheduler_id = args.get("scheduler_id", "")
        if not _job_id:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_id").as_flask()

        _all_schedulers = get_schedulers()
        if not _scheduler_id:
            if len(_all_schedulers) == 1:
                _scheduler = _all_schedulers[0]
            else:
                logger.error(
                    "There is more than 1 scheduler configured for this SOCA, scheduler_id must be set"
                )
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="scheduler_id"
                ).as_flask()
        else:
            _scheduler = next(
                (
                    scheduler
                    for scheduler in _all_schedulers
                    if scheduler.identifier == _scheduler_id
                ),
                None,
            )
            if not _scheduler:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find {_scheduler_id}. Accepted values: {[scheduler.identifier for scheduler in _all_schedulers]}"
                ).as_flask()

        _get_job = SocaHpcJobFetcher(scheduler_info=_scheduler).by_job_id(
            job_id=_job_id
        )

        if _get_job.get("success") is True:
            _serialize_output = SocaCastEngine(
                data=_get_job.get("message")
            ).serialize_json()
            if _serialize_output.get("success") is True:
                return SocaResponse(
                    success=True, message=json.loads(_serialize_output.message)
                ).as_flask()
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to serialize job {_get_job.get('message')} due to {_serialize_output.get('message')}"
                )

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to fetch job due to {_get_job.get('message')}"
            ).as_flask()

    @private_api
    @feature_flag(flag_name="HPC", mode="api")
    def post(self):
        """
        Submit a job
        ---
        openapi: 3.1.0
        operationId: submitJob
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
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - payload
                  - interpreter
                properties:
                  payload:
                    type: string
                    format: base64
                    minLength: 1
                    description: Base64 encoded job submission script
                    example: IyEvYmluL2Jhc2gKI1BCUyAtTiBteV9qb2IKZWNobyAiSGVsbG8gV29ybGQi
                  interpreter:
                    type: string
                    minLength: 1
                    description: Interpreter to use (either valid scheduler identifier or system interpreter such as /bin/bash, /bin/csh, /bin/sh or /bin/zsh)
                    example: qsub
        responses:
          '200':
            description: Job submitted successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "123"
          '400':
            description: Missing payload or invalid base64 encoding
          '401':
            description: Authentication required
          '500':
            description: Job submission failed
        """
        parser = reqparse.RequestParser()
        parser.add_argument("payload", type=str, location="form")
        parser.add_argument("interpreter", type=str, location="form")
        args = parser.parse_args()
        _payload = args.get("payload", "")
        _interpreter = args.get("interpreter", "")

        logger.debug(
            f"Received job submission request {_payload=} / {_interpreter=} "
        )

        if not _interpreter:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="interpreter"
            ).as_flask()
        else:
            _all_schedulers = [scheduler.identifier for scheduler in get_schedulers()]
            # add more system interpreter as needed
            _valid_system_interpreter = ["/bin/bash", "/bin/csh", "/bin/zsh", "/bin/sh"]
            if (
                _interpreter not in _all_schedulers
                and _interpreter not in _valid_system_interpreter
            ):
                return SocaError.GENERIC_ERROR(
                    f"interpreter is invalid, detected {_interpreter}, must be one of {_all_schedulers} or {_valid_system_interpreter}"
                ).as_flask()

        try:
            _user = request.headers.get("X-EDH-USER")
            if _user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

            if _interpreter in _all_schedulers:
                _submit_job = SocaHpcJobSubmit(
                    scheduler_id=_interpreter, user=_user, cwd=f"{config.Config.USER_HOME}/{_user}"
                ).submit_encoded_payload(payload=_payload)

            elif _interpreter in _valid_system_interpreter:
                _submit_job = SocaShellScriptSubmit(
                    interpreter=_interpreter, user=_user, cwd=f"{config.Config.USER_HOME}/{_user}"
                ).submit_encoded_payload(payload=_payload)

            logger.debug(f"Submit Job Debug Result: {_submit_job}")
            if _submit_job.get("success") is True:
                return SocaResponse(
                    success=True, message=_submit_job.get("message")
                ).as_flask()
            else:
                return SocaError.GENERIC_ERROR(
                    f"{_submit_job.get('message')}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to generate and submit job because of {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @private_api
    @feature_flag(flag_name="HPC", mode="api")
    def delete(self):
        r"""
        Delete a job
        ---
        openapi: 3.1.0
        operationId: deleteJob
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
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - job_id
                properties:
                  job_id:
                    type: string
                    pattern: '^[0-9]+\.[a-zA-Z0-9_.-]+$'
                    minLength: 1
                    description: ID of the job to delete
                    example: "123"
                  scheduler_id:
                    type: string
                    pattern: '^[a-zA-Z0-9_.-]+$'
                    minLength: 1
                    description: ID of the scheduler. Optional if only one scheduler is configured
                    example: "openpbs-soca-default"
        responses:
          '200':
            description: Job deleted successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: Job deleted successfully
          '400':
            description: Missing job_id parameter
          '401':
            description: Authentication required
          '403':
            description: User is not the job owner
          '404':
            description: Job not found or already terminated
          '500':
            description: Job deletion failed
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_id", type=str, location="form")
        parser.add_argument("scheduler_id", type=str, location="form")

        args = parser.parse_args()
        _job_id = args.get("job_id", "")
        _scheduler_id = args.get("scheduler_id", "")
        logger.info(f"Received job deletion request {_job_id=} / {_scheduler_id=}")
        if not _job_id:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_id").as_flask()

        _all_schedulers = get_schedulers()
        if not _scheduler_id:
            if len(_all_schedulers) == 1:
                _scheduler = _all_schedulers[0]
                _scheduler_id = _scheduler.identifier
            else:
                logger.error(
                    "There is more than 1 scheduler configured for this SOCA, scheduler_id must be set"
                )
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="scheduler_id"
                ).as_flask()
        else:
            _scheduler = next(
                (
                    scheduler
                    for scheduler in _all_schedulers
                    if scheduler.identifier == _scheduler_id
                ),
                None,
            )
            if not _scheduler:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find {_scheduler_id}. Accepted values: {[scheduler.identifier for scheduler in _all_schedulers]}"
                ).as_flask()

        # Note we cannot use SocaHttpClient -> GET /api/scheduler/job as we need the raw SocaHpcJob object
        _get_job_info = SocaHpcJobFetcher(scheduler_info=_scheduler).by_job_id(
            job_id=_job_id
        )

        if _get_job_info.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable fo fetch job {_job_id} because of {_get_job_info.get('message')}"
            ).as_flask()
        else:
            if not _get_job_info.get("message"):
                return SocaError.GENERIC_ERROR(
                    helper=f"Job {_job_id} not found"
                ).as_flask()

            _job_info = _get_job_info.get("message")[0]
            _job_owner = _job_info.job_owner
            _request_user = request.headers.get("X-EDH-USER")
            if _request_user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

            if _request_user != _job_owner:
                return SocaError.GENERIC_ERROR(
                    helper=f"Job ID {_job_id} exist but is not owned by {_request_user}. You can only delete job owned by you."
                ).as_flask()
            try:
                logger.debug("Submitting the job deletion request")
                _delete_job_request = SocaHpcJobController(job=_job_info).delete_job()
                if _delete_job_request.get("success") is True:
                    return SocaResponse(
                        success=True, message=_(f"Job {_job_id}  deleted successfully")
                    ).as_flask()
                else:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to delete Job ID {_job_id} because of {_delete_job_request.get('message')}",
                    ).as_flask()

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return SocaError.GENERIC_ERROR(
                    helper=f"Unknown error trying to delete job: {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                ).as_flask()
