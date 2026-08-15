# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
import logging
import re
from decorators import private_api, feature_flag
from utils.config import SocaConfig
import json
from utils.response import SocaResponse
from utils.error import SocaError
from flask import request
from flask_babel import gettext as _
from utils.aws.batch_client import SocaAWSBatchClient

logger = logging.getLogger("soca_logger")


class BatchJob(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="api")
    def get(self):
        """
        Get AWS Batch Job Details
        ---
        openapi: 3.1.0
        operationId: getBatchJobDetails
        tags:
          - AWS Batch
        summary: Retrieve details of a specific AWS Batch job
        description: Gets detailed information about an AWS Batch job including status, configuration, and container details
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
          - name: job_id
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: AWS Batch job ID
            example: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        responses:
          '200':
            description: Job details retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      properties:
                        job_id:
                          type: string
                        job_name:
                          type: string
                        job_queue:
                          type: string
                        status:
                          type: string
                        job_definition:
                          type: string
                        created_at:
                          type: integer
                        started_at:
                          type: integer
                        stopped_at:
                          type: integer
                        status_reason:
                          type: string
          '400':
            description: Bad request - missing required parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: job_id"
          '404':
            description: Job not found
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Job not found"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to retrieve job details"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_id", type=str, location="args")
        args = parser.parse_args()

        _job_id = args.get("job_id") or ""
        if not _job_id:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_id").as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _batch_client = SocaAWSBatchClient()
        _describe_response = _batch_client.describe_jobs(job_ids=[_job_id])

        if _describe_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to describe job {_job_id}: {_describe_response.get('message')}"
            ).as_flask()

        _jobs = _describe_response.get("message", {}).get("jobs", [])
        if not _jobs:
            return SocaError.GENERIC_ERROR(helper=f"Job {_job_id} not found").as_flask()

        _job = _jobs[0]

        # Validate job ownership via tags
        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )
        _job_tags = _job.get("tags", {})
        _job_owner = _job_tags.get("soca_JobOwner", "")
        _cluster_id = _job_tags.get("soca_ClusterId", "")

        if _job_owner != _user or _cluster_id != _soca_cluster_id:
            return SocaError.GENERIC_ERROR(
                helper="This job does not seem to belong to you"
            ).as_flask()

        job_info = {
            "job_id": _job.get("jobId"),
            "job_name": _job.get("jobName"),
            "job_queue": _job.get("jobQueue"),
            "status": _job.get("status"),
            "job_definition": _job.get("jobDefinition"),
            "created_at": _job.get("createdAt"),
            "started_at": _job.get("startedAt"),
            "stopped_at": _job.get("stoppedAt"),
            "status_reason": _job.get("statusReason", ""),
        }

        return SocaResponse(success=True, message=job_info).as_flask()

    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="api")
    def post(self):
        """
        Submit AWS Batch Job
        ---
        openapi: 3.1.0
        operationId: submitBatchJob
        tags:
          - AWS Batch
        summary: Submit a new AWS Batch job
        description: Creates and submits a new job to AWS Batch with the provided configuration
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - job_name
                  - job_definition
                  - job_queue
                properties:
                  job_name:
                    type: string
                    minLength: 1
                    maxLength: 128
                    description: Name for the job
                    example: "my-batch-job"
                  job_definition:
                    type: string
                    minLength: 1
                    description: ARN of the job definition
                    example: "arn:aws:batch:us-east-1:123456789012:job-definition/my-def:1"
                  job_queue:
                    type: string
                    minLength: 1
                    description: ARN of the job queue
                    example: "arn:aws:batch:us-east-1:123456789012:job-queue/my-queue"
                  job_dependencies:
                    type: string
                    description: Comma-separated list of job IDs this job depends on
                    example: "job-id-1,job-id-2"
                  array_size:
                    type: string
                    description: Array size for array jobs (2-10000)
                    example: "10"
                  overrideCommands:
                    type: string
                    format: json
                    description: JSON array of command to override the container. First element is typically the executable, followed by arguments.
                    example: '["python", "train.py", "--epochs", "10"]'
                  envVars:
                    type: string
                    format: json
                    description: JSON array of environment variable objects
                    example: '[{"name": "MY_ENV", "value": "Hello"}]'
                  scheduling_priority:
                    type: string
                    description: Scheduling priority (0-9999) for prioritizing jobs in a queue
                    example: "100"
                  job_attempts:
                    type: string
                    description: Number of times to retry the job (1-10)
                    example: "3"
                  execution_timeout:
                    type: string
                    description: Execution timeout in seconds after which the job is terminated
                    example: "3600"
                  vcpus:
                    type: string
                    description: Number of vCPUs reserved for the container (e.g., 0.25, 1, 2)
                    example: "1"
                  memory:
                    type: string
                    description: Hard limit of memory in GB to present to the container
                    example: "2"
                  consumableResources:
                    type: string
                    format: json
                    description: JSON array of custom consumable resource objects (max 5 total including VCPU and MEMORY)
                    example: '[{"type": "GPU", "value": "1"}, {"type": "FPGA", "value": "2"}]'
        responses:
          '200':
            description: Job submitted successfully
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "Job my-batch-job submitted successfully. Job ID: a1b2c3d4"
          '400':
            description: Bad request - missing or invalid parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: job_name"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to submit AWS Batch job"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_name", type=str, location="form")
        parser.add_argument("job_definition", type=str, location="form")
        parser.add_argument("job_queue", type=str, location="form")
        parser.add_argument("job_dependencies", type=str, location="form")
        parser.add_argument("array_size", type=str, location="form")
        parser.add_argument("overrideCommands", type=str, location="form")
        parser.add_argument("envVars", type=str, location="form")
        parser.add_argument("scheduling_priority", type=str, location="form")
        parser.add_argument("job_attempts", type=str, location="form")
        parser.add_argument("execution_timeout", type=str, location="form")
        parser.add_argument("vcpus", type=str, location="form")
        parser.add_argument("memory", type=str, location="form")
        parser.add_argument("consumableResources", type=str, location="form")
        args = parser.parse_args()

        logger.info(f"Received parameters for new AWS Batch job request: {args}")

        _job_name = args.get("job_name") or ""
        _job_definition = args.get("job_definition") or ""
        _job_queue = args.get("job_queue") or ""

        if not _job_name:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_name").as_flask()
        else:
            if not re.match(r"^[a-zA-Z0-9_-]+$", _job_name):
                return SocaError.GENERIC_ERROR(
                    helper=f"Invalid job_name: {_job_name}. Valid characters are a-z, A-Z, 0-9, hyphens (-), and underscores (_)."
                ).as_flask()

        if not _job_definition:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="job_definition"
            ).as_flask()

        if not _job_queue:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_queue").as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        # Parse job dependencies
        _depends_on = []
        _job_dependencies = args.get("job_dependencies") or ""
        if _job_dependencies:
            for dep_id in _job_dependencies.split(","):
                dep_id = dep_id.strip()
                if dep_id:
                    _depends_on.append({"jobId": dep_id})

        # Parse array properties
        _array_properties = {}
        _array_size = args.get("array_size") or ""
        if _array_size:
            try:
                _size = int(_array_size)
                if _size < 2 or _size > 10000:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Invalid array size: {_array_size}. Must be between 2 and 10000."
                    ).as_flask()
                _array_properties = {"size": _size}
            except ValueError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Invalid array size: {_array_size}. Expected an integer."
                ).as_flask()

        # Parse scheduling priority
        _scheduling_priority = None
        _scheduling_priority_str = args.get("scheduling_priority") or ""
        if _scheduling_priority_str:
            try:
                _scheduling_priority = int(_scheduling_priority_str)
                if _scheduling_priority < 0 or _scheduling_priority > 9999:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Invalid scheduling priority: {_scheduling_priority}. Must be between 0 and 9999."
                    ).as_flask()
            except ValueError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Invalid scheduling priority: {_scheduling_priority_str}. Expected an integer."
                ).as_flask()

        # Parse retry strategy (job attempts)
        _retry_strategy = {}
        _job_attempts_str = args.get("job_attempts") or ""
        if _job_attempts_str:
            try:
                _attempts = int(_job_attempts_str)
                if _attempts < 1 or _attempts > 10:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Invalid job attempts: {_attempts}. Must be between 1 and 10."
                    ).as_flask()
                _retry_strategy = {"attempts": _attempts}
            except ValueError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Invalid job attempts: {_job_attempts_str}. Expected an integer."
                ).as_flask()

        # Parse execution timeout
        _timeout = {}
        _execution_timeout_str = args.get("execution_timeout") or ""
        if _execution_timeout_str:
            try:
                _timeout_seconds = int(_execution_timeout_str)
                if _timeout_seconds < 60:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Invalid execution timeout: {_timeout_seconds}. Must be at least 60 seconds."
                    ).as_flask()
                _timeout = {"attemptDurationSeconds": _timeout_seconds}
            except ValueError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Invalid execution timeout: {_execution_timeout_str}. Expected an integer."
                ).as_flask()
        else:
            # Default timeout of 24 hours if not specified
            _timeout = {"attemptDurationSeconds": 86400}

        # Parse container overrides
        _container_overrides = {}

        if args.get("overrideCommands") is not None:
            try:
                _command = json.loads(args.get("overrideCommands"))
                if _command and len(_command) > 0:
                    _container_overrides["command"] = _command
            except json.JSONDecodeError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse overrideCommands as JSON"
                ).as_flask()

        if args.get("envVars") is not None:
            try:
                _env_vars = json.loads(args.get("envVars"))
                _container_overrides["environment"] = _env_vars
            except json.JSONDecodeError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse envVars as JSON"
                ).as_flask()

        # Parse resource requirements (vCPUs and Memory)
        _resource_requirements = []
        _vcpus_str = args.get("vcpus") or ""
        if _vcpus_str:
            try:
                _vcpus = float(_vcpus_str)
                if _vcpus < 0.25:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Invalid vCPUs: {_vcpus}. Must be at least 0.25."
                    ).as_flask()
                _resource_requirements.append({"type": "VCPU", "value": str(_vcpus)})
            except ValueError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Invalid vCPUs: {_vcpus_str}. Expected a number."
                ).as_flask()

        _memory_str = args.get("memory") or ""
        if _memory_str:
            try:
                _memory_gb = float(_memory_str)
                if _memory_gb < 0.5:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Invalid memory: {_memory_gb}. Must be at least 0.5 GB."
                    ).as_flask()
                # AWS Batch expects memory in MiB
                _memory_mib = int(_memory_gb * 1024)
                _resource_requirements.append({"type": "MEMORY", "value": str(_memory_mib)})
            except ValueError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Invalid memory: {_memory_str}. Expected a number."
                ).as_flask()

        # Parse custom consumable resources
        _consumable_resources_str = args.get("consumableResources") or ""
        if _consumable_resources_str:
            try:
                _consumable_resources = json.loads(_consumable_resources_str)
                for resource in _consumable_resources:
                    resource_type = resource.get("type", "").strip()
                    resource_value = resource.get("value", "").strip()

                    if resource_type and resource_value:
                        # Validate total resource count doesn't exceed 5
                        if len(_resource_requirements) >= 5:
                            return SocaError.GENERIC_ERROR(
                                helper=f"Maximum of 5 total resource requirements allowed (including VCPU and MEMORY)."
                            ).as_flask()

                        _resource_requirements.append({
                            "type": resource_type,
                            "value": resource_value
                        })
            except json.JSONDecodeError:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse consumableResources as JSON"
                ).as_flask()

        if _resource_requirements:
            _container_overrides["resourceRequirements"] = _resource_requirements

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        logger.info(f"Submitting AWS Batch job {_job_name} to queue {_job_queue}")

        _batch_client = SocaAWSBatchClient()

        # Build submit_job parameters
        _submit_params = {
            "job_name": _job_name,
            "job_queue": _job_queue,
            "job_definition": _job_definition,
            "timeout": _timeout,
            "depends_on": _depends_on,
            "container_overrides": _container_overrides if _container_overrides else None,
            "array_properties": _array_properties,
            "tags": {
                "edh:JobOwner": _user,
                "edh:ClusterId": _soca_cluster_id,
            },
        }

        # Add optional parameters if provided
        if _scheduling_priority is not None:
            _submit_params["scheduling_priority"] = _scheduling_priority

        if _retry_strategy:
            _submit_params["retry_strategy"] = _retry_strategy

        _submit_response = _batch_client.submit_job(**_submit_params)

        if _submit_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to submit job: {_submit_response.get('message')}"
            ).as_flask()

        _result = _submit_response.get("message", {})
        _submitted_job_id = _result.get("jobId", "unknown")

        return SocaResponse(
            success=True,
            message=_(f"Job {_job_name} submitted successfully. Job ID: {_submitted_job_id}"),
        ).as_flask()

    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="api")
    def delete(self):
        """
        Delete (Terminate) AWS Batch Job
        ---
        openapi: 3.1.0
        operationId: deleteBatchJob
        tags:
          - AWS Batch
        summary: Terminate an existing AWS Batch job
        description: Terminates an AWS Batch job. Only the job owner can terminate their jobs.
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
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
                    minLength: 1
                    maxLength: 256
                    description: AWS Batch job ID to terminate
                    example: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                  reason:
                    type: string
                    maxLength: 1000
                    default: "Terminated by user"
                    description: Reason for terminating the job
                    example: "No longer needed"
        responses:
          '200':
            description: Job terminated successfully
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "Job a1b2c3d4 terminated successfully."
          '400':
            description: Bad request - missing required parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: job_id"
          '403':
            description: Forbidden - job does not belong to user
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "This job does not seem to belong to you"
          '404':
            description: Job not found
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Job not found"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to terminate job"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_id", type=str, location="form")
        parser.add_argument("reason", type=str, location="form")
        args = parser.parse_args()

        _job_id = args.get("job_id") or ""
        _reason = args.get("reason") or "Terminated by user"

        if not _job_id:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_id").as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        logger.info(f"Terminating AWS Batch job {_job_id} requested by {_user}")

        _batch_client = SocaAWSBatchClient()

        # First, verify ownership by describing the job
        _describe_response = _batch_client.describe_jobs(job_ids=[_job_id])
        if _describe_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to describe job {_job_id}: {_describe_response.get('message')}"
            ).as_flask()

        _jobs = _describe_response.get("message", {}).get("jobs", [])
        if not _jobs:
            return SocaError.GENERIC_ERROR(helper=f"Job {_job_id} not found").as_flask()

        _job = _jobs[0]

        # Validate job ownership via tags
        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )
        _job_tags = _job.get("tags", {})
        _job_owner = _job_tags.get("edh:JobOwner", "")
        _cluster_id = _job_tags.get("edh:ClusterId", "")

        if _job_owner != _user or _cluster_id != _soca_cluster_id:
            return SocaError.GENERIC_ERROR(
                helper="This job does not seem to belong to you. Missing or incorrect edh:jobOwner or edh:ClusterId tag."
            ).as_flask()

        # Terminate the job
        _terminate_response = _batch_client.terminate_job(
            job_id=_job_id, reason=_reason
        )

        logger.info(f"Job termination response: {_terminate_response}")
        if _terminate_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to terminate job {_job_id}: {_terminate_response.get('message')}"
            ).as_flask()

        return SocaResponse(
            success=True, message=_(f"Job {_job_id} terminated successfully.")
        ).as_flask()
