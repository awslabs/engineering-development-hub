# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from decorators import private_api, feature_flag
from utils.config import SocaConfig
import json
from utils.response import SocaResponse
from utils.error import SocaError
import tempfile, base64
from flask import request
from flask_babel import gettext as _
from utils.aws.eks_client import SocaEKSClient

import re

logger = logging.getLogger("soca_logger")


class EKSJob(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_EKS", mode="api")
    def get(self):
        """
        Get EKS Job Details
        ---
        openapi: 3.1.0
        operationId: getEksJobDetails
        tags:
          - Elastic Kubernetes Service (EKS)
        summary: Retrieve details of a specific EKS job
        description: Gets detailed information about an EKS job including status, configuration, and pod information
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
          - name: eks_cluster
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 100
              pattern: '^[a-zA-Z0-9._-]+$'
            description: Name of the EKS cluster
            example: "my-soca-cluster"
          - name: job_name
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 253
              pattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
            description: Name of the job to retrieve
            example: "simulation-job-001"
          - name: namespace
            in: query
            required: false
            schema:
              type: string
              minLength: 1
              maxLength: 63
              pattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
              default: "default"
            description: Kubernetes namespace
            example: "default"
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
                      required:
                        - job_name
                        - status
                        - namespace
                        - cluster
                        - owner
                      properties:
                        job_name:
                          type: string
                          example: "simulation-job-001"
                        status:
                          type: string
                          enum: ["Running", "Succeeded", "Failed", "Unknown"]
                          example: "Running"
                        namespace:
                          type: string
                          example: "default"
                        cluster:
                          type: string
                          example: "my-soca-cluster"
                        owner:
                          type: string
                          example: "john.doe"
                        created_time:
                          type: string
                          format: date-time
                          nullable: true
                          example: "2024-01-15T10:30:00Z"
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
                      example: "Missing required parameter: job_name"
          '401':
            description: Unauthorized - invalid authentication
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
                      example: "Unauthorized: Verify if the IAM role is allowed to connect to cluster"
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
                      example: "Job not found in namespace default"
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
        parser.add_argument("eks_cluster", type=str, location="args")
        parser.add_argument("job_name", type=str, location="args")
        parser.add_argument("namespace", type=str, location="args")
        args = parser.parse_args()

        _eks_cluster = args.get("eks_cluster") or ""
        _job_name = args.get("job_name") or ""
        _namespace = args.get("namespace") or "default"

        if not _eks_cluster:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="eks_cluster"
            ).as_flask()

        if not _job_name:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_name").as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _soca_eks_client = SocaEKSClient(cluster_name=_eks_cluster)
        if _soca_eks_client.healthcheck() is False:
            return SocaError.GENERIC_ERROR(
                helper=f"EKS cluster {_eks_cluster} is unreachable. Check firewall/security group rules."
            ).as_flask()
        _get_job_response = _soca_eks_client.read_namespaced_job(
            name=_job_name, namespace=_namespace
        )
        if _get_job_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get job {_job_name} in namespace {_namespace}: {_get_job_response.get('message')}"
            ).as_flask()
        else:
            _get_job = _get_job_response.get("message")

        # Validate job ownership
        _job_labels = _get_job.metadata.labels or {}
        _job_owner = _job_labels.get("soca_JobOwner", "")
        _cluster_id = _job_labels.get("soca_ClusterId", "")
        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        if _job_owner != _user or _cluster_id != _soca_cluster_id:
            return SocaError.GENERIC_ERROR(
                helper="This job does not seem to belong to you"
            ).as_flask()

        job_info = {
            "job_name": _get_job.metadata.name,
            "status": (
                _get_job.status.conditions[0].type
                if _get_job.status.conditions
                else "Unknown"
            ),
            "namespace": _get_job.metadata.namespace,
            "cluster": _eks_cluster,
            "owner": _job_owner,
            "created_time": (
                _get_job.metadata.creation_timestamp.isoformat()
                if _get_job.metadata.creation_timestamp
                else None
            ),
        }

        return SocaResponse(success=True, message=job_info).as_flask()

    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_EKS", mode="api")
    def post(self):
        r"""
        Submit EKS Job
        ---
        openapi: 3.1.0
        operationId: submitEksJob
        tags:
          - Elastic Kubernetes Service (EKS)
        summary: Submit a new EKS job
        description: Creates and submits a new job to the specified EKS cluster with the provided configuration
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
                  - image_uri
                  - eks_cluster
                  - job_name
                properties:
                  image_uri:
                    type: string
                    minLength: 1
                    maxLength: 1000
                    pattern: '^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$'
                    description: Container image URI to run
                    example: "nginx:latest"
                  eks_cluster:
                    type: string
                    minLength: 1
                    maxLength: 100
                    pattern: '^[a-zA-Z0-9._-]+$'
                    description: Name of the EKS cluster
                    example: "my-soca-cluster"
                  job_name:
                    type: string
                    minLength: 1
                    maxLength: 253
                    pattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
                    description: Unique name for the job
                    example: "simulation-job-001"
                  cpu:
                    type: string
                    pattern: '^[0-9]+(\.[0-9]+)?$'
                    default: "1"
                    description: CPU resource allocation (cores)
                    example: "2"
                  gpu:
                    type: string
                    pattern: '^[0-9]+(\.[0-9]+)?$'
                    default: "0"
                    description: GPU resource allocation
                    example: "2"
                  memory:
                    type: string
                    pattern: '^[0-9]+(\.[0-9]+)?$'
                    default: "1"
                    description: Memory allocation in GB
                    example: "4"
                  instance_type:
                    type: string
                    pattern: '^[a-z0-9]+\.[a-z0-9]+$'
                    description: EC2 instance type for node selection
                    example: "m5.large"
                  overrideCommands:
                    type: string
                    format: json
                    description: JSON array of command to execute
                    example: '["echo", "hello"]'
                  overrideArgs:
                    type: string
                    format: json
                    description: JSON array of arguments for the command
                    example: '["world"]'
                  envVars:
                    type: string
                    format: json
                    description: JSON array of Key;Value for Environment Variable
                    example: f' [{"name": "MY_ENV", "value": "Hello"}, {"name": "API_KEY", "value": "12345"}]'
                  namespace:
                    type: string
                    minLength: 1
                    maxLength: 63
                    pattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
                    default: "default"
                    description: Kubernetes namespace
                    example: "default"
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
                      example: "Job submitted successfully"
          '400':
            description: Bad request - invalid parameters
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
                      example: "Unable to parse command as JSON"
          '401':
            description: Unauthorized - missing or invalid authentication
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
                      example: "Unauthorized: Verify if the IAM role is allowed to connect to cluster"
          '404':
            description: Namespace not found
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
                      example: "Namespace not found on your EKS cluster"
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
                      example: "Unable to submit EKS job"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("image_uri", type=str, location="form")
        parser.add_argument("eks_cluster", type=str, location="form")
        parser.add_argument("job_name", type=str, location="form")
        parser.add_argument("cpu", type=str, location="form")
        parser.add_argument("memory", type=str, location="form")
        parser.add_argument("gpu", type=str, location="form")
        parser.add_argument("instance_type", type=str, location="form")
        parser.add_argument("overrideCommands", type=str, location="form")
        parser.add_argument("overrideArgs", type=str, location="form")
        parser.add_argument("envVars", type=str, location="form")

        parser.add_argument("namespace", type=str, location="form")

        args = parser.parse_args()
        logger.info(f"Received parameters for new EKS job request: {args}")
        _image_uri = args.get("image_uri") or ""
        _eks_cluster = args.get("eks_cluster") or ""
        _job_name = args.get("job_name") or ""
        _cpu = args.get("cpu") or "1"
        _gpu = args.get("gpu") or "0"
        _memory = args.get("memory") or "1"
        _instance_type = args.get("instance_type") or ""
        _namespace = args.get("namespace") or "default"

        if not _image_uri:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="image_uri").as_flask()

        if not _eks_cluster:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="eks_cluster"
            ).as_flask()

        if not _job_name:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_name").as_flask()

        if args.get("envVars", None) is None:
            _env = []
        else:
            try:
                _env = json.loads(args.get("envVars"))
            except json.JSONDecodeError:
                _env = []

        if args.get("overrideCommands", None) is None:
            _command = []
        else:
            try:
                _command = json.loads(args.get("overrideCommands"))
            except Exception as err:
                logger.error(
                    f"Unable to parse overrideCommands {args.get('overrideCommands', '[]')} as JSON: {err}"
                )
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse overrideCommands {args.get('overrideCommands', '[]')}"
                ).as_flask()

        if args.get("overrideArgs", None) is None:
            _args = []
        else:
            try:
                _args = json.loads(args.get("overrideArgs", "[]"))
            except Exception as err:
                logger.error(
                    f"Unable to parse overrideArgs {args.get('overrideArgs', '[]')} as JSON: {err}"
                )
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse overrideArgs {args.get('overrideArgs', '[]')}"
                ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _soca_eks_client = SocaEKSClient(cluster_name=_eks_cluster)
        if _soca_eks_client.healthcheck() is False:
            return SocaError.GENERIC_ERROR(
                helper=f"EKS cluster {_eks_cluster} is unreachable. Check firewall/security group rules."
            ).as_flask()

        logger.info(f"Submitting job {_job_name} to cluster {_eks_cluster}")

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        try:
            # we use Mi to better handle partial Gb (e.g: 2.5G)
            _memory_gb = float(_memory)
            _memory_mb = int(_memory_gb * 1024)
            _memory_str = f"{_memory_mb}Mi"
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid Memory value: {_memory}, expected integer or float"
            ).as_flask()

        try:
            _cpu_input = float(_cpu)
            # For simplicity, format as string, even if Kubernetes accepts numeric
            if _cpu_input < 1:
                _cpu_str = f"{int(_cpu_input * 1000)}m"  # 0.5 -> "500m" -> half a cpu
            else:
                _cpu_str = str(_cpu_input)  # 1 -> 1 cpu
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid CPU value: {_cpu}, expected integer or float"
            ).as_flask()

        _node_selector = {}
        if _instance_type:
            _node_selector["node.kubernetes.io/instance-type"] = _instance_type

        try:
            # Validate GPU is a correct number
            int(_gpu)
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid GPU value: {_gpu}, expected integer"
            ).as_flask()

        if _gpu != "0":
            _node_selector["nvidia.com/gpu"] = _gpu

        if not re.match(
            "[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*",
            _job_name.lower(),
        ):
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid job name: {_job_name}. A lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character"
            ).as_flask()

        job_manifest = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": _job_name.lower(),  # force lowercase
                "labels": {  # : is not supported by kube
                    "edh_JobOwner": _user,
                    "edh_ClusterId": _soca_cluster_id,
                },
            },
            "spec": {
                "ttlSecondsAfterFinished": 3600,
                "template": {
                    "spec": {
                        "nodeSelector": _node_selector,
                        "containers": [
                            {
                                "name": "example",
                                "image": _image_uri,
                                "command": _command,
                                "args": _args,
                                "resources": {
                                    "requests": {
                                        "cpu": _cpu_str,
                                        "memory": _memory_str,
                                    },
                                    "limits": {"cpu": _cpu_str, "memory": _memory_str},
                                },
                                "env": _env,
                            }
                        ],
                        "restartPolicy": "Never",
                    }
                },
                "backoffLimit": 4,
            },
        }
        logger.info(f"Submitting job with manifest: {job_manifest=}")
        _job_submit_response = _soca_eks_client.create_namespaced_job(
            body=job_manifest, namespace=_namespace
        )
        if _job_submit_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"{_job_submit_response.get('message')}"
            ).as_flask()
        else:
            return SocaResponse(
                success=True, message=_(f"Job {_job_name} submitted successfully.")
            ).as_flask()

    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_EKS", mode="api")
    def delete(self):
        """
        Delete EKS Job
        ---
        openapi: 3.1.0
        operationId: deleteEksJob
        tags:
          - Elastic Kubernetes Service (EKS)
        summary: Delete an existing EKS job
        description: Deletes an EKS job from the specified cluster and namespace. Only the job owner can delete their jobs.
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
                  - eks_cluster
                  - job_name
                properties:
                  eks_cluster:
                    type: string
                    minLength: 1
                    maxLength: 100
                    pattern: '^[a-zA-Z0-9._-]+$'
                    description: Name of the EKS cluster where the job is running
                    example: "my-soca-cluster"
                  job_name:
                    type: string
                    minLength: 1
                    maxLength: 253
                    pattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
                    description: Name of the job to delete
                    example: "simulation-job-001"
                  namespace:
                    type: string
                    minLength: 1
                    maxLength: 63
                    pattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
                    default: "default"
                    description: Kubernetes namespace where the job is located
                    example: "default"
        responses:
          '200':
            description: Job deleted successfully
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
                      example: "Job 'simulation-job-001' deleted successfully."
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
                      example: "Missing required parameter: job_name"
          '401':
            description: Unauthorized - invalid authentication or insufficient permissions
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
                      example: "Unauthorized: Verify if the IAM role is allowed to connect to cluster"
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
            description: Job not found in the specified namespace
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
                      example: "Job simulation-job-001 not found in namespace default"
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
                      example: "Unable to delete job"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("eks_cluster", type=str, location="form")
        parser.add_argument("job_name", type=str, location="form")
        parser.add_argument("namespace", type=str, location="form")
        args = parser.parse_args()
        _eks_cluster = args.get("eks_cluster") or ""
        _job_name = args.get("job_name") or ""
        _namespace = args.get("namespace") or "default"

        if not _eks_cluster:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="eks_cluster"
            ).as_flask()

        if not _job_name:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_name").as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        logger.info(f"Deleting job {_job_name} from cluster {_eks_cluster}")
        _soca_eks_client = SocaEKSClient(cluster_name=_eks_cluster)
        if _soca_eks_client.healthcheck() is False:
            return SocaError.GENERIC_ERROR(
                helper=f"EKS cluster {_eks_cluster} is unreachable. Check firewall/security group rules."
            ).as_flask()
        logger.info("Checking if job belong to current user")

        _get_job_response = _soca_eks_client.read_namespaced_job(
            name=_job_name, namespace=_namespace
        )
        if _get_job_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get job {_job_name} due to {_get_job_response.get('message')}"
            ).as_flask()
        else:
            _get_job = _get_job_response.get("message")

        # Validate if job has the correct labels
        _job_labels = _get_job.metadata.labels or {}
        _job_owner = _job_labels.get("edh_JobOwner", "")
        _cluster_id = _job_labels.get("edh_ClusterId", "")

        if _job_owner != _user or _cluster_id != SocaConfig(
            key="/configuration/ClusterId"
        ).get_value().get("message"):
            return SocaError.GENERIC_ERROR(
                helper="This job does not seem to belong to you. Missing or incorrect edh_JobOwner or edh_ClusterId label."
            )

        delete_response = _soca_eks_client.delete_namespaced_job(
            name=_job_name, namespace=_namespace
        )

        logger.info(f"Job deletion response: {delete_response}")
        if delete_response.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete job due to {delete_response.get('message')}"
            ).as_flask()
        else:
            return SocaResponse(
                success=True, message=_(f"Job {_job_name} deleted successfully.")
            ).as_flask()
