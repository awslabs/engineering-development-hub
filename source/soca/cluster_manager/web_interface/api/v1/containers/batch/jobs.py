# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
import logging
import time
from decorators import private_api, feature_flag
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.error import SocaError
from flask import request
from utils.aws.batch_client import SocaAWSBatchClient

logger = logging.getLogger("soca_logger")


class BatchJobs(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="api")
    def get(self):
        """
        List AWS Batch Jobs
        ---
        openapi: 3.1.0
        operationId: listBatchJobs
        tags:
          - AWS Batch
        summary: List all AWS Batch jobs owned by the requesting user
        description: |
          Lists AWS Batch jobs across all visible job queues (tagged with edh:visibility:<ClusterId> = true).
          Only jobs with matching soca_JobOwner and soca_ClusterId tags are returned.
          Optionally filter by a specific job queue or job status.
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
          - name: job_queue
            in: query
            required: false
            schema:
              type: string
              maxLength: 256
            description: ARN or name of a specific job queue to list jobs from. If omitted, jobs from all visible queues are returned.
            example: "arn:aws:batch:us-east-1:123456789012:job-queue/my-queue"
          - name: job_status
            in: query
            required: false
            schema:
              type: string
              enum: ["SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED"]
            description: Filter jobs by status. If omitted, all statuses are returned.
            example: "RUNNING"
          - name: time_range
            in: query
            required: false
            schema:
              type: integer
              minimum: 1
              default: 24
            description: Time range in hours to look back for jobs. Only jobs created within this window are returned. Defaults to 24 hours.
            example: 48
        responses:
          '200':
            description: Jobs retrieved successfully
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
                      type: array
                      items:
                        type: object
                        properties:
                          jobId:
                            type: string
                          jobName:
                            type: string
                          jobQueue:
                            type: string
                          jobQueueName:
                            type: string
                          jobDefinition:
                            type: string
                          status:
                            type: string
                          createdAt:
                            type: integer
                          startedAt:
                            type: integer
                          stoppedAt:
                            type: integer
                          statusReason:
                            type: string
                          tags:
                            type: object
          '400':
            description: Bad request
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
                      example: "Unable to list AWS Batch jobs"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_queue", type=str, location="args")
        parser.add_argument("job_status", type=str, location="args")
        parser.add_argument("time_range", type=int, location="args")
        args = parser.parse_args()

        _requested_queue = args.get("job_queue") or ""
        _requested_status = args.get("job_status") or ""
        _time_range_hours = args.get("time_range") or 24
        _created_after = int(time.time() * 1000) - (_time_range_hours * 3600 * 1000)
        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        logger.info(f"AWS Batch job listing requested by {_user} with {_requested_status=} and {_requested_queue=}")

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        _batch_client = SocaAWSBatchClient()

        if _requested_queue:
            _queue_arns = [_requested_queue]
            _queue_name_map = {_requested_queue: _requested_queue.split("/")[-1]}
            logger.info(f"job_queue is specified: {_queue_name_map}")
        else:
            logger.info("job_queue is not specified, finding all queues")
            _queue_arns = []
            _queue_name_map = {}
            next_token = None
            while True:
                _response = _batch_client.describe_job_queues(next_token=next_token)

                if _response.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to describe job queues: {_response.get('message')}"
                    ).as_flask()

                _result = _response.get("message", {})
                for queue in _result.get("jobQueues", []):
                    if queue.get("status") != "VALID":
                        continue
                    if queue.get("state") != "ENABLED":
                        continue
                    tags = queue.get("tags", {})
                    if tags.get(f"edh:visibility:{_soca_cluster_id}", "").lower() == "true":
                        _arn = queue.get("jobQueueArn", "")
                        _queue_arns.append(_arn)
                        _queue_name_map[_arn] = queue.get("jobQueueName", "")

                next_token = _result.get("nextToken")
                if not next_token:
                    break
        
        logger.info(f"Queues to check: {_queue_arns}")
        _user_jobs = []

        for _queue_arn in _queue_arns:
            _queue_name = _queue_name_map.get(_queue_arn, _queue_arn.split("/")[-1])
            logger.info(f"Listing jobs for queue {_queue_name}")

            # List jobs from queue (optionally filtered by status)
            # AWS Batch ListJobs only returns RUNNING jobs by default,
            # so query all statuses when no specific status is requested
            _statuses_to_query = (
                [_requested_status]
                if _requested_status
                else ["SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED"]
            )
            _job_summaries = []
            for _status in _statuses_to_query:
                next_token = None
                while True:
                    _list_response = _batch_client.list_jobs(
                        job_queue=_queue_arn,
                        job_status=_status,
                        next_token=next_token,
                    )

                    logger.debug(f"List jobs response for status {_status}: {_list_response}")
                    if _list_response.get("success") is False:
                        return SocaError.GENERIC_ERROR(
                            helper=f"Unable to list jobs for queue {_queue_name}: {_list_response.get('message')}"
                        ).as_flask()

                    _list_result = _list_response.get("message", {})
                    _job_summaries.extend(_list_result.get("jobSummaryList", []))
                    next_token = _list_result.get("nextToken")
                    if not next_token:
                        break

            if not _job_summaries:
                continue

            # Filter job summaries by time range before describing
            _job_summaries = [
                j for j in _job_summaries
                if j.get("createdAt", 0) >= _created_after
            ]

            if not _job_summaries:
                continue

            logger.info(f"Found {len(_job_summaries)} jobs in queue {_queue_name} within last {_time_range_hours}h")
            # Describe jobs in batches of 100 to get full details including tags
            _job_ids = [j.get("jobId") for j in _job_summaries if j.get("jobId")]
            for i in range(0, len(_job_ids), 100):
                _batch_ids = _job_ids[i : i + 100]
                _describe_response = _batch_client.describe_jobs(job_ids=_batch_ids)

                if _describe_response.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to describe jobs: {_describe_response.get('message')}"
                    ).as_flask()

                _describe_result = _describe_response.get("message", {})
                for _job in _describe_result.get("jobs", []):
                    _tags = _job.get("tags", {})
                    if (
                        _tags.get("edh:JobOwner") == _user
                        and _tags.get("edh:ClusterId") == _soca_cluster_id
                    ):
                        logger.info(f"{_job.get('jobId')} belongs to {_user}, fetching info")
                        _job["jobQueueName"] = _queue_name
                        _user_jobs.append(_job)
                    else:
                        logger.info(f"{_job.get('jobId')} does NOT belongs to {_user}, skipping")

        _user_jobs.sort(key=lambda j: j.get("createdAt", 0), reverse=True)
        logger.info(f"Returning {len(_user_jobs)} jobs for user {_user}")
        return SocaResponse(success=True, message=_user_jobs).as_flask()
