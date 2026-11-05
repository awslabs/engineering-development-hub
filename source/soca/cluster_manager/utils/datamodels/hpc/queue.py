# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Literal, Optional
from pydantic import Field
from utils.response import SocaResponse
from utils.validators import Validators
from utils.datamodels.hpc.shared.job_resources import SocaHpcJobResourceModel
import logging

logger = logging.getLogger("soca_logger")


class SocaHpcQueue(SocaHpcJobResourceModel):
    queues: list =  Field(default_factory=list)
    max_running_jobs: int = None
    max_provisioned_instances: int = None

    # Queue ACLs:  https://awslabs.github.io/engineering-development-hub-documentation/documentation/tutorials/manage-queue-acls/
    allowed_users: list =  Field(default_factory=list)  # empty list = all users can submit job
    excluded_users: list = (
        []
    )  # empty list = no restriction, ["*"] = only allowed_users can submit job

    # Queue mode (can be either fifo or fairshare)
    queue_mode: Literal["fifo", "fairshare"] = "fifo"

    # Instance types restrictions: https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/manage-queue-instance-types/
    allowed_instance_types: list = (
        []  # Empty list, all EC2 instances allowed. You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    )
    excluded_instance_types: list = (
        []  # Empty list, no EC2 instance types prohibited.  You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    )

    # List of parameters user can not override: https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/manage-queue-restricted-parameters/
    restricted_parameters: list = Field(default_factory=list)

    # Scaling mode (can be either single_job, or multiple_jobs): single_job runs a single job per EC2 instance, multiple_jobs allows running multiple jobs on the same EC2 instance
    scaling_mode: Literal["single_job", "multiple_jobs"] = (
        "single_job"  # Allowed values: single_job, multiple_jobs
    )

    # List of additional security groups / IAM instance profile that can be used https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/use-custom-sgs-roles/
    allowed_security_group_ids: list = Field(default_factory=list)
    allowed_instance_profiles: list = Field(default_factory=list)

    # How many subjobs of ONE array may hold capacity at the same time. The array
    # may be longer than this; the rest queue and are dispatched as nodes free.
    # 0 means no limit.
    max_running_subjobs: Optional[int] = 100

    def validate_queue(self) -> SocaResponse:
        errors = []

        # queues must be a non-empty list
        if not isinstance(self.queues, list):
            errors.append("queues must be a list")
        elif not self.queues:
            errors.append("queues cannot be empty")

        # max_running_jobs must be a non-negative integer if provided
        if self.max_running_jobs is not None:
            if not isinstance(self.max_running_jobs, int) or self.max_running_jobs < 0:
                errors.append("max_running_jobs must be a non-negative integer")

        # max_provisioned_instances must be a non-negative integer if provided
        if self.max_provisioned_instances is not None:
            if (
                not isinstance(self.max_provisioned_instances, int)
                or self.max_provisioned_instances < 0
            ):
                errors.append(
                    "max_provisioned_instances must be a non-negative integer"
                )

        # max_running_subjobs must be a non-negative integer if provided
        if self.max_running_subjobs is not None:
            if not Validators.is_non_negative_int(self.max_running_subjobs):
                errors.append("max_running_subjobs must be a non-negative integer")

        # allowed_users and excluded_users must be lists
        if not isinstance(self.allowed_users, list):
            errors.append("allowed_users must be a list")

        if not isinstance(self.excluded_users, list):
            errors.append("excluded_users must be a list")

        # queue_mode must be "fifo" or "fairshare"
        if self.queue_mode not in ["fifo", "fairshare"]:
            errors.append("queue_mode must be either 'fifo' or 'fairshare'")

        # allowed_instance_types and excluded_instance_types must be lists
        if not isinstance(self.allowed_instance_types, list):
            errors.append("allowed_instance_types must be a list")
        if not isinstance(self.excluded_instance_types, list):
            errors.append("excluded_instance_types must be a list")

        # restricted_parameters must be a list
        if not isinstance(self.restricted_parameters, list):
            errors.append("restricted_parameters must be a list")

        # scaling_mode must be "single_job" or "multiple_jobs"
        if self.scaling_mode not in ["single_job", "multiple_jobs"]:
            errors.append("scaling_mode must be either 'single_job' or 'multiple_jobs'")

        # Warned rather than refused: a cluster carrying this setting today
        # keeps working, it just does not get shared nodes. The orchestrator
        # provisions one capacity per job and pins that job to it, so a queue
        # configured for multiple_jobs still gets one instance per job and is
        # billed for it. terminate_when_idle is read only for keep_forever
        # capacity, so it has no effect here either.
        if self.scaling_mode == "multiple_jobs":
            logger.warning(
                "scaling_mode is set to 'multiple_jobs' but the orchestrator "
                "provisions one instance per job and pins the job to it, so this "
                "queue still gets single_job behavior and terminate_when_idle is "
                "not applied. To share one instance across several jobs, provision "
                "AlwaysOn capacity with 'edhctl nodes create-alwayson "
                "--terminate-when-idle <minutes>' and submit against it."
            )

        # allowed_security_group_ids and allowed_instance_profiles must be lists
        if not isinstance(self.allowed_security_group_ids, list):
            errors.append("allowed_security_group_ids must be a list")
        if not isinstance(self.allowed_instance_profiles, list):
            errors.append("allowed_instance_profiles must be a list")

        if errors:
            return SocaResponse(success=False, message=errors)
        else:
            return SocaResponse(success=True, message=None)
