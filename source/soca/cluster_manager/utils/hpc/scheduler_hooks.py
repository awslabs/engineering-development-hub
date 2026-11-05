# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import yaml
from typing import Optional
from utils.response import SocaResponse
from utils.config import SocaConfig
from utils.error import SocaError
from utils.aws.boto3_wrapper import get_boto
from utils.logger import SocaLogger
from utils.hpc.hooks.validate_project_budget import main as hook_validate_budget
from utils.hpc.hooks.validate_instance_types import main as hook_validate_instance_types
from utils.hpc.hooks.validate_restricted_parameters import (
    main as hook_validate_restricted_parameters,
)
from utils.hpc.hooks.validate_security_groups import (
    main as hook_validate_security_groups,
)
from utils.hpc.hooks.validate_instance_profile import (
    main as hook_validate_instance_profile,
)
from utils.hpc.hooks.validate_queues_acls import main as hook_validate_queues_acls


ec2_client = get_boto(service_name="ec2").message
budget_client = get_boto(service_name="budgets").message
sts_client = get_boto(service_name="sts").message


class SocaHpcHooksValidator:

    def __init__(
        self,
        job_owner: str,
        job_queue: str,
        job_project: Optional[str] = None,
    ):

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().message
        )

        self.job_owner = job_owner
        self.job_queue = job_queue
        self.job_project = job_project
        self.queue_settings_file = f"/opt/edh/{_soca_cluster_id}/cluster_manager/orchestrator/settings/queue_mapping.yml"
        self.budget_config_file = f"/opt/edh/{_soca_cluster_id}/cluster_manager/orchestrator/settings/project_cost_manager.txt"
        self.license_settings_file = f"/opt/edh/{_soca_cluster_id}/cluster_manager/orchestrator/settings/licenses_mapping.yml"
        self.queue_config = None

        # Create SocaLogger
        logger = SocaLogger(name="soca_logger").timed_rotating_file_handler(
            file_path=f"/opt/edh/{_soca_cluster_id}/cluster_manager/orchestrator/logs/hooks.log"
        )

        try:
            _queue_reader = open(self.queue_settings_file, "r")
            self.queue_data = yaml.safe_load(_queue_reader)
        except Exception as err:
            logger.error(
                f"Unable to read {self.queue_settings_file} due to {err}",
                exc_info=True,
            )
            raise ValueError(f"Unable to read {self.queue_settings_file} due to {err}")

        logger.debug(f"Validating Queue Settings File: {self.queue_data=}")

        # Check if Queue exists in queue_mapping.yml
        for section, config in self.queue_data.get("queue_type", {}).items():
            if self.job_queue in config.get("queues", []):
                if self.queue_config is None:
                    self.queue_config = config
                else:
                    raise ValueError(
                        f"Queue {self.job_queue} is defined more than once in {self.queue_settings_file}"
                    )

        logger.debug(
            f"Validating Hooks: {self.job_owner=} / {self.job_queue=} / {self.job_project=} / {self.queue_config=}"
        )
    
    def validate_queue_acls(self) -> SocaResponse | SocaError:
        """
        Validate if user is allowed for a given queue
        """
        return hook_validate_queues_acls(obj=self)

    def validate_instance_types(
        self, instance_types: list[str]
    ) -> SocaResponse | SocaError:
        """
        Validate if instance type is valid
        """
        return hook_validate_instance_types(obj=self, instance_types=instance_types)

    def validate_restricted_parameters(
        self, job_parameters: list
    ) -> SocaResponse | SocaError:
        """
        job_parameters: List of job resources explicitly specified by the user at job submission
        """
        return hook_validate_restricted_parameters(
            obj=self, job_parameters=job_parameters
        )

    def validate_iam_instance_profile(
        self, instance_profile_name: str
    ) -> SocaResponse | SocaError:
        """
        Validate if IAM instance profile is valid
        """
        return hook_validate_instance_profile(
            obj=self, instance_profile_name=instance_profile_name
        )

    def validate_security_groups(
        self, security_groups: list[str]
    ) -> SocaResponse | SocaError:
        """
        Validate if security groups are valid
        """
        return hook_validate_security_groups(obj=self, security_groups=security_groups)

    def validate_project_budget(
        self,
        allow_job_no_project: bool = False,
        allow_user_multiple_projects: bool = True,
    ) -> SocaResponse | SocaError:
        """
        allow_job_no_project: Change if you do not want to enforce project at job submission
        allow_user_multiple_projects:  Change if you want to restrict a user to one project
        """
        return hook_validate_budget(
            obj=self,
            allow_job_no_project=allow_job_no_project,
            allow_user_multiple_projects=allow_user_multiple_projects,
        )
