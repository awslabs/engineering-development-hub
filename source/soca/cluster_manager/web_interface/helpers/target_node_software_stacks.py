######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import logging
import utils.aws.boto3_wrapper as utils_boto3
from models import (
    db,
    TargetNodeSoftwareStacks,
)
from utils.error import SocaError
from utils.response import SocaResponse
from functools import wraps
from typing import Optional
from flask import session
from utils.http_client import SocaHttpClient
import json
import config

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


class TargetNodeSoftwareStacksHelper:
    def __init__(self, software_stack_id: int, is_active: Optional[bool] = True):
        self._software_stack_id = software_stack_id
        self._is_active = is_active
        self._software_stack_data = None

        if is_active not in [True, False]:
            logger.warning(
                f"Invalid is_active flag, detected {self._is_active } default to True"
            )
            self._is_active = True

        self._software_stack_data = TargetNodeSoftwareStacks.query.filter(
            TargetNodeSoftwareStacks.is_active == self._is_active,
            TargetNodeSoftwareStacks.id == self._software_stack_id,
        ).first()

        if not self._software_stack_data:
            logger.error(f"Unable to retrieve stack info for {self._software_stack_id}")
            self._software_stack_info = None
        else:
            self._software_stack_info = self._software_stack_data.as_dict()

    def get_stack_info(self):
        if self._software_stack_info:
            return SocaResponse(success=True, message=self._software_stack_info)
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve stack info for {self._software_stack_id}"
            )

    def validate(
        self,
        instance_type: str,
        root_size: int,
        subnet_id: str,
        session_owner: str,
        project: str,
    ) -> dict:
        # Validate if:
        # 1 - A user can use this AMI
        # 2 - The instance type chose is valid
        # 3 - The root size is valid
        # 4 - The subnet is valid
        # 5 - The username is valid
        # 6 - Budget is valid
        logger.info(
            f"Validating if user {session_owner} has permission of VDI stack {self._software_stack_info}"
        )
        _check_permissions = SocaHttpClient(
            endpoint=f"/api/user/resources_permissions",
            headers={
                "X-EDH-TOKEN": config.Config.API_ROOT_KEY,
            },
        ).post(
            data={
                "target_nodes": f"{self._software_stack_info.get('id')}",
                "exclude_columns": "thumbnail",
                "user": session_owner,
            }
        )
        if _check_permissions.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get resource_permissions for {session.get('user')} because of {_check_permissions}"
            )

        else:
            _get_stack_info = _check_permissions.get("message").get(
                "target_node_software_stacks"
            )
            if not _get_stack_info:
                return SocaError.GENERIC_ERROR(
                    helper="Stack does not exist, is inactive or user do not have permissions"
                )
            else:
                _stack_info = _get_stack_info[0]

        _max_root_size = _stack_info.get("profile").get("max_root_size")
        _allowed_subnet_ids = _stack_info.get("profile").get("allowed_subnet_ids")
        _ami_arch = _stack_info.get("ami_arch")
        try:
            _allowed_instance_types = json.loads(
                _stack_info.get("profile").get("allowed_instance_types")
            )
            try:
                if instance_type not in _allowed_instance_types.get(_ami_arch, []):
                    return SocaError.GENERIC_ERROR(
                        helper=f"Instance type {instance_type} is not allowed for this stack"
                    )
            except Exception as err:
                logger.error(f"allowed_instance_types error because of {err}")
                return SocaError.GENERIC_ERROR(
                    helper=f"allowed_instance_types exist but {_ami_arch} does not sems to be a list: {_allowed_instance_types}"
                )
        except Exception as err:
            logger.error(f"Unable to parse allowed_instance_types because of {err}")
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to parse allowed_instance_types for {_stack_info.get("profile").get("allowed_instance_types")}"
            )

        if root_size > _max_root_size:
            return SocaError.GENERIC_ERROR(
                helper=f"Root size {root_size} is not allowed for this stack, maximum value if {_max_root_size}"
            )

        if subnet_id not in _allowed_subnet_ids.split(","):
            return SocaError.GENERIC_ERROR(
                helper=f"Subnet {subnet_id} is not allowed for this stack"
            )

        if project:
            try:
                _check_budget = SocaHttpClient(
                    endpoint=f"/api/cost_management/budget",
                    headers={
                        "X-EDH-TOKEN": config.Config.API_ROOT_KEY,
                    },
                ).get(params={"project_name": project})
            except Exception as err:
                _check_budget = None
                logger.warning(
                    f"Budget check for project {project} errored, allowing launch: {err}"
                )
            if not _check_budget or _check_budget.get("success") is not True:
                logger.warning(
                    f"Budget check for project {project} unavailable, allowing launch"
                )
            else:
                _budget_msg = _check_budget.get("message") or {}
                if (_budget_msg.get("usage_pct", 0) or 0) >= 100:
                    return SocaError.GENERIC_ERROR(
                        helper="The budget allocation for this project has been exceeded."
                    )
                logger.info(f"Budget {_budget_msg} is valid")

        return SocaResponse(success=True, message=True)
