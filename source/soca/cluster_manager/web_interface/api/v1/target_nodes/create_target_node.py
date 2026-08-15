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
import config
from flask_restful import Resource, reqparse
import logging
from datetime import datetime, timezone

import json
from utils.config import SocaConfig
from decorators import private_api, feature_flag
from flask import request
from flask_babel import gettext as _
import re
import uuid
import sys
import os
from botocore.exceptions import ClientError
from models import db, TargetNodeSessions
import target_nodes_cloudformation_builder
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.odcr_helper import create_capacity_reservation
from utils.aws.ec2_helper import create_capacity_dry_run
from utils.aws.cloudformation_client import SocaCfnClient
from utils.aws.ssm_helper import get_ami_id_from_alias
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.stack_naming import generate_stack_name
from utils.jinjanizer import SocaJinja2Renderer
from helpers.target_node_software_stacks import TargetNodeSoftwareStacksHelper
from helpers.base_image_registry import resolve_launch_ami
import base64
import random
from pathlib import Path
import base64
import re

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def parse_user_data_variables(s: str) -> dict:
    pair_pattern = r"\s*([^=,\s]+)\s*=\s*([^,]*)\s*"

    matches = list(re.finditer(pair_pattern, s))
    if not matches:
        return {}

    # Join matched substrings exactly as they appeared (preserving spacing)
    matched_str = ",".join(match.group(0).strip() for match in matches)
    normalized_input = s.strip()

    if matched_str != normalized_input:
        raise ValueError(f"Invalid input format: unmatched portion in '{s}'")

    result = {}
    for match in matches:
        key, value = match.groups()
        result[key] = value
    return result


def get_user_pubkeys(username: str):
    _ssh_dir = Path(config.Config.USER_HOME) / username / ".ssh"
    _public_keys = []
    if not _ssh_dir.exists():
        logger.error(
            f"Unable to retrieve pubkey for {username=} because {_ssh_dir} does not exist."
        )
        return False

    _pub_files = list(_ssh_dir.glob("*.pub"))
    if not _pub_files:
        logger.error(f"No pubkey found for  {username=} under {_ssh_dir}")
        return False

    for pub_file in _pub_files:
        try:
            with pub_file.open("r") as f:
                content = f.read().strip()
                _public_keys.append(content)
        except Exception as e:
            logger.warning(f"Error reading {pub_file.name}: {e}")

    return _public_keys


class CreateTargetNode(Resource):
    @private_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def post(self):
        r"""
        Create a new target node session
        ---
        openapi: 3.1.0
        operationId: createTargetNodeSession
        tags:
          - Target Nodes
        summary: Create a new target node session for CAE simulations
        description: Creates a new target node session with specified configuration including instance type, software stack, and networking parameters
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: john.doe
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: Authentication token for the SOCA user
            example: abc123token
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - instance_type
                  - session_name
                  - software_stack_id
                  - project
                properties:
                  instance_type:
                    type: string
                    pattern: '^[a-z0-9]+\.[a-z0-9]+$'
                    description: AWS EC2 instance type for the target node
                    example: m5.large
                  session_name:
                    type: string
                    pattern: '^[a-zA-Z0-9-]{1,32}$'
                    maxLength: 32
                    description: Name for the target node session (max 32 chars, alphanumeric and hyphens only)
                    example: my-simulation-session
                  software_stack_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the software stack to use
                    example: "123"
                  project:
                    type: string
                    minLength: 1
                    description: Project name for the target node session
                    example: default
                  disk_size:
                    type: string
                    pattern: '^[0-9]+$'
                    description: Root disk size in GB
                    example: "100"
                  subnet_id:
                    type: string
                    pattern: '^subnet-[a-f0-9]{8,17}$'
                    description: AWS subnet ID (random private subnet used if not specified)
                    example: subnet-12345678
                  tenancy:
                    type: string
                    enum: [default, dedicated, host]
                    description: EC2 tenancy type
                    example: default
                  nested_virtualization:
                    type: string
                    enum: ["true", "false"]
                    description: Enable nested virtualization on the instance (requires EnableNestedVirtualization feature flag)
                    example: "false"
        responses:
          '200':
            description: Target node session created successfully
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
                      example: Session my-simulation-session started successfully.
          '400':
            description: Bad request - missing or invalid parameters
          '401':
            description: Authentication required
          '403':
            description: Forbidden - user quota exceeded or access denied
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("instance_type", type=str, location="form")
        parser.add_argument("disk_size", type=str, location="form")
        parser.add_argument("session_name", type=str, location="form")
        parser.add_argument("software_stack_id", type=str, location="form")
        parser.add_argument("subnet_id", type=str, location="form")
        parser.add_argument("tenancy", type=str, location="form")
        parser.add_argument("nested_virtualization", type=str, location="form")
        parser.add_argument("project", type=str, location="form")
        args = parser.parse_args()

        _session_uuid = str(uuid.uuid4())

        logger.info(
            f"Received parameter for new target node session request: {args}, setting up session uuid {_session_uuid}"
        )
        try:
            _user = request.headers.get("X-EDH-USER")
            if _user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

            _check_disk_size = SocaCastEngine(args["disk_size"]).cast_as(
                expected_type=int
            )
            if _check_disk_size.get("success") is True:
                args["disk_size"] = _check_disk_size.get("message")
            else:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"disk_size error: {_check_disk_size.message} ",
                ).as_flask()

            if args["session_name"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    helper="session_name",
                ).as_flask()
            else:
                _session_name = re.sub(
                    pattern=r"[^a-zA-Z0-9]",
                    repl="",
                    string=str(args["session_name"])[:32],
                )[:32]

            if not args["subnet_id"]:
                logger.info("No subnet_id specified, default to 'auto'")
                args["subnet_id"] = "auto"

            if not args["nested_virtualization"]:
                args["nested_virtualization"] = False
            else:
                _check_nested_virt = SocaCastEngine(args["nested_virtualization"]).cast_as(
                    expected_type=bool
                )
                if _check_nested_virt.get("success"):
                    args["nested_virtualization"] = _check_nested_virt.get("message")
                else:
                    args["nested_virtualization"] = False

            if args["nested_virtualization"] is True:
                _nv_flag = SocaConfig(
                    key="/configuration/FeatureFlags/TargetNodes/EnableNestedVirtualization"
                ).get_value(return_as=bool)
                if not (_nv_flag.get("success") is True and _nv_flag.get("message") is True):
                    logger.warning("nested_virtualization requested but EnableNestedVirtualization feature flag is disabled, ignoring")
                    args["nested_virtualization"] = False

            logger.debug(f"Session name {_session_name}")

            # Validate input
            if args["instance_type"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="instance_type"
                ).as_flask()
            else:
                instance_type = args["instance_type"]

            if args.get("project") is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="project"
                ).as_flask()

            # Retrieve SOCA specific variable from AWS Parameter Store
            _get_soca_parameters = (
                SocaConfig(
                    key="/",
                )
                .get_value(return_as=dict)
                .get("message")
            )

            if not _get_soca_parameters:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper="Unable to query SSM for this SOCA environment",
                ).as_flask()

            _stack_name = generate_stack_name(
                cluster_id=_get_soca_parameters.get("/configuration/ClusterId"),
                owner=_user,
                session_uuid=_session_uuid,
            )
            logger.debug(f"VDI will be provisioned by {_stack_name=}")

            _max_session_count = config.Config.TARGET_NODE_SESSION_COUNT
            logger.debug(
                f"Max Target Node Session Count per user: {_max_session_count}"
            )

            _find_active_target_nodes_sessions = TargetNodeSessions.query.filter(
                TargetNodeSessions.is_active == True,
                TargetNodeSessions.session_owner == _user,
            ).count()

            logger.debug(
                f"Found {_find_active_target_nodes_sessions} active session(s) for {_user}"
            )

            if _find_active_target_nodes_sessions >= _max_session_count:
                return SocaError.GENERIC_ERROR(
                    helper=f"User already has {_find_active_target_nodes_sessions} target nodes. Delete one of contact SOCA admin to increase the quota."
                ).as_flask()

            # Get all public key for the user
            _user_public_keys = get_user_pubkeys(username=_user)  # return a list

            if args["software_stack_id"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="software_stack_id"
                ).as_flask()
            else:
                _software_stack_id = SocaCastEngine(
                    data=args["software_stack_id"]
                ).cast_as(expected_type=int)
                if _software_stack_id.get("success"):
                    _get_software_stack = TargetNodeSoftwareStacksHelper(
                        software_stack_id=_software_stack_id.get("message"),
                        is_active=True,
                    )
                else:
                    return SocaError.GENERIC_ERROR(
                        helper=f"software_stack_id does not seems to be a valid integer: {_software_stack_id.message}",
                    ).as_flask()

            # Validate Software Stack Information
            _get_software_stack_info = _get_software_stack.get_stack_info()
            if _get_software_stack_info.get("success") is True:
                _software_stack_info = _get_software_stack_info.get("message")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to get Software Stack Info: {_get_software_stack_info.get('message')}",
                ).as_flask()

            _check_disk_size = SocaCastEngine(args["disk_size"]).cast_as(
                expected_type=int
            )
            if _check_disk_size.get("success") is True:
                args["disk_size"] = _check_disk_size.get("message")
            else:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"disk_size error: {_check_disk_size.message} ",
                ).as_flask()

            # Check if specified AMI ID is an alias
            if _software_stack_info.get("ami_id").startswith("/aws/service/"):
                _fetch_ami = get_ami_id_from_alias(
                    alias_name=_software_stack_info.get("ami_id")
                )
                if _fetch_ami.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=_fetch_ami.get("message")
                    ).as_flask()
                else:
                    _ami_id = _fetch_ami.get("message")
                    
            else:
                _ami_id = _software_stack_info.get("ami_id")

            # Owned-base indirection: swap to the local owned copy when active (passthrough if FF off)
            _ami_id = resolve_launch_ami(_ami_id).get("message")

            # Note: if subnet_id is set to `auto`, SOCA will cycle trough the list until capacity is available
            _selected_subnet = None
            _soca_private_subnets = (
                SocaCastEngine(
                    _get_soca_parameters.get("/configuration/PrivateSubnets")
                )
                .cast_as(expected_type=list)
                .get("message")
            )

            if (
                SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation")
                .get_value(return_as=bool)
                .get("message")
                is False
            ):
                logger.info(
                    "/configuration/FeatureFlags/EnableCapacityReservation flag is set to False, SOCA will NOT verify capacity availability"
                )

                if args["subnet_id"] == "auto":
                    logger.info(
                        f"subnet_id is 'auto' and capacity reservation check is not enabled, SOCA will pick a random subnet from {_soca_private_subnets}"
                    )
                    _selected_subnet = random.choice(_soca_private_subnets)
                else:
                    _selected_subnet = args["subnet_id"]

                logger.info(f"Selected Subnet: {_selected_subnet}")

            else:
                logger.info(
                    "/configuration/FeatureFlags/EnableCapacityReservation flag is set to True, SOCA will verify capacity availability"
                )
                if args["subnet_id"] != "auto":
                    logger.info(
                        f"Specific subnet_id has been specified {args.get('subnet_id')}, checking if capacity is available"
                    )
                    _selected_subnet = args.get("subnet_id")
                    logger.info(
                        f"Requesting ODCR for {args.get('instance_type')}, instance_count=1, capacity_reservation_name={_stack_name}, subnet_ids={[_selected_subnet]}, {_ami_id}"
                    )
                    _request_on_demand_capacity_reservation = (
                        create_capacity_reservation(
                            probe_capacity_only=True,
                            desired_capacity=1,
                            capacity_reservation_name=_stack_name,
                            instance_type=args.get("instance_type"),
                            subnet_id=_selected_subnet,
                            instance_ami=_ami_id,
                            tenancy=args.get("tenancy"),
                        )
                    )
                    if _request_on_demand_capacity_reservation.get("success") is True:
                        logger.info(
                            f"ODCR succeeded, capacity is available in subnet_id {_selected_subnet}: {_request_on_demand_capacity_reservation.get('message')}"
                        )

                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=f"Unable to create capacity reservation due to {_request_on_demand_capacity_reservation.message}"
                        ).as_flask()

                else:
                    logger.info(
                        "subnet_id is 'auto'. SOCA will try pick a random subnet and cycle through others subnet id until capacity is available"
                    )
                    random.shuffle(_soca_private_subnets)
                    for _subnet_id in _soca_private_subnets:
                        logger.info(
                            f"Requesting ODCR for {args.get('instance_type')}, instance_count=1, capacity_reservation_name={_stack_name}, subnet_id={_subnet_id}, {_ami_id}"
                        )
                        _request_on_demand_capacity_reservation = (
                            create_capacity_reservation(
                                probe_capacity_only=True,
                                desired_capacity=1,
                                instance_type=args.get("instance_type"),
                                capacity_reservation_name=_stack_name,
                                subnet_id=_subnet_id,
                                instance_ami=_ami_id,
                                tenancy=args.get("tenancy"),
                            )
                        )
                        if (
                            _request_on_demand_capacity_reservation.get("success")
                            is True
                        ):
                            _selected_subnet = _subnet_id
                            logger.info(
                                f"ODCR succeeded, capacity is available in subnet_id {_selected_subnet} : {_request_on_demand_capacity_reservation.get("message")}"
                            )
                            break
                        else:
                            logger.warning(
                                f"Unable to create capacity reservation due to {_request_on_demand_capacity_reservation.message}, trying the next subnet in list"
                            )

            if _selected_subnet is None:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find available capacity in all subnets provided {_soca_private_subnets}. Try again later."
                ).as_flask()

            # Validate Software Stack Permissions
            _get_software_stack_permissions = _get_software_stack.validate(
                instance_type=instance_type,
                root_size=args["disk_size"],
                subnet_id=_selected_subnet,
                session_owner=_user,
                project=args.get("project"),
            )

            if _get_software_stack_permissions.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=_get_software_stack_permissions.get("message"),
                ).as_flask()

            # Get the user data template associated to the software stack
            _encoded_user_data_template = _software_stack_info.get("user_data").get(
                "user_data"
            )
            _decoded_user_data_template = base64.b64decode(
                _encoded_user_data_template
            ).decode("utf-8")

            # software_stack ensure ami_user_data_variables is in the correct format
            _extra_user_data_variables = parse_user_data_variables(
                _software_stack_info.get("ami_user_data_variables")
            )
            logger.info(
                f"Retrieve extra  user data variable {_extra_user_data_variables=}"
            )

            # Validate Software Stack Permissions
            _get_software_stack_permissions = _get_software_stack.validate(
                instance_type=instance_type,
                root_size=args["disk_size"],
                subnet_id=_selected_subnet,
                session_owner=_user,
                project=args.get("project"),
            )

            if _get_software_stack_permissions.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=_get_software_stack_permissions.get("message"),
                ).as_flask()

            logger.debug(f"Retrieved associated {_decoded_user_data_template}")

            # Must add the variable specific to the software stack
            _user_data_variables = {
                "EDH_USER": _user,  # default
                "EDH_USER_PUBLIC_KEYS": _user_public_keys,  # default
                **_extra_user_data_variables,
            }

            logger.info(f"{_user_data_variables=} requested for target node")

            get_user_data = SocaJinja2Renderer().from_string(
                data=_decoded_user_data_template, variables=_user_data_variables
            )
            if get_user_data.get("success") is True:
                _rendered_user_data = get_user_data.get("message")

                byte_size = len(_rendered_user_data.encode("utf-8"))
                kb_size = byte_size / 1024
                logger.debug(
                    f"EC2 User Data must be less than 16 KB, detected {kb_size:.1f}"
                )
                if byte_size > 16 * 1024:
                    return SocaError.GENERIC_ERROR(
                        helper=f"User Data on EC2 are limited to 16 KB. Current size is {kb_size:.1f} KB"
                    ).as_flask()

            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to generate User data due to {get_user_data.get('message')}"
                ).as_flask()

            _stack_name = generate_stack_name(
                cluster_id=_get_soca_parameters.get("/configuration/ClusterId"),
                owner=_user,
                session_uuid=_session_uuid,
            )
            logger.debug(f"VDI will be provisioned by {_stack_name=}")

            launch_parameters = {
                "security_group_id": _get_soca_parameters.get(
                    "/configuration/TargetNodeSecurityGroup"
                ),
                "instance_profile": _get_soca_parameters.get(
                    "/configuration/TargetNodeInstanceProfileArn"
                ),
                "instance_type": instance_type,
                "project": args.get("project"),
                "subnet_id": _selected_subnet,
                "tenancy": args["tenancy"],
                "image_id": _ami_id,
                "session_name": _session_name,
                "session_uuid": _session_uuid,
                "disk_size": args["disk_size"],
                "volume_type": _get_soca_parameters.get(
                    "/configuration/DefaultVolumeType"
                ),
                "cluster_id": _get_soca_parameters.get("/configuration/ClusterId"),
                "metadata_http_tokens": _get_soca_parameters.get(
                    "/configuration/MetadataHttpTokens"
                ),
                "user": _user,
                "Version": _get_soca_parameters.get("/configuration/Version"),
                "Region": _get_soca_parameters.get("/configuration/Region"),
                "DefaultMetricCollection": SocaCastEngine(
                    _get_soca_parameters.get("/configuration/DefaultMetricCollection")
                )
                .cast_as(expected_type=bool)
                .get("message"),
                "SolutionMetricsLambda": _get_soca_parameters.get(
                    "/configuration/SolutionMetricsLambda"
                ),
                "NestedVirtLauncherLambda": _get_soca_parameters.get(
                    "/configuration/NestedVirtLauncherLambda"
                ),
                "TargetNodeInstanceProfileArn": _get_soca_parameters.get(
                    "/configuration/TargetNodeInstanceProfileArn"
                ),
                "user_data": base64.b64encode(
                    _rendered_user_data.encode("utf-8")
                ).decode("utf-8"),
                "custom_tags": {},
                "nested_virtualization": args["nested_virtualization"],
            }

            # Get custom tags if specified
            _tags_allowed = SocaConfig(
                key="/configuration/FeatureFlags/TargetNodes/AllowCustomTags"
            ).get_value(return_as=bool)
            if _tags_allowed.get("success") is True:
                if _tags_allowed.get("message") is True:
                    _get_tags = SocaConfig(key="/configuration/CustomTags/").get_value(
                        allow_unknown_key=True
                    )
                    if _get_tags.get("success") is True:
                        _tag_dict = SocaCastEngine(
                            data=_get_tags.get("message")
                        ).autocast(preserve_key_name=True)
                        if _tag_dict.get("success") is True:
                            logger.info(f"Adding new tags: {_tag_dict.get('message')}")
                            launch_parameters["custom_tags"] = _tag_dict.get("message")
                        else:
                            logger.error(
                                f"Unable to autocast custom tags {_tag_dict=} "
                            )
                    else:
                        logger.warning(
                            "/configuration/CustomTags/ does not exist in this environment, ignoring ..."
                        )
                else:
                    logger.warning(
                        f"Unable to determine if tags are allowed because of: {_tags_allowed=} "
                    )

            else:
                logger.warning(
                    "Custom tags are not allowed. AllowCustomTagsTargetNodes is set to false"
                )

            logger.debug(f"Launch parameters for target node: {launch_parameters}")

            _custom_tags = []
            if launch_parameters.get("custom_tags"):
                for tag in launch_parameters["custom_tags"].values():
                    if tag.get("Enabled", ""):
                        _custom_tags.append({"Key": tag["Key"], "Value": tag["Value"]})
                    else:
                        logger.warning(
                            f"{tag} does not have Enabled key or Enabled is False."
                        )

            logger.debug(f"Trying to perform DryRun with {launch_parameters}")
            dry_run_launch = create_capacity_dry_run(
                disk_size=launch_parameters.get("disk_size"),
                instance_type=launch_parameters.get("instance_type"),
                image_id=launch_parameters.get("image_id"),
                security_group_id=[launch_parameters.get("security_group_id")],
                subnet_id=launch_parameters.get("subnet_id"),
                user_data=launch_parameters.get("user_data"),
                instance_profile=launch_parameters.get("instance_profile"),
                custom_tags=launch_parameters.get("custom_tags"),
                volume_type=launch_parameters.get("volume_type"),
                hibernate=launch_parameters.get("hibernate", False),
                metadata_http_tokens=launch_parameters.get("metadata_http_tokens"),
                key_name=_get_soca_parameters.get("/configuration/SSHKeyPair"),
                desired_capacity=1,
            )
            if dry_run_launch.get("success"):
                launch_template = target_nodes_cloudformation_builder.main(
                    **launch_parameters
                )
                if launch_template.get("success") is True:
                    _cfn_stack_name = re.sub(
                        r"[^a-zA-Z0-9\-]",
                        "",
                        _stack_name,
                    )

                    _cfn_stack_tags = [
                        {
                            "Key": "edh:JobName",
                            "Value": str(launch_parameters["session_name"]),
                        },
                        {
                            "Key": "edh:TargetNodeSessionUUID",
                            "Value": str(launch_parameters["session_uuid"]),
                        },
                        {"Key": "edh:JobProject", "Value": args.get("project")},
                        {"Key": "edh:JobOwner", "Value": _user},
                        {
                            "Key": "edh:ClusterId",
                            "Value": str(launch_parameters["cluster_id"]),
                        },
                        {"Key": "edh:NodeType", "Value": "target_node"},
                    ]

                    _create_stack = SocaCfnClient(
                        stack_name=_cfn_stack_name
                    ).create_stack(
                        template_body=launch_template.get("message"),
                        tags=_cfn_stack_tags,
                    )
                    if _create_stack.get("success") is True:
                        logger.info(
                            f"CloudFormation stack {_cfn_stack_name} successfully created"
                        )

                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=f"{_create_stack.get('message')}"
                        ).as_flask()

                else:

                    return SocaError.GENERIC_ERROR(
                        helper=f"{launch_template.get('message')}.",
                    ).as_flask()
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="ec2",
                    helper=f"{dry_run_launch.get('message')}",
                ).as_flask()

            logger.info(
                "New Target Node CloudFormation request successful, adding session on the database"
            )

            # Adding Software Stack thumbnail, maybe one day we will add a live screenshot from DCV
            _session_thumbnail = _software_stack_info.get("thumbnail")

            new_session = TargetNodeSessions(
                is_active=True,
                created_on=datetime.now(timezone.utc),
                deactivated_on=None,
                session_owner=_user,
                session_name=_session_name,
                session_project=args.get("project"),
                stack_name=_cfn_stack_name,
                session_uuid=_session_uuid,
                session_thumbnail=_session_thumbnail,
                schedule=json.dumps(config.Config.DCV_DEFAULT_SCHEDULE),
                session_state_latest_change_time=datetime.now(timezone.utc),
                instance_private_dns=None,
                instance_private_ip=None,
                instance_state="pending",
                instance_id=None,
                os_family=_software_stack_info.get("os_family"),
                instance_type=args["instance_type"],
                session_connection_instructions="instruction will go here",
                target_node_software_stack_id=_software_stack_info.get("id"),
                session_state="pending",
            )

            try:
                db.session.add(new_session)
                db.session.commit()
            except Exception as err:
                logger.error(
                    "Cloudformation stack created but DB error, deleting cloudformation stack"
                )
                _delete_stack = SocaCfnClient(stack_name=_cfn_stack_name).delete_stack()
                if _delete_stack.get("success") is False:
                    return SocaError.AWS_API_ERROR(
                        service_name="cloudformation",
                        helper=f"Unable to delete CloudFormation stack {_cfn_stack_name} due to {_delete_stack.get("success")}",
                    ).as_flask()
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query=new_session,
                    helper=f"Unable to add desktop db entry due to {err}",
                ).as_flask()

            logger.info(
                f"Session {_session_name} with UUID {_session_uuid} started successfully."
            )

            return SocaResponse(
                success=True,
                message=_(f"Session {_session_name} started successfully."),
            ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
