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

from flask_restful import Resource, reqparse
import logging
from decorators import admin_api, restricted_api, private_api, feature_flag
import json
from datetime import datetime, timezone
from models import db, TargetNodeProfiles, TargetNodeSoftwareStacks
import math
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.config import SocaConfig
import utils.aws.ec2_helper as ec2_helper
from flask import request
from flask_babel import gettext as _
from sqlalchemy.orm import joinedload


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class TargetNodeProfilesManager(Resource):

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def get(self):
        """
        Get target node profiles
        ---
        openapi: 3.1.0
        operationId: getTargetNodeProfiles
        tags:
          - Target Nodes
        summary: Retrieve target node profiles
        description: Returns target node profile information including allowed instance types and subnet configurations
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin.user
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: Authentication token for the SOCA user
            example: abc123token
          - name: profile_id
            in: query
            schema:
              type: string
              pattern: '^[0-9]+$'
            required: false
            description: Specific profile ID to retrieve (returns all if not specified)
            example: "1"
        responses:
          '200':
            description: Target node profiles retrieved successfully
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
                      description: Dictionary of profile IDs mapped to profile details
                      additionalProperties:
                        type: object
                        properties:
                          id:
                            type: integer
                          profile_name:
                            type: string
                          allowed_instance_types:
                            type: string
                          max_root_size:
                            type: integer
          '400':
            description: Bad request - invalid profile ID
          '401':
            description: Authentication required
          '403':
            description: Admin access required
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="args")
        args = parser.parse_args()

        logger.debug(f"List Target Node Profile with {request.args}")
        _profile_info = {}
        if args["profile_id"] is None:
            _list_profiles = TargetNodeProfiles.query.filter_by(is_active=True).options(
                joinedload(TargetNodeProfiles.target_node_software_stacks)
            )
        else:
            if (
                cast_result := SocaCastEngine(data=args["profile_id"]).cast_as(int)
            ).get("success"):
                _profile_id = cast_result.get("message")
                _list_profiles = TargetNodeProfiles.query.filter_by(
                    id=_profile_id, is_active=True
                ).options(joinedload(TargetNodeProfiles.target_node_software_stacks))
            else:
                return SocaError.GENERIC_ERROR(
                    helper="profile_id does not seems to be a valid integer"
                )

        if _list_profiles.count() == 0:
            logger.warning("No Target Node Profiles found")
            return SocaResponse(
                success=True, message=_("No Target Node Profiles found")
            ).as_flask()
        else:
            for _profile in _list_profiles.all():
                _profile_info[_profile.id] = _profile.as_dict()
                _profile_info[_profile.id]["software_stack_ids"] = [
                    stack.id for stack in _profile.target_node_software_stacks
                ]

            return SocaResponse(success=True, message=_profile_info).as_flask()

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def post(self):
        r"""
        Create a new target node profile
        ---
        openapi: 3.1.0
        operationId: createTargetNodeProfile
        tags:
          - Target Nodes
        summary: Create a new target node profile
        description: Creates a new target node profile with specified instance types, subnets, and resource limits
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin.user
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
                  - profile_name
                  - pattern_allowed_instance_types
                  - allowed_subnet_ids
                  - max_root_size
                properties:
                  profile_name:
                    type: string
                    pattern: '^[a-zA-Z0-9_-]+$'
                    minLength: 1
                    maxLength: 100
                    description: Name for the new profile
                    example: high-performance-profile
                  pattern_allowed_instance_types:
                    type: string
                    pattern: '^[a-z0-9.*,\s]+$'
                    description: Comma-separated list of allowed EC2 instance type patterns
                    example: "m5.*,c5.*"
                  allowed_subnet_ids:
                    type: string
                    pattern: '^subnet-[a-f0-9]{8,17}(,subnet-[a-f0-9]{8,17})*$'
                    description: Comma-separated list of allowed subnet IDs
                    example: "subnet-12345678,subnet-87654321"
                  max_root_size:
                    type: string
                    pattern: '^[0-9]+$'
                    description: Maximum root disk size in GB
                    example: "100"
                  description:
                    type: string
                    maxLength: 500
                    description: Profile description (max 500 characters)
                    example: Profile for high-performance computing workloads
        responses:
          '200':
            description: Target node profile created successfully
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
                      example: high-performance-profile registered successfully in SOCA
          '400':
            description: Bad request - missing or invalid parameters
          '401':
            description: Authentication required
          '403':
            description: Admin access required
          '409':
            description: Conflict - profile name already exists
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("profile_name", type=str, location="form")
        parser.add_argument("pattern_allowed_instance_types", type=str, location="form")
        parser.add_argument("allowed_subnet_ids", type=str, location="form")
        parser.add_argument("max_root_size", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        args = parser.parse_args()

        logger.debug(
            f"Received TargetNodeProfilesManager Registration Request args {args}"
        )
        _profile_name = args["profile_name"]
        _pattern_allowed_instance_types = args["pattern_allowed_instance_types"]
        _allowed_subnet_ids = args["allowed_subnet_ids"]
        _max_root_size_cast = SocaCastEngine(data=args["max_root_size"]).cast_as(int)
        if _max_root_size_cast.get("success") is not True:
            return SocaError.GENERIC_ERROR(
                helper=f"max_root_size must be a valid integer {args['max_root_size']}"
            ).as_flask()
        _max_root_size = _max_root_size_cast.get("message")
        _description = args.get("description", "")
        if _description and len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helper="Description cannot be greater than 500 characters"
            ).as_flask()
            
        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _required_input = [
            "profile_name",
            "pattern_allowed_instance_types",
            "allowed_subnet_ids",
            "max_root_size",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        # Validate Subnets
        _soca_private_subnets = (
            SocaConfig(key="/configuration/PrivateSubnets")
            .get_value(return_as=list)
            .get("message")
        )

        try:
            _proposed_subnets = [
                item.strip() for item in args["allowed_subnet_ids"].split(",")
            ]
        except Exception:
            return SocaError.GENERIC_ERROR(
                helper="allowed_subnet_ids must be a comma separated strings of subnets"
            ).as_flask()

        for _subnet in _proposed_subnets:
            if _subnet not in _soca_private_subnets:
                return SocaError.GENERIC_ERROR(
                    helper=f"Subnet {_subnet} is not a valid private subnet. Update the value or add this subnet to /configuration/PrivateSubnets",
                ).as_flask()

        # Validate list of EC2 instances
        _proposed_pattern_allowed_instance_types = [
            item.strip() for item in args["pattern_allowed_instance_types"].split(",")
        ]
        _instances_list = ec2_helper.get_instance_types_by_architecture(
            instance_type_pattern=_proposed_pattern_allowed_instance_types
        )
        if _instances_list.get("success") is True:
            _allowed_instance_types = _instances_list.get("message")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"pattern_allowed_instance_types must be a valid EC2 instance type pattern",
            ).as_flask()

        try:
            # Round up to the next integer size versus using int() or round() which can round _down_
            _max_root_size: int = math.ceil(float(args["max_root_size"]))
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper=f"max_root_size must be a valid integer",
            ).as_flask()

        if TargetNodeProfiles.query.filter_by(
            is_active=True, profile_name=_profile_name
        ).first():
            return SocaError.GENERIC_ERROR(
                helper=f"Profile name {_profile_name} already exists, pick a different name or deactivate the existing one",
            ).as_flask()

        _new_profile_creation = TargetNodeProfiles(
            profile_name=_profile_name,
            allowed_subnet_ids=",".join(_proposed_subnets),
            pattern_allowed_instance_types=_pattern_allowed_instance_types,
            allowed_instance_types=json.dumps(_allowed_instance_types),
            max_root_size=_max_root_size,
            description=_description,
            is_active=True,
            created_on=datetime.now(timezone.utc),
            created_by=_user,
        )

        try:
            db.session.add(_new_profile_creation)
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_new_profile_creation,
                helper=f"Unable to add Target Node Profile {_profile_name} to DB due to {err}",
            )

        return SocaResponse(
            success=True,
            message=_(f"{_profile_name} registered successfully in SOCA"),
        ).as_flask()

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def delete(self):
        """
        Delete a target node profile
        ---
        openapi: 3.1.0
        operationId: deleteTargetNodeProfile
        tags:
          - Target Nodes
        summary: Delete an existing target node profile
        description: Deactivates a target node profile if it's not being used by any software stacks
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin.user
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
                  - profile_id
                properties:
                  profile_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the profile to delete
                    example: "2"
        responses:
          '200':
            description: Target node profile deleted successfully
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
                      example: Target Node Profile removed from SOCA
          '400':
            description: Bad request - missing or invalid parameters
          '401':
            description: Authentication required
          '403':
            description: Forbidden - cannot delete default profile or profile in use
          '404':
            description: Profile not found or already deactivated
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received Target Node Profile Delete for {args}")

        if args["profile_id"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="profile_id").as_flask()

        _validate_profile_id = SocaCastEngine(data=args["profile_id"]).cast_as(int)

        if _validate_profile_id.get("success") is True:
            _profile_id = _validate_profile_id.get("message")
        else:
            return SocaError.IMAGE_DEREGISTER_ERROR(
                image_label=args["profile_id"],
                helper=f"profile_id does not seems to be a valid integer {args['profile_id']}",
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _check_profile = TargetNodeProfiles.query.filter_by(
            id=_profile_id, is_active=True
        ).first()

        if _check_profile:

            if _check_profile.id == 1 or _check_profile.profile_name == "default":
                return SocaError.GENERIC_ERROR(
                    helper=f"Profile {_check_profile.profile_name} is a default profile and cannot be deleted"
                ).as_flask()

            _software_stack_using_profile = TargetNodeSoftwareStacks.query.filter_by(
                target_node_profile_id=_check_profile.id, is_active=True
            )
            if _software_stack_using_profile.count() > 0:
                return SocaError.GENERIC_ERROR(
                    helper=f"Profile {_check_profile.profile_name} is used by {_software_stack_using_profile.count()} software stacks. Update them first."
                ).as_flask()

            try:
                _check_profile.is_active = False
                _check_profile.deactivated_on = datetime.now(timezone.utc)
                _check_profile.deactivated_by = _user
                db.session.commit()
            except Exception as err:
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query=_check_profile,
                    helper=f"Unable to deactivate target node profile {_profile_id} due to {err}",
                ).as_flask()

            logger.info(f"Target Node Profile deleted from SOCA")
            return SocaResponse(
                success=True, message=_(f"Target Node Profile removed from SOCA")
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Target Node Profile not found or already deactivated",
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def put(self):
        r"""
        Update a target node profile
        ---
        openapi: 3.1.0
        operationId: updateTargetNodeProfile
        tags:
          - Target Nodes
        summary: Update an existing target node profile
        description: Updates the configuration of an existing target node profile including instance types, subnets, and resource limits
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin.user
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
                  - profile_id
                  - pattern_allowed_instance_types
                  - allowed_subnet_ids
                  - max_root_size
                properties:
                  profile_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the profile to update
                    example: "2"
                  pattern_allowed_instance_types:
                    type: string
                    pattern: '^[a-z0-9.*,\s]+$'
                    description: Comma-separated list of allowed EC2 instance type patterns
                    example: "m5.*,c5.*,r5.*"
                  allowed_subnet_ids:
                    type: string
                    pattern: '^subnet-[a-f0-9]{8,17}(,subnet-[a-f0-9]{8,17})*$'
                    description: Comma-separated list of allowed subnet IDs
                    example: "subnet-12345678,subnet-87654321"
                  max_root_size:
                    type: string
                    pattern: '^[0-9]+$'
                    description: Maximum root disk size in GB
                    example: "200"
                  description:
                    type: string
                    maxLength: 500
                    description: Profile description (max 500 characters)
                    example: Updated profile for high-performance computing workloads
        responses:
          '200':
            description: Target node profile updated successfully
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
                      example: Profile updated successfully
          '400':
            description: Bad request - missing or invalid parameters
          '401':
            description: Authentication required
          '403':
            description: Admin access required
          '404':
            description: Profile not found
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="form")
        parser.add_argument("pattern_allowed_instance_types", type=str, location="form")
        parser.add_argument("allowed_subnet_ids", type=str, location="form")
        parser.add_argument("max_root_size", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        args = parser.parse_args()
        _pattern_allowed_instance_types = args["pattern_allowed_instance_types"]
        _allowed_subnet_ids = args["allowed_subnet_ids"]
        _max_root_size_cast = SocaCastEngine(data=args["max_root_size"]).cast_as(int)
        if _max_root_size_cast.get("success") is not True:
            return SocaError.GENERIC_ERROR(
                helper=f"max_root_size must be a valid integer {args['max_root_size']}"
            ).as_flask()
        _max_root_size = _max_root_size_cast.get("message")
        _profile_id = args["profile_id"]
        _description = args.get("description", "")
        if _description and len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helper="Description cannot be greater than 500 characters"
            ).as_flask()
        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _required_input = [
            "pattern_allowed_instance_types",
            "allowed_subnet_ids",
            "max_root_size",
            "profile_id",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        _profile_id_cast = SocaCastEngine(data=_profile_id).cast_as(int)
        if _profile_id_cast.get("success") is True:
            _profile_id = _profile_id_cast.get("message")
            _profile_to_update = TargetNodeProfiles.query.filter_by(
                id=_profile_id, is_active=True
            ).first()
            if not _profile_to_update:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find existing target node profile with id {_profile_id}",
                ).as_flask()
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"profile_id does not seems to be a valid integer",
            ).as_flask()

        # Validate Subnets
        _soca_private_subnets = (
            SocaConfig(key="/configuration/PrivateSubnets")
            .get_value(return_as=list)
            .get("message")
        )

        try:
            _proposed_subnets = [
                item.strip() for item in args["allowed_subnet_ids"].split(",")
            ]
        except Exception:
            return SocaError.GENERIC_ERROR(
                helper="allowed_subnet_ids must be a comma separated strings of subnets"
            ).as_flask()

        for _subnet in _proposed_subnets:
            if _subnet not in _soca_private_subnets:
                return SocaError.GENERIC_ERROR(
                    helper=f"Subnet {_subnet} is not a valid private subnet. Update the value or add this subnet to /configuration/PrivateSubnets",
                ).as_flask()

        # Validate list of EC2 instances
        _proposed_pattern_allowed_instance_types = [
            item.strip() for item in args["pattern_allowed_instance_types"].split(",")
        ]
        _instances_list = ec2_helper.get_instance_types_by_architecture(
            instance_type_pattern=_proposed_pattern_allowed_instance_types
        )
        if _instances_list.get("success") is True:
            _allowed_instance_types = _instances_list.get("message")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"pattern_allowed_instance_types must be a valid EC2 instance type pattern",
            ).as_flask()

        try:
            # Round up to the next integer size versus using int() or round() which can round _down_
            _max_root_size: int = math.ceil(float(args["max_root_size"]))
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper="max_root_size must be a valid integer",
            ).as_flask()

        try:
            _profile_to_update.allowed_subnet_ids = ",".join(_proposed_subnets)
            _profile_to_update.pattern_allowed_instance_types = (
                _pattern_allowed_instance_types
            )
            _profile_to_update.allowed_instance_types = json.dumps(
                _allowed_instance_types
            )
            _profile_to_update.max_root_size = _max_root_size
            _profile_to_update.description = _description
            db.session.add(_profile_to_update)
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_profile_to_update,
                helper=f"Unable to edit Target Node Profile to DB due to {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=_(f"Profile updated successfully"),
        ).as_flask()
