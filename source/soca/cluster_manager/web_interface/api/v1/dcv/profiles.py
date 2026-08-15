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
from models import db, VirtualDesktopProfiles, SoftwareStacks
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


class VirtualDesktopProfilesManager(Resource):

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        """
        Get virtual desktop profiles
        ---
        openapi: 3.1.0
        operationId: getVirtualDesktopProfiles
        tags:
          - Virtual Desktops
        summary: Get virtual desktop profiles
        description: Retrieves virtual desktop profiles, optionally filtered by profile ID (admin access required)
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              example: "admin.user"
            description: SOCA username for authentication (must be admin)
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            description: SOCA authentication token
          - in: query
            name: profile_id
            required: false
            schema:
              type: string
              example: "1"
            description: Specific profile ID to retrieve (returns all if not specified)
        responses:
          '200':
            description: Virtual desktop profiles retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      oneOf:
                        - type: string
                          example: "No Virtual Desktop Profiles found"
                        - type: object
                          additionalProperties:
                            type: object
                            properties:
                              id:
                                type: integer
                                example: 1
                              profile_name:
                                type: string
                                example: "Standard Profile"
                              description:
                                type: string
                                example: "Standard virtual desktop profile"
                              allowed_subnet_ids:
                                type: string
                                example: "subnet-12345,subnet-67890"
                              pattern_allowed_instance_types:
                                type: string
                                example: "m5.*,t3.*"
                              max_root_size:
                                type: integer
                                example: 50
                              software_stack_ids:
                                type: array
                                items:
                                  type: integer
                                example: [1, 2, 3]
          '400':
            description: Invalid profile ID
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "profile_id does not seems to be a valid integer"
          '403':
            description: Insufficient permissions or feature not enabled
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 403
                    message:
                      type: string
                      example: "Admin access required"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="args")
        args = parser.parse_args()

        logger.debug(f"List Virtual Desktops Profile with {request.args}")
        _profile_info = {}
        if args["profile_id"] is None:
            _list_vdi_profiles = VirtualDesktopProfiles.query.filter_by(
                is_active=True
            ).options(joinedload(VirtualDesktopProfiles.software_stacks))
        else:
            if (
                cast_result := SocaCastEngine(data=args["profile_id"]).cast_as(int)
            ).get("success"):
                _profile_id = cast_result.get("message")
                _list_vdi_profiles = VirtualDesktopProfiles.query.filter_by(
                    id=_profile_id, is_active=True
                ).options(joinedload(VirtualDesktopProfiles.software_stacks))
            else:
                return SocaError.GENERIC_ERROR(
                    helper="profile_id does not seems to be a valid integer"
                )

        if _list_vdi_profiles.count() == 0:
            logger.warning("No Virtual Desktop Profiles found")
            return SocaResponse(
                success=True, message=_("No Virtual Desktop Profiles found")
            ).as_flask()
        else:
            for _profile in _list_vdi_profiles.all():
                _profile_info[_profile.id] = _profile.as_dict()
                _profile_info[_profile.id]["software_stack_ids"] = [
                    stack.id for stack in _profile.software_stacks
                ]

            return SocaResponse(success=True, message=_profile_info).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        """
        Create a new virtual desktop profile
        ---
        openapi: 3.1.0
        operationId: createVirtualDesktopProfile
        tags:
          - Virtual Desktops
        summary: Create virtual desktop profile
        description: Creates a new virtual desktop profile with specified configuration (admin access required)
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              example: "admin.user"
            description: SOCA username for authentication (must be admin)
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            description: SOCA authentication token
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
                  - description
                properties:
                  profile_name:
                    type: string
                    description: Name for the virtual desktop profile
                    example: "Engineering Profile"
                  pattern_allowed_instance_types:
                    type: string
                    description: Comma-separated patterns for allowed EC2 instance types
                    example: "m5.*,c5.*,r5.*"
                  allowed_subnet_ids:
                    type: string
                    description: Comma-separated list of allowed subnet IDs
                    example: "subnet-12345678,subnet-87654321"
                  max_root_size:
                    type: string
                    description: Maximum root volume size in GB
                    example: "100"
                  description:
                    type: string
                    maxLength: 500
                    description: Profile description (max 500 characters)
                    example: "Profile for engineering workloads with high compute requirements"
        responses:
          '200':
            description: Virtual desktop profile created successfully
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
                      example: "Engineering Profile registered successfully in SOCA"
          '400':
            description: Invalid request parameters
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "Missing required parameter: profile_name"
          '401':
            description: Authentication failed
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 401
                    message:
                      type: string
                      example: "Missing required header: X-EDH-USER"
          '403':
            description: Insufficient permissions or feature not enabled
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 403
                    message:
                      type: string
                      example: "Admin access required"
          '409':
            description: Profile name already exists
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Profile name Engineering Profile already exists"
          '500':
            description: Database or validation error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to add VDI Profile to DB"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("profile_name", type=str, location="form")
        parser.add_argument("pattern_allowed_instance_types", type=str, location="form")
        parser.add_argument("allowed_subnet_ids", type=str, location="form")
        parser.add_argument("max_root_size", type=str, location="form")
        parser.add_argument("description", type=str, location="form")

        args = parser.parse_args()

        logger.debug(
            f"Received VirtualDesktopProfilesManager Registration Request args {args}"
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
            "description",
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
                item.strip() for item in _allowed_subnet_ids.split(",")
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
                helper=f"_max_root_size must be a valid integer",
            ).as_flask()

        if VirtualDesktopProfiles.query.filter_by(
            is_active=True, profile_name=_profile_name
        ).first():
            return SocaError.GENERIC_ERROR(
                helper=f"Profile name {_profile_name} already exists, pick a different name or deactivate the existing one",
            ).as_flask()

        _new_profile_creation = VirtualDesktopProfiles(
            profile_name=_profile_name,
            description=_description,
            allowed_subnet_ids=",".join(_proposed_subnets),
            pattern_allowed_instance_types=_pattern_allowed_instance_types,
            allowed_instance_types=json.dumps(_allowed_instance_types),
            max_root_size=_max_root_size,
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
                helper=f"Unable to add VDI Profile {_profile_name} to DB due to {err}",
            )

        return SocaResponse(
            success=True,
            message=_(f"{_profile_name} registered successfully in SOCA"),
        ).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def delete(self):
        """
        Delete a virtual desktop profile
        ---
        openapi: 3.1.0
        operationId: deleteVirtualDesktopProfile
        tags:
          - Virtual Desktops
        summary: Delete virtual desktop profile
        description: Deactivates a virtual desktop profile by setting is_active to false (admin access required)
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              example: "admin.user"
            description: SOCA username for authentication (must be admin)
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            description: SOCA authentication token
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
                    description: ID of the profile to delete
                    example: "1"
        responses:
          '200':
            description: Virtual desktop profile deleted successfully
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
                      example: "VDI Profile removed from SOCA"
          '400':
            description: Missing or invalid profile ID
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "Missing required parameter: profile_id"
          '403':
            description: Insufficient permissions or feature not enabled
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 403
                    message:
                      type: string
                      example: "Admin access required"
          '404':
            description: Profile not found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "VDI Profile not found or already deactivated"
          '500':
            description: Database error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to deactivate software stack due to database error"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received Profile Delete for {args}")

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

        _check_profile = VirtualDesktopProfiles.query.filter_by(
            id=_profile_id, is_active=True
        ).first()

        if _check_profile:

            if _check_profile.id == 1 or _check_profile.profile_name == "default":
                return SocaError.GENERIC_ERROR(
                    helper=f"Profile {_check_profile.profile_name} is a default profile and cannot be deleted"
                ).as_flask()

            _software_stack_using_profile = SoftwareStacks.query.filter_by(
                virtual_desktop_profile_id=_check_profile.id, is_active=True
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
                    helper=f"Unable to deactivate software stack {_profile_id} due to {err}",
                ).as_flask()

            logger.info(f"VDI Profile deleted from SOCA")
            return SocaResponse(
                success=True, message=_(f"VDI Profile removed from SOCA")
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"VDI Profile not found or already deactivated",
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def put(self):
        """
        Update a virtual desktop profile
        ---
        openapi: 3.1.0
        operationId: updateVirtualDesktopProfile
        tags:
          - Virtual Desktops
        summary: Update virtual desktop profile
        description: Updates an existing virtual desktop profile with new configuration (admin access required)
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              example: "admin.user"
            description: SOCA username for authentication (must be admin)
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            description: SOCA authentication token
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
                  - description
                properties:
                  profile_id:
                    type: string
                    description: ID of the profile to update
                    example: "1"
                  pattern_allowed_instance_types:
                    type: string
                    description: Comma-separated patterns for allowed EC2 instance types
                    example: "m5.*,c5.*,r5.*"
                  allowed_subnet_ids:
                    type: string
                    description: Comma-separated list of allowed subnet IDs
                    example: "subnet-12345678,subnet-87654321"
                  max_root_size:
                    type: string
                    description: Maximum root volume size in GB
                    example: "100"
                  description:
                    type: string
                    maxLength: 500
                    description: Profile description (max 500 characters)
                    example: "Updated profile for engineering workloads"
        responses:
          '200':
            description: Virtual desktop profile updated successfully
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
                      example: "Profile updated successfully"
          '400':
            description: Invalid request parameters
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: profile_id"
          '401':
            description: Authentication failed
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required header: X-EDH-USER"
          '403':
            description: Insufficient permissions or feature not enabled
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Admin access required"
          '404':
            description: Profile not found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to find existing virtual desktop profile"
          '500':
            description: Database or validation error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to edit VDI Profile to DB"
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
            "description",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        _profile_id_cast = SocaCastEngine(data=_profile_id).cast_as(int)
        if _profile_id_cast.get("success") is True:
            _profile_id = _profile_id_cast.get("message")
            _profile_to_update = VirtualDesktopProfiles.query.filter_by(
                id=_profile_id, is_active=True
            ).first()
            if not _profile_to_update:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find existing virtual desktop profile with id {_profile_id}",
                ).as_flask()
        else:
            return SocaError.GENERIC_ERROR(
                helper="profile_id does not seems to be a valid integer",
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
                helper="pattern_allowed_instance_types must be a valid EC2 instance type pattern",
            ).as_flask()

        try:
            # Round up to the next integer size versus using int() or round() which can round _down_
            _max_root_size: int = math.ceil(float(args["max_root_size"]))
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper="_max_root_size must be a valid integer",
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
                helper=f"Unable to edit VDI Profile to DB due to {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=_("Profile updated successfully"),
        ).as_flask()
