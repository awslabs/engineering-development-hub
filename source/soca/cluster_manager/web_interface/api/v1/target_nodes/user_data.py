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
from datetime import datetime, timezone
from models import (
    db,
    user_data_target_node_software_stack_association,
    VirtualDesktopProfiles,
    SoftwareStacks,
    TargetNodeUserData,
    TargetNodeSoftwareStacks,
)
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.jinjanizer import SocaJinja2Renderer
from flask import request
from flask_babel import gettext as _
from sqlalchemy.orm import joinedload
import base64


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class TargetNodeUserDataManager(Resource):

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def get(self):
        """
        Get user data templates
        ---
        openapi: 3.1.0
        operationId: getUserDataTemplates
        tags:
          - Target Nodes
          - User Data
        summary: Get user data templates
        description: Retrieve user data templates for target nodes
        security:
          - socaAuth: []
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
              example: "admin"
            description: SOCA username for authentication
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              minLength: 1
              example: "abc123token"
            description: SOCA authentication token
          - in: query
            name: template_id
            required: false
            schema:
              type: string
              pattern: '^[0-9]+$'
              example: "1"
            description: Specific template ID to retrieve
        responses:
          '200':
            description: User data templates retrieved successfully
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
                      example: {"1": {"id": 1, "template_name": "default", "description": "Default template"}}
          '400':
            description: Invalid template_id parameter
          '401':
            description: Authentication required
          '403':
            description: Admin access required
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-EDH-USER
              description: SOCA authentication using username and token headers
        """
        parser = reqparse.RequestParser()
        parser.add_argument("template_id", type=str, location="args")
        args = parser.parse_args()

        logger.debug(f"List User Data Template with {request.args}")

        _template_info = {}
        if args["template_id"] is None:
            _list_user_data_templates = TargetNodeUserData.query.options(
                joinedload(TargetNodeUserData.target_node_software_stacks)
            ).filter_by(is_active=True)

        else:
            if (
                cast_result := SocaCastEngine(data=args["template_id"]).cast_as(int)
            ).get("success"):
                _template_id = cast_result.get("message")
                _list_user_data_templates = TargetNodeUserData.query.options(
                    joinedload(TargetNodeUserData.target_node_software_stacks)
                ).filter_by(id=_template_id, is_active=True)
            else:
                return SocaError.GENERIC_ERROR(
                    helper="template_id does not seems to be a valid integer"
                )

        logger.debug(f"Found {_list_user_data_templates.all()}")

        if _list_user_data_templates.count() == 0:
            logger.warning("No User Data Template found")
            return SocaResponse(success=True, message={}).as_flask()
        else:
            for _template in _list_user_data_templates.all():
                _template_info[_template.id] = _template.as_dict()

            return SocaResponse(success=True, message=_template_info).as_flask()

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def post(self):
        """
        Create a new user data template
        ---
        openapi: 3.1.0
        operationId: createUserDataTemplate
        tags:
          - Target Nodes
          - User Data
        summary: Create a new user data template
        description: Create a new user data template for target nodes
        security:
          - socaAuth: []
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
              example: "admin"
            description: SOCA username for authentication
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              minLength: 1
              example: "abc123token"
            description: SOCA authentication token
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - template_name
                  - description
                  - user_data
                properties:
                  template_name:
                    type: string
                    minLength: 1
                    maxLength: 100
                    pattern: '^[a-zA-Z0-9._-]+$'
                    description: Name for the user data template
                    example: "my-custom-template"
                  description:
                    type: string
                    minLength: 1
                    maxLength: 500
                    description: Description of the template (max 500 characters)
                    example: "Custom user data template for CAE workloads"
                  user_data:
                    type: string
                    minLength: 1
                    maxLength: 16384
                    pattern: '^#!/bin/bash'
                    description: EC2 user data script (max 16KB)
                    example: "#!/bin/bash\necho 'Hello World'"
        responses:
          '200':
            description: User data template created successfully
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
                      example: "User Data template has been created successfully"
          '400':
            description: Missing required parameters or validation error
          '401':
            description: Authentication required
          '403':
            description: Admin access required
          '409':
            description: Template name already exists
          '500':
            description: Database error during creation
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-EDH-USER
              description: SOCA authentication using username and token headers
        """
        parser = reqparse.RequestParser()
        parser.add_argument("template_name", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("user_data", type=str, location="form")
        args = parser.parse_args()

        logger.debug(f"Received TargetNodeUserDataManager Create Request args {args}")
        _template_name = args.get("template_name", "")
        _description = args.get("description", "")
        _user_data = args.get("user_data", "")

        if not _template_name:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="template_name"
            ).as_flask()

        if not _description:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="description"
            ).as_flask()

        if not _user_data:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user_data").as_flask()

        byte_size = len(_user_data.encode("utf-8"))
        kb_size = byte_size / 1024
        logger.debug(f"EC2 User Data must be less than 16 KB, detected {kb_size:.1f}")
        if byte_size > 16 * 1024:
            return SocaError.GENERIC_ERROR(
                helper=f"User Data on EC2 are limited to 16 KB. Current size is {kb_size:.1f} KB"
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        if len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helper="Description cannot be greater than 500 characters"
            ).as_flask()

        if TargetNodeUserData.query.filter_by(
            is_active=True, template_name=_template_name
        ).first():
            return SocaError.GENERIC_ERROR(
                helper=f"Template name {_template_name} already exists, pick a different name or deactivate the existing one",
            ).as_flask()

       
        _is_valid_template = SocaJinja2Renderer.validate_template(data=_user_data)
        if _is_valid_template.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=f"Specified J2 template has invalid syntax {_is_valid_template.get('message')}").as_flask()
        
        try:
            _user_data_encoded_bytes = base64.b64encode(_user_data.encode("utf-8"))
            _user_data_encoded_string = _user_data_encoded_bytes.decode("utf-8")
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to encode user data to base64 due to {err}"
            ).as_flask()

        _new_template_request = TargetNodeUserData(
            template_name=_template_name,
            description=_description,
            user_data=_user_data_encoded_string,
            is_active=True,
            created_on=datetime.now(timezone.utc),
            created_by=_user,
        )

        try:
            db.session.add(_new_template_request)
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_new_template_request,
                helper=f"Unable to add new user data template to DB due to {err}",
            )

        return SocaResponse(
            success=True,
            message=_(f"User Data template has been created successfully"),
        ).as_flask()

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def delete(self):
        """
        Delete a user data template
        ---
        openapi: 3.1.0
        operationId: deleteUserDataTemplate
        tags:
          - Target Nodes
          - User Data
        summary: Delete a user data template
        description: Delete a user data template for target nodes
        security:
          - socaAuth: []
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
              example: "admin"
            description: SOCA username for authentication
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              minLength: 1
              example: "abc123token"
            description: SOCA authentication token
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - template_id
                properties:
                  template_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the template to delete
                    example: "2"
        responses:
          '200':
            description: User data template deleted successfully
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
                      example: "User Data Template deleted successfully"
          '400':
            description: Missing template_id or invalid ID
          '401':
            description: Authentication required
          '403':
            description: Admin access required or default template cannot be deleted
          '404':
            description: Template not found
          '409':
            description: Template is in use by active software stacks
          '500':
            description: Database error during deletion
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-EDH-USER
              description: SOCA authentication using username and token headers
        """
        parser = reqparse.RequestParser()
        parser.add_argument("template_id", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received User Data Template Delete for {args}")

        if args["template_id"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="template_id"
            ).as_flask()

        _validate_template_id = SocaCastEngine(data=args["template_id"]).cast_as(int)

        if _validate_template_id.get("success") is True:
            _template_id = _validate_template_id.get("message")
        else:
            return SocaError.IMAGE_DEREGISTER_ERROR(
                image_label=args["template_id"],
                helper=f"template_id does not seems to be a valid integer {args['template_id']}",
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _check_template_id = TargetNodeUserData.query.filter_by(
            id=_template_id, is_active=True
        ).first()

        if _check_template_id:
            if (
                _check_template_id.id == 1
                or _check_template_id.template_name == "default"
            ):
                return SocaError.GENERIC_ERROR(
                    helper=f"Profile {_check_template_id.template_name} is a default profile and cannot be deleted"
                ).as_flask()

            _software_stack_using_user_data = TargetNodeSoftwareStacks.query.join(
                user_data_target_node_software_stack_association
            ).filter(
                user_data_target_node_software_stack_association.c.template_id
                == _check_template_id.id,
                TargetNodeSoftwareStacks.is_active == True,
            )

            if _software_stack_using_user_data.count() > 0:
                return SocaError.GENERIC_ERROR(
                    helper=f"User Data template is being used by {_software_stack_using_user_data.count()} active target node software stacks. Update them first."
                ).as_flask()

            try:
                _check_template_id.is_active = False
                _check_template_id.deactivated_on = datetime.now(timezone.utc)
                _check_template_id.deactivated_by = _user
                db.session.commit()
            except Exception as err:
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query=_check_template_id,
                    helper=f"Unable to deactivate User Data Template {_check_template_id} due to {err}",
                ).as_flask()

            return SocaResponse(
                success=True, message=_(f"User Data Template deleted successfully")
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"User Data Template not found or already deactivated",
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def put(self):
        """
        Update an existing user data template
        ---
        openapi: 3.1.0
        operationId: updateUserDataTemplate
        tags:
          - Target Nodes
          - User Data
        summary: Update an existing user data template
        description: Update an existing user data template for target nodes
        security:
          - socaAuth: []
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
              example: "admin"
            description: SOCA username for authentication
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              minLength: 1
              example: "abc123token"
            description: SOCA authentication token
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - template_id
                  - description
                  - user_data
                properties:
                  template_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the template to update
                    example: "2"
                  description:
                    type: string
                    minLength: 1
                    maxLength: 500
                    description: Updated description (max 500 characters)
                    example: "Updated custom template description"
                  user_data:
                    type: string
                    minLength: 1
                    maxLength: 16384
                    pattern: '^#!/bin/bash\r'
                    description: Updated EC2 user data script (max 16KB)
                    example: "#!/bin/bash\r\necho 'Updated script'"
        responses:
          '200':
            description: User data template updated successfully
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
                      example: "User Data Template has been updated successfully"
          '400':
            description: Missing required parameters or validation error
          '401':
            description: Authentication required
          '403':
            description: Admin access required
          '404':
            description: Template not found
          '500':
            description: Database error during update
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-EDH-USER
              description: SOCA authentication using username and token headers
        """
        parser = reqparse.RequestParser()
        parser.add_argument("template_id", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("user_data", type=str, location="form")
        args = parser.parse_args()

        logger.debug(f"Received TargetNodeUserDataManager Edit Request args {args}")
        _description = args.get("description", "")
        _user_data = args.get("user_data", "")
        _template_id = args.get("template_id", None)

        if _template_id is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="template_id"
            ).as_flask()

        if not _description:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="description"
            ).as_flask()
        if not _user_data:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user_data").as_flask()

        byte_size = len(_user_data.encode("utf-8"))
        kb_size = byte_size / 1024
        logger.debug(f"EC2 User Data must be less than 16 KB, detected {kb_size:.1f}")
        if byte_size > 16 * 1024:
            return SocaError.GENERIC_ERROR(
                helper=f"User Data on EC2 are limited to 16 KB. Current size is {kb_size:.1f} KB"
            )

        if not _user_data.startswith("#!/bin/bash\r"):
            return SocaError.GENERIC_ERROR(
                helper="User Data must start with #!/bin/bash<return carriage>"
            ).as_flask()
        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        if len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helper="Description cannot be greater than 500 characters"
            ).as_flask()

        _template_id_cast = SocaCastEngine(data=_template_id).cast_as(int)
        if _template_id_cast.get("success") is True:
            _template_id = _template_id_cast.get("message")
            _template_to_update = TargetNodeUserData.query.filter_by(
                id=_template_id, is_active=True
            ).first()

            if not _template_to_update:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find existing user data template with id {_template_id}",
                ).as_flask()
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"template_id does not seems to be a valid integer",
            ).as_flask()

        try:
            _user_data_encoded_bytes = base64.b64encode(_user_data.encode("utf-8"))
            _user_data_encoded_string = _user_data_encoded_bytes.decode("utf-8")
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to encode user data to base64 due to {err}"
            ).as_flask()

        try:
            # note: name cannot be changed
            _template_to_update.description = _description
            _template_to_update.user_data = _user_data_encoded_string
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_template_to_update,
                helper=f"Unable to update user data template to DB due to {err}",
            )

        return SocaResponse(
            success=True,
            message=_(f"User Data Template has been updated successfully"),
        ).as_flask()
