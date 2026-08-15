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

from flask import request
from flask_babel import gettext as _
from flask_restful import Resource, reqparse
import logging
from decorators import admin_api, restricted_api, private_api, feature_flag
import os
import stat
import sys
import base64
import binascii
from utils.error import SocaError
from utils.response import SocaResponse
from utils.user_filesystems_acls import check_user_permission, Permissions
from pathlib import Path
import config

logger = logging.getLogger("soca_logger")


class Files(Resource):
    @private_api
    @feature_flag(flag_name="FILE_BROWSER", mode="api")
    def get(self):
        r"""
        Retrieve content of a file
        ---
        openapi: 3.1.0
        operationId: getFileContent
        tags:
          - System Files
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA authentication token
            example: abc123token
          - name: file
            in: query
            schema:
              type: string
              pattern: '^/[a-zA-Z0-9_./\-]+$'
              minLength: 1
            required: true
            description: Full path to the file to read
            example: /home/user/config.txt
        responses:
          '200':
            description: File content retrieved successfully
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
                      example: "File content here..."
          '400':
            description: Missing file parameter or file not found
          '401':
            description: Authentication required
          '403':
            description: Permission denied or restricted path
        """
        parser = reqparse.RequestParser()
        parser.add_argument("file", type=str, location="args")
        args = parser.parse_args()
        _generic_error_message = (
            "Unable to retrieve file content. Check logs for additional details."
        )

        if not args.get("file", ""):
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="file").as_flask()
        try:
            file_to_read = Path(args["file"])
            if not file_to_read.is_file():
                logger.error(f"{file_to_read} is not a file")
                return SocaError.GENERIC_ERROR(helper=_generic_error_message).as_flask()

            _folder = file_to_read.parent.resolve()
            if any(_folder.is_relative_to(Path(_p).resolve()) for _p in config.Config.PATH_TO_RESTRICT):
                logger.error(f"{file_to_read=} is in a restricted path")
                return SocaError.GENERIC_ERROR(helper=_generic_error_message).as_flask()

            if (
                check_user_permission(
                    user=request.headers.get("X-EDH-USER"),
                    permissions=Permissions.READ,
                    path=file_to_read,
                    paths_to_restrict=config.Config.PATH_TO_RESTRICT,
                )
                is True
            ):
                try:
                    # Atomic open; O_NOFOLLOW refuses a symlink swapped in after the permission check, O_NONBLOCK avoids a FIFO block (uwsgi runs as root).
                    _fd = os.open(file_to_read, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    if not stat.S_ISREG(os.fstat(_fd).st_mode):
                        os.close(_fd)
                        return SocaError.GENERIC_ERROR(helper=_generic_error_message).as_flask()
                    with os.fdopen(_fd, "r", closefd=True) as file:
                        return SocaResponse(
                            success=True, message=file.read()
                        ).as_flask()
                except Exception as err:
                    logger.error(f"Unable to read {file_to_read} due to {err}")
                    return SocaError.GENERIC_ERROR(
                        helper=_generic_error_message
                    ).as_flask()
            else:
                logger.error("User does not have the permission to read this file.")
                return SocaError.GENERIC_ERROR(helper=_generic_error_message).as_flask()

        except UnicodeDecodeError:
            return SocaError.GENERIC_ERROR(
                helper=f"{args['file']} is not readable (this is probably not a valid text format)"
            ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error(f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}")
            return SocaError.GENERIC_ERROR(helper=_generic_error_message).as_flask()

    @private_api
    @feature_flag(flag_name="FILE_BROWSER", mode="api")
    def post(self):
        """
        Create or update a file
        ---
        openapi: 3.1.0
        operationId: createOrUpdateFile
        tags:
          - System Files
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA authentication token
            example: abc123token
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - file_name
                  - file_content
                properties:
                  file_name:
                    type: string
                    format: base64
                    minLength: 1
                    description: Base64 encoded file path
                    example: L2hvbWUvdXNlci9jb25maWcudHh0
                  file_content:
                    type: string
                    format: base64
                    minLength: 1
                    description: Base64 encoded file content
                    example: SGVsbG8gV29ybGQ=
        responses:
          '200':
            description: File created/updated successfully
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
                      example: File Updated.
          '400':
            description: Missing parameters or invalid base64 encoding
          '401':
            description: Authentication required
          '403':
            description: Permission denied to write file
        """
        parser = reqparse.RequestParser()
        parser.add_argument("file_name", type=str, location="form")
        parser.add_argument("file_content", type=str, location="form")
        args = parser.parse_args()
        _generic_error_message = _("Unable to create file. Check logs for additional info")
        if not args.get("file_name", ""):
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="file_name").as_flask()
        if not args.get("file_content", ""):
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="file_content"
            ).as_flask()

        try:
            file_name = Path(base64.b64decode(args["file_name"]).decode("utf-8"))
            file_content = base64.b64decode(args["file_content"]).decode("utf-8")
        except binascii.Error:
            logger.error(
                f"Unable to decode payload. Make sure you have encoded the data with b64"
            )
            return SocaError.GENERIC_ERROR(helper=_generic_error_message).as_flask()
        except Exception as err:
            logger.error(f"Unable to decode payload due to {err}")
            return SocaError.GENERIC_ERROR(helper=_generic_error_message)

        logger.info(f"Receive file Update request for _{file_name}_")

        try:
            if not file_name.is_file():
                return SocaError.GENERIC_ERROR(
                    helper=f"{file_name} does not sems to be a file."
                ).as_flask()

            if (
                check_user_permission(
                    user=request.headers.get("X-EDH-USER"),
                    permissions=Permissions.WRITE,
                    path=file_name.parent,  # validate if user has write permission to the folder where the file will be created/updated
                )
                is True
            ):
                try:
                    # O_NOFOLLOW refuses a symlink swapped in after the parent-dir permission check, O_NONBLOCK avoids a FIFO block (uwsgi runs as root).
                    _fd = os.open(file_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644)
                    if not stat.S_ISREG(os.fstat(_fd).st_mode):
                        os.close(_fd)
                        return SocaError.GENERIC_ERROR(helper=_generic_error_message).as_flask()
                    with os.fdopen(_fd, "w", closefd=True) as file:
                        file.write(file_content)
                    return SocaResponse(
                        success=True, message=_("File Updated.")
                    ).as_flask()
                except Exception as err:
                    logger.error(f"Unable to create {file_name} due to {err}")
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to create file"
                    ).as_flask()
            else:
                return SocaError.GENERIC_ERROR(
                    helper="You do not have permission to update this file"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to update {file_name}: {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
