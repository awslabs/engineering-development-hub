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


from flask_restful import Resource
from flask import request
import logging
from datetime import datetime, date
from decorators import private_api, feature_flag
import utils.aws.ec2_helper as utils_ec2
from utils.config import SocaConfig
from utils.error import SocaError

logger = logging.getLogger("soca_logger")


def _json_safe(obj):
    """Recursively convert datetime objects to ISO strings for JSON serialization."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


class ListLoginNodes(Resource):
    @private_api
    @feature_flag(flag_name="LOGIN_NODES", mode="api")
    def get(self):
        """
        List all login node instances
        ---
        openapi: 3.1.0
        operationId: listLoginNodes
        tags:
          - Login Nodes
        summary: List all running login node instances
        description: Retrieve full EC2 instance details for all running login nodes in the SOCA cluster
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: SOCA username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: SOCA authentication token
        responses:
          '200':
            description: Login node instances retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: array
                      description: List of EC2 instance objects for running login nodes
                      items:
                        type: object
                        description: EC2 instance description (AWS DescribeInstances format)
          '401':
            description: Authentication required
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
                      example: "Authentication required"
          '500':
            description: AWS API error
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
                      example: "AWS API error"
        """
        logger.debug("Fetching all Login Nodes IPs for your SOCA environment")
        user = request.headers.get("X-EDH-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _result = utils_ec2.describe_instances_paginate(
            filters=[
                {"Name": "tag:edh:NodeType", "Values": ["login_node"]},
                {"Name": "instance-state-name", "Values": ["running"]},
                {
                    "Name": "tag:edh:ClusterId",
                    "Values": [
                        SocaConfig(key="/configuration/ClusterId")
                        .get_value()
                        .get("message")
                    ],
                },
            ]
        )

        if _result.get("success") is False:
            return {"success": False, "message": _result.get("message")}, 500

        login_nodes = _json_safe(_result.get("message"))
        logger.debug(f"Login nodes list: {login_nodes}")
        return {"success": True, "message": login_nodes}, 200
