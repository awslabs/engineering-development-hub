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
import ast
import re
import math
from models import Projects
import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse
from utils.config import SocaConfig
from utils.error import SocaError
from botocore.exceptions import ClientError
from decorators import admin_api
from flask import request

logger = logging.getLogger("soca_logger")


budgets_client = utils_boto3.get_boto(service_name="budgets").message
sts_client = utils_boto3.get_boto(service_name="sts").message


class AwsBudgets(Resource):
    @staticmethod
    @admin_api
    def get():
        """
        List all available AWS budgets
        ---
        openapi: 3.1.0
        operationId: listAwsBudgets
        tags:
          - Cost Management
        summary: List all available AWS budgets
        description: Retrieves a list of all AWS budgets available in the current account
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
        responses:
          '200':
            description: List of available budgets retrieved successfully
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
                        type: string
                        minLength: 1
                        maxLength: 100
                      description: List of budget names
                      example: ["monthly-budget", "quarterly-budget", "project-alpha-budget"]
          '401':
            description: Unauthorized - invalid authentication
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
                      example: "Authentication failed"
          '403':
            description: Forbidden - insufficient permissions
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
                      example: "Admin access required"
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
                      example: "Error retrieving budget list, check logs for more details."
        """
        try:
            _identity = sts_client.get_caller_identity()
            account_id = _identity["Account"]
            _partition = _identity["Arn"].split(":")[1]
            if _partition == "aws-us-gov":
                logger.info("AWS Budgets is not callable in the aws-us-gov partition; returning empty budget list.")
                return SocaResponse(success=True, message=[]).as_flask()
            budgets_response = budgets_client.describe_budgets(AccountId=account_id)
            budgets = []
            for budget in budgets_response.get("Budgets", []):
                budget_name = budget["BudgetName"]
                budgets.append(budget_name)

            return SocaResponse(success=True, message=budgets).as_flask()

        except Exception as e:
            logger.error(f"Error retrieving budget list: {str(e)}")
            return SocaError.GENERIC_ERROR(
                helper=f"Error retrieving budget list, check logs for more details."
            ).as_flask()
