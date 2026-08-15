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
from decorators import admin_api, private_api
from flask import request

logger = logging.getLogger("soca_logger")


budgets_client = utils_boto3.get_boto(service_name="budgets").message
sts_client = utils_boto3.get_boto(service_name="sts").message


class AwsBudgetInfo(Resource):
    @staticmethod
    @private_api
    def get():
        """
        Get AWS Budget information for a project
        ---
        openapi: 3.1.0
        operationId: getAwsBudgetInfo
        tags:
          - Cost Management
        summary: Retrieve AWS budget information for a project
        description: Gets current spend, forecasted spend, total budget, and usage percentage for a specific project's AWS budget
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
          - name: project_name
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 100
              pattern: '^[a-zA-Z0-9._-]+$'
            description: Name of the project
            example: "my-research-project"
        responses:
          '200':
            description: Budget information retrieved successfully
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
                      required:
                        - budget_exist
                        - current_spend
                        - forecast_spend
                        - forecast_available
                        - total_budget
                        - usage_pct
                      properties:
                        budget_exist:
                          type: boolean
                          description: Whether a budget exists for this project
                          example: true
                        current_spend:
                          type: number
                          minimum: 0
                          description: Current spend amount in USD
                          example: 1250.75
                        forecast_spend:
                          type: number
                          minimum: 0
                          description: Forecasted spend amount in USD
                          example: 1800.50
                        forecast_available:
                          type: boolean
                          description: Whether forecast data is available from AWS
                          example: true
                        total_budget:
                          type: number
                          minimum: 0
                          description: Total budget amount in USD
                          example: 5000.00
                        usage_pct:
                          type: number
                          minimum: 0
                          description: Usage percentage of total budget
                          example: 25.02
                        forecast_pct:
                          type: number
                          minimum: 0
                          description: Forecasted usage percentage of total budget
                          example: 36.01
          '400':
            description: Bad request - missing required parameters
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
                      example: "Missing required parameter: project_name"
          '404':
            description: Project or budget not found
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
                      example: "Project my-research-project not found or deactivated"
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
                      example: "Unable to retrieve budget information, check log for more details"
        """
        parser = reqparse.RequestParser()
        parser.add_argument(
            "project_name",
            type=str,
            location="args",
        )
        args = parser.parse_args()
        _project_name = args.get("project_name", "")

        if not _project_name:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="project_name"
            ).as_flask()
        else:
            logger.info(f"Retrieving associated AWS budget for project {_project_name}")
            _project_info = Projects.query.filter_by(
                is_active=True, project_name=_project_name
            ).first()
            if not _project_info:
                return SocaError.GENERIC_ERROR(
                    helper=f"Project  {_project_name} not found or deactivated",
                ).as_flask()
            else:
                _aws_budget = _project_info.aws_budget
                logger.info(f"AWS Budget for project {_project_name}: {_aws_budget}")
                if not _aws_budget:
                    logger.info(f"No AWS budget found for project {_project_name}")
                    message = {
                        "budget_exist": False,
                        "current_spend": 0,
                        "forecast_spend": 0,
                        "forecast_available": False,
                        "total_budget": 0,
                        "usage_pct": 0,
                    }
                else:
                    logger.info(f"Budget found for project {_project_name}")
                    try:
                        _identity = sts_client.get_caller_identity()
                        account_id = _identity["Account"]
                        if _identity["Arn"].split(":")[1] == "aws-us-gov":
                            logger.info("AWS Budgets is not callable in the aws-us-gov partition; returning no budget data.")
                            return SocaResponse(success=True, message={
                                "budget_exist": False,
                                "current_spend": 0,
                                "forecast_spend": 0,
                                "forecast_available": False,
                                "total_budget": 0,
                                "usage_pct": 0,
                            }).as_flask()

                        try:
                            budget_response = budgets_client.describe_budget(
                                AccountId=account_id, BudgetName=_aws_budget
                            )
                        except ClientError as e:
                            if e.response["Error"]["Code"] == "NotFoundException":
                                return SocaError.GENERIC_ERROR(
                                    helper=f"Budget {_aws_budget} no longer exists"
                                ).as_flask()
                            else:
                                return SocaError.GENERIC_ERROR(
                                    helper=f"Unable to retrieve budget information, check log for more details"
                                ).as_flask()

                        try:
                            budget = budget_response["Budget"]
                            if budget["BudgetType"] != "COST":
                                return SocaError.GENERIC_ERROR(
                                    helper=f"Budget {_aws_budget} is not a cost budget"
                                ).as_flask()

                            total_budget = float(budget["BudgetLimit"]["Amount"])
                            _calc = budget.get("CalculatedSpend", {})
                            current_spend = float(
                                _calc.get("ActualSpend", {}).get("Amount", 0) or 0
                            )
                            _forecast = _calc.get("ForecastedSpend", {})
                            forecast_available = "Amount" in _forecast
                            forecast_spend = float(_forecast.get("Amount", 0) or 0)
                            usage_pct = (
                                (current_spend / total_budget * 100)
                                if total_budget > 0
                                else 0
                            )
                            forecast_pct = (
                                (forecast_spend / total_budget * 100)
                                if total_budget > 0
                                else 0
                            )
                        except Exception as err:
                            logger.error(
                                f"Unable to calculate BudgetLimit, ActualSpend or ForecastedSpend due to {err}"
                            )
                            return SocaError.GENERIC_ERROR(
                                helper=f"Unable to retrieve budget information, check log for more details"
                            ).as_flask()
                        message = {
                            "budget_exist": True,
                            "current_spend": current_spend,
                            "forecast_spend": forecast_spend,
                            "forecast_available": forecast_available,
                            "total_budget": total_budget,
                            "usage_pct": round(usage_pct, 2),
                            "forecast_pct": round(forecast_pct, 2),
                        }
                        logger.debug(
                            f"Budget information for {_project_name}: {message}"
                        )

                    except Exception as e:
                        logger.error(f"Error retrieving budget data: {str(e)}")
                        return SocaError.GENERIC_ERROR(
                            helper=f"Error retrieving budget data, check logs for more details."
                        ).as_flask()

                return SocaResponse(success=True, message=message).as_flask()
