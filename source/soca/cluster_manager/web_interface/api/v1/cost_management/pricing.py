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
from decorators import private_api
from flask_babel import gettext as _
import logging
import ast
import re
import math
import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse
from utils.config import SocaConfig
from utils.aws.ec2_helper import describe_instance_types


logger = logging.getLogger("soca_logger")


def get_compute_pricing(instance_type: str) -> dict:
    _pricing = {}
    client_pricing = utils_boto3.get_boto(
        service_name="pricing", region_name="us-east-1"
    ).message

    region = SocaConfig(key="/configuration/Region").get_value().message

    response = client_pricing.get_products(
        ServiceCode="AmazonEC2",
        Filters=[
            {
                "Type": "TERM_MATCH",
                "Field": "instanceType",
                "Value": instance_type,
            },
            {
                "Type": "TERM_MATCH",
                "Field": "regionCode",
                "Value": region,
            },
            {
                "Type": "TERM_MATCH",
                "Field": "operatingSystem",
                "Value": "Linux",
            },
            {
                "Type": "TERM_MATCH",
                "Field": "tenancy",
                "Value": "Shared",
            },
        ],
    )
    logger.debug(f"Retrieving pricing information for {instance_type}: {response}")
    for data in response["PriceList"]:
        _price_list = ast.literal_eval(data)
        for term_type, term_data in _price_list["terms"].items():
            for sku, sku_data in term_data.items():
                for rate_code, price_dimension in sku_data["priceDimensions"].items():
                    description = price_dimension["description"].lower()
                    price = float(price_dimension["pricePerUnit"]["USD"])

                    # On-Demand Pricing
                    if (
                        term_type == "OnDemand"
                        and f"on demand linux {instance_type} instance hour"
                        in description.lower()
                    ):
                        _pricing["ondemand"] = price

                    # Reserved Pricing (1 year, no upfront)
                    elif (
                        term_type != "OnDemand"
                        and sku_data["termAttributes"]["OfferingClass"] == "standard"
                        and sku_data["termAttributes"]["LeaseContractLength"] == "1yr"
                        and sku_data["termAttributes"]["PurchaseOption"] == "No Upfront"
                        and "linux/unix (amazon vpc)" in description.lower()
                    ):
                        _pricing["reserved"] = price
    return _pricing


class AwsPrice(Resource):
    @private_api
    def get(self):
        r"""
        Calculate AWS pricing for compute and storage resources
        ---
        openapi: 3.1.0
        operationId: calculateAwsPricing
        tags:
          - Cost Management
        summary: Calculate AWS pricing for compute and storage resources
        description: Estimates the cost of running a job with specified compute and storage requirements
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
          - name: instance_type
            in: query
            required: true
            schema:
              type: string
              pattern: '^[a-z0-9]+\.[a-z0-9]+$'
            description: EC2 instance type
            example: "m5.large"
          - name: wall_time
            in: query
            required: false
            schema:
              type: string
              pattern: f'^([0-9]{1,2}):([0-5][0-9]):([0-5][0-9])$'
              default: "01:00:00"
            description: Job duration in HH:MM:SS format
            example: "02:30:00"
          - name: vcpus
            in: query
            required: false
            schema:
              type: integer
              minimum: 1
              maximum: 1000
            description: Number of vCPUs to allocate
            example: 4
          - name: scratch_size
            in: query
            required: false
            schema:
              type: integer
              minimum: 0
              maximum: 10000
              default: 0
            description: Scratch storage size in GB
            example: 100
          - name: root_size
            in: query
            required: false
            schema:
              type: integer
              minimum: 8
              maximum: 1000
              default: 40
            description: Root disk size in GB
            example: 50
          - name: fsx_capacity
            in: query
            required: false
            schema:
              type: integer
              minimum: 0
              maximum: 100000
              default: 0
            description: FSx storage capacity in GB
            example: 1200
          - name: fsx_type
            in: query
            required: false
            schema:
              type: string
              enum: ["SCRATCH_1", "SCRATCH_2", "PERSISTENT_1", "PERSISTENT_2"]
              default: "SCRATCH_2"
            description: FSx storage type
            example: "SCRATCH_2"
        responses:
          '200':
            description: Pricing calculation successful
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
                        - compute
                        - estimated_total_cost
                        - estimated_hourly_cost
                        - estimated_storage_cost
                      properties:
                        compute:
                          type: object
                          required:
                            - ondemand
                            - reserved
                            - on_demand_hourly_rate
                            - reserved_hourly_rate
                            - estimated_on_demand_cost
                            - estimated_reserved_cost
                            - nodes
                            - walltime
                            - instance_type
                            - vcpus
                          properties:
                            ondemand:
                              type: number
                              minimum: 0
                              description: Raw on-demand price per hour from AWS Pricing API
                              example: 0.096
                            reserved:
                              type: number
                              minimum: 0
                              description: Raw reserved price per hour from AWS Pricing API
                              example: 0.058
                            on_demand_hourly_rate:
                              type: number
                              minimum: 0
                              example: 0.096
                            reserved_hourly_rate:
                              type: number
                              minimum: 0
                              example: 0.058
                            estimated_on_demand_cost:
                              type: number
                              minimum: 0
                              example: 0.192
                            estimated_reserved_cost:
                              type: number
                              minimum: 0
                              example: 0.116
                            nodes:
                              type: integer
                              minimum: 1
                              example: 1
                            walltime:
                              type: number
                              minimum: 0
                              example: 2.5
                            instance_type:
                              type: string
                              example: "m5.large"
                            vcpus:
                              type: integer
                              nullable: true
                              example: 4
                        estimated_total_cost:
                          type: number
                          minimum: 0
                          example: 0.205
                        estimated_hourly_cost:
                          type: number
                          minimum: 0
                          example: 0.103
                        estimated_storage_cost:
                          type: number
                          minimum: 0
                          example: 0.013
                        scratch_size:
                          type: string
                          example: "0.007"
                        root_size:
                          type: string
                          example: "0.003"
                        fsx_capacity:
                          type: string
                          example: "0.003"
                        storage_pct:
                          oneOf:
                            - type: number
                              minimum: 0
                              maximum: 100
                            - type: integer
                          description: Storage cost percentage of total (float when non-zero, integer 0 when no storage cost)
                          example: 6.34
                        compute_pct:
                          oneOf:
                            - type: string
                            - type: integer
                          description: Compute cost percentage of total (string when non-zero, integer 0 when no compute cost)
                          example: "93.66"
          '400':
            description: Invalid parameters or wall_time format
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
                      example: "wall_time must use HH:MM:SS format and only use valid numbers"
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
          '404':
            description: Instance type pricing not found
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
                      example: "Unable to retrieve price for m5.large"
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
                      example: "Unable to get compute price. Instance type may be incorrect or region name not tracked correctly?"
        """
        _region_resp = SocaConfig(key="/configuration/Region").get_value()
        _region = _region_resp.message if _region_resp.success is True else ""
        if _region.startswith("us-gov-"):
            return SocaResponse(
                success=False,
                message=_("Cost estimation is not available in the GovCloud partition (the AWS Pricing API is not offered in aws-us-gov)."),
            ).as_flask()

        parser = reqparse.RequestParser()
        parser.add_argument("instance_type", type=str, location="args")
        parser.add_argument(
            "wall_time",
            type=str,
            location="args",
            help="Please specify wall_time using HH:MM:SS format",
            default="01:00:00",
        )
        parser.add_argument(
            "vcpus",
            type=int,
            location="args",
            help="Please specify how many vcpus you want to allocate",
        )
        parser.add_argument(
            "scratch_size",
            type=int,
            location="args",
            help="Please specify storage in GB to allocate to /scratch partition (Default 0)",
            default=0,
        )
        parser.add_argument(
            "root_size",
            type=int,
            location="args",
            help="Please specify your AMI root disk space (Default 40gb)",
            default=40,
        )
        parser.add_argument(
            "fsx_capacity",
            type=int,
            location="args",
            help="Please specify fsx_storage in GB",
            default=0,
        )
        parser.add_argument("fsx_type", type=str, location="args", default="SCRATCH_2")
        args = parser.parse_args()
        instance_type = args["instance_type"]
        scratch_size = args["scratch_size"]
        root_size = args["root_size"]
        fsx_storage = args["fsx_capacity"]
        fsx_type = args["fsx_type"]
        vcpus = args["vcpus"]
        sim_cost = {}

        # Change value below as needed if you use a different region
        EBS_GP3_STORAGE_BASELINE = 0.08  # us-east-1 0.08 cts per gb per month
        FSX_STORAGE_BASELINE = 0.13  # us-east-1 Persistent (50 MB/s/TiB baseline, up to 1.3 GB/s/TiB burst)  Scratch (200 MB/s/TiB baseline, up to 1.3 GB/s/TiB burst)

        try:
            sim_hours, sim_minutes, sim_seconds = map(
                float, args["wall_time"].split(":")
            )
        except Exception as e:
            return SocaResponse(
                success=False,
                message=_("wall_time must use HH:MM:SS format and only use valid numbers"),
            ).as_flask()

        walltime = sim_hours + (sim_minutes / 60) + (sim_seconds / 3600)

        if float(walltime) == 0.0:
            return SocaResponse(
                success=False,
                message="wall_time cannot be 00:00:00",
            ).as_flask()

        # Calculate number of nodes required based on instance type and vCPUs requested
        if vcpus is None:
            nodect = 1
        else:
            _describe_instance_type = describe_instance_types(
                instance_types=[instance_type]
            )
        if _describe_instance_type.get("success") is False:
            return SocaResponse(
                success=False,
                message=_(f"Unable to describe_instance {instance_type} because of {_describe_instance_type.get('message')} "),
            ).as_flask()
        else:
            _describe_instance_types = _describe_instance_type.get("message")

            for instance_info in _describe_instance_types.get("InstanceTypes"):
                _cpu_per_system = instance_info["VCpuInfo"]["DefaultVCpus"]

            nodect = math.ceil(int(vcpus) / _cpu_per_system)

        # Calculate EBS Storage (storage * ebs_price * sim_time_in_secs / (walltime_seconds * 30 days) * number of nodes
        sim_cost["scratch_size"] = (
            f"{(scratch_size * EBS_GP3_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)) * nodect:.3f}"
        )
        sim_cost["root_size"] = (
            f"{(root_size * EBS_GP3_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)) * nodect:.3f}"
        )

        # Calculate FSx Storage (storage * fsx_price * sim_time_in_secs / (second_in_a_day * 30 days)
        sim_cost["fsx_capacity"] = (
            f"{(fsx_storage * FSX_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)):.3f}"
        )

        # Calculate Compute Price
        try:
            _compute_price = {}
            _compute_price = get_compute_pricing(instance_type=instance_type)
            if not _compute_price:
                return SocaResponse(
                    success=False,
                    message=_(f"Unable to retrieve price for {instance_type}"),
                ).as_flask()

            _ondemand_price = _compute_price.get("ondemand")
            if _ondemand_price is None:
                return SocaResponse(
                    success=False,
                    message=_(f"Unable to retrieve 'ondemand' price for {instance_type}: {_compute_price}"),
                ).as_flask()

            # No 1yr No-Upfront Standard RI offering for this family; fall back to on-demand.
            _reserved_is_fallback = _compute_price.get("reserved") is None
            _reserved_price = _compute_price.get("reserved", _ondemand_price)

            _compute_price["reserved"] = _reserved_price
            _compute_price["reserved_price_is_fallback"] = _reserved_is_fallback
            _compute_price["on_demand_hourly_rate"] = float(f"{_ondemand_price:.3f}")
            _compute_price["reserved_hourly_rate"] = float(f"{_reserved_price:.3f}")
            _compute_price["nodes"] = nodect
            _compute_price["walltime"] = float(f"{walltime:.3f}")
            _compute_price["instance_type"] = instance_type
            _compute_price["estimated_on_demand_cost"] = float(
                f"{(_ondemand_price * nodect) * walltime:.3f}"
            )
            _compute_price["estimated_reserved_cost"] = float(
                f"{(_reserved_price * nodect) * walltime:.3f}"
            )

            sim_cost["compute"] = _compute_price
        except Exception as err:
            return SocaResponse(
                success=False,
                message=_(f"Unable to get compute price. Instance type may be incorrect or region name not tracked correctly? Error: {err}"),
            ).as_flask()

        # Output
        sim_cost["estimated_storage_cost"] = float(
            f"{float(sim_cost['fsx_capacity']) + float(sim_cost['scratch_size']) + float(sim_cost['root_size']) :.3f}"
        )

        sim_cost["estimated_total_cost"] = float(
            f"{float(sim_cost['estimated_storage_cost']) + float(sim_cost['compute']['estimated_on_demand_cost']) :.3f}"
        )

        sim_cost["estimated_hourly_cost"] = float(
            f"{float(sim_cost['estimated_total_cost']) / float(walltime) :.3f}"
        )

        sim_cost["storage_pct"] = float(
            f"{float((sim_cost['estimated_storage_cost']) / float(sim_cost['estimated_total_cost'])) * 100 :.3f}"
            if float(sim_cost["estimated_storage_cost"]) != 0.000
            else 0
        )

        sim_cost["compute_pct"] = (
            f"{float((sim_cost['compute']['estimated_on_demand_cost']) / float(sim_cost['estimated_total_cost'])) * 100 :.3f}"
            if float(sim_cost["compute"]["estimated_on_demand_cost"]) != 0.000
            else 0
        )

        sim_cost["compute"]["vcpus"] = vcpus
        return SocaResponse(success=True, message=sim_cost).as_flask()
