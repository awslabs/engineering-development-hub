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
import botocore.exceptions
import config
from flask_restful import Resource, reqparse
import logging
from datetime import datetime, timezone
import gzip
import json
from utils.config import SocaConfig
from decorators import private_api, feature_flag
from flask import request, session
from flask_babel import gettext as _
import re
import uuid
import sys
import os
from pathlib import Path
import shutil
from botocore.exceptions import ClientError
from models import db, VirtualDesktopSessions
import dcv_cloudformation_builder

import utils.aws.boto3_wrapper as utils_boto3
from utils.datamodels.constants import SocaLinuxBaseOS, SocaWindowsBaseOS
from utils.aws.ssm_helper import get_ami_id_from_alias
from utils.aws.ec2_helper import (
    create_capacity_dry_run,
    describe_images,
    describe_subnets,
)
from utils.aws.odcr_helper import (
    create_capacity_reservation,
    validate_existing_capacity_reservation,
    get_reservation_info_soca_capacity_reservation,
)
from utils.aws.cloudformation_client import SocaCfnClient
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.stack_naming import generate_stack_name
from utils.jinjanizer import SocaJinja2Generator
from helpers.software_stacks import SoftwareStacksHelper
from helpers.base_image_registry import resolve_launch_ami
import pathlib
import base64
import remote_desktop_common
import random
import secrets
import string

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def clean_user_data(text_to_remove: list, data: str) -> str:
    _ec2_user_data = data
    for _t in text_to_remove:
        _ec2_user_data = re.sub(f"{_t}", "", _ec2_user_data, flags=re.IGNORECASE)

    # Remove leading spaces
    _ec2_user_data = re.sub(r"^[ \t]+", "", _ec2_user_data, flags=re.MULTILINE)

    # Remove lines that start with '#' but not '#!'
    _ec2_user_data = re.sub(r"^(?!#!)#.*\n?", "", _ec2_user_data, flags=re.MULTILINE)

    # Finally remove blank lines
    _ec2_user_data = re.sub(r"^\s*\n", "", _ec2_user_data, flags=re.MULTILINE)

    return _ec2_user_data


class CreateVirtualDesktop(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        r"""
        Create a new DCV virtual desktop session
        ---
        openapi: 3.1.0
        operationId: createVirtualDesktop
        tags:
          - Virtual Desktops
        summary: Create new virtual desktop session
        description: Provisions a new EC2 instance with DCV for remote desktop access
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
                properties:
                  instance_type:
                    type: string
                    pattern: '^[a-z0-9]+\.[a-z0-9]+$'
                    description: EC2 instance type for the virtual desktop
                    example: "m5.large"
                  capacity_reservation_id:
                    type: string
                    description: Existing Capacity Reservation ID to assign
                    example: "cr-abd123"
                  disk_size:
                    type: string
                    pattern: '^[0-9]+$'
                    description: EBS root volume size in GB
                    example: "50"
                  session_name:
                    type: string
                    minLength: 1
                    maxLength: 32
                    pattern: '^[a-zA-Z0-9]+$'
                    description: Name for the DCV session (alphanumeric only, max 32 chars)
                    example: "MyDesktop01"
                  software_stack_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the software stack to use
                    example: "1"
                  subnet_id:
                    type: string
                    pattern: '^subnet-[a-f0-9]{8,17}$'
                    description: Subnet ID where to launch the EC2 instance
                    example: "subnet-12345678"
                  project:
                    type: string
                    minLength: 1
                    maxLength: 100
                    pattern: '^[a-zA-Z0-9._-]+$'
                    description: Project to map the VDI desktop to
                    example: "myproject"
                  hibernate:
                    type: string
                    enum: ["true", "false"]
                    description: Enable hibernation support
                    example: "false"
                  tenancy:
                    type: string
                    enum: ["default", "dedicated"]
                    description: EC2 tenancy type
                    example: "default"
                  session_type:
                    type: string
                    enum: ["default", "console", "virtual"]
                    description: Type of DCV session
                    example: "default"
                  nested_virtualization:
                    type: string
                    enum: ["true", "false"]
                    description: Enable nested virtualization support (requires feature flag)
                    example: "false"
                  bootstrap_cache_bypass:
                    type: string
                    enum: ["true", "false"]
                    description: Bypass the bootstrap template cache for this session (debugging)
                    example: "false"
                  on_behalf_of:
                    type: string
                    description: Admin-only - create session on behalf of another user
                    example: "another.user"
        responses:
          '200':
            description: Virtual desktop session creation initiated successfully
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
                      example: "Session MyDesktop01 started successfully."
          '400':
            description: Invalid request parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "Missing required parameter: instance_type"
          '401':
            description: Authentication failed
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 401
                    message:
                      type: string
                      example: "Invalid authentication credentials"
          '403':
            description: Feature not enabled or insufficient permissions
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 403
                    message:
                      type: string
                      example: "Virtual desktops feature is not enabled"
          '500':
            description: Internal server error during session creation
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 500
                    message:
                      type: string
                      example: "Failed to create virtual desktop session"
        """

        parser = reqparse.RequestParser()
        # instance_type and software_stack_id have no sensible default - they
        # MUST come from the caller. The rest get safe defaults so missing
        # form fields don't propagate as None into downstream boto3 APIs
        # that reject None (Tenancy, etc) or into casts that fail (disk_size).
        parser.add_argument("instance_type", type=str, location="form", required=True)
        parser.add_argument(
            "software_stack_id", type=str, location="form", required=True
        )
        parser.add_argument("disk_size", type=str, location="form", default="50")
        parser.add_argument(
            "session_name", type=str, location="form"
        )  # auto-uuid'd if None
        parser.add_argument("project", type=str, location="form", default="default")
        parser.add_argument("subnet_id", type=str, location="form", default="auto")
        parser.add_argument("hibernate", type=str, location="form", default="false")
        parser.add_argument("tenancy", type=str, location="form", default="default")
        parser.add_argument(
            "nested_virtualization", type=str, location="form", default="false"
        )
        parser.add_argument(
            "session_type", type=str, location="form", default="virtual"
        )
        parser.add_argument(
            "capacity_reservation_id", type=str, location="form"
        )  # None = no ODCR
        parser.add_argument("spot", type=str, location="form", default="false")
        # bootstrap_cache_bypass: when "true"/"yes"/"1", forces THIS create
        # to render bootstrap templates fresh per-session and write to the
        # per-session S3 prefix, bypassing the BootstrapTemplateCache
        # entirely. Useful for A/B perf comparison and for debugging
        # suspect cached entries on a single session without affecting
        # the cluster-wide cache state. The cache flag default behavior
        # otherwise applies. Logged audibly when set.
        parser.add_argument(
            "bootstrap_cache_bypass", type=str, location="form", default="false"
        )
        parser.add_argument(
            "on_behalf_of", type=str, location="form"
        )  # admin-only: create for another user
        args = parser.parse_args()
        _session_uuid = str(uuid.uuid4())

        logger.info(
            f"Received parameter for new DCV session request: {args}, setting up session uuid {_session_uuid}"
        )
        try:
            _user = request.headers.get("X-EDH-USER") or session.get("user")
            if _user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

            # Admin override: a sudoers admin (or the server API root key) may
            # create a session on behalf of another user. on_behalf_of is never
            # trusted from a non-admin -- they can only create for themselves.
            _is_admin = (
                request.headers.get("X-EDH-TOKEN", "") == config.Config.API_ROOT_KEY
                or session.get("sudoers", False) is True
            )
            _on_behalf_of = (args.get("on_behalf_of") or "").strip().lower()
            if _on_behalf_of and _is_admin and _on_behalf_of != _user.lower():
                logger.info(
                    f"Admin {_user!r} creating session on behalf of {_on_behalf_of!r}"
                )
                _user = _on_behalf_of

            # sanitize session_name
            if args["session_name"] is None:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="session_name cannot be null",
                ).as_flask()

            else:
                _session_name = re.sub(
                    pattern=r"[^a-zA-Z0-9]",
                    repl="",
                    string=str(args["session_name"])[:32],
                )[:32]

            if args["project"] is None:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="project cannot be null",
                ).as_flask()

            logger.debug(f"Session name {_session_name}")

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
            else:
                soca_parameters = _get_soca_parameters
            # Stack name is a pure infra identifier (cluster + owner + uuid). The
            # user-supplied session_name never enters it -- see utils.stack_naming.
            _stack_name = generate_stack_name(
                cluster_id=_get_soca_parameters.get("/configuration/ClusterId"),
                owner=_user,
                session_uuid=_session_uuid,
            )
            logger.debug(f"VDI will be provisioned by {_stack_name=}")

            # Validate input
            if args["instance_type"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="instance_type"
                ).as_flask()
            else:
                instance_type = args["instance_type"]

            if args["session_type"] not in ["default", "console", "virtual"]:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"session_type must be default, console or virtual. Detected {args['session_type']}",
                ).as_flask()

            if args["session_type"] not in config.Config.DCV_ALLOWED_SESSION_TYPES:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"session_type must be one of {config.Config.DCV_ALLOWED_SESSION_TYPES}. Detected {args['session_type']}",
                ).as_flask()

            if args["software_stack_id"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="software_stack_id"
                ).as_flask()
            else:
                _software_stack_id = SocaCastEngine(
                    data=args["software_stack_id"]
                ).cast_as(expected_type=int)
                if _software_stack_id.get("success"):
                    _get_software_stack = SoftwareStacksHelper(
                        software_stack_id=_software_stack_id.get("message"),
                        is_active=True,
                    )

                else:
                    return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                        session_number=_session_uuid,
                        session_owner=_user,
                        helper=f"software_stack_id does not seems to be a valid integer: {_software_stack_id.message}",
                    ).as_flask()

            # Validate Software Stack Information
            _get_software_stack_info = _get_software_stack.get_stack_info()
            if _get_software_stack_info.get("success") is True:
                _software_stack_info = _get_software_stack_info.get("message")
            else:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"{_get_software_stack_info.get('message')}",
                ).as_flask()

            # Check if specified AMI ID is an alias
            if _software_stack_info.get("ami_id").startswith("/aws/service/"):
                _fetch_ami = get_ami_id_from_alias(
                    alias_name=_software_stack_info.get("ami_id")
                )
                if _fetch_ami.get("success") is True:
                    _ami_id = _fetch_ami.get("message")
                else:
                    return SocaError.GENERIC_ERROR(
                        helper=_fetch_ami.get("message")
                    ).as_flask()
            else:
                _ami_id = _software_stack_info.get("ami_id")
            # Owned-base indirection: swap to the local owned copy when active (passthrough if FF off)
            _ami_id = resolve_launch_ami(_ami_id).get("message")

            # Resolve InstancePlatform from the AMI metadata
            _instance_platform = ""
            _img_resp = describe_images(image_ids=[_ami_id])
            if _img_resp.get("success"):
                _images = _img_resp.get("message", {}).get("Images", [])
                if _images:
                    _instance_platform = _images[0].get("PlatformDetails", "")

            if not _instance_platform:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to determine InstancePlatform for AMI {_ami_id}",
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

            if not args["hibernate"]:
                args["hibernate"] = False
            else:
                _check_hibernate = SocaCastEngine(args["hibernate"]).cast_as(
                    expected_type=bool
                )
                if _check_hibernate.get("success"):
                    args["hibernate"] = _check_hibernate.get("message")
                else:
                    args["hibernate"] = False

            if not args["nested_virtualization"]:
                args["nested_virtualization"] = False
            else:
                _check_nested_virt = SocaCastEngine(
                    args["nested_virtualization"]
                ).cast_as(expected_type=bool)
                if _check_nested_virt.get("success"):
                    args["nested_virtualization"] = _check_nested_virt.get("message")
                else:
                    args["nested_virtualization"] = False

            if args["nested_virtualization"] is True:
                _nv_flag = SocaConfig(
                    key="/configuration/FeatureFlags/VirtualDesktops/EnableNestedVirtualization"
                ).get_value(return_as=bool)
                if not (
                    _nv_flag.get("success") is True and _nv_flag.get("message") is True
                ):
                    logger.warning(
                        "nested_virtualization requested but EnableNestedVirtualization feature flag is disabled, ignoring"
                    )
                    args["nested_virtualization"] = False

            if not args["subnet_id"]:
                logger.info("No subnet_id specified, default to 'auto'")
                args["subnet_id"] = "auto"

            # Note: if subnet_id is set to `auto`, SOCA will cycle trough the list until capacity is available
            _selected_subnet = None
            _soca_private_subnets = (
                SocaCastEngine(
                    _get_soca_parameters.get("/configuration/PrivateSubnets")
                )
                .cast_as(expected_type=list)
                .get("message")
            )

            _async_raw = (
                SocaConfig(key="/configuration/FeatureFlags/AsyncPlacement")
                .get_value(default="false", allow_unknown_key=True)
                .get("message", "false")
            )
            _async_cast = SocaCastEngine(_async_raw).cast_as(expected_type=bool)
            _async_on = (
                _async_cast.get("message")
                if _async_cast.get("success") is True
                else False
            )

            if _async_on or (
                SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation")
                .get_value(return_as=bool)
                .get("message")
                is False
            ):
                if _async_on:
                    logger.info(
                        "AsyncPlacement enabled - skipping synchronous ODCR probe; "
                        "DcvPlacement Lambda probes subnets and reserves capacity"
                    )
                else:
                    logger.info(
                        "/configuration/FeatureFlags/EnableCapacityReservation flag is set to False, SOCA will NOT verify capacity availability"
                    )

                if args["subnet_id"] == "auto":
                    if args["capacity_reservation_id"]:
                        # A capacity reservation is AZ-locked. Rather than force
                        # the user to also pick the matching subnet, derive it
                        # from the reservation's AZ automatically.
                        _cr_info = get_reservation_info_soca_capacity_reservation(
                            capacity_reservation_id=args["capacity_reservation_id"]
                        )
                        _cr_az = (
                            _cr_info.availability_zone
                            if getattr(_cr_info, "reservation_exist", False)
                            else None
                        )
                        if not _cr_az:
                            return SocaError.GENERIC_ERROR(
                                helper=f"Unable to resolve the Availability Zone for capacity reservation {args['capacity_reservation_id']}. Verify it exists and is active."
                            ).as_flask()
                        _ds_resolve = describe_subnets(subnet_ids=_soca_private_subnets)
                        if _ds_resolve.get("success") is not True:
                            return SocaError.AWS_API_ERROR(
                                service_name="ec2",
                                helper=(
                                    f"Unable to describe subnets to resolve AZ "
                                    f"for capacity reservation: "
                                    f"{_ds_resolve.get('message')}"
                                ),
                            ).as_flask()
                        _subnets_in_az = [
                            _s.get("SubnetId")
                            for _s in _ds_resolve.get("message", {}).get("Subnets", [])
                            if _s.get("AvailabilityZone") == _cr_az
                        ]
                        if not _subnets_in_az:
                            return SocaError.GENERIC_ERROR(
                                helper=f"No private subnet is available in the capacity reservation's Availability Zone ({_cr_az}). Add a private subnet in {_cr_az} or choose a different reservation."
                            ).as_flask()
                        _selected_subnet = random.choice(_subnets_in_az)
                        logger.info(
                            f"subnet_id 'auto' with capacity_reservation_id {args['capacity_reservation_id']}: auto-resolved subnet {_selected_subnet} from reservation AZ {_cr_az}"
                        )
                    else:
                        logger.info(
                            f"subnet_id is 'auto' and capacity reservation check is not enabled, SOCA will pick a random subnet from {_soca_private_subnets}"
                        )
                        _selected_subnet = random.choice(_soca_private_subnets)
                else:
                    _selected_subnet = args["subnet_id"]

                logger.info(f"Selected Subnet: {_selected_subnet}")

            else:
                if args["capacity_reservation_id"]:
                    logger.info(
                        f"capacity_reservation_id flag is set with value {args['capacity_reservation_id']=}, skipping ODCR request check"
                    )
                    if args["subnet_id"] == "auto":
                        return SocaError.GENERIC_ERROR(
                            helper="You must specify a subnet_id and not use 'auto' when selecting a capacity reservation id."
                        ).as_flask()
                    else:
                        _selected_subnet = args["subnet_id"]
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
                            f"Probing capacity availability for {args.get('instance_type')}, instance_count=1, subnet_ids={_selected_subnet}, {_ami_id}"
                        )
                        _request_on_demand_capacity_reservation = (
                            create_capacity_reservation(
                                probe_capacity_only=True,
                                desired_capacity=1,
                                capacity_reservation_name=_stack_name,
                                instance_type=args.get("instance_type"),
                                subnet_id=_selected_subnet,
                                instance_ami=_ami_id,
                                instance_platform=_instance_platform,
                                tenancy=args.get("tenancy"),
                            )
                        )
                        if (
                            _request_on_demand_capacity_reservation.get("success")
                            is True
                        ):
                            logger.info(
                                f"ODCR succeeded, capacity is available in subnet_id {_selected_subnet}: {_request_on_demand_capacity_reservation.get('message')}"
                            )

                        else:
                            logger.error(
                                f"Unable to create capacity reservation due to {_request_on_demand_capacity_reservation.message}"
                            )
                            return SocaError.GENERIC_ERROR(
                                helper=f"Unable to provision the Virtual Desktop because the available AWS capacity in the selected subnet is insufficient. Try again later or choose a different subnet / instance type."
                            ).as_flask()

                    else:
                        logger.info(
                            "subnet_id is 'auto'. SOCA will try pick a random subnet and cycle through others subnet id until capacity is available"
                        )
                        random.shuffle(_soca_private_subnets)
                        for _subnet_id in _soca_private_subnets:
                            logger.info(
                                f"Requesting ODCR for {args.get('instance_type')}, instance_count=1, capacity_reservation_name={_stack_name}, subnet_id={[_subnet_id]}, {_ami_id}"
                            )
                            _request_on_demand_capacity_reservation = (
                                create_capacity_reservation(
                                    probe_capacity_only=True,
                                    desired_capacity=1,
                                    instance_type=args.get("instance_type"),
                                    capacity_reservation_name=_stack_name,
                                    subnet_id=_subnet_id,
                                    instance_ami=_ami_id,
                                    instance_platform=_instance_platform,
                                    tenancy=args.get("tenancy"),
                                )
                            )
                            if (
                                _request_on_demand_capacity_reservation.get("success")
                                is True
                            ):
                                _selected_subnet = _subnet_id
                                logger.info(
                                    f"ODCR succeeded, capacity is available in subnet_id {_selected_subnet}: {_request_on_demand_capacity_reservation.get("message")}"
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

            # Do this check at the end once we know the subnet to pick
            if args["capacity_reservation_id"]:
                logger.info(
                    f"Received capacity_reservation_id {args['capacity_reservation_id']} for this request, validating it .. "
                )

                _capacity_reservation = get_reservation_info_soca_capacity_reservation(
                    capacity_reservation_id=args["capacity_reservation_id"]
                )
                logger.info(f"{_capacity_reservation=}")

                _validate_odcr = validate_existing_capacity_reservation(
                    capacity_reservation=_capacity_reservation,
                    instance_type=instance_type,
                    subnet_id=_selected_subnet,
                    desired_capacity=1,
                    instance_ami=_ami_id,
                )
                if _validate_odcr.get("success") is True:
                    logger.info("Capacity reservation is valid, proceeding")
                else:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to validate capacity reservation due to {_validate_odcr.message}"
                    ).as_flask()

            # VDI pool: a configured + enabled pool GRANTS its instance type for
            # this stack even when that type is outside the profile's traditional
            # allowed_instance_types -- the admin who provisioned the pool IS the
            # authorization (an admin went to the trouble of creating it, so its
            # ready/warm members are claimable). Collect the stack's enabled pool
            # types and pass them as an allow-list extension to validate().
            _pool_granted_instance_types = []
            try:
                from helpers import vdi_pool_store

                _pool_cfg_resp = vdi_pool_store.get_pool_config(
                    _software_stack_id.message
                )
                _pool_cfg = _pool_cfg_resp.get("message") or {}
                if _pool_cfg_resp.get("success") and _pool_cfg.get("enabled"):
                    _pool_granted_instance_types = [
                        (e.get("instance_type") or "").strip()
                        for e in _pool_cfg.get("entries", [])
                        if e.get("enabled", True)
                        and (e.get("instance_type") or "").strip()
                    ]
            except Exception as _pool_lookup_err:
                logger.warning(
                    f"VDI pool allow-list lookup failed (continuing with stack "
                    f"allow-list only): {_pool_lookup_err}"
                )

            # Validate Software Stack Permissions
            _get_software_stack_permissions = _get_software_stack.validate(
                instance_type=instance_type,
                root_size=args["disk_size"],
                subnet_id=_selected_subnet,
                session_owner=_user,
                project=args.get("project"),
                extra_allowed_instance_types=_pool_granted_instance_types,
            )

            if _get_software_stack_permissions.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=_get_software_stack_permissions.get("message"),
                ).as_flask()

            # Validate if user does not have hit maximum number of desktop
            if (
                remote_desktop_common.max_concurrent_desktop_limit_reached(
                    os_family=_software_stack_info.get("os_family"), session_owner=_user
                )
                is True
            ):
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=f"Max number of Linux or Windows session already reached for this user (Linux: Max {config.Config.DCV_LINUX_SESSION_COUNT}, Windows: max {config.Config.DCV_WINDOWS_SESSION_COUNT})",
                ).as_flask()

            # Configure Session Type
            if args["session_type"] == "default":
                logger.info("Detected default session type, setting up automatically)")
                if _software_stack_info.get("os_family") == "windows":
                    _session_type = "console"
                else:
                    # Ubuntu does not work well with virtual session, default to console
                    # GPU instance also use console session by default
                    # Also edit cluster_node_bootstrap/templates/linux/dcv/dcv_server.sh.j2 if you modify this list
                    if _software_stack_info.get("ami_base_os") in [
                        "ubuntu2204",
                        "ubuntu2404",
                    ]:
                        _session_type = "console"
                    elif args["instance_type"].startswith("p") or args[
                        "instance_type"
                    ].startswith("g"):
                        # GPU use console by default
                        _session_type = "console"
                    else:
                        _session_type = "virtual"
            else:
                _session_type = args["session_type"]

            logger.info(f"Detected session type: {_session_type}")
            if (
                _session_type == "virtual"
                and _software_stack_info.get("os_family") == "windows"
            ):
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=f"Windows only support console or default session type, detected {args['session_type']}",
                ).as_flask()

            # Add SOCA job specific variables
            # job/xxx -> Job Specific (JobId, InstanceType, JobProject ...)
            # configuration/xxx -> SOCA environment specific (ClusterName, Base OS, Region ...)
            # system/xxx -> system related information (e.g: packages to install, DCV version, EFA version ...)

            # Create bootstrap UUID for this job
            _bootstrap_uuid = str(uuid.uuid4())

            # Add custom bootstrap path specific to current job id
            soca_parameters["/job/BootstrapPath"] = (
                f"/apps/edh/{soca_parameters.get('/configuration/ClusterId')}/shared/logs/bootstrap/dcv_node/{_user}/{_session_name}/{_session_uuid}/{_bootstrap_uuid}"
            )

            _bootstrap_s3_location_folder = f"{soca_parameters.get('/configuration/ClusterId')}/config/do_not_delete/bootstrap/dcv_node/{_bootstrap_uuid}/{_session_uuid}"

            soca_parameters["/job/BootstrapScriptsS3Location"] = (
                f"s3://{soca_parameters.get('/configuration/S3Bucket')}/{_bootstrap_s3_location_folder}/"
            )

            # add custom dcv parameter
            soca_parameters["/job/NodeType"] = "dcv_node"
            soca_parameters["/dcv/SessionOwner"] = _user
            soca_parameters["/dcv/JobProject"] = args.get("project")
            soca_parameters["/dcv/SessionType"] = _session_type
            # Both Windows and Linux now use a unique UUID per session. On
            # Windows, the auto-created console session is renamed to this
            # UUID at boot via the `name` registry key under
            # session-management/automatic-console-session — see
            # templates/windows/dcv/dcv_session_setup.ps.j2. Without this
            # rename, multiple Windows VDIs in the same cluster would all
            # register a session named "console" and collide at the broker
            # (and in the S3 screenshot prefix).
            soca_parameters["/dcv/SessionId"] = _session_uuid

            soca_parameters["/dcv/SessionName"] = _session_name
            # DCV Auth Token Verifier — broker validates tokens in high-scale mode.
            # Port 8445 is the broker's agent connector (broker.properties:
            # agent-to-broker-connector-https-port). The DCV server posts to
            # /agent/validate-authentication-token there. See
            # https://docs.aws.amazon.com/dcv/latest/sm-admin/configure-dcv-server.html
            _dcv_high_scale_check = (
                SocaConfig(key="/dcv/high_scale_enabled")
                .get_value()
                .get("message", "false")
            )
            if str(_dcv_high_scale_check).lower() == "true":
                _backend_nlb = (
                    SocaConfig(key="/dcv/backend_nlb_dns")
                    .get_value()
                    .get("message", "")
                )
                soca_parameters["/dcv/AuthTokenVerifier"] = (
                    f"https://{_backend_nlb}:8445/agent/validate-authentication-token"
                )
            else:
                soca_parameters["/dcv/AuthTokenVerifier"] = (
                    f"https://{SocaConfig(key='/configuration/ControllerPrivateDnsName').get_value().get('message')}:{config.Config.FLASK_PORT}/api/dcv/authenticator"
                )
            if _software_stack_info.get("os_family") == "windows":
                # Build a 9-char password with at least 3 digits, 3 uppercase,
                # 3 lowercase, then shuffle. Uses secrets + SystemRandom for
                # cryptographic randomness (not the default random module which
                # is seeded from time()).
                _pw_chars = (
                    [secrets.choice(string.digits) for _i in range(3)]
                    + [secrets.choice(string.ascii_uppercase) for _i in range(3)]
                    + [secrets.choice(string.ascii_lowercase) for _i in range(3)]
                )
                random.SystemRandom().shuffle(_pw_chars)
                _session_local_admin_password = "".join(_pw_chars)

                soca_parameters["/dcv/LocalAdminPassword"] = (
                    _session_local_admin_password
                )
                soca_parameters["/dcv/WindowsAutoLogon"] = (
                    "true" if config.Config.DCV_WINDOWS_AUTOLOGON is True else "false"
                )
            else:
                _session_local_admin_password = None

            soca_parameters["/job/BaseOS"] = _software_stack_info.get("ami_base_os")
            soca_parameters["/configuration/BaseOS"] = _software_stack_info.get(
                "ami_base_os"
            )  # legacy

            # DCV High-Scale: pass broker endpoint to VDI hosts for SM Agent
            _dcv_high_scale = (
                SocaConfig(key="/dcv/high_scale_enabled")
                .get_value()
                .get("message", "false")
            )
            if str(_dcv_high_scale).lower() == "true":
                soca_parameters["/configuration/DcvHighScale"] = "true"
                soca_parameters["/dcv/BrokerHost"] = (
                    SocaConfig(key="/dcv/backend_nlb_dns")
                    .get_value()
                    .get("message", "")
                )
                soca_parameters["/dcv/BrokerAgentPort"] = (
                    SocaConfig(key="/dcv/broker/agent_port")
                    .get_value()
                    .get("message", "47100")
                )

            # ----- DCV event-relay (SNS+Lambda push) per-session secret ---
            # Read by the bootstrap-rendered 00_session_env files and exported
            # into /etc/environment so the publish helper finds them. Both
            # are nullable in the bootstrap path -- if either is missing the
            # helper silently no-ops, leaving cold-session probe as the
            # safety net.
            #
            # Provenance is established at the AWS layer via the SQS
            # SenderId attribute (= role-id:i-XXXXXXXX) which the relay
            # Lambda extracts from the message and forwards to the
            # controller for cross-checking. No per-session HMAC, no IID
            # document, no Fernet ciphertext to manage. See
            # docs/DCVEventRelay.md for the full chain of trust.
            try:
                _events_queue_url_resp = SocaConfig(
                    key="/configuration/DcvSessionEventsQueueUrl"
                ).get_value(default="", allow_unknown_key=True)
                _events_queue_url = (
                    _events_queue_url_resp.message
                    if _events_queue_url_resp.success
                    else ""
                )
                if _events_queue_url:
                    soca_parameters["/dcv/SessionEventsQueueUrl"] = _events_queue_url
            except Exception as _err:
                logger.debug(
                    f"DCV event-relay: SocaConfig read failed (legacy "
                    f"cluster, expected): {_err}"
                )

            logger.debug(f"soca_parameters for DCV User Data: {soca_parameters}")

            # User Data is generated below, AFTER the BootstrapTemplateCache
            # render has populated /job/BootstrapScriptsS3Location and
            # /job/SessionEnvS3Location with their final (possibly cached)
            # values. Rendering it here would bake in the early per-session
            # defaults and the worker would s3 sync from a dir that only
            # contains 00_session_env.* (cache puts the big bootstrap
            # bodies elsewhere).

            # Create bootstrap setup invoked by user data
            # Create directory structure
            _mode = 0o755
            _bootstrap_path = pathlib.Path(soca_parameters.get("/job/BootstrapPath"))
            _bootstrap_path.mkdir(parents=True, exist_ok=True, mode=_mode)

            # If the structure does not exist, Path.mkdir will create all folder with 777 permissions.
            # This code will update all permissions back to 755
            for parent in reversed(_bootstrap_path.parents):
                if parent.exists():
                    os.chmod(parent, _mode)

            # Bootstrap Sequence: Generate templates and upload them to S3.
            #
            # Routed through the BootstrapTemplateCache when enabled
            # (default true) so the big bootstrap bodies are rendered
            # once per (stack-config, .j2 tree) and reused across
            # sessions of the same software stack. Per-session values
            # are surfaced via a separate small env file
            # (00_session_env.sh / .ps1) that the worker UserData stub
            # sources before running the cached big bootstrap.
            #
            # See docs/BootstrapTemplateCache.md.
            from utils.bootstrap_render import render_bootstrap_bundle

            if _software_stack_info.get("os_family") == "windows":
                _big_templates = [
                    "windows_virtual_desktop/02_setup.ps1",
                    "windows_virtual_desktop/03_setup_post_reboot.ps1",
                ]
                _session_env_template = "windows_virtual_desktop/00_session_env.ps1"
                _session_env_filename = "00_session_env.ps1"
            else:
                _big_templates = [
                    "templates/linux/system_packages/install_required_packages.sh",
                    "templates/linux/filesystems_automount.sh",
                    "compute_node/02_setup.sh",
                    "compute_node/03_setup_post_reboot.sh",
                    "compute_node/04_setup_user_customization.sh",
                ]
                _session_env_template = "templates/linux/00_session_env.sh"
                _session_env_filename = "00_session_env.sh"

            try:
                # Parse the per-request bypass flag. Anything resembling
                # "true"/"yes"/"1" triggers a per-session render that
                # skips the cache for this single create.
                _cache_bypass_raw = (
                    (args.get("bootstrap_cache_bypass") or "false").strip().lower()
                )
                _cache_bypass = _cache_bypass_raw in ("true", "yes", "1", "on")
                if _cache_bypass:
                    logger.warning(
                        "BootstrapTemplateCache BYPASSED for session=%s by request "
                        "(actor=%s) -- this create will render fresh and write to "
                        "per-session S3 prefix instead of the shared cache.",
                        _session_name,
                        _user,
                    )

                _render_result = render_bootstrap_bundle(
                    soca_parameters=soca_parameters,
                    bootstrap_root=(
                        f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID')}/"
                        "cluster_node_bootstrap/"
                    ),
                    s3_client=utils_boto3.get_boto(service_name="s3").message,
                    bucket=soca_parameters.get("/configuration/S3Bucket"),
                    cluster_id=soca_parameters.get("/configuration/ClusterId"),
                    per_session_prefix=_bootstrap_s3_location_folder,
                    cache_prefix=(
                        f"{soca_parameters.get('/configuration/ClusterId')}/"
                        "bootstrap/cache"
                    ),
                    big_templates=_big_templates,
                    session_env_template=_session_env_template,
                    session_env_filename=_session_env_filename,
                    cache_bypass=_cache_bypass,
                )
            except Exception as exc:
                logger.exception(
                    "Bootstrap render failed for session=%s: %s",
                    _session_name,
                    exc,
                )
                return SocaResponse(
                    success=False,
                    message=_(
                        f"Unable to generate bootstrap templates because of {exc}"
                    ),
                ).as_flask()

            # Update soca_parameters so the user_data stub render below
            # picks up the new S3 locations. The user_data stub itself
            # stays per-session-rendered (it IS the per-session
            # UserData) but it now references both the per-session env
            # file and the (possibly cached) big bootstrap prefix.
            soca_parameters["/job/BootstrapScriptsS3Location"] = (
                _render_result.bootstrap_scripts_s3
            )
            soca_parameters["/job/SessionEnvS3Location"] = _render_result.session_env_s3
            logger.info(
                "Bootstrap render: cache_key=%s cache_hit=%s",
                _render_result.cache_key,
                _render_result.cache_hit,
            )

            # Now that soca_parameters has the final (possibly cached) S3
            # locations, render the per-session UserData stub. The stub
            # references both /job/BootstrapScriptsS3Location (the cached
            # big bootstrap bodies) and /job/SessionEnvS3Location (the
            # per-session env file) at template-render time -- which is
            # NOW, after the cache has run. Rendering this earlier would
            # bake in the early per-session defaults and miss the cache
            # bodies entirely.
            if _software_stack_info.get("os_family") == "windows":
                _user_data_template = "windows_virtual_desktop/01_user_data.ps1.j2"
            else:
                _user_data_template = "compute_node/01_user_data.sh.j2"

            _generate_user_data = SocaJinja2Generator(
                get_template=_user_data_template,
                template_dirs=[
                    f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID')}/cluster_node_bootstrap/"
                ],
                variables=soca_parameters,
            ).to_stdout(autocast_values=True)

            if _generate_user_data.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=f"Unable to generate UserData Jinja2 template because of {_generate_user_data.get('message')}",
                ).as_flask()
            else:
                user_data = clean_user_data(
                    text_to_remove=[
                        "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                        "# SPDX-License-Identifier: Apache-2.0",
                    ],
                    data=_generate_user_data.get("message"),
                )

            if args["hibernate"]:
                try:
                    check_hibernation_support = client_ec2.describe_instance_types(
                        InstanceTypes=[instance_type],
                        Filters=[{"Name": "hibernation-supported", "Values": ["true"]}],
                    )
                    logger.debug(
                        f"Checking instance {instance_type} for Hibernation support: {check_hibernation_support}"
                    )
                    if len(check_hibernation_support.get("InstanceTypes", {})) == 0:
                        if config.Config.DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT is True:
                            return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                                session_number=args["session_name"],
                                session_owner=_user,
                                helper=f"Sorry your administrator limited DCV to instances that support hibernation mode",
                            ).as_flask()
                        else:
                            return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                                session_number=args["session_name"],
                                session_owner=_user,
                                helper=f"Sorry you have selected {instance_type} with hibernation support, but this instance type does not support it. Either disable hibernation support or pick a different instance type",
                            ).as_flask()
                    else:
                        # The instance type supports hibernation, but AWS also
                        # enforces an OS-specific RAM ceiling (V1587014009):
                        # exceeding it makes the VDI CloudFormation stack fail at
                        # launch. Reject it here with a clear message. Reuses the
                        # MemoryInfo already returned above (no extra API call).
                        from api.v1.dcv.instance_type_search import hibernation_ram_ok

                        _hib_mem_mib = (
                            check_hibernation_support["InstanceTypes"][0]
                            .get("MemoryInfo", {})
                            .get("SizeInMiB")
                        )
                        _ram_ok, _ram_reason = hibernation_ram_ok(
                            _hib_mem_mib,
                            _software_stack_info.get("ami_base_os"),
                        )
                        if _ram_ok is False:
                            return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                                session_number=args["session_name"],
                                session_owner=_user,
                                helper=f"{instance_type}: {_ram_reason}",
                            ).as_flask()
                except ClientError as e:
                    return SocaError.AWS_API_ERROR(
                        service_name="ec2",
                        helper=f"Error while checking hibernation support of instance {instance_type} because of {e}",
                    ).as_flask()

            if _software_stack_info.get("ami_base_os") in [
                os.value for os in SocaWindowsBaseOS
            ]:
                # Windows OS, do not use gzip
                _encoded_user_data = base64.b64encode(user_data.encode("utf-8")).decode(
                    "utf-8"
                )
            else:
                # Linux distro, use gzip to save UserData size
                _encoded_user_data = base64.b64encode(
                    gzip.compress(user_data.encode("utf-8"))
                ).decode("utf-8")

            _spot_requested = False
            if (
                SocaCastEngine(args.get("spot"))
                .cast_as(expected_type=bool)
                .get("message")
                is True
            ):
                _spot_allowed = SocaConfig(
                    key="/configuration/FeatureFlags/VirtualDesktops/AllowSpot"
                ).get_value(return_as=bool)
                if (
                    _spot_allowed.get("success") is True
                    and _spot_allowed.get("message") is True
                ):
                    _spot_requested = True
                else:
                    logger.warning(
                        "Spot requested but FeatureFlags/VirtualDesktops/AllowSpot is not enabled; ignoring"
                    )

            _ipv6_cast = SocaCastEngine(
                _get_soca_parameters.get(
                    "/configuration/FeatureFlags/Networking/EnableIPv6", False
                )
            ).cast_as(expected_type=bool)
            _enable_ipv6 = (
                _ipv6_cast.get("message")
                if _ipv6_cast.get("success") is True
                else False
            )

            launch_parameters = {
                "security_group_id": _get_soca_parameters.get(
                    "/configuration/VdiNodeSecurityGroup"
                ),
                "instance_profile": _get_soca_parameters.get(
                    "/configuration/VdiNodeInstanceProfileArn"
                ),
                "instance_type": instance_type,
                "subnet_id": _selected_subnet,
                "tenancy": args.get("tenancy"),
                "project": args.get("project"),
                "image_id": _ami_id,
                "session_name": _session_name,
                "session_uuid": _session_uuid,
                "base_os": _software_stack_info.get("ami_base_os"),
                "disk_size": args["disk_size"],
                "volume_type": _get_soca_parameters.get(
                    "/configuration/DefaultVolumeType"
                ),
                "volume_acceleration": _software_stack_info.get("volume_acceleration"),
                "cluster_id": _get_soca_parameters.get("/configuration/ClusterId"),
                "metadata_http_tokens": _get_soca_parameters.get(
                    "/configuration/MetadataHttpTokens"
                ),
                "hibernate": args["hibernate"],
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
                "VdiNodeInstanceProfileArn": _get_soca_parameters.get(
                    "/configuration/VdiNodeInstanceProfileArn"
                ),
                "user_data": _encoded_user_data,
                "custom_tags": {},
                "capacity_reservation_id": args["capacity_reservation_id"],
                "nested_virtualization": args["nested_virtualization"],
                "enable_ipv6": _enable_ipv6,
                "spot": _spot_requested,
            }

            # Get custom tags if specified
            logger.info("Checking if custom tags exist")
            _tags_allowed = SocaConfig(
                key="/configuration/FeatureFlags/VirtualDesktops/AllowCustomTags"
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
                    "Custom tags are not allowed. AllowCustomTagsVDI is set to false"
                )

            logger.debug(f"Launch parameters for DCV: {launch_parameters}")

            # --- Async placement (skips dry-run + ODCR + CreateStack) ---
            _async_flag = SocaConfig(
                key="/configuration/FeatureFlags/AsyncPlacement"
            ).get_value(default="false", allow_unknown_key=True)
            if _async_flag.success and _async_flag.message.lower() == "true":
                launch_parameters["async_placement"] = True
                launch_template = dcv_cloudformation_builder.main(**launch_parameters)
                if launch_template.get("success") is not True:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Template build failed: {launch_template.get('message')}"
                    ).as_flask()
                _cfn_stack_name = re.sub(r"[^a-zA-Z0-9\-]", "", _stack_name)
                _cfn_stack_tags = [
                    {
                        "Key": "edh:JobName",
                        "Value": str(launch_parameters["session_name"]),
                    },
                    {"Key": "edh:JobOwner", "Value": _user},
                    {
                        "Key": "edh:ClusterId",
                        "Value": str(launch_parameters["cluster_id"]),
                    },
                    {"Key": "edh:JobProject", "Value": args.get("project")},
                    {"Key": "edh:NodeType", "Value": "dcv_node"},
                    {
                        "Key": "edh:BaseOS",
                        "Value": _software_stack_info.get("ami_base_os"),
                    },
                    {"Key": "edh:SessionUuid", "Value": str(_session_uuid)},
                ]
                # VDI pool: try an idle HOT member before cold placement. On a
                # hit, write a placing row with the claimed instance_id; the
                # session_state_watcher registers the broker session and
                # promotes placing->running (no cold launch). Miss -> continue.
                from helpers import vdi_pool_allocator

                # Pool members are provisioned console (vdi_pool_render sets
                # SessionType=console). Default resolution can pick "virtual"
                # (non-GPU AL2023), which a console member can't serve -- force
                # the claim to the member's actual type.
                _pool_session_type = "console"
                _pool_claim = vdi_pool_allocator.try_claim_hot(
                    stack_id=_software_stack_id.message,
                    instance_type=args["instance_type"],
                    owner=_user,
                    base_os=_software_stack_info.get("ami_base_os"),
                    session_uuid=_session_uuid,
                    session_type=_pool_session_type,
                    session_name=_session_name,
                )
                if _pool_claim:
                    _pool_session = VirtualDesktopSessions(
                        is_active=True,
                        created_on=datetime.now(timezone.utc),
                        deactivated_on=None,
                        session_owner=_user,
                        session_uuid=_session_uuid,
                        session_project=args.get("project"),
                        session_id=soca_parameters["/dcv/SessionId"],
                        session_name=_session_name,
                        stack_name=_cfn_stack_name,
                        session_local_admin_password=_session_local_admin_password,
                        authentication_token=_pool_claim.get("broker_session_id"),
                        session_token=str(uuid.uuid4()),
                        session_thumbnail=_software_stack_info.get("thumbnail"),
                        schedule=json.dumps(config.Config.DCV_DEFAULT_SCHEDULE),
                        session_state=(
                            "running" if _pool_claim.get("ready") else "placing"
                        ),
                        session_state_latest_change_time=datetime.now(timezone.utc),
                        instance_private_dns=None,
                        instance_private_ip=None,
                        instance_id=_pool_claim.get("instance_id"),
                        instance_type=args["instance_type"],
                        instance_base_os=_software_stack_info.get("ami_base_os"),
                        os_family=_software_stack_info.get("os_family"),
                        support_hibernation=args["hibernate"],
                        software_stack_id=_software_stack_id.message,
                        session_type=_pool_session_type,
                    )
                    try:
                        db.session.add(_pool_session)
                        db.session.commit()
                    except Exception as _pool_err:
                        db.session.rollback()
                        return SocaError.GENERIC_ERROR(
                            helper=f"Pool desktop claimed but DB write failed: {_pool_err}"
                        ).as_flask()
                    return (
                        {
                            "success": True,
                            "message": f"Pool desktop assigned for {_session_uuid}",
                        },
                        200,
                    )

                # Resolve CFN notification ARNs (same as sync path)
                _async_cfn_notification_arns = []
                _cfn_topic_resp = SocaConfig(
                    key="/configuration/CfnEventsTopicArn"
                ).get_value(default="", allow_unknown_key=True)
                if _cfn_topic_resp.success and _cfn_topic_resp.message:
                    _async_cfn_notification_arns = [_cfn_topic_resp.message]

                from utils.async_placement import enqueue_placement

                _enqueue_result = enqueue_placement(
                    session_uuid=_session_uuid,
                    stack_name=_cfn_stack_name,
                    template_body=launch_template.get("message"),
                    cfn_tags=_cfn_stack_tags,
                    cfn_notification_arns=_async_cfn_notification_arns,
                    instance_type=args.get("instance_type"),
                    ami_id=_ami_id,
                    capacity_reservation_id=args["capacity_reservation_id"],
                    spot=_spot_requested,
                    subnet_ids=(
                        [_selected_subnet]
                        if args["capacity_reservation_id"]
                        else _soca_private_subnets
                    ),
                    tenancy=args.get("tenancy"),
                    instance_platform=_instance_platform,
                    session_row=VirtualDesktopSessions(
                        is_active=True,
                        created_on=datetime.now(timezone.utc),
                        deactivated_on=None,
                        session_owner=_user,
                        session_uuid=_session_uuid,
                        session_project=args.get("project"),
                        session_id=soca_parameters["/dcv/SessionId"],
                        session_name=_session_name,
                        stack_name=_cfn_stack_name,
                        session_local_admin_password=_session_local_admin_password,
                        authentication_token=None,
                        session_token=str(uuid.uuid4()),
                        session_thumbnail=_software_stack_info.get("thumbnail"),
                        schedule=json.dumps(config.Config.DCV_DEFAULT_SCHEDULE),
                        session_state="placing",
                        session_state_latest_change_time=datetime.now(timezone.utc),
                        instance_private_dns=None,
                        instance_private_ip=None,
                        instance_id=None,
                        instance_type=args["instance_type"],
                        instance_base_os=_software_stack_info.get("ami_base_os"),
                        os_family=_software_stack_info.get("os_family"),
                        support_hibernation=args["hibernate"],
                        is_spot=_spot_requested,
                        software_stack_id=_software_stack_id.message,
                        session_type=_session_type,
                    ),
                )
                if _enqueue_result.get("success"):
                    return (
                        {
                            "success": True,
                            "message": f"Placement queued for {_session_uuid}",
                        },
                        200,
                    )
                else:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Async placement failed: {_enqueue_result.get('message')}"
                    ).as_flask()
            # --- End async placement ---

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
                hibernate=launch_parameters.get("hibernate"),
                metadata_http_tokens=launch_parameters.get("metadata_http_tokens"),
                key_name=_get_soca_parameters.get("/configuration/SSHKeyPair"),
                desired_capacity=1,
            )
            logger.info(f"Dry Run Result: {dry_run_launch}")

            if dry_run_launch.get("success"):
                launch_template = dcv_cloudformation_builder.main(**launch_parameters)
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
                        {"Key": "edh:JobOwner", "Value": _user},
                        {"Key": "edh:JobProject", "Value": "desktop"},
                        {
                            "Key": "edh:ClusterId",
                            "Value": str(launch_parameters["cluster_id"]),
                        },
                        {"Key": "edh:JobProject", "Value": args.get("project")},
                        {"Key": "edh:NodeType", "Value": "dcv_node"},
                        {
                            "Key": "edh:BaseOS",
                            "Value": _software_stack_info.get("ami_base_os"),
                        },
                        {
                            "Key": "edh:SessionUuid",
                            "Value": str(_session_uuid),
                        },
                    ]

                    # Optional: subscribe the per-cluster CFN events SNS
                    # topic so stack lifecycle events flow into the relay
                    # Lambda for grid-timeline first-dot rendering.
                    # Resolved at create time (not boot) so a topic added
                    # via hot-patch is picked up immediately.
                    _cfn_notification_arns = []
                    _cfn_topic_resp = SocaConfig(
                        key="/configuration/CfnEventsTopicArn"
                    ).get_value(default="", allow_unknown_key=True)
                    if _cfn_topic_resp.success and _cfn_topic_resp.message:
                        _cfn_notification_arns = [_cfn_topic_resp.message]

                    _create_stack = SocaCfnClient(
                        stack_name=_cfn_stack_name
                    ).create_stack(
                        template_body=launch_template.get("message"),
                        tags=_cfn_stack_tags,
                        notification_arns=_cfn_notification_arns,
                    )
                    if _create_stack.get("success") is True:
                        logger.info(
                            f"CloudFormation stack {_cfn_stack_name} successfully created"
                        )

                    else:
                        logger.info(
                            f"Stack could not be created, deleting {soca_parameters['/job/BootstrapPath']}"
                        )
                        try:
                            folder = Path(soca_parameters["/job/BootstrapPath"])
                            if folder.exists():
                                shutil.rmtree(folder)
                        except Exception as err:
                            logger.warning(
                                f"Unable to delete {soca_parameters['/job/BootstrapPath']} due to {err}"
                            )

                        return SocaError.GENERIC_ERROR(
                            helper=f"{_create_stack.get('message')}"
                        ).as_flask()
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="ec2",
                    helper=f"{dry_run_launch.get('message')}",
                ).as_flask()

            logger.info(
                "New Virtual Desktop CloudFormation request successful, adding session on the database"
            )

            # Adding Software Stack thumbnail, maybe one day we will add a live screenshot from DCV
            _session_thumbnail = _software_stack_info.get("thumbnail")

            new_session = VirtualDesktopSessions(
                is_active=True,
                created_on=datetime.now(timezone.utc),
                deactivated_on=None,
                session_owner=_user,
                session_uuid=_session_uuid,
                session_project=args.get("project"),
                session_id=soca_parameters["/dcv/SessionId"],
                session_name=_session_name,
                stack_name=_cfn_stack_name,
                session_local_admin_password=_session_local_admin_password,
                authentication_token=None,
                session_token=str(uuid.uuid4()),
                session_thumbnail=_session_thumbnail,
                schedule=json.dumps(config.Config.DCV_DEFAULT_SCHEDULE),
                session_state="pending",
                session_state_latest_change_time=datetime.now(timezone.utc),
                instance_private_dns=None,
                instance_private_ip=None,
                instance_id=None,
                instance_type=args["instance_type"],
                instance_base_os=_software_stack_info.get("ami_base_os"),
                os_family=_software_stack_info.get("os_family"),
                support_hibernation=args["hibernate"],
                is_spot=_spot_requested,
                software_stack_id=_software_stack_id.message,
                session_type=_session_type,
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
