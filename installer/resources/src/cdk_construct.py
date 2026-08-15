#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

import shutil
from aws_cdk.aws_logs import ILogGroup, LogGroup
from botocore.client import BaseClient
import cdk_construct_user_customization
from helpers.lambda_fleet_stack import LambdaFleetStack
from constructs import Construct
import os
import tempfile
import datetime
import typing
from typing import Optional, TypeVar, Union, List, Dict
from aws_cdk import (
    Duration,
    Stack,
    NestedStack,
    App,
    Tags,
    Environment,
    Aws,
    CustomResource,
    CfnOutput,
    CfnDeletionPolicy,
    Fn,
    RemovalPolicy,
    aws_directoryservice as ds,
    aws_dynamodb as dynamodb,
    aws_efs as efs,
    aws_ec2 as ec2,
    aws_globalaccelerator as globalaccelerator,
    aws_autoscaling as autoscaling,
    aws_opensearchservice as opensearch,
    aws_opensearchserverless as opensearchserverless,
    aws_elasticache as elasticache,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_events as events,
    aws_events_targets,
    aws_fsx as fsx,
    aws_lambda as aws_lambda,
    aws_logs as logs,
    aws_iam as iam,
    aws_backup as backup,
    aws_certificatemanager as acm,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subscriptions,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    aws_lambda_event_sources as lambda_event_sources,
    aws_route53resolver as route53resolver,
    aws_ssm as ssm,
    aws_s3 as s3,
    aws_s3_assets as s3_assets,
    aws_kms as kms,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    CfnTag,
    Annotations,
    Aspects,
    Size,
    Stack,
    Tags,
    aws_batch as batch,
    aws_ecs as ecs,
    aws_ec2 as ec2,
)

import json
import sys
import base64
import ast
import hashlib
import tempfile
from types import SimpleNamespace
import jinja2
from jinja2 import select_autoescape, FileSystemLoader

from helpers import (
    security_groups as security_groups_helper,
    secretsmanager as secretsmanager_helper,
    boto3_wrapper as boto3_helper,
    storage as storage_helper,
    user_data as user_data_helper,
    webshell as webshell_helper,
    database as database_helper,
    aoss as aoss_helper,
    vdi_pools as vdi_pools_helper,
    dcv_session_sharing as dcv_session_sharing_helper,
    user_preferences as user_preferences_helper,
    ai_token_usage as ai_token_usage_helper,
)
from helpers.aspects import CdkTokenGuardAspect, EventSourceMappingTagStripAspect, LambdaExecWrapperAspect
import re
import pathlib
import logging
import uuid
from rich.text import Text
from rich.table import Table
from rich.logging import RichHandler


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one
class CustomFormatter(logging.Formatter):
    def format(self, record):
        if not isinstance(record.msg, (Text, Table)):
            if record.levelno == logging.ERROR:
                record.msg = f"[bold red]{record.msg}[/bold red]"
            elif record.levelno == logging.WARNING:
                record.msg = f"[bold yellow]{record.msg} [/bold yellow]"
            elif record.levelno == logging.FATAL:
                record.msg = f"[bold red] FATAL {record.msg}[/bold red]"

        return super().format(record)


class CustomLogger(logging.getLoggerClass()):
    def fatal(self, msg, *args, **kwargs):
        self.critical(msg, *args, **kwargs)
        sys.exit(1)


_soca_debug = os.environ.get("SOCA_DEBUG", False)
if _soca_debug in ["1", "enabled", "true", "True", "on", "2", "trace"]:
    _log_level = logging.DEBUG
    _formatter = CustomFormatter("[%(asctime)s] %(levelname)s - %(message)s")
else:
    _log_level = logging.INFO
    _formatter = CustomFormatter("%(message)s")

_rich_handler = RichHandler(
    rich_tracebacks=True,
    markup=True,
    show_time=False,
    show_level=False,
    show_path=False,
)
_rich_handler.console.file = sys.stdout
_rich_handler.setFormatter(_formatter)

logging.basicConfig(level=_log_level, handlers=[_rich_handler])
logging.setLoggerClass(CustomLogger)
logging.root.manager.loggerDict.pop("soca_logger", None)
logger = logging.getLogger("soca_logger")

for _logger_name in ["boto3", "botocore"]:
    logging.getLogger(_logger_name).setLevel(
        logging.DEBUG if _soca_debug in {"trace", "2"} else logging.WARNING
    )


# sitecustomize.py shipped in the boto3 layer; the exec wrapper puts it on the
# path at cold start, where it sets the SO0072 UA on every botocore session.
_SOCA_LAMBDA_UA_SITECUSTOMIZE = '''# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# AUTO-GENERATED -- sets the SO0072 solution-attribution User-Agent on botocore.
_SOCA_USER_AGENT_EXTRA = "AwsSolution/SO0072/26.8.0"

try:
    import botocore.session as _soca_bc_session

    _soca_orig_session_init = _soca_bc_session.Session.__init__

    def _soca_session_init(self, *args, **kwargs):
        _soca_orig_session_init(self, *args, **kwargs)
        _existing = self.user_agent_extra or ""
        if _SOCA_USER_AGENT_EXTRA not in _existing:
            self.user_agent_extra = (
                _SOCA_USER_AGENT_EXTRA
                if not _existing
                else _existing + " " + _SOCA_USER_AGENT_EXTRA
            )

    if not getattr(_soca_bc_session.Session, "_soca_ua_patched", False):
        _soca_bc_session.Session.__init__ = _soca_session_init
        _soca_bc_session.Session._soca_ua_patched = True
except Exception:
    pass
'''


_SOCA_LAMBDA_UA_WRAPPER = '''#!/bin/bash
# AUTO-GENERATED -- AWS_LAMBDA_EXEC_WRAPPER: put the layer's sitecustomize on the path, then exec the runtime.
export PYTHONPATH="/opt/python${PYTHONPATH:+:$PYTHONPATH}"
exec "$@"
'''


def get_service_principal_url_suffix():
    region = user_specified_variables.region
    # amazonaws.eu is not a correct endpoint for AWS::IAM::ServiceLinkedRole  or AWS::IAM::Role  and must use amazonaws.com
    _url_suffix = "amazonaws.com" if region.startswith("eusc-") else Aws.URL_SUFFIX
    return _url_suffix


def get_lambda_runtime_version() -> aws_lambda.Runtime:
    return typing.cast(aws_lambda.Runtime, aws_lambda.Runtime.PYTHON_3_13)


def get_supported_azs_list_by_instance_type(region: str, instance_type: str) -> list:
    """
    Return a sorted list of the AZs for a given instance type and region. This indicates the AZs where a specific instance_type can be deployed within the region.
    """
    logger.debug(
        f"get_supported_azs_list_by_instance_type: Resolving the supported AZs in {region=} for {instance_type=}"
    )

    # FIXME TODO - This should probably use a more global EC2 client
    _ec2_client = boto3_helper.get_boto(
        service_name="ec2",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )

    _supported_az_list: list = []

    try:
        # Pager not needed since we are filtering for exact-match of an instance type
        _resp = _ec2_client.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[
                {"Name": "instance-type", "Values": [instance_type]},
            ],
        )
        logger.debug(f"Response: {_resp=}")

    except Exception as _err:
        logger.error(_err)
        exit(1)

    # What we validate in the reply API response
    _types_validation: dict = {
        "InstanceType": instance_type,
        "LocationType": "availability-zone",
    }

    for _offering in _resp.get("InstanceTypeOfferings", []):

        for _type_valid in _types_validation:
            if _offering.get(_type_valid) != _types_validation.get(_type_valid):
                logger.error(
                    f"API validation failed for {_type_valid} . Does not match expected value {_types_validation.get(_type_valid)} - Got back {_offering.get(_type_valid)}. Possible defect!"
                )
                continue

        # Shouldn't happen - but we check just in case
        if _offering.get("Location") not in _supported_az_list:
            _supported_az_list.append(_offering.get("Location"))
        else:
            logger.warning(
                f"Duplicate AZ for {_offering.get('Location')} - possible API return corruption"
            )

    if not _supported_az_list:
        logger.fatal(f"No supported AZs found for {region=} / {instance_type=}")
        exit(1)

    logger.debug(
        f"Supported AZs for {region=} / {instance_type=}({len(_supported_az_list)}): {', '.join(_supported_az_list)}"
    )

    return sorted(_supported_az_list)


def get_config_key(
    key_name: str,
    required: bool = True,
    default: typing.Any = None,
    expected_type: [str, int, float, bool, list, dict] = str,
) -> typing.Any:

    _result = install_props
    for key in key_name.split("."):
        _result = _result.get(key)
        if _result is None:
            break

    if required and _result is None:
        logger.fatal(f"{key_name} must be set but returned no value")

    if _result is None and default is not None:
        # logger.debug(f"Default specified as  [[ {default} ]] / Type: {type(default)} - Returning")
        return default
    else:
        # Empty result with no default - so we infer what the caller wants from the expected_type
        # and return a matching 'empty' that matches that type.
        # This makes sure that we return to the caller what they are expecting (e.g. a string) versus a NoneType.
        try:
            if _result is None:
                # logger.debug(
                #     f"Result lookup is empty - Expected {expected_type} for {key_name} / Returning empty equiv for the data type"
                # )
                if expected_type is str:
                    _ret_value: str = ""
                elif expected_type is int:
                    _ret_value: int = 0
                elif expected_type is float:
                    _ret_value: float = 0.0
                elif expected_type is bool:
                    _ret_value: bool = False
                elif expected_type is list:
                    _ret_value: list = []
                elif expected_type is dict:
                    _ret_value: dict = {}
                else:
                    # This shouldn't happen
                    logger.fatal(
                        f"Unsupported type passed to get_config_key(): {expected_type}"
                    )

                logger.debug(
                    f"Returning an empty equiv for key {key_name} - [[ {_ret_value} ]] / {type(_ret_value)}"
                )
                return _ret_value
            else:
                return expected_type(_result)
        except ValueError:
            logger.fatal(f"Expected {expected_type} for {key_name}")


def flatten_parameterstore_config(
    d: dict, parent_key: str = "", sep: str = "/"
) -> dict:
    _items = []
    for k, v in d.items():
        # Remove index number (/0, /1 etc ...) generated during the iterate process
        parent_key = re.sub(r"/\d+$|^\d+/", "", parent_key)
        # Create the new key, cast everything as string
        _new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            _items.extend(flatten_parameterstore_config(v, _new_key, sep=sep).items())
        elif isinstance(v, list):
            _items.append((_new_key, " ".join(v)))
        else:
            _items.append((_new_key, v))
    return dict(_items)


def get_subnet_route_table_by_subnet_id(subnet_ids: list) -> dict:
    """
    Return the route tables associated with a list of given subnets.
    The returned dict contains the subnetID and route-table IDs for those found.
    """
    _return_dict: dict = {}

    # Subnets to VPC lookup
    # Needed to resolve a subnet to a specific VPC-ID for the def route table
    # subnet-123 -> vpc-123
    _subnet_to_vpc: dict = {}

    # Store a mapping of VPCId to RTB ID for defaults
    # These do not explicitly show up in the return API as the default is a fallback
    # dict is simple lookup of:
    # vpc-123 -> rtb-123
    # This can therefore be applied to any subnets in vpc-123 that have not seen
    # explicit associations
    _default_rtb_id_by_vpc_id: dict = {}

    logger.debug(f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=}")

    ec2_client = boto3_helper.get_boto(
        service_name="ec2",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )

    # First - make sure we understand our subnets to VPC mappings

    logger.debug("Starting Subnet to VPC mapping lookup")
    _vpc_lu_paginator = ec2_client.get_paginator("describe_subnets")

    _vpc_lu_iterator = _vpc_lu_paginator.paginate(SubnetIds=subnet_ids)

    for _vpc_lu_i in _vpc_lu_iterator:
        logger.debug(f"Processing VPC LU: {_vpc_lu_i=}")
        for _vpc_lu_subnet in _vpc_lu_i.get("Subnets", []):
            _subnet_state: str = _vpc_lu_subnet.get("State", "")
            _subnet_vpc_id: str = _vpc_lu_subnet.get("VpcId", "")
            _subnet_subnet_id: str = _vpc_lu_subnet.get("SubnetId", "")

            if not _subnet_state:
                logger.fatal(f"Cannot determine subnet state for subnets {subnet_ids}")

            if not _subnet_vpc_id:
                logger.fatal(
                    f"Cannot determine subnet VPC ids for subnets {subnet_ids}"
                )

            if not _subnet_subnet_id:
                logger.fatal(f"Cannot determine subnet IDs for subnets {subnet_ids}")

            # Sanity
            if _subnet_state not in ["available"]:
                logger.warning(
                    f"SubnetID {_subnet_subnet_id} in VPC {_subnet_vpc_id} - state ({_subnet_state}) is not available - skipping"
                )
                continue

            logger.debug(
                f"Saving Subnet to VPC mapping of {_subnet_subnet_id} - {_subnet_vpc_id}"
            )
            _subnet_to_vpc[_subnet_subnet_id] = _subnet_vpc_id

    logger.debug("Completed Subnet to VPC mapping lookup")

    # Grab the default route-tables for the VPCs
    # We need these for returns that don't have explicit associations

    _def_rtb_paginator = ec2_client.get_paginator("describe_route_tables")
    logger.debug("Scanning for VPC default route tables")
    _def_rtb_iterator = _def_rtb_paginator.paginate(
        Filters=[{"Name": "association.main", "Values": ["true"]}]
    )
    for _rt_i in _def_rtb_iterator:
        for _rt in _rt_i.get("RouteTables", []):
            _vpc_id: str = _rt.get("VpcId", "")
            _owner_id: str = _rt.get("OwnerId", "")
            if not _vpc_id:
                logger.fatal("Unable to determine VPCId for Route Table entry")
            if not _owner_id:
                logger.fatal("Unable to determine OwnerID for Route Table entry")

            logger.debug(f"VPC {_vpc_id} / Owner {_owner_id}")

            for _associations in _rt.get("Associations", []):
                _rtb_id: str = _associations.get("RouteTableId", "")
                if not _rtb_id:
                    logger.fatal(f"Unable to determine RouteTableId for {_vpc_id}")

                if _associations.get("Main", False):
                    logger.debug(f"Default RTB VPC {_vpc_id} - {_rtb_id}")
                    _default_rtb_id_by_vpc_id[_vpc_id] = _rtb_id
                else:
                    logger.debug(
                        f"VPC {_vpc_id} - Assoc {_associations=} . Non-Default. This can be normal."
                    )

    # Now query the subnets we are actually interested in
    logger.debug(f"Querying route tables for subnets {subnet_ids=}")

    _rt_paginator = ec2_client.get_paginator("describe_route_tables")
    _rt_iterator = _rt_paginator.paginate(
        Filters=[{"Name": "association.subnet-id", "Values": subnet_ids}]
    )

    for _rt_i in _rt_iterator:
        logger.debug(f"Processing {_rt_i}")
        for _rt in _rt_i.get("RouteTables", []):
            logger.debug(f"Processing RouteTables {_rt=}")
            _rtb_id: str = _rt.get("RouteTableId", "")
            _vpc_id: str = _rt.get("VpcId", "")
            _owner_id: str = _rt.get("OwnerId", "")

            if not _vpc_id:
                logger.fatal("Unable to determine VPCId for Route Table entry")
            if not _owner_id:
                logger.fatal("Unable to determine OwnerID for Route Table entry")

            logger.debug(f"VPC {_vpc_id} / Owner {_owner_id}")

            for _associations in _rt.get("Associations", []):
                # SubnetIds only appear in explicit associations between the Route Tables and Subnets
                # The default route table may therefore apply to a subnet and not be explicitly listed
                # in the API return.
                # If we don't have an _rtb_id - assume that the subnet uses the default route table ID
                logger.debug(f"Scanning {_rtb_id=}")
                if not _rtb_id:
                    logger.debug(
                        f"Performing lookup for default route table for {_vpc_id=}"
                    )
                    _def_rtb_id: str = _default_rtb_id_by_vpc_id.get(_vpc_id, "")

                    if not _def_rtb_id:
                        logger.fatal(
                            f"Unable to find explicit route-table ID for subnet and no default exists for VPC {_vpc_id}"
                        )

                    _rtb_id = _def_rtb_id
                    logger.info(f"Using VPC {_vpc_id} default route table of {_rtb_id}")

                _subnet_id = _associations.get("SubnetId", "")
                if _subnet_id in subnet_ids:
                    if _subnet_id not in _return_dict:
                        _return_dict[_subnet_id] = _rtb_id
                    else:
                        logger.debug(
                            f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=} / found duplicate subnet {_subnet_id=} in route table {_rtb_id}"
                        )
                else:
                    # The response came back for a subnetID we are not interested in?
                    logger.warning(
                        f"get_subnet_route_table_by_subnet_id() got information for {_subnet_id} - but I didnt ask for it!  Defect?"
                    )
                    continue

    # Sanity check - make sure we have a route table for each subnet and apply VPC default otherwise
    _missing_subnet_ids = [x for x in subnet_ids if x not in _return_dict.keys()]

    if _missing_subnet_ids:
        for _missing_subnet_id in _missing_subnet_ids:
            logger.debug(
                f"Trying to resolve default RTB for Subnet ID {_missing_subnet_id}"
            )
            _vpc_def_rtb: str = _default_rtb_id_by_vpc_id.get(
                _subnet_to_vpc.get(_missing_subnet_id, ""), ""
            )

            if not _vpc_def_rtb:
                logger.fatal(
                    f"Unable to resolve Subnet route table information for {_missing_subnet_id}"
                )
            _return_dict[_missing_subnet_id] = _vpc_def_rtb

        # logger.fatal(
        #     f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=} / missing route table for {_missing_subnet_ids=}"
        # )

    logger.debug(
        f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=} / returning {_return_dict=}"
    )
    return _return_dict


def get_arch_for_instance_type(region: str, instancetype: str) -> str:
    _found_arch = None
    logger.debug(
        f"get_arch_for_instance_type() called with {region=} / {instancetype=}"
    )
    ec2_client = boto3_helper.get_boto(
        service_name="ec2",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )
    _resp = ec2_client.describe_instance_types(InstanceTypes=[instancetype])

    _instance_info = _resp.get("InstanceTypes", {})

    for _i in _instance_info:
        _instance_name = _i.get("InstanceType", None)
        # This shouldn't happen with an exact-match search
        if _instance_name != instancetype:
            continue

        _proc_info = _i.get("ProcessorInfo", {})
        if _proc_info:
            _arch = sorted(_proc_info.get("SupportedArchitectures", []))
            _found_arch = _arch[0]

    return _found_arch


def is_valid_backup_vault_arn(arn: str) -> bool:
    """
    Check if the provided ARN is a valid AWS Backup vault ARN
    """
    _backup_vault_arn_pattern = r"^arn:(aws|aws-us-gov|aws-cn):backup:[a-z0-9\-]+:[0-9]{12}:backup-vault:[a-zA-Z0-9\-]+$"
    return bool(re.match(_backup_vault_arn_pattern, arn))


def validate_kms_key_id(kms_client: BaseClient, key_id: str) -> tuple[bool, str]:
    """
    Validate the KMS KeyID via the AWS API and return the ARN.
    This can take an ARN as the key_id or an alias name.
    """
    logger.debug(f"validate_kms_key_id() called with {kms_client=} / {key_id=}")

    if not key_id:
        logger.debug("No KMS key_id passed to is_valid_kms_key_id() - rejecting.")
        return False, ""
    if not kms_client:
        logger.fatal(
            "No KMS client passed to is_valid_kms_key_id() - unable to continue. Probable code defect."
        )

    # If we are passed something that doesn't look like an ARN - fixup the name as it
    # is an alias lookup. E.g. 'MyEBSCMK' becomes 'alias/MyEBSCMK' for API calls.
    # This also covers AWS default keys. E.g. "aws/ebs" becomes "alias/aws/ebs"
    if is_arn_string(arn_string=key_id, arn_type="kms_key_id"):
        logger.debug(f"Looks like a KMS KeyID ARN: {key_id}")
    else:
        logger.debug(f"Alias KeyID: {key_id} -> alias/{key_id}")
        key_id = f"alias/{key_id}"

    try:
        _key_information = kms_client.describe_key(KeyId=key_id).get("KeyMetadata", {})
    # TODO - Add specific exceptions with proper errors/logging/returns
    except kms_client.exceptions.NotFoundException as e:
        logger.error(f"KMS KeyID: {key_id} not found: {e}")
        return False, ""
    except Exception as e:
        logger.error(f"Error performing KMS KeyID validation: {e}")
        return False, ""

    if _key_information:
        logger.debug(f"Found KMS KeyID: {key_id} - KeyInformation - {_key_information}")

        # Make sure the key is enabled
        # If it is not enabled - we purposely exit hard here versus assuming something
        # about encryption that could be incorrect. Never assume about security/encryption!
        if not _key_information.get("Enabled", False):
            logger.error(f"KMS KeyID: {key_id} is disabled. Unable to use this KeyID")
            return False, ""
        else:
            logger.debug(f"KMS KeyID: {key_id} is enabled. Good.")

        # Enabled and ready to go
        _key_descr: str = _key_information.get("Description", "")
        _key_creation_str: str = str(_key_information.get("CreationDate", ""))
        _key_arn_str: str = _key_information.get("Arn", "")
        logger.debug(
            f"Acceptable KMS KeyID found: {key_id} - {_key_descr} - {_key_creation_str} - ARN: {_key_arn_str}"
        )
        return True, _key_arn_str
    return False, ""


def is_arn_string(arn_string: str, arn_type: str = "") -> bool:
    """
    Check if the provided string is an ARN. Optionally with stricter enforcement for known ARN types (arn_type).
    """
    _service_arns: dict = {
        "kms_key_id": r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32}|alias/[a-zA-Z0-9/_-]+|(arn:aws[-a-z]*:kms:[a-z0-9-]+:\d{12}:((key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})|(key/mrk-[0-9a-f]{32})|(alias/[a-zA-Z0-9/_-]+))))$",
    }

    _re_pattern: str = ""
    if arn_type:
        logger.debug(f"Looking for specific ARN pattern for {arn_type}")
        _re_pattern = _service_arns.get(arn_type.lower(), "")
        if not _re_pattern:
            _re_pattern = "^arn:aws[-a-z]*:"
            logger.warning(
                f"No specific ARN pattern found for {arn_type} . Using basic ARN string validation: {_re_pattern}"
            )
        else:
            logger.debug(f"Using specific ARN pattern for {arn_type}: {_re_pattern}")

    else:
        _re_pattern = "^arn:aws[-a-z]*:"
        logger.debug(f"Performing basic ARN string validation: {_re_pattern}")

    return bool(re.match(pattern=_re_pattern, string=arn_string))


def return_ebs_volume_type(volume_string: str, fallback_volume: str = "gp2") -> str:
    """
    For a given string value of an EBS volume - return the proper CDK representation or the fallback volume.
    """
    logger.debug(
        f"Looking for EBS volume type: {volume_string} / Fallback: {fallback_volume}"
    )

    if not volume_string:
        logger.warning(
            "No volume_string passed to return_ebs_volume_type() - probable defect"
        )
        if fallback_volume:
            volume_string = fallback_volume
        else:
            logger.fatal(
                "No volume_string or fallback_volume passed to return_ebs_volume_type() - unable to continue. Probable code defect."
            )

    if not isinstance(volume_string, str):
        logger.fatal(
            "volume_string must be a string - unable to continue. Probable code defect."
        )

    if not isinstance(fallback_volume, str):
        logger.fatal(
            "fallback_volume must be a string - unable to continue. Probable code defect."
        )

    _ebs_volume_type_map = {_m.name.lower(): _m for _m in ec2.EbsDeviceVolumeType}
    _ebs_volume_type_map.update(
        {
            "default": ec2.EbsDeviceVolumeType.GP3,
            "standard": ec2.EbsDeviceVolumeType.GP3,  # override: avoid magnetic
            "__fallback__": ec2.EbsDeviceVolumeType.GP2,  # kept at GP2
        }
    )
    # Fallback for our fallback
    _fallback_value = _ebs_volume_type_map.get(fallback_volume.lower())

    if not _fallback_value:
        _fallback_value = _ebs_volume_type_map.get("__fallback__")
        logger.warning(
            f"Invalid fallback value: {fallback_volume} - Defaulting to __fallback__: {_fallback_value}"
        )

    logger.debug(f"Looking for EBS volume type: {volume_string}")
    _volume_type = _ebs_volume_type_map.get(volume_string.lower(), _fallback_value)

    logger.debug(f"Returning {_volume_type}")

    return _volume_type


def get_kms_key_id(config_key_names: list, allow_global_default: bool = True) -> str:
    """
    Retrieve the KMS key ID (ARN) based on the provided key names from the config. If this key doesn't exist, check for the global KMS KeyID. If not - return an empty string.
    """
    _kms_client = boto3_helper.get_boto(
        service_name="kms",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )
    _kms_key_id: str = ""
    _global_config_key_location: str = "Config.kms_key_id"

    # If we allow the global default - append it to the end of the list for ease of use
    # Since this is a 'first match wins' - it will be consulted in the last/lowest priority/fallback case.
    if allow_global_default:

        _global_key_id = get_config_key(
            key_name=_global_config_key_location,
            required=False,
            expected_type=str,
            default="",
        )
        logger.debug(
            f"Global KMS KeyID: {_global_key_id} /  Type: {type(_global_key_id)}"
        )
        if len(_global_key_id) > 0:
            if _global_config_key_location not in config_key_names:
                logger.debug(
                    f"Adding Global key ID location ({_global_config_key_location}) to list of key names to validate (allow_global_default) as it contains a valid entry ({_global_key_id})"
                )
                config_key_names.append(_global_config_key_location)
            else:
                # Warn the user - but it is non-fatal at this stage
                logger.warning(
                    f"Global KMS KeyID location ({_global_config_key_location}) is already in the list of config key names to validate. Check your configuration. Continuing anyway"
                )
        elif _global_key_id == "":
            logger.debug(
                f"Blank Global KMS KeyID found at {_global_config_key_location} for fallback."
            )
            config_key_names.append(_global_config_key_location)
    else:
        logger.warning(
            "allow_global_default set to False. Skipping global default key ID check."
        )

    # No incoming configuration key list to validate
    # This only takes place when we are set for allow_global_default False and get an empty list of config keys to check
    if not config_key_names:
        logger.warning("No config_key_names passed to get_kms_key_id - returning empty")
        return ""

    logger.debug(
        f"Looking for resource specific KMS KeyID: {config_key_names} / Allow Global Default: {allow_global_default}"
    )

    for _key_name in config_key_names:
        logger.debug(f"Determining KeyID validity: {_key_name}")

        _kms_key_id = get_config_key(
            key_name=_key_name, required=False, expected_type=str, default=""
        )

        if _kms_key_id == "" and _key_name == config_key_names[-1]:
            logger.debug(f"Last Empty KeyID found at {_key_name} - using defaults")
            break
        elif _kms_key_id == "":
            logger.debug(f"Empty KeyID found at {_key_name} - trying next entry")
            continue

        logger.debug(f"Preparing to API lookup keyID: {_kms_key_id}")
        _key_lu_result, _key_arn = validate_kms_key_id(
            kms_client=_kms_client, key_id=_kms_key_id
        )

        if _key_lu_result:
            logger.debug(
                f"Validated/Selected KeyID: {_key_name} /  {_kms_key_id} / ARN: {_key_arn}"
            )
            _kms_key_id = _key_arn
            break
        else:
            logger.warning(
                f"Invalid KeyID at {_key_name}  / {_kms_key_id}. Trying next entry"
            )
            continue

    # Exiting the for loop we should have a valid _kms_key_id

    logger.debug(f"Returning KMS KeyID: {_kms_key_id}")
    return _kms_key_id


class SOCAInstall(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        cluster_tags: Optional[List[Dict]] = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.vpc_interface_endpoints = {}
        self.vpc_gateway_endpoints = {}
        self.deployment_id: str = str(uuid.uuid4())
        self.tag_ec2_resource_lambda = None

        # Track every BulkSSMWriter CustomResource so the final resources
        # (e.g. the `cdk_completed` signal parameter) can depend on all
        # of them and wait for SSM writes to finish before signaling the rest to continue
        self._bulk_ssm_writers = []

        # KeyName -> TagKeyValue
        # That we should make sure all resources have
        self.cluster_tags = cluster_tags

        # A list of address-families that are enabled
        self.networking_enabled_af = ["ipv4"]
        if get_config_key(
            key_name="Config.feature_flags.Networking.EnableIPv6",
            expected_type=bool,
            required=False,
            default=False,
        ):
            self.networking_enabled_af.append("ipv6")

        _template_dirs = [
            pathlib.Path.cwd().parent,  # for user_data folder
            pathlib.Path(
                f"{pathlib.Path.cwd()}/../../../source/soca/cluster_node_bootstrap/"  # for all templates
            ).resolve(),
        ]

        self.jinja2_env = jinja2.Environment(
            loader=FileSystemLoader(_template_dirs),
            extensions=["jinja2.ext.do"],
            autoescape=select_autoescape(
                enabled_extensions=("j2", "jinja2"),
                default_for_string=True,
                default=True,
            ),
        )

        # Init SOCA resources
        self.soca_resources = {
            "alb": None,
            "nlb": None,
            "alb_sg": None,
            "nlb_sg": None,
            "dcv_frontend_nlb_sg": None,
            "dcv_backend_nlb_sg": None,
            "dcv_screenshot_lambda_sg": None,
            "dcv_event_relay_lambda_sg": None,
            "ssm_config_sync_lambda_sg": None,
            "elasticache": None,
            "elasticache_sg": None,
            "database": None,
            "database_sg": None,
            "database_secret": None,
            "backup_role": None,
            "custom_ami_map": {},
            "base_os": user_specified_variables.base_os,
            "compute_node_instance_profile": None,
            "compute_node_role": None,
            "vdi_node_instance_profile": None,
            "vdi_node_role": None,
            "target_node_instance_profile": None,
            "target_node": None,
            "compute_node_sg": None,
            "vdi_node_sg": None,
            "target_node_sg": None,
            "ami_id": None,
            "os_domain": None,
            "os_collection_endpoint": None,
            "fs_apps": None,
            "fs_data": None,
            "get_es_private_ip_lambda_role": None,
            "login_node_sg": None,
            "nat_gateway_ips": [],
            "controller_eip": None,
            "controller_instance": None,
            "controller_role": None,
            "controller_sg": None,
            "spot_fleet_role": None,
            "solution_metrics_lambda_role": None,
            "vpc": None,
            "soca_secret": None,
            "soca_config": None,
            "cluster_tags": self.cluster_tags,
        }
        self.soca_filesystems = {}
        self._bulk_ssm_writers = []  # Track all BulkSSMWriter CustomResources for dependency ordering
        # Capacity-bumper requests queued by features (e.g. dcv_infrastructure())
        # whose call sites run BEFORE configuration() builds the cdk_completed
        # sentinel. Drained by _flush_pending_capacity_bumpers() right after
        # self.configuration() in __init__. See _register_asg_capacity_bumper().
        self._pending_capacity_bumpers: list[dict] = []

        self._base_os = user_specified_variables.base_os
        self._region = user_specified_variables.region
        self._partition = user_specified_variables.partition

        logger.debug("Creating SOCAInstall()")
        logger.debug(f"Base OS                 : {self._base_os}")
        logger.debug(f"Region                  : {self._region}")
        logger.debug(f"Partition               : {self._partition}")
        logger.debug(f"Deployment ID           : {self.deployment_id}")
        logger.debug(f"Deployment Tags         : {self.cluster_tags}")

        _supported_base_os = get_config_key(
            key_name="Parameters.system.base_os.supported",
            required=True,
            expected_type=list,
        )
        _eol_base_os = get_config_key(
            key_name="Parameters.system.base_os.eol",
            required=True,
            expected_type=list,
        )
        # Store architectures as they may come in handy for jobs that differ from the Controller architecture
        # TODO - a bit of a hack
        for _arch in ["arm64", "x86_64"]:
            if _arch not in self.soca_resources["custom_ami_map"]:
                self.soca_resources["custom_ami_map"][_arch] = {}

            for _base_os_available in _eol_base_os + _supported_base_os:
                self.soca_resources["custom_ami_map"][_arch][_base_os_available] = (
                    ""
                    if not get_config_key(
                        key_name=f"RegionMap.{self._region}.{_arch}.{_base_os_available}",
                        required=False,
                    )
                    else get_config_key(
                        key_name=f"RegionMap.{self._region}.{_arch}.{_base_os_available}",
                        required=False,
                    )
                )

        # Determine our architecture base on controller
        # and our ami_id based on base_os/architecture
        # user_specified_variables.custom_ami

        _located_ami = None
        _instance_type: list = get_config_key(
            key_name="Config.controller.instance_type",
            expected_type=list,
            required=False,
            default=["m8i-flex.large", "m7i-flex.large", "m5.large"],
        )
        logger.debug(f"ControllerNode - Configured instance type: {_instance_type}")

        self._instance_type, self._instance_arch, _default_instance_ami = (
            self.select_best_instance(
                instance_list=_instance_type,
                region=user_specified_variables.region,
                fallback_instance="m5.large",
            )
        )

        logger.debug(
            f"ControllerNode - Selected instance type: { self._instance_type} / Arch: {self._instance_arch}"
        )

        #
        # Used later to store our ControllerEIP value (IP address)
        #
        self._controller_eip_value = None

        # Cache Info

        self.cache_info = {
            "enabled": get_config_key(
                key_name="Config.services.aws_elasticache.enabled",
                expected_type=bool,
                default=True,
                required=False,
            ),
            "engine": get_config_key(
                key_name="Config.services.aws_elasticache.engine", expected_type=str
            ),
            "port": None,
            "endpoint": None,
            "ttl": {
                "short": get_config_key(
                    key_name="Config.services.aws_elasticache.ttl.short",
                    expected_type=int,
                ),
                "long": get_config_key(
                    key_name="Config.services.aws_elasticache.ttl.long",
                    expected_type=int,
                ),
            },
        }
        # Our DS domain is used for route53 rule creation
        # This can be specified in the configuration as directoryservice.name - defaults to <cluster_id>.local
        _ds_domain_name = get_config_key(
            key_name="Config.directoryservice.domain_name",
            expected_type=str,
            required=False,
            default=f"{user_specified_variables.cluster_id}.local",
        ).lower()

        _ds_provider = get_config_key(
            key_name="Config.directoryservice.provider"
        ).lower()
        _use_existing_directory = False
        _endpoint = None

        if _ds_provider in {"existing_openldap", "existing_active_directory"}:
            _endpoint = get_config_key(
                key_name=f"Config.directoryservice.{_ds_provider}.endpoint",
                required=False,
                default=None,
            )
            _use_existing_directory = True

        self.directory_service_resource_setup = {
            "use_existing_directory": _use_existing_directory,
            "provider": _ds_provider,
            "domain_name": _ds_domain_name.lower(),
            "short_name": get_config_key(
                key_name="Config.directoryservice.short_name",
                expected_type=str,
                required=False,
                default=_ds_domain_name.split(".")[0].upper()[:15],
            ).upper(),
            "domain_base": get_config_key(
                key_name="Config.directoryservice.domain_base",
                expected_type=str,
                required=False,
                default=f"dc={',dc='.join(_ds_domain_name.split('.'))}".lower(),
            ).lower(),
            "endpoint": _endpoint.lower() if _endpoint is not None else _endpoint,
            "ad_aws_directory_service_id": False,
            "service_account_secret_arn": get_config_key(
                key_name=f"Config.directoryservice.{_ds_provider}.service_account_secret_name_arn",
                required=False,
                default=None,
            ),
            "domain_controller_ips": [],
        }

        # Retrieve Directory OU/CN settings based on config values
        # Default options that are created automatically by AWS DS and cannot be changed
        _aws_specific_default_value = {
            "aws_ds_managed_activedirectory": {
                "admins_search_base": f"{get_config_key(key_name=f'Config.directoryservice.aws_ds_managed_activedirectory.admins_search_base')},OU=Users,OU={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
                "people_search_base": f"ou=Users,ou={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
                "group_search_base": f"ou=Users,ou={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
            },
        }

        if _ds_provider in _aws_specific_default_value.keys():
            self.directory_service_resource_setup["people_search_base"] = (
                _aws_specific_default_value[_ds_provider].get("people_search_base")
            )
            self.directory_service_resource_setup["group_search_base"] = (
                _aws_specific_default_value[_ds_provider].get("group_search_base")
            )
            self.directory_service_resource_setup["admins_search_base"] = (
                _aws_specific_default_value[_ds_provider].get("admins_search_base")
            )

        else:
            _admins_search_base = get_config_key(
                key_name=f"Config.directoryservice.{self.directory_service_resource_setup.get('provider')}.admins_search_base"
            ).lower()
            _people_search_base = get_config_key(
                key_name=f"Config.directoryservice.{self.directory_service_resource_setup.get('provider')}.people_search_base"
            ).lower()
            _group_search_base = get_config_key(
                key_name=f"Config.directoryservice.{self.directory_service_resource_setup.get('provider')}.group_search_base"
            ).lower()

            # People
            if (
                self.directory_service_resource_setup.get("domain_base")
                not in _people_search_base
            ):
                self.directory_service_resource_setup["people_search_base"] = (
                    f"{_people_search_base},{self.directory_service_resource_setup.get('domain_base')}"
                )
            else:
                self.directory_service_resource_setup["people_search_base"] = (
                    f"{_people_search_base}"
                )

            # Group
            if (
                self.directory_service_resource_setup.get("domain_base")
                not in _group_search_base
            ):
                self.directory_service_resource_setup["group_search_base"] = (
                    f"{_group_search_base},{self.directory_service_resource_setup.get('domain_base')}"
                )
            else:
                self.directory_service_resource_setup["group_search_base"] = (
                    f"{_group_search_base}"
                )

            # Admins
            if (
                self.directory_service_resource_setup.get("domain_base")
                not in _admins_search_base
            ):
                self.directory_service_resource_setup["admins_search_base"] = (
                    f"{_admins_search_base},{self.directory_service_resource_setup.get('domain_base')}"
                )
            else:
                self.directory_service_resource_setup["admins_search_base"] = (
                    f"{_admins_search_base}"
                )

        # Validate Directory Settings
        if (
            self._base_os in ("rhel8", "rhel9", "rocky8", "rocky9")
            and self.directory_service_resource_setup.get("provider") == "openldap"
        ):
            logger.fatal(
                f"Base OS of {self._base_os} does not support openldap. Please use aws_ds_managed_activedirectory, existing_active_directory, or existing_openldap instead"
            )

        if self.directory_service_resource_setup.get("endpoint") is not None:
            if (
                re.match(
                    r"^(ldaps://|ldap://)",
                    self.directory_service_resource_setup.get("endpoint"),
                )
                is None
            ):
                logger.fatal(
                    f"Config.directoryservice.{_ds_provider}.use_existing_directory is set but does not start with ldaps:// or ldap://"
                )

        if (
            self.directory_service_resource_setup.get("use_existing_directory") is True
            and self.directory_service_resource_setup.get("service_account_secret_arn")
            is None
        ):
            logger.fatal(
                f"Config.directoryservice.{_ds_provider}.use_existing_directory is set to True but Config.directoryservice.service_account_secret_arn is not set"
            )

        if (
            self.directory_service_resource_setup.get("use_existing_directory") is None
            and self.directory_service_resource_setup.get("service_account_secret_arn")
            is not None
        ):
            logger.fatal(
                f"Config.directoryservice.{_ds_provider}.use_existing_directory is None but Config.directoryservice.service_account_secret_arn is set"
            )

        logger.debug(
            f"DS Environment Setup Name: {self.directory_service_resource_setup}"
        )

        # Validate Scheduler installation mechanism
        _scheduler_deployment_options = get_config_key(
            "Parameters.system.scheduler.openpbs", expected_type=dict
        )

        _scheduler_deployment_type = _scheduler_deployment_options.get(
            "deployment_type"
        )

        if _scheduler_deployment_type == "git":
            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "repo"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.repo is None but must be set since Parameters.scheduler.openpbs.deployment_type is et to {_scheduler_deployment_type}"
                )

            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "version"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.version is None but must be set since Parameters.scheduler.openpbs.deployment_type is et to {_scheduler_deployment_type}"
                )

        if _scheduler_deployment_type == "s3_tgz":
            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "s3_uri"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.s3_uri is None but must be set since Parameters.scheduler.openpbs.deployment_type is et to {_scheduler_deployment_type}"
                )

            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "version"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.version is None but must be set since Parameters.scheduler.openpbs.deployment_type is et to {_scheduler_deployment_type}"
                )

        _schedulers_to_install = get_config_key(
            key_name="Config.scheduler.scheduler_engine",
            expected_type=list,
            default=[],
        )

        for _scheduler in _schedulers_to_install:
            if _scheduler not in ["lsf", "openpbs", "slurm"]:
                logger.warning(
                    f"{_scheduler} is not a valid/supported scheduler to be installed on SOCA Controller, ignoring ..."
                )

            if _scheduler == "lsf":
                _lsf_errors = []
                if (
                    get_config_key(
                        key_name="Parameters.system.scheduler.lsf.version", default=None
                    )
                    is None
                ):
                    _lsf_errors.append(
                        "Parameters.system.scheduler.lsf.version is not set"
                    )

                _lsf_installer_s3_uri = get_config_key(
                    key_name="Parameters.system.scheduler.lsf.lsf_installer_s3_uri",
                    default=None,
                )
                if _lsf_installer_s3_uri is None:
                    _lsf_errors.append(
                        "Parameters.system.scheduler.lsf.lsf_installer_s3_uri is not set"
                    )
                else:
                    if _lsf_installer_s3_uri.endswith("/"):
                        _bucket_name = re.search(
                            r"s3://([^/]+)/", _lsf_installer_s3_uri
                        )
                        if _bucket_name:
                            if _bucket_name.group(1) != user_specified_variables.bucket:
                                _lsf_errors.append(
                                    f"lsf_installer_s3_uri must use the same bucket name as {user_specified_variables.bucket}, detected {_lsf_installer_s3_uri}"
                                )
                        else:
                            _lsf_errors.append(
                                f"{_lsf_installer_s3_uri} does not seems to be a valid S3 url, must be s3://<bucket>/<path>..../"
                            )

                    else:
                        _lsf_errors.append(
                            f"lsf_installer_s3_uri must end with / , detected {_lsf_installer_s3_uri}"
                        )

                if (
                    get_config_key(
                        key_name="Parameters.system.scheduler.lsf.lsf_entitlement_file_name",
                        default=None,
                    )
                    is None
                ):
                    _lsf_errors.append(
                        "Parameters.system.scheduler.lsf.lsf_entitlement_file_name is not set "
                    )

                if (
                    get_config_key(
                        key_name="Parameters.system.scheduler.lsf.lsf_installer_file_name",
                        default=None,
                    )
                    is None
                ):
                    _lsf_errors.append(
                        "Parameters.system.scheduler.lsf.lsf_installer_file_name is not set"
                    )

                if _lsf_errors:
                    logger.fatal(
                        f"LSF scheduler installation detected but the following errors have been reported {_lsf_errors}"
                    )

        _apps_provider = user_specified_variables.fs_apps_provider
        _data_provider = user_specified_variables.fs_data_provider

        if self.directory_service_resource_setup.get("provider") in [
            "openldap",
            "existing_openldap",
        ]:
            for fs_provider in [_apps_provider, _data_provider]:
                if fs_provider == "fsx_ontap":
                    logger.fatal(
                        "Config.storage.apps.provider and/or Config.storage.data.provider are set to fsx_ontap but Config.directoryservice.provider is not ActiveDirectory. AD is required for FSx ONTAP"
                    )

        self.soca_resources["ami_id"] = (
            self.soca_resources["custom_ami_map"]
            .get(self._instance_arch, "x86_64")
            .get(self._base_os, "amazonlinux2")
        )

        # Resolve our secretsmanager key for future use
        _sm_key_id: str = get_kms_key_id(
            config_key_names=[
                "Config.services.aws_secretsmanager.kms_key_id",  # Current configuration for kms_key_id
            ],
            allow_global_default=True,
        )

        logger.debug(f"Resolved SecretsManager KMS Key ID configuration: {_sm_key_id}")
        self.soca_resources["secretsmanager_kms_key_id"] = (
            kms.Key.from_key_arn(self, id="SecretsManagerKMSKey", key_arn=_sm_key_id)
            if _sm_key_id
            else None
        )
        logger.debug(
            f"Resolved SecretsManager KMS Key ID: {_sm_key_id} : {self.soca_resources['secretsmanager_kms_key_id']}"
        )

        # Create SOCA environment
        self.create_cluster_log_group()

        self.network()  # Create Network environment

        if self._auto_mpl_enabled():
            logger.info("Automatic EC2 Managed Prefix List (MPL) mode is active")
            self.managed_prefix_lists()  # Create Managed Prefix Lists (MPL) that are needed prior to SGs

        self.security_groups()  # Create Security Groups

        self.iam_roles()  # Create IAM roles and policies for primary roles needed to deploy resources

        # Create boto3 Lambda layer with version from config (no Docker)
        _boto3_version = get_config_key(
            key_name="Config.lambda_layers.Boto3Version",
            required=False,
            default="",
        )
        if _boto3_version:
            import subprocess

            _layers_base = os.path.join(
                os.path.dirname(__file__), "..", ".lambda_layers"
            )
            _layer_base = os.path.join(_layers_base, f"boto3-{_boto3_version}")
            _layer_dir = os.path.join(_layer_base, "python")
            if not os.path.exists(_layer_dir):
                # Remove any old version dirs
                if os.path.exists(_layers_base):
                    for d in os.listdir(_layers_base):
                        if d.startswith("boto3-"):
                            shutil.rmtree(os.path.join(_layers_base, d))
                os.makedirs(_layer_dir)
                subprocess.check_call(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "install",
                        f"boto3=={_boto3_version}",
                        "-t",
                        _layer_dir,
                        "--no-cache-dir",
                        "-q",
                    ]
                )

            # sitecustomize.py written into the layer each synth; 26.8.0 is
            # substituted by the release pipeline (github_release.py), like on-box.
            with open(
                os.path.join(_layer_dir, "sitecustomize.py"), "w", encoding="utf-8"
            ) as _sc_fh:
                _sc_fh.write(_SOCA_LAMBDA_UA_SITECUSTOMIZE)

            # Exec-wrapper script -> /opt/bin/edh-ua-wrapper (see LambdaExecWrapperAspect).
            _wrapper_bin_dir = os.path.join(_layer_base, "bin")
            os.makedirs(_wrapper_bin_dir, exist_ok=True)
            _wrapper_file = os.path.join(_wrapper_bin_dir, "edh-ua-wrapper")
            with open(_wrapper_file, "w", encoding="utf-8") as _wr_fh:
                _wr_fh.write(_SOCA_LAMBDA_UA_WRAPPER)
            os.chmod(_wrapper_file, 0o755)

            self.soca_resources["boto3_layer"] = aws_lambda.LayerVersion(
                self,
                "Boto3Layer",
                description=f"boto3 {_boto3_version}",
                compatible_runtimes=[
                    typing.cast(aws_lambda.Runtime, get_lambda_runtime_version())
                ],
                code=aws_lambda.Code.from_asset(os.path.dirname(_layer_dir)),
            )
        else:
            self.soca_resources["boto3_layer"] = None

        # Set AWS_LAMBDA_EXEC_WRAPPER on functions that attach the boto3 layer.
        if self.soca_resources.get("boto3_layer") is not None:
            Aspects.of(self).add(
                LambdaExecWrapperAspect(
                    self.soca_resources["boto3_layer"].layer_version_arn
                )
            )

        # Redis Lambda layer for SsmConfigSync (and any future Lambda that
        # needs to talk to ElastiCache directly). Mirrors the boto3_layer
        # pattern: install at synth time into a local dir, point Layer asset
        # at that dir. redis-py is pure-Python so cross-platform install
        # is safe.
        _redis_version = get_config_key(
            key_name="Config.lambda_layers.RedisVersion",
            required=False,
            default="5.2.1",  # matches controller venv pin in soca_python_controller_requirements.txt.j2
        )
        if _redis_version:
            import subprocess as _subp_redis  # local alias to avoid confusing readers

            _redis_layer_base_dir = os.path.join(
                os.path.dirname(__file__), "..", ".lambda_layers", f"redis-{_redis_version}"
            )
            _redis_layer_python_dir = os.path.join(_redis_layer_base_dir, "python")
            if not os.path.exists(_redis_layer_python_dir):
                # Clean any stale older versions
                _redis_layers_root = os.path.join(
                    os.path.dirname(__file__), "..", ".lambda_layers"
                )
                if os.path.exists(_redis_layers_root):
                    for _d in os.listdir(_redis_layers_root):
                        if _d.startswith("redis-"):
                            shutil.rmtree(os.path.join(_redis_layers_root, _d))
                os.makedirs(_redis_layer_python_dir)
                _subp_redis.check_call(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "install",
                        f"redis=={_redis_version}",
                        "-t",
                        _redis_layer_python_dir,
                        "--no-cache-dir",
                        "-q",
                    ]
                )
            self.soca_resources["redis_layer"] = aws_lambda.LayerVersion(
                self,
                "RedisLayer",
                description=f"redis-py {_redis_version} (used by SsmConfigSync and future cache Lambdas)",
                compatible_runtimes=[
                    typing.cast(aws_lambda.Runtime, get_lambda_runtime_version())
                ],
                code=aws_lambda.Code.from_asset(_redis_layer_base_dir),
            )
        else:
            self.soca_resources["redis_layer"] = None

        # Cryptography Lambda layer -- reusable across any Lambda that needs
        # X.509 / CA generation (first consumer: DcvBrokerCaGenerator). Unlike
        # the boto3/redis layers (pure-Python, host-arch-agnostic), cryptography
        # ships COMPILED, arch-specific wheels: a plain `pip install -t` on the
        # installer host would bake the host's wheel and ImportError on the
        # Lambda runtime. So we fetch the wheel for the Lambda's runtime + arch
        # (manylinux x86_64, abi3) explicitly. Consumers MUST pin
        # architecture=X86_64 to match.
        _crypto_version = get_config_key(
            key_name="Config.lambda_layers.CryptographyVersion",
            required=False,
            default="48.0.0",
        )
        if _crypto_version:
            import subprocess as _subp_crypto  # local alias, mirrors redis layer

            _crypto_layer_base_dir = os.path.join(
                os.path.dirname(__file__),
                "..",
                ".lambda_layers",
                f"cryptography-{_crypto_version}",
            )
            _crypto_layer_python_dir = os.path.join(_crypto_layer_base_dir, "python")
            if not os.path.exists(_crypto_layer_python_dir):
                _crypto_layers_root = os.path.join(
                    os.path.dirname(__file__), "..", ".lambda_layers"
                )
                if os.path.exists(_crypto_layers_root):
                    for _d in os.listdir(_crypto_layers_root):
                        if _d.startswith("cryptography-"):
                            shutil.rmtree(os.path.join(_crypto_layers_root, _d))
                os.makedirs(_crypto_layer_python_dir)
                # cryptography publishes abi3 wheels that load on any 3.x
                # runtime. cryptography 48.x ships manylinux_2_28 (AL2023 Lambda
                # = glibc 2.34, compatible); manylinux2014 listed as a fallback
                # for older pins. --only-binary forbids a host source build.
                _subp_crypto.check_call(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "install",
                        f"cryptography=={_crypto_version}",
                        "--platform",
                        "manylinux_2_28_x86_64",
                        "--platform",
                        "manylinux2014_x86_64",
                        "--only-binary=:all:",
                        "--python-version",
                        "3.13",
                        "--implementation",
                        "cp",
                        "-t",
                        _crypto_layer_python_dir,
                        "--no-cache-dir",
                        "-q",
                    ]
                )
            self.soca_resources["cryptography_layer"] = aws_lambda.LayerVersion(
                self,
                "CryptographyLayer",
                description=(
                    f"cryptography {_crypto_version} (x86_64 manylinux; "
                    "X.509/CA generation -- e.g. DcvBrokerCaGenerator)"
                ),
                compatible_runtimes=[
                    typing.cast(aws_lambda.Runtime, get_lambda_runtime_version())
                ],
                compatible_architectures=[aws_lambda.Architecture.X86_64],
                code=aws_lambda.Code.from_asset(_crypto_layer_base_dir),
            )
        else:
            self.soca_resources["cryptography_layer"] = None

        # psycopg (v3) Lambda layer -- reusable across any Lambda that needs
        # in-VPC Aurora/Postgres access (first consumer: UsbAllowlistResolver).
        # Like cryptography, psycopg[binary] ships COMPILED, arch-specific
        # wheels (bundled libpq + krb5/openssl/sasl .so): a plain host
        # `pip install -t` would bake the host's wheel (e.g. macOS) and
        # ImportError on the Lambda runtime. Fetch the manylinux x86_64 wheels
        # for the Lambda runtime explicitly. Consumers MUST pin
        # architecture=X86_64 to match.
        _psycopg_version = get_config_key(
            key_name="Config.lambda_layers.PsycopgVersion",
            required=False,
            default="3.3.4",
        )
        if _psycopg_version:
            import subprocess as _subp_psycopg  # local alias, mirrors crypto layer

            _psycopg_layer_base_dir = os.path.join(
                os.path.dirname(__file__),
                "..",
                ".lambda_layers",
                f"psycopg-{_psycopg_version}",
            )
            _psycopg_layer_python_dir = os.path.join(
                _psycopg_layer_base_dir, "python"
            )
            if not os.path.exists(_psycopg_layer_python_dir):
                _psycopg_layers_root = os.path.join(
                    os.path.dirname(__file__), "..", ".lambda_layers"
                )
                if os.path.exists(_psycopg_layers_root):
                    for _d in os.listdir(_psycopg_layers_root):
                        if _d.startswith("psycopg-"):
                            shutil.rmtree(os.path.join(_psycopg_layers_root, _d))
                os.makedirs(_psycopg_layer_python_dir)
                # psycopg[binary] pulls the compiled psycopg_binary wheel
                # (manylinux2014 x86_64 = glibc 2.17, runs on AL2023 glibc
                # 2.34). --only-binary forbids a host source build.
                _subp_psycopg.check_call(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "install",
                        f"psycopg[binary]=={_psycopg_version}",
                        "--platform",
                        "manylinux2014_x86_64",
                        "--only-binary=:all:",
                        "--python-version",
                        "3.13",
                        "--implementation",
                        "cp",
                        "-t",
                        _psycopg_layer_python_dir,
                        "--no-cache-dir",
                        "-q",
                    ]
                )
            self.soca_resources["psycopg_layer"] = aws_lambda.LayerVersion(
                self,
                "PsycopgLayer",
                description=(
                    f"psycopg[binary] {_psycopg_version} (x86_64 manylinux; "
                    "in-VPC Aurora/Postgres access -- e.g. UsbAllowlistResolver)"
                ),
                compatible_runtimes=[
                    typing.cast(aws_lambda.Runtime, get_lambda_runtime_version())
                ],
                compatible_architectures=[aws_lambda.Architecture.X86_64],
                code=aws_lambda.Code.from_asset(_psycopg_layer_base_dir),
            )
        else:
            self.soca_resources["psycopg_layer"] = None

        self.generic_resources()

        if get_config_key(
            key_name="Config.network.enable_vpc_gateway_endpoints",
            expected_type=bool,
            required=False,
            default=True,
        ):
            self.create_vpc_gateway_endpoints()

        if get_config_key(
            key_name="Config.network.use_vpc_endpoints",
            expected_type=bool,
            required=False,
        ):
            self.create_vpc_endpoints()

        if get_config_key(
            key_name="Config.services.aws_elasticache.enabled",
            expected_type=bool,
            default=True,
            required=False,
        ):
            self.elasticache()  # Create ElastiCache backend (deps: subnets, SGs)

        # Database backend (deps: subnets, SGs). The helper no-ops and returns
        # the info skeleton when Config.database.provider has no infra (e.g. sqlite).
        self.database()

        # Owned-base AMI lineage reconciler (copies base AMIs local -> fast capture + retirement
        # durability). Requires Aurora; gated at runtime by the BaseImageAcceleration feature flag.
        self.base_image_reconciler()

        # USB remotization allowlist resolver (Hardware Profile feature). The VDI
        # boot hook (attested) and the controller (admin API/CLI preview) call it
        # to resolve an instance's effective USB device allowlist. Requires the

        # Always deployed; Lambda no-ops until AllowSavedDesktops is enabled.
        self.spot_interruption_capture()

        if (
            get_config_key(
                key_name="Config.analytics.enabled",
                expected_type=bool,
                default=True,
                required=False,
            )
            is True
        ):
            self.analytics()  # Create Analytics domain

        self.directory_service()  # Create Directory Service (any flavor)

        self.storage()  # Create Storage

        if get_config_key(
            key_name="Config.services.resources_mirroring.enabled",
            expected_type=bool,
            default=True,
            required=False,
        ):
            self.resources_mirroring()  # Cloud-side artifact mirror (SFN + Lambdas + trigger)

        self.controller()  # Configure the Controller

        if get_config_key(
            key_name="Config.dcv.high_scale",
            expected_type=bool,
            default=False,
            required=False,
        ):
            logger.debug(
                "Configuring DCV High-Scale Deployment due to Config.dcv.high_scale==True"
            )
            # Configure HA / high-scale DCV infrastructure
            self.dcv_infrastructure()

        self.user_preferences()  # Generic WebUI user-preferences DDB table + SSM org defaults

        self.config_editor_audit()  # Configuration Editor audit trail DDB table (config-audit)
        self.ai_token_usage()  # AI Assistant daily token usage DDB table

        self.viewer()  # Configure the DCV Load Balancer
        self.login_nodes()  # Configure the Login Nodes
        self.webshell()  # Wire up /web_terminal/endpoint routing (no-op if disabled)

        if get_config_key(
            key_name="Config.services.aws_batch.create_default_edh_environment",
            expected_type=bool,
            required=False,
            default=False,
        ):
            self.aws_batch()

        # Determine AGA configuration status
        _alb_public_bool: bool = (
            True if user_specified_variables.deployment_mode == "public" else False
        )

        if _alb_public_bool and get_config_key(
            key_name="Config.network.aws_aga.enabled",
            expected_type=bool,
            default=False,
            required=False,
        ):
            logger.debug("AGA is enabled, configuring it")
            self.configure_aws_aga()
        else:
            logger.debug("AGA is not enabled, skipping it")

        # Notification infrastructure
        if get_config_key(
            key_name="Config.services.notification.enabled",
            expected_type=bool,
            required=False,
            default=True,
        ):
            logger.debug("Cluster Notification is enabled, configuring it")
            self.notification_infrastructure()

        # DCV high-scale CloudWatch alarms (depends on both the screenshot
        # poller and the SNS notification topic existing).
        self._dcv_high_scale_alarms()

        # ----- Lambda Fleet NestedStack -----
        # Houses the ops-automation Lambda fleet (~146 resources) in a
        # NestedStack to stay within the 500-resource CFN limit.
        # Instantiated here because layers, VPC, SGs, and all shared
        # infra the fleet depends on are ready by this point.
        _enable_bootstrap_cache = get_config_key(
            key_name="Config.feature_flags.BootstrapTemplateCache.enabled",
            expected_type=bool,
            required=False,
            default=True,
        )
        _enable_dcv_hs = get_config_key(
            key_name="Config.dcv.high_scale",
            expected_type=bool,
            default=False,
            required=False,
        )
        _enable_session_sharing = get_config_key(
            key_name="Config.dcv.session_sharing.enabled",
            expected_type=bool,
            default=True,
            required=False,
        ) and _enable_dcv_hs

        self.lambda_fleet_stack = LambdaFleetStack(
            self,
            "LambdaFleetStack",
            cluster_id=user_specified_variables.cluster_id,
            soca_resources=self.soca_resources,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            principals_suffix=principals_suffix,
            get_lambda_runtime_version=get_lambda_runtime_version,
            flatten_parameterstore_config=flatten_parameterstore_config,
            return_ebs_volume_type=return_ebs_volume_type,
            get_supported_azs_list_by_instance_type=get_supported_azs_list_by_instance_type,
            is_networking_af_enabled=self.is_networking_af_enabled,
            enable_dcv_high_scale=_enable_dcv_hs,
            enable_bootstrap_cache=_enable_bootstrap_cache,
            enable_session_sharing=_enable_session_sharing,
            enable_usb_allowlist=get_config_key(
                key_name="Config.services.usb_remotization.enabled",
                expected_type=bool,
                default=True,
                required=False,
            ) and bool(self.soca_resources.get("database")),
            directory_service_resource_setup=self.directory_service_resource_setup
            if hasattr(self, "directory_service_resource_setup")
            else None,
        )

        self.configuration()  # Store SOCA config
        # Drain any AsgCapacityBumper requests queued by earlier features
        # (e.g. dcv_infrastructure) that needed the cdk_completed sentinel
        # which configuration() just built.
        self._flush_pending_capacity_bumpers()

        if get_config_key(
            key_name="Config.services.aws_backup.enabled",
            expected_type=bool,
            required=False,
            default=True,
        ):
            self.backups()  # Configure AWS Backup & Restore
        else:
            logger.warning("AWS Backup integration is disabled per configuration")

        # User customization (Post Configuration)
        cdk_construct_user_customization.main(self, self.soca_resources)

        CfnOutput(
            self,
            "StackName",
            value=f"{Aws.STACK_NAME}",
        )

        # Cross-cutting synth-time validator: fail synth if any CDK token
        # has leaked into a deploy-time string surface (UserData, Lambda
        # env vars, CfnOutputs, Custom Resource properties, or s3_assets
        # source files). See docs/CdkTokenGuard.md for context.
        Aspects.of(self).add(CdkTokenGuardAspect())

        # some partitions reject tags on event source mappings.
        # ("Tags not supported in request"). The app-level cluster tags
        # propagate to every taggable resource, so strip Tags from ESMs in
        # non-commercial partitions (no-op in aws). See helpers/aspects/esm_tag_strip.py.
        Aspects.of(self).add(EventSourceMappingTagStripAspect(partition=self._partition))

    def create_cluster_log_group(self):
        """
        Create a common cluster log group.
        """
        # Create a common Logging group for the cluster and cluster-resources.
        # NOTE: This creates a named log group of the clusterID and RETAIN policy.
        # This means you will run into a conflict if you reinstall with the same name
        # and have not manually removed the log group
        # This is a circuit breaker to make sure a human intervention takes place to remove
        # the old log group
        #

        _log_prefix: str = get_config_key(
            key_name="Config.services.logging",
            expected_type=str,
            required=False,
        )

        self.soca_resources["cluster_log_group"] = self.generate_log_group(
            name="CommonLogs",
        )

    def get_log_deployment_id(self) -> str:
        """
        Return the log deployment ID, which is tied to the deployment ID.
        """

        logger.debug(
            f"Returning Deployment ID tag for logging group: {self.deployment_id}"
        )
        return self.deployment_id

    def _get_bulk_ssm_lambda(self) -> aws_lambda.Function:
        """
        Lazily create the shared BulkSSMWriter Lambda.

        A single Lambda + IAM role is created the first time this is called
        and then reused by every CustomResource that bulk-writes SSM
        parameters. The role is least-privilege:

        - ssm:PutParameter / DeleteParameter / DeleteParameters /
          GetParameter / GetParameters / AddTagsToResource /
          RemoveTagsFromResource, scoped to /edh/{cluster_id}/*
        - logs:CreateLogGroup / CreateLogStream / PutLogEvents (any)

        S3 GetObject is granted per-asset inside ``_write_bulk_ssm_params``
        via ``asset.grant_read(self._bulk_ssm_lambda_role)`` so no broad
        bucket-wide permission is needed. This limits functionality of the lambda to that S3 asset/file by design.
        """
        if not hasattr(self, "_bulk_ssm_lambda"):
            _role = iam.Role(
                self,
                "BulkSSMWriterRole",
                description="IAM role for Bulk SSM Parameter Writer Lambda",
                assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
            )
            _policy = iam.Policy(
                self,
                "BulkSSMWriterPolicy",
                statements=[
                    iam.PolicyStatement(
                        actions=[
                            "ssm:PutParameter",
                            "ssm:DeleteParameter",
                            "ssm:DeleteParameters",
                            "ssm:GetParameter",
                            "ssm:GetParameters",
                            "ssm:AddTagsToResource",
                            "ssm:RemoveTagsFromResource",
                        ],
                        resources=[
                            f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:"
                            f"parameter/edh/{user_specified_variables.cluster_id}/*"
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources=["*"],
                    ),
                ],
            )
            _role.attach_inline_policy(_policy)

            # Store policy + role refs so callers can:
            # - depend CustomResources on the policy (race-condition fix)
            # - grant per-asset S3 read on the role
            self._bulk_ssm_policy = _policy
            self._bulk_ssm_lambda_role = _role

            self._bulk_ssm_lambda = aws_lambda.Function(
                self,
                f"{user_specified_variables.cluster_id}-BulkSSMWriter",
                function_name=f"{user_specified_variables.cluster_id}-BulkSSMWriter",
                description="Write SSM parameters in bulk via Custom Resource",
                memory_size=256,
                runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
                timeout=Duration.minutes(15),
                log_group=self.generate_log_group(name="BulkSSMWriterLambda"),
                role=_role,
                handler="BulkSSMWriter.lambda_handler",
                code=aws_lambda.Code.from_asset("../functions/BulkSSMWriter"),
                layers=[_l for _l in [self.soca_resources.get("boto3_layer")] if _l]
                or None,
            )
        return self._bulk_ssm_lambda

    def _write_bulk_ssm_params(self, cr_id: str, params: dict | None = None, resolved_params: dict | None = None, exclude_keys: set | None = None):
        """Extracted to helpers/ssm.py."""
        from helpers import ssm as _helper

        return _helper._write_bulk_ssm_params(
            self,
            cr_id=cr_id,
            params=params,
            resolved_params=resolved_params,
            exclude_keys=exclude_keys,
        )

    def _get_asg_capacity_bumper_lambda(self) -> aws_lambda.Function:
        """
        Lazily create the shared AsgCapacityBumper Lambda + IAM role.

        Used to keep ASG-backed services (DCV broker, DCV gateway, and
        future opt-in ASGs) at MinSize=0 / DesiredCapacity=0 during stack
        create. A per-ASG Custom Resource depends on the cdk_completed
        sentinel and bumps MinSize+DesiredCapacity to their target values
        only after the SSM parameter tree is fully written. Cleaner ops
        logs: instances launch into a populated SSM tree and never
        emit "ParameterNotFound" / poll-loop noise during normal boot.

        IAM is tag-condition-scoped to this cluster's ASGs via
        aws:ResourceTag/edh:ClusterId, which CDK propagates onto every
        cluster resource.
        """
        if not hasattr(self, "_asg_bumper_lambda"):
            _role = iam.Role(
                self,
                "AsgCapacityBumperRole",
                description="IAM role for the ASG capacity bumper Lambda",
                assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
            )
            _role.attach_inline_policy(
                iam.Policy(
                    self,
                    "AsgCapacityBumperPolicy",
                    statements=[
                        iam.PolicyStatement(
                            actions=["autoscaling:UpdateAutoScalingGroup"],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/edh:ClusterId": user_specified_variables.cluster_id
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                            ],
                            resources=["*"],
                        ),
                    ],
                )
            )
            self._asg_bumper_lambda = aws_lambda.Function(
                self,
                f"{user_specified_variables.cluster_id}-AsgCapacityBumper",
                function_name=f"{user_specified_variables.cluster_id}-AsgCapacityBumper",
                description="Custom Resource Lambda that bumps ASG MinSize+DesiredCapacity after cdk_completed sentinel is set",
                memory_size=128,
                runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
                timeout=Duration.minutes(5),
                log_group=self.generate_log_group(name="AsgCapacityBumperLambda"),
                role=_role,
                handler="AsgCapacityBumper.lambda_handler",
                code=aws_lambda.Code.from_asset("../functions/AsgCapacityBumper"),
                layers=[_l for _l in [self.soca_resources.get("boto3_layer")] if _l]
                or None,
            )
        return self._asg_bumper_lambda

    def _register_asg_capacity_bumper(
        self,
        cr_id: str,
        asg: "autoscaling.AutoScalingGroup",
        target_min: int,
        target_desired: int,
    ) -> "CustomResource | None":
        """
        Register a Custom Resource that bumps an ASG's MinSize and
        DesiredCapacity after the cdk_completed sentinel is written.

        The ASG should be constructed with min_capacity=0 and
        desired_capacity=0; max_capacity stays at the real target so the
        bump can take effect without a separate Update.

        Idempotency:
        - Create: bumps to (target_min, target_desired)
        - Update: no-op (preserves operator-set scaling across stack updates)
        - Delete: no-op (CFN tears the ASG down)

        Failure on Create signals FAILED to CFN, the stack rolls back,
        and the ASG stays at 0/0 -- no half-bootstrapped instances.

        Ordering:
        - If cdk_completed_param exists at call time, the CR is built
          immediately and returned.
        - If not (caller runs before configuration() in __init__), the
          request is queued. _flush_pending_capacity_bumpers() drains
          the queue right after self.configuration() and re-enters this
          helper, which then takes the immediate path. Queued path
          returns None.
        """
        if "cdk_completed_param" not in self.soca_resources:
            # Sentinel not built yet (caller runs before configuration() in
            # __init__). Queue the request; _flush_pending_capacity_bumpers()
            # will materialize the CR after configuration() completes.
            self._pending_capacity_bumpers.append({
                "cr_id": cr_id,
                "asg": asg,
                "target_min": target_min,
                "target_desired": target_desired,
            })
            logger.debug(
                f"Queued AsgCapacityBumper {cr_id} (sentinel not yet built); "
                f"will materialize in _flush_pending_capacity_bumpers()"
            )
            return None

        _bumper_lambda = self._get_asg_capacity_bumper_lambda()

        _cr = CustomResource(
            self,
            cr_id,
            service_token=_bumper_lambda.function_arn,
            properties={
                "AsgName": asg.auto_scaling_group_name,
                "TargetMin": str(target_min),
                "TargetDesired": str(target_desired),
            },
        )

        # The bumper must run AFTER:
        #   - the ASG itself exists (implicit via the auto_scaling_group_name property reference)
        #   - the cdk_completed sentinel parameter has been written, which
        #     is gated by every BulkSSMWriter Custom Resource
        _cr.node.add_dependency(asg)
        _cr.node.add_dependency(self.soca_resources["cdk_completed_param"])

        logger.debug(
            f"Registered AsgCapacityBumper CR {cr_id} for "
            f"ASG={asg.node.id}, MinSize={target_min}, DesiredCapacity={target_desired}"
        )
        return _cr

    def _flush_pending_capacity_bumpers(self) -> None:
        """Materialize any AsgCapacityBumper Custom Resources that were
        queued before cdk_completed_param existed. Called once from
        __init__ immediately after self.configuration().

        Idempotent: clears the queue. Safe to call when queue is empty.
        """
        if "cdk_completed_param" not in self.soca_resources:
            raise RuntimeError(
                "_flush_pending_capacity_bumpers() called before "
                "cdk_completed_param was constructed. configuration() must "
                "run first."
            )
        if not self._pending_capacity_bumpers:
            return
        logger.debug(
            f"Flushing {len(self._pending_capacity_bumpers)} queued "
            f"AsgCapacityBumper requests"
        )
        # Snapshot + clear so a recursive call (shouldn't happen, but be
        # safe) cannot double-process.
        _queue = list(self._pending_capacity_bumpers)
        self._pending_capacity_bumpers.clear()
        for _req in _queue:
            # Re-enter the helper. cdk_completed_param exists now, so the
            # immediate path runs and the CR is built.
            self._register_asg_capacity_bumper(**_req)

    def _register_ad_computer_cleaner(self) -> aws_lambda.Function:
        """
        Stand up the AD-orphan cleanup pipeline:

          EventBridge (EC2 shutting-down) --> Lambda --> ssm:SendCommand
              -- targeted at this cluster's controller (tag-based) --
            on the controller: adcli delete-computer SOCA-<hash> using
            the cached AD service-account credentials the controller
            wrote during its own AD join.

        Why this exists
        ---------------
        SOCA names AD computer accounts with a deterministic
        SOCA-<sha1[-10:]> hostname per instance, but adcli also auto-
        registers a servicePrincipalName based on the OS hostname
        (host/ip-X-X-X-X.<region>.compute.internal). That SPN is shared
        by every instance that ever holds the same private IP. SOCA had
        no teardown logic, so terminated instances leave their AD
        computer object (with its SPN) behind. When a new instance
        reuses the same private IP, realm-join fails with AD error
        000021C7 / Att 90303 (servicePrincipalName).

        This pipeline removes the AD object on terminate so its SPN goes
        with it. Best-effort: a missed event (Lambda concurrency limit,
        EventBridge outage, controller down) leaves an orphan that an
        operator can clean manually with `adcli delete-computer`.

        Idempotent: only registers the Lambda+rule on first call.
        """
        if hasattr(self, "_ad_computer_cleaner_lambda"):
            return self._ad_computer_cleaner_lambda

        _role = iam.Role(
            self,
            "ADComputerCleanerRole",
            description="IAM role for the AD computer-object cleanup Lambda",
            assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        )
        _role.attach_inline_policy(
            iam.Policy(
                self,
                "ADComputerCleanerPolicy",
                statements=[
                    # Read tags off the terminating instance so we can
                    # filter by cluster and derive the AD object name.
                    # DescribeInstances does not support resource-level
                    # IAM scoping, so this is "*" -- the Lambda code
                    # explicitly filters on edh:ClusterId before acting.
                    iam.PolicyStatement(
                        actions=["ec2:DescribeInstances"],
                        resources=["*"],
                    ),
                    # Fire AWS-RunShellScript at the controller. Scoped
                    # to AWS-managed documents (no custom doc needed)
                    # plus EC2 instances tagged for this cluster.
                    iam.PolicyStatement(
                        actions=["ssm:SendCommand"],
                        resources=[
                            f"arn:{Aws.PARTITION}:ssm:{user_specified_variables.region}::document/AWS-RunShellScript",
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=["ssm:SendCommand"],
                        resources=[
                            f"arn:{Aws.PARTITION}:ec2:{user_specified_variables.region}:{Aws.ACCOUNT_ID}:instance/*",
                        ],
                        conditions={
                            "StringEquals": {
                                "aws:ResourceTag/edh:ClusterId": user_specified_variables.cluster_id,
                                "aws:ResourceTag/edh:NodeType": "controller",
                            }
                        },
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        actions=["secretsmanager:GetSecretValue"],
                        resources=[
                            f"{self.directory_service_resource_setup.get('service_account_secret_arn')}",
                        ],
                    ),
                ],
            )
        )

        _lambda = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-ADComputerCleaner",
            function_name=f"{user_specified_variables.cluster_id}-ADComputerCleaner",
            description="Deletes the AD computer object on EC2 terminate of ephemeral SOCA nodes (compute, login, dcv) so SPN does not orphan.",
            memory_size=128,
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            timeout=Duration.minutes(2),
            log_group=self.generate_log_group(name="ADComputerCleanerLambda"),
            role=_role,
            handler="ADComputerCleaner.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/ADComputerCleaner"),
            layers=[_l for _l in [self.soca_resources.get("boto3_layer")] if _l]
            or None,
            environment={
                "EDH_CLUSTER_ID": user_specified_variables.cluster_id,
                "AD_SERVICE_ACCOUNT_SECRET_ARN": self.directory_service_resource_setup.get("service_account_secret_arn"),
            },
            # No retries -- best-effort. EventBridge re-invoking on a
            # transient failure would just amplify noise.
            retry_attempts=0,
        )

        # EventBridge: fire on shutting-down rather than terminated, so
        # we still have a window to dispatch the SSM command before the
        # SSM agent on the controller has any reason to be busy. The
        # AD object cleanup itself does not need the EC2 instance to be
        # alive.
        events.Rule(
            self,
            "ADComputerCleanerRule",
            description=(
                f"Trigger {user_specified_variables.cluster_id}-ADComputerCleaner "
                f"on EC2 shutting-down for ephemeral nodes in this cluster"
            ),
            enabled=True,
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=["EC2 Instance State-change Notification"],
                detail={"state": ["shutting-down"]},
            ),
            targets=[aws_events_targets.LambdaFunction(_lambda)],
        )

        self._ad_computer_cleaner_lambda = _lambda
        return _lambda

    def _register_bootstrap_cache_cleaner(self) -> aws_lambda.Function:
        """
        Stand up the BootstrapTemplateCache aging pipeline:

          EventBridge cron (weekly Sun 03:00 UTC) --> Lambda --> S3
              ListObjects + DeleteObjects scoped to <cluster_id>/
              bootstrap/cache/. Deletes cache entries whose marker
              .stack_meta.json is older than cleanup_retention_days
              (default 30). Bodies under the entry prefix are deleted
              along with the marker.

        Why this exists
        ---------------
        The cluster S3 bucket is operator-supplied -- SOCA does NOT
        own it and cannot install a bucket-wide lifecycle policy from
        CDK. Instead this SOCA-owned Lambda runs on a cluster-local
        schedule with IAM scoped only to the cache prefix, so we never
        need bucket-config write permissions. See docs/
        BootstrapTemplateCache.md.

        Idempotent: only registers the Lambda + rule on first call.
        """
        if hasattr(self, "_bootstrap_cache_cleaner_lambda"):
            return self._bootstrap_cache_cleaner_lambda

        _retention_days = get_config_key(
            key_name="Config.feature_flags.BootstrapTemplateCache.cleanup_retention_days",
            required=False,
            expected_type=int,
            default=30,
        )

        _role = iam.Role(
            self,
            "BootstrapCacheCleanerRole",
            description="IAM role for the bootstrap-cache aging Lambda",
            assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        )

        _bucket_name = user_specified_variables.bucket
        _cache_prefix = (
            f"{user_specified_variables.cluster_id}/bootstrap/cache/"
        )
        _role.attach_inline_policy(
            iam.Policy(
                self,
                "BootstrapCacheCleanerPolicy",
                statements=[
                    # ListBucket scoped via prefix condition so we can
                    # only enumerate inside the cache prefix.
                    iam.PolicyStatement(
                        actions=["s3:ListBucket"],
                        resources=[f"arn:{Aws.PARTITION}:s3:::{_bucket_name}"],
                        conditions={
                            "StringLike": {
                                "s3:prefix": [f"{_cache_prefix}*"],
                            }
                        },
                    ),
                    # Delete only objects under the cache prefix. Keys
                    # in any other prefix are unreachable to this role.
                    iam.PolicyStatement(
                        actions=["s3:DeleteObject"],
                        resources=[
                            f"arn:{Aws.PARTITION}:s3:::{_bucket_name}/{_cache_prefix}*"
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources=["*"],
                    ),
                ],
            )
        )

        _lambda = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-BootstrapCacheCleaner",
            function_name=f"{user_specified_variables.cluster_id}-BootstrapCacheCleaner",
            description="Weekly aging sweep over the BootstrapTemplateCache S3 prefix. Deletes entries older than cleanup_retention_days.",
            memory_size=256,
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            timeout=Duration.minutes(5),
            log_group=self.generate_log_group(name="BootstrapCacheCleanerLambda"),
            role=_role,
            handler="BootstrapCacheCleaner.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/BootstrapCacheCleaner"),
            layers=[_l for _l in [self.soca_resources.get("boto3_layer")] if _l]
            or None,
            environment={
                "BUCKET": _bucket_name,
                "PREFIX": _cache_prefix,
                "RETENTION_DAYS": str(_retention_days),
            },
            retry_attempts=0,
        )

        # Weekly schedule: Sunday at 03:00 UTC. Spreads load away from
        # weekday peaks. Cron syntax: minute hour day-of-month month
        # day-of-week year. Use `?` for unspecified DoM/DoW alternate.
        events.Rule(
            self,
            "BootstrapCacheCleanerSchedule",
            description=(
                f"Weekly aging sweep of "
                f"{user_specified_variables.cluster_id} bootstrap-template "
                f"cache (retention_days={_retention_days})"
            ),
            enabled=True,
            schedule=events.Schedule.cron(
                minute="0", hour="3", week_day="SUN"
            ),
            targets=[aws_events_targets.LambdaFunction(_lambda)],
        )

        self._bootstrap_cache_cleaner_lambda = _lambda
        return _lambda

    def base_image_reconciler(self):
        """Deploy the owned-base AMI lineage reconciler Lambda + EventBridge rules.

        Copies AWS-published base AMIs into the account (owned lineage) so snapshot capture is
        incremental and the ids survive AWS retiring the public bases. Requires Aurora; a no-op
        otherwise. Behavior is gated at runtime by /configuration/BaseImageAcceleration/Enabled.
        See helpers/cdk/base_image_reconciler.py and docs/GoldenImageLineage-Design.md.
        """
        if not self.soca_resources.get("database"):
            logger.debug(
                "Base image reconciler skipped -- no Aurora database provisioned"
            )
            return

        from helpers.cdk.base_image_reconciler import build_base_image_reconciler

        database_name = get_config_key(
            key_name="Config.database.aurora_serverless_v2.database_name",
            expected_type=str,
            default="edh",
            required=False,
        )
        build_base_image_reconciler(
            self,
            cluster_id=user_specified_variables.cluster_id,
            database_name=database_name,
            region=user_specified_variables.region,
            get_lambda_runtime_version=get_lambda_runtime_version,
        )

    def usb_allowlist_resolver(self):
        """Deploy the boot-time USB device allowlist resolver Lambda + IAM Function URL.

        The VDI boot hook (attested instance-id) and the controller (admin
        API/CLI preview of a specified instance) call this to fetch an
        instance's effective USB allowlist as rendered usb-devices.conf lines.
        Requires the Aurora database provider and vdi_node_role; a no-op on
        sqlite/legacy clusters. See helpers/cdk/usb_allowlist_resolver.py.
        """
        if not self.soca_resources.get("database"):
            logger.debug(
                "USB allowlist resolver skipped -- no Aurora database provisioned"
            )
            return
        if "vdi_node_role" not in self.soca_resources:
            logger.debug(
                "USB allowlist resolver skipped -- vdi_node_role not present"
            )
            return

        from helpers.cdk.usb_allowlist_resolver import build_usb_allowlist_resolver

        database_name = get_config_key(
            key_name="Config.database.aurora_serverless_v2.database_name",
            expected_type=str,
            default="edh",
            required=False,
        )
        build_usb_allowlist_resolver(
            self,
            cluster_id=user_specified_variables.cluster_id,
            database_name=database_name,
            get_lambda_runtime_version=get_lambda_runtime_version,
            get_config_key=get_config_key,
        )

    def spot_interruption_capture(self):
        """Deploy the Spot interruption auto-capture Lambda + EventBridge rule.

        Always deployed; the Lambda no-ops until AllowSavedDesktops is enabled,
        so the feature can be turned on post-deployment via config alone.
        Requires the Aurora database + VPC; a no-op on sqlite/legacy clusters.
        See helpers/cdk/spot_interruption_capture.py.
        """
        if not self.soca_resources.get("database"):
            logger.debug(
                "Spot interruption capture skipped -- no Aurora database provisioned"
            )
            return

        from helpers.cdk.spot_interruption_capture import build_spot_interruption_capture

        database_name = get_config_key(
            key_name="Config.database.aurora_serverless_v2.database_name",
            expected_type=str,
            default="edh",
            required=False,
        )
        build_spot_interruption_capture(
            self,
            cluster_id=user_specified_variables.cluster_id,
            database_name=database_name,
            get_lambda_runtime_version=get_lambda_runtime_version,
        )

    def resources_mirroring(self):
        """Deploy the cloud-side resource mirror executor (SFN Inline Map + Lambdas +
        install-time custom-resource trigger). See helpers/cdk/resources_mirroring.py and
        docs/ResourceMirrorLambda-Design.md (D1-D16b). No-op for method=install-host
        (that path mirrors pre-deploy in install_soca.py). The trigger reads the manifest
        (seeded to S3 by the installer) and fires the SFN; the EvaluateResults gate maps
        to the custom-resource result (hard mode -> CFN rollback on failure)."""
        from helpers.cdk.resources_mirroring import (
            resources_mirroring as _build_resource_mirror,
        )

        method = get_config_key(
            key_name="Config.services.resources_mirroring.method",
            expected_type=str, default="cloud-no-vpc", required=False,
        )
        if method == "install-host":
            return  # mirrored pre-deploy by the installer; nothing to deploy here

        bucket = user_specified_variables.bucket
        cluster_id = user_specified_variables.cluster_id
        # Bucket region hint (D15): the installer probes the bucket's real region and
        # writes it here; fall back to the cluster region if unset.
        bucket_region = get_config_key(
            key_name="Config.services.resources_mirroring.bucket_region",
            expected_type=str, default=user_specified_variables.region, required=False,
        ) or user_specified_variables.region

        vpc_config = None
        if method == "cloud-in-vpc-nat":
            vpc_config = {
                "vpc": self.soca_resources["vpc"],
                "subnets": ec2.SubnetSelection(
                    subnets=self.soca_resources["vpc"].private_subnets
                ),
            }

        _build_resource_mirror(
            self,
            cluster_id=cluster_id,
            mirror_bucket_name=bucket,
            manifest_s3_key=f"{cluster_id}/resources_mirroring/manifest.json",
            mirror_region=bucket_region,
            failure_mode=get_config_key(
                key_name="Config.services.resources_mirroring.failure_mode",
                expected_type=str, default="hard", required=False),
            max_concurrency=get_config_key(
                key_name="Config.services.resources_mirroring.max_concurrency",
                expected_type=int, default=16, required=False),
            mirror_s3_sources=get_config_key(
                key_name="Config.services.resources_mirroring.mirror_s3_sources",
                expected_type=bool, default=True, required=False),
            vpc_config=vpc_config,
            get_lambda_runtime_version=get_lambda_runtime_version,
        )

    def generate_log_group(
        self,
        name: str,
        prefix: str | None = None,
        log_group_class: str | None = None,
        retention: str | None = None,
        removal_policy: str | None = None,
        include_cluster_id: bool | None = True,
    ) -> ILogGroup:
        """
        Generate and return a Cloudwatch log group.
        """

        if not name:
            logger.fatal("generate_log_group() called without a name! Probable defect!")
            exit(1)

        _log_deployment_id: str = self.get_log_deployment_id()

        _log_prefix: str = get_config_key(
            key_name="Config.services.logging.log_group_prefix",
            expected_type=str,
            required=False,
            default=prefix if prefix else "/edh",
        )
        # FIXME TODO - Size warning on large prefixes? Make sure it has leading /?

        _log_group_class: str = get_config_key(
            key_name="Config.services.logging.log_group_class",
            expected_type=str,
            required=False,
            default=log_group_class.upper() if log_group_class else "STANDARD",
        )
        if _log_group_class not in logs.LogGroupClass:
            logger.fatal(
                f"Unknown Log Group Class {_log_group_class} ! Supported Classes: {list(logs.LogGroupClass)}"
            )
        _log_group_class_enum: logs.LogGroupClass = logs.LogGroupClass(
            _log_group_class.upper()
        )

        _log_retention_policy: str = get_config_key(
            key_name="Config.services.logging.retention_policy",
            expected_type=str,
            required=False,
            default=retention.upper() if retention else "THREE_YEARS",
        )
        if _log_retention_policy not in logs.RetentionDays:
            logger.fatal(
                f"Unknown Retention Policy {_log_retention_policy} ! Supported Retention Policies: {list(logs.RetentionDays)}"
            )
        _log_group_retention_policy_enum: logs.RetentionDays = logs.RetentionDays(
            _log_retention_policy.upper()
        )

        _log_removal_policy: str = get_config_key(
            key_name="Config.services.logging.removal_policy",
            expected_type=str,
            required=False,
            default=removal_policy.upper() if removal_policy else "RETAIN",
        )
        if _log_removal_policy not in RemovalPolicy:
            logger.fatal(
                f"Unknown Removal Policy {_log_removal_policy} ! Supported Removal Policies: {list(RemovalPolicy)}"
            )
        _log_group_removal_policy_enum: RemovalPolicy = RemovalPolicy(
            _log_removal_policy.upper()
        )

        _log_include_cluster_id: str = get_config_key(
            key_name="Config.services.logging.log_group_include_cluster_id",
            expected_type=bool,
            required=False,
            default=True,
        )

        _log_kms_key_id = get_kms_key_id(
            config_key_names=[
                "Config.services.logging.kms_key_id",
            ],
            allow_global_default=True,
        )

        # Now we can finally smash it all together
        _cluster_name_str: str = (
            f"{user_specified_variables.cluster_id}" if include_cluster_id else ""
        )
        _lg_name: str = f"{_cluster_name_str}/{name}"
        _log_group_full_name: str = f"{_log_prefix}/{_lg_name}/{_log_deployment_id}"

        logger.debug(
            f"Creating an LogGroup for {_log_prefix=}/{name=} / {_log_group_full_name=} / {_log_retention_policy=} / {_log_removal_policy=} / {_log_include_cluster_id=} / {_log_kms_key_id=} / {_log_group_class_enum=}"
        )

        return logs.LogGroup(
            self,
            f"SOCALogGroup{name.capitalize()}",
            log_group_name=_log_group_full_name,
            log_group_class=_log_group_class_enum,
            retention=_log_group_retention_policy_enum,
            removal_policy=_log_group_removal_policy_enum,
            encryption_key=(
                kms.Key.from_key_arn(
                    self, f"LogGroupKmsKey{name.capitalize()}", _log_kms_key_id
                )
                if _log_kms_key_id
                else None
            ),
        )

    def generic_resources(self):
        pass

    def network(self):
        """Extracted to helpers/network.py."""
        from helpers import network as _helper

        return _helper.network(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
        )

    def elasticache(self):
        """Deploy AWS ElastiCache for SOCA Controller.

        Implementation extracted to helpers/elasticache.py.
        """
        from helpers import elasticache as elasticache_helper

        elasticache_helper.setup(
            self,
            self.soca_resources,
            user_specified_variables,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
        )

    def database(self):
        """Provision the database backend for the SOCA web app state.

        Implementation lives in helpers/database.py; this method is just the
        entry point called from the main stack orchestration. The helper is a
        no-op (returns the info skeleton) when Config.database.provider does not
        provision infrastructure (e.g. sqlite).

        Must be called AFTER the VPC, the security groups (database_sg) and the
        Secrets Manager KMS key exist.
        """
        self.database_info = database_helper.setup_database(
            scope=self,
            soca_resources=self.soca_resources,
            user_specified_variables=user_specified_variables,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            secretsmanager_helper=secretsmanager_helper,
        )

    def dcv_infra_security_groups(self):
        """
        Create DCV Infrastructure security groups when Config.dcv.high_scale == True
        """
        logger.debug(
            "in dcv_infra_security_groups() - Creating SGs for DCV High Scale ..."
        )

        for _dcv_node_type in ("dcv_broker", "dcv_gateway"):
            # FIXME TODO - Narrow down to specific ports for each app
            logger.debug(f"Adding NLB all traffic rule for {_dcv_node_type}")
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources[f"{_dcv_node_type}_sg"],
                peer=self.soca_resources["nlb_sg"],
                connection=ec2.Port.all_traffic(),
                description=f"Allow ELB to DCV {_dcv_node_type}",
            )

            logger.debug(f"Adding all traffic rule for intra-{_dcv_node_type}")
            # FIXME TODO - Narrow down to specific ports for each app
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources[f"{_dcv_node_type}_sg"],
                peer=self.soca_resources[f"{_dcv_node_type}_sg"],
                connection=ec2.Port.all_traffic(),
                description=f"Allow intra-{_dcv_node_type} communications",
            )

        # Now our specific role rules
        # Broker
        # Gateway-to-Broker
        # FIXME TODO - Narrow down to specific ports for each app
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["dcv_broker_sg"],
            peer=self.soca_resources["dcv_gateway_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow DCV gateway to broker",
        )
        # Gateway

        # Manager

    def _auto_mpl_enabled(self) -> bool:
        """
        Resolve whether Automatic Managed Prefix List (MPL) mode is active for this deploy.

        Returns True only when BOTH:
          * Config.feature_flags.Networking.AutoManagedPrefixList is enabled (default: True), and
          * the deploy identity is authorized for ec2:CreateManagedPrefixList.

        If the permission is absent (e.g. a customer bootstrapped a scoped CFN execution
        role), we fall back to classic CIDR security-group rules so the deploy still
        succeeds. Result is cached for the lifetime of the synth.
        """
        if hasattr(self, "_auto_mpl_enabled_cached"):
            return self._auto_mpl_enabled_cached

        _flag: bool = get_config_key(
            key_name="Config.feature_flags.Networking.AutoManagedPrefixList",
            expected_type=bool,
            required=False,
            default=True,
        )
        if not _flag:
            self._auto_mpl_enabled_cached = False
            return False

        from botocore.exceptions import ClientError

        _enabled: bool = True
        try:
            _ec2_client = boto3_helper.get_boto(
                service_name="ec2",
                profile_name=user_specified_variables.profile,
                region_name=user_specified_variables.region,
            )
            # DryRun validates authorization without creating anything
            _ec2_client.create_managed_prefix_list(
                DryRun=True,
                PrefixListName="edh-mpl-permission-probe",
                MaxEntries=1,
                AddressFamily="IPv4",
            )
        except ClientError as _e:
            _code = _e.response.get("Error", {}).get("Code", "")
            if _code == "DryRunOperation":
                _enabled = True
            else:
                _enabled = False
                logger.warning(
                    f"AutoManagedPrefixList is enabled but the deploy identity cannot create MPLs ({_code}). "
                    "Falling back to classic CIDR security-group rules for this deployment."
                )
        except Exception as _e:
            _enabled = False
            logger.warning(
                f"AutoManagedPrefixList permission probe failed ({_e}); falling back to classic CIDR rules."
            )

        if not _enabled:
            _notice = (
                "\n" + "!" * 78 + "\n"
                "  AutoManagedPrefixList is ENABLED but this deploy identity is NOT\n"
                "  authorized to create Managed Prefix Lists. Falling back to CLASSIC\n"
                "  CIDR security-group rules for THIS deployment (install continues).\n"
                "  To use classic CIDR rules by design and silence this notice, set\n"
                "  Config.feature_flags.Networking.AutoManagedPrefixList = false.\n"
                + "!" * 78 + "\n"
            )
            print(_notice, flush=True)

        self._auto_mpl_enabled_cached = _enabled
        return _enabled

    def managed_prefix_lists(self):
        """Extracted to helpers/network.py."""
        from helpers import network as _helper

        return _helper.managed_prefix_lists(
            self,
            user_specified_variables=user_specified_variables,
        )

    def managed_prefix_list_for_clients(self, cluster_id: str):
        """
        Create the MPL for remote clients.
        """
        logger.debug(
            f"[PREVIEW] - Creating MPL for Remote Client(s) for cluster {cluster_id}"
        )

        _client_prefixes_by_af: dict = {"IP_V4": [], "IP_V6": []}

        # Determine if we have client-ip arguments

        if not user_specified_variables.client_ip:
            logger.error(
                "Unable to determine IPv4 client range from client_ip. Unable to continue. Defect?"
            )
            exit(1)

        logger.debug(
            f"managed_prefix_lists - Using Client-IP for MPL: {user_specified_variables.client_ip=}"
        )

        # We can skip validation of the prefix since it was pre-validated in the installer
        # TODO - these can be merged into a loop over the AFs
        # IP_V4 is always enabled
        for _prefix in user_specified_variables.client_ip:
            logger.debug(f"Adding prefix to clients MPL: {_prefix}")
            if _prefix not in _client_prefixes_by_af["IP_V4"]:
                _client_prefixes_by_af["IP_V4"].append(_prefix)
            else:
                logger.warning(
                    f"Duplicate entry for clients IPv4 MPL skipped: {_prefix=}  /  Current: {_client_prefixes_by_af['IP_V4']}"
                )

        # IP_V6 is optional
        if (
            self.is_networking_af_enabled(address_family="ipv6")
            and user_specified_variables.client_ipv6
        ):
            for _prefix in user_specified_variables.client_ipv6:
                logger.debug(f"Adding prefix to clients MPL: {_prefix}")
                if _prefix not in _client_prefixes_by_af["IP_V6"]:
                    _client_prefixes_by_af["IP_V6"].append(_prefix)
                else:
                    logger.warning(
                        f"Duplicate entry for clients IPv6 MPL skipped: {_prefix=}  /  Current: {_client_prefixes_by_af['IP_V6']}"
                    )

        logger.debug(f"Client IPs by AF dump: {_client_prefixes_by_af=}")

        # Now that our _client_prefixes_by_af is populated (new or existing resources) - we can build the MPLs
        #
        # Create a VPC peer equiv MPL for each address-family
        #
        for _af in _client_prefixes_by_af.keys():
            logger.debug(f"Creating {_af}/Clients MPL")

            if _af == "IP_V6" and not self.is_networking_af_enabled(
                address_family="ipv6"
            ):
                logger.debug(
                    "Skipping IPv6 Clients MPL - IPv6 address-family is not enabled"
                )
                continue

            _cidr_entry_list: list = []

            for _cidr in _client_prefixes_by_af.get(_af, []):
                logger.debug(f"Adding {_cidr} to Clients MPL for {_af}")
                _cidr_entry_list.append(
                    ec2.CfnPrefixList.EntryProperty(
                        cidr=_cidr,
                        description=f"Client {_af} CIDR - {_cidr}",
                    )
                )

            # Error if we have a zero list in IPv4 only
            if _af == "IP_V4" and not _cidr_entry_list:
                logger.fatal("Unable to construct IPv4 Clients MPL - Possible defect?")
                exit(1)

            # TODO - What is a good default for clients sizing?
            # Probably should be an easier way to control this magic number
            if len(_cidr_entry_list) > 16:
                logger.warning(
                    f"Clients CIDR MPL for {_af=} is larger than 16 entries - Entries: {_cidr_entry_list=}"
                )
                if _soca_debug:
                    logger.debug("Allowing larger Clients MPL due to SOCA_DEBUG")
                else:
                    logger.error(
                        f"Considering large Clients MPL for {_af} as FATAL - rerun in SOCA_DEBUG mode to allow unrestricted MPL size. Entries: {_cidr_entry_list=}"
                    )
                    exit(1)

            self.soca_resources[f"clients_mpl_{_af}"] = ec2.PrefixList(
                self,
                f"{cluster_id}-Clients-{_af}",
                prefix_list_name=f"{cluster_id}-Clients-{_af}",
                max_entries=max(
                    len(_cidr_entry_list), 16
                ),  #  Default to the larger of <size of the list> or 16
                address_family=ec2.AddressFamily[_af.upper()],
                entries=(
                    _cidr_entry_list if _cidr_entry_list else None
                ),  # None allows us to stub and add later in Console/API/etc
            )
            logger.debug(f"Client MPL completed for Cluster {cluster_id}")

    def managed_prefix_list_for_vpc(self, cluster_id: str):
        """
        Create the MPL for the VPC range(s).
        """
        logger.debug(
            f"[PREVIEW] - Creating MPL for VPC CIDR(s) for cluster {cluster_id}"
        )

        # If we are in existing_resources (VPC) mode, query the VPC for all the Prefixes
        # for the upcoming MPL entries.

        _vpc_prefixes_by_af: dict = {"IP_V4": [], "IP_V6": []}

        if user_specified_variables.vpc_id:
            # Existing VPC: enumerate ALL associated CIDR blocks (primary + secondary),
            # for both address-families, so the VPC MPL covers multi-CIDR VPCs.
            _ipv6_enabled = self.is_networking_af_enabled(address_family="ipv6")
            try:
                _ec2_client = boto3_helper.get_boto(
                    service_name="ec2",
                    profile_name=user_specified_variables.profile,
                    region_name=user_specified_variables.region,
                )
                _vpc_info = _ec2_client.describe_vpcs(
                    VpcIds=[user_specified_variables.vpc_id]
                )["Vpcs"][0]

                for _assoc in _vpc_info.get("CidrBlockAssociationSet", []):
                    if _assoc.get("CidrBlockState", {}).get("State") == "associated":
                        _cidr = _assoc.get("CidrBlock")
                        if _cidr and _cidr not in _vpc_prefixes_by_af["IP_V4"]:
                            _vpc_prefixes_by_af["IP_V4"].append(_cidr)

                if _ipv6_enabled:
                    for _assoc in _vpc_info.get("Ipv6CidrBlockAssociationSet", []):
                        if (
                            _assoc.get("Ipv6CidrBlockState", {}).get("State")
                            == "associated"
                        ):
                            _cidr6 = _assoc.get("Ipv6CidrBlock")
                            if _cidr6 and _cidr6 not in _vpc_prefixes_by_af["IP_V6"]:
                                _vpc_prefixes_by_af["IP_V6"].append(_cidr6)
            except Exception as _e:
                logger.warning(
                    f"Unable to enumerate CIDRs for existing VPC {user_specified_variables.vpc_id}: {_e}. Falling back to the primary CIDR."
                )
                _existing_vpc = self.soca_resources.get("vpc")
                _primary = (
                    getattr(_existing_vpc, "vpc_cidr_block", None)
                    if _existing_vpc
                    else None
                )
                if _primary:
                    _vpc_prefixes_by_af["IP_V4"].append(_primary)
            logger.debug(
                f"managed_prefix_lists - Existing VPC {user_specified_variables.vpc_id} CIDRs: {_vpc_prefixes_by_af}"
            )

        else:
            # New VPC: single primary IPv4 CIDR from the CLI. The MPL still lets an
            # admin add more CIDRs later without touching the SGs.
            logger.debug(
                f"managed_prefix_lists - New VPC prefixes: {user_specified_variables.vpc_cidr=} / {user_specified_variables.vpc_cidr_ipv6=}"
            )
            _vpc_prefixes_by_af["IP_V4"].append(user_specified_variables.vpc_cidr)

            if self.is_networking_af_enabled(address_family="ipv6"):
                if user_specified_variables.vpc_cidr_ipv6:
                    _vpc_prefixes_by_af["IP_V6"].append(
                        user_specified_variables.vpc_cidr_ipv6
                    )
                else:
                    _vpc = self.soca_resources.get("vpc")
                    if _vpc is not None and getattr(
                        _vpc, "vpc_ipv6_cidr_blocks", None
                    ):
                        _vpc_prefixes_by_af["IP_V6"].append(
                            Fn.select(0, _vpc.vpc_ipv6_cidr_blocks)
                        )

        # Now that our _vpc_prefixes_by_af is populated (new or existing resources) - we can build the MPLs
        #
        # Create a VPC peer equiv MPL for each address-family
        #
        for _af in _vpc_prefixes_by_af.keys():
            logger.debug(f"Creating {_af}/VPC MPL")

            if _af == "IP_V6" and not self.is_networking_af_enabled(
                address_family="ipv6"
            ):
                logger.debug(
                    "Skipping IPv6 VPC MPL - IPv6 address-family is not enabled"
                )
                continue

            _cidr_entry_list: list = []

            for _vpc_cidr in _vpc_prefixes_by_af.get(_af, []):
                _cidr_entry_list.append(
                    ec2.CfnPrefixList.EntryProperty(
                        cidr=_vpc_cidr,
                        description=f"VPC {_af} CIDR - {_vpc_cidr}",
                    )
                )

            # Error if we have a zero list in IPv4 only
            if _af == "IP_V4" and not _cidr_entry_list:
                logger.fatal("Unable to construct IPv4 VPC MPL - Possible defect?")
                exit(1)

            if len(_cidr_entry_list) > 5:
                logger.fatal(
                    f"VPC CIDR MPL for {_af=} is > 5 entries - Error detected. Defect?"
                )
                exit(1)

            self.soca_resources[f"vpc_mpl_{_af}"] = ec2.PrefixList(
                self,
                f"{cluster_id}-VPC-{_af}",
                prefix_list_name=f"{cluster_id}-VPC-{_af}",
                max_entries=5,  #  Max number of VPC CIDR Blocks per address-family (as of July 2025)
                address_family=ec2.AddressFamily[_af.upper()],
                entries=(
                    _cidr_entry_list if _cidr_entry_list else None
                ),  # None allows us to stub and add later in Console/API/etc
            )

    def security_groups(self):
        """Extracted to helpers/cluster_security_groups.py."""
        from helpers import cluster_security_groups as _helper

        return _helper.security_groups(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
        )

    def create_vpc_gateway_endpoints(self):
        """
        Create VPC Gateway Endpoints for accessing AWS services.
        """

        logger.debug("Creating VPC Gateway Endpoints")

    def create_vpc_endpoints(self):
        """Extracted to helpers/network.py."""
        from helpers import network as _helper

        return _helper.create_vpc_endpoints(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
        )

    def iam_roles(self):
        """Extracted to helpers/iam.py."""
        from helpers import iam as _helper

        return _helper.iam_roles(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
            principals_suffix=principals_suffix,
            get_service_principal_url_suffix=get_service_principal_url_suffix,
        )

    def directory_service(self):
        """Extracted to helpers/directory_service.py."""
        from helpers import directory_service as _helper

        return _helper.directory_service(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
        )

    def directory_service_aws_mad(self):
        """Extracted to helpers/directory_service.py."""
        from helpers import directory_service as _helper

        return _helper.directory_service_aws_mad(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
        )

    def aws_route53_resolver(self, launch_subnets: list, dns_ip_addresses: list):
        """Extracted to helpers/network.py."""
        from helpers import network as _helper

        return _helper.aws_route53_resolver(
            self,
            launch_subnets=launch_subnets,
            dns_ip_addresses=dns_ip_addresses,
            user_specified_variables=user_specified_variables,
        )

    def _storage_build_efs_filesystem(self, fs_key: str):
        """Extracted to helpers/filesystems.py."""
        from helpers import filesystems as _helper

        return _helper._storage_build_efs_filesystem(
            self,
            fs_key=fs_key,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
        )

    def _storage_build_fsx_lustre_filesystem(self, fs_key: str):
        """Extracted to helpers/filesystems.py."""
        from helpers import filesystems as _helper

        return _helper._storage_build_fsx_lustre_filesystem(
            self,
            fs_key=fs_key,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
        )

    def get_fsx_pricing_data(self, region: Optional[str]) -> list:
        """
        Get pricing data for AmazonFSx
        """

        _pricing_data: list = []

        # Where we connect to for pricing API endpoint
        _pricing_region: str = ""

        if region:
            if region.startswith("ap"):
                _pricing_region = "ap-south-1"
            elif region.startswith("eu"):
                _pricing_region = "eu-central-1"
            else:
                # default to us-east-1
                _pricing_region = "us-east-1"
        else:
            # default to us-east-1
            _pricing_region = "us-east-1"

        logger.debug(f"Using Pricing region endpoint from: {_pricing_region}")
        _pricing_client = boto3_helper.get_boto(
            service_name="pricing",
            profile_name=user_specified_variables.profile,
            region_name=_pricing_region,
        )

        _pricing_paginator = _pricing_client.get_paginator("get_products")

        _filters: list = []

        if not region:
            logger.debug("Retrieving pricing data for ALL AWS Regions")
        else:
            # Add our specific region to the filter to have a smaller API req/response
            logger.debug(f"Retrieving pricing data for specific region: {region}")
            _filters.append(
                {"Field": "regionCode", "Value": region, "Type": "TERM_MATCH"}
            )

        _pricing_iterator = _pricing_paginator.paginate(
            ServiceCode="AmazonFSx",
            Filters=_filters,
            PaginationConfig={"MaxResults": 100},
        )

        _pricing_pages: int = 0
        _pricing_entries: int = 0

        for _page in _pricing_iterator:
            _pricing_pages += 1
            for _entry in _page.get("PriceList", {}):
                _pricing_entries += 1
                _pricing_data.append(_entry)

        if not _pricing_data:
            logger.fatal(
                f"No FSx pricing data retrieved. Check auth for pricing API at region {_pricing_region}."
            )

        logger.debug(
            f"Pricing data retrieved: {_pricing_pages} pages, {_pricing_entries} entries"
        )
        return _pricing_data

    def get_fsx_deployment_options(self, region: Optional[str] = None) -> dict:
        """
        Get the deployment options for FSx
        """

        _reply_data: dict = {}
        _pricing_data = self.get_fsx_pricing_data(region=region if region else None)

        logger.debug(f"Pricing data retrieved len: {len(_pricing_data)} ")

        for _entry in _pricing_data:
            _pricing = ast.literal_eval(_entry)
            _attribs = _pricing.get("product", {}).get("attributes", {})
            if not _attribs:
                # something didn't work for this region - just skip it
                continue

            _region = _attribs.get("regionCode", "")
            _dep_type = _attribs.get("deploymentOption", "")
            _fs_type = _attribs.get("fileSystemType", "")
            _usage_type = _attribs.get("usagetype", "")

            # SnapLock is "" , Backup is "N/A". Skip em.
            if "N/A" in _dep_type or _dep_type == "":
                continue

            if _region not in _reply_data:
                _reply_data[_region] = {}

            if _fs_type not in _reply_data[_region]:
                _reply_data[_region][_fs_type] = []

            if _dep_type not in _reply_data[_region][_fs_type]:
                _reply_data[_region][_fs_type].append(_dep_type)
        logger.debug(f"Reply Data len: {len(_reply_data)}")
        return _reply_data

    def get_fsx_deployment_options_by_region(self, region: str) -> dict:
        """
        Get the deployment options for FSx in a specific region
        """

        logger.debug(f"Getting FSx deployment options for region {region}")

        _fsx_deployment_options: dict = self.get_fsx_deployment_options(region=region)

        if not _fsx_deployment_options:
            logger.fatal("No FSx deployment options retrieved. Check auth.")

        if not _fsx_deployment_options.get(region, {}):
            logger.fatal(
                f"No FSx deployment options retrieved for region {region}. Check auth."
            )

        logger.debug(
            f"FSx Deployment Options for region {region}: {len(_fsx_deployment_options.get(region, {}))}"
        )
        return {region: _fsx_deployment_options.get(region, {})}

    def _storage_build_fsx_ontap_filesystem(self, fs_key: str):
        """Extracted to helpers/filesystems.py."""
        from helpers import filesystems as _helper

        return _helper._storage_build_fsx_ontap_filesystem(
            self,
            fs_key=fs_key,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            get_subnet_route_table_by_subnet_id=get_subnet_route_table_by_subnet_id,
        )

    def _storage_build_fsx_openzfs_filesystem(self, fs_key: str) -> str:
        """
        Build an FSx/OpenZFS filesystem.
        """
        logger.fatal(f"FSx/OpenZFS creation is not implemented for {fs_key=}!")
        return "fs-123"

    def storage(self):
        """Extracted to helpers/filesystems.py."""
        from helpers import filesystems as _helper

        return _helper.storage(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
        )

    def _storage_register_filesystem(self, fs_id: str, fs_key: str, fs_provider: str):
        """
        Register a filesystem (new or existing) for inclusion in the SOCA cluster.
        This will populate the proper SSM Parameter Store paths of .../FileSystems/... for new or existing filesystems.
        """
        #
        # Update any technology providers here for default mount options
        # TODO - This should find its way to Param Store for defaults on existing clusters?
        #
        _mount_options_by_provider: dict = {
            "efs": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
            "fsx_lustre": "defaults,noatime,flock,_netdev",
            "fsx_ontap": "defaults,noatime,_netdev",
            "fsx_openzfs": "noatime,nfsvers=4.2,sync,nconnect=16,rsize=1048576,wsize=1048576",  # This is for linux kernel 5.3+
            # Linux kernel 5.2 and below (no nconnect option)
            # "fsx_openzfs": "noatime,nfsvers=4.2,sync,nconnect=16,rsize=1048576,wsize=1048576",
        }

        logger.debug(
            f"_storage_register_filesystem: Asked to register filesystem {fs_id=} {fs_key=} {fs_provider=}"
        )

        # Sanity check
        if not fs_key or not fs_id or not fs_provider:
            raise ValueError(
                "Unable to continue - invalid filesystem register request. Defect?"
            )

        if fs_provider not in _mount_options_by_provider:
            raise ValueError(
                f"Unable to continue - invalid filesystem register request. Unknown provider options for {fs_provider=}. New filesystem provider type?"
            )

        self.soca_filesystems[f"{fs_key}"] = {
            "provider": fs_provider,
            "mount_path": f"/{fs_key}",
            "mount_options": _mount_options_by_provider.get(
                fs_provider, ""
            ),  # Fallback may break provider
            "mount_target": fs_id,  #  We only need the FS-ID , not the FQDN.  We handle it later in bootstrap
            "on_mount_failure": "exit",
            "enabled": "true",
        }

    def controller(self):
        """Extracted to helpers/controller.py."""
        from helpers import controller as _helper

        return _helper.controller(
            self,
            endpoints_suffix=endpoints_suffix,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            flatten_parameterstore_config=flatten_parameterstore_config,
            return_ebs_volume_type=return_ebs_volume_type,
            get_supported_azs_list_by_instance_type=get_supported_azs_list_by_instance_type,
        )

    def configuration(self):
        """
        Store SOCA configuration in a Secret Manager's Secret.
        Controller/Compute Nodes have the permission to read the secret
        """
        solution_metrics_lambda = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-SolutionMetricsLambda",
            function_name=f"{user_specified_variables.cluster_id}-Metrics",
            description="Send SOCA anonymous Metrics to AWS",
            memory_size=128,
            role=self.soca_resources["solution_metrics_lambda_role"],
            timeout=Duration.minutes(3),
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            log_group=self.generate_log_group(name="Metrics"),
            handler="SolutionMetricsLambda.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/SolutionMetricsLambda"),
            layers=[l for l in [self.soca_resources.get("boto3_layer")] if l],
        )

        nested_virt_launcher_lambda = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-NestedVirtLauncher",
            function_name=f"{user_specified_variables.cluster_id}-NestedVirtLauncher",
            description="Launch EC2 instances with nested virtualization enabled",
            memory_size=128,
            role=self.soca_resources["nested_virt_launcher_lambda_role"],
            timeout=Duration.minutes(5),
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            log_group=self.generate_log_group(name="NestedVirtLauncher"),
            handler="NestedVirtLauncher.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/NestedVirtLauncher"),
            layers=[l for l in [self.soca_resources.get("boto3_layer")] if l],
        )

        # TODO FIXME - This can be cleaned up
        _subnet_listings: dict = {
            "public": [],
            "private": [],
        }

        if (
            user_specified_variables.public_subnets
            and user_specified_variables.private_subnets
        ):
            logger.debug(
                "Using supplied public and private subnets for Param configuration"
            )

            # format for user_specified is subnet-123,us-east-1a
            for _sn in user_specified_variables.public_subnets:
                _sn_id: str = _sn.split(",")[0]
                logger.debug(f"Adding public subnet - {_sn_id}")
                _subnet_listings["public"].append(_sn_id)
            for _sn in user_specified_variables.private_subnets:
                _sn_id: str = _sn.split(",")[0]
                logger.debug(f"Adding private subnet - {_sn_id}")
                _subnet_listings["private"].append(_sn_id)

        else:
            # SOCA created the VPC - so it should be clean, and we can use the CDK methods
            logger.debug("Using SOCA created VPC subnets for Param configuration")

            for pub_sub in self.soca_resources["vpc"].public_subnets:
                logger.debug(f"Public subnet: {pub_sub.subnet_id}")
                _subnet_listings["public"].append(pub_sub.subnet_id)

            for priv_sub in self.soca_resources["vpc"].private_subnets:
                logger.debug(f"Private subnet: {priv_sub.subnet_id}")
                _subnet_listings["private"].append(priv_sub.subnet_id)

        # Determine our mounting for /apps and /data
        # /apps
        _fs_apps_provider: str = user_specified_variables.fs_apps_provider
        if user_specified_variables.fs_apps:
            _fs_apps_mount: str = f"{user_specified_variables.fs_apps}"
        else:
            _fs_apps_mount: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_apps"],
                storage_provider=_fs_apps_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_apps_provider != "fsx_ontap"
                    else get_config_key(
                        key_name="Config.storage.apps.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )

        # /data
        _fs_data_provider: str = user_specified_variables.fs_data_provider

        if user_specified_variables.fs_data:
            _fs_data_mount: str = f"{user_specified_variables.fs_data}"
        else:
            _fs_data_mount: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_data"],
                storage_provider=_fs_data_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_data_provider != "fsx_ontap"
                    else get_config_key(
                        key_name="Config.storage.data.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )

        # Allow config file over-ride of the SOCA admin default username
        if self.directory_service_resource_setup.get("use_existing_directory") is False:
            _def_admin_username: str = get_config_key(
                key_name="Config.admin_user_name",
                required=False,
                default="edhadmin",
                expected_type=str,
            )

            _secret_string: str = '{"username": "' + _def_admin_username + '"}'
            _default_soca_user_secret = secretsmanager_helper.create_secret(
                scope=self,
                construct_id="EDHAdminUserSecret",
                secret_name=f"/edh/{user_specified_variables.cluster_id}/EDHAdminUser",
                secret_string_template=json.dumps({"username": _def_admin_username}),
                kms_key_id=(
                    self.soca_resources["secretsmanager_kms_key_id"]
                    if self.soca_resources["secretsmanager_kms_key_id"]
                    else None
                ),
            )

        # Handle custom tags
        _custom_tags = {}
        for tag in get_config_key(
            key_name="Config.custom_tags",
            expected_type=list,
            default=[],
            required=False,
        ):
            _custom_tags[re.sub(r"[^A-Za-z0-9]", "", tag.get("Key"))] = {
                "Key": tag.get("Key"),
                "Value": tag.get("Value"),
                "Enabled": True,
            }

        # Save for any other items that may need a clean version of the custom_tags
        self.soca_resources["custom_tags"] = _custom_tags
        self.soca_resources["soca_config"] = {
            "AWSAccountId": Aws.ACCOUNT_ID,
            "VpcId": self.soca_resources["vpc"].vpc_id,
            "DeploymentId": self.deployment_id,
            "PublicSubnets": _subnet_listings.get("public", []),
            "PrivateSubnets": _subnet_listings.get("private", []),
            "ControllerPrivateIP": self.soca_resources[
                "controller_instance"
            ].attr_private_ip,
            "ControllerPrivateDnsName": self.soca_resources[
                "controller_instance"
            ].attr_private_dns_name,
            "ControllerInstanceId": self.soca_resources[
                "controller_instance"
            ].attr_instance_id,
            "ControllerSecurityGroup": self.soca_resources[
                "controller_sg"
            ].security_group_id,
            "ComputeNodeSecurityGroup": self.soca_resources[
                "compute_node_sg"
            ].security_group_id,
            "VdiNodeSecurityGroup": self.soca_resources[
                "vdi_node_sg"
            ].security_group_id,
            "TargetNodeSecurityGroup": self.soca_resources[
                "target_node_sg"
            ].security_group_id,
            "ControllerIAMRoleArn": self.soca_resources["controller_role"].role_arn,
            "SpotFleetIAMRoleArn": self.soca_resources["spot_fleet_role"].role_arn,
            "ControllerIAMRole": self.soca_resources["controller_role"].role_name,
            "ComputeNodeIAMRoleArn": self.soca_resources["compute_node_role"].role_arn,
            "ComputeNodeIAMRole": self.soca_resources["compute_node_role"].role_name,
            "ComputeNodeInstanceProfileArn": f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:instance-profile/{self.soca_resources['compute_node_instance_profile'].ref}",
            "VdiNodeIAMRoleArn": self.soca_resources["vdi_node_role"].role_arn,
            "VdiNodeIAMRole": self.soca_resources["vdi_node_role"].role_name,
            "VdiNodeInstanceProfileArn": f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:instance-profile/{self.soca_resources['vdi_node_instance_profile'].ref}",
            "TargetNodeIAMRole": self.soca_resources["target_node_role"].role_name,
            "TargetNodeInstanceProfileArn": f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:instance-profile/{self.soca_resources['target_node_instance_profile'].ref}",
            "ClusterId": user_specified_variables.cluster_id,
            "Version": get_config_key("Config.version"),
            "Region": user_specified_variables.region,
            "S3Bucket": user_specified_variables.bucket,
            "SSHKeyPair": user_specified_variables.ssh_keypair,
            "CustomAMI": self.soca_resources["ami_id"],
            "CustomAMIMap": self.soca_resources["custom_ami_map"],
            "DCVEntryPointDNSName": self.soca_resources["alb"].load_balancer_dns_name,
            "LoadBalancerDNSName": self.soca_resources["alb"].load_balancer_dns_name,
            "LoadBalancerArn": self.soca_resources["alb"].load_balancer_arn,
            "NLBLoadBalancerDNSName": self.soca_resources["nlb"].load_balancer_dns_name,
            "BaseOS": user_specified_variables.base_os,
            "S3InstallFolder": user_specified_variables.cluster_id,
            "SolutionMetricsLambda": solution_metrics_lambda.function_arn,
            "NestedVirtLauncherLambda": nested_virt_launcher_lambda.function_arn,
            "DefaultMetricCollection": "true",
            "MetadataHttpTokens": get_config_key(
                key_name="Config.metadata_http_tokens"
            ),
            "DefaultVolumeType": get_config_key(
                key_name="Config.controller.volume_type"
            ),
            "VolumeInitializationRate": get_config_key(
                key_name="Config.dcv.volume_initialization_rate",
                expected_type=int,
                default=300,
                required=False,
            ),
            "HPCJobDeploymentMethod": "fleet",  # asg or fleet
            "HPC/SOCAInstalledSchedulerList": get_config_key(
                key_name="Config.scheduler.scheduler_engine", expected_type=list
            ),
            # Defaults for eVDI/DCV
            "DCVDefaultVersion": get_config_key("Config.dcv.version"),
            "DCVAllowPreviousGenerations": False,  # Allow Previous Generation(older) instances
            "DCVAllowBareMetal": False,  # Allow Bare Metal instances to be shown
            "DCVAllowedInstances": get_config_key(
                key_name="Config.dcv.allowed_instances", expected_type=list
            ),
            "DCVDeniedInstances": [
                "*.48xlarge"
            ],  # Wildcards of instance types that should be denied that otherwise may be permitted in the AllowedInstances
            #
            "SchedulerOpenPBSDeploymentType": get_config_key(
                "Parameters.system.scheduler.openpbs.deployment_type"
            ),
            "AIAssistant/allowed_daily_tokens_per_user": get_config_key(
                "Config.ai_assistant.allowed_daily_tokens_per_user"
            ),
            "AIAssistant/allowed_bedrock_model_ids": json.dumps(
                (lambda _cfg: ["us-gov.anthropic.claude-sonnet-5", "us-gov.anthropic.claude-opus-4-8", "us-gov.anthropic.claude-sonnet-4-5-20250929-v1:0"]
                 if self._partition == "aws-us-gov" and (not _cfg or not all(str(_m).startswith("us-gov.") for _m in _cfg))
                 else _cfg)(
                    get_config_key(
                        "Config.ai_assistant.allowed_bedrock_model_ids",
                        required=False,
                        expected_type=list,
                    ) or []
                )
            ),
            "AIAssistant/allowed_mcp_servers": json.dumps(
                get_config_key(
                    "Config.ai_assistant.allowed_mcp_servers",
                    required=False,
                    expected_type=list,
                )
            ),

        }

        if "openpbs" in self.soca_resources["soca_config"].get(
            "HPC/SOCAInstalledSchedulerList"
        ):
            _openpbs_install_pbs_exec = get_config_key(
                key_name="Parameters.system.scheduler.openpbs.pbs_exec",
                expected_type=str,
            ).replace("$EDH_CLUSTER_ID", user_specified_variables.cluster_id)
            _openpbs_install_pbs_home = get_config_key(
                key_name="Parameters.system.scheduler.openpbs.pbs_home",
                expected_type=str,
            ).replace("$EDH_CLUSTER_ID", user_specified_variables.cluster_id)

            self.soca_resources["soca_config"][f"HPC/schedulers/openpbs-default"] = {
                "enabled": True,
                "provider": "openpbs",
                "endpoint": self.soca_resources[
                    "controller_instance"
                ].attr_private_dns_name,
                "binary_folder_paths": f"{_openpbs_install_pbs_exec}/bin",
                "soca_managed_nodes_provisioning": True,
                "identifier": f"openpbs-default",
                "pbs_configuration": {
                    "pbs_exec": _openpbs_install_pbs_exec,
                    "pbs_home": _openpbs_install_pbs_home,
                },
            }

        if "pbspro" in self.soca_resources["soca_config"].get(
            "HPC/SOCAInstalledSchedulerList"
        ):
            _pbspro_install_pbs_exec = get_config_key(
                key_name="Parameters.system.scheduler.pbspro.pbs_exec",
                expected_type=str,
            ).replace("$EDH_CLUSTER_ID", user_specified_variables.cluster_id)
            _pbspro_install_pbs_home = get_config_key(
                key_name="Parameters.system.scheduler.pbspro.pbs_home",
                expected_type=str,
            ).replace("$EDH_CLUSTER_ID", user_specified_variables.cluster_id)

            self.soca_resources["soca_config"][f"HPC/schedulers/pbspro-default"] = {
                "enabled": True,
                "provider": "pbspro",
                "endpoint": self.soca_resources[
                    "controller_instance"
                ].attr_private_dns_name,
                "binary_folder_paths": f"{_pbspro_install_pbs_exec}/bin",
                "soca_managed_nodes_provisioning": True,
                "identifier": f"pbspro-default",
                "pbs_configuration": {
                    "pbs_exec": _pbspro_install_pbs_exec,
                    "pbs_home": _pbspro_install_pbs_home,
                },
            }

        if "slurm" in self.soca_resources["soca_config"].get(
            "HPC/SOCAInstalledSchedulerList"
        ):

            _slurm_install_prefix_path = get_config_key(
                key_name="Parameters.system.scheduler.slurm.install_prefix_path",
                expected_type=str,
            ).replace("$EDH_CLUSTER_ID", user_specified_variables.cluster_id)

            _slurm_install_sysconfig_path = get_config_key(
                key_name="Parameters.system.scheduler.slurm.install_sysconfig_path",
                expected_type=str,
            ).replace("$EDH_CLUSTER_ID", user_specified_variables.cluster_id)

            self.soca_resources["soca_config"][f"HPC/schedulers/slurm-default"] = {
                "enabled": True,
                "provider": "slurm",
                "endpoint": self.soca_resources[
                    "controller_instance"
                ].attr_private_dns_name,
                "binary_folder_paths": f"{_slurm_install_prefix_path}/bin:{_slurm_install_prefix_path}/sbin",
                "soca_managed_nodes_provisioning": False,
                "identifier": f"slurm-default",
                "slurm_configuration": {
                    "install_prefix_path": _slurm_install_prefix_path,
                    "install_sysconfig_path": _slurm_install_sysconfig_path,
                },
            }

        if "lsf" in self.soca_resources["soca_config"].get(
            "HPC/SOCAInstalledSchedulerList"
        ):
            _lsf_install_lsf_top = get_config_key(
                key_name="Parameters.system.scheduler.lsf.lsf_top",
                expected_type=str,
            ).replace("$EDH_CLUSTER_ID", user_specified_variables.cluster_id)

            self.soca_resources["soca_config"][f"HPC/schedulers/lsf-default"] = {
                "enabled": True,
                "provider": "lsf",
                "endpoint": self.soca_resources[
                    "controller_instance"
                ].attr_private_dns_name,
                "binary_folder_paths": "",
                "soca_managed_nodes_provisioning": True,
                "identifier": f"lsf-default",
                "lsf_configuration": {
                    "version": get_config_key(
                        key_name="Parameters.system.scheduler.lsf.version",
                        expected_type=str,
                    ),
                    "lsf_top": f"{_lsf_install_lsf_top}",
                },
            }

        # Analytics configuration
        _is_analytics_enabled = get_config_key(
            key_name="Config.analytics.enabled",
            expected_type=bool,
            required=False,
            default=True,
        )
        _analytics_config = {
            "engine": get_config_key(
                key_name="Config.analytics.engine",
                expected_type=str,
                required=False,
                default="opensearch",
            ),
            "enabled": _is_analytics_enabled,
        }

        if _is_analytics_enabled:
            if not user_specified_variables.os_endpoint:
                _analytics_engine: str = _analytics_config.get("engine", "")
                logger.debug(f"Analytics engine: {_analytics_engine}")

                if _analytics_engine in {"opensearch"}:
                    _analytics_config["endpoint"] = (
                        f"https://{self.soca_resources['os_domain'].domain_endpoint}"
                    )
                elif _analytics_engine in {"opensearch_serverless", "aoss_serverless"}:
                    _cr_endpoint = self.soca_resources.get("os_collection_endpoint")
                    if _cr_endpoint is not None:
                        # NextGen custom-resource path: the Lambda returns the
                        # full https endpoint (https://<id>.aoss.<region>.on.aws)
                        _analytics_config["endpoint"] = _cr_endpoint
                    else:
                        logger.debug(
                            f"OS Endpoint: {self.soca_resources['os_domain']=}"
                        )
                        _analytics_config["endpoint"] = (
                            f"https://{self.soca_resources['os_domain'].attr_collection_endpoint}"
                        )
                else:
                    logger.fatal(
                        f"Unsupported analytics engine defined: {_analytics_engine}"
                    )
            else:
                logger.debug(
                    f"Analytics Endpoint: {user_specified_variables.os_endpoint=}"
                )
                if not user_specified_variables.os_endpoint.startswith(
                    "https://"
                ) and not user_specified_variables.os_endpoint.startswith("http://"):
                    _analytics_config["endpoint"] = (
                        f"https://{user_specified_variables.os_endpoint}"
                    )
                else:
                    _analytics_config["endpoint"] = user_specified_variables.os_endpoint
        else:
            _analytics_config["endpoint"] = "NO_ENDPOINT_CONFIGURED"

        # Store SOCA config on AWS SSM Parameter Store
        _parameter_store_prefix = f"/edh/{user_specified_variables.cluster_id}"

        # --- Bulk SSM Writer: lazily created, shared across __init__ and dcv_infrastructure ---
        _bulk_ssm_lambda = self._get_bulk_ssm_lambda()

        # Retrieve all static SOCA parameters defined in default_config.yml
        _parameter_store_keys = flatten_parameterstore_config(
            get_config_key(key_name="Parameters", expected_type=dict)
        )
        # Build full parameter-name -> value map and bulk-write in one CR.
        # All values here are synth-time-known strings from default_config.yml,
        # so they ride over S3 via the `params` channel (no size limit).
        _bulk_static_params = {
            f"{_parameter_store_prefix}/{_k}": str(_v)
            for _k, _v in _parameter_store_keys.items()
        }
        # Model C: exclude SSM keys owned by the resource-mirror executor so the
        # mirror is their SOLE writer (no race on the s3|original repoint). The
        # installer derives this set from the manifest's config_keys.
        _mirror_excluded_keys = set()
        if get_config_key(
            key_name="Config.services.resources_mirroring.enabled",
            expected_type=bool, default=True, required=False,
        ) and get_config_key(
            key_name="Config.services.resources_mirroring.method",
            expected_type=str, default="cloud-no-vpc", required=False,
        ) != "install-host":
            _mirror_excluded_keys = set(get_config_key(
                key_name="Config.services.resources_mirroring.excluded_ssm_keys",
                expected_type=list, default=[], required=False,
            ) or [])

        self._write_bulk_ssm_params(
            "BulkSSMStaticParams",
            params=_bulk_static_params,
            exclude_keys=_mirror_excluded_keys,
        )
        logger.debug(
            f"Bulk-wrote {len(_bulk_static_params)} static Parameter store entries"
        )

        if _custom_tags:
            for _tag_id in _custom_tags.keys():
                self.soca_resources["soca_config"][f"CustomTags/{_tag_id}"] = (
                    _custom_tags[_tag_id]
                )

        # Flatten Config Dict

        # Remove unwanted config keys

        for ds_keys in [
            "ds",  # Optional if using existing_active_directory/openldap
            "ds_admin_username",  # We do not want to store this on SSM
            "ds_admin_password",  # We do not want to store this on SSM
        ]:
            if ds_keys in self.directory_service_resource_setup:
                del self.directory_service_resource_setup[ds_keys]

        # Make a copy of the list version of the obj
        _ds_resources = self.directory_service_resource_setup.copy()

        # Update directory_service_resource_setup[domain_controller_ips] list to a str for SSM
        _ds_resources["domain_controller_ips"] = str(
            self.directory_service_resource_setup["domain_controller_ips"]
        )

        # Feature Flags - remove webInterface as they use a different format and already been added
        _ff = get_config_key(
            key_name="Config.feature_flags",
            expected_type=dict,
            required=True,
        )

        _dicts_to_flatten = {
            "/configuration/Analytics": _analytics_config,
            "/configuration/UserDirectory": _ds_resources,
            "/configuration/Cache": flatten_parameterstore_config(self.cache_info),
            "/configuration/Database": flatten_parameterstore_config(self.database_info),
            "/configuration/FileSystems": flatten_parameterstore_config(
                self.soca_filesystems
            ),
            "/configuration/FeatureFlags": flatten_parameterstore_config(_ff),
            "/configuration/HPC/hooks": {
                "check_budget": False,
                "check_restricted_parameters": True,
                "check_instance_types": True,
                "check_custom_security_groups": True,
                "check_custom_iam_instance_profile": True,
                "check_queue_acls": True,
            },
            "/configuration/WebShell": flatten_parameterstore_config(
                get_config_key(
                    key_name="Config.webshell",
                    expected_type=dict,
                    required=True,
                ),
            ),
            # Password Policy for the UserDirectory
            "/configuration/UserDirectory/password_policy": flatten_parameterstore_config(
                get_config_key(
                    key_name="Config.directoryservice.aws_ds_managed_activedirectory.password_policy",
                    expected_type=dict,
                    required=False,
                    default={"enabled": True},
                ),
            ),
            # Web interface settings (e.g. file tail). Optional block — if
            # the user removed it from default_config.yml, fall back to
            # empty dict and rely on the view-side defaults in tail.py.
            "/configuration/WebInterface": flatten_parameterstore_config(
                get_config_key(
                    key_name="Config.web_interface",
                    expected_type=dict,
                    required=False,
                    default={},
                ),
            ),
            # File transfer engine selector (v1 = Dropzone + native download,
            # v2 = Uppy/tus + parallel download). Optional block; defaults to v1
            # so fresh installs pre-create the key and it is UI-flippable.
            "/configuration/FileBrowser": flatten_parameterstore_config(
                get_config_key(
                    key_name="Config.file_browser",
                    expected_type=dict,
                    required=False,
                    default={"TransferEngine": "v1"},
                ),
            ),
            # My HPC Jobs listing controls (visibility ceiling, default window, row cap,
            # finished-by-default). Optional block; pre-created on fresh installs so the
            # keys are UI/edhctl-flippable and read hot by the my_jobs view + scheduler jobs API.
            "/configuration/HPC/JobListing": flatten_parameterstore_config(
                get_config_key(
                    key_name="Config.hpc_job_listing",
                    expected_type=dict,
                    required=False,
                    default={
                        "VisibilityScope": "all",
                        "DefaultWindow": "24h",
                        "MaxRows": "1000",
                        "IncludeFinished": "true",
                    },
                ),
            ),
            # Owned-base AMI acceleration flag (default off). Pre-creates the keys so they are
            # UI/edhctl-flippable and read on the launch hot path by resolve_launch_ami().
            # Priority is authored as a YAML list of base_os[:arch] and seeded as a comma string.
            "/configuration/BaseImageAcceleration": flatten_parameterstore_config(
                {
                    "Enabled": str(
                        get_config_key(
                            key_name="Config.base_image_acceleration.Enabled",
                            expected_type=str,
                            required=False,
                            default="false",
                        )
                    ),
                    "Priority": json.dumps(
                        get_config_key(
                            key_name="Config.base_image_acceleration.Priority",
                            expected_type=dict,
                            required=False,
                            default={
                                "x86_64": ["windows2025", "amazonlinux2023"],
                                "arm64": ["amazonlinux2023"],
                            },
                        )
                    ),
                }
            ),
        }

        _ssm_config_n: int = 1
        # Build name -> value map for all dynamic/tokenized config.
        # These values may contain CDK tokens (cache endpoints, FS IDs,
        # DS DNS, etc.) so we send them through the `resolved_params`
        # channel -- CFN resolves the tokens before invoking the Lambda
        # and CDK auto-wires the DependsOn tree from every referenced
        # resource.
        _bulk_dynamic_params: dict = {}

        for _parent_prefix, _dict in _dicts_to_flatten.items():
            _dict_flattened = flatten_parameterstore_config(_dict)
            for _k, _v in _dict_flattened.items():
                _bulk_dynamic_params[
                    f"{_parameter_store_prefix}{_parent_prefix}/{_k}"
                ] = str(_v)
                _ssm_config_n += 1

        logger.debug(f"Collected dynamic SSM config entries: {_ssm_config_n=}")

        # Retrieve dynamic SOCA parameters created during the CDK
        # (soca_config contains lots of CDK tokens: VPC id, ALB ARN,
        # role ARNs, subnet id lists, etc.). Merge into the same bulk
        # writer so one CR handles everything runtime.
        #
        # Note: lists (e.g. PublicSubnets, PrivateSubnets) are intentionally
        # stored as Python-list repr strings -- consumers parse them back
        # with ast.literal_eval. Preserve that wire format via plain str().
        _ssm_dyn_n: int = 1
        for _k, _v in self.soca_resources["soca_config"].items():
            _bulk_dynamic_params[f"{_parameter_store_prefix}/configuration/{_k}"] = str(
                _v
            )
            _ssm_dyn_n += 1

        logger.debug(f"Collected SSM Dyn entries: {_ssm_dyn_n=}")

        if _bulk_dynamic_params:
            self._write_bulk_ssm_params(
                "BulkSSMDynamicParams",
                resolved_params=_bulk_dynamic_params,
            )
            logger.debug(
                f"Bulk-wrote {len(_bulk_dynamic_params)} dynamic Parameter store entries"
            )

        # Controller host has R/W permissions. Delete permissions are not allowed
        self.soca_resources["controller_role"].attach_inline_policy(
            iam.Policy(
                self,
                "AttachParameterStorePolicyToController",
                statements=[
                    iam.PolicyStatement(
                        actions=["ssm:DescribeParameters"],
                        effect=iam.Effect.ALLOW,
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "ssm:GetParameters",
                            "ssm:GetParameterHistory",
                            "ssm:GetParametersByPath",
                            "ssm:GetParameter",
                            "ssm:PutParameter",
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter{_parameter_store_prefix}/*"
                        ],
                    ),
                ],
            )
        )

        # All other nodes only have R permissions
        for _role in [
            "compute_node_role",
            "vdi_node_role",
            "spot_fleet_role",
            "login_node_role",
            "target_node_role",
        ]:
            self.soca_resources[_role].attach_inline_policy(
                iam.Policy(
                    self,
                    f"AttachParameterStorePolicyTo{_role.split('_')[0].capitalize()}Node",
                    statements=[
                        iam.PolicyStatement(
                            actions=["ssm:DescribeParameters"],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "ssm:GetParameters",
                                "ssm:GetParameterHistory",
                                "ssm:GetParametersByPath",
                                "ssm:GetParameter",
                            ],
                            effect=iam.Effect.ALLOW,
                            resources=[
                                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter{_parameter_store_prefix}/*"
                            ],
                        ),
                    ],
                )
            )

        # Create IAM policy and attach it to both Controller and Compute Nodes group
        self.soca_resources["controller_role"].attach_inline_policy(
            iam.Policy(
                self,
                "AttachSecretManagerPolicyToController",
                statements=[
                    iam.PolicyStatement(
                        actions=[
                            "secretsmanager:GetSecretValue",
                            "secretsmanager:DescribeSecret",
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            # Covers every EDH cluster secret under the /edh/<cluster>/
                            # namespace, INCLUDING the DCV event-relay HMAC key
                            # (/edh/<cluster>/dcv-event-relay-key) the controller reads
                            # to validate relay POSTs.
                            f"arn:{Aws.PARTITION}:secretsmanager:{Aws.REGION}:{Aws.ACCOUNT_ID}:secret:/edh/{user_specified_variables.cluster_id}/*",
                            f"{self.directory_service_resource_setup.get('service_account_secret_arn')}",
                        ],
                    )
                ],
            )
        )

        # WS3: fleet-shared session key material in SM under /edh/<cluster>/ (covered by the controller wildcard grant above); SM-generated value, the web app derives the Fernet key from it.
        _session_signer_secret = secretsmanager.Secret(
            self,
            "SessionSignerSecret",
            secret_name=f"/edh/{user_specified_variables.cluster_id}/SessionSignerKey",
            description="Flask session signer SECRET_KEY (fleet-shared, rotation-ready)",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=64,
                exclude_punctuation=True,
                include_space=False,
                require_each_included_type=False,
            ),
        )
        _session_encryption_secret = secretsmanager.Secret(
            self,
            "SessionEncryptionSecret",
            secret_name=f"/edh/{user_specified_variables.cluster_id}/SessionEncryptionKey",
            description="Session payload encryption key material; app derives a Fernet key (fleet-shared, rotation-ready)",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=64,
                exclude_punctuation=True,
                include_space=False,
                require_each_included_type=False,
            ),
        )
        ssm.StringParameter(
            self,
            "SessionSignerSecretArnParam",
            parameter_name=f"/edh/{user_specified_variables.cluster_id}/configuration/WebInterface/SessionSignerSecretArn",
            string_value=_session_signer_secret.secret_arn,
            description="SecretsManager ARN for the Flask session signer key",
        )
        ssm.StringParameter(
            self,
            "SessionEncryptionSecretArnParam",
            parameter_name=f"/edh/{user_specified_variables.cluster_id}/configuration/WebInterface/SessionEncryptionSecretArn",
            string_value=_session_encryption_secret.secret_arn,
            description="SecretsManager ARN for the session payload encryption key",
        )
        ssm.StringParameter(
            self,
            "SessionBackendParam",
            parameter_name=f"/edh/{user_specified_variables.cluster_id}/configuration/WebInterface/session_backend",
            string_value="redis",
            description="Flask-session backend selector (SSM is source of truth): redis (Valkey-backed, default) or dynamodb. Runtime-flippable, no redeploy.",
        )
        # IAM database authentication: grant the controller rds-db:connect for the
        # app user so the web app connects to Aurora with short-lived IAM tokens
        # (no long-lived password). Skipped when the provider is not aurora.
        if self.database_info.get("iam_auth") and self.database_info.get(
            "cluster_resource_id"
        ):
            self.soca_resources["controller_role"].attach_inline_policy(
                iam.Policy(
                    self,
                    "AttachDatabaseIamConnectToController",
                    statements=[
                        iam.PolicyStatement(
                            actions=["rds-db:connect"],
                            effect=iam.Effect.ALLOW,
                            resources=[
                                f"arn:{Aws.PARTITION}:rds-db:{Aws.REGION}:{Aws.ACCOUNT_ID}:"
                                f"dbuser:{self.database_info['cluster_resource_id']}/"
                                f"{self.database_info['app_user']}"
                            ],
                        )
                    ],
                )
            )
        # Compute Nodes can only query some secrets
        _compute_node_iam_resources = [
            f"{self.directory_service_resource_setup.get('service_account_secret_arn')}"
        ]

        # IAM-only cache auth: nodes authenticate to Valkey via SigV4 IAM tokens
        # (elasticache:Connect on the scoped readonly user), so there is no cache
        # password secret for node roles to read. Closes the GetSecretValue->
        # password vector the POC exploited.

        # FIXME TODO - this can be merged with the prior loop as well
        # VDI nodes (vdi_node_role) join AD during bootstrap and read the
        # directory service-account secret via Get-Secret, so they need the
        # same secretsmanager:GetSecretValue grant as compute. Omitting it
        # leaves the VDI unable to fetch the join credential -- the AD-join
        # bootstrap phase fails and the desktop hangs at "joining AD".
        for _role in {"compute_node_role", "vdi_node_role", "spot_fleet_role", "login_node_role"}:
            self.soca_resources[_role].attach_inline_policy(
                iam.Policy(
                    self,
                    f"AttachSecretManagerPolicyTo{_role.split('_')[0].capitalize()}Node",
                    statements=[
                        iam.PolicyStatement(
                            actions=["secretsmanager:GetSecretValue"],
                            effect=iam.Effect.ALLOW,
                            resources=_compute_node_iam_resources,
                        )
                    ],
                )
            )

        _install_scheduler_from_s3_uri = get_config_key(
            key_name="Parameters.system.scheduler.openpbs.s3_tgz.s3_uri",
            expected_type=str,
            required=False,
            default="",
        )
        if _install_scheduler_from_s3_uri:
            try:
                _s3_uri_bucket_name = re.search(
                    r"s3://([^/]+)", _install_scheduler_from_s3_uri
                ).group(1)
            except AttributeError:
                logger.fatal(
                    f"s3_uri {_install_scheduler_from_s3_uri} does not seems to be a valid s3_uri"
                )

            _custom_openpbs_s3_bucket_policy = iam.Policy(
                self,
                "AttachCustomS3BucketSchedulerPolicyToComputeNode",
                statements=[
                    iam.PolicyStatement(
                        actions=["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:{Aws.PARTITION}:s3:::{_s3_uri_bucket_name}/*",
                            f"arn:{Aws.PARTITION}:s3:::{_s3_uri_bucket_name}",
                        ],
                    )
                ],
            )
            for _rn in {
                "compute_node_role",
                "controller_role",
                "login_node_role",
                "spot_node_role",
                "target_node_role",
            }:
                self.soca_resources[_rn].attach_inline_policy(
                    _custom_openpbs_s3_bucket_policy
                )

        # cdk_completed is the canary the controller waits on before bootstrap.
        # It must not be written until ALL bulk SSM writers have finished.
        _final_ssm_parameter = ssm.StringParameter(
            self,
            "ParameterCDKCompleted",
            parameter_name=f"{_parameter_store_prefix}/cdk_completed",
            string_value="true",
            tier=ssm.ParameterTier.STANDARD,
        )
        _final_ssm_parameter.node.add_dependency(self.soca_resources["nlb"])
        # cdk_completed must also flip only after every BulkSSMWriter CR
        # finishes, so nothing downstream of SSM reads a half-populated
        # parameter tree.
        for _writer in self._bulk_ssm_writers:
            _final_ssm_parameter.node.add_dependency(_writer)
        if self.directory_service_resource_setup.get("ds"):
            _final_ssm_parameter.node.add_dependency(
                self.directory_service_resource_setup["ds"]
            )
        # Expose for downstream gating constructs (e.g. ASG capacity
        # bumpers waiting for the SSM parameter tree to be complete
        # before launching their backing instances).
        self.soca_resources["cdk_completed_param"] = _final_ssm_parameter

    def analytics(self):
        """
        Create Analytics cluster. This will be used for jobs and hosts analytics.
        """
        _desired_engine: str = get_config_key(
            key_name="Config.analytics.engine",
            expected_type=str,
            required=False,
            default="opensearch",
        ).lower()

        if _desired_engine in {"opensearch"}:
            self.analytics_opensearch()
        elif _desired_engine in {"opensearch_serverless", "aoss_serverless"}:
            aoss_helper.create_collection(
                scope=self,
                soca_resources=self.soca_resources,
                user_specified_variables=user_specified_variables,
                get_config_key=get_config_key,
                get_lambda_runtime_version=get_lambda_runtime_version,
            )
        else:
            logger.fatal(
                f"Config.analytics.engine must be one of opensearch or opensearch_serverless. Detected {_desired_engine}"
            )

    def is_opensearch_instance_available_by_role(
        self,
        opensearch_client,
        opensearch_engine: str,
        instance_type: str,
        instance_role: str,
        region: str,
    ) -> bool:
        """
        Return if the combo of instance_type, region, availability_zone, and OpenSearch role are available.
        """
        logger.debug(
            f"Using OpenSearch client: {opensearch_client=} to validate {instance_type=} as a {instance_role=} in region {region}"
        )

        # We need to validate the instance is available and available for the Role
        try:
            _instance_available_response = opensearch_client.list_instance_type_details(
                EngineVersion=opensearch_engine,
                InstanceType=instance_type,
                RetrieveAZs=True,  # Required to be True in the API call when sending the InstanceType
            ).get("InstanceTypeDetails", {})[0]
        except opensearch_client.exceptions.ValidationException as e:
            logger.warning(
                f"Exception During OpenSearch instance validation: {e.response['Error']['Message']}"
            )
            return False

        logger.debug(
            f"OpenSearch instance type details: {_instance_available_response=}"
        )

        _instance_available_roles: list = _instance_available_response.get(
            "InstanceRole", []
        )
        logger.debug(
            f"Instance roles available for {instance_type}: {_instance_available_roles}"
        )

        if instance_role.lower() in _instance_available_roles:
            logger.debug(f"Validated instance {instance_type} for role {instance_role}")
            return True
        else:
            logger.debug(
                f"Unable to find OpenSearch role for instance - skipping {instance_type}"
            )
            return False

    def select_best_instance_for_opensearch(
        self,
        opensearch_client,
        opensearch_engine: str,
        instance_types: list,
        instance_role: str,
        region: str,
    ) -> str:
        """
        Return the best (first) opensearch instance that is available for a particular OpenSearch role.
        """

        logger.debug(
            f"Using OpenSearch client: {opensearch_client=} to validate {instance_types=} as a {instance_role=} with engine {opensearch_engine} in region {region}"
        )

        for _instance_type in instance_types:
            if self.is_opensearch_instance_available_by_role(
                opensearch_client=opensearch_client,
                opensearch_engine=opensearch_engine,
                instance_type=_instance_type,
                instance_role=instance_role,
                region=region,
            ):
                # First match wins - just return if we find something that works
                return _instance_type

        # We shouldn't make it this far - if we do - there is no matching instance. We should just fail/exit?
        logger.fatal(
            f"Unable to find a matching OpenSearch instance type that works! Unable to continue."
        )
        return ""  # Unused - silence code checkers

    def analytics_opensearch(self):
        """Extracted to helpers/analytics.py."""
        from helpers import analytics as _helper

        return _helper.analytics_opensearch(
            self,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            return_ebs_volume_type=return_ebs_volume_type,
            get_service_principal_url_suffix=get_service_principal_url_suffix,
        )

    def backups(self):
        """Extracted to helpers/backups.py."""
        from helpers import backups as _helper

        return _helper.backups(
            self,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            is_valid_backup_vault_arn=is_valid_backup_vault_arn,
        )

    def login_nodes(self):
        """Extracted to helpers/login_nodes.py."""
        from helpers import login_nodes as _helper

        return _helper.login_nodes(
            self,
            endpoints_suffix=endpoints_suffix,
            install_props=install_props,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            flatten_parameterstore_config=flatten_parameterstore_config,
            return_ebs_volume_type=return_ebs_volume_type,
        )

    def webshell(self):
        """Wire up the in-browser SSH terminal (webshell) feature.



        Must be called AFTER both login_nodes() (which creates login_node_asg
        and login_node_sg) and viewer() (which creates https_listener).
        """
        webshell_helper.setup_webshell(
            scope=self,
            soca_resources=self.soca_resources,
            user_specified_variables=user_specified_variables,
            get_config_key=get_config_key,
        )

    def viewer(self):
        """Extracted to helpers/dcv.py."""
        from helpers import dcv as _helper

        return _helper.viewer(
            self,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            principals_suffix=principals_suffix,
            get_lambda_runtime_version=get_lambda_runtime_version,
            flatten_parameterstore_config=flatten_parameterstore_config,
            return_ebs_volume_type=return_ebs_volume_type,
        )
    def configure_aws_aga(self):
        """Extracted to helpers/global_accelerator.py."""
        from helpers import global_accelerator as _helper

        return _helper.configure_aws_aga(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
        )

    def viewer_analytics_opensearch(self):
        """
        Configure the view for OpenSearch Analytics
        """
        if not user_specified_variables.os_endpoint:
            CfnOutput(
                self,
                "AnalyticsDashboard",
                value=f"https://{self.soca_resources['os_domain'].domain_endpoint}/_dashboards",
            )

        else:
            CfnOutput(
                self,
                "AnalyticsDashboard",
                value=f"https://{user_specified_variables.os_endpoint}/{'_dashboards' if get_config_key('Config.analytics.engine')  == 'opensearch' else '_plugin/kibana'}/",
            )

    def aws_batch(self):
        """Extracted to helpers/batch.py."""
        from helpers import batch as _helper

        return _helper.aws_batch(
            self,
            user_specified_variables=user_specified_variables,
        )

    @staticmethod
    def is_instance_available(instance_type: str, region: str) -> bool:
        """
        Check if the specified instance type is available in the given region.
        """
        ec2_client = boto3_helper.get_boto(
            service_name="ec2",
            profile_name=user_specified_variables.profile,
            region_name=region,
        )

        try:
            # pagination is not a concern since we are always looking at a single instance type
            response = ec2_client.describe_instance_types(
                InstanceTypes=[instance_type],
                Filters=[{"Name": "supported-usage-class", "Values": ["on-demand"]}],
            )
        except Exception as err:
            # This is a logger.warning vs logger.error since instance
            # types naturally vary between regions and do not represent
            # a hard error condition to concern the user.
            logger.warning(
                f"Error checking instance type availability for {instance_type} in {region}.  Error: {err}"
            )
            return False

        return len(response["InstanceTypes"]) > 0

    def select_best_instance(
        self, instance_list: list, region: str, fallback_instance: str
    ) -> tuple[str, str, str]:
        """
        Return the best instance type from a given list and region. This probes the region for instance availability and will return the first one that is available in the region.

        Returns tuple of (instance_type, instance_architecture, instance_ami).
        """
        _selected_instance: str = "amnesiac"
        _default_ami_for_instance: str = ""
        _instance_arch: str = "unknown"

        logger.debug(
            f"Selecting best instance from {instance_list} for region {region} ..."
        )
        for _instance in instance_list:
            if self.is_instance_available(instance_type=_instance, region=region):
                _instance_arch = get_arch_for_instance_type(
                    region=self._region, instancetype=_instance
                )
                _default_ami_for_instance = (
                    self.soca_resources.get("custom_ami_map", {})
                    .get(_instance_arch, {})
                    .get(self._base_os, "")
                )
                if _default_ami_for_instance:
                    _selected_instance = _instance
                    break
                else:
                    logger.warning(
                        f"No AMI found for {_instance} (arch {_instance_arch}, base os {self._base_os}, region {region}, testing next instance in selection"
                    )

        if _default_ami_for_instance is None:
            logger.fatal(
                "No AMI on region_map.yml found. Choose a different OS/Region or Architecture"
            )

        if _selected_instance == "amnesiac":
            _selected_instance = fallback_instance if fallback_instance else "m5.large"
            _instance_arch = "x86_64"

        logger.debug(
            f"Selected instance type of {_selected_instance} (Arch: {_instance_arch}) from {instance_list} in region {region} AMI is {_default_ami_for_instance}"
        )
        return _selected_instance, _instance_arch, _default_ami_for_instance

    @staticmethod
    def return_ebs_volume_name(base_os: str) -> str:
        """
        Return the EBS volume name based on the BaseOS.
        """
        _ebs_device_name: str = "unknown"

        if base_os.lower() in {"amazonlinux2", "amazonlinux2023"}:
            _ebs_device_name = "/dev/xvda"
        else:
            _ebs_device_name = "/dev/sda1"

        logger.debug(
            f"Returning EBS volume name {_ebs_device_name} for BaseOS: {base_os}"
        )
        return _ebs_device_name

    def dcv_infrastructure(self):
        """Extracted to helpers/dcv.py."""
        from helpers import dcv as _helper

        return _helper.dcv_infrastructure(
            self,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            principals_suffix=principals_suffix,
            get_lambda_runtime_version=get_lambda_runtime_version,
            flatten_parameterstore_config=flatten_parameterstore_config,
            return_ebs_volume_type=return_ebs_volume_type,
        )
    def dcv_event_relay(self):
        """Extracted to helpers/dcv.py."""
        from helpers import dcv as _helper

        return _helper.dcv_event_relay(
            self,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            principals_suffix=principals_suffix,
            get_lambda_runtime_version=get_lambda_runtime_version,
            flatten_parameterstore_config=flatten_parameterstore_config,
            return_ebs_volume_type=return_ebs_volume_type,
        )
    def ssm_config_sync(self):
        """Extracted to helpers/ssm.py."""
        from helpers import ssm as _helper

        return _helper.ssm_config_sync(
            self,
            get_config_key=get_config_key,
            user_specified_variables=user_specified_variables,
            get_lambda_runtime_version=get_lambda_runtime_version,
        )

    def vdi_pools(self):
        """
        Provision the VDI pooling DynamoDB tables (config / ledger /
        summary). Implementation lives in helpers/vdi_pools.py; this is the
        thin entry point. Pool AWS resources -- ASGs, warm pools,
        launch templates, scheduled actions, alarms -- are created at
        RUNTIME by the PoolController.
        """
        vdi_pools_helper.setup(
            scope=self,
            soca_resources=self.soca_resources,
            user_specified_variables=user_specified_variables,
            lambda_runtime=get_lambda_runtime_version(),
            get_config_key=get_config_key,
        )

    def session_sharing(self):
        """
        Provision DCV session sharing infrastructure (profiles/grants DDB
        tables + expiry Lambda). Gated by Config.dcv.session_sharing.enabled
        AND Config.dcv.high_scale (sharing requires the broker).
        """
        _enabled = get_config_key(
            key_name="Config.dcv.session_sharing.enabled",
            expected_type=bool,
            default=True,
            required=False,
        )
        _high_scale = get_config_key(
            key_name="Config.dcv.high_scale",
            expected_type=bool,
            default=False,
            required=False,
        )
        if not _enabled:
            return
        if not _high_scale:
            raise ValueError(
                "Config.dcv.session_sharing.enabled=True requires "
                "Config.dcv.high_scale=True (session sharing depends on the DCV broker)."
            )
        dcv_session_sharing_helper.setup(
            scope=self,
            soca_resources=self.soca_resources,
            user_specified_variables=user_specified_variables,
            lambda_runtime=get_lambda_runtime_version(),
            get_config_key=get_config_key,
        )

    def vdi_launch_history(self):
        """Extracted to helpers/vdi_launch_history.py."""
        from helpers import vdi_launch_history as _helper

        return _helper.vdi_launch_history(
            self,
            user_specified_variables=user_specified_variables,
            get_lambda_runtime_version=get_lambda_runtime_version,
        )

    def config_editor_audit(self):
        """Configuration Editor audit trail DDB table (always-on admin surface)."""
        from helpers import config_audit as _helper

        return _helper.setup(self, user_specified_variables=user_specified_variables)

    def user_preferences(self):
        """Extracted to helpers/user_preferences.py."""
        from helpers import user_preferences as _helper

        return _helper.setup(
            self,
            user_specified_variables=user_specified_variables,
        )

    def ai_token_usage(self):
        """Provision the AI Assistant daily token usage DDB table."""
        ai_token_usage_helper.setup(
            scope=self,
            soca_resources=self.soca_resources,
            user_specified_variables=user_specified_variables,
        )

    def is_networking_af_enabled(self, address_family: str):
        """
        Determine if the address-family is enabled for this instance of SOCAInstall
        """
        return True if address_family in self.networking_enabled_af else False

    def _dcv_high_scale_alarms(self):
        """Extracted to helpers/dcv.py."""
        from helpers import dcv as _helper

        return _helper._dcv_high_scale_alarms(
            self,
            get_config_key=get_config_key,
            get_kms_key_id=get_kms_key_id,
            user_specified_variables=user_specified_variables,
            principals_suffix=principals_suffix,
            get_lambda_runtime_version=get_lambda_runtime_version,
            flatten_parameterstore_config=flatten_parameterstore_config,
            return_ebs_volume_type=return_ebs_volume_type,
        )
    def notification_infrastructure(self):
        """Create Cluster Notification Infrastructure.

        Implementation extracted to helpers/notifications.py.
        """
        from helpers import notifications as notifications_helper

        notifications_helper.setup(
            self,
            self.soca_resources,
            user_specified_variables,
            get_kms_key_id=get_kms_key_id,
            principals_suffix=principals_suffix,
        )


if __name__ == "__main__":
    app = App()

    # User specified variables/install properties, queryable as Python Object
    user_specified_variables = json.loads(
        json.dumps(
            {
                "install_properties": base64.b64decode(
                    app.node.try_get_context("install_properties")
                ).decode("utf-8"),
                "bucket": app.node.try_get_context("bucket"),
                "region": app.node.try_get_context("region"),
                "email_address": ast.literal_eval(
                    base64.b64decode(app.node.try_get_context("email_address")).decode(
                        "utf-8"
                    )
                ),
                "deployment_mode": app.node.try_get_context("deployment_mode"),
                "partition": app.node.try_get_context("partition"),
                "base_os": app.node.try_get_context("base_os"),
                "ssh_keypair": app.node.try_get_context("ssh_keypair"),
                "client_ip": ast.literal_eval(
                    base64.b64decode(app.node.try_get_context("client_ip")).decode(
                        "utf-8"
                    ),
                ),
                "client_ipv6": None,  # Save for later since it may be None from installer
                "prefix_list_id": app.node.try_get_context("prefix_list_id"),
                "prefix_list_id_ipv6": app.node.try_get_context("prefix_list_id_ipv6"),
                "custom_ami": app.node.try_get_context("custom_ami"),
                "cluster_id": app.node.try_get_context("cluster_id"),
                "vpc_cidr": app.node.try_get_context("vpc_cidr"),
                "vpc_cidr_ipv6": app.node.try_get_context("vpc_cidr_ipv6"),
                "create_es_service_role": (
                    False
                    if app.node.try_get_context("create_es_service_role") == "False"
                    else True
                ),
                "vpc_azs": app.node.try_get_context("vpc_azs"),
                "vpc_id": app.node.try_get_context("vpc_id"),
                "public_subnets": (
                    app.node.try_get_context("public_subnets")
                    if app.node.try_get_context("public_subnets") is None
                    else ast.literal_eval(
                        base64.b64decode(
                            app.node.try_get_context("public_subnets")
                        ).decode("utf-8")
                    )
                ),
                "private_subnets": (
                    app.node.try_get_context("private_subnets")
                    if app.node.try_get_context("private_subnets") is None
                    else ast.literal_eval(
                        base64.b64decode(
                            app.node.try_get_context("private_subnets")
                        ).decode("utf-8")
                    )
                ),
                "fs_apps_provider": app.node.try_get_context("fs_apps_provider"),
                "fs_apps": app.node.try_get_context("fs_apps"),
                "fs_data_provider": app.node.try_get_context("fs_data_provider"),
                "fs_data": app.node.try_get_context("fs_data"),
                "compute_node_sg": app.node.try_get_context("compute_node_sg"),
                "vdi_node_sg": app.node.try_get_context("vdi_node_sg"),
                "controller_sg": app.node.try_get_context("controller_sg"),
                "alb_sg": app.node.try_get_context("alb_sg"),
                "nlb_sg": app.node.try_get_context("nlb_sg"),
                "login_node_sg": app.node.try_get_context("login_node_sg"),
                "vpc_endpoint_sg": app.node.try_get_context("vpc_endpoint_sg"),
                "elasticache_sg": app.node.try_get_context("elasticache_sg"),
                "database_sg": app.node.try_get_context("database_sg"),
                "compute_node_role": app.node.try_get_context("compute_node_role"),
                "controller_role": app.node.try_get_context("controller_role"),
                "directory_service_user": app.node.try_get_context(
                    "directory_service_user"
                ),
                "directory_service_user_password": app.node.try_get_context(
                    "directory_service_user_password"
                ),
                "directory_service_shortname": app.node.try_get_context(
                    "directory_service_shortname"
                ),
                "directory_service_name": app.node.try_get_context(
                    "directory_service_name"
                ),
                "directory_service_id": app.node.try_get_context(
                    "directory_service_id"
                ),
                "directory_service_ds_dns": app.node.try_get_context(
                    "directory_service_dns"
                ),
                "os_endpoint": app.node.try_get_context("os_endpoint"),
                "ldap_host": app.node.try_get_context("ldap_host"),
                "compute_node_role_name": app.node.try_get_context(
                    "compute_node_role_name"
                ),
                "compute_node_role_arn": app.node.try_get_context(
                    "compute_node_role_arn"
                ),
                "compute_node_role_from_previous_soca_deployment": app.node.try_get_context(
                    "compute_node_role_from_previous_soca_deployment"
                ),
                "controller_role_name": app.node.try_get_context(
                    "controller_role_name"
                ),
                "controller_role_arn": app.node.try_get_context("controller_role_arn"),
                "controller_role_from_previous_soca_deployment": app.node.try_get_context(
                    "controller_role_from_previous_soca_deployment"
                ),
                "spotfleet_role_name": app.node.try_get_context("spotfleet_role_name"),
                "spotfleet_role_arn": app.node.try_get_context("spotfleet_role_arn"),
                "spotfleet_role_from_previous_soca_deployment": app.node.try_get_context(
                    "spotfleet_role_from_previous_soca_deployment"
                ),
                "tls_certificate": app.node.try_get_context(
                    "tls_certificate"
                ),
                "profile": (
                    None
                    if app.node.try_get_context("profile") == "False"
                    else app.node.try_get_context("profile")
                ),
            }
        ),
        object_hook=lambda d: SimpleNamespace(**d),
    )

    # Some items we have to delay for more flexibility
    # We dont have the ability to do any ipv6 enable detection just yet
    if app.node.try_get_context("client_ipv6"):
        logger.debug("Setting Client IPv6")
        user_specified_variables.client_ipv6 = ast.literal_eval(
            base64.b64decode(
                app.node.try_get_context("client_ipv6"),
            ).decode("utf-8"),
        )
    else:
        logger.debug("No Client IPv6 conversion needed")

    install_props = json.loads(
        user_specified_variables.install_properties,
    )

    # List of AWS endpoints & principals suffix
    endpoints_suffix = {
        "fsx_lustre": f"fsx.{Aws.REGION}.{get_service_principal_url_suffix()}",
        "fsx_openzfs": f"fsx.{Aws.REGION}.{get_service_principal_url_suffix()}",
        "fsx_ontap": f"fsx.{Aws.REGION}.{{get_service_principal_url_suffix()}}",
        "efs": f"efs.{Aws.REGION}.{get_service_principal_url_suffix()}",
    }

    principals_suffix = {
        "backup": f"backup.{get_service_principal_url_suffix()}",
        "cloudwatch": f"cloudwatch.{get_service_principal_url_suffix()}",
        "ec2": f"ec2.{get_service_principal_url_suffix()}",
        "lambda": f"lambda.{get_service_principal_url_suffix()}",
        "sns": f"sns.{get_service_principal_url_suffix()}",
        "spotfleet": f"spotfleet.{get_service_principal_url_suffix()}",
        "ssm": f"ssm.{get_service_principal_url_suffix()}",
    }

    # Apply tags to all CDK taggable resources
    #
    # If we don't have custom_tags defined in the configuration file, we still have default_tags
    #
    # We add all tags to cluster_tags since there are a few resources that still struggle with this
    # (LaunchTemplates) due to how they accept Tags.
    #
    # This provides a uniform way to access _all_ the tags that should be present for the SOCA cluster and
    # associated resources via the SOCAInstaller().

    _cluster_tags: list = [
        {"Key": "edh:ClusterId", "Value": user_specified_variables.cluster_id},
        {"Key": "edh:CreatedOn", "Value": str(datetime.datetime.now(datetime.UTC))},
        {
            "Key": "edh:Version",
            "Value": get_config_key(
                key_name="Config.version", required=False, default="26.4.0"
            ),
        },
    ]

    # Tags that originate from our configuration file
    if get_config_key(key_name="Config.custom_tags", required=False):
        for custom_tag in get_config_key(
            key_name="Config.custom_tags",
            expected_type=list,
            required=False,
        ):
            _tag_key: str = custom_tag.get("Key")
            _tag_value: str = custom_tag.get("Value")
            if not _tag_key:
                logger.warning("Skipping broken tag specification (check config file)")
                continue

            # Don't check the tag value here - since tag values can be blank

            logger.debug(
                f"Adding Custom Tag from configuration file:    Key: {_tag_key}  /  Value: {_tag_value}"
            )
            _cluster_tags.append({"Key": _tag_key, "Value": _tag_value})

    # Info? Debug?
    logger.debug(
        f"Complete Cluster Tags (default tags plus custom tags): {_cluster_tags=}"
    )

    # Apply all tags to the CDK App
    # While this covers _most_ resources, there are still some that are missed
    # due to CDK-isms/defects
    for _cluster_tag in _cluster_tags:
        Tags.of(app).add(_cluster_tag.get("Key"), _cluster_tag.get("Value"))

    # Launch Cfn generation
    cdk_env = Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"],
        region=(
            user_specified_variables.region
            if user_specified_variables.region
            else os.environ["CDK_DEFAULT_REGION"]
        ),
    )

    install = SOCAInstall(
        app,
        user_specified_variables.cluster_id,
        env=cdk_env,
        cluster_tags=_cluster_tags,
        description=f"SOCA cluster version {get_config_key('Config.version')}",
        termination_protection=get_config_key(
            key_name="Config.termination_protection",
            expected_type=bool,
            required=False,
            default=True,
        ),
    )
    app.synth()
