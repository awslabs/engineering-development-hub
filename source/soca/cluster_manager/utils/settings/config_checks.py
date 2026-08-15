# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import ast
import re
from utils.response import SocaResponse
from utils.error import SocaError
from typing import Any
from utils.aws.boto3_wrapper import get_boto
from botocore.exceptions import ClientError
import os
import yaml
import logging

logger = logging.getLogger("soca_logger")


class SocaConfigKeyVerifier:
    _IMMUTABLE_KEYS = [
        "/configuration/AWSAccountId",
        "/configuration/ClusterId",
        "/configuration/Region",
        "/packages/controller",
        "/packages/dcv_amazonlinux",
        "/packages/openldap_server",
        "/packages/sssd",
        "/packages/system",
    ]

    _SPECIAL_VALIDATION_TESTS = [
        "list_of_strings",
        "list_of_int",
        "valid_iam_role",
        "valid_s3_bucket",
        "valid_ssh_keypair",
        "list_of_ec2_instances",
        "list_of_ec2_subnet_ids",
        "validate_feature_flags",
        "validate_custom_tags",
        "validate_schedulers",
        "validate_hooks",
    ]

    _KEY_CONFIG_FILE = f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID')}/cluster_manager/utils/settings/socaconfig_key_validator.yml"

    def __init__(self, key: str):
        self.key = key

    @staticmethod
    def get_validation_test(schema: dict, keys: list):
        for key in keys:
            schema = schema.get(key)
            if schema is None:
                return None
        return schema

    def check(self, value: Any):
        # Note: All SSM are stored as str, however we just validate if the string value can be cast as expected type
        # ex: "['subnet-1', 'subnet-2', 'subnet-3']" -> Stored on SSM as String but retrieved on SOCA as list
        if not isinstance(value, str):
            value = str(value)

        if not self.key.startswith("/"):
            key = f"/{self.key}"
        else:
            key = self.key

        if key in SocaConfigKeyVerifier._IMMUTABLE_KEYS:
            return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                helper=f"{key} is immutable, you cannot change its value"
            )

        logger.info(
            f"Reading SocaConfig key checkers {SocaConfigKeyVerifier._KEY_CONFIG_FILE}"
        )

        try:
            with open(SocaConfigKeyVerifier._KEY_CONFIG_FILE, "r") as file:
                try:
                    _schema = yaml.safe_load(file)
                except yaml.YAMLError as e:
                    return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                        helper=f"Error parsing YAML file {SocaConfigKeyVerifier._KEY_CONFIG_FILE} because of  {e}"
                    )
        except Exception as err:
            return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                helper=f"Unable to access YAML config file {SocaConfigKeyVerifier._KEY_CONFIG_FILE} due to {err}"
            )
        # /configuration/FileSystems tree has an extra unique UUID (fs name)
        # e.g /configuration/FileSystems/mycustompath/provider
        # We remove `mycustompath` as this is customer supplier and validate the key /configuration/FileSystems/provider
        if "/configuration/FileSystems/" in key:
            _key = key.split("/configuration/FileSystems/")[1]
            key = f"/configuration/FileSystems/{'/'.join(_key.split('/')[1:])}"

        # key uses this type of format /job/BaseOS, but yaml db is dict {"configuration": { "BaseOS": ... } }
        # we flatten the key e.g: ["configuration","BaseOS"] then parse the dictionary tree
        _validation_test = self.get_validation_test(
            _schema, [item for item in key.split("/") if item]
        )

        # CustomTags are unique to each customer, so we cannot pre-populate socaconfig_key_validator.yml in advance
        if "/configuration/CustomTags/" in key:
            _validation_test = "validate_custom_tags"

        if "/configuration/HPC/schedulers/" in key:
            _validation_test = "validate_schedulers"

        if "/configuration/HPC/hooks/" in key:
            _validation_test = "validate_hooks"

        logger.debug(f"Detected Validation Test for {key} -> {_validation_test}")
        if _validation_test is None:
            return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                helper=f"{key} does not exist in util.config_checks"
            )
        else:
            if _validation_test in SocaConfigKeyVerifier._SPECIAL_VALIDATION_TESTS:
                if _validation_test == "list_of_strings":
                    _result = self.verify_list_of_type(
                        value=value, list_item_type="str", item_pattern=None
                    )
                elif _validation_test == "list_of_int":
                    _result = self.verify_list_of_type(
                        value=value, list_item_type="int"
                    )
                elif _validation_test == "valid_iam_role":
                    _result = self.valid_iam_role(role_name=value)

                elif _validation_test == "valid_s3_bucket":
                    _result = self.valid_s3_bucket(bucket_name=value)

                elif _validation_test == "valid_ssh_keypair":
                    _result = self.valid_ssh_keypair(key_name=value)

                elif _validation_test == "valid_ssh_keypair":
                    _result = self.valid_ssh_keypair(key_name=value)

                elif _validation_test == "validate_feature_flags":
                    _result = self.validate_feature_flags(flag_value=value)

                elif _validation_test == "validate_custom_tags":
                    _result = self.validate_custom_tags(flag_value=value)

                elif _validation_test == "validate_schedulers":
                    _result = self.validate_schedulers(flag_value=value)

                elif _validation_test == "validate_hooks":
                    _result = self.validate_hooks(flag_value=value)

                elif _validation_test == "list_of_ec2_subnet_ids":
                    _list_of_subnets = ast.literal_eval(value)
                    if not isinstance(_list_of_subnets, list):
                        _result = SocaError.SOCA_CONFIG_KEY_VERIFIER(
                            helper=f"{value} is not a list"
                        )
                    else:
                        _result = self.valid_subnet_id(subnet_ids=_list_of_subnets)
            else:
                _result = self.verify_regex(value=value, regex_pattern=_validation_test)

            if _result is True:
                return SocaResponse(success=True, message="")
            else:
                return SocaResponse(success=False, message=_result)

    @staticmethod
    def validate_hooks(flag_value: str):
        try:
            bool(flag_value)
            return True
        except Exception as err:
            return f"{flag_value} must be a boolean"

    @staticmethod
    def validate_schedulers(flag_value: str):
        try:
            _flag_value = ast.literal_eval(flag_value)
        except Exception as err:
            return f"{flag_value} invalid syntax."

        _required_keys = [
            "enabled",
            "provider",
            "endpoint",
            "soca_managed_nodes_provisioning",
            "identifier",
        ]

        _lsf_configuration_keys = ["version", "lsf_top"]
        _pbs_configuration_keys = ["pbs_exec", "pbs_home"]
        _slurm_configuration_keys = ["install_prefix_path", "install_sysconfig_path"]

        if not isinstance(_flag_value, dict):
            return f"{_flag_value} does not seems to be a valid dictionary"
        else:

            for key in _required_keys:
                if _flag_value.get(key, None) is None:
                    return f"{key} is missing or empty"

            if str(_flag_value.get("enabled")).lower() not in ["true", "false"]:
                return "enabled value is not a boolean, must be either True or False"

            if _flag_value.get("provider").lower() not in ["slurm", "lsf", "openpbs"]:
                return "provider value is not a valid scheduler, must be either slurm, openpbs or lsf"

            if "lsf_configuration" in _flag_value.keys():
                if isinstance(_flag_value.get("lsf_configuration"), dict):
                    _lsf_configuration_as_dict = _flag_value.get("lsf_configuration")
                else:
                    try:
                        _lsf_configuration_as_dict = ast.literal_eval(
                            _flag_value.get("lsf_configuration")
                        )
                        if not isinstance(_lsf_configuration_as_dict, dict):
                            return "lsf_configuration is not a valid dictionary"
                    except Exception as err:
                        return f"Unable to cast lsf_configuration as valid a valid dictionary due to {err}"
                for _k in _lsf_configuration_keys:
                    if _lsf_configuration_as_dict.get(_k, None) is None:
                        return f"lsf_configuration.{_k} is missing or empty"

            if "pbs_configuration" in _flag_value.keys():
                if isinstance(_flag_value.get("pbs_configuration"), dict):
                    _pbs_configuration_as_dict = _flag_value.get("pbs_configuration")
                else:
                    try:
                        _pbs_configuration_as_dict = ast.literal_eval(
                            _flag_value.get("pbs_configuration")
                        )
                        if not isinstance(_pbs_configuration_as_dict, dict):
                            return "pbs_configuration is not a valid dictionary"
                    except Exception as err:
                        return f"Unable to cast pbs_configuration as valid a valid dictionary due to {err}"

                for _k in _pbs_configuration_keys:
                    if _pbs_configuration_as_dict.get(_k, None) is None:
                        return f"pbs_configuration.{_k} is missing or empty"

            if "slurm_configuration" in _flag_value.keys():
                if isinstance(_flag_value.get("slurm_configuration"), dict):
                    _slurm_configuration_as_dict = _flag_value.get(
                        "slurm_configuration"
                    )
                else:
                    try:
                        _slurm_configuration_as_dict = ast.literal_eval(
                            _flag_value.get("slurm_configuration")
                        )
                        if not isinstance(_slurm_configuration_as_dict, dict):
                            return "slurm_configuration is not a valid dictionary"
                    except Exception as err:
                        return f"Unable to cast slurm_configuration as valid a valid dictionary due to {err}"
                for _k in _slurm_configuration_keys:
                    if _slurm_configuration_as_dict.get(_k, None) is None:
                        return f"slurm_configuration.{_k} is missing or empty"

        return True

    @staticmethod
    def validate_custom_tags(flag_value: str):
        try:
            _flag_value = ast.literal_eval(flag_value)
        except Exception as err:
            return f"{flag_value} invalid syntax. Enabled must be bool, Key/Value must be a str"

        if not isinstance(_flag_value, dict):
            return f"{_flag_value} does not seems to be a valid dictionary"

        else:
            if not "Enabled" in _flag_value.keys():
                return f"Enabled key is missing in {_flag_value}"
            else:
                if str(_flag_value.get("Enabled")).lower() not in ["true", "false"]:
                    return (
                        f"Enabled value is not a boolean, must be either True or False"
                    )

            if "Key" not in _flag_value.keys():
                return f"Key is missing in {_flag_value}"
            else:
                if not isinstance(_flag_value.get("Key"), str):
                    return f"Key is not a str"
                else:
                    if (
                        _flag_value.get("Key").startswith("edh:")
                        or _flag_value.get("Key").startswith("aws:")
                        or _flag_value.get("Key") == "Name"
                    ):
                        return f"Key cannot start with edh: or aws: or be 'Name'"

            if "Value" not in _flag_value.keys():
                return f"Value is missing in {_flag_value}"
            else:
                if not isinstance(_flag_value.get("Value"), str):
                    return f"Value value is not a str"

            return True

    @staticmethod
    def validate_feature_flags(flag_value: str):
        try:
            _flag_value = ast.literal_eval(flag_value)
        except Exception as err:
            return f"{flag_value} invalid syntax. Enabled must be bool, allowed/denied_users must be a list of str"

        if not isinstance(_flag_value, dict):
            return f"{_flag_value} does not seems to be a valid dictionary"

        else:
            if not "enabled" in _flag_value.keys():
                return f"enabled key is missing in {_flag_value}"
            else:
                if str(_flag_value.get("enabled")).lower() not in ["true", "false"]:
                    return (
                        f"enabled value is not a boolean, must be either True or False"
                    )

            if "allowed_users" not in _flag_value.keys():
                return f"allowed_users key is missing in {_flag_value}"
            else:
                if not isinstance(_flag_value.get("allowed_users"), list):
                    return f"allowed_users value is not a list"
                else:
                    for item in _flag_value.get("allowed_users"):
                        if not isinstance(item, str):
                            return (
                                f"allowed_users must be a list of string {_flag_value}"
                            )

            if "denied_users" not in _flag_value.keys():
                return f"denied_users key is missing in {_flag_value}"
            else:
                if not isinstance(_flag_value.get("denied_users"), list):
                    return f"denied_users value is not a list"
                else:
                    for item in _flag_value.get("denied_users"):
                        if not isinstance(item, str):
                            return (
                                f"denied_users must be a list of string {_flag_value}"
                            )
            return True

    @staticmethod
    def valid_subnet_id(subnet_ids: list) -> [bool, str]:
        _ec2_client = get_boto(service_name="ec2").message
        try:
            _ec2_client.describe_subnets(SubnetIds=subnet_ids)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidSubnetID.NotFound":
                return f"One or more subnets in {subnet_ids} do not exist"
            else:
                return f"Unable to verify {subnet_ids} because of {e}"

    @staticmethod
    def valid_s3_bucket(bucket_name: str) -> [bool, str]:
        _s3_client = get_boto(service_name="s3").message
        try:
            _s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return f"{bucket_name} does not exist"
            else:
                return f"Unable to verify {bucket_name} because of {e}"

    @staticmethod
    def valid_ssh_keypair(key_name):
        _ec2_client = get_boto(service_name="ec2").message

        try:
            _ec2_client.describe_key_pairs(KeyNames=[key_name])
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidKeyPair.NotFound":
                return f"{key_name} does not seem to exist in the region"
            else:
                return f"Unable to verify {key_name} because of {e}"

    @staticmethod
    def valid_iam_role(role_name: str) -> [bool, str]:
        _iam_client = get_boto(service_name="iam").message
        try:
            _iam_client.get_role(RoleName=role_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return "IAM role does not exist"
            else:
                return f"Unable to check IAM role due to {e}"

    @staticmethod
    def verify_list_of_type(
        value: str, list_item_type: str, item_pattern: str = None
    ) -> [bool, str]:
        _allowed_item_type = ["str", "int", "float", "dict", "list"]

        if list_item_type not in _allowed_item_type:
            return f"list_item_type must be {' '.join(_allowed_item_type)}"

        if item_pattern and list_item_type != "str":
            return "item_pattern can only be set if list_item_type is set to str"

        if not isinstance(value, list):
            try:
                value = ast.literal_eval(value)
            except Exception as err:
                logger.error(f"Unable to cast {value} as a list due to {err}")
                return False

        if list_item_type == "str":
            if item_pattern:
                if all(
                    isinstance(item, str) and re.match(item_pattern, item)
                    for item in value
                ):
                    return True
                else:
                    return f"One or more items in the list do not match the pattern {item_pattern}"
            else:
                if all(isinstance(item, str) for item in value):
                    return True
                else:
                    return f"One or more items in the list are not strings"

        elif list_item_type == "int":
            if all(isinstance(item, int) for item in value):
                return True
            else:
                return f"One or more items in the list are not integers"

        elif list_item_type == "float":
            if all(isinstance(item, float) for item in value):
                return True
            else:
                return f"One or more items in the list are not floats"

        elif list_item_type == "dict":
            if all(isinstance(item, dict) for item in value):
                return True
            else:
                return f"One or more items in the list are not dictionaries"

        elif list_item_type == "list":
            if all(isinstance(item, list) for item in value):
                return True
            else:
                return f"One or more items in the list are not lists"
        else:
            return f"Unsupported list_item_type: {list_item_type}"

    @staticmethod
    def verify_regex(value: str, regex_pattern: str) -> [bool, str]:
        if re.match(regex_pattern, value):
            return True
        else:
            return f"Verify regex: {value} is does not match {regex_pattern}"
