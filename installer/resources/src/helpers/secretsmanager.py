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

from aws_cdk import (
    aws_secretsmanager as secretsmanager,
    aws_kms as kms,
)
import ast
from constructs import Construct

def create_secret(
    scope: Construct,
    construct_id: str,
    secret_name: str,
    secret_string_template: str,
    exclude_characters: str = "!\"#$%&'()*+,-./\\:;<=>?@[]^_`{|}~",
    exclude_punctuation: bool = True,
    exclude_numbers: bool = False,
    exclude_lowercase: bool = False,
    exclude_uppercase: bool = False,
    require_each_included_type: bool = True,
    password_length: int = 20,
    include_space: bool = False,
    kms_key_id: kms.IKey = None,
) -> secretsmanager.Secret:
    return secretsmanager.Secret(
        scope=scope,
        id=construct_id,
        secret_name=secret_name,
        generate_secret_string=secretsmanager.SecretStringGenerator(
            exclude_characters=exclude_characters,
            exclude_numbers=exclude_numbers,
            exclude_punctuation=exclude_punctuation,
            exclude_lowercase=exclude_lowercase,
            exclude_uppercase=exclude_uppercase,
            require_each_included_type=require_each_included_type,
            include_space=include_space,
            secret_string_template=secret_string_template,
            password_length=password_length,
            generate_string_key="password",
        ),
        encryption_key=kms_key_id if kms_key_id else None,
    )


def resolve_secret_as_str(
    secret_construct: Construct, password_key: str = "password"
) -> str:
    return secret_construct.secret_value_from_json(password_key).to_string()


def retrieve_secret_value(secret_id: str, region_name: str) -> dict:
    # Route through shared-session cache; see helpers.boto3_wrapper.
    from helpers.boto3_wrapper import get_shared_session
    _sm_client = get_shared_session().client("secretsmanager", region_name=region_name)
    _get_secret = _sm_client.get_secret_value(SecretId=secret_id).get(
        "SecretString", None
    )
    if _get_secret:
        return ast.literal_eval(_get_secret)
    else:
        return {}
