# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import json
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from typing import Optional

logger = logging.getLogger("soca_logger")


class SocaSecret:
    def __init__(
        self,
        secret_id: str,
        secret_id_prefix: Optional[
            str
        ] = f"/edh/{os.environ.get('EDH_CLUSTER_ID')}/",
        version_stage: str = "AWSCURRENT", # AWS Managed: AWSCURRENT, AWSPREVIOUS, AWSPENDING. Also accepts customers specific stage name
        version_id: Optional[str] = None,
        as_json: bool = True,

    ):
        self._secret_id = f"{secret_id_prefix}{secret_id}"
        self._version_stage = version_stage
        self._version_id = version_id
        self._as_json = as_json

    def get_secret(self) -> SocaResponse:
        logger.debug(f"Retrieving secret {self._secret_id} from secretsmanager ")
        _sm_client = utils_boto3.get_boto(service_name="secretsmanager").message
        try:
            _params = {"SecretId": self._secret_id}
            if self._version_id:
                _params["VersionId"] = self._version_id
            if self._version_stage:
                _params["VersionStage"] = self._version_stage
            _fetch_secret = _sm_client.get_secret_value(**_params)
            
            if _fetch_secret.get("SecretString", None) is None:
                return SocaError.AWS_API_ERROR(
                    service_name="secretsmanager",
                    helper=f" SecretId {self._secret_id}  (version stage {self._version_stage}, version id {self._version_id}) exists but is empty",
                )
            else:
                if self._as_json is False:
                    # Raw (non-JSON) secret -- e.g. cryptographic key material stored as a plain string.
                    return SocaResponse(success=True, message=_fetch_secret.get("SecretString"))
                try:
                    _secret_string = json.loads(_fetch_secret.get("SecretString"))
                    logger.debug(
                        f"SecretString for Secret {self._secret_id} retrieved successfully"
                    )
                    return SocaResponse(success=True, message=_secret_string)
                except Exception as e:
                    return SocaError.AWS_API_ERROR(
                        service_name="secretsmanager",
                        helper=f"SecretString (version stage {self._version_stage}, version id {self._version_id}) returned but unable to load as json due to {e}",
                    )

        except _sm_client.exceptions.ResourceNotFoundException:
            return SocaError.AWS_API_ERROR(
                service_name="secretsmanager",
                helper=f"ResourceNotFoundException - SecretId {self._secret_id} does not exist",
            )

        except Exception as e:
            return SocaError.AWS_API_ERROR(
                service_name="secretsmanager",
                helper=f"Unknown error while trying to retrieve secret {self._secret_id}. Trace: {e}",
            )

    def get_version_stages(self) -> SocaResponse:
        """
        Return the set of staging labels currently attached to any version of
        this secret (e.g. {"AWSCURRENT", "AWSPREVIOUS", "AWSPENDING"}) via
        describe_secret.

        Lets a caller confirm an OPTIONAL stage exists BEFORE calling
        get_secret() for it. AWSPREVIOUS, for example, does not exist on a
        never-rotated secret; probing first avoids a spurious AWS_API_ERROR
        on the expected miss.
        """
        logger.debug(f"Describing staging labels for secret {self._secret_id}")
        _boto = utils_boto3.get_boto(service_name="secretsmanager")
        if _boto.get("success") is False:
            return SocaError.AWS_API_ERROR(
                service_name="secretsmanager",
                helper=f"Failed to get boto3 client while describing secret {self._secret_id}",
            )
        _sm_client = _boto.get("message")
        try:
            _meta = _sm_client.describe_secret(SecretId=self._secret_id)
            _stages = set()
            for _labels in _meta.get("VersionIdsToStages", {}).values():
                _stages.update(_labels)
            return SocaResponse(success=True, message=_stages)
        except _sm_client.exceptions.ResourceNotFoundException:
            return SocaError.AWS_API_ERROR(
                service_name="secretsmanager",
                helper=f"ResourceNotFoundException - SecretId {self._secret_id} does not exist",
            )
        except Exception as e:
            return SocaError.AWS_API_ERROR(
                service_name="secretsmanager",
                helper=f"Unknown error while describing secret {self._secret_id}. Trace: {e}",
            )
