# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse


client_fsx = utils_boto3.get_boto(service_name="fsx").message

logger = logging.getLogger("soca_logger")


def describe_file_systems(
    filesystem_ids: list,
) -> SocaResponse:
    logger.info(f"Running describe_file_systems with {filesystem_ids=}")
    try:
        _describe_filesystem = client_fsx.describe_file_systems(
            FileSystemIds=filesystem_ids
        )
        logger.debug(f"describe_filesystem Results: {_describe_filesystem}")
        return SocaResponse(success=True, message=_describe_filesystem)
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run _describe_filesystem because of {err}"
        )
