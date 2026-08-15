# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Admin read-only status for owned-base AMI acceleration ("Local Acceleration Mirror").

Backs the admin status panel: returns the feature state + per-base registry rows
(status, source/owned ids, owner, deprecation, age, ref-count) for the cluster region.
"""

import logging

from flask import request
from flask_restful import Resource

from decorators import admin_api
from helpers.base_image_registry import list_status

logger = logging.getLogger("soca_logger")


class BaseImageStatusManager(Resource):
    @admin_api
    def get(self):
        """Owned-base AMI acceleration status (admin).
        ---
        openapi: 3.1.0
        operationId: getBaseImageAccelerationStatus
        tags:
          - Virtual Desktops
        summary: Local Acceleration Mirror status
        description: Feature state + per-base owned-copy registry rows for the cluster region (admin access required).
        responses:
          '200':
            description: Status payload
        """
        _region = request.args.get("region")
        return list_status(region=_region).as_flask()
