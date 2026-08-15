# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Admin endpoints for the BootstrapTemplateCache.

Provides:
  - GET  /api/admin/bootstrap_cache         -- summary (config + entry count)
  - POST /api/admin/bootstrap_cache/refresh -- delete every cache marker;
                                               next create-of-each-stack
                                               re-renders the bundle.

Both require admin (the @admin_api decorator). The endpoints are
read-only against AWS until the explicit POST. Surfaced in the admin
status page UI as a "Refresh bootstrap cache" button (see
templates/admin/cluster_status/dcv_overview.html).

Why an explicit refresh button: the cache is content-addressable and
TTL-safety-netted, so it should NEVER be functionally wrong. But when
operators are debugging weird VDI bootstrap behavior, a one-click
"force everything to re-render" is a paved-path escape hatch that
beats SSH-into-controller-and-delete-S3-objects.
"""

import logging
import os

from flask_restful import Resource

from decorators import admin_api
from utils.bootstrap_cache import BootstrapCache
from utils.config import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")


def _make_cache() -> BootstrapCache:
    """Build a BootstrapCache wired to this cluster's bucket+prefix."""
    cluster_id = os.environ.get("EDH_CLUSTER_ID", "")
    bucket_resp = SocaConfig(key="/configuration/S3Bucket").get_value()
    bucket = bucket_resp.message if bucket_resp.success else ""
    if not (cluster_id and bucket):
        raise RuntimeError(
            f"Cannot resolve cluster bucket: cluster_id={cluster_id!r} "
            f"bucket={bucket!r}"
        )
    s3 = utils_boto3.get_boto(service_name="s3").message
    return BootstrapCache(
        s3_client=s3,
        bucket=bucket,
        prefix=f"{cluster_id}/bootstrap/cache",
        # Refresh / list operations are not gated on the feature flag.
        # Operators may want to inspect/clean the cache even when the
        # feature is disabled (e.g. during rollback).
        enabled=True,
    )


def get_cache_summary() -> SocaResponse:
    """Return the cache status summary as a SocaResponse / SocaError.

    Shared by the header-authed API Resource (BootstrapCacheStatus) and the
    session-authed admin view route (views/admin/cluster_status/dcv_overview),
    so the browser page and API clients return identical data. AWS/config
    errors are handled here and surfaced as SocaError rather than propagated.
    """
    try:
        return SocaResponse(success=True, message=_build_cache_summary())
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to read BootstrapCache: %s", exc)
        return SocaError.GENERIC_ERROR(helper=f"BootstrapCache unavailable: {exc}")


def _build_cache_summary() -> dict:
    """Build the cache status summary (config flags + marker entries)."""
    cache = _make_cache()

    # Config flags so the UI can show the operator the current configuration
    # alongside the cache state.
    enabled = (
        SocaConfig(key="/configuration/feature_flags/BootstrapTemplateCache/enabled")
        .get_value(default=True, allow_unknown_key=True, return_as=bool)
        .get("message", True)
    )
    ttl_minutes = (
        SocaConfig(key="/configuration/feature_flags/BootstrapTemplateCache/ttl_minutes")
        .get_value(default=120, allow_unknown_key=True, return_as=int)
        .get("message", 120)
    )
    cleanup_retention_days = (
        SocaConfig(key="/configuration/feature_flags/BootstrapTemplateCache/cleanup_retention_days")
        .get_value(default=30, allow_unknown_key=True, return_as=int)
        .get("message", 30)
    )

    # Count entries by listing markers under the prefix. Cheap.
    entries = []
    entry_count = 0
    paginator = cache._s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=cache._bucket, Prefix=f"{cache._prefix}/"):
        for obj in page.get("Contents") or []:
            if obj["Key"].endswith(f"/{BootstrapCache.MARKER_NAME}"):
                entries.append(
                    {
                        "key": obj["Key"],
                        "last_modified": obj["LastModified"].isoformat(),
                        "size": obj["Size"],
                    }
                )
                entry_count += 1

    return {
        "enabled": enabled,
        "ttl_minutes": ttl_minutes,
        "cleanup_retention_days": cleanup_retention_days,
        "bucket": cache._bucket,
        "prefix": cache._prefix,
        "entry_count": entry_count,
        "entries": entries,
    }


def refresh_cache() -> SocaResponse:
    """Delete every cache marker so the next create-of-each-stack re-renders.

    Shared by the API Resource (BootstrapCacheRefresh) and the session-authed
    admin view route. AWS errors are handled here and surfaced as SocaError.
    """
    try:
        cache = _make_cache()
        deleted = cache.refresh_all()
        logger.info("BootstrapCache.refresh_all: %d markers deleted by admin", deleted)
        return SocaResponse(
            success=True,
            message={
                "markers_deleted": deleted,
                "bucket": cache._bucket,
                "prefix": cache._prefix,
            },
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("BootstrapCache.refresh_all failed: %s", exc)
        return SocaError.GENERIC_ERROR(helper=f"BootstrapCache refresh failed: {exc}")


class BootstrapCacheStatus(Resource):
    """GET /api/admin/bootstrap_cache -- summary of cache state."""

    @admin_api
    def get(self):
        r"""
        Get bootstrap template cache status summary
        ---
        openapi: 3.1.0
        operationId: getBootstrapCacheStatus
        tags:
          - Admin
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
        responses:
          '200':
            description: Cache status summary including config flags and entry list
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      properties:
                        enabled:
                          type: boolean
                        ttl_minutes:
                          type: integer
                        cleanup_retention_days:
                          type: integer
                        bucket:
                          type: string
                        prefix:
                          type: string
                        entry_count:
                          type: integer
                        entries:
                          type: array
                          items:
                            type: object
                            properties:
                              key:
                                type: string
                              last_modified:
                                type: string
                                format: date-time
                              size:
                                type: integer
          '401':
            description: Authentication required or not an admin
          '500':
            description: Failed to read bootstrap cache state
        """
        return get_cache_summary().as_flask()


class BootstrapCacheRefresh(Resource):
    """POST /api/admin/bootstrap_cache/refresh -- delete all markers
    so next create-of-each-stack re-renders the bundle.
    """

    @admin_api
    def post(self):
        r"""
        Refresh bootstrap template cache by deleting all markers
        ---
        openapi: 3.1.0
        operationId: refreshBootstrapCache
        tags:
          - Admin
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
        responses:
          '200':
            description: Cache markers deleted successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      properties:
                        markers_deleted:
                          type: integer
                        bucket:
                          type: string
                        prefix:
                          type: string
          '401':
            description: Authentication required or not an admin
          '500':
            description: Cache refresh operation failed
        """
        return refresh_cache().as_flask()
