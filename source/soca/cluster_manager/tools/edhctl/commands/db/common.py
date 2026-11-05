# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for edhctl db commands."""

import logging
import sys
from contextlib import contextmanager

import click
import psycopg

import utils.aws.boto3_wrapper as utils_boto3
from commands.common import get_cluster_id, is_controller_instance
from utils.aws.secretsmanager_client import SocaSecret
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


def _get_boto_client(service_name: str) -> SocaResponse:
    """Return a boto3 client wrapped in SocaResponse. Region is resolved by the wrapper."""
    _response = utils_boto3.get_boto(service_name=service_name)
    if _response.get("success") is False:
        logger.error(f"Failed to get boto3 client for {service_name}")
        return SocaError.AWS_API_ERROR(
            service_name=service_name,
            helper=f"Unable to create boto3 client for {service_name}: {_response.get('message')}",
        )
    return SocaResponse(success=True, message=_response.get("message"))


def get_rds_client() -> SocaResponse:
    """Return a boto3 RDS client wrapped in SocaResponse."""
    return _get_boto_client(service_name="rds")


def get_cloudwatch_client() -> SocaResponse:
    """Return a boto3 CloudWatch client wrapped in SocaResponse."""
    return _get_boto_client(service_name="cloudwatch")


def _resolve_client(response: SocaResponse):
    """Unwrap a SocaResponse client or abort the CLI with the error message."""
    if response.get("success") is False:
        click.echo(f"Error: {response.get('message')}", err=True)
        sys.exit(1)
    return response.get("message")


def get_db_secret() -> SocaResponse:
    """Fetch DB admin credentials from Secrets Manager."""
    _secret = SocaSecret(secret_id="DatabaseAdminSecret").get_secret()
    if _secret.get("success") is False:
        logger.error(f"Unable to retrieve DatabaseAdminSecret: {_secret.get('message')}")
    return _secret


@contextmanager
def db_connection():
    """Context manager yielding an open psycopg connection to the cluster DB."""
    if not is_controller_instance():
        click.echo("Error: edhctl db commands must run on the controller.", err=True)
        sys.exit(1)

    _secret = get_db_secret()
    if _secret.get("success") is False:
        click.echo(f"Error: {_secret.get('message')}", err=True)
        sys.exit(1)

    _creds = _secret.get("message")
    try:
        # kwargs (not a DSN string) so psycopg escapes values containing spaces or quotes
        _conn = psycopg.connect(
            host=_creds.get("host"),
            port=_creds.get("port"),
            dbname=_creds.get("dbname"),
            user=_creds.get("username"),
            password=_creds.get("password"),
            sslmode="require",
        )
    except Exception as err:
        logger.error(f"Unable to connect to the cluster database: {err}")
        click.echo(f"Error: unable to connect to the cluster database: {err}", err=True)
        sys.exit(1)

    try:
        yield _conn
    finally:
        _conn.close()


def get_db_cluster_identifier() -> SocaResponse:
    """Resolve the Aurora cluster identifier via the edh:ClusterId tag."""
    _cluster_id = get_cluster_id()
    _rds = _resolve_client(get_rds_client())
    _matches = []
    try:
        # paginate: describe_db_clusters caps at 100 per page and the tagged
        # cluster may sit on a later page in a busy account
        _paginator = _rds.get_paginator("describe_db_clusters")
        for _page in _paginator.paginate():
            for _cluster in _page.get("DBClusters", []):
                _tags = {t.get("Key"): t.get("Value") for t in _cluster.get("TagList", [])}
                if _tags.get("edh:ClusterId") == _cluster_id:
                    _matches.append(
                        {
                            "identifier": _cluster.get("DBClusterIdentifier"),
                            "restored_from": _tags.get("edh:RestoredFrom"),
                        }
                    )
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="rds",
            helper=f"Failed to describe DB clusters: {err}",
        )

    if Validators.is_list_not_empty(_matches):
        _conventional = f"{_cluster_id}-aurorapg"
        # a PITR restore can leave a second tagged cluster behind; never let a
        # clone shadow the cluster this controller actually runs against
        for _match in _matches:
            if _match.get("identifier") == _conventional:
                return SocaResponse(success=True, message=_conventional)

        _originals = [m for m in _matches if m.get("restored_from") is None]
        if Validators.is_list_length_greater_than(_matches, 1):
            logger.warning(
                f"Multiple RDS clusters carry edh:ClusterId={_cluster_id}: "
                f"{[m.get('identifier') for m in _matches]}"
            )
        _chosen = (_originals or _matches)[0]
        return SocaResponse(success=True, message=_chosen.get("identifier"))

    # Fall back to the naming convention when the cluster is untagged
    logger.warning(
        f"No RDS cluster tagged edh:ClusterId={_cluster_id} across all pages, "
        f"falling back to the naming convention"
    )
    return SocaResponse(success=True, message=f"{_cluster_id}-aurorapg")


def _resolve_db_cluster_identifier() -> str:
    """Unwrap the cluster identifier or abort the CLI with the error message."""
    _response = get_db_cluster_identifier()
    if _response.get("success") is False:
        click.echo(f"Error: {_response.get('message')}", err=True)
        sys.exit(1)
    return _response.get("message")


def _format_bytes(n: int) -> str:
    """Human-readable byte size. Internal formatting helper."""
    if n >= 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024 / 1024:.1f} GB"
    elif n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    elif n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _echo_json(data) -> None:
    """Serialize a payload to JSON via SocaCastEngine and echo it."""
    _serialized = SocaCastEngine(data).serialize_json(indent=2)
    if _serialized.get("success") is False:
        click.echo(f"Error: {_serialized.get('message')}", err=True)
        sys.exit(1)
    click.echo(_serialized.get("message"))


def _cast_str(value) -> str:
    """Safely cast a value to str via SocaCastEngine, empty string on failure."""
    _cast = SocaCastEngine(value).cast_as(str)
    return _cast.get("message") if _cast.get("success") else ""
