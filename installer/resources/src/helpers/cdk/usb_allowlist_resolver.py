# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
USB Allowlist Resolver -- CDK wiring (Hardware Profile feature)

Builds the boot-time resolver Lambda that a VDI calls, SigV4-signed with its
instance role, to fetch its effective USB device allowlist as rendered DCV
usb-devices.conf filter lines.

Invoked from cdk_construct.py after the database, VPC, and vdi_node_role exist.
"""

import logging

from aws_cdk import Duration
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda
from aws_cdk import aws_ssm as ssm

from helpers import security_groups as security_groups_helper
from helpers.cdk.edh_internal_api import (
    add_iam_lambda_route,
    get_or_create_internal_api,
)

logger = logging.getLogger("soca_logger")

FUNCTIONS_DIR = "../functions"  # asset path convention (from installer/resources/src)


def build_usb_allowlist_resolver(
    scope,
    cluster_id: str,
    database_name: str,
    get_lambda_runtime_version,
    get_config_key=None,
):
    """Create the USB allowlist resolver Lambda + IAM Function URL.

    Args:
        scope: the SOCAInstall construct (exposes soca_resources + generate_log_group).
        cluster_id: EDH cluster id (for resource/SSM naming).
        database_name: Aurora default database name (Config.database.*.database_name).
        get_lambda_runtime_version: shared runtime helper (keeps the fleet on one version).

    Returns:
        The created aws_lambda.Function.
    """
    vpc = scope.soca_resources["vpc"]
    database = scope.soca_resources["database"]
    database_secret = scope.soca_resources["database_secret"]
    database_sg = scope.soca_resources["database_sg"]
    vdi_node_role = scope.soca_resources["vdi_node_role"]

    # ---------- Lambda security group (egress to Aurora + AWS endpoints) ----------
    resolver_sg = ec2.SecurityGroup(
        scope,
        f"{cluster_id}-UsbAllowlistResolverSG",
        vpc=vpc,
        description="USB allowlist resolver Lambda -- egress to Aurora + Secrets Manager/KMS",
        allow_all_outbound=True,
    )
    # Aurora accepts the resolver on the Postgres port.
    security_groups_helper.create_ingress_rule(
        security_group=database_sg,
        peer=resolver_sg,
        connection=ec2.Port.tcp(database.cluster_endpoint.port),
        description="USB allowlist resolver Lambda (read-only) to Aurora",
    )

    # ---------- Execution role ----------
    resolver_role = iam.Role(
        scope,
        f"{cluster_id}-UsbAllowlistResolverRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        description="USB allowlist resolver Lambda execution role (read-only DB + secret)",
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            ),
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
    )
    # secretsmanager:GetSecretValue + kms:Decrypt on the secret's CMK.
    database_secret.grant_read(resolver_role)

    # ---------- Resolver Lambda (in-VPC) ----------
    # psycopg (compiled libpq) is provided by the shared PsycopgLayer built in
    # cdk_construct.py -- the asset dir carries only the handler. The layer is
    # x86_64 manylinux, so the function MUST pin architecture=X86_64 to match.
    _psycopg_layer = scope.soca_resources.get("psycopg_layer")
    resolver_lambda = aws_lambda.Function(
        scope,
        f"{cluster_id}-UsbAllowlistResolver",
        function_name=f"{cluster_id}-UsbAllowlistResolver",
        description="Boot-time USB device allowlist resolver (attested instance-id -> usb-devices.conf)",
        runtime=get_lambda_runtime_version(),
        architecture=aws_lambda.Architecture.X86_64,
        handler="UsbAllowlistResolver.handler",
        code=aws_lambda.Code.from_asset(f"{FUNCTIONS_DIR}/UsbAllowlistResolver"),
        layers=[_l for _l in [_psycopg_layer, scope.soca_resources.get("boto3_layer")] if _l] or None,
        timeout=Duration.seconds(30),
        memory_size=256,
        log_group=scope.generate_log_group(name="UsbAllowlistResolverLambda"),
        role=resolver_role,
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        security_groups=[resolver_sg],
        environment={
            "DB_HOST": database.cluster_read_endpoint.hostname,
            "DB_PORT": str(database.cluster_endpoint.port),
            "DB_NAME": database_name,
            "DB_SECRET_ARN": database_secret.secret_arn,
            # Roles allowed to resolve an EXPLICIT target instance (API/CLI
            # preview). The controller plane only -- VDIs remain attested-only.
            "TRUSTED_RESOLVER_ROLES": scope.soca_resources["controller_role"].role_name,
        },
        retry_attempts=0,
    )

    _internal_api = get_or_create_internal_api(
        scope, cluster_id, get_config_key=get_config_key
    )
    _route_path = add_iam_lambda_route(
        scope,
        cluster_id=cluster_id,
        api=_internal_api,
        route_key="ANY /v1/dcv/usb-allowlist",
        handler=resolver_lambda,
        invoker_roles=[vdi_node_role, scope.soca_resources["controller_role"]],
        construct_prefix="UsbAllowlist",
    )
    _resolver_url = f"{_internal_api.attr_api_endpoint}{_route_path}"

    # Publish the URL so the VDI boot hook can read it (SSM, per-cluster path).
    ssm.StringParameter(
        scope,
        f"{cluster_id}-UsbAllowlistResolverUrlParam",
        parameter_name=f"/edh/{cluster_id}/configuration/UsbAllowlistResolverUrl",
        string_value=_resolver_url,
        description="HTTP API route the VDI boot hook calls to fetch its USB allowlist",
    )

    scope.soca_resources["usb_allowlist_resolver_lambda"] = resolver_lambda
    logger.debug("USB allowlist resolver Lambda + internal HTTP API route configured")
    return resolver_lambda
