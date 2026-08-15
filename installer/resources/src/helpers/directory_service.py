#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import Aws, Fn, aws_directoryservice as ds, aws_iam as iam

import sys

from helpers import secretsmanager as secretsmanager_helper
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# AWS Directory Service (AD/Managed AD) provisioning. Extracted verbatim from cdk_construct.py.

logger = logging.getLogger("soca_logger")


def directory_service(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
):
    """
    Determine our desired directory service and create it.
    """

    logger.debug(
        f"Determining required directory service for {scope.directory_service_resource_setup.get('provider')}"
    )

    _ds_provider_for_cleaner = scope.directory_service_resource_setup.get("provider")

    if scope.directory_service_resource_setup.get("provider") in {
        "aws_ds_simple_activedirectory"
    }:
        logger.error(
            "AWS SimpleAD is no longer supported. Please update your configuration to use a supported Directory Service"
        )
        sys.exit(1)
        # return scope.directory_service_aws_simplead()

    elif scope.directory_service_resource_setup.get("provider") in {
        "aws_ds_managed_activedirectory"
    }:
        logger.debug("Creating AWS Manage AD Directory Service")
        scope.directory_service_aws_mad()

    elif (
        scope.directory_service_resource_setup.get("provider")
        == "existing_active_directory"
    ):
        logger.info(
            "Using existing Active Directory. Retrieving specified configuration"
        )
        scope.directory_service_resource_setup["domain_controller_ips"] = (
            get_config_key(
                key_name="Config.directoryservice.existing_active_directory.dc_ips",
                required=True,
                expected_type=list,
            )
        )

        logger.info("Retrieving specific AD Service Account User/Password")
        _ad_service_account_secret = get_config_key(
            key_name="Config.directoryservice.existing_active_directory.service_account_secret_name_arn",
            required=True,
            expected_type=str,
        )
        _ad_service_account_credentials = (
            secretsmanager_helper.retrieve_secret_value(
                secret_id=_ad_service_account_secret,
                region_name=user_specified_variables.region,
            )
        )
        scope.directory_service_resource_setup["ds_admin_username"] = (
            _ad_service_account_credentials.get("username", None)
        )
        scope.directory_service_resource_setup["ds_admin_password"] = (
            _ad_service_account_credentials.get("password", None)
        )

        if (
            scope.directory_service_resource_setup["ds_admin_username"] is None
            or scope.directory_service_resource_setup["ds_admin_password"] is None
        ):
            logger.fatal(
                f"Unable to retrieve username/password for the service account. Please check the secret provided on {_ad_service_account_secret}"
            )
            sys.exit(1)

    elif (
        scope.directory_service_resource_setup.get("provider") == "existing_openldap"
    ):
        logger.debug("Using existing OpenLDAP. SOCA won't create it.")

    elif scope.directory_service_resource_setup.get("provider") == "openldap":
        logger.debug(
            "Self-hosted OpenLDAP will be initialized with the controller instance."
        )
    else:
        logger.fatal(
            f"Unknown Directory Service provider: {scope.directory_service_resource_setup.get('provider')}"
        )
        sys.exit(1)

    # Register the AD-orphan cleanup pipeline AFTER the provider logic has
    # populated service_account_secret_arn (which may be a CDK token from a
    # just-created Secret). Registering before the provider runs would pass
    # None into the IAM policy resource list.


def directory_service_aws_mad(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
):
    """
    Deploy an AWS Manage AD Directory Service
    """
    logger.debug("Creating AWS MAD Directory Service in aws_mad_directory_service")

    if not user_specified_variables.vpc_id:
        launch_subnets = [
            scope.soca_resources["vpc"].private_subnets[0].subnet_id,
            scope.soca_resources["vpc"].private_subnets[1].subnet_id,
        ]
    else:
        launch_subnets = [
            user_specified_variables.private_subnets[0].split(",")[0],
            user_specified_variables.private_subnets[1].split(",")[0],
        ]

    # Create a new AWS Directory Service Managed AD
    _secret_name: str = (
        f"/edh/{user_specified_variables.cluster_id}/UserDirectoryServiceAccount"
    )
    scope.directory_service_resource_setup["ds_admin_username"] = (
        "Admin"  # Cannot be changed
    )

    scope.directory_service_resource_setup["ds_admin_password"] = (
        secretsmanager_helper.create_secret(
            scope=scope,
            construct_id="UserDirectoryDomainAdmin",
            secret_name=_secret_name,
            secret_string_template=(
                f'{{"username":"{scope.directory_service_resource_setup["ds_admin_username"]}'
                f'@{scope.directory_service_resource_setup.get("domain_name")}"}}'
            ),
            require_each_included_type=True,
            kms_key_id=(
                scope.soca_resources["secretsmanager_kms_key_id"]
                if scope.soca_resources["secretsmanager_kms_key_id"]
                else None
            ),
        )
    )
    scope.directory_service_resource_setup["service_account_secret_arn"] = (
        scope.directory_service_resource_setup["ds_admin_password"].secret_full_arn
    )
    scope.directory_service_resource_setup["ds"] = ds.CfnMicrosoftAD(
        scope,
        "DSManagedAD",
        name=scope.directory_service_resource_setup.get("domain_name"),
        edition=get_config_key(
            key_name="Config.directoryservice.activedirectory.edition",
            expected_type=str,
            required=False,
            default="Standard",
        ),
        short_name=scope.directory_service_resource_setup.get("short_name"),
        password=secretsmanager_helper.resolve_secret_as_str(
            secret_construct=scope.directory_service_resource_setup[
                "ds_admin_password"
            ]
        ),
        vpc_settings=ds.CfnMicrosoftAD.VpcSettingsProperty(
            subnet_ids=launch_subnets, vpc_id=scope.soca_resources["vpc"].vpc_id
        ),
    )

    scope.directory_service_resource_setup["ad_aws_directory_service_id"] = (
        scope.directory_service_resource_setup["ds"].ref
    )
    # Scope the controller's ds:ResetUserPassword to this cluster's directory
    # (the id only exists after the directory is created, so this can't live in
    # the base controller policy which is built before the directory).
    scope.soca_resources["controller_role"].add_to_policy(
        iam.PolicyStatement(
            actions=["ds:ResetUserPassword"],
            resources=[
                f"arn:{Aws.PARTITION}:ds:{Aws.REGION}:{Aws.ACCOUNT_ID}:directory/"
                f"{scope.directory_service_resource_setup['ad_aws_directory_service_id']}"
            ],
        )
    )
    scope.directory_service_resource_setup["endpoint"] = (
        f"ldap://{scope.directory_service_resource_setup['ds'].name}"
    )

    scope.directory_service_resource_setup["domain_controller_ips"] = [
        Fn.select(
            0, scope.directory_service_resource_setup["ds"].attr_dns_ip_addresses
        ),
        Fn.select(
            1, scope.directory_service_resource_setup["ds"].attr_dns_ip_addresses
        ),
    ]

    # Finally, fixup our DNS unless instructed not to
    # Some Shared VPC environments do not allow the downstream account to create R53 resolvers.
    if get_config_key(
        key_name="Config.directoryservice.create_route53_resolver",
        expected_type=bool,
        required=False,
        default=True,
    ):
        scope.aws_route53_resolver(
            launch_subnets=launch_subnets,
            dns_ip_addresses=scope.directory_service_resource_setup[
                "ds"
            ].attr_dns_ip_addresses,
        )
    else:
        logger.info(
            "Bypassing Route53 Resolver Creation due to Config.directoryservice.create_route53_resolver_rule == False"
        )
