# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import argparse
import os

from helpers.installer.install_model import (
    BASE_OS_PREVIEW,
    FilesystemProvider,
    installable_base_os_values,
)
from helpers.installer.i18n import _


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=_(
            "Create EDH installer. Visit https://awslabs.github.io/engineering-development-hub-documentation/documentation/01-install-edh-cluster/ if you need help"
        )
    )

    # Repeatable, and layered on top of default_config.yml rather than replacing
    # it. default stays None so argparse never appends to a shared list object.
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        action="append",
        default=None,
        help=_(
            "Path of custom config file(s), applied over default_config.yml and "
            "local_config_*.yml in the order given. Repeatable."
        ),
    )

    parser.add_argument(
        "--default-config",
        type=str,
        default=f"{os.path.dirname(os.path.realpath(__file__))}/../../../../default_config.yml",
        help=_("Path of the base config file. Defaults to default_config.yml ."),
    )

    parser.add_argument(
        "--ipv6",
        action="store_const",
        const=True,
        default=False,
        help=_(
            "Enable IPv6 for client-ipv6 probe (required for all IPv6) (default: False)"
        ),
    )

    parser.add_argument(
        "--override",
        type=str,
        action="append",
        nargs="+",
        help=_(
            "Configuration key(s) to override. Syntax is '<key_name>,<type>,<value>'. You can use multiple --override if needed."
        ),
    )

    parser.add_argument(
        "--cdk-no-strict",
        action="store_const",
        const=True,
        default=False,
        help=_("Disable CDK --strict setting (Failure on CDK stack warnings)"),
    )

    parser.add_argument(
        "--cdk-debug",
        action="store_const",
        const=True,
        default=False,
        help=_("Enable CDK debug mode"),
    )

    parser.add_argument(
        "--cdk-cloudformation-execution-policies",
        "--cloudformation-execution-policies",
        type=str,
        action="append",
        help=_("AWS CDK CloudFormation Execution Policy ARNs"),
    )

    parser.add_argument(
        "--cdk-role-arn", type=str, help=_("AWS CDK CloudFormation Execution Role ARN")
    )

    parser.add_argument(
        "--cdk-bootstrap-kms-key-id",
        "--cdk-bs-kms-id",
        type=str,
        help=_("AWS CDK Bootstrap KMS Key ID"),
    )

    parser.add_argument(
        "--cdk-profile",
        type=str,
        help=_("AWS CDK Bootstrap Profile"),
    )

    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        help=_(
            "AWS CLI profile to use. See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html"
        ),
    )

    parser.add_argument(
        "--cdk-custom-permissions-boundary",
        type=str,
        help=_("AWS CDK Custom Permissions Boundary"),
    )

    parser.add_argument(
        "--cdk-no-termination-protection",
        action="store_const",
        const=True,
        default=False,
        help=_(
            "Do not pass --termination-protection to 'cdk bootstrap'. Bootstrapping an "
            "already-bootstrapped environment is an UpdateStack on CDKToolkit, so the "
            "flag changes that setting on a toolkit stack EDH does not own."
        ),
    )

    parser.add_argument(
        "--cdk-skip-bootstrap",
        action="store_const",
        const=True,
        default=False,
        help=_(
            "Do not run 'cdk bootstrap' even when the environment version cannot be "
            "confirmed. Use when the deploy identity cannot read "
            "/cdk-bootstrap/<qualifier>/version but the environment is known good."
        ),
    )

    parser.add_argument(
        "--cdk-cmd",
        type=str,
        choices=[
            "deploy",
            "create",
            "update",
            "ls",
            "list",
            "synth",
            "synthesize",
            "destroy",
            "bootstrap",
        ],
        default="deploy",
    )
    parser.add_argument(
        "--cdk-method",
        type=str,
        choices=["direct", "change-set"],
        default="direct",
        help=_(
            "CDK deployment method (only used when --cdk-cmd is deploy/create/update). "
            "'direct' (default) calls CreateStack/UpdateStack directly; faster, simpler "
            "progress display, recommended for SOCA which is install-only. SOCA references "
            "existing AWS resources (VPC, subnets, certificates, key pairs) via synth-time "
            "lookups, which are unaffected by deploy method. "
            "'change-set' creates and executes a CFN change set; use this if you need a "
            "CloudFormation change set audit record for compliance, want to preview "
            "replacement risk on incremental updates, or are forking the installer to "
            "use 'cdk deploy --import-existing-resources' (which requires change-set)."
        ),
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json"],
        help=_("Output CfnOutputs via a text file"),
    )

    parser.add_argument(
        "--skip-config-message",
        action="store_const",
        const=True,
        default=None,
        help=_("Skip the configuration review prompt"),
    )

    parser.add_argument(
        "-r",
        "--region",
        type=str,
        help=_("AWS region to deploy EDH in"),
    )

    parser.add_argument(
        "--base-os",
        type=str,
        # Installable values only: an OS that cannot host a controller (a DCV-only OS
        # such as macOS) is registered for its runtime roles but is not a cluster base
        # OS, and must be rejected here as well as hidden from the prompt.
        choices=installable_base_os_values(),
        help=_(
            "Base OS for EDH controller and login nodes. Values in {preview} are "
            "preview releases, not for production use."
        ).format(preview=", ".join(sorted(BASE_OS_PREVIEW)) or "none"),
    )

    parser.add_argument(
        "--preview",
        action="store_true",
        help=_(
            "Show preview base OS releases in the interactive selection list. "
            "--base-os accepts a preview value with or without this flag; it only "
            "controls whether the interactive list offers one."
        ),
    )

    parser.add_argument(
        "--name",
        "-n",
        type=str,
        help=_("EDH cluster name (e.g. edh-mycluster)"),
    )

    parser.add_argument(
        "--email-address",
        type=str,
        action="append",
        help=_(
            "Email address for cluster notifications (can be specified multiple times)"
        ),
    )

    parser.add_argument(
        "-b",
        "--bucket",
        type=str,
        help=_("S3 bucket for EDH state storage"),
    )

    parser.add_argument(
        "--ssh-keypair",
        type=str,
        help=_("EC2 SSH key pair name"),
    )

    parser.add_argument(
        "--vpc-cidr",
        type=str,
        help=_("VPC CIDR block for new VPC (e.g. 10.0.0.0/16)"),
    )

    parser.add_argument(
        "--vpc-id",
        type=str,
        help=_("Existing VPC ID to deploy into"),
    )

    parser.add_argument(
        "--client-ip",
        type=str,
        action="append",
        help=_(
            "Client IPv4 IP/CIDR authorized to access EDH (can be specified multiple times, or as one comma-separated value)"
        ),
    )

    parser.add_argument(
        "--client-ipv6",
        type=str,
        action="append",
        help=_(
            "Client IPv6 CIDR authorized to access EDH (can be specified multiple times, or as one comma-separated value). Requires --ipv6"
        ),
    )

    parser.add_argument(
        "--public-subnets",
        type=str,
        nargs="+",
        help=_(
            "Public subnet IDs when using an existing VPC. Use + to specify more than 1 subnet."
        ),
    )

    parser.add_argument(
        "--private-subnets",
        type=str,
        nargs="+",
        help=_(
            "Private subnet IDs when using an existing VPC. Use + to specify more than 1 subnet."
        ),
    )

    parser.add_argument(
        "--prefix-list-id",
        type=str,
        help=_("Select if you want to add Prefix List to your security groups."),
    )

    parser.add_argument(
        "--fs-apps-provider",
        type=str,
        choices=[e.value for e in FilesystemProvider],
        help=_(
            "Filesystem provider for /apps (efs, fsx_lustre, fsx_ontap, fsx_openzfs)"
        ),
    )

    parser.add_argument(
        "--fs-apps",
        type=str,
        help=_("Existing filesystem DNS/IP for /apps"),
    )

    parser.add_argument(
        "--fs-data-provider",
        type=str,
        choices=[e.value for e in FilesystemProvider],
        help=_(
            "Filesystem provider for /data (efs, fsx_lustre, fsx_ontap, fsx_openzfs)"
        ),
    )

    parser.add_argument(
        "--fs-data",
        type=str,
        help=_("Existing filesystem DNS/IP for /data"),
    )

    parser.add_argument(
        "--os-domain",
        type=str,
        help=_("Existing OpenSearch domain endpoint URL"),
    )
    parser.add_argument(
        "--tls-certificate",
        type=str,
        help=_(
            "TLS certificate for the cluster ALB. Pass 'auto' to reuse the EDH default ACM cert "
            "(creating a self-signed one if absent -- not for production), or an ACM certificate ARN. "
            "Omit to use the interactive prompt."
        ),
    )

    parser.add_argument(
        "--deployment-mode",
        type=str,
        choices=["public", "private"],
        help=_(
            "Decide where to deploy the Elastic and Network Load Balancer (public -recommended- or private subnets). If private, ensure you have a VPN or Direct Connect set up to access the cluster from your client machines."
        ),
    )

    parser.add_argument(
        "--skip-cmk-checks",
        action="store_true",
        default=False,
        help=_("Skip Customer Managed KMS Key policy validation checks"),
    )
    return parser
