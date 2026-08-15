# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import argparse
import os

from helpers.installer.install_model import BaseOS, FilesystemProvider
from helpers.installer.i18n import _


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=_(
            "Create EDH installer. Visit https://awslabs.github.io/engineering-development-hub-documentation/documentation/01-install-edh-cluster/ if you need help"
        )
    )

    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=f"{os.path.dirname(os.path.realpath(__file__))}/../../../../default_config.yml",
        help=_("Path of custom config file(s). Defaults to default_config.yml ."),
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
        "--cdk-termination-protection",
        type=bool,
        help=_("AWS CDK Termination Protection setting"),
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
        choices=[e.value for e in BaseOS],
        help=_("Base OS for EDH controller and login nodes"),
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
            "Client IP/CIDR authorized to access EDH (can be specified multiple times)"
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
