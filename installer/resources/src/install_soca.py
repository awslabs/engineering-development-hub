#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


from __future__ import annotations

import datetime
import urllib3
import questionary
import ipaddress
import traceback
import os
import time
import json
import base64
import sys


from questionary import Choice, Separator
from requests.exceptions import Timeout, ConnectionError
from botocore.client import ClientError
from botocore.exceptions import ValidationError
from requests import get
from pydantic import ValidationError
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from helpers.installer.install_cli_args import build_arg_parser
from helpers.installer.install_model import (
    BaseOS,
    FilesystemProvider,
    InstallParameters,
)
from helpers.installer.helpers import (
    kms_prepare_account_aliases,
    get_default_region,
    build_boto3_client,
    build_logger,
    detect_customer_ip,
    get_install_properties,
    get_sts_info,
    get_ami_mapping,
    stream_subprocess,
    retrieve_secret_value,
    upload_objects,
    build_lambda_dependency,
    inline_validate_with,
    check_prefix_list,
    list_acm_certificates,
    create_self_signed_certificate_and_upload_to_acm,
    check_kms_key_principals,
    resources_mirroring,
)

import helpers.installer.constants as constants
from helpers.installer import bucket_picker
from helpers.installer.i18n import _

console = Console()
logger = build_logger(console=console)
urllib3.disable_warnings()


def show_banner(config_path: str) -> None:
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style="bold #8a9bb8", no_wrap=True)
    info_table.add_column(style="#e8eef7")
    info_table.add_row(
        "💻 Source Code",
        "[#4db8ff]https://github.com/awslabs/engineering-development-hub[/]",
    )
    info_table.add_row(
        "📖 Documentation",
        "[#4db8ff]https://awslabs.github.io/engineering-development-hub-documentation/[/]",
    )
    info_table.add_row("📁 Config File", f"[#4db8ff]{config_path}[/]")
    info_table.add_row(
        "🔕 Silent Installation",
        "[#8a9bb8]Use --help to see all the options you can pass via CLI arguments to perform a silent installation[/]",
    )
    info_table.add_row(
        "🔑 AWS STS Identity",
        f"[#8a9bb8]{_sts_caller_identity.get("Arn", "")}[/]",
    )

    info_panel = Panel(
        info_table,
        border_style="cyan",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(
        Panel(
            Group(
                Align.center(f"[bold #ffcc00]{constants.EDH_ASCII}[/]\n"),
                info_panel,
                Align.center(_("[italic #8a9bb8]Press Ctrl+C to exit at any time[/]")),
            ),
            title=_("[bold #e8eef7]Engineering Development Hub (EDH)[/]"),
            border_style="cyan",
            subtitle="Version 26.8.0",
            padding=(1, 4),
        )
    )
    console.print()


def override_keys(keys_to_override: list, install_properties: dict) -> dict:
    override_mapping: dict = {}

    for key in keys_to_override:
        override_info = key.split(",")
        if len(override_info) != 3:
            logger.error(
                f"Override information must use the following format: '<key_name>,<type>,<new_value>' (ex: Config.termination_protection,Bool,False). Detected {key}"
            )
            sys.exit(1)
        else:
            key_name = override_info[0]
            value_type = override_info[1]
            key_value = override_info[2]

            _value_type = value_type.lower()

            match _value_type:
                case "bool":
                    if key_value.lower() == "true":
                        key_value = True
                    elif key_value.lower() == "false":
                        key_value = False
                    else:
                        logger.error(
                            f"{key_name} does not seem to be a valid boolean. Please specify either True or False."
                        )
                        sys.exit(1)
                case "str" | "string":
                    key_value = str(key_value)
                case "list":
                    key_value = key_value.split("+")
                case "int" | "integer":
                    try:
                        key_value = int(key_value)
                    except ValueError:
                        logger.error(f"Expected {value_type} but detected {key_value}")
                        sys.exit(1)
                case _:
                    logger.error(
                        f"Value type must be bool/boolean/str/string/int/integer/list. Detected {_value_type}"
                    )
                    sys.exit(1)
        override_mapping[key_name] = key_value

    override_lines = "\n".join(
        f"  [bold #8a9bb8]{k}[/] = [#4db8ff]{v}[/]" for k, v in override_mapping.items()
    )
    console.print(
        Panel(
            override_lines,
            border_style="cyan",
            title="[bold #e8eef7]CLI Configuration Overrides[/]",
            padding=(1, 2),
        )
    )

    for key, value in override_mapping.items():
        keys = key.split(".")
        temp_dict = install_properties
        try:
            for k in keys[:-1]:
                temp_dict = temp_dict[k]
        except KeyError:
            logger.warning(
                f"Override key '{key}' does not exist in configuration, skipping"
            )
            continue
        if keys[-1] not in temp_dict:
            logger.warning(
                f"Override key '{key}' does not exist in configuration, skipping"
            )
            continue
        temp_dict[keys[-1]] = value

    return install_properties


def spinner(message: str, spinner: str = "aesthetic"):
    logger.debug(f"Displaying spinner with message: {message}")
    return console.status(f"[bold #4db8ff]{message}[/bold #4db8ff]", spinner=spinner)


def extract_kms_keys(data: dict, path: str = "") -> list[dict[str, str]]:
    """Recursively extract all kms_key_id and volume_kms_key_id values from a nested dict."""
    results = []
    for key, value in data.items():
        current_path = f"{path}.{key}" if path else key
        if key in ("kms_key_id", "volume_kms_key_id") and value is not None:
            results.append({"path": current_path, "value": value})
        elif isinstance(value, dict):
            results.extend(extract_kms_keys(value, current_path))
    return results


# ── AWS region discovery + grouping ─────────────────────────────────────────
# Logical grouping used in the install-time region picker. Keys are the
# region-code prefix (e.g. "us-east" → "Americas"). Order here defines the
# order groups appear in the picker.
_REGION_GROUP_ORDER: list[tuple[str, tuple[str, ...]]] = [
    ("Americas", ("us-east", "us-west", "ca-", "sa-", "mx-")),
    ("Europe", ("eu-",)),
    ("Europe (Sovereign)", ("eusc-",)),
    ("Asia Pacific", ("ap-",)),
    ("Middle East", ("me-", "il-")),
    ("Africa", ("af-",)),
    ("GovCloud (US)", ("us-gov-",)),
    ("China", ("cn-",)),
]


def _region_group(code: str) -> str:
    """Return the group label for a given region code. Unknown prefixes fall
    into 'Other' so a newly-announced region never breaks the picker."""
    for group, prefixes in _REGION_GROUP_ORDER:
        if any(code.startswith(p) for p in prefixes):
            return group
    return "Other"


def _fetch_region_metadata(client_ssm, codes: list[str]) -> dict[str, dict[str, str]]:
    """Batch SSM lookups for longName + geolocationCountry for each region.

    Uses ssm:GetParameters (chunks of 10) rather than ssm:GetParameter per
    region. Falls back to deriving a display name from the code when SSM is
    unavailable or a region is missing from the metadata store.
    """
    needed: list[str] = []
    for c in codes:
        needed.append(f"/aws/service/global-infrastructure/regions/{c}/longName")
        needed.append(
            f"/aws/service/global-infrastructure/regions/{c}/geolocationCountry"
        )

    resolved: dict[str, dict[str, str]] = {c: {} for c in codes}
    try:
        for i in range(0, len(needed), 10):
            chunk = needed[i : i + 10]
            resp = client_ssm.get_parameters(Names=chunk)
            for p in resp.get("Parameters", []):
                parts = p["Name"].split("/")
                code = parts[-2]
                key = parts[-1]
                resolved.setdefault(code, {})[key] = p["Value"]
    except Exception as err:
        # SSM perms missing or service hiccup — degrade gracefully rather than
        # fail the install. The picker will still work; entries just show the
        # region code in place of the long name.
        #
        # TODO: cross-partition SSM fallback. AWS's public region-metadata
        # parameters (/aws/service/global-infrastructure/*) are ONLY populated
        # in the commercial partition. When this installer runs INSIDE
        # GovCloud / China / EUSC, the local SSM has no such params and we
        # land in this except block, dropping back to code-only labels.
        # Fix: try a second lookup against commercial us-east-1 using creds
        # from an AWS_COMMERCIAL_PROFILE env var, if set. Deferred — out of
        # scope for the initial uplift.
        logger.warning(
            f"SSM region metadata lookup failed, falling back to code-only labels: {err}"
        )
    # Sensible defaults for anything the SSM lookup didn't fill in
    for code, data in resolved.items():
        data.setdefault("longName", code)
        data.setdefault("geolocationCountry", code.split("-")[0].upper())

    # Ensure EU Sovereign Cloud regions show "Sovereign Cloud" in the picker.
    for code, data in resolved.items():
        if code.startswith("eusc-") and "Sovereign" not in data["longName"]:
            data["longName"] = f"{data['longName']} (Sovereign Cloud)"
    return resolved


def _build_region_choices(region_meta: dict[str, dict[str, str]]) -> list:
    """Build the questionary.select choices list with:
    - regions grouped by geography via non-selectable Separator headers
    - regions sorted alphabetically by code within each group
    - fixed-width columns, right-padded to keep visual alignment in the picker
    - each row left-padded with whitespace so the block of choices sits roughly
      centred in the terminal, matching the centered-data-residency hint
      printed above the picker
    """
    import shutil

    # Bucket by group label
    buckets: dict[str, list[str]] = {label: [] for label, _ in _REGION_GROUP_ORDER}
    buckets["Other"] = []
    for code in region_meta:
        buckets[_region_group(code)].append(code)

    # Fixed-width row format:
    #   <code:16>  [<country:2>]   <long name>
    # e.g. "us-east-1         [US]   US East (N. Virginia)"
    # Brackets around the country code make the data-residency hint visually
    # obvious at a glance without requiring color support.
    ROW_FMT = "{code:<16}  [{country:<2}]  {long_name}"

    # Work out the longest rendered row so we can compute a single centring
    # offset that applies uniformly to every row (separators and choices).
    sample_rows = []
    for code, meta in region_meta.items():
        sample_rows.append(
            ROW_FMT.format(
                code=code,
                country=meta["geolocationCountry"],
                long_name=meta["longName"],
            )
        )
    max_row_width = max(len(r) for r in sample_rows) if sample_rows else 0

    # Try to center in the current terminal; fall back to 80 cols if we can't
    # query it (non-tty, broken terminfo, etc.).
    term_cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    left_pad = max(0, (term_cols - max_row_width) // 2)
    pad = " " * left_pad

    choices: list = []
    group_order = [label for label, _ in _REGION_GROUP_ORDER] + ["Other"]
    for label in group_order:
        codes = sorted(buckets.get(label, []))
        if not codes:
            continue
        # Separator — also centered for visual consistency
        sep_text = f"── {label} ──"
        sep_pad = max(0, (term_cols - len(sep_text)) // 2)
        choices.append(Separator(" " * sep_pad + sep_text))
        for code in codes:
            meta = region_meta[code]
            row = ROW_FMT.format(
                code=code,
                country=meta["geolocationCountry"],
                long_name=meta["longName"],
            )
            choices.append(Choice(title=pad + row, value=code))
    return choices


def _pick_s3_bucket(region: str, aws_profile: str | None) -> str | None:
    """Optional '?' affordance for the S3 bucket prompt: list the buckets the
    account owns (grouped by region, install region first) and return the
    selected name. Returns None to fall back to manual entry -- on cancel, an
    empty account, or any AWS error -- so the convenience feature never blocks
    the install."""
    try:
        with spinner("Listing S3 buckets you own ..."):
            _s3 = build_boto3_client(
                service_name="s3", region_name=region, aws_profile=aws_profile
            )
            _buckets = bucket_picker.list_owned_buckets(_s3)
    except Exception as _err:  # noqa: BLE001 - convenience feature must never hard-fail
        logger.error(
            f"Could not list S3 buckets ({_err}); enter the bucket name manually."
        )
        return None

    if not _buckets:
        logger.warning(
            "No S3 buckets found in this account; enter the bucket name manually."
        )
        return None

    try:
        return questionary.select(
            _("Select an S3 bucket ({count} found; type to filter):").format(
                count=len(_buckets)
            ),
            choices=bucket_picker.build_bucket_choices(_buckets, region),
            use_search_filter=True,
            use_jk_keys=False,
            style=constants.EDH_STYLE,
        ).unsafe_ask()
    except KeyboardInterrupt:
        # Cancelling the picker returns to manual entry rather than aborting the
        # whole install; the manual text prompt still aborts on Ctrl-C as usual.
        return None


if __name__ == "__main__":
    parser = build_arg_parser()
    args = parser.parse_args()
    _install_directory = os.path.dirname(os.path.realpath(__file__))
    os.chdir(path=_install_directory)

    console.clear()

    # Set a dark background for better visibility
    sys.stdout.write("\033]11;#1a1b26\033\\")
    sys.stdout.flush()

    # Check if AWS_PROFILE or AWS_DEFAULT_PROFILE exist
    # If environment variable and --profile are  not set, we will use the default profile in .aws/credentials
    _aws_profile = os.environ.get(
        "AWS_PROFILE", os.environ.get("AWS_DEFAULT_PROFILE", None)
    )
    if args.profile:
        if _aws_profile:
            logger.warning(
                f"Using AWS profile sourced from CLI: {args.profile} but also found default profile: {_aws_profile}"
            )
        _aws_profile = args.profile

    # must be called before the banner as we display the IAM role/user ARN used to launch the installer
    with spinner("Fetching AWS STS caller identity ..."):
        _sts_caller_identity = get_sts_info(aws_profile=_aws_profile)

    # Print banner
    show_banner(config_path=args.config)

    with spinner("Building Lambda dependency ..."):
        build_lambda_dependency(install_directory=_install_directory)

    with spinner("Fetching install properties ..."):
        _get_install_properties = get_install_properties(path=args.config)

    with spinner("Checking Configuration overrides ..."):
        if args.override:
            overrides: list = [item for sublist in args.override for item in sublist]
            _get_install_properties = override_keys(
                keys_to_override=overrides,
                install_properties=_get_install_properties,
            )

    # --ipv6 enables the IPv6 address-family feature flag for the whole install (dual-stack)
    if args.ipv6:
        _get_install_properties.setdefault("Config", {}).setdefault(
            "feature_flags", {}
        ).setdefault("Networking", {})["EnableIPv6"] = True
        logger.debug(
            "--ipv6 set: enabling Config.feature_flags.Networking.EnableIPv6"
        )

    install_parameters = {
        "deployment_mode": args.deployment_mode,
        "skip_config_message": args.skip_config_message,
        "email_address": args.email_address,
        "base_os": args.base_os,
        "bucket": args.bucket,
        "ssh_keypair": args.ssh_keypair,
        "cluster_name": args.name,
        "cluster_id": args.name,
        "region": args.region,
        "client_ip": args.client_ip,
        "vpc_id": args.vpc_id,
        "vpc_cidr": args.vpc_cidr,
        "partition": _sts_caller_identity.get("Partition"),
        "account_id": _sts_caller_identity.get("Account"),
        "public_subnets": args.public_subnets,
        "private_subnets": args.private_subnets,
        "fs_apps_provider": args.fs_apps_provider,
        "fs_apps": args.fs_apps,
        "fs_data_provider": args.fs_data_provider,
        "fs_data": args.fs_data,
        "create_es_service_role": False,
        "os_domain": args.os_domain,
        "prefix_list_id": None,
        "prefix_list_id_ipv6": None,
        "client_ipv6": None,
        "tls_certificate": args.tls_certificate,
    }

    try:
        # We need to get the default region for the user’s partition before we can build the clients to get the list of regions to show in the prompt, so we will build a temporary client here with the default region to get the list of regions, then re-build the clients after the user selects their region
        default_region = get_default_region(
            sts_partition=install_parameters["partition"]
        )
        client_ec2 = build_boto3_client(
            service_name="ec2", region_name=default_region, aws_profile=_aws_profile
        )
        client_ssm = build_boto3_client(
            service_name="ssm", region_name=default_region, aws_profile=_aws_profile
        )

        # Fetching  all AMIs
        # note: 999-my-ami-defaults.yaml will override any AMI values for the region specified in the config file if present, this allows us to have custom AMI values for certain regions without having to maintain a full RegionMap.d file
        with spinner("Fetching all AMIs from `region_map.d` folder ..."):
            try:
                _region_map = get_ami_mapping()

                if _region_map is None:
                    logger.error(
                        f"No AMI found for region {install_parameters['region']}. Exiting..."
                    )
                    sys.exit(1)
                else:
                    # Merge RegionMap to the install properties
                    _get_install_properties = {
                        **_get_install_properties,
                        "RegionMap": _region_map,
                    }

                logger.debug(
                    f"Latest AMI for region {install_parameters['region']}: {_region_map}"
                )
            except Exception as err:
                logger.error(
                    f"Error fetching the AMI MAP for region {install_parameters['region']}: {err}"
                )
                sys.exit(1)

        # Display Config Message disclaimer
        if not install_parameters.get("skip_config_message"):
            _config_choice = questionary.select(
                _(
                    "EDH will create AWS resources using the default parameters specified in {config_file}.\n"
                    "Make sure you have read, reviewed and updated them (if needed). Continue?"
                ).format(config_file=args.config),
                choices=[
                    _("Continue"),
                    _("Abort"),
                ],
                default=_("Continue"),
                style=constants.EDH_STYLE,
            ).unsafe_ask()
            if _config_choice == _("Abort"):
                console.print(_("[yellow]Aborted by user.[/yellow]"))
                sys.exit(0)
        # End of config message disclaimer

        # Begin Region
        if not install_parameters.get("region"):
            try:
                with spinner("Fetching available AWS regions for your AWS account ..."):
                    region_codes = [
                        r["RegionName"]
                        for r in client_ec2.describe_regions(AllRegions=False).get(
                            "Regions", []
                        )
                    ]
                    region_meta = _fetch_region_metadata(client_ssm, region_codes)
            except Exception as err:
                logger.error(f"Error fetching AWS regions: {err}")
                sys.exit(1)

            if not region_meta:
                logger.error("No AWS regions available to select. Exiting...")
                sys.exit(1)

            install_parameters["region"] = questionary.select(
                _("Select the region where you want to deploy your EDH cluster:"),
                instruction=_(
                    "(Your data will reside in the region you select. "
                    "Country code [CC] is shown to help with data-residency.)"
                ),
                choices=_build_region_choices(region_meta),
                use_search_filter=True,
                use_jk_keys=False,
                default=default_region,
                style=constants.EDH_STYLE,
            ).unsafe_ask()
        # End Region

        # At this point we have the region, we will re-build the clients with the correct region for validation and later use
        logger.debug(
            f"User selected region: {install_parameters['region']}, creating clients with this region for validation and use in CDK deployment"
        )

        with spinner("Building boto3 clients ..."):
            import time as _time  # local alias; avoids shadowing any top-level time import

            _boto_build_t0 = _time.monotonic()
            logger.debug(
                f"boto3 client build: starting batch of 11 clients "
                f"(SOCA_BOTO3_SHARED_SESSION="
                f"{os.environ.get('SOCA_BOTO3_SHARED_SESSION', 'on')})"
            )
            client_ec2 = build_boto3_client(
                service_name="ec2",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_ssm = build_boto3_client(
                service_name="ssm",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_sts = build_boto3_client(
                service_name="sts",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_s3_resource = build_boto3_client(
                service_name="s3",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
                resource=True,
            )
            client_s3 = build_boto3_client(
                service_name="s3",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_efs = build_boto3_client(
                service_name="efs",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_fsx = build_boto3_client(
                service_name="fsx",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_cloudformation = build_boto3_client(
                service_name="cloudformation",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_iam = build_boto3_client(
                service_name="iam",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_kms = build_boto3_client(
                service_name="kms",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_secretsmanager = build_boto3_client(
                service_name="secretsmanager",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            client_acm = build_boto3_client(
                service_name="acm",
                region_name=install_parameters["region"],
                aws_profile=_aws_profile,
            )
            _boto_build_elapsed = _time.monotonic() - _boto_build_t0
            logger.debug(
                f"boto3 client build: completed batch of 11 clients in "
                f"{_boto_build_elapsed:.2f}s "
                f"(avg {_boto_build_elapsed * 100:.0f}ms/client)"
            )

        logger.debug(
            "Re-built boto3 clients with user-selected region for validation and use in CDK deployment"
        )

        if args.prefix_list_id:
            with spinner(message=_("Validating EC2 Prefix List ID ... ")):
                _pl_info = check_prefix_list(
                    ec2_client=client_ec2, prefix_list_id=args.prefix_list_id
                )
                # note: check_prefix_list() already verify if the Address family is either IPv4 or IPv6 and exit otherwise.
                if _pl_info.get("AddressFamily") == "IPv4":
                    install_parameters["prefix_list_id"] = args.prefix_list_id
                elif _pl_info.get("AddressFamily") == "IPv6":
                    install_parameters["prefix_list_id_ipv6"] = args.prefix_list_id

        # Performing KMS key alias check to pre-generate service default KMS key Aliases if needed
        with spinner("Performing KMS key alias check ..."):
            kms_prepare_account_aliases(client=client_kms)

        if args.skip_cmk_checks:
            logger.warning(
                "Skipping Customer Managed KMS Key policy validation checks as per user request. Make sure you have the right permissions set on your KMS keys to avoid deployment failure. See documentation https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/encryption-everywhere-with-kms/"
            )
        else:
            with spinner("Checking Customer Managed KMS Key permissions ..."):
                _kms_keys = extract_kms_keys(_get_install_properties)
                # example output
                # [{'path': 'Config.storage.kms_key_id', 'value': 'arn:aws:kms:eu-west-1:redacted:key/redacted'}, {'path': 'Config.login_node.volume_kms_key_id', 'value': 'alias/aws/ebs'},
                # {'path': 'Config.controller.volume_kms_key_id', 'value': 'arn:aws:kms:eu-west-1:redacted:key/redacted'}]
                if _kms_keys:
                    for kms_key in _kms_keys:
                        if not kms_key["value"].startswith("alias/"):
                            logger.info(
                                f"Verifying permissions for KMS Key referenced at {kms_key['path']}: {kms_key['value']}"
                            )
                            if not check_kms_key_principals(
                                kms_client=client_kms,
                                key_id=kms_key["value"],
                                account_id=install_parameters["account_id"],
                                require_cloudwatch=(
                                    True
                                    if "logging.kms_key_id" in kms_key["path"]
                                    or kms_key["path"] == "Config.kms_key_id"
                                    else False
                                ),
                            ):
                                logger.error(
                                    f"KMS Key {kms_key['value']} referenced at {kms_key['path']} does not have the required permissions. Please update the KMS key policy to include the required permissions and try again. See documentation https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/encryption-everywhere-with-kms/"
                                )
                                sys.exit(1)

        # Verify if we have the default Service Linked Role for OpenSearch. EDH will create it if needed
        with spinner("Validating OpenSearch SLR ..."):
            try:
                logger.debug(f"Validating OpenSearch SLR")
                _iam_paginator = client_iam.get_paginator("list_roles")
                _iam_iter = _iam_paginator.paginate(
                    PathPrefix="/aws-service-role/opensearchservice.amazonaws.com"
                )
                for _page in _iam_iter:
                    logger.debug(f"Processing Role page: {_page}")
                    if not _page.get("Roles", []):
                        install_parameters["create_es_service_role"] = True
                        break

            except ClientError as err:
                logger.error(
                    f"Unable to determine if you have a ServiceLinked Role created on your account for OpenSearch. Verify your IAM permissions: {err} "
                )
                sys.exit(1)

        if not install_parameters.get("cluster_name"):
            while True:
                _cluster_suffix = questionary.text(
                    _(
                        "Please provide your EDH environment name (edh- is automatically added as a prefix):"
                    ),
                    instruction="edh-",
                    validate=lambda v: (
                        True
                        if 3 <= len(v) <= 11
                        else "Name must be between 3 and 11 characters"
                    ),  # note: edh- is added as prefix, and max lenght is 15. The actual cluster name should then be anything between 3 and 11
                    style=constants.EDH_STYLE,
                ).unsafe_ask()
                install_parameters["cluster_name"] = f"edh-{_cluster_suffix.lower()}"
                install_parameters["cluster_id"] = f"edh-{_cluster_suffix.lower()}"
                try:
                    with spinner(
                        message=_("Checking if name is available on Cloudformation")
                    ):
                        # this also check if there is not already a Cloudformation stack with the same name
                        InstallParameters._validate_cluster_name_unique(
                            install_parameters["cluster_name"],
                            install_parameters["region"],
                        )
                    break
                except ValueError as e:
                    logger.error(str(e))
            logger.debug(
                f"User specified cluster name: {install_parameters['cluster_name']}"
            )
        else:
            # automatically add `edh-` prefix when custom --name is specified via CLI
            # 15 char max size will still be validated automatically later via model
            if not install_parameters.get("cluster_name").startswith("edh-"):
                install_parameters["cluster_name"] = (
                    f"edh-{install_parameters.get('cluster_name').lower()}"
                )
                install_parameters["cluster_id"] = install_parameters.get(
                    "cluster_name"
                )

                logger.warning(
                    f"Specified --name does not start with edh-. Cluster name will be {install_parameters['cluster_name']}"
                )

        if not install_parameters.get("email_address"):
            install_parameters["email_address"] = [
                questionary.text(
                    _("Email address for cluster notifications:"),
                    validate=lambda val: inline_validate_with(
                        InstallParameters, "email_address"
                    )([val]),
                    style=constants.EDH_STYLE,
                ).unsafe_ask()
            ]
            logger.debug(
                f"User specified email address: {install_parameters['email_address']}"
            )

        # Cert resolution: 3 modes
        #   1. install_parameters["tls_certificate"] is an ARN (str
        #      starting with "arn:") -> use it as-is, no prompt.
        #   2. install_parameters["tls_certificate"] == TLS_CERTIFICATE_AUTO
        #      -> headless auto-create path (matches "create" prompt choice).
        #   3. install_parameters["tls_certificate"] is falsy -> show
        #      the interactive prompt.
        TLS_CERTIFICATE_AUTO = "auto"
        _cert_initial = install_parameters.get("tls_certificate")
        _cert_is_auto = _cert_initial == TLS_CERTIFICATE_AUTO
        if _cert_is_auto:
            # Clear the sentinel so the create-path code below sets the real ARN.
            install_parameters["tls_certificate"] = None

        if not install_parameters.get("tls_certificate"):
            if _cert_is_auto:
                _cert_choice = "create"
                logger.info(
                    "TLS: --tls-certificate auto -> using EDH default self-signed cert "
                    "(create-if-missing). Self-signed; not for production."
                )
            else:
                _cert_choice = questionary.select(
                    _("How would you like to configure the HTTPS certificate?"),
                    choices=[
                        Choice(
                            title=_("Let EDH create a self-signed certificate"),
                            value="create",
                        ),
                        Choice(
                            title=_("Use an existing ACM certificate"),
                            value="existing",
                        ),
                    ],
                    style=constants.EDH_STYLE,
                    default="create",
                ).unsafe_ask()
            if _cert_choice == "existing":
                with spinner("Fetching ACM certificates ..."):
                    _acm_certs = list_acm_certificates(acm_client=client_acm)

                if not _acm_certs:
                    logger.error(
                        f"No issued certificates found in ACM for region {install_parameters['region']}."
                    )
                    sys.exit(1)

                _cert_domain_w = max(len(c["domain_name"]) for c in _acm_certs)
                install_parameters["tls_certificate"] = questionary.select(
                    _("Select the ACM certificate to use:"),
                    choices=[
                        Choice(
                            title=f"{c['domain_name']:<{_cert_domain_w}}  {c['certificate_arn']}",
                            value=c["certificate_arn"],
                        )
                        for c in _acm_certs
                    ],
                    style=constants.EDH_STYLE,
                ).unsafe_ask()
            else:
                with spinner("Checking for existing EDH default certificate ..."):
                    _acm_certs = list_acm_certificates(acm_client=client_acm)

                _existing_default = next(
                    (
                        c
                        for c in _acm_certs
                        if c["domain_name"] == "EDH.DEFAULT.CREATE.YOUR.OWN.CERTIFICATE"
                    ),
                    None,
                )

                if _existing_default:
                    install_parameters["tls_certificate"] = _existing_default[
                        "certificate_arn"
                    ]
                    logger.info(
                        f"Using existing EDH default certificate: {_existing_default['certificate_arn']}"
                    )
                else:
                    with spinner(
                        "Creating self-signed certificate and uploading it to ACM ..."
                    ):
                        _new_cert_arn = (
                            create_self_signed_certificate_and_upload_to_acm(
                                acm_client=client_acm
                            )
                        )

                    with spinner("Waiting for certificate to be in ISSUED state ..."):
                        for _attempt in range(30):
                            _acm_certs = list_acm_certificates(
                                acm_client=client_acm, certificate_arn=_new_cert_arn
                            )
                            if _acm_certs:
                                break
                            time.sleep(2)
                        else:
                            logger.error(
                                "Certificate did not reach ISSUED state within 60 seconds."
                            )
                            sys.exit(1)

                    install_parameters["tls_certificate"] = _new_cert_arn

            logger.debug(
                f"User selected ACM certificate: {install_parameters['tls_certificate']}"
            )

        if not install_parameters.get("base_os"):
            install_parameters["base_os"] = questionary.select(
                _(
                    "Select the default operating system for your EDH cluster (this can be changed post deployment):"
                ),
                choices=[Choice(title=e.value, value=e.value) for e in BaseOS],
                default="amazonlinux2023",
                style=constants.EDH_STYLE,
            ).unsafe_ask()
            logger.debug(f"User specified base OS: {install_parameters['base_os']}")

        try:
            _region_map[install_parameters["region"]]["x86_64"][
                install_parameters["base_os"]
            ]
        except KeyError:
            logger.error(
                f"Base OS {install_parameters['base_os']} is not available for region {install_parameters['region']}. Exiting..."
            )
            sys.exit(1)

        if not install_parameters.get("client_ip"):
            with spinner("Detecting your IPv4 address ..."):
                try:
                    detected_ip = detect_customer_ip(address_family="ipv4")
                    logger.debug(f"Detected customer IPv4 address: {detected_ip}")
                except Exception as err:
                    logger.error(f"Error detecting customer IPv4 address: {err}")
                    detected_ip = ""

            install_parameters["client_ip"] = [
                questionary.text(
                    _(
                        "Client IPv4 or CIDR range authorized to access EDH on TCP ports 443/22 (this can be changed post-install):"
                    ),
                    validate=lambda val: inline_validate_with(
                        InstallParameters, "client_ip"
                    )([val]),
                    style=constants.EDH_STYLE,
                    default=detected_ip,
                ).unsafe_ask()
            ]
            logger.debug(f"User specified client IP: {install_parameters['client_ip']}")

        # Dual-stack: detect + prompt a separate IPv6 client range when IPv6 is enabled
        if args.ipv6 and not install_parameters.get("client_ipv6"):
            with spinner("Detecting your IPv6 address ..."):
                try:
                    detected_ipv6 = detect_customer_ip(address_family="ipv6")
                    logger.debug(f"Detected customer IPv6 address: {detected_ipv6}")
                except Exception as err:
                    logger.error(f"Error detecting customer IPv6 address: {err}")
                    detected_ipv6 = ""

            install_parameters["client_ipv6"] = [
                questionary.text(
                    _(
                        "Client IPv6 or CIDR range authorized to access EDH on TCP ports 443/22 (this can be changed post-install):"
                    ),
                    validate=lambda val: inline_validate_with(
                        InstallParameters, "client_ipv6"
                    )([val]),
                    style=constants.EDH_STYLE,
                    default=detected_ipv6,
                ).unsafe_ask()
            ]
            logger.debug(
                f"User specified client IPv6: {install_parameters['client_ipv6']}"
            )

        if not install_parameters.get("deployment_mode"):
            install_parameters["deployment_mode"] = questionary.select(
                _(
                    "How should EDH be deployed?\n"
                    "  Public: Load balancers are placed in public subnets, protected by security groups and prefix lists. Only your authorized IPs ({client_ip}) can reach EDH (this list can be changed post-install).\n"
                    "  Private: Load balancers are placed in private subnets. Requires a VPN or Direct Connect for access."
                ).format(
                    client_ip=", ".join(
                        (install_parameters.get("client_ip") or [])
                        + (install_parameters.get("client_ipv6") or [])
                    )
                ),
                choices=[
                    Choice(
                        title=_(
                            "Public (Recommended) - Internet-facing load balancers, access restricted by firewall rules"
                        ),
                        value="public",
                    ),
                    Choice(
                        title=_(
                            "Private - Internal load balancers, requires VPN/Direct Connect. Not internet routable."
                        ),
                        value="private",
                    ),
                ],
                style=constants.EDH_STYLE,
                default="public",
            ).unsafe_ask()

        if not install_parameters.get("ssh_keypair"):
            with spinner("Fetching available SSH key pairs ..."):
                try:
                    _available_keypairs = InstallParameters._list_ssh_keypairs(
                        install_parameters["region"]
                    )
                except ValueError as e:
                    logger.error(str(e))
                    sys.exit(1)

                if not _available_keypairs:
                    logger.error(
                        f"No SSH key pairs found in {install_parameters['region']}. Create one first."
                    )
                    sys.exit(1)

            # Fixed-width columns keep values aligned across entries.
            # Widest key name sets column 1; key type is 3 chars; date is 10.
            _kp_name_w = max(len(kp["name"]) for kp in _available_keypairs)
            install_parameters["ssh_keypair"] = questionary.select(
                _("Choose the SSH keypair to use: "),
                choices=[
                    Choice(
                        title=f"{kp['name']:<{_kp_name_w}}  {kp['type']:<8}  {kp['created']}",
                        value=kp["name"],
                    )
                    for kp in _available_keypairs
                ],
                style=constants.EDH_STYLE,
            ).unsafe_ask()
            logger.debug(
                f"User specified SSH keypair: {install_parameters['ssh_keypair']}"
            )

        if not install_parameters.get("bucket"):
            # Accept the '?' picker sentinel through the field validator, then
            # branch on it. A real name still gets full pydantic format
            # validation here and the HeadBucket ownership check below; '?' can
            # never be a valid bucket name so there is no collision.
            _bucket_field_validate = inline_validate_with(InstallParameters, "bucket")

            def _bucket_or_list(value: str):
                if (value or "").strip() == "?":
                    return True
                return _bucket_field_validate(value)

            while True:
                _bucket_answer = questionary.text(
                    _(
                        "Enter the name of an S3 bucket that the application will use to store cluster data (or type '?' to list buckets you own):"
                    ),
                    validate=_bucket_or_list,
                    style=constants.EDH_STYLE,
                ).unsafe_ask()
                _bucket_answer = (_bucket_answer or "").strip()
                if _bucket_answer == "?":
                    _picked = _pick_s3_bucket(
                        region=install_parameters["region"],
                        aws_profile=_aws_profile,
                    )
                    if not _picked:
                        continue
                    _bucket_answer = _picked
                with spinner("Checking S3 Bucket permissions ..."):
                    try:
                        InstallParameters._validate_s3_bucket(_bucket_answer)
                        install_parameters["bucket"] = _bucket_answer
                        break
                    except ValueError as e:
                        logger.error(str(e))
            logger.debug(f"User specified S3 bucket: {install_parameters['bucket']}")

        if install_parameters.get("vpc_id") and install_parameters.get("vpc_cidr"):
            logger.error(
                "Both vpc_id and vpc_cidr are provided. Please provide only one of them."
            )
            sys.exit(1)

        if install_parameters.get("vpc_id") and not (
            install_parameters.get("public_subnets")
            and install_parameters.get("private_subnets")
        ):
            logger.error(
                "vpc_id is provided without subnet_ids. Please provide both public_subnets and private_subnets or remove vpc_id."
            )
            sys.exit(1)

        # CLI-supplied subnets need to match the format the interactive
        # picker stores ("<subnet-id>,<az>"). Bare IDs get enriched; entries
        # the user pre-formatted as "<id>,<az>" get validated against the
        # actual AZ in EC2 (mismatch errors fast, not cryptically at CFN
        # time). One DescribeSubnets call per VPC handles both.
        if install_parameters.get("vpc_id") and (
            install_parameters.get("public_subnets")
            or install_parameters.get("private_subnets")
        ):
            with spinner(
                f"Resolving AZs for CLI-supplied subnets in {install_parameters['vpc_id']} ..."
            ):
                try:
                    _vpc_subnets = InstallParameters._list_subnets(
                        region=install_parameters["region"],
                        vpc_id=install_parameters["vpc_id"],
                    )
                except ValueError as _e:
                    logger.error(f"Failed to look up subnets for AZ enrichment: {_e}")
                    sys.exit(1)
            _id_to_az = {s["subnet_id"]: s["az"] for s in _vpc_subnets}

            for _key in ("public_subnets", "private_subnets"):
                _items = install_parameters.get(_key, [])
                _enriched = []
                for _sn in _items:
                    _flag = f"--{_key.replace('_', '-')}"
                    if "," in _sn:
                        _id, _, _claimed_az = _sn.partition(",")
                        _id = _id.strip()
                        _claimed_az = _claimed_az.strip()
                        _real_az = _id_to_az.get(_id)
                        if not _real_az:
                            logger.error(
                                f"{_flag} {_id} not found in VPC "
                                f"{install_parameters['vpc_id']} (region "
                                f"{install_parameters['region']})."
                            )
                            sys.exit(1)
                        if _claimed_az != _real_az:
                            logger.error(
                                f"{_flag} {_id} is in AZ {_real_az}, not {_claimed_az} "
                                f"as supplied. Correct value: {_id},{_real_az}"
                            )
                            sys.exit(1)
                        _enriched.append(f"{_id},{_real_az}")
                    else:
                        _real_az = _id_to_az.get(_sn)
                        if not _real_az:
                            logger.error(
                                f"{_flag} {_sn} not found in VPC "
                                f"{install_parameters['vpc_id']} (region "
                                f"{install_parameters['region']})."
                            )
                            sys.exit(1)
                        _enriched.append(f"{_sn},{_real_az}")
                install_parameters[_key] = _enriched
            logger.debug(
                f"Validated/enriched CLI subnets: "
                f"public={install_parameters['public_subnets']}, "
                f"private={install_parameters['private_subnets']}"
            )

        if not install_parameters.get("vpc_id") and not install_parameters.get(
            "vpc_cidr"
        ):
            _vpc_choice = questionary.select(
                _("VPC configuration:"),
                choices=[
                    Choice(title=_("Create a new VPC"), value="new"),
                    Choice(title=_("Use an existing VPC"), value="existing"),
                ],
                style=constants.EDH_STYLE,
            ).unsafe_ask()

            if _vpc_choice == "new":
                with spinner("Fetching existing VPC CIDRs ..."):
                    try:
                        _existing_vpcs = InstallParameters._list_vpcs(
                            install_parameters["region"]
                        )
                        _existing_cidrs = [
                            ipaddress.ip_network(v["cidr"], strict=False)
                            for v in _existing_vpcs
                            if v.get("cidr")
                        ]
                    except ValueError as e:
                        logger.warning(f"Could not fetch existing VPCs: {e}")
                        _existing_cidrs = []

                if _existing_cidrs:
                    _vpc_table = Table(
                        show_header=True,
                        header_style="bold #ffcc00",
                        expand=True,
                        padding=(0, 1),
                    )
                    _vpc_table.add_column("VPC ID", style="#4db8ff")
                    _vpc_table.add_column("CIDR", style="#00cc66")
                    _vpc_table.add_column("Name", style="#e8eef7")
                    for v in _existing_vpcs:
                        if v.get("cidr"):
                            _vpc_table.add_row(
                                v["vpc_id"], v["cidr"], v.get("name", "")
                            )
                    console.print()
                    console.print(
                        Panel(
                            _vpc_table,
                            title=f"[bold #4db8ff]Existing VPCs in {install_parameters['region']}[/]",
                            border_style="cyan",
                            padding=(1, 2),
                        )
                    )

                _base_validate = inline_validate_with(InstallParameters, "vpc_cidr")

                def _validate_cidr_no_overlap(value: str) -> bool | str:
                    result = _base_validate(value)
                    if result is not True:
                        return result
                    new_net = ipaddress.ip_network(value, strict=False)
                    for existing in _existing_cidrs:
                        if new_net.overlaps(existing):
                            return f"CIDR {value} overlaps with existing VPC {existing}"
                    return True

                while True:
                    install_parameters["vpc_cidr"] = questionary.text(
                        _("VPC CIDR block (e.g. 10.0.0.0/16):"),
                        default="10.0.0.0/16",
                        validate=_validate_cidr_no_overlap,
                        style=constants.EDH_STYLE,
                    ).unsafe_ask()
                    break

                logger.debug(
                    f"User specified VPC CIDR: {install_parameters['vpc_cidr']}"
                )
            else:
                with spinner("Fetching VPCs ..."):
                    try:
                        _available_vpcs = InstallParameters._list_vpcs(
                            install_parameters["region"]
                        )
                    except ValueError as e:
                        logger.error(str(e))
                        sys.exit(1)

                if not _available_vpcs:
                    logger.error(
                        f"No VPCs found in {install_parameters['region']}. Create one first."
                    )
                    sys.exit(1)

                # Fixed-width columns: VPC ID is 21 chars (prefix 'vpc-' + 17),
                # CIDR varies but cap to widest observed, name fills the rest.
                _vpc_id_w = max(len(v["vpc_id"]) for v in _available_vpcs)
                _vpc_cidr_w = max(len(v["cidr"]) for v in _available_vpcs)
                install_parameters["vpc_id"] = questionary.select(
                    _("Select an existing VPC:"),
                    choices=[
                        Choice(
                            title=(
                                f"{v['vpc_id']:<{_vpc_id_w}}  {v['cidr']:<{_vpc_cidr_w}}  {v['name']}"
                                if v["name"]
                                else f"{v['vpc_id']:<{_vpc_id_w}}  {v['cidr']:<{_vpc_cidr_w}}"
                            ),
                            value=v["vpc_id"],
                        )
                        for v in _available_vpcs
                    ],
                    style=constants.EDH_STYLE,
                ).unsafe_ask()
                logger.debug(f"User specified VPC ID: {install_parameters['vpc_id']}")

                with spinner("Fetching subnets ..."):
                    try:
                        _available_subnets = InstallParameters._list_subnets(
                            install_parameters["region"], install_parameters["vpc_id"]
                        )
                    except ValueError as e:
                        logger.error(str(e))
                        sys.exit(1)

                if len(_available_subnets) < 4:
                    logger.error(
                        f"VPC {install_parameters['vpc_id']} has only {len(_available_subnets)} subnet(s). "
                        "At least 4 subnets are required (2 public + 2 private)."
                    )
                    sys.exit(1)

                # Fixed-width columns: subnet ID, CIDR, AZ, then name.
                _sn_id_w = max(len(s["subnet_id"]) for s in _available_subnets)
                _sn_cidr_w = max(len(s["cidr"]) for s in _available_subnets)
                _sn_az_w = max(len(s["az"]) for s in _available_subnets)
                _subnet_choices = [
                    Choice(
                        title=(
                            f"{s['subnet_id']:<{_sn_id_w}}  {s['cidr']:<{_sn_cidr_w}}  {s['az']:<{_sn_az_w}}  {s['name']}"
                            if s["name"]
                            else f"{s['subnet_id']:<{_sn_id_w}}  {s['cidr']:<{_sn_cidr_w}}  {s['az']}"
                        ),
                        value=f"{s['subnet_id']},{s['az']}",
                    )
                    for s in _available_subnets
                ]

                while True:
                    install_parameters["public_subnets"] = questionary.checkbox(
                        _("Select at least 2 public subnets:"),
                        choices=_subnet_choices,
                        style=constants.EDH_STYLE,
                    ).unsafe_ask()
                    if len(install_parameters["public_subnets"]) >= 2:
                        break
                    logger.error("You must select at least 2 public subnets.")
                logger.debug(
                    f"User specified public subnets: {install_parameters['public_subnets']}"
                )

                _remaining_choices = [
                    c
                    for c in _subnet_choices
                    if c.value not in install_parameters["public_subnets"]
                ]

                while True:
                    install_parameters["private_subnets"] = questionary.checkbox(
                        _("Select at least 2 private subnets:"),
                        choices=_remaining_choices,
                        style=constants.EDH_STYLE,
                    ).unsafe_ask()
                    if len(install_parameters["private_subnets"]) >= 2:
                        break
                    logger.error("You must select at least 2 private subnets.")
                logger.debug(
                    f"User specified private subnets: {install_parameters['private_subnets']}"
                )

        if not install_parameters.get("fs_apps_provider"):
            install_parameters["fs_apps_provider"] = questionary.select(
                _(
                    "Select the filesystem provider for /apps (where applications will be installed):"
                ),
                choices=[
                    Choice(title=e.value, value=e.value) for e in FilesystemProvider
                ],
                style=constants.EDH_STYLE,
            ).unsafe_ask()
            logger.debug(
                f"User specified filesystem provider for /apps: {install_parameters['fs_apps_provider']}"
            )

        if not install_parameters.get("fs_data_provider"):
            install_parameters["fs_data_provider"] = questionary.select(
                _(
                    "Select the filesystem provider for /data (where user data will be stored):"
                ),
                choices=[
                    Choice(title=e.value, value=e.value) for e in FilesystemProvider
                ],
                style=constants.EDH_STYLE,
            ).unsafe_ask()
            logger.debug(
                f"User specified filesystem provider for /data: {install_parameters['fs_data_provider']}"
            )

        # Validate the parameters
        try:
            logger.debug(install_parameters)
            with spinner("Validating parameters ..."):
                params = InstallParameters(
                    create_es_service_role=install_parameters.get(
                        "create_es_service_role"
                    ),
                    partition=install_parameters.get("partition"),
                    region=install_parameters.get("region"),
                    base_os=install_parameters.get("base_os"),
                    cluster_name=install_parameters.get("cluster_name"),
                    email_address=install_parameters.get("email_address"),
                    bucket=install_parameters.get("bucket"),
                    ssh_keypair=install_parameters.get("ssh_keypair"),
                    vpc_cidr=install_parameters.get("vpc_cidr"),
                    vpc_id=install_parameters.get("vpc_id"),
                    client_ip=install_parameters.get("client_ip"),
                    fs_apps_provider=install_parameters.get("fs_apps_provider"),
                    fs_data_provider=install_parameters.get("fs_data_provider"),
                    public_subnet_ids=install_parameters.get("public_subnets"),
                    private_subnet_ids=install_parameters.get("private_subnets"),
                    os_domain=install_parameters.get("os_domain"),
                    tls_certificate=install_parameters.get("tls_certificate"),
                )
                console.print(
                    "\n[#00cc66]:white_check_mark: Parameters validated, continuing installation ... [/]\n"
                )

        except ValidationError as err:
            # Cluster-name collision: surface a clean, actionable message + the
            # existing edh-* stack names, not the raw pydantic errors.pydantic.dev dump.
            if "already exists in" in str(err):
                _region = install_parameters.get("region")
                logger.error(
                    f"A CloudFormation stack named {install_parameters.get('cluster_name')!r} "
                    f"already exists in {_region}. Choose a different --cluster-name."
                )
                try:
                    _existing = InstallParameters.list_existing_cluster_stacks(_region)
                    if _existing:
                        logger.error(
                            "Existing EDH cluster stacks in this region: "
                            + ", ".join(_existing)
                        )
                except Exception:
                    pass
                sys.exit(1)
            logger.error(f"Parameter validation error: {err}")
            sys.exit(1)

        _mirror_cfg = (
            _get_install_properties.get("Config", {})
            .get("services", {})
            .get("resources_mirroring", {})
        )
        if not _mirror_cfg:
            logger.error("resources_mirroring section not found in config file.")
            sys.exit(1)

        _mirror_method = _mirror_cfg.get("method")
        # only print the message if the mirroring is enabled and the method is default
        if _mirror_method not in [
            "cloud-no-vpc",
            "cloud-in-vpc-nat",
            "install-host",
            "ask",
        ]:
            logger.error(
                f"Invalid resources_mirroring.method '{_mirror_method}' in config file. "
                f"Valid values are: cloud-no-vpc, cloud-in-vpc-nat, install-host, ask. "
            )
            sys.exit(1)
        if _mirror_cfg.get("enabled") is True:
            if _mirror_method == "ask":
                _mirror_choice = questionary.select(
                    _(
                        "EDH download required external resources (Python, DCV, EFA, GPU drivers, etc.) from trusted sources such as python.org, github.com, nodejs.org, efa-installer.amazonaws.com.\n"
                        "  You can mirror these resources to your own in-account S3 bucket so EDH nodes download from S3 instead of the internet.\n"
                        "  This is recommended for reliability and faster provisioning.\n"
                        "  All external resources can be found on {config_file}, section 'Parameters'.\n"
                        "  How would you like to handle external resources (~5GB)?"
                    ).format(config_file=args.config),
                    choices=[
                        Choice(
                            title=_(
                                "Mirror resources to S3 automatically via Lambda (running in EDH VPC) at install time (Recommended)"
                            ),
                            value="cloud-in-vpc-nat",
                        ),
                        Choice(
                            title=_(
                                "Mirror resources to S3 automatically via Lambda (not running in VPC) at install time"
                            ),
                            value="cloud-no-vpc",
                        ),
                        Choice(
                            title=_(
                                "Mirror resources to S3 via this host (download+upload) before deploying EDH"
                            ),
                            value="install-host",
                        ),
                        Choice(
                            title=_(
                                "No S3 Mirroring (EDH nodes will download from the internet directly)"
                            ),
                            value="skip",
                        ),
                    ],
                    style=constants.EDH_STYLE,
                    default="cloud-in-vpc-nat",
                ).unsafe_ask()
                if _mirror_choice == "skip":
                    _get_install_properties["Config"]["services"][
                        "resources_mirroring"
                    ]["enabled"] = False
                else:
                    _get_install_properties["Config"]["services"][
                        "resources_mirroring"
                    ]["method"] = _mirror_choice

            if (
                _get_install_properties["Config"]["services"]["resources_mirroring"][
                    "method"
                ]
                == "install-host"
            ):
                # download+upload via this host now and
                # rewrite the Parameters section in-place to the S3 mirror (pre-deploy).
                _get_install_properties["Parameters"] = resources_mirroring(
                    parameters=_get_install_properties.get("Parameters", {}),
                    s3_bucket=install_parameters.get("bucket"),
                    cluster_name=install_parameters.get("cluster_name"),
                    s3_client=client_s3,
                    spinner=spinner,
                )
            else:
                # Cloud path (D9-D16, Model C): generate the manifest, seed it to S3,
                # and let CDK deploy the SFN/Lambda mirror executor which runs at
                # install via the custom-resource trigger. The executor is the SOLE
                # writer of the mirrored SSM keys, so we exclude them from BulkSSMWriter.
                _cluster = install_parameters.get("cluster_name")
                _bucket = install_parameters.get("bucket")
                from helpers.installer.manifest_generator import (
                    generate_manifest,
                    write_manifest_to_s3,
                )

                try:
                    _loc = client_s3.get_bucket_location(
                        Bucket=install_parameters.get("bucket")
                    ).get("LocationConstraint")
                    _bucket_region = _loc or "us-east-1"
                except Exception as _err:
                    logger.warning(
                        f"Could not probe region for s3://{install_parameters.get("bucket")}: {_err}; "
                        f"falling back to install region."
                    )
                    _bucket_region = install_parameters["region"]

                _mirror_s3 = build_boto3_client(
                    service_name="s3",
                    region_name=_bucket_region,
                    aws_profile=_aws_profile,
                )
                with spinner(message=_("Generating resource mirror manifest ...")):
                    _items = generate_manifest(
                        parameters=_get_install_properties.get("Parameters", {}),
                        cluster_name=_cluster,
                        ssm_prefix=f"/edh/{_cluster}",
                        mirror_s3_sources=_mirror_cfg.get(
                            "mirror_s3_sources", True
                        ),
                        mirror_gpu_nvidia=_mirror_cfg.get(
                            "mirror_gpu_nvidia", True
                        ),
                        mirror_gpu_amd=_mirror_cfg.get("mirror_gpu_amd", False),
                        s3_client=_mirror_s3,
                    )
                    write_manifest_to_s3(
                        _items,
                        _mirror_s3,
                        _bucket,
                        f"{_cluster}/resources_mirroring/manifest.json",
                    )
                # Model C: keys the mirror executor will own (exclude from BulkSSMWriter).
                _excluded = sorted(
                    {it["config_key"] for it in _items if it.get("config_key")}
                )
                _mirror_cfg["excluded_ssm_keys"] = _excluded
                _mirror_cfg["bucket_region"] = _bucket_region
                _get_install_properties.setdefault("Config", {}).setdefault(
                    "services", {}
                )["resources_mirroring"] = _mirror_cfg
                logger.info(
                    f"Resource mirror ({_mirror_method}): seeded manifest "
                    f"({len(_items)} items) to s3://{_bucket}/{_cluster}/"
                    f"resources_mirroring/manifest.json; excluded {len(_excluded)} "
                    f"SSM keys from BulkSSMWriter; bucket_region={_bucket_region}"
                )
        else:
            _rm_cfg = (
                _get_install_properties.setdefault("Config", {})
                .setdefault("services", {})
                .setdefault("resources_mirroring", {})
            )
            _rm_cfg["enabled"] = False
            logger.info(
                "Resource mirror: Skip selected; setting "
                "Config.services.resources_mirroring.enabled=false "
                "(no manifest seeded, so the cloud trigger is not deployed)."
            )

        # Prepare CDK input
        # Convert some input with special characters to base64 as we will invoke CDK via the CLI
        install_parameters["client_ip"] = base64.b64encode(
            str(install_parameters["client_ip"]).encode("utf-8")
        ).decode("utf-8")
        if install_parameters.get("client_ipv6"):
            install_parameters["client_ipv6"] = base64.b64encode(
                str(install_parameters["client_ipv6"]).encode("utf-8")
            ).decode("utf-8")
        install_parameters["email_address"] = base64.b64encode(
            str(install_parameters["email_address"]).encode("utf-8")
        ).decode("utf-8")
        install_parameters["install_properties"] = base64.b64encode(
            json.dumps(_get_install_properties).encode("utf-8")
        ).decode("utf-8")

        if install_parameters["public_subnets"] is not None:
            install_parameters["public_subnets"] = base64.b64encode(
                json.dumps(install_parameters["public_subnets"]).encode("utf-8")
            ).decode("utf-8")

        if install_parameters["private_subnets"] is not None:
            install_parameters["private_subnets"] = base64.b64encode(
                json.dumps(install_parameters["private_subnets"]).encode("utf-8")
            ).decode("utf-8")

        logger.debug(
            f"Install Parameters sent to CDK: {json.dumps(install_parameters, indent=2, default=str)}"
        )

        # Begin CDK installation
        _cdk_common_args: str = (
            f"--output cdk.out/{install_parameters['cluster_id']}/{install_parameters['region']}"
        )

        _cdk_table = Table(
            show_header=False,
            expand=True,
            padding=(0, 1),
        )
        _cdk_table.add_column("Setting", style="bold #8a9bb8", no_wrap=True)
        _cdk_table.add_column("Value", style="#e8eef7")

        _cdk_table.add_row(
            "CDK Output Directory",
            f"cdk.out/{install_parameters["cluster_name"]}/{install_parameters['region']}",
        )

        if args.cdk_cloudformation_execution_policies:
            for _policy in args.cdk_cloudformation_execution_policies:
                _cdk_common_args += f" --cloudformation-execution-policies {_policy}"
            _cdk_table.add_row(
                "Execution Policies", ", ".join(args.cdk_cloudformation_execution_policies)
            )

        if args.cdk_role_arn:
            _cdk_common_args += f" --role-arn {args.cdk_role_arn}"
            _cdk_table.add_row("Role ARN", args.cdk_role_arn)

        if args.cdk_bootstrap_kms_key_id:
            _cdk_common_args += (
                f" --bootstrap-kms-key-id {args.cdk_bootstrap_kms_key_id}"
            )
            _cdk_table.add_row("Bootstrap KMS Key", args.cdk_bootstrap_kms_key_id)

        if args.cdk_custom_permissions_boundary:
            _cdk_common_args += (
                f" --custom-permissions-boundary {args.cdk_custom_permissions_boundary}"
            )
            _cdk_table.add_row(
                "Permissions Boundary", args.cdk_custom_permissions_boundary
            )

        # --termination-protection is bootstrap-only (cdk deploy rejects it); app-stack protection comes from the Stack construct. Applied to cmd_bootstrap below.
        _cdk_table.add_row("Termination Protection", "[#00cc66]Enabled[/]")

        if args.cdk_debug:
            _cdk_common_args += " --debug -v -v -v"
            _cdk_table.add_row("Debug Mode", "[#00cc66]Enabled[/]")

        if args.cdk_profile:
            _cdk_common_args += f" --profile {args.cdk_profile}"
            _cdk_table.add_row("Profile", args.cdk_profile)

        if args.cdk_no_strict:
            _cdk_table.add_row("Strict Mode", "[#ff6b6b]Disabled[/]")
        else:
            _cdk_common_args += " --strict"
            _cdk_table.add_row("Strict Mode", "[#00cc66]Enabled[/]")

        if args.cdk_cmd in ["create", "update"]:
            cdk_cmd = "deploy"
        else:
            cdk_cmd = args.cdk_cmd

        # CDK deployment method only applies to deploy operations. Default
        # is 'direct' (no ChangeSet) -- faster and avoids the known
        # ChangeSet-progress-bar denominator artifact for stacks with
        # >100 resources. SOCA references existing AWS resources via
        # synth-time lookups (Vpc.from_lookup etc.), which are unaffected
        # by the deploy method. Override with --cdk-method change-set if
        # you need a CFN change set audit record, want to preview
        # replacement risk, or are using cdk deploy --import-existing-resources.
        if cdk_cmd == "deploy":
            _cdk_common_args += f" --method {args.cdk_method}"
            _cdk_table.add_row(
                "Deployment Method",
                f"[#00cc66]{args.cdk_method}[/]"
                + (" [dim](no ChangeSet)[/]" if args.cdk_method == "direct" else ""),
            )

        console.print()
        console.print(
            Panel(
                _cdk_table,
                title="[bold #e8eef7]AWS Cloud Development Kit (CDK) Settings[/]",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        console.print()

        cmd = f"cdk {cdk_cmd} {_cdk_common_args} -c {' -c '.join('{}={}'.format(key,val) for (key,val) in install_parameters.items() if val is not None)} --require-approval never"
        cmd_bootstrap = f"cdk bootstrap --termination-protection {_cdk_common_args} aws://{install_parameters['account_id']}/{install_parameters['region']} -c {' -c '.join('{}={}'.format(key,val) for (key,val) in install_parameters.items() if val is not None)}"

        # Log command in history book
        with open("installer_history.txt", "a+") as f:
            f.write(f"""\n==== [{datetime.datetime.now(datetime.UTC)}] ====
    {cmd}
    {str(install_parameters)}
    =============================""")

        # First, Bootstrap the environment. This will create a staging S3 bucket if needed
        with spinner(message=_("Bootstrapping CDK environment ...")):
            stream_subprocess(console=console, command=cmd_bootstrap)

        # Increase SSM Throughput if needed (https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-throughput.html)
        # Settings will be restored if needed post deployment
        disable_ssm_high_throughput_post_install: bool = False

        # Upload required assets to customer S3 account
        if cdk_cmd == "deploy":
            with spinner(
                message=f"Uploading required S3 objects to {install_parameters['bucket']}"
            ):
                upload_objects(
                    s3_client=client_s3_resource,
                    install_directory=_install_directory,
                    bucket=install_parameters["bucket"],
                    cluster_id=install_parameters["cluster_id"],
                    region=install_parameters["region"],
                )

            with spinner(message=_("Enabling SSM High Throughput mode ...")):
                _check_ssm_high_throughput = client_ssm.get_service_setting(
                    SettingId="/ssm/parameter-store/high-throughput-enabled"
                )

                if (
                    _check_ssm_high_throughput.get("ServiceSetting").get("SettingValue")
                    == "false"
                ):
                    logger.warning(
                        "Temporarily enabling /ssm/parameter-store/high-throughput-enabled for EDH deployment"
                    )
                    # try/catch
                    # Validate the update
                    client_ssm.update_service_setting(
                        SettingId="/ssm/parameter-store/high-throughput-enabled",
                        SettingValue="true",
                    )
                    disable_ssm_high_throughput_post_install = True

        # Then launch the actual EDH installer
        console.print()
        console.print(
            Panel(
                "Starting EDH Deployment, launching CDK ... ",
                border_style="cyan",
                style="bold #e8eef7",
            )
        )
        console.print()
        launch_installer = os.system(cmd)  # nosec

        if cdk_cmd == "deploy":
            # Optional - Re-enable SSM default
            if disable_ssm_high_throughput_post_install:
                logger.warning(
                    "Restoring /ssm/parameter-store/high-throughput-enabled to its previous value post-deployment"
                )
                try:
                    client_ssm.update_service_setting(
                        SettingId="/ssm/parameter-store/high-throughput-enabled",
                        SettingValue="false",
                    )
                except Exception as e:
                    logger.error(
                        f"Unable to restore /ssm/parameter-store/high-throughput-enabled setting to false. Error: {e}"
                    )

            if int(launch_installer) == 0:
                # EDH is installed. We will now wait until EDH is fully configured (when the ELB returns HTTP 200)
                console.print()
                console.print(
                    Panel(
                        "🎉 [bold green]EDH was deployed successfully on your AWS account! Please allow up to 30 minutes for EDH to be fully configured and accessible.[/bold green]",
                        border_style="green",
                        padding=(1, 2),
                    )
                )
                console.print()

                if _get_install_properties.get("Config", {}).get(
                    "directoryservice", {}
                ).get("provider", "") not in [
                    "existing_openldap",
                    "existing_active_directory",
                ]:
                    with spinner(
                        message=_(
                            "Retrieving EDH Admin credentials from AWS Secrets Manager ..."
                        )
                    ):
                        _get_admin_password = retrieve_secret_value(
                            secretsmanager_client=client_secretsmanager,
                            secret_id=f"/edh/{install_parameters['cluster_id']}/EDHAdminUser",
                        )

                    info_table = Table(show_header=False, box=None, padding=(0, 2))
                    info_table.add_column(style="#8a9bb8", no_wrap=True)
                    info_table.add_column(style="#e8eef7")
                    info_table.add_row(
                        "Default Username",
                        _get_admin_password.get("username"),
                    )
                    info_table.add_row(
                        "Default Password",
                        _get_admin_password.get("password"),
                    )
                    console.print(
                        Panel(
                            info_table,
                            title="[bold #e8eef7]EDH Default Admin Credentials[/]",
                            border_style="cyan",
                            padding=(1, 4),
                        )
                    )
                    console.print()
                    console.print(
                        Panel(
                            "⏳ [bold #ffcc00]EDH is not ready yet.[/bold #ffcc00]\n\n"
                            "The deployment is still being configured in the background. Please note this can take up to 30 minutes, depending on your EDH configuration and services enabled.\n"
                            "Please wait until the process below confirms that EDH is fully ready before attempting to log in.",
                            border_style="#ffcc00",
                            padding=(1, 2),
                        )
                    )
                    console.print()

                else:
                    logger.info(
                        f"[bold #ffcc00]Using an existing Active Directory or OpenLDAP. Use an existing user to log in."
                    )

                # Post-install resource mirror report (cloud mirror path only).
                # Rendered here -- right after the admin-credentials section and
                # BEFORE the readiness/endpoint-probe loop -- so the mirror summary
                # is visible immediately rather than gated behind the ~30 min probe.
                # Placed at the new-admin/existing-AD convergence so it shows on both.
                if (
                    _mirror_cfg.get("enabled") is True
                    and _mirror_cfg.get("method") != "install-host"
                ):
                    try:
                        from helpers.installer.mirror_report import (
                            render_mirror_report,
                        )

                        render_mirror_report(
                            mirror_bucket=install_parameters.get("bucket"),
                            prefix=f"{install_parameters.get('cluster_name')}/resources_mirroring/",
                            region=(
                                _mirror_cfg.get("bucket_region")
                                or install_parameters["region"]
                            ),
                            console=console,
                        )
                    except Exception as _rep_err:
                        logger.warning(f"Mirror report skipped: {_rep_err}")

                try:
                    check_cfn = client_cloudformation.describe_stacks(
                        StackName=install_parameters["cluster_id"]
                    )
                    if args.format == "json":
                        with open(
                            f"{install_parameters['cluster_id']}.output", "w"
                        ) as outfile:
                            json.dump(check_cfn["Stacks"][0]["Outputs"], outfile)

                    for output in check_cfn["Stacks"][0]["Outputs"]:
                        if output["OutputKey"] == "WebUserInterface":
                            _edh_endpoint_url = output["OutputValue"]
                            # Run a first check to determine if client IP provided by the customer is valid
                            try:
                                get(
                                    f"{output['OutputValue']}", verify=False, timeout=35
                                )  # nosec
                            except Timeout:
                                # We cannot log the IP here as it is now a b64-list by this point and it may get large
                                # Or we are in MPL mode. So we just tell the user to go to the console to fix the issue.
                                logger.warning(
                                    f"Unable to connect to the EDH endpoint URL {_edh_endpoint_url}. Maybe your IP is not valid/has changed (maybe you are behind a proxy?). If that's the case please go to AWS console and authorize your real IP address on the ALB and NLB Security Groups / Prefix-Lists to access EDH"
                                )
                                sys.exit(1)
                            except ConnectionError as e:
                                logger.warning(
                                    f"Encountered ConnectionError. Unable to connect to the EDH endpoint URL {_edh_endpoint_url}. Error: {e} "
                                )
                                sys.exit(1)
                            except ConnectionRefusedError as e:
                                logger.warning(
                                    f"Encountered ConnectionRefusedError. Unable to connect to the EDH endpoint URL {_edh_endpoint_url}. Error: {e} "
                                )
                                sys.exit(1)

                            soca_check_loop = 0
                            if install_parameters["vpc_id"]:
                                # EDH deployment is shorter when using existing resources, so we increase the timeout
                                max_check_loop = 15
                            else:
                                max_check_loop = 10
                            # print(f"DEBUG - Starting Endpoint check loop - MaxCheckLoop: {max_check_loop}")

                            with spinner(
                                message=_(
                                    "Waiting for EDH to be fully configured, this can take up to 30 minutes ..."
                                )
                            ):
                                # Inline check helper: any transient network
                                # error during the wait (Timeout, ConnectionError,
                                # ConnectionRefusedError) is treated as "not
                                # ready yet" -- we sleep and retry instead of
                                # crashing the installer. Bootstrap intentionally
                                # restarts uwsgi several times during 03_setup;
                                # a 15s read timeout during one of those restarts
                                # is normal, not fatal.
                                def _endpoint_ready(_url: str) -> bool:
                                    try:
                                        return (
                                            get(
                                                _url, verify=False, timeout=15
                                            ).status_code
                                            == 200
                                        )  # nosec
                                    except (
                                        Timeout,
                                        ConnectionError,
                                        ConnectionRefusedError,
                                    ) as _err:
                                        logger.info(
                                            f"⏳ Transient {type(_err).__name__} polling {_url} -- treating as not ready, will retry."
                                        )
                                        return False
                                    except Exception as _err:
                                        logger.warning(
                                            f"Unexpected error polling {_url}: {_err} -- treating as not ready, will retry."
                                        )
                                        return False

                                while (
                                    not _endpoint_ready(_edh_endpoint_url)
                                    and soca_check_loop <= max_check_loop
                                ):
                                    logger.info(
                                        "⏳  EDH environment not ready yet, waiting for bootstrap sequence to complete. Checking again in 300 seconds ... "
                                    )
                                    time.sleep(300)
                                    soca_check_loop += 1
                                    if soca_check_loop >= max_check_loop:
                                        logger.warning(
                                            f"Could not determine if EDH is ready after {max_check_loop*2} minutes. Connect to the system via SSM and check the logs. "
                                        )
                                        sys.exit(1)

                            # at this point EDH Web UI is fully operational, however the user creation will happen within the next 20 to 40 seconds.
                            # Adding extra delay to be sure the user is created and customer can click and login.
                            with spinner(
                                message=_(
                                    "Waiting for EDH Admin user to be created ..."
                                )
                            ):
                                logger.info(
                                    "⏳  EDH environment not ready yet, waiting for default EDH Admin user to be created. Checking again in 120 seconds ... "
                                )
                                time.sleep(120)
                            console.print("\n")
                            console.print(
                                Panel(
                                    f"[bold green]✅ Your EDH environment is ready![/]\n"
                                    f"\n"
                                    f"🌐 Login URL:   [bold underline #4db8ff]{_edh_endpoint_url}[/]\n"
                                    f"\n"
                                    f"👤 Username:    [bold white]{_get_admin_password.get('username')}[/]\n"
                                    f"🔑 Password:    [bold white]{_get_admin_password.get('password')}[/]\n",
                                    title="[bold #e8eef7]🚀 EDH Deployment Complete[/]",
                                    border_style="#00cc66",
                                    padding=(1, 4),
                                )
                            )

                except ValidationError:
                    logger.error(
                        f"{install_parameters['cluster_id']} is not a valid cloudformation stack"
                    )
                except ClientError as err:
                    logger.error(
                        f"Unable to retrieve {install_parameters['cluster_id']} stack outputs, probably due to a permission error (your IAM account do not have permission to run cloudformation:Describe*. Log in to AWS console to view your stack connection endpoints"
                    )

        elif args.cdk_cmd == "destroy":
            # Destroy stack if known
            cmd_destroy = f"cdk destroy {install_parameters['cluster_id']} -c {' -c '.join('{}={}'.format(key, val) for (key, val) in install_parameters.items() if val is not None)} --require-approval never"
            logger.info(f"Deleting stack, running {cmd_destroy}")
            delete_stack = os.system(cmd_destroy)  # nosec
        else:
            # synth, ls etc.
            pass
            # console.print(params.model_dump_json(indent=2))

    except KeyboardInterrupt:
        console.print("\n" + _("[red] Installation cancelled.[/red]"))

    except Exception as err:
        tb = traceback.extract_tb(err.__traceback__)[-1]
        logger.error(f"{err} ({tb.filename}:{tb.lineno} in {tb.name})")
        sys.exit(1)
