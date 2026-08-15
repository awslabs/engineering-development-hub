# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import boto3
import sys
import os
import datetime
import time
import ipaddress
import shlex
import ast
import shutil
import re
import logging
import os
import sys
import yaml
import subprocess
import json
import tempfile
import shutil
import ssl
import urllib.request
from urllib.parse import urlparse
import hashlib
from pydantic import ValidationError
from typing import Annotated, Optional
from pathlib import Path
from botocore.client import ClientError
from botocore import config
from shutil import make_archive
from botocore.client import ClientError
from botocore import config
from requests import get, RequestException
from typing import Literal
from yaml.scanner import ScannerError
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.logging import RichHandler
from . import constants as install_constants
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger("soca_logger")


class CustomFormatter(logging.Formatter):
    def format(self, record):
        if not isinstance(record.msg, (Text, Table)):
            style, label = install_constants.EDH_LOG_STYLES.get(
                record.levelno, ("#e8eef7", "")
            )
            prefix = f"{label}: " if label and record.levelno >= logging.WARNING else ""
            record.msg = f"[{style}]{prefix}{record.msg}[/{style}]"

        return super().format(record)


def stream_subprocess(console: Console, command: str):
    process = subprocess.Popen(
        shlex.split(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for line in process.stdout:
        console.print(
            line, end="", markup=False, highlight=False
        )  # Let Rich render ANSI
    process.wait()

    if process.returncode != 0:
        sys.exit(process.returncode)


def build_logger(console: Console | None = None):
    _soca_debug = os.environ.get("EDH_DEBUG", os.environ.get("SOCA_DEBUG", "0"))
    if _soca_debug == "1":
        _log_level = logging.DEBUG
        _formatter = CustomFormatter("[%(asctime)s] %(levelname)s - %(message)s")
    else:
        _log_level = logging.INFO
        _formatter = CustomFormatter("%(message)s")

    _rich_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        markup=True,
        show_time=False,
        show_level=False,
        show_path=False,
    )
    _rich_handler.setFormatter(_formatter)
    logging.basicConfig(
        level=_log_level,
        handlers=[_rich_handler],
    )

    logger = logging.getLogger("soca_logger")
    logger.success = lambda msg, *a, **kw: logger.log(
        install_constants.SUCCESS, msg, *a, **kw
    )

    for _logger_name in ["boto3", "botocore"]:
        logging.getLogger(_logger_name).setLevel(
            logging.DEBUG if _soca_debug in {"trace", "2"} else logging.WARNING
        )

    return logger


def get_sts_info(aws_profile: Optional[str] = None) -> dict:
    if aws_profile:
        session = boto3.session.Session(profile_name=aws_profile)
    else:
        session = boto3.session.Session()

    try:
        _sts_client = session.client("sts")
        _sts_caller_identity = _sts_client.get_caller_identity()

    except ClientError as e:
        logger.error(
            f"boto3 was unable to validate STS: {e}. \n\n Please verify if you have AWS_DEFAULT_REGION set via env variable or in your ~/.aws/credentials or ~/.aws/config files"
        )
        sys.exit(1)
    except Exception as e:
        logger.error(f"General Error: Unable to validate AWS credentials via STS: {e}")
        sys.exit(1)

    _sts_caller_arn = _sts_caller_identity.get("Arn", "")
    _sts_caller_account = _sts_caller_identity.get("Account", "")
    _sts_partition = ""

    if not _sts_caller_arn:
        logger.error("Unable to determine AWS partition via STS. Exiting...")
        sys.exit(1)

    if not _sts_caller_account:
        logger.error("Unable to determine AWS AccountID via STS. Exiting...")
        sys.exit(1)

    try:
        _sts_partition = _sts_caller_arn.split(":")[1]
    except IndexError as err:
        logger.error(
            f"Unable to determine AWS partition via STS. Error: {err}. Exiting..."
        )
        sys.exit(1)

    logger.debug(f"STS-discovered caller ARN: {_sts_caller_arn}")
    logger.debug(f"STS-discovered AWS partition: {_sts_partition}")
    logger.debug(f"STS-discovered AWS account ID: {_sts_caller_account}")
    # Surface the validated partition on the identity dict. STS GetCallerIdentity does
    # NOT return a "Partition" key (only UserId/Account/Arn), so callers that read
    # .get("Partition") would otherwise get None. Derived-from-ARN + fail-fast above
    # guarantees a real value here (aws | aws-cn | aws-us-gov).
    _sts_caller_identity["Partition"] = _sts_partition
    return _sts_caller_identity


def build_boto3_client(
    service_name: str,
    region_name: str,
    resource: bool = False,
    aws_profile: Optional[str] = None,
) -> boto3.session.Session.client:
    """
    Build a boto3 client/resource for the given service + region.

    Delegates to the canonical shared-session helper in
    ``helpers.boto3_wrapper`` so all installer call sites share a
    single cached ``boto3.session.Session`` per profile -- avoiding
    repeated credential-provider-chain invocations.

    Behaviour is gated by the ``SOCA_BOTO3_SHARED_SESSION`` env var;
    see ``helpers.boto3_wrapper`` for details.
    """

    # Import locally so existing circular-import-sensitive callers
    # aren't forced to drag the wrapper module into their import chain.
    from helpers.boto3_wrapper import (
        get_shared_session,
        _session_was_hit,
        _use_shared_session,
    )

    logger.debug(
        f"Building boto3 client for {service_name} in region {region_name} "
        f"with resource={resource}"
    )
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/26.8.0"}
    boto_extra_config = config.Config(**aws_solution_user_agent)

    _t0 = time.monotonic()
    session = get_shared_session(aws_profile)
    _t_session = time.monotonic()

    try:
        if resource:
            _result = session.resource(
                service_name, region_name=region_name, config=boto_extra_config
            )
        else:
            _result = session.client(
                service_name, region_name=region_name, config=boto_extra_config
            )
    except Exception as e:
        logger.error(f"Error occurred while building boto3 client: {e}")
        sys.exit(1)

    _t_done = time.monotonic()
    logger.debug(
        f"boto3 build timing: service={service_name} "
        f"resource={resource} "
        f"session={'shared' if _use_shared_session() else 'fresh'} "
        f"{'(hit)' if _session_was_hit(aws_profile) else '(miss)'} "
        f"session_ms={(_t_session - _t0) * 1000:.0f} "
        f"client_ms={(_t_done - _t_session) * 1000:.0f} "
        f"total_ms={(_t_done - _t0) * 1000:.0f}"
    )
    return _result


# Legacy compatibility shim. The shared-session cache lives in
# helpers.boto3_wrapper now; these module-level names are preserved
# so any external caller that imported them directly continues to
# work (previously they were populated by an inlined implementation
# of the cache -- we now proxy to the canonical location).
def _get_shared_session(aws_profile: Optional[str]) -> boto3.session.Session:
    """Deprecated alias -- use helpers.boto3_wrapper.get_shared_session."""
    from helpers.boto3_wrapper import get_shared_session

    return get_shared_session(aws_profile)


def get_default_region(sts_partition: str) -> str:
    default_region = None
    match sts_partition:
        case "aws":
            default_region = "us-east-1"
        case "aws-us-gov":
            default_region = "us-gov-west-1"
        case "aws-cn":
            default_region = "cn-north-1"
        case "aws-eusc":
            default_region = "eusc-de-east-1"
        case _:
            default_region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    if not default_region:
        logger.error("Unable to determine default region. Exiting...")
        sys.exit(1)

    logger.debug(f"Default region for partition {sts_partition} is {default_region}")
    return default_region


def kms_prepare_account_aliases(client: boto3.session) -> int:
    """
    Query KMS for existing key AWS service aliases and create them if they don't exist.
    """
    logger.debug("Preparing KMS account aliases")
    _aliases_created: int = 0
    _aliases_existing: int = 0

    try:
        # Get all existing aliases
        _kms_paginator = client.get_paginator("list_aliases")
        _kms_iterator = _kms_paginator.paginate()
        for _kms_aliases in _kms_iterator:
            for _alias in _kms_aliases.get("Aliases", []):

                _a_name: str = _alias.get("AliasName", "")

                # We are only concerned about AWS namespace alias that act as defaults for services
                if not _a_name.startswith("alias/aws/"):
                    logger.debug(
                        f"Ignoring KMS alias as it is not related to a service: {_a_name}"
                    )
                    continue

                # IndexError potential
                _a_servicename: str = _a_name.split("/")[-1]
                _a_create: datetime.datetime = _alias.get("CreationDate")

                if _a_create is None:
                    logger.info(
                        f"KMS - Creating first-time service alias for {_a_servicename} ({_a_name})"
                    )
                    client.describe_key(KeyId=_a_name)
                    _aliases_created += 1
                else:
                    logger.debug(
                        f"KMS Alias for service {_a_servicename} ({_a_name}) already exists"
                    )
                    _aliases_existing += 1
                continue

    except ClientError as _err:
        logger.error(f"Unable to create KMS service alias: {_err}")
        sys.exit(1)
    except Exception as _err:
        logger.error(f"Unable to create KMS service alias: {_err}")
        sys.exit(1)

    # For the list of services that do not appear in the list_aliases until they are created
    for _alias_name in ["alias/aws/sns"]:
        logger.debug(f"KMS - Checking service alias for {_alias_name}")
        _key = client.describe_key(KeyId=_alias_name).get("KeyMetadata", {})
        if not _key:
            logger.error(f"Unable to lookup KMS service alias: {_alias_name}")
            sys.exit(1)
        _key_id: str = _key.get("KeyId", "")
        _key_manager: str = _key.get("KeyManager", "")
        if not _key_id:
            logger.error(f"Unable to create KMS service alias: {_alias_name}")
            sys.exit(1)

        logger.debug(
            f"Service default KMS key: {_alias_name}: {_key_id} / {_key_manager=}"
        )

    logger.debug(
        f"KMS service aliases created: {_aliases_created} / Existing: {_aliases_existing}"
    )
    return _aliases_created


def is_valid_address(address_family: Literal["ipv4", "ipv6"], address: list) -> bool:
    """
    Determine if an address (list) is a valid member of the desired address-family.
    """

    _invalid: bool = False

    if isinstance(address, str):
        logger.debug(f"Fixing address to list of addresses")
        address = [address]

    for _address in address:
        try:
            logger.debug(f"Determining if {_address=} is valid for {address_family=}")
            _ip_object = (
                ipaddress.IPv4Network(_address)
                if address_family == "ipv4"
                else ipaddress.IPv6Network(_address)
            )
        except ipaddress.AddressValueError as _e:
            # We dont care about the details - just that it failed
            logger.debug(f"Exception in IP validation for ({_address}): {_e}")
            _invalid = True

    if _invalid:
        logger.debug(
            f"At least one IP address is valid for {address_family}: {address}"
        )
        return False
    else:
        logger.debug(f"All IP addresses are valid for {address_family}: {address}")
        return True


def aggregate_address(
    address_family: Literal["ipv4", "ipv6"], address: str, mask: int
) -> str:
    """
    Aggregate an IPv4 or IPv6 address to a given mask.
    """
    logger.debug(
        f"aggregate_address - {address_family=} / {address=}  to {mask=} boundary"
    )
    try:
        _addr_tuple: str = f"{address}/{mask}"
        _ip_object = (
            ipaddress.IPv4Network(address=f"{_addr_tuple}", strict=False)
            if address_family == "ipv4"
            else ipaddress.IPv6Network(address=f"{_addr_tuple}", strict=False)
        )
        # Now that we have constructed the _ip_object - it will have our network address and prefixlen
        return f"{_ip_object.network_address}/{_ip_object.prefixlen}"
    except ipaddress.AddressValueError:
        # We dont care about the details - just that it failed
        return ""


def detect_customer_ip(address_family: Literal["ipv4", "ipv6"]) -> str:
    """
    Try to determine the customer IP address by using the checkip.amazonaws.com service.
    """
    logger.debug(f"Determine source IP address - {address_family=}")

    #
    # Our _check_url_by_af contains important configuration items for IP probes.
    #
    # enabled - if we should probe this address-family or not
    # url - the destination we should connect to
    # aggregate_mask_bits - the number of bits that we aggregate.
    # E.g. 32 for IPv4 'host' address (192.0.2.1 - > 192.0.2.1/32)
    # 64 to aggregate IPv6 to the /64 - (2001:db8:26e0:991e:1014:2412:530a:cafe -> 2001:db8:26e0:991e::/64)
    #
    _check_url_by_af: dict = {
        "ipv4": {
            "enabled": True,
            "url": "https://checkip.amazonaws.com/",
            "aggregate_mask_bits": 32,
        },
        "ipv6": {
            "enabled": address_family == "ipv6",
            "url": "https://checkip.global.api.aws",
            "aggregate_mask_bits": 64,
        },
    }

    check_url = _check_url_by_af.get(address_family, {}).get("url", "")
    _mask_bits = _check_url_by_af.get(address_family, {}).get(
        "aggregate_mask_bits", 32 if address_family == "ipv4" else 64
    )
    _af_is_enabled: bool = _check_url_by_af.get(address_family, {}).get(
        "enabled", False
    )

    _formal_af_name: str = str(
        address_family[:2].upper() + address_family[2:]
    )  # IPv4 , IPv6

    if not _af_is_enabled:
        logger.warning(f"Address-family {_formal_af_name} is disabled. Skipping.")
        return ""

    if not check_url:
        logger.fatal(
            f"Unable to determine probe address for address-family: {address_family} . Exiting."
        )
        exit(1)

    logger.debug(
        f"\n====== Trying to detect your {_formal_af_name} address via {check_url} . Use SilentInstall.client_ip in your config file to specify manually if needed ======\n"
    )

    client_ip: str = ""
    _agg_address: str = ""
    try:
        get_client_ip = get(url=check_url, timeout=15)
        if get_client_ip.status_code == 200:
            # Should return a clean string. May still need sanity check

            client_ip = f"{str(get_client_ip.text).strip()}"

            _is_valid_address: bool = is_valid_address(
                address_family=address_family, address=client_ip
            )

            if not _is_valid_address:
                logger.warning(
                    f"Unable to determine validity of address {client_ip} for {_formal_af_name}. "
                    f"Falling back to manual entry."
                )
                return ""

            logger.debug(f"Is Valid {_formal_af_name} Address?: {_is_valid_address}")

            # Now that we know it is valid - lets aggregate it
            _agg_address = aggregate_address(
                address_family=address_family, address=client_ip, mask=_mask_bits
            )
            logger.debug(f"Aggregate {_formal_af_name} address: {_agg_address=}")

        else:
            logger.warning(
                f"Unable to automatically determine {_formal_af_name} client via {check_url} . Error: {get_client_ip}"
            )

    except RequestException as _e:
        logger.warning(
            f"Unable to automatically determine client {_formal_af_name} via {check_url} . Error: {_e}"
        )

    return _agg_address


def get_ami_mapping() -> dict:
    region_map_dir = Path(__file__).resolve().parents[4] / "region_map.d" / "aws"
    mapping: dict = {}

    if not region_map_dir.is_dir():
        logger.error(f"Region map directory not found: {region_map_dir}")
        sys.exit(1)

    for filepath in sorted(region_map_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(filepath.read_text())
        except (ScannerError, FileNotFoundError) as err:
            logger.warning(f"Skipping {filepath.name}: {err}")
            continue

        if not isinstance(data, dict):
            continue

        for region, architectures in data.items():
            if not isinstance(architectures, dict):
                continue
            mapping.setdefault(region, {}).update(architectures)

    return mapping


def get_install_properties(path: str) -> dict:
    # Retrieve SOCA configuration properties
    logger.debug(f"Configuration file path: {path}")
    try:
        with open(path, "r") as config_file:
            config_parameters = yaml.safe_load(config_file)
    except ScannerError as _err:
        logger.error(f"{path} is not a valid YAML file. Verify syntax, {_err}")
        sys.exit(1)
    except FileNotFoundError:
        logger.error(
            f"{path} not found. Make sure the file exist and the path is correct."
        )
        sys.exit(1)

    if config_parameters:
        return config_parameters
    else:
        return {}
        # sys.exit("No parameters were found in configuration file.")


def retrieve_secret_value(secretsmanager_client: boto3.client, secret_id: str) -> dict:
    logger.debug(f"Fetching Secret ID - {secret_id}")
    _get_secret = secretsmanager_client.get_secret_value(SecretId=secret_id).get(
        "SecretString", None
    )
    if _get_secret:
        return ast.literal_eval(_get_secret)
    else:
        logger.error(f"Unable to fetch secret {secret_id}")
        return {}


def format_byte_size(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def upload_objects(
    s3_client: boto3.client, install_directory: str, bucket: str, cluster_id: str, region: str
) -> bool:
    # Upload required assets to customer S3 bucket
    logger.info(f"\n====== Uploading install files to {bucket}/{cluster_id} ======\n")
    dist_directory = f"{install_directory}/../../dist/{cluster_id}/"
    if os.path.isdir(dist_directory):
        logger.info(
            f"{dist_directory} already exist. Creating a new one for your build"
        )
        shutil.rmtree(dist_directory)
    os.makedirs(dist_directory)

    # Move required file to dist/ directory
    make_archive(
        f"{dist_directory}soca", "gztar", f"{install_directory}/../../../source/soca"
    )

    for item in os.listdir(f"{install_directory}/../upload_to_s3/{cluster_id}/{region}/"):
        # Construct full path to item
        s = os.path.join(f"{install_directory}/../upload_to_s3/{cluster_id}/{region}/", item)
        d = os.path.join(f"{dist_directory}/config/do_not_delete/", item)

        # Move each item to the destination
        if os.path.isdir(s):
            shutil.move(s, d)
        else:
            shutil.move(s, d)

    try:
        shutil.rmtree(f"{install_directory}/../upload_to_s3/{cluster_id}/{region}/")
    except Exception as _e:
        logger.error(
            f"Unable to delete {install_directory}/../upload_to_s3/{cluster_id}/{region}/ because of {_e}"
        )
        sys.exit(1)

    try:
        install_bucket = s3_client.Bucket(bucket)
        all_files = []
        for path, subdirs, files in os.walk(f"{dist_directory}"):
            path = path.replace("\\", "/")
            for file in files:
                all_files.append((path, file))

        # upload small files first to trigger the progress bar
        all_files.sort(key=lambda x: os.path.getsize(os.path.join(x[0], x[1])))

        total_files = len(all_files)
        for idx, (path, file) in enumerate(all_files, start=1):
            full_path = os.path.join(path, file)
            find_upload_location = re.search(f"(.+)/dist/{cluster_id}/(.+)", full_path)
            if find_upload_location:
                upload_location = f"{cluster_id}/{find_upload_location.group(2)}"
            else:
                print(
                    f"Unable to determine upload location. {full_path} does not match regex '(.+)/dist/{cluster_id}/(.+)'"
                )
                sys.exit(1)

            pct = int((idx / total_files) * 100)
            bar_len = 30
            filled = int(bar_len * idx // total_files)
            bar = "█" * filled + "░" * (bar_len - filled)
            logger.info(
                f"[{bar}] {pct:>3}% ({idx}/{total_files}) Uploading {file} to s3://{bucket}/{upload_location}"
            )
            install_bucket.upload_file(os.path.join(path, file), upload_location)
        return True
    except Exception as upload_error:
        logger.error(f"Error during upload {upload_error}")
        sys.exit(1)


def build_lambda_dependency(install_directory: str) -> int:
    logger.debug("Building Lambda dependency")
    lambda_functions_folders = f"{install_directory}/../functions/"
    for _dir in os.scandir(lambda_functions_folders):
        if _dir.is_file():
            continue
        for filename in os.listdir(_dir):
            if filename == "requirements.txt":
                logger.debug(f"Installing Python dependencies for {_dir.path}")
                _cmd = [
                    "pip3",
                    "install",
                    "--python-version",
                    f"{os.environ['SOCA_PYTHON_VERSION']}",
                    "-r",
                    f"{_dir.path}/requirements.txt",
                    "--platform",
                    "manylinux2014_x86_64",
                    "--target",
                    f"{_dir.path}",
                    "--implementation",
                    "cp",
                    "--only-binary=:all:",
                    "--upgrade",
                ]
                result = subprocess.run(
                    _cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                if result.returncode != 0:
                    logger.error(f"Error during Lambda Dependency {result}")
                    sys.exit(1)
                else:
                    return 0


def inline_validate_with(model_cls, field: str):
    from pydantic import TypeAdapter

    info = model_cls.model_fields[field]
    adapter = TypeAdapter(
        Annotated[info.annotation, *info.metadata] if info.metadata else info.annotation
    )

    before_validators = []
    for name, v in model_cls.__pydantic_decorators__.field_validators.items():
        if v.info.mode == "before" and (not v.info.fields or field in v.info.fields):
            before_validators.append(getattr(model_cls, name))

    def _validate(value: str) -> bool | str:
        try:
            for fn in before_validators:
                value = fn(value)
            adapter.validate_python(value)
            return True
        except (ValidationError, ValueError) as exc:
            if isinstance(exc, ValueError):
                return str(exc)
            errors = exc.errors()
            msgs = []
            for e in errors:
                ctx = e.get("ctx", {})
                if "error" in ctx:
                    msgs.append(str(ctx["error"]))
                else:
                    msgs.append(e["msg"])
            return "; ".join(dict.fromkeys(msgs))

    return _validate


def check_prefix_list(ec2_client: boto3.client, prefix_list_id: str) -> dict | None:
    try:
        response = ec2_client.describe_managed_prefix_lists(
            PrefixListIds=[prefix_list_id]
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidPrefixListID.NotFound":
            logger.error(f"Prefix list {prefix_list_id} not found.")
            sys.exit(1)
        else:
            logger.error(f"Unable to lookup Prefix List ID: AWS boto3 error: {e}")
            sys.exit(1)
    except Exception as err:
        logger.error(f"Unable to lookup Prefix List ID: generic error: {err}")
        sys.exit(1)

    _pl = response["PrefixLists"][0]
    logger.debug(f"Prefix List ID: {_pl['PrefixListId']}")
    logger.debug(f"Name: {_pl.get('PrefixListName', 'N/A')}")
    logger.debug(f"State: {_pl.get('State', 'N/A')}")
    logger.debugint(f"Address Family: {_pl.get('AddressFamily', None)}")
    logger.debug(f"Max Entries: {_pl.get('MaxEntries', 'N/A')}")
    logger.debug(f"Version: {_pl.get('Version', 'N/A')}")
    logger.debug(f"Owner ID: {_pl.get('OwnerId', 'N/A')}")

    _address_family = _pl.get("AddressFamily", None)
    if not _address_family:
        logger.error(
            f"Unable to determine address family for prefix list {prefix_list_id}: {_pl}"
        )
        sys.exit(1)
    elif _address_family not in ["IPv4", "IPv6"]:
        logger.error(
            f"Unsupported address family {_address_family} for prefix list {prefix_list_id}"
        )
        sys.exit(1)
    else:
        return _pl


def list_acm_certificates(
    acm_client: boto3.client, certificate_arn: Optional[str] = None
) -> list[dict[str, str]]:
    """Return a list of ISSUED ACM certificates in the region.

    Each entry: {domain_name, certificate_arn}.
    If certificate_arn is provided, only returns that certificate (if it exists and is ISSUED).
    """
    certs: list[dict[str, str]] = []
    try:
        if certificate_arn:
            resp = acm_client.describe_certificate(CertificateArn=certificate_arn)
            cert_detail = resp.get("Certificate", {})
            if cert_detail.get("Status") == "ISSUED":
                certs.append(
                    {
                        "domain_name": cert_detail.get("DomainName", ""),
                        "certificate_arn": cert_detail["CertificateArn"],
                    }
                )
        else:
            paginator = acm_client.get_paginator("list_certificates")
            for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
                for cert in page.get("CertificateSummaryList", []):
                    certs.append(
                        {
                            "domain_name": cert.get("DomainName", ""),
                            "certificate_arn": cert["CertificateArn"],
                        }
                    )
    except ClientError as e:
        logger.error(f"Unable to list ACM certificates: {e}")
        sys.exit(1)
    return certs


def create_self_signed_certificate_and_upload_to_acm(
    acm_client: boto3.client,
) -> str:
    """Generate a self-signed certificate and import it into ACM.

    Returns the ACM certificate ARN.
    """

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "Engineering Development Hub"
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, "EDH.DEFAULT.CREATE.YOUR.OWN.CERTIFICATE"
            ),
        ]
    )

    # Create a 10 years self-signed certificate
    # see link below to create  a valid certificate and DNS for your EDH environment
    # Refer to https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/update-soca-dns-ssl-certificate/
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365 * 10)
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    try:
        resp = acm_client.import_certificate(
            Certificate=cert_pem,
            PrivateKey=key_pem,
            Tags=[
                {"Key": "Name", "Value": "EDH Default Self-Signed"},
                {
                    "Key": "Description",
                    "Value": "https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/update-soca-dns-ssl-certificate/",
                },
            ],
        )
        certificate_arn = resp["CertificateArn"]
        logger.info(f"EDH Self-signed certificate imported to ACM: {certificate_arn}")
        return certificate_arn
    except ClientError as e:
        logger.error(f"Unable to import self-signed certificate to ACM: {e}")
        sys.exit(1)


def check_kms_key_principals(
    kms_client: boto3.client, key_id: str, account_id: str, require_cloudwatch: bool
) -> bool:
    """Validate that a KMS CMK key policy contains the required principals.

    This performs a minimal check — it verifies that expected principals exist
    in the policy, not that the full set of actions or conditions is correct.
    KMS policies are complex and vary by service, so only principal presence
    is validated here.

    Required principals:
        - arn:aws:iam::<account_id>:root
          The root principal is required at install time because EDH IAM roles
          do not exist yet. Post-installation, the policy can be scoped down
          to specific role ARNs.
          Ideal permissions:
            "kms:*" (default when creating a CMK via the console)

        - logs.<region>.amazonaws.com (when require_cloudwatch=True)
          Required for CloudWatch Logs encryption integration.
          Ideal permissions:
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:Describe*"


    Use --skip-cmk-checks to bypass this validation.
    """
    response = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
    policy = json.loads(response["Policy"])

    _has_root_access = False
    _has_cloudwatch_access = False

    key_region = key_id.split(":")[3] if key_id.startswith("arn:") else None
    if not key_region:
        logger.error(f"Unable to determine region from KMS key ID: {key_id}")
        return False
    key_partition = key_id.split(":")[1] if key_id.startswith("arn:") else "aws"
    expected_principal = f"arn:{key_partition}:iam::{account_id}:root"
    expected_cw_principal = f"logs.{key_region}.amazonaws.com" if key_region else None

    for statement in policy.get("Statement", []):
        principal = statement.get("Principal", {})

        # Check root account principal
        aws_principal = (
            principal.get("AWS") if isinstance(principal, dict) else principal
        )
        # principals can be either str or list[str]
        if isinstance(aws_principal, list):
            if expected_principal in aws_principal:
                _has_root_access = True
        elif aws_principal == expected_principal:
            _has_root_access = True

        # Check CloudWatch Logs service principal
        if require_cloudwatch and expected_cw_principal:
            service_principal = (
                principal.get("Service") if isinstance(principal, dict) else None
            )
            # principals can be either str or list[str]
            if isinstance(service_principal, list):
                if expected_cw_principal in service_principal:
                    _has_cloudwatch_access = True
            elif service_principal == expected_cw_principal:
                _has_cloudwatch_access = True

    if not _has_root_access:
        return False
    if require_cloudwatch and not _has_cloudwatch_access:
        return False
    return True


def resources_mirroring(
    parameters: dict, s3_bucket: str, cluster_name: str, s3_client, spinner: callable
) -> dict:
    """Download all external resources from the Parameters section, validate SHA256
    checksums when available, upload to S3, and rewrite URLs in-place.

    Returns the modified parameters dict with all URLs pointing to S3.
    """
    MIRROR_EXCLUDE_URLS = [
        "https://us.download.nvidia.com/tesla",
        "https://repo.radeon.com/amdgpu",
        "https://ec2-linux-nvidia-drivers.s3.amazonaws.com",
        "https://ec2-windows-nvidia-drivers.s3.amazonaws.com",
        "https://ec2-amd-linux-drivers.s3.amazonaws.com",
        "https://ec2-amd-windows-drivers.s3.amazonaws.com",
    ]

    S3_BASE_PREFIX = f"{cluster_name}/resources_mirroring"
    # files will be downloaded to a temp directory before uploading to S3. Directory is cleaned up after mirroring is done.
    TMP_DIR = tempfile.mkdtemp(prefix="edh_mirror_")

    def _should_skip(url: str) -> bool:
        """
        Determine if a URL should be skipped from mirroring based on exclusion rules.
        """
        if url.startswith("s3://"):
            logger.info(f"Skipping already-S3 URL: {url}")
            return True
        if "%region%" in url or "%os%" in url or "%architecture%" in url:
            logger.info(f"Skipping URL with template variable: {url}")
            return True
        if url.endswith(".git") or url.startswith("git://"):
            logger.info(f"Skipping git repository URL: {url}")
            return True
        for excluded in MIRROR_EXCLUDE_URLS:
            if url.startswith(excluded):
                logger.info(f"Skipping excluded URL: {url}")
                return True
        return False

    def _url_to_s3_key(url: str) -> str:
        """
        Convert a URL to an S3 object key.

        e.g:
            if URL is https://d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-17701-el7-aarch64.tgz
        S3 key will be:
            s3://<bucket>/<prefix>/resources_mirroring/d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-17701-el7-aarch64.tgz
        """
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https"):
            domain = parsed.netloc
            path = parsed.path.lstrip("/")
            key = f"{domain}/{path}" if path else domain
        elif parsed.scheme == "s3":
            bucket = parsed.netloc
            path = parsed.path.lstrip("/")
            key = f"{bucket}/{path}" if path else bucket
        else:
            key = url.replace("://", "/")
        return f"{S3_BASE_PREFIX}/{key}"

    def _count_urls(node) -> int:
        """
        Recursively count the number of URLs in the parameters dict for progress tracking.
        """
        count = 0
        if isinstance(node, dict):
            for value in node.values():
                if isinstance(value, str) and value.startswith(
                    ("http://", "https://", "s3://")
                ):
                    if not _should_skip(value):
                        count += 1
                else:
                    count += _count_urls(value)
        elif isinstance(node, list):
            for item in node:
                count += _count_urls(item)
        elif isinstance(node, str):
            if node.startswith(("http://", "https://", "s3://")) and not _should_skip(
                node
            ):
                count += 1
        return count

    def _compute_sha256(file_path: str) -> str:
        """
        Compute the SHA256 hash of a file.
        """
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    total_urls = _count_urls(parameters)
    current_url = [0]

    def _download_and_upload(
        url: str, s3_key: str, expected_sha256: str | None = None
    ) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            current_url[0] += 1
            return True
        local_path = os.path.join(TMP_DIR, s3_key)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        current_url[0] += 1
        with spinner(f"[{current_url[0]}/{total_urls}] Downloading {url} ..."):
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                try:
                    ctx = ssl.create_default_context()
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "EDH-ResourceMirror/1.0"}
                    )
                    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
                        with open(local_path, "wb") as f:
                            shutil.copyfileobj(resp, f)
                    break
                except Exception as e:
                    if attempt < max_attempts:
                        logger.warning(
                            f"Attempt {attempt}/{max_attempts} failed for {url}: {e}. Retrying in 10 seconds..."
                        )
                        time.sleep(10)
                    else:
                        logger.error(
                            f"Failed to download {url} after {max_attempts} attempts: {e}"
                        )
                        shutil.rmtree(TMP_DIR, ignore_errors=True)
                        sys.exit(1)

        if expected_sha256:
            actual_sha256 = _compute_sha256(local_path)
            if actual_sha256 != expected_sha256:
                logger.error(
                    f"SHA256 mismatch for {url}: expected {expected_sha256}, got {actual_sha256}. "
                    f"Upload stopped as security measure. Update the sha256 entry in the config file "
                    f"if the source file has changed and you trust the new file."
                )
                shutil.rmtree(TMP_DIR, ignore_errors=True)
                sys.exit(1)
            logger.info(f"SHA256 verified for {url}")

        with spinner(
            f"[{current_url[0]}/{total_urls}] Uploading to s3://{s3_bucket}/{s3_key} ..."
        ):
            try:
                s3_client.upload_file(local_path, s3_bucket, s3_key)
                logger.info(f"[green]Uploaded: s3://{s3_bucket}/{s3_key}[/]")
                return True
            except Exception as e:
                logger.error(f"Failed to upload s3://{s3_bucket}/{s3_key}: {e}")
                shutil.rmtree(TMP_DIR, ignore_errors=True)
                sys.exit(1)

    def _rewrite_urls(node):
        """
        Recursively traverse the parameters dict, mirror resources to S3, and rewrite URLs in-place.
        """

        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and value.startswith(
                    ("http://", "https://", "s3://")
                ):
                    if _should_skip(value):
                        continue
                    expected_sha256 = node.get("sha256")
                    s3_key = _url_to_s3_key(value)
                    _download_and_upload(value, s3_key, expected_sha256=expected_sha256)
                    node[key] = f"s3://{s3_bucket}/{s3_key}|{value}"
                else:
                    node[key] = _rewrite_urls(value)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                node[i] = _rewrite_urls(item)
        elif isinstance(node, str):
            if node.startswith(("http://", "https://", "s3://")):
                if _should_skip(node):
                    return node
                s3_key = _url_to_s3_key(node)
                _download_and_upload(node, s3_key)
                return f"s3://{s3_bucket}/{s3_key}|{node}"
        return node

    logger.info(f"Mirroring {total_urls} external resources to S3 ...")
    _rewrite_urls(parameters)
    shutil.rmtree(TMP_DIR, ignore_errors=True)
    logger.info("Resource mirroring complete.")
    return parameters
