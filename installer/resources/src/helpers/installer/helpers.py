# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import boto3
import sys
import os
import datetime
import fnmatch
import functools
import importlib.util
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
from typing import Annotated, Any, Optional
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


def _load_soca_util(module_name: str, repo_root: Path):
    # Modules under source/soca ship to nodes, so the installer reads them from
    # disk rather than duplicating their contents. Anything loaded this way MUST
    # be dependency-free -- the installer runs outside the cluster venv.
    _module_path = (
        repo_root / "source" / "soca" / "cluster_manager" / "utils"
        / f"{module_name}.py"
    )
    _spec = importlib.util.spec_from_file_location(
        f"edh_{module_name}", _module_path
    )
    _module = importlib.util.module_from_spec(_spec)
    # Executing a module writes bytecode next to it. This runs against the
    # operator's own source tree moments before make_archive(), so without this
    # the archive would carry a stray __pycache__ into every node.
    _previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        _spec.loader.exec_module(_module)
    finally:
        sys.dont_write_bytecode = _previous
    return _module


@functools.lru_cache(maxsize=1)
def get_edh_version() -> str:
    # Canonical version lives under source/soca so it also ships to nodes; read it, never duplicate it.
    # Cached because build_boto3_client() calls this on every client construction,
    # and each uncached call re-reads and re-executes the module file.
    return _load_soca_util(
        module_name="version", repo_root=Path(__file__).resolve().parents[5]
    ).__version__


def verify_installer_tree(release_root: str) -> dict:
    """Verify installer/** against the shipped installer manifest (Phase 7).

    This runs HERE, on the operator's workstation, because it is the only place
    the installer tree exists. installer/** never reaches a node, so
    `edhctl support verify` on a cluster has nothing to compare -- a node-only
    check would miss this class of modification entirely, and a recent customer
    fork's changes were located entirely in installer/.

    Verifying before the deploy is also strictly more useful than verifying
    after: a tampered or forked installer tree is caught before it builds a
    cluster rather than after.

    Returns {"status": ..., "modified": [...], "missing": [...]}. status is
    "verified", "deviations", or "no_baseline". Never raises and never exits --
    failure to PRODUCE this check is not a reason to block an install.
    """
    try:
        _integrity = _load_soca_util(
            module_name="integrity_manifest", repo_root=Path(release_root)
        )
        _manifest = _integrity.read_installer_manifest(release_root=release_root)
        if not (_manifest.get("files") or {}):
            return {"status": "no_baseline", "modified": [], "missing": []}

        _on_disk = _integrity.build_file_map(
            tree_root=release_root,
            exclude_prefixes=(f"{_integrity.CODE_TREE_PREFIX}/",),
        )
        _modified = []
        _missing = []
        for _relative_path, _expected_hash in _manifest["files"].items():
            _actual_hash = _on_disk.get(_relative_path)
            if _actual_hash is None:
                _missing.append(_relative_path)
            elif _actual_hash != _expected_hash:
                _modified.append(_relative_path)

        return {
            "status": "deviations" if (_modified or _missing) else "verified",
            "modified": sorted(_modified),
            "missing": sorted(_missing),
            "build_id": _manifest.get("build_id"),
            "tracked": len(_manifest["files"]),
        }
    except Exception as _err:
        logger.debug(f"Installer tree verification could not run: {_err}")
        return {"status": "no_baseline", "modified": [], "missing": []}


def report_installer_tree_integrity(release_root: str) -> None:
    """Log the installer-tree verdict at startup. Advisory, never fatal.

    Paths are printed because every one is already public in the GitHub release,
    exactly as in `edhctl support verify`. File content is never printed.
    """
    _result = verify_installer_tree(release_root=release_root)

    if _result["status"] == "no_baseline":
        logger.debug(
            "No installer integrity manifest present; skipping installer-tree "
            "verification. This is expected when installing from a source "
            "checkout rather than a published release."
        )
        return

    if _result["status"] == "verified":
        logger.info(
            f"Installer tree verified against the shipped manifest "
            f"({_result['tracked']} files, build_id={_result['build_id']})."
        )
        return

    logger.warning(
        f"Installer tree DEVIATES from the shipped manifest "
        f"(build_id={_result['build_id']}): "
        f"{len(_result['modified'])} modified, {len(_result['missing'])} missing. "
        f"This install will deploy code that differs from the published release."
    )
    for _relative_path in _result["modified"]:
        logger.warning(f"  modified: {_relative_path}")
    for _relative_path in _result["missing"]:
        logger.warning(f"  missing:  {_relative_path}")


def generate_dev_manifest_if_needed(source_soca_directory: str, repo_root: str):
    # Without this the manifest is only ever produced by the full release path,
    # so no development cluster would carry one, `edhctl support verify` would
    # no-op, and the entire code path would rot between release cycles.
    #
    # A release manifest is authoritative and left untouched. A *dev* manifest
    # is always regenerated: it describes whichever tree it was generated from,
    # so reusing a stale one left behind by an earlier install of a different
    # tree would silently validate against the wrong baseline.
    #
    # HONEST LIMITATION: a dev manifest is a SELF-BASELINE. It matches the tree
    # it was generated from, so it detects post-install drift but cannot detect
    # workstation-side modification -- the same flaw that disqualified
    # soca.tar.gz as a baseline. For dev builds, build-time provenance rests on
    # build_type + git_dirty + commit SHA, not on hash verification.
    # Failure to produce a diagnostic must never abort an install. Only
    # deviations FOUND by a check are subject to the fatality knob.
    #
    # The WHOLE body is guarded, and on Exception rather than OSError. This runs
    # immediately before make_archive() on both installer paths, so anything that
    # escapes takes the deployment with it -- and the two riskiest calls are the
    # module load, which imports and execs a file off disk, and read_manifest,
    # which parses JSON. Neither raises OSError for the failures that matter.
    try:
        _integrity = _load_soca_util(
            module_name="integrity_manifest", repo_root=Path(repo_root)
        )

        _existing = _integrity.read_manifest(tree_root=source_soca_directory)
        if _existing.get("build_type") == _integrity.BUILD_TYPE_RELEASE:
            logger.debug(
                f"Release manifest present (build_id "
                f"{_existing.get('build_id')}); leaving it untouched."
            )
            return

        _manifest = _integrity.build_manifest(
            tree_root=source_soca_directory,
            version=get_edh_version(),
            build_type=_integrity.BUILD_TYPE_DEV,
            git_directory=repo_root,
        )
        _integrity.write_manifest(
            tree_root=source_soca_directory, manifest=_manifest
        )
        logger.info(
            f"Generated dev integrity manifest: "
            f"{len(_manifest['files'])} files, "
            f"build_id={_manifest['build_id']} "
            f"(self-baseline -- detects post-install drift only)"
        )
    except Exception as _err:
        logger.warning(
            f"Could not generate the dev integrity manifest ({_err}). "
            f"Install continues; `edhctl support verify` will report no "
            f"baseline on this cluster."
        )


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
    aws_solution_user_agent = {
        "user_agent_extra": f"AwsSolution/SO0072/{get_edh_version()}"
    }
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


_CIDR_INPUT_SEPARATORS: str = ",;"


def normalize_cidr_input(value: Any) -> list:
    """
    Split one operator answer into a list of CIDRs, dropping exact duplicates.

    Accepts a single CIDR, a delimited string ("10.0.0.0/8, 192.0.2.0/24"), a
    list of either, or None. Order is preserved and overlapping entries are kept
    as given.

    Normalization only: an unparseable value passes through so the model
    validator can reject it by name.
    """
    if value is None:
        return []

    _items: list = value if isinstance(value, list) else [value]

    _flat: list = []
    for _item in _items:
        if not isinstance(_item, str):
            _flat.append(_item)
            continue
        _candidate: str = _item
        for _separator in _CIDR_INPUT_SEPARATORS:
            _candidate = _candidate.replace(_separator, " ")
        _flat.extend(_candidate.split())

    # Compare normalized (10.0.0.1/8 and 10.0.0.0/8 are one entry), keep verbatim.
    _unique: list = []
    _seen: set = set()
    for _entry in _flat:
        _key: Any = _entry
        if isinstance(_entry, str) and "/" in _entry:
            try:
                _key = str(ipaddress.ip_network(_entry, strict=False))
            except ValueError:
                _key = _entry
        if _key in _seen:
            continue
        _seen.add(_key)
        _unique.append(_entry)

    logger.debug(f"normalize_cidr_input - {value=} normalized to {_unique=}")
    return _unique


# An existing VPC must carry 2 public and 2 private subnets for a public
# deployment. A private deployment places every entry point in a private subnet
# and selects no public subnet, so it needs only the 2 private ones. Two is a
# floor rather than a preference: OpenSearch exits the synth below 2 private
# subnets (helpers/analytics.py).
EXISTING_VPC_MIN_SUBNETS: dict = {"public": 4, "private": 2}


def is_private_deployment(deployment_mode: Any) -> bool:
    """
    True when the operator asked for private load balancers.

    Tests for "private" rather than "not public": the installer relaxes the
    public subnet requirement only on an explicit choice, so a run that somehow
    reaches the subnet gates without a mode is held to the stricter one. The CDK
    layer reads the same value the other way around (deployment_mode ==
    "public"), and both prompts and --deployment-mode offer only these two.
    """
    return deployment_mode == "private"


def existing_vpc_subnet_requirement(deployment_mode: Any) -> tuple:
    """
    (minimum subnet count, that requirement in words) for an existing VPC.
    """
    if is_private_deployment(deployment_mode=deployment_mode):
        return EXISTING_VPC_MIN_SUBNETS["private"], "2 private"
    return EXISTING_VPC_MIN_SUBNETS["public"], "2 public + 2 private"


def supplied_subnets_error(
    deployment_mode: Any, public_subnets: Any, private_subnets: Any
) -> Optional[str]:
    """
    Why --vpc-id cannot be honored with the subnet lists supplied, or None.

    --vpc-id means the operator picks the subnets, since nothing else can. A
    private deployment supplies only --private-subnets, because no public
    subnet is created, selected or consumed on that path.
    """
    if not private_subnets:
        return (
            "vpc_id is provided without private_subnets. Please provide "
            "private_subnets or remove vpc_id."
        )

    if (
        not is_private_deployment(deployment_mode=deployment_mode)
        and not public_subnets
    ):
        return (
            "vpc_id is provided without public_subnets. Please provide "
            "public_subnets, select the private deployment mode, or remove vpc_id."
        )

    return None


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

    _manual_flag: str = "--client-ip" if address_family == "ipv4" else "--client-ipv6"

    logger.debug(
        f"\n====== Trying to detect your {_formal_af_name} address via {check_url} . "
        f"Pass {_manual_flag} to specify it manually ======\n"
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


# LOCAL_CONFIG_GLOB is the only auto-loaded form, and it is gitignored.
# LOCAL_CONFIG_EXAMPLE is the shipped template. Neither it nor
# LOCAL_CONFIG_REFUSED matches the glob; LOCAL_CONFIG_REFUSED is reported with
# a rename hint rather than ignored.
LOCAL_CONFIG_GLOB: str = "local_config_*.yml"
LOCAL_CONFIG_EXAMPLE: str = "local_config.example.yml"
LOCAL_CONFIG_REFUSED: str = "local_config.yml"


def deep_merge_config(base: dict, overlay: dict) -> dict:
    # Mappings merge key by key; scalars and lists replace outright. Lists
    # replace rather than concatenate so a layer can shorten dc_ips or a
    # subnet list, not only extend it.
    merged: dict = dict(base)
    for key, overlay_value in overlay.items():
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(overlay_value, dict):
            merged[key] = deep_merge_config(base_value, overlay_value)
        else:
            merged[key] = overlay_value
    return merged


def _config_leaf_keys(node: dict, prefix: str = ""):
    # Dotted paths of every leaf, for provenance. A dict-valued key is not a
    # leaf; an empty dict is, since it carries a value the merge can replace.
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict) and value:
            yield from _config_leaf_keys(value, path)
        else:
            yield path


def resolve_config_paths(
    explicit_paths: Optional[list] = None,
    default_config_path: Optional[str] = None,
) -> list:
    # Layer order, lowest precedence first: shipped defaults, local_config_*.yml
    # in sorted order, then --config paths in the order given.
    if default_config_path is None:
        default_config_path = str(
            Path(__file__).resolve().parents[4] / "default_config.yml"
        )

    _layers: list = [default_config_path]
    _config_dir = Path(default_config_path).resolve().parent

    # Both near-miss names below are reported rather than skipped. The name the
    # hint suggests is checked against the glob itself rather than against any
    # one bad name: swapping .yaml for .yml only replaces the last suffix, so
    # local_config.yaml lands on LOCAL_CONFIG_REFUSED and local_config.bak.yaml
    # lands on local_config.bak.yml, which has no underscore and so is not
    # auto-loaded either. Both would send the operator into a second abort.
    for _mistyped in sorted(_config_dir.glob("local_config*.yaml")):
        _suggested = _mistyped.with_suffix(".yml")
        if not fnmatch.fnmatch(_suggested.name, LOCAL_CONFIG_GLOB):
            _suggested = _config_dir / "local_config_site.yml"
        logger.error(
            f"Found {_mistyped}, but an auto-loaded overlay must match "
            f"{LOCAL_CONFIG_GLOB}. Rename it to {_suggested} or pass it with "
            f"--config."
        )
        sys.exit(1)

    _refused = _config_dir / LOCAL_CONFIG_REFUSED
    if _refused.is_file():
        logger.error(
            f"Found {_refused}, which is not loaded: an auto-loaded overlay must "
            f"match {LOCAL_CONFIG_GLOB}. Rename it to "
            f"{_config_dir / 'local_config_site.yml'} (any suffix after the "
            f"underscore works) or pass it with --config."
        )
        sys.exit(1)

    # Sorted so ordering is explicit and reproducible: local_config_10_base.yml
    # applies before local_config_20_site.yml.
    for _overlay in sorted(_config_dir.glob(LOCAL_CONFIG_GLOB)):
        _layers.append(str(_overlay))

    _layers.extend(explicit_paths or [])
    return _layers


def get_install_properties(
    path: Optional[str] = None, paths: Optional[list] = None
) -> dict:
    # Retrieve SOCA configuration properties, merging each layer over the last.
    _paths: list = paths if paths is not None else [path]
    logger.debug(f"Configuration file layers: {_paths}")

    config_parameters: dict = {}
    provenance: dict = {}

    for _path in _paths:
        try:
            with open(_path, "r") as config_file:
                _layer = yaml.safe_load(config_file)
        # YAMLError, not ScannerError: an unclosed flow sequence raises
        # ParserError, which ScannerError does not catch.
        except yaml.YAMLError as _err:
            logger.error(f"{_path} is not a valid YAML file. Verify syntax, {_err}")
            sys.exit(1)
        except FileNotFoundError:
            logger.error(
                f"{_path} not found. Make sure the file exist and the path is correct."
            )
            sys.exit(1)

        if not _layer:
            logger.debug(f"{_path} is empty, nothing to merge")
            continue
        if not isinstance(_layer, dict):
            logger.error(f"{_path} must contain a YAML mapping at the top level")
            sys.exit(1)

        for _key in _config_leaf_keys(_layer):
            provenance[_key] = _path
        config_parameters = deep_merge_config(config_parameters, _layer)

    if not config_parameters:
        return {}

    _base_layer = _paths[0]
    _overridden = {k: v for k, v in provenance.items() if v != _base_layer}
    if _overridden:
        logger.info(
            f"{len(_overridden)} configuration key(s) overridden by {len(_paths) - 1} "
            f"additional layer(s)"
        )
        for _key, _source in sorted(_overridden.items()):
            logger.debug(f"  {_key} <- {_source}")

    # Provenance is logged, never returned: this dict is JSON-serialized into
    # the CDK context and partly written to SSM, so an extra key would travel.
    # version is single-sourced from utils/version.py, never from the YAML.
    config_parameters.setdefault("Config", {})["version"] = get_edh_version()
    return config_parameters


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

    # Stamp the integrity baseline BEFORE archiving, or it never reaches a node.
    # Release builds already carry one and it is left untouched. Both installer
    # entry points archive source/soca separately, so both must call this or the
    # feature silently no-ops on whichever path skips it.
    generate_dev_manifest_if_needed(
        source_soca_directory=f"{install_directory}/../../../source/soca",
        repo_root=f"{install_directory}/../../..",
    )

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
    from cdk_construct import LAMBDA_PYTHON_VERSION

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
                    LAMBDA_PYTHON_VERSION,
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
    logger.debug(f"Address Family: {_pl.get('AddressFamily', None)}")
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
