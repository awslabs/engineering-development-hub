# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import re
import textwrap

from enum import Enum

from typing import Annotated, Optional, Any, List
from botocore.exceptions import ClientError
from helpers.boto3_wrapper import get_shared_session
from helpers.installer.helpers import list_acm_certificates, normalize_cidr_input
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    HttpUrl,
    IPvAnyNetwork,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)


class BaseOS(str, Enum):
    AL2023 = "amazonlinux2023"
    AL2027 = "amazonlinux2027"
    RHEL8 = "rhel8"
    RHEL9 = "rhel9"
    ROCKY8 = "rocky8"
    ROCKY9 = "rocky9"
    UBUNTU2204 = "ubuntu2204"
    UBUNTU2404 = "ubuntu2404"


# Human-readable labels for the base OS values, used to build the installer's
# questionary prompt. The enum VALUE remains the only thing the rest of the installer
# consumes (and the only thing --base-os accepts); these are display strings only.
#
# Deliberately NOT wrapped in _(): these are product names, i.e. proper nouns that are
# the same in every locale. The PREVIEW warning appended alongside them IS translated,
# at its use site in install_soca.py where gettext can extract it.
# Base OS values that are preview / pre-GA releases. These are selectable so they can be
# evaluated, but the installer flags them in the prompt so nobody picks one for a
# production cluster by accident. The flag is unconditional: it is shown whenever the OS
# is offered, and no CLI option suppresses it.
#
# The legacy installer expressed this with a per-OS {"visible": bool} map
# (install_soca_legacy.py). The questionary prompt replaced that with a plain list
# derived from this enum, which left no way to say "selectable but not recommended" --
# this set restores that distinction.
BASE_OS_PREVIEW: frozenset = frozenset(
    {
        "amazonlinux2027",  # public preview, SUPPORT_END 2026-12-31
    }
)


class NodeRole(str, Enum):
    """
    The roles an EDH node can serve.

    These are not invented here: the values are exactly what EDH already writes to
    /job/NodeType and what the bootstrap templates already branch on. They divide into
    two groups, which matters for how a base OS is chosen:

      INSTALL-TIME roles are built by CDK from the single base OS chosen at install.
      RUNTIME roles pick their own base OS per request -- a job says `base_os=`, a VDI
      desktop carries one on its software stack.
    """

    # Install-time (CDK, from user_specified_variables.base_os)
    CONTROLLER = "controller"
    LOGIN_NODE = "login_node"
    DCV_BROKER = "dcv_broker"
    DCV_GATEWAY = "dcv_gateway"
    # Runtime (per job / per desktop / per target node)
    COMPUTE_NODE = "compute_node"
    DCV_NODE = "dcv_node"
    TARGET_NODE = "target_node"


# Roles built by CDK at install time from the single chosen base OS. An OS that cannot
# serve one of these, and has no substitute for it, cannot be an install target at all.
INSTALL_TIME_ROLES: frozenset = frozenset(
    {
        NodeRole.CONTROLLER,
        NodeRole.LOGIN_NODE,
        NodeRole.DCV_BROKER,
        NodeRole.DCV_GATEWAY,
    }
)

# Roles a base OS CANNOT serve, and what to use in its place.
#
# Read as exceptions, not as an allowlist: an OS absent from this map serves every role.
# A positive OS-by-role matrix would be len(BaseOS) * len(NodeRole) cells to keep
# correct, which is the drift shape that left rhel10 registered in all 37 region maps
# and selectable nowhere.
#
#   "<base_os>": { NodeRole.X: "<substitute base_os>"  -> that role runs on the substitute
#                  NodeRole.Y: None }                  -> that role is impossible here
#
# A None on any INSTALL_TIME_ROLES entry makes the OS non-installable, so it is hidden
# from the installer prompt and rejected by --base-os. It can still be used by the
# runtime roles it does support.
BASE_OS_ROLE_FALLBACK: dict[str, dict[str, Optional[str]]] = {
    # Amazon DCV publishes no al2027 package family, so every DCV role runs on AL2023.
    # The controller and login nodes are unaffected, so AL2027 remains installable.
    "amazonlinux2027": {
        NodeRole.DCV_BROKER: "amazonlinux2023",
        NodeRole.DCV_GATEWAY: "amazonlinux2023",
        NodeRole.DCV_NODE: "amazonlinux2023",
    },
    # Shape a DCV-only OS would take once macOS is registered in BaseOS. Not enabled
    # here: macOS also needs the arm64_mac / x86_64_mac architectures threaded through,
    # which is its own change. Registering it WITHOUT this entry would offer macOS as a
    # cluster base OS in the prompt.
    # "macos15": {
    #     NodeRole.CONTROLLER: None,
    #     NodeRole.LOGIN_NODE: None,
    #     NodeRole.DCV_BROKER: None,
    #     NodeRole.DCV_GATEWAY: None,
    #     NodeRole.COMPUTE_NODE: None,
    #     NodeRole.TARGET_NODE: None,
    #     # DCV_NODE absent -> macOS serves it natively, which is the whole point.
    # },
}


def role_name(role) -> str:
    """
    The wire name of a role, for display and log messages.

    Needed because NodeRole is a (str, Enum) rather than enum.StrEnum, and from Python
    3.12 onward f"{NodeRole.DCV_BROKER}" renders "NodeRole.DCV_BROKER" instead of
    "dcv_broker". Equality and dict lookup against a plain string still work, so
    resolution is unaffected -- this is purely about not showing an operator an enum
    repr. Accepts a plain string too, so a hand-written registry key still formats.
    """
    return str(getattr(role, "value", role))


def base_os_role_target(base_os: str, role: str) -> Optional[str]:
    """
    Which base OS actually serves `role` when the cluster's base OS is `base_os`.

    Returns `base_os` itself normally, a substitute where one is registered, or None when
    the role cannot be served at all. Callers building a node MUST use the return value
    rather than the cluster base OS, or the host gets one OS's AMI with another OS's
    user_data.
    """
    return BASE_OS_ROLE_FALLBACK.get(base_os, {}).get(role, base_os)


def base_os_substituted_roles(base_os: str) -> dict:
    """Roles that run on a DIFFERENT OS than the one selected, as {role: substitute}."""
    return {
        _role: _target
        for _role, _target in BASE_OS_ROLE_FALLBACK.get(base_os, {}).items()
        if _target is not None and _target != base_os
    }


def base_os_unserviceable_roles(base_os: str) -> frozenset:
    """Roles this OS cannot serve at all, with no substitute."""
    return frozenset(
        _role
        for _role, _target in BASE_OS_ROLE_FALLBACK.get(base_os, {}).items()
        if _target is None
    )


def base_os_is_installable(base_os: str) -> bool:
    """
    Can a cluster be installed on this base OS?

    False when any install-time role is unserviceable with no substitute -- a DCV-only
    OS such as macOS cannot host a controller, so offering it as a cluster base OS would
    be a trap. Such an OS stays registered for the runtime roles it does support.
    """
    return not (base_os_unserviceable_roles(base_os) & INSTALL_TIME_ROLES)


def installable_base_os_values() -> list:
    """The base OS values a cluster can actually be installed on, in enum order."""
    return [e.value for e in BaseOS if base_os_is_installable(e.value)]


BASE_OS_LABELS: dict[str, str] = {
    "amazonlinux2023": "Amazon Linux 2023",
    "amazonlinux2027": "Amazon Linux 2027",
    "rhel8": "Red Hat Enterprise Linux 8",
    "rhel9": "Red Hat Enterprise Linux 9",
    "rocky8": "Rocky Linux 8",
    "rocky9": "Rocky Linux 9",
    "ubuntu2204": "Ubuntu 22.04 LTS",
    "ubuntu2404": "Ubuntu 24.04 LTS",
}


# questionary renders a Choice description as "  Description: <text>" in a single
# prompt_toolkit token and does no wrapping of its own (2.1.1 contains no textwrap,
# get_terminal_size or width handling anywhere), so anything past the terminal edge is
# cut mid-word with no ellipsis. The prefix is 15 characters and lands on the FIRST line
# only, which is why the first line has to be narrower than its continuations.
_QUESTIONARY_DESCRIPTION_PREFIX = "  Description: "


def wrap_choice_description(
    text: str,
    width: int,
    prefix_len: int = len(_QUESTIONARY_DESCRIPTION_PREFIX),
) -> str:
    """
    Hard-wrap a Choice description so questionary cannot truncate it.

    Wraps as though the renderer's prefix were part of the text, then removes it again,
    which is what makes the first line reserve room for a prefix it never contains.
    Continuations are indented to prefix_len so they align under the text rather than
    under "Description:". Long tokens are never split, matching _wrap_prompt(): a broken
    identifier is worse than a slightly over-long line.

    Takes width rather than reading the terminal so it stays testable without a TTY.
    """
    if not text:
        return text
    _pad = " " * prefix_len
    _lines = textwrap.wrap(
        _pad + text,
        width=max(width, prefix_len + 20),
        subsequent_indent=_pad,
        break_long_words=False,
        break_on_hyphens=False,
    )
    if not _lines:
        return text
    # Drop the padding we prepended; the renderer supplies the real prefix.
    _lines[0] = _lines[0][prefix_len:]
    return "\n".join(_lines)


def base_os_choice_rows(
    preview_tag: str = "PREVIEW",
    preview_help: str = "Preview release. Not for production use.",
    substitution_help: str = "Unsupported roles run on another OS: {substitutions}.",
    include_preview: bool = False,
    width: Optional[int] = None,
) -> list:
    """
    Build the (title, value, description) rows for the base OS selection prompt.

    Only INSTALLABLE base OSes are returned: an OS that cannot host a controller is not
    a cluster base OS and must not be offered, even though it stays registered for the
    runtime roles it supports.

    Preview releases are omitted unless include_preview is set (--preview), so the
    default list stays short and nobody is offered a pre-GA OS they did not ask for.
    This does NOT gate --base-os, which accepts a preview value either way: hiding a
    row is about what the prompt offers, not about what the installer supports. When a
    preview row IS shown it always carries the preview tag and warning.

    Lives here rather than inline in the prompt so that it is testable without a TTY,
    and so the label map cannot silently drift out of step with the BaseOS enum. The
    caller supplies the translatable strings, because gettext is installed in the
    installer entrypoint rather than in this module. `value` is always the bare base_os
    token: it is what the rest of the installer consumes, what --base-os accepts, and
    what `qsub -l base_os=` takes, so it is also kept visible in the title.

    width, when given, hard-wraps each description to that many columns. The caller
    supplies it for the same reason it supplies the strings: terminal size belongs to the
    entrypoint. Left as None the descriptions come back unwrapped, which is what the
    tests assert against.
    """
    _rows: list = []
    for _member in BaseOS:
        _value = _member.value
        if not base_os_is_installable(_value):
            continue
        _is_preview = _value in BASE_OS_PREVIEW
        if _is_preview and not include_preview:
            continue
        _label = BASE_OS_LABELS.get(_value, _value)
        _title = f"{_label} ({_value})" + (f"  [{preview_tag}]" if _is_preview else "")

        # Description composes: a preview OS that also substitutes roles says both.
        _notes: list = []
        if _is_preview:
            _notes.append(preview_help)
        _subs = base_os_substituted_roles(_value)
        if _subs:
            # Group by target so a shared substitute is named once rather than per role:
            # "dcv_broker, dcv_gateway, dcv_node on amazonlinux2023", not three clauses.
            _by_target: dict = {}
            for _role, _target in _subs.items():
                _by_target.setdefault(_target, []).append(role_name(_role))
            _notes.append(
                substitution_help.format(
                    substitutions="; ".join(
                        f"{', '.join(sorted(_roles))} on {_target}"
                        for _target, _roles in sorted(_by_target.items())
                    )
                )
            )

        _description = " ".join(_notes) if _notes else None
        if _description is not None and width:
            _description = wrap_choice_description(_description, width)
        _rows.append((_title, _value, _description))
    return _rows


class FilesystemProvider(str, Enum):
    EFS = "efs"
    FSX_LUSTRE = "fsx_lustre"
    FSX_ONTAP = "fsx_ontap"
    FSX_OPENZFS = "fsx_openzfs"


class InstallParameters(BaseModel):
    # Validates only the user-facing install inputs, not the full default_config.yml.

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    create_es_service_role: bool  # Whether to create the OpenSearch service-linked role. Ignored if SLR already exists.
    partition: str  # AWS partition (aws, aws-us-gov, aws-cn) derived from STS at startup
    region: str  # AWS region to install EDH in
    base_os: BaseOS  # Base OS for the controller and compute nodes
    cluster_name: Annotated[
        str, StringConstraints(min_length=5, max_length=15)
    ]  # Unique EDH cluster name (5-15 characters). Used as the CloudFormation stack name.
    email_address: List[EmailStr]  # Admin email address(es) for cluster notifications
    bucket: Annotated[
        str, StringConstraints(min_length=1)
    ]  # S3 bucket for EDH artifacts and configuration
    ssh_keypair: str  # EC2 SSH key pair name for instance access
    vpc_cidr: Optional[
        List[IPvAnyNetwork]
    ]  # VPC CIDR(s) to create. Mutually exclusive with vpc_id.
    vpc_id: Optional[
        str
    ]  # Existing VPC ID to deploy into. Mutually exclusive with vpc_cidr.
    client_ip: List[
        IPvAnyNetwork
    ]  # IP/CIDR range(s) allowed to access EDH via ALB (443/80) and NLB (22). More IPs can be added post-deployment.
    client_ipv6: Optional[
        List[IPvAnyNetwork]
    ] = None  # IPv6 CIDR range(s) allowed to access EDH when dual-stack (EnableIPv6) is enabled.
    fs_apps_provider: FilesystemProvider  # Filesystem provider for /apps
    fs_data_provider: FilesystemProvider  # Filesystem provider for /data
    public_subnet_ids: Optional[
        List[str]
    ]  # Public subnet IDs when using an existing VPC. Requires vpc_id.
    private_subnet_ids: Optional[
        List[str]
    ]  # Private subnet IDs when using an existing VPC. Requires vpc_id.

    os_domain: Optional[HttpUrl]  # Existing OpenSearch domain endpoint
    tls_certificate: Optional[str]  # ACM certificate ARN for the load balancer

    # Field validators & functions provide inline feedback in the TUI as the user types (via validate_with()).
    # Model validators run later, when the full InstallParameters object is constructed.
    @field_validator("email_address", mode="before")
    @classmethod
    def _validate_email_addresses(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list):
            for addr in v:
                if not isinstance(addr, str):
                    continue
                try:
                    EmailStr._validate(addr)
                except (ValueError, ValidationError):
                    raise ValueError(f"{addr!r} is not a valid email address")
        return v

    @field_validator("cluster_name", mode="before")
    @classmethod
    def _validate_cluster_name(cls, v: Any) -> Any:
        if isinstance(v, str):
            if not v.startswith("edh-"):
                raise ValueError("Cluster name must start with 'edh-'")
            if not (5 <= len(v) <= 15):
                raise ValueError("Cluster name must be between 5 and 15 characters")
            if not v.removeprefix("edh-").isalnum():
                raise ValueError(
                    "Cluster name must only contain alphanumeric characters"
                )
        return v

    @field_validator("vpc_cidr", mode="before")
    @classmethod
    def _validate_cidr(cls, v: Any) -> Any:
        # No splitting: vpc_cidr is a single CIDR everywhere downstream.
        return cls._check_cidr_items(v)

    @field_validator("client_ip", "client_ipv6", mode="before")
    @classmethod
    def _validate_client_cidr(cls, v: Any) -> Any:
        # One "before" validator per field: inline_validate_with() applies them
        # in declaration order, not pydantic's.
        if v is None:
            return v
        _normalized = normalize_cidr_input(v)
        if not _normalized:
            # List[...] would accept the empty list a blank answer produces.
            raise ValueError(
                "at least one CIDR is required (e.g. 203.0.113.4/32, or several separated by a comma)"
            )
        return cls._check_cidr_items(_normalized)

    @classmethod
    def _check_cidr_items(cls, v: Any) -> Any:
        if v is None:
            return v
        # convert as list since vpc_cidr is a single str but client_ip is a list of CIDR
        items = v if isinstance(v, list) else [v]
        for item in items:

            # early catch if not string
            if not isinstance(item, str):
                raise ValueError(f"{item!r} is not a valid CIDR")

            if "/" not in item:
                raise ValueError(
                    f"{item!r} is not a valid CIDR, netmask notation required (e.g. 10.0.0.0/16 or fd00::/8)"
                )
            try:
                IPvAnyNetwork(item)
            except ValueError:
                raise ValueError(
                    f"{item!r} is not a valid CIDR (e.g. 10.0.0.0/16 or fd00::/8)"
                )
        return v if isinstance(v, list) else [v]

    @model_validator(mode="after")
    def validate_aws_resources(self) -> "InstallParameters":
        self._validate_region(region=self.region, partition=self.partition)
        self._validate_s3_bucket(self.bucket)
        self._validate_ssh_keypair(self.ssh_keypair, self.region)
        self._validate_cluster_name_unique(self.cluster_name, self.region)
        if self.tls_certificate:
            self._validate_acm_certificate_exists(self.tls_certificate, self.region)

        if not self.vpc_id and not self.vpc_cidr:
            raise ValueError(
                "Either vpc_id or vpc_cidr must be set: set vpc_id to reuse an "
                "existing VPC, or vpc_cidr to create a new one."
            )

        if self.vpc_id and self.vpc_cidr:
            raise ValueError(
                "vpc_id and vpc_cidr are mutually exclusive: set vpc_id to "
                "reuse an existing VPC, or vpc_cidr to create a new one."
            )

        subnet_ids = (self.public_subnet_ids or []) + (self.private_subnet_ids or [])
        if subnet_ids and not self.vpc_id:
            raise ValueError(
                "public_subnet_ids/private_subnet_ids require vpc_id to be set."
            )

        if self.vpc_id:
            ec2 = get_shared_session().client("ec2", region_name=self.region)
            self._validate_vpc_exists(ec2, self.vpc_id)
            if subnet_ids:
                self._validate_subnets_in_vpc(ec2, self.vpc_id, subnet_ids)

        return self

    @staticmethod
    def _validate_region(region: str, partition: str) -> None:
        # note: this does not check if your AWS account has opt-in for the region
        # This is verified when you do an interactive installer, but silent installer will just validate if the region specified in default_config.yml is valid
        if region not in get_shared_session().get_available_regions("ec2", partition_name=partition):
            raise ValueError(f"{region!r} is not a valid AWS region in the {partition!r} partition.")

    @staticmethod
    def _validate_s3_bucket(bucket: str) -> None:
        s3 = get_shared_session().client("s3")
        try:
            s3.head_bucket(Bucket=bucket)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("404", "NoSuchBucket"):
                raise ValueError(f"S3 bucket {bucket!r} does not exist.") from e
            if code in ("403", "AccessDenied", "Forbidden"):
                raise ValueError(
                    f"Access denied to S3 bucket {bucket!r}; check IAM permissions."
                ) from e
            raise ValueError(f"Unable to access S3 bucket {bucket!r}: {e}") from e

    @staticmethod
    def _validate_cluster_name_unique(cluster_name: str, region: str) -> None:
        cfn = get_shared_session().client("cloudformation", region_name=region)
        try:
            cfn.describe_stacks(StackName=cluster_name)
        except ClientError as e:
            if "does not exist" in str(e):
                return
            raise ValueError(
                f"Unable to check CloudFormation stack {cluster_name!r}: {e}"
            ) from e
        raise ValueError(
            f"A CloudFormation stack named {cluster_name!r} already exists in {region}."
        )

    @staticmethod
    def list_existing_cluster_stacks(region: str) -> List[str]:
        """Return active bare edh-<suffix> cluster stack names in the region (collision guidance)."""
        cfn = get_shared_session().client("cloudformation", region_name=region)
        active = [
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_COMPLETE",
            "ROLLBACK_COMPLETE",
            "CREATE_IN_PROGRESS",
            "UPDATE_IN_PROGRESS",
        ]
        # Match only bare cluster stacks (edh-<suffix>), not job/session/nested
        # stacks like edh-x-job-1-..., edh-x-edhadmin-<uuid>, edh-x-LambdaFleetStack...
        cluster_re = re.compile(r"^edh-[a-z0-9]+$")
        names = []
        try:
            paginator = cfn.get_paginator("list_stacks")
            for page in paginator.paginate(StackStatusFilter=active):
                for s in page.get("StackSummaries", []):
                    name = s.get("StackName", "")
                    if cluster_re.match(name):
                        names.append(name)
        except ClientError:
            pass
        return sorted(set(names))

    @staticmethod
    def _list_ssh_keypairs(region: str) -> List[dict[str, str]]:
        """Return a list of dicts: {name, type, created}.

        Sorted by a natural-key of the key name so 'my-key-2' comes before
        'my-key-10', and human-named groups ('prod-*', 'dev-*') cluster.
        """
        ec2 = get_shared_session().client("ec2", region_name=region)
        try:
            resp = ec2.describe_key_pairs()
        except ClientError as e:
            raise ValueError(f"Unable to list SSH key pairs: {e}") from e

        pairs = []
        for kp in resp.get("KeyPairs", []):
            created_dt = kp.get("CreateTime")
            created = created_dt.strftime("%Y-%m-%d") if created_dt else ""
            pairs.append(
                {
                    "name": kp["KeyName"],
                    "type": kp.get("KeyType", ""),
                    "created": created,
                }
            )

        # Natural-sort by key name (so user-named prefixes stay grouped
        # and numeric suffixes sort correctly).
        def _natural_key(text: str) -> list:
            return [
                int(part) if part.isdigit() else part.lower()
                for part in re.split(r"(\d+)", text)
            ]

        return sorted(pairs, key=lambda p: _natural_key(p["name"]))

    @staticmethod
    def _validate_ssh_keypair(keypair: str, region: str) -> None:
        ec2 = get_shared_session().client("ec2", region_name=region)
        try:
            ec2.describe_key_pairs(KeyNames=[keypair])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "InvalidKeyPair.NotFound":
                raise ValueError(
                    f"SSH key pair {keypair!r} does not exist in {region}."
                ) from e
            raise ValueError(f"Unable to verify SSH key pair {keypair!r}: {e}") from e

    @staticmethod
    def _list_vpcs(region: str) -> List[dict[str, str]]:
        ec2 = get_shared_session().client("ec2", region_name=region)
        try:
            resp = ec2.describe_vpcs()
        except ClientError as e:
            raise ValueError(f"Unable to list VPCs: {e}") from e
        vpcs = []
        for v in resp.get("Vpcs", []):
            vpc_id = v["VpcId"]
            cidr = v.get("CidrBlock", "")
            name = ""
            for tag in v.get("Tags", []):
                if tag.get("Key") == "Name":
                    name = tag.get("Value", "")
                    break
            vpcs.append({"vpc_id": vpc_id, "cidr": cidr, "name": name})

        # Sort so similarly-named VPCs cluster together in the picker
        # (e.g. all "prod-*" before "dev-*"). Zero-dep natural-sort idiom:
        # split on digit runs so "vpc-10" sorts after "vpc-2". Falls back
        # to VPC ID when no Name tag is set.
        def _natural_key(text: str) -> list:
            return [
                int(part) if part.isdigit() else part.lower()
                for part in re.split(r"(\d+)", text)
            ]

        return sorted(
            vpcs,
            key=lambda v: (
                _natural_key(v["name"] or v["vpc_id"]),
                v["vpc_id"],
            ),
        )

    @staticmethod
    def _list_subnets(region: str, vpc_id: str) -> List[dict[str, str]]:
        ec2 = get_shared_session().client("ec2", region_name=region)
        try:
            resp = ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
        except ClientError as e:
            raise ValueError(f"Unable to list subnets for VPC {vpc_id}: {e}") from e
        subnets = []
        for s in resp.get("Subnets", []):
            name = ""
            for tag in s.get("Tags", []):
                if tag.get("Key") == "Name":
                    name = tag.get("Value", "")
                    break
            subnets.append(
                {
                    "subnet_id": s["SubnetId"],
                    "cidr": s.get("CidrBlock", ""),
                    "az": s.get("AvailabilityZone", ""),
                    "name": name,
                }
            )

        # Sort so the questionary picker groups similarly-named subnets
        # together (e.g. all "private-*" before all "public-*") rather
        # than interleaving them by AZ. Sort keys, in priority order:
        #
        #   1. Numeric-aware (natural) lowercased Name tag -- keeps
        #      related names adjacent and orders numeric suffixes
        #      correctly (private-1, private-2, private-10 instead of
        #      the lexicographic private-1, private-10, private-2).
        #      Falls back to SubnetId when a Name tag is absent.
        #   2. Availability Zone -- within a Name-group, line up by
        #      AZ (us-east-2a, -2b, -2c) for predictable multi-AZ
        #      selection.
        #   3. SubnetId -- final tie-breaker for stable ordering.
        #
        # Zero-dep natsort idiom: split on digit runs, cast digit
        # substrings to int so "10" sorts after "2".
        def _natural_key(text: str) -> list:
            return [
                int(part) if part.isdigit() else part.lower()
                for part in re.split(r"(\d+)", text)
            ]

        return sorted(
            subnets,
            key=lambda s: (
                _natural_key(s["name"] or s["subnet_id"]),
                s["az"],
                s["subnet_id"],
            ),
        )

    @staticmethod
    def _validate_vpc_exists(ec2: Any, vpc_id: str) -> None:
        try:
            resp = ec2.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as e:
            raise ValueError(f"Unable to describe VPC {vpc_id}: {e}") from e
        if not resp.get("Vpcs"):
            raise ValueError(f"VPC {vpc_id} not found in the target region.")

    @staticmethod
    def _validate_subnets_in_vpc(ec2: Any, vpc_id: str, subnet_ids: List[str]) -> None:
        # Entries may be "subnet-xxx" or "subnet-xxx,az-name" (when using existing vpc), extract just the ID
        clean_ids = [s.split(",")[0].strip() for s in subnet_ids]
        try:
            resp = ec2.describe_subnets(SubnetIds=clean_ids)
        except ClientError as e:
            raise ValueError(f"Unable to describe subnets {clean_ids}: {e}") from e
        mismatched = [
            s["SubnetId"] for s in resp.get("Subnets", []) if s.get("VpcId") != vpc_id
        ]
        if mismatched:
            raise ValueError(f"Subnets {mismatched} do not belong to VPC {vpc_id}.")

    @staticmethod
    def _validate_acm_certificate_exists(certificate_arn: str, region: str) -> None:
        if not certificate_arn.startswith("arn:"):
            raise ValueError(
                f"ACM certificate ARN {certificate_arn!r} is not a valid ARN."
            )
        acm = get_shared_session().client("acm", region_name=region)
        result = list_acm_certificates(acm_client=acm, certificate_arn=certificate_arn)
        if not result:
            raise ValueError(
                f"ACM certificate {certificate_arn!r} was not found or is not in "
                f"ISSUED status in {region}."
            )
