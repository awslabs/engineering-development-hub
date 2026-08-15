# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import re

from enum import Enum

from typing import Annotated, Optional, Any, List
from botocore.exceptions import ClientError
from helpers.boto3_wrapper import get_shared_session
from helpers.installer.helpers import list_acm_certificates
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
    RHEL8 = "rhel8"
    RHEL9 = "rhel9"
    ROCKY8 = "rocky8"
    ROCKY9 = "rocky9"
    UBUNTU2204 = "ubuntu2204"
    UBUNTU2404 = "ubuntu2404"


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

    @field_validator("vpc_cidr", "client_ip", "client_ipv6", mode="before")
    @classmethod
    def _validate_cidr(cls, v: Any) -> Any:
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
