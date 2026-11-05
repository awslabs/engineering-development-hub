# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import json
import logging
import os
import pathlib
import uuid
import yaml
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from typing import (
    Any,
    Dict,
    Optional,
    Callable,
    List,
    Literal,
    TypeVar,
)
from botocore.exceptions import ClientError

from utils.aws.boto3_wrapper import get_boto
from utils.aws.ec2_helper import (
    describe_images,
    describe_subnets,
    describe_instances_paginate,
)
from utils.aws.iam_helper import get_instance_profile, list_instance_profiles
from utils.config import SocaConfig
from utils.subprocess_client import SocaSubprocessClient
from utils.error import SocaError
from utils.response import SocaResponse
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider

logger = logging.getLogger("soca_logger")

F = TypeVar("F", bound=Callable)


def cluster_must_be_visible() -> Callable[[F], F]:
    """
    Refuse to run the wrapped method unless the PCS cluster carries this environment's
    edh:visibility:<cluster id>=true tag. EDH must never read or modify a cluster that is not
    visible to it, so every cluster-scoped public method goes through this gate (directly, or
    via cluster_must_be_active).
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            _invisible = self._check_cluster_visible()
            if _invisible is not None:
                return _invisible
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


def cluster_must_be_active() -> Callable[[F], F]:
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Visibility first: never describe / act on a cluster this environment cannot see.
            _invisible = self._check_cluster_visible()
            if _invisible is not None:
                return _invisible

            # Lazily refresh the cluster state once so callers don't have to remember to
            # call get_cluster() first. get_cluster() is undecorated (no recursion) and we
            # skip listing queues/node groups to keep this cheap.
            # Surface the refresh error as-is: otherwise a throttle / AccessDenied / not-found
            # would be reported as a misleading "must be ACTIVE (current: None)".
            if getattr(self, "_cluster_state", None) is None:
                _refresh = self.get_cluster(
                    list_queues=False, list_compute_node_groups=False
                )
                if _refresh.get("success") is False:
                    return _refresh

            if getattr(self, "_cluster_state", None) != "ACTIVE":
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Cluster {getattr(self, '_cluster_name', 'UNKNOWN')} must be in ACTIVE state (current: {getattr(self, '_cluster_state', 'UNKNOWN')}) Run get_cluster() to refresh the cluster state."
                    )
                )

            return func(self, *args, **kwargs)

        return wrapper

    return decorator


class SocaAWSPCSClient:
    """
    AWS PCS Client for SOCA

    Requirements (for now - this is an alpha client)

    For PCS cluster (if not using existing): VPC ID + Subnet IDs + Security Group
    For PCS Compute Node:  IAM instance profile + Launch Template
    """

    def __init__(self, cluster_name: str, region_name: Optional[str] = None):
        _pcs_boto = get_boto(service_name="pcs", region_name=region_name)
        if _pcs_boto.get("success") is False:
            # Fail loudly at construction rather than NPE on the first API call.
            raise RuntimeError(
                f"Unable to initialize PCS boto3 client for {cluster_name}: {_pcs_boto.get('message')}"
            )
        self._pcs_client = _pcs_boto.message
        self._region_name = region_name
        self._cluster_name = cluster_name

        # _cluster_identifier / _cluster_state will be automatically populated after a create_cluster() or a successfull get_cluster()
        self._cluster_identifier = None
        self._cluster_slurmctld_endpoint = None
        self._cluster_state = None
        self._cluster_subnet_ids = None
        self._cluster_security_group_ids = None
        self._soca_scheduler_info = None
        # Memoized so the edh:ClusterId tag lookup does not hit SSM on every create call.
        self._edh_cluster_id = None
        # Memoized result of the edh:visibility tag gate (see _check_cluster_visible). Only a
        # positive result is cached; a refusal is re-evaluated on the next call.
        self._cluster_visible = False
        # GetCluster payload, described once per client instance (instances are per-request)
        # and shared by the visibility gate, get_cluster(), get_client() and the bootstrap
        # render. See _describe_cluster(); pass refresh=True to re-read live state.
        self._cluster_obj = None

    def _describe_cluster(self, refresh: bool = False) -> Dict[str, Any]:
        """
        Return the PCS GetCluster "cluster" payload, calling the API only on first use (or when
        refresh=True). Raises like the boto3 call so callers keep their own error mapping.
        """
        if refresh or self._cluster_obj is None:
            self._cluster_obj = self._pcs_client.get_cluster(
                clusterIdentifier=self._cluster_name
            ).get("cluster", {})
        return self._cluster_obj

    @property
    def cluster_slurmctld_endpoint(self) -> Optional[Dict[str, Any]]:
        if not self._cluster_slurmctld_endpoint:
            self.get_cluster()
        return self._cluster_slurmctld_endpoint

    @property
    def cluster_identifier(self) -> Optional[str]:
        return self._cluster_identifier

    @property
    def cluster_name(self) -> Optional[str]:
        return self._cluster_name

    @property
    def cluster_state(self) -> Optional[str]:
        return self._cluster_state

    @property
    def cluster_security_group_ids(self) -> Optional[List[str]]:
        return self._cluster_security_group_ids

    @property
    def soca_scheduler_info(self) -> Optional[SocaHpcSchedulerProvider]:
        return self._soca_scheduler_info

    # ------------------------------------------------------------------ helpers

    def _pcs_error(self, err: Exception, action: str) -> SocaError:
        """
        Map a boto3/PCS exception to a SocaError with a consistent, actionable message.
        Distinguishes the common ClientError codes so callers can reason about the failure
        (not found / access denied / conflict / throttling) instead of parsing a string.
        """
        if isinstance(err, ClientError):
            _code = err.response.get("Error", {}).get("Code", "")
            if _code == "ResourceNotFoundException":
                return SocaError.GENERIC_ERROR(
                    helper=f"{action} failed: PCS resource not found for cluster {self._cluster_name} ({err})"
                )
            if _code == "AccessDeniedException":
                return SocaError.GENERIC_ERROR(
                    helper=f"{action} failed: access denied. Verify IAM permissions ({err})"
                )
            if _code in ("ConflictException", "ResourceAlreadyExistsException"):
                return SocaError.GENERIC_ERROR(
                    helper=f"{action} failed: conflicting state or resource already exists ({err})"
                )
            if _code in ("ThrottlingException", "TooManyRequestsException"):
                return SocaError.GENERIC_ERROR(
                    helper=f"{action} failed: throttled by PCS, retry later ({err})"
                )
            if _code == "ServiceQuotaExceededException":
                return SocaError.GENERIC_ERROR(
                    helper=f"{action} failed: PCS service quota exceeded ({err})"
                )
            return SocaError.GENERIC_ERROR(
                helper=f"{action} failed for {self._cluster_name}: {err}"
            )
        return SocaError.GENERIC_ERROR(
            helper=f"{action} failed for {self._cluster_name}: {err}"
        )

    @staticmethod
    def _ssm_default(key: str, as_list: bool = False) -> Optional[Any]:
        """Read an EDH SocaConfig/SSM value, returning None when it cannot be resolved."""
        _cfg = SocaConfig(key=key)
        if as_list:
            return _cfg.get_value(return_as=list).get("message")
        return _cfg.get_value().get("message")

    def _edh_cluster_id_value(self) -> Optional[str]:
        """Resolve (and memoize) the EDH cluster id used for the edh:ClusterId tag."""
        if self._edh_cluster_id is None:
            self._edh_cluster_id = self._ssm_default("/configuration/ClusterId")
        return self._edh_cluster_id

    def _has_edh_visibility_tag(self, tags: Optional[Dict[str, str]]) -> bool:
        """
        True only when tags carry this environment's edh:visibility:<cluster id> key AND its
        value is exactly "true" (case-sensitive, matching the controller IAM policy). A missing
        key, any other value, or an unresolvable cluster id returns False.
        """
        _cluster_id = self._edh_cluster_id_value()
        if not _cluster_id or not tags:
            return False
        return tags.get(f"edh:visibility:{_cluster_id}") == "true"

    def _with_edh_tags(
        self, tags: Optional[Dict[str, str]], resource_desc: str
    ) -> Dict[str, str]:
        """
        Merge the caller's tags with the mandatory EDH tags:
          - edh:ClusterId=<cluster id>          -- the ABAC key the controller IAM policy gates
                                                    create/delete on, unique to this EDH
                                                    environment.
          - edh:visibility:<cluster id>=true    -- the app-side visibility marker; enough for
                                                    this environment to see/use a resource, but
                                                    not to delete it (that needs edh:ClusterId).
        Both are set last so they always win over caller-supplied values, and only when the
        cluster id resolves.
        """
        _tags: Dict[str, str] = dict(tags) if tags else {}
        _cluster_id = self._edh_cluster_id_value()
        if _cluster_id:
            _tags["edh:ClusterId"] = _cluster_id
            _tags[f"edh:visibility:{_cluster_id}"] = "true"
        else:
            logger.warning(
                f"Unable to resolve /configuration/ClusterId; creating {resource_desc} "
                "without the edh:ClusterId / edh:visibility tags"
            )
        return _tags

    def _get_resource_tags(self, resource_arn: str) -> Dict[str, str]:
        """
        Fetch a PCS resource's tags via ListTagsForResource. PCS Cluster / ComputeNodeGroup /
        Queue describe objects do NOT carry a `tags` member (unlike the EC2 launch template),
        so tags are only retrievable through this call keyed by the resource ARN. Returns an
        empty dict on any failure so the caller can fail safe.
        """
        try:
            return (
                self._pcs_client.list_tags_for_resource(resourceArn=resource_arn).get(
                    "tags"
                )
                or {}
            )
        except Exception as err:
            logger.error(f"Unable to list tags for PCS resource {resource_arn}: {err}")
            return {}

    def _check_cluster_visible(self) -> Optional[SocaError]:
        """
        Visibility gate for every cluster-scoped operation: the cluster must carry
        edh:visibility:<cluster id>=true. Returns None when visible, otherwise a SocaError.

        Only the cluster ARN is read (to fetch its tags -- PCS describe payloads carry none);
        nothing about the cluster is returned to the caller unless the gate passes. Fails
        closed: an unresolvable cluster id, ARN, or tag set refuses access.
        """
        if self._cluster_visible:
            return None

        _cluster_id = self._edh_cluster_id_value()
        if not _cluster_id:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to access PCS cluster {self._cluster_name}: unable to resolve "
                    "this EDH environment's cluster id (/configuration/ClusterId)"
                )
            )

        try:
            _arn = self._describe_cluster().get("arn")
        except Exception as err:
            return self._pcs_error(err, f"Resolve PCS cluster {self._cluster_name}")
        if not _arn:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to access PCS cluster {self._cluster_name}: its ARN could not "
                    "be resolved, so its visibility tag cannot be verified"
                )
            )

        if not self._has_edh_visibility_tag(self._get_resource_tags(_arn)):
            logger.warning(
                f"PCS cluster {self._cluster_name} is missing edh:visibility:{_cluster_id}=true; refusing access"
            )
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"PCS cluster {self._cluster_name} is not visible to this EDH environment "
                    f"(missing edh:visibility:{_cluster_id}=true)"
                )
            )

        self._cluster_visible = True
        return None

    def _validate_edh_tags(
        self, resource_arn: Optional[str], resource_desc: str
    ) -> Optional[SocaError]:
        """
        Guard a delete: confirm the resource carries edh:ClusterId=<cluster id> (the ABAC key
        _with_edh_tags() stamps on create and the controller IAM policy gates deletes on).
        edh:visibility:<cluster id>=true only grants visibility (enforced separately by the
        cluster gate / launch template filters) and is NOT sufficient to delete. Returns
        None when the tag matches (delete may proceed); otherwise a SocaError explaining the refusal,
        so a delete can never touch a resource EDH did not create. Fails safe: if this
        environment's cluster id cannot be resolved, or the resource ARN / its tags cannot be
        read, we cannot prove ownership, so the delete is refused rather than allowed.

        Tags are fetched from PCS via ListTagsForResource keyed by resource_arn -- PCS describe
        objects (cluster / compute node group / queue) do not include a `tags` member. For EC2
        resources (launch templates) whose tags ARE returned by describe, call
        _validate_edh_tags_dict directly with the already-fetched tag dict instead.
        """
        if not resource_arn:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to delete {resource_desc}: the resource ARN could not be "
                    "resolved, so its EDH ownership tags cannot be verified"
                )
            )
        return self._validate_edh_tags_dict(
            self._get_resource_tags(resource_arn), resource_desc
        )

    def _validate_edh_tags_dict(
        self, tags: Optional[Dict[str, str]], resource_desc: str
    ) -> Optional[SocaError]:
        """
        Core EDH ownership check operating on an already-fetched tag dict (see _validate_edh_tags
        for the full semantics). Used directly for EC2 resources whose describe response includes
        tags; PCS resources go through _validate_edh_tags, which fetches the tags first.
        """
        _tags = tags or {}
        _cluster_id = self._edh_cluster_id_value()
        if not _cluster_id:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to delete {resource_desc}: unable to resolve this EDH "
                    "environment's cluster id (/configuration/ClusterId), so ownership of the "
                    "resource cannot be verified"
                )
            )
        if _tags.get("edh:ClusterId") != _cluster_id:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to delete {resource_desc}: its edh:ClusterId tag "
                    f"({_tags.get('edh:ClusterId')!r}) does not match this EDH environment "
                    f"({_cluster_id!r})"
                )
            )
        return None

    def _validate_ami(self, ami_id: str) -> Optional[SocaError]:
        """
        Guard a create: confirm the AMI id exists and is available before we register it on a
        launch template or a compute node group. PCS/EC2 only surface a bad AMI at launch time
        (a stuck node group, not a clear API error), so we describe it up-front here.

        Delegates to the shared utils.aws.ec2_helper.describe_images helper, which filters on
        state=available; an empty Images list therefore means the AMI is missing, inaccessible,
        or not yet available. Returns None when the AMI is usable; otherwise a SocaError. Note
        this helper is scoped to the SOCA install region, which is normally where the PCS
        cluster runs too. Returns None when usable; otherwise a SocaError explaining why not.
        """
        if not ami_id:
            return SocaError.GENERIC_ERROR(
                helper="No AMI id provided; an AMI id is required to validate against EC2"
            )

        _described = describe_images(image_ids=[ami_id])
        if _described.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to validate AMI {ami_id}: {_described.get('message')}"
            )

        _images = (_described.get("message") or {}).get("Images", [])
        if not _images:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"AMI {ami_id} was not found, is not accessible to this account, or is not "
                    "in the 'available' state"
                )
            )
        return None

    def _validate_subnets(self, subnet_ids: List[str]) -> Optional[SocaError]:
        """
        Guard a create: confirm every subnet id exists before we register it on a compute node
        group, so an unknown subnet is rejected here rather than surfacing later as a node group
        that never launches.

        Delegates to the shared utils.aws.ec2_helper.describe_subnets helper; an invalid id
        raises InvalidSubnetID.NotFound (surfaced as success=False). Like the AMI check, this
        helper is scoped to the SOCA install region -- normally where the PCS cluster runs too.
        Returns None when all subnets resolve; otherwise a SocaError explaining the failure.
        """
        if not subnet_ids:
            return SocaError.GENERIC_ERROR(
                helper="No subnet ids provided; at least one subnet id is required to validate"
            )

        _described = describe_subnets(subnet_ids=subnet_ids)
        if _described.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to validate subnet(s) {subnet_ids}: {_described.get('message')}"
            )

        # describe_subnets returns only the subnets it could resolve; flag any that are missing.
        _found = {
            s.get("SubnetId")
            for s in (_described.get("message") or {}).get("Subnets", [])
        }
        _missing = [s for s in subnet_ids if s not in _found]
        if _missing:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Subnet(s) {_missing} were not found or are not accessible to this account"
                )
            )
        return None

    def _load_launch_template_data(self, path: str) -> Dict[str, Any] | SocaError:
        """
        Load an EC2 LaunchTemplateData body from a .json / .yaml / .yml file.

        Returns the parsed dict, or a SocaError if the file is missing, has an unsupported
        extension, cannot be parsed, or does not deserialize to a mapping.
        """
        if not path or not isinstance(path, str):
            return SocaError.GENERIC_ERROR(
                helper="A non-empty launch_template_data_path is required"
            )
        if not os.path.isfile(path):
            return SocaError.GENERIC_ERROR(
                helper=f"Launch template data file {path} does not exist or is not a file"
            )

        _ext = os.path.splitext(path)[1].lower()
        if _ext not in (".json", ".yaml", ".yml"):
            return SocaError.GENERIC_ERROR(
                helper=f"Unsupported launch template data file extension {_ext!r} ({path}); use .json, .yaml or .yml"
            )

        try:
            with open(path, "r", encoding="utf-8") as _fh:
                # yaml.safe_load parses JSON too (JSON is a subset of YAML), but branch by
                # extension so parse errors are reported against the format the user intended.
                if _ext == ".json":
                    _data = json.load(_fh)
                else:
                    _data = yaml.safe_load(_fh)
        except (OSError, ValueError, yaml.YAMLError) as _err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to parse launch template data file {path}: {_err}"
            )

        if not isinstance(_data, dict):
            return SocaError.GENERIC_ERROR(
                helper=f"Launch template data file {path} must contain a mapping/object, got {type(_data).__name__}"
            )
        return _data

    @classmethod
    def list_clusters(
        cls, region_name: Optional[str] = None, edh_visible_only: bool = True
    ) -> SocaResponse | SocaError:
        """
        List the PCS clusters in the account/region.

        This is a fleet-wide operation, not tied to a single cluster, so it is a classmethod
        that builds its own boto3 client rather than reusing an instance bound to one
        cluster_name. Returns the raw PCS cluster summaries (name, id, arn, status, ...).

        With edh_visible_only (default), only clusters visible to this EDH environment are
        returned: they must carry edh:visibility:<cluster id>=true. ListClusters summaries
        carry no tags, so they are fetched per cluster via ListTagsForResource. Fails closed: a
        cluster whose tags cannot be read is hidden, and an unresolvable
        /configuration/ClusterId returns an error rather than every cluster.
        """
        _pcs_boto = get_boto(service_name="pcs", region_name=region_name)
        if _pcs_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize PCS boto3 client: {_pcs_boto.get('message')}"
            )
        _client = _pcs_boto.message

        _edh_cluster_id = None
        if edh_visible_only:
            _edh_cluster_id = (
                SocaConfig(key="/configuration/ClusterId").get_value().get("message")
            )
            if not _edh_cluster_id:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        "Unable to resolve /configuration/ClusterId, so PCS clusters owned "
                        "by this EDH environment cannot be identified"
                    )
                )

        _clusters: List[Dict[str, Any]] = []
        try:
            _paginator = _client.get_paginator("list_clusters")
            for _page in _paginator.paginate():
                _clusters.extend(_page.get("clusters", []))
        except Exception as err:
            return SocaError.GENERIC_ERROR(helper=f"Unable to list PCS clusters: {err}")

        if not edh_visible_only:
            return SocaResponse(success=True, message=_clusters)

        _visibility_key = f"edh:visibility:{_edh_cluster_id}"

        def _cluster_tags(_arn: str) -> Optional[Dict[str, str]]:
            try:
                return _client.list_tags_for_resource(resourceArn=_arn).get("tags") or {}
            except Exception as err:
                logger.error(
                    f"Unable to list tags for PCS cluster {_arn}; hiding it: {err}"
                )
                return None

        # One ListTagsForResource per cluster: fetch them concurrently, keep the listing order.
        _with_arn = [_c for _c in _clusters if _c.get("arn")]
        if not _with_arn:
            return SocaResponse(success=True, message=[])
        with ThreadPoolExecutor(max_workers=min(10, len(_with_arn))) as _pool:
            _all_tags = list(_pool.map(_cluster_tags, [_c["arn"] for _c in _with_arn]))
        _visible: List[Dict[str, Any]] = [
            _cluster
            for _cluster, _tags in zip(_with_arn, _all_tags)
            if _tags and _tags.get(_visibility_key) == "true"
        ]
        return SocaResponse(success=True, message=_visible)

    def create_cluster(
        self,
        subnet_ids: Optional[List[str]] = None,
        security_group_ids: Optional[List[str]] = None,
        size: Literal["SMALL", "MEDIUM", "LARGE"] = "SMALL",
        scheduler: Optional[Dict[str, Any]] = None,
        network_type: Literal["IPV4", "IPV6"] = "IPV4",
        slurm_configuration: Optional[Dict[str, Any]] = None,
        client_token: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> SocaResponse | SocaError:
        """
        Create an AWS PCS cluster.

        Mirrors the full boto3 pcs.create_cluster() request surface:
        https://docs.aws.amazon.com/boto3/latest/reference/services/pcs/client/create_cluster.html

        Args:
            subnet_ids: Subnet(s) for the cluster networking. If not provided, defaults to the
                EDH private subnets from /configuration/PrivateSubnets on SSM. Note that PCS
                currently supports a single subnet.
            security_group_ids: Security group(s) attached to the cluster. If not provided,
                defaults to the EDH compute node security group from
                /configuration/ComputeNodeSecurityGroup on SSM.
            size: Cluster size. One of SMALL | MEDIUM | LARGE.
            scheduler: Scheduler dict {"type": "SLURM", "version": <ver>}. PCS only supports SLURM.
                Supported versions: 24.11 | 25.05 | 25.11 | 26.05. Defaults to SLURM 26.05.
            network_type: IPV4 | IPV6. Defaults to IPV4.
            slurm_configuration: Optional Slurm settings, e.g.
                {
                    "scaleDownIdleTimeInSeconds": 600,
                    "slurmCustomSettings": [{"parameterName": "...", "parameterValue": "..."}],
                    "slurmdbdCustomSettings": [{"parameterName": "...", "parameterValue": "..."}],
                    "cgroupCustomSettings": [{"parameterName": "...", "parameterValue": "..."}],
                    "accounting": {"mode": "STANDARD" | "NONE", "defaultPurgeTimeInDays": -1},
                    "slurmRest": {"mode": "STANDARD" | "NONE"},
                }
            client_token: Optional idempotency token. When provided, retries with the same
                token will not create duplicate clusters (useful for double-submit-prone
                on-demand spawns from the web app). Omitted from the request when None.
            tags: Optional key/value tags applied to the cluster. The edh:ClusterId tag is
                always added (and takes precedence) so the PCS cluster is traceable back to the
                EDH environment that created it.

        Returns:
            SocaResponse(message={"id": <cluster id>, "name": <cluster name>}) on success.
        """

        if scheduler is None:
            scheduler = {"type": "SLURM", "version": "26.05"}

        # Default to the EDH private subnets registered on SSM when the caller did not specify any.
        if not subnet_ids:
            subnet_ids = self._ssm_default(
                "/configuration/PrivateSubnets", as_list=True
            )
            if not subnet_ids:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        "No subnet_ids provided and /configuration/PrivateSubnets could not be "
                        f"resolved on SSM; cannot create PCS cluster {self._cluster_name}"
                    )
                )
            logger.info(
                f"No subnet_ids provided, defaulting to EDH private subnets: {subnet_ids}"
            )

        # Default to the EDH compute node security group registered on SSM when none was given.
        if not security_group_ids:
            _default_compute_sg = self._ssm_default(
                "/configuration/ComputeNodeSecurityGroup"
            )
            if not _default_compute_sg:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        "No security_group_ids provided and /configuration/ComputeNodeSecurityGroup "
                        f"could not be resolved on SSM; cannot create PCS cluster {self._cluster_name}"
                    )
                )
            security_group_ids = [_default_compute_sg]
            logger.info(
                f"No security_group_ids provided, defaulting to EDH compute node security group: {security_group_ids}"
            )

        # PCS CreateCluster accepts exactly one subnet. The EDH PrivateSubnets default resolves
        # to several (one per AZ), and a caller may paste more than one, so cap to the first and
        # log the rest instead of letting PCS reject the request with a ValidationException.
        if subnet_ids and len(subnet_ids) > 1:
            logger.info(
                f"PCS supports a single subnet; using {subnet_ids[0]} of {subnet_ids} "
                f"for cluster {self._cluster_name}"
            )
            subnet_ids = [subnet_ids[0]]

        if not self._edh_cluster_id_value():
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to create PCS cluster {self._cluster_name}: unable to resolve this EDH environment's cluster "
                    "id (/configuration/ClusterId), so the mandatory edh:visibility tag cannot be set"
                )
            )
        _tags = self._with_edh_tags(tags, f"PCS cluster {self._cluster_name}")

        # Only include optional keys when the caller provided them so boto3 applies its own
        # defaults for anything left unset.
        _create_cluster_args: Dict[str, Any] = {
            "clusterName": self._cluster_name,
            "scheduler": scheduler,
            "size": size,
            "networking": {
                "subnetIds": subnet_ids,
                "securityGroupIds": security_group_ids,
                "networkType": network_type,
            },
        }

        if slurm_configuration is not None:
            _create_cluster_args["slurmConfiguration"] = slurm_configuration
        if client_token:
            _create_cluster_args["clientToken"] = client_token
        if _tags:
            _create_cluster_args["tags"] = _tags

        try:
            _create_pcs = self._pcs_client.create_cluster(**_create_cluster_args)
            self._cluster_identifier = _create_pcs.get("cluster", {}).get("id", None)
            if self._cluster_identifier is None:
                return SocaError.GENERIC_ERROR(
                    helper="Unable to retrieve cluster ID from create_cluster()"
                )
            self._cluster_state = "CREATING"
            self._cluster_security_group_ids = security_group_ids
            self._cluster_subnet_ids = subnet_ids
            return SocaResponse(
                success=True,
                message={"id": self._cluster_identifier, "name": self._cluster_name},
            )

        except Exception as err:
            return self._pcs_error(err, f"Create PCS cluster {self._cluster_name}")

    @cluster_must_be_visible()
    def delete_cluster(self) -> SocaResponse | SocaError:
        """
        Delete the PCS cluster. PCS refuses to delete a cluster that still has queues or compute
        node groups; that dependency error is surfaced as-is.
        """
        # Never delete a cluster this EDH environment did not create: validate its tags first.
        try:
            _cluster_obj = self._describe_cluster()
        except Exception as err:
            return self._pcs_error(err, f"Get PCS cluster {self._cluster_name}")
        # Callers use cluster_identifier after the delete (e.g. to unregister it from EDH).
        if self._cluster_identifier is None:
            self._cluster_identifier = _cluster_obj.get("id")
        _invalid = self._validate_edh_tags(
            _cluster_obj.get("arn"), f"PCS cluster {self._cluster_name}"
        )
        if _invalid is not None:
            return _invalid

        try:
            self._pcs_client.delete_cluster(clusterIdentifier=self._cluster_name)
            return SocaResponse(
                success=True,
                message=f"Delete initiated for {self._cluster_name}, your PCS cluster will be removed shortly",
            )
        except Exception as err:
            return self._pcs_error(err, f"Delete PCS cluster {self._cluster_name}")

    @cluster_must_be_visible()
    def get_cluster(
        self,
        list_queues: bool = True,
        list_compute_node_groups: bool = True,
        refresh: bool = False,
    ) -> SocaResponse | SocaError:
        try:
            logger.info(
                f"Retrieve {self._cluster_name} info with {list_queues} and {list_compute_node_groups}"
            )
            _queues = []
            _compute_node_groups = []
            # Reuses the describe the visibility gate just made; refresh=True re-reads it.
            _cluster_info = {"cluster": self._describe_cluster(refresh=refresh)}
            self._cluster_state = _cluster_info.get("cluster", {}).get("status", "")
            if self._cluster_identifier is None:
                self._cluster_identifier = _cluster_info.get("cluster", {}).get(
                    "id", None
                )

            if self._cluster_security_group_ids is None:
                self._cluster_security_group_ids = (
                    _cluster_info.get("cluster", {})
                    .get("networking", {})
                    .get("securityGroupIds", None)
                )
            if self._cluster_subnet_ids is None:
                self._cluster_subnet_ids = (
                    _cluster_info.get("cluster", {})
                    .get("networking", {})
                    .get("subnetIds", None)
                )
            logger.debug(f"{self._cluster_name} is in {self._cluster_state} state.")

            _cluster_endpoints = _cluster_info.get("cluster", {}).get("endpoints", [])
            if self._cluster_slurmctld_endpoint is None:
                logger.debug(f"Found cluster endpoints: {_cluster_endpoints}")
                for _endpoint in _cluster_endpoints:
                    if _endpoint.get("type", "") == "SLURMCTLD":
                        self._cluster_slurmctld_endpoint = _endpoint

            if list_queues is True:
                if self._cluster_state == "ACTIVE":
                    _get_queues = self.list_queues()
                    if _get_queues.get("success") is True:
                        _queues = _get_queues.get("message")
                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=_get_queues.get("message")
                        )
                else:
                    logger.warning(
                        f"list_queues is set to True but {self._cluster_state=} is not ACTIVE. Ignoring call and returning empty list"
                    )

            if list_compute_node_groups:
                if self._cluster_state == "ACTIVE":
                    _get_compute_node_groups = self.list_compute_node_groups()
                    if _get_compute_node_groups.get("success") is True:
                        _compute_node_groups = _get_compute_node_groups.get("message")
                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=_get_compute_node_groups.get("message")
                        )
                else:
                    logger.warning(
                        f"list_compute_node_groups is set to True but {self._cluster_state=} is not ACTIVE. Ignoring call and returning empty list"
                    )

            _pcs_cluster_info = {
                "cluster": _cluster_info.get("cluster", {}),
                "queues": _queues,
                "compute_node_groups": _compute_node_groups,
            }
            logger.debug(f"{self._cluster_name} result: {_pcs_cluster_info} ")

            return SocaResponse(
                success=True,
                message=_pcs_cluster_info,
            )

        except ClientError as err:
            _error_code = err.response["Error"]["Code"]
            if _error_code == "ResourceNotFoundException":
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find a PCS cluster named {self._cluster_name}. Call create_cluster() to first create this cluster"
                )
            elif _error_code == "AccessDeniedException":
                return SocaError.GENERIC_ERROR(
                    helper=f"Access denied when retrieving PCS cluster {self._cluster_name}. Verify IAM permissions."
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to retrieve cluster information for {self._cluster_name} because of {err}",
                )

        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve cluster information for {self._cluster_name} because of {err}",
            )

    @cluster_must_be_active()
    def get_client(self, include_auth_key: bool = True) -> SocaResponse | SocaError:
        """
        Build what an EDH host needs to connect to this PCS cluster as a Slurm client through
        sackd, using the same layout as `edhctl pcs register` (tools/edhctl/commands/pcs.py) and
        the PCS Connect tab: PCS Slurm at /opt/aws/pcs/scheduler/slurm-<version>, one sackd per
        cluster with its runtime dir at /run/slurm-<pcs cluster id>. Requires the cluster to be
        ACTIVE (enforced by cluster_must_be_active).

        Args:
            include_auth_key: When True (default), fetch and decode the shared Slurm key from
                Secrets Manager (base64-decoded to raw bytes). When False, only the secret
                ARN/version is returned (no sensitive key material).

        Returns:
            SocaResponse(message={
                "cluster_name": str,
                "cluster_id": str,
                "slurm_version": str,
                "slurmctld": {"ip": str, "port": str},
                "install_prefix_path": str,     # /opt/aws/pcs/scheduler/slurm-<version>
                "install_sysconfig_path": str,  # /run/slurm-<id>/conf (sackd configless conf)
                "sack_socket_path": str,        # /run/slurm-<id>/sack.socket
                "edhctl_command": str,          # `edhctl pcs register ...` to register with EDH
                "auth_key": {
                    "secret_arn": str,
                    "secret_version": str,
                    "slurm_key": bytes | None,  # decoded key material
                },
            })
        """
        logger.info(
            f"Building SLURM client config for PCS cluster {self._cluster_name}"
        )
        try:
            _cluster = self._describe_cluster()
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve PCS cluster {self._cluster_name} to build client config because of {err}"
            )

        # Locate the SLURMCTLD endpoint. IPv4 clusters expose privateIpAddress; IPv6-only
        # clusters leave it empty and populate ipv6Address instead.
        _slurmctld = None
        for _endpoint in _cluster.get("endpoints", []):
            if _endpoint.get("type") == "SLURMCTLD":
                _slurmctld = _endpoint
                break
        if _slurmctld is None:
            return SocaError.GENERIC_ERROR(
                helper=f"No SLURMCTLD endpoint found for PCS cluster {self._cluster_name}; cannot build client config"
            )
        _slurmctld_ip = _slurmctld.get("privateIpAddress") or _slurmctld.get(
            "ipv6Address"
        )
        if not _slurmctld_ip:
            return SocaError.GENERIC_ERROR(
                helper=f"SLURMCTLD endpoint for PCS cluster {self._cluster_name} has no reachable IP address"
            )

        _auth_key = _cluster.get("slurmConfiguration", {}).get("authKey", {}) or {}
        _secret_arn = _auth_key.get("secretArn")
        _secret_version = _auth_key.get("secretVersion")
        if not _secret_arn:
            return SocaError.GENERIC_ERROR(
                helper=f"PCS cluster {self._cluster_name} has no slurmConfiguration.authKey; cannot build client config"
            )

        # The PCS secret holds the SLURM key as a base64 string; the runbook base64-decodes
        # it into slurm.key. Decode here so the caller can write the bytes directly.
        _slurm_key = None
        if include_auth_key:
            _get_secret = get_boto(
                service_name="secretsmanager", region_name=self._region_name
            )
            if _get_secret.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to create a Secrets Manager client to read the SLURM auth key because of {_get_secret.get('message')}"
                )
            _secretsmanager_client = _get_secret.message
            try:
                _secret_kwargs: Dict[str, Any] = {"SecretId": _secret_arn}
                if _secret_version:
                    _secret_kwargs["VersionId"] = _secret_version
                _secret_value = _secretsmanager_client.get_secret_value(
                    **_secret_kwargs
                )
                _secret_string = _secret_value.get("SecretString")
                if _secret_string is not None:
                    _slurm_key = base64.b64decode(_secret_string.strip())
                elif _secret_value.get("SecretBinary"):
                    _slurm_key = _secret_value["SecretBinary"]
            except Exception as err:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to read SLURM auth key {_secret_arn} from Secrets Manager because of {err}"
                )

        _slurm_version = (_cluster.get("scheduler") or {}).get("version")
        _pcs_cluster_id = _cluster.get("id")
        _install_prefix_path = f"/opt/aws/pcs/scheduler/slurm-{_slurm_version}"
        _sackd_runtime_path = f"/run/slurm-{_pcs_cluster_id}"

        # `edhctl pcs register` resolves the endpoint, Slurm version and paths from the PCS API
        # and registers the cluster with provider aws_pcs, so it never drifts from this layout.
        _edhctl_command = (
            "/opt/edh/$EDH_CLUSTER_ID/cluster_manager/edhctl pcs register "
            f'--cluster-identifier "{self._cluster_name}" --force'
        )

        return SocaResponse(
            success=True,
            message={
                "cluster_name": self._cluster_name,
                "cluster_id": _pcs_cluster_id,
                "slurm_version": _slurm_version,
                "slurmctld": {
                    "ip": _slurmctld_ip,
                    "port": _slurmctld.get("port"),
                },
                "install_prefix_path": _install_prefix_path,
                "install_sysconfig_path": f"{_sackd_runtime_path}/conf",
                "sack_socket_path": f"{_sackd_runtime_path}/sack.socket",
                "edhctl_command": _edhctl_command,
                "auth_key": {
                    "secret_arn": _secret_arn,
                    "secret_version": _secret_version,
                    "slurm_key": _slurm_key,
                },
            },
        )

    @cluster_must_be_active()
    def export_slurm_key_to_edh(self) -> SocaResponse | SocaError:
        """
        Export this PCS cluster's shared SLURM auth key from Secrets Manager onto the EDH
        Controller filesystem, so a login node (or the controller) can use it as slurm.key.

        Writes the base64-decoded key to:
            /apps/edh/<edh_cluster_id>/shared/pcs/<pcs_cluster_id>/slurm.key

        This is the equivalent of the AWS "get-secret-value | base64 -d | tee slurm.key" flow,
        but keeps the key material off the operator's shell history. Because the key is a
        long-lived shared credential, the file and its parent directory are locked down to
        root only (dir 0700, file 0600, both owned by root) per BSC/ARCC filesystem-permission
        guidance -- group and other get NO access. Missing parent directories are created
        0755 root:root. Client nodes read the key directly from this shared path, so the
        administrator grants the account sackd runs as read access via a group (EFS/NFS has no
        POSIX ACLs): every parent directory must be traversable and the group must have the
        same GID on every node.

        Requires the cluster to be ACTIVE (cluster_must_be_active). Returns the written path.
        """
        _client_get = self.get_client(include_auth_key=True)
        if _client_get.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to build client config to export the SLURM key because of {_client_get.get('message')}"
            )
        _client_info = _client_get.get("message") or {}
        _auth_key = _client_info.get("auth_key", {}) or {}
        _slurm_key = _auth_key.get("slurm_key")
        if not _slurm_key:
            return SocaError.GENERIC_ERROR(
                helper=f"No SLURM auth key material was returned for PCS cluster {self._cluster_name}; cannot export it"
            )

        _edh_cluster_id = self._edh_cluster_id_value()
        if not _edh_cluster_id:
            return SocaError.GENERIC_ERROR(
                helper="Unable to resolve the EDH cluster id (/configuration/ClusterId); cannot determine the export path"
            )

        _pcs_cluster_id = _client_info.get("cluster_id") or self._cluster_name
        _pcs_root = pathlib.Path(f"/apps/edh/{_edh_cluster_id}/shared/pcs")
        _key_dir = _pcs_root / _pcs_cluster_id
        _key_path = _key_dir / "slurm.key"

        # Refuse to overwrite an existing key: it may already be in use, and silently replacing
        # it could break login nodes relying on the current key. The operator must delete it
        # from the filesystem first before re-exporting.
        if _key_path.exists():
            return SocaError.GENERIC_ERROR(
                helper=f"A SLURM key already exists at {_key_path}. Delete it from the filesystem first before re-exporting."
            )

        try:
            # Missing parents are created one by one as 0755 root:root (traversable, NOT writable
            # by group/other). Do not use mkdir(parents=True): parents then get the default 0777
            # masked by the umask -- world-writable under umask 0 -- ignoring `mode`.
            _previous_umask = os.umask(0o022)
            try:
                for _parent in reversed(_key_dir.parents):
                    if not _parent.exists():
                        _parent.mkdir(mode=0o755)
                        os.chown(_parent, 0, 0)

                # Anyone able to write the pcs/ root could rename a cluster dir and plant their own
                # slurm.key, so it must be root-owned and never group/world-writable. Also repairs
                # a pcs/ root left 0777 by a previous export.
                os.chown(_pcs_root, 0, 0)
                _pcs_root_mode = os.stat(_pcs_root).st_mode & 0o7777
                if _pcs_root_mode & 0o022:
                    os.chmod(_pcs_root, _pcs_root_mode & ~0o022)
                    logger.warning(
                        f"{_pcs_root} was group/world-writable ({oct(_pcs_root_mode)}), removed write access for group/other"
                    )

                # Refuse a pre-existing key dir we did not create (symlink or not root-owned):
                # it may have been planted while the pcs/ root was writable.
                if _key_dir.is_symlink() or (
                    _key_dir.exists() and os.lstat(_key_dir).st_uid != 0
                ):
                    return SocaError.GENERIC_ERROR(
                        helper=f"{_key_dir} already exists but is a symlink or is not owned by root. Inspect and remove it before exporting the SLURM key."
                    )
                _key_dir.mkdir(mode=0o700, exist_ok=True)
            finally:
                os.umask(_previous_umask)
            # The key dir and the key file itself (below) are root-only: 0700 / 0600 root:root.
            os.chmod(_key_dir, 0o700)
            os.chown(_key_dir, 0, 0)

            # Write atomically to a temp file in the same (root-only) dir, then rename over the
            # target so a reader never sees a partially written key. 0600 root:root.
            _tmp_path = _key_dir / ".slurm.key.tmp"
            _fd = os.open(_tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(_fd, _slurm_key)
            finally:
                os.close(_fd)
            os.chmod(_tmp_path, 0o600)
            os.chown(_tmp_path, 0, 0)
            os.replace(_tmp_path, _key_path)
        except PermissionError as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to write the SLURM key to {_key_path} (permission denied). The web service must run as root to export it: {err}"
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to export the SLURM key to {_key_path} because of {err}"
            )

        logger.info(
            f"Exported SLURM auth key for PCS cluster {self._cluster_name} to {_key_path} (root-only)"
        )
        return SocaResponse(
            success=True,
            message={
                "cluster_name": self._cluster_name,
                "cluster_id": _pcs_cluster_id,
                "slurm_key_path": str(_key_path),
                "secret_arn": _auth_key.get("secret_arn"),
            },
        )

    # -- Queues --
    @cluster_must_be_active()
    def list_queues(self) -> SocaResponse | SocaError:
        logger.debug(f"About to list queue for {self._cluster_name}")
        _queues = []
        try:
            _queues_paginator = self._pcs_client.get_paginator("list_queues")
            for page in _queues_paginator.paginate(
                clusterIdentifier=self._cluster_name
            ):
                _queues.extend(page.get("queues", []))

            logger.debug(
                f"Found PCS queues associated to {self._cluster_name}: {_queues}"
            )
            return SocaResponse(success=True, message=_queues)
        except Exception as err:
            return self._pcs_error(err, f"List PCS queues for {self._cluster_name}")

    @cluster_must_be_active()
    def create_queue(
        self,
        queue_name: str,
        compute_node_group_ids: Optional[List[str]] = None,
        slurm_configuration: Optional[Dict[str, Any]] = None,
        client_token: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> SocaResponse | SocaError:
        """
        Create a queue on the PCS cluster.

        Mirrors the boto3 pcs.create_queue() request surface:
        https://docs.aws.amazon.com/boto3/latest/reference/services/pcs/client/create_queue.html

        Args:
            queue_name: Name of the queue to create.
            compute_node_group_ids: Compute node group id(s) to associate with the queue. Each id
                is mapped to a computeNodeGroupConfigurations entry.
            slurm_configuration: Optional Slurm settings, e.g.
                {"slurmCustomSettings": [{"parameterName": "...", "parameterValue": "..."}]}
            client_token: Optional idempotency token. Omitted from the request when None.
            tags: Optional key/value tags applied to the queue. The edh:ClusterId tag is always
                added (and takes precedence) so the queue is traceable back to the EDH environment.

        Returns:
            SocaResponse(message={"id": <queue id>, "name": <queue name>}) on success.
        """
        logger.info(f"Creating {queue_name=} with {compute_node_group_ids=}")

        if not self._edh_cluster_id_value():
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to create PCS queue {queue_name}: unable to resolve this EDH environment's cluster "
                    "id (/configuration/ClusterId), so the mandatory edh:visibility tag cannot be set"
                )
            )
        _tags = self._with_edh_tags(tags, f"PCS queue {queue_name}")

        # Only include optional keys when provided so boto3 applies its own defaults otherwise.
        _create_queue_args: Dict[str, Any] = {
            "clusterIdentifier": self._cluster_name,
            "queueName": queue_name,
        }
        if compute_node_group_ids:
            _create_queue_args["computeNodeGroupConfigurations"] = [
                {"computeNodeGroupId": t} for t in compute_node_group_ids
            ]
        if slurm_configuration is not None:
            _create_queue_args["slurmConfiguration"] = slurm_configuration
        if client_token:
            _create_queue_args["clientToken"] = client_token
        if _tags:
            _create_queue_args["tags"] = _tags

        try:
            _create_queue = self._pcs_client.create_queue(**_create_queue_args)
            return SocaResponse(
                success=True,
                message={
                    "id": _create_queue.get("queue", {}).get("id"),
                    "name": _create_queue.get("queue", {}).get("name", queue_name),
                },
            )
        except Exception as err:
            return self._pcs_error(err, f"Create PCS queue {queue_name}")

    @cluster_must_be_visible()
    def get_queue(self, queue_identifier: str) -> SocaResponse | SocaError:
        """
        Retrieve a single queue, including its full computeNodeGroupConfigurations and
        slurmConfiguration (list_queues only returns summaries).

        Returns:
            SocaResponse(message=<queue dict>) on success.
        """
        logger.debug(f"Get queue {queue_identifier} for {self._cluster_name}")
        try:
            _get = self._pcs_client.get_queue(
                clusterIdentifier=self._cluster_name,
                queueIdentifier=queue_identifier,
            )
            return SocaResponse(success=True, message=_get.get("queue", {}))
        except Exception as err:
            return self._pcs_error(
                err, f"Get PCS queue {queue_identifier} for {self._cluster_name}"
            )

    @cluster_must_be_active()
    def update_queue(
        self,
        queue_identifier: str,
        compute_node_group_ids: Optional[List[str]] = None,
        slurm_configuration: Optional[Dict[str, Any]] = None,
    ) -> SocaResponse | SocaError:
        """
        Update a queue on the PCS cluster. PCS replaces the queue's compute node group
        configuration wholesale, so compute_node_group_ids must be the FULL desired set
        (attaching and detaching are both expressed as the resulting list). Pass an empty
        list to detach every group.

        Mirrors the boto3 pcs.update_queue() request surface:
        https://docs.aws.amazon.com/boto3/latest/reference/services/pcs/client/update_queue.html

        Args:
            queue_identifier: Name or id of the queue to update.
            compute_node_group_ids: Full desired set of compute node group id(s). None leaves
                the association untouched; [] detaches all.
            slurm_configuration: Optional Slurm settings to update.

        Returns:
            SocaResponse(message={"id": <queue id>, "name": <queue name>}) on success.
        """
        logger.info(
            f"Updating queue {queue_identifier} for {self._cluster_name} with {compute_node_group_ids=}"
        )
        # Never mutate a queue this EDH environment did not create: validate its tags first,
        # mirroring the guard on delete_queue.
        _get_queue = self.get_queue(queue_identifier)
        if _get_queue.get("success") is False:
            return _get_queue
        _invalid = self._validate_edh_tags(
            (_get_queue.get("message") or {}).get("arn"),
            f"PCS queue {queue_identifier} for {self._cluster_name}",
        )
        if _invalid is not None:
            return _invalid

        _update_queue_args: Dict[str, Any] = {
            "clusterIdentifier": self._cluster_name,
            "queueIdentifier": queue_identifier,
        }
        # None means "leave unchanged"; a list (including []) is sent so callers can detach all.
        if compute_node_group_ids is not None:
            _update_queue_args["computeNodeGroupConfigurations"] = [
                {"computeNodeGroupId": t} for t in compute_node_group_ids
            ]
        if slurm_configuration is not None:
            _update_queue_args["slurmConfiguration"] = slurm_configuration

        try:
            _update_queue = self._pcs_client.update_queue(**_update_queue_args)
            return SocaResponse(
                success=True,
                message={
                    "id": _update_queue.get("queue", {}).get("id"),
                    "name": _update_queue.get("queue", {}).get(
                        "name", queue_identifier
                    ),
                },
            )
        except Exception as err:
            return self._pcs_error(
                err, f"Update PCS queue {queue_identifier} for {self._cluster_name}"
            )

    @cluster_must_be_visible()
    def delete_queue(self, queue_identifier: str) -> SocaResponse | SocaError:
        logger.info(
            f"About to delete Queue {queue_identifier} for {self._cluster_name}"
        )
        # Never delete a queue this EDH environment did not create: validate its tags first.
        _get_queue = self.get_queue(queue_identifier)
        if _get_queue.get("success") is False:
            return _get_queue
        _invalid = self._validate_edh_tags(
            (_get_queue.get("message") or {}).get("arn"),
            f"PCS queue {queue_identifier} for {self._cluster_name}",
        )
        if _invalid is not None:
            return _invalid

        try:
            self._pcs_client.delete_queue(
                clusterIdentifier=self._cluster_name,
                queueIdentifier=queue_identifier,
            )
            return SocaResponse(
                success=True,
                message=f"Delete initiated for {queue_identifier} for {self._cluster_name}, your queue  will be removed shortly",
            )
        except Exception as err:
            return self._pcs_error(
                err, f"Delete PCS queue {queue_identifier} for {self._cluster_name}"
            )

    # -- Launch Templates --
    @staticmethod
    def _ensure_base64_user_data(user_data: Any) -> str:
        """
        Return UserData as a valid base64 string suitable for EC2 CreateLaunchTemplate.

        botocore only auto-base64-encodes UserData for RunInstances / CreateLaunchConfiguration,
        NOT CreateLaunchTemplate, so a plaintext UserData reaches EC2 unencoded and fails with
        InvalidUserData.Malformed. This makes the client tolerant of either input:
          - bytes            -> base64-encoded.
          - already base64   -> passed through unchanged (our own render output).
          - plaintext str    -> base64-encoded.
        A string is treated as "already base64" only when it strictly decodes AND round-trips
        back to itself; a shell script (newlines, '#', '!', spaces) fails that test and is
        encoded, so we never double-encode our render output nor mis-detect a real script.
        """
        if isinstance(user_data, bytes):
            return base64.b64encode(user_data).decode("utf-8")
        _text = str(user_data)
        _candidate = _text.strip()
        try:
            _decoded = base64.b64decode(_candidate, validate=True)
            if base64.b64encode(_decoded).decode("utf-8") == _candidate:
                return _candidate
        except (binascii.Error, ValueError):
            pass
        return base64.b64encode(_text.encode("utf-8")).decode("utf-8")

    def _render_pcs_nodebootstrapped_script(
        self,
        node_type: str = "pcs_node",
        base_os: Optional[str] = None,
    ) -> SocaResponse | SocaError:
        """
        Render + upload the EDH compute-node bootstrap for a PCS compute node and return the S3
        URI of the script PCS runs at the `nodeBootstrapped` node lifecycle stage.

        Reuses the exact big bootstrap bodies EDH uses for its own compute/DCV/login nodes
        (install_required_packages -> filesystems_automount -> 02_setup.sh.j2 -> ...), rendered
        and uploaded through the shared render_bootstrap_bundle() cache. NodeType is "pcs_node",
        which the templates use to (a) skip the SOCA scheduler install/stop -- the node is managed
        by the PCS-managed Slurm controller -- and (b) sync AD users locally instead of realm-
        joining, so ephemeral PCS scale-out nodes never leave orphaned AD computer objects.

        Unlike EC2 UserData (a MIME multipart doc PCS appends to, so it cannot be gzipped and must
        fit EC2's 16KB limit), a node lifecycle action is a standalone script fetched from S3: up
        to 2 MiB, no MIME wrapping, and PCS runs it as root before slurmd. So this returns the
        `s3://` location of pcs_node/lifecycle_actions/nodebootstrapped/01_setup.sh (the
        lifecycle-action entry point) rather
        than a base64 UserData blob. The PCS node instance profile already has s3:GetObject on the
        EDH bucket (the script itself `aws s3 sync`s the big bodies from there), so the PCS agent
        can download this script with the same profile.

        Returns SocaResponse(message=<s3 URI string>) or a SocaError.
        """
        _config = SocaConfig(key="/").get_value(return_as=dict).get("message")
        if not _config:
            return SocaError.GENERIC_ERROR(
                helper="Unable to query SSM for this EDH environment; cannot render PCS bootstrap UserData"
            )
        _soca_parameters: Dict[str, Any] = dict(_config)

        _cluster_id = _soca_parameters.get("/configuration/ClusterId")
        if not _cluster_id:
            return SocaError.GENERIC_ERROR(
                helper="/configuration/ClusterId is not set; cannot render PCS bootstrap UserData"
            )

        if not base_os:
            base_os = _soca_parameters.get("/configuration/BaseOS")
        if not base_os:
            return SocaError.GENERIC_ERROR(
                helper=(
                    "No base_os provided and /configuration/BaseOS is not set; cannot render "
                    "PCS bootstrap UserData"
                )
            )

        _bootstrap_uuid = str(uuid.uuid4())
        _bootstrap_s3_prefix = (
            f"{_cluster_id}/config/do_not_delete/bootstrap/pcs_node/"
            f"{self._cluster_name}/{_bootstrap_uuid}"
        )
        _soca_parameters["/job/NodeType"] = node_type
        _soca_parameters["/job/BaseOS"] = base_os
        _soca_parameters["/configuration/BaseOS"] = (
            base_os  # legacy key some templates read
        )
        _soca_parameters["/job/BootstrapPath"] = (
            f"/apps/edh/{_cluster_id}/shared/logs/bootstrap/pcs_node/"
            f"{self._cluster_name}/{_bootstrap_uuid}"
        )
        _soca_parameters["/job/BootstrapScriptsS3Location"] = (
            f"s3://{_soca_parameters.get('/configuration/S3Bucket')}/{_bootstrap_s3_prefix}/"
        )

        # Identify the target PCS cluster to the bootstrap. These are per-node render values
        # (not cluster-wide EDH config), so they go under the /job/ namespace alongside
        # /job/NodeType and /job/BaseOS. We pass everything we can read about the cluster at
        # render time -- even values no include consumes yet -- so future bootstrap logic and
        # troubleshooting have them without another API round-trip. The most load-bearing is
        # /job/PCSClusterVersion (scheduler.version, e.g. "26.05"): the PCS agent enables the
        # Slurm binaries at runtime for exactly this version, so a custom AMI MUST have that
        # series installed or the node fails to register. Since the Slurm version is a CLUSTER
        # property and this launch template is created against a specific cluster, we resolve it
        # here and bake it in rather than relying on a global SSM parameter or manual entry;
        # install_pcs_slurm.sh.j2 reads /job/PCSClusterVersion (default "26.05").
        #
        # NOTE: per-instance identifiers (PCS compute node group id, EC2 instance id) are NOT
        # knowable at render time -- one launch template is shared across node groups and every
        # instance they scale out -- so those are populated by the PCS agent / IMDS at boot, not
        # here.
        # SLURMCTLD endpoint (ip/port) so configure_pcs_slurm.sh.j2 can bake a self-managed
        # slurm.conf pointing slurmd at the PCS-managed controller. Initialized OUTSIDE the try
        # so the fail-fast check below still runs if get_cluster() raises.
        _pcs_slurmctld_ip = None
        _pcs_slurmctld_port = None
        try:
            _pcs_cluster = self._describe_cluster()
            # IPv4 clusters expose privateIpAddress; IPv6-only clusters populate ipv6Address.
            for _endpoint in _pcs_cluster.get("endpoints", []):
                if _endpoint.get("type") == "SLURMCTLD":
                    _pcs_slurmctld_ip = _endpoint.get(
                        "privateIpAddress"
                    ) or _endpoint.get("ipv6Address")
                    _pcs_slurmctld_port = _endpoint.get("port")
                    break
            # (SSM /job/ key, value) pairs; only non-empty values are set.
            _pcs_job_params = {
                "/job/PCSClusterName": _pcs_cluster.get("name") or self._cluster_name,
                "/job/PCSClusterId": _pcs_cluster.get("id"),
                "/job/PCSClusterArn": _pcs_cluster.get("arn"),
                "/job/PCSClusterStatus": _pcs_cluster.get("status"),
                "/job/PCSSchedulerType": _pcs_cluster.get("scheduler", {}).get("type"),
                "/job/PCSClusterVersion": _pcs_cluster.get("scheduler", {}).get(
                    "version"
                ),
                "/job/PCSSlurmctldIp": _pcs_slurmctld_ip,
                "/job/PCSSlurmctldPort": _pcs_slurmctld_port,
            }
            for _key, _value in _pcs_job_params.items():
                if _value:
                    _soca_parameters[_key] = _value
            _cluster_slurm_version = _pcs_job_params.get("/job/PCSClusterVersion")
            if _cluster_slurm_version:
                logger.info(
                    f"PCS cluster {self._cluster_name} (id={_pcs_cluster.get('id')}) uses Slurm "
                    f"{_cluster_slurm_version}; PCS compute nodes will install that major series."
                )
            else:
                logger.warning(
                    f"Could not read scheduler.version for PCS cluster {self._cluster_name}; "
                    f"install_pcs_slurm.sh.j2 will fall back to its default Slurm major series."
                )
        except Exception as err:
            logger.warning(
                f"Unable to resolve PCS cluster metadata for {self._cluster_name}: {err}. "
                f"install_pcs_slurm.sh.j2 will fall back to its default Slurm major series."
            )

        # A PCS compute node cannot function without the SLURMCTLD endpoint: slurmd runs
        # configless (--conf-server=<ip>:<port>) and pulls its authoritative config from the
        # controller. If we render the bootstrap now, whatever we bake is frozen into the
        # uploaded lifecycle-action script. When the endpoint is unresolved (cluster not ACTIVE
        # yet, or the get_cluster() call above failed) the /job/PCSSlurmctldIp:Port params are
        # never set, context.get() returns None, and configure_pcs_slurm.sh.j2 renders literal
        # "None" into --conf-server -- slurmd then can't reach the controller and dies with
        # "Unable to determine this slurmd's NodeName". Fail fast here so the operator recreates
        # the node group once the cluster is ACTIVE, rather than shipping a guaranteed-broken node.
        if node_type == "pcs_node" and not (
            _pcs_slurmctld_ip and _pcs_slurmctld_port
        ):
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"No SLURMCTLD endpoint resolved for PCS cluster {self._cluster_name} "
                    f"(ip={_pcs_slurmctld_ip!r}, port={_pcs_slurmctld_port!r}); cannot render a "
                    f"PCS compute-node bootstrap that would only fail at boot. Ensure the cluster "
                    f"is ACTIVE and exposes its SLURMCTLD endpoint, then recreate the launch template."
                )
            )

        # When the directory is Active Directory, PCS nodes sync users locally from
        # users_info.json (produced by `edhctl ad export`) rather than realm-joining. Ensure the
        # file exists so sync_ad_users_locally.sh has something to read; keeping it fresh is the
        # controller's existing responsibility (same file the ephemeral HPC nodes consume).
        if _soca_parameters.get("/configuration/UserDirectory/provider") in (
            "aws_ds_managed_activedirectory",
            "existing_active_directory",
        ):
            _users_info = (
                f"/apps/edh/{_cluster_id}/shared/active_directory/sync/users_info.json"
            )
            if not pathlib.Path(_users_info).exists():
                logger.info(
                    f"{_users_info} missing; generating it with 'edhctl ad export' for PCS user sync"
                )
                _export = SocaSubprocessClient(
                    run_command=f"/opt/edh/{_cluster_id}/cluster_manager/edhctl ad export"
                ).run()
                if _export.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=(
                            f"Unable to generate {_users_info} for PCS AD user sync because of "
                            f"{_export.get('message')}"
                        )
                    )

        # Render + upload the big bootstrap bodies (install_required_packages, filesystems_automount,
        # 02_setup, ...) through the shared cache, exactly like the HPC path. sync_ad_users_locally.sh
        # is {% include %}'d inside 02_setup so it is rendered as part of that body -- no separate entry.
        from utils.bootstrap_render import render_bootstrap_bundle

        _s3_boto = get_boto(service_name="s3", region_name=self._region_name)
        if _s3_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize S3 boto3 client: {_s3_boto.get('message')}"
            )

        try:
            _render_result = render_bootstrap_bundle(
                soca_parameters=_soca_parameters,
                bootstrap_root=f"/opt/edh/{_cluster_id}/cluster_node_bootstrap/",
                s3_client=_s3_boto.message,
                bucket=_soca_parameters.get("/configuration/S3Bucket"),
                cluster_id=_cluster_id,
                per_session_prefix=_bootstrap_s3_prefix,
                cache_prefix=f"{_cluster_id}/bootstrap/cache",
                big_templates=[
                    "templates/linux/system_packages/install_required_packages.sh",
                    "templates/linux/filesystems_automount.sh",
                    "compute_node/02_setup.sh",
                    "compute_node/03_setup_post_reboot.sh",
                    "compute_node/04_setup_user_customization.sh",
                    # PCS nodeBootstrapped lifecycle-action entry point: PCS fetches this from S3
                    # and runs it as root before slurmd. It drives the heavy bootstrap
                    # (packages/filesystems/02_setup); no reboots (PCS forbids them), re-run as a
                    # fast no-op on EVERY_BOOT via its done-file. See
                    # pcs_node/lifecycle_actions/nodebootstrapped/01_setup.sh.j2.
                    "pcs_node/lifecycle_actions/nodebootstrapped/01_setup.sh",
                ],
                session_env_template="templates/linux/00_session_env.sh",
                session_env_filename="00_session_env.sh",
                # Bypass the shared bootstrap cache for PCS. Unlike a VDI/HPC session (which boots
                # within minutes of the render, so the cache prefix is guaranteed to still exist),
                # a PCS compute node group is long-lived and scales out new instances for days or
                # weeks. Its nodeBootstrapped script URI is registered ONCE here and must stay
                # valid for every future scale-out. The cache prefix is ephemeral -- the TTL forces
                # a re-render under a NEW key and old bodies are reaped by the S3 lifecycle policy /
                # cache refresh (see bootstrap_cache.py), so a node scaling out later would 404 on
                # nodebootstrapped.sh and fail to bootstrap. cache_bypass renders every body + the
                # env file into the stable per-session (per-node-group) prefix, self-contained, so
                # BootstrapScriptsS3Location points at a location that lives as long as the CNG.
                cache_bypass=True,
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to render PCS bootstrap bundle for {self._cluster_name} because of {err}"
            )

        _soca_parameters["/job/BootstrapScriptsS3Location"] = (
            _render_result.bootstrap_scripts_s3
        )
        _soca_parameters["/job/SessionEnvS3Location"] = _render_result.session_env_s3

        # The nodeBootstrapped lifecycle-action entry point
        # (pcs_node/lifecycle_actions/nodebootstrapped/01_setup.sh) was rendered + uploaded alongside
        # the other big bodies above. render_bootstrap_bundle keys each template by its basename under
        # bootstrap_scripts_s3, so the script PCS fetches is <bootstrap_scripts_s3>/01_setup.sh. Return
        # that S3 URI; the caller registers it as the nodeBootstrapped script on the compute node group.
        _script_s3_uri = (
            f"{_render_result.bootstrap_scripts_s3.rstrip('/')}/01_setup.sh"
        )

        logger.info(
            f"Rendered EDH nodeBootstrapped script for PCS cluster {self._cluster_name} "
            f"at {_script_s3_uri} (node_type={node_type}, base_os={base_os})"
        )
        return SocaResponse(success=True, message=_script_s3_uri)

    @cluster_must_be_visible()
    def create_launch_template(
        self,
        template_name: Optional[str] = None,
        security_group_ids: Optional[List[str]] = None,
        launch_template_data: Optional[Dict[str, Any]] = None,
        launch_template_data_path: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        instance_tags: Optional[Dict[str, str]] = None,
    ) -> SocaResponse | SocaError:
        """
        Create an EC2 launch template suitable for a PCS compute node group.

        PCS supplies the AMI, instance type(s), subnet and IAM instance profile itself via
        create_compute_node_group(), so the launch template only needs to carry what PCS does
        NOT set -- primarily the security group(s) the compute nodes use to reach the SLURM
        controller. The security group(s) and template name are auto-detected from the EDH
        environment when not provided.

        The LaunchTemplateData body must be supplied via EXACTLY ONE of launch_template_data
        (inline dict) or launch_template_data_path (a .json / .yaml / .yml file). Passing both,
        or neither, is an error. Auto-detected security groups are still merged into whichever
        source you provide, but only if that source does not already set SecurityGroupIds.

        The resulting launch template id is what you pass as launch_template_id to
        create_compute_node_group().

        Args:
            template_name: Launch template name. Defaults to "edh-pcs-<cluster_name>".
            security_group_ids: Security group(s) for the compute nodes. Auto-detected when None.
            launch_template_data: Inline LaunchTemplateData dict. Mutually exclusive with
                launch_template_data_path; exactly one must be provided.
            launch_template_data_path: Path to a JSON or YAML file holding the LaunchTemplateData
                body. Mutually exclusive with launch_template_data; exactly one must be provided.
            tags: Optional tags for the launch template resource. The edh:ClusterId tag is always
                added so the template is traceable back to the EDH environment.
            instance_tags: Optional cost-allocation tags (e.g. edh:Pcs:team / department / project)
                to stamp on the EC2 instances AND EBS volumes PCS launches from this template. This
                is the ONLY reliable way to get cost tags onto the billable resources: PCS tags on
                the compute node group do NOT propagate to instances -- instance tags come from the
                launch template's LaunchTemplateData.TagSpecifications, which this populates. Merged
                into any TagSpecifications already present in the launch template body.

        Note: the EDH bootstrap for PCS nodes is NOT injected here as UserData. It runs as a PCS
        node lifecycle action (nodeBootstrapped stage) configured on the compute node group -- see
        _render_pcs_nodebootstrapped_script and create_compute_node_group(edh_bootstrap=True). A
        caller may still pass its own UserData via launch_template_data; it is honored as-is.

        Returns:
            SocaResponse(message={"id", "name", "default_version", "latest_version"}) on success.
        """
        # LaunchTemplateData must come from exactly one source (inline or file).
        if launch_template_data is not None and launch_template_data_path is not None:
            return SocaError.GENERIC_ERROR(
                helper=(
                    "Pass only one of launch_template_data or launch_template_data_path, "
                    "not both, when creating a launch template"
                )
            )
        if launch_template_data is None and launch_template_data_path is None:
            return SocaError.GENERIC_ERROR(
                helper=(
                    "A launch template body is required: provide either launch_template_data "
                    "(inline dict) or launch_template_data_path (a .json / .yaml file)"
                )
            )

        # Load the body from file when a path was given. On error the helper returns a
        # SocaResponse(success=False) (SocaError.* factories return a SocaResponse, NOT a
        # SocaError instance); on success it returns the parsed dict.
        if launch_template_data_path is not None:
            _loaded = self._load_launch_template_data(launch_template_data_path)
            if isinstance(_loaded, SocaResponse):
                return _loaded
            launch_template_data = _loaded

        _ec2_boto = get_boto(service_name="ec2", region_name=self._region_name)
        if _ec2_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize EC2 boto3 client: {_ec2_boto.get('message')}"
            )
        _ec2_client = _ec2_boto.message

        # Resolve the security group(s): caller-provided, then the cluster's own SGs, then the
        # EDH compute node security group on SSM.
        if not security_group_ids:
            security_group_ids = self._cluster_security_group_ids
        if not security_group_ids:
            _default_compute_sg = self._ssm_default(
                "/configuration/ComputeNodeSecurityGroup"
            )
            if _default_compute_sg:
                security_group_ids = [_default_compute_sg]
        if not security_group_ids:
            return SocaError.GENERIC_ERROR(
                helper=(
                    "No security_group_ids provided and neither the cluster security groups "
                    "nor /configuration/ComputeNodeSecurityGroup could be resolved on SSM; "
                    f"cannot create a launch template for {self._cluster_name}"
                )
            )

        # Minimal launch template data. PCS overrides AMI / instance type / subnet / instance
        # profile, so we only set the security groups unless the caller supplied a full payload.
        _lt_data: Dict[str, Any] = (
            dict(launch_template_data) if launch_template_data else {}
        )
        # Attach the resolved security groups. EC2 rejects a top-level SecurityGroupIds together
        # with NetworkInterfaces ("Network interfaces and an instance-level security groups may not
        # be specified on the same request") -- this happens when the body requests an EFA
        # interface. In that case put the groups on each interface's Groups (if it does not already
        # carry its own) instead of at the top level.
        _network_interfaces = _lt_data.get("NetworkInterfaces")
        if _network_interfaces:
            for _ni in _network_interfaces:
                if isinstance(_ni, dict) and not _ni.get("Groups"):
                    _ni["Groups"] = list(security_group_ids)
        else:
            _lt_data.setdefault("SecurityGroupIds", security_group_ids)

        # NOTE: the EDH bootstrap is NOT injected here. On a PCS node it runs as a node lifecycle
        # action (nodeBootstrapped stage) configured on the compute node group -- see
        # create_compute_node_group(edh_bootstrap=True). A caller may still supply its own UserData
        # via launch_template_data; it is honored as-is (and base64-normalized below).

        # EC2 CreateLaunchTemplate requires LaunchTemplateData.UserData to be base64 (unlike
        # RunInstances, botocore does NOT auto-encode it for this operation), so a caller-supplied
        # plaintext UserData -- e.g. from the advanced JSON/YAML payload -- trips
        # InvalidUserData.Malformed. Normalize whatever is present: our own render output is
        # already base64 and passes through untouched; raw text is encoded here.
        if _lt_data.get("UserData"):
            _lt_data["UserData"] = self._ensure_base64_user_data(_lt_data["UserData"])

        # Cost-allocation tags that must land on the launched EC2 instances / EBS volumes (PCS
        # does NOT propagate compute-node-group tags to instances -- only the launch template's
        # LaunchTemplateData.TagSpecifications does). The mandatory EDH tags (edh:ClusterId +
        # edh:visibility) are stamped here too so every instance/volume EDH PCS launches carries
        # both, matching the launch template / cluster / queue / node group resources. Merge into
        # instance/volume tag specs already in the body rather than clobbering them; keys we set
        # win on collision.
        _instance_tags = self._with_edh_tags(
            instance_tags, f"instances launched by launch template {template_name}"
        )
        if _instance_tags:
            _existing_specs = _lt_data.get("TagSpecifications") or []
            _specs_by_type: Dict[str, Dict[str, str]] = {}
            _other_specs: List[Dict[str, Any]] = []
            for _spec in _existing_specs:
                _rtype = _spec.get("ResourceType")
                if _rtype in ("instance", "volume"):
                    _specs_by_type[_rtype] = {
                        t.get("Key"): t.get("Value") for t in _spec.get("Tags", [])
                    }
                else:
                    _other_specs.append(_spec)
            for _rtype in ("instance", "volume"):
                _merged = _specs_by_type.get(_rtype, {})
                _merged.update(_instance_tags)
                _specs_by_type[_rtype] = _merged
            _lt_data["TagSpecifications"] = _other_specs + [
                {
                    "ResourceType": _rtype,
                    "Tags": [{"Key": k, "Value": v} for k, v in _tags_map.items()],
                }
                for _rtype, _tags_map in _specs_by_type.items()
            ]

        # ImageId is optional on a launch template (PCS usually supplies the AMI on the compute
        # node group), but if one is baked into the template -- inline or via the JSON/YAML file
        # -- it must be a real, available AMI.
        _lt_image_id = _lt_data.get("ImageId")
        if _lt_image_id:
            _validate_ami = self._validate_ami(_lt_image_id)
            if _validate_ami is not None:
                return _validate_ami

        # Subnets are also optional on a launch template; when present they live on the
        # NetworkInterfaces entries as SubnetId. Validate any the payload carries so a bad
        # subnet baked into the JSON/YAML is rejected here rather than at launch time.
        _lt_subnet_ids = [
            _ni["SubnetId"]
            for _ni in _lt_data.get("NetworkInterfaces", [])
            if isinstance(_ni, dict) and _ni.get("SubnetId")
        ]
        if _lt_subnet_ids:
            _validate_subnets = self._validate_subnets(_lt_subnet_ids)
            if _validate_subnets is not None:
                return _validate_subnets

        if not template_name:
            template_name = f"edh-pcs-{self._cluster_name}"

        _tags = self._with_edh_tags(tags, f"PCS launch template {template_name}")

        _create_lt_args: Dict[str, Any] = {
            "LaunchTemplateName": template_name,
            "LaunchTemplateData": _lt_data,
        }
        if _tags:
            _create_lt_args["TagSpecifications"] = [
                {
                    "ResourceType": "launch-template",
                    "Tags": [{"Key": k, "Value": v} for k, v in _tags.items()],
                }
            ]

        logger.info(
            f"Creating EC2 launch template {template_name} for PCS cluster "
            f"{self._cluster_name} with {security_group_ids=}"
        )
        try:
            _create_lt = _ec2_client.create_launch_template(**_create_lt_args)
            _lt = _create_lt.get("LaunchTemplate", {})
            return SocaResponse(
                success=True,
                message={
                    "id": _lt.get("LaunchTemplateId"),
                    "name": _lt.get("LaunchTemplateName", template_name),
                    "default_version": _lt.get("DefaultVersionNumber"),
                    "latest_version": _lt.get("LatestVersionNumber"),
                },
            )
        except Exception as err:
            return self._pcs_error(err, f"Create launch template {template_name}")

    def _edh_launch_template_filters(self) -> List[Dict[str, Any]]:
        """
        Build the EC2 describe_launch_templates tag filter that scopes results to launch
        templates visible to this EDH environment: edh:visibility:<cluster id>=true. Every
        launch template read (list, get, version resolution, pre-delete lookup) goes through
        this filter, so a template without the tag is never returned, used, or modified.
        Fails safe: if this environment's cluster id cannot be resolved the filter matches nothing
        (rather than every template in the account), so an unscoped lookup-by-id can never find
        a foreign template.
        """
        _cluster_id = self._edh_cluster_id_value()
        if not _cluster_id:
            logger.warning(
                "Unable to resolve /configuration/ClusterId; scoping launch template lookups to "
                "an impossible tag value so no foreign template is returned"
            )
            return [
                {
                    "Name": "tag:edh:visibility:__edh_cluster_id_unresolved__",
                    "Values": ["true"],
                }
            ]
        return [{"Name": f"tag:edh:visibility:{_cluster_id}", "Values": ["true"]}]

    def list_launch_templates(self) -> SocaResponse | SocaError:
        """
        List the EC2 launch templates visible to this EDH environment (filtered on the
        edh:visibility:<cluster id>=true tag create_launch_template() applies).

        Returns:
            SocaResponse(message=[{"id", "name", "default_version", "latest_version",
            "created_at", "tags"}]) on success.
        """
        _ec2_boto = get_boto(service_name="ec2", region_name=self._region_name)
        if _ec2_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize EC2 boto3 client: {_ec2_boto.get('message')}"
            )
        _ec2_client = _ec2_boto.message

        _launch_templates: List[Dict[str, Any]] = []
        try:
            _paginator = _ec2_client.get_paginator("describe_launch_templates")
            for _page in _paginator.paginate(
                Filters=self._edh_launch_template_filters()
            ):
                for _lt in _page.get("LaunchTemplates", []):
                    _launch_templates.append(
                        {
                            "id": _lt.get("LaunchTemplateId"),
                            "name": _lt.get("LaunchTemplateName"),
                            "default_version": _lt.get("DefaultVersionNumber"),
                            "latest_version": _lt.get("LatestVersionNumber"),
                            "created_at": _lt.get("CreateTime"),
                            "tags": {
                                _t.get("Key"): _t.get("Value")
                                for _t in _lt.get("Tags", [])
                            },
                        }
                    )
            return SocaResponse(success=True, message=_launch_templates)
        except Exception as err:
            return self._pcs_error(
                err, f"List launch templates for {self._cluster_name}"
            )

    def get_launch_template(self, launch_template_id: str) -> SocaResponse | SocaError:
        """
        Retrieve a single EC2 launch template, scoped to this EDH environment via the same
        edh:visibility tag filter list_launch_templates() uses, so a template not visible to this
        environment simply returns no match (and cannot be managed/deleted from its page).

        Returns:
            SocaResponse(message={"id", "name", "default_version", "latest_version",
            "created_at", "tags"}) on success.
        """
        if not launch_template_id:
            return SocaError.GENERIC_ERROR(
                helper="A launch_template_id is required to retrieve a launch template"
            )

        _ec2_boto = get_boto(service_name="ec2", region_name=self._region_name)
        if _ec2_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize EC2 boto3 client: {_ec2_boto.get('message')}"
            )
        _ec2_client = _ec2_boto.message

        try:
            # DescribeLaunchTemplates has no "launch-template-id" filter (only name/tag/create-time
            # are valid Filter names); the id must go through the LaunchTemplateIds parameter. The
            # EDH tag Filters still apply on top, so a template EDH did not create is filtered out.
            _describe = _ec2_client.describe_launch_templates(
                LaunchTemplateIds=[launch_template_id],
                Filters=self._edh_launch_template_filters(),
            )
        except Exception as err:
            return self._pcs_error(
                err, f"Describe launch template {launch_template_id}"
            )

        _templates = _describe.get("LaunchTemplates") or []
        if not _templates:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Launch template {launch_template_id} was not found among the launch "
                    f"templates created by this EDH environment"
                )
            )

        _lt = _templates[0]
        return SocaResponse(
            success=True,
            message={
                "id": _lt.get("LaunchTemplateId"),
                "name": _lt.get("LaunchTemplateName"),
                "default_version": _lt.get("DefaultVersionNumber"),
                "latest_version": _lt.get("LatestVersionNumber"),
                "created_at": _lt.get("CreateTime"),
                "tags": {_t.get("Key"): _t.get("Value") for _t in _lt.get("Tags", [])},
            },
        )

    def get_launch_template_image_id(
        self, launch_template_id: str, launch_template_version: Optional[str] = None
    ) -> SocaResponse | SocaError:
        """
        Return the AMI (ImageId) baked into a launch template version, e.g. to show the AMI a
        compute node group inherits when it does not set amiId itself.

        Returns:
            SocaResponse(message="<ami id>") on success.
        """
        if not launch_template_id:
            return SocaError.GENERIC_ERROR(
                helper="A launch_template_id is required to retrieve its AMI"
            )

        _ec2_boto = get_boto(service_name="ec2", region_name=self._region_name)
        if _ec2_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize EC2 boto3 client: {_ec2_boto.get('message')}"
            )
        _ec2_client = _ec2_boto.message

        _version = str(launch_template_version or "$Default").strip()
        try:
            _describe = _ec2_client.describe_launch_template_versions(
                LaunchTemplateId=launch_template_id, Versions=[_version]
            )
        except Exception as err:
            return self._pcs_error(
                err, f"Describe launch template {launch_template_id} version {_version}"
            )

        _versions = _describe.get("LaunchTemplateVersions") or []
        _image_id = (
            (_versions[0].get("LaunchTemplateData") or {}).get("ImageId")
            if _versions
            else None
        )
        if not _image_id:
            return SocaError.GENERIC_ERROR(
                helper=f"Launch template {launch_template_id} version {_version} has no ImageId"
            )
        return SocaResponse(success=True, message=_image_id)

    def _resolve_launch_template_version(
        self, launch_template_id: str, launch_template_version: Optional[str]
    ) -> SocaResponse | SocaError:
        """
        Resolve a launch template version to the concrete numeric version PCS requires.

        CreateComputeNodeGroup rejects the EC2 aliases ($Latest / $Default, or "latest" /
        "default") with "Launch template version must be a numeric value". A version that is
        already numeric is returned unchanged; an alias is resolved by describing the template
        and mapping to its LatestVersionNumber / DefaultVersionNumber.

        Returns:
            SocaResponse(message="<numeric version>") on success.
        """
        _version = (
            str(launch_template_version).strip()
            if launch_template_version is not None
            else ""
        )

        _ec2_boto = get_boto(service_name="ec2", region_name=self._region_name)
        if _ec2_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize EC2 boto3 client: {_ec2_boto.get('message')}"
            )
        _ec2_client = _ec2_boto.message

        try:
            # Scoped by the EDH visibility filter: a node group must never reference a launch
            # template that is not visible to this environment.
            _describe = _ec2_client.describe_launch_templates(
                LaunchTemplateIds=[launch_template_id],
                Filters=self._edh_launch_template_filters(),
            )
            _lts = _describe.get("LaunchTemplates", [])
            if not _lts:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Launch template {launch_template_id} was not found among the launch "
                        f"templates visible to this EDH environment; cannot resolve version "
                        f"'{launch_template_version}'"
                    )
                )
            # A numeric version is used as-is, but only after the template itself passed the
            # visibility-scoped describe above.
            if _version.isdigit():
                return SocaResponse(success=True, message=_version)

            _lt = _lts[0]
            _alias = _version.lower().lstrip("$")
            if _alias in ("", "latest"):
                _resolved = _lt.get("LatestVersionNumber")
            elif _alias == "default":
                _resolved = _lt.get("DefaultVersionNumber")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Unsupported launch template version '{launch_template_version}' for "
                        f"{launch_template_id}; provide a numeric version, $Latest, or $Default"
                    )
                )
            if _resolved is None:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Could not resolve a numeric version for launch template "
                        f"{launch_template_id} (alias '{launch_template_version}')"
                    )
                )
            return SocaResponse(success=True, message=str(int(_resolved)))
        except Exception as err:
            return self._pcs_error(
                err, f"Resolve launch template version for {launch_template_id}"
            )

    def delete_launch_template(
        self, launch_template_id: str
    ) -> SocaResponse | SocaError:
        """
        Delete an EC2 launch template, but only if it carries this EDH environment's tags.

        The id is first resolved through the edh:visibility:<cluster id>=true filter used by
        list_launch_templates(), then the template must also carry edh:ClusterId=<cluster id>
        (the tag the controller IAM policy gates ec2:DeleteLaunchTemplate on). A template that
        fails either check is refused rather than deleted.
        """
        if not launch_template_id:
            return SocaError.GENERIC_ERROR(
                helper="A launch_template_id is required to delete a launch template"
            )

        _ec2_boto = get_boto(service_name="ec2", region_name=self._region_name)
        if _ec2_boto.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to initialize EC2 boto3 client: {_ec2_boto.get('message')}"
            )
        _ec2_client = _ec2_boto.message

        # Confirm the template is visible before deleting: describe it with the
        # edh:visibility:<cluster id>=true filter plus the id, so a template missing the tag
        # simply returns no match. If the cluster id is unresolved the filter is already an
        # impossible value, so describe returns nothing and the delete is refused.
        try:
            # The id goes through LaunchTemplateIds (there is no "launch-template-id" Filter); the
            # EDH tag + visibility Filters still apply, so a foreign template returns no match and
            # the delete below is refused -- preserving the ownership guard.
            _describe = _ec2_client.describe_launch_templates(
                LaunchTemplateIds=[launch_template_id],
                Filters=self._edh_launch_template_filters(),
            )
        except Exception as err:
            return self._pcs_error(
                err, f"Describe launch template {launch_template_id}"
            )

        if not _describe.get("LaunchTemplates"):
            # The filtered describe returned nothing, so either the template does not exist at
            # all or it exists but lacks the EDH tags. Re-describe WITHOUT the tag filters to
            # tell the operator exactly why the delete is refused (missing which tag, vs. gone).
            try:
                _unfiltered = _ec2_client.describe_launch_templates(
                    LaunchTemplateIds=[launch_template_id]
                )
            except Exception:
                _unfiltered = {}
            _templates = _unfiltered.get("LaunchTemplates") or []
            if not _templates:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Launch template {launch_template_id} does not exist; "
                        f"refusing to delete it"
                    )
                )
            _tags = {
                _t.get("Key"): _t.get("Value")
                for _t in (_templates[0].get("Tags") or [])
            }
            _tag_error = self._validate_edh_tags_dict(
                _tags, f"launch template {launch_template_id}"
            )
            return _tag_error or SocaError.GENERIC_ERROR(
                helper=(
                    f"Launch template {launch_template_id} was not found among the launch "
                    f"templates created by this EDH environment; refusing to delete it"
                )
            )

        # Visible is required to even see the template; deleting additionally requires
        # edh:ClusterId ownership (the controller IAM policy gates ec2:DeleteLaunchTemplate on it).
        _found_tags = {
            _t.get("Key"): _t.get("Value")
            for _t in (_describe["LaunchTemplates"][0].get("Tags") or [])
        }
        _tag_error = self._validate_edh_tags_dict(
            _found_tags, f"launch template {launch_template_id}"
        )
        if _tag_error is not None:
            return _tag_error

        logger.info(
            f"Deleting EC2 launch template {launch_template_id} for PCS cluster "
            f"{self._cluster_name}"
        )
        try:
            _delete = _ec2_client.delete_launch_template(
                LaunchTemplateId=launch_template_id
            )
            _lt = _delete.get("LaunchTemplate", {})
            return SocaResponse(
                success=True,
                message={
                    "id": _lt.get("LaunchTemplateId", launch_template_id),
                    "name": _lt.get("LaunchTemplateName"),
                },
            )
        except Exception as err:
            return self._pcs_error(err, f"Delete launch template {launch_template_id}")

    # -- Compute Node Groups --
    @cluster_must_be_active()
    def list_compute_node_groups(self) -> SocaResponse | SocaError:
        logger.debug(f"About to list compute node groups for {self._cluster_name}")
        _compute_node_groups = []
        try:
            _compute_node_group_paginator = self._pcs_client.get_paginator(
                "list_compute_node_groups"
            )

            for page in _compute_node_group_paginator.paginate(
                clusterIdentifier=self._cluster_name,
            ):
                _compute_node_groups.extend(page.get("computeNodeGroups", []))

            logger.debug(
                f"Found PCS Compute Node Groups associated to {self._cluster_name}: {_compute_node_groups}"
            )
            return SocaResponse(success=True, message=_compute_node_groups)
        except Exception as err:
            return self._pcs_error(
                err, f"List PCS compute node groups for {self._cluster_name}"
            )

    @cluster_must_be_visible()
    def list_cluster_instances(self) -> SocaResponse | SocaError:
        """
        List the EC2 instances AWS PCS has provisioned for this cluster.

        PCS stamps every compute node it launches with aws:pcs:cluster-id=<cluster id> (and
        aws:pcs:compute-node-group-id), so we resolve this cluster's id and filter EC2 on that
        tag rather than on any EDH tag -- these are PCS-managed instances, not resources this
        code created. Terminated instances are excluded so the view reflects what is actually
        provisioned. Returns a list of flattened dicts (id, state, type, group, az, ips, launch
        time) ready for the detail page; the raw boto3 instance is kept under "raw".
        """
        # get_cluster() populates _cluster_identifier; resolve it lazily if a caller hasn't yet.
        if self._cluster_identifier is None:
            _refresh = self.get_cluster(
                list_queues=False, list_compute_node_groups=False
            )
            if _refresh.get("success") is False:
                return _refresh
        if not self._cluster_identifier:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to resolve the PCS cluster id for {self._cluster_name}; cannot list its instances"
            )

        _filters = [
            {"Name": "tag:aws:pcs:cluster-id", "Values": [self._cluster_identifier]},
            {
                "Name": "instance-state-name",
                "Values": [
                    "pending",
                    "running",
                    "shutting-down",
                    "stopping",
                    "stopped",
                ],
            },
        ]
        _described = describe_instances_paginate(filters=_filters)
        if _described.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to list EC2 instances for {self._cluster_name}: {_described.get('message')}"
            )

        _instances = []
        for _i in _described.get("message") or []:
            _tags = {t.get("Key"): t.get("Value") for t in _i.get("Tags", [])}
            _instances.append(
                {
                    "id": _i.get("InstanceId"),
                    "state": _i.get("State", {}).get("Name"),
                    "instance_type": _i.get("InstanceType"),
                    "compute_node_group_id": _tags.get("aws:pcs:compute-node-group-id"),
                    "availability_zone": _i.get("Placement", {}).get(
                        "AvailabilityZone"
                    ),
                    "private_ip": _i.get("PrivateIpAddress"),
                    "launch_time": _i.get("LaunchTime"),
                    "raw": _i,
                }
            )
        # Newest first so freshly-scaled nodes surface at the top.
        _instances.sort(key=lambda i: str(i.get("launch_time") or ""), reverse=True)
        return SocaResponse(success=True, message=_instances)

    @staticmethod
    def _role_is_pcs_scoped(role: Dict[str, Any]) -> bool:
        """
        Whether an IAM role (as returned in an instance profile's Roles) is one AWS PCS will
        accept for a compute node group: its name starts with "AWSPCS" or its IAM path is
        "/aws-pcs/". This is the guardrail from the CreateComputeNodeGroup docs, shared by the
        create-time validation and list_pcs_instance_profiles().
        """
        return (role.get("RoleName") or "").startswith("AWSPCS") or (
            role.get("Path") or "/"
        ) == "/aws-pcs/"

    def list_pcs_instance_profiles(self) -> SocaResponse | SocaError:
        """
        List the IAM instance profiles whose role AWS PCS will accept for a compute node group
        (role name starts with "AWSPCS" or role path is "/aws-pcs/"). Used to populate the
        instance-profile dropdown on the create form so only usable profiles are offered.

        Returns a list of {arn, name, role_name} dicts. Note the pcs:RegisterComputeNodeGroupInstance
        permission requirement cannot be introspected cheaply and is not checked here.
        """
        _list = list_instance_profiles()
        if _list.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to list IAM instance profiles: {_list.get('message')}"
            )

        _profiles = []
        for _ip in _list.get("message") or []:
            _roles = _ip.get("Roles") or []
            if any(self._role_is_pcs_scoped(r) for r in _roles):
                _profiles.append(
                    {
                        "arn": _ip.get("Arn"),
                        "name": _ip.get("InstanceProfileName"),
                        "role_name": (_roles[0].get("RoleName") if _roles else None),
                    }
                )
        _profiles.sort(key=lambda p: str(p.get("name") or ""))
        return SocaResponse(success=True, message=_profiles)

    @cluster_must_be_active()
    def create_compute_node_group(
        self,
        group_name: str,
        launch_template_id: str,
        instance_types: List[str],
        desired_capacity: Optional[int] = None,
        ami_id: Optional[str] = None,
        launch_template_version: str = "$Latest",
        instance_profile_arn: Optional[str] = None,
        subnet_ids: Optional[List[str]] = None,
        purchase_option: Optional[
            Literal[
                "ONDEMAND",
                "SPOT",
                "CAPACITY_BLOCK",
                "INTERRUPTIBLE_CAPACITY_RESERVATION",
            ]
        ] = "ONDEMAND",
        min_instance_count: Optional[int] = None,
        max_instance_count: Optional[int] = None,
        spot_options: Optional[Dict[str, Any]] = None,
        slurm_configuration: Optional[Dict[str, Any]] = None,
        node_lifecycle_actions: Optional[Dict[str, Any]] = None,
        edh_bootstrap: bool = False,
        edh_base_os: Optional[str] = None,
        client_token: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> SocaResponse | SocaError:
        """
        Create a compute node group on the PCS cluster.

        Mirrors the boto3 pcs.create_compute_node_group() request surface:
        https://docs.aws.amazon.com/boto3/latest/reference/services/pcs/client/create_compute_node_group.html

        Args:
            group_name: Name of the compute node group (must be 25 characters or fewer).
            launch_template_id / launch_template_version: EC2 launch template (customLaunchTemplate).
            instance_types: EC2 instance types, mapped to instanceConfigs entries.
            desired_capacity: Optional legacy shortcut for a fixed-size group (min == max). Used
                only for a bound not set by min_instance_count / max_instance_count.
            ami_id: Optional AMI id for the compute nodes. When omitted, PCS uses the AMI
                (ImageId) baked into the launch template -- which is where EDH configures the
                image and its matching bootstrap, so the CNG normally leaves this unset.
            instance_profile_arn: IAM instance profile ARN (validated before the call). If not
                provided, defaults to the dedicated EDH PCS node instance profile from
                /configuration/PCSNodeInstanceProfileArn on SSM (its role sits at the IAM path
                "/aws-pcs/" so PCS accepts it, unlike the generic compute-node profile).
            subnet_ids: Subnet(s); defaults to the cluster's subnets when not provided.
            purchase_option: ONDEMAND | SPOT | CAPACITY_BLOCK | INTERRUPTIBLE_CAPACITY_RESERVATION.
            min_instance_count / max_instance_count: scalingConfiguration bounds (required unless
                desired_capacity is given). Must satisfy 0 <= min <= max and max >= 1.
            spot_options: Optional, e.g. {"allocationStrategy": "price-capacity-optimized"}.
            node_lifecycle_actions: Optional lifecycle scripts to run on compute nodes, e.g.
                {
                    "stages": {
                        "nodeBootstrapped": [
                            {
                                "name": "configure",
                                "scriptSource": {"scriptLocation": "s3://bucket/key"},
                                "onError": "TERMINATE",
                                "executionPolicy": "FIRST_BOOT_ONLY",
                            }
                        ],
                    },
                    "scriptCachingPolicy": "CACHE_ONCE",
                }
            edh_bootstrap: When True and node_lifecycle_actions is not already provided, render +
                upload the EDH compute-node bootstrap and register it as a nodeBootstrapped lifecycle
                action (onError=STOP_SEQUENCE, executionPolicy=EVERY_BOOT) so PCS runs it as root after
                its own node setup and before slurmd. This is where EDH bootstrap lives for PCS
                nodes (not launch-template UserData). See _render_pcs_nodebootstrapped_script.
            edh_base_os: Base OS to render the EDH bootstrap for (e.g. "amazonlinux2023"). Only used
                when edh_bootstrap is True; defaults to /configuration/BaseOS on SSM.
            slurm_configuration: Optional, e.g.
                {
                    "scaleDownIdleTimeInSeconds": 600,
                    "slurmCustomSettings": [{"parameterName": "...", "parameterValue": "..."}],
                    "gresCustomSettings": [{"Name": "gpu", "Type": "a100", "File": "/dev/nvidia[0-7]"}],
                }
            tags: Optional key/value tags. The edh:ClusterId tag is always added (and takes
                precedence) so the node group is traceable back to the EDH environment.
        """

        logger.info(
            f"Creating PCS compute node group {group_name=} with {launch_template_id=} {launch_template_version=} / {instance_types=} / {desired_capacity=} / {ami_id} / {instance_profile_arn=} / {subnet_ids=} / {purchase_option=}"
        )
        if len(group_name) > 25:
            return SocaError.GENERIC_ERROR(
                helper=f"Compute Node Group name must be 25 characters or fewer. Current length is {len(group_name)}"
            )

        # ami_id is optional: when omitted PCS uses the launch template's ImageId. When one IS
        # provided, confirm it exists and is available in the cluster's region before we register
        # it, so a bad AMI is rejected here rather than surfacing later as a node group that never
        # launches.
        if ami_id:
            _validate_ami = self._validate_ami(ami_id)
            if _validate_ami is not None:
                return _validate_ami

        # Default to the dedicated EDH PCS node instance profile registered on SSM when none was
        # given. This profile's role sits at the IAM path "/aws-pcs/" and carries
        # pcs:RegisterComputeNodeGroupInstance, so PCS accepts it -- unlike the generic
        # compute-node profile, which fails the PCS-scoped role guardrail below.
        if not instance_profile_arn:
            instance_profile_arn = self._ssm_default(
                "/configuration/PCSNodeInstanceProfileArn"
            )
            if not instance_profile_arn:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        "No instance_profile_arn provided and /configuration/PCSNodeInstanceProfileArn "
                        f"could not be resolved on SSM; cannot create PCS compute node group {group_name}"
                    )
                )
            logger.info(
                f"No instance_profile_arn provided, defaulting to EDH PCS node instance profile: {instance_profile_arn}"
            )

        _validate_iam_instance_profile = get_instance_profile(
            instance_profile_name=instance_profile_arn.split("/")[-1]
        )
        if _validate_iam_instance_profile.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to validate IAM Instance Profile {instance_profile_arn} because {_validate_iam_instance_profile.get('message')}"
            )

        # PCS resolves the IAM role *through* the instance profile, so the profile must actually
        # have a role attached; otherwise CreateComputeNodeGroup fails with "can't access a role
        # associated with the instance profile because the role ARN is invalid". Also forward the
        # canonical instance-profile ARN returned by IAM rather than the raw input, so PCS never
        # receives a role ARN (or a mistyped one) in the iamInstanceProfileArn field.
        _instance_profile = _validate_iam_instance_profile.get("message", {}).get(
            "InstanceProfile", {}
        )
        _roles = _instance_profile.get("Roles") or []
        if not _roles:
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"IAM instance profile {instance_profile_arn} has no IAM role attached; "
                    "PCS requires the instance profile to carry a role it can assume for the "
                    "compute nodes"
                )
            )

        # PCS only accepts an instance profile whose role is clearly PCS-scoped: per the
        # CreateComputeNodeGroup docs the role name must start with "AWSPCS" OR the role must have
        # the IAM path "/aws-pcs/". A role that satisfies neither (e.g. the generic EDH compute
        # node role) makes CreateComputeNodeGroup fail with "can't access a role associated with
        # the instance profile because the role ARN is invalid". Catch that here with an
        # actionable message instead of the opaque PCS ValidationException. (The role must also
        # carry the pcs:RegisterComputeNodeGroupInstance permission, which we cannot introspect
        # cheaply, so we only guard the name/path guardrail here.)
        _pcs_scoped_role = any(self._role_is_pcs_scoped(r) for r in _roles)
        if not _pcs_scoped_role:
            _role_names = [r.get("Arn", r.get("RoleName")) for r in _roles]
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"IAM instance profile {instance_profile_arn} references role(s) "
                    f"{_role_names} that AWS PCS will not accept: the instance profile role must "
                    "have a name starting with 'AWSPCS' or the IAM path '/aws-pcs/', and carry "
                    "the pcs:RegisterComputeNodeGroupInstance permission"
                )
            )

        instance_profile_arn = _instance_profile.get("Arn", instance_profile_arn)

        # min/max define the scaling bounds. desired_capacity is a legacy shortcut for a
        # fixed-size group (min == max == desired_capacity), used only for a bound not given.
        _min_instance_count = (
            min_instance_count if min_instance_count is not None else desired_capacity
        )
        _max_instance_count = (
            max_instance_count if max_instance_count is not None else desired_capacity
        )
        if _min_instance_count is None or _max_instance_count is None:
            return SocaError.GENERIC_ERROR(
                helper="min_instance_count and max_instance_count are required to create a compute node group"
            )
        if (
            _min_instance_count < 0
            or _max_instance_count < 1
            or _max_instance_count < _min_instance_count
        ):
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid scaling bounds {_min_instance_count=} / {_max_instance_count=}: "
                "expected 0 <= min <= max and max >= 1"
            )

        # Resolve subnets: caller-provided, then the cluster's own subnets, then the EDH
        # private subnets on SSM. Fail hard if none resolve, since boto3 requires subnetIds.
        _subnet_ids = (
            subnet_ids
            or self._cluster_subnet_ids
            or self._ssm_default("/configuration/PrivateSubnets", as_list=True)
        )
        if not _subnet_ids:
            return SocaError.GENERIC_ERROR(
                helper=(
                    "No subnet_ids provided and neither the cluster subnets nor "
                    "/configuration/PrivateSubnets could be resolved; cannot create PCS "
                    f"compute node group {group_name}"
                )
            )

        # Confirm the resolved subnets actually exist before registering them.
        _validate_subnets = self._validate_subnets(_subnet_ids)
        if _validate_subnets is not None:
            return _validate_subnets

        # PCS requires a numeric launch template version; resolve $Latest / $Default aliases to
        # the concrete version number before the call (otherwise CreateComputeNodeGroup fails with
        # "Launch template version must be a numeric value").
        _resolve_lt_version = self._resolve_launch_template_version(
            launch_template_id, launch_template_version
        )
        if _resolve_lt_version.get("success") is False:
            return _resolve_lt_version
        launch_template_version = _resolve_lt_version.get("message")

        # Always tag the node group with the EDH cluster id
        if not self._edh_cluster_id_value():
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Refusing to create PCS compute node group {group_name}: unable to resolve this EDH environment's cluster "
                    "id (/configuration/ClusterId), so the mandatory edh:visibility tag cannot be set"
                )
            )
        _tags = self._with_edh_tags(tags, f"PCS compute node group {group_name}")

        # Rendered + uploaded only once every validation above has passed, so a rejected request
        # does not leave an orphan S3 bootstrap behind (or pay for the render in the web request).
        # EDH bootstrap for PCS nodes runs as a nodeBootstrapped lifecycle action (root, after PCS
        # node setup, before slurmd) -- not as launch-template UserData. Render + upload the
        # bootstrap and register it here, unless the caller already supplied an explicit
        # node_lifecycle_actions payload (which wins).
        if edh_bootstrap and node_lifecycle_actions is None:
            _script = self._render_pcs_nodebootstrapped_script(base_os=edh_base_os)
            # SocaError.* factories return SocaResponse(success=False), so check success rather
            # than the type -- otherwise a failed render would fall through and its error message
            # would be used as the script S3 location, creating a broken node group.
            if _script.get("success") is False:
                return _script
            node_lifecycle_actions = {
                "stages": {
                    "nodeBootstrapped": [
                        {
                            "name": "edh-bootstrap",
                            "scriptSource": {"scriptLocation": _script.get("message")},
                            # Stop the script sequence (do NOT terminate the node) if the
                            # bootstrap fails: it mounts the shared filesystems and configures
                            # the user directory, so a node that skipped it must not accept jobs
                            # -- but STOP_SEQUENCE keeps the instance alive so the failure can be
                            # inspected (logs, mount state) instead of the node being torn down.
                            "onError": "STOP_SEQUENCE",
                            # install_required_packages (kernel) and filesystems_automount (Lustre
                            # client module) can each reboot BEFORE the mount; PCS re-runs
                            # nodeBootstrapped before slurmd on every boot, and the script's
                            # done-file makes post-completion re-runs a fast no-op.
                            "executionPolicy": "EVERY_BOOT",
                        }
                    ],
                },
                "scriptCachingPolicy": "CACHE_ONCE",
            }

        # Only include optional keys when provided so boto3 applies its own defaults otherwise.
        _create_cng_args: Dict[str, Any] = {
            "clusterIdentifier": self._cluster_name,
            "computeNodeGroupName": group_name,
            "subnetIds": _subnet_ids,
            "purchaseOption": purchase_option,
            "customLaunchTemplate": {
                "id": launch_template_id,
                "version": launch_template_version,
            },
            "iamInstanceProfileArn": instance_profile_arn,
            "scalingConfiguration": {
                "minInstanceCount": _min_instance_count,
                "maxInstanceCount": _max_instance_count,
            },
            "instanceConfigs": [{"instanceType": t} for t in instance_types],
        }
        # Only send amiId when the caller provided one; otherwise PCS inherits the launch
        # template's ImageId (where EDH configures the image + its matching bootstrap).
        if ami_id:
            _create_cng_args["amiId"] = ami_id
        if spot_options is not None:
            _create_cng_args["spotOptions"] = spot_options
        if slurm_configuration is not None:
            _create_cng_args["slurmConfiguration"] = slurm_configuration
        if node_lifecycle_actions is not None:
            _create_cng_args["nodeLifecycleActions"] = node_lifecycle_actions
        if client_token:
            _create_cng_args["clientToken"] = client_token
        if _tags:
            _create_cng_args["tags"] = _tags

        try:
            _create_compute_node = self._pcs_client.create_compute_node_group(
                **_create_cng_args
            )

            return SocaResponse(
                success=True,
                message={
                    "id": _create_compute_node.get("computeNodeGroup", {}).get("id"),
                    "name": _create_compute_node.get("computeNodeGroup", {}).get(
                        "name"
                    ),
                },
            )

        except Exception as err:
            return self._pcs_error(err, f"Create PCS compute node group {group_name}")

    @cluster_must_be_visible()
    def get_compute_node_group(
        self, compute_node_group_identifier: str
    ) -> SocaResponse | SocaError:
        """
        Retrieve a single compute node group, including its full configuration (list_compute_
        node_groups only returns summaries).

        Returns:
            SocaResponse(message=<compute node group dict>) on success.
        """
        logger.debug(
            f"Get compute node group {compute_node_group_identifier} for {self._cluster_name}"
        )
        try:
            _get = self._pcs_client.get_compute_node_group(
                clusterIdentifier=self._cluster_name,
                computeNodeGroupIdentifier=compute_node_group_identifier,
            )
            return SocaResponse(success=True, message=_get.get("computeNodeGroup", {}))
        except Exception as err:
            return self._pcs_error(
                err,
                f"Get PCS compute node group {compute_node_group_identifier} for {self._cluster_name}",
            )

    @cluster_must_be_visible()
    def delete_compute_node_group(
        self, compute_node_group_identifier
    ) -> SocaResponse | SocaError:
        logger.info(
            f"About to delete Compute Node Group ID {compute_node_group_identifier} for {self._cluster_name}"
        )
        # Never delete a compute node group this EDH environment did not create: validate tags.
        try:
            _cng_obj = self._pcs_client.get_compute_node_group(
                clusterIdentifier=self._cluster_name,
                computeNodeGroupIdentifier=compute_node_group_identifier,
            ).get("computeNodeGroup", {})
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve compute node group {compute_node_group_identifier=} for {self._cluster_name} before delete due to {err}"
            )
        _invalid = self._validate_edh_tags(
            _cng_obj.get("arn"),
            f"PCS compute node group {compute_node_group_identifier} for {self._cluster_name}",
        )
        if _invalid is not None:
            return _invalid

        try:
            self._pcs_client.delete_compute_node_group(
                clusterIdentifier=self._cluster_name,
                computeNodeGroupIdentifier=compute_node_group_identifier,
            )
            return SocaResponse(
                success=True,
                message=f"Delete initiated for {compute_node_group_identifier} for {self._cluster_name}, your compute node group will be removed shortly",
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete {compute_node_group_identifier=} for {self._cluster_name} due to {err}"
            )

    @cluster_must_be_active()
    def update_compute_node_group(
        self,
        compute_node_group_identifier: str,
        ami_id: Optional[str] = None,
        subnet_ids: Optional[List[str]] = None,
        launch_template_id: Optional[str] = None,
        launch_template_version: Optional[str] = None,
        purchase_option: Optional[
            Literal[
                "ONDEMAND",
                "SPOT",
                "CAPACITY_BLOCK",
                "INTERRUPTIBLE_CAPACITY_RESERVATION",
            ]
        ] = None,
        min_instance_count: Optional[int] = None,
        max_instance_count: Optional[int] = None,
        spot_options: Optional[Dict[str, Any]] = None,
        instance_profile_arn: Optional[str] = None,
        slurm_configuration: Optional[Dict[str, Any]] = None,
        client_token: Optional[str] = None,
    ) -> SocaResponse | SocaError:
        """
        Update a compute node group on the PCS cluster.

        Mirrors the boto3 pcs.update_compute_node_group() request surface:
        https://docs.aws.amazon.com/boto3/latest/reference/services/pcs/client/update_compute_node_group.html

        Only the fields the caller supplies are sent; everything else is left as-is. Note that
        the instance types (instanceConfigs) are NOT updatable on an existing compute node group
        -- PCS rejects them on update, so create a new group if the instance mix must change.

        Two request members are "all-or-nothing" objects on the PCS side, so a partial change is
        merged with the group's current configuration before the call:
          * scalingConfiguration requires BOTH minInstanceCount and maxInstanceCount; if only one
            is supplied, the other is filled from the group's current scaling configuration.
          * customLaunchTemplate requires BOTH id and version; if only one is supplied, the other
            is filled from the group's current launch template.

        Args:
            compute_node_group_identifier: Name or id of the compute node group to update.
            ami_id: New AMI id (validated before the call).
            subnet_ids: New subnet(s) (validated before the call).
            launch_template_id / launch_template_version: New EC2 launch template. $Latest /
                $Default aliases are resolved to a numeric version before the call.
            purchase_option: ONDEMAND | SPOT | CAPACITY_BLOCK | INTERRUPTIBLE_CAPACITY_RESERVATION.
            min_instance_count / max_instance_count: scalingConfiguration bounds.
            spot_options: Optional, e.g. {"allocationStrategy": "price-capacity-optimized"}.
            instance_profile_arn: New IAM instance profile ARN (validated, PCS-scoped, before the call).
            slurm_configuration: Optional Slurm settings to update.
            client_token: Optional idempotency token.

        Returns:
            SocaResponse(message={"id": <id>, "name": <name>}) on success.
        """
        logger.info(
            f"Updating compute node group {compute_node_group_identifier} for {self._cluster_name}"
        )
        # Never mutate a compute node group this EDH environment did not create: validate its
        # tags first, mirroring the guard on delete_compute_node_group. The current config is
        # also reused to complete the all-or-nothing scaling/launch-template objects below.
        _get = self.get_compute_node_group(compute_node_group_identifier)
        if _get.get("success") is False:
            return _get
        _current = _get.get("message") or {}
        _invalid = self._validate_edh_tags(
            _current.get("arn"),
            f"PCS compute node group {compute_node_group_identifier} for {self._cluster_name}",
        )
        if _invalid is not None:
            return _invalid

        _update_cng_args: Dict[str, Any] = {
            "clusterIdentifier": self._cluster_name,
            "computeNodeGroupIdentifier": compute_node_group_identifier,
        }

        if ami_id is not None:
            _validate_ami = self._validate_ami(ami_id)
            if _validate_ami is not None:
                return _validate_ami
            _update_cng_args["amiId"] = ami_id

        if subnet_ids is not None:
            _validate_subnets = self._validate_subnets(subnet_ids)
            if _validate_subnets is not None:
                return _validate_subnets
            _update_cng_args["subnetIds"] = subnet_ids

        if purchase_option is not None:
            _update_cng_args["purchaseOption"] = purchase_option

        if spot_options is not None:
            _update_cng_args["spotOptions"] = spot_options

        if slurm_configuration is not None:
            _update_cng_args["slurmConfiguration"] = slurm_configuration

        # IAM instance profile: apply the same PCS-scoped-role guardrail used on create so a
        # profile PCS would reject is caught here with an actionable message.
        if instance_profile_arn is not None:
            _validate_iam_instance_profile = get_instance_profile(
                instance_profile_name=instance_profile_arn.split("/")[-1]
            )
            if _validate_iam_instance_profile.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to validate IAM Instance Profile {instance_profile_arn} because {_validate_iam_instance_profile.get('message')}"
                )
            _instance_profile = _validate_iam_instance_profile.get("message", {}).get(
                "InstanceProfile", {}
            )
            _roles = _instance_profile.get("Roles") or []
            if not _roles:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"IAM instance profile {instance_profile_arn} has no IAM role attached; "
                        "PCS requires the instance profile to carry a role it can assume for the "
                        "compute nodes"
                    )
                )
            if not any(self._role_is_pcs_scoped(r) for r in _roles):
                _role_names = [r.get("Arn", r.get("RoleName")) for r in _roles]
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"IAM instance profile {instance_profile_arn} references role(s) "
                        f"{_role_names} that AWS PCS will not accept: the instance profile role must "
                        "have a name starting with 'AWSPCS' or the IAM path '/aws-pcs/', and carry "
                        "the pcs:RegisterComputeNodeGroupInstance permission"
                    )
                )
            _update_cng_args["iamInstanceProfileArn"] = _instance_profile.get(
                "Arn", instance_profile_arn
            )

        # scalingConfiguration is an all-or-nothing object: PCS requires both bounds. Fill any
        # unspecified bound from the group's current scaling configuration.
        if min_instance_count is not None or max_instance_count is not None:
            _current_scaling = _current.get("scalingConfiguration") or {}
            _min = (
                min_instance_count
                if min_instance_count is not None
                else _current_scaling.get("minInstanceCount")
            )
            _max = (
                max_instance_count
                if max_instance_count is not None
                else _current_scaling.get("maxInstanceCount")
            )
            if _min is None or _max is None:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        "Unable to resolve both minInstanceCount and maxInstanceCount for compute "
                        f"node group {compute_node_group_identifier}; provide both values"
                    )
                )
            _update_cng_args["scalingConfiguration"] = {
                "minInstanceCount": _min,
                "maxInstanceCount": _max,
            }

        # customLaunchTemplate is an all-or-nothing object: PCS requires both id and version.
        # Fill any unspecified part from the group's current launch template, and resolve
        # $Latest / $Default aliases to a numeric version.
        if launch_template_id is not None or launch_template_version is not None:
            _current_lt = _current.get("customLaunchTemplate") or {}
            _lt_id = launch_template_id or _current_lt.get("id")
            if not _lt_id:
                return SocaError.GENERIC_ERROR(
                    helper=(
                        "Unable to resolve the launch template id for compute node group "
                        f"{compute_node_group_identifier}; provide launch_template_id"
                    )
                )
            # The current version number only means something for the current template: when
            # switching to a different template without a version, use the new one's $Latest.
            if launch_template_version:
                _lt_version = launch_template_version
            elif _lt_id == _current_lt.get("id"):
                _lt_version = _current_lt.get("version") or "$Latest"
            else:
                _lt_version = "$Latest"
            _resolve_lt_version = self._resolve_launch_template_version(
                _lt_id, _lt_version
            )
            if _resolve_lt_version.get("success") is False:
                return _resolve_lt_version
            _update_cng_args["customLaunchTemplate"] = {
                "id": _lt_id,
                "version": _resolve_lt_version.get("message"),
            }

        if client_token:
            _update_cng_args["clientToken"] = client_token

        try:
            _update = self._pcs_client.update_compute_node_group(**_update_cng_args)
            return SocaResponse(
                success=True,
                message={
                    "id": _update.get("computeNodeGroup", {}).get("id"),
                    "name": _update.get("computeNodeGroup", {}).get(
                        "name", compute_node_group_identifier
                    ),
                },
            )
        except Exception as err:
            return self._pcs_error(
                err,
                f"Update PCS compute node group {compute_node_group_identifier} for {self._cluster_name}",
            )
