# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Discovery of pre-existing AWS resources an EDH cluster can re-use.

Every function here is pure data: it queries AWS, returns plain Python
structures, and never prompts or prints. Presentation and selection belong
to the caller so the TUI keeps a single consistent prompt idiom.

Ported from the reachable discovery paths of ``install_soca_legacy.py``
(``_get_filesystems_by_vpc``) and ``find_existing_resources.py``
(``FindExistingResource.find_elasticsearch``).
"""

import ipaddress
import logging

logger = logging.getLogger("soca_logger")

# FSx types EDH can mount as an existing /apps or /data filesystem.
# ONTAP is selected per-volume rather than per-filesystem: a volume only becomes
# mountable once it is paired with its SVM's NFS endpoint and junction path.
# WINDOWS is excluded because EDH does not mount SMB shares for these paths.
SUPPORTED_FSX_TYPES = frozenset({"LUSTRE", "OPENZFS", "ONTAP"})

# describe_storage_virtual_machines caps the number of IDs per request.
_SVM_QUERY_CHUNK_SIZE = 50

# FSx per-type configuration block holding DeploymentType.
_FSX_CONFIG_KEY = {
    "LUSTRE": "LustreConfiguration",
    "OPENZFS": "OpenZFSConfiguration",
    "ONTAP": "OntapConfiguration",
    "WINDOWS": "WindowsConfiguration",
}


def _format_byte_size(num, suffix: str = "B") -> str:
    """Human-readable byte size.

    Deliberately duplicated from ``helpers.installer.helpers.format_byte_size``
    rather than imported: that module pulls in ``constants``, which imports
    ``questionary``, and dragging the TUI dependency chain in here would make
    this module unimportable for off-cluster unit tests.
    """

    for _unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {_unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def discover_filesystems(
    efs_client,
    fsx_client,
    region: str,
    vpc_id: str,
    dns_suffix: str = "amazonaws.com",
) -> dict:
    """Return EFS and FSx filesystems in ``vpc_id`` that EDH can re-use.

    Returns ``{"filesystems": [...], "skipped": [...]}``. Each filesystem
    entry carries ``id``, ``name``, ``dns_name``, ``size``, ``fs_type``,
    ``description``, ``features`` and ``mount_target``.

    ``fs_type`` matches the ``FilesystemProvider`` enum values (``efs``,
    ``fsx_lustre``, ``fsx_openzfs``, ``fsx_ontap``) so it can be assigned
    straight to ``fs_*_provider``.

    ``mount_target`` is the exact value to assign to ``fs_apps`` / ``fs_data``.
    It is provider-specific and must not be second-guessed by the caller:
    ``mount_efs`` / ``mount_fsx_lustre`` / ``mount_fsx_openzfs`` reduce it with
    ``cut -d'.' -f1`` so a DNS name is fine, but ``mount_fsx_ontap`` feeds it
    straight to ``describe-volumes --volume-ids`` and therefore requires a bare
    ``fsvol-`` volume ID.

    ``skipped`` carries ``{"id", "reason"}`` so the caller can explain why a
    filesystem the operator expected to see was excluded.
    """

    _filesystems: list = []
    _skipped: list = []

    _discover_efs(
        efs_client=efs_client,
        region=region,
        vpc_id=vpc_id,
        dns_suffix=dns_suffix,
        filesystems=_filesystems,
        skipped=_skipped,
    )
    _discover_fsx(
        fsx_client=fsx_client,
        vpc_id=vpc_id,
        filesystems=_filesystems,
        skipped=_skipped,
    )

    logger.debug(
        f"Filesystem discovery in {region}/{vpc_id}: "
        f"{len(_filesystems)} usable, {len(_skipped)} skipped"
    )
    return {"filesystems": _filesystems, "skipped": _skipped}


def _discover_efs(
    efs_client,
    region: str,
    vpc_id: str,
    dns_suffix: str,
    filesystems: list,
    skipped: list,
) -> None:
    """Append every re-usable EFS filesystem in ``vpc_id`` to ``filesystems``."""

    for _page in efs_client.get_paginator("describe_file_systems").paginate():
        for _fs in _page.get("FileSystems", []):
            _fs_id: str = _fs.get("FileSystemId", "")
            if not _fs_id:
                continue

            if _fs.get("LifeCycleState", "").upper() != "AVAILABLE":
                skipped.append(
                    {
                        "id": _fs_id,
                        "reason": f"EFS lifecycle is {_fs.get('LifeCycleState', 'unknown')}, must be AVAILABLE",
                    }
                )
                continue

            if _fs.get("NumberOfMountTargets", 0) <= 0:
                skipped.append({"id": _fs_id, "reason": "EFS has no mount targets"})
                continue

            # An EFS filesystem is only reachable from this VPC when at least
            # one of its mount targets lives in it.
            _mount_targets = efs_client.describe_mount_targets(
                FileSystemId=_fs_id
            ).get("MountTargets", [])
            if not any(_mt.get("VpcId") == vpc_id for _mt in _mount_targets):
                skipped.append(
                    {"id": _fs_id, "reason": "EFS has no mount target in this VPC"}
                )
                continue

            _perf_mode: str = _fs.get("PerformanceMode", "")
            if _perf_mode != "generalPurpose":
                skipped.append(
                    {
                        "id": _fs_id,
                        "reason": f"EFS performance mode {_perf_mode or 'unknown'} is unsupported",
                    }
                )
                continue

            _throughput_mode: str = _fs.get("ThroughputMode", "unknown")
            if _throughput_mode == "provisioned":
                _features = (
                    f"GP/Provisioned/"
                    f"{_fs.get('ProvisionedThroughputInMibps', 0.0)} MiB/s"
                )
            else:
                _features = f"GP/{_throughput_mode.capitalize()}"

            _fs_name: str = _fs.get("Name", "")
            _fs_size: str = _format_byte_size(
                _fs.get("SizeInBytes", {}).get("Value", 0)
            )
            _dns_name: str = f"{_fs_id}.efs.{region}.{dns_suffix}"

            filesystems.append(
                {
                    "id": _fs_id,
                    "filesystem_id": _fs_id,
                    "name": _fs_name,
                    "dns_name": _dns_name,
                    "size": _fs_size,
                    "fs_type": "efs",
                    "description": f"EFS: {_fs_name or _fs_id} {_dns_name}",
                    "features": _features,
                    "mount_target": _dns_name,
                }
            )
            logger.debug(f"Discovered EFS {_fs_id} ({_fs_name}) {_fs_size}")


def _discover_fsx(
    fsx_client,
    vpc_id: str,
    filesystems: list,
    skipped: list,
) -> None:
    """Append every re-usable FSx filesystem in ``vpc_id`` to ``filesystems``."""

    for _page in fsx_client.get_paginator("describe_file_systems").paginate():
        for _fs in _page.get("FileSystems", []):
            _fs_id: str = _fs.get("FileSystemId", "")
            if not _fs_id:
                continue

            _fs_type: str = _fs.get("FileSystemType", "").upper()

            if _fs.get("Lifecycle", "").upper() not in {"AVAILABLE", "UPDATING"}:
                skipped.append(
                    {
                        "id": _fs_id,
                        "reason": f"FSx/{_fs_type} lifecycle is {_fs.get('Lifecycle', 'unknown')}",
                    }
                )
                continue

            if _fs_type not in SUPPORTED_FSX_TYPES:
                skipped.append(
                    {
                        "id": _fs_id,
                        "reason": f"FSx type {_fs_type or 'unknown'} cannot be re-used as /apps or /data",
                    }
                )
                continue

            if _fs.get("VpcId", "") != vpc_id:
                skipped.append({"id": _fs_id, "reason": "FSx is not in this VPC"})
                continue

            # DeploymentType drives mount behaviour, so refuse anything we
            # cannot positively identify rather than guessing.
            _deployment_type: str = _fs.get(
                _FSX_CONFIG_KEY.get(_fs_type, ""), {}
            ).get("DeploymentType", "")
            if not _deployment_type:
                skipped.append(
                    {
                        "id": _fs_id,
                        "reason": f"Unable to determine FSx/{_fs_type} deployment type",
                    }
                )
                continue

            _features_list: list = [_deployment_type]
            _fs_version: str = _fs.get("FileSystemTypeVersion", "")
            if _fs_version:
                _features_list.append(f"Version: {_fs_version}")

            _fs_name: str = next(
                (
                    _tag.get("Value", "")
                    for _tag in _fs.get("Tags", [])
                    if _tag.get("Key") == "Name"
                ),
                "",
            )
            _provider: str = f"fsx_{_fs_type.lower()}"

            # ONTAP is mounted per-volume, so it fans out into one entry per
            # mountable volume instead of a single filesystem-level entry.
            if _fs_type == "ONTAP":
                _discover_ontap_volumes(
                    fsx_client=fsx_client,
                    filesystem_id=_fs_id,
                    filesystem_name=_fs_name,
                    base_features=_features_list,
                    filesystems=filesystems,
                    skipped=skipped,
                )
                continue

            _fs_size: str = _format_byte_size(
                num=_fs.get("StorageCapacity", 0) * 1024 * 1024 * 1024
            )
            _dns_name: str = _fs.get("DNSName", "")

            filesystems.append(
                {
                    "id": _fs_id,
                    "filesystem_id": _fs_id,
                    "name": _fs_name,
                    "dns_name": _dns_name,
                    "size": _fs_size,
                    "fs_type": _provider,
                    "description": f"FSx/{_fs_type}: {_fs_name or _fs_id} {_dns_name}",
                    "features": "\n".join(_features_list),
                    # mount_fsx_lustre / mount_fsx_openzfs reduce this with
                    # cut -d'.' -f1, so the DNS name resolves to the ID on-host.
                    "mount_target": _dns_name or _fs_id,
                }
            )
            logger.debug(
                f"Discovered FSx/{_fs_type} {_fs_id} ({_fs_name}) {_fs_size}"
            )


def _discover_ontap_volumes(
    fsx_client,
    filesystem_id: str,
    filesystem_name: str,
    base_features: list,
    filesystems: list,
    skipped: list,
) -> None:
    """Append each mountable ONTAP volume of ``filesystem_id`` to ``filesystems``.

    An ONTAP volume is only mountable once paired with its SVM, so this resolves
    volumes first, then the owning SVMs, and emits one selectable entry per
    volume. The SVM's Active Directory state is surfaced in ``features`` because
    an SVM with no AD join makes NFSv4 group membership fall back to ``nobody``.
    """

    _candidate_volumes: dict = {}
    _svm_ids: list = []

    for _page in fsx_client.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "file-system-id", "Values": [filesystem_id]}]
    ):
        for _volume in _page.get("Volumes", []):
            _volume_id: str = _volume.get("VolumeId", "")
            if not _volume_id:
                continue

            _ontap_config: dict = _volume.get("OntapConfiguration", {})
            if not _ontap_config:
                skipped.append(
                    {"id": _volume_id, "reason": "ONTAP volume has no OntapConfiguration"}
                )
                continue

            # The SVM root volume is namespace plumbing, never a data target.
            if _ontap_config.get("StorageVirtualMachineRoot", True):
                logger.debug(f"Skipping ONTAP volume {_volume_id}: SVM root volume")
                continue

            # RW only. An LS volume is a read-only load-sharing mirror, and both
            # /apps and /data must be writable, so an LS volume would mount and
            # then fail every write at runtime.
            _ontap_volume_type: str = _ontap_config.get("OntapVolumeType", "").upper()
            if _ontap_volume_type != "RW":
                skipped.append(
                    {
                        "id": _volume_id,
                        "reason": f"ONTAP volume type {_ontap_volume_type or 'unknown'} is not writable (RW)",
                    }
                )
                continue

            if _volume.get("Lifecycle", "").upper() not in {"CREATED", "MISCONFIGURED"}:
                skipped.append(
                    {
                        "id": _volume_id,
                        "reason": f"ONTAP volume lifecycle is {_volume.get('Lifecycle', 'unknown')}",
                    }
                )
                continue

            # Without a junction path the volume is not exported into the SVM
            # namespace, so it cannot be NFS-mounted.
            if not _ontap_config.get("JunctionPath", ""):
                skipped.append(
                    {"id": _volume_id, "reason": "ONTAP volume has no junction path"}
                )
                continue

            _svm_id: str = _ontap_config.get("StorageVirtualMachineId", "")
            if not _svm_id:
                skipped.append(
                    {"id": _volume_id, "reason": "ONTAP volume has no owning SVM"}
                )
                continue

            _candidate_volumes[_volume_id] = _volume
            if _svm_id not in _svm_ids:
                _svm_ids.append(_svm_id)

    if not _candidate_volumes:
        skipped.append(
            {
                "id": filesystem_id,
                "reason": "FSx/ONTAP has no mountable volumes (junction path + non-root + RW/LS)",
            }
        )
        return

    _svms: dict = _describe_svms(fsx_client=fsx_client, svm_ids=_svm_ids)

    for _volume_id, _volume in _candidate_volumes.items():
        _ontap_config: dict = _volume.get("OntapConfiguration", {})
        _svm_id: str = _ontap_config.get("StorageVirtualMachineId", "")
        _svm: dict = _svms.get(_svm_id, {})

        if not _svm:
            skipped.append(
                {
                    "id": _volume_id,
                    "reason": f"Owning SVM {_svm_id} is not usable (not CREATED, or no NFS endpoint)",
                }
            )
            continue

        _features_list: list = [*base_features]

        _junction_path: str = _ontap_config.get("JunctionPath", "")
        _nfs_dns: str = _svm.get("nfs_dns", "")
        _features_list.append(f"NFS: {_nfs_dns}:{_junction_path}")

        # AD linkage is the usual source of ONTAP mount trouble, so state it
        # plainly at selection time rather than discovering it at bootstrap.
        if _svm.get("ad_domain"):
            _features_list.append(f"AD: {_svm['ad_domain']}")
        else:
            _features_list.append("AD: not joined (NFSv4 owners may map to nobody)")

        if _svm.get("smb_dns"):
            _features_list.append("SMB: available")

        _security_style: str = _ontap_config.get("SecurityStyle", "")
        if _security_style:
            _features_list.append(f"Security: {_security_style}")

        _volume_name: str = _volume.get("Name", "")
        _svm_name: str = _svm.get("name", _svm_id)

        filesystems.append(
            {
                "id": _volume_id,
                "filesystem_id": filesystem_id,
                "name": (
                    f"{_volume_name or _volume_id} via SVM {_svm_name} "
                    f"(path {_junction_path})"
                ),
                "dns_name": f"{_nfs_dns}:{_junction_path}",
                "size": _format_byte_size(_ontap_config.get("SizeInBytes", 0)),
                "fs_type": "fsx_ontap",
                "description": (
                    f"FSx/ONTAP: {_volume_name or _volume_id} via SVM {_svm_name} "
                    f"- {_nfs_dns}:{_junction_path}"
                ),
                "features": "\n".join(_features_list),
                # mount_fsx_ontap passes this straight to
                # describe-volumes --volume-ids, so it MUST be the volume ID and
                # not the NFS endpoint.
                "mount_target": _volume_id,
            }
        )
        logger.debug(
            f"Discovered FSx/ONTAP volume {_volume_id} on {filesystem_id} "
            f"({filesystem_name}) via SVM {_svm_name}"
        )


def _describe_svms(fsx_client, svm_ids: list) -> dict:
    """Return ``{svm_id: {name, nfs_dns, smb_dns, ad_domain}}`` for usable SVMs.

    SVMs that are not fully created, or that expose no NFS endpoint, are omitted
    so the caller reports the owning volume as unusable.
    """

    _svms: dict = {}

    for _offset in range(0, len(svm_ids), _SVM_QUERY_CHUNK_SIZE):
        _chunk = svm_ids[_offset : _offset + _SVM_QUERY_CHUNK_SIZE]
        for _page in fsx_client.get_paginator(
            "describe_storage_virtual_machines"
        ).paginate(StorageVirtualMachineIds=_chunk):
            for _svm in _page.get("StorageVirtualMachines", []):
                _svm_id: str = _svm.get("StorageVirtualMachineId", "")
                if not _svm_id:
                    continue

                if _svm.get("Lifecycle", "").upper() != "CREATED":
                    logger.debug(
                        f"Skipping SVM {_svm_id}: lifecycle is {_svm.get('Lifecycle', 'unknown')}"
                    )
                    continue

                _nfs: dict = _svm.get("Endpoints", {}).get("Nfs", {})
                # Prefer the DNS name; mount_fsx_ontap resolves via DNSName and
                # an IP is only a fallback for endpoints that omit it.
                _nfs_dns: str = _nfs.get("DNSName", "") or next(
                    iter(_nfs.get("IpAddresses", []) or []), ""
                )
                if not _nfs_dns:
                    logger.debug(f"Skipping SVM {_svm_id}: no NFS endpoint")
                    continue

                _svms[_svm_id] = {
                    "name": _svm.get("Name", "") or _svm_id,
                    "nfs_dns": _nfs_dns,
                    "smb_dns": _svm.get("Endpoints", {}).get("Smb", {}).get("DNSName", ""),
                    "ad_domain": _svm.get("ActiveDirectoryConfiguration", {})
                    .get("SelfManagedActiveDirectoryConfiguration", {})
                    .get("DomainName", ""),
                }

    return _svms


def get_mount_target_security_groups(
    efs_client, fsx_client, ec2_client, filesystem: dict
) -> list:
    """Return the security group IDs guarding a filesystem's mount targets.

    A re-used filesystem is only reachable if these groups admit NFS from the
    cluster's node security groups. EDH does not modify security groups it does
    not own, so the caller surfaces these to the operator.

    Returns an empty list when the groups cannot be determined; the caller must
    treat that as unknown rather than as "no restriction".
    """

    _fs_id: str = filesystem.get("filesystem_id") or filesystem.get("id", "")
    if not _fs_id:
        return []

    _groups: list = []
    try:
        if filesystem.get("fs_type") == "efs":
            for _mt in efs_client.describe_mount_targets(FileSystemId=_fs_id).get(
                "MountTargets", []
            ):
                _mt_id: str = _mt.get("MountTargetId", "")
                if not _mt_id:
                    continue
                _groups.extend(
                    efs_client.describe_mount_target_security_groups(
                        MountTargetId=_mt_id
                    ).get("SecurityGroups", [])
                )
        else:
            # FSx exposes its mount targets as ENIs rather than an EFS-style API.
            _enis: list = []
            for _fs in fsx_client.describe_file_systems(
                FileSystemIds=[_fs_id]
            ).get("FileSystems", []):
                _enis.extend(_fs.get("NetworkInterfaceIds", []) or [])
            if _enis:
                for _eni in ec2_client.describe_network_interfaces(
                    NetworkInterfaceIds=_enis
                ).get("NetworkInterfaces", []):
                    _groups.extend(
                        _g.get("GroupId", "")
                        for _g in _eni.get("Groups", [])
                        if _g.get("GroupId")
                    )
    except Exception as _err:
        logger.debug(f"Unable to resolve mount target security groups for {_fs_id}: {_err}")
        return []

    return sorted(set(_groups))


def check_nfs_cidr_access(ec2_client, security_group_ids: list, subnet_cidrs: list) -> dict:
    """Report whether ``security_group_ids`` admit NFS from every subnet CIDR.

    Returns ``{"covered", "permitted_cidrs", "uncovered_cidrs", "error"}``.

    CIDR is the only mechanism an operator can pre-authorize here: the cluster's
    node security groups are created by CDK during the deploy, so they do not
    exist to be referenced when this runs. ``covered`` is False when unknown, so
    an unreadable rule set never reads as permitted.
    """

    if not security_group_ids or not subnet_cidrs:
        return {
            "covered": False,
            "permitted_cidrs": [],
            "uncovered_cidrs": list(subnet_cidrs),
            "error": "no security groups or subnets to evaluate",
        }

    _permitted: list = []
    try:
        for _sg in ec2_client.describe_security_groups(
            GroupIds=list(security_group_ids)
        ).get("SecurityGroups", []):
            for _rule in _sg.get("IpPermissions", []):
                _proto = str(_rule.get("IpProtocol", ""))
                # "-1" is all protocols and carries no port range.
                if _proto == "-1":
                    _permitted.extend(
                        _r.get("CidrIp", "") for _r in _rule.get("IpRanges", [])
                    )
                    continue
                if _proto.lower() != "tcp":
                    continue
                _from, _to = _rule.get("FromPort"), _rule.get("ToPort")
                if _from is None or _to is None or not _from <= 2049 <= _to:
                    continue
                _permitted.extend(
                    _r.get("CidrIp", "") for _r in _rule.get("IpRanges", [])
                )
    except Exception as _err:
        logger.debug(f"Unable to read rules for {security_group_ids}: {_err}")
        return {
            "covered": False,
            "permitted_cidrs": [],
            "uncovered_cidrs": list(subnet_cidrs),
            "error": str(_err),
        }

    _permitted = sorted({_c for _c in _permitted if _c})
    _permitted_nets = []
    for _cidr in _permitted:
        try:
            _permitted_nets.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError:
            continue

    _uncovered: list = []
    for _cidr in subnet_cidrs:
        try:
            _subnet_net = ipaddress.ip_network(_cidr, strict=False)
        except ValueError:
            _uncovered.append(_cidr)
            continue
        # Version guard: subnet_of() raises TypeError across IP versions.
        if not any(
            _subnet_net.version == _p.version and _subnet_net.subnet_of(_p)
            for _p in _permitted_nets
        ):
            _uncovered.append(_cidr)

    return {
        "covered": not _uncovered,
        "permitted_cidrs": _permitted,
        "uncovered_cidrs": _uncovered,
        "error": "",
    }


def discover_opensearch_domains(es_client, vpc_id: str) -> dict:
    """Return VPC-attached OpenSearch domains in ``vpc_id`` EDH can re-use.

    Returns ``{"domains": [...], "skipped": [...]}``. Each domain entry
    carries ``name``, ``engine``, ``version`` and ``endpoint``, where
    ``endpoint`` is the value EDH passes to CDK as ``os_endpoint``.

    Provisioned domains only. OpenSearch Serverless collections are not
    discoverable through this API and are not supported as a re-use target.
    """

    _domains: list = []
    _skipped: list = []

    for _entry in es_client.list_domain_names(EngineType="OpenSearch").get(
        "DomainNames", []
    ):
        _domain_name: str = _entry.get("DomainName", "")
        if not _domain_name:
            continue

        # EngineType from the listing is authoritative. Do not infer the engine
        # from the version string.
        _engine: str = _entry.get("EngineType", "") or "unknown"

        _domain: dict = es_client.describe_elasticsearch_domain(
            DomainName=_domain_name
        ).get("DomainStatus", {})

        if _domain.get("Deleted", False):
            _skipped.append({"name": _domain_name, "reason": "Domain is deleted"})
            continue

        if not _domain.get("Created", False):
            _skipped.append({"name": _domain_name, "reason": "Domain is still being created"})
            continue

        if _domain.get("UpgradeProcessing", False):
            _skipped.append({"name": _domain_name, "reason": "Domain is upgrading"})
            continue

        # A public domain is unreachable from the cluster's private subnets.
        _domain_vpc_id: str = _domain.get("VPCOptions", {}).get("VPCId", "")
        if not _domain_vpc_id:
            _skipped.append(
                {"name": _domain_name, "reason": "Domain is not VPC-attached"}
            )
            continue

        if _domain_vpc_id != vpc_id:
            _skipped.append(
                {"name": _domain_name, "reason": f"Domain is in {_domain_vpc_id}"}
            )
            continue

        # A VPC domain reports no flat Endpoint; it exposes an Endpoints map that
        # now carries both "vpc" (classic es.amazonaws.com) and "vpcv2" (newer
        # aos.on.aws). Pin "vpc" explicitly rather than trusting dict order.
        _endpoints: dict = _domain.get("Endpoints", {}) or {}
        _endpoint: str = (
            _endpoints.get("vpc", "")
            or _domain.get("Endpoint", "")
            or next(iter(_endpoints.values()), "")
        )
        if not _endpoint:
            _skipped.append(
                {"name": _domain_name, "reason": "Domain has no reachable endpoint"}
            )
            continue

        # The legacy es API reports the version under ElasticsearchVersion even
        # for OpenSearch domains; EngineVersion is the newer opensearch API key.
        _engine_version: str = _domain.get("ElasticsearchVersion", "") or _domain.get(
            "EngineVersion", ""
        )

        _domains.append(
            {
                "name": _domain_name,
                "engine": _engine,
                "version": _engine_version,
                "endpoint": _endpoint,
            }
        )
        logger.debug(
            f"Discovered {_engine} domain {_domain_name} ({_engine_version}) at {_endpoint}"
        )

    logger.debug(
        f"OpenSearch discovery in {vpc_id}: "
        f"{len(_domains)} usable, {len(_skipped)} skipped"
    )
    return {"domains": _domains, "skipped": _skipped}
