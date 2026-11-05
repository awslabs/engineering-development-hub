# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click

import re
from commands.common import print_output, is_controller_instance, confirm
from commands.config import set as config_set
from commands.config import get as config_get
from commands.config import key_exists as config_key_exists
from utils.aws.ec2_helper import describe_instances_paginate
from utils.aws.ssm_helper import describe_instance_platforms, execute_ssm_document
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.datamodels.constants import SocaLinuxBaseOS
from utils.jinjanizer import SocaJinja2Generator
from utils.validators import Validators


# Single source for mount_target validation, shared by `set` and `update`. These
# were previously two separate literals and both carried the same broken nfs
# pattern, so keeping one table is what prevents them drifting again.
#
# nfs accepts "host" or "host:/path", where host is an IPv4 address or a DNS
# name. A colon must be followed by an absolute export path: a port has no
# meaning in fstab's nfs4 device field (use the port= mount option), so
# "host:2049/export" is refused rather than written into /etc/fstab. IPv6
# literals are not accepted. This is a syntax guardrail, not an address
# validator -- an out-of-range octet such as 10.0.1.555 still passes.
# Every pattern is anchored at BOTH ends. Validation uses re.match, which
# anchors the start implicitly and the end not at all, so the three
# filesystem-id patterns previously accepted anything after a valid-looking
# prefix -- "fs-abcdefgh anything" passed and was written into the FileSystems
# config and from there into the mount and fstab bootstrap. The nfs, fsx_ontap
# and s3 entries were already anchored; these now match them.
_MOUNT_TARGET_REGEX = {
    "efs": r"^fs-[0-9a-z]{8,40}$",
    "nfs": r"^(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)(?::/[^\s:]*)?$",
    "fsx_lustre": r"^fs-[0-9a-z]{8,40}$",
    "fsx_ontap": r"^fsvol-\w{8,}$",
    "fsx_openzfs": r"^fs-[0-9a-z]{8,40}$",
    "s3": r"(?!(^(xn--|sthree-|sthree-configurator)|.+(-s3alias|--ol-s3)$))^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$",
}

# Node types whose bootstrap runs filesystems_automount.sh. dcv_broker and
# dcv_gateway are absent on purpose: their user_data never mounts an EDH
# filesystem, so applying to them would add a mount rather than repair one.
_FILESYSTEM_NODE_TYPES = (
    "controller",
    "login_node",
    "compute_node",
    "dcv_node",
    "target_node",
)

# The always-on node types. Every other type reads the FileSystems tree when it
# launches, so a config change reaches it without help; these two outlive the
# change and are what `apply` exists for.
_ALWAYSON_NODE_TYPES = ("controller", "login_node")

# Where apply stages its rendered script. Deliberately NOT the launch-time
# bootstrap prefix: overwriting that would hand a node launched later a script
# rendered for whatever --base-os this invocation happened to use.
_APPLY_S3_PREFIX = "config/do_not_delete/bootstrap/apply"


@click.group()
def filesystems():
    """Manage the cluster's mounted filesystem definitions."""
    pass


@filesystems.command()
@click.option(
    "-k",
    "--key",
    help="Specify a top level FileSystem UUID key (e.g: apps, data ...)",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
@click.option(
    "--flatten",
    is_flag=True,
    default=False,
    help="Flatten Key as stored on SSM",
)
@click.pass_context
def get(ctx, key, output, flatten):
    """Show the configuration of one or all filesystems."""
    if key is not None:
        if not key.endswith("/"):
            key = f"{key}/"

        if "/configuration/FileSystems/" in key:
            _ssm_key = key
        else:
            _ssm_key = f"/configuration/FileSystems/{key}"
    else:
        _ssm_key = f"/configuration/FileSystems/"

    ctx.meta["echo"] = False
    _get_key = ctx.invoke(config_get, key=_ssm_key)
    if flatten:
        print_output(message=_get_key, output=output)
    else:
        _fs_data = {}
        for key, value in _get_key.items():
            parts = key.replace("/configuration/FileSystems/", "").split("/")
            current_dict = _fs_data
            for part in parts[:-1]:
                if part not in current_dict:
                    current_dict[part] = {}
                current_dict = current_dict[part]

            current_dict[parts[-1]] = value
        print_output(message=_fs_data, output=output)


@filesystems.command()
@click.option(
    "-n",
    "--filesystem-name",
    type=str,
    required=True,
    help="Specify a top level FileSystem UUID key (e.g: apps, data ...)",
)
@click.option(
    "-p",
    "--provider",
    type=click.Choice(
        [
            "efs",
            "nfs",
            "fsx_lustre",
            "fsx_ontap",
            "fsx_openzfs",
            "s3",
        ]
    ),
    required=True,
    help="Specify a provider for the filesystem",
)
@click.option(
    "-m",
    "--mount-path",
    type=str,
    required=True,
    help="Specify a mount path for the filesystem",
)
@click.option(
    "-t",
    "--mount-target",
    type=str,
    required=True,
    help="Specify the mount target for the filesystem",
)
@click.option(
    "-o",
    "--mount-options",
    required=False,
    help="Specify mount options for the filesystem",
)
@click.option(
    "-f",
    "--on-mount-failure",
    type=click.Choice(["ignore", "exit"]),
    default="ignore",
    help="Specify on mount failure behavior",
)
@click.option(
    "-e",
    "--enabled",
    type=click.Choice(["true", "false"]),
    default="true",
    help="Enable the filesystem",
)
@click.option(
    "-d",
    "--mount-drive-letter",
    type=str,
    required=False,
    help="(fsx_ontap only) Windows drive letter (A-Z) to auto-map the CIFS share to on Windows VDIs. Recommend F or later -- A-E are commonly used by system/instance-store-scratch/CD-ROM; any letter already in use on the instance is skipped. Opt-in: omit to disable Windows auto-mount for this filesystem.",
)
@click.option(
    "--cifs-share-name",
    type=str,
    required=False,
    help="(fsx_ontap only) OPTIONAL override of the CIFS/SMB share name to map on Windows VDIs. For shares EDH creates, the controller auto-publishes the correct name -- leave this UNSET. Set it only to map a share EDH did not create, or one renamed from the default.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    type=bool,
    help="Force create, ignore confirmation message",
)
@click.pass_context
def set(
    ctx,
    filesystem_name,
    provider,
    mount_path,
    mount_target,
    mount_options,
    on_mount_failure,
    enabled,
    mount_drive_letter,
    cifs_share_name,
    force,
):
    """Define a new filesystem."""

    _providers = {
        "efs": {
            "help_message": "Expected mount_target is a valid EFS Filesystem ID (e.g fs-abcde123)",
            "default_mount_options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
        },
        "nfs": {
            "help_message": "Expected mount_target is a valid IP or DNS name with optional :/path ",
            "default_mount_options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
        },
        "fsx_lustre": {
            "help_message": "Expected mount_target is a valid FSx Lustre Filesystem ID (e.g fs-abcde123)",
            "default_mount_options": "defaults,noatime,flock,_netdev",
        },
        "fsx_ontap": {
            "help_message": "Expected mount_target is a valid FSx for NetApp Ontap Volume ID (e.g fsvol-abcde123)",
            "default_mount_options": "defaults,noatime,_netdev",
        },
        "fsx_openzfs": {
            "help_message": "Expected mount_target is a valid Fsx for OpenZFS Filesystem ID (e.g fs-abcde123)",
            "default_mount_options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
        },
        "s3": {
            "help_message": "Expected mount_target is a valid S3 bucket name",
            "default_mount_options": "--read-only",
        },
    }

    if provider not in _providers.keys():
        print_output(
            message=f"Provider selected is not part of {_providers.keys()}", error=True
        )

    if not mount_path.startswith("/"):
        print_output(message=f"Mount path must start with /", error=True)

    # s3-mountpoint expects just the bucket name
    if provider == "s3" and mount_target.startswith("s3://"):
        mount_target = mount_target.replace("s3://", "")

    if mount_options is None:
        mount_options = _providers[provider]["default_mount_options"]
        print_output(
            message=f"Mount options not specified. Using default: {mount_options}"
        )

    if not re.match(_MOUNT_TARGET_REGEX[provider], mount_target):
        print_output(
            message=f"Selected mount_target {mount_target} is not valid for provider {provider}. {_providers[provider]['help_message']}. Expected Regex: {_MOUNT_TARGET_REGEX[provider]}",
            error=True,
        )

    # mount_drive_letter is opt-in and only meaningful for fsx_ontap (the only
    # multi-protocol provider with a CIFS/SMB endpoint). Normalize "z" / "Z" / "Z:" -> "Z:".
    if mount_drive_letter:
        if provider != "fsx_ontap":
            print_output(
                message="--mount-drive-letter is only supported for provider fsx_ontap",
                error=True,
            )
        _drive = mount_drive_letter.rstrip(":").upper()
        if not re.match(r"^[A-Z]$", _drive):
            print_output(
                message="--mount-drive-letter must be a single letter A-Z",
                error=True,
            )
        mount_drive_letter = f"{_drive}:"

    if cifs_share_name:
        if provider != "fsx_ontap":
            print_output(
                message="--cifs-share-name is only supported for provider fsx_ontap",
                error=True,
            )
        if "\\" in cifs_share_name or "/" in cifs_share_name or Validators.is_string_length_greater_than(cifs_share_name, 80):
            print_output(
                message="--cifs-share-name must be a valid CIFS share name (no slashes, 80 chars max)",
                error=True,
            )

    # For EDH-created shares the controller auto-publishes cifs_share_name, so a drive
    # letter alone is sufficient. Only warn when a share name is given without a letter.
    if cifs_share_name and not mount_drive_letter:
        print_output(
            message="Note: --cifs-share-name has no effect without --mount-drive-letter; set a drive letter to enable Windows auto-mount."
        )

    # Reminder: All SSM keys are stored as str
    _ssm_keys = {
        f"/configuration/FileSystems/{filesystem_name}/provider": str(provider),
        f"/configuration/FileSystems/{filesystem_name}/mount_path": str(mount_path),
        f"/configuration/FileSystems/{filesystem_name}/mount_target": str(mount_target),
        f"/configuration/FileSystems/{filesystem_name}/enabled": str(enabled).lower(),
        f"/configuration/FileSystems/{filesystem_name}/on_mount_failure": str(
            on_mount_failure
        ),
        f"/configuration/FileSystems/{filesystem_name}/mount_options": str(
            mount_options
        ),
    }

    # Sparse: only written when the admin opted in. smb_dns is NOT set here -- it is
    # resolved and published by the controller (from the FSx API) at mount time.
    if mount_drive_letter:
        _ssm_keys[
            f"/configuration/FileSystems/{filesystem_name}/mount_drive_letter"
        ] = str(mount_drive_letter)
    if cifs_share_name:
        _ssm_keys[
            f"/configuration/FileSystems/{filesystem_name}/cifs_share_name"
        ] = str(cifs_share_name)
    if force is False:
        print_output(_ssm_keys, output="json")
        if (
            confirm(
                prompt="Do you want to create this new filesystem (add --force to skip this confirmation) ?"
            )
            is False
        ):
            print_output(message="Exiting", error=True)

    # proceed to actual filesystem creation
    for key, value in _ssm_keys.items():
        ctx.meta["echo"] = True
        ctx.invoke(config_set, key=key, value=value, called_from="filesystems")


@filesystems.command()
@click.option(
    "-n",
    "--filesystem-name",
    type=str,
    required=True,
    help="Specify a top level FileSystem UUID key (e.g: apps, data ...)",
)
@click.option(
    "-k",
    "--key",
    type=click.Choice(["mount_options", "enabled", "mount_path", "mount_target", "mount_drive_letter", "cifs_share_name", "svm_netbios_name", "svm_organizational_unit", "svm_file_system_administrators_group"]),
    help="You can only update mount_options, enabled, mount_path, mount_target, mount_drive_letter, cifs_share_name, svm_netbios_name, svm_organizational_unit or svm_file_system_administrators_group key for an existing filesystem.",
    required=True,
)
@click.option("-v", "--value", help="New value", required=True)
@click.option(
    "-p",
    "--provider",
    type=click.Choice(["efs", "nfs", "fsx_lustre", "fsx_ontap", "fsx_openzfs", "s3"]),
    help="Filesystem provider type",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    type=bool,
    help="Force update",
)
@click.pass_context
def update(ctx, filesystem_name, key, value, provider, force):
    """Change one field of an existing filesystem."""
    if filesystem_name in ["apps", "data"]:
        if force is False:
            print_output(
                message="Updating /data or /apps reserved filesystems are not recommended. Pass --force to ignore this error, but be advised this could break provisioning of your new SOCA nodes",
                error=True,
            )

    if key == "mount_path" and not value.startswith("/"):
        print_output(message="Mount path must start with /", error=True)

    if key == "enabled" and value.lower() not in ["true", "false"]:
        print_output(message="Enabled must be true or false", error=True)

    # mount_drive_letter: single letter A-Z, normalized to "Z:". Honored only for
    # fsx_ontap filesystems on Windows VDIs (ignored by other providers).
    if key == "mount_drive_letter":
        _drive = value.rstrip(":").upper()
        if not re.match(r"^[A-Z]$", _drive):
            print_output(
                message="mount_drive_letter must be a single letter A-Z",
                error=True,
            )
        value = f"{_drive}:"

    # cifs_share_name: admin-owned CIFS/SMB share name. Honored only for fsx_ontap on Windows VDIs.
    if key == "cifs_share_name":
        if "\\" in value or "/" in value or Validators.is_string_length_greater_than(value, 80):
            print_output(
                message="cifs_share_name must be a valid CIFS share name (no slashes, 80 chars max)",
                error=True,
            )

    # svm_* keys: the SVM's AD domain join parameters, written at install time
    # and read by the controller bootstrap. Editable so a failed join can be
    # corrected without a reinstall; a change takes effect on the next join.
    if key == "svm_netbios_name":
        if not re.match(r"^[A-Za-z0-9-]{1,15}$", value):
            print_output(
                message="svm_netbios_name must be 1-15 characters, letters, digits or hyphen",
                error=True,
            )
        value = value.upper()

    if key == "svm_organizational_unit":
        if not re.match(r"^(OU|CN)=", value, re.IGNORECASE):
            print_output(
                message="svm_organizational_unit must be a distinguished name starting with OU= or CN=",
                error=True,
            )

    if key == "svm_file_system_administrators_group":
        if Validators.is_string_length_greater_than(value, 256) or not value.strip():
            print_output(
                message="svm_file_system_administrators_group must be a non-empty AD group name, 256 chars max",
                error=True,
            )

    if key == "mount_target":
        if provider is None:
            print_output(
                message="You must specify the filesystem provider when updating the mount_target. Pass --provider or -p",
                error=True,
            )
        else:
            if not re.match(_MOUNT_TARGET_REGEX[provider], value):
                print_output(
                    message=f"Selected mount_target value {value} for {filesystem_name} is not valid for provider {provider}. Expected Regex: {_MOUNT_TARGET_REGEX[provider]}",
                    error=True,
                )

    # config_key_exists returns SocaConfig's own success flag. The previous check
    # compared `ctx.invoke(get, ...) is False`, and this module's get() returns
    # None on every path, so it never fired -- an update against a misspelled
    # name wrote a key under it and invented a filesystem. It also printed the
    # whole filesystem tree as a side effect of every update.
    if not ctx.invoke(
        config_key_exists, key=f"/configuration/FileSystems/{filesystem_name}/"
    ):
        print_output(message=f"Filesystem {filesystem_name} does not exist", error=True)
    else:
        ctx.meta["echo"] = True
        ctx.invoke(
            config_set,
            key=f"/configuration/FileSystems/{filesystem_name}/{key}",
            value=value,
            called_from="filesystems",
        )


def _apply_group_targets(cluster_id: str, node_types: tuple, instance_ids: tuple):
    """
    Running instances of this cluster that apply may target, keyed by node type.

    Returns (groups, skipped). A node is skipped, with the reason recorded, when
    the SSM agent cannot be reached or the platform is not Linux -- the rendered
    artifact is a bash script, and Windows drive mapping is a different template
    entirely.
    """
    _filters = [
        {"Name": "tag:edh:ClusterId", "Values": [cluster_id]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ]
    if not instance_ids:
        # sorted() rather than list(): SocaCastEngine.cast_as(list) routes a
        # non-list through ast.literal_eval, which rejects a real tuple
        # ("malformed node or string"), so the prescribed cast cannot express
        # this conversion. Sorting also makes the filter deterministic.
        _filters.append({"Name": "tag:edh:NodeType", "Values": sorted(node_types)})

    _described = describe_instances_paginate(filters=_filters)
    if _described.get("success") is False:
        print_output(message=_described.get("message"), error=True)

    _candidates = {}
    for _instance in _described.get("message", []):
        _iid = _instance.get("InstanceId")
        _tags = {_t["Key"]: _t.get("Value") for _t in _instance.get("Tags", [])}
        _candidates[_iid] = _tags.get("edh:NodeType")

    _skipped = {}
    if instance_ids:
        for _iid in instance_ids:
            if _iid not in _candidates:
                _skipped[_iid] = (
                    f"not a running instance tagged edh:ClusterId={cluster_id}"
                )
        _candidates = {
            _iid: _nt for _iid, _nt in _candidates.items() if _iid in instance_ids
        }

    if not _candidates:
        return {}, _skipped

    _platforms = describe_instance_platforms(instance_ids=sorted(_candidates))
    if _platforms.get("success") is False:
        print_output(message=_platforms.get("message"), error=True)
    _platforms = _platforms.get("message")

    _groups = {}
    for _iid, _node_type in sorted(_candidates.items()):
        _info = _platforms.get(_iid, {})
        if _info.get("ping_status") != "Online":
            _skipped[_iid] = f"SSM agent {_info.get('ping_status', 'Unknown')}"
            continue
        if _info.get("platform_type") != "Linux":
            _skipped[_iid] = f"platform {_info.get('platform_type', 'Unknown')}"
            continue
        # An untagged node cannot be rendered for: /job/NodeType selects whether
        # the ONTAP first-setup function is even DEFINED, while the call site
        # gates on the node's own EDH_NODE_TYPE -- guessing wrong yields a
        # "command not found" partway through a mount.
        if _node_type not in _FILESYSTEM_NODE_TYPES:
            _skipped[_iid] = f"edh:NodeType={_node_type or 'unset'}"
            continue
        _groups.setdefault(_node_type, []).append(_iid)

    return _groups, _skipped


def _apply_render(soca_parameters: dict, node_type: str, base_os: str) -> str:
    """Render filesystems_automount.sh for one node type and stage it on S3."""
    _cluster_id = soca_parameters.get("/configuration/ClusterId")
    _bucket = soca_parameters.get("/configuration/S3Bucket")
    _key = f"{_cluster_id}/{_APPLY_S3_PREFIX}/{node_type}/filesystems_automount.sh"

    # .copy() rather than dict(): this is a copy idiom, not a type conversion.
    # SocaJinja2Generator.to_s3(autocast_values=True) calls
    # SocaCastEngine.autocast(), whose body does self._data.clear() then
    # update(), so handing it the caller's own dict would let it rewrite the
    # keys of a dict this loop reuses once per node type.
    _variables = soca_parameters.copy()
    _variables["/job/NodeType"] = node_type
    _variables["/job/BaseOS"] = base_os
    _variables["/job/BootstrapPath"] = (
        f"/apps/edh/{_cluster_id}/shared/logs/bootstrap/{node_type}"
    )
    # Suppresses the one-time ONTAP SVM setup. See mount_fsx_ontap.sh.j2.
    _variables["/job/FilesystemsApply"] = True

    _rendered = SocaJinja2Generator(
        get_template="templates/linux/filesystems_automount.sh.j2",
        template_dirs=[f"/opt/edh/{_cluster_id}/cluster_node_bootstrap/"],
        variables=_variables,
    ).to_s3(bucket_name=_bucket, key=_key, autocast_values=True)

    if _rendered.get("success") is False:
        print_output(
            message=f"Unable to render filesystems_automount.sh for {node_type}: {_rendered.get('message')}",
            error=True,
        )
    return _key


def _apply_commands(bucket: str, key: str, region: str) -> list:
    """
    The shell AWS-RunShellScript runs on each target.

    The download is guarded because mktemp creates the file before the copy
    runs: a failed copy leaves it empty, bash exits 0 on an empty script, and
    the node would report exit=0 having mounted nothing. Both the copy's exit
    status and a zero-byte result are refused so a script that never arrived
    is reported as a failure rather than as a successful no-op.
    """
    return [
        "set -o pipefail",
        '_EDH_APPLY=$(mktemp /tmp/edh_filesystems_apply.XXXXXX.sh)',
        'trap \'rm -f "${_EDH_APPLY}"\' EXIT',
        f'if ! aws s3 cp "s3://{bucket}/{key}" "${{_EDH_APPLY}}" --region {region} --only-show-errors; then',
        f'  echo "unable to download s3://{bucket}/{key}" >&2',
        "  exit 1",
        "fi",
        'if [[ ! -s "${_EDH_APPLY}" ]]; then',
        f'  echo "downloaded s3://{bucket}/{key} is empty" >&2',
        "  exit 1",
        "fi",
        '/bin/bash "${_EDH_APPLY}"',
        "_EDH_APPLY_RC=$?",
        'echo "filesystems_automount exit=${_EDH_APPLY_RC}"',
        "findmnt -rn -o TARGET,SOURCE,FSTYPE -t nfs,nfs4,lustre,fuse.mount-s3 || true",
        "exit ${_EDH_APPLY_RC}",
    ]


def _apply_node_result(node: dict) -> dict:
    """
    One node's line in the report.

    The mount script logs the entire FileSystems tree at INFO on stderr, so a
    raw invocation record is tens of kilobytes per node that say nothing when
    the mount worked. stdout carries the exit code and the resulting mount
    table, which is the whole result on success; stderr is kept only when the
    node did not succeed, because that is the only time it explains anything.

    Both are split into lines so a serialized report renders one line per
    line rather than one string full of escapes.
    """
    _result = {
        "instance_id": node.get("instance_id"),
        "status": node.get("status"),
        "stdout": (node.get("stdout") or "").splitlines()[-15:],
    }
    if node.get("status") != "Success":
        _result["stderr"] = (node.get("stderr") or "").splitlines()[-25:]
    return _result


@filesystems.command()
@click.option(
    "--node-types",
    type=click.Choice(_FILESYSTEM_NODE_TYPES),
    multiple=True,
    default=_ALWAYSON_NODE_TYPES,
    help="Node types to apply to. Defaults to the always-on types; every other type reads the FileSystems tree when it launches.",
)
@click.option(
    "--instance-ids",
    type=str,
    help="Apply to these instances only, separated by , or +. Overrides --node-types, but an instance outside this cluster is still refused.",
)
@click.option(
    "--base-os",
    type=click.Choice(SocaLinuxBaseOS),
    default=None,
    help="Base OS to render for. Defaults to /configuration/BaseOS. Set it when a target's AMI OS differs from the controller's, since package manager and Lustre client selection are rendered from it.",
)
@click.option(
    "--timeout",
    type=int,
    default=1800,
    help="Seconds to wait for each node to finish. A filesystem that cannot be reached costs roughly 11 minutes per node before the mount retries are exhausted.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Render and report the targets, run nothing.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    type=bool,
    help="Skip the confirmation prompt",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def apply(node_types, instance_ids, base_os, timeout, dry_run, force, output):
    """
    Re-run the filesystem mounts on running nodes.

    `set` and `update` write SSM only, and every path that mounts a filesystem
    is launch-time, so an always-on node keeps its fstab until it is replaced.
    This renders the CURRENT template -- not the copy a node rendered at boot --
    and runs it, so a change to the mount code reaches live nodes too.
    """
    if not is_controller_instance():
        print_output(
            message="This command can only be executed from the EDH controller host",
            error=True,
        )

    _soca_parameters = SocaConfig(key="/").get_value(return_as=dict).get("message")
    if not _soca_parameters:
        print_output(message="Unable to query SSM for this EDH environment", error=True)

    _cluster_id = _soca_parameters.get("/configuration/ClusterId")
    _bucket = _soca_parameters.get("/configuration/S3Bucket")
    _region = _soca_parameters.get("/configuration/Region")
    for _label, _value in (
        ("/configuration/ClusterId", _cluster_id),
        ("/configuration/S3Bucket", _bucket),
        ("/configuration/Region", _region),
    ):
        if not _value:
            print_output(message=f"{_label} is not set on SSM", error=True)

    if base_os is None:
        base_os = _soca_parameters.get("/configuration/BaseOS")
        if not base_os:
            print_output(
                message="No --base-os given and /configuration/BaseOS is not set; cannot render the mount script",
                error=True,
            )

    # tuple() over a generator is collection construction, not a type
    # conversion: there is no source value of another type to cast, and
    # SocaCastEngine takes one object rather than an iterator.
    #
    # Each token is stripped because the separators are routinely typed with a
    # space after them. `--instance-ids "i-a, i-b"` yielded " i-b", which
    # matches no InstanceId, so _apply_group_targets reported the operator's
    # second target as "not a running instance tagged edh:ClusterId=..." and
    # applied to the first one only. An empty token is dropped rather than
    # carried into the describe call.
    _instance_ids = tuple(
        _stripped
        for _part in (instance_ids or "").split(",")
        for _i in _part.split("+")
        if (_stripped := _i.strip())
    )

    _groups, _skipped = _apply_group_targets(
        cluster_id=_cluster_id, node_types=node_types, instance_ids=_instance_ids
    )

    if _skipped:
        for _iid, _reason in sorted(_skipped.items()):
            print_output(message=f"[skipped] {_iid}: {_reason}")

    if not _groups:
        print_output(
            message="No running Linux node of this cluster matched. Nothing to apply.",
            error=True,
        )

    _plan = {}
    for _node_type, _ids in sorted(_groups.items()):
        _plan[_node_type] = {
            "instances": _ids,
            "s3_key": _apply_render(
                soca_parameters=_soca_parameters,
                node_type=_node_type,
                base_os=base_os,
            ),
            "base_os": base_os,
        }

    # print_output's "text" mode click.echo()s the object, which for a nested
    # dict is a Python repr with literal \n in it. The plan and the per-node
    # results are both structured, so they are serialized either way.
    _fmt = output if output in ("json", "yaml") else "json"

    print_output(message=_plan, output=_fmt)

    if dry_run:
        print_output(message="--dry-run: rendered only, nothing was run.")
        return _plan

    if force is False:
        if (
            confirm(
                prompt="Mount the current FileSystems tree on these nodes (add --force to skip this confirmation) ?"
            )
            is False
        ):
            print_output(message="Exiting", error=True)

    # Hoisted out of the loop: timeout does not vary per node type, and
    # executionTimeout must be a list of str for AWS-RunShellScript.
    _execution_timeout = SocaCastEngine(timeout).cast_as(str)
    if _execution_timeout.success is False:
        print_output(
            message=f"Unable to use --timeout {timeout}: {_execution_timeout.message}",
            error=True,
        )

    _results = {}
    for _node_type, _detail in _plan.items():
        _run = execute_ssm_document(
            document_name="AWS-RunShellScript",
            parameters={
                "commands": _apply_commands(
                    bucket=_bucket, key=_detail["s3_key"], region=_region
                ),
                "executionTimeout": [_execution_timeout.message],
            },
            # TimeoutSeconds bounds DELIVERY, not the run; the waiter below is
            # what has to cover a slow mount.
            timeout=600,
            max_attempts=timeout,
            instance_ids=_detail["instances"],
        )
        if _run.get("success") is False:
            _results[_node_type] = {"error": _run.get("message")}
            continue
        _results[_node_type] = [
            _apply_node_result(_node) for _node in _run.get("message", [])
        ]

    print_output(message=_results, output=_fmt)

    _failed = [
        _r.get("instance_id")
        for _group in _results.values()
        if Validators.is_list(_group)
        for _r in _group
        if _r.get("status") != "Success"
    ]
    if _failed or any(Validators.is_dict(_g) for _g in _results.values()):
        print_output(
            message=f"filesystems apply did not succeed everywhere. Failed: {_failed or 'see errors above'}",
            error=True,
        )

    print_output(message="filesystems apply completed on all targeted nodes.")
    return _results
