# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Web-tier render of the session-less VDI pool bootstrap (3c-1).

Produces the COMPLETE launch_spec the reconciler needs to build a per-stack
launch template:
  * per-stack AMI (alias-resolved), base_os, root_size  (via vdi_pool_resolve)
  * cluster-wide LT inputs: instance profile, SG, volume type, IMDS tokens,
    SSH key, subnets  (from the SocaConfig "/" dump)
  * base64 session-less user_data

Reuses render_bootstrap_bundle -- which caches the BIG bootstrap per
stack-config and reuses it across sessions -- with a GENERIC context (no
Session* values, /dcv/PoolMember=true) written to a STACK-scoped S3 prefix.
Mirrors the create_virtual_desktop render path so a pool member boots, installs
DCV, and registers with the broker WITHOUT creating a session (high-scale
already skips auto-session creation).

Run at PUT (and on stack edit) so launch_spec stays fresh. Plain-data returns.
"""

import base64
import gzip
import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

import utils.aws.boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.jinjanizer import SocaJinja2Generator

from helpers import vdi_pool_resolve

logger = logging.getLogger("soca_logger")


def build_launch_spec(stack) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Resolve + render the full launch_spec for a VDI software stack.

    Returns (launch_spec, None) or (None, error). Never raises.
    """
    # 1. Per-stack AMI / base_os / root_size (reuses VDI alias resolution).
    _spec, _err = vdi_pool_resolve.resolve_launch_spec(stack)
    if _err:
        return None, _err

    # 2. Full config dump for cluster-wide context + LT inputs.
    _params = SocaConfig(key="/").get_value(return_as=dict).get("message")
    if not _params:
        return None, "unable to query SSM for cluster configuration"

    _cluster = _params.get("/configuration/ClusterId")
    _bucket = _params.get("/configuration/S3Bucket")
    _base_os = str(_spec.get("base_os") or "").lower()
    _os_family = (getattr(stack, "os_family", None) or "").lower()
    _is_windows = _os_family == "windows" or "windows" in _base_os

    # 3. Generic, session-less DCV/pool context.
    soca_parameters = dict(_params)
    soca_parameters["/job/NodeType"] = "dcv_node"
    soca_parameters["/dcv/SessionOwner"] = ""
    soca_parameters["/dcv/SessionId"] = ""
    soca_parameters["/dcv/SessionName"] = ""
    soca_parameters["/dcv/SessionType"] = "console"
    soca_parameters["/dcv/PoolMember"] = "true"
    # So the pool member can publish the attested pool-ready event to the relay.
    soca_parameters["/dcv/SessionEventsQueueUrl"] = _params.get(
        "/configuration/DcvSessionEventsQueueUrl", ""
    )
    soca_parameters["/job/BaseOS"] = _spec.get("base_os")
    soca_parameters["/configuration/BaseOS"] = _spec.get("base_os")

    if (
        str(SocaConfig(key="/dcv/high_scale_enabled").get_value().get("message", "false")).lower()
        == "true"
    ):
        _nlb = SocaConfig(key="/dcv/backend_nlb_dns").get_value().get("message", "")
        soca_parameters["/configuration/DcvHighScale"] = "true"
        soca_parameters["/dcv/BrokerHost"] = _nlb
        soca_parameters["/dcv/BrokerAgentPort"] = (
            SocaConfig(key="/dcv/broker/agent_port").get_value().get("message", "47100")
        )
        soca_parameters["/dcv/AuthTokenVerifier"] = (
            f"https://{_nlb}:8445/agent/validate-authentication-token"
        )

    # 4. Stack-scoped (NOT per-session) bootstrap prefix.
    _stack_prefix = (
        f"{_cluster}/config/do_not_delete/bootstrap/dcv_pool/{stack.id}"
    )
    soca_parameters["/job/BootstrapPath"] = (
        f"/apps/edh/{_cluster}/shared/logs/bootstrap/dcv_pool/{stack.id}"
    )
    soca_parameters["/job/BootstrapScriptsS3Location"] = (
        f"s3://{_bucket}/{_stack_prefix}/"
    )

    # 5. Render the bundle (reuses cached big bootstrap) + the user_data stub.
    from utils.bootstrap_render import render_bootstrap_bundle

    if _is_windows:
        _big = [
            "windows_virtual_desktop/02_setup.ps1",
            "windows_virtual_desktop/03_setup_post_reboot.ps1",
        ]
        _env_tpl = "windows_virtual_desktop/00_session_env.ps1"
        _env_file = "00_session_env.ps1"
        _ud_tpl = "windows_virtual_desktop/01_user_data.ps1.j2"
    else:
        _big = [
            "templates/linux/system_packages/install_required_packages.sh",
            "templates/linux/filesystems_automount.sh",
            "compute_node/02_setup.sh",
            "compute_node/03_setup_post_reboot.sh",
            "compute_node/04_setup_user_customization.sh",
        ]
        _env_tpl = "templates/linux/00_session_env.sh"
        _env_file = "00_session_env.sh"
        _ud_tpl = "compute_node/01_user_data.sh.j2"

    _root = f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID')}/cluster_node_bootstrap/"
    try:
        _render = render_bootstrap_bundle(
            soca_parameters=soca_parameters,
            bootstrap_root=_root,
            s3_client=utils_boto3.get_boto(service_name="s3").message,
            bucket=_bucket,
            cluster_id=_cluster,
            per_session_prefix=_stack_prefix,
            cache_prefix=f"{_cluster}/bootstrap/cache",
            big_templates=_big,
            session_env_template=_env_tpl,
            session_env_filename=_env_file,
            cache_bypass=False,
        )
    except Exception as exc:  # render failure must not 500 the API
        logger.exception(
            "pool bootstrap render failed for stack=%s", getattr(stack, "id", None)
        )
        return None, f"bootstrap render failed: {exc}"

    soca_parameters["/job/BootstrapScriptsS3Location"] = _render.bootstrap_scripts_s3
    soca_parameters["/job/SessionEnvS3Location"] = _render.session_env_s3

    _gen = SocaJinja2Generator(
        get_template=_ud_tpl,
        template_dirs=[_root],
        variables=soca_parameters,
    ).to_stdout(autocast_values=True)
    if _gen.get("success") is False:
        return None, f"user_data render failed: {_gen.get('message')}"

    # EC2 LaunchTemplate UserData is capped at 16 KB measured on the
    # base64-DECODED bytes. The rendered Linux stub pulls in common.j2
    # (logging + file_download + aws_cli retry wrapper + IMDS + package mgmt)
    # and runs ~26 KB raw, which overflows the cap -- CreateLaunchTemplate
    # then fails with InvalidUserData.Malformed and no pool ASG is ever
    # created. gzip-compress for Linux (cloud-init auto-decompresses gzipped
    # UserData, ~26 KB -> ~7 KB); Windows EC2Launch does NOT auto-decompress
    # gzip, so leave Windows raw. Same OS split as create_virtual_desktop.py.
    _rendered_ud = _gen.get("message").encode("utf-8")
    if _is_windows:
        _bootstrap_user_data = base64.b64encode(_rendered_ud).decode("utf-8")
    else:
        _bootstrap_user_data = base64.b64encode(
            gzip.compress(_rendered_ud)
        ).decode("utf-8")

    # 5b. Stamp the spec with a content hash of its render inputs: the bundle
    # cache key (templates .j2 tree + cluster-relevant config) plus the
    # per-stack AMI/base_os/root_size the cache key does not see. The
    # convergence sweep and stack-edit hook compare this stamp to the stored
    # one to decide whether a re-render is needed; put_pool_config uses it as a
    # compare-and-set guard so racing writers cannot double-apply.
    from utils.bootstrap_cache import compute_stack_cache_key

    try:
        _bundle_key = compute_stack_cache_key(
            soca_parameters=soca_parameters, bootstrap_root=_root
        )
    except Exception as exc:
        logger.exception(
            "spec_input_hash bundle-key compute failed for stack=%s",
            getattr(stack, "id", None),
        )
        return None, f"spec input-hash computation failed: {exc}"

    _spec_input_hash = hashlib.sha256(
        json.dumps(
            {
                "bundle_key": _bundle_key,
                "stack": {
                    "ami_id": _spec.get("ami_id"),
                    "base_os": _spec.get("base_os"),
                    "root_size": _spec.get("root_size"),
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    # 6. Cluster-wide LT inputs + subnets.
    _subnets = (
        SocaCastEngine(_params.get("/configuration/PrivateSubnets"))
        .cast_as(expected_type=list)
        .get("message")
        or []
    )

    _spec.update(
        {
            "instance_profile_arn": _params.get(
                "/configuration/VdiNodeInstanceProfileArn"
            ),
            "security_group_id": _params.get(
                "/configuration/VdiNodeSecurityGroup"
            ),
            "volume_type": _params.get("/configuration/DefaultVolumeType") or "gp3",
            "metadata_http_tokens": _params.get("/configuration/MetadataHttpTokens")
            or "required",
            "ssh_key_name": _params.get("/configuration/SSHKeyPair"),
            "subnet_ids": _subnets,
            "bootstrap_user_data": _bootstrap_user_data,
            "bootstrap_scripts_s3": _render.bootstrap_scripts_s3,
            "session_env_s3": _render.session_env_s3,
            "os_family": "windows" if _is_windows else "linux",
            "spec_input_hash": _spec_input_hash,
        }
    )
    return _spec, None
