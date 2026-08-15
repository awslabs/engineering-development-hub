# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resolve a VDI software stack into the per-stack launch inputs the
PoolController needs to render a launch template.

Only the per-stack bits live here -- ami_id (alias-resolved), base_os,
root_size. These are denormalized into the pool config DDB (`launch_spec` on
the META item) at PUT time so the reconciler stays DB-free, reusing the SAME
AMI-alias resolution the VDI launch path uses. Cluster-wide inputs (security
group, instance profile, subnets, volume type, SSH key, region) are
cluster-stable and identical across pools, so the reconciler reads those from
SSM /configuration/* directly rather than duplicating them per stack.

Should be re-run on stack edit so launch_spec does not go stale when a stack's
AMI changes (stack-edit re-resolve hook -- follow-on).

Plain-data returns (no SocaResponse/SocaError); the endpoint wraps errors.
"""

import logging
from typing import Any, Dict, Optional, Tuple

from utils.aws.ssm_helper import get_ami_id_from_alias

logger = logging.getLogger("soca_logger")


def resolve_launch_spec(stack) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Resolve a SoftwareStacks row into {ami_id, base_os, root_size}.

    `stack` is a SoftwareStacks ORM row. Returns (spec, None) on success or
    (None, error) on failure. AMI aliases (/aws/service/...) are resolved to a
    concrete ami-id, mirroring create_virtual_desktop.
    """
    _ami = getattr(stack, "ami_id", None)
    if not _ami:
        return None, "software stack has no ami_id"

    if str(_ami).startswith("/aws/service/"):
        _resolved = get_ami_id_from_alias(alias_name=_ami)
        if _resolved.get("success") is not True:
            return None, f"AMI alias resolution failed: {_resolved.get('message')}"
        _ami = _resolved.get("message")

    # Resolve AMI root device name via describe_images (established pattern:
    # dcv_cloudformation_builder, target_nodes_cloudformation_builder, ec2_helper).
    _root_device_name = None
    try:
        import utils.aws.boto3_wrapper as utils_boto3

        _ec2 = utils_boto3.get_boto(service_name="ec2").message
        _img = _ec2.describe_images(ImageIds=[_ami])
        _root_device_name = (_img.get("Images") or [{}])[0].get("RootDeviceName")
    except Exception as _e:
        logger.warning("vdi_pool_resolve: describe_images(%s) failed: %s", _ami, _e)

    return (
        {
            "ami_id": _ami,
            "base_os": getattr(stack, "ami_base_os", None),
            "root_size": getattr(stack, "ami_root_disk_size", None),
            "root_device_name": _root_device_name,
        },
        None,
    )
