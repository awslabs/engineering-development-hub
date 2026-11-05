# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

from troposphere.ec2 import Tag, TagSpecifications
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

# Resource types created AT LAUNCH by a LaunchTemplate, tagged via
# LaunchTemplateData.TagSpecifications. "spot-instances-request" is deliberately
# excluded: the controller role has no ec2:CreateTags on that resource type, so
# requesting it would fail the launch rather than no-op.
LAUNCH_TEMPLATE_DATA_RESOURCE_TYPES: tuple = (
    "instance",
    "volume",
    "network-interface",
)

# The LaunchTemplate resource itself. Tagged via the top-level
# LaunchTemplate.TagSpecifications, which is a sibling of LaunchTemplateData --
# LaunchTemplateData.TagSpecifications only tags what the template launches.
LAUNCH_TEMPLATE_RESOURCE_TYPE: str = "launch-template"


def build_tag_specifications(
    base_tags: dict, resource_types: tuple = LAUNCH_TEMPLATE_DATA_RESOURCE_TYPES
) -> SocaResponse:
    """
    Build one troposphere TagSpecifications entry per resource type from a single
    base tag mapping, so every launch-created resource carries the same tags.
    """
    if not Validators.is_dict_not_empty(base_tags):
        return SocaError.GENERIC_ERROR(
            helper=f"build_tag_specifications requires a non-empty dict, received {type(base_tags)}"
        )

    if not resource_types:
        return SocaError.GENERIC_ERROR(
            helper="build_tag_specifications requires at least one resource type"
        )

    try:
        _tags = [Tag(Key=_k, Value=_v) for _k, _v in base_tags.items()]
        _specifications = [
            TagSpecifications(ResourceType=_resource_type, Tags=_tags)
            for _resource_type in resource_types
        ]
        logger.debug(
            f"Built TagSpecifications for {resource_types} with {len(_tags)} tags"
        )
        return SocaResponse(success=True, message=_specifications)
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to build TagSpecifications for {resource_types} due to {e}"
        )


def build_launch_template_tag_specifications(base_tags: dict) -> SocaResponse:
    """
    Build the TagSpecifications for the LaunchTemplate resource itself.
    """
    return build_tag_specifications(
        base_tags=base_tags, resource_types=(LAUNCH_TEMPLATE_RESOURCE_TYPE,)
    )


def build_dry_run_tag_specifications(
    custom_tags: dict = None, node_type: str = None
) -> SocaResponse:
    """
    Build plain-dict TagSpecifications for a RunInstances DryRun probe.

    The probe must carry the same mandatory tags a real launch does. A tag-policy
    SCP conditioned on aws:RequestTag denies an untagged DryRun with
    UnauthorizedOperation, which otherwise surfaces as a bogus capacity failure
    even though the real launch (tagged via the LaunchTemplate) would succeed.

    Returns plain dicts rather than troposphere objects: the probe calls the EC2
    API directly, it does not render CloudFormation.
    """
    _tags: dict = {}

    _cluster_id = (
        SocaConfig(key="/configuration/ClusterId")
        .get_value(return_as=str)
        .get("message")
    )
    if _cluster_id:
        _cast_cluster_id = SocaCastEngine(data=_cluster_id).cast_as(str)
        if _cast_cluster_id.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to cast /configuration/ClusterId {_cluster_id} as str"
            )
        _tags["edh:ClusterId"] = _cast_cluster_id.get("message")
    else:
        logger.warning(
            "Unable to resolve /configuration/ClusterId for the DryRun probe; "
            "submitting the probe without edh:ClusterId"
        )

    if node_type:
        _cast_node_type = SocaCastEngine(data=node_type).cast_as(str)
        if _cast_node_type.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to cast node_type {node_type} as str"
            )
        _tags["edh:NodeType"] = _cast_node_type.get("message")

    # Snapshot the mandatory keys before merging custom tags. A custom tag keyed
    # edh:ClusterId or edh:NodeType would otherwise silently overwrite the value
    # the real launch submits, so the probe would validate a tag set that is not
    # the one being validated for. The launch builders skip colliding keys with a
    # warning; do the same here so probe and launch cannot disagree.
    _mandatory_keys = frozenset(_tags.keys())

    for _tag in (custom_tags or {}).values():
        if not Validators.is_dict(_tag) or not _tag.get("Key"):
            logger.warning(f"{_tag} is not a valid custom tag entry, skipping")
            continue
        if _tag.get("Enabled"):
            if _tag["Key"] in _mandatory_keys:
                logger.warning(
                    f"Specified custom tags {_tag.get('Key')} is already defined in tag list, skipping ..."
                )
                continue
            _tags[_tag["Key"]] = _tag.get("Value", "")
        else:
            logger.warning(f"{_tag} does not have Enabled key or Enabled is False")

    if not _tags:
        logger.warning("DryRun probe has no tags to submit")
        return SocaResponse(success=True, message=[])

    _rendered = [{"Key": _k, "Value": _v} for _k, _v in _tags.items()]
    # volume is included because the probe also passes BlockDeviceMappings and a
    # tag policy may gate volume creation independently of the instance.
    return SocaResponse(
        success=True,
        message=[
            {"ResourceType": "instance", "Tags": _rendered},
            {"ResourceType": "volume", "Tags": _rendered},
        ],
    )
