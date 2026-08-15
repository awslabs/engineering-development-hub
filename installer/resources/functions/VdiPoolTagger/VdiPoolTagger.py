# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0   

"""
VdiPoolTagger -- cosmetic EC2 Name/role tagging for VDI pool members.

Purpose
-------
Make it obvious in the EC2 console whether a VDI-pool instance is a transient
warm-pool member or a promoted, live (hot) desktop. The VDI pool ASGs all
launch with the same propagated ``Name`` tag (the ASG name), so warm and hot
instances are otherwise indistinguishable.

This Lambda is event-driven (EventBridge, source ``aws.autoscaling``) and is
deliberately separate from VdiPoolReconciler so cosmetic tagging never adds
latency or load to the reconcile loop.

Naming scheme (``<asg-name>`` = the standard pool ASG name):
  * in / entering the warm pool   -> Name = ``<asg-name>-warming``, edh:pool_role=warm
  * promoted to live service      -> Name = ``<asg-name>-hot``,     edh:pool_role=hot

Only the cosmetic ``Name`` tag and the additive ``edh:pool_role`` tag are ever
written. The reconciler's discovery tags (edh:pool_id / edh:managed_by /
edh:instance_type / edh:stack_id) are NEVER touched, so pool membership lookups
are unaffected.

Triggers (EventBridge detail-types), both of which carry Origin/Destination for
warm-pool ASGs:
  * "EC2 Instance-launch Lifecycle Action"  -- fires early (Warmed:Pending:Wait)
  * "EC2 Instance Launch Successful"        -- fires on completion / promotion

Transition mapping (detail.Origin / detail.Destination):
  * Destination == "WarmPool"                              -> warming
  * Origin == "WarmPool" and Destination == "AutoScalingGroup" -> hot (promotion)
  * Destination == "AutoScalingGroup" (direct launch, no warm pool) -> hot

NOTE: this Lambda never calls complete_lifecycle_action -- it only reads the
event and tags. The existing provisioning lifecycle hook (completed by the
on-host agent / relay) is unaffected.
"""

import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_ec2 = boto3.client("ec2")

WARM_SUFFIX = "-warming"
HOT_SUFFIX = "-hot"
ROLE_TAG_KEY = "edh:pool_role"

# Only act on VDI pool ASGs. The EventBridge rule already filters by this
# prefix, but we re-check defensively so a mis-scoped rule can never rename
# non-pool instances.
_POOL_ASG_MARKER = "-vdipool-"


def _strip_role_suffix(name):
    """Return the base ASG name with any prior -warming/-hot suffix removed."""
    if not name:
        return ""
    for _sfx in (WARM_SUFFIX, HOT_SUFFIX):
        if name.endswith(_sfx):
            return name[: -len(_sfx)]
    return name


def _current_name_tag(instance_id):
    """Best-effort read of the instance's current Name tag (fallback base)."""
    try:
        _resp = _ec2.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [instance_id]},
                {"Name": "key", "Values": ["Name"]},
            ]
        )
        for _t in _resp.get("Tags", []):
            return _t.get("Value")
    except Exception as exc:  # pragma: no cover - best effort
        logger.warning("describe_tags failed for %s: %s", instance_id, exc)
    return None


def _apply_tags(instance_id, name, role):
    _ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "Name", "Value": name},
            {"Key": ROLE_TAG_KEY, "Value": role},
        ],
    )
    logger.info(
        "tagged %s Name=%s %s=%s", instance_id, name, ROLE_TAG_KEY, role
    )


def lambda_handler(event, context):
    _detail = event.get("detail") or {}
    _instance_id = _detail.get("EC2InstanceId")
    _asg_name = _detail.get("AutoScalingGroupName")
    _origin = _detail.get("Origin")
    _destination = _detail.get("Destination")

    if not _instance_id:
        logger.info(
            "no EC2InstanceId; ignoring detail-type=%s", event.get("detail-type")
        )
        return {"ok": True, "skipped": "no_instance"}

    # Defensive scope guard -- only ever rename VDI pool instances.
    if _asg_name and _POOL_ASG_MARKER not in _asg_name:
        logger.info("asg %s not a vdi pool; ignoring", _asg_name)
        return {"ok": True, "skipped": "not_pool_asg"}

    # Base = stable ASG name (preferred), else current Name with suffix stripped.
    _base = _strip_role_suffix(_asg_name) or _strip_role_suffix(
        _current_name_tag(_instance_id)
    )
    if not _base:
        logger.warning("could not resolve base name for %s; ignoring", _instance_id)
        return {"ok": True, "skipped": "no_base_name"}

    # Promotion out of the warm pool into live service -> hot.
    if _origin == "WarmPool" and _destination == "AutoScalingGroup":
        _name = f"{_base}{HOT_SUFFIX}"
        _apply_tags(_instance_id, _name, "hot")
        return {"ok": True, "instance": _instance_id, "role": "hot", "name": _name}

    # Anything entering / inside the warm pool -> warming.
    if _destination == "WarmPool":
        _name = f"{_base}{WARM_SUFFIX}"
        _apply_tags(_instance_id, _name, "warm")
        return {"ok": True, "instance": _instance_id, "role": "warm", "name": _name}

    # Direct launch straight into the ASG (no warm pool) -> hot.
    if _destination == "AutoScalingGroup":
        _name = f"{_base}{HOT_SUFFIX}"
        _apply_tags(_instance_id, _name, "hot")
        return {"ok": True, "instance": _instance_id, "role": "hot", "name": _name}

    logger.info(
        "unhandled origin=%s destination=%s for %s",
        _origin,
        _destination,
        _instance_id,
    )
    return {"ok": True, "skipped": "unhandled"}
