# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
VDI Pool reconciler -- declarative desired->actual for DCV VDI pools.

Pools are admin RUNTIME config (changes far more often than deploys), so the
pool AWS resources are managed here at runtime via boto3, not in CDK. CDK lays
down only the static scaffolding (this Lambda, its role, the DDB tables, the
EventBridge schedule).

Triggers (event["action"], default "reconcile"):
  * "reconcile"                 -- EventBridge schedule: drift-sweep all stacks
  * "reconcile" + "stack_id"    -- single-stack apply (fired on admin config change)
  * "teardown"                  -- delete ALL tag-managed pool resources (uninstall)

Discovery + cleanup are tag-based: every managed resource carries
  edh:ClusterId=<cluster>, edh:managed_by=VdiPoolReconciler,
  edh:pool_id=POOL#<stack_id>#<instance_type>.

PHASE 3a (this file): reads desired config, discovers actual tag-managed ASGs,
computes and LOGS the diff. It makes NO changes to AWS. The mutating steps are
added in later phases:
  * 3b -- ASG + warm-pool create/update/delete
  * 3c -- session-less launch-template render
  * 3d -- scheduled actions, alarms, teardown sweep
"""

import base64
import gzip
import hashlib
import json
import logging
import os
import ssl
import urllib.request
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ParamValidationError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")
CONFIG_TABLE = f"{CLUSTER_ID}-vdi-pool-config"
SUMMARY_TABLE = f"{CLUSTER_ID}-vdi-pool-summary"

MANAGED_TAG_KEY = "edh:managed_by"
MANAGED_TAG_VALUE = "VdiPoolReconciler"
CLUSTER_TAG_KEY = "edh:ClusterId"
POOL_ID_TAG_KEY = "edh:pool_id"

_ddb = boto3.resource("dynamodb")
_asg = boto3.client("autoscaling")
_ec2 = boto3.client("ec2")
_cw = boto3.client("cloudwatch")

METRIC_NS = "EDH/DCVHighScale"
SCHED_PREFIX = "vdipool-"
# Stale CLAIMED/RESERVED ledger rows older than this are reaped (the member
# left the pool at claim; the detached desktop is a normal VDI handled by the
# standard lifecycle). Generous hygiene window.
_REAP_ABANDON_SECONDS = 900
# A tombstoned (config-removed) pool ASG is deleted once it has drained to 0
# instances AND has been DRAINING longer than this grace window. The grace
# lets a quick remove->re-add reuse the same ASG instead of racing a delete.
_DRAIN_GRACE_SECONDS = 900
# Launch lifecycle hook timeout (instance launch -> announces readiness). MUST
# exceed the on-host pool-ready agent's DCV-readiness wait (900s) so a slow boot
# (e.g. GPU g6f DCV init) re-emits BEFORE the hook abandons -- otherwise warm
# resumes ABANDON-loop at the timeout (observed on g6f). Decoupled: agent 900s
# < hook 1200s, ~5 min slack for emit + relay + complete_lifecycle_action.
_PROVISIONING_HOOK_TIMEOUT_SECONDS = 1200
_DOW = {
    "mon": "MON",
    "tue": "TUE",
    "wed": "WED",
    "thu": "THU",
    "fri": "FRI",
    "sat": "SAT",
    "sun": "SUN",
}


def _pool_id(stack_id, instance_type):
    return f"POOL#{stack_id}#{instance_type}"


def _positive_int_or_none(*candidates):
    """First candidate that casts to a positive int, else None.

    Pool timeout overrides are optional and may be stored on either the
    per-entry TYPE# item or the stack-level META item, as DDB Decimal, str
    or int. A missing, empty, unparseable or non-positive value falls
    through to the next candidate so a malformed override degrades to the
    reconciler default instead of raising inside the reconcile loop or
    setting a nonsense timeout.
    """
    for _c in candidates:
        if _c is None or _c == "":
            continue
        try:
            _v = int(_c)
        except (TypeError, ValueError):
            continue
        if _v > 0:
            return _v
    return None


def _read_desired(stack_id=None):
    """Read desired pool state from the config table.

    Returns {pool_id: {stack_id, instance_type, hot_count, warm_count, ...,
    stack_meta}} for every enabled (stack, instance_type) entry. When
    stack_id is given, only that stack is read.
    """
    table = _ddb.Table(CONFIG_TABLE)
    desired = {}

    if stack_id is not None:
        from boto3.dynamodb.conditions import Key

        items = table.query(
            KeyConditionExpression=Key("pk").eq(f"STACK#{stack_id}")
        ).get("Items", [])
    else:
        # Drift sweep: scan the whole (small) config table.
        items = table.scan().get("Items", [])

    # Group items by stack: META holds stack-level flags, TYPE# holds entries.
    by_stack = {}
    for it in items:
        _pk = it.get("pk", "")
        by_stack.setdefault(_pk, {"meta": {}, "entries": []})
        if it.get("sk") == "META":
            by_stack[_pk]["meta"] = it
        elif str(it.get("sk", "")).startswith("TYPE#"):
            by_stack[_pk]["entries"].append(it)

    for _pk, grp in by_stack.items():
        _sid = grp["meta"].get("stack_id")
        _stack_enabled = bool(grp["meta"].get("enabled"))
        for _entry in grp["entries"]:
            _it = _entry["instance_type"]
            # active = stack enabled AND entry enabled. A configured-but-
            # inactive entry stays "desired" (so its ASG is kept) but PARKED
            # at 0/0/0; only entries removed from config entirely fall out of
            # `desired` and get tombstoned by the reconcile delete path.
            _entry_enabled = _entry.get("enabled", True)
            if isinstance(_entry_enabled, str):
                _entry_enabled = _entry_enabled.strip().lower() not in (
                    "false", "0", "no", "",
                )
            _active = _stack_enabled and bool(_entry_enabled)
            desired[_pool_id(_sid, _it)] = {
                "stack_id": _sid,
                "instance_type": _it,
                "active": _active,
                "hot_count": int(_entry.get("hot_count", 0)),
                "warm_count": int(_entry.get("warm_count", 0)),
                # Optional per-pool launch hook timeout override (seconds).
                # The admin API stores this on the META item (it is a
                # pool-level field in validate_pool_config, and
                # validate_pool_type_config never emits it), so read the
                # entry first for forward compatibility and fall back to
                # META. Reading only the entry made the override
                # unreachable and silently pinned every pool to
                # _PROVISIONING_HOOK_TIMEOUT_SECONDS. None -> that default.
                "provisioning_timeout_seconds": _positive_int_or_none(
                    _entry.get("provisioning_timeout_seconds"),
                    grp["meta"].get("provisioning_timeout_seconds"),
                ),
                # Optional per-pool connect-abandon override (seconds): how
                # long a CLAIMED/RESERVED ledger row may sit before the
                # reaper releases it. Same META-level storage as above.
                # None -> _REAP_ABANDON_SECONDS.
                "connect_abandon_timeout_seconds": _positive_int_or_none(
                    _entry.get("connect_abandon_timeout_seconds"),
                    grp["meta"].get("connect_abandon_timeout_seconds"),
                ),
                "on_demand_base_count": 0,
                "on_demand_percentage_above_base": 100,
                # ODCR reserved-capacity tier: per-entry CR id targets this
                # exact instance type (a CR is pinned to one type+AZ+platform).
                "capacity_reservation_id": _entry.get("capacity_reservation_id"),
                "odcr_fallback_to_od_when_full": _entry.get(
                    "odcr_fallback_to_od_when_full", True
                ),
                # Spot temporarily DISABLED (2026-06-15): forced to pure
                # On-Demand here regardless of the stored on_demand_* values.
                # The DDB fields + MIP construction are intentionally left in
                # place (framework) so Spot can return as a discrete Spot-only
                # (no-warm) ASG tier after the ODCR work. Re-enable by reading
                # the stored values again:
                #   "on_demand_base_count": int(_entry.get("on_demand_base_count", 0)),
                #   "on_demand_percentage_above_base":
                #       int(_entry.get("on_demand_percentage_above_base", 100)),
                "launch_spec": grp["meta"].get("launch_spec"),
                "stack_meta": grp["meta"],
            }
    return desired


def _discover_actual():
    """Discover existing tag-managed pool ASGs, keyed by edh:pool_id tag."""
    actual = {}
    _paginator = _asg.get_paginator("describe_auto_scaling_groups")
    for _page in _paginator.paginate():
        for _g in _page.get("AutoScalingGroups", []):
            _tags = {t["Key"]: t["Value"] for t in _g.get("Tags", [])}
            if _tags.get(MANAGED_TAG_KEY) != MANAGED_TAG_VALUE:
                continue
            if _tags.get(CLUSTER_TAG_KEY) != CLUSTER_ID:
                continue
            _pid = _tags.get(POOL_ID_TAG_KEY)
            if _pid:
                actual[_pid] = _g
    return actual


def _lt_name(stack_id):
    return f"{CLUSTER_ID}-vdipool-{stack_id}"


def _root_device(launch_spec):
    """Root block-device name from the AMI's RootDeviceName (resolved at render
    time by vdi_pool_resolve, matching dcv_cloudformation_builder). Falls back
    to /dev/sda1 (safe default: covers Ubuntu + Windows; Amazon Linux also
    accepts it as an alias for /dev/xvda)."""
    return (launch_spec or {}).get("root_device_name") or "/dev/sda1"


def _ensure_lt_user_data(launch_spec):
    """Return the LaunchTemplate UserData (base64) for this launch_spec.

    The producer (web_interface helpers/vdi_pool_render.build_launch_spec)
    SHOULD already store the correctly-encoded value: gzip+base64 for Linux,
    raw base64 for Windows. This is a defensive, IDEMPOTENT re-encode so that
    (a) pool configs written before the producer gzip-fix and (b) any future
    producer drift still fit under the 16 KB EC2 UserData cap -- EC2 otherwise
    rejects oversize UserData with InvalidUserData.Malformed and no pool ASG
    is ever created.

    Linux: ensure the decoded payload is gzip-compressed (cloud-init
    auto-decompresses). Idempotent -- payloads already gzipped (magic 1f 8b)
    are returned unchanged, so we never double-compress.
    Windows: EC2Launch does NOT auto-decompress gzip, so the stored value is
    passed through verbatim (raw base64).
    """
    _b64 = launch_spec["bootstrap_user_data"]
    if str(launch_spec.get("os_family", "linux")).lower() == "windows":
        return _b64
    try:
        _raw = base64.b64decode(_b64)
    except Exception:
        # Not decodable as base64 -- leave untouched rather than corrupt it.
        return _b64
    if _raw[:2] == b"\x1f\x8b":  # already gzip-compressed
        return _b64
    # mtime=0 -> deterministic gzip; default mtime embeds a timestamp, so the
    # LT-change hash would differ every reconcile (spurious new LT versions).
    return base64.b64encode(gzip.compress(_raw, mtime=0)).decode("utf-8")


def _build_lt_data(launch_spec):
    """Build EC2 LaunchTemplateData from the denormalized launch_spec.

    Returns (data, None) when all required inputs are present, else
    (None, reason). Required inputs are supplied by 3c-1 (the web-tier
    session-less render + cluster-input denormalization); until then this
    gates and the reconciler skips LT creation.
    """
    if not launch_spec:
        return None, "no launch_spec on config"
    _required = (
        "ami_id",
        "instance_profile_arn",
        "security_group_id",
        "bootstrap_user_data",
    )
    _missing = [k for k in _required if not launch_spec.get(k)]
    if _missing:
        return None, f"launch_spec missing {_missing} (awaiting 3c-1 render)"

    _data = {
        "ImageId": launch_spec["ami_id"],
        "IamInstanceProfile": {"Arn": launch_spec["instance_profile_arn"]},
        "SecurityGroupIds": [launch_spec["security_group_id"]],
        "UserData": _ensure_lt_user_data(launch_spec),  # gzip(Linux)+base64; idempotent
        "MetadataOptions": {
            "HttpEndpoint": "enabled",
            "HttpTokens": launch_spec.get("metadata_http_tokens", "required"),
            # Lets the claim-personalization agent read edh:JobOwner credential-free.
            "InstanceMetadataTags": "enabled",
        },
        "BlockDeviceMappings": [
            {
                "DeviceName": _root_device(launch_spec),
                "Ebs": {
                    "VolumeSize": int(launch_spec.get("root_size") or 30),
                    "VolumeType": launch_spec.get("volume_type", "gp3"),
                    "Encrypted": True,
                    "DeleteOnTermination": True,
                },
            }
        ],
    }
    if launch_spec.get("ssh_key_name"):
        _data["KeyName"] = launch_spec["ssh_key_name"]
    # Resolved by the web tier (helpers.vdi_root_volume); absent for gp2.
    _root_ebs = _data["BlockDeviceMappings"][0]["Ebs"]
    if launch_spec.get("volume_iops"):
        _root_ebs["Iops"] = int(launch_spec["volume_iops"])
    if launch_spec.get("volume_throughput"):
        _root_ebs["Throughput"] = int(launch_spec["volume_throughput"])
    return _data, None


def _ensure_stack_launch_template(stack_id, launch_spec):
    """Create/update ONE session-less launch template per stack.

    Idempotent via a content hash stored in the edh:lt_hash tag -- a new LT
    version is only cut when the rendered data changes (avoids version churn
    on every reconcile). The per-(stack,type) ASGs (3b) reference this LT via
    MixedInstancesPolicy overrides that pin the instance type. Returns
    {"id", "version"} or None when gated.
    """
    _data, _reason = _build_lt_data(launch_spec)
    if _data is None:
        logger.info("LT ensure stack=%s skipped: %s", stack_id, _reason)
        return None

    _name = _lt_name(stack_id)
    # Hash over the STORED bootstrap_user_data, not the re-encoded UserData, so
    # encoding (gzip) can never trigger a spurious version; a real bootstrap
    # change updates the stored value and still bumps the hash.
    _hash_basis = dict(_data)
    _hash_basis["UserData"] = launch_spec.get("bootstrap_user_data", "")
    _hash = hashlib.sha256(
        json.dumps(_hash_basis, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]

    try:
        _resp = _ec2.describe_launch_templates(LaunchTemplateNames=[_name])
        _lt = _resp["LaunchTemplates"][0]
        _tags = {t["Key"]: t["Value"] for t in _lt.get("Tags", [])}
        if _tags.get("edh:lt_hash") == _hash:
            logger.info("LT stack=%s unchanged (hash=%s)", stack_id, _hash)
            return {
                "id": _lt["LaunchTemplateId"],
                "version": str(_lt["LatestVersionNumber"]),
                "changed": False,
            }
        _ver = _ec2.create_launch_template_version(
            LaunchTemplateId=_lt["LaunchTemplateId"],
            SourceVersion=str(_lt["DefaultVersionNumber"]),
            LaunchTemplateData=_data,
        )["LaunchTemplateVersion"]
        _ec2.modify_launch_template(
            LaunchTemplateId=_lt["LaunchTemplateId"],
            DefaultVersion=str(_ver["VersionNumber"]),
        )
        _ec2.create_tags(
            Resources=[_lt["LaunchTemplateId"]],
            Tags=[{"Key": "edh:lt_hash", "Value": _hash}],
        )
        logger.info(
            "LT stack=%s updated to v%s (hash=%s)",
            stack_id,
            _ver["VersionNumber"],
            _hash,
        )
        return {
            "id": _lt["LaunchTemplateId"],
            "version": str(_ver["VersionNumber"]),
            "changed": True,
        }
    except _ec2.exceptions.ClientError as err:
        _code = err.response.get("Error", {}).get("Code", "")
        if "NotFound" not in _code:
            raise
        _created = _ec2.create_launch_template(
            LaunchTemplateName=_name,
            LaunchTemplateData=_data,
            TagSpecifications=[
                {
                    "ResourceType": "launch-template",
                    "Tags": [
                        {"Key": CLUSTER_TAG_KEY, "Value": CLUSTER_ID},
                        {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
                        {"Key": "edh:stack_id", "Value": str(stack_id)},
                        {"Key": "edh:lt_hash", "Value": _hash},
                    ],
                }
            ],
        )["LaunchTemplate"]
        logger.info(
            "LT stack=%s created %s", stack_id, _created["LaunchTemplateId"]
        )
        return {"id": _created["LaunchTemplateId"], "version": "1", "changed": False}


def _asg_name(stack_id, instance_type):
    return f"{CLUSTER_ID}-vdipool-{stack_id}-{str(instance_type).replace('.', '-')}"


def _pool_tags(pool_id, d):
    _name = _asg_name(d["stack_id"], d["instance_type"])
    return [
        {"Key": CLUSTER_TAG_KEY, "Value": CLUSTER_ID, "PropagateAtLaunch": True},
        {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE, "PropagateAtLaunch": True},
        {"Key": POOL_ID_TAG_KEY, "Value": pool_id, "PropagateAtLaunch": True},
        {"Key": "edh:stack_id", "Value": str(d["stack_id"]), "PropagateAtLaunch": True},
        {"Key": "edh:instance_type", "Value": d["instance_type"], "PropagateAtLaunch": True},
        {"Key": "Name", "Value": _name, "PropagateAtLaunch": True},
    ]


def _mixed_instances_policy(lt_id, d):
    """Single-type MIP: pins the one instance type (no substitution -- exact
    sizing) and carries the On-Demand/Spot purchase mix."""
    return {
        "LaunchTemplate": {
            "LaunchTemplateSpecification": {
                "LaunchTemplateId": lt_id,
                "Version": "$Latest",
            },
            "Overrides": [{"InstanceType": d["instance_type"]}],
        },
        "InstancesDistribution": {
            "OnDemandBaseCapacity": int(d["on_demand_base_count"]),
            "OnDemandPercentageAboveBaseCapacity": int(
                d["on_demand_percentage_above_base"]
            ),
            "SpotAllocationStrategy": "price-capacity-optimized",
        },
    }


def _capacity_reservation_specification(d):
    """Build the ASG-level CapacityReservationSpecification for a single
    (stack, instance_type) pool entry.

    A Capacity Reservation is pinned to one instance type + AZ + platform,
    so per-entry `capacity_reservation_id` (validate_pool_type_config) is
    the only correct place for a bare CR id -- it targets exactly the
    instance type this ASG launches. The stack-level
    `capacity_reservation_group_arn` (validate_pool_config) is the fallback:
    a group can span multiple instance types/AZs, and AWS resolves per-launch
    which member CR matches this entry's instance type. Precedence: per-entry
    CR id > stack-level group ARN > none (no reserved tier for this entry).

    CapacityReservationPreference:
      capacity-reservations-first -- prefer the reservation, fall back to
        On-Demand/Spot when it's full (default; matches the per-entry
        odcr_fallback_to_od_when_full convention).
      capacity-reservations-only -- hard-fail when the reservation is full;
        admin is enforcing the reservation as a capacity cap.
    """
    _stack_meta = d.get("stack_meta") or {}
    _cr_id = d.get("capacity_reservation_id")
    _cr_group_arn = _stack_meta.get("capacity_reservation_group_arn")
    if not _cr_id and not _cr_group_arn:
        return None

    _fallback = (
        d.get("odcr_fallback_to_od_when_full")
        if _cr_id
        else _stack_meta.get("capacity_reservation_fallback_to_od")
    )
    _preference = (
        "capacity-reservations-first"
        if _fallback is not False
        else "capacity-reservations-only"
    )
    _target = (
        {"CapacityReservationIds": [_cr_id]}
        if _cr_id
        else {"CapacityReservationResourceGroupArns": [_cr_group_arn]}
    )
    return {
        "CapacityReservationPreference": _preference,
        "CapacityReservationTarget": _target,
    }


def _apply_warm_pool(asg_name, hot, warm, pool_state):
    if warm > 0:
        # Warm pool size = max(MinSize, MaxGroupPreparedCapacity - Desired).
        # Per AWS: "Only when MaxGroupPreparedCapacity and MinSize are set to
        # the same value does the warm pool have an ABSOLUTE size." So to hold
        # EXACTLY `warm` Stopped instances DECOUPLED from hot/Desired, set both
        # cap AND MinSize = warm. Then cap-Desired <= warm always, so the
        # MinSize floor wins at every Desired (incl. 0 on scheduled drain) ->
        # warm stays exactly `warm`. Hot is governed independently by the ASG
        # DesiredCapacity. (History: unset/-1 gave MaxSize-Desired; hot+warm+2
        # gave warm+2; hot+warm coupled warm to Desired -> drifted off-hours.)
        _asg.put_warm_pool(
            AutoScalingGroupName=asg_name,
            MinSize=warm,
            MaxGroupPreparedCapacity=warm,
            PoolState=pool_state or "Stopped",
        )
    else:
        # warm == 0 -> remove the warm pool. ForceDelete=True is required: a
        # plain delete is rejected while the pool still holds a member
        # (ScalingActivityInProgress mid-hook, or ResourceInUse when Stopped).
        try:
            _asg.delete_warm_pool(AutoScalingGroupName=asg_name, ForceDelete=True)
        except _asg.exceptions.ClientError as err:
            # A missing warm pool is the normal steady state once warm has been
            # set to 0 (nothing to delete) -- not an error. AWS returns
            # ValidationError "No warm pool found ..." in that case; log it at
            # debug and move on. Only surface genuinely unexpected failures so a
            # real teardown problem (e.g. a persistent ScalingActivityInProgress)
            # is visible instead of silently swallowed.
            _e = err.response.get("Error", {})
            if _e.get("Code") == "ValidationError" and "No warm pool found" in _e.get("Message", ""):
                logger.debug(f"no warm pool to delete for {asg_name} (warm=0)")
            else:
                logger.error(f"delete_warm_pool failed for {asg_name}: {err}")


def _ensure_pool_asg(pool_id, d, lt_id, pool_state, exists):
    """Create/update the single-type ASG for a (stack, instance_type) pool.

    MinSize = hot_count; DesiredCapacity = hot_count + outstanding warm-claim
    reservations; MaxSize = that plus a buffer for detach-backfill transients.
    Warm pool sized to warm_count.

    Desired includes reservations because a warm claim raises desired to
    promote a member out of the warm pool, and this function is the
    declarative authority on desired -- without the addend the next sweep
    would undo every warm promotion within 5 minutes. MinSize deliberately
    stays at hot_count so the group scales back down once reservations clear.
    """
    _name = _asg_name(d["stack_id"], d["instance_type"])
    # PARKED (configured but not active) -> 0/0/0, no warm pool. ACTIVE ->
    # hot/warm sizes. Either way the ASG is kept so re-activation is instant.
    _active = bool(d.get("active", True))
    _hot = int(d["hot_count"]) if _active else 0
    _warm = int(d["warm_count"]) if _active else 0
    # A PARKED pool serves nobody, so an in-flight reservation against it is
    # not honoured -- it expires via the reaper and the session falls back to
    # a cold launch.
    _reserved = int(d.get("reserved_count") or 0) if _active else 0
    _desired = _hot + _reserved
    _max = (_desired + 2) if _active else 0
    _status = "ACTIVE" if _active else "PARKED"
    _subnets = (d.get("launch_spec") or {}).get("subnet_ids") or []
    _vpc_zone = ",".join(_subnets)
    _mip = _mixed_instances_policy(lt_id, d)
    _cr_spec = _capacity_reservation_specification(d)

    if exists:
        _update_kwargs = dict(
            AutoScalingGroupName=_name,
            MinSize=_hot,
            MaxSize=_max,
            DesiredCapacity=_desired,
            MixedInstancesPolicy=_mip,
            VPCZoneIdentifier=_vpc_zone,
        )
        # CapacityReservationSpecification has no "unset" sentinel on update --
        # pass {"CapacityReservationPreference": "none"} explicitly when a
        # previously-set target is removed, so a stack that drops its CR
        # config reverts the ASG to unreserved On-Demand/Spot instead of
        # silently keeping the last-applied target.
        _update_kwargs["CapacityReservationSpecification"] = _cr_spec or {
            "CapacityReservationPreference": "none"
        }
        _asg.update_auto_scaling_group(**_update_kwargs)
        _asg.create_or_update_tags(
            Tags=[
                dict(t, ResourceId=_name, ResourceType="auto-scaling-group")
                for t in _pool_tags(pool_id, d)
            ]
        )
        logger.info(
            "ASG %s updated (status=%s hot=%d warm=%d reserved=%d desired=%d)",
            _name, _status, _hot, _warm, _reserved, _desired,
        )
    else:
        _create_kwargs = dict(
            AutoScalingGroupName=_name,
            MixedInstancesPolicy=_mip,
            MinSize=_hot,
            MaxSize=_max,
            DesiredCapacity=_desired,
            VPCZoneIdentifier=_vpc_zone,
            HealthCheckType="EC2",
            NewInstancesProtectedFromScaleIn=False,
            Tags=_pool_tags(pool_id, d),
        )
        if _cr_spec:
            _create_kwargs["CapacityReservationSpecification"] = _cr_spec
        _asg.create_auto_scaling_group(**_create_kwargs)
        logger.info(
            "ASG %s created (status=%s hot=%d warm=%d reserved=%d desired=%d)",
            _name, _status, _hot, _warm, _reserved, _desired,
        )

    # Stamp pool_status; ACTIVE/PARKED also clears any prior DRAINING tombstone
    # (re-add reuse path) since the reaper only deletes status==DRAINING.
    _asg.create_or_update_tags(
        Tags=[
            {
                "ResourceId": _name,
                "ResourceType": "auto-scaling-group",
                "Key": "edh:pool_status",
                "Value": _status,
                "PropagateAtLaunch": False,
            }
        ]
    )

    _apply_warm_pool(_name, _hot, _warm, pool_state)
    _apply_lifecycle_hook(_name, d.get("provisioning_timeout_seconds"))
    _apply_schedule(_name, _hot, (d.get("stack_meta") or {}).get("schedule"))
    _apply_alarms(pool_id, _name)
    return _name


def _days_to_cron(days):
    """Map a friendly days string (e.g. 'Mon-Fri', 'mon,wed', 'daily') to a
    cron day-of-week field."""
    d = (days or "").strip().lower().replace(" ", "")
    if d in ("daily", "all", "everyday", "*", ""):
        return "*"
    if "-" in d and "," not in d:
        _a, _b = d.split("-", 1)
        return f"{_DOW.get(_a[:3], 'MON')}-{_DOW.get(_b[:3], 'FRI')}"
    _parts = [_DOW[p[:3]] for p in d.split(",") if p[:3] in _DOW]
    return ",".join(_parts) if _parts else "*"


def _hhmm(value):
    _h, _m = str(value).split(":")
    return int(_h), int(_m)


def _apply_lifecycle_hook(asg_name, timeout_seconds=None):
    """Pending:Wait launch hook so DesiredCapacity tracks READY members.
    The DcvEventRelay completes the hook with CONTINUE when a member announces
    readiness (pool-ready -> ledger AVAILABLE). DefaultResult=ABANDON: a member
    that never announces readiness within HeartbeatTimeout is a FAILURE, so the
    ASG terminates + relaunches it rather than admitting a never-ready box that
    counts toward capacity but has no AVAILABLE ledger row (un-claimable).

    HeartbeatTimeout uses the per-pool provisioning_timeout_seconds override
    when set, else the reconciler default. It MUST exceed the on-host agent's
    DCV-readiness wait (slow GPU nodes) or the hook ABANDON-loops."""
    _timeout = (
        int(timeout_seconds)
        if timeout_seconds
        else _PROVISIONING_HOOK_TIMEOUT_SECONDS
    )
    try:
        _asg.put_lifecycle_hook(
            LifecycleHookName="vdipool-ready",
            AutoScalingGroupName=asg_name,
            LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
            HeartbeatTimeout=_timeout,
            DefaultResult="ABANDON",
        )
    except _asg.exceptions.ClientError as err:
        logger.warning("lifecycle hook on %s failed: %s", asg_name, err)


def _apply_schedule(asg_name, hot, schedule):
    """Translate the active-hours schedule into ASG scheduled actions: scale hot
    up at each window start, drain hot to 0 at window end (warm pool untouched).
    Clears managed actions first so removing the schedule clears them."""
    try:
        _existing = _asg.describe_scheduled_actions(
            AutoScalingGroupName=asg_name
        ).get("ScheduledUpdateGroupActions", [])
        for _a in _existing:
            if _a["ScheduledActionName"].startswith(SCHED_PREFIX):
                _asg.delete_scheduled_action(
                    AutoScalingGroupName=asg_name,
                    ScheduledActionName=_a["ScheduledActionName"],
                )
    except _asg.exceptions.ClientError as err:
        logger.warning("clear scheduled actions on %s failed: %s", asg_name, err)

    if not schedule:
        return
    _tz = schedule.get("timezone") or "UTC"
    for _i, _w in enumerate(schedule.get("windows") or []):
        try:
            _sh, _sm = _hhmm(_w.get("start", "0:0"))
            _eh, _em = _hhmm(_w.get("end", "0:0"))
        except Exception:
            logger.warning("bad schedule window on %s: %s", asg_name, _w)
            continue
        _dow = _days_to_cron(_w.get("days", ""))
        _asg.put_scheduled_update_group_action(
            AutoScalingGroupName=asg_name,
            ScheduledActionName=f"{SCHED_PREFIX}up-{_i}",
            Recurrence=f"{_sm} {_sh} * * {_dow}",
            MinSize=hot,
            DesiredCapacity=hot,
            TimeZone=_tz,
        )
        _asg.put_scheduled_update_group_action(
            AutoScalingGroupName=asg_name,
            ScheduledActionName=f"{SCHED_PREFIX}down-{_i}",
            Recurrence=f"{_em} {_eh} * * {_dow}",
            MinSize=0,
            DesiredCapacity=0,
            TimeZone=_tz,
        )


def _apply_alarms(pool_id, asg_name):
    """Advisory collision-rate alarm (metric math with an attempts floor so low
    volume does not fire). Sustained-breach (3x5min). INSUFFICIENT_DATA until
    the PoolAllocator emits ClaimAttempts/ClaimCollisions."""
    try:
        _cw.put_metric_alarm(
            AlarmName=f"{SCHED_PREFIX}collision-{pool_id}",
            AlarmDescription=(
                "VDI pool under-provisioned: sustained claim-collision rate"
            ),
            EvaluationPeriods=3,
            DatapointsToAlarm=3,
            Threshold=25.0,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            TreatMissingData="notBreaching",
            Metrics=[
                {
                    "Id": "attempts",
                    "ReturnData": False,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": METRIC_NS,
                            "MetricName": "ClaimAttempts",
                            "Dimensions": [{"Name": "pool_id", "Value": pool_id}],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                },
                {
                    "Id": "collisions",
                    "ReturnData": False,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": METRIC_NS,
                            "MetricName": "ClaimCollisions",
                            "Dimensions": [{"Name": "pool_id", "Value": pool_id}],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                },
                {
                    "Id": "rate",
                    "ReturnData": True,
                    "Label": "CollisionRatePct",
                    "Expression": "IF(attempts >= 20, 100*collisions/attempts, 0)",
                },
            ],
        )
    except _cw.exceptions.ClientError as err:
        logger.warning("collision alarm for %s failed: %s", pool_id, err)


def _delete_pool_asg(pool_id, asg):
    """Tombstone a pool ASG whose config entry was REMOVED entirely: drain to
    zero + drop the warm pool + tag DRAINING/drained_at. We deliberately do
    NOT delete the ASG here -- a same-named ASG that is still deleting blocks
    re-adding the same (stack, instance_type). Keeping the (now-empty) ASG
    lets a re-add reuse it instantly; the reaper deletes it once it has fully
    drained past the grace window."""
    _name = asg["AutoScalingGroupName"]
    try:
        _asg.update_auto_scaling_group(
            AutoScalingGroupName=_name, MinSize=0, MaxSize=0, DesiredCapacity=0
        )
    except Exception as err:
        logger.warning("tombstone resize failed for %s: %s", _name, err)
    try:
        _asg.delete_warm_pool(AutoScalingGroupName=_name, ForceDelete=True)
    except Exception:
        pass  # no warm pool to remove
    _now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        _asg.create_or_update_tags(
            Tags=[
                {
                    "ResourceId": _name,
                    "ResourceType": "auto-scaling-group",
                    "Key": "edh:pool_status",
                    "Value": "DRAINING",
                    "PropagateAtLaunch": False,
                },
                {
                    "ResourceId": _name,
                    "ResourceType": "auto-scaling-group",
                    "Key": "edh:drained_at",
                    "Value": _now,
                    "PropagateAtLaunch": False,
                },
            ]
        )
    except Exception as err:
        logger.warning("tombstone tag failed for %s: %s", _name, err)
    logger.info(
        "ASG %s tombstoned (pool %s removed; reaper deletes after drain+grace)",
        _name,
        pool_id,
    )


def _coerce_bool(value):
    """Coerce a DDB/string/bool config value to a Python bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def _recycle_pool_asg(asg_name):
    """Instance-refresh a pool ASG onto the current LT (MinHealthyPercentage=0 =
    full burn-down). Idempotent: an in-progress refresh is a no-op."""
    try:
        _asg.start_instance_refresh(
            AutoScalingGroupName=asg_name,
            Preferences={
                "MinHealthyPercentage": 0,
                "InstanceWarmup": 0,
                "ScaleInProtectedInstances": "Ignore",
                "StandbyInstances": "Terminate",
            },
        )
        logger.info("recycle: instance refresh started for %s", asg_name)
        return True
    except _asg.exceptions.InstanceRefreshInProgressFault:
        logger.info("recycle: refresh already in progress for %s (no-op)", asg_name)
        return False
    except Exception as exc:
        logger.exception("recycle: instance refresh failed for %s: %s", asg_name, exc)
        return False


def _recycle_stack(stack_id=None):
    """Recycle every pool ASG for a stack (stack_id=None = all). Returns the ASG
    names a refresh was started for."""
    _started = []
    _prefix = f"POOL#{stack_id}#" if stack_id is not None else None
    for _pid, _g in _discover_actual().items():
        if _prefix and not _pid.startswith(_prefix):
            continue
        if _recycle_pool_asg(_g["AutoScalingGroupName"]):
            _started.append(_g["AutoScalingGroupName"])
    logger.info("recycle stack=%s: started refresh on %d ASG(s)", stack_id, len(_started))
    return _started


def _stamp_apply_status(stack_id, status):
    """Write apply_status onto a stack's META item. Best-effort.

    The reconciler is the only component that knows whether a desired pool
    actually reached AWS, so it is the only honest writer of this field. A
    failure here must not fail the reconcile: the ASGs are already correct and
    the next sweep re-stamps.
    """
    try:
        _ddb.Table(CONFIG_TABLE).update_item(
            Key={"pk": f"STACK#{stack_id}", "sk": "META"},
            UpdateExpression="SET apply_status = :s, applied_at = :t",
            ExpressionAttributeValues={
                ":s": status,
                ":t": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            ConditionExpression="attribute_exists(pk)",
        )
    except Exception as err:
        logger.warning(
            "could not stamp apply_status=%s on stack %s: %s", status, stack_id, err
        )


def _reconcile(stack_id=None):
    """Compute the desired vs actual diff and ensure per-stack launch
    templates (3c-2). ASG/warm-pool CRUD (3b) and deletes (3d) are still
    pending; LT-ensure is gated until 3c-1 supplies launch_spec inputs."""
    desired = _read_desired(stack_id)
    actual = _discover_actual()

    # Scope guard: a single-stack reconcile must only diff THIS stack's pools.
    # _discover_actual returns every stack's ASGs, so without this filter
    # to_delete would tombstone other stacks' pools (cross-stack churn).
    if stack_id is not None:
        _scope_prefix = f"POOL#{stack_id}#"
        actual = {p: g for p, g in actual.items() if p.startswith(_scope_prefix)}

    to_create = [p for p in desired if p not in actual]
    to_update = [p for p in desired if p in actual]
    to_delete = [p for p in actual if p not in desired]

    logger.info(
        "vdi-pool reconcile (stack_id=%s): desired=%d actual=%d "
        "create=%s update=%s delete=%s",
        stack_id,
        len(desired),
        len(actual),
        to_create,
        to_update,
        to_delete,
    )

    # Ensure ONE launch template per stack (per-type ASGs reference it).
    _lt_by_stack = {}
    for _d in desired.values():
        _sid = _d["stack_id"]
        if _sid not in _lt_by_stack:
            _lt_by_stack[_sid] = _ensure_stack_launch_template(
                _sid, _d.get("launch_spec")
            )

    # 3b: create/update per-type ASGs (+ warm pool); delete removed pools.
    _asg_results = {}
    _deferred = []
    # Pools whose ensure did not land, split by cause so apply_status can be
    # stamped truthfully: _gated = launch template not rendered yet,
    # _failed = a real error (already logged with a traceback). _deferred is
    # separate because it is a benign retry-next-cycle condition.
    _gated = []
    _failed = []
    # Transient create/update faults that just mean "an old same-named ASG is
    # still deleting" (e.g. a tombstone was reaped moments ago, or a fast
    # remove->re-add). These are NOT errors -- the create succeeds on a later
    # cycle once AWS finishes the delete. Treat them as deferred, not failures.
    _transient = (
        _asg.exceptions.AlreadyExistsFault,
        _asg.exceptions.ResourceInUseFault,
    )
    # Outstanding warm-claim reservations, read ONCE per reconcile. Folded into
    # each pool's desired capacity by _ensure_pool_asg so this declarative pass
    # sustains an in-flight warm promotion instead of setting desired back to
    # hot_count and destroying the member a user is waiting for.
    _reserved_by_pool = _reserved_counts()
    for _pid in to_create + to_update:
        _d = desired[_pid]
        _d["reserved_count"] = _reserved_by_pool.get(_pid, 0)
        _lt = _lt_by_stack.get(_d["stack_id"])
        if not _lt:
            logger.info(
                "ASG ensure %s skipped: launch template gated (awaiting render)",
                _pid,
            )
            _gated.append(_pid)
            continue
        _pstate = (_d.get("stack_meta") or {}).get("pool_state") or "Stopped"
        try:
            _asg_results[_pid] = _ensure_pool_asg(
                _pid, _d, _lt["id"], _pstate, exists=_pid in actual
            )
        except _transient as exc:
            # Idempotent: the next reconcile (PUT re-invoke or the periodic
            # schedule) retries cleanly once the prior delete completes.
            logger.info(
                "ASG ensure %s deferred (same-named ASG still deleting; "
                "will retry next reconcile): %s",
                _pid,
                exc,
            )
            _deferred.append(_pid)
        except Exception as exc:
            logger.exception("ASG ensure failed for %s: %s", _pid, exc)
            _failed.append(_pid)

    for _pid in to_delete:
        try:
            _delete_pool_asg(_pid, actual[_pid])
        except Exception as exc:
            logger.exception("ASG delete failed for %s: %s", _pid, exc)
            _failed.append(_pid)

    # Stamp the per-stack apply outcome onto the META item. put_pool_config and
    # cas_update_launch_spec both write apply_status=PENDING_APPLY and nothing
    # ever wrote anything else, so the field could never leave PENDING_APPLY and
    # an admin had no way to tell a finished apply from a stuck one.
    #
    # APPLIED means every desired pool of that stack had its ASG ensured on this
    # pass. Anything outstanding -- gated on an unrendered launch template,
    # deferred behind a still-deleting ASG, or failed -- leaves the stack
    # PENDING_APPLY, and is written back even if the stack was previously
    # APPLIED so a later regression is visible rather than sticky.
    _incomplete = set(_gated) | set(_deferred) | set(_failed)
    _pools_by_stack = {}
    for _pid, _d in desired.items():
        _pools_by_stack.setdefault(_d["stack_id"], []).append(_pid)
    _apply_status = {}
    for _sid, _pids in _pools_by_stack.items():
        _ok = not any(_p in _incomplete for _p in _pids)
        _status = "APPLIED" if _ok else "PENDING_APPLY"
        _apply_status[str(_sid)] = _status
        _stamp_apply_status(_sid, _status)

    # Auto-recycle: when a stack's LT actually changed AND recycle_on_lt_change
    # is on, burn down + relaunch its members onto the new LT (uniform fleet).
    # Deterministic gzip means "changed" is real, so this never fires when idle.
    _recycled = []
    _meta_by_stack = {}
    for _d in desired.values():
        _meta_by_stack.setdefault(_d["stack_id"], _d.get("stack_meta") or {})
    for _sid, _lt in _lt_by_stack.items():
        if not (_lt and _lt.get("changed")):
            continue
        if not _coerce_bool(_meta_by_stack.get(_sid, {}).get("recycle_on_lt_change")):
            continue
        logger.info(
            "auto-recycle: stack %s LT changed + recycle_on_lt_change=on -> recycling pools",
            _sid,
        )
        _recycled.extend(_recycle_stack(_sid))

    # Re-discover after the ensure pass so the stamped summary and the depth
    # gauges describe the post-apply state rather than the pre-apply one. Kept
    # in a separate name: `actual` is what the diff above was computed from, and
    # the returned "actual" count must keep meaning that. A failure here falls
    # back to the pre-apply view, which is stale but not wrong.
    _observed = actual
    try:
        _observed = _discover_actual()
        if stack_id is not None:
            _observed = {
                p: g
                for p, g in _observed.items()
                if p.startswith(f"POOL#{stack_id}#")
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "post-apply re-discovery failed, stamping pre-apply view: %s", exc
        )

    # Stamp measured per-pool depth so the launch modal can report real warm
    # capacity instead of the admin's configured warm_count.
    _stamp_pool_summary(_observed)

    # Phase 3: emit per-pool depth gauges (best-effort) for the Pools dashboard
    # depth sparklines. Never breaks a reconcile.
    _emit_pool_gauges(_observed)

    return {
        "desired": len(desired),
        "actual": len(actual),
        "create": to_create,
        "update": to_update,
        "delete": to_delete,
        "deferred": _deferred,
        "gated": _gated,
        "failed": _failed,
        "apply_status": _apply_status,
        "recycled": _recycled,
        "launch_templates": {
            str(k): (v or {}).get("id") for k, v in _lt_by_stack.items()
        },
        "asgs": _asg_results,
    }


def _warm_state_counts(asg_name):
    """Per-lifecycle-state warm pool counts for one ASG.

    describe_auto_scaling_groups returns only the aggregate WarmPoolSize, which
    counts members still in Warmed:Pending (booting, not yet promotable).
    describe_warm_pool returns per-instance LifecycleState, so this separates
    "parked and promotable in ~30s" from "still coming up". Affordable here
    because the reconciler runs on a schedule; the end-user availability API
    must never make this call per request, which is why the result is stamped
    into the summary table instead.

    Returns {"promotable": int, "warming_up": int, "total": int} and never
    raises -- a describe failure yields zeros, which the caller records as
    "unmeasured" rather than as "empty".
    """
    _promotable = 0
    _warming_up = 0
    _total = 0
    try:
        _paginator = _asg.get_paginator("describe_warm_pool")
        for _page in _paginator.paginate(AutoScalingGroupName=asg_name):
            for _i in _page.get("Instances", []):
                _state = _i.get("LifecycleState") or ""
                _total += 1
                # Terminal parked states: the member is stopped/hibernated and
                # a desired-capacity bump promotes it. Anything else under
                # Warmed: is still transitioning.
                if _state in ("Warmed:Stopped", "Warmed:Hibernated", "Warmed:Running"):
                    _promotable += 1
                elif _state.startswith("Warmed:"):
                    _warming_up += 1
    except Exception as exc:  # noqa: BLE001 - measurement must not break reconcile
        logger.warning("warm pool describe failed for %s: %s", asg_name, exc)
        return {"promotable": 0, "warming_up": 0, "total": 0, "measured": False}
    return {
        "promotable": _promotable,
        "warming_up": _warming_up,
        "total": _total,
        "measured": True,
    }


def _stamp_pool_summary(actual):
    """Stamp measured per-pool depth into the summary table.

    The table is declared in CDK as "reconciler-stamped per-pool status +
    stats" (pk=POOL#<stack>#<type>, sk="SUMMARY") and the reconciler role
    already has write access to it, but nothing ever wrote a row. The launch
    modal consequently reported the admin's CONFIGURED warm_count as live
    warm capacity, which never moves and does not drop to zero when a warm
    pool fails to fill.

    This writes what the reconciler actually observed, so the end-user API can
    report a measurement with one cheap DDB read and no AWS calls per request.
    Best-effort per pool: a failure on one row must not break the reconcile.
    """
    _table = _ddb.Table(SUMMARY_TABLE)
    _now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for _pid, _g in (actual or {}).items():
        _name = _g.get("AutoScalingGroupName")
        if not _name:
            continue
        _insvc = len([
            i for i in (_g.get("Instances") or [])
            if i.get("LifecycleState") == "InService"
        ])
        _warm = _warm_state_counts(_name)
        try:
            _table.put_item(
                Item={
                    "pk": _pid,
                    "sk": "SUMMARY",
                    "asg_name": _name,
                    "hot_in_service": _insvc,
                    "warm_promotable": _warm["promotable"],
                    "warm_warming_up": _warm["warming_up"],
                    "warm_total": _warm["total"],
                    "warm_measured": _warm["measured"],
                    "desired_capacity": int(_g.get("DesiredCapacity") or 0),
                    "min_size": int(_g.get("MinSize") or 0),
                    "max_size": int(_g.get("MaxSize") or 0),
                    "updated_at": _now,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("pool summary stamp failed for %s: %s", _pid, exc)


def _emit_pool_gauges(actual):
    """Phase 3: emit per-pool depth gauges to EDH/DCVHighScale (dim pool_id) so
    the Pools dashboard can chart hot / warm / ready depth over time. InService
    pool members are the ready-now hot tier (claimed members are detached), so
    ReadyNow == HotDepth == InService count here. Best-effort -- a CloudWatch
    failure must never break a reconcile. Requires cloudwatch:PutMetricData on
    EDH/* (codified for the reconciler role in helpers/vdi_pools.py)."""
    _data = []
    _now = datetime.now(timezone.utc)
    for _pid, _g in (actual or {}).items():
        _insvc = len([
            i for i in (_g.get("Instances") or [])
            if i.get("LifecycleState") == "InService"
        ])
        _warm = int(_g.get("WarmPoolSize") or 0)
        _desired = int(_g.get("DesiredCapacity") or 0)
        _dims = [{"Name": "pool_id", "Value": _pid}]
        for _mname, _val in (
            ("ReadyNow", _insvc),
            ("HotDepth", _insvc),
            ("WarmDepth", _warm),
            ("DesiredDepth", _desired),
        ):
            _data.append({
                "MetricName": _mname,
                "Dimensions": _dims,
                "Timestamp": _now,
                "Value": float(_val),
                "Unit": "Count",
            })
    if not _data:
        return
    try:
        for _i in range(0, len(_data), 20):  # PutMetricData cap = 20 metrics/call
            _cw.put_metric_data(Namespace=METRIC_NS, MetricData=_data[_i:_i + 20])
    except Exception as exc:  # noqa: BLE001 - telemetry must never break reconcile
        logger.warning("pool depth gauge emit failed: %s", exc)


def _parse_ts(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except Exception:
        return None


def _reap_tombstoned_asgs(desired_pids=None):
    """Delete pool ASGs tombstoned by config removal once they have fully
    drained (0 instances) and sat DRAINING past the grace window. Scheduled
    sweep only. Parked (status=PARKED) ASGs are config-present and never
    reaped here -- only status=DRAINING (entry removed). A pool_id that is
    currently desired (re-added) is skipped outright, so a remove->re-add
    never races the reaper."""
    _desired = desired_pids or set()
    _now = datetime.now(timezone.utc)
    for _pid, _g in _discover_actual().items():
        if _pid in _desired:
            continue  # re-added; reconcile owns it, never reap
        _tags = {t["Key"]: t["Value"] for t in _g.get("Tags", [])}
        if _tags.get("edh:pool_status") != "DRAINING":
            continue
        if _g.get("Instances"):
            continue  # not fully drained yet
        _drained = _parse_ts(_tags.get("edh:drained_at"))
        if _drained and (_now - _drained).total_seconds() < _DRAIN_GRACE_SECONDS:
            continue  # within grace -> still reusable by a re-add
        try:
            _asg.delete_auto_scaling_group(
                AutoScalingGroupName=_g["AutoScalingGroupName"], ForceDelete=True
            )
            logger.info(
                "reaped tombstoned ASG %s (pool %s)",
                _g["AutoScalingGroupName"],
                _pid,
            )
        except Exception as err:
            logger.warning(
                "tombstone reap failed for %s: %s",
                _g["AutoScalingGroupName"],
                err,
            )


def _reserved_counts():
    """Outstanding warm-claim reservations per pool, from the ledger.

    A RESERVED row is a user waiting on a warm member that is being promoted.
    Folding it into the reconcile's desired capacity is what makes the
    promotion SURVIVE: the reconcile is declarative and sets
    DesiredCapacity=hot_count, so on its own it would set desired straight back
    down within one 5-minute sweep and undo the kick -- terminating the very
    member a user is waiting for, and on a warm pool with no
    InstanceReusePolicy that member is destroyed rather than re-parked.

    Treating a reservation as desired state rather than special-casing the
    reconcile also means the convergence is self-healing: when the claim binds
    or the reaper expires the reservation past
    connect_abandon_timeout_seconds, the count drops and the next sweep
    returns the pool to its configured size with no extra bookkeeping.

    Returns {pool_id: count}; {} on any error, which degrades to the prior
    behaviour (desired == hot_count) rather than inflating a pool on bad data.
    """
    _counts = {}
    try:
        _rows = (
            _ddb.Table(f"{CLUSTER_ID}-vdi-pool-ledger").scan().get("Items", [])
        )
    except Exception as err:
        logger.warning("reserved count scan failed: %s", err)
        return {}
    for _r in _rows:
        if _r.get("status") != "RESERVED":
            continue
        _pk = _r.get("pk")
        if _pk:
            _counts[_pk] = _counts.get(_pk, 0) + 1
    if _counts:
        logger.info("outstanding warm reservations: %s", _counts)
    return _counts


def _promote_warm(stack_id, instance_type):
    """Promote ONE warm member of a pool into service by raising desired capacity.

    This is the "kick" half of the warm claim. Raising DesiredCapacity is the
    documented primitive for taking a member out of a warm pool: the ASG starts
    a Warmed:Stopped instance, runs it through Pending:Wait (where the launch
    hook pauses it until the on-host agent announces pool-ready), and lands it
    InService. The claim path then detaches it like any hot member.

    Deliberately does NOT pick a member and StartInstances it. A
    Warmed:Stopped instance is lifecycle state the ASG owns, so starting it
    out of band is drift the ASG converges back to stopped, and DetachInstances
    is documented to require InService / Standby / a retained state, which
    Warmed:Stopped is not. The cost is that the caller cannot choose WHICH
    member it gets, which is free: members of one POOL#stack#type are fungible.

    Lives in the reconciler rather than the web tier because of IAM. The
    controller role holds no autoscaling:SetDesiredCapacity (verified with
    simulate-principal-policy: implicitDeny), while this role already holds
    autoscaling:UpdateAutoScalingGroup gated to the cluster tag -- and
    UpdateAutoScalingGroup sets DesiredCapacity. The controller already has
    lambda:InvokeFunction on this function for the apply path. So the kick
    needs no new grant and therefore no stack update, which matters because
    EDH never does stack updates: a design needing new IAM would be dead on
    every installed cluster.

    Returns a plain dict the web tier can branch on; never raises.
    """
    _pid = _pool_id(stack_id, instance_type)
    _name = _asg_name(stack_id, instance_type)
    _result = {"pool_id": _pid, "asg_name": _name, "promoted": False}
    try:
        _groups = _asg.describe_auto_scaling_groups(
            AutoScalingGroupNames=[_name]
        ).get("AutoScalingGroups", [])
    except Exception as err:
        _result["reason"] = f"describe_auto_scaling_groups failed: {err}"
        logger.warning("promote_warm %s: %s", _pid, _result["reason"])
        return _result
    if not _groups:
        _result["reason"] = "asg_not_found"
        return _result
    _g = _groups[0]
    _desired = int(_g.get("DesiredCapacity") or 0)
    _max = int(_g.get("MaxSize") or 0)
    _result["desired_before"] = _desired
    _result["max_size"] = _max

    # At MaxSize there is nowhere to put the promoted member. Report it rather
    # than calling and letting AWS clamp silently.
    if _desired >= _max:
        _result["reason"] = "at_max_size"
        return _result

    _warm = _warm_state_counts(_name)
    _result["warm_promotable"] = _warm.get("promotable", 0)
    _result["warm_measured"] = bool(_warm.get("measured"))
    if not _warm.get("measured"):
        # Unmeasured is not empty, but it is also not a basis for starting an
        # instance. Refuse and let the caller fall through to a cold launch.
        _result["reason"] = "warm_depth_unmeasured"
        return _result
    if _warm.get("promotable", 0) < 1:
        _result["reason"] = "no_promotable_warm_member"
        return _result

    try:
        _asg.update_auto_scaling_group(
            AutoScalingGroupName=_name, DesiredCapacity=_desired + 1
        )
    except Exception as err:
        _result["reason"] = f"update_auto_scaling_group failed: {err}"
        logger.warning("promote_warm %s: %s", _pid, _result["reason"])
        return _result

    _result["promoted"] = True
    _result["desired_after"] = _desired + 1
    _result["reason"] = "promoted"
    logger.info(
        "promote_warm %s: desired %d -> %d on %s (promotable warm was %d)",
        _pid,
        _desired,
        _desired + 1,
        _name,
        _warm.get("promotable", 0),
    )
    return _result


def _reap_ledger():
    """Ledger-hygiene sweep (scheduled only). Removes:
      * AVAILABLE rows whose EC2 instance no longer exists/running (stale --
        would otherwise be claimed and fail),
      * WARMED rows whose EC2 instance no longer exists at all (a parked warm
        reserve is SUPPOSED to be stopped, so "not running" is not stale here),
        and
      * stale CLAIMED/RESERVED rows older than the abandon window (the member
        left the pool at claim; the detached desktop is a normal VDI reaped by
        the standard lifecycle).

    The abandon window is per-pool: connect_abandon_timeout_seconds from the
    pool config when set, else _REAP_ABANDON_SECONDS. Before this read the
    setting was validated, stored and rendered back into the admin form while
    no consumer existed, so it did nothing.

    Pure DDB + EC2 (Filters, so missing IDs don't error); no DB access."""
    _name = f"{CLUSTER_ID}-vdi-pool-ledger"
    try:
        _rows = _ddb.Table(_name).scan().get("Items", [])
    except Exception as err:
        logger.warning("ledger reap scan failed: %s", err)
        return
    if not _rows:
        return

    # Per-pool abandon windows. Best-effort: a config read failure falls the
    # whole sweep back to the default window rather than skipping hygiene.
    _windows = {}
    try:
        for _pid, _d in _read_desired().items():
            _w = _d.get("connect_abandon_timeout_seconds")
            if _w:
                _windows[_pid] = _w
    except Exception as err:
        logger.warning(
            "ledger reap could not read per-pool abandon windows, "
            "using default %ds: %s",
            _REAP_ABANDON_SECONDS,
            err,
        )

    # Describe every row whose instance identity matters. AVAILABLE rows are
    # pruned when the instance is not pending/running (a stopped member is not
    # claimable). WARMED rows are the opposite case: the member is SUPPOSED to
    # be stopped, so they are pruned only when the instance no longer exists at
    # all -- hence two sets from one describe rather than one.
    _describe_ids = [
        r["sk"] for r in _rows if r.get("status") in ("AVAILABLE", "WARMED")
    ]
    _running = set()
    _exists = set()
    _describe_ok = True
    for _i in range(0, len(_describe_ids), 100):
        _batch = _describe_ids[_i : _i + 100]
        try:
            _resp = _ec2.describe_instances(
                Filters=[{"Name": "instance-id", "Values": _batch}]
            )
            for _res in _resp.get("Reservations", []):
                for _inst in _res.get("Instances", []):
                    _state = _inst.get("State", {}).get("Name")
                    if _state != "terminated":
                        _exists.add(_inst["InstanceId"])
                    if _state in ("pending", "running"):
                        _running.add(_inst["InstanceId"])
        except Exception as err:
            logger.warning("ledger reap describe failed: %s", err)
            _describe_ok = False  # skip state-based pruning to avoid false deletes

    _now = datetime.now(timezone.utc)
    _table = _ddb.Table(_name)
    _deleted = 0
    for _r in _rows:
        _st = _r.get("status")
        _stale = False
        if _st == "AVAILABLE":
            if _describe_ok and _r["sk"] not in _running:
                _stale = True
        elif _st == "WARMED":
            # A parked warm reserve: stopped is its NORMAL state, so only a
            # vanished (terminated) instance makes the row stale. Pruning on
            # "not running" here would delete every healthy warm member's row
            # on the first sweep.
            if _describe_ok and _r["sk"] not in _exists:
                _stale = True
        elif _st in ("CLAIMED", "RESERVED"):
            _ts = _parse_ts(
                _r.get("reserved_at") or _r.get("claimed_at") or _r.get("registered_at")
            )
            _window = _windows.get(_r.get("pk"), _REAP_ABANDON_SECONDS)
            if _ts and (_now - _ts).total_seconds() > _window:
                _stale = True
        if _stale:
            try:
                _table.delete_item(Key={"pk": _r["pk"], "sk": _r["sk"]})
                _deleted += 1
            except Exception:
                pass
    if _deleted:
        logger.info("ledger reap: removed %d stale rows", _deleted)


def _teardown():
    """Delete ALL tag-managed pool resources (uninstall). They are runtime-created
    and NOT in the CFN stack, so they would orphan otherwise. HARD-deletes (no
    reaper is coming) and also terminates claimed/detached desktops the ASG
    delete would miss."""
    actual = _discover_actual()
    for _pid, _g in actual.items():
        _name = _g["AutoScalingGroupName"]
        try:
            _asg.delete_warm_pool(AutoScalingGroupName=_name, ForceDelete=True)
        except Exception:
            pass  # no warm pool to remove
        try:
            # ForceDelete terminates all members and skips the drain wait.
            _asg.delete_auto_scaling_group(
                AutoScalingGroupName=_name, ForceDelete=True
            )
        except Exception as exc:
            logger.exception("teardown ASG %s failed: %s", _pid, exc)
        try:
            _cw.delete_alarms(AlarmNames=[f"{SCHED_PREFIX}collision-{_pid}"])
        except Exception:
            pass
    # Detached/claimed desktops are no longer ASG members but still carry the
    # propagated edh:managed_by + edh:ClusterId instance tags -- terminate them
    # so a torn-down cluster leaves no running pool-launched instances.
    _orphans = _discover_pool_instances()
    if _orphans:
        try:
            # SkipOsShutdown: pool instances are disposable -> force terminate.
            # Fallback for older boto3 that doesn't know the param.
            try:
                _ec2.terminate_instances(InstanceIds=_orphans, SkipOsShutdown=True)
            except (_ec2.exceptions.ClientError, ParamValidationError, TypeError) as _sk_err:
                logger.info("terminate SkipOsShutdown unsupported (%s); retrying graceful", _sk_err)
                _ec2.terminate_instances(InstanceIds=_orphans)
            logger.info("teardown terminated %d detached pool instance(s)", len(_orphans))
        except Exception as exc:
            logger.exception("teardown terminate detached instances failed: %s", exc)
    try:
        _lts = _ec2.describe_launch_templates(
            Filters=[
                {"Name": f"tag:{MANAGED_TAG_KEY}", "Values": [MANAGED_TAG_VALUE]},
                {"Name": f"tag:{CLUSTER_TAG_KEY}", "Values": [CLUSTER_ID]},
            ]
        ).get("LaunchTemplates", [])
        for _lt in _lts:
            _ec2.delete_launch_template(
                LaunchTemplateId=_lt["LaunchTemplateId"]
            )
    except Exception as exc:
        logger.exception("teardown launch templates failed: %s", exc)
    logger.info(
        "vdi-pool teardown complete: %d ASGs removed, %d detached instances",
        len(actual),
        len(_orphans),
    )
    return {"torn_down": list(actual.keys()), "detached_terminated": _orphans}


def _discover_pool_instances():
    """Instance IDs (running/pending/stopped) tagged as this cluster's pool
    members -- including desktops detached from their ASG on claim. Used by
    teardown to terminate stragglers the ASG delete would miss."""
    _ids = []
    try:
        _pager = _ec2.get_paginator("describe_instances")
        for _page in _pager.paginate(
            Filters=[
                {"Name": f"tag:{MANAGED_TAG_KEY}", "Values": [MANAGED_TAG_VALUE]},
                {"Name": f"tag:{CLUSTER_TAG_KEY}", "Values": [CLUSTER_ID]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                },
            ]
        ):
            for _r in _page.get("Reservations", []):
                for _i in _r.get("Instances", []):
                    _ids.append(_i["InstanceId"])
    except Exception as exc:
        logger.exception("discover pool instances failed: %s", exc)
    return _ids


def _cfn_respond(event, context, status, data=None, reason=None):
    """Send a CloudFormation custom-resource response to the pre-signed URL.
    Must always answer or the stack create/delete hangs until timeout."""
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason
            or f"See CloudWatch log stream: {getattr(context, 'log_stream_name', '')}",
            "PhysicalResourceId": event.get("PhysicalResourceId")
            or f"vdi-pool-teardown-{CLUSTER_ID}",
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "Data": data or {},
        }
    ).encode("utf-8")
    _req = urllib.request.Request(
        event["ResponseURL"],
        data=body,
        method="PUT",
        headers={"content-type": "", "content-length": str(len(body))},
    )
    urllib.request.urlopen(_req, timeout=15, context=ssl.create_default_context())


def _handle_cfn_event(event, context):
    """CFN custom-resource entry point for the teardown hook. The pool ASGs/
    warm pools/LTs are created out-of-band by this reconciler (not CFN), so a
    stack delete would orphan them. This resource fires teardown on Delete.

    Create/Update are no-ops (the periodic reconcile owns provisioning). Delete
    ALWAYS answers SUCCESS even on partial failure -- a FAILED Delete wedges the
    whole stack deletion, which is worse than a leak; the tag/registry janitor
    is the backstop for anything teardown misses."""
    _rt = event.get("RequestType")
    try:
        if _rt == "Delete":
            _result = _teardown()
            _cfn_respond(event, context, "SUCCESS", _result)
        else:
            # Create / Update: nothing to do here.
            _cfn_respond(event, context, "SUCCESS", {"noop": _rt})
    except Exception as _e:  # noqa: BLE001 -- must always answer CFN
        logger.exception("VdiPool teardown custom resource failed (RequestType=%s)", _rt)
        if _rt == "Delete":
            # Never block stack deletion on a best-effort cleanup failure.
            _cfn_respond(event, context, "SUCCESS", {"error": str(_e), "best_effort": True})
        else:
            _cfn_respond(event, context, "FAILED", reason=str(_e))


def lambda_handler(event, context):
    event = event or {}

    # CloudFormation custom-resource invocation (teardown hook) -- distinguished
    # by the RequestType/ResponseURL envelope CFN sends (vs the EventBridge
    # schedule and the web-tier API invoke, which send {"action": ...}).
    if "RequestType" in event and "ResponseURL" in event:
        return _handle_cfn_event(event, context)

    action = event.get("action", "reconcile")
    logger.info("VdiPoolReconciler invoked: action=%s cluster=%s", action, CLUSTER_ID)

    if not CLUSTER_ID:
        logger.error("EDH_CLUSTER_ID not set; aborting")
        return {"ok": False, "error": "EDH_CLUSTER_ID not set"}

    if action == "teardown":
        return {"ok": True, **_teardown()}

    if action == "recycle":
        # Manual burn-down + relaunch of a stack's pool members onto the current
        # LT (admin "Recycle pool" button). No stack_id -> recycle ALL pools.
        return {"ok": True, "recycled": _recycle_stack(event.get("stack_id"))}

    if action == "promote_warm":
        # Warm-claim kick, invoked by the web tier's PoolAllocator. Does NOT
        # run a reconcile: raising desired is the whole operation, and running
        # the declarative reconcile here would immediately set desired back to
        # the configured hot_count and undo it.
        _sid = event.get("stack_id")
        _itype = event.get("instance_type")
        if _sid is None or not _itype:
            return {
                "ok": False,
                "error": "promote_warm requires stack_id and instance_type",
            }
        return {"ok": True, **_promote_warm(_sid, _itype)}

    _stack_id = event.get("stack_id")
    _result = _reconcile(stack_id=_stack_id)
    # Ledger hygiene + tombstone reaping only on the periodic full sweep
    # (not per-stack applies).
    if _stack_id is None:
        _reap_ledger()
        _desired_pids = set(
            _result.get("create", [])
            + _result.get("update", [])
            + _result.get("deferred", [])
        )
        _reap_tombstoned_asgs(_desired_pids)
    return {"ok": True, **_result}
