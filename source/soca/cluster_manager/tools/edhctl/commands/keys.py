# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
edhctl keys -- report on the KMS keys THIS cluster uses.

SCOPE, and it is bounded by what the cluster is connected to rather than by a
scan. Two sources, both specific to this cluster:

  1. keys tagged edh:ClusterId for this cluster -- the keys EDH created
  2. keys named in this cluster's own configuration -- the keys the customer
     told EDH to use

Nothing else is looked at. kms:ListKeys is deliberately not used and not
granted: enumerating every key in the account is how a per-cluster tool ends up
reporting on another team's resources, and no other edhctl subcommand does that.

    edhctl keys report                      this cluster's keys
    edhctl keys report -v                   full ids, ARNs, tags, rotation, dates
    edhctl keys report --reclaimable-only    just the keys nothing uses
    edhctl keys report --output json        machine readable

STATES.

    in-use            holds this cluster's alias, or is this cluster's only key
    superseded        an earlier build of this cluster left it behind: a sibling
                      key holds the alias and this one holds none. Reclaimable,
                      and it is this operator's own cluster, so the remedy is
                      theirs to run
    customer-key      named in this cluster's configuration, readable, and not
                      EDH created. Its lifecycle is its owner's business, so it
                      is reported and never called reclaimable
    pending-deletion  already scheduled, no longer billed, no action
    missing           configuration names a key that does not exist here
    undetermined      a read was denied, so the key could not be classified

WHY THE READS ARE GRANTED ON Resource "*" AND NOT TAG SCOPED. A customer may
add the EDH controller role to their own key's key policy by hand, which is the
documented way to let EDH use a key EDH did not create. That key carries the
customer's tags and not edh:ClusterId, so an IAM read grant conditioned on
aws:ResourceTag/edh:ClusterId denies it -- and because KMS requires BOTH the
identity policy and the key policy to allow, the identity denial makes the
customer's manual grant useless. Confirmed by simulation: the controller's
tag-conditioned reads returned implicitDeny with no matched statements against
an untagged key, whatever that key's policy says.

So the reads are unconditioned, and for KMS specifically that is a smaller
concession than it looks: the identity policy is not the boundary, the key
policy is. An IAM grant on "*" confers nothing on a key whose policy does not
name the principal. It is not nothing, though, and the honest statement is
this: a key carrying the common root delegation statement
(Principal: account root, Action: kms:*) becomes READABLE by the controller --
metadata and key policy, never key material and never plaintext. Both
non-EDH customer keys in the test account carry that statement, so this is the
normal case rather than the exception.

WRITES ARE A DIFFERENT QUESTION and are not in this change. Rotation writes
must be tag scoped, because an unconditioned write grant would let the EDH
controller rotate a customer key that also protects non-EDH workloads. And the
controller must NEVER hold kms:TagResource or kms:UntagResource on keys: with
tag-based authorization a principal that can write the tag can widen its own
authorization, so the tag is written by CloudFormation at create time and by
nothing else.

WHY A FAILED READ IS NEVER A FINDING. KMS answers AccessDeniedException rather
than an empty result when a caller is not permitted, so treating a denial as an
absence would print a deletion recommendation produced by a permissions gap.
Every denial lands in `undetermined` and is never reclaimable. The denial cause
is reported because it says WHO must act: a cause naming the identity policy is
an EDH gap and our bug to fix, one naming the key policy needs the key's owner
to add the controller role, and an explicit deny means the owner excluded EDH
deliberately and should not be asked again.

REGION. KMS keys are regional and this reports the cluster's own region. Nothing
is deleted: kms:ScheduleKeyDeletion is not in the controller's grant, and the
remedy is printed for an administrator to run.
"""

import logging
from datetime import datetime, timezone

import click
from botocore.exceptions import ClientError

from commands.common import get_cluster_id, print_output
from utils.aws import boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

# The tag the EDH app-level tagging aspect puts on every resource CloudFormation
# creates for a cluster, and the only thing that makes a key discoverable and
# readable here. An IMPORTED key never receives it, because an imported key is
# not a stack resource -- which is also what a customer's own key looks like.
_CLUSTER_TAG = "edh:ClusterId"

# Set by some EDH resources and not others -- the four AI Assist keys in the
# test account carried edh:Component=AIAssist while the DCV TLS and peer-probe
# keys did not. Used only as a label source, never for classification, because
# a tag present on some keys of the same kind cannot decide anything.
_COMPONENT_TAG = "edh:Component"

# Key storage is $1/month per customer managed key, prorated hourly. Rotation
# adds $1/month for the first rotation and $1/month for the second, and is not
# billed beyond that. Used only to put a number on the report; it is not a quote.
_USD_PER_KEY_MONTH = 1.0
_USD_PER_ROTATION_MONTH = 1.0
_MAX_BILLED_ROTATIONS = 2

# A key already scheduled for deletion is not billed and needs no action.
_PENDING_STATES = ("PendingDeletion", "PendingReplicaDeletion")

# Config values naming an AWS managed alias are not customer managed keys, cost
# nothing and cannot be rotated or deleted by the customer, so they are not
# reported as configured CMK references. Two volume_kms_key_id keys ship with
# alias/aws/ebs as their default, so without this every cluster would list them.
_AWS_MANAGED_ALIAS_PREFIX = "alias/aws/"

# Any config key ending in this names a CMK for some EDH resource. Matched on
# the suffix rather than on a fixed list of paths so that volume_kms_key_id is
# included and a config key added later is not silently missed.
_CONFIG_KEY_SUFFIX = "kms_key_id"

# A multi-Region key id is this prefix followed by 32 hex characters, so it is
# 36 characters long like a UUID but carries a single hyphen rather than four.
# AWS documents the prefix as the way to identify an MRK programmatically.
_MRK_PREFIX = "mrk-"

# Tail _denial_cause appends when the KMS error code is not AccessDeniedException
# -- a retryable server fault such as KMSInternalException. Shared with the
# advice classifier so the two cannot drift: the advice for a fault is the
# opposite of the advice for a denial, and matching on a literal spelled out in
# both places is how that pairing silently breaks.
_NOT_A_DENIAL = "(not a denial)"

_STATE_IN_USE = "in-use"
_STATE_SUPERSEDED = "superseded"
_STATE_PENDING = "pending-deletion"
_STATE_CUSTOMER = "customer-key"
_STATE_MISSING = "missing"
_STATE_UNDETERMINED = "undetermined"

_STATE_ORDER = (
    _STATE_SUPERSEDED,
    _STATE_IN_USE,
    _STATE_CUSTOMER,
    _STATE_PENDING,
    _STATE_MISSING,
    _STATE_UNDETERMINED,
)

# Where a key came into the report from. Both sources are specific to this
# cluster; neither enumerates the account.
_SOURCE_EDH = "edh-tag"
_SOURCE_CONFIG = "config"
_SOURCE_BOTH = "edh-tag+config"

# Whether the controller can read a key, which is the question a customer
# supplied key actually raises. Reported per key rather than per report: KMS
# authorizes per action, so a customer can grant some reads and not others.
_ACCESS_OK = "readable"
_ACCESS_DENIED = "denied"
_ACCESS_ABSENT = "not-found"


@click.group()
def keys():
    """Report on the KMS keys protecting this cluster's resources."""
    pass


def _build_client(service_name: str, output: str = "text"):
    """Return a boto client, exiting with a readable message if it cannot be built.

    output is threaded in so a report asked for as JSON fails as JSON too.
    print_output writes to stdout, so an error path pinned to text puts prose
    into the stream the caller is parsing.
    """
    _response = utils_boto3.get_boto(service_name=service_name)
    if _response.get("success") is False:
        print_output(
            message=(
                f"Unable to create a {service_name} client: {_response.get('message')}"
            ),
            output=output,
            error=True,
        )
    return _response.get("message")


def _denial_cause(err: ClientError) -> str:
    """Name which gate refused a KMS call, or the fault if it was not refused.

    KMS answers AccessDeniedException for all three denial causes and only the
    message text differs, so the gate attribution is best-effort enrichment over
    a reliable "undetermined" base and never the branch any decision depends on.
    AWS can reword these strings without notice. Verified against a
    purpose-built key: an identity gap, a key policy omitting the action, and a
    key policy carrying an explicit deny each produced a distinct message tail
    under one code.

    The code is checked before the message because not every failure is a
    denial. KMS documents DependencyTimeoutException and KMSInternalException as
    retryable server faults, and reporting one of those as "access denied" sends
    the operator to repair IAM that is not broken.

    Both fields were cast with str() before. The cast is a no-op on every real
    response because botocore populates them as strings, and it is the wrong
    tool for the one case it would cover: str(None) and
    SocaCastEngine(None).cast_as(str) both succeed with the literal "None",
    which this function then reported as a KMS error code named None and
    classified as "not a denial". _code is validated by the is_string_not_empty
    check below, so it needs no separate guard. _message does, because it is
    tested with `in` -- which raises TypeError on a non-string and would cost
    the whole report rather than this one key's attribution.
    """
    _error = err.response.get("Error", {})
    _code = _error.get("Code", "")
    _message = _error.get("Message", "")
    if not Validators.is_string(_message):
        _message = ""
    if Validators.is_string_not_empty(_code) and _code != "AccessDeniedException":
        return f"{_code} {_NOT_A_DENIAL}"
    if "no identity-based policy allows" in _message:
        return "controller IAM is missing the action"
    if "explicit deny in a resource-based policy" in _message:
        return "key policy explicitly denies EDH"
    if "no resource-based policy allows" in _message:
        return "key policy does not grant EDH the action"
    return "access denied"


def _discover_this_clusters_keys(tagging_client, cluster_id: str) -> list:
    """Find the KMS keys tagged for this cluster, and only those.

    A server-side tag filter rather than ListKeys plus a client-side test:
    another cluster's key is never returned at all, so the report cannot leak
    one through a filtering bug, and the account is never enumerated.

    This is discovery, not authorization. The reads are NOT tag conditioned --
    see the module docstring -- because a customer's manually granted key
    carries none of EDH's tags and a tag condition on the identity policy would
    make that grant unusable.

    The response carries the full tag set, so no per-key ListResourceTags call
    is needed and that action is not in the controller's grant.
    """
    _rows = []
    _paginator = tagging_client.get_paginator("get_resources")
    for _page in _paginator.paginate(
        ResourceTypeFilters=["kms"],
        TagFilters=[{"Key": _CLUSTER_TAG, "Values": [cluster_id]}],
    ):
        for _entry in _page.get("ResourceTagMappingList", []):
            _arn = _entry.get("ResourceARN", "")
            _tags = {
                _t.get("Key"): _t.get("Value") for _t in _entry.get("Tags", [])
            }
            _rows.append(
                {
                    "key_id": _arn.rsplit("/", 1)[-1],
                    "arn": _arn,
                    "tags": _tags,
                    "cluster_id": _tags.get(_CLUSTER_TAG),
                    "aliases": [],
                    "source": _SOURCE_EDH,
                    "config_keys": [],
                    "access": _ACCESS_OK,
                    "access_detail": None,
                    "undetermined_reason": None,
                }
            )
    return _rows


def _configured_key_values() -> list:
    """The CMKs this cluster's configuration tells EDH to use.

    Returned as (config_key, value) pairs and not resolved here. The value may
    be a key id, a key ARN, an alias or an alias ARN -- DescribeKey accepts all
    four, so the probe resolves it rather than this parser guessing.

    AWS managed aliases are excluded: two volume_kms_key_id config keys default
    to alias/aws/ebs, which is not a customer managed key, costs nothing and
    cannot be rotated or deleted by the customer. Without this exclusion every
    cluster would report two keys it does not own and cannot act on.

    Matched on the kms_key_id suffix rather than a fixed list of config paths,
    so volume_kms_key_id is included and a config key added later is not
    silently missed.
    """
    _found = []
    _response = SocaConfig(key="/").get_value(return_as=dict)
    _parameters = _response.get("message") or {}
    if not Validators.is_dict(_parameters):
        return _found
    for _path, _value in sorted(_parameters.items()):
        if not _path.lower().endswith(_CONFIG_KEY_SUFFIX):
            continue
        # A config value can be None (every kms_key_id ships as ~), so the type
        # is checked before the content rather than assumed.
        if not Validators.is_string(_value):
            continue
        _value = _value.strip()
        # Whitespace-only counts as unset: an unset key is not a reference and
        # must not be looked up, because a blank KeyId is a wasted call.
        if not Validators.is_string_not_empty(_value):
            continue
        if _value.lower().startswith(_AWS_MANAGED_ALIAS_PREFIX):
            continue
        _found.append((_path, _value))
    return _found


def _known_row_for(known: dict, value: str):
    """The already-discovered row this configuration value names, if any.

    Needed because the success path resolves the value through DescribeKey and a
    refused read leaves it unresolved, so a key that is both tagged for this
    cluster and named in its configuration would be reported twice -- once
    undetermined from the tag scan and again undetermined from the probe.

    A key id or key ARN carries the id itself. An alias is matched against the
    alias names already recorded on the discovered rows, which is the one form
    that cannot be resolved without a call.
    """
    if not Validators.is_string_not_empty(value):
        return None
    _value = value.strip()
    _candidate = _value.rsplit("/", 1)[-1] if ":key/" in _value else _value
    if _candidate in known:
        return known[_candidate]
    _alias = _value.rsplit(":", 1)[-1] if _value.startswith("arn:") else _value
    if not _alias.startswith("alias/"):
        return None
    for _row in known.values():
        if _alias in (_row.get("aliases") or []):
            return _row
    return None


def _probe_configured_keys(kms_client, configured: list, known: dict) -> list:
    """Find out what the controller can actually read of each configured key.

    This is the whole point of reading configuration rather than only tags. A
    customer may add the EDH controller role to their own key's key policy by
    hand, and when they have, EDH can read that key even though it carries none
    of EDH's tags and no tag filter can discover it. Asking is the only way to
    know: the answer depends on a resource policy EDH does not own and cannot
    predict.

    Three outcomes, never two. DescribeKey either succeeds, is refused, or
    reports the key does not exist -- and a refusal is further attributed to the
    gate that refused, because that says who must act.

    `known` maps an already-discovered key id to its row, so a key that is BOTH
    tagged for this cluster and named in its configuration is annotated rather
    than listed twice. That is the opt-in case: a customer who tags their own
    key so the controller's write grants will reach it.

    `_unresolved` does the same job for the two outcomes that leave the value
    unresolved. A refused or absent key has no key id to dedupe on, so the raw
    configuration value is the handle, and one CMK protecting two services --
    one key named by two config keys -- is reported as one row naming both
    rather than two rows double-counting it. Keying on the raw value is the
    honest limit: two different spellings of the same refused key cannot be
    recognized as one, because resolving them is the call that was refused.
    """
    _rows = []
    _unresolved = {}
    for _config_key, _value in configured:
        _seen = _unresolved.get(_value)
        if _seen is not None:
            # Same unresolved value, already reported. Record that this config
            # key names it too; without this the report carries a row per
            # reference rather than per key, and keys_unreadable counts one key
            # as several.
            _seen.setdefault("config_keys", []).append(_config_key)
            continue
        try:
            _meta = kms_client.describe_key(KeyId=_value).get("KeyMetadata", {})
        except ClientError as _err:
            _code = _err.response.get("Error", {}).get("Code", "")
            if _code in ("NotFoundException", "InvalidArnException"):
                # Configuration names a key that is not here. Reported rather
                # than skipped: whatever EDH was told to encrypt with it is
                # either failing or silently falling back.
                _row = {
                    "key_id": _value,
                    "arn": "",
                    "tags": {},
                    "aliases": [],
                    "source": _SOURCE_CONFIG,
                    "config_keys": [_config_key],
                    "access": _ACCESS_ABSENT,
                    "state": _STATE_MISSING,
                    "undetermined_reason": None,
                    "access_detail": f"DescribeKey: {_code or 'not found'}",
                }
                _rows.append(_row)
                _unresolved[_value] = _row
                continue
            _denied = _known_row_for(known, _value)
            if _denied is not None:
                # Same key, already reported undetermined by the tag scan. The
                # refusal left the value unresolved, so without this the report
                # would carry two rows for one physical key.
                _denied["source"] = _SOURCE_BOTH
                _denied.setdefault("config_keys", []).append(_config_key)
                _unresolved[_value] = _denied
                continue
            _row = {
                "key_id": _value,
                "arn": "",
                "tags": {},
                "aliases": [],
                "source": _SOURCE_CONFIG,
                "config_keys": [_config_key],
                "access": _ACCESS_DENIED,
                "state": _STATE_UNDETERMINED,
                "undetermined_reason": f"DescribeKey: {_denial_cause(_err)}",
                "access_detail": f"DescribeKey: {_denial_cause(_err)}",
            }
            _rows.append(_row)
            _unresolved[_value] = _row
            continue

        _key_id = _meta.get("KeyId", _value)
        _existing = known.get(_key_id)
        if _existing is not None:
            # Already found by tag. Record that configuration names it too and
            # leave its classification alone -- it is an EDH key either way.
            _existing["source"] = _SOURCE_BOTH
            _existing.setdefault("config_keys", []).append(_config_key)
            continue

        _row = {
            "key_id": _key_id,
            "arn": _meta.get("Arn", ""),
            "tags": {},
            # The alias read failure is dropped here on purpose: a config row's
            # state comes from the probe, never from the alias comparison.
            "aliases": _aliases_for(kms_client, _meta.get("Arn") or _key_id)[0],
            "source": _SOURCE_CONFIG,
            "config_keys": [_config_key],
            "access": _ACCESS_OK,
            "key_manager": _meta.get("KeyManager"),
            "key_state": _meta.get("KeyState"),
            "description": _meta.get("Description") or "",
            "created": _meta.get("CreationDate"),
            "deletion_date": _meta.get("DeletionDate"),
            "key_spec": _meta.get("KeySpec"),
            "origin": _meta.get("Origin"),
            "multi_region": _meta.get("MultiRegion"),
            "undetermined_reason": None,
            "access_detail": None,
        }
        # Pending deletion outranks everything: a configured key on its way out
        # means this cluster is about to lose the key it encrypts with, which is
        # a sharper fact than who manages it.
        if _row["key_state"] in _PENDING_STATES:
            _row["state"] = _STATE_PENDING
        else:
            _row["state"] = _STATE_CUSTOMER
        # Rotation count is only billed on customer managed keys, and an AWS
        # managed key reached through config costs nothing.
        if _row["key_manager"] == "CUSTOMER":
            _row["rotations_billed"] = _rotations_billed(
                kms_client, _meta.get("Arn") or _key_id
            )
        _rows.append(_row)
        known[_key_id] = _row
    return _rows


def _aliases_for(kms_client, key_arn: str) -> tuple:
    """The aliases pointing at one key, and why the read failed if it did.

    Asked per key rather than account-wide, so the call names a key this cluster
    already owns. kms:ListAliases itself cannot be tag-conditioned -- KMS
    aliases are not a taggable resource, confirmed by ListResourceTags refusing
    an alias ARN with "Key Aliases are not supported for this operation" -- so
    the grant is unconditioned, and it returns alias names and target key ids
    only, no key metadata and no key policy.

    The failure is returned rather than swallowed because an empty alias list is
    what makes a key `superseded`, and a key whose alias read failed must not be
    called reclaimable on the strength of a read that did not happen.
    """
    _names = []
    try:
        _paginator = kms_client.get_paginator("list_aliases")
        for _page in _paginator.paginate(KeyId=key_arn):
            for _alias in _page.get("Aliases", []):
                _names.append(_alias.get("AliasName", ""))
    except ClientError as _err:
        logger.warning(f"Unable to list aliases for {key_arn}: {_err}")
        return [], f"ListAliases: {_denial_cause(_err)}"
    return sorted(_names), None


def _rotations_billed(kms_client, key_arn: str) -> int:
    """How many rotations of this key are being billed, capped at two.

    Reported because a rotated key costs more than $1/month, so a superseded key
    that has been rotating for two years is three times the waste of a fresh one.
    """
    try:
        _rotations = kms_client.list_key_rotations(KeyId=key_arn).get("Rotations", [])
    except ClientError:
        return 0
    # Validators bundles the type check with the comparison, which matters
    # because this runs OUTSIDE the except above: a response whose Rotations is
    # not a list would otherwise raise TypeError from len() and cost the whole
    # report, rather than this one key's rotation count.
    if not Validators.is_list(_rotations):
        return 0
    if Validators.is_list_length_greater_equal_than(_rotations, _MAX_BILLED_ROTATIONS):
        return _MAX_BILLED_ROTATIONS
    return len(_rotations)


def _describe_keys(kms_client, rows: list) -> list:
    """Fill in each key's metadata, aliases and rotation count.

    Each key is described independently and a denial is recorded on that key
    rather than aborting, because one unreadable key must not cost the report
    every other key. A key EDH created can still be unreadable if its key policy
    was edited afterwards.
    """
    for _row in rows:
        try:
            _meta = kms_client.describe_key(KeyId=_row["arn"]).get("KeyMetadata", {})
        except ClientError as _err:
            _row.update(
                {
                    "key_manager": None,
                    "key_state": None,
                    "description": "",
                    "access": _ACCESS_DENIED,
                    "access_detail": f"DescribeKey: {_denial_cause(_err)}",
                    "undetermined_reason": f"DescribeKey: {_denial_cause(_err)}",
                }
            )
            # Aliases are still worth asking for: ListAliases is authorized by
            # the identity policy alone, so a key policy that refuses
            # DescribeKey does not refuse this. It is the only name such a row
            # can carry, and it is what matches the key against a configured
            # alias when the probe cannot resolve one.
            _row["aliases"], _ = _aliases_for(kms_client, _row["arn"])
            continue

        _row.update(
            {
                "key_manager": _meta.get("KeyManager"),
                "key_state": _meta.get("KeyState"),
                "description": _meta.get("Description") or "",
                "created": _meta.get("CreationDate"),
                # DescribeKey returns DeletionDate on a pending key, which is
                # how long is left to call CancelKeyDeletion. It does NOT return
                # PendingWindowInDays -- that is an input to ScheduleKeyDeletion
                # only -- so the remaining window is derived from this date.
                "deletion_date": _meta.get("DeletionDate"),
                "key_spec": _meta.get("KeySpec"),
                "origin": _meta.get("Origin"),
                "multi_region": _meta.get("MultiRegion"),
            }
        )
        # Every discovered key is customer managed by construction: discovery is
        # a tag filter, and an AWS managed key cannot carry edh:ClusterId
        # because KMS does not permit tagging one. So there is no KeyManager
        # branch here -- a guard for a state the discovery cannot produce would
        # read as a safeguard while adding none.
        _row["aliases"], _row["alias_read_failed"] = _aliases_for(
            kms_client, _row["arn"]
        )
        _row["rotations_billed"] = _rotations_billed(kms_client, _row["arn"])
    return rows


def _classify(rows: list) -> list:
    """Assign a state to the EDH-created keys, which are the tag-discovered ones.

    Keys reached through configuration are classified by the probe instead: the
    lifecycle states here are EDH's own build history, and a customer's key has
    none. Calling someone else's key `superseded` would be a deletion
    recommendation for a resource EDH does not own.

    No CloudFormation lookup. Every row is tagged for the cluster edhctl is
    running on, and that cluster is live by construction, so there is nothing to
    correlate against a stack list.

    Ordered so that no state is reached by inference from a failed read: an
    undetermined key is settled before anything that would make it reclaimable.
    """
    # Derived from LIVE, READABLE keys only. Two kinds of row would otherwise
    # lend their alias to this test and make a sibling reclaimable:
    #
    #   - a key pending deletion. KMS deletes a key's aliases only when the
    #     waiting period ENDS, so for 7 to 30 days a scheduled key still holds
    #     its alias. An operator who schedules the aliased key by hand would
    #     then see the live key that holds no alias reported superseded.
    #   - a key whose DescribeKey was refused. _describe_keys still reads its
    #     aliases, because ListAliases is authorized by the identity policy
    #     alone, so an unreadable key can carry one.
    #
    # In both cases the surviving key is the one still in use, and the state
    # printed alongside `superseded` is a schedule-key-deletion command.
    _any_alias = any(
        _r.get("aliases")
        for _r in rows
        if _r.get("key_state") not in _PENDING_STATES
        and not _r.get("undetermined_reason")
    )

    for _row in rows:
        # Pending deletion is settled first, and only because DescribeKey
        # SUCCEEDED for it: the key is on its way out and is no longer billed,
        # so it needs no action whether or not anything else can be read.
        # When DescribeKey itself was denied, key_state is None and the
        # undetermined branch below catches it.
        if _row.get("key_state") in _PENDING_STATES:
            _row["state"] = _STATE_PENDING
            continue
        if _row.get("undetermined_reason"):
            _row["state"] = _STATE_UNDETERMINED
            continue
        # A failed alias read cannot distinguish superseded from in-use, and the
        # empty list it returns is the input to that very test. Settled as
        # undetermined rather than guessed, so a transient ListAliases error --
        # KMS answers it with a retryable 500 as well as an authorization
        # refusal -- never prints a schedule-key-deletion command.
        if _row.get("alias_read_failed"):
            _row["state"] = _STATE_UNDETERMINED
            _row["undetermined_reason"] = _row["alias_read_failed"]
            _row["access_detail"] = _row["alias_read_failed"]
            continue

        # A key sharing this cluster with a sibling that holds an alias, while
        # holding none itself, is a previous build's key: the alias moved to the
        # newer key and this one is attached to nothing. The test is relative
        # within the cluster, so it stays silent for a cluster whose keys never
        # had aliases at all.
        #
        # There is deliberately no row-count clause here. `_any_alias` already
        # makes a single-key cluster unreachable: one key either holds the alias
        # (so the first test fails) or does not (so _any_alias is False). A
        # `len(rows) > 1` guard was removed after mutation testing showed it
        # could be inverted without any test noticing, which is the signature of
        # a clause that cannot change the outcome.
        if not _row.get("aliases") and _any_alias:
            _row["state"] = _STATE_SUPERSEDED
            continue

        _row["state"] = _STATE_IN_USE

    return rows


def _monthly_cost(rows: list) -> float:
    """Monthly storage cost of the keys given, rotation included."""
    _total = 0.0
    for _row in rows:
        _total += _USD_PER_KEY_MONTH
        _total += _row.get("rotations_billed", 0) * _USD_PER_ROTATION_MONTH
    return _total


def _short_id(key_id: str) -> str:
    """A key id shortened to its distinguishing head, for the table's KEY column.

    The full id is in --verbose, in --output json and in every remediation
    command printed, since KMS does not accept a truncated key id.

    Two id shapes exist and they shorten differently:

      UUID   c3ae58cb-0213-4c19-8cd8-170568a2ec41 -- 36 characters, 4 hyphens.
             The first segment is what the console and the key ARN both lead
             with, so eight characters is the natural head.
      MRK    mrk-1234abcd12ab34cd56ef1234567890ab -- a multi-Region key, also
             36 characters but with a single hyphen, so the UUID test rejects
             it. The "mrk-" prefix is identical on every multi-Region key and
             carries no information, so the eight characters are taken AFTER
             it and the prefix is kept as the signal that this key exists in
             more than one region.

    An MRK reaches this report through the configured-key probe: EDH creates no
    multi-Region key, but a customer can name one in any kms_key_id config key,
    which is the path the probe exists for. Before the prefix was recognized an
    MRK fell through to the "-" branch and rendered with no identifier at all,
    while _verbose_blocks still labelled it multi-region.

    A value that is neither shape is a configured value EDH could not resolve --
    an alias, or a typo -- and truncating that produced "alias/no" for
    alias/no-such-key-anywhere, which identifies nothing. Such a row shows no
    key id at all, because there is no key, and the configured value is its
    name instead.
    """
    _value = key_id or ""
    if Validators.is_string_length_equal_of(_value, 36):
        if _value.count("-") == 4:
            return _value[:8]
        if _value.startswith(_MRK_PREFIX):
            # Prefix plus eight significant characters, so an MRK is as
            # distinguishable as a UUID row rather than four hex wide. The KEY
            # column is sized from the widest value, so this widens it only in
            # a report that actually contains a multi-Region key.
            return _value[: len(_MRK_PREFIX) + 8]
    if "/" in _value or Validators.is_string_length_greater_than(_value, 8):
        return "-"
    return _value


def _label(row: dict) -> str:
    """A human name for a key, from whatever the account actually carries.

    Four sources in descending reliability, because no single one is present on
    every key in a real account:

      alias          the strongest, and what the console shows -- but only 1 of
                     15 keys in the test account had one, so it cannot be the
                     only source
      Name tag       the general AWS convention. EDH does not set it, but other
                     products in the same account do, and such a key would
                     otherwise show as a bare UUID with nothing beside it
      edh:Component  set on some EDH keys (AIAssist), absent on others
      description    EDH writes a good one ("CMK for the DCV high-scale gateway
                     TLS cert secret (edh-dcvtls1)"), so it is the fallback
                     rather than nothing. Truncated here; full text in --verbose

    A key EDH could not read has none of those, because they all come from a
    call that was refused. For such a row the configured value is the only
    identifying thing there is, and it is what the operator has to go and look
    at, so it is used last rather than leaving the row blank.

    Returns "" when nothing at all is available, which is honest: inventing a
    name from the key id would be noise.
    """
    _aliases = row.get("aliases") or []
    if _aliases:
        # Strip the "alias/" prefix every alias carries; it is the same six
        # characters on every row and costs width that the distinguishing part
        # of the name needs.
        return _aliases[0].removeprefix("alias/")
    _tags = row.get("tags") or {}
    if _tags.get("Name"):
        return _tags["Name"]
    if _tags.get(_COMPONENT_TAG):
        return _tags[_COMPONENT_TAG]
    if row.get("description"):
        return row["description"]
    if row.get("access") in (_ACCESS_DENIED, _ACCESS_ABSENT):
        return row.get("key_id") or ""
    return ""


def _days_until(when) -> int:
    """Whole days from now until a timezone-aware datetime, floored at 0."""
    if when is None:
        return 0
    return max(0, (when - datetime.now(timezone.utc)).days)


def _age_days(when) -> int:
    if when is None:
        return 0
    return max(0, (datetime.now(timezone.utc) - when).days)


def _note(row: dict) -> str:
    """The one fact that matters most for this key's state.

    State-dependent on purpose. A single general-purpose column would have to
    show the same field for every row, and the useful field differs: a pending
    key's is how long is left to cancel, an undetermined key's is which gate
    refused, and a reclaimable key's is what it costs to leave alone.
    """
    _state = row.get("state")
    if _state == _STATE_UNDETERMINED:
        return row.get("undetermined_reason") or "could not read this key"
    if _state == _STATE_MISSING:
        return "configuration names a key that is not in this region"
    if _state == _STATE_CUSTOMER:
        # The useful fact is who manages it and therefore who can rotate it:
        # an AWS managed key cannot be rotated on demand by anyone, and a
        # customer managed one is its owner's to rotate.
        _manager = row.get("key_manager")
        if _manager == "AWS":
            return "AWS managed: rotation and deletion are not yours to control"
        return "customer managed, readable: rotation is the key owner's to run"
    if _state == _STATE_PENDING:
        _date = row.get("deletion_date")
        if _date is None:
            return "scheduled for deletion"
        return (
            f"deletes {_date.strftime('%Y-%m-%d')}, "
            f"{_days_until(_date)}d left to cancel"
        )
    if _state == _STATE_SUPERSEDED:
        _cost = _USD_PER_KEY_MONTH + (
            row.get("rotations_billed", 0) * _USD_PER_ROTATION_MONTH
        )
        return f"{_age_days(row.get('created'))}d old, ${_cost:.0f}/month"
    return ""


def _rotation_detail(kms_client, key_arn: str) -> str:
    """Rotation status as one line, for --verbose only.

    Behind the flag because this is an extra API call per key and the default
    view does not show it.

    Expect "disabled" on every pending-deletion key, and do not read it as a
    defect in this report. Scheduling deletion turns rotation off: a key that
    answered KeyRotationEnabled=true with RotationPeriodInDays=365 answers
    false with no period and no next date once ScheduleKeyDeletion has run.
    Verified on the same key either side of the schedule.

    A denied read returns "unknown" rather than "disabled" for the same reason
    the classification has an undetermined state: reporting a key as unrotated
    when the status could not be read is a false compliance answer.
    """
    try:
        _status = kms_client.get_key_rotation_status(KeyId=key_arn)
    except ClientError as _err:
        return f"unknown ({_denial_cause(_err)})"
    if not _status.get("KeyRotationEnabled"):
        return "disabled"
    _period = _status.get("RotationPeriodInDays")
    _next = _status.get("NextRotationDate")
    _parts = ["enabled"]
    if _period:
        _parts.append(f"every {_period} days")
    if _next:
        _parts.append(f"next {_next.strftime('%Y-%m-%d')}")
    return ", ".join(_parts)


def _table(rows: list) -> list:
    """The default view: one line per key, led by a name rather than a UUID.

    Column widths are computed from the rows actually shown rather than fixed,
    so a cluster whose names are all short does not carry padding for names it
    does not have. NAME is capped because a KMS description can run to 8000
    characters and one long one would push NOTE off the terminal.

    SOURCE is a column rather than a verbose-only field because it decides who
    may act on a row: an edh-tag key is this operator's, a config key is the
    customer's and EDH only reads it.
    """
    _sorted = sorted(rows, key=lambda _r: (_r["state"], _label(_r), _r["key_id"]))

    _key_w = max(8, *(len(_short_id(_r["key_id"])) for _r in _sorted))
    _state_w = max(5, *(len(_r["state"]) for _r in _sorted))
    _src_w = max(6, *(len(_r.get("source") or "-") for _r in _sorted))
    _name_w = min(34, max(4, *(len(_label(_r)) for _r in _sorted)))

    _lines = [
        f"{'KEY':<{_key_w}}  {'STATE':<{_state_w}}  {'SOURCE':<{_src_w}}  "
        f"{'NAME':<{_name_w}}  NOTE"
    ]
    for _row in _sorted:
        _name = _label(_row)
        if Validators.is_string_length_greater_than(_name, _name_w):
            _name = _name[: _name_w - 3] + "..."
        _lines.append(
            f"{_short_id(_row['key_id']):<{_key_w}}  "
            f"{_row['state']:<{_state_w}}  "
            f"{(_row.get('source') or '-'):<{_src_w}}  "
            f"{_name:<{_name_w}}  {_note(_row)}".rstrip()
        )
    return _lines


def _verbose_blocks(kms_client, rows: list) -> list:
    """--verbose: a block per key instead of a row, with the full identifiers.

    A block rather than more columns because the full key id alone is 36
    characters and the ARN is over 70, so any table carrying them wraps and
    becomes less readable than the short form it replaced.
    """
    _lines = []
    for _row in sorted(
        rows, key=lambda _r: (_r["state"], _label(_r), _r["key_id"])
    ):
        _lines.append(f"{_row['key_id']}  [{_row['state']}]")

        def _field(name, value):
            if value:
                _lines.append(f"  {name:<14} {value}")

        _field("name", _label(_row) or None)
        _field("source", _row.get("source"))
        _field("config", "  ".join(_row.get("config_keys") or []))
        _field("access", _row.get("access"))
        _field("arn", _row.get("arn"))
        _field("managed by", _row.get("key_manager"))
        _field("description", _row.get("description"))
        _field("aliases", "  ".join(_row.get("aliases") or []))
        if _row.get("created"):
            _field(
                "created",
                f"{_row['created'].strftime('%Y-%m-%d')} "
                f"({_age_days(_row['created'])} days ago)",
            )
        if _row.get("deletion_date"):
            _field(
                "deletes",
                f"{_row['deletion_date'].strftime('%Y-%m-%d')} "
                f"({_days_until(_row['deletion_date'])} days left to cancel "
                "with kms:CancelKeyDeletion)",
            )
        _spec = [_p for _p in (_row.get("key_spec"), _row.get("origin")) if _p]
        if _row.get("multi_region"):
            _spec.append("multi-region")
        _field("key", "  ".join(_spec))

        # Only reached with --verbose, so the extra API call per key is paid
        # for by a flag rather than on every run. Skipped entirely when
        # DescribeKey was already refused: a second call to the same key can
        # only be refused again, and spending it would turn one denial into two
        # lines of noise.
        if _row.get("access") == _ACCESS_OK and _row.get("arn"):
            _field("rotation", _rotation_detail(kms_client, _row["arn"]))
            _cost = _USD_PER_KEY_MONTH + (
                _row.get("rotations_billed", 0) * _USD_PER_ROTATION_MONTH
            )
            _billed = _row.get("rotations_billed", 0)
            if _row.get("key_manager") == "CUSTOMER":
                _field(
                    "cost",
                    f"${_cost:.2f}/month"
                    + (
                        f" (storage plus {_billed} billed rotation(s))"
                        if _billed
                        else ""
                    ),
                )

        _tags = _row.get("tags") or {}
        if _tags:
            _field(
                "tags",
                "  ".join(f"{_k}={_v}" for _k, _v in sorted(_tags.items())),
            )
        _field("undetermined", _row.get("undetermined_reason"))
        _lines.append("")
    return _lines


@keys.command()
@click.option(
    "--reclaimable-only",
    is_flag=True,
    default=False,
    help="Only list this cluster's keys that nothing uses",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Full key ids, ARNs, tags, rotation status and dates",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def report(reclaimable_only, verbose, output):
    """Report the KMS keys this cluster uses, and what EDH can read of them.

    Two sources, both bounded to this cluster: keys tagged edh:ClusterId for
    this cluster, and keys named in this cluster's own configuration. The
    account is never enumerated.

    \b
      in-use            holds this cluster's alias, or is its only key
      superseded        an earlier build of this cluster left it behind: a
                        sibling holds the alias and this one holds none
      customer-key      config names it, EDH can read it, EDH did not create it
      pending-deletion  already scheduled, no longer billed, no action
      missing           config names a key that is not in this region
      undetermined      a read was denied, so it could not be classified

    \b
    A key EDH did not create is readable only if its own key policy grants the
    controller role, which the key's owner adds by hand. So EDH asks rather than
    assumes, and reports which gate refused: an identity-policy cause is an EDH
    gap, a key-policy cause needs the key's owner, and an explicit deny means
    they excluded EDH on purpose.

    Nothing is deleted, and nothing a customer owns is ever proposed for
    deletion. The controller holds no kms:ScheduleKeyDeletion grant; the command
    to run is printed for an administrator.
    """
    _cluster_id = get_cluster_id()
    _kms = _build_client("kms", output=output)
    _tagging = _build_client("resourcegroupstaggingapi", output=output)

    try:
        _edh_rows = _discover_this_clusters_keys(_tagging, _cluster_id)
    except ClientError as _err:
        print_output(
            message=(
                f"Unable to discover this cluster's KMS keys: {_err}. The "
                "controller needs tag:GetResources, granted in "
                "ControllerServices.json Sid KmsDiscoverThisClustersKeysByTag."
            ),
            output=output,
            error=True,
        )
        return

    _edh_rows = _classify(_describe_keys(_kms, _edh_rows))

    # Probed after the EDH keys are classified, and handed the index of what is
    # already known, so a key that is both tagged and configured is annotated
    # rather than reported twice. A customer who tags their own key to opt into
    # the controller's write grants produces exactly that overlap.
    _known = {_r["key_id"]: _r for _r in _edh_rows}
    _config_rows = _probe_configured_keys(_kms, _configured_key_values(), _known)
    _rows = _edh_rows + _config_rows

    _counts = {}
    for _row in _rows:
        _counts[_row["state"]] = _counts.get(_row["state"], 0) + 1

    # Reclaimable is EDH-created keys only. That is structural rather than
    # filtered here: `superseded` is assigned by _classify, which runs on the
    # tag-discovered rows alone, and the probe only ever assigns `customer-key`
    # or `pending-deletion`. So a key EDH did not create cannot reach this list,
    # and a second guard on `source` would be a check for a state the code
    # cannot produce. A key that is BOTH tagged and configured IS an EDH key and
    # does belong here.
    _reclaimable = [_r for _r in _rows if _r["state"] == _STATE_SUPERSEDED]
    _unreadable = [_r for _r in _rows if _r.get("access") == _ACCESS_DENIED]
    _shown = _reclaimable if reclaimable_only else _rows

    if output != "text":
        print_output(
            message={
                "cluster_id": _cluster_id,
                "region": _kms.meta.region_name,
                "counts": _counts,
                "keys_in_cluster": len(_rows),
                "keys_from_edh_tag": len(_edh_rows),
                "keys_from_config": len(_config_rows),
                "keys_unreadable": len(_unreadable),
                "reclaimable_keys": len(_reclaimable),
                "reclaimable_usd_per_month": round(_monthly_cost(_reclaimable), 2),
                "keys": _shown,
            },
            output=output,
        )
        return

    _lines = [
        f"Cluster            : {_cluster_id}",
        f"Region             : {_kms.meta.region_name}",
        f"Keys in scope      : {len(_rows)}"
        f"  ({len(_edh_rows)} EDH created, {len(_config_rows)} from config)",
    ]
    for _state in _STATE_ORDER:
        if _counts.get(_state):
            _lines.append(f"  {_state:<16} : {_counts[_state]}")
    _lines.append("")

    if not _shown:
        _lines.append(
            "No reclaimable keys."
            if reclaimable_only
            else (
                f"No KMS keys are tagged {_CLUSTER_TAG}={_cluster_id}, and this "
                "cluster's configuration names none. Every encrypted resource "
                "is therefore using an AWS managed key."
            )
        )
    elif verbose:
        _lines.extend(_verbose_blocks(_kms, _shown))
    else:
        _lines.extend(_table(_shown))

    if _reclaimable:
        _lines.append("")
        _lines.append(
            f"{len(_reclaimable)} EDH created key(s) are reclaimable, costing "
            f"about ${_monthly_cost(_reclaimable):.2f}/month. Deletion is not "
            "performed here. Review each one, then from a principal holding "
            "kms:ScheduleKeyDeletion:"
        )
        _lines.append("")
        for _row in sorted(_reclaimable, key=lambda _r: _r["key_id"]):
            _lines.append(
                f"  aws kms schedule-key-deletion --key-id {_row['key_id']} "
                "--pending-window-in-days 30"
            )
        _lines.append("")
        _lines.append(
            "A 30 day window stops the storage charge immediately and stays "
            "reversible with kms:CancelKeyDeletion for the whole window."
        )

    if _unreadable:
        _lines.extend(_unreadable_advice(_unreadable))

    if _counts.get(_STATE_MISSING):
        _lines.append("")
        _lines.append(
            f"{_counts[_STATE_MISSING]} configured key(s) do not exist in "
            f"{_kms.meta.region_name}. Whatever EDH was told to encrypt with "
            "them is either failing or has fallen back to an AWS managed key. "
            "Correct the value with `edhctl config set`, which applies the key "
            "validator and updates the cache layer."
        )

    print_output(message="\n".join(_lines), output="text")


def _unreadable_advice(unreadable: list) -> list:
    """Say who has to act on each key EDH could not read, and exactly how.

    Split by the gate that refused, because the causes have different owners and
    merging them would send an operator to the wrong one. An identity-policy
    denial is EDH's own bug. A key-policy denial needs a statement the key's
    owner adds -- printed verbatim, because "grant the controller access" is not
    an actionable instruction and the KMS console does not suggest one. An
    explicit deny is a decision already made. A retryable server fault is nobody
    to grant anything, and an unattributed denial is a denial whose gate could
    not be named.

    Every bucket has advice. A row reaching none of them is listed with its
    detail and no owner, which is the one answer this function exists to rule
    out.
    """
    _lines = ["", f"{len(unreadable)} key(s) could not be read:"]

    _by_cause = {
        "edh": [],
        "owner": [],
        "denied": [],
        "fault": [],
        "unattributed": [],
    }
    for _row in unreadable:
        _detail = _row.get("access_detail") or ""
        if "controller IAM" in _detail:
            _by_cause["edh"].append(_row)
        elif "does not grant EDH" in _detail:
            _by_cause["owner"].append(_row)
        elif "explicitly denies" in _detail:
            _by_cause["denied"].append(_row)
        elif _NOT_A_DENIAL in _detail:
            _by_cause["fault"].append(_row)
        else:
            _by_cause["unattributed"].append(_row)

    for _row in unreadable:
        _where = ", ".join(_row.get("config_keys") or []) or "edh:ClusterId tag"
        _lines.append(
            f"  {_short_id(_row['key_id'])}  {_row.get('access_detail')}"
            f"  (from {_where})"
        )

    if _by_cause["edh"]:
        _lines.append("")
        _lines.append(
            "An identity-policy cause is an EDH defect, not a customer action: "
            "the controller role is missing the KMS read actions in "
            "ControllerServices.json Sid KmsReadConfiguredAndOwnedKeys. Report "
            "it rather than editing a key policy."
        )

    if _by_cause["owner"]:
        _lines.append("")
        _lines.append(
            "A key-policy cause means EDH's identity policy allows the read and "
            "the key's own policy does not. Only the key's owner can change "
            "that. Add this statement to the key policy, in the KMS console "
            "under Key policy, or with kms:PutKeyPolicy:"
        )
        _lines.append("")
        for _line in _key_policy_statement():
            _lines.append(f"  {_line}")
        _lines.append("")
        _lines.append(
            "These are read actions only. They let EDH report on the key and "
            "evidence its rotation; they do not let EDH decrypt with it, rotate "
            "it or delete it."
        )

    if _by_cause["denied"]:
        _lines.append("")
        _lines.append(
            "An explicit deny is a decision the key's owner already made. EDH "
            "will not report on that key and should not be asked to; it is "
            "listed so the gap is visible rather than silent."
        )

    if _by_cause["fault"]:
        _lines.append("")
        _lines.append(
            "A fault is not an authorization problem and needs no grant from "
            "anyone. KMS documents KMSInternalException and "
            "DependencyTimeoutException as retryable server faults, so re-run "
            "the report; a key that keeps faulting is an AWS Support question, "
            "not a policy one."
        )

    if _by_cause["unattributed"]:
        _lines.append("")
        _lines.append(
            "An unattributed denial is a refusal whose gate could not be named. "
            "KMS answers every denial cause with one error code and only the "
            "message text differs, so the attribution above is text matching "
            "and AWS can reword it without notice. Check both gates: the "
            "controller role's KMS read actions in ControllerServices.json Sid "
            "KmsReadConfiguredAndOwnedKeys, and the key's own policy."
        )

    return _lines


def _key_policy_statement() -> list:
    """The statement a key owner adds to let EDH report on their key.

    Printed with the controller role as a placeholder rather than resolved: the
    controller cannot read its own role ARN without iam:GetRole, which it is not
    granted and should not be for this, and printing a wrong ARN confidently is
    worse than printing one the operator substitutes.
    """
    return [
        "{",
        '  "Sid": "AllowEdhControllerToReportOnThisKey",',
        '  "Effect": "Allow",',
        '  "Principal": {"AWS": "<the EDH controller role ARN>"},',
        '  "Action": [',
        '    "kms:DescribeKey",',
        '    "kms:GetKeyPolicy",',
        '    "kms:GetKeyRotationStatus",',
        '    "kms:ListKeyRotations"',
        "  ],",
        '  "Resource": "*"',
        "}",
    ]
