######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Typed access layer over the mesh DynamoDB Global Tables and Secrets Manager.

Every DDB operation the overlay daemon performs goes through this module, so
serialization lives in one place and the IAM permission scope the daemon needs
is derivable from one file.

Physical table names are resolved per call through table_names.resolve(), which
caches after the first lookup. Resolution is deliberately not done at import
time: the mesh table prefix arrives from controller bootstrap or from SSM, so
binding names at import would either fail in any process that imports this
module before the environment is wired, or silently cache a name resolved
before configuration was available.

Multi-account access
--------------------
When clusters in DIFFERENT AWS accounts share one mesh, the Global Tables live
in the mesh creator's account and a joining cluster cannot reach them with its
local credentials. The mesh creator therefore deploys a participant role (see
helpers/cdk/cross_region/mesh_iam.py::build_mesh_participant_role) trusted by
each peer account, and a joining cluster's daemon assumes it before touching
DDB.

  * configure(mesh_role_arn=...) is called once at process start. None or an
    empty string means same-account, which issues no STS calls at all.
  * Once configured, the DDB resource is built from the assumed role's
    credentials. Those credentials are refreshable, so a daemon can run for
    days without restarting to re-assume.
  * The Secrets Manager secret holding the WireGuard private key stays in the
    LOCAL account, so the Secrets Manager client is intentionally NOT routed
    through the assumed role.
"""

from __future__ import annotations
import logging
import os
import time
from typing import List, Optional, Tuple

import boto3
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
from botocore.exceptions import ClientError, BotoCoreError

from . import table_names
from .models import (
    AuditEvent,
    FenceOperation,
    FenceProposal,
    FenceVote,
    Health,
    HealthObservation,
    MeshMeta,
    Peer,
    ProposalState,
    VoteValue,
)


logger = logging.getLogger("soca_logger")

# Sort key of the per-mesh metadata row in the overlay_config table.
_META_SORT_KEY = "_meta"

# Module-level cross-account configuration, set by configure().
_mesh_role_arn: Optional[str] = None
_mesh_role_session_name: str = "edh-overlay-daemon"
_mesh_role_external_id: Optional[str] = None


# ------------------------------------------------------------------------------
# Errors
# ------------------------------------------------------------------------------


class DDBQueryError(Exception):
    """Raised when DDB cannot be queried at all (timeout, 5xx, AccessDenied)."""


class DDBBallotIncompleteError(DDBQueryError):
    """
    Raised when a vote row exists but cannot be read, so a tally would be wrong.

    A subclass of `DDBQueryError` rather than a sibling, deliberately: every existing
    handler for that type keeps working, and a caller that needs to tell the two apart
    catches this one first. The distinction matters because the two need opposite
    treatment. A `DDBQueryError` from a throttle or a timeout clears by itself and
    retrying is right. This does not clear: the row is malformed and stays malformed
    until somebody changes it, so answering a client with a retryable status would
    have them retry forever.
    """


class DDBConditionFailedError(Exception):
    """Raised when a conditional put or update was refused by its condition."""


class RegionNotConfiguredError(Exception):
    """
    Raised by configure() when no region could be resolved.

    A configuration error rather than an operational one, so it is deliberately
    not translated into DDBQueryError: it is raised before any client exists and
    the only remedy is to pass --region or set EDH_REGION.
    """


# ------------------------------------------------------------------------------
# Boto resources (lazy, cross-account aware)
# ------------------------------------------------------------------------------


_ddb = None
_secretsmanager = None
# Pinned by configure(). Every client this module builds passes it, so none of
# them can silently resolve a region from the ambient environment.
_region: Optional[str] = None


def configure(
    *,
    mesh_role_arn: Optional[str] = None,
    session_name: str = "edh-overlay-daemon",
    external_id: Optional[str] = None,
    region: Optional[str] = None,
) -> None:
    """
    Configure cross-account access to the mesh Global Tables.

    Call once at process start. Pass mesh_role_arn=None or an empty string to
    use the local account's credentials directly, which is the same-account
    default. Calling this again discards the cached DDB resource so the next
    operation picks up the new credentials.

    `region` pins every client this module builds, and a region is required. It
    was optional with an environment fallback that could return None, so a client
    was still built with region_name=None and resolved its region from instance
    metadata. Refusing here is what makes the pin real: the daemon is handed its
    region on the command line and in EDH_REGION, so there is no case where it
    legitimately has none, and failing at startup with a clear message beats
    talking to a region nobody chose.
    """
    global _mesh_role_arn, _mesh_role_session_name, _mesh_role_external_id
    global _ddb, _secretsmanager, _region
    arn = (mesh_role_arn or "").strip() or None
    resolved = (region or "").strip() or _region_from_environment()
    if not resolved:
        raise RegionNotConfiguredError(
            "No region was given and none could be read from EDH_REGION, "
            "AWS_REGION or AWS_DEFAULT_REGION. Every AWS client this daemon "
            "builds needs one, and without it each would resolve a region from "
            "instance metadata, which can differ from the region this cluster "
            "runs in. Pass --region or set EDH_REGION."
        )
    _mesh_role_arn = arn
    _mesh_role_session_name = session_name or "edh-overlay-daemon"
    _mesh_role_external_id = (external_id or "").strip() or None
    _region = resolved
    _ddb = None
    _secretsmanager = None
    if arn:
        logger.info(
            "ddb_client: cross-account mode, role_arn=%s session_name=%s "
            "external_id_set=%s region=%s",
            arn,
            _mesh_role_session_name,
            bool(_mesh_role_external_id),
            _region,
        )
    else:
        logger.info(
            "ddb_client: same-account mode, no STS assume-role, region=%s", _region
        )


def _region_from_environment() -> Optional[str]:
    """
    The region the daemon was installed for, from its own variable first.

    EDH_REGION is what the controller bootstrap exports and what the systemd unit
    bakes in, so it is the authoritative answer here. AWS_REGION is accepted as a
    fallback for anyone running the module by hand.
    """
    for name in ("EDH_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return None


def _refresh_assumed_credentials() -> dict:
    """
    Botocore credential-refresh callback.

    Botocore calls this before the assumed role's credentials expire, which is
    what lets the daemon run indefinitely without re-assuming by hand.
    """
    sts = boto3.client("sts", region_name=_region)
    kwargs = {
        "RoleArn": _mesh_role_arn,
        "RoleSessionName": _mesh_role_session_name,
        "DurationSeconds": 3600,
    }
    if _mesh_role_external_id:
        kwargs["ExternalId"] = _mesh_role_external_id
    creds = sts.assume_role(**kwargs)["Credentials"]
    return {
        "access_key": creds["AccessKeyId"],
        "secret_key": creds["SecretAccessKey"],
        "token": creds["SessionToken"],
        "expiry_time": creds["Expiration"].isoformat(),
    }


def _build_cross_account_session() -> boto3.session.Session:
    """Build a session whose credentials re-assume the role on expiry."""
    refreshable = RefreshableCredentials.create_from_metadata(
        metadata=_refresh_assumed_credentials(),
        refresh_using=_refresh_assumed_credentials,
        method="sts-assume-role",
    )
    botocore_session = get_session()
    botocore_session._credentials = refreshable
    return boto3.Session(botocore_session=botocore_session)


def _get_ddb():
    global _ddb
    if _ddb is None:
        if _mesh_role_arn:
            _ddb = _build_cross_account_session().resource(
                "dynamodb", region_name=_region
            )
        else:
            _ddb = boto3.resource("dynamodb", region_name=_region)
    return _ddb


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        # Always local credentials: the WireGuard private key lives in this
        # cluster's Secrets Manager, not the mesh creator's.
        _secretsmanager = boto3.client("secretsmanager", region_name=_region)
    return _secretsmanager


def _table(short_name: str):
    """
    Return the boto3 Table for a mesh table, resolving its physical name.

    A resolution failure is translated into DDBQueryError rather than allowed to
    surface as TableNameResolutionError. This is called BEFORE the try block in
    every function in this module, so an untranslated raise here bypassed each
    one's own error handling and escaped as a type no caller handles: the two
    callers that matter, bootstrap's mesh reads and the serve loop, both handle
    DDBQueryError, so a cluster with an unresolvable table prefix produced an
    uncaught traceback instead of the operator-facing failure each has. The
    original error is chained, so its message, which explains exactly which
    source failed to supply a prefix, is preserved.
    """
    try:
        physical = table_names.resolve(short_name)
    except table_names.TableNameResolutionError as e:
        raise DDBQueryError(str(e)) from e
    return _get_ddb().Table(physical)


def mesh_table(short_name: str):
    """
    The configured boto3 Table for a mesh table, for a subsystem outside this module.

    This exists so that a sibling subsystem owning its own table - the delegation
    ledger is the first - reads and writes it through the session this module
    configured, rather than building one of its own. That is not a tidiness
    preference. `configure()` REFUSES to run without a region, for the reason
    given in its docstring, and a caller doing `boto3.resource("dynamodb")` for
    itself defeats that refusal completely: it gets a client with
    region_name=None, which resolves a region from instance metadata and can
    therefore read a different region's copy of a Global Table than every other
    operation in the process. The failure is silent and looks like replication
    lag. Going through here also inherits the cross-account role and the
    translation of a name-resolution failure into DDBQueryError.

    Deliberately thin, and deliberately NOT a place to add per-table logic. A
    table's schema, validators and row model belong to the subsystem that reads
    them, which is what schema.py records at lines 45-47 and what keeps this
    module from having to import every consumer.
    """
    return _table(short_name)


# ------------------------------------------------------------------------------
# Mesh query
# ------------------------------------------------------------------------------


def query_mesh(mesh_id: str) -> Tuple[List[Peer], Optional[MeshMeta]]:
    """
    Return (peers, meta) for a mesh. Meta is None when the mesh has no rows.

    Raises DDBQueryError when the underlying query fails. A row that fails
    validation is logged and skipped rather than aborting the read, so one
    corrupt or future-versioned row cannot take down the daemon's view of the
    whole mesh.
    """
    table = _table("overlay_config")
    # Paginated deliberately. A Query returns at most 1MB per page and signals
    # more results with LastEvaluatedKey; a truncated page is a successful
    # response, so reading one page silently drops whatever did not fit. The
    # rows skipped below are the reason that matters here: they are filtered
    # client-side, so they are fetched and charged against the page limit before
    # being discarded, and their number grows with protocol activity rather than
    # with the mesh's capped cluster count. Losing the _meta row to a later page
    # is the worst case, because bootstrap then reports a mesh with peers and no
    # address plan.
    items: List[dict] = []
    query_kwargs: dict = {
        "KeyConditionExpression": "mesh_id = :m",
        "ExpressionAttributeValues": {":m": mesh_id},
        "ConsistentRead": False,  # Global Tables do not support strong reads
    }
    try:
        while True:
            resp = table.query(**query_kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e

    meta = None
    peers: List[Peer] = []
    for item in items:
        sort_key = item.get("cluster_id", "")
        # The overlay_config table also carries the fence protocol's proposal
        # and vote rows and the freeze sentinel. Those are owned by other
        # subsystems and are read through their own accessors, so skip them
        # here rather than trying to validate them as peers.
        if (
            sort_key.startswith("fence#")
            or sort_key.startswith("vote#")
            or sort_key.startswith("control#")
        ):
            continue
        try:
            if sort_key == _META_SORT_KEY:
                meta = _item_to_meta(item)
            else:
                peers.append(_item_to_peer(item))
        except DDBQueryError:
            # Schema-version dispatch found no usable validator. Already
            # logged by the registry; skip the row and keep the rest.
            continue
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(
                "skipping malformed row mesh_id=%s cluster_id=%s: %s",
                item.get("mesh_id"),
                item.get("cluster_id"),
                e,
            )
            continue
    return peers, meta


# ------------------------------------------------------------------------------
# Writes
# ------------------------------------------------------------------------------


def put_meta_conditional(meta: MeshMeta) -> None:
    """
    Create the mesh metadata row, failing if it already exists.

    This is what makes mesh creation a race-free election: two clusters both
    trying to create the same mesh will both attempt this put, and exactly one
    condition succeeds.
    """
    table = _table("overlay_config")
    try:
        table.put_item(
            Item=_meta_to_item(meta),
            ConditionExpression=(
                "attribute_not_exists(mesh_id) AND attribute_not_exists(cluster_id)"
            ),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DDBConditionFailedError(str(e)) from e
        raise DDBQueryError(str(e)) from e
    except BotoCoreError as e:
        raise DDBQueryError(str(e)) from e


def allocate_site_seq(mesh_id: str) -> int:
    """
    Atomically allocate the next site sequence number for a joining cluster.

    Returns the value allocated to the caller. The site sequence indexes into
    the mesh address plan, so two clusters must never receive the same one;
    the atomic increment is what guarantees that.
    """
    table = _table("overlay_config")
    try:
        resp = table.update_item(
            Key={"mesh_id": mesh_id, "cluster_id": _META_SORT_KEY},
            UpdateExpression="SET next_site_seq = next_site_seq + :one",
            ExpressionAttributeValues={":one": 1},
            ReturnValues="UPDATED_OLD",
        )
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e
    return int(resp["Attributes"]["next_site_seq"])


def put_peer(peer: Peer) -> None:
    """
    Write a peer row under an optimistic-concurrency check.

    peer.revision is the revision the caller READ. This writes revision + 1
    guarded on the stored row still carrying the revision that was read, so a
    concurrent writer raises DDBConditionFailedError instead of silently
    winning. Rows written before revisions existed carry no revision
    attribute, which the condition accepts.
    """
    table = _table("overlay_config")
    item = _peer_to_item(peer)
    prior_revision = peer.revision
    item["revision"] = prior_revision + 1
    try:
        table.put_item(
            Item=item,
            ConditionExpression=(
                "attribute_not_exists(revision) OR revision = :prior_rev"
            ),
            ExpressionAttributeValues={":prior_rev": prior_revision},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DDBConditionFailedError(
                f"put_peer revision conflict for cluster_id={peer.cluster_id} "
                f"(expected prior revision={prior_revision})"
            ) from e
        raise DDBQueryError(str(e)) from e
    except BotoCoreError as e:
        raise DDBQueryError(str(e)) from e


def populate_pre_registered_peer(
    *,
    mesh_id: str,
    cluster_id: str,
    site_seq: int,
    pubkey: str,
    endpoint: str,
    ula_prefix: str,
    cgn_prefix: str,
    cluster_name: str,
    region: str,
    account_id: str,
    actor: str,
) -> None:
    """
    Fill in the cryptographic and addressing fields of a pre-registered row.

    An administrator can pre-register a cluster before it exists, creating a
    row with an empty pubkey. When that cluster boots it calls this to claim
    the row. The lifecycle field is left untouched, so an administrator who
    already approved the cluster does not have to approve it again.

    Refuses a row whose pubkey is already populated, which means another writer
    claimed it first.
    """
    table = _table("overlay_config")
    history_entry = {
        "ts": int(time.time()),
        "to": "populated",
        "by": actor,
        "reason": "controller boot: populated pubkey, endpoint and site_seq on pre-registered row",
    }
    try:
        table.update_item(
            Key={"mesh_id": mesh_id, "cluster_id": cluster_id},
            UpdateExpression=(
                "SET pubkey = :pk, endpoint = :ep, site_seq = :ss, "
                "ula_prefix = :ula, cgn_prefix = :cgn, "
                "cluster_name = :cn, #r = :rg, account_id = :acct, "
                "pre_registered = :false, "
                "lifecycle_history = list_append(if_not_exists(lifecycle_history, :empty), :entry) "
                "ADD revision :one"
            ),
            ExpressionAttributeNames={"#r": "region"},
            ExpressionAttributeValues={
                ":pk": pubkey,
                ":ep": endpoint,
                ":ss": site_seq,
                ":ula": ula_prefix,
                ":cgn": cgn_prefix,
                ":cn": cluster_name,
                ":rg": region,
                ":acct": account_id,
                ":false": False,
                ":empty": [],
                ":entry": [history_entry],
                ":emptystr": "",
                ":one": 1,
            },
            ConditionExpression=(
                "attribute_exists(mesh_id) AND attribute_exists(cluster_id) AND "
                "(attribute_not_exists(pubkey) OR pubkey = :emptystr)"
            ),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DDBConditionFailedError(
                f"populate_pre_registered_peer: row {cluster_id} in mesh "
                f"{mesh_id} no longer has an empty pubkey (race or already populated)"
            ) from e
        raise DDBQueryError(str(e)) from e
    except BotoCoreError as e:
        raise DDBQueryError(str(e)) from e


def update_peer_lifecycle(
    *,
    mesh_id: str,
    cluster_id: str,
    new_lifecycle: Lifecycle,
    actor: str,
    reason: str,
    expected_revision: int,
) -> None:
    """
    Move a peer to a new lifecycle state, gated on it not having changed.

    Appends to the row's `lifecycle_history` and increments `revision` in the same
    update, so the history and the revision cannot disagree about how many
    transitions a row has seen.

    `expected_revision` is REQUIRED. The prototype made it optional and documented
    the omitted case as safe "where the caller has a higher-level guarantee no
    concurrent writer exists", and then no caller ever passed it, so no transition
    was concurrency-checked at all. Two administrators clicking at the same moment,
    or an approve racing a revoke, both succeeded and the last write won. This CR
    hit the same shape in its own region pinning: an optional check is one that
    gets omitted, so there is no default here to omit.

    Raises DDBConditionFailedError when the row is missing or its revision has
    moved, which the caller reports as a conflict rather than retrying blindly:
    the state it validated the transition against is no longer the state on the
    row, so the decision has to be made again.
    """
    table = _table("overlay_config")
    history_entry = {
        "ts": int(time.time()),
        "to": new_lifecycle.value,
        "by": actor,
        "reason": reason,
    }
    # A row carrying no revision attribute at all is tolerated only when the
    # caller claims revision 0, which is what Peer.revision means by "never
    # written". put_peer already tolerates the missing attribute and this did not,
    # so a row predating revisions could be re-registered but never approved: the
    # equality would compare against an absent attribute, which DynamoDB evaluates
    # as false, and every transition on that row would be permanently refused.
    # Kept narrow deliberately. Tolerating the absence for a nonzero expected
    # revision would mean accepting a claim about a revision the row cannot have
    # had, which is the concurrency check the caller asked for being waived.
    if expected_revision == 0:
        _revision_condition = "(attribute_not_exists(revision) OR revision = :prior_rev)"
    else:
        _revision_condition = "revision = :prior_rev"

    try:
        table.update_item(
            Key={"mesh_id": mesh_id, "cluster_id": cluster_id},
            UpdateExpression=(
                "SET lifecycle = :lc, "
                "lifecycle_history = list_append("
                "if_not_exists(lifecycle_history, :empty), :entry) "
                "ADD revision :one"
            ),
            ExpressionAttributeValues={
                ":lc": new_lifecycle.value,
                ":empty": [],
                ":entry": [history_entry],
                ":meta": _META_SORT_KEY,
                ":one": 1,
                ":prior_rev": expected_revision,
            },
            # The row must exist, must not be the metadata row, and must still be
            # at the revision the caller read. Excluding the metadata row matters
            # because its sort key lives in the same table and the same partition,
            # so a cluster_id of "_meta" reaching here would write a lifecycle onto
            # the mesh's address plan.
            ConditionExpression=(
                "attribute_exists(mesh_id) AND attribute_exists(cluster_id) "
                "AND cluster_id <> :meta "
                f"AND {_revision_condition}"
            ),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DDBConditionFailedError(str(e)) from e
        raise DDBQueryError(str(e)) from e
    except BotoCoreError as e:
        raise DDBQueryError(str(e)) from e


def read_cluster_state_heartbeats(mesh_id: str) -> List[dict]:
    """
    Every cluster's most recent heartbeat row for a mesh.

    The counterpart to write_cluster_state_heartbeat, which CR3 shipped without a
    reader. This is the liveness signal that actually exists today: each row says
    when a cluster last completed a sync, whether it succeeded, and how many peers
    it saw, so a stalled daemon is detectable from any cluster in the mesh rather
    than only from the one it is stalled on.

    Paginated to exhaustion. A partial read here would under-report liveness, and
    under-reporting liveness reads as "that cluster is dead" to whoever is looking,
    which is the opposite of a safe default. This is the same defect class as the
    single-page mesh read CR3 fixed at revision 1.
    """
    table = _table("cluster_state")
    rows: List[dict] = []
    query_kwargs: dict = {
        "KeyConditionExpression": "mesh_id = :m",
        "ExpressionAttributeValues": {":m": mesh_id},
        "ConsistentRead": False,  # Global Tables do not support strong reads
    }
    try:
        while True:
            response = table.query(**query_kwargs)
            rows.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e
    return rows


def query_audit_events(
    *,
    mesh_id: str,
    limit: int,
    start_key: Optional[dict] = None,
    matches=None,
    max_pages: int = 20,
) -> Tuple[List[dict], Optional[dict], bool]:
    """
    Audit rows for a mesh, newest first, up to `limit` that satisfy `matches`.

    Returns the rows, the key to resume from or None, and whether the page budget
    ran out before either the limit was reached or the table was exhausted.

    `matches` is applied while paging rather than to a single page. The prototype
    fetched one page of `Limit=limit` and filtered afterwards, so asking for fifty
    approvals returned however many approvals happened to be in the newest fifty
    rows of any kind: `limit` did not mean what any caller would read it to mean,
    and a filter matching nothing on the first page looked like no matching events
    existed at all. Same shape as the single-page mesh read from CR3.

    `max_pages` bounds the work, because a filter that matches nothing would
    otherwise walk the whole partition inside one HTTP request. Exhausting it is
    reported rather than hidden, so the caller can say the answer is incomplete
    instead of presenting it as final.
    """
    table = _table("overlay_audit")
    collected: List[dict] = []
    query_kwargs: dict = {
        "KeyConditionExpression": "mesh_id = :m",
        "ExpressionAttributeValues": {":m": mesh_id},
        "ScanIndexForward": False,  # newest first
        "ConsistentRead": False,
    }
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key

    pages = 0
    last_key: Optional[dict] = None
    try:
        while True:
            response = table.query(**query_kwargs)
            pages += 1
            for item in response.get("Items", []):
                if matches is None or matches(item):
                    collected.append(item)
                    if len(collected) >= limit:
                        # Resume from this item next time rather than from the end
                        # of the page, or the rows between it and the page end
                        # would be skipped entirely.
                        return (
                            collected,
                            {
                                "mesh_id": item["mesh_id"],
                                "event_id": item["event_id"],
                            },
                            False,
                        )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                return collected, None, False
            if pages >= max_pages:
                return collected, last_key, True
            query_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e


def append_audit_event(event: AuditEvent) -> None:
    """
    Append an audit event, failing if its event_id was already written.

    The audit table is append-only by IAM policy as well as by this condition
    (see helpers/cdk/cross_region/ddb_global_tables.py::enforce_append_only),
    so a replayed event is refused rather than overwriting the original.
    """
    table = _table("overlay_audit")
    try:
        table.put_item(
            Item=_audit_to_item(event),
            ConditionExpression="attribute_not_exists(event_id)",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DDBConditionFailedError(str(e)) from e
        raise DDBQueryError(str(e)) from e
    except BotoCoreError as e:
        raise DDBQueryError(str(e)) from e


def write_cluster_state_heartbeat(
    *,
    mesh_id: str,
    cluster_id: str,
    last_sync_ts: int,
    peer_count: int,
    daemon_version: str,
    last_sync_ok: bool,
    extra: Optional[dict] = None,
) -> None:
    """
    Write this cluster's heartbeat row, overwriting the previous one.

    Written every sync cycle. Because the table is a Global Table, every peer
    and the mesh creator's monitoring can see how recently each cluster
    completed a sync, which is what makes a stalled daemon detectable from
    outside the cluster it is stalled on.
    """
    table = _table("cluster_state")
    item: dict = {
        "mesh_id": mesh_id,
        "cluster_id": cluster_id,
        "last_sync_ts": int(last_sync_ts),
        "peer_count": int(peer_count),
        "daemon_version": str(daemon_version),
        "last_sync_ok": bool(last_sync_ok),
    }
    if extra:
        for key, value in extra.items():
            if key not in item:
                item[key] = value
    try:
        table.put_item(Item=item)
    except (ClientError, BotoCoreError) as e:
        # BotoCoreError as well as ClientError, matching query_mesh. Catching
        # only ClientError here left connection and endpoint-resolution failures
        # to propagate as themselves rather than as DDBQueryError, so a caller
        # handling DDBQueryError did not in fact cover this call.
        raise DDBQueryError(str(e)) from e


# ------------------------------------------------------------------------------
# Secrets Manager (WireGuard private key)
# ------------------------------------------------------------------------------


def read_private_key_secret(secret_arn: str) -> Optional[str]:
    """
    Return the stored WireGuard private key, or None when the secret has no
    value yet. A missing secret is the first-boot case, not an error.
    """
    sm = _get_secretsmanager()
    try:
        resp = sm.get_secret_value(SecretId=secret_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise DDBQueryError(f"Cannot read private key secret: {e}") from e
    except BotoCoreError as e:
        # Kept as its own clause rather than combined with the one above, which
        # reads e.response and so is ClientError-only. This path is reached from
        # bootstrap._ensure_wg_keypair, whose caller catches only BootstrapError,
        # so an untranslated connection failure killed the install with a
        # traceback rather than a clean exit.
        raise DDBQueryError(f"Cannot read private key secret: {e}") from e
    # SecretBinary arrives already decoded. It is declared `type: blob` in the
    # secretsmanager model and this is the json protocol, so botocore's
    # BaseJSONParser runs it through _default_blob_parser, which is
    # base64.b64decode with the comment "Blobs are always returned as bytes
    # type". Decoding a second time here raised binascii.Error on a real key or
    # silently produced garbage. The service documentation says the value is
    # base64 for the Python SDK, which describes the wire format rather than what
    # boto3 hands back; the parser is what actually runs.
    if "SecretBinary" in resp:
        return resp["SecretBinary"].decode()
    # .get rather than subscript: a secret version can carry neither field, and
    # this line sits outside the try above, so a subscript raised a bare KeyError
    # past every caller's handling. None is the value _ensure_wg_keypair already
    # treats as "no key stored yet", which is the recoverable reading of an empty
    # version and is what this function's docstring promises.
    return resp.get("SecretString")


def write_private_key_secret(secret_arn: str, privkey: str) -> None:
    sm = _get_secretsmanager()
    try:
        sm.put_secret_value(SecretId=secret_arn, SecretString=privkey)
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(f"Cannot write private key secret: {e}") from e


# ------------------------------------------------------------------------------
# Item to dataclass converters
# ------------------------------------------------------------------------------


def _item_to_peer(item: dict) -> Peer:
    """
    Validate a peer row through the schema registry and return the model.

    Raises DDBQueryError when no validator can handle the row's schema
    version; query_mesh treats that as a skippable row.
    """
    from . import schema as _schema

    model, _was_fallback = _schema.registry.validate(_schema.TABLE_PEER, item)
    if model is None:
        raise DDBQueryError(
            f"unsupported schema_version "
            f"({item.get('schema_version')}/{item.get('min_compatible_version')}) "
            f"on peer row mesh_id={item.get('mesh_id')} cluster_id={item.get('cluster_id')}"
        )
    return model


def _item_to_meta(item: dict) -> MeshMeta:
    """Validate a mesh metadata row through the schema registry."""
    from . import schema as _schema

    model, _was_fallback = _schema.registry.validate(_schema.TABLE_META, item)
    if model is None:
        raise DDBQueryError(
            f"unsupported schema_version "
            f"({item.get('schema_version')}/{item.get('min_compatible_version')}) "
            f"on meta row mesh_id={item.get('mesh_id')}"
        )
    return model


def _peer_to_item(peer: Peer) -> dict:
    item = {
        "mesh_id": peer.mesh_id,
        "cluster_id": peer.cluster_id,
        "cluster_name": peer.cluster_name,
        "region": peer.region,
        "account_id": peer.account_id,
        "site_seq": peer.site_seq,
        "pubkey": peer.pubkey,
        "endpoint": peer.endpoint,
        "ula_prefix": peer.ula_prefix,
        "cgn_prefix": peer.cgn_prefix,
        "lifecycle": peer.lifecycle.value,
        "joined_at": peer.joined_at,
        "joined_by": peer.joined_by,
        "lifecycle_history": peer.lifecycle_history,
        # Always written so a future reader can dispatch on version.
        "schema_version": peer.schema_version,
        "min_compatible_version": peer.min_compatible_version,
        "revision": peer.revision,
    }
    if peer.pubkey_next:
        item["pubkey_next"] = peer.pubkey_next
    if peer.endpoint_ipv6:
        # Written because the validator reads it back. Omitted from the item
        # entirely, the field round-tripped to None on every write, so a value
        # set on a Peer was silently discarded rather than stored.
        item["endpoint_ipv6"] = peer.endpoint_ipv6
    if peer.decommissioned_at:
        item["decommissioned_at"] = peer.decommissioned_at
    if peer.tombstoned_at:
        item["tombstoned_at"] = peer.tombstoned_at
    return item


def _meta_to_item(meta: MeshMeta) -> dict:
    item = {
        "mesh_id": meta.mesh_id,
        "cluster_id": _META_SORT_KEY,
        "mesh_ula_prefix": meta.mesh_ula_prefix,
        "mesh_cgn_prefix": meta.mesh_cgn_prefix,
        "next_site_seq": meta.next_site_seq,
        "created_at": meta.created_at,
        "created_by": meta.created_by,
        "key_rotation_days": meta.key_rotation_days,
        "decommission_to_tombstone_days": meta.decommission_to_tombstone_days,
        "schema_version": meta.schema_version,
        "min_compatible_version": meta.min_compatible_version,
        "revision": meta.revision,
    }
    if meta.auto_decommission_days is not None:
        item["auto_decommission_days"] = meta.auto_decommission_days
    return item


def _audit_to_item(event: AuditEvent) -> dict:
    return {
        "mesh_id": event.mesh_id,
        "event_id": event.event_id,
        "action": event.action,
        "target_cluster_id": event.target_cluster_id,
        "actor": event.actor,
        "reason": event.reason,
        "ts": event.ts,
        "metadata": event.metadata,
        # Written as empty strings rather than omitted when the source cannot
        # be resolved, so a reader can index them unconditionally.
        "source_cluster_id": event.source_cluster_id or "",
        "source_region": event.source_region or "",
        "source_account_id": event.source_account_id or "",
        "schema_version": event.schema_version,
        "min_compatible_version": event.min_compatible_version,
    }


# ------------------------------------------------------------------------------
# Quorum proposals and votes
#
# Both live in overlay_config under namespaced sort keys, which query_mesh
# already skips rather than validating as peers. Reads and writes here are the
# storage half of fence.py: that module decides, this one persists, and the two
# are split so the decision rules stay testable without a table.
# ------------------------------------------------------------------------------

# Registered with the schema registry rather than added to schema.py, because
# that module says so in as many words: validators for the fence protocol's rows
# ship with the subsystem that reads them, and the registry is the extension
# point. Registering here keeps every row-shape decision in the storage layer and
# leaves fence.py pure, which its own test pins.
TABLE_FENCE_PROPOSAL = "overlay_config_fence_proposal"
TABLE_FENCE_VOTE = "overlay_config_fence_vote"


def _validate_fence_proposal_v1(item: dict) -> FenceProposal:
    """Validate a v1 proposal row."""
    return FenceProposal(
        mesh_id=item["mesh_id"],
        proposal_id=item["proposal_id"],
        proposer=item.get("proposer", ""),
        operation=FenceOperation(item["operation"]),
        target=item.get("target", ""),
        reason=item.get("reason", ""),
        proposed_at=int(item.get("proposed_at", 0)),
        expires_at=int(item.get("expires_at", 0)),
        state=ProposalState(item.get("state", "open")),
        committed_by_override=bool(item.get("committed_by_override", False)),
        paused_total_seconds=int(item.get("paused_total_seconds", 0)),
        metadata=dict(item.get("metadata", {})),
        schema_version=int(item.get("schema_version", 1)),
        min_compatible_version=int(item.get("min_compatible_version", 1)),
        revision=int(item.get("revision", 0)),
    )


def _validate_fence_vote_v1(item: dict) -> FenceVote:
    """Validate a v1 vote row."""
    return FenceVote(
        mesh_id=item["mesh_id"],
        proposal_id=item["proposal_id"],
        voter=item["voter"],
        vote=VoteValue(item["vote"]),
        voted_at=int(item.get("voted_at", 0)),
        reason=item.get("reason", ""),
        schema_version=int(item.get("schema_version", 1)),
        min_compatible_version=int(item.get("min_compatible_version", 1)),
    )


def _register_fence_schemas() -> None:
    """
    Register the fence validators once.

    Idempotent and guarded, so importing this module twice or registering after a
    reload does not silently replace a validator with an identical one and hide a
    version conflict.
    """
    from . import schema as _schema

    if not _schema.registry.has(TABLE_FENCE_PROPOSAL, 1):
        _schema.registry.register(
            TABLE_FENCE_PROPOSAL, 1, _validate_fence_proposal_v1
        )
    if not _schema.registry.has(TABLE_FENCE_VOTE, 1):
        _schema.registry.register(TABLE_FENCE_VOTE, 1, _validate_fence_vote_v1)


def _item_to_proposal(item: dict) -> FenceProposal:
    """Validate a proposal row through the schema registry and return the model."""
    from . import schema as _schema

    _register_fence_schemas()
    model, _was_fallback = _schema.registry.validate(TABLE_FENCE_PROPOSAL, item)
    if model is None:
        raise DDBQueryError(
            f"unsupported schema_version "
            f"({item.get('schema_version')}/{item.get('min_compatible_version')}) "
            f"on proposal row mesh_id={item.get('mesh_id')} "
            f"proposal_id={item.get('proposal_id')}"
        )
    return model


def _item_to_vote(item: dict) -> FenceVote:
    """Validate a vote row through the schema registry and return the model."""
    from . import schema as _schema

    _register_fence_schemas()
    model, _was_fallback = _schema.registry.validate(TABLE_FENCE_VOTE, item)
    if model is None:
        raise DDBQueryError(
            f"unsupported schema_version "
            f"({item.get('schema_version')}/{item.get('min_compatible_version')}) "
            f"on vote row mesh_id={item.get('mesh_id')} "
            f"proposal_id={item.get('proposal_id')}"
        )
    return model


def _proposal_to_item(proposal: FenceProposal) -> dict:
    from . import fence as _fence

    return {
        "mesh_id": proposal.mesh_id,
        # The sort key. Built by fence so the writer here and the reader in
        # query_mesh cannot disagree about what a proposal row looks like.
        "cluster_id": _fence.proposal_sort_key(proposal.proposal_id),
        "proposal_id": proposal.proposal_id,
        "proposer": proposal.proposer,
        "operation": proposal.operation.value,
        "target": proposal.target,
        "reason": proposal.reason,
        "proposed_at": proposal.proposed_at,
        "expires_at": proposal.expires_at,
        "state": proposal.state.value,
        "committed_by_override": proposal.committed_by_override,
        "paused_total_seconds": proposal.paused_total_seconds,
        "metadata": proposal.metadata,
        "schema_version": proposal.schema_version,
        "min_compatible_version": proposal.min_compatible_version,
        "revision": proposal.revision,
    }


def _vote_to_item(vote: FenceVote) -> dict:
    from . import fence as _fence

    return {
        "mesh_id": vote.mesh_id,
        "cluster_id": _fence.vote_sort_key(vote.proposal_id, vote.voter),
        "proposal_id": vote.proposal_id,
        "voter": vote.voter,
        "vote": vote.vote.value,
        "voted_at": vote.voted_at,
        "reason": vote.reason,
        "schema_version": vote.schema_version,
        "min_compatible_version": vote.min_compatible_version,
    }


def put_fence_proposal(proposal: FenceProposal) -> None:
    """
    Write a new proposal, refusing if one already exists under that id.

    Conditional on the row being absent for the same reason append_audit_event is:
    a replayed create must not silently reset an in-flight decision's state or its
    voting window. A proposal id carries a millisecond timestamp, so a genuine
    collision is not expected and a refusal here means something replayed.
    """
    from . import fence as _fence

    table = _table("overlay_config")
    try:
        table.put_item(
            Item=_proposal_to_item(proposal),
            ConditionExpression="attribute_not_exists(cluster_id)",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DDBConditionFailedError(
                f"proposal {proposal.proposal_id} already exists"
            ) from e
        raise DDBQueryError(str(e)) from e
    except BotoCoreError as e:
        raise DDBQueryError(str(e)) from e


def put_fence_vote(vote: FenceVote) -> None:
    """
    Record a vote, overwriting this voter's previous one on the same proposal.

    Unconditional on purpose, and the distinction from put_fence_proposal matters.
    The row is keyed on (proposal_id, voter), so an overwrite can only ever replace
    a peer's own earlier vote, which is a peer changing its mind and is allowed. A
    conditional write would instead make a re-vote fail with a conflict the operator
    cannot resolve.
    """
    table = _table("overlay_config")
    try:
        table.put_item(Item=_vote_to_item(vote))
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e


def read_fence_proposals(mesh_id: str) -> List[FenceProposal]:
    """
    Every proposal row for a mesh, paginated to exhaustion.

    Complete rather than a first page, because a partial read under-reports open
    proposals and an open proposal is a pending destructive action. Missing one
    would let a second proposal be raised for a target already under decision, and
    would hide it from the operator looking for what is outstanding. Same defect
    class as the single-page mesh read CR3 fixed and the single-page audit read
    CR-304228329 fixed.

    A row that cannot be validated is skipped with a warning rather than failing
    the read, so one malformed proposal does not hide every other one.
    """
    from . import fence as _fence

    table = _table("overlay_config")
    proposals: List[FenceProposal] = []
    query_kwargs: dict = {
        "KeyConditionExpression": "mesh_id = :m AND begins_with(cluster_id, :p)",
        "ExpressionAttributeValues": {
            ":m": mesh_id,
            ":p": _fence.PROPOSAL_PREFIX,
        },
        "ConsistentRead": False,  # Global Tables do not support strong reads
    }
    try:
        while True:
            response = table.query(**query_kwargs)
            for item in response.get("Items", []):
                try:
                    proposals.append(_item_to_proposal(item))
                except (DDBQueryError, KeyError, ValueError, TypeError) as e:
                    logger.warning(
                        "skipping malformed proposal row mesh_id=%s cluster_id=%s: %s",
                        item.get("mesh_id"),
                        item.get("cluster_id"),
                        e,
                    )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e
    return proposals


def read_fence_votes(mesh_id: str, proposal_id: str) -> List[FenceVote]:
    """
    Every vote cast on one proposal, paginated to exhaustion.

    A partial read here changes a tally, and a tally decides whether a cluster is
    decommissioned, so this is the one read in this module where truncation would
    directly cause a wrong destructive outcome rather than a wrong display.

    An unreadable row therefore FAILS the read rather than being skipped, which is the
    opposite of `read_fence_proposals`. That asymmetry is the point. Skipping a
    proposal row means not acting on that proposal, which is safe. Skipping a vote row
    means deciding on a ballot the code knows is incomplete: a complete ballot of two
    NO votes on a three-peer mesh rejects, and dropping one of those rows leaves the
    same proposal open and available to be committed later.

    An earlier revision logged a warning and continued here, which contradicted the
    paragraph above: it guarded against truncation by pagination and then introduced
    truncation by content. Review caught it.

    Failing is safe because every caller contains it per proposal. The daemon sweep
    leaves that proposal for the next cycle and still decides the others, and the API's
    list endpoint reports the proposal with no tally rather than a wrong one. Reaping
    does not use this reader at all, precisely so that deleting a malformed row does
    not depend on parsing it.
    """
    from . import fence as _fence

    table = _table("overlay_config")
    votes: List[FenceVote] = []
    query_kwargs: dict = {
        "KeyConditionExpression": "mesh_id = :m AND begins_with(cluster_id, :p)",
        "ExpressionAttributeValues": {
            ":m": mesh_id,
            ":p": f"{_fence.VOTE_PREFIX}{proposal_id}#",
        },
        "ConsistentRead": False,
    }
    try:
        while True:
            response = table.query(**query_kwargs)
            for item in response.get("Items", []):
                try:
                    votes.append(_item_to_vote(item))
                except (DDBQueryError, KeyError, ValueError, TypeError) as e:
                    # Logged at error rather than warning: unlike a throttled read this
                    # does not clear on its own, so the proposal stays undecidable until
                    # somebody looks at the row.
                    logger.error(
                        "unreadable vote row mesh_id=%s cluster_id=%s, so the tally "
                        "for proposal %s cannot be trusted and is not computed: %s",
                        item.get("mesh_id"),
                        item.get("cluster_id"),
                        proposal_id,
                        e,
                    )
                    raise DDBBallotIncompleteError(
                        f"vote row {item.get('cluster_id')!r} on proposal "
                        f"{proposal_id} could not be read, so the ballot is "
                        f"incomplete: {e}"
                    ) from e
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e
    return votes


def transition_fence_proposal(
    *,
    mesh_id: str,
    proposal_id: str,
    new_state: ProposalState,
    expected_state: ProposalState,
) -> None:
    """
    Move a proposal to a new state, only if it is still in the state we read.

    `expected_state` is REQUIRED, and this is the whole reason this function
    exists rather than a plain put. Every daemon in the mesh evaluates every open
    proposal on its own cycle, so two of them can decide the same proposal in the
    same second. Without the condition both would write, and the loser would
    re-run whatever the commit does: a decommission applied twice, or a commit
    overwriting a rejection that landed first.

    Raises DDBConditionFailedError when the row has already moved, which the
    caller should treat as another daemon having got there first rather than as an
    error to report.
    """
    from . import fence as _fence

    table = _table("overlay_config")
    try:
        table.update_item(
            Key={
                "mesh_id": mesh_id,
                "cluster_id": _fence.proposal_sort_key(proposal_id),
            },
            UpdateExpression="SET #s = :new ADD revision :one",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={
                ":new": new_state.value,
                ":expected": expected_state.value,
                ":one": 1,
            },
            ConditionExpression=(
                "attribute_exists(cluster_id) AND #s = :expected"
            ),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DDBConditionFailedError(
                f"proposal {proposal_id} is no longer {expected_state.value}"
            ) from e
        raise DDBQueryError(str(e)) from e
    except BotoCoreError as e:
        raise DDBQueryError(str(e)) from e


def delete_fence_proposal(mesh_id: str, proposal_id: str) -> None:
    """
    Delete a finalised proposal and every vote cast on it.

    The daemon reaps rather than DynamoDB expiring rows: overlay_config declares
    no TTL attribute, and adding one would put peer lifecycle rows and the mesh
    metadata row under the same reaper. A per-row decision made by code that knows
    which rows are proposals is narrower than a table-wide rule that trusts every
    writer never to set the attribute by accident.

    Votes go first. If the delete is interrupted between the two, orphaned votes
    are harmless because every read of them is scoped to a proposal id that no
    longer exists, whereas a proposal left without its votes would tally as
    unanimous silence and could be re-decided.

    The votes are collected by their RAW sort keys from the query response rather
    than by iterating `read_fence_votes`, and that difference is the whole point of
    doing it this way. That reader skips any row it cannot validate, logging a
    warning and continuing, so a malformed vote row would never be returned here,
    never be deleted, and become a permanent orphan the moment the proposal row went:
    nothing is ever scoped to it again. Reaping must not depend on the rows being
    parseable, because the rows most likely to need reaping are the ones that are not.
    """
    table = _table("overlay_config")
    from . import fence as _fence

    prefix = f"{_fence.VOTE_PREFIX}{proposal_id}#"
    query_kwargs: dict = {
        "KeyConditionExpression": "mesh_id = :m AND begins_with(cluster_id, :p)",
        "ExpressionAttributeValues": {":m": mesh_id, ":p": prefix},
        # Only the key is needed, and asking for less means a malformed row's other
        # attributes cannot get in the way of deleting it.
        "ProjectionExpression": "mesh_id, cluster_id",
        "ConsistentRead": False,
    }
    try:
        while True:
            response = table.query(**query_kwargs)
            for item in response.get("Items", []):
                sort_key = item.get("cluster_id")
                if not sort_key:
                    continue
                table.delete_item(
                    Key={"mesh_id": mesh_id, "cluster_id": sort_key}
                )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key

        table.delete_item(
            Key={
                "mesh_id": mesh_id,
                "cluster_id": _fence.proposal_sort_key(proposal_id),
            }
        )
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e


# ------------------------------------------------------------------------------
# Observed reachability, in the overlay_health table
# ------------------------------------------------------------------------------

# Its own real table, unlike the fence rows which share overlay_config. That is
# the CDK's choice rather than one made here: overlay_health has been provisioned
# since CR-302707670 with partition key mesh_id and sort key pair_id, and the
# daemon has resolved its name since CR-303187764. Nothing wrote to it until now.
TABLE_HEALTH = "overlay_health"


def _validate_health_observation_v1(item: dict) -> HealthObservation:
    """Validate a v1 observation row from the overlay_health table."""
    return HealthObservation(
        mesh_id=item["mesh_id"],
        observer=item["observer"],
        observed=item["observed"],
        last_attempt_ts=int(item.get("last_attempt_ts", 0)),
        health=Health(item.get("health", "unknown")),
        last_ok_ts=(
            int(item["last_ok_ts"]) if item.get("last_ok_ts") is not None else None
        ),
        last_rtt_ms=(
            int(item["last_rtt_ms"]) if item.get("last_rtt_ms") is not None else None
        ),
        consecutive_failures=int(item.get("consecutive_failures", 0)),
        recent_rtt_ms=[int(v) for v in item.get("recent_rtt_ms", [])],
        schema_version=int(item.get("schema_version", 1)),
        min_compatible_version=int(item.get("min_compatible_version", 1)),
    )


def _register_health_schemas() -> None:
    """
    Register the health validator once.

    Through the registry rather than by editing schema.py, which documents at lines
    45-47 that validators ship with the subsystem that reads them. Idempotent so a
    double import cannot replace a validator and hide a version conflict.
    """
    from . import schema as _schema

    if not _schema.registry.has(TABLE_HEALTH, 1):
        _schema.registry.register(TABLE_HEALTH, 1, _validate_health_observation_v1)


def _item_to_observation(item: dict) -> HealthObservation:
    """Validate an observation row through the schema registry."""
    from . import schema as _schema

    _register_health_schemas()
    model, _was_fallback = _schema.registry.validate(TABLE_HEALTH, item)
    if model is None:
        raise DDBQueryError(
            f"unsupported schema_version "
            f"({item.get('schema_version')}/{item.get('min_compatible_version')}) "
            f"on health row mesh_id={item.get('mesh_id')} "
            f"pair_id={item.get('pair_id')}"
        )
    return model


def _observation_to_item(observation: HealthObservation) -> dict:
    """
    One observation as its stored row.

    `observer` and `observed` are written as their own attributes even though both
    are recoverable from `pair_id`. That is deliberate: a reader that had to split
    the key would need a parser, and the equivalent parser in the fence subsystem
    shipped broken because every real id contained the separator it split on.
    """
    item = {
        "mesh_id": observation.mesh_id,
        "pair_id": observation.pair_id,
        "observer": observation.observer,
        "observed": observation.observed,
        "last_attempt_ts": observation.last_attempt_ts,
        "health": observation.health.value,
        "consecutive_failures": observation.consecutive_failures,
        "recent_rtt_ms": list(observation.recent_rtt_ms),
        "schema_version": observation.schema_version,
        "min_compatible_version": observation.min_compatible_version,
    }
    # Written only when set, so "never succeeded" is an absent attribute rather
    # than a zero that would read as the epoch.
    if observation.last_ok_ts is not None:
        item["last_ok_ts"] = observation.last_ok_ts
    if observation.last_rtt_ms is not None:
        item["last_rtt_ms"] = observation.last_rtt_ms
    return item


def put_health_observation(observation: HealthObservation) -> None:
    """
    Record one observer's view of one peer.

    Deliberately UNCONDITIONAL, for the same reason `put_fence_vote` is: the key is
    the (observer, observed) pair, so a write can only replace this observer's own
    earlier view of that peer. There is no other writer to lose an update to, and a
    condition would mean a probe round failing because the previous round succeeded.
    """
    table = _table(TABLE_HEALTH)
    try:
        table.put_item(Item=_observation_to_item(observation))
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e


def read_health_observations(mesh_id: str) -> List[HealthObservation]:
    """
    Every observation in the mesh, from every observer, paginated to exhaustion.

    An unreadable row is SKIPPED with a warning, which is the opposite of
    `read_fence_votes` and deliberately so. A dropped vote decides a destructive
    operation on an incomplete ballot; a dropped observation leaves one cell of a
    reachability matrix unknown, which the reader renders as unknown.

    That difference is safe only because of how the escalation path consumes this.
    It requires a MINIMUM number of observers reporting a peer unavailable before it
    will act, so a skipped row can only lower that count and never raise it: an
    unreadable row can delay an escalation but cannot cause one.
    """
    table = _table(TABLE_HEALTH)
    observations: List[HealthObservation] = []
    query_kwargs: dict = {
        "KeyConditionExpression": "mesh_id = :m",
        "ExpressionAttributeValues": {":m": mesh_id},
        "ConsistentRead": False,
    }
    try:
        while True:
            response = table.query(**query_kwargs)
            for item in response.get("Items", []):
                try:
                    observations.append(_item_to_observation(item))
                except (DDBQueryError, KeyError, ValueError, TypeError) as e:
                    logger.warning(
                        "skipping malformed health row mesh_id=%s pair_id=%s: %s",
                        item.get("mesh_id"),
                        item.get("pair_id"),
                        e,
                    )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError) as e:
        raise DDBQueryError(str(e)) from e
    return observations
