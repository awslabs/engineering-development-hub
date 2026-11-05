######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
The delegation ledger: storage for the cross-region system of record.

One row per locally submitted job that a peer is running. The table
(`delegations`) has been provisioned since the Global Tables CR with partition
key mesh_id and sort key local_job_id, plus an `origin-open-index` GSI keyed on
local_cluster_id, and nothing has written to it until now.

Every read and write goes through `ddb_client.mesh_table`, so the ledger uses the
same configured session, region pin and cross-account role as the rest of the
mesh. Rows are validated through the shipped schema registry, and the validator
is registered here rather than in schema.py because a table's schema ships with
the subsystem that reads it.

WHAT THIS MODULE DELIBERATELY DOES NOT DO: decide anything. It stores what it is
told and reports what it holds. The reconciler owns the question of what a state
transition means, and the ordering rule that keeps a parked stub recoverable
lives there, where it can be read as one sequence.
"""

from __future__ import annotations

import logging
import time
from typing import Any, List, Optional

from botocore.exceptions import BotoCoreError, ClientError

from utils.cast import SocaCastEngine

from overlay_daemon import ddb_client
from overlay_daemon.ddb_client import DDBQueryError

from .models import Delegation, TERMINAL_STATES
from .scheduler_drivers.base import NormalizedState

logger = logging.getLogger("soca_logger")

TABLE_DELEGATIONS = "delegations"
OPEN_INDEX = "origin-open-index"

# How long a finished delegation is kept. The audit question it answers - which
# cluster ran this user's work - outlives the schedulers on both sides, since PBS
# keeps finished jobs for 72 hours.
RETENTION_DAYS = 30

# TTL given to a row while its job is still open.
#
# An open delegation has no natural expiry, but DynamoDB TTL wants an attribute
# on every row: leaving it unset means a row that never reaches a terminal state
# is kept forever, and a mesh that loses a peer mid-flight produces exactly those
# rows. A year is long enough that no live job reaches it and short enough that
# abandoned rows do not accumulate across the cluster's life. It is deliberately
# far longer than RETENTION_DAYS, because a row disappearing while its job is
# still running is the one outcome that leaves an orphaned stub with no ledger
# entry to explain it.
OPEN_TTL_DAYS = 365


class DelegationError(Exception):
    """A delegation row could not be read or written.

    EVERY entry point in this module raises this and nothing else, because both
    of the module's callers are written against it: the reconciler catches it
    around `update_state` and `mark_stub_released` specifically so a failed
    record leaves the delegation for the next pass instead of aborting the pass.
    Two other exception classes reach these functions and are translated here
    rather than allowed to escape:

      - `DDBQueryError`, from `ddb_client.mesh_table` resolving the physical table
        name. Resolution is cached only on success, so a configuration store that
        cannot be consulted - the transient case its own message calls out - makes
        every operation raise it. Uncaught, that aborts a whole reconciliation
        pass; worse in `mark_stub_released`, where the stub is already out of the
        queue and only the record failed, which is the one case that except clause
        exists for.
      - `ValueError` / `KeyError` / `TypeError`, from the row validator, which
        `get` translates. See its docstring for why it raises where the open list
        skips.
    """


class DelegationConflictError(DelegationError):
    """A conditional write was refused because the row already exists.

    Separate from DelegationError because the two want opposite handling: a
    transport or throughput failure is worth retrying, while a refused condition
    means another writer got there first and retrying cannot help.
    """


class DelegationMissingError(DelegationError):
    """An update was refused because no row exists for that key.

    A DynamoDB `update_item` is an UPSERT, so without a condition an update
    against a vanished key does not fail - it manufactures a row holding only the
    two key attributes plus whatever the expression sets. Such a row is permanent
    (nothing sets `expires_at` on it, so TTL never reaps it and this module has no
    delete path), invisible (`origin-open-index` is keyed on `local_cluster_id`,
    which it lacks, so the reconciler never lists it), and it POISONS THE KEY:
    `create` is conditional on `attribute_not_exists(mesh_id)` and the partial row
    carries mesh_id because that is the partition key, so a later legitimate
    delegation for the same local_job_id is refused - which is exactly the
    unrecorded-remote-job failure `create`'s condition exists to prevent.

    A subclass of DelegationError so both existing handlers in the reconciler keep
    catching it, but distinct for the same reason DelegationConflictError is: the
    row is gone, so retrying cannot help.
    """


def _row_int(item: dict, field: str, *, default: Optional[int]) -> Optional[int]:
    """
    One integer field off a delegation row, cast through the shipped engine.

    THE CAST GOES THROUGH SocaCastEngine RATHER THAN Validators because DynamoDB
    hands numbers back as `Decimal`: `Validators.is_int(Decimal("1"))` is False,
    so a guard built on it would refuse every row the table actually holds, while
    the engine converts a Decimal correctly. Measured, both directions.

    An ABSENT field takes the default without a cast, since casting a literal
    proves nothing. A field that is PRESENT and uncastable raises `ValueError`,
    which is the contract `schema.registry.validate` documents for a validator,
    so `list_needing_reconciliation` skips and warns on that one row and the rest
    of the cluster's delegations are unaffected. Bare `int()` raised the same
    exception type; what it could not say is which of the six fields was bad.
    """
    raw = item.get(field)
    if raw is None:
        return default
    cast = SocaCastEngine(data=raw).cast_as(int)
    if not cast.success:
        raise ValueError(
            f"delegation row mesh_id={item.get('mesh_id')} "
            f"local_job_id={item.get('local_job_id')} carries an unreadable "
            f"{field}: {cast.message}"
        )
    return cast.message


def _row_stub_released(item: dict) -> bool:
    """
    Whether the local parked stub has already been taken out of the queue.

    THIS FIELD ALONE DOES NOT RAISE on an uncastable value, and the asymmetry
    against `_row_int` is deliberate. `cast_as(bool)` is stricter than `bool()`:
    it refuses `Decimal("1")` and `1`, which `bool()` read as True (measured).
    Raising would skip the whole row, and a skipped row is never reconciled -
    which is exactly the stub-parked-forever failure the `stub_released` split
    was introduced to prevent, so the stricter cast would have reintroduced it
    through the validator.

    An unreadable value therefore falls back to False, meaning "assume not
    released". That is the recoverable direction: `_release_stub` retries on the
    next pass, and `delegation_sync` already records that a second cancel of an
    already-cancelled job is harmless. Reading it as True abandons the stub with
    nothing left to notice it.
    """
    raw = item.get("stub_released")
    if raw is None:
        return False
    cast = SocaCastEngine(data=raw).cast_as(bool)
    if not cast.success:
        logger.warning(
            "delegation_store: delegation %s in mesh %s carries an unreadable "
            "stub_released (%r); treating it as not released so the next pass "
            "retries the release, which is harmless if it already happened",
            item.get("local_job_id"),
            item.get("mesh_id"),
            raw,
        )
        return False
    return cast.message


def _validate_delegation_v1(item: dict) -> Delegation:
    """
    Validate a v1 row from the delegations table.

    `state` is passed through `NormalizedState`, so a row carrying a value outside
    the vocabulary raises rather than being handed to the reconciler, which would
    otherwise compare it against the terminal set, find no match, and poll the
    peer about it forever.
    """
    return Delegation(
        mesh_id=item["mesh_id"],
        local_job_id=item["local_job_id"],
        local_cluster_id=item["local_cluster_id"],
        remote_cluster_id=item["remote_cluster_id"],
        remote_job_id=item["remote_job_id"],
        owner=item.get("owner", ""),
        state=NormalizedState(item.get("state", "unknown")),
        submitted_ts=_row_int(item, "submitted_ts", default=0),
        updated_ts=_row_int(item, "updated_ts", default=0),
        completed_ts=_row_int(item, "completed_ts", default=None),
        stub_released=_row_stub_released(item),
        expires_at=_row_int(item, "expires_at", default=None),
        schema_version=_row_int(item, "schema_version", default=1),
        min_compatible_version=_row_int(item, "min_compatible_version", default=1),
    )


def _register_schemas() -> None:
    """Register the delegation validator once. Idempotent, so a double import
    cannot replace a validator and hide a version conflict."""
    from overlay_daemon import schema as _schema

    if not _schema.registry.has(TABLE_DELEGATIONS, 1):
        _schema.registry.register(TABLE_DELEGATIONS, 1, _validate_delegation_v1)


def _item_to_delegation(item: dict) -> Delegation:
    """Validate a row through the schema registry."""
    from overlay_daemon import schema as _schema

    _register_schemas()
    model, _was_fallback = _schema.registry.validate(TABLE_DELEGATIONS, item)
    if model is None:
        raise DelegationError(
            f"unsupported schema_version "
            f"({item.get('schema_version')}/{item.get('min_compatible_version')}) "
            f"on delegation row mesh_id={item.get('mesh_id')} "
            f"local_job_id={item.get('local_job_id')}"
        )
    return model


def _delegation_to_item(delegation: Delegation) -> dict:
    """Render a delegation as a row. `state` is stored as its string value so the
    table holds the vocabulary rather than a Python repr."""
    return {
        "mesh_id": delegation.mesh_id,
        "local_job_id": delegation.local_job_id,
        "local_cluster_id": delegation.local_cluster_id,
        "remote_cluster_id": delegation.remote_cluster_id,
        "remote_job_id": delegation.remote_job_id,
        "owner": delegation.owner,
        "state": delegation.state.value,
        "submitted_ts": delegation.submitted_ts,
        "updated_ts": delegation.updated_ts,
        "completed_ts": delegation.completed_ts,
        "stub_released": delegation.stub_released,
        "expires_at": delegation.expires_at,
        "schema_version": delegation.schema_version,
        "min_compatible_version": delegation.min_compatible_version,
    }


def create(
    *,
    mesh_id: str,
    local_job_id: str,
    local_cluster_id: str,
    remote_cluster_id: str,
    remote_job_id: str,
    owner: str,
    state: NormalizedState = NormalizedState.SUBMITTED,
    now: Optional[int] = None,
) -> Delegation:
    """
    Record a new delegation, returning the row as written.

    Conditional on the row not already existing. A delegation is created straight
    after a dispatch has been accepted by a peer, and an unconditional write there
    means a retried dispatch silently overwrites the first attempt's
    remote_job_id - which loses the only reference to a job that is at that moment
    running on the peer, so nothing will ever reconcile or cancel it.
    """
    stamp = int(time.time()) if now is None else int(now)
    delegation = Delegation(
        mesh_id=mesh_id,
        local_job_id=local_job_id,
        local_cluster_id=local_cluster_id,
        remote_cluster_id=remote_cluster_id,
        remote_job_id=remote_job_id,
        owner=owner,
        state=state,
        submitted_ts=stamp,
        updated_ts=stamp,
        expires_at=stamp + OPEN_TTL_DAYS * 86400,
    )
    try:
        ddb_client.mesh_table(TABLE_DELEGATIONS).put_item(
            Item=_delegation_to_item(delegation),
            ConditionExpression=(
                "attribute_not_exists(mesh_id) AND attribute_not_exists(local_job_id)"
            ),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DelegationConflictError(
                f"a delegation already exists for local_job_id={local_job_id} in "
                f"mesh {mesh_id}. The dispatch that produced remote_job_id="
                f"{remote_job_id} on {remote_cluster_id} is not recorded, so that "
                f"remote job will not be reconciled or cancelled by this cluster."
            ) from e
        raise DelegationError(f"could not create delegation {local_job_id}: {e}") from e
    except (BotoCoreError, DDBQueryError) as e:
        raise DelegationError(f"could not create delegation {local_job_id}: {e}") from e
    return delegation


def update_state(
    *,
    mesh_id: str,
    local_job_id: str,
    state: NormalizedState,
    now: Optional[int] = None,
) -> None:
    """
    Record the remote job's state.

    Reaching a terminal state sets completed_ts and shortens the TTL to the
    retention window. It does NOT mark the local stub released: that is a separate
    fact recorded by `mark_stub_released` only once the release has actually
    happened.
    """
    stamp = int(time.time()) if now is None else int(now)
    expression = "SET #s = :s, updated_ts = :u"
    values: dict[str, Any] = {":s": state.value, ":u": stamp}
    if state in TERMINAL_STATES:
        expression += ", completed_ts = :c, expires_at = :e"
        values[":c"] = stamp
        values[":e"] = stamp + RETENTION_DAYS * 86400
    try:
        ddb_client.mesh_table(TABLE_DELEGATIONS).update_item(
            Key={"mesh_id": mesh_id, "local_job_id": local_job_id},
            UpdateExpression=expression,
            ConditionExpression="attribute_exists(mesh_id)",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues=values,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DelegationMissingError(
                f"no delegation exists for local_job_id={local_job_id} in mesh "
                f"{mesh_id}, so it was not recorded as {state.value}. The write was "
                f"refused rather than creating a partial row, which would have been "
                f"permanent, invisible to the reconciler, and would have blocked a "
                f"later delegation for this job id."
            ) from e
        raise DelegationError(
            f"could not update delegation {local_job_id} to {state.value}: {e}"
        ) from e
    except (BotoCoreError, DDBQueryError) as e:
        raise DelegationError(
            f"could not update delegation {local_job_id} to {state.value}: {e}"
        ) from e


def mark_stub_released(
    *, mesh_id: str, local_job_id: str, now: Optional[int] = None
) -> None:
    """
    Record that the local parked stub has been taken out of the queue.

    Written only after the release succeeded. Writing it alongside the terminal
    state instead would mean a failed release is indistinguishable from a
    successful one, and since a delegation that is terminal and released is never
    listed again, the stub would stay parked with nothing left to notice it.
    """
    stamp = int(time.time()) if now is None else int(now)
    try:
        ddb_client.mesh_table(TABLE_DELEGATIONS).update_item(
            Key={"mesh_id": mesh_id, "local_job_id": local_job_id},
            UpdateExpression="SET stub_released = :r, updated_ts = :u",
            ConditionExpression="attribute_exists(mesh_id)",
            ExpressionAttributeValues={":r": True, ":u": stamp},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise DelegationMissingError(
                f"no delegation exists for local_job_id={local_job_id} in mesh "
                f"{mesh_id}, so the stub release was not recorded. The stub IS out "
                f"of the local queue, which is the outcome that mattered; the write "
                f"was refused rather than creating a partial row carrying only "
                f"stub_released."
            ) from e
        raise DelegationError(
            f"could not mark the stub for {local_job_id} released: {e}"
        ) from e
    except (BotoCoreError, DDBQueryError) as e:
        raise DelegationError(
            f"could not mark the stub for {local_job_id} released: {e}"
        ) from e


def get(*, mesh_id: str, local_job_id: str) -> Optional[Delegation]:
    """
    One delegation, or None when no row exists.

    AN UNREADABLE ROW RAISES DelegationError HERE, where the sibling
    `list_needing_reconciliation` skips it, and the asymmetry is the point. The
    validator raises ValueError on an uncastable field and KeyError on an absent
    required one, so leaving the call outside this function's error handling let
    both escape past the DelegationError contract this module documents - and the
    reconciler's two catch sites name that class explicitly.

    Neither of the sibling's two answers is available here. Returning None would
    say "no row exists" about a row that does, and the caller that wants this
    function is a dispatch idempotency check: told a delegation is absent, it
    dispatches the job a second time and the peer runs the user's work twice.
    Skipping has nothing to skip to. So the only safe report is that the row
    could not be read, which is what the caller can act on.
    """
    try:
        item = (
            ddb_client.mesh_table(TABLE_DELEGATIONS)
            .get_item(Key={"mesh_id": mesh_id, "local_job_id": local_job_id})
            .get("Item")
        )
    except (BotoCoreError, ClientError, DDBQueryError) as e:
        raise DelegationError(f"could not read delegation {local_job_id}: {e}") from e
    if not item:
        return None
    # Separate from the read above rather than folded into it, because the two
    # failures want different remedies: a transport error is worth retrying,
    # while a row this cluster cannot parse needs looking at.
    #
    # NARROW ON PURPOSE. `_item_to_delegation` already raises DelegationError, with
    # a message naming both schema versions, for a row written by a future peer;
    # DelegationError is not a subclass of any of these three, so it passes through
    # with that message intact. Catching Exception here would flatten "upgrade this
    # cluster" into "look at one row".
    try:
        return _item_to_delegation(item)
    except (ValueError, KeyError, TypeError) as e:
        raise DelegationError(
            f"delegation {local_job_id} in mesh {mesh_id} exists but could not be "
            f"read: {e}"
        ) from e


def list_needing_reconciliation(*, local_cluster_id: str) -> List[Delegation]:
    """
    Every delegation from this cluster that the reconciler still has work on.

    PAGINATED, through the resource API's own paginator rather than a single
    `query` call. A single call returns one page, capped at 1 MB, and silently
    reports whatever fit: the reconciler would then poll the first N delegations
    forever and never learn that the rest exist, which is indistinguishable from
    a cluster with no backlog. A busy mesh is exactly where that page fills.

    A row whose state is outside the vocabulary is SKIPPED with a warning rather
    than raising, because one hand-edited or future-version row must not stop
    every other delegation on the cluster from being reconciled. The skip is safe
    in this direction: an unreconciled delegation is retried on the next pass and
    stays visible in the ledger, whereas aborting the pass stalls all of them.

    The table is resolved inside the loop rather than once above it so that a
    resolution failure is translated by this function's own handler. `resolve`
    caches on success, so per-page costs a dict lookup and a Table construction,
    no call.
    """
    rows: List[Delegation] = []
    kwargs: dict[str, Any] = {
        "IndexName": OPEN_INDEX,
        "KeyConditionExpression": "local_cluster_id = :c",
        "ExpressionAttributeValues": {":c": local_cluster_id},
        "ScanIndexForward": False,
    }
    while True:
        try:
            response = ddb_client.mesh_table(TABLE_DELEGATIONS).query(**kwargs)
        except (BotoCoreError, ClientError, DDBQueryError) as e:
            raise DelegationError(
                f"could not list delegations for {local_cluster_id}: {e}"
            ) from e
        for item in response.get("Items", []):
            try:
                delegation = _item_to_delegation(item)
            except (DelegationError, ValueError, KeyError, TypeError):
                logger.warning(
                    "delegation_store: skipping unreadable row local_job_id=%s in "
                    "mesh=%s; the rest of this cluster's delegations are unaffected",
                    item.get("local_job_id"),
                    item.get("mesh_id"),
                    exc_info=True,
                )
                continue
            if delegation.needs_reconciliation:
                rows.append(delegation)
        last = response.get("LastEvaluatedKey")
        if not last:
            return rows
        kwargs["ExclusiveStartKey"] = last
