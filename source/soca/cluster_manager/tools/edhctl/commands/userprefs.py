# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
edhctl userprefs -- admin tooling for the WebUI user-preferences store
(DynamoDB table ``{cluster_id}-user-preferences``, PK = username).

Backstop for the user-preferences cleanup lifecycle (see
web_interface/docs/UserPreferences-Design.md, decision #7 / §10):

  * PRIMARY cleanup is the in-band hook -- the WebUI user-delete flow calls
    user_pref_store.clear_all() when a user is deprovisioned through EDH.
  * This CLI is the BACKSTOP for the only gap that hook misses: a user removed
    out-of-band (directly in the directory, bypassing EDH). An orphaned prefs
    row is inert (keyed by username, only ever read when THAT user logs in) and
    harmless until username reuse -- so cleanup is an operator-invoked,
    preview-then-ACK action, NOT an autonomous background deleter.

``reconcile`` diffs the prefs table against the live directory (the identity
provider, same enumeration as ``GET /api/ldap/users``). It PREVIEWS by default
and only deletes with an explicit ACK.

SAFETY GUARD: the directory enumeration must return a COMPLETE, non-empty list
before any prune. If it fails -- including ``SIZELIMIT_EXCEEDED`` on a directory
larger than the server page cap (until the LDAP paging fix lands fleet-wide) --
or returns zero users, the command ABORTS and deletes nothing. A partial or
failed listing must never be read as "these users are gone."
"""

import logging

import click
from fnmatch import fnmatch

from commands.common import (
    confirm,
    get_cluster_id,
    is_controller_instance,
    print_output,
)
from utils.aws import boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

_PK = "username"


def _table_name() -> str:
    return f"{get_cluster_id()}-user-preferences"


def _ddb():
    """Low-level DynamoDB client (mirrors web_interface user_pref_store._ddb)."""
    _resp = utils_boto3.get_boto(service_name="dynamodb")
    if _resp.get("success") is False:
        SocaError.AWS_API_ERROR(
            service_name="dynamodb",
            helper=f"Failed to get dynamodb client: {_resp.get('message')}",
        )
        return None
    return _resp.get("message")


def _all_pref_usernames(table: str) -> list:
    """
    Paginated Scan of every username with a stored preferences row. Pagination
    is mandatory -- an un-paginated Scan silently stops at the first 1 MB page.
    """
    _client = _ddb()
    if _client is None:
        print_output("Failed to connect to DynamoDB.", error=True)
        return []
    _names = []
    _kwargs = {
        "TableName": table,
        "ProjectionExpression": "#u",
        "ExpressionAttributeNames": {"#u": _PK},
    }
    while True:
        _resp = _client.scan(**_kwargs)
        for _item in _resp.get("Items", []):
            if _PK in _item and "S" in _item[_PK]:
                _names.append(_item[_PK]["S"])
        _last = _resp.get("LastEvaluatedKey")
        if not _last:
            break
        _kwargs["ExclusiveStartKey"] = _last
    return _names


def _decode_item(item: dict) -> dict:
    """Decode a DDB attribute map to plain python scalars."""
    _out = {}
    for _k, _v in item.items():
        if "BOOL" in _v:
            _out[_k] = _v["BOOL"]
        elif "N" in _v:
            _cast = SocaCastEngine(_v["N"]).cast_as(expected_type=int)
            _out[_k] = _cast.get("message") if _cast.get("success") else None
        elif "S" in _v:
            _out[_k] = _v["S"]
    return _out


def _scan_items(table: str) -> list:
    """Paginated Scan returning the full (raw) item maps for every row."""
    _client = _ddb()
    if _client is None:
        print_output("Failed to connect to DynamoDB.", error=True)
        return []
    _items = []
    _kwargs = {"TableName": table}
    while True:
        _resp = _client.scan(**_kwargs)
        _items.extend(_resp.get("Items", []))
        _last = _resp.get("LastEvaluatedKey")
        if not _last:
            break
        _kwargs["ExclusiveStartKey"] = _last
    return _items


def _directory_usernames() -> set:
    """
    Enumerate the CURRENT set of directory usernames via the identity provider
    (same base/filter/attr as GET /api/ldap/users). Returns a set.

    SAFETY GUARD (see module docstring): aborts the whole command -- pruning
    nothing -- if the enumeration fails (incl. SIZELIMIT_EXCEEDED on a directory
    bigger than the server page cap before the LDAP paging fix) or returns
    empty. Never prune against a partial/failed snapshot.
    """
    from utils.config import SocaConfig
    from utils.identity_provider_client import SocaIdentityProviderClient

    _provider_resp = SocaConfig(
        key="/configuration/UserDirectory/provider"
    ).get_value()
    if not _provider_resp.success:
        print_output(
            "Unable to resolve /configuration/UserDirectory/provider; "
            "cannot reconcile.",
            error=True,
        )
    _provider = _provider_resp.message

    _base_resp = SocaConfig(
        key="/configuration/UserDirectory/people_search_base"
    ).get_value()
    if not _base_resp.success or not _base_resp.message:
        print_output(
            "Unable to resolve /configuration/UserDirectory/people_search_base; "
            "cannot reconcile.",
            error=True,
        )
    _base = _base_resp.message

    if _provider in ("openldap", "existing_openldap"):
        _filter = "(objectClass=person)"
        _attr = "uid"
    elif _provider == "aws_ds_managed_activedirectory":
        _filter = (
            "(&(objectClass=user)(!(sAMAccountName=Admin))"
            "(!(sAMAccountName=krbtgt))(!(sAMAccountName=AWS_*)))"
        )
        _attr = "sAMAccountName"
    else:  # existing_activedirectory
        _filter = (
            "(&(objectClass=user)(!(sAMAccountName=Administrator))"
            "(!(sAMAccountName=krbtgt))(!(sAMAccountName=AWS_*)))"
        )
        _attr = "sAMAccountName"

    _client = SocaIdentityProviderClient()
    _client.initialize()
    _client.bind_as_service_account()
    _resp = _client.search(base=_base, filter=_filter, attr_list=[_attr])

    if not _resp.get("success"):
        print_output(
            f"Directory enumeration failed: {_resp.get('message')}. Refusing to "
            f"prune on an incomplete/failed listing -- a directory larger than "
            f"the server page cap needs the LDAP paging fix first. No rows "
            f"deleted.",
            error=True,
        )

    _names = set()
    for _dn, _attrs in _resp.get("message") or []:
        _vals = _attrs.get(_attr) or []
        if _vals:
            _v = _vals[0]
            _names.add(_v.decode("utf-8") if Validators.is_bytes(_v) else _v)

    if not _names:
        print_output(
            "Directory enumeration returned 0 usernames. Refusing to prune (a "
            "bad/empty listing must not orphan every live user). No rows deleted.",
            error=True,
        )
    return _names


@click.group()
def userprefs():
    """Manage the WebUI user-preferences store."""
    pass


@userprefs.command()
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    default=False,
    help="Delete orphaned rows after an explicit confirmation. "
    "Default is preview-only (no deletes).",
)
@click.option(
    "--yes",
    "skip_prompt",
    is_flag=True,
    default=False,
    help="With --apply, skip the interactive confirmation (for scripted use).",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json"]),
    help="Output format for the preview.",
)
@click.pass_context
def reconcile(ctx, apply_changes, skip_prompt, output):
    """
    Find prefs rows whose username is no longer in the directory and (with ACK)
    delete them. Preview-only by default.
    """
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host.",
            error=True,
        )

    _table = _table_name()
    _dir_names = _directory_usernames()  # aborts here if listing is unsafe
    _pref_names = _all_pref_usernames(_table)
    _orphans = sorted(n for n in _pref_names if n not in _dir_names)

    logger.info(
        f"userprefs reconcile: table={_table} pref_rows={len(_pref_names)} "
        f"directory_users={len(_dir_names)} orphans={len(_orphans)}"
    )

    if output == "json":
        print_output(
            {
                "table": _table,
                "pref_rows": len(_pref_names),
                "directory_users": len(_dir_names),
                "orphans": _orphans,
            },
            output="json",
        )
    else:
        print_output(
            f"Preferences table   : {_table}\n"
            f"Prefs rows          : {len(_pref_names)}\n"
            f"Directory users     : {len(_dir_names)}\n"
            f"Orphaned prefs rows : {len(_orphans)}"
        )
        if _orphans:
            print_output("Orphans:\n  " + "\n  ".join(_orphans))

    if not _orphans:
        print_output("Nothing to reconcile -- no orphaned preference rows.")
        return

    if not apply_changes:
        print_output(
            "\nPreview only. Re-run with --apply to delete the rows above "
            "(you will be asked to confirm)."
        )
        return

    if not skip_prompt:
        if not confirm(
            f"\nDelete {len(_orphans)} orphaned preference row(s)? This cannot "
            f"be undone"
        ):
            print_output("Aborted. No rows deleted.")
            return

    _client = _ddb()
    if _client is None:
        print_output("Failed to connect to DynamoDB.", error=True)
        return
    _deleted = 0
    for _user in _orphans:
        try:
            _client.delete_item(TableName=_table, Key={_PK: {"S": _user}})
            logger.info(f"userprefs reconcile: deleted orphan row user={_user}")
            _deleted += 1
        except Exception as err:
            logger.error(f"userprefs reconcile: failed to delete {_user}: {err}")
            print_output(f"  WARNING: failed to delete {_user}: {err}")

    print_output(f"Deleted {_deleted} of {len(_orphans)} orphaned row(s).")


@userprefs.command()
@click.argument("user", required=False)
@click.option(
    "--like",
    "pattern",
    default=None,
    help="Glob over usernames (e.g. 'orphan.test-*'). Mutually exclusive with USER.",
)
@click.option(
    "--output",
    default="json",
    type=click.Choice(["text", "json"]),
    help="Output format.",
)
@click.pass_context
def show(ctx, user, pattern, output):
    """Inspect stored prefs: one exact USER, or every row matching --like."""
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host.",
            error=True,
        )
    if (user is None) == (pattern is None):
        print_output(
            "Provide exactly one of USER or --like PATTERN.", error=True
        )
    _table = _table_name()

    if pattern:
        _rows = [
            _decode_item(_it)
            for _it in _scan_items(_table)
            if fnmatch(_it.get(_PK, {}).get("S", ""), pattern)
        ]
        _rows.sort(key=lambda r: r.get(_PK, ""))
        if not _rows:
            print_output(f"No stored preferences match '{pattern}'.")
            return
        if output == "json":
            print_output(_rows, output="json")
        else:
            print_output(f"{len(_rows)} row(s) matching '{pattern}':")
            for _r in _rows:
                print_output(f"  {_r}")
        return

    _client = _ddb()
    if _client is None:
        print_output("Failed to connect to DynamoDB.", error=True)
        return
    _resp = _client.get_item(TableName=_table, Key={_PK: {"S": user}})
    _item = _resp.get("Item")
    if not _item:
        print_output(f"No stored preferences for '{user}' (resolves to defaults).")
        return
    print_output(_decode_item(_item), output=output)


@userprefs.command(name="list")
@click.option(
    "--like",
    "pattern",
    default=None,
    help="Glob filter over usernames (e.g. 'anna.*').",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json"]),
    help="Output format.",
)
@click.pass_context
def list_(ctx, pattern, output):
    """List usernames with a stored prefs row (optionally filtered by --like)."""
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host.",
            error=True,
        )
    _names = _all_pref_usernames(_table_name())
    if pattern:
        _names = [n for n in _names if fnmatch(n, pattern)]
    _names.sort()
    if output == "json":
        print_output({"count": len(_names), "usernames": _names}, output="json")
    else:
        _suffix = f" matching '{pattern}'" if pattern else ""
        print_output(f"{len(_names)} row(s){_suffix}")
        if _names:
            print_output("\n".join("  " + n for n in _names))


@userprefs.command()
@click.argument("user", required=False)
@click.option(
    "--like",
    "pattern",
    default=None,
    help="Glob over usernames for a bulk clear (e.g. 'orphan.test-*'). "
    "Mutually exclusive with USER.",
)
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    default=False,
    help="Delete after an explicit confirmation. Default is preview-only.",
)
@click.option(
    "--yes",
    "skip_prompt",
    is_flag=True,
    default=False,
    help="With --apply, skip the interactive confirmation (for scripted use).",
)
@click.pass_context
def clear(ctx, user, pattern, apply_changes, skip_prompt):
    """
    Delete stored prefs for one exact USER, or every row matching --like.
    Preview-then-ACK, same gating as reconcile.
    """
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host.",
            error=True,
        )
    if (user is None) == (pattern is None):
        print_output(
            "Provide exactly one of USER or --like PATTERN.", error=True
        )
    _table = _table_name()
    _client = _ddb()
    if _client is None:
        print_output("Failed to connect to DynamoDB.", error=True)
        return

    if pattern:
        _targets = sorted(
            n for n in _all_pref_usernames(_table) if fnmatch(n, pattern)
        )
        _scope = f"pattern '{pattern}'"
    else:
        _resp = _client.get_item(TableName=_table, Key={_PK: {"S": user}})
        _targets = [user] if _resp.get("Item") else []
        _scope = f"user '{user}'"

    print_output(f"Matched {len(_targets)} row(s) for {_scope}.")
    if _targets:
        _preview = _targets[:200]
        print_output("\n".join("  " + t for t in _preview))
        if Validators.is_list_length_greater_than(_targets, 200):
            print_output(f"  ... and {len(_targets) - 200} more")

    if not _targets:
        print_output("Nothing to clear.")
        return

    if not apply_changes:
        print_output(
            "\nPreview only. Re-run with --apply to delete the row(s) above "
            "(you will be asked to confirm)."
        )
        return

    if not skip_prompt:
        if not confirm(
            f"\nDelete {len(_targets)} preference row(s)? This cannot be undone"
        ):
            print_output("Aborted. No rows deleted.")
            return

    _deleted = 0
    for _u in _targets:
        try:
            _client.delete_item(TableName=_table, Key={_PK: {"S": _u}})
            logger.info(f"userprefs clear: deleted user={_u} ({_scope})")
            _deleted += 1
        except Exception as err:
            logger.error(f"userprefs clear: failed to delete {_u}: {err}")
            print_output(f"  WARNING: failed to delete {_u}: {err}")

    print_output(f"Deleted {_deleted} of {len(_targets)} row(s).")
