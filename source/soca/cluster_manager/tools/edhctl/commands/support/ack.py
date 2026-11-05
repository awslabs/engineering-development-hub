# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import getpass
import logging
import os
from datetime import datetime, timezone

import click

from commands.common import confirm, print_output
from commands.support.common import (
    ABSENT_SENTINEL,
    SOURCE_EDH_PATCH,
    SOURCE_OPERATOR,
    get_tree_root,
    read_ledger,
    verify_tree,
    write_ledger,
)
from utils.integrity_manifest import hash_file

logger = logging.getLogger("soca_logger")


@click.group()
def ack():
    """Manage hash-pinned acknowledgements of known deviations."""
    pass


def _pin_for(tree_root: str, relative_path: str) -> str:
    # A MISSING file pins the ABSENCE. If content later appears at that path it
    # is a new deviation, not a satisfied acknowledgement.
    _full_path = os.path.join(tree_root, relative_path)
    if not os.path.isfile(_full_path):
        return ABSENT_SENTINEL
    return hash_file(file_path=_full_path)


@ack.command("add")
@click.argument("paths", nargs=-1)
@click.option(
    "--all-pending",
    is_flag=True,
    default=False,
    help=(
        "Acknowledge every currently-unexplained deviation (MODIFIED + "
        "MISSING). Does not touch PATCHED entries, which EDH already explains."
    ),
)
@click.option(
    "--reason",
    required=True,
    help="Why this deviation is expected. Required for single and bulk alike.",
)
@click.option(
    "--yes",
    "assume_yes",
    is_flag=True,
    default=False,
    help=(
        "Skip the interactive confirmation on --all-pending. Required with "
        "--output json|yaml, which cannot prompt."
    ),
)
@click.option("--output", default="text", type=click.Choice(["text", "json", "yaml"]))
def ack_add(paths, all_pending, reason, assume_yes, output):
    """Acknowledge deviations, pinned to their current content hash.

    Acknowledgement reclassifies a deviation; it never reduces the headline
    count. `verify --ignore-acknowledgements` always reports raw truth, so an
    acknowledgement cannot hide anything from EDH support.
    """
    _tree = get_tree_root()
    if _tree.get("success") is False:
        print_output(message=_tree.get("message"), output=output, error=True)
        return
    _tree_root = _tree.get("message")

    if bool(paths) == bool(all_pending):
        print_output(
            message="Provide either explicit paths or --all-pending, not both.",
            output=output,
            error=True,
        )
        return

    _targets = list(paths)
    if all_pending:
        _findings = verify_tree(tree_root=_tree_root)
        if _findings.get("success") is False:
            print_output(
                message=_findings.get("message"), output=output, error=True
            )
            return
        _message = _findings.get("message")
        # --all-pending is a UX affordance, NEVER a storage format. It expands
        # here, at execution time, into N individual hash-pinned entries. A
        # stored glob or pattern would match files that do not exist yet, which
        # is exactly the path-pinned blind spot the design forbids.
        _targets = list(_message.get("modified") or []) + list(
            _message.get("missing") or []
        )
        if not _targets:
            print_output(
                message="Nothing pending to acknowledge.", output=output
            )
            return
        # The listing and the prompt are human-readable output on stdout, and
        # confirm() blocks on stdin. Emitting either under --output json|yaml
        # would corrupt the machine-readable contract and then hang, so a
        # non-text run must carry --yes to state its intent up front instead.
        if output != "text" and assume_yes is False:
            print_output(
                message=(
                    "--all-pending with --output json|yaml cannot prompt for "
                    "confirmation. Re-run with --yes to confirm up front."
                ),
                output=output,
                error=True,
            )
            return
        if output == "text":
            click.echo(f"About to acknowledge {len(_targets)} deviation(s):")
            for _path in _targets:
                click.echo(f"  {_path}")
        if assume_yes is False:
            if confirm(prompt="Acknowledge all of the above?") is False:
                print_output(
                    message="Aborted. Nothing was written.", output=output
                )
                return

    _read = read_ledger(tree_root=_tree_root)
    if _read.get("success") is False:
        print_output(message=_read.get("message"), output=output, error=True)
        return
    _ledger = _read.get("message")

    _now = datetime.now(timezone.utc).isoformat()
    _operator = getpass.getuser()
    _added = []
    for _relative_path in _targets:
        _existing = _ledger.get(_relative_path) or {}
        if _existing.get("source") == SOURCE_EDH_PATCH:
            # Already explained by EDH; not operator-acknowledgeable.
            logger.debug(f"Skipping EDH-patched entry {_relative_path}")
            continue
        _ledger[_relative_path] = {
            "hash": _pin_for(tree_root=_tree_root, relative_path=_relative_path),
            "reason": reason,
            "acknowledged_at": _now,
            "acknowledged_by": _operator,
            "source": SOURCE_OPERATOR,
        }
        _added.append(_relative_path)

    _written = write_ledger(tree_root=_tree_root, ledger=_ledger)
    if _written.get("success") is False:
        print_output(message=_written.get("message"), output=output, error=True)
        return

    print_output(
        message={
            "acknowledged": sorted(_added),
            "count": len(_added),
            "ledger": _written.get("message"),
        }
        if output != "text"
        else f"Acknowledged {len(_added)} path(s). Ledger: {_written.get('message')}",
        output=output,
    )


@ack.command("list")
@click.option("--output", default="text", type=click.Choice(["text", "json", "yaml"]))
def ack_list(output):
    """List acknowledgements recorded on this node."""
    _tree = get_tree_root()
    if _tree.get("success") is False:
        print_output(message=_tree.get("message"), output=output, error=True)
        return

    _read = read_ledger(tree_root=_tree.get("message"))
    if _read.get("success") is False:
        print_output(message=_read.get("message"), output=output, error=True)
        return
    _ledger = _read.get("message")

    if output != "text":
        print_output(message=_ledger, output=output)
        return

    if not _ledger:
        click.echo("No acknowledgements recorded.")
        return
    click.echo(f"{len(_ledger)} acknowledgement(s):")
    for _path in sorted(_ledger):
        _entry = _ledger[_path]
        _pin = _entry.get("hash")
        _shown = "absent" if _pin == ABSENT_SENTINEL else str(_pin)[:12]
        click.echo(f"  {_path}")
        click.echo(
            f"      pinned={_shown}  by={_entry.get('acknowledged_by')}  "
            f"at={_entry.get('acknowledged_at')}  "
            f"source={_entry.get('source')}"
        )
        click.echo(f"      reason: {_entry.get('reason')}")


@ack.command("remove")
@click.argument("paths", nargs=-1)
@click.option(
    "--all",
    "remove_all",
    is_flag=True,
    default=False,
    help="Remove every acknowledgement.",
)
@click.option("--output", default="text", type=click.Choice(["text", "json", "yaml"]))
def ack_remove(paths, remove_all, output):
    """Remove acknowledgements.

    Needs no confirmation guard: removing an acknowledgement can only make the
    report noisier, never quieter.
    """
    _tree = get_tree_root()
    if _tree.get("success") is False:
        print_output(message=_tree.get("message"), output=output, error=True)
        return
    _tree_root = _tree.get("message")

    if bool(paths) == bool(remove_all):
        print_output(
            message="Provide either explicit paths or --all, not both.",
            output=output,
            error=True,
        )
        return

    _read = read_ledger(tree_root=_tree_root)
    if _read.get("success") is False:
        print_output(message=_read.get("message"), output=output, error=True)
        return
    _ledger = _read.get("message")

    _removed = []
    if remove_all:
        _removed = sorted(_ledger)
        _ledger = {}
    else:
        for _relative_path in paths:
            if _relative_path in _ledger:
                del _ledger[_relative_path]
                _removed.append(_relative_path)

    _written = write_ledger(tree_root=_tree_root, ledger=_ledger)
    if _written.get("success") is False:
        print_output(message=_written.get("message"), output=output, error=True)
        return

    print_output(
        message={"removed": sorted(_removed), "count": len(_removed)}
        if output != "text"
        else f"Removed {len(_removed)} acknowledgement(s).",
        output=output,
    )
