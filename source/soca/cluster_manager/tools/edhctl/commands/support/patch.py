# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
`edhctl support patch` -- apply an EDH-supplied patch bundle.

This is the producer for the PATCHED label. Without it, a file EDH itself asked a
customer to change is indistinguishable from a file the customer changed on their
own: both are a hash mismatch, both read as MODIFIED, and the operator is left to
remember which is which.

WHAT PATCHED IS, AND IS NOT. It is an ATTRIBUTION label, not a cryptographic
claim. Bundles are not signed, so a determined operator could hand-write a
patch.json and launder their own change into PATCHED. That is deliberately not
defended against, for the same reason the acknowledgement ledger is not:

  * the operator owns the cluster, so there is no boundary to defend
  * Invariant 1 already covers support's need for truth -- PATCHED is a
    reclassified subset that never reduces the headline deviation count, and
    `verify --ignore-acknowledgements` reports the raw set regardless of what any
    ledger entry claims

Signing would need a key-distribution story EDH does not have, and would buy
nothing against the only actor who can write this ledger.

Ordering here is the safety property. A bundle carries the hash it expects to
find BEFORE it patches, so applying a bundle to a tree that has already drifted
is refused rather than layered on top of unknown state.
"""

import hashlib
import json
import logging
import os
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone

import click

from commands.common import confirm, print_output
from commands.support.common import (
    SOURCE_EDH_PATCH,
    get_tree_root,
    read_ledger,
    write_ledger,
)
from utils.error import SocaError
from utils.integrity_manifest import hash_file, is_within_tree, read_manifest
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

BUNDLE_MANIFEST_NAME = "patch.json"
BUNDLE_PAYLOAD_DIR = "files"


@click.group()
def patch():
    """Apply and inspect EDH-supplied patch bundles."""
    pass


def compute_bundle_digest(patch_manifest: dict) -> str:
    """Fingerprint a bundle over its declared file transitions.

    Covers (path, before, after) for every file plus the patch identity, so a
    truncated or edited bundle fails to recompute. Not a signature -- it detects
    corruption, not forgery.
    """
    _digest = hashlib.sha256()
    _digest.update(str(patch_manifest.get("patch_id") or "").encode("utf-8"))
    _digest.update(str(patch_manifest.get("ticket") or "").encode("utf-8"))
    _files = patch_manifest.get("files") or {}
    for _relative_path in sorted(_files):
        _entry = _files[_relative_path]
        _digest.update(_relative_path.encode("utf-8"))
        _digest.update(str(_entry.get("sha256_before") or "").encode("utf-8"))
        _digest.update(str(_entry.get("sha256_after") or "").encode("utf-8"))
    return _digest.hexdigest()


def read_bundle(bundle_path: str, staging_directory: str) -> SocaResponse:
    """Extract a bundle and validate its own integrity before trusting it."""
    if not os.path.isfile(bundle_path):
        return SocaError.GENERIC_ERROR(helper=f"No patch bundle at {bundle_path}")

    try:
        with tarfile.open(bundle_path) as _tar:
            # filter="data" refuses absolute paths, parent traversal, and device
            # nodes. A patch bundle is untrusted input arriving over email or S3.
            _tar.extractall(staging_directory, filter="data")
    except (tarfile.TarError, OSError, ValueError) as _err:
        return SocaError.GENERIC_ERROR(
            helper=f"Could not extract {bundle_path}: {_err}"
        )

    _manifest_path = os.path.join(staging_directory, BUNDLE_MANIFEST_NAME)
    if not os.path.isfile(_manifest_path):
        return SocaError.GENERIC_ERROR(
            helper=f"Bundle is missing {BUNDLE_MANIFEST_NAME}"
        )
    try:
        with open(_manifest_path, "r") as _fh:
            _patch_manifest = json.load(_fh)
    except (OSError, ValueError) as _err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unreadable {BUNDLE_MANIFEST_NAME}: {_err}"
        )

    _declared = _patch_manifest.get("bundle_digest")
    _recomputed = compute_bundle_digest(patch_manifest=_patch_manifest)
    if _declared != _recomputed:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"Bundle digest mismatch: declared {_declared}, recomputed "
                f"{_recomputed}. The bundle is corrupt or was edited."
            )
        )

    if not (_patch_manifest.get("files") or {}):
        return SocaError.GENERIC_ERROR(helper="Bundle declares no files")

    return SocaResponse(success=True, message=_patch_manifest)


def check_applies_to(patch_manifest: dict, tree_root: str) -> SocaResponse:
    """Refuse a bundle authored against a different release.

    Applying a patch built for another build produces a file that matches neither
    the old release nor the new one, which is how a cluster ends up in a state
    nobody can reason about. The before-hash check would catch most of these
    anyway, but failing on the explicit constraint gives the operator a message
    that says WHY rather than just reporting an unexpected hash.
    """
    _manifest = read_manifest(tree_root=tree_root)
    if not _manifest:
        return SocaError.GENERIC_ERROR(
            helper=(
                "No integrity manifest on this cluster, so the patch cannot be "
                "matched to a release. Refusing to apply."
            )
        )

    _applies_to = patch_manifest.get("applies_to") or {}
    _wanted_version = _applies_to.get("version")
    _actual_version = _manifest.get("version")
    if _wanted_version and _wanted_version != _actual_version:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"Patch targets EDH {_wanted_version} but this cluster runs "
                f"{_actual_version}."
            )
        )

    _wanted_digests = _applies_to.get("manifest_digests") or []
    _actual_digest = _manifest.get("manifest_digest")
    if _wanted_digests and _actual_digest not in _wanted_digests:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"Patch was authored against a different build. This cluster's "
                f"manifest digest is {str(_actual_digest)[:16]}, which is not in "
                f"the bundle's target list."
            )
        )
    return SocaResponse(success=True, message=_manifest)


def plan_patch(patch_manifest: dict, tree_root: str) -> SocaResponse:
    """Classify every file in the bundle against the tree as it is right now.

    Returns {"to_apply": [...], "already_applied": [...], "blocked": [...]}.
    Nothing is written -- this is what --dry-run reports and what apply gates on.
    """
    _to_apply = []
    _already_applied = []
    _blocked = []

    for _relative_path, _transition in (patch_manifest.get("files") or {}).items():
        # A manifest key is untrusted data, and it is what decides where bytes
        # land. Refuse anything that leaves the tree before the path is used for
        # anything at all, including the isfile() probe below.
        if not is_within_tree(tree_root=tree_root, relative_path=_relative_path):
            _blocked.append(
                {
                    "path": _relative_path,
                    "reason": (
                        "path escapes the cluster tree and will not be touched"
                    ),
                }
            )
            continue

        _full_path = os.path.join(tree_root, _relative_path)
        _before = _transition.get("sha256_before")
        _after = _transition.get("sha256_after")

        if not os.path.isfile(_full_path):
            _blocked.append(
                {"path": _relative_path, "reason": "file is absent on this cluster"}
            )
            continue

        _actual = hash_file(file_path=_full_path)
        if _actual == _after:
            # Idempotent: re-running a bundle is a normal operator action, and it
            # must not read as a failure.
            _already_applied.append(_relative_path)
        elif _actual == _before:
            _to_apply.append(_relative_path)
        else:
            _blocked.append(
                {
                    "path": _relative_path,
                    "reason": (
                        "current content matches neither the expected pre-patch "
                        "nor post-patch hash -- this file has been changed by "
                        "something else"
                    ),
                }
            )

    return SocaResponse(
        success=True,
        message={
            "to_apply": sorted(_to_apply),
            "already_applied": sorted(_already_applied),
            "blocked": sorted(_blocked, key=lambda _b: _b["path"]),
        },
    )


def _install_file(source_path: str, destination_path: str) -> SocaResponse:
    """Replace a file, preserving its mode, via a same-directory rename.

    Same directory so the rename is atomic: a half-written shipped file would be
    worse than an unapplied patch.
    """
    try:
        _mode = os.stat(destination_path).st_mode & 0o777
        _directory = os.path.dirname(destination_path)
        _fd, _temporary = tempfile.mkstemp(dir=_directory)
        os.close(_fd)
        shutil.copyfile(source_path, _temporary)
        os.chmod(_temporary, _mode)
        os.replace(_temporary, destination_path)
    except OSError as _err:
        return SocaError.GENERIC_ERROR(
            helper=f"Could not install {destination_path}: {_err}"
        )
    return SocaResponse(success=True, message=destination_path)


@patch.command("apply")
@click.argument("bundle")
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Report what would change and why, without writing anything.",
)
@click.option(
    "--yes",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt.",
)
@click.option("--output", default="text", type=click.Choice(["text", "json", "yaml"]))
def patch_apply(bundle, dry_run, yes, output):
    """Apply an EDH-supplied patch bundle and record it as PATCHED.

    Refuses unless every targeted file currently matches the hash the bundle
    expects to find, so a patch is never layered over a tree that has drifted for
    some other reason.
    """
    _tree = get_tree_root()
    if _tree.get("success") is False:
        print_output(message=_tree.get("message"), output=output, error=True)
        return
    _tree_root = _tree.get("message")

    with tempfile.TemporaryDirectory() as _staging:
        _read = read_bundle(bundle_path=bundle, staging_directory=_staging)
        if _read.get("success") is False:
            print_output(message=_read.get("message"), output=output, error=True)
            return
        _patch_manifest = _read.get("message")

        _applies = check_applies_to(
            patch_manifest=_patch_manifest, tree_root=_tree_root
        )
        if _applies.get("success") is False:
            print_output(message=_applies.get("message"), output=output, error=True)
            return

        _planned = plan_patch(
            patch_manifest=_patch_manifest, tree_root=_tree_root
        ).get("message")

        _summary = {
            "patch_id": _patch_manifest.get("patch_id"),
            "ticket": _patch_manifest.get("ticket"),
            "description": _patch_manifest.get("description"),
            "to_apply": _planned["to_apply"],
            "already_applied": _planned["already_applied"],
            "blocked": _planned["blocked"],
            "dry_run": dry_run,
        }

        if _planned["blocked"]:
            _summary["applied"] = []
            _summary["result"] = "REFUSED"
            if output == "text":
                click.echo(
                    f"Patch {_summary['patch_id']} ({_summary['ticket']}) "
                    f"REFUSED -- {len(_planned['blocked'])} file(s) are not in "
                    f"the state this patch expects:"
                )
                for _entry in _planned["blocked"]:
                    click.echo(f"  {_entry['path']}: {_entry['reason']}")
                click.echo(
                    "Run 'edhctl support verify' to see the current deviation "
                    "set before retrying."
                )
            else:
                print_output(message=_summary, output=output)
            # A refusal is a failure to apply, so it must be distinguishable from
            # a successful apply by exit code alone. The post-install
            # verification branches below already exit non-zero via
            # print_output(error=True); this path exits directly instead so the
            # human-readable detail above is not printed a second time.
            sys.exit(1)

        if not _planned["to_apply"]:
            # SELF-HEAL a partial apply. If the writes landed but record_patch
            # failed, the files now match the post-patch hash, so planning puts
            # them all in already_applied and this branch returns before
            # record_patch is ever reached again. Without the backfill below the
            # tree would stay patched with no PATCHED entry, and verify would
            # report those files as unexplained MODIFIED forever -- the outcome
            # this feature exists to prevent.
            _already = list(_planned["already_applied"])
            _split = recordable_paths(
                tree_root=_tree_root, applied=[], already_applied=_already
            )
            _unrecorded = _split["unrecorded"]
            if _unrecorded:
                _recorded = record_patch(
                    tree_root=_tree_root,
                    patch_manifest=_patch_manifest,
                    paths=_split["recordable"],
                )
                if _recorded.get("success") is False:
                    print_output(
                        message=(
                            f"{len(_unrecorded)} file(s) are already at the "
                            f"post-patch hash but carry no PATCHED ledger entry, "
                            f"and the ledger could not be written: "
                            f"{_recorded.get('message')}. Until it is, "
                            f"'edhctl support verify' will report them as "
                            f"unexplained. Re-run this command once the ledger "
                            f"is writable."
                        ),
                        output=output,
                        error=True,
                    )
                    return
                _summary["applied"] = []
                _summary["result"] = "RECORDED"
                print_output(
                    message=_summary
                    if output != "text"
                    else (
                        f"Patch {_summary['patch_id']} was already on disk but "
                        f"unrecorded. Wrote {len(_unrecorded)} PATCHED ledger "
                        f"entry(ies); nothing on disk changed."
                    ),
                    output=output,
                )
                return

            _summary["applied"] = []
            _summary["result"] = "ALREADY_APPLIED"
            print_output(
                message=_summary
                if output != "text"
                else (
                    f"Patch {_summary['patch_id']} is already applied "
                    f"({len(_planned['already_applied'])} file(s) already at the "
                    f"post-patch hash). Nothing to do."
                ),
                output=output,
            )
            return

        if dry_run:
            _summary["applied"] = []
            _summary["result"] = "DRY_RUN"
            if output == "text":
                click.echo(
                    f"Patch {_summary['patch_id']} ({_summary['ticket']}) would "
                    f"change {len(_planned['to_apply'])} file(s):"
                )
                for _relative_path in _planned["to_apply"]:
                    click.echo(f"  {_relative_path}")
                if _planned["already_applied"]:
                    click.echo(
                        f"  ({len(_planned['already_applied'])} already at the "
                        f"post-patch hash)"
                    )
            else:
                print_output(message=_summary, output=output)
            return

        if yes is False:
            click.echo(
                f"Patch {_summary['patch_id']} ({_summary['ticket']}) will "
                f"replace {len(_planned['to_apply'])} shipped file(s):"
            )
            for _relative_path in _planned["to_apply"]:
                click.echo(f"  {_relative_path}")
            if confirm(prompt="Apply this patch?") is False:
                print_output(
                    message="Aborted. Nothing was written.", output=output
                )
                return

        _applied = []
        for _relative_path in _planned["to_apply"]:
            _source = os.path.join(_staging, BUNDLE_PAYLOAD_DIR, _relative_path)
            if not os.path.isfile(_source):
                print_output(
                    message=(
                        f"Bundle declares {_relative_path} but carries no payload "
                        f"for it."
                    ),
                    output=output,
                    error=True,
                )
                return
            # Defence in depth. plan_patch() already blocked escaping keys and
            # apply refuses to run with anything blocked, so reaching this is a
            # bug rather than an expected path -- which is exactly why it is
            # checked again at the point of the write.
            if not is_within_tree(
                tree_root=_tree_root, relative_path=_relative_path
            ):
                print_output(
                    message=(
                        f"Refusing to write {_relative_path}: it escapes the "
                        f"cluster tree."
                    ),
                    output=output,
                    error=True,
                )
                return
            _destination = os.path.join(_tree_root, _relative_path)
            _installed = _install_file(
                source_path=_source, destination_path=_destination
            )
            if _installed.get("success") is False:
                print_output(
                    message=_installed.get("message"), output=output, error=True
                )
                return

            # Verify what actually landed rather than trusting the copy.
            _expected = _patch_manifest["files"][_relative_path]["sha256_after"]
            _actual = hash_file(file_path=_destination)
            if _actual != _expected:
                print_output(
                    message=(
                        f"{_relative_path} hashed {_actual} after install but the "
                        f"bundle expected {_expected}. Stopping."
                    ),
                    output=output,
                    error=True,
                )
                return
            _applied.append(_relative_path)

    # Record AFTER the writes land and verify, so a failed install never leaves a
    # ledger entry claiming a patch that is not on disk. Operator-acknowledged
    # paths are excluded: EDH does not overwrite someone else's attribution.
    _split = recordable_paths(
        tree_root=_tree_root,
        applied=_applied,
        already_applied=_planned["already_applied"],
    )
    _recorded = record_patch(
        tree_root=_tree_root,
        patch_manifest=_patch_manifest,
        paths=_split["recordable"],
    )
    if _recorded.get("success") is False:
        # The writes are already on disk and verified at this point, so this is a
        # PARTIAL state, not a failed apply. Say so, because a generic error here
        # reads as "nothing happened" while the tree is in fact patched and
        # unattributed. Re-running the same bundle backfills the entry.
        print_output(
            message=(
                f"Patch {_summary['patch_id']} was written to disk and verified, "
                f"but the PATCHED ledger entry could not be recorded: "
                f"{_recorded.get('message')}. The tree IS patched; until the "
                f"ledger is written 'edhctl support verify' will report these "
                f"files as unexplained. Re-run this command once the ledger is "
                f"writable to record them."
            ),
            output=output,
            error=True,
        )
        return

    _summary["applied"] = _applied
    _summary["result"] = "APPLIED"
    print_output(
        message=_summary
        if output != "text"
        else (
            f"Applied patch {_summary['patch_id']} ({_summary['ticket']}): "
            f"{len(_applied)} file(s) replaced. Recorded as PATCHED -- "
            f"'edhctl support verify' will attribute these to EDH rather than "
            f"reporting them as unexplained."
        ),
        output=output,
    )


def recordable_paths(tree_root: str, applied: list, already_applied: list) -> dict:
    """Split already-applied paths into ones EDH may claim and ones it may not.

    record_patch writes `source: edh_patch` unconditionally, and a file reaches
    already_applied whenever its content matches the post-patch hash -- which
    includes the case where the OPERATOR made the same change and acknowledged it
    themselves. Recording those would replace their reason, source and
    acknowledged_by with an EDH attribution, quietly rewriting the audit trail
    the ledger exists to keep.

    Returns {"recordable": [...], "unrecorded": [...], "operator_owned": [...]}:
    what may be written, which of those still lack an EDH entry (so a caller can
    tell whether there is anything to do), and what was left alone.
    """
    _read = read_ledger(tree_root=tree_root)
    _existing = (
        _read.get("message") or {} if _read.get("success") is not False else {}
    )

    _recordable = list(applied)
    _operator_owned = []
    for _relative_path in already_applied:
        _source = (_existing.get(_relative_path) or {}).get("source")
        if _source in (None, SOURCE_EDH_PATCH):
            _recordable.append(_relative_path)
        else:
            _operator_owned.append(_relative_path)

    _unrecorded = [
        _relative_path
        for _relative_path in _recordable
        if (_existing.get(_relative_path) or {}).get("source") != SOURCE_EDH_PATCH
    ]
    return {
        "recordable": _recordable,
        "unrecorded": _unrecorded,
        "operator_owned": _operator_owned,
    }


def record_patch(tree_root: str, patch_manifest: dict, paths: list) -> SocaResponse:
    """Write PATCHED ledger entries, hash-pinned like every other entry.

    Pinned to the post-patch hash, so editing a patched file afterwards flips it
    straight back to MODIFIED -- a patch does not become a blanket excuse for the
    file it touched.
    """
    _read = read_ledger(tree_root=tree_root)
    if _read.get("success") is False:
        return _read
    _ledger = _read.get("message")

    _now = datetime.now(timezone.utc).isoformat()
    for _relative_path in paths:
        _transition = (patch_manifest.get("files") or {}).get(_relative_path) or {}
        _ledger[_relative_path] = {
            "hash": _transition.get("sha256_after"),
            "reason": (
                f"{patch_manifest.get('ticket')}: "
                f"{patch_manifest.get('description')}"
            ),
            "acknowledged_at": _now,
            "acknowledged_by": "edh-support",
            "source": SOURCE_EDH_PATCH,
            "patch_id": patch_manifest.get("patch_id"),
            "ticket": patch_manifest.get("ticket"),
        }
    return write_ledger(tree_root=tree_root, ledger=_ledger)


@patch.command("list")
@click.option("--output", default="text", type=click.Choice(["text", "json", "yaml"]))
def patch_list(output):
    """List EDH patches recorded on this cluster."""
    _tree = get_tree_root()
    if _tree.get("success") is False:
        print_output(message=_tree.get("message"), output=output, error=True)
        return

    _read = read_ledger(tree_root=_tree.get("message"))
    if _read.get("success") is False:
        print_output(message=_read.get("message"), output=output, error=True)
        return

    _by_patch = {}
    for _relative_path, _entry in (_read.get("message") or {}).items():
        if _entry.get("source") != SOURCE_EDH_PATCH:
            continue
        _patch_id = _entry.get("patch_id") or "unknown"
        _by_patch.setdefault(
            _patch_id,
            {
                "patch_id": _patch_id,
                "ticket": _entry.get("ticket"),
                "reason": _entry.get("reason"),
                "applied_at": _entry.get("acknowledged_at"),
                "files": [],
            },
        )["files"].append(_relative_path)

    for _record in _by_patch.values():
        _record["files"] = sorted(_record["files"])

    if output != "text":
        print_output(message=sorted(_by_patch.values(), key=lambda _r: _r["patch_id"]), output=output)
        return

    if not _by_patch:
        click.echo("No EDH patches recorded.")
        return
    click.echo(f"{len(_by_patch)} EDH patch(es) recorded:")
    for _patch_id in sorted(_by_patch):
        _record = _by_patch[_patch_id]
        click.echo(f"  {_patch_id}  ticket={_record['ticket']}")
        click.echo(f"      applied={_record['applied_at']}")
        click.echo(f"      {_record['reason']}")
        for _relative_path in _record["files"]:
            click.echo(f"      - {_relative_path}")
