# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import difflib
import glob
import logging
import os
import sys
import tarfile
import tempfile
from datetime import datetime, timezone

import click

from commands.common import get_cluster_id, print_output
from commands.support.common import (
    REGISTERED_TARGETS,
    TARGET_CODE,
    TARGET_INSTALLER,
    aggregate_exit_code,
    assert_restricted,
    build_report,
    format_multi_target_text,
    installer_target_report,
    get_fatality,
    get_tree_root,
    verify_tree,
)

logger = logging.getLogger("soca_logger")

# Each node keeps the install artifact it booted from. Used ONLY as a source of
# "before" text for diffs -- never as a baseline for the verdict, which comes
# from the manifest. A customer-generated artifact cannot be a root of trust,
# but it is perfectly adequate for rendering a diff a human will read.
BOOTSTRAP_ASSET_GLOB = "/root/edh_bootstrap_*/soca.tar.gz"


def _locate_shipped_archive() -> str:
    _candidates = sorted(glob.glob(BOOTSTRAP_ASSET_GLOB))
    return _candidates[-1] if _candidates else ""


def _export_patch(tree_root: str, paths: list, destination: str) -> str:
    """Write a unified diff for `paths` to `destination` at 0600 in a 0700 dir.

    Returns the path written, or "" when no baseline text is available.
    """
    _archive = _locate_shipped_archive()
    if not _archive:
        return ""

    os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(destination), 0o700)

    _diff_lines = []
    with tempfile.TemporaryDirectory() as _staging:
        with tarfile.open(_archive) as _tar:
            for _relative_path in paths:
                try:
                    _member = _tar.extractfile(f"./{_relative_path}")
                except KeyError:
                    _member = None
                _before = (
                    _member.read().decode("utf-8", "replace").splitlines(
                        keepends=True
                    )
                    if _member
                    else []
                )
                try:
                    with open(
                        os.path.join(tree_root, _relative_path),
                        "r",
                        errors="replace",
                    ) as _fh:
                        _after = _fh.readlines()
                except OSError:
                    _after = []
                _diff_lines.extend(
                    difflib.unified_diff(
                        _before,
                        _after,
                        fromfile=f"a/{_relative_path}",
                        tofile=f"b/{_relative_path}",
                    )
                )

    # Mode set at creation, so the file is never briefly world-readable.
    _fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(_fd, "w") as _fh:
        _fh.writelines(_diff_lines)
    return destination


def _handle_export_patch(tree_root, cluster_id, report, export_patch, output):
    """Write the patch and return a status string for the report."""
    _deviating = list(report.get("modified") or [])
    if not _deviating:
        return "no deviating files to export"

    _destination = export_patch
    if _destination == "AUTO":
        _stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # Deliberately OUTSIDE /opt/edh/<cluster_id>: a code-bearing artifact
        # inside the verified tree would appear as UNTRACKED on the next run and
        # is a leak-in-place risk.
        _destination = os.path.join(
            "/apps/edh",
            cluster_id,
            "shared",
            "support",
            f"integrity-{cluster_id}-{report.get('build_id')}-{_stamp}.patch",
        )

    _written = _export_patch(
        tree_root=tree_root, paths=_deviating, destination=_destination
    )
    if not _written:
        return (
            "unavailable: no local install artifact "
            f"({BOOTSTRAP_ASSET_GLOB}) to diff against"
        )

    _permissions = assert_restricted(path=_written)
    if _permissions.get("success") is False:
        print_output(
            message=_permissions.get("message"), output=output, error=True
        )
        return ""
    return _written


@click.command()
@click.option(
    "--target",
    default="all",
    type=click.Choice(["all", "code", "installer"]),
    help=(
        "Verification target. Defaults to all, which runs every registered "
        "target and reports a section per target. 'code' is the shipped node "
        "tree; 'installer' is the installer workstation tree, which is not "
        "verifiable from a node (see its section for why)."
    ),
)
@click.option(
    "--export-patch",
    is_flag=False,
    flag_value="AUTO",
    default=None,
    help=(
        "Write a unified diff of deviating files to a 0600 file and print only "
        "its path. Diff content is NEVER written to stdout."
    ),
)
@click.option(
    "--show-unclassified",
    is_flag=True,
    default=False,
    help=(
        "Enumerate unclassified untracked paths. Withheld by default because "
        "they are customer-authored and the filenames may be sensitive; this "
        "is what keeps default output safe to paste into a ticket."
    ),
)
@click.option(
    "--ignore-acknowledgements",
    is_flag=True,
    default=False,
    help="Report raw truth, ignoring the acknowledgement ledger.",
)
@click.option("--output", default="text", type=click.Choice(["text", "json", "yaml"]))
def verify(target, export_patch, show_unclassified, ignore_acknowledgements, output):
    """Report which shipped files have been locally modified.

    Default output is safe to paste into a ticket: it carries file paths and
    hashes but never file content, and untracked paths are summarised by prefix
    rather than enumerated.
    """
    _selected = (
        list(REGISTERED_TARGETS) if target == "all" else [target]
    )
    _cluster_id = get_cluster_id()
    _fatality = get_fatality()
    _reports = []

    for _target in _selected:
        if _target == TARGET_INSTALLER:
            # Structurally unverifiable from a node. Reported rather than
            # omitted so a reader cannot mistake `--target all` for coverage it
            # did not get.
            _reports.append(
                installer_target_report(
                    cluster_id=_cluster_id, fatality=_fatality
                )
            )
            continue

        _tree = get_tree_root()
        if _tree.get("success") is False:
            print_output(message=_tree.get("message"), output=output, error=True)
            return
        _tree_root = _tree.get("message")

        _findings = verify_tree(
            tree_root=_tree_root,
            ignore_acknowledgements=ignore_acknowledgements,
        )
        if _findings.get("success") is False:
            print_output(
                message=_findings.get("message"), output=output, error=True
            )
            return

        _report = build_report(
            findings=_findings.get("message"),
            cluster_id=_cluster_id,
            fatality=_fatality,
            show_unclassified=show_unclassified,
        )

        if export_patch is not None:
            _report["patch_export"] = _handle_export_patch(
                tree_root=_tree_root,
                cluster_id=_cluster_id,
                report=_report,
                export_patch=export_patch,
                output=output,
            )
        _reports.append(_report)

    if output == "text":
        # One formatter for every run. It dispatches per report on that
        # report's own shape, so a lone NOT_APPLICABLE target renders correctly.
        click.echo(
            format_multi_target_text(
                reports=_reports, show_unclassified=show_unclassified
            )
        )
        for _report in _reports:
            _patch = _report.get("patch_export")
            if _patch:
                click.echo("")
                click.echo(f"Patch: {_patch}")
                if os.path.isfile(str(_patch)):
                    click.echo(
                        "WARNING: that file contains source code. Review it "
                        "before sharing. Diff text is derived from this node's "
                        "own install artifact, not from a trusted baseline."
                    )
    else:
        print_output(
            message=_reports if len(_reports) > 1 else _reports[0],
            output=output,
        )

    # max() across targets: a later clean target must not mask an earlier
    # failing one.
    sys.exit(aggregate_exit_code(reports=_reports))
