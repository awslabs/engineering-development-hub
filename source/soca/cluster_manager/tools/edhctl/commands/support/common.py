# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Shared engine for `edhctl support verify` and `edhctl support ack`.

Classification, the acknowledgement ledger, and report construction live here so
the command modules stay thin.

The hashing and digest arithmetic deliberately does NOT live here -- it is in
utils/integrity_manifest.py, which is also loaded by the release tool and the
installer. All three must agree byte-for-byte or verification reports false
deviations.
"""

import json
import logging
import os
import stat

from commands.common import get_cluster_id
from utils.config import SocaConfig
from utils.error import SocaError
from utils.integrity_manifest import (
    LEDGER_DIRECTORY_NAME,
    MANIFEST_FILENAME,
    RUNTIME_PREFIXES,
    build_file_map,
    hash_file,
    is_regenerated_on_node,
    is_runtime_installed,
    read_deviation_record,
    read_manifest,
)
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

# Node-local. S3 was rejected for v1: it does not buy trust (the customer owns
# the bucket), the ledger describes node state so node lifetime is correct, and
# a remote store would make a diagnostic tool network- and IAM-dependent.
# Imported from utils.integrity_manifest so the ledger path, the build-time
# deviation record path, and the runtime-prefix classification cannot drift.
LEDGER_DIRECTORY = LEDGER_DIRECTORY_NAME
LEDGER_FILENAME = "ledger.json"

# Sentinel pinning an acknowledged ABSENCE. If content later appears at the
# path it is a new deviation, not a satisfied acknowledgement.
ABSENT_SENTINEL = "__ABSENT__"

SOURCE_OPERATOR = "operator"
SOURCE_EDH_PATCH = "edh_patch"

KNOB_KEY = "/configuration/Integrity/on_validation_failure"
KNOB_DEFAULT = "warn"

# RUNTIME_PREFIXES is imported from utils.integrity_manifest so the producer
# (which excludes these) and the verifier (which classifies them) can never
# drift apart on what counts as runtime-installed.

RESULT_PASS = "PASS"
RESULT_REVIEW = "REVIEW"
RESULT_WARN = "WARN"
RESULT_FAIL = "FAIL"
RESULT_IGNORED = "IGNORED"
# Returned by the installer target seen from a node, where there is structurally
# nothing to compare. Declared here with its siblings rather than beside that
# function, because _RESULT_SEVERITY below has to be able to name it.
RESULT_NOT_APPLICABLE = "NOT_APPLICABLE"

# Explicit ranking so a multi-target run reports the WORST result rather than the
# last one seen. Without it the headline depended on target ordering: a code
# target at WARN followed by an installer target at REVIEW reported REVIEW and
# understated unexplained deviations.
#
# Every rank is DISTINCT, deliberately. Equal ranks leave max() returning the
# first element on a tie, which is the same ordering dependency in a smaller
# place -- giving NOT_APPLICABLE and PASS both 0 would still report
# `Overall: NOT_APPLICABLE` for [NOT_APPLICABLE, PASS] even though a real target
# passed. Ordered by how much attention the result deserves: nothing to check,
# then checked and clean, then a verdict the operator suppressed via the knob,
# then the three findings. IGNORED outranks PASS because suppressed coverage is
# worth surfacing in a headline that would otherwise read as verified.
#
# EVERY result constant must appear here; a missing key falls back to 0 and
# reintroduces a tie, which is what test_every_result_constant_has_a_severity
# exists to catch.
_RESULT_SEVERITY = {
    RESULT_NOT_APPLICABLE: 0,
    RESULT_PASS: 1,
    RESULT_IGNORED: 2,
    RESULT_REVIEW: 3,
    RESULT_WARN: 4,
    RESULT_FAIL: 5,
}


def worst_result(results: list) -> str:
    """Return the most severe result in `results`, or PASS if none are given."""
    if not results:
        return RESULT_PASS
    return max(results, key=lambda _r: _RESULT_SEVERITY.get(_r, 0))


def get_tree_root() -> SocaResponse:
    """Resolve the shipped tree on this node (/opt/edh/<cluster_id>)."""
    _cluster_id = get_cluster_id()
    _tree_root = os.path.join("/opt/edh", _cluster_id)
    if not os.path.isdir(_tree_root):
        return SocaError.GENERIC_ERROR(
            helper=f"Shipped tree not found at {_tree_root}"
        )
    return SocaResponse(success=True, message=_tree_root)


def get_fatality() -> str:
    """Read the fatality knob, defaulting to warn when unset."""
    _knob = SocaConfig(key=KNOB_KEY).get_value()
    if _knob.get("success") is True:
        _value = str(_knob.get("message") or "").strip().lower()
        if _value in ("ignore", "warn", "exit"):
            return _value
        logger.warning(
            f"{KNOB_KEY} holds an unrecognized value; using {KNOB_DEFAULT}."
        )
    return KNOB_DEFAULT


def get_ledger_path(tree_root: str) -> str:
    return os.path.join(tree_root, LEDGER_DIRECTORY, LEDGER_FILENAME)


def read_ledger(tree_root: str) -> SocaResponse:
    """Read the acknowledgement ledger. Absent is normal, not an error."""
    _path = get_ledger_path(tree_root=tree_root)
    if not os.path.isfile(_path):
        return SocaResponse(success=True, message={})
    try:
        with open(_path, "r") as _fh:
            _ledger = json.load(_fh)
    except (OSError, ValueError) as _err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unreadable acknowledgement ledger at {_path}: {_err}"
        )
    return SocaResponse(success=True, message=_ledger)


def write_ledger(tree_root: str, ledger: dict) -> SocaResponse:
    """Write the ledger 0600 inside a 0700 directory."""
    _directory = os.path.join(tree_root, LEDGER_DIRECTORY)
    _path = get_ledger_path(tree_root=tree_root)
    try:
        os.makedirs(_directory, mode=0o700, exist_ok=True)
        # exist_ok skips the mode on an existing directory, so assert it.
        os.chmod(_directory, 0o700)
        # Written to a temp file in the SAME directory and then renamed, because
        # os.replace is atomic within a filesystem. Truncating the live ledger
        # and writing in place would leave partial JSON if the process died
        # mid-write, and read_ledger treats unparseable JSON as an error that
        # verify_tree propagates -- so a single interrupted write would break
        # both `support verify` and `ack list` until someone repaired the file by
        # hand. The temp file shares the 0700 directory and carries the same 0600
        # mode, so the content is never briefly world-readable either.
        _temporary_path = f"{_path}.tmp.{os.getpid()}"
        try:
            _fd = os.open(
                _temporary_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
            with os.fdopen(_fd, "w") as _fh:
                json.dump(ledger, _fh, indent=2, sort_keys=True)
                _fh.flush()
                os.fsync(_fh.fileno())
            os.replace(_temporary_path, _path)
        except BaseException:
            # Including KeyboardInterrupt and SystemExit: a half-written temp
            # file left beside the ledger is litter that the UNTRACKED
            # classifier would later report.
            try:
                os.unlink(_temporary_path)
            except OSError:
                pass
            raise
    except OSError as _err:
        return SocaError.GENERIC_ERROR(
            helper=f"Could not write acknowledgement ledger to {_path}: {_err}"
        )
    return SocaResponse(success=True, message=_path)


def classify_untracked(relative_paths: list) -> dict:
    """Bucket untracked paths by known runtime prefix.

    Returns {"buckets": {prefix: count}, "unclassified": [paths]}.

    UNTRACKED is summarised by prefix rather than enumerated for two
    independent reasons: noise (a clean cluster carries ~25k runtime files) and
    redaction (untracked paths are customer-authored, so the filenames
    themselves may be sensitive).
    """
    _buckets = {}
    _unclassified = []
    for _relative_path in relative_paths:
        if is_regenerated_on_node(relative_path=_relative_path):
            _buckets["<regenerated>"] = _buckets.get("<regenerated>", 0) + 1
            continue
        if is_runtime_installed(relative_path=_relative_path):
            for _prefix in RUNTIME_PREFIXES:
                if _relative_path.startswith(_prefix):
                    _buckets[_prefix] = _buckets.get(_prefix, 0) + 1
                    break
        else:
            _unclassified.append(_relative_path)
    return {"buckets": _buckets, "unclassified": _unclassified}


def verify_tree(tree_root: str, ignore_acknowledgements: bool = False) -> SocaResponse:
    """Classify every file in the shipped tree against the release manifest."""
    _manifest = read_manifest(tree_root=tree_root)
    if not _manifest:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"No integrity manifest at "
                f"{os.path.join(tree_root, MANIFEST_FILENAME)}. This cluster "
                f"predates manifest generation; there is no baseline to verify "
                f"against."
            )
        )

    _expected = _manifest.get("files") or {}

    _ledger = {}
    if ignore_acknowledgements is False:
        _read = read_ledger(tree_root=tree_root)
        if _read.get("success") is False:
            return _read
        _ledger = _read.get("message")

    # Only manifest-tracked paths need a hash. Untracked paths are classified by
    # prefix from their path alone, so hashing them would be work whose result is
    # discarded.
    _on_disk = build_file_map(
        tree_root=tree_root, tracked_paths=frozenset(_expected)
    )

    _verified = []
    _modified = []
    _missing = []
    _acknowledged = []
    _patched = []

    for _relative_path, _expected_hash in _expected.items():
        _entry = _ledger.get(_relative_path) or {}
        _pinned = _entry.get("hash")
        _source = _entry.get("source")

        if _relative_path not in _on_disk:
            if _pinned == ABSENT_SENTINEL:
                _record = {"path": _relative_path, "was": "MISSING", "entry": _entry}
                if _source == SOURCE_EDH_PATCH:
                    _patched.append(_record)
                else:
                    _acknowledged.append(_record)
            else:
                _missing.append(_relative_path)
            continue

        _actual_hash = _on_disk[_relative_path]
        if _actual_hash == _expected_hash:
            _verified.append(_relative_path)
        elif _pinned == _actual_hash:
            # Hash-pinned, not path-pinned: a further edit flips straight back
            # to MODIFIED.
            _record = {"path": _relative_path, "was": "MODIFIED", "entry": _entry}
            if _source == SOURCE_EDH_PATCH:
                _patched.append(_record)
            else:
                _acknowledged.append(_record)
        else:
            _modified.append(_relative_path)

    # Phase 6: attribute each deviation to WHEN it entered. A hash mismatch
    # looks identical whether the file was changed on the installer workstation
    # before packaging or hot-patched on the running cluster months later, and
    # those mean completely different things for a support case.
    _record = read_deviation_record(tree_root=tree_root)
    _build_time_paths = set(_record.get("modified") or []) | set(
        _record.get("missing") or []
    )
    _build_time = sorted(
        _p for _p in _modified + _missing if _p in _build_time_paths
    )
    _post_install = sorted(
        _p for _p in _modified + _missing if _p not in _build_time_paths
    )

    _untracked = [_p for _p in _on_disk if _p not in _expected]
    _classified = classify_untracked(relative_paths=_untracked)

    # Acknowledgement RECLASSIFIES, it never reduces the headline. A customer's
    # self-declarations cannot shrink the number EDH support reads.
    _unexplained = len(_modified) + len(_missing)
    _total_deviations = _unexplained + len(_acknowledged) + len(_patched)

    return SocaResponse(
        success=True,
        message={
            "manifest": {
                _k: _v for _k, _v in _manifest.items() if _k != "files"
            },
            "tracked_count": len(_expected),
            "verified_count": len(_verified),
            "modified": sorted(_modified),
            "missing": sorted(_missing),
            "acknowledged": sorted(_acknowledged, key=lambda _r: _r["path"]),
            "patched": sorted(_patched, key=lambda _r: _r["path"]),
            "untracked_count": len(_untracked),
            "untracked_buckets": _classified["buckets"],
            "unclassified": sorted(_classified["unclassified"]),
            "unexplained": _unexplained,
            "total_deviations": _total_deviations,
            # Empty dict when no record exists -- attribution is unavailable
            # rather than assumed, and the report says so.
            "build_time_record": _record,
            "build_time_deviations": _build_time if _record else [],
            "post_install_deviations": _post_install if _record else [],
        },
    )


def resolve_result(findings: dict, fatality: str) -> dict:
    """Map findings plus the knob onto a result label and exit code.

    An UNCLASSIFIED untracked file is where a planted file appears, so a run
    that found one must never report PASS. It is reported as REVIEW rather than
    counted as a deviation: the runtime-prefix classifier is not yet proven
    complete against every cluster shape, and folding unclassified files into
    the unexplained count would gate node boot under `exit` on that list being
    exhaustive. REVIEW surfaces the finding without that risk.
    """
    _unexplained = findings.get("unexplained")
    _unclassified_count = len(findings.get("unclassified") or [])

    if fatality == "ignore":
        return {"result": RESULT_IGNORED, "exit_code": 0}
    if _unexplained > 0:
        if fatality == "exit":
            return {"result": RESULT_FAIL, "exit_code": 1}
        return {"result": RESULT_WARN, "exit_code": 0}
    if _unclassified_count > 0:
        return {"result": RESULT_REVIEW, "exit_code": 0}
    return {"result": RESULT_PASS, "exit_code": 0}


def build_report(
    findings: dict,
    cluster_id: str,
    fatality: str,
    show_unclassified: bool = False,
) -> dict:
    """Assemble the redaction-safe report payload.

    REDACTION CONTRACT -- default output is safe to paste into a ticket:
      * tracked paths and hashes are printed; every tracked path is already
        public in the GitHub release, so they leak nothing
      * build identity is printed; provenance, no customer content
      * UNTRACKED paths are prefix-summarised, never enumerated; they are
        customer-authored and the filenames may themselves be sensitive
      * file CONTENT is never included, in any output format

    json/yaml carry identical fields and identical redaction. JSON is the
    likelier leak path because it gets piped and scripted, not the safer one.
    """
    _manifest = findings.get("manifest") or {}
    _resolved = resolve_result(findings=findings, fatality=fatality)

    _build_type = _manifest.get("build_type")
    if _build_type == "release":
        _baseline_note = "release baseline"
    else:
        # Stated plainly in the command's own output rather than buried in docs:
        # a dev manifest matches the tree it was generated from, so it detects
        # post-install drift but cannot detect workstation-side modification.
        _baseline_note = (
            "dev self-baseline -- build-time integrity NOT verifiable"
        )

    _unclassified = findings.get("unclassified") or []
    _report = {
        "cluster_id": cluster_id,
        "version": _manifest.get("version"),
        "build_type": _build_type,
        "git_commit": _manifest.get("git_commit"),
        "git_dirty": _manifest.get("git_dirty"),
        "build_id": _manifest.get("build_id"),
        "baseline": _baseline_note,
        "target": "code",
        "tracked_count": findings.get("tracked_count"),
        "deviations": findings.get("total_deviations"),
        "unexplained": findings.get("unexplained"),
        "modified": findings.get("modified"),
        "missing": findings.get("missing"),
        "acknowledged": [_r["path"] for _r in findings.get("acknowledged") or []],
        "patched": [_r["path"] for _r in findings.get("patched") or []],
        # PATCHED must carry the ticket reference -- "EDH changed this" is only
        # useful to an operator or to support if you can say WHICH change.
        "patch_tickets": {
            _r["path"]: (_r.get("entry") or {}).get("ticket")
            for _r in findings.get("patched") or []
        },
        "untracked_count": findings.get("untracked_count"),
        "untracked_buckets": findings.get("untracked_buckets"),
        "unclassified_count": len(_unclassified),
        "build_time_record_present": bool(findings.get("build_time_record")),
        "build_time_deviations": findings.get("build_time_deviations"),
        "post_install_deviations": findings.get("post_install_deviations"),
        "on_validation_failure": fatality,
        "result": _resolved["result"],
        "exit_code": _resolved["exit_code"],
    }
    # json/yaml carry IDENTICAL redaction to text. JSON is the likelier leak
    # path because it gets piped and scripted, not the safer one.
    if show_unclassified:
        _report["unclassified"] = _unclassified
    return _report


def format_report_text(report: dict, show_unclassified: bool = False) -> str:
    _dirty = "+dirty" if report.get("git_dirty") else ""
    _commit = (report.get("git_commit") or "nogit")[:7]
    _lines = [
        f"EDH integrity check -- {report.get('cluster_id')}",
        f"Build:     {report.get('version')}  "
        f"build_type={report.get('build_type')}  "
        f"git={_commit}{_dirty}  build_id={report.get('build_id')}",
        f"Manifest:  present ({report.get('baseline')})",
        f"Target:    {report.get('target')}   "
        f"({report.get('tracked_count')} files tracked)",
        "",
        f"DEVIATIONS: {report.get('deviations')}  "
        f"({report.get('unexplained')} unexplained)",
        f"  MODIFIED       {len(report.get('modified') or [])}",
        f"  MISSING        {len(report.get('missing') or [])}",
        f"  PATCHED        {len(report.get('patched') or [])}",
        f"  ACKNOWLEDGED   {len(report.get('acknowledged') or [])}",
    ]

    _build_time = set(report.get("build_time_deviations") or [])
    _has_record = report.get("build_time_record_present")
    for _label in ("modified", "missing", "patched", "acknowledged"):
        _paths = report.get(_label) or []
        if _paths:
            _lines.append("")
            _lines.append(_label.upper())
            _tickets = report.get("patch_tickets") or {}
            for _p in _paths:
                _ticket_suffix = (
                    f"   {_tickets[_p]}"
                    if _label == "patched" and _tickets.get(_p)
                    else ""
                )
                if not _has_record:
                    _lines.append(f"  {_p}{_ticket_suffix}")
                elif _p in _build_time:
                    # Present at first boot: the file was already like this when
                    # the artifact was packaged, on the installer workstation.
                    _lines.append(f"  {_p}{_ticket_suffix}   [build-time]")
                else:
                    _lines.append(f"  {_p}{_ticket_suffix}   [post-install]")
    if (report.get("modified") or report.get("missing")) and not _has_record:
        _lines.append("")
        _lines.append(
            "  (no build-time record on this cluster -- cannot distinguish a "
            "workstation change from a post-install one)"
        )

    _lines.append("")
    _lines.append(f"UNTRACKED: {report.get('untracked_count')}")
    _buckets = report.get("untracked_buckets") or {}
    for _prefix, _count in sorted(_buckets.items(), key=lambda _kv: -_kv[1]):
        _lines.append(f"  {_prefix:<46} {_count:>6}   runtime-installed")
    _unclassified = report.get("unclassified") or []
    _unclassified_count = report.get("unclassified_count") or 0
    if _unclassified_count:
        _lines.append(
            f"  {'<unclassified>':<46} {_unclassified_count:>6}   REVIEW"
        )
        # NOT enumerated by default. These are customer-authored paths and the
        # filenames may themselves be sensitive, which is the whole reason
        # default output is safe to paste into a ticket. --show-unclassified
        # reveals them for local triage.
        if show_unclassified:
            _lines.extend(f"      {_p}" for _p in _unclassified)
        else:
            _lines.append(
                "      (paths withheld; re-run with --show-unclassified)"
            )

    _lines.append("")
    _lines.append(
        f"Result: {report.get('result')}  "
        f"(on_validation_failure={report.get('on_validation_failure')})"
    )
    return "\n".join(_lines)


def assert_restricted(path: str) -> SocaResponse:
    """Confirm a path is 0600 inside a 0700 directory.

    /apps is the shared cluster filesystem and is visible to cluster users, so
    these permissions are load-bearing rather than decorative.
    """
    try:
        _file_mode = stat.S_IMODE(os.stat(path).st_mode)
        _dir_mode = stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode)
    except OSError as _err:
        return SocaError.GENERIC_ERROR(helper=f"Cannot stat {path}: {_err}")
    if _file_mode != 0o600 or _dir_mode != 0o700:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"{path} is {oct(_file_mode)} in a {oct(_dir_mode)} directory; "
                f"expected 0o600 in 0o700"
            )
        )
    return SocaResponse(success=True, message=path)


# ---------------------------------------------------------------------------
# Multi-target aggregation (Phase 7)
# ---------------------------------------------------------------------------

TARGET_CODE = "code"
TARGET_INSTALLER = "installer"
REGISTERED_TARGETS = (TARGET_CODE, TARGET_INSTALLER)


def installer_target_report(cluster_id: str, fatality: str) -> dict:
    """The installer target as seen FROM A NODE: structurally unverifiable.

    installer/** exists only on the operator's workstation and never reaches a
    cluster, so there is nothing here to compare against. Reporting that plainly
    is the honest answer -- silently omitting the target would let a reader
    believe `--target all` had covered the installer tree when it had not, and
    inventing a PASS would be worse.

    The check itself is real, it just lives where the tree does: the installer
    performs it at startup before deploying.
    """
    return {
        "cluster_id": cluster_id,
        "target": TARGET_INSTALLER,
        "result": RESULT_NOT_APPLICABLE,
        "exit_code": 0,
        "reason": (
            "installer/** never reaches a node, so it cannot be verified here. "
            "The installer verifies its own tree at startup, on the workstation "
            "where that tree exists."
        ),
        "on_validation_failure": fatality,
    }


def aggregate_exit_code(reports: list) -> int:
    """Under `exit`, a multi-target run fails if ANY target has deviations.

    Aggregating with max() rather than taking the last target's code means a
    later clean target cannot mask an earlier failing one.
    """
    return max([_r.get("exit_code") or 0 for _r in reports] or [0])


def format_multi_target_text(
    reports: list, show_unclassified: bool = False
) -> str:
    """Render one section per target, with an overall verdict when >1.

    Used for EVERY run, including a single target. A NOT_APPLICABLE report has
    none of the fields format_report_text expects, so routing a lone
    `--target installer` through that formatter printed "Build: None",
    "DEVIATIONS: None" and "UNTRACKED: None". Dispatching on the report's own
    shape here rather than on how many targets ran removes that class of bug.
    """
    _sections = []
    for _report in reports:
        if _report.get("result") == RESULT_NOT_APPLICABLE:
            _sections.append(
                f"Target:    {_report.get('target')}   "
                f"{RESULT_NOT_APPLICABLE}\n"
                f"  {_report.get('reason')}"
            )
        else:
            _sections.append(
                format_report_text(
                    report=_report, show_unclassified=show_unclassified
                )
            )

    if len(reports) > 1:
        _worst = worst_result(
            results=[_report.get("result") for _report in reports]
        )
        _sections.append(f"Overall: {_worst}  ({len(reports)} target(s) run)")
    return "\n\n".join(_sections)
