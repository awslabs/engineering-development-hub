# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Canonical integrity-manifest implementation.

This module is the SINGLE definition of how a manifest is built and how its
digest is computed. Three separate consumers must agree byte-for-byte or the
whole integrity feature silently reports false deviations:

  1. the release tool  (tests/modules/github_release.py) -- release manifests
  2. the installer     (installer/resources/src/...)     -- dev manifests
  3. `edhctl support verify` on a node                    -- verification

DEPENDENCY-FREE BY REQUIREMENT -- DO NOT ADD IMPORTS BEYOND THE STANDARD LIBRARY.

This is also a deliberate, documented exemption from the repository's
"never use subprocess directly, use utils.subprocess_client.SocaSubprocessClient"
guideline. `git_identity()` below calls `subprocess.run` itself because
SocaSubprocessClient lives in the cluster virtual environment, and two of this
module's three consumers (the release tool and the installer) run on an operator
workstation where that environment does not exist, while the third (the bootstrap
integrity gate) runs before it is available. Importing the wrapper here would make
the module unimportable from exactly the callers that need it most. Any future
subprocess use in this file inherits the same constraint.

Consumers 1 and 2 run on an operator workstation, outside the cluster virtual
environment. `utils.response` imports flask, so importing SocaResponse here
would make this module unimportable from the release tool and the installer,
which is precisely why the logic cannot live behind the usual SOCA wrappers.

For the same reason the public functions here return plain built-in types
rather than SocaResponse/SocaError. The `edhctl support verify` command is the
correct place to wrap these results, because it runs on the controller where
the cluster venv is present.
"""

import datetime
import hashlib
import json
import logging
import os
import subprocess

logger = logging.getLogger("soca_logger")

# Lives at the root of the shipped tree, which is source/soca/ in the repo and
# /opt/edh/<cluster_id>/ on a node.
MANIFEST_FILENAME = ".edh-integrity-manifest.json"

# Node-local state owned by this feature: the acknowledgement ledger and the
# build-time deviation record. Defined here rather than in the edhctl command so
# the prefix below and the record path cannot drift apart.
LEDGER_DIRECTORY_NAME = ".edh-integrity"

# Second manifest, covering the INSTALLER target (Phase 7).
#
# installer/** exists only on the operator's workstation and never reaches a
# node, so it cannot be verified by edhctl on a cluster -- there is nothing there
# to compare. It therefore gets its own manifest at the RELEASE ROOT rather than
# inside source/soca/, because unlike the code manifest it has no reason to ride
# into soca.tar.gz.
#
# Scope is "the release tree minus source/soca/", which makes the two manifests
# jointly complete over everything a release ships, with no overlap and no gap:
# installer/, .github/, the root docs, and source/requirements.txt.
INSTALLER_MANIFEST_FILENAME = ".edh-installer-manifest.json"
CODE_TREE_PREFIX = "source/soca"

# Read in 1 MiB chunks so a large file never lands in memory whole.
_HASH_CHUNK_BYTES = 1024 * 1024

# Recorded instead of a digest for a path the caller declared it does not need
# hashed. Deliberately not a valid sha256 hex string, so if it ever reached a
# comparison it would mismatch loudly rather than tie with something.
HASH_NOT_COMPUTED = "<not-hashed>"

BUILD_TYPE_RELEASE = "release"
BUILD_TYPE_DEV = "dev"

# Derived artifacts that are REGENERATED ON THE NODE and must therefore never
# appear in a manifest, whoever produced it.
#
# `.mo` catalogs are recompiled by `pybabel compile` on every web tier start,
# and bytecode is rewritten on first import. Their content on the node will not
# match whatever the producer hashed, so recording them guarantees a phantom
# MODIFIED for each one on every cluster.
#
# The release tool strips these from the build tree, so excluding them here is a
# no-op on that path. The installer cannot delete them -- it is packaging the
# operator's own working tree -- so without this exclusion a dev install would
# report a bogus deviation for each catalog on exactly the clusters used to
# exercise the feature between releases.
#
# `edhctl support verify` classifies these as runtime-installed UNTRACKED,
# which is the correct place for them.
_REGENERATED_SUFFIXES = (".mo", ".pyc", ".pyo")
_REGENERATED_DIRECTORIES = ("__pycache__",)


# Trees installed at bootstrap rather than shipped: the embedded Python runtime,
# OpenPBS, npm modules, and the acknowledgement ledger. A build-time tree NEVER
# contains these, so a producer that sees them is being pointed at a populated
# node tree by mistake -- and baking them into a baseline would make every
# subsequent check vacuous while still reporting PASS.
#
# The verifier deliberately does NOT skip these: it needs them present in order
# to report the UNTRACKED prefix summary and, more importantly, to isolate
# anything OUTSIDE them as <unclassified>, which is where a planted file appears.
RUNTIME_PREFIXES = (
    # Runtime-INSTALLED trees: written once at bootstrap, never shipped.
    "python/",
    "schedulers/",
    "cluster_manager/web_interface/static/node_modules/",
    # sqlite and openssl11 are COMPILED into the tree by sqlite.sh.j2 and
    # soca_python.sh.j2. Zero files are tracked under packages/, so it can never
    # legitimately appear in a manifest.
    "packages/",
    f"{LEDGER_DIRECTORY_NAME}/",
    # Runtime-MUTABLE state: written CONTINUOUSLY by a running cluster and
    # therefore never comparable against any baseline. Without these entries the
    # report carries a permanent, growing deviation on every cluster forever,
    # which is precisely the noise that trains an operator to stop reading it.
    "cluster_manager/analytics/logs/",
    "cluster_manager/orchestrator/logs/",
    "cluster_manager/web_interface/logs/",
    # Operator data produced by edhctl db, not shipped code.
    "cluster_manager/web_interface/db_backups/",
    "cluster_manager/web_interface/db_exports/",
)

# Individual mutable files rather than whole trees. admin_api_key.txt is rotated
# on every real web-tier start, so it deviates after any restart.
RUNTIME_FILES = ("cluster_manager/web_interface/admin_api_key.txt",)


def is_runtime_installed(relative_path: str) -> bool:
    if relative_path in RUNTIME_FILES:
        return True
    return relative_path.startswith(RUNTIME_PREFIXES)


def is_regenerated_on_node(relative_path: str) -> bool:
    if relative_path.endswith(_REGENERATED_SUFFIXES):
        return True
    _parts = relative_path.split(os.sep)
    return any(_directory in _parts for _directory in _REGENERATED_DIRECTORIES)


def is_within_tree(tree_root: str, relative_path: str) -> bool:
    """True when `relative_path` stays inside `tree_root` once resolved.

    Manifest keys are DATA, and a patch bundle is untrusted input that arrives
    over email or S3. `tarfile.extractall(filter="data")` guards the payload
    inside a bundle, but nothing guards the manifest keys that decide where those
    bytes are written, so a key of `../../etc/...` would resolve outside the tree.

    Lives here rather than in the applier so the producer that records keys and
    the applier that consumes them cannot disagree about what is acceptable.
    Resolves symlinks, because a link inside the tree pointing out of it reaches
    the same place by a different route.
    """
    if not relative_path or os.path.isabs(relative_path):
        return False
    _root = os.path.realpath(tree_root)
    _resolved = os.path.realpath(os.path.join(_root, relative_path))
    return _resolved == _root or _resolved.startswith(_root + os.sep)


def hash_file(file_path: str) -> str:
    _digest = hashlib.sha256()
    with open(file_path, "rb") as _fh:
        for _chunk in iter(lambda: _fh.read(_HASH_CHUNK_BYTES), b""):
            _digest.update(_chunk)
    return _digest.hexdigest()


def build_file_map(
    tree_root: str,
    skip_runtime: bool = False,
    exclude_prefixes: tuple = (),
    tracked_paths: frozenset = frozenset(),
) -> dict:
    # Paths are relative to the root of the shipped tree so the same manifest
    # is meaningful in the repo (source/soca/) and on a node
    # (/opt/edh/<cluster_id>/), which are the same tree at different mount
    # points.
    #
    # Symlinks are skipped rather than followed: hashing a link's target would
    # record content that does not belong to this tree, and a link whose target
    # changes would read as a modification of a file that was never touched.
    _files = {}
    for _dirpath, _dirnames, _filenames in os.walk(tree_root):
        _dirnames[:] = [_d for _d in _dirnames if _d != ".git"]
        for _filename in _filenames:
            _full_path = os.path.join(_dirpath, _filename)
            _relative_path = os.path.relpath(_full_path, tree_root)
            # A manifest cannot contain its own hash. Its digest is the
            # authenticity check value instead. Both are skipped so the two
            # targets stay disjoint regardless of which root is being walked.
            if _relative_path in (MANIFEST_FILENAME, INSTALLER_MANIFEST_FILENAME):
                continue
            if exclude_prefixes and _relative_path.startswith(exclude_prefixes):
                continue
            if os.path.islink(_full_path) or not os.path.isfile(_full_path):
                continue
            if is_regenerated_on_node(relative_path=_relative_path):
                continue
            if skip_runtime and is_runtime_installed(
                relative_path=_relative_path
            ):
                continue
            # Failure to PRODUCE a check is never fatal (see the module header),
            # so one unreadable file must not abort the walk. A skipped path is
            # absent from the map, which on the verifier side means a manifest
            # entry we could not hash reports as a deviation rather than as a
            # silent pass -- the correct outcome, since an unreadable file
            # cannot be attested.
            if tracked_paths and _relative_path not in tracked_paths:
                # The VERIFIER keeps runtime files in the map so it can classify
                # UNTRACKED paths, but for those it reads only the KEY and throws
                # the hash away. A clean cluster carries roughly 25,000 such
                # files, so hashing them all was gigabytes of SHA-256 per run for
                # a value nothing reads. Producers pass no tracked_paths and keep
                # hashing everything.
                _files[_relative_path] = HASH_NOT_COMPUTED
                continue
            try:
                _files[_relative_path] = hash_file(file_path=_full_path)
            except OSError as _err:
                logger.warning(
                    f"Skipping unreadable file {_relative_path}: {_err}"
                )
    return _files


def compute_manifest_digest(files: dict) -> str:
    # Fingerprint of the entire shipped tree: a hash over the sorted
    # (path, hash) pairs. Sorting is what makes it reproducible regardless of
    # filesystem walk order, so an independent recomputation from the git tag
    # yields the same value. Doubles as the authenticity check value, so
    # build_id needs no second hashing pass.
    _digest = hashlib.sha256()
    for _relative_path in sorted(files):
        _digest.update(_relative_path.encode("utf-8"))
        _digest.update(files[_relative_path].encode("utf-8"))
    return _digest.hexdigest()


def git_identity(directory: str) -> tuple:
    # Returns (commit, dirty). A dev install routinely runs from a worktree
    # with uncommitted changes, so a bare commit SHA would report two
    # materially different trees as the same build -- the dirty flag is what
    # keeps build_id honest.
    #
    # Absence of git is not an error: a customer installing from an extracted
    # release tarball has no repository. Unknown provenance is reported as
    # dirty because that is the conservative reading.
    #
    # No directory at all is the same case, and is handled here rather than by
    # the except clause below: subprocess raises TypeError on a None argument,
    # which is not an OSError and would escape as a crash.
    if not directory:
        logger.debug("No git directory supplied; provenance is unknown.")
        return "", True

    try:
        _commit = subprocess.run(
            ["git", "-C", directory, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        _status = subprocess.run(
            ["git", "-C", directory, "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return _commit, bool(_status)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as _err:
        logger.debug(f"No usable git identity in {directory}: {_err}")
        return "", True


def build_manifest(
    tree_root: str, version: str, build_type: str, git_directory: str
) -> dict:
    # skip_runtime because this is a PRODUCER. At build time the tree has no
    # runtime trees anyway, so this is a no-op there; it is what stops a manifest
    # generated against a populated node tree from swallowing them.
    _files = build_file_map(tree_root=tree_root, skip_runtime=True)
    _manifest_digest = compute_manifest_digest(files=_files)
    _commit, _dirty = git_identity(directory=git_directory)

    _short_commit = _commit[:7] if _commit else "nogit"
    _build_id = (
        f"{_short_commit}{'+dirty' if _dirty else ''}-{_manifest_digest[:6]}"
    )

    return {
        "version": version,
        "build_type": build_type,
        "target": "code",
        "git_commit": _commit,
        "git_dirty": _dirty,
        "manifest_digest": _manifest_digest,
        "build_id": _build_id,
        # timezone.utc rather than datetime.UTC: the latter is 3.11+, and this
        # module is deliberately runnable by any Python that happens to be
        # available, including a distro 3.9.
        "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "files": _files,
    }


def write_manifest(tree_root: str, manifest: dict) -> str:
    # sort_keys so two builds of identical content produce identical bytes.
    _manifest_path = os.path.join(tree_root, MANIFEST_FILENAME)
    with open(_manifest_path, "w") as _fh:
        json.dump(manifest, _fh, indent=2, sort_keys=True)
    return _manifest_path


def read_manifest(tree_root: str) -> dict:
    # Returns {} when absent or unreadable. A missing or corrupt manifest is a
    # normal condition the caller decides how to handle, not an exception --
    # failure to PRODUCE a check must never be fatal, only deviations FOUND by
    # one may be.
    _manifest_path = os.path.join(tree_root, MANIFEST_FILENAME)
    if not os.path.isfile(_manifest_path):
        return {}
    try:
        with open(_manifest_path, "r") as _fh:
            return json.load(_fh)
    except (OSError, ValueError) as _err:
        logger.warning(f"Unreadable manifest at {_manifest_path}: {_err}")
        return {}


# ---------------------------------------------------------------------------
# Build-time deviation record (Phase 6)
#
# Answers WHEN a deviation entered, which the manifest alone cannot: a hash
# mismatch looks identical whether the file was modified on the installer
# workstation before packaging or hot-patched on the running cluster months
# later. Those two have completely different meanings for a support case.
#
# Deliberately NOT a second manifest. Only the deviation SET is recorded --
# empty on an honest install -- which gives the same discrimination for
# near-zero storage, captured at the one moment when "install time" is
# unambiguous. At check time:
#
#   deviating now, path IN the record     -> entered before packaging
#   deviating now, path NOT in the record -> entered after install
# ---------------------------------------------------------------------------

DEVIATION_RECORD_FILENAME = "build_deviations.json"


def _deviation_record_path(tree_root: str) -> str:
    # Lives beside the acknowledgement ledger, under a prefix the verifier
    # already classifies as runtime-installed.
    return os.path.join(
        tree_root, LEDGER_DIRECTORY_NAME, DEVIATION_RECORD_FILENAME
    )


def compute_deviations(tree_root: str, manifest: dict) -> dict:
    """Return the tracked paths that deviate from the manifest right now.

    Only MODIFIED and MISSING, both of which are defined over manifest-tracked
    paths. Untracked additions are excluded by construction, which is what lets
    this run after the runtime trees are installed without contaminating the
    result.
    """
    _expected = manifest.get("files") or {}
    # skip_runtime=True is free correctness-wise and not free performance-wise: a
    # manifest is produced with runtime paths excluded, so `_expected` can never
    # contain one and hashing them changes no result. This runs at bootstrap AFTER
    # the interpreter and node_modules trees are installed, so without the flag it
    # SHA-256-hashes roughly 25,000 runtime files on every boot for nothing.
    _on_disk = build_file_map(tree_root=tree_root, skip_runtime=True)

    _modified = []
    _missing = []
    for _relative_path, _expected_hash in _expected.items():
        _actual_hash = _on_disk.get(_relative_path)
        if _actual_hash is None:
            _missing.append(_relative_path)
        elif _actual_hash != _expected_hash:
            _modified.append(_relative_path)

    return {"modified": sorted(_modified), "missing": sorted(_missing)}


def write_deviation_record(tree_root: str, manifest: dict) -> str:
    """Record the build-time deviation set. WRITE-ONCE; returns "" if skipped.

    Two guards, both load-bearing:

    1. RELEASE ONLY. A dev manifest is a self-baseline generated from the very
       tree being packaged, so any workstation modification is already inside
       the baseline and invisible to this comparison. Recording an
       always-empty set for dev builds would imply a guarantee that does not
       exist.

    2. WRITE-ONCE. 02_prerequisites.sh.j2 re-runs after a reboot
       (cloud_init_rerun_user_data), and an operator may hot-patch and then
       reboot. Rewriting the record would absorb that hot patch into the
       build-time set and label a post-install change as shipped-that-way --
       the exact opposite of this record's purpose.
    """
    if manifest.get("build_type") != BUILD_TYPE_RELEASE:
        logger.debug(
            "Skipping build-time deviation record: build_type is not release."
        )
        return ""

    _path = _deviation_record_path(tree_root=tree_root)
    if os.path.isfile(_path):
        logger.debug(f"Build-time deviation record already present at {_path}.")
        return ""

    _deviations = compute_deviations(tree_root=tree_root, manifest=manifest)
    _record = {
        "build_id": manifest.get("build_id"),
        "manifest_digest": manifest.get("manifest_digest"),
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "modified": _deviations["modified"],
        "missing": _deviations["missing"],
    }

    os.makedirs(os.path.dirname(_path), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(_path), 0o700)
    _fd = os.open(_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(_fd, "w") as _fh:
        json.dump(_record, _fh, indent=2, sort_keys=True)
    return _path


def read_deviation_record(tree_root: str) -> dict:
    """Read the build-time record. Absent or corrupt reads as {}."""
    _path = _deviation_record_path(tree_root=tree_root)
    if not os.path.isfile(_path):
        return {}
    try:
        with open(_path, "r") as _fh:
            return json.load(_fh)
    except (OSError, ValueError) as _err:
        logger.warning(f"Unreadable build-time deviation record at {_path}: {_err}")
        return {}


def build_installer_manifest(
    release_root: str, version: str, build_type: str, git_directory: str
) -> dict:
    """Manifest for the INSTALLER target: the release tree minus source/soca/.

    Deliberately a separate manifest rather than a second section inside the code
    manifest. The code manifest ships to every node inside soca.tar.gz; adding
    installer hashes to it would put paths on nodes that can never resolve there,
    so every one of them would read as MISSING forever.
    """
    _files = build_file_map(
        tree_root=release_root,
        exclude_prefixes=(f"{CODE_TREE_PREFIX}/",),
    )
    _manifest_digest = compute_manifest_digest(files=_files)
    _commit, _dirty = git_identity(directory=git_directory)
    _short_commit = _commit[:7] if _commit else "nogit"

    return {
        "version": version,
        "build_type": build_type,
        "target": "installer",
        "git_commit": _commit,
        "git_dirty": _dirty,
        "manifest_digest": _manifest_digest,
        "build_id": (
            f"{_short_commit}{'+dirty' if _dirty else ''}-{_manifest_digest[:6]}"
        ),
        "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "files": _files,
    }


def write_installer_manifest(release_root: str, manifest: dict) -> str:
    _path = os.path.join(release_root, INSTALLER_MANIFEST_FILENAME)
    with open(_path, "w") as _fh:
        json.dump(manifest, _fh, indent=2, sort_keys=True)
    return _path


def read_installer_manifest(release_root: str) -> dict:
    """Absent or corrupt reads as {} -- a missing baseline is not an exception."""
    _path = os.path.join(release_root, INSTALLER_MANIFEST_FILENAME)
    if not os.path.isfile(_path):
        return {}
    try:
        with open(_path, "r") as _fh:
            return json.load(_fh)
    except (OSError, ValueError) as _err:
        logger.warning(f"Unreadable installer manifest at {_path}: {_err}")
        return {}
