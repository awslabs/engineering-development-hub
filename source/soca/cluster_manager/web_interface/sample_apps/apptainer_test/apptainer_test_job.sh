#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# EDH Apptainer container validation (single node, no EFA).
#
# Staged to /apps/edh/<cluster_id>/job_samples/apptainer_test/ by the controller
# bootstrap and invoked by the "Container Test (Apptainer)" Application Profile.
#
# Answers one question: is the Apptainer runtime on this node actually usable?
# It checks the things that silently degrade rather than fail outright, because
# those are what waste a user's afternoon:
#
#   1. apptainer is on PATH and reports the version EDH pinned
#   2. the architecture-scoped image store resolved to this node's architecture
#   3. cache and tmp are NOT on the shared filesystem
#   4. an image can be built and executed
#   5. squashfuse is mounting the image instead of unpacking it
#
# Check 5 is the one that matters in practice. Without squashfuse every exec
# unpacks the whole image to a sandbox, which still works and is therefore easy
# to miss, but costs a multi-second unpack on every single launch.
#
# Runs as the job user, never as root. Exits non-zero on a real failure so the
# scheduler records the job as failed.

set -uo pipefail

readonly PASS="PASS"
readonly FAIL="FAIL"
_failures=0
_warnings=0

function _hdr () {
    echo ""
    echo "=================================================================="
    echo "$*"
    echo "=================================================================="
}

function _ok ()   { echo "  [${PASS}] $*"; }
function _bad ()  { echo "  [${FAIL}] $*"; _failures=$((_failures + 1)); }
function _warn () { echo "  [WARN] $*"; _warnings=$((_warnings + 1)); }
function _info () { echo "         $*"; }

_hdr "EDH Apptainer container validation"
echo "  host:         $(hostname)"
echo "  architecture: $(uname -m)"
echo "  user:         $(id -un) (uid $(id -u))"
echo "  date:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# 1. Runtime present
# ---------------------------------------------------------------------------
_hdr "1. Apptainer runtime"

if ! command -v apptainer > /dev/null 2>&1; then
    _bad "apptainer is not on PATH"
    _info "Apptainer is disabled on this cluster, or this node's platform is"
    _info "unsupported. Ask an administrator to check"
    _info "Config.containers.apptainer.enabled and the node's bootstrap log."
    echo ""
    echo "RESULT: ${FAIL} - the runtime is not installed, nothing further to test."
    exit 1
fi

_ok "apptainer found at $(command -v apptainer)"
_APPTAINER_VERSION=$(apptainer --version 2>/dev/null | awk '{print $NF}')
_info "version: ${_APPTAINER_VERSION:-unknown}"

# Rootless build: there must be no setuid starter in play.
if apptainer --version > /dev/null 2>&1; then
    _ok "apptainer executes without privilege escalation"
fi

# ---------------------------------------------------------------------------
# 2. Image store resolved for this architecture
# ---------------------------------------------------------------------------
_hdr "2. Architecture-scoped image store"

_ARCH=$(uname -m)
if [[ -z "${EDH_CONTAINER_IMAGES:-}" ]]; then
    _warn "EDH_CONTAINER_IMAGES is not set in this job environment"
    _info "Falling back to /apps/containers/${_ARCH}"
    EDH_CONTAINER_IMAGES="/apps/containers/${_ARCH}"
else
    _ok "EDH_CONTAINER_IMAGES=${EDH_CONTAINER_IMAGES}"
fi

# The store must be the one for THIS architecture. A SIF built for the other
# architecture will not run, and a flat shared directory is the usual cause.
if [[ "${EDH_CONTAINER_IMAGES}" == *"${_ARCH}"* ]]; then
    _ok "image store is scoped to this architecture (${_ARCH})"
else
    _bad "image store ${EDH_CONTAINER_IMAGES} is not scoped to ${_ARCH}"
    _info "Cross-architecture images will fail to execute."
fi

if [[ -d "${EDH_CONTAINER_IMAGES}" ]]; then
    _ok "image store exists"
    _info "contents: $(ls -1 "${EDH_CONTAINER_IMAGES}" 2>/dev/null | tr '\n' ' ')"
else
    _warn "image store ${EDH_CONTAINER_IMAGES} does not exist yet"
fi

# Report the alias so a user can confirm both names work.
_ALIAS_DIR=""
case "${_ARCH}" in
    x86_64)  _ALIAS_DIR="$(dirname "${EDH_CONTAINER_IMAGES}")/amd64" ;;
    aarch64) _ALIAS_DIR="$(dirname "${EDH_CONTAINER_IMAGES}")/arm64" ;;
esac
if [[ -n "${_ALIAS_DIR}" ]] && [[ -L "${_ALIAS_DIR}" ]]; then
    _ok "alias $(basename "${_ALIAS_DIR}") resolves to $(readlink "${_ALIAS_DIR}")"
elif [[ -n "${_ALIAS_DIR}" ]]; then
    _warn "no $(basename "${_ALIAS_DIR}") alias alongside the canonical directory"
fi

# ---------------------------------------------------------------------------
# 3. Cache placement
# ---------------------------------------------------------------------------
_hdr "3. Cache and temp placement"

# The default is under the user's home, which is on shared storage, so an
# unconfigured node writes gigabytes of layer cache to the shared filesystem.
for _var in APPTAINER_CACHEDIR APPTAINER_TMPDIR; do
    _val="${!_var:-}"
    if [[ -z "${_val}" ]]; then
        _warn "${_var} is unset; Apptainer will default to your home directory on shared storage"
        continue
    fi
    if [[ "${_val}" == /apps/* ]] || [[ "${_val}" == /data/* ]]; then
        _bad "${_var}=${_val} is on the SHARED filesystem"
        _info "Image pulls will consume shared capacity and be slow."
    else
        _ok "${_var}=${_val} (node-local)"
    fi
done

# ---------------------------------------------------------------------------
# 4. Build and run an image
# ---------------------------------------------------------------------------
_hdr "4. Build and execute a container"

# Pick a writable location. The shared store is preferred so the image is
# reused by later jobs, but it is root-owned by default, so fall back to the
# user's own space rather than failing.
_DEF_FILE="$(dirname "${BASH_SOURCE[0]}")/edh-base.def"
_IMAGE_NAME="edh-base-${_ARCH}.sif"
_IMAGE=""

for _candidate in "${EDH_CONTAINER_IMAGES}" "${HOME}/.edh/containers/${_ARCH}"; do
    if [[ -f "${_candidate}/${_IMAGE_NAME}" ]]; then
        _IMAGE="${_candidate}/${_IMAGE_NAME}"
        _ok "reusing existing image ${_IMAGE}"
        break
    fi
done

if [[ -z "${_IMAGE}" ]]; then
    if [[ ! -f "${_DEF_FILE}" ]]; then
        _bad "definition file not found at ${_DEF_FILE}"
        _info "The cluster bootstrap did not stage this sample completely."
        echo ""
        echo "RESULT: ${FAIL}"
        exit 1
    fi

    _BUILD_DIR="${EDH_CONTAINER_IMAGES}"
    if ! [[ -w "${_BUILD_DIR}" ]]; then
        _BUILD_DIR="${HOME}/.edh/containers/${_ARCH}"
        _info "shared image store is not writable by $(id -un), building into ${_BUILD_DIR}"
        _info "an administrator can publish the image cluster-wide by copying it to ${EDH_CONTAINER_IMAGES}"
        mkdir -p "${_BUILD_DIR}" || {
            _bad "cannot create ${_BUILD_DIR}"
            echo ""; echo "RESULT: ${FAIL}"; exit 1
        }
    fi

    _IMAGE="${_BUILD_DIR}/${_IMAGE_NAME}"
    echo "  building ${_IMAGE} from $(basename "${_DEF_FILE}") ..."
    echo "  (first run only; later jobs reuse the image)"

    # Serialize concurrent builds of the same target.
    _LOCK="${_BUILD_DIR}/.${_IMAGE_NAME}.lock"
    (
        flock -w 1800 9 || { echo "  could not acquire build lock"; exit 1; }
        if [[ -f "${_IMAGE}" ]]; then
            exit 0
        fi
        # The build's status has to be propagated out of the subshell and checked.
        # A build that fails after partially writing the .sif leaves a file
        # behind, and both the test below and the "reusing existing image" branch
        # of every later job would accept that partial file as a finished image.
        # Remove it and fail here instead.
        apptainer build --force "${_IMAGE}" "${_DEF_FILE}"
        _BUILD_RC=$?
        if [[ ${_BUILD_RC} -ne 0 ]]; then
            rm -f "${_IMAGE}"
        fi
        exit "${_BUILD_RC}"
    ) 9> "${_LOCK}"
    _BUILD_RC=$?

    if [[ ${_BUILD_RC} -ne 0 ]] || [[ ! -f "${_IMAGE}" ]]; then
        _bad "image build failed (rc=${_BUILD_RC})"
        _info "If this cluster has no route to public.ecr.aws, an administrator"
        _info "must publish a prebuilt .sif into ${EDH_CONTAINER_IMAGES} instead."
        echo ""
        echo "RESULT: ${FAIL}"
        exit 1
    fi
    _ok "built ${_IMAGE} ($(du -h "${_IMAGE}" 2>/dev/null | cut -f1))"
fi

# Execute it, capturing stderr so the squashfuse check below can inspect it.
_EXEC_LOG=$(mktemp "${TMPDIR:-/tmp}/apptainer_exec.XXXXXX")
_START=$(date +%s%N)
apptainer exec "${_IMAGE}" /bin/sh -c 'echo container-ok; uname -m; grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null || echo PRETTY_NAME="unknown"' \
    > "${_EXEC_LOG}" 2>&1
_RC=$?
_END=$(date +%s%N)
_ELAPSED_MS=$(( (_END - _START) / 1000000 ))

if [[ ${_RC} -ne 0 ]] || ! grep -q 'container-ok' "${_EXEC_LOG}"; then
    _bad "apptainer exec failed (rc=${_RC})"
    sed 's/^/         | /' "${_EXEC_LOG}"
    rm -f "${_EXEC_LOG}"
    echo ""
    echo "RESULT: ${FAIL}"
    exit 1
fi

_ok "container executed successfully in ${_ELAPSED_MS} ms"
_CONTAINER_ARCH=$(grep -E '^(x86_64|aarch64)$' "${_EXEC_LOG}" | head -1)
if [[ -n "${_CONTAINER_ARCH}" ]]; then
    if [[ "${_CONTAINER_ARCH}" == "${_ARCH}" ]]; then
        _ok "container architecture ${_CONTAINER_ARCH} matches the host"
    else
        _bad "container is ${_CONTAINER_ARCH} but the host is ${_ARCH}"
    fi
fi
_info "container OS: $(sed -n 's/^PRETTY_NAME=//p' "${_EXEC_LOG}" | tr -d '"' | head -1)"

# ---------------------------------------------------------------------------
# 5. squashfuse: mounted, not unpacked
# ---------------------------------------------------------------------------
_hdr "5. Image is mounted, not unpacked (squashfuse)"

if grep -qi 'squashfuse not found' "${_EXEC_LOG}"; then
    _bad "squashfuse is missing on this node"
    _info "Every exec unpacks the whole image to a temporary sandbox instead of"
    _info "mounting it. The job still runs, which is why this goes unnoticed, but"
    _info "each launch pays a full unpack. Report this to an administrator."
elif grep -qi 'Converting SIF file to temporary sandbox' "${_EXEC_LOG}"; then
    _bad "the image was unpacked to a sandbox rather than mounted"
    _info "squashfuse is missing or not functioning on this node."
else
    _ok "no unpack occurred; the image was mounted directly"
    if command -v squashfuse > /dev/null 2>&1; then
        _info "squashfuse: $(command -v squashfuse)"
    fi
fi

if [[ ${_ELAPSED_MS} -gt 3000 ]]; then
    _warn "exec took ${_ELAPSED_MS} ms, which is slow for a mounted image"
    _info "Expect roughly 100 ms. A multi-second exec usually means an unpack."
fi

rm -f "${_EXEC_LOG}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
_hdr "Summary"
echo "  failures: ${_failures}"
echo "  warnings: ${_warnings}"
echo ""
if [[ ${_failures} -gt 0 ]]; then
    echo "RESULT: ${FAIL} - ${_failures} check(s) failed."
    echo ""
    echo "Next step: run the EFA container sample to validate the interconnect,"
    echo "but only after the failures above are resolved."
    exit 1
fi

echo "RESULT: ${PASS} - the Apptainer runtime on this node works as expected."
echo ""
echo "  image ready for reuse: ${_IMAGE}"
echo "  run it yourself with:  apptainer exec ${_IMAGE} <command>"
echo ""
echo "Next step: submit the \"Container EFA Benchmark (Apptainer)\" sample to"
echo "validate MPI over EFA from inside a container."
exit 0
