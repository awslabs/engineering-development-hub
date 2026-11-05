#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# EDH Apptainer + EFA validation (multi-node MPI from inside a container).
#
# Staged to /apps/edh/<cluster_id>/job_samples/apptainer_efa_test/ by the
# controller bootstrap and invoked by the "Container EFA Benchmark (Apptainer)"
# Application Profile.
#
# The failure this exists to catch is SILENT. If the container's libfabric and
# OpenMPI do not ABI-match the host's, MPI still runs -- it just falls back to
# TCP and the interconnect does nothing. The job succeeds, the user sees no
# error, and the cluster quietly delivers a fraction of the bandwidth it was
# provisioned for. So this script does not merely check that MPI works: it
# measures EFA against TCP and reports the ratio.
#
# Two things make the ABI match work, and both are handled here:
#
#   1. The image is built from the node's OWN EFA installer tarball, staged by
#      the Apptainer bootstrap template to a user-readable location. Deriving
#      the container's RPMs from a separately pinned EFA version reintroduces
#      skew, and the live EFA version does move per cluster.
#   2. mpirun is invoked from the HOST with --prefix, and starts the container
#      per rank. There is no PBS tm launcher in the AWS OpenMPI build (plm is
#      isolated, rsh, slurm only), so ranks are placed over ssh, which works as
#      the job user but not as root, and needs --prefix to find the remote orted.
#
# EFA needs no --bind flags: Apptainer's default "mount dev = yes" exposes
# /dev/infiniband/*, and those devices are mode crw-rw-rw-.

set -uo pipefail

readonly PASS="PASS"
readonly FAIL="FAIL"
_failures=0
_warnings=0

readonly MPI_PREFIX="${MPI_PREFIX:-/opt/amazon/openmpi}"
readonly MPIRUN="${MPI_PREFIX}/bin/mpirun"

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

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ARCH=$(uname -m)

_hdr "EDH Apptainer + EFA validation"
echo "  host:         $(hostname)"
echo "  architecture: ${_ARCH}"
echo "  user:         $(id -un) (uid $(id -u))"
echo "  date:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# 0. Node list
# ---------------------------------------------------------------------------
_hdr "0. Job topology"

# Build a host list from whichever scheduler placed us.
_HOSTFILE=""
if [[ -n "${PBS_NODEFILE:-}" ]] && [[ -f "${PBS_NODEFILE}" ]]; then
    _HOSTFILE="${PBS_NODEFILE}"
    _info "using PBS_NODEFILE"
elif [[ -n "${LSB_DJOB_HOSTFILE:-}" ]] && [[ -f "${LSB_DJOB_HOSTFILE}" ]]; then
    _HOSTFILE="${LSB_DJOB_HOSTFILE}"
    _info "using LSB_DJOB_HOSTFILE"
elif [[ -n "${SLURM_JOB_NODELIST:-}" ]]; then
    _HOSTFILE=$(mktemp "${TMPDIR:-/tmp}/hostfile.XXXXXX")
    scontrol show hostnames "${SLURM_JOB_NODELIST}" > "${_HOSTFILE}" 2>/dev/null
    _info "using SLURM_JOB_NODELIST"
fi

if [[ -z "${_HOSTFILE}" ]] || [[ ! -s "${_HOSTFILE}" ]]; then
    _bad "could not determine the job's node list"
    _info "This sample must run under a scheduler with at least 2 nodes."
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi

_NODE_COUNT=$(sort -u "${_HOSTFILE}" | wc -l | tr -d ' ')
_RANK_COUNT=$(wc -l < "${_HOSTFILE}" | tr -d ' ')
echo "  unique nodes: ${_NODE_COUNT}"
echo "  total slots:  ${_RANK_COUNT}"
sort -u "${_HOSTFILE}" | sed 's/^/           /'

if [[ "${_NODE_COUNT}" -lt 2 ]]; then
    _warn "only ${_NODE_COUNT} node in this job"
    _info "EFA carries traffic BETWEEN nodes. A single-node job exercises shared"
    _info "memory instead, so the comparison below proves nothing. Resubmit with"
    _info "at least 2 nodes to validate the interconnect."
fi

# ---------------------------------------------------------------------------
# 1. Prerequisites on the host
# ---------------------------------------------------------------------------
_hdr "1. Host prerequisites"

if ! command -v apptainer > /dev/null 2>&1; then
    _bad "apptainer is not on PATH"
    _info "Apptainer is disabled on this cluster or unsupported on this platform."
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi
# Resolve the absolute path once, here, and use it everywhere below.
#
# This is not tidiness. The remote MPI ranks are placed by OpenMPI's orted over
# ssh, and a non-interactive ssh shell does not source /etc/profile.d -- which is
# the ONLY thing apptainer.sh.j2 uses to put the install prefix on PATH (there is
# no symlink into /usr/local/bin and no PATH entry in /etc/environment). mpirun's
# --prefix resolves orted, not apptainer. So a bare `apptainer` in the launch line
# depends on mpirun forwarding this shell's PATH to the remote rank, which is
# behaviour rather than contract; an absolute path needs no PATH at all. The
# install prefix is the same on every node, so the path resolved here is valid
# there.
_APPTAINER="$(command -v apptainer)"
_ok "apptainer $("${_APPTAINER}" --version 2>/dev/null | awk '{print $NF}') at ${_APPTAINER}"

if [[ ! -x "${MPIRUN}" ]]; then
    _bad "mpirun not found at ${MPIRUN}"
    _info "The EFA installer provides OpenMPI here. Was this node launched with"
    _info "efa_support=true?"
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi
_ok "mpirun found at ${MPIRUN}"

# EFA on the host. Without a device here, nothing inside a container can help.
if [[ ! -d /dev/infiniband ]]; then
    _bad "/dev/infiniband does not exist on this node"
    _info "This node has no EFA device. Check that the job requested"
    _info "efa_support=true and that the instance type supports EFA."
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi
_ok "/dev/infiniband present: $(ls -1 /dev/infiniband 2>/dev/null | tr '\n' ' ')"

if command -v fi_info > /dev/null 2>&1 || [[ -x /opt/amazon/efa/bin/fi_info ]]; then
    _FI_INFO=$(command -v fi_info || echo /opt/amazon/efa/bin/fi_info)
    if "${_FI_INFO}" -p efa > /dev/null 2>&1; then
        _ok "host reports the efa libfabric provider"
        _info "domains: $("${_FI_INFO}" -p efa 2>/dev/null | awk '/domain:/{print $2}' | sort -u | tr '\n' ' ')"
    else
        _bad "host libfabric does not report an efa provider"
    fi
fi

# ---------------------------------------------------------------------------
# 2. The EFA-enabled image
# ---------------------------------------------------------------------------
_hdr "2. EFA-enabled container image"

_DEF_FILE="${_SELF_DIR}/edh-efa.def"
_IMAGE=""

# The staged EFA installer, and the version the image name must carry.
#
# Resolved HERE, above the reuse loop, because the name is what decides whether a
# cached image is accepted. The container's libfabric and OpenMPI are installed
# from this installer, so an image built from one EFA version is not
# interchangeable with one built from another: reusing a stale .sif after a
# version bump reintroduces exactly the host/container ABI mismatch and silent
# TCP fallback this sample exists to detect, and it does so on every node, from
# shared storage, indefinitely. The staged installer tree is already
# version-keyed (efa-installer-<version>, plus the EFA_VERSION marker); the image
# was not.
#
# Read softly rather than required. A node with no marker keeps the legacy
# unversioned name, and the build branch below still fails on the missing marker
# with its own diagnosis -- so resolving the version early does not turn a
# missing staging into a new failure mode here.
_EFA_SRC="${EDH_EFA_INSTALLER_DIR:-/apps/containers/efa-installer}"
_EFA_VER=""
if [[ -f "${_EFA_SRC}/EFA_VERSION" ]]; then
    # Filtered because this string becomes a path component, and it is read from
    # a file on shared storage rather than from the cluster configuration.
    _EFA_VER="$(tr -cd 'A-Za-z0-9._-' < "${_EFA_SRC}/EFA_VERSION")"
fi
_IMAGE_NAME="edh-efa-${_ARCH}${_EFA_VER:+-${_EFA_VER}}.sif"

if [[ -z "${EDH_CONTAINER_IMAGES:-}" ]]; then
    EDH_CONTAINER_IMAGES="/apps/containers/${_ARCH}"
    _warn "EDH_CONTAINER_IMAGES unset, assuming ${EDH_CONTAINER_IMAGES}"
fi

for _candidate in "${EDH_CONTAINER_IMAGES}" "${HOME}/.edh/containers/${_ARCH}"; do
    if [[ -f "${_candidate}/${_IMAGE_NAME}" ]]; then
        _IMAGE="${_candidate}/${_IMAGE_NAME}"
        _ok "reusing existing image ${_IMAGE}"
        break
    fi
done

if [[ -z "${_IMAGE}" ]]; then
    # The image must be built from THIS cluster's EFA installer. The Apptainer
    # bootstrap stages a user-readable copy; without it the ABI match is guesswork.
    #
    # Test the EFA_VERSION marker rather than the directory. The bootstrap writes
    # that file LAST and publishes the tree by an atomic rename, so the marker is
    # what distinguishes a complete staging from a directory that happens to be
    # there -- an older unversioned layout, or a copy left behind by a node that
    # died. Building from a half-copied installer is the silent ABI mismatch this
    # sample exists to catch.
    if [[ ! -f "${_EFA_SRC}/EFA_VERSION" ]]; then
        _bad "no complete EFA installer staged at ${_EFA_SRC}"
        _info "The container's libfabric and OpenMPI must come from the same EFA"
        _info "installer as the host, or MPI silently falls back to TCP. The"
        _info "Apptainer bootstrap stages this and records EFA_VERSION when the"
        _info "copy is complete; its absence means the node bootstrap did not"
        _info "finish, or EFA is not installed here."
        if [[ -d "${_EFA_SRC}" ]]; then
            _info "The directory exists but carries no EFA_VERSION, so it is an"
            _info "incomplete or pre-versioning staging rather than a usable one."
        fi
        echo ""; echo "RESULT: ${FAIL}"; exit 1
    fi
    _ok "EFA installer staged at ${_EFA_SRC}"
    _info "version: ${_EFA_VER}"

    # An unversioned image from before the name carried a version is deliberately
    # NOT reused: nothing records which installer built it, so accepting it is the
    # guess this change removes. Say so, because otherwise the rebuild looks
    # unexplained to whoever reads the job log.
    for _legacy in "${EDH_CONTAINER_IMAGES}/edh-efa-${_ARCH}.sif" "${HOME}/.edh/containers/${_ARCH}/edh-efa-${_ARCH}.sif"; do
        if [[ -f "${_legacy}" ]]; then
            _info "ignoring ${_legacy}: built before images were version-keyed, so the"
            _info "EFA version it carries is unknown. Safe to delete once this build succeeds."
        fi
    done

    if [[ ! -f "${_DEF_FILE}" ]]; then
        _bad "definition file not found at ${_DEF_FILE}"
        echo ""; echo "RESULT: ${FAIL}"; exit 1
    fi

    _BUILD_DIR="${EDH_CONTAINER_IMAGES}"
    if ! [[ -w "${_BUILD_DIR}" ]]; then
        _BUILD_DIR="${HOME}/.edh/containers/${_ARCH}"
        _info "shared store not writable by $(id -un), building into ${_BUILD_DIR}"
        mkdir -p "${_BUILD_DIR}" || { _bad "cannot create ${_BUILD_DIR}"; echo ""; echo "RESULT: ${FAIL}"; exit 1; }
    fi
    _IMAGE="${_BUILD_DIR}/${_IMAGE_NAME}"

    echo "  building ${_IMAGE} (first run only; this takes several minutes) ..."
    _LOCK="${_BUILD_DIR}/.${_IMAGE_NAME}.lock"
    (
        flock -w 3600 9 || { echo "  could not acquire build lock"; exit 1; }
        if [[ -f "${_IMAGE}" ]]; then
            exit 0
        fi
        # tail keeps the job log readable, so the build's own status comes from
        # PIPESTATUS rather than from the pipeline. It has to be checked: a build
        # that fails after partially writing the .sif leaves a file behind, and
        # both the test below and the "reusing existing image" branch of every
        # later job would accept that partial file as a finished image. Remove it
        # and fail here instead.
        "${_APPTAINER}" build --force \
            --build-arg EFA_SRC="${_EFA_SRC}" \
            "${_IMAGE}" "${_DEF_FILE}" 2>&1 | tail -25
        _BUILD_RC=${PIPESTATUS[0]}
        if [[ ${_BUILD_RC} -ne 0 ]]; then
            rm -f "${_IMAGE}"
        fi
        exit "${_BUILD_RC}"
    ) 9> "${_LOCK}"
    _BUILD_RC=$?

    if [[ ${_BUILD_RC} -ne 0 ]] || [[ ! -f "${_IMAGE}" ]]; then
        _bad "image build failed (rc=${_BUILD_RC})"
        echo ""; echo "RESULT: ${FAIL}"; exit 1
    fi
    _ok "built ${_IMAGE} ($(du -h "${_IMAGE}" 2>/dev/null | cut -f1))"
fi

# ---------------------------------------------------------------------------
# 3. EFA visible INSIDE the container
# ---------------------------------------------------------------------------
_hdr "3. EFA provider inside the container"

# No --bind flags: this is the point. If this needs binds, something changed.
_FI_OUT=$("${_APPTAINER}" exec "${_IMAGE}" fi_info -p efa 2>&1)
if echo "${_FI_OUT}" | grep -q 'provider: efa'; then
    _ok "the efa provider is visible inside the container with no bind flags"
    echo "${_FI_OUT}" | grep -E 'provider:|domain:|type:' | sed 's/^/         | /' | head -12
else
    _bad "the efa provider is NOT visible inside the container"
    echo "${_FI_OUT}" | sed 's/^/         | /' | head -12
    _info "Expected Apptainer's default 'mount dev = yes' to expose"
    _info "/dev/infiniband/*. Check the runtime configuration."
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi

# Device naming is NOT portable across base OSes: amazonlinux2 reports efa_0-rdm
# while newer base OSes report rdmap0s26-rdm or similar. Report, never assume.
_DOMAINS=$(echo "${_FI_OUT}" | awk '/domain:/{print $2}' | sort -u | tr '\n' ' ')
_info "container EFA domains: ${_DOMAINS}"

# ---------------------------------------------------------------------------
# 4. Multi-node MPI: EFA versus TCP
# ---------------------------------------------------------------------------
_hdr "4. Multi-node MPI latency, EFA versus TCP"

_PROBE_STAGED="${_SELF_DIR}/mpi_latency_probe.c"
# The probe is compiled inside the container and then executed inside the
# container on every node, so BOTH the source and the binary must live somewhere
# the container and every node can see. Apptainer bind-mounts $HOME and /tmp by
# default but NOT /apps, where these sample assets are staged -- compiling
# straight from ${_SELF_DIR} fails with "No such file or directory" out of cc1
# even though the file plainly exists on the host.
#
# $HOME is on the shared filesystem and is bound into the container, so copy the
# source there and build in place. It deliberately does NOT go in TMPDIR: this
# feature points APPTAINER_TMPDIR at node-local /scratch, which is neither shared
# between nodes nor bound into the container, so neither the source nor the
# resulting binary would be reachable by the remote ranks.
_PROBE_DIR="${HOME}/.edh/mpi_probe"
mkdir -p "${_PROBE_DIR}" 2>/dev/null
_PROBE="${_PROBE_DIR}/mpi_latency_probe.c"
_PROBE_BIN="${_PROBE_DIR}/mpi_latency_probe.$$"

if [[ ! -f "${_PROBE_STAGED}" ]]; then
    _bad "latency probe source not found at ${_PROBE_STAGED}"
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi
if ! cp -f "${_PROBE_STAGED}" "${_PROBE}"; then
    _bad "unable to copy the probe source into ${_PROBE_DIR}"
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi

# Compile the probe INSIDE the container so it links the container's MPI.
echo "  compiling the probe inside the container ..."
if ! "${_APPTAINER}" exec "${_IMAGE}" /opt/amazon/openmpi/bin/mpicc \
        -O2 -o "${_PROBE_BIN}" "${_PROBE}" 2>&1 | sed 's/^/         | /'; then
    _warn "probe compilation reported output; continuing if the binary exists"
fi
if [[ ! -x "${_PROBE_BIN}" ]]; then
    _bad "could not build the MPI latency probe"
    echo ""; echo "RESULT: ${FAIL}"; exit 1
fi
_ok "probe built"

# Two ranks on two DIFFERENT nodes, so the message actually crosses the fabric.
_TWO_HOSTS=$(sort -u "${_HOSTFILE}" | head -2 | paste -sd, -)

function _run_probe () {
    local _provider="$1"
    # --prefix is required: ranks are placed over ssh and the remote orted is
    # not otherwise found. FI_PROVIDER is set explicitly so an unavailable
    # provider fails loudly instead of silently falling back.
    #
    # Only forward cache variables that are actually set. `mpirun -x VAR` for an
    # undefined VAR is an error in OpenMPI, so forwarding them unconditionally
    # would fail the run for a reason unrelated to the fabric.
    local _fwd=()
    local _v
    for _v in APPTAINER_CACHEDIR APPTAINER_TMPDIR; do
        if [[ -n "${!_v:-}" ]]; then
            _fwd+=("-x" "${_v}")
        fi
    done

    # ${_fwd[@]+...} is required, not defensive. Under `set -u` (line 32) bash
    # before 4.4 treats "${_fwd[@]}" on an EMPTY array as an unbound variable, and
    # empty is the ordinary case here: neither cache variable is set unless the job
    # shell sourced /etc/environment or profile.d, which a non-login scheduler
    # shell may not do. The failure is quiet rather than loud, which is why it
    # matters: this function is called as `$(_run_probe ...)`, so the abort kills
    # only the substitution subshell, mpirun never runs, the measurement comes back
    # empty, and the sample then reports "the EFA run produced no measurement" --
    # blaming the fabric for a shell defect. The guarded form expands to zero
    # arguments when empty and is unchanged when populated.
    "${MPIRUN}" \
        --prefix "${MPI_PREFIX}" \
        -np 2 \
        --host "${_TWO_HOSTS}" \
        --map-by node \
        -x FI_PROVIDER="${_provider}" \
        "${_fwd[@]+"${_fwd[@]}"}" \
        "${_APPTAINER}" exec "${_IMAGE}" "${_PROBE_BIN}" 2>&1
}

echo ""
echo "  --- FI_PROVIDER=efa ---"
_EFA_OUT=$(_run_probe efa)
echo "${_EFA_OUT}" | sed 's/^/         | /'
_EFA_US=$(echo "${_EFA_OUT}" | awk '/half-round-trip/{print $(NF-1)}' | tail -1)

echo ""
echo "  --- FI_PROVIDER=tcp ---"
_TCP_OUT=$(_run_probe tcp)
echo "${_TCP_OUT}" | sed 's/^/         | /'
_TCP_US=$(echo "${_TCP_OUT}" | awk '/half-round-trip/{print $(NF-1)}' | tail -1)

rm -f "${_PROBE_BIN}"

echo ""
if [[ -z "${_EFA_US}" ]]; then
    _bad "the EFA run produced no measurement"
    _info "With FI_PROVIDER=efa set explicitly, this means EFA was unusable."
elif [[ -z "${_TCP_US}" ]]; then
    _warn "the TCP run produced no measurement, so no comparison is possible"
    _ok "EFA half-round-trip: ${_EFA_US} us"
else
    _ok "EFA half-round-trip: ${_EFA_US} us"
    _ok "TCP half-round-trip: ${_TCP_US} us"
    _RATIO=$(awk -v t="${_TCP_US}" -v e="${_EFA_US}" 'BEGIN{ if (e>0) printf "%.2f", t/e; else print "0" }')
    _info "TCP is ${_RATIO}x the EFA latency"

    # Calibrated against a real 2-node hpc6id.32xlarge run, which is the default
    # instance type for this sample: EFA 16.25 us against TCP 24.68 us, a ratio of
    # 1.52x. An earlier hand-run on the same instance type showed 8.2x, so the
    # ratio depends heavily on how well TCP happens to perform and is NOT a
    # reliable pass/fail signal on its own -- a 2x bar reports a false alarm on a
    # correctly working flagship configuration.
    #
    # So the ratio is supporting evidence, not the verdict. The load-bearing
    # assertions are section 3 (the efa provider enumerates inside the container)
    # and the fact that the explicit FI_PROVIDER=efa run completed at all, since
    # an unavailable provider fails rather than falling back. Only EFA being no
    # faster than TCP is treated as a real failure.
    if awk -v r="${_RATIO}" 'BEGIN{exit !(r > 1.2)}'; then
        _ok "EFA is carrying the traffic (${_RATIO}x faster than TCP)"
        _info "The ratio varies with TCP performance and instance rail count;"
        _info "anything above parity alongside a successful FI_PROVIDER=efa run"
        _info "means the fabric is in use."
    elif awk -v r="${_RATIO}" 'BEGIN{exit !(r > 1.0)}'; then
        _warn "EFA is only marginally faster than TCP (${_RATIO}x)"
        _info "The provider enumerated and the run completed, so EFA is in use, but"
        _info "this is worth a second look on a multi-rail instance."
    else
        _bad "EFA is no faster than TCP (${_RATIO}x)"
        _info "The container's MPI and libfabric probably do not match the host's."
        _info "Rebuild the image from this node's EFA installer."
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
_hdr "Summary"
echo "  nodes:    ${_NODE_COUNT}"
echo "  image:    ${_IMAGE}"
echo "  EFA:      ${_EFA_US:-no measurement} us"
echo "  TCP:      ${_TCP_US:-no measurement} us"
echo "  failures: ${_failures}"
echo "  warnings: ${_warnings}"
echo ""
if [[ ${_failures} -gt 0 ]]; then
    echo "RESULT: ${FAIL} - ${_failures} check(s) failed."
    exit 1
fi
echo "RESULT: ${PASS} - MPI over EFA works from inside the container."
echo ""
echo "  reuse this image in your own jobs with:"
echo "    ${MPIRUN} --prefix ${MPI_PREFIX} -x FI_PROVIDER=efa \\"
echo "        apptainer exec ${_IMAGE} <your-mpi-program>"
exit 0
