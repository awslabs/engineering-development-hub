#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install and start the cross-region overlay daemon on the controller.
#
# Run once during controller bootstrap, when
# Config.services.cross_region.enabled is true. It:
#   1. installs the WireGuard userspace tools and confirms the kernel module
#   2. runs the daemon's bootstrap subcommand once, creating or joining the mesh
#   3. renders and installs the systemd unit
#   4. enables and starts it
#
# Idempotent. Re-running is safe: the bootstrap subcommand recognises this
# cluster's own row and does nothing, and the unit install is a rewrite.
#
# Step 2 is the one step allowed to fail the controller install. Everything
# else can be retried later, but a cluster that cannot determine whether it is
# creating or joining a mesh must not proceed, because guessing produces two
# clusters with conflicting address plans.
#
# Pre-conditions, from the bootstrap pipeline's /etc/environment:
#   EDH_CLUSTER_ID, EDH_MESH_ID, EDH_REGION, EDH_WG_SECRET_ARN,
#   EDH_MESH_TABLE_PREFIX, EDH_CONTROLLER_IP

set -euo pipefail

# shellcheck disable=SC1091
source /etc/environment

: "${EDH_CLUSTER_ID:?EDH_CLUSTER_ID must be set}"
: "${EDH_MESH_ID:?EDH_MESH_ID must be set}"
: "${EDH_REGION:?EDH_REGION must be set}"
: "${EDH_WG_SECRET_ARN:?EDH_WG_SECRET_ARN must be set}"
: "${EDH_MESH_TABLE_PREFIX:?EDH_MESH_TABLE_PREFIX must be set}"
# The address peers dial to reach this cluster. Taken from the value the
# controller bootstrap already resolved and exported, rather than read from
# instance metadata here: EDH's own launch templates set HttpTokens=required by
# default (Config.metadata_http_tokens), so an unauthenticated metadata request
# is answered with 401, and the repo's rule is to never call 169.254.169.254
# directly. get_ipv4_host_address, which produces this, uses `hostname -I` and
# needs no metadata service at all.
: "${EDH_CONTROLLER_IP:?EDH_CONTROLLER_IP must be set; the controller bootstrap exports it before invoking this script}"

CLUSTER_BASE="/opt/edh/${EDH_CLUSTER_ID}"
DAEMON_DIR="${CLUSTER_BASE}/cluster_manager/overlay_daemon"
SCRIPTS_DIR="${DAEMON_DIR}/scripts"
TEMPLATE="${SCRIPTS_DIR}/edh-overlay-daemon.service.j2"
UNIT_PATH="/etc/systemd/system/edh-overlay-daemon.service"
EDH_PYTHON="${EDH_PYTHON:-${CLUSTER_BASE}/python/latest/bin/python3}"

log() { echo "[install-overlay-daemon] $*"; }

# ----------------------------------------------------------------------
# 1. WireGuard
# ----------------------------------------------------------------------

log "installing wireguard-tools"
if command -v dnf >/dev/null 2>&1; then
    dnf -y install wireguard-tools
elif command -v yum >/dev/null 2>&1; then
    yum -y install wireguard-tools
else
    log "FATAL: neither dnf nor yum is available"
    exit 2
fi

if ! modprobe wireguard 2>/dev/null; then
    log "FATAL: the kernel WireGuard module is not available"
    exit 3
fi

# ----------------------------------------------------------------------
# 2. Create or join the mesh
# ----------------------------------------------------------------------

log "running daemon bootstrap for mesh ${EDH_MESH_ID}"

# Each value is captured into its own variable and checked before use, rather
# than being written as a command substitution in an argument position. Under
# `set -euo pipefail` a substitution that FAILS in an argument position does not
# abort the script and its exit status is not even observable afterwards, so a
# transient STS failure silently passed --account-id "" and --iam-principal ""
# into bootstrap and registered a peer row with a blank identity. The `if !`
# wrapper around bootstrap below does not help with that: it tests the exit
# status of the python process, which is reached with the empty arguments
# already in place.
#
# Each capture is wrapped in `if !` for the same reason the bootstrap call is.
# A bare assignment does trip `set -e`, but it aborts at the assignment with no
# message, so the operator is left with a failed install and no explanation.
# The emptiness check afterwards covers the other case: a command that exits 0
# and prints nothing, which argparse accepts because required=True tests
# presence rather than content.
# Both STS calls pin the region, as every other AWS call in this feature does.
# Left unpinned, the CLI resolves a region from the environment and falls back to
# instance metadata, which these hosts answer with 401 because
# Config.metadata_http_tokens defaults to required, and which the repo forbids
# reaching at all. EDH_REGION is validated at the top of this script, and the
# daemon invocation below already passes it, so the script was pinning the region
# where it handed it to something else and not on its own two calls.
if ! ACCOUNT_ID="$(aws sts get-caller-identity --region "${EDH_REGION}" --query Account --output text)"; then
    log "FATAL: could not read this account's id from STS, so the cluster's"
    log "       identity in the mesh cannot be established. Check the"
    log "       controller's credentials and its route to STS."
    exit 5
fi

if ! IAM_PRINCIPAL="$(aws sts get-caller-identity --region "${EDH_REGION}" --query Arn --output text)"; then
    log "FATAL: could not read this controller's IAM principal from STS."
    log "       Check the controller's credentials and its route to STS."
    exit 5
fi

ENDPOINT="${EDH_CONTROLLER_IP}:${EDH_LISTEN_PORT:-51820}"

for _required in ACCOUNT_ID IAM_PRINCIPAL ENDPOINT; do
    if [[ -z "${!_required}" ]]; then
        log "FATAL: ${_required} resolved empty. Registering a peer row with a"
        log "       blank identity or endpoint would leave a mesh member no"
        log "       peer can reach, which is worse than failing the install."
        exit 5
    fi
done

# Invoked inside `if` so that its failure is handled here rather than aborting
# on `set -e`. Written as a plain command with a trailing `$?` check, the check
# is unreachable: set -e terminates the script at the failing command, so the
# operator never sees the explanation for why the install stopped.
if ! PYTHONPATH="${CLUSTER_BASE}/cluster_manager" \
    "${EDH_PYTHON}" -m overlay_daemon bootstrap \
        --mesh-id "${EDH_MESH_ID}" \
        --cluster-id "${EDH_CLUSTER_ID}" \
        --cluster-name "${EDH_CLUSTER_NAME:-${EDH_CLUSTER_ID}}" \
        --region "${EDH_REGION}" \
        --account-id "${ACCOUNT_ID}" \
        --endpoint "${ENDPOINT}" \
        --private-key-secret-arn "${EDH_WG_SECRET_ARN}" \
        --iam-principal "${IAM_PRINCIPAL}" \
        --mesh-role-arn "${EDH_MESH_ROLE_ARN:-}" \
        --mesh-role-external-id "${EDH_MESH_ROLE_EXTERNAL_ID:-}" \
        --key-rotation-days "${EDH_KEY_ROTATION_DAYS:-90}" \
        --auto-decommission-days "${EDH_AUTO_DECOMMISSION_DAYS:-90}" \
        --decommission-to-tombstone-days "${EDH_DECOMMISSION_TO_TOMBSTONE_DAYS:-30}" \
        --wait-for-approval "${EDH_BOOTSTRAP_WAIT:-0}"; then
    log "FATAL: daemon bootstrap failed, so the mesh state could not be"
    log "       established. Refusing to start the daemon. The install fails"
    log "       here deliberately: see the bootstrap output above for the cause."
    exit 4
fi

log "this cluster is registered in mesh ${EDH_MESH_ID}."
log "If it JOINED, its lifecycle is PENDING and an administrator must approve"
log "it from Admin -> Mesh on any cluster already in the mesh. The tunnel comes"
log "up on its own within one sync interval of that approval, whenever it lands."

# ----------------------------------------------------------------------
# 3. Render and install the unit
# ----------------------------------------------------------------------

log "rendering the systemd unit into ${UNIT_PATH}"
EDH_PYTHON="${EDH_PYTHON}" \
EDH_LISTEN_PORT="${EDH_LISTEN_PORT:-51820}" \
EDH_MTU="${EDH_MTU:-1280}" \
EDH_SYNC_INTERVAL_SECONDS="${EDH_SYNC_INTERVAL_SECONDS:-30}" \
EDH_MESH_ROLE_ARN="${EDH_MESH_ROLE_ARN:-}" \
EDH_MESH_ROLE_EXTERNAL_ID="${EDH_MESH_ROLE_EXTERNAL_ID:-}" \
"${EDH_PYTHON}" - "${TEMPLATE}" "${UNIT_PATH}" <<'PYTHON'
import os
import sys

import jinja2

template_path, unit_path = sys.argv[1], sys.argv[2]

with open(template_path) as handle:
    template = handle.read()

# StrictUndefined so a variable the template needs and the caller forgot fails
# here, rather than rendering an empty value into a unit that then starts with
# no mesh id or no table prefix.
rendered = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(
    template
).render(
    EDH_CLUSTER_ID=os.environ["EDH_CLUSTER_ID"],
    EDH_MESH_ID=os.environ["EDH_MESH_ID"],
    EDH_MESH_TABLE_PREFIX=os.environ["EDH_MESH_TABLE_PREFIX"],
    EDH_REGION=os.environ["EDH_REGION"],
    EDH_WG_SECRET_ARN=os.environ["EDH_WG_SECRET_ARN"],
    EDH_PYTHON=os.environ["EDH_PYTHON"],
    EDH_LISTEN_PORT=os.environ["EDH_LISTEN_PORT"],
    EDH_MTU=os.environ["EDH_MTU"],
    EDH_SYNC_INTERVAL_SECONDS=os.environ["EDH_SYNC_INTERVAL_SECONDS"],
    # Empty on a single-account mesh, which renders no flag at all rather than
    # an empty one.
    EDH_MESH_ROLE_ARN=os.environ.get("EDH_MESH_ROLE_ARN", ""),
    EDH_MESH_ROLE_EXTERNAL_ID=os.environ.get("EDH_MESH_ROLE_EXTERNAL_ID", ""),
)

with open(unit_path, "w") as handle:
    handle.write(rendered)
print(f"wrote {unit_path} ({len(rendered)} bytes)")
PYTHON

chmod 0644 "${UNIT_PATH}"
chmod 0755 "${SCRIPTS_DIR}/ensure-interface.sh"

# ----------------------------------------------------------------------
# 4. Enable and start
# ----------------------------------------------------------------------

mkdir -p /etc/wireguard
chmod 0700 /etc/wireguard

# The unit's CapabilityBoundingSet does not include CAP_DAC_OVERRIDE, so root
# cannot traverse a directory missing its execute bit. Some bootstrap paths
# leave the daemon's directories without it, which surfaces as the unit being
# unable to exec ensure-interface.sh. Re-applying a mode with the owner execute
# bit is idempotent and cheap.
#
# The cluster base must stay world-traversable: it is the parent of schedulers/
# where OpenPBS lives, and non-root users traverse it to run qstat and qsub.
# Tightening it here once broke PBS for every non-root caller.
chmod 0755 "${CLUSTER_BASE}" 2>/dev/null || true
chmod 0750 "${CLUSTER_BASE}/cluster_manager" "${DAEMON_DIR}" "${SCRIPTS_DIR}" 2>/dev/null || true

log "enabling and starting edh-overlay-daemon.service"
systemctl daemon-reload
systemctl enable edh-overlay-daemon.service
systemctl restart edh-overlay-daemon.service

# Report the outcome once, from the loop's own result. A loop that breaks on
# success and then falls through into an unconditional warning tells the
# operator the service failed on every healthy install.
for _ in $(seq 1 10); do
    if systemctl is-active --quiet edh-overlay-daemon.service; then
        log "edh-overlay-daemon.service is active"
        exit 0
    fi
    sleep 2
done

log "WARN: edh-overlay-daemon.service did not become active within 20s."
log "      The install is not failed on this: the unit restarts on its own and"
log "      a PENDING cluster legitimately has nothing to do yet. Investigate"
log "      with: journalctl -u edh-overlay-daemon -n 100"
exit 0
