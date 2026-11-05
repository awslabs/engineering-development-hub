#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install and start the cross-region mesh sidecar on the controller.
#
# Run once during controller bootstrap, after install-overlay-daemon.sh, when
# Config.services.cross_region.enabled is true. It:
#   1. makes the launcher executable
#   2. renders and installs the systemd unit
#   3. enables and starts it
#
# Idempotent. Re-running rewrites the unit and restarts the service.
#
# UNLIKE install-overlay-daemon.sh, NOTHING HERE MAY FAIL THE CONTROLLER INSTALL.
# That script's step 2 is allowed to, because a cluster that cannot tell whether it
# is creating or joining a mesh must not proceed. The sidecar is different: if it
# does not come up, this cluster serves no peer-facing mesh routes and everything
# else about it works. The unit carries Restart=always, so the ordinary case of an
# overlay interface that is not ready yet resolves itself without an operator.
#
# Pre-conditions, from the bootstrap pipeline's /etc/environment:
#   EDH_CLUSTER_ID

set -euo pipefail

# `set -a` around the source, matching edhmeshsidecar.sh. set_environment_variable
# writes BARE `KEY=value` lines, because /etc/environment is read by pam_env and
# pam_env treats `export FOO` as a variable named "export". A bare line sourced
# without -a becomes a shell variable and is NOT exported, so the render below --
# which runs in a child process and reads os.environ -- would raise KeyError while
# every shell-level expansion in this script worked and the `:?` guard passed.
#
# During a controller install this is masked: set_environment_variable also exports
# into its own shell, so 03_setup's children inherit the variable already exported.
# The path that breaks is the one this script's header and 03_setup's own failure
# message both advertise -- an operator re-running it by hand in a fresh shell,
# which is the recovery for exactly the failure that message describes.
set -a
# shellcheck disable=SC1091
source /etc/environment
set +a

: "${EDH_CLUSTER_ID:?EDH_CLUSTER_ID must be set}"

CLUSTER_BASE="/opt/edh/${EDH_CLUSTER_ID}"
SIDECAR_DIR="${CLUSTER_BASE}/cluster_manager/mesh_sidecar"
TEMPLATE="${SIDECAR_DIR}/edh-mesh-sidecar.service.j2"
UNIT_PATH="/etc/systemd/system/edh-mesh-sidecar.service"
EDH_PYTHON="${EDH_PYTHON:-${CLUSTER_BASE}/python/latest/bin/python3}"

log() { echo "[install-mesh-sidecar] $*"; }

# ----------------------------------------------------------------------
# 1. The launcher
# ----------------------------------------------------------------------

# Granted here rather than carried in git. The controller applies `chmod -R 600`
# across cluster_manager/ during prerequisites and then grants +x per file at
# setup, so a mode bit committed to the repository is stripped before this point
# either way. edhwebui.sh is 0644 in git for the same reason.
chmod 0755 "${SIDECAR_DIR}/edhmeshsidecar.sh"

# ----------------------------------------------------------------------
# 2. Render and install the unit
# ----------------------------------------------------------------------

log "rendering the systemd unit into ${UNIT_PATH}"
"${EDH_PYTHON}" - "${TEMPLATE}" "${UNIT_PATH}" <<'PYTHON'
import os
import sys

import jinja2

template_path, unit_path = sys.argv[1], sys.argv[2]

with open(template_path) as handle:
    template = handle.read()

# StrictUndefined so a variable the template needs and this script forgot fails
# here, rather than rendering an empty value into a unit whose ExecStart then
# points at /opt/edh//cluster_manager and fails at exec with no cause named.
rendered = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(
    template
).render(
    EDH_CLUSTER_ID=os.environ["EDH_CLUSTER_ID"],
)

with open(unit_path, "w") as handle:
    handle.write(rendered)
print(f"wrote {unit_path} ({len(rendered)} bytes)")
PYTHON

chmod 0644 "${UNIT_PATH}"

# ----------------------------------------------------------------------
# 3. Enable and start
# ----------------------------------------------------------------------

log "enabling and starting edh-mesh-sidecar.service"
systemctl daemon-reload
systemctl enable edh-mesh-sidecar.service
systemctl restart edh-mesh-sidecar.service

# Checked with systemctl rather than by calling the sidecar. It listens on the
# overlay address and on nothing else - there is no loopback socket to curl, which
# is the whole point of the process - so the only thing reachable from here is the
# unit's own state.
for _ in $(seq 1 10); do
    if systemctl is-active --quiet edh-mesh-sidecar.service; then
        log "edh-mesh-sidecar.service is active"
        exit 0
    fi
    sleep 2
done

log "WARN: edh-mesh-sidecar.service did not become active within 20s."
log "      The install is not failed on this: the unit retries on its own."
log "      The launcher refuses to start until ${EDH_MESH_INTERFACE:-edh-mesh0}"
log "      carries a global address, so the likely causes are that the overlay"
log "      daemon has not completed its first start, or that its interface step"
log "      found no address plan on this cluster's peer row, which means the"
log "      daemon bootstrap did not finish. Awaiting mesh approval is NOT one of"
log "      the causes: a joining cluster is given its address plan at bootstrap"
log "      and holds it while its lifecycle is still PENDING."
log "      Investigate with: journalctl -u edh-mesh-sidecar -n 100"
exit 0
