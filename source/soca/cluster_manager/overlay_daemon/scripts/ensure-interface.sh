#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the mesh WireGuard interface and its own addresses.
#
# Runs as ExecStartPre for edh-overlay-daemon.service. This script owns the
# [Interface] side only: the private key, the listen port, the MTU and this
# cluster's own addresses. The daemon owns peers, which it manages with
# wg syncconf against an interface that already exists.
#
# Idempotent. An interface that is already up with the right settings is left
# alone, so a daemon restart does not bounce the tunnel.
#
# Inputs, all set by the systemd unit:
#   EDH_CLUSTER_ID
#   EDH_MESH_ID
#   EDH_MESH_TABLE_PREFIX
#   EDH_REGION
#   EDH_WG_SECRET_ARN
#   EDH_LISTEN_PORT       (default 51820)
#   EDH_MTU               (default 1280)

set -euo pipefail

: "${EDH_CLUSTER_ID:?EDH_CLUSTER_ID must be set}"
: "${EDH_MESH_ID:?EDH_MESH_ID must be set}"
: "${EDH_REGION:?EDH_REGION must be set}"
: "${EDH_WG_SECRET_ARN:?EDH_WG_SECRET_ARN must be set}"
# Required rather than defaulted. A wrong prefix names a table belonging to no
# mesh, and on a cluster upgraded from the pre-namespacing version of this
# feature an unprefixed table can genuinely exist and hold stale data, so
# guessing here would read a real table and report a mesh that is not there.
# overlay_daemon.table_names refuses for the same reason.
: "${EDH_MESH_TABLE_PREFIX:?EDH_MESH_TABLE_PREFIX must be set; the installer publishes it and the systemd unit bakes it in}"

# The interface name is deliberately NOT overridable here. It was
# "${EDH_INTERFACE:-edh-mesh0}", an override the daemon cannot see: wg_config
# hardcodes the name and uses it for wg syncconf, wg set and every ip route
# call, so setting it brought the interface up under one name and left the
# daemon operating on another. That fails every command rather than getting one
# value wrong, and no configuration key ships for it, so the override was
# undocumented surface with a sharp edge. One name, one definition; a test
# asserts this literal matches wg_config.INTERFACE_NAME.
INTERFACE="edh-mesh0"
LISTEN_PORT="${EDH_LISTEN_PORT:-51820}"
MTU="${EDH_MTU:-1280}"
KEY_FILE="/etc/wireguard/${INTERFACE}.key"
CONFIG_TABLE="${EDH_TABLE_OVERLAY_CONFIG:-edh_${EDH_MESH_TABLE_PREFIX}_overlay_config}"

log() { logger -t "edh-overlay-iface" "$*"; echo "$*" >&2; }

# ----------------------------------------------------------------------
# 1. Private key on disk, from Secrets Manager
# ----------------------------------------------------------------------

if [[ ! -s "${KEY_FILE}" ]]; then
    log "no private key on disk; fetching from Secrets Manager"
    mkdir -p /etc/wireguard
    chmod 0700 /etc/wireguard
    # Written through a restrictive umask so the key is never briefly readable
    # between creation and chmod.
    ( umask 0377 && aws --region "${EDH_REGION}" secretsmanager get-secret-value \
        --secret-id "${EDH_WG_SECRET_ARN}" \
        --query SecretString --output text > "${KEY_FILE}" )
    chmod 0400 "${KEY_FILE}"
fi

# ----------------------------------------------------------------------
# 2. This cluster's addresses, from its own row in the mesh table
# ----------------------------------------------------------------------

PEER_ROW=$(aws --region "${EDH_REGION}" dynamodb get-item \
    --table-name "${CONFIG_TABLE}" \
    --key "{\"mesh_id\": {\"S\": \"${EDH_MESH_ID}\"}, \"cluster_id\": {\"S\": \"${EDH_CLUSTER_ID}\"}}" \
    --output json) || { log "FATAL: cannot read this cluster's row from ${CONFIG_TABLE}"; exit 2; }

read -r ULA CGN <<<"$(printf '%s' "${PEER_ROW}" | python3 -c '
import json, sys
item = json.load(sys.stdin).get("Item", {})
print(item.get("ula_prefix", {}).get("S", ""), item.get("cgn_prefix", {}).get("S", ""))
')"

if [[ -z "${ULA}" || -z "${CGN}" ]]; then
    log "FATAL: this cluster's row has no address plan, so bootstrap has not"
    log "       completed. Run: python3 -m overlay_daemon bootstrap --help"
    exit 3
fi

# The controller is the first host in each of this cluster's own prefixes.
# Derived by stripping the prefix length and appending, which is correct here
# because both values are generated in a fixed form: the IPv6 prefix always
# ends in "::" and the IPv4 one always ends in ".0".
V6_ADDR="${ULA%::/64}::1/64"
V4_ADDR="${CGN%.0/24}.1/24"

# ----------------------------------------------------------------------
# 3. Interface, key, port, MTU, addresses
# ----------------------------------------------------------------------

if ! ip link show "${INTERFACE}" >/dev/null 2>&1; then
    log "creating interface ${INTERFACE}"
    ip link add dev "${INTERFACE}" type wireguard
fi

ip link set dev "${INTERFACE}" mtu "${MTU}"
wg set "${INTERFACE}" private-key "${KEY_FILE}" listen-port "${LISTEN_PORT}"

# Already-assigned addresses are the desired end state, so a rejection here is
# not a failure.
ip addr add "${V6_ADDR}" dev "${INTERFACE}" 2>/dev/null || true
ip addr add "${V4_ADDR}" dev "${INTERFACE}" 2>/dev/null || true

ip link set "${INTERFACE}" up

log "interface ${INTERFACE} up: v6=${V6_ADDR} v4=${V4_ADDR} mtu=${MTU} port=${LISTEN_PORT}"
