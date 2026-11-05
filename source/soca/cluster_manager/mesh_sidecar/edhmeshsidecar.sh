#!/usr/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# edhmeshsidecar.sh start|stop|restart|status|foreground
#
# `foreground` is what edh-mesh-sidecar.service invokes: it execs uwsgi in place so
# systemd supervises the uwsgi process itself. The other verbs are for an operator
# at a shell.
#
# The mesh sidecar: a second uwsgi application serving ONLY the peer-facing mesh
# routes, bound to this cluster's overlay address rather than to 0.0.0.0.
#
# WHY THE ENTRY FILE IS NOT NAMED wsgi.py, and this is not cosmetic.
# edhwebui.sh finds its own processes with
#
#     ps aux | grep uwsgi | grep wsgi.py
#
# which is an unanchored substring match. Any sidecar entry file whose name ENDS in
# wsgi.py - mesh_sidecar_wsgi.py, sidecar_wsgi.py - matches it, so `edhwebui.sh
# stop` would kill -9 this process too, and `edhwebui.sh status` would report the
# web interface running when only the sidecar was. The entry file is therefore
# mesh_sidecar_entry.py, which contains no such substring, and this script's own
# status match is that filename so it cannot select the web interface either.
#
# BIND ADDRESS. The overlay address on edh-mesh0, not 0.0.0.0. That is the whole
# security property of splitting these routes out: a peer-facing route is
# unreachable from the public listener because nothing is listening for it there.
# If the interface has no address the sidecar does NOT fall back to a wildcard
# bind - it refuses to start and says why, because a fallback here would silently
# publish the routes this split exists to withhold.

set -a  # auto-export vars (bare /etc/environment KEY=value lines are not exported on source)
source /etc/environment
set +a
source "/opt/edh/${EDH_CLUSTER_ID}/python/latest/edh_python.env"

UWSGI_BIN="/opt/edh/${EDH_CLUSTER_ID}/python/latest/bin/uwsgi"
UWSGI_FILE='mesh_sidecar_entry.py'
MESH_INTERFACE="${EDH_MESH_INTERFACE:-edh-mesh0}"
MESH_SIDECAR_PORT="${EDH_MESH_SIDECAR_PORT:-8444}"

# Small deliberately. Every caller is another cluster's reconciler making short
# requests, not a browser, and a mesh is capped at a small number of peers.
UWSGI_PROCESSES=2
UWSGI_THREADS=4
BUFFER_SIZE=32768

# Both entries are needed: the endpoint modules live under web_interface/api, and
# overlay_daemon and utils live at the cluster_manager root. app.py also inserts
# these itself, so the application is importable however it is started; this makes
# the uwsgi invocation independent of the working directory.
export PYTHONPATH="/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/:/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/web_interface/"

UWSGI_OPTIONS+="--die-on-term "
UWSGI_OPTIONS+="--threaded-logger "
UWSGI_OPTIONS+="--log-micros "
# 0022 -> 755 dirs / 644 files. On --daemonize uwsgi resets the umask to 0 unless
# told otherwise, which is how the web interface ended up creating world-writable
# __pycache__ and log files.
UWSGI_OPTIONS+="--umask 0022 "
# Its own stats socket. The web interface holds 127.0.0.1:9191, and two uwsgi
# supervisors on one socket means the second fails to bind and logs a cause
# nobody reads.
UWSGI_OPTIONS+="--stats 127.0.0.1:9192 "

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

cd "$(dirname "$0")" || exit 1

STATE_DIR="state"
CERT="${STATE_DIR}/sidecar.crt"
KEY="${STATE_DIR}/sidecar.key"

status ()
    {
    status_check_process=$(ps aux | grep uwsgi | grep "$UWSGI_FILE" | grep -v grep | awk '{print $2}')
    }

mesh_address ()
    {
    # The first global address on the overlay interface. -o for one line per
    # address so the field positions are stable, and `scope global` so a link-local
    # address is never selected: binding to fe80:: would look like success and be
    # unreachable from every peer.
    mesh_ip=$(ip -o addr show dev "$MESH_INTERFACE" scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -n1)
    }

preflight ()
    {
    # Everything both start modes need before uwsgi: the address, the directories,
    # the certificate, and the bind specification. Shared rather than copied because
    # the refusal below is the security property of this whole process, and a second
    # copy of it is a copy that can be edited on its own.
    mesh_address
    if [[ -z $mesh_ip ]]; then
        echo "REFUSING TO START: interface ${MESH_INTERFACE} has no global address."
        echo "The sidecar binds to the overlay address on purpose, so that the"
        echo "peer-facing mesh routes are not reachable from the public listener."
        echo "Starting on 0.0.0.0 instead would publish exactly the routes this"
        echo "process exists to keep on the mesh, so there is no fallback."
        echo "Check that the overlay is up: ip addr show ${MESH_INTERFACE}"
        exit 1
    fi

    mkdir -p "${STATE_DIR}" logs
    chmod 700 "${STATE_DIR}"

    if [[ ! -f "${CERT}" || ! -f "${KEY}" ]]; then
        echo "No sidecar certificate found, generating a self-signed one ..."
        # Self-signed and peers do not verify it. The transport is already
        # authenticated and encrypted by WireGuard, which authenticates every
        # packet by Curve25519 before this process sees it; TLS here is for the
        # HTTP client's sake rather than for trust. A real CA would add a rotation
        # and distribution problem without adding a property the tunnel lacks.
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -subj "/CN=edh-mesh-sidecar-${EDH_CLUSTER_ID}" \
            -keyout "${KEY}" -out "${CERT}" >/dev/null 2>&1 || {
                echo "Could not generate the sidecar certificate."
                exit 1
            }
        chmod 600 "${KEY}"
        chmod 644 "${CERT}"
    fi

    # Bracket a literal IPv6 address, which uwsgi needs to tell the address from
    # the port separator.
    if [[ "$mesh_ip" == *:* ]]; then
        bind_spec="[${mesh_ip}]:${MESH_SIDECAR_PORT}"
    else
        bind_spec="${mesh_ip}:${MESH_SIDECAR_PORT}"
    fi
    }

build_uwsgi_argv ()
    {
    # One definition of the invocation, so the supervised and the detached mode
    # cannot drift in the arguments that decide what is served and where. The only
    # difference between them is --daemonize, which the caller appends.
    UWSGI_ARGV=(
        --master
        --https "${bind_spec},${CERT},${KEY}"
        --wsgi-file "$UWSGI_FILE"
        --processes "$UWSGI_PROCESSES"
        --threads "$UWSGI_THREADS"
        --enable-threads
        --buffer-size "$BUFFER_SIZE"
        --log-maxsize 104857600
    )
    }

if [[ $# -eq 0 ]] ; then
    echo 'Usage: edhmeshsidecar.sh start|stop|restart|status|foreground'
    exit 0
fi

case "$1" in
    ## START
    start)
    status
    if [[ -n $status_check_process ]]; then
        echo "The mesh sidecar is already running with PIDs: $status_check_process"
        echo 'Run "edhmeshsidecar.sh stop" first.'
        exit 0
    fi

    preflight
    build_uwsgi_argv

    echo "Starting the mesh sidecar on ${bind_spec} (${MESH_INTERFACE})"
    $UWSGI_BIN "${UWSGI_ARGV[@]}" \
        --daemonize logs/mesh_sidecar.log \
        ${UWSGI_OPTIONS}
    ;;
    ## FOREGROUND
    foreground)
    # What the systemd unit invokes, and the reason the unit does not invoke
    # `start`. That mode hands uwsgi --daemonize, so the script returns as soon as
    # uwsgi forks away; under Type=simple systemd reads the script's exit as the
    # service dying and restarts it, which then meets the already-running check
    # above and exits 0 - another clean exit, so the loop continues against a
    # perfectly healthy sidecar.
    #
    # Here uwsgi is exec'd in place, so it becomes the unit's main process and
    # systemd supervises it directly. --die-on-term is already in
    # UWSGI_OPTIONS, which is what makes systemd's SIGTERM a clean shutdown rather
    # than uwsgi's default brutal reload.
    #
    # No already-running check: systemd owns the lifecycle in this mode, and a
    # refusal here would turn a stale process-table match into a unit that will not
    # start. A genuine second instance is reported by uwsgi failing to bind, and the
    # unit retries.
    #
    # The refusal in preflight is what covers an interface that is not up yet: it
    # exits 1, systemd waits RestartSec and tries again, bounded by the unit's
    # StartLimitBurst.
    preflight
    build_uwsgi_argv

    echo "Starting the mesh sidecar in the foreground on ${bind_spec} (${MESH_INTERFACE})"
    exec $UWSGI_BIN "${UWSGI_ARGV[@]}" ${UWSGI_OPTIONS}
    ;;
    ## STOP
    stop)
    status
    if [[ -z $status_check_process ]]; then
        echo 'The mesh sidecar is not running'
    else
        kill -9 $status_check_process
    fi
    ;;
    ## RESTART
    restart)
        echo 'Restarting the mesh sidecar ...'
        $0 stop
        sleep 3
        $0 start
    ;;
    ## STATUS
    status)
        status
        if [[ -z $status_check_process ]]; then
            echo 'The mesh sidecar is not running'
        else
            echo "The mesh sidecar is running with PIDs: $status_check_process"
        fi
    ;;
    *) echo 'Usage: edhmeshsidecar.sh start|stop|restart|status|foreground' ;;
esac
