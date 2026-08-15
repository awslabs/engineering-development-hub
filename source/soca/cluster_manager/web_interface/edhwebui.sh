#!/usr/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


#
# edhwebui.sh start|stop|status|restart
#


set -a  # auto-export vars (bare /etc/environment KEY=value lines are not exported on source)
source /etc/environment
set +a
source "/opt/edh/${EDH_CLUSTER_ID}/python/latest/edh_python.env"
UWSGI_BIN="/opt/edh/${EDH_CLUSTER_ID}/python/latest/bin/uwsgi"
UWSGI_BIND='0.0.0.0:8443'

UWSGI_PROCESSES=5
UWSGI_THREADS=$(nproc)
UWSGI_FILE='wsgi.py'
BUFFER_SIZE=32768

# ---------------------------------------------------------------------------
# Gevent / SSE support.
#
# When UWSGI_GEVENT_ENABLED=1 (default), uwsgi runs in cooperative concurrency
# mode: each worker process is one OS thread driving N greenlets. This is
# REQUIRED for the DCV event-relay SSE endpoint (/api/dcv/events/stream)
# which holds long-lived HTTP connections per browser. Without it, 5 procs
# x nproc threads = ~20 connection slots and the WebUI becomes unreachable
# under load.
#
# Sized for ~1000 concurrent SSE-connected users on SQLite (5 procs x 512
# greenlets = 2560 slots, ~2x headroom). Bump UWSGI_GEVENT_GREENLETS for
# larger fleets; revisit Redis pub/sub at the Aurora migration cutover.
#
# Set UWSGI_GEVENT_ENABLED=0 to revert to the legacy thread-per-request
# model (no SSE; small clusters / smoke tests only).
# ---------------------------------------------------------------------------
UWSGI_GEVENT_ENABLED=${UWSGI_GEVENT_ENABLED:-1}
UWSGI_GEVENT_GREENLETS=${UWSGI_GEVENT_GREENLETS:-512}
UWSGI_LISTEN_BACKLOG=${UWSGI_LISTEN_BACKLOG:-2048}

if [[ "${UWSGI_GEVENT_ENABLED}" == "1" ]]; then
    # gevent mode: one OS thread per worker, all concurrency via greenlets
    UWSGI_THREADS=1
    UWSGI_OPTIONS+="--gevent ${UWSGI_GEVENT_GREENLETS} "
    # Use --gevent-early-monkey-patch (NOT --gevent-monkey-patch) so ssl
    # is patched BEFORE urllib3/requests/botocore import it. With the
    # post-load variant, those modules cache references to the un-patched
    # ssl and a localhost HTTPS call from SocaHttpClient recurses
    # infinitely (RecursionError surfaces as "maximum recursion depth").
    UWSGI_OPTIONS+="--gevent-early-monkey-patch "
    UWSGI_OPTIONS+="--listen ${UWSGI_LISTEN_BACKLOG} "
    UWSGI_OPTIONS+="--so-keepalive "
    # SSE-specific: connections are long-lived; harakiri must NOT kill them,
    # post-buffering must be off so chunks flush immediately. The
    # X-Accel-Buffering: no header is set per-response from Flask in the
    # SSE endpoint (api/v1/dcv/event_stream.py) -- NOT here, because
    # uwsgi --add-header with a value containing whitespace breaks shell
    # word-splitting when UWSGI_OPTIONS expands on the exec line.
    UWSGI_OPTIONS+="--harakiri 0 "
    UWSGI_OPTIONS+="--post-buffering 0 "
fi
export PYTHONPATH=/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/
#
# Select UWSGI options to build the command-line
#
# Stats
UWSGI_OPTIONS+="--stats 127.0.0.1:9191 "
# Produce memory reporting in stats
UWSGI_OPTIONS+="--memory-report "
# Log the X-Forwarded-for instead of the ELB source IP addresses
UWSGI_OPTIONS+="--log-x-forwarded-for "
# Allow offloading threads. Under gevent (UWSGI_GEVENT_ENABLED=1) we use
# a small fixed pool independent of UWSGI_THREADS (which is 1 in gevent
# mode); under legacy threaded mode we match nproc as before.
if [[ "${UWSGI_GEVENT_ENABLED}" == "1" ]]; then
    UWSGI_OPTIONS+="--offload-threads 2 "
else
    UWSGI_OPTIONS+="--offload-threads ${UWSGI_THREADS} "
fi
# Allow logging via threaded logger
UWSGI_OPTIONS+="--threaded-logger "
# Log in microseconds
UWSGI_OPTIONS+="--log-micros "
# Needed for proper shutdown
UWSGI_OPTIONS+="--die-on-term "
# Set a sane umask. On --daemonize, uwsgi resets the process umask to 0 unless
# told otherwise, so files/dirs created by the workers (interpreter __pycache__,
# the app log files, tmp) were world/group-writable (777 dirs, 666 files).
# 0022 -> 755 dirs / 644 files (V1660218709, V1734110841).
UWSGI_OPTIONS+="--umask 0022 "

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

cd $(dirname "$0")
status ()
    {
    status_check_process=$(ps aux | grep uwsgi | grep $UWSGI_FILE | awk '{print $2}')
    }

if [[ $# -eq 0 ]] ; then
    echo 'Usage: edhwebui.sh start|stop|restart|status'
    exit 0
fi

case "$1" in
    ## START
    start)

    ## Create the structure if does not exist
    if [[ ! -d "tmp/" ]]; then
      echo "First configuration: Creating tmp/ folder structure, please wait 10 seconds"
      mkdir -p tmp/ssh
      mkdir -p tmp/zip_downloads
      chmod 700 tmp/
      sleep 10
    fi

    ## Create the structure if does not exist
    if [[ ! -d "logs/" ]]; then
      echo "First configuration: Creating logs/ folder structure, please wait 10 seconds"
      mkdir -p logs/
      chmod 700 logs/
      sleep 10
    fi


    status
    mkdir -p keys
    chmod 600 keys
    if [[ -z $status_check_process ]]; then
        echo 'Starting EDH'
        if [[ ! -f keys/dcv_secret_key.txt ]]; then
            echo 'No dcv Key detected, creating new one ...'
            # /!\ ATTENTION
            # DCV Secret Key used to authenticate DCV sessions via /api/system/dcv_authenticator.
            # If you delete/change this value, your existing sessions will become inaccessible and your user must re-create them
            dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64 > keys/dcv_secret_key.txt
            chmod 600 keys/dcv_secret_key.txt
            sleep 5
        fi

        export SOCA_DCV_TOKEN_SYMMETRIC_KEY=$(cat keys/dcv_secret_key.txt)

        tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 32 > keys/admin_api_key.txt
        chmod 600 keys/admin_api_key.txt
        export SOCA_FLASK_API_ROOT_KEY=$(cat keys/admin_api_key.txt)

        # Compile i18n translation catalogs (.po -> .mo)
        # .mo files are gitignored; must be compiled at startup time from .po sources.
        # Errors are logged to logs/i18n_compile.log rather than swallowed so broken
        # translation catalogs can be diagnosed. Non-fatal: Flask-Babel silently
        # falls back to English if .mo files are missing or unreadable.
        mkdir -p logs
        if command -v pybabel &> /dev/null; then
            pybabel compile -d translations/ >> logs/i18n_compile.log 2>&1 || \
                echo "[$(date -u +%FT%TZ)] pybabel compile failed — see above" >> logs/i18n_compile.log
        elif command -v python3 &> /dev/null; then
            python3 -c "from babel.messages.frontend import compile_catalog; import sys; sys.argv=['','compile','-d','translations/']; compile_catalog()" >> logs/i18n_compile.log 2>&1 || \
                echo "[$(date -u +%FT%TZ)] python3 compile_catalog failed — see above" >> logs/i18n_compile.log
        else
            echo "[$(date -u +%FT%TZ)] WARN: neither pybabel nor python3 available; skipping catalog compile — UI will run in English" >> logs/i18n_compile.log
        fi

        # Launching process
        $UWSGI_BIN --master --https $UWSGI_BIND,cert.crt,cert.key --wsgi-file $UWSGI_FILE --processes $UWSGI_PROCESSES --log-maxsize 104857600 --threads $UWSGI_THREADS --daemonize logs/uwsgi.log --enable-threads --buffer-size $BUFFER_SIZE --check-static /opt/edh/${EDH_CLUSTER_ID}/cluster_manager/web_interface/static ${UWSGI_OPTIONS}

    else
       echo 'EDH is already running with PIDs: ' $status_check_process
        echo 'Run "edhwebui.sh stop" first.'
    fi

    ;;
    ## STOP
    stop)
    status
    if [[ -z $status_check_process ]]; then
           echo 'EDH is not running'
       else
          kill -9 $status_check_process


       fi
    ;;
    ## RESTART
    restart)
        echo 'Restarting EDH...'
        $0 stop
        sleep 3
        $0 start
        echo 'EDH restarted successfully.'
    ;;
    ## STATUS
    status)
        status
        if [[ -z $status_check_process ]]; then
            echo 'EDH is not running'
        else
           echo 'EDH is running with PIDs: ' $status_check_process

        fi


     ;;
    *) echo 'Usage: edhwebui.sh start|stop|restart|status' ;;
esac