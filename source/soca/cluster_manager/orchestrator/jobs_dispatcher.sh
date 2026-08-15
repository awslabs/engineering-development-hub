#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Load environments
# shellcheck source=/dev/null
set -a  # auto-export vars (bare /etc/environment KEY=value lines are not exported on source)
source /etc/environment
set +a

# shellcheck source=/dev/null
source "/opt/edh/${EDH_CLUSTER_ID}/python/latest/edh_python.env"


PYTHON_BIN="/opt/edh/${EDH_CLUSTER_ID}/python/latest/bin/python3"
BASE_DIR="/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/orchestrator"
CONFIG_FILE="$BASE_DIR/settings/queue_mapping.yml"

if [[ -z "$1" ]]; then
    echo "Usage: $0 <queue_type>"
    echo "Example: $0 compute"
    exit 1
else
    TARGET=$1
fi


# Set SOCA_LEGACY_SCHEDULER to "false" to use the old orchestration mechanism
# This scheduling mode is no longer supported
export SOCA_LEGACY_SCHEDULER="false" 

# export SOCA_DEBUG=1 # Uncomment to enable SOCA_DEBUG log

if [[ "${SOCA_LEGACY_SCHEDULER}" == "true" ]]; then
    export PBS_CONF_FILE="/opt/edh/${EDH_CLUSTER_ID}/schedulers/default/openpbs/pbs.conf"
    source "${PBS_CONF_FILE}"
    echo "Running in Legacy Scheduler mode. This mode is not being supported anymore."
    ${PYTHON_BIN} "${BASE_DIR}/legacy/dispatcher.py" -c "${CONFIG_FILE}" -t "${TARGET}"
else
    ${PYTHON_BIN} "${BASE_DIR}/dispatcher.py" -c "${CONFIG_FILE}" -t "${TARGET}"
fi