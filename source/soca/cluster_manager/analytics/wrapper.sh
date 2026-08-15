#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Check if exactly one argument is provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 {cluster_nodes_tracking|job_tracking|desktop_hosts_tracking}"
  exit 1
else
  ANALYTICS_MODE=${1}
fi

set -a  # auto-export vars (bare /etc/environment KEY=value lines are not exported on source)
source /etc/environment
set +a

if [[ -z "${EDH_CLUSTER_ID}" ]]; then
  echo "EDH_CLUSTER_ID environment variable not found."
  exit 1
else
  source "/opt/edh/${EDH_CLUSTER_ID}/python/latest/edh_python.env"
  case ${ANALYTICS_MODE} in
    cluster_nodes_tracking)
      "/opt/edh/${EDH_CLUSTER_ID}/python/latest/bin/python3" "/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/analytics/cluster_nodes_tracking.py"
      ;;

    job_tracking)
      "/opt/edh/${EDH_CLUSTER_ID}/python/latest/bin/python3" "/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/analytics/job_tracking.py"
      ;;

    desktop_hosts_tracking)
       "/opt/edh/${EDH_CLUSTER_ID}/python/latest/bin/python3" "/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/analytics/desktop_hosts_tracking.py"
      ;;

    target_nodes_tracking)
       "/opt/edh/${EDH_CLUSTER_ID}/python/latest/bin/python3" "/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/analytics/target_nodes_tracking.py"
      ;;

    *)
      echo "Invalid argument: ${ANALYTICS_MODE}"
      echo "Usage: $0 {cluster_nodes_tracking|job_tracking|desktop_hosts_tracking}"
      exit 1
      ;;
  esac


fi
