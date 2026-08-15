#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# This file send the scheduler logs to S3 every day
# This is particularly useful is you are planning to do data mining with services such as Glue / Athena
# To prevent disk to fill up, we also remove ***unmodified*** files after 10 days (default). This value can be changed using DATA_RETENTION_IN_DAYS variable

# Note: SOCA also supports AWS Backup  https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/backup-restore-your-cluster/

exec > "$(dirname "$(realpath "$0")")/send_logs_s3.log" 2>&1

set -a  # auto-export vars (bare /etc/environment KEY=value lines are not exported on source)
source /etc/environment
set +a
AWSCLI=$(which aws)
S3_BUCKET_REGION=$(${AWSCLI} s3api get-bucket-location --bucket ${EDH_INSTALL_BUCKET} --output text)

# Number of days logs stay in the server without being modified
# It's not recommended to keep this settings too low, as the script could delete config file for job that hasn't been processed yet
# Recommended to keep this value > 5 days
DATA_RETENTION_IN_DAYS=10

# Backup location
BACKUP_S3_PREFIX_LOCATION="s3://${EDH_INSTALL_BUCKET}/${EDH_CLUSTER_ID}/${EDH_VERSION}/cluster_logs"

# Content of these directory will be backup to S3, and file/dir may be subject to removal based on DATA_RETENTION_IN_DAYS value
# Folders that does not exist will simply be skipped. This list contains all folders irrespective of your Scheduler choices
DIRS_TO_SYNC=(
  "/opt/edh/${EDH_CLUSTER_ID}/cluster_node_bootstrap/logs/dcv_node/"
  "/opt/edh/${EDH_CLUSTER_ID}/cluster_node_bootstrap/logs/compute_node/"
  "/opt/edh/${EDH_CLUSTER_ID}/cluster_node_bootstrap/logs/login_node/"
  "/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/orchestrator/logs/"
  "/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/analytics/logs/"
  "/opt/edh/${EDH_CLUSTER_ID}/cluster_manager/web_interface/logs/"
)

# Define PBS-related folders (will be skipped if you don't use OpenPBS)
PBS_FOLDERS=(
  "/opt/edh/${EDH_CLUSTER_ID}/schedulers/default/pbs/var/spool/pbs/server_logs/"
  "/opt/edh/${EDH_CLUSTER_ID}/schedulers/default/pbs/var/spool/pbs/pbs/sched_logs/"
  "/opt/edh/${EDH_CLUSTER_ID}/schedulers/default/pbs/var/spool/pbs/spool/pbs/server_priv/accounting/"
)

# Define LSF-related folders (will be skipped if you don't use LSF)
LSF_FOLDERS=(
  "/opt/edh/${EDH_CLUSTER_ID}/schedulers/default/lsf/logs/"
)

# Define SLURM-related folders (will be skipped if you don't use Slurm)
SLURM_FOLDERS=(
  "/opt/edh/${EDH_CLUSTER_ID}/schedulers/default/slurm/etc/"
)

DIRS_TO_SYNC+=("${PBS_FOLDERS[@]}")
DIRS_TO_SYNC+=("${LSF_FOLDERS[@]}")
DIRS_TO_SYNC+=("${SLURM_FOLDERS[@]}")


for DIR in "${DIRS_TO_SYNC[@]}"
do
  if [[ -d "${DIR}" ]]; then
    # Sync directory to S3
    ${AWSCLI} s3 sync "${DIR}" "${BACKUP_S3_PREFIX_LOCATION}/${DIR}" --region ${S3_BUCKET_REGION} --quiet

    # Delete file/directory if needed
    if [[ ${DIR} =~ "/opt/edh/${EDH_CLUSTER_ID}/cluster_node_bootstrap/logs/compute_node/" ]] || [[ ${DIR} =~ "/opt/edh/${EDH_CLUSTER_ID}/cluster_node_bootstrap/logs/dcv_node/" ]]; then
      # Find all directory and delete them if older than data retention
      # These directory contains log file specific to ephemeral hosts (DCV/HPC nodes)
      find "${DIR}" -mindepth 1 -maxdepth 1 -type d -mtime +${DATA_RETENTION_IN_DAYS} -print0 | while IFS= read -r -d '' dir; do
        echo "Removing compute_node/dcv_node directory: ${dir}"
        rm -r "${dir}"
      done
    else
      # Find all files and delete them if older than data retention
      find "${DIR}" -type f -mtime +${DATA_RETENTION_IN_DAYS} -print0 | while IFS= read -r -d '' file; do
        echo "Removing file: ${file}"
        rm "$file"
      done
   fi
  else
    echo "Skipping Directory ${DIR} because it does not exist."
  fi
done