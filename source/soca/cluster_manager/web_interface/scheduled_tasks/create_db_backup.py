######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################


import logging
import os
import sqlite3
import datetime
from utils.config import SocaConfig

logger = logging.getLogger("scheduled_tasks_db_backup")


# Note: This script frequency is managed via app.py
def backup_db(
    socaweb_folder: str = f"/opt/edh/{SocaConfig(key='/configuration/ClusterId').get_value().get('message')}/cluster_manager/web_interface",
    backup_retention_days: int = 10,
):
    _backup_dir = f"{socaweb_folder}/db_backups"
    if not os.path.exists(_backup_dir):
        os.makedirs(_backup_dir, mode=0o750)

    _timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    _backup_file = os.path.join(_backup_dir, f"backup_{_timestamp}.sqlite")

    # Aurora PG mode: no local db.sqlite file. Aurora handles backups natively
    _source_sqlite = f"{socaweb_folder}/db.sqlite"
    if not os.path.exists(_source_sqlite):
        logger.info(
            "Local db.sqlite not present (Aurora PG mode); skipping SQLite backup."
        )
        return

    # Create a backup, main DB is db.sqlite
    conn = sqlite3.connect(_source_sqlite)
    backup_conn = sqlite3.connect(_backup_file)
    with backup_conn:
        conn.backup(backup_conn)
    conn.close()
    backup_conn.close()

    logger.info(f"DB Backup created: {_backup_file}")

    # Rotate backups
    now = datetime.datetime.now()
    _cutoff_date = now - datetime.timedelta(days=backup_retention_days)

    for filename in os.listdir(_backup_dir):
        file_path = os.path.join(_backup_dir, filename)

        if os.path.isfile(file_path):  # Ensure it's a file
            file_creation_time = datetime.datetime.fromtimestamp(
                os.path.getctime(file_path)
            )  # Get file creation time

            if file_creation_time < _cutoff_date:  # Check if it's older than 10 days
                os.remove(file_path)
                logger.info(f"Deleted old backup: {file_path}")
