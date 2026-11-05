# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from commands.db.status import status
from commands.db.connections import connections
from commands.db.capacity import capacity
from commands.db.tables import table_sizes, bloat
from commands.db.locks import locks
from commands.db.schema import schema
from commands.db.snapshot import snapshot
from commands.db.vacuum import vacuum
from commands.db.pitr import pitr
from commands.db.migrate import db_export, db_import


@click.group()
def db():
    """Aurora database management commands."""
    pass


db.add_command(status)
db.add_command(connections)
db.add_command(capacity)
db.add_command(table_sizes)
db.add_command(bloat)
db.add_command(locks)
db.add_command(schema)
db.add_command(snapshot)
db.add_command(vacuum)
db.add_command(pitr)
db.add_command(db_export)
db.add_command(db_import)
