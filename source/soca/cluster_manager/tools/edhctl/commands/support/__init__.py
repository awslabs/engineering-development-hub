# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click

from commands.support.ack import ack
from commands.support.patch import patch
from commands.support.verify import verify


@click.group()
def support():
    """Support and diagnostic commands."""
    pass


support.add_command(verify)
support.add_command(ack)
support.add_command(patch)
