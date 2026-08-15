# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from commands.config import config
from commands.cache import cache
from commands.filesystems import filesystems
from commands.ad import ad
from commands.schedulers import schedulers
from commands.nodes import nodes
from commands.login_nodes import login_nodes
from commands.userprefs import userprefs
from commands.hardware_profiles import hardware_profile, usb_profile
from commands.logs import logs

from utils.logger import SocaLogger
import os

@click.group()
@click.pass_context
def cli(ctx):
    # Log file is located in the user's home directory
    _log_file_location = f"{os.path.expanduser('~')}/.soca/edhctl.log"
    logger = SocaLogger().rotating_file_handler(file_path=_log_file_location)
    ctx.obj = {'logger': logger}


cli.add_command(config)
cli.add_command(cache)
cli.add_command(filesystems)
cli.add_command(ad)
cli.add_command(schedulers)
cli.add_command(nodes)
cli.add_command(login_nodes)
cli.add_command(userprefs)
cli.add_command(hardware_profile)
cli.add_command(usb_profile)
cli.add_command(logs)

if __name__ == "__main__":
    cli(obj={})