# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from commands.logs.aws_lambda import logs_lambda
from commands.logs.hpc import logs_hpc
from commands.logs.web_interface import logs_webinterface


@click.group()
def logs():
    pass


logs.add_command(logs_lambda)
logs.add_command(logs_hpc)
logs.add_command(logs_webinterface)
