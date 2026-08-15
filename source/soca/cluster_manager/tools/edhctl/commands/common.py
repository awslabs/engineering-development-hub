# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import yaml
import click
import sys
import os
from utils.config import SocaConfig
from typing import Union

logger = logging.getLogger("soca_logger")


def get_cluster_id() -> str:
    _get_cluster_id = SocaConfig(key="/configuration/ClusterId").get_value()
    if _get_cluster_id.get("success") is True:
        return _get_cluster_id.get("message")
    else:
        click.echo(f"Unable to retrieve Cluster ID because of {_get_cluster_id}")
        sys.exit(1)


def is_controller_instance() -> bool:
    if os.environ.get("EDH_NODE_TYPE", None) == "controller":
        return True
    else:
        return False


def confirm(prompt: str) -> bool:
    while True:
        _ans = input(prompt + " (yes/no): ").strip().lower()
        if _ans == "yes":
            return True
        elif _ans == "no":
            return False
        else:
            click.echo("Please answer 'yes' or 'no'.")


def print_output(
    message: Union[str, dict], output: str = "text", error: bool = False
) -> Union[str, dict]:
    try:
        if output == "json":
            click.echo(json.dumps(message, indent=4, default=str))
        elif output == "text":
            click.echo(message)
        elif output == "yaml":
            click.echo(yaml.dump(message))
        else:
            click.echo(
                "Unrecognized output format. Supported values are text, json or yaml"
            )
            sys.exit(1)

        if error:
            logger.error(message)
            sys.exit(1)
    except Exception as err:
        click.echo(f"Unable to print output because of {err}")
        logger.error(err)
        sys.exit(1)
