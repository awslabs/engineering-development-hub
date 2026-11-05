# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
import sys
from commands.common import print_output, is_controller_instance
from commands.cache import set as cache_set
from utils.config import SocaConfig


@click.group()
def config():
    """Read, change and roll back cluster configuration keys."""
    pass


@config.command()
@click.option(
    "-f",
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def snapshot(output):
    """
    Output entire configuration.

    Recommended to run this command on a regular basis to back up your entire SOCA configuration tree
    """
    _ctx = click.get_current_context()
    _ctx.invoke(get, key="/", output=output)


@config.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify a SOCA configuration key or configuration tree",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
@click.pass_context
def get(ctx, key, output):
    """
    Print a given SOCA configuration key.

    Single Key: config get --key /configuration/ClusterId

    Tree Hierarchy: config get --key /configuration/
    """
    _echo = ctx.meta.get("echo", True)
    _get_key = SocaConfig(key=key).get_value().get("message")
    if _echo:
        print_output(message=_get_key, output=output)
    else:
        return _get_key


@config.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify a SOCA configuration key or configuration tree",
)
@click.pass_context
def key_exists(ctx, key):
    """
    Return True if a specified key exist
    """
    return SocaConfig(key=key).get_value().get("success")

@config.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify at least one key. Support multiple --key as needed",
)
@click.option(
    "-v",
    "--value",
    required=True,
    help="New Value",
)
@click.pass_context
def set(ctx, key, value, called_from=False):
    """
    Update a SOCA configuration key.

    config set --key /configuration/ClusterId --value "MyValue"
    """
    if is_controller_instance():
        if "/configuration/FileSystems/" in key and called_from != "filesystems":
            print_output(
                f"/configuration/FileSystems/ tree can only be managed via 'edhctl filesystems'.",
                error=True,
            )
        
        if "/configuration/HPC/schedulers/" in key and called_from != "schedulers":
            print_output(
                "/configuration/HPC/schedulers/ tree can only be managed via 'edhctl schedulers'.",
                error=True,
            )
        _update = SocaConfig(key=key).set_value(value=value)

        if _update.success:
            ctx.meta["echo"] = False
            ctx.invoke(cache_set, key=key, value=value, called_from="config")
            print_output(f"Success: Key has been updated successfully")
        else:
            print_output(f"{_update.message}", error=True)
    else:
        print_output(f"This command can only be executed from the SOCA controller host")


@config.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify at least one key.",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
@click.pass_context
def history(ctx, key, output):
    """
    Show version history for a SOCA configuration key

    config history --key /configuration/ClusterId
    """
    _echo = ctx.meta.get("echo", True)
    _get_history = SocaConfig(key=key).get_value_history(sort="desc")
    if _get_history.success:
        if _echo:
            print_output(message=_get_history.get("message"), output=output)
        else:
            return _get_history
    else:
        print_output(
            message=f"Unable to get history for {key} because of {_get_history}"
        )


@config.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify at least one key. Support multiple --key as needed",
)
@click.option(
    "-v",
    "--version",
    help="Rollback to a specific version. If not specified, value will be restored to N-1 version",
    type=int,
)
@click.option("--force", is_flag=True, help="Overwrite the parameter if it exists.")
@click.pass_context
def rollback(ctx, key, version, force):
    """
    Rollback a SOCA configuration key to a previous value

    Rollback to Version -1: config rollback --key /configuration/ClusterId
    Rollback to specific version: config rollback  --key /configuration/ClusterId --version <version>
    """
    if is_controller_instance():
        ctx.meta["echo"] = False
        _get_history = ctx.invoke(history, key=key)
        if _get_history.get("success"):
            _history = _get_history.get("message")
            _history_count = len(_history)

            if not version:
                click.echo("No --version specified, Rollback to the previous version")
                if _history_count == 1:
                    print_output("Error: There is no history for this key.", error=True)
                else:
                    _rollback_to = _history[_history_count - 1]

            else:
                if version in _history.keys():
                    _rollback_to = _history[version]
                else:
                    print_output(
                        f"Version specified {version} is not found. Detected Versions: {_history.keys()}",
                        error=True,
                    )

            if not force:
                if click.prompt(
                    f"RollBack to: {_rollback_to} Confirm (use --force to skip)?",
                    type=click.Choice(["Yes", "No"], case_sensitive=False),
                ):
                    pass
                else:
                    sys.exit(0)
            ctx.meta["echo"] = True
            ctx.invoke(set, key=key, value=_rollback_to["Value"])
        else:
            print_output(
                f"Unable to get history for this key {_get_history}", error=True
            )
    else:
        print_output(f"This command can only be executed from the SOCA controller host")
