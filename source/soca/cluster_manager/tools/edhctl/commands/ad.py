# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations
import click
import sys
from commands.common import print_output, is_controller_instance
from utils.config import SocaConfig
from utils.subprocess_client import SocaSubprocessClient
import json
import grp
import pwd
import os
import datetime


_group_cache = {}  # global cache: group_name -> gid


def get_user_groups(user: str, logger: "logging.Logger") -> list:
    """Get all valid groups a user belongs to."""

    global _group_cache
    logger.info(f"Resolving groups for {user}")
    try:
        _user_info = pwd.getpwnam(user)
    except KeyError:
        logger.warning(f"Skipping {user}: user cannot be resolved")
        return []

    _gids = os.getgrouplist(user, _user_info.pw_gid)

    groups = []

    for gid in _gids:
        try:
            name = grp.getgrgid(gid).gr_name
        except KeyError:
            # group cannot be resolved (deleted AD group)
            logger.warning(f"Skipping {user}: group {gid} cannot be resolved")
            continue

        if name not in _group_cache:
            _group_cache[name] = str(gid)

        groups.append({"name": name, "gid": _group_cache[name]})

    logger.info(f"Found {groups=} for {user=}")
    return groups


@click.group()
def ad():
    """Active Directory integration commands."""
    pass


@ad.command()
@click.pass_context
def export(ctx):
    """
    Export json with a list of all AD users
    """
    logger = ctx.obj["logger"]
    if is_controller_instance():
        _get_provider = SocaConfig(
            key="/configuration/UserDirectory/provider"
        ).get_value()
        _get_cluster_id = SocaConfig(key="/configuration/ClusterId").get_value()
        if _get_provider.get("success") is False:
            print_output(
                f"Unable to retrieve User Directory Provider because of {_get_provider}",
                error=True,
            )

        if _get_cluster_id.get("success") is False:
            print_output(
                f"Unable to retrieve Cluster ID because of {_get_cluster_id}",
                error=True,
            )

        logger.info(f"{_get_cluster_id=}, {_get_provider=}")

        if _get_provider.get("message") in [
            "aws_ds_managed_activedirectory",
            "existing_active_directory",
        ]:
            # do not modify these variables, they are used by template/linux/user_directory/sync_ad_users_locally.sh
            _home_location = "/data/home"
            _json_output_file = f"/apps/edh/{_get_cluster_id.get('message')}/shared/active_directory/sync/users_info.json"

            logger.info(f"User export will be exported to {_json_output_file}")
            os.makedirs(os.path.dirname(_json_output_file), exist_ok=True)

            logger.info(
                f"Finding all users based on $HOME location of {_home_location=} "
            )
            try:
                _users = [
                    d
                    for d in os.listdir(_home_location)
                    if os.path.isdir(os.path.join(_home_location, d))
                ]
            except FileNotFoundError:
                sys.exit(f"Directory {_home_location} not found.")

            logger.info(f"Found {len(_users)} users")
            user_data = []

            for user in _users:
                logger.info(f"Fetching user info for {user}")
                _output = SocaSubprocessClient(
                    run_command=f"getent passwd {user}"
                ).run()
                if _output.get("success") is True:
                    parts = _output.get("message").get("stdout").split(":")
                    _user_info = {
                        "username": parts[0].strip(),
                        "uid": parts[2].strip(),
                        "gid": parts[3].strip(),
                        "comment": parts[4].strip(),
                        "home": parts[5].strip(),
                        "shell": parts[6].strip(),
                    }
                    logger.info(f"{user=} info: {_user_info}")
                else:
                    logger.warning(
                        f"Skipping {user}: not found via getent, skipping ... "
                    )
                    continue

                logger.info(f"Fetching group info for {user}")
                groups = get_user_groups(user=user, logger=logger)
                _user_info["groups"] = groups
                user_data.append(_user_info)

            logger.info(f"Exporting results to {_json_output_file}")
            try:
                with open(_json_output_file, "w") as jsonfile:
                    json.dump(
                        {
                            "last_sync": datetime.datetime.now(
                                datetime.timezone.utc
                            ).isoformat(),
                            "users": user_data,
                        },
                        jsonfile,
                        indent=2,
                    )
                    print_output(f"Successfully exported {_json_output_file}")
            except Exception as err:
                sys.exit(f"Unable to export {_json_output_file} because of {err}")

        else:
            print_output(
                "This command is only supported for Active Directory", error=True
            )

    else:
        print_output("This command can only be executed from the SOCA controller host")
