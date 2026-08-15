# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from commands.common import (
    print_output,
    is_controller_instance,
    confirm,
)

from utils.datamodels.constants import SocaLinuxBaseOS
from utils.jinjanizer import SocaJinja2Generator
from utils.config import SocaConfig
from utils.datamodels.constants import SocaLinuxBaseOS


@click.group()
def login_nodes():
    pass


@login_nodes.command()
@click.option(
    "--base-os",
    default="text",
    type=click.Choice(SocaLinuxBaseOS),
    required=True,
    help="The base OS to use for the login nodes.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    type=bool,
    help="Force delete, ignore confirmation message",
)
def rebuild_bootstrap(base_os, force):

    if not is_controller_instance():
        print_output(
            "This command can only be run on a controller instance. Please connect to a controller instance and try again.",
            error=True,
        )

    if force is False:
        if (
            confirm(
                prompt=f"Do you want to Rebuilding bootstrap script for login nodes ... ?"
            )
            is False
        ):
            print_output(message="Exiting", error=True)

    _soca_parameters = SocaConfig(key="/").get_value(return_as=dict).get("message")

    if not _soca_parameters:
        print_output("Unable to query SSM for this SOCA environment", error=True)

    _cluster_id = _soca_parameters.get("/configuration/ClusterId")
    _bootstrap_s3_location_folder = (
        f"{_cluster_id}/config/do_not_delete/bootstrap/login_node"
    )

    _templates_to_render = [
        "templates/linux/system_packages/install_required_packages.sh",
        "templates/linux/filesystems_automount.sh",
        "compute_node/02_setup.sh",
        "compute_node/03_setup_post_reboot.sh",
    ]

    # add additional parameters specific to login nodes
    _soca_parameters["/job/NodeType"] = "login_node"
    _soca_parameters["/job/BaseOS"] = base_os
    _soca_parameters["/job/BootstrapPath"] = (
        f"/apps/edh/{_cluster_id}/shared/logs/bootstrap/login_node"
    )

    for _t in _templates_to_render:
        # Render Template
        _render_bootstrap_setup_template = SocaJinja2Generator(
            get_template=f"{_t}.j2",
            template_dirs=[f"/opt/edh/{_cluster_id}/cluster_node_bootstrap/"],
            variables=_soca_parameters,
        ).to_s3(
            bucket_name=_soca_parameters.get("/configuration/S3Bucket"),
            key=f"{_bootstrap_s3_location_folder}/{_t.split('/')[-1]}",
            autocast_values=True,
        )

        if _render_bootstrap_setup_template.get("success") is False:
            print_output(
                f"Unable to generate {_t}.j2 Jinja2 template because of {_render_bootstrap_setup_template.get('message')}",
                error=True,
            )
        else:
            print_output(
                f"[+]{_t}.j2 Jinja2 template has been successfully rendered and uploaded to S3 at the following location: s3://{_soca_parameters.get('/configuration/S3Bucket')}/{_bootstrap_s3_location_folder}/{_t.split('/')[-1]}"
            )

    print_output(
        message="----------------\nBootstrap scripts for login nodes has been successfully rebuilt and uploaded to S3. New Login Nodes will now use the updated bootstrap script. Please note that existing Login Nodes will not be affected and will continue to use the previously rendered bootstrap script until they are terminated and replaced by new Login Nodes."
    )
