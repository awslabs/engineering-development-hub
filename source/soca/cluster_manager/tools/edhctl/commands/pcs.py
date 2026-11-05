# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import click

from commands.common import print_output, is_controller_instance
from commands.schedulers import set as schedulers_set
from utils.aws.pcs_client import SocaAWSPCSClient


@click.group()
def pcs():
    """AWS PCS helpers for EDH."""
    pass


@pcs.command()
@click.option(
    "--cluster-identifier",
    type=str,
    required=True,
    help="PCS cluster name or id to register as an EDH scheduler",
)
@click.option(
    "--region",
    type=str,
    required=False,
    help="AWS region of the PCS cluster. Defaults to the controller's region.",
)
@click.option(
    "--enabled",
    type=click.Choice(["true", "false"]),
    default="true",
    help="Enable/Disable the scheduler on EDH",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    type=bool,
    help="Force create, ignore confirmation message",
)
@click.pass_context
def register(
    ctx,
    cluster_identifier,
    region,
    enabled,
    force,
):
    """
    Register an AWS PCS cluster as an EDH scheduler.

    Thin wrapper over `edhctl schedulers set` that fills in the PCS-specific defaults:
    provider is always slurm, and --manage-host-provisioning is false because AWS PCS --
    not EDH -- provisions and manages the compute capacity. The SLURMCTLD endpoint and the
    Slurm version are resolved from the PCS API (pcs:GetCluster) given --cluster-identifier.
    """
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host",
            error=True,
        )

    # Resolve the SLURMCTLD endpoint and Slurm version from the PCS API.
    try:
        _client = SocaAWSPCSClient(cluster_name=cluster_identifier, region_name=region)
    except RuntimeError as err:
        print_output(message=f"Unable to initialize the PCS client: {err}", error=True)

    _get_cluster = _client.get_cluster(
        list_queues=False, list_compute_node_groups=False
    )
    if _get_cluster.get("success") is False:
        print_output(message=_get_cluster.get("message"), error=True)

    _cluster = _get_cluster.get("message", {}).get("cluster", {})
    slurm_version = _cluster.get("scheduler", {}).get("version")

    endpoint = None
    endpoint_port = None
    for _ep in _cluster.get("endpoints", []):
        if _ep.get("type") == "SLURMCTLD":
            # IPv4 clusters expose privateIpAddress; IPv6-only clusters populate
            # ipv6Address instead.
            endpoint = _ep.get("privateIpAddress") or _ep.get("ipv6Address")
            endpoint_port = _ep.get("port")
            break

    if not endpoint:
        print_output(
            message=f"Could not resolve a SLURMCTLD endpoint for {cluster_identifier}. "
            "Verify the cluster is ACTIVE and exposes a SLURMCTLD endpoint.",
            error=True,
        )
    if not slurm_version:
        print_output(
            message=f"Could not resolve the Slurm version for {cluster_identifier}.",
            error=True,
        )

    # PCS always installs Slurm at /opt/aws/pcs/scheduler/slurm-<version>. The Slurm config and
    # socket come from this cluster's own sackd (RuntimeDirectory=slurm-<pcs_cluster_id>, see the
    # PCS Connect tab), so several PCS clusters can be registered on the same controller.
    pcs_cluster_id = _cluster.get("id")
    if not pcs_cluster_id:
        print_output(
            message=f"Could not resolve the PCS cluster id for {cluster_identifier}.",
            error=True,
        )
    install_prefix_path = f"/opt/aws/pcs/scheduler/slurm-{slurm_version}"
    sackd_runtime_path = f"/run/slurm-{pcs_cluster_id}"

    _slurm_configuration = json.dumps(
        {
            "install_prefix_path": install_prefix_path,
            "install_sysconfig_path": f"{sackd_runtime_path}/conf",
            "sack_socket_path": f"{sackd_runtime_path}/sack.socket",
            # Used by the node bootstrap (templates/linux/scheduler/aws_pcs/configure_client.sh.j2)
            # to onboard VDI / login nodes when /configuration/services/aws_pcs/auto_onboard_client
            # is true.
            "pcs_cluster_id": pcs_cluster_id,
            "slurm_version": slurm_version,
            "slurmctld_port": str(endpoint_port or 6817),
        }
    )

    ctx.invoke(
        schedulers_set,
        scheduler_identifier=cluster_identifier,
        provider="aws_pcs",
        endpoint=endpoint,
        binary_folder_paths=f"{install_prefix_path}/bin:{install_prefix_path}/sbin",
        manage_host_provisioning="false",
        lsf_configuration=None,
        pbs_configuration=None,
        slurm_configuration=_slurm_configuration,
        enabled=enabled,
        force=force,
    )
