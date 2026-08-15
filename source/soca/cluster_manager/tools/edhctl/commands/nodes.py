# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
import uuid
import datetime
import ast
from commands.common import (
    print_output,
    is_controller_instance,
    get_cluster_id,
    confirm,
)
from utils.aws.ec2_helper import describe_instances_paginate, describe_instance_types
from utils.datamodels.hpc.shared.job import SocaHpcJob
from utils.datamodels.hpc.scheduler import SocaHpcScheduler
from utils.aws.cloudformation_client import SocaCfnClient
from utils.datamodels.constants import SocaLinuxBaseOS
from utils.aws.ec2_helper import describe_images
from utils.aws.odcr_helper import get_reservation_info_soca_capacity_reservation
from utils.datamodels.hpc.shared.job_resources import SocaHpcJobState
from commands.config import get as config_get


@click.group()
def nodes():
    pass


@nodes.command()
@click.option(
    "--scheduler-identifier",
    help="Find all nodes configured for a specific scheduler identifier. (default to all schedulers configured on your environment)",
)
@click.option(
    "--stack-id",
    help="Find all nodes configured for a static ID",
)
@click.option(
    "--node-lifecycles",
    type=click.Choice(["ondemand", "alwayson"]),
    multiple=True,
    default=["ondemand", "alwayson"],
    help="Choose to display ondemand and/or alwayson nodes. Show all nodes if not set.",
)
@click.option(
    "--node-types",
    type=click.Choice(
        [
            "controller",
            "login_node",
            "compute_node",
            "target_node",
            "dcv_node",
        ]
    ),
    default=[
        "controller",
        "login_node",
        "compute_node",
        "target_node",
        "dcv_node",
    ],
    multiple=True,
    help="Choose to display controller, alwayson, login_node, compute_node and/or dcv_node nodes. Show all nodes if not set.",
)
def list(
    scheduler_identifier,
    stack_id,
    node_lifecycles,
    node_types,
):

    _filters = [
        {"Name": "instance-state-name", "Values": ["pending", "running"]},
        {
            "Name": "tag:edh:ClusterId",
            "Values": [get_cluster_id()],
        },
    ]

    if scheduler_identifier:
        _filters.append(
            {"Name": "tag:edh:SchedulerIdentifier", "Values": [scheduler_identifier]}
        )

    if stack_id:
        _filters.append({"Name": "tag:edh:StackId", "Values": [stack_id]})

    if "ondemand" in node_lifecycles:
        _filters.append(
            {"Name": "tag:edh:KeepForever", "Values": ["false", "False", "FALSE"]},
        )

    if "alwayson" in node_lifecycles:
        _filters.append(
            {
                "Name": "tag:edh:KeepForever",
                "Values": ["true", "True", "TRUE"],
            },
        )

    _nodes_type = []

    for _node_type in node_types:
        _nodes_type.append(_node_type)

    if _nodes_type:
        _filters.append(
            {
                "Name": "tag:edh:NodeType",
                "Values": _nodes_type,
            },
        )

    _fetch_instances = describe_instances_paginate(filters=_filters)
    if _fetch_instances.get("success") is False:
        print_output(message=_fetch_instances.get("message"), error=True)
    else:
        print_output(message=_fetch_instances.get("message"), output="json")


@nodes.command()
@click.option(
    "--scheduler-identifier",
    required=True,
    help="Create a new always on for a specific",
)
@click.option(
    "--job-owner",
    required=True,
    help="Job owner for the new always on node(s)",
)
@click.option("--job-queue", required=True, type=str, help="Job Queue")
@click.option(
    "--instance-type", required=True, type=str, help="Instance Type to provision"
)
@click.option(
    "--nodes", type=int, help="Number of nodes to create", required=True, default=1
)
@click.option(
    "--instance-ami", type=str, required=True, help="EC2 Image ID for the node(s)"
)
@click.option(
    "--base-os",
    type=click.Choice(SocaLinuxBaseOS),
    required=True,
    help="Operating system to use",
)
@click.option(
    "--root-size",
    type=int,
    default=None,
    help="Size of the root partition. Will use the default one configured for your AMI if not set",
)
@click.option(
    "--instance-profile",
    type=str,
    default=None,
    help="IAM Instance Profile for the node(s)",
)
@click.option(
    "--security-groups",
    type=str,
    default=None,
    help="List of Security group ID(s) to assign. Separated by , or +",
)
@click.option(
    "--subnet-ids",
    type=str,
    default=None,
    help="List of Subnet ID(s) to deploy capacity on. Separated by , or +",
)
@click.option(
    "--capacity-reservation-id",
    type=str,
    default=None,
    help="Capacity Reservation ID to use",
)
@click.option(
    "--anonymous-metrics",
    type=bool,
    default=True,
    help="Enable or disable anonymous data tracking",
)
@click.option(
    "--fsx-lustre",
    default=None,
    help="FSx for Lustre association: True for new FSxL or provide fs-id",
)
@click.option(
    "--fsx-lustre-size", type=int, default=None, help="FSx for Lustre size if used"
)
@click.option(
    "--fsx-lustre-deployment-type",
    type=str,
    default=None,
    help="FSx for Lustre deployment type",
)
@click.option(
    "--fsx-lustre-per-unit-throughput",
    type=int,
    default=None,
    help="FSxL throughput per unit",
)
@click.option(
    "--fsx-lustre-storage-type", type=str, default=None, help="FSxL storage type"
)
@click.option(
    "--scratch-iops",
    type=int,
    default=None,
    help="Use io2 for scratch instead of gp3 (IOPS)",
)
@click.option(
    "--scratch-size", type=int, default=None, help="Custom /scratch size in GiB"
)
@click.option("--spot-price", default=None, help="Spot price (float, int, or 'auto')")
@click.option(
    "--spot-allocation-count", type=int, default=None, help="Spot allocation count"
)
@click.option(
    "--spot-allocation-strategy",
    type=click.Choice(["capacity-optimized", "lowest-price", "diversified"]),
    default=None,
    help="Spot allocation strategy",
)
@click.option(
    "--keep-ebs",
    type=bool,
    default=False,
    help="Preserve EBS after capacity deletion",
)
@click.option(
    "--placement-group",
    type=bool,
    default=False,
    help="Enable placement group for the node(s)",
)
@click.option(
    "--efa-support",
    type=bool,
    default=False,
    help="Enable Elastic Fabric Adapter (EFA)",
)
@click.option(
    "--force-ri", type=bool, default=False, help="Require Reserved Instance only"
)
@click.option(
    "--ht-support",
    type=bool,
    default=False,
    help="Enable or disable Hyper-Threading",
)
@click.pass_context
def create_alwayson(
    ctx,
    scheduler_identifier,
    job_owner,
    job_queue,
    instance_type,
    nodes,
    instance_ami,
    base_os,
    root_size,
    instance_profile,
    security_groups,
    subnet_ids,
    capacity_reservation_id,
    anonymous_metrics,
    fsx_lustre,
    fsx_lustre_size,
    fsx_lustre_deployment_type,
    fsx_lustre_per_unit_throughput,
    fsx_lustre_storage_type,
    scratch_iops,
    scratch_size,
    spot_price,
    spot_allocation_count,
    spot_allocation_strategy,
    keep_ebs,
    placement_group,
    efa_support,
    force_ri,
    ht_support,
):
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host",
            error=True,
        )

    if len(instance_type.split("+")) > 1:
        print_output(
            message="You must only specify a single instance type when using create-always-on",
            error=True,
        )

    # getting Scheduler informations
    ctx.meta["echo"] = False  # do not print response and return as result instead
    _get_scheduler_info = ctx.invoke(
        config_get, key=f"/configuration/HPC/schedulers/{scheduler_identifier}"
    )
    try:
        _scheduler_info = SocaHpcScheduler(**ast.literal_eval(_get_scheduler_info))
    except Exception as err:
        print_output(
            message=f"Unable to get scheduler information for {scheduler_identifier} due to {err}. Verify scheduler identifier name.",
            error=True,
        )

    if not isinstance(_scheduler_info, SocaHpcScheduler):
        print_output(
            message=f"{scheduler_identifier} does not seems to be a valid SocaHpcScheduler. Found {_get_scheduler_info}.",
            error=True,
        )

    _alwayson_uuid = f"alwayson-{uuid.uuid4()}"
    _cluster_id = get_cluster_id()

    # Note: we validate the required parameters for SocaHpcJob.
    # We do not need to use SocaHpcSlurmJob / SocaHpcLSFJob / SocaHpcPBSJob as we just want to validate the overall configuration in order to provision the capacity
    _job = SocaHpcJob.model_construct()
    _job.job_id = _alwayson_uuid
    _job.job_name = _alwayson_uuid
    _job.job_owner = job_owner
    _job.job_queue = job_queue
    _job.instance_types = [instance_type]
    _job.job_queue_time = int(datetime.datetime.now().timestamp())
    _job.job_compute_node = "tbd"
    _job.nodes = nodes
    _job.base_os = base_os
    _job.job_state = SocaHpcJobState.QUEUED  # alwayson always QUEUED; enum avoids serialization warning
    _job.job_scheduler_info = _scheduler_info
    _job.job_scheduler_state = "alwayson"
    _job.instance_ami = instance_ami
    _job.instance_profile = instance_profile
    _job.security_groups = (
        [
            s
            for part in security_groups.split(",")
            for s in part.split("+")
            if s  # ignore empty strings
        ]
        if security_groups is not None
        else None
    )
    _job.subnet_ids = (
        [
            s
            for part in subnet_ids.split(",")
            for s in part.split("+")
            if s  # ignore empty strings
        ]
        if subnet_ids is not None
        else None
    )
    _job.capacity_reservation_id = (
        get_reservation_info_soca_capacity_reservation(
            capacity_reservation_id=capacity_reservation_id
        )
        if capacity_reservation_id is not None
        else None
    )
    _job.anonymous_metrics = anonymous_metrics
    _job.fsx_lustre = fsx_lustre
    _job.fsx_lustre_size = fsx_lustre_size
    _job.fsx_lustre_deployment_type = fsx_lustre_deployment_type
    _job.fsx_lustre_per_unit_throughput = fsx_lustre_per_unit_throughput
    _job.fsx_lustre_storage_type = fsx_lustre_storage_type
    _job.scratch_iops = scratch_iops
    _job.scratch_size = scratch_size
    _job.spot_price = spot_price
    _job.spot_allocation_count = spot_allocation_count
    _job.spot_allocation_strategy = spot_allocation_strategy
    _job.keep_ebs = keep_ebs
    _job.placement_group = placement_group
    _job.efa_support = efa_support
    _job.force_ri = force_ri
    _job.ht_support = ht_support

    _get_image = describe_images(image_ids=[instance_ami])
    if _get_image.get("success") is True:
        _image_details = _get_image.get("message")
        _ami_root_size = _image_details["Images"][0].get("BlockDeviceMappings")[0][
            "Ebs"
        ]["VolumeSize"]
    else:
        print_output(
            message=f"Unable to get image details for {instance_ami} due to {_get_image.get('message')}",
            error=True,
        )
    _job.cpus = None
    _get_instance_type = describe_instance_types(instance_types=[instance_type])
    if _get_instance_type.get("success") is True:
        _describe_instance_types = _get_instance_type.get("message")
        for instance_info in _describe_instance_types.get("InstanceTypes"):
            if _job.ht_support is True:
                _job.cpus = instance_info["VCpuInfo"]["DefaultVCpus"]
            else:
                _job.cpus = instance_info["VCpuInfo"]["DefaultCores"]
    else:
        print_output(
            message=f"Unable to get instance type details for {instance_type} due to {_get_instance_type.get('message')}",
            error=True,
        )

    if _job.cpus is None:
        print_output(
            message=f"Unable to calculate cpus for {instance_type}",
            error=True,
        )

    if root_size:
        if root_size < _ami_root_size:
            print_output(
                message=f"Root size ({root_size} GiB) must be greater than {_ami_root_size} GiB",
                error=True,
            )
        else:
            _job.root_size = root_size
    else:
        # root_size not specified, default to the one configured for the AMI
        _job.root_size = _ami_root_size

    # Validating AlwaysOn configuration
    try:
        _job._normalize()
    except Exception as err:
        print_output(
            message=f"Unable to validate job configuration. Received error {err}",
            error=True,
        )

    # Provision Nodes
    _launch_capacity = _job.provision_capacity(
        cluster_id=_cluster_id,
        stack_name=f"{_cluster_id}-{_alwayson_uuid}-{_scheduler_info.identifier}",
        keep_forever=True,
        terminate_when_idle=0,
    )

    if _launch_capacity.get("success") is False:
        print_output(
            message=f"Unable to provision capacity due to {_launch_capacity.get('message')}",
            error=True,
        )
    else:
        print_output(
            message=f"Capacity tagged {_alwayson_uuid} has been created. This capacity will run 24/7 until you delete the associated Cloudformation stack."
        )


@nodes.command()
@click.option(
    "--alwayson-identifier",
    required=True,
    help="Specify an alwayson identifier",
    type=str,
)
def list_alwayson(alwayson_identifier):
    filters = [
        {"Name": "instance-state-name", "Values": ["pending", "running"]},
        {"Name": "tag:edh:ClusterId", "Values": [get_cluster_id()]},
        {"Name": "tag:edh:KeepForever", "Values": ["True", "true", "TRUE"]},
        {"Name": "tag:edh:JobName", "Values": [alwayson_identifier]},
    ]

    result = describe_instances_paginate(filters=filters)
    if result.get("success") is False:
        print_output(result.get("message"), error=True)

    # Group instances by AlwaysOn ID
    grouped_instances = {}
    for instance in result.get("message", []):
        _job_id = next(
            (
                tag["Value"]
                for tag in instance.get("Tags", [])
                if tag["Key"] == "edh:JobId"
            ),
            None,
        )

        _stack_identifier = next(
            (tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"),
            None,
        )

        if _stack_identifier and instance.get("PrivateDnsName"):
            grouped_instances.setdefault(_stack_identifier, []).append(
                f"{instance['PrivateDnsName']} (InstanceID: {instance['InstanceId']}) (Stack Identifier: {_stack_identifier}) (AlwaysOn Identifier {_job_id})"
            )

    print_output(grouped_instances, output="json")


@nodes.command()
@click.option(
    "--alwayson-stack-identifier",
    required=True,
    help="Delete all nodes associated to a specific Cloudformation Stack Identifier",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    type=bool,
    help="Force delete, ignore confirmation message",
)
def delete_alwayson(alwayson_stack_identifier, force):

    if force is False:
        if (
            confirm(
                prompt=f"Do you want to delete AlwaysOn capacity {alwayson_stack_identifier} (add --force to skip this confirmation) ?"
            )
            is False
        ):
            print_output(message="Exiting", error=True)

    _cluster_id = get_cluster_id()
    if alwayson_stack_identifier.startswith(_cluster_id) is False:
        alwayson_stack_identifier = f"{_cluster_id}-{alwayson_stack_identifier}"

    _delete_stack = SocaCfnClient(stack_name=alwayson_stack_identifier).delete_stack(
        ignore_missing_stack=True
    )
    if _delete_stack.get("success") is True:
        print_output(
            message=f"{alwayson_stack_identifier} cloudformation stack will be deleted if it exist. Capacity will be removed shortly"
        )
    else:
        print_output(message=_delete_stack.get("message"), error=True)
