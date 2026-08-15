#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import (
    Tags,
    Size,
    aws_batch as batch,
    aws_ecs as ecs,
)


import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# AWS Batch compute environment provisioning. Extracted verbatim from cdk_construct.py.

logger = logging.getLogger("soca_logger")


def aws_batch(
    scope,
    *,
    user_specified_variables=None,
):
    # Simple Fargate compute environment
    compute_environment = batch.FargateComputeEnvironment(
        scope,
        "FargateComputeEnv",
        compute_environment_name=f"{user_specified_variables.cluster_id}-default-fargate-environment",
        vpc=scope.soca_resources["vpc"],
        maxv_cpus=256,
        enabled=True,
        security_groups=[scope.soca_resources["compute_node_sg"]],
    )

    # Job queue
    job_queue = batch.JobQueue(
        scope,
        "EdhDefaultQueue",
        job_queue_name=f"{user_specified_variables.cluster_id}-default-queue",
    )
    job_queue.add_compute_environment(compute_environment, order=1)

    # Job definition - Hello World using amazonlinux2023
    job_definition = batch.EcsJobDefinition(
        scope,
        "HelloWorldJobDef",
        job_definition_name=f"{user_specified_variables.cluster_id}-default-hello-world",
        container=batch.EcsFargateContainerDefinition(
            scope,
            "HelloWorldContainer",
            image=ecs.ContainerImage.from_registry(
                "public.ecr.aws/amazonlinux/amazonlinux:2023"
            ),
            command=["echo", "Hello World!"],
            memory=Size.mebibytes(512),
            cpu=0.25,
        ),
    )

    # Tag all resources with edh:visibility
    for resource in [compute_environment, job_queue, job_definition]:
        Tags.of(resource).add(
            f"edh:visibility:{user_specified_variables.cluster_id}", "true"
        )
