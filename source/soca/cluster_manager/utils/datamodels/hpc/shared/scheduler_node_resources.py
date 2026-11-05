# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import BaseModel, field_validator, model_validator
from enum import Enum
import logging
import re
from typing import Optional, Union, Literal
from utils.cast import coerce_scalar_fields_to_str
from utils.validators import Validators
from utils.datamodels.hpc.scheduler import SocaHpcScheduler

logger = logging.getLogger("soca_logger")


class SocaSchedulerNodeState(str, Enum):
    ACTIVE = "active"  # Node is up and actively running jobs
    IDLE = "idle"  # Node is up but not running any jobs. Node must be in this state to be subject to terminate if --terminate_when_idle is set
    DOWN = "down"  # Node is not available
    OTHER = "other"  # Reserved or unknown states


class SocaSchedulerNodeResourceModel(BaseModel):
    # Job ID associated to the node
    job_id: str

    # Scheduler info associated to the node
    scheduler_info: SocaHpcScheduler

    # Compute Node associated to the node (tbd = no capacity associated yet, otherwise use job id)
    compute_node: Union[Literal["tbd"], str, int]

    # Last time node changed state
    last_state_change_timestamp: int

    # CloudFormation Stack ID associated to the node
    stack_id: str

    # Node state
    node_state: SocaSchedulerNodeState

    # Whether the host is AlwaysOn
    keep_forever: bool

    # Time (in minutes) after a idle node is removed. 0 to disable
    terminate_when_idle: int

    # Instance ID associated to this node
    instance_id: Optional[str] = None

    # Cloudformation Stack associated to the node
    stack_id: Optional[str] = None
    # Scheduler Specific attributes will be added in the relevant class (e.g: SocaHpcNodePBS, SocaHpcNodeLSF ...)

    @model_validator(mode="before")
    @classmethod
    def coerce_scalar_str_fields(cls, data):
        """Node models are built by constructor from scheduler JSON, so unlike
        SocaHpcJob there is no _normalize() to coerce inferred scalars in."""
        if Validators.is_dict(data):
            return coerce_scalar_fields_to_str(cls, dict(data))
        return data

    @field_validator("compute_node")
    @classmethod
    def validate_compute_node(cls, v):
        if isinstance(v, str):
            # allow literal "tbd", job just being queued and no compute node specified
            if v == "tbd":
                return v

            # Allow compute node starting with "job" or "alwayson". `job<job_id>` is the legacy convention and will be superseded by just int<job_id>.
            # alwayson-<uuid> are identifier for alwayson instance
            if re.match(r"^(job|alwayson)", v):
                return v

            # LSF always returns a string, we just validate if it's a number
            if v.isdigit():
                return int(v)

            # A job array SUBJOB's capacity key, "<parent>-<index>" (see
            # utils.hpc.job_identity.capacity_key). An array PARENT collapses to
            # its bare job number and is already covered by isdigit() above, so
            # this branch only matters once capacity is provisioned per subjob.
            #
            # Kept as a string rather than coerced to an int: unlike the LSF case
            # above there is no single number to return, and the two components
            # are the identity.
            if re.match(r"^\d+-\d+$", v):
                return v

        # Allow numeric values. The SOCA NextGen Scheduler now uses the actual job ID as the compute-node reference rather than the job<job_id> format.
        if isinstance(v, int):
            return v

        raise ValueError(
            "compute_node must be 'tbd', start with 'job', start with 'alwayson', "
            "be numeric, or be a job array subjob key (<parent>-<index>)"
        )
