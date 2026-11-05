# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations


from typing import Optional

from utils.datamodels.hpc.shared.job import SocaHpcJob
from pydantic import Field


class SocaHpcJobPBS(SocaHpcJob):
    # Required attributes are inherited from SocaHpcJob

    # Optional PBS job attributes, not needed for SOCA, but added here in case you want to add additional customization
    # This map the attributes from qstat -f -F json
    pbs_job_name: Optional[str] = None  # Job Name
    pbs_job_owner: Optional[str] = None  # Job Owner
    pbs_job_state: Optional[str] = None  # Job State
    pbs_error_path: Optional[str] = None  # Job Error_Path
    pbs_output_path: Optional[str] = None  # Job Output_Path
    pbs_queue: Optional[str] = None  # Job Queue
    pbs_server: Optional[str] = None  # Job Server
    pbs_checkpoint: Optional[str] = None  # Job checkpoint
    pbs_ctime: Optional[str] = None  # Job creation time
    pbs_hold_types: Optional[str] = None  # Job Hold_Types
    pbs_join_path: Optional[str] = None  # Job Join_Path
    pbs_keep_files: Optional[str] = None  # Job Keep_Files
    pbs_mail_points: Optional[str] = None  # Job Mail_Points
    pbs_mtime: Optional[str] = None  # Job modification time
    pbs_priority: Optional[int] = None  # Job Priority
    pbs_qtime: Optional[str] = None  # Job queue time
    pbs_rerunable: Optional[bool] = None  # Job Rerunable
    pbs_resource_list: Optional[dict] = Field(default_factory=dict)  # Job Resource_List
    pbs_schedselect: Optional[str] = None  # Job Schedselect
    pbs_substate: Optional[int] = None  # Job Substate
    pbs_variable_list: Optional[dict] = Field(
        default_factory=dict
    )  # Job Variable_List
    pbs_euser: Optional[str] = None  # Job euser
    pbs_egroup: Optional[str] = None  # Job egroup
    pbs_queue_rank: Optional[int] = None  # Job queue rank
    pbs_queue_type: Optional[str] = None  # Job queue type
    pbs_comment: Optional[str] = None  # Job comment
    pbs_etime: Optional[str] = None  # Job elapsed time
    pbs_submit_arguments: Optional[str] = None  # Job submit arguments
    pbs_executable: Optional[str] = None  # Job executable
    # Job depend. Carries BOTH directions: a dependent shows afterok:<parent>
    # and the parent shows beforeok:<dependent>. A satisfied edge is cleared
    # by the scheduler, so pbs_submit_arguments is the durable record of what
    # a job was submitted to wait on.
    pbs_depend: Optional[str] = None
    # Job Exit_status. Absent until the job has actually run, which is what
    # separates a job the scheduler removed for an unsatisfiable dependency
    # from one that ran and failed.
    pbs_exit_status: Optional[int] = None
    pbs_argument_list: Optional[str] = None  # Job argument list
    pbs_submit_host: Optional[str] = None  # Submission Host
    pbs_project: Optional[str] = None  # Job project

    # Job array attributes, verbatim from qstat -f -F json.
    #
    # EDH's own logic reads the normalized, scheduler-neutral fields on
    # SocaHpcJob (is_array, array_subjob_count, array_indices_remaining,
    # array_state_count) -- Slurm spells the same concepts differently, so
    # nothing in the provisioning path should branch on a pbs_ field.
    #
    # These keep the RAW strings for the customization hook this file documents,
    # including PBS's literal "-" sentinel in array_indices_remaining, which the
    # normalized field deliberately turns into None.
    pbs_array: Optional[str] = None  # "True" on an array parent
    pbs_array_id: Optional[str] = None  # parent id, present on a subjob
    pbs_array_index: Optional[int] = None  # this subjob's index
    pbs_array_state_count: Optional[str] = (
        None  # "Queued:4 Running:12 Exiting:0 Expired:0"
    )
    pbs_array_indices_submitted: Optional[str] = None  # "1-100", "0-999:10"
    pbs_array_indices_remaining: Optional[str] = None  # "13-16", or "-" when none
