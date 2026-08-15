# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import config
import json
import base64
import pathlib
import re
import math
from views.file_explorer import decrypt
from flask import render_template, request, redirect, session, flash, Blueprint
from flask_babel import gettext as _
from decorators import login_required, feature_flag

from utils.aws.ec2_helper import describe_instance_types
from utils.datamodels.hpc.scheduler import get_schedulers
from utils.jinjanizer import SocaJinja2Renderer
from utils.http_client import SocaHttpClient
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider
from utils.hpc.scheduler_command_builder import SocaHpcPBSJobCommandBuilder

logger = logging.getLogger("soca_logger")
submit_job = Blueprint("submit_job", __name__, template_folder="templates")

# Options delimiter character for Checkbox group values
# should be a single char - such as a comma (,) (default) , or pipe (|) depending on site policy
MULTI_SELECT_DELIMITER = ","


@submit_job.route("/submit_job", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def index():
    _input_file = request.args.get("input_file", "")
    _user = session.get("user", "")
    logger.info(f"Received submit_job GET request with {_input_file=}")
    if not _input_file:
        flash(
            _(
                "What input file do you want to use? Navigate to the folder where your input file is located then click 'Use as Simulation Input'"
            ),
            "info",
        )
        return redirect("/file_explorer")

    _get_authorized_application_profiles = SocaHttpClient(
        endpoint=f"/api/user/resources_permissions",
        headers={
            "X-EDH-USER": _user,
            "X-EDH-TOKEN": session.get("api_key", ""),
        },
    ).get(params={"application_profiles": "all"})

    if _get_authorized_application_profiles.get("success") is False:
        logger.error(
            f"Unable to list application_profiles for {_user} because of {_get_authorized_application_profiles.get('message')}"
        )
        flash(
            _("Unable to list applications. See logs for additional details"),
            "error",
        )
        _application_profiles = {}
    else:
        _application_profiles = _get_authorized_application_profiles.get("message").get(
            "application_profiles"
        )

    logger.debug(
        f"List of available application profiles for {_user}: {_application_profiles}"
    )
    return render_template(
        "submit_job.html",
        application_profiles=_application_profiles,
        input_file=False if _input_file is None else _input_file,
    )


@submit_job.route("/submit_job", methods=["POST"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def job_submission():
    _app = request.form.get("app", "")
    _input_file = request.form.get("input_file", "")
    _user = session.get("user", "")
    logger.info(f"Received submit_job POST request with {_app=} / {_input_file=}")

    if not _app or not _input_file:
        flash(_("Missing required parameters (app and input_file)."), "error")
        return redirect("/submit_job")

    _get_authorized_application_profiles = SocaHttpClient(
        endpoint=f"/api/user/resources_permissions",
        headers={
            "X-EDH-USER": session["user"],
            "X-EDH-TOKEN": session["api_key"],
        },
    ).get(params={"application_profiles": f"{_app}"})

    if _get_authorized_application_profiles.get("success") is False:
        logger.error(
            f"Unable to list application profile {_app} for {_user} because of {_get_authorized_application_profiles.get('message')}"
        )
        flash(
            _(
                f"Unable to list application profile {_app}. See logs for additional details."
            ),
            "error",
        )
        return redirect("/submit_job")

    _get_application_profile = _get_authorized_application_profiles.get("message").get(
        "application_profiles", []
    )

    _file_info = decrypt(_input_file)
    if _file_info.get("success") is False:
        logger.error(f"Unable to decrypt file {_input_file} due to {_file_info}")
        flash(
            _(
                "Unable to use this file as an input (maybe the file was removed or you do not have permission to access it."
            ),
            "error",
        )
        return redirect("/submit_job")
    else:
        try:
            _input_file_path = pathlib.Path(
                json.loads(_file_info.get("message")).get("file_path", "")
            )
            _input_path = str(_input_file_path).rstrip().lstrip()
            if _input_file_path.exists():
                _input_name = _input_file_path.name
                _input_file_parent = _input_file_path.parent
            else:
                logger.error(
                    f"Unable to find input file {_input_file_path} in {_file_info}. File does not exist"
                )
                return redirect("/submit_job")

        except Exception as err:
            logger.error(f"Unable to read input  {_file_info} file path due to {err}")
            flash(
                _(
                    "Unable to extract input file information. See logs for additional details"
                ),
                "error",
            )
            return redirect("/submit_job")

    if _get_application_profile:
        try:
            _profile_form = base64.b64decode(
                _get_application_profile[0].get("profile_form")
            ).decode()
        except Exception as err:
            logger.error(
                f"Unable to read application profile profile_form due to {err}"
            )
            flash(
                _(
                    "Unable to extract profile information. See logs for additional details"
                ),
                "error",
            )
            return redirect("/submit_job")

        _profile_interpreter = _get_application_profile[0].get(
            "profile_interpreter", None
        )
        if not _profile_interpreter:
            logger.error(
                f"Unable to read application profile profile_interpreter due to {err}"
            )
            flash(
                _(
                    "Unable to extract profile information. See logs for additional details"
                ),
                "error",
            )
            return redirect("/submit_job")

        _profile_job = _get_application_profile[0].get("profile_job", None)
        if not _profile_job:
            logger.error(f"Unable to read application profile profile_job due to {err}")
            flash(
                _(
                    "Unable to extract profile information. See logs for additional details"
                ),
                "error",
            )

        _profile_name = _get_application_profile[0].get("profile_name", None)
        if not _profile_name:
            logger.error(
                f"Unable to read application profile profile_name due to {err}"
            )
            flash(
                _(
                    "Unable to extract profile information. See logs for additional details"
                ),
                "error",
            )

        logger.debug(
            f"About to proceed to job submission using {_app}: {_profile_form=} {_profile_job=} {_profile_name=} {_profile_interpreter=}"
        )
        return render_template(
            "submit_job_selected_application.html",
            profile_name=_profile_name,
            user=_user,
            profile_form=_profile_form,
            profile_job=_profile_job,
            page="submit_job",
            profile_interpreter=_profile_interpreter,
            all_schedulers_identifiers=[
                scheduler.identifier for scheduler in get_schedulers()
            ],
            input_path=_input_path,
            input_file_path=_input_file_parent,
            input_name=_input_name,
        )

    else:
        logger.error(
            f"Unable to get application info: {_get_authorized_application_profiles}"
        )
        flash(_("Application not found or user is not authorized."), "error")
        return redirect("/submit_job")


@submit_job.route("/submit_job/send", methods=["POST"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def send_job():
    _profile_interpreter = request.form.get("profile_interpreter", "")
    _cpus = request.form.get("vcpus", "1")
    try:
        _requested_cpus = int(_cpus)
    except ValueError:
        logger.error(f"Received cpus {_cpus=} is not a valid integer")
        flash(_("cpus must be a valid integer"), "error")
        return redirect("/file_explorer")

    _instance_type = request.form.get("instance_type", "")
    _job_script = request.form.get("job_script", "")
    logger.info(
        f"Requested HPC job submission for {_profile_interpreter=} {_requested_cpus=} {_instance_type=}. Add debug to view entire job_script."
    )
    logger.debug(f"Received job script {_job_script}")
    try:
        _job_to_submit = base64.b64decode(_job_script).decode()
    except Exception as err:
        logger.error(
            f"Received job script {_job_script=} does not seems to be a valid base64. Error {err}"
        )
        flash(
            _("Unable to read the job script. See logs for additional details."),
            "error",
        )
        return redirect("/file_explorer")

    logger.debug(f"About to submit HPC job {_job_to_submit}")
    is_hpc_scheduler = False
    _scheduler_info = None
    for _scheduler in get_schedulers():
        if _scheduler.identifier == _profile_interpreter:
            is_hpc_scheduler = True
            _scheduler_info = _scheduler
            break

    if is_hpc_scheduler:
        # Handle case where interpreter is an actual HPC scheduler and not system interpreter
        if not _instance_type:
            logger.error(
                f"Interpreter is HPC scheduler {_profile_interpreter} but instance_type is not set"
            )
            flash(_("You must specify cpus and instance_type parameters"), "error")
            return redirect("/file_explorer")

        # Calculate the number of nodes to be provisioned for the simulation
        _pattern_ht_support = re.compile(
            r"(?im)^#PBS\s+-l\s+.*\bht_support\s*=\s*(true|false)\b"
        )
        _match_ht_support = _pattern_ht_support.search(_job_to_submit)
        if _match_ht_support:
            _ht_support_value = (
                False if _match_ht_support.group(1).lower() == "false" else True
            )
            logger.info(f"Found ht_support value to {_ht_support_value}")
        else:
            logger.info("ht_support not specified, default to False")
            _ht_support_value = False

        _cpu_per_system = 0
        _describe_instance_type = describe_instance_types(
            instance_types=[_instance_type]
        )
        if _describe_instance_type.get("success") is False:
            logger.error(
                f"Unable to describe instance type {_instance_type} due to {_describe_instance_type}"
            )
            flash(
                _("Unable to describe instance type. See logs for additional details."),
                "error",
            )
            return redirect("/file_explorer")
        else:
            _describe_instance_types = _describe_instance_type.get("message")

            for instance_info in _describe_instance_types.get("InstanceTypes"):
                if _ht_support_value is True:
                    _cpu_per_system = instance_info["VCpuInfo"]["DefaultVCpus"]
                else:
                    _cpu_per_system = instance_info["VCpuInfo"]["DefaultCores"]

        logger.info(
            f"Instance type {_instance_type} has {_cpu_per_system} vCPUs per system due to {_ht_support_value=}"
        )
        if _cpu_per_system == 0:
            logger.error(
                f"Unable to determine vCPU count for instance type {_instance_type}. VcpuInfo.DefaultVCpus not found for {_instance_type} in {_describe_instance_types}"
            )
            flash(
                _(
                    "Unable to determine vCPU count for instance type. See logs for additional details."
                ),
                "error",
            )
            return redirect("/file_explorer")

        _requested_node_count = math.ceil(_requested_cpus / _cpu_per_system)

        # Update the nodecount for the job
        _find_shebang = re.search(r"#!([^\s]+)", _job_to_submit)
        if _find_shebang:
            _shebang = _find_shebang.group(1)
        else:
            _shebang = False

        if _scheduler_info.provider in [
            SocaHpcSchedulerProvider.OPENPBS.value,
            SocaHpcSchedulerProvider.PBSPRO.value,
        ]:
            logger.info(
                "Detected PBS job scheduler, Checking if job count is already specified"
            )

            _check_job_node_count = re.search(r"#PBS -l select=(\d+)", _job_to_submit)
            if _check_job_node_count:
                if str(_check_job_node_count.group(1)) != str(_requested_node_count):
                    logger.info(
                        f"Updating node count from {_check_job_node_count.group(1)} to {_requested_node_count}"
                    )
                    _job_to_submit = re.sub(
                        r"(?P<select_prefix>#PBS -l select=)\d+",
                        rf"\g<select_prefix>{_requested_node_count}",
                        _job_to_submit,
                    )
                else:
                    logger.info(
                        "Node count is already specified and matches the request"
                    )
            else:
                logger.debug("Node count is not specified, adding it")
                if _shebang:
                    # Add right after shebang
                    _job_to_submit = _job_to_submit.replace(
                        _shebang,
                        _shebang
                        + "\n#Added by SOCA Web UI \n"
                        + f"#PBS -l select={_requested_node_count}:ncpus={_cpu_per_system}:mpiprocs={_cpu_per_system}\n",
                    )
                else:
                    # Add first line
                    _job_to_submit = (
                        "# Added by SOCA Web UI \n"
                        f"#PBS -l select={_requested_node_count}:ncpus={_cpu_per_system}:mpiprocs={_cpu_per_system}\n"
                        + _job_to_submit
                    )
                logger.debug("Added node count, ncpus, and mpiprocs to job script")

        elif _scheduler_info.provider == SocaHpcSchedulerProvider.LSF.value:
            # tba
            pass

        elif _scheduler_info.provider == SocaHpcSchedulerProvider.SLURM.value:
            # tba
            pass

    _job_script_parameters = {}
    for _param_name in request.form:
        _param_value = request.form.get(_param_name)

        if _param_name.endswith(
            "[]"
        ):  # Multi-select (Checkbox Group) look like: name[]
            _param_value = MULTI_SELECT_DELIMITER.join(
                request.form.getlist(_param_name)
            )
            # Now remove the [] from the param name to make it easier for the user in the job scripting
            _param_name = _param_name[:-2]

        logger.debug(
            f"Processing Form inputs for macro expansion - Parameter name: ({_param_name}), Value: ({_param_value})"
        )

        if _param_name != "csrf_token":
            if _param_name.lower() == "user":
                _job_script_parameters[_param_name] = session["user"]
            elif _param_name == "HOME":
                _job_script_parameters[_param_name] = (
                    f"{config.Config.USER_HOME}/{session.get('user')}"
                )
            else:
                _job_script_parameters[_param_name] = _param_value

    logger.info(f"Found all Job Parameters; {_job_script_parameters}")

    # PBS rejects `qsub -N` names with chars outside its allowed set (e.g. '@' from
    # StarCCM+ filenames). Normalize the job_name form field before rendering the
    # #PBS -N directive so the submit doesn't fail with 'illegal -N value'.
    if (
        is_hpc_scheduler
        and _scheduler_info.provider
        in (
            SocaHpcSchedulerProvider.OPENPBS.value,
            SocaHpcSchedulerProvider.PBSPRO.value,
        )
        and _job_script_parameters.get("job_name")
    ):
        _orig_job_name = _job_script_parameters["job_name"]
        _job_script_parameters["job_name"] = SocaHpcPBSJobCommandBuilder(
            scheduler_info=_scheduler_info
        ).normalize_job_name(_orig_job_name)
        if _job_script_parameters["job_name"] != _orig_job_name:
            logger.info(
                f"Normalized PBS job name {_orig_job_name!r} -> {_job_script_parameters['job_name']!r}"
            )

    _render_job_payload = SocaJinja2Renderer().from_string(
        data=_job_to_submit, variables=_job_script_parameters
    )

    if _render_job_payload.get("success") is True:
        _rendered_payload = _render_job_payload.get("message")
    else:
        logger.error(f"Unable to render job payload due to {_render_job_payload}")
        flash(
            f"Unable to generate job script {_render_job_payload.get('message')}",
            "error",
        )
        return redirect("/my_jobs")

    # Browser textareas (pre_exec/post_exec, etc.) submit CRLF line endings, which
    # some schedulers reject. Normalize to LF-only so any multiline field is submit-safe.
    _rendered_payload = _rendered_payload.replace("\r\n", "\n").replace("\r", "\n")

    _encoded_payload = base64.b64encode(_rendered_payload.encode()).decode()

    logger.info("Submitting final payload")
    logger.debug(f"{_encoded_payload}")

    _send_hpc_job = SocaHttpClient(
        endpoint="/api/scheduler/job",
        headers={"X-EDH-TOKEN": session["api_key"], "X-EDH-USER": session["user"]},
    ).post(data={"payload": _encoded_payload, "interpreter": _profile_interpreter})

    if _send_hpc_job.get("success") is True:
        logger.info(_send_hpc_job)
        flash(
            _(f"Job submitted successfully: {_send_hpc_job.get('message')}"),
            "success",
        )

    else:
        logger.error(f"Unable to send HPC job due to {_send_hpc_job}")
        flash(
            _(f"{_send_hpc_job.get('message')}"),
            "error",
        )

    return redirect("/my_jobs")
