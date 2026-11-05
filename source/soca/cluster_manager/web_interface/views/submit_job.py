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
from utils.hpc.scheduler_command_builder import (
    SocaHpcLSFJobCommandBuilder,
    SocaHpcPBSJobCommandBuilder,
    SocaHpcPCSJobCommandBuilder,
    SocaHpcSlurmJobCommandBuilder,
)
from utils.hpc.job_identity import count_array_indices
from utils.user_filesystems_acls import check_user_permission, Permissions

logger = logging.getLogger("soca_logger")
submit_job = Blueprint("submit_job", __name__, template_folder="templates")

# Options delimiter character for Checkbox group values
# should be a single char - such as a comma (,) (default) , or pipe (|) depending on site policy
MULTI_SELECT_DELIMITER = ","

# formBuilder type of the EDH file picker field (static/js/edh_workflow_file_picker.js). Its values are
# re-validated server side at submission since the input is a free text field.
FILE_PICKER_FIELD_TYPE = "edhFilePicker"

# Which builder owns normalize_job_name for each provider. Keyed on the enum's
# value because _scheduler_info.provider is the string form.
_JOB_NAME_BUILDERS = {
    SocaHpcSchedulerProvider.OPENPBS.value: SocaHpcPBSJobCommandBuilder,
    SocaHpcSchedulerProvider.PBSPRO.value: SocaHpcPBSJobCommandBuilder,
    SocaHpcSchedulerProvider.LSF.value: SocaHpcLSFJobCommandBuilder,
    SocaHpcSchedulerProvider.SLURM.value: SocaHpcSlurmJobCommandBuilder,
    SocaHpcSchedulerProvider.AWS_PCS.value: SocaHpcPCSJobCommandBuilder,
}


def _is_true(value) -> bool:
    # formBuilder stores checkbox attributes as booleans or "true"/"false" strings
    return value is True or str(value).lower() in ("true", "required")


# Keep in sync with TERM_RE / parseTerm() / parse() in static/js/edh_workflow_form_conditions.js
_CONDITION_RE = re.compile(r"^([^!=<>\s]+)\s*(>=|<=|!=|=|>|<)\s*(.*)$")


def _parse_condition(condition: str) -> tuple[str, str, str | None]:
    """Parse one "showIf" term into (controlling field, operator, expected value)."""
    condition = condition.strip()
    if not condition:
        # empty side of && / || (e.g. "a &&"): never matches
        return "", "invalid", None
    if condition.startswith("!") and not re.search(r"[=<>]", condition):
        return condition[1:].strip(), "empty", None
    _match = _CONDITION_RE.match(condition)
    if _match:
        return _match.group(1), _match.group(2), _match.group(3).strip()
    return condition, "set", None


def _parse_expression(condition: str) -> list[list[tuple[str, str, str | None]]]:
    """
    Parse a full "showIf" condition into OR groups of AND terms. && binds tighter than ||
    and there are no parentheses: "a && b || c" -> [[a, b], [c]] meaning (a AND b) OR c.
    """
    return [
        [_parse_condition(_term) for _term in _group.split("&&")]
        for _group in condition.split("||")
    ]


def _to_number(value) -> float | None:
    try:
        _n = float(str(value).strip())
    except ValueError:
        return None
    return _n if math.isfinite(_n) else None


def _condition_matches(op: str, expected: str | None, values: list) -> bool:
    if op == "invalid":
        return False
    if op == "set":
        return bool(values)
    if op == "empty":
        return not values
    if op in ("=", "!="):
        # = and != accept several alternatives separated by |
        _hit = any(_v in [_e.strip() for _e in expected.split("|")] for _v in values)
        return _hit if op == "=" else not _hit
    # > >= < <= : numeric only; a non-numeric (or empty) value never matches
    _expected = _to_number(expected)
    if _expected is None:
        return False
    _compare = {
        ">": lambda n: n > _expected,
        ">=": lambda n: n >= _expected,
        "<": lambda n: n < _expected,
        "<=": lambda n: n <= _expected,
    }[op]
    return any(_n is not None and _compare(_n) for _n in map(_to_number, values))


def _is_field_visible(field: dict, fields_by_name: dict, form, _seen: frozenset = frozenset()) -> bool:
    """
    Server side twin of static/js/edh_workflow_form_conditions.js: evaluate the formBuilder "showIf"
    attribute of `field` against the submitted form. Terms are combined with && / || (&& binds
    tighter, no parentheses):
      other_field              -> visible when other_field has a non-empty value / is checked
      !other_field             -> visible when other_field is empty / nothing checked
      other_field=a|b          -> visible when a (or b) is among other_field values
      other_field!=a|b         -> visible when neither a nor b is among other_field values
      other_field>N >=N <N <=N -> numeric comparison, False when the value is not a number
    A hidden controlling field counts as empty, so conditions chain. A cycle (A depends on B,
    B on A) stops the recursion; the fields then simply follow their submitted values.
    """
    _condition = str(field.get("showIf") or "").strip()
    _name = field.get("name")
    if not _condition or _name in _seen:
        return True

    def _values_of(ctrl: str) -> list:
        _ctrl_field = fields_by_name.get(ctrl)
        if _ctrl_field is not None and not _is_field_visible(
            _ctrl_field, fields_by_name, form, _seen | {_name}
        ):
            return []
        return [
            _v.strip()
            for _v in form.getlist(ctrl) + form.getlist(f"{ctrl}[]")
            if _v and _v.strip()
        ]

    return any(
        all(
            _condition_matches(_op, _expected, _values_of(_ctrl))
            for _ctrl, _op, _expected in _group
        )
        for _group in _parse_expression(_condition)
    )


def _hidden_field_names(profile_form: list, form) -> set:
    """Names of the fields hidden by a "showIf" condition for this submission."""
    _fields = [_f for _f in profile_form if isinstance(_f, dict) and _f.get("name")]
    _by_name = {_f["name"]: _f for _f in _fields}
    return {_f["name"] for _f in _fields if not _is_field_visible(_f, _by_name, form)}


def _get_authorized_application_profile(app_id: str) -> dict | None:
    """
    Return the application profile `app_id` if the current user is authorized to use it
    (same /api/user/resources_permissions check used to list workflows), otherwise None.
    """
    _get_authorized_application_profiles = SocaHttpClient(
        endpoint="/api/user/resources_permissions",
        headers={
            "X-EDH-USER": session.get("user", ""),
            "X-EDH-TOKEN": session.get("api_key", ""),
        },
    ).get(params={"application_profiles": f"{app_id}"})

    if _get_authorized_application_profiles.get("success") is False:
        logger.error(
            f"Unable to get application profile {app_id} for {session.get('user')} because of {_get_authorized_application_profiles.get('message')}"
        )
        return None

    _profiles = (_get_authorized_application_profiles.get("message") or {}).get(
        "application_profiles", []
    )
    return _profiles[0] if _profiles else None


def _validate_file_picker_values(profile_form: list, form, user: str) -> tuple[dict, str | None]:
    """
    Validate every EDH file picker value submitted for this workflow against the field
    definition stored server side (allowMultiple / selectType / required) and the user's
    filesystem permissions (check_user_permission + PATH_TO_RESTRICT).

    Returns (validated_values, error). validated_values maps field name -> the resolved
    paths joined with MULTI_SELECT_DELIMITER, so the job script receives exactly what was
    checked. error is None when everything is valid, otherwise a user facing message.
    """
    _validated = {}
    _hidden = _hidden_field_names(profile_form, form)
    for _field in profile_form:
        if not isinstance(_field, dict) or _field.get("type") != FILE_PICKER_FIELD_TYPE:
            continue

        _name = _field.get("name", "")
        if _name in _hidden:
            # Hidden by a "showIf" condition: not required, and any posted value is dropped.
            _validated[_name] = ""
            continue
        _label = _field.get("label") or _name
        _value = (form.get(_name) or "").strip()
        if not _value:
            if _is_true(_field.get("required")):
                return {}, _("%(label)s is required.", label=_label)
            _validated[_name] = ""
            continue

        _paths = [_p.strip() for _p in _value.split(MULTI_SELECT_DELIMITER)]
        if any(not _p for _p in _paths):
            return {}, _(
                "%(label)s contains an empty path. Paths containing a comma are not supported.",
                label=_label,
            )
        if len(_paths) > 1 and not _is_true(_field.get("allowMultiple")):
            return {}, _("%(label)s accepts a single path only.", label=_label)

        _select_type = _field.get("selectType") or "file"
        _resolved = []
        for _path in _paths:
            if not _path.startswith("/"):
                return {}, _("%(label)s: %(path)s must be an absolute path.", label=_label, path=_path)

            _real = pathlib.Path(_path).resolve()
            # Same generic message for missing / denied paths so the check does not reveal
            # whether a path the user cannot read exists.
            _denied = _(
                "%(label)s: %(path)s does not exist or you are not authorized to access it.",
                label=_label,
                path=_path,
            )
            if (
                check_user_permission(
                    path=str(_real),
                    permissions=Permissions.READ,
                    user=user,
                    paths_to_restrict=config.Config.PATH_TO_RESTRICT,
                )
                is False
                or not _real.exists()
            ):
                logger.warning(f"File picker {_name}: {user} cannot read {_real}")
                return {}, _denied

            if _select_type == "file" and not _real.is_file():
                return {}, _("%(label)s: %(path)s is not a file.", label=_label, path=_path)
            if _select_type == "folder" and not _real.is_dir():
                return {}, _("%(label)s: %(path)s is not a folder.", label=_label, path=_path)
            _resolved.append(str(_real))

        _validated[_name] = MULTI_SELECT_DELIMITER.join(_resolved)

    return _validated, None


@submit_job.route("/submit_job", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def index():
    _input_file = request.args.get("input_file", "")
    _user = session.get("user", "")
    # input_file is optional: set when coming from the file explorer ("Use as Simulation Input"),
    # empty when the workflow is picked directly from /submit_job.
    logger.info(f"Received submit_job GET request with {_input_file=}")

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
        input_file=_input_file,
    )


@submit_job.route("/submit_job", methods=["POST"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def job_submission():
    _app = request.form.get("app", "")
    _input_file = request.form.get("input_file", "")
    _user = session.get("user", "")
    logger.info(f"Received submit_job POST request with {_app=} / {_input_file=}")

    if not _app:
        flash(_("Missing required parameter (app)."), "error")
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

    if not _input_file:
        # No input file selected: the form starts empty and the job runs from the user's home.
        _input_path = ""
        _input_name = ""
        _input_file_parent = f"{config.Config.USER_HOME}/{_user}"
    else:
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
            app_id=_app,
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
    _user = session.get("user", "")
    # Re-load the workflow server side: the job script, interpreter and form definition come
    # from the stored application profile (after the authorization check), never from the
    # browser, so they cannot be altered by editing the page.
    _app = request.form.get("app", "")
    _application_profile = _get_authorized_application_profile(_app) if _app else None
    if not _application_profile:
        logger.error(f"send_job: application {_app=} not found or {_user} is not authorized")
        flash(_("Application not found or user is not authorized."), "error")
        return redirect("/submit_job")

    _profile_interpreter = _application_profile.get("profile_interpreter", "")
    try:
        _profile_form = json.loads(
            base64.b64decode(_application_profile.get("profile_form") or "").decode() or "[]"
        )
    except Exception as err:
        logger.error(f"Unable to read application profile profile_form due to {err}")
        flash(_("Unable to extract profile information. See logs for additional details"), "error")
        return redirect("/submit_job")

    if not isinstance(_profile_form, list):
        _profile_form = []
    # Reject line breaks in submitted values: a "\n" in e.g. job_name would let the user inject
    # extra scheduler directives (#PBS / #SBATCH / #BSUB lines) or shell commands in the job
    # script. Only fields defined as textarea in the stored workflow (e.g. user_pre_exec) may
    # be multi-line.
    _multiline_fields = {
        _f["name"]
        for _f in _profile_form
        if isinstance(_f, dict) and _f.get("name") and _f.get("type") == "textarea"
    }
    for _param_name in request.form:
        _base_name = _param_name[:-2] if _param_name.endswith("[]") else _param_name
        if _base_name in _multiline_fields:
            continue
        if any("\n" in _v or "\r" in _v for _v in request.form.getlist(_param_name)):
            logger.warning(f"send_job: {_user} submitted a line break in {_base_name!r}, refusing")
            flash(
                _(
                    "%(field)s cannot contain line breaks. Only multi-line text area fields accept them.",
                    field=_base_name,
                ),
                "error",
            )
            return redirect("/submit_job")

    # Fields hidden by a "showIf" condition reach the job script empty (see _is_field_visible)
    _hidden_fields = _hidden_field_names(_profile_form, request.form)

    # array_indices is interpolated into a "#PBS -J {{array_indices}}" directive,
    # so it needs an allowlist, not just the line-break check above. A newline is
    # already refused, but a SAME-LINE injection is not: a value of
    #
    #     1-100 -l select=999:ncpus=96
    #
    # carries no line break and PBS honours both options on the one directive
    # line, so the user would escape the form's own sizing.
    #
    # count_array_indices is the allowlist AND the sizing function the dispatcher
    # uses, deliberately: a value that cannot be sized cannot be submitted, and
    # there is no second definition of "valid indices" to drift from this one. It
    # accepts only digits, '-', ':' and ',' and returns 0 for anything else.
    _array_indices = request.form.get("array_indices", "")
    if _array_indices and "array_indices" not in _hidden_fields:
        _subjob_count = count_array_indices(_array_indices).get("message")
        if _subjob_count < 1:
            logger.warning(
                f"send_job: {_user} submitted an unusable array_indices "
                f"{_array_indices!r}, refusing"
            )
            flash(
                _(
                    "Subjob indices are not valid. Use a range like 1-100, a "
                    "stepped range like 0-999:10, or a comma-separated list like "
                    "1-4,9-10. Only digits, '-', ':' and ',' are accepted."
                ),
                "error",
            )
            return redirect("/submit_job")

        # No size ceiling is checked here. PBS refuses an oversized array at
        # qsub via max_array_size, so the submission fails with the
        # administrator's real limit for this server/queue rather than a
        # duplicate EDH constant that could drift from it. What PBS does NOT
        # catch is the injection above -- "1-100 -l select=999:ncpus=96" is a
        # perfectly legal array size to PBS -- which is why the allowlist stays.
        logger.info(
            f"send_job: array_indices {_array_indices!r} validated, "
            f"{_subjob_count} subjobs"
        )

    _file_picker_values, _file_picker_error = _validate_file_picker_values(
        _profile_form, request.form, _user
    )
    if _file_picker_error:
        flash(_file_picker_error, "error")
        return redirect("/submit_job")

    # input_file_path (working directory) is a hidden field: the user must be able to read it.
    _input_file_path = request.form.get("input_file_path", "")
    if _input_file_path and (
        check_user_permission(
            path=str(pathlib.Path(_input_file_path).resolve()),
            permissions=Permissions.READ,
            user=_user,
            paths_to_restrict=config.Config.PATH_TO_RESTRICT,
        )
        is False
    ):
        logger.warning(f"send_job: {_user} cannot read input_file_path {_input_file_path}")
        flash(_("You are not authorized to access this location and/or this path is restricted by the Administrator."), "error")
        return redirect("/submit_job")

    _cpus = request.form.get("vcpus", "1")
    try:
        _requested_cpus = int(_cpus)
    except ValueError:
        logger.error(f"Received cpus {_cpus=} is not a valid integer")
        flash(_("cpus must be a valid integer"), "error")
        return redirect("/file_explorer")

    _instance_type = request.form.get("instance_type", "")
    _job_script = _application_profile.get("profile_job", "")
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

    if is_hpc_scheduler and not _instance_type:
        # instance_type is optional: e.g. on AWS PCS the compute node group defines the instance
        # types. Without it EDH cannot calculate the node count, so the job script is submitted
        # as written and must request its own nodes.
        logger.info(
            f"Interpreter is HPC scheduler {_profile_interpreter} without instance_type, skipping node count calculation"
        )

    if is_hpc_scheduler and _instance_type:
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

        # Internal fields of the submission form, not job parameters.
        if _param_name not in ("csrf_token", "app", "job_script", "profile_interpreter"):
            if _param_name in _hidden_fields:
                _job_script_parameters[_param_name] = ""
            elif _param_name in _file_picker_values:
                # Use the paths validated by _validate_file_picker_values (resolved, ACL checked)
                _job_script_parameters[_param_name] = _file_picker_values[_param_name]
            elif _param_name.lower() == "user":
                _job_script_parameters[_param_name] = session["user"]
            elif _param_name == "HOME":
                _job_script_parameters[_param_name] = (
                    f"{config.Config.USER_HOME}/{session.get('user')}"
                )
            else:
                _job_script_parameters[_param_name] = _param_value

    # Kept available to job scripts as before, but always the server side value.
    _job_script_parameters["profile_interpreter"] = _profile_interpreter
    logger.info(f"Found all Job Parameters; {_job_script_parameters}")

    # Scheduler directives reject or mis-parse some characters in a job name: PBS
    # refuses chars outside its own set (e.g. '@' from StarCCM+ filenames), and a
    # double quote breaks out of a quoted directive such as
    # `#BSUB -J "{{job_name}}[{{array_indices}}]"` and appends further options.
    if is_hpc_scheduler and _job_script_parameters.get("job_name"):
        _job_name_builder = _JOB_NAME_BUILDERS.get(_scheduler_info.provider)
        if _job_name_builder is None:
            logger.warning(
                f"send_job: no job_name normalizer for {_scheduler_info.provider=}, "
                f"leaving the submitted name as-is"
            )
        else:
            _orig_job_name = _job_script_parameters["job_name"]
            _job_script_parameters["job_name"] = _job_name_builder(
                scheduler_info=_scheduler_info
            ).normalize_job_name(_orig_job_name)
            if _job_script_parameters["job_name"] != _orig_job_name:
                logger.info(
                    f"Normalized job name {_orig_job_name!r} -> {_job_script_parameters['job_name']!r}"
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
