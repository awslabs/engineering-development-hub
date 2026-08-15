######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from flask_babel import gettext as _
from decorators import login_required, feature_flag
from utils.datamodels.hpc.scheduler import get_schedulers
from utils.http_client import SocaHttpClient
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.error import SocaError
from utils.hpc.job_scope import resolve_job_scope
from utils.datamodels.hpc.job_scope_result import SocaJobScopeResult
from models import Projects
from extensions import db


logger = logging.getLogger("soca_logger")
my_jobs = Blueprint("my_jobs", __name__, template_folder="templates")


def _get_project_peers(caller: str) -> set:
    """User-member peers across the caller's shared projects (+ self). Group-based project membership is a future refinement."""
    _peers = set()
    try:
        _groups = session.get("groups", []) or []
        _project_ids = Projects.get_allowed_projects_for_user(
            db_session=db.session, user_name=caller, groups=_groups
        )
        if _project_ids:
            for _project in (
                db.session.query(Projects).filter(Projects.id.in_(_project_ids)).all()
            ):
                _peers.update(_project.allowed_users)
    except Exception as err:
        logger.error(
            f"Unable to resolve project peers for {caller}, defaulting to self only: {err}"
        )
    _peers.add(caller)
    return _peers


def _scoped_job_payload() -> dict:
    """Resolve the session user's visibility scope, query the scheduler jobs API server-side
    (keeping the api_key off the browser), post-filter to allowed owners, and return a
    JSON-serializable payload for client-side rendering."""
    _scheduler_id = request.args.get("scheduler_id", "all")
    _queue = request.args.get("queue", "")
    _caller = session.get("user", "unknown-user")
    _is_admin = session.get("sudoers", False) is True

    # Default view = Mine (self) when no explicit user filter is provided
    _requested_user = request.args.get("user", None)
    if _requested_user is None:
        _requested_user = _caller

    _posture_resp = SocaConfig(
        key="/configuration/HPC/JobListing/VisibilityScope"
    ).get_value(default="all")
    _posture_raw = (
        _posture_resp.get("message") if _posture_resp.get("success") is True else "all"
    )
    _posture_cast = SocaCastEngine(data=_posture_raw).cast_as(str)
    _posture = (
        _posture_cast.get("message").strip().lower()
        if _posture_cast.get("success") is True
        else "all"
    )

    _project_peers = None
    if not _is_admin and _posture == "project":
        _project_peers = _get_project_peers(_caller)

    _scope_resp = resolve_job_scope(
        caller=_caller,
        is_admin=_is_admin,
        posture=_posture,
        requested_user=_requested_user,
        project_peers=_project_peers,
    )
    _scope = (
        _scope_resp.get("message")
        if _scope_resp.get("success") is True
        else SocaJobScopeResult(effective_user=_caller, allowed_owners={_caller})
    )
    _effective_user = _scope.effective_user
    _allowed_owners = _scope.allowed_owners

    # Pass-through coarse-bound params supplied by the front end (safe defaults otherwise)
    _params = {
        "user": _effective_user or "",
        "scheduler_id": _scheduler_id,
        "queue": _queue,
    }
    for _p in ("include_finished", "since", "until", "max_rows"):
        _v = request.args.get(_p)
        if _v not in (None, ""):
            _params[_p] = _v

    _resp = SocaHttpClient(
        endpoint="/api/scheduler/jobs",
        headers={"X-EDH-USER": session.get("user", "unknown-user"), "X-EDH-TOKEN": session.get("api_key", "")},
    ).get(params=_params)

    _payload = {
        "success": False,
        "jobs": [],
        "scheduler_errors": [],
        "capped": False,
        "max_rows": None,
    }
    if _resp.get("success") is True:
        _msg = _resp.get("message") or {}
        _jobs = _msg.get("jobs", [])
        # Defense-in-depth: enforce the resolved visibility ceiling on returned jobs
        if _allowed_owners is not None:
            _jobs = [j for j in _jobs if j.get("job_owner") in _allowed_owners]
        _payload.update(
            {
                "success": True,
                "jobs": _jobs,
                "scheduler_errors": _msg.get("scheduler_errors", []),
                "capped": _msg.get("capped", False),
                "max_rows": _msg.get("max_rows"),
            }
        )
    else:
        logger.error(f"Unable to retrieve jobs: {_resp.get('message')}")
    return _payload


@my_jobs.route("/my_jobs", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def index():
    _scheduler_list = [scheduler.identifier for scheduler in get_schedulers()]
    _dw_resp = SocaConfig(key="/configuration/HPC/JobListing/DefaultWindow").get_value(
        default="24h"
    )
    _default_window = (
        _dw_resp.get("message") if _dw_resp.get("success") is True else "24h"
    )
    _if_resp = SocaConfig(key="/configuration/HPC/JobListing/IncludeFinished").get_value(
        return_as=bool, default=True
    )
    _include_finished_default = (
        _if_resp.get("message") if _if_resp.get("success") is True else True
    )
    return render_template(
        "my_jobs.html",
        scheduler_list=_scheduler_list,
        page="my_jobs",
        default_window=_default_window,
        include_finished_default=_include_finished_default,
        current_user=session.get("user", "unknown-user"),
    )


@my_jobs.route("/my_jobs/data", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def data():
    _payload = _scoped_job_payload()
    if not _payload.get("success"):
        return SocaError.GENERIC_ERROR(
            helper="Unable to retrieve scoped job listing — check scheduler connectivity"
        ).as_flask()
    return SocaResponse(success=True, message=_payload).as_flask()


@my_jobs.route("/my_jobs/delete", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def delete_job():
    _job_id = request.args.get("job_id", "")
    _scheduler_id = request.args.get("scheduler_id", "")
    if not _job_id or not _scheduler_id:
        flash(_("scheduler_id and job_id must be specified"))
        return redirect("/my_jobs")

    _delete_job = SocaHttpClient(
        endpoint="/api/scheduler/job",
        headers={"X-EDH-USER": session.get("user", "unknown-user"), "X-EDH-TOKEN": session.get("api_key", "")},
    ).delete(data={"job_id": _job_id, "scheduler_id": _scheduler_id})

    if _delete_job.get("success") is True:
        flash(_(
            "Request to delete job was successful. The job will be removed from the queue shortly"),
            "success",
        )
    else:
        logger.info(
            f"Unable to delete {_job_id=} for {_scheduler_id=} due to {_delete_job.get('message')}"
        )
        flash(_(
            f"Unable to delete this job {_job_id} for scheduler {_scheduler_id}. See logs for additional details."),
            "error",
        )
    return redirect("/my_jobs")
