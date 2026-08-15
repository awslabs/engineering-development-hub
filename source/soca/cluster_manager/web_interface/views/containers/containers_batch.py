# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from decorators import login_required, feature_flag
from flask import Blueprint, render_template, session, redirect
from flask_babel import gettext as _
from utils.config import SocaConfig
from utils.http_client import SocaHttpClient
from utils.aws.boto3_wrapper import get_boto
from flask import request, flash, redirect

logger = logging.getLogger("soca_logger")
containers_batch = Blueprint("containers_batch", __name__, template_folder="templates")


@containers_batch.route("/containers/batch/setup", methods=["GET"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="view")
def setup_job():
    logger.info(f"Preparing Batch job with data {request.form.to_dict()}")

    _soca_cluster_id = (
        SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    )

    # Get Batch job queue
    _get_batch_job_queue = SocaHttpClient(
        endpoint=f"/api/containers/batch/job_queue",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    logger.debug(f"Get Batch Job Queues Info {_get_batch_job_queue}")
    if _get_batch_job_queue.get("success") is True:
        _job_queues = _get_batch_job_queue.get("message")
    else:
        logger.error(
            f"Unable to list Batch Job Queue image because of {_get_batch_job_queue}"
        )
        flash(_(
            f"Unable to list Batch Job Queue due to {_get_batch_job_queue.get('message')}"),
            "error",
        )
        _job_queues = []

    # Get Batch job definition
    _get_batch_job_definition = SocaHttpClient(
        endpoint=f"/api/containers/batch/job_definition",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    logger.debug(f"Get Batch Job Definition Info {_get_batch_job_definition}")
    if _get_batch_job_definition.get("success") is True:
        _job_definitions = _get_batch_job_definition.get("message")
    else:
        logger.error(
            f"Unable to list Batch job definition because of {_get_batch_job_definition}"
        )
        flash(_(
            f"Unable to list your Batch Job Definition due to {_get_batch_job_definition.get('message')}"),
            "error",
        )
        _job_definitions = []

    return render_template(
        "containers/batch/setup.html",
        page="containers",
        batch_job_definitions=_job_definitions,
        batch_job_queues=_job_queues,
        cluster_id=_soca_cluster_id,
    )


@containers_batch.route("/containers/batch/submit", methods=["POST"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="view")
def submit_job():
    logger.info(f"Submitting Batch job with data {request.form.to_dict()}")
    _submit_job = SocaHttpClient(
        endpoint="/api/containers/batch/job",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).post(data=request.form.to_dict())

    if _submit_job.get("success") is True:
        flash(_(
            f"{_submit_job.get('message', '')}"),
            "success",
        )
        return redirect("/containers/batch/list")
    else:
        flash(
            _submit_job.get(
                "message",
                _("Unable to submit AWS Batch job due to {error}").format(error=_submit_job.get('message')),
            ),
            "error",
        )
        return redirect("/containers/batch/setup")


@containers_batch.route("/containers/batch/list", methods=["GET"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="view")
def list_jobs():
    logger.info("Listing AWS Batch jobs")

    _get_batch_jobs = SocaHttpClient(
        endpoint="/api/containers/batch/jobs",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get(params=request.args.to_dict())
    logger.debug(f"Received Batch Jobs: {_get_batch_jobs}")
    if _get_batch_jobs.get("success") is True:
        _batch_jobs = _get_batch_jobs.get("message", [])
    else:
        logger.error(f"Unable to list AWS Batch jobs: {_get_batch_jobs}")
        flash(
            _get_batch_jobs.get(
                "message",
                _("Unable to list AWS Batch jobs due to {error}").format(error=_get_batch_jobs.get('message')),
            ),
            "error",
        )
        _batch_jobs = []

    return render_template(
        "containers/batch/list.html",
        page="containers",
        batch_jobs=_batch_jobs,
    )


@containers_batch.route("/containers/batch/delete", methods=["POST"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="view")
def delete_job():
    _job_id = request.form.get("job_id")
    logger.info(f"Deleting AWS Batch job {_job_id}")

    if not _job_id:
        flash(_("Job ID is required to delete a Batch job."), "error")
        return redirect("/containers/batch/list")

    _delete_job = SocaHttpClient(
        endpoint=f"/api/containers/batch/job",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).delete(
        data={
            "job_id": _job_id,
            "reason": request.form.get("reason", "Cancelled by user"),
        }
    )

    logger.info(f"Delete Job Response: {_delete_job}")
    if _delete_job.get("success") is True:
        flash(_(f"Batch job {_job_id} has been deleted successfully."), "success")
    else:
        flash(
            _delete_job.get("message", _("Unable to delete Batch job {job_id}.").format(job_id=_job_id)),
            "error",
        )

    return redirect("/containers/batch/list")
