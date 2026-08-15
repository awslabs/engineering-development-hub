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
containers_eks = Blueprint("containers_eks", __name__, template_folder="templates")


@containers_eks.route("/containers/eks/setup", methods=["POST"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_EKS", mode="view")
def setup_job():
    logger.info(f"Preparing EKS job with data {request.form.to_dict()}")
    _image_uri = request.form.to_dict().get("image_uri", None)
    if not _image_uri:
        flash(_("Please select an image to run your job"), "error")
        return redirect("/containers/images")

    _get_eks_cluster = SocaHttpClient(
        endpoint=f"/api/containers/eks/list_clusters",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    logger.debug(f"Get EKS cluster Info {_get_eks_cluster}")
    if _get_eks_cluster.get("success") is True:
        _eks_clusters = _get_eks_cluster.get("message")
    else:
        logger.error(f"Unable to list EKS clusters image because of {_get_eks_cluster}")
        flash(_(f"Unable to list your clusters images due to {_get_eks_cluster.get('message')}"), "error")
        _eks_clusters = []

    _soca_cluster_id = (
        SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    )

    return render_template(
        "containers/eks/setup.html",
        eks_clusters=_eks_clusters,
        image_uri=_image_uri,
        page="containers",
        cluster_id=_soca_cluster_id,
    )


@containers_eks.route("/containers/eks/submit", methods=["POST"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_EKS", mode="view")
def submit_job():
    logger.info(f"Submitting EKS job with data {request.form.to_dict()}")
    _submit_job = SocaHttpClient(
        endpoint="/api/containers/eks/job",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).post(request.form.to_dict())
    if _submit_job.get("success") is True:
        flash(_(f"Your job was submitted successfully"), "success")
        return redirect("/containers/eks/list")
    else:
        # i18n: message is a dynamic API response — translate at the API layer
        flash(
            _submit_job.get("message"),
            "error",
        )
        return redirect("/containers/images")


@containers_eks.route("/containers/eks/list", methods=["GET"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_EKS", mode="view")
def list_jobs():
    logger.info("Listing EKS jobs")
    _soca_cluster_id = (
        SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    )
    _namespace = request.args.get("namespace", "default")
    _cluster = request.args.get("cluster", "")
    _containers = {}

    try:

        if not _cluster:
            _resource_tagging = get_boto(
                service_name="resourcegroupstaggingapi"
            ).message
            response = _resource_tagging.get_resources(
                TagFilters=[
                    {"Key": f"edh:visibility:{_soca_cluster_id}", "Values": ["true"]}
                ],
                ResourceTypeFilters=["eks:cluster"],
            )

            tagged_clusters = [
                arn.split("/")[-1]
                for res in response.get("ResourceTagMappingList", [])
                for arn in [res.get("ResourceARN")]
            ]

            logger.info(f"Found tagged EKS clusters: {tagged_clusters}")
        else:
            tagged_clusters = [_cluster]

        for cluster in tagged_clusters:
            logger.info(f"Checking for job {cluster} and namespace {_namespace}")
            _get_job_for_cluster = SocaHttpClient(
                endpoint="/api/containers/eks/jobs",
                headers={
                    "X-EDH-USER": session["user"],
                    "X-EDH-TOKEN": session["api_key"],
                },
            ).get(params={"cluster": cluster, "namespace": _namespace})
            if _get_job_for_cluster.get("success") is True:
                _containers[cluster] = _get_job_for_cluster.get("message")
            else:
                logger.error(
                    f"Unable to list job for cluster {cluster} because of {_get_job_for_cluster}"
                )
                flash(_(
                    f"{_get_job_for_cluster.get('message')}"),
                    "error",
                )

    except Exception as err:
        logger.error(f"Error listing containers: {err}")
        flash(_(f"Failed to list containers: {err}"), "error")

    logger.debug(f"Detected jobs {_containers}")
    return render_template(
        "containers/eks/list.html",
        containers=_containers,
        page="containers",
    )


@containers_eks.route("/containers/eks/delete", methods=["GET"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT_EKS", mode="view")
def delete_job():
    _delete_job = SocaHttpClient(
        endpoint=f"/api/containers/eks/job",
        headers={
            "X-EDH-USER": session.get("user"),
            "X-EDH-TOKEN": session.get("api_key"),
        },
    ).delete(data=request.args.to_dict())
    if _delete_job.get("success") is True:
        flash(_(f"Your job was deleted successfully"), "success")
    else:
        # i18n: message is a dynamic API response — translate at the API layer
        flash(
            _delete_job.get("message"),
            "error",
        )
    return redirect("/containers/eks/list")
