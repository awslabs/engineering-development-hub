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
ecr_images = Blueprint("ecr_images", __name__, template_folder="templates")


@ecr_images.route("/containers/images", methods=["GET"])
@login_required
def index():
    logger.info("Listing all Container images available")
    _user = session.get("user")

    _soca_cluster_id = (
        SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    )

    _get_ecr_repo_info = SocaHttpClient(
        endpoint=f"/api/containers/ecr/repository",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    logger.debug(f"Get ECR Repo Info {_get_ecr_repo_info}")
    if _get_ecr_repo_info.get("success") is True:
        _container_images = _get_ecr_repo_info.get("message")
    else:
        logger.error(f"Unable to list container image because of {_get_ecr_repo_info}")
        flash(_("Unable to list your container images"), "error")
        _container_images = {}

    _get_eks_cluster = SocaHttpClient(
        endpoint=f"/api/containers/eks/list_clusters",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    logger.debug(f"Get EKS cluster Info {_get_eks_cluster}")
    if _get_eks_cluster.get("success") is True:
        _eks_clusters = _get_eks_cluster.get("message")
    else:
        logger.error(
            f"Unable to list EKS clusters image because of {_get_ecr_repo_info}"
        )
        flash(_("Unable to list your clusters images"), "error")
        _eks_clusters = []

    
    logger.debug(f"All ECR Repo and Images {_container_images}")
    logger.debug(f"All EKS Clusters {_eks_clusters}")

    return render_template(
        "containers/ecr_images.html",
        container_images=_container_images,
        eks_clusters=_eks_clusters,
        cluster_id=_soca_cluster_id,
        page="containers_list_images",

    )
