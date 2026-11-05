# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import logging
from flask import render_template, Blueprint, request, session
from decorators import login_required, feature_flag
from utils.datamodels.hpc.scheduler import get_schedulers, SocaHpcSchedulerProvider

logger = logging.getLogger("soca_logger")
my_api_tokens = Blueprint("my_api_tokens", __name__, template_folder="templates")


@my_api_tokens.route("/my_api_tokens", methods=["GET"])
@login_required
@feature_flag(flag_name="MY_API_TOKENS", mode="view")
def index():
    # Get a default scheduler to show API instructions
    _openpbs_scheduler = ""
    for _scheduler in get_schedulers():
        if _scheduler.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:
            _openpbs_scheduler = _scheduler.identifier

    return render_template(
        "my_api_tokens.html",
        user=session.get("user", ""),
        openpbs_scheduler=_openpbs_scheduler,
        scheduler_host=request.host_url,
        page="my_api_tokens",
    )
