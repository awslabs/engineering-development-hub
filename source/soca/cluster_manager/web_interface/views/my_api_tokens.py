# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import logging
import config
from flask import render_template, Blueprint, request, session
from flask_babel import gettext as _
from decorators import login_required, feature_flag
from utils.http_client import SocaHttpClient
from utils.datamodels.hpc.scheduler import get_schedulers, SocaHpcSchedulerProvider

logger = logging.getLogger("soca_logger")
my_api_tokens = Blueprint("my_api_tokens", __name__, template_folder="templates")


@my_api_tokens.route("/my_api_tokens", methods=["GET"])
@login_required
@feature_flag(flag_name="MY_API_TOKENS", mode="view")
def index():
    _check_user_key = SocaHttpClient(
        endpoint="/api/user/api_key",
        headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
    ).get(params={"user": session.get("user", "")})

    if _check_user_key.get("success") is False:
        logger.error(f"Unable to retrieve API key for user due to {_check_user_key}")
        _user_token = "UNKNOWN"
    else:
        _user_token = _check_user_key.get("message")

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
        user_token=_user_token,
        openpbs_scheduler=_openpbs_scheduler,
        scheduler_host=request.host_url,
        page="my_api_tokens",
    )
