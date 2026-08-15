# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from flask_babel import gettext as _
from requests import get, delete
from decorators import login_required, feature_flag
from utils.config import SocaConfig
from utils.http_client import SocaHttpClient
from utils.datamodels.hpc.scheduler import get_schedulers, SocaHpcSchedulerProvider

logger = logging.getLogger("soca_logger")
my_api_key = Blueprint("my_api_key", __name__, template_folder="templates")


@my_api_key.route("/my_api_key", methods=["GET"])
@login_required
@feature_flag(flag_name="MY_API_KEY_MANAGEMENT", mode="view")
def index():
    _check_user_key = SocaHttpClient(
        endpoint="/api/user/api_key",
        headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
    ).get(params={"user": session.get("user", "")})

    if _check_user_key.get("success") is False:
        logger.error(f"Unable to retrieve API key for user due to {_check_user_key}")
        _user_token = "UNKNOWN"
        flash(_(
            "Unable to retrieve API key for user. See logs for additional details."),
            "error",
        )
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
        "my_api_key.html",
        user_token=_user_token,
        openpbs_scheduler=_openpbs_scheduler,
        scheduler_host=request.host_url,
    )


@my_api_key.route("/reset_api_key", methods=["POST"])
@login_required
@feature_flag(flag_name="MY_API_KEY_MANAGEMENT", mode="view")
def reset_key():
    user = request.form.get("user", None)
    if user is not None:
        if user != session.get("user", ""):
            flash("You can only reset your own API key", "error")
            return redirect("/my_api_key")

        invalidate_user_key = delete(
            config.Config.FLASK_ENDPOINT + "/api/user/api_key",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            data={"user": user},
            verify=False,
        )  # nosec
        logger.info(
            str(request)
            + ": invalidate_user_key: Status: "
            + str(invalidate_user_key.status_code)
        )
        logger.debug(
            "invalidate_user_key: Content: " + str(invalidate_user_key._content)
        )

        if invalidate_user_key.status_code == 200:
            session.pop("api_key", None)
            return redirect("/my_api_key")
        else:
            logger.error(
                "Error while trying to reset Trace: " + str(invalidate_user_key)
            )
            return redirect("/my_api_key")

    else:
        return redirect("/my_api_key")
