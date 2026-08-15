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
from requests import get, post, put
from decorators import login_required, feature_flag
import string
import secrets
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.config import SocaConfig
from utils.http_client import SocaHttpClient

logger = logging.getLogger("soca_logger")
my_account = Blueprint("my_account", __name__, template_folder="templates")


@my_account.route("/my_account", methods=["GET"])
@login_required
@feature_flag(flag_name="MY_ACCOUNT_MANAGEMENT", mode="view")
def index():
    group_name = f"{session['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
    _get_user_ldap_group = SocaHttpClient(
        endpoint="/api/ldap/group", headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY}
    ).get(params={"group": group_name})
    # Add-user picker uses /api/ldap/users?q= typeahead; no full fetch here.
    all_users = []
    group_members = []

    if _get_user_ldap_group.success:
        for _member in _get_user_ldap_group.message.get("members"):
            if (
                f"{'uid=' if config.Config.DIRECTORY_AUTH_PROVIDER in ['openldap', 'existing_openldap'] else 'cn='}{session['user']},"
                not in _member.lower()
            ):
                group_members.append(_member)

    # Resolved user preferences for the generic Preferences panel (one control
    # per catalog pref). Best-effort: a store error yields an empty list and the
    # panel simply renders nothing. (The add-user picker uses the /api/ldap/users
    # ?q= typeahead from the ldap-paging change merged here -- no eager full-user
    # fetch -- so all_users stays empty.)
    _prefs_view = []
    try:
        from utils import user_pref_store as _user_prefs
        from utils import user_pref_catalog as _user_pref_catalog
        from utils.datamodels.soca_user_preferences import ResolvedPrefView

        _resolved_resp = _user_prefs.resolve_all(session["user"])
        _resolved = _resolved_resp.message if _resolved_resp.success else {}
        for _key in _user_pref_catalog._all_keys():
            _spec = _user_pref_catalog._spec(_key) or {}
            _meta = _resolved.get(_key, {})
            _prefs_view.append(
                ResolvedPrefView(
                    key=_key,
                    type=_spec.get("type"),
                    value=_meta.get("value"),
                    is_set=_meta.get("is_set", False),
                    source=_meta.get("source"),
                    allowed=_meta.get("allowed"),
                    min=_meta.get("min"),
                    max=_meta.get("max"),
                ).model_dump()
            )
    except Exception as _pref_err:
        logger.warning(f"user preferences panel resolve failed: {_pref_err}")
        _prefs_view = []

    return render_template(
        "my_account.html",
        group_members=group_members,
        all_users=all_users,
        user_preferences=_prefs_view,
    )


@my_account.route("/manage_group", methods=["POST"])
@feature_flag(flag_name="MY_ACCOUNT_MANAGEMENT", mode="view")
@login_required
def manage_group():
    group_name = f"{session['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
    user = request.form.get("user")
    action = request.form.get("action")
    _update_group = SocaHttpClient(
        endpoint="/api/ldap/group", headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY}
    ).put(data={"group": group_name, "user": user, "action": action})

    if _update_group.success:
        flash(_("Group update successfully"), "success")
    else:
        flash(_(f"Unable to update group:{_update_group.message}"), "error")

    return redirect("/my_account")


@my_account.route("/reset_password", methods=["POST"])
@feature_flag(flag_name="MY_ACCOUNT_MANAGEMENT", mode="view")
@login_required
def reset_key():
    password = request.form.get("password", None)
    password_verif = request.form.get("password_verif", None)
    admin_reset = request.form.get("admin_reset", None)
    if admin_reset == "yes":
        # Admin can generate a temp password on behalf of the user
        user = request.form.get("user", None)
        if user is None:
            return redirect("/admin/users")
        elif user == session["user"]:
            flash(_(
                "You can not reset your own password using this tool. Please visit 'My Account' section for that"),
                "error",
            )
            return redirect("/admin/users")
        else:
            password = "".join(
                secrets.choice(
                    string.ascii_lowercase + string.ascii_uppercase + string.digits
                )
                for _i in range(25)
            )
            change_password = post(
                config.Config.FLASK_ENDPOINT + "/api/user/reset_password",
                headers={
                    "X-EDH-TOKEN": session["api_key"],
                    "X-EDH-USER": session["user"],
                },
                data={"user": user, "password": password},
                verify=False,
            )  # nosec
            if change_password.status_code == 200:
                flash(_(
                    "Password for ")
                    + user
                    + " has been changed to "
                    + password
                    + "<hr> User is recommended to change it using 'My Account' section",
                    "success",
                )
                return redirect("/admin/users")
            else:
                flash(_(
                    "Unable to reset password. Error: ") + str(change_password._content),
                    "error",
                )
                return redirect("/admin/users")
    else:
        if password is not None:
            # User can change their own password
            if password == password_verif:
                change_password = post(
                    config.Config.FLASK_ENDPOINT + "/api/user/reset_password",
                    headers={
                        "X-EDH-TOKEN": config.Config.API_ROOT_KEY,
                        "X-EDH-USER": session["user"],
                    },
                    data={"user": session["user"], "password": password},
                    verify=False,
                )  # nosec

                if change_password.status_code == 200:
                    flash(_("Your password has been changed successfully."), "success")
                    return redirect("/my_account")
                else:
                    flash(_(
                        "Unable to reset your password. Error: ")
                        + str(change_password._content),
                        "error",
                    )
                    return redirect("/my_account")
            else:
                flash(_("Password does not match"), "error")
                return redirect("/my_account")
        else:
            return redirect("/my_account")
