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
from utils.http_client import SocaHttpClient
from decorators import login_required, admin_only, feature_flag
from utils.subprocess_client import SocaSubprocessClient
import os

logger = logging.getLogger("soca_logger")
admin_users = Blueprint("admin_users", __name__, template_folder="templates")


@admin_users.route("/admin/users", methods=["GET"])
@login_required
@admin_only
@feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="view")
def index():
    _shells = SocaSubprocessClient(run_command="cat /etc/shells").run(
        timeout=30, shell=False
    )
    if _shells.success:
        all_shells = _shells.message["stdout"].split("\n")[:-1]  # remove last empty
    else:
        logger.error("Unable to retrieve shells installed on the system")
        all_shells = ["/bin/bash"]
    # User pickers (delete / reset / grant / revoke) use an on-demand bounded
    # typeahead against /api/ldap/users?q= instead of rendering the full
    # directory, so this view no longer fetches the entire user list.
    return render_template(
        "admin/users.html",
        all_shells=all_shells,
        directory=config.Config.DIRECTORY_AUTH_PROVIDER,
    )


@admin_users.route("/admin/manage_sudo", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="view")
def manage_sudo():
    user = request.form.get("user", None)
    action = request.form.get("action", None)
    if user == session["user"]:
        flash(_("You can not manage your own Admin permissions."), "error")
        return redirect("/admin/users")

    if action in ["grant", "revoke"]:
        if user is not None:
            if action == "grant":
                give_sudo = SocaHttpClient(
                    endpoint="/api/ldap/sudo",
                    headers={
                        "X-EDH-TOKEN": session["api_key"],
                        "X-EDH-USER": session["user"],
                    },
                ).post(data={"user": user})
                if give_sudo.success:
                    flash(_("Admin permissions granted"), "success")
                else:
                    flash(_("Error: ") + str(give_sudo.get("message")), "error")
                return redirect("/admin/users")

            else:
                # Revoke SUDO
                remove_sudo = SocaHttpClient(
                    endpoint="/api/ldap/sudo",
                    headers={
                        "X-EDH-TOKEN": session["api_key"],
                        "X-EDH-USER": session["user"],
                    },
                ).delete(data={"user": user})
                if remove_sudo.success:
                    flash(_("Admin permissions revoked"), "success")
                else:
                    flash(_("Error: ") + str(remove_sudo.get("message")), "error")

                return redirect("/admin/users")

        else:
            return redirect("/admin/users")
    else:
        return redirect("/admin/users")


@admin_users.route("/admin/create_user", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="view")
def create_new_account():
    user = str(request.form.get("user"))
    password = str(request.form.get("password"))
    email = str(request.form.get("email"))
    sudoers = request.form.get("sudo", None)
    shell = request.form.get("shell", "/bin/bash")
    uid = request.form.get(
        "uid", None
    )  # 0 if not specified. Will automatically generate uid
    gid = request.form.get(
        "gid", None
    )  # 0 if not specified. Will automatically generate gid
    create_new_user = SocaHttpClient(
        endpoint="/api/ldap/user",
        headers={"X-EDH-TOKEN": session["api_key"], "X-EDH-USER": session["user"]},
    ).post(
        data={
            "user": user,
            "password": password,
            "email": email,
            "sudoers": 0 if sudoers is None else 1,
            "shell": shell,
            "uid": 0 if not uid else uid,
            "gid": 0 if not gid else gid,
        }
    )

    if create_new_user.success:
        # Create API key
        create_user_key = SocaHttpClient(
            endpoint="/api/user/api_key",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).get(params={"user": user})
        if create_user_key.success:
            flash(_("User ") + user + " has been created successfully", "success")
        else:
            flash(_(
                "User created but unable to generate API token: ")
                + str(create_user_key.get("message")),
                "error",
            )

        return redirect("/admin/users")
    else:
        flash(_(
            "Unable to create new user. API returned error: ")
            + str(create_new_user.get("message")),
            "error",
        )
        return redirect("/admin/users")


@admin_users.route("/admin/delete_user", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="view")
def delete_account():
    user = str(request.form.get("user_to_delete"))
    if session["user"] == user:
        flash(_("You cannot delete your own account."), "error")
        return redirect("/admin/users")

    delete_user = SocaHttpClient(
        endpoint="/api/ldap/user",
        headers={"X-EDH-TOKEN": session["api_key"], "X-EDH-USER": session["user"]},
    ).delete(data={"user": user})

    if delete_user.success:
        flash(_("User: ") + user + " has been deleted correctly", "success")
    else:
        flash(_(
            "Could not delete user: ") + user + ". Check trace: " + str(delete_user.get("message")),
            "error",
        )

    return redirect("/admin/users")
