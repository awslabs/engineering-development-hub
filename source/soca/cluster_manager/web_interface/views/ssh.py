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
from decorators import login_required, feature_flag
import config
import feature_flags
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Optional
from flask import (
    send_file,
    render_template,
    Blueprint,
    session,
    redirect,
    request,
    flash,
    make_response,
)
import os
import io
import pwd
import stat
import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse
from utils.subprocess_client import SocaSubprocessClient


logger = logging.getLogger("soca_logger")

ssh = Blueprint("ssh", __name__, template_folder="templates")


@ssh.route("/ssh", methods=["GET"])
@login_required
@feature_flag(flag_name="LOGIN_NODES", mode="view")
def home():
    _login_nodes_endpoint = (
        SocaConfig(key="/configuration/NLBLoadBalancerDNSName")
        .get_value()
        .get("message")
    )
    # The in-browser terminal is gated by its own feature flag. When disabled
    # the template simply hides the tab; the user-facing instructions for
    # external SSH clients are always shown.
    _user = session.get("user", "unknown-user")
    return render_template(
        "ssh.html",
        login_nodes_endpoint=_login_nodes_endpoint,
        user=_user,
        api_key=session.get("api_key", ""),
    )

@ssh.route("/ssh/get_key", methods=["GET"])
@login_required
@feature_flag(flag_name="LOGIN_NODES", mode="view")
def get_key():
    user = session.get("user", "unknown-user")
    # these are the keys generated when you create a new user
    _ssh_keys = ["id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"]

    try:
        _uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return SocaError.GENERIC_ERROR(helper=f"Unknown user {user}").as_flask()

    _key_fd = None
    for _key in _ssh_keys:
        _key_path = f"/data/home/{user}/.ssh/{_key}"
        try:
            # Atomic open; O_NOFOLLOW rejects a symlink at open() time, O_NONBLOCK avoids a FIFO block (uwsgi runs as root).
            _fd = os.open(_key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            logger.warning(f"{_key_path} is not a regular file or is a symlink.")
            continue
        _st = os.fstat(_fd)
        # Regular file owned by the requesting user only -- never root/other (defeats hardlink + device tricks).
        if not stat.S_ISREG(_st.st_mode) or _st.st_uid != _uid:
            os.close(_fd)
            logger.warning(f"{_key_path} failed regular-file/owner check.")
            continue
        _key_fd = _fd
        break

    if _key_fd is None:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to locate any user private key {','.join(_ssh_keys)} in /data/home/{user}/.ssh/, please try again"
        ).as_flask()

    logger.debug(f"Downloading pem file for {user}")
    return send_file(
        io.FileIO(_key_fd, closefd=True),
        as_attachment=True,
        download_name=f"{user}_soca_privatekey.pem",
        mimetype="application/octet-stream",
    )
