# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from decorators import login_required, feature_flag
import re
from typing import List, Optional
from flask import render_template, Blueprint, session, request, make_response, flash
import utils.aws.boto3_wrapper as utils_boto3
from utils.http_client import SocaHttpClient
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.error import SocaError
from utils.aws.ssm_helper import execute_ssm_document

logger = logging.getLogger("soca_logger")

web_terminal = Blueprint("web_terminal", __name__, template_folder="templates")


@web_terminal.route("/web_terminal", methods=["GET"])
@login_required
@feature_flag(flag_name="LOGIN_NODES", mode="view")
@feature_flag(flag_name="WEBSHELL", mode="view")
def home():
    _login_nodes_endpoint = (
        SocaConfig(key="/configuration/NLBLoadBalancerDNSName")
        .get_value()
        .get("message")
    )
    _user = session.get("user", "unknown-user")
    _user_api_key = session.get("api_key", "")

    _get_login_nodes = SocaHttpClient(
        endpoint="/api/login_nodes/list",
        headers={
            "X-EDH-TOKEN": _user_api_key,
            "X-EDH-USER": _user,
        },
    ).get()

    logger.info(f"Found Login nodes: {_get_login_nodes} for Web Terminal")
    if _get_login_nodes.get("success"):
        _has_running_login_nodes = len(_get_login_nodes.get("message"))
    else:
        _has_running_login_nodes = 0

    return render_template(
        "web_terminal.html",
        login_nodes_endpoint=_login_nodes_endpoint,
        has_running_login_nodes=_has_running_login_nodes,
        user=_user,
    )


@web_terminal.route("/web_terminal/terminal_auth", methods=["POST"])
@login_required
@feature_flag(flag_name="LOGIN_NODES", mode="view")
@feature_flag(flag_name="WEBSHELL", mode="view")
def terminal_auth():
    """
    Set a short-lived, HttpOnly, Secure, SameSite=Strict cookie carrying
    the user's EDH token. The frontend calls this right before opening
    the WebSocket, so the cookie accompanies the WebSocket upgrade but
    never appears in URLs or ALB access logs.

    Per BSC12 Secure Cookies:
      * Secure              - HTTPS only
      * HttpOnly            - not readable from JS (XSS hardening)
      * SameSite=Strict     - our WebSocket is same-origin; no third-party ctx
      * Path=/web_terminal/endpoint  - cookie is sent only on the WS endpoint, not
                              on unrelated WebUI pages
      * Max-Age=60          - single-use; the browser doesn't need it
                              after the WebSocket opens

    The webshell service on the login node reads the cookie once during
    the WebSocket upgrade and then ignores it. Only this endpoint sets
    the cookie; nothing else extends its lifetime.
    """
    # Short lifetime for the webshell auth cookie. The frontend sets it right
    # before opening the WebSocket; the server consumes it once and the browser
    # does not need it afterwards. 60 seconds gives plenty of slack for slow
    # networks without leaving a long-lived token in the cookie jar.
    _WEBSHELL_COOKIE_NAME = "edh_webshell_auth"
    _WEBSHELL_COOKIE_MAX_AGE_SECONDS = 60

    _user = session.get("user", "")
    _api_key = session.get("api_key", "")
    if not _user or not _api_key:
        return SocaResponse(
            success=False,
            message="no active session",
            status_code=401,
        ).as_flask()

    # set_cookie() requires a real Response object, so build one from a
    # SocaResponse payload and then attach the cookie. Keeps the response
    # body shape consistent with the rest of the WebUI.
    _payload, _status = SocaResponse(success=True, message="cookie set").as_flask()
    response = make_response(_payload, _status)
    response.set_cookie(
        _WEBSHELL_COOKIE_NAME,
        # Embed both user and token as a single opaque value. '|' is a
        # safe separator because usernames are POSIX-validated (no '|')
        # and tokens are UUID-like.
        value=f"{_user}|{_api_key}",
        max_age=_WEBSHELL_COOKIE_MAX_AGE_SECONDS,
        secure=True,
        httponly=True,
        samesite="Strict",
        path="/web_terminal/endpoint",
    )
    return response


@web_terminal.route("/web_terminal/popout", methods=["GET"])
@login_required
@feature_flag(flag_name="LOGIN_NODES", mode="view")
@feature_flag(flag_name="WEBSHELL", mode="view")
def popout():
    """
    Standalone full-window browser terminal. The inline /ssh page opens this
    URL in a new window when the user clicks 'Pop Out'. Each pop-out carries
    a distinct ?session=popout-N query param so the login node spins up an
    independent tmux session (edh_<user>_popout-N) that is not shared with
    the inline 'main' session.

    Auth is identical to the inline terminal: POST /web_terminal/terminal_auth sets a
    short-lived HttpOnly cookie, then WS connects to /web_terminal/endpoint. The
    WEBSHELL feature flag gates this route for the same subset of users as
    the inline terminal.
    """
    _user = session.get("user", "unknown-user")

    # The session label is echoed into the WS URL client-side. We pass the
    # raw query param through to the template; the login node re-validates
    # it with _SESSION_NAME_RE before use. Default to 'main' so the
    # URL /web_terminal/popout (no query) still works as a standalone terminal.
    # Empty default (not "main") so the popout JS can distinguish "the
    # popout button passed an explicit ?session=<label>" (auto-attach to
    # that tab) from "user opened /web_terminal/popout directly with no session
    # query" (show discovery list, let the user choose).
    _session_label = request.args.get("session", "")
    return render_template(
        "ssh_popout.html",
        user=_user,
        session_label=_session_label,
    )


@web_terminal.route("/web_terminal/sessions", methods=["GET"])
@login_required
@feature_flag(flag_name="LOGIN_NODES", mode="view")
@feature_flag(flag_name="WEBSHELL", mode="view")
def api_sessions():
    """List the logged-in user's tmux webshell sessions across all login nodes.

    The controller fans out an ssm:SendCommand to every running login node
    in the cluster and aggregates the per-instance output. Each returned
    session record includes the originating instance_id so the UI can show
    which node hosts each session.
    """
    _user = session.get("user", "unknown-user")
    if not re.compile(r"^[a-z_][a-z0-9_-]{0,31}$").match(_user):
        # Should never trigger -- session["user"] is set by the auth flow
        # which already validates POSIX-username shape -- but cheap to assert.
        return SocaError.GENERIC_ERROR(
            helper="Invalid User",
            status_code=502,
        ).as_flask()

    _region = SocaConfig(key="/configuration/Region").get_value().get("message")
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    if not _region or not _cluster_id:
        return SocaError.GENERIC_ERROR(
            helper="cluster config not available",
            status_code=502,
        ).as_flask()

    _results = execute_ssm_document(
        node_type="login_node",
        document_name=f"{_cluster_id}-WebshellListSessions",
        parameters={"User": [_user]},
        timeout=30,
        max_attempts=3,
    )

    if _results.get("success") is False:
        # Either no running login nodes, or send_command itself failed.
        # Both are operational errors from the user's perspective.
        return SocaError.GENERIC_ERROR(
            helper="Unable to retrieve sessions: no login nodes available or SSM error",
            status_code=502,
        ).as_flask()

    _sessions: List[dict] = []
    _user_prefix = f"edh_{_user}_"
    for _r in _results.get("message"):
        if _r["status"] != "Success":
            logger.warning(
                f"WebshellListSessions on {_r['instance_id']} status={_r['status']}: "
                f"stderr={_r.get('stderr', '')[:200]}"
            )
            continue
        for _line in _r["stdout"].splitlines():
            _line = _line.strip()
            if not _line:
                continue
            # The SSM document body emits one pipe-separated line per matching
            # tmux session:
            #   <session_name>|<created_unix>|<last_attached_unix>|<attached_0_or_1>|<windows>
            # We re-validate that session_name starts with our edh_<user>_
            # prefix as defence in depth: the document already filters with
            # `grep "^edh_<user>_"`, but if the user's tmux server held some
            # rogue session with a colliding prefix, we still skip it here.
            _parts = _line.split("|")
            if len(_parts) < 5:
                continue
            _name, _created, _last_attached, _attached, _windows = _parts[:5]
            if not _name.startswith(_user_prefix):
                continue
            try:
                _sessions.append(
                    {
                        "label": _name[len(_user_prefix) :],
                        "created_at": int(_created) if _created else 0,
                        "last_attached_at": (
                            int(_last_attached) if _last_attached else 0
                        ),
                        "attached": _attached == "1",
                        "windows": int(_windows) if _windows else 1,
                        "instance_id": _r["instance_id"],
                    }
                )
            except ValueError:
                # Malformed line; skip silently rather than 500 the whole
                # API for one bad row.
                continue

    return SocaResponse(
        success=True,
        message={"sessions": _sessions},
    ).as_flask()


@web_terminal.route("/web_terminal/sessions/kill", methods=["POST"])
@login_required
@feature_flag(flag_name="LOGIN_NODES", mode="view")
@feature_flag(flag_name="WEBSHELL", mode="view")
def api_sessions_kill():
    """Kill a tmux webshell session for the logged-in user.

    Broadcasts the kill to every running login node. The kill SSM document
    is idempotent (tmux kill-session for a non-existent target is a no-op
    that the document body swallows), so broadcasting is safe and saves us
    from having to track which node owns the session in client state.
    """
    _user = session.get("user", "unknown-user")
    if not re.compile(r"^[a-z_][a-z0-9_-]{0,31}$").match(_user):
        return SocaError.GENERIC_ERROR(
            helpoer="Invalid User", status_code=400
        ).as_flask()

    _data = request.get_json(silent=True) or {}
    _label = (_data.get("label") or "").strip()
    if not _label:
        return SocaError.GENERIC_ERROR(
            helpoer="Label is required", status_code=400
        ).as_flask()

    if not re.compile(r"^[a-zA-Z0-9_-]{1,32}$").match(_label):
        return SocaError.GENERIC_ERROR(
            helpoer="Invalid Label", status_code=400
        ).as_flask()

    _region = SocaConfig(key="/configuration/Region").get_value().get("message")
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    if not _region or not _cluster_id:
        return SocaError.GENERIC_ERROR(
            helpoer="cluster config not available", status_code=500
        ).as_flask()

    _results = execute_ssm_document(
        node_type="login_node",
        document_name=f"{_cluster_id}-WebshellKillSession",
        parameters={"User": [_user], "Label": [_label]},
        timeout=30,
        max_attempts=3,
    )

    if _results.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helpoer="No login nodes available", status_code=502
        ).as_flask()

    # Success if at least one login node executed the document successfully.
    # The document is idempotent so a Success status on a node where the
    # session didn't exist is still a correct outcome -- the end state
    # ("session is gone") is what the caller wanted.
    if any(_r["status"] == "Success" for _r in _results.get("message")):
        return SocaResponse(success=True, message="killed").as_flask()

    # All nodes either failed or timed out. Surface the first one's stderr
    # for diagnostics.
    _first = _results.get("message")[0]
    _msg = _first.get("stderr", "").strip() or "kill failed on all nodes"
    return SocaError.GENERIC_ERROR(helpoer=_msg, status_code=502).as_flask()
