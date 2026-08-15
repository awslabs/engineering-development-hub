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
import cognito_auth
from decorators import login_required
from flask import (
    render_template,
    request,
    redirect,
    session,
    flash,
    Blueprint,
    current_app,
    send_from_directory,
)
from requests import post, get
from utils.http_client import SocaHttpClient
from utils.validators import Validators
from urllib.parse import urlparse, urljoin
import re

logger = logging.getLogger("soca_logger")


def validate_safe_redirect(url: str | None) -> str | None:
    """
    Validate that a redirect URL is a safe, same-origin relative path.
    Returns the URL if safe, None otherwise.
    """
    logger.info(f"Received fwd url {url}")
    if not url:
        return None
    _parsed = urlparse(url)
    if _parsed.scheme or _parsed.netloc:
        return None
    
    # Only allow a clean path with safe characters
    if not re.match(r"^/[a-zA-Z0-9_\-./~?&=%#@]*$", url):
        return None
    
    if "/.." in url:
        return None
    return _parsed.path

index = Blueprint("index", __name__, template_folder="templates")


@index.route("/ping", methods=["GET"])
def ping():
    session.clear()
    return "Alive", 200


@index.route("/api/api.json", methods=["GET"])
def api_json():
    return send_from_directory("api/v1", "api.json")


@index.route("/api/doc", methods=["GET"])
def api_docs():
    _default_api_doc_provider = "rapidoc"
    api_doc_provider = request.args.get("ui", _default_api_doc_provider)
    if api_doc_provider not in ["rapidoc", "swagger"]:
        api_doc_provider = _default_api_doc_provider

    return render_template("api_doc.html", api_doc_provider=api_doc_provider)


@index.route("/", methods=["GET"])
@login_required
def home():
    # Honor the user's default landing-page preference: redirect away from the
    # dashboard if they chose a specific page. "home" (default) falls through
    # and renders the dashboard, so there is no redirect loop. Best-effort: any
    # preference-store error leaves the user on the dashboard.
    try:
        from utils import user_pref_store as _user_prefs

        _landing_resp = _user_prefs.resolve_pref(
            session["user"], "default_landing_page"
        )
        _landing = (
            _landing_resp.message.get("value") if _landing_resp.success else None
        )
        _landing_routes = {
            "virtual_desktops": "/virtual_desktops",
            "file_browser": "/file_explorer",
            "jobs": "/submit_job",
            "my_account": "/my_account",
        }
        if _landing in _landing_routes:
            return redirect(_landing_routes[_landing])
    except Exception as _landing_err:
        logger.warning(f"default_landing_page resolve failed: {_landing_err}")

    sudoers = session["sudoers"]
    _custom_links = config.Config.INDEX_PAGE_CUSTOM_LINKS
    _valid_links = []
    if Validators.is_list(value=_custom_links):
        for link in _custom_links:
            if "url" not in link or "text" not in link:
                logger.warning(
                    "One of your custom links is missing required keys 'url' or 'text', ignoring ... "
                )
                continue

            _parsed_url = urlparse(link.get("url"))
            if _parsed_url.scheme.lower() not in ["http", "https"]:
                logger.warning(
                    f"{link.get('url')} is not an HTTP or HTTPS url, ignoring ... "
                )
                continue

            if not _parsed_url.netloc:
                logger.warning(
                    f"{link.get('url')} does not seems to have any netloc, ignoring ... "
                )
                continue

            _valid_links.append(link)
    else:
        _custom_links = []
        logger.warning(
            "config.Config.INDEX_PAGE_CUSTOM_LINKS is not a valid list ignoring ... "
        )

    return render_template("index.html", sudoers=sudoers, custom_links=_valid_links)


@index.route("/login", methods=["GET"])
def login():
    redirect_url = validate_safe_redirect(request.args.get("fwd", None))

    _custom_links = config.Config.LOGIN_PAGE_CUSTOM_LINKS
    _valid_links = []
    if Validators.is_list(value=_custom_links):
        for link in _custom_links:
            if "url" not in link or "text" not in link:
                logger.warning(
                    "One of your custom links is missing required keys 'url' or 'text', ignoring ... "
                )
                continue

            _parsed_url = urlparse(link.get("url"))
            if _parsed_url.scheme.lower() not in ["http", "https"]:
                logger.warning(
                    f"{link.get('url')} is not an HTTP or HTTPS url, ignoring ... "
                )
                continue

            if not _parsed_url.netloc:
                logger.warning(
                    f"{link.get('url')} does not seems to have any netloc, ignoring ... "
                )
                continue

            _valid_links.append(link)
    else:
        _custom_links = []
        logger.warning(
            "config.Config.LOGIN_PAGE_CUSTOM_LINKS is not a valid list ignoring ... "
        )

    if redirect_url is None:
        return render_template("login.html", custom_links=_valid_links, redirect=False)
    else:
        return render_template("login.html", custom_links=_valid_links, redirect=redirect_url)


@index.route("/logout", methods=["POST"])
@login_required
def logout():
    _user = session.get("user", "unknown-user")
    logger.info(f"User {_user} logged out")
    session.clear()
    return redirect("/")


@index.route("/robots.txt", methods=["GET"])
def robots():
    # in case SOCA is accidentally set to wide open, this prevents the website from being indexed on Search Engines
    session.clear()
    return "Disallow: /"


@index.route("/auth", methods=["POST"])
def authenticate():
    """Authenticate a user and establish a Flask session.

    Content-negotiated response shape:
      - Browser callers (default Accept) get the original UX: 302 redirect
        to "/" or `redirect_path` on success, 302 to "/login" with a flash
        on failure. Status codes are 302 in both cases for backwards
        compatibility with the HTML login page.
      - JSON callers (Accept: application/json or X-Requested-With:
        XMLHttpRequest) get real HTTP status codes:
            200 {"success": True, "user": ..., "redirect": ...}     on success
            401 {"success": False, "message": "Invalid credentials"} on bad creds
            400 {"success": False, "message": "user/password required"} on missing fields

    Both paths use the same backend LDAP authentication call, so the only
    difference is the response shape.
    """
    user = request.form.get("user")
    password = request.form.get("password")
    redirect_path = validate_safe_redirect(request.form.get("redirect"))

    _wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    logger.info(f"Received login request for: {user} (json_client={_wants_json})")

    if user is None or password is None:
        if _wants_json:
            return (
                {"success": False, "message": "user and password are required"},
                400,
            )
        return redirect("/login")

    check_auth = SocaHttpClient(
        endpoint="/api/ldap/authenticate",
        headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
    ).post(data={"user": user, "password": password})
    logger.info(f"Check Auth for {user} response: {check_auth}")

    if not check_auth.success:
        if _wants_json:
            return (
                {"success": False, "message": str(check_auth.message)},
                401,
            )
        # i18n: message is a dynamic auth API response — translate at the API layer
        flash(check_auth.message)
        return redirect("/login")

    # Success path — populate the session
    session["user"] = user.lower()
    logger.info("User authenticated, checking sudo permissions")
    check_sudo_permission = SocaHttpClient(
        endpoint="/api/ldap/sudo",
        headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
    ).get(params={"user": user})
    session["sudoers"] = bool(check_sudo_permission.success)

    _target = redirect_path if redirect_path is not None else "/"

    if _wants_json:
        return (
            {
                "success": True,
                "user": session["user"],
                "sudoers": session["sudoers"],
                "redirect": _target,
            },
            200,
        )

    return redirect(_target)


@index.route("/oauth", methods=["GET"])
def oauth():
    next_url = request.args.get("state")
    sso_auth = cognito_auth.sso_authorization(request.args.get("code"))
    cognito_root_url = config.Config.COGNITO_ROOT_URL
    if sso_auth["success"] is True:
        logger.info("User authenticated, checking sudo permissions")
        check_sudo_permission = get(
            config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            params={"user": session["user"]},
            verify=False,
        )  # nosec
        if check_sudo_permission.status_code == 200:
            session["sudoers"] = True
        else:
            session["sudoers"] = False

        if next_url:
            return redirect(cognito_root_url + next_url)
        else:
            return redirect(cognito_root_url)
    else:
        # i18n: message is a dynamic SSO API response — translate at the API layer
        flash(str(sso_auth["message"]), "error")
        return redirect("/login")
