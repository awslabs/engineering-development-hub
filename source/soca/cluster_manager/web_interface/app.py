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

import logging.config

from flask import (
    Flask,
    redirect,
    jsonify,
    flash,
    request,
    session,
    g,
    make_response,
    url_for,
)
from flask_restful import Api
from flask_session import Session
from utils.session_keys import EncryptedSerializer, install_signed_session, ensure_dynamodb_ttl, install_dynamodb_expires_at
from flask_babel import Babel, gettext as _
from werkzeug.debug import DebuggedApplication
from urllib.parse import urlparse
import validators

from api.v1.scheduler.job import Job
from api.v1.scheduler.jobs import Jobs

from api.v1.ldap.sudo import Sudo
from api.v1.ldap.ids import Ids
from api.v1.ldap.user import User
from api.v1.ldap.users import Users
from api.v1.ldap.group import Group
from api.v1.ldap.groups import Groups
from api.v1.ldap.authenticate import Authenticate
from api.v1.login_nodes.list import ListLoginNodes
from api.v1.system.files import Files
from api.v1.ai_assistant.converse import AiAssistantConverse
from api.v1.ai_assistant.converse_stream import AiAssistantConverseStream
from api.v1.ai_assistant.usage import AiAssistantUsage
from api.v1.ai_assistant.mcp_servers import AiAssistantMcpServers

from api.v1.user.resources_permissions import GetUserResourcesPermissions
from api.v1.user.run_command import RunRemoteCommand
from api.v1.user.preferences import UserPreferences
from api.v1.user.api_key import ApiKey
from api.v1.token.user_tokens import UserTokens
from api.v1.token.user_token_detail import UserTokenDetail
from api.v1.token.user_token_renew import UserTokenRenew
from api.v1.token.user_token_policy import UserTokenPolicy
from api.v1.token.user_token_authenticate import UserTokenAuthenticate

from api.v1.cost_management.pricing import AwsPrice
from api.v1.cost_management.budget import AwsBudgetInfo
from api.v1.cost_management.budgets import AwsBudgets

from api.v1.dcv.authenticator import DcvAuthenticator
from api.v1.dcv.session_event import DcvSessionEvent, DcvSessionEventRotationTest
from api.v1.dcv.event_stream import DcvEventStream, DcvEventStreamSession
from api.v1.dcv.create_virtual_desktop import CreateVirtualDesktop
from api.v1.admin.bootstrap_cache import (
    BootstrapCacheStatus,
    BootstrapCacheRefresh,
)
from api.v1.dcv.get_connection_file import GetVirtualDesktopConnectionFile
from api.v1.dcv.list_virtual_desktops import ListVirtualDesktops
from api.v1.dcv.list_all_virtual_desktops import ListAllVirtualDesktops
from api.v1.dcv.delete_virtual_desktop import DeleteVirtualDesktop
from api.v1.dcv.stop_virtual_desktop import StopVirtualDesktop
from api.v1.dcv.save_and_shutdown import SaveAndShutdown
from api.v1.dcv.resume_saved_desktop import ResumeSavedDesktop, VdiResumeOptions
from api.v1.dcv.saved_desktop_lifecycle import RecycleSavedDesktop, RecoverSavedDesktop
from api.v1.dcv.saved_images_progress import SavedImagesProgress
from api.v1.dcv.start_virtual_desktop import StartVirtualDesktop
from api.v1.dcv.resize_virtual_desktop import ResizeVirtualDesktop
from api.v1.dcv.update_virtual_desktop_schedule import UpdateVirtualDesktopSchedule
from api.v1.dcv.get_virtual_desktops_session_state import GetVirtualDesktopsSessionState
from api.v1.dcv.software_stacks import SoftwareStacksManager
from api.v1.dcv.golden_images import (
    GoldenImageNominate,
    GoldenImageNominations,
    GoldenImageApprove,
    GoldenImageReject,
    GoldenImagePublish,
    GoldenImageRollback,
    GoldenImageVersions,
)
from api.v1.dcv.base_image_status import BaseImageStatusManager
from api.v1.dcv.pool import VdiPoolManager, VdiPoolSpecRefresh
from api.v1.dcv.pool_availability import VdiPoolAvailability
from api.v1.dcv.instance_type_specs import VdiInstanceTypeSpecs
from api.v1.dcv.instance_type_search import VdiInstanceTypeSearch
from api.v1.dcv.profiles import VirtualDesktopProfilesManager
from api.v1.dcv.usb_profiles import (
    UsbProfilesManager,
    UsbProfileDetail,
    UsbProfileEntriesManager,
    UsbProfileEntryDetail,
    UsbFilterStringParse,
)
from api.v1.token.admin_tokens import AdminTokens
from api.v1.token.admin_token_create import AdminTokenCreate
from api.v1.token.admin_token_revoke import AdminTokenRevoke
from api.v1.token.admin_audit_log import AdminAuditLog
from api.v1.token.admin_token_policy import AdminTokenPolicy
from api.v1.admin.config_editor import (
    ConfigTree,
    ConfigParams,
    ConfigParamDetail,
    ConfigSearch,
    ConfigHistory,
    ConfigBatch,
    ConfigActivity,
)
from api.v1.dcv.hardware_profiles import (
    HardwareProfilesManager,
    HardwareProfileDetail,
    HardwareProfileBinding,
    HardwareProfileBindingsList,
    HardwareProfileSubProfileTypes,
    HardwareProfilePreview,
)
from api.v1.dcv.virtual_desktop_screenshot import VirtualDesktopScreenshot
from api.v1.dcv.dcv_session_sharing import (
    DcvSessionSharingProfiles,
    DcvSessionSharingProfileDetail,
    DcvSessionSharingGrants,
    DcvSessionSharingGrantDetail,
    DcvSessionSharingSharedToMe,
    DcvSessionSharingUserSearch,
    DcvSessionSharingAdminSessions,
    DcvSessionSharingSettings,
)
from api.v1.dcv.dcv_session_sharing_connect import (
    DcvSessionSharingConnect,
    DcvSessionSharingConnectNonce,
    DcvSessionSharingLink,
)

from api.v1.projects.projects import ProjectsManager

from api.v1.applications.list_applications import ListApplications
from api.v1.applications.application import Application
from api.v1.applications.export_application import ExportApplication
from api.v1.applications.import_application import ImportApplication

from api.v1.target_nodes.create_target_node import CreateTargetNode
from api.v1.target_nodes.user_data import TargetNodeUserDataManager
from api.v1.target_nodes.software_stacks import TargetNodeSoftwareStacksManager
from api.v1.target_nodes.profiles import TargetNodeProfilesManager
from api.v1.target_nodes.delete_target_node import DeleteTargetNode
from api.v1.target_nodes.list_target_node import ListTargetNode
from api.v1.target_nodes.stop_target_node import StopTargetNode
from api.v1.target_nodes.start_target_node import StartTargetNode
from api.v1.target_nodes.get_target_node_session_state import GetTargetNodeSessionState
from api.v1.target_nodes.update_target_node_schedule import UpdateTargetNodeSchedule
from api.v1.target_nodes.resize_target_node import ResizeTargetNode

from api.v1.containers.ecr.repository import ECRRepository
from api.v1.containers.eks.list_clusters import EKSListClusters
from api.v1.containers.eks.job import EKSJob
from api.v1.containers.eks.jobs import EKSJobs

from api.v1.containers.batch.job_queue import BatchJobQueue
from api.v1.containers.batch.job_definition import BatchJobDefinition
from api.v1.containers.batch.job import BatchJob
from api.v1.containers.batch.jobs import BatchJobs

from views.index import index
from views.ssh import ssh
from views.web_terminal import web_terminal
from views.my_api_key import my_api_key
from views.my_api_tokens import my_api_tokens
from views.admin.users import admin_users
from views.admin.groups import admin_groups
from views.admin.applications import admin_applications
from views.admin.virtual_desktops.software_stacks import (
    admin_virtual_desktops_software_stacks,
)
from views.admin.virtual_desktops.base_image_acceleration import (
    admin_base_image_acceleration,
)
from views.admin.virtual_desktops.profiles import admin_virtual_desktops_profiles
from views.admin.virtual_desktops.session_sharing import admin_virtual_desktops_session_sharing
from views.admin.virtual_desktops.hardware_profiles import admin_virtual_desktops_hardware_profiles
from views.admin.virtual_desktops.golden_images import admin_golden_images
from views.admin.config.config_editor import admin_config_editor
from views.admin.virtual_desktops.list_all_virtual_desktops import (
    admin_virtual_desktops_list_all,
)
from views.admin.cluster_status.dcv_overview import admin_cluster_status_dcv_overview
from views.admin.projects.projects import admin_projects

from views.admin.target_nodes.user_data import admin_target_nodes_user_data
from views.admin.target_nodes.software_stacks import admin_target_nodes_software_stacks
from views.admin.target_nodes.profiles import admin_target_nodes_profiles
from views.admin.token_audit import admin_token_audit

from views.my_jobs import my_jobs
from views.my_activity import my_activity
from views.virtual_desktops import virtual_desktops
from views.my_account import my_account
from views.file_explorer import file_explorer
from views.tail import tail
from views.ai_assistant import ai_assistant
from views.submit_job import submit_job
from views.target_nodes import target_nodes
from views.containers.ecr_images import ecr_images
from views.containers.containers_eks import containers_eks
from views.containers.containers_batch import containers_batch


from flask_wtf.csrf import CSRFProtect, CSRFError
from config import app_config

import config

if config.Config.DIRECTORY_AUTH_PROVIDER in [
    "aws_ds_managed_activedirectory",
]:
    from api.v1.ldap.activedirectory.reset_password import Reset
else:
    from api.v1.ldap.reset_password import Reset
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

import soca_samples
import os
import stat
import sys
from utils.logger import SocaLogger
import json

from extensions import db, scheduler
import feature_flags

app = Flask(__name__)

# i18n configuration
LANGUAGES = {
    "en": {"name": "English", "flag": "🇺🇸"},
    "es": {"name": "Español", "flag": "🇪🇸", "review_needed": True},
    "es_MX": {"name": "Español (México)", "flag": "🇲🇽", "review_needed": True},
    "de": {"name": "Deutsch", "flag": "🇩🇪", "review_needed": True},
    "ja": {"name": "日本語", "flag": "🇯🇵", "review_needed": True},
    "ko": {"name": "한국어", "flag": "🇰🇷", "review_needed": True},
    "fr": {"name": "Français", "flag": "🇫🇷", "review_needed": True},
    "pt": {"name": "Português", "flag": "🇧🇷", "review_needed": True},
    "zh": {"name": "简体中文", "flag": "🇨🇳", "review_needed": True},
    "zh_TW": {"name": "繁體中文", "flag": "🇹🇼", "review_needed": True},
    "hi": {"name": "हिन्दी", "flag": "🇮🇳", "review_needed": True},
    "it": {"name": "Italiano", "flag": "🇮🇹", "review_needed": True},
}
app.config["BABEL_DEFAULT_LOCALE"] = "en"
app.config["BABEL_TRANSLATION_DIRECTORIES"] = "translations"


def _safe_referrer(default: str = "/") -> str:
    """Return request.referrer if it is same-origin as the current request,
    else the fallback. Prevents open-redirect via spoofed Referer header.

    Logs at ERROR level when a cross-origin Referer is detected and discarded
    so a SOC can detect open-redirect probing attempts against SOCA.
    """
    ref = request.referrer
    if not ref:
        return default
    try:
        parsed = urlparse(ref)
    except ValueError:
        app.logger.error(
            "open-redirect attempt: unparseable Referer from %s to %s (Referer=%r, User-Agent=%r)",
            request.remote_addr,
            request.path,
            ref,
            request.headers.get("User-Agent", ""),
        )
        return default
    # Same-origin: either no netloc (relative) or netloc matches current host.
    if parsed.netloc and parsed.netloc != request.host:
        app.logger.error(
            "open-redirect attempt: cross-origin Referer rejected. "
            "src_ip=%s path=%s host=%s referer_host=%s user=%s user_agent=%r",
            request.remote_addr,
            request.path,
            request.host,
            parsed.netloc,
            session.get("user", "<anonymous>"),
            request.headers.get("User-Agent", ""),
        )
        return default
    return ref


@app.before_request
def _apply_pref_recovery_params():
    # One-shot login recovery for lockout-class prefs (decision #9 / §9).
    #   ?noprefs    -> ignore the stored row for THIS render (non-destructive);
    #                  get_raw_row returns {} so every pref resolves to its
    #                  admin/code default -- restores a usable UI to fix a bad pref.
    #   ?resetprefs -> clear_all (delete the row) then render from defaults.
    # Never sticky: read from request.args each request, no session writes, so a
    # plain navigation without the param restores normal pref resolution.
    if "noprefs" not in request.args and "resetprefs" not in request.args:
        return
    g._skip_user_prefs = True
    if "resetprefs" in request.args:
        _user = session.get("user")
        if _user:
            try:
                from utils import user_pref_store as _prefs

                _prefs.clear_all(_user)
            except Exception as _err:
                logger.warning(
                    "?resetprefs clear_all failed for %s: %s", _user, _err
                )


@app.before_request
def _start_request_timer():
    import time
    import uuid as _uuid
    g._request_start = time.monotonic()
    g.request_id = str(_uuid.uuid4())[:8]
    g.authenticated_user = None
    g.token_id = None
    g.token_name = None
    g.token_type = None
    g.actor_type = None
    g.source_ref = None
    g.auth_denied_reason = None


@app.after_request
def _write_audit_log(response):
    if not request.path.startswith("/api/"):
        return response
    if request.path == "/api/admin/audit" and request.args.get("since_id") is not None:
        return response
    import time
    from utils.token_service import write_audit_log
    duration_ms = int((time.monotonic() - g.get("_request_start", time.monotonic())) * 1000)
    g.request_duration_ms = duration_ms
    user = g.get("authenticated_user") or request.headers.get("X-EDH-USER") or session.get("user") or "anonymous"
    write_audit_log(
        user=user,
        status_code=response.status_code,
        denied_reason=g.get("auth_denied_reason"),
    )
    return response


def get_locale():
    # Resolved once per request (Flask-Babel calls this as the locale selector,
    # and a couple of views call it directly). Memoized on flask.g so the
    # stored-preference lookup costs at most one DynamoDB GetItem per request.
    if hasattr(g, "_resolved_locale"):
        return g._resolved_locale
    _loc = _resolve_locale()
    g._resolved_locale = _loc
    return _loc


def _resolve_locale():
    _cookie = request.cookies.get("lang")

    # 1. Stored user preference (authenticated users only) -- the cross-browser
    #    source of truth for language. Wrapped so a DynamoDB hiccup degrades
    #    gracefully to the legacy cookie / Accept-Language chain.
    _user = session.get("user")
    if _user and not getattr(g, "_skip_user_prefs", False):
        try:
            from utils import user_pref_store as _prefs

            _pref_resp = _prefs.resolve_pref(_user, "language")
            _pref = _pref_resp.message if _pref_resp.success else {}
            if _pref.get("is_set") and _pref.get("value") in LANGUAGES:
                return _pref["value"]
            # Lazy one-shot migration: a returning user with a legacy `lang`
            # cookie but no stored pref -- adopt their prior choice into the
            # store once; the pref is authoritative thereafter.
            if _cookie and _cookie in LANGUAGES:
                _prefs.set_pref(_user, "language", _cookie)
                return _cookie
        except Exception as _err:
            logger.warning(
                "language preference resolve failed for %s: %s", _user, _err
            )

    # 2. Explicit `lang` cookie (anonymous/pre-auth, or authed user mid-migration)
    if _cookie and _cookie in LANGUAGES:
        return _cookie

    # 3. API requests (X-EDH-USER present): honor Accept-Language if config allows
    if config.Config.LOCALIZE_API_RESPONSES and request.headers.get("X-EDH-USER"):
        api_lang = request.accept_languages.best_match(LANGUAGES.keys())
        if api_lang:
            return api_lang

    # 4. Browser auto-detect / default
    return request.accept_languages.best_match(LANGUAGES.keys(), default="en")


babel = Babel(app, locale_selector=get_locale)


@app.route("/lang/<lang>")
def set_language(lang):
    if lang not in LANGUAGES:
        lang = "en"

    # Persist to the user's stored preferences (cross-browser) when
    # authenticated, alongside the cookie. Best-effort: the cookie write below
    # always happens, so the selection still takes effect if the store errors.
    _user = session.get("user")
    if _user:
        try:
            from utils import user_pref_store as _prefs

            _prefs.set_pref(_user, "language", lang)
        except Exception as _err:
            logger.warning(
                "failed to persist language preference for %s: %s", _user, _err
            )

    target = _safe_referrer("/")
    if request.args.get("beta") == "1":
        separator = "&" if "?" in target else "?"
        target = f"{target}{separator}beta=1"
    response = make_response(redirect(target))
    response.set_cookie("lang", lang, max_age=60 * 60 * 24 * 365)
    return response


# Custom Jinja2 filters
@app.template_filter("folder_name_truncate")
def folder_name_truncate(folder_name):
    # This make sure folders with long name on /file_explorer are displayed correctly
    if folder_name.__len__() < 20:
        return folder_name
    else:
        split_number = [20, 40, 60]
        for number in split_number:
            try:
                if (
                    folder_name[number] != "-"
                    and folder_name[number - 1] != "-"
                    and folder_name[number + 1] != "-"
                ):
                    folder_name = folder_name[:number] + "-" + folder_name[number:]
            except IndexError:
                break
        return folder_name


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Return a clear, cause-specific error for CSRF failures.

    Flask-WTF's CSRFError carries `e.description` with the actual reason —
    "The CSRF token is missing.", "The CSRF token is invalid.", "The
    referrer does not match the host." etc. Forward that verbatim so
    operators (and humans reading the flash) can tell the four root causes
    apart instead of seeing a single misleading "token expired" message.

    Content-negotiated: programmatic callers (Accept: application/json
    or X-Requested-With: XMLHttpRequest) get a structured 403 JSON body
    so they can act on the failure. Browsers continue to get the
    flash-and-redirect UX they had before.
    """
    _reason = getattr(e, "description", None) or "CSRF validation failed"
    
    # Rewrite technical CSRF errors into user-friendly messages.
    # Token expiration is the most common case (idle session timeout).
    if _reason == "The CSRF token has expired.":
        _reason = "Token has expired. As a security measure we have refreshed your token. Please re-submit your request again."
    
    _wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )
    if _wants_json:
        return (
            {"success": False, "message": _reason, "code": "CSRF_REJECTED"},
            403,
        )
    flash(_(_reason), "warning")
    return redirect(_safe_referrer("/"))


@app.context_processor
def inject_global_template_variables():
    _global_variables = {}
    _amazon_q_business_url = config.Config.AMAZON_Q_BUSINESS_URL
    if validators.url(_amazon_q_business_url) is True:
        _global_variables["AMAZON_Q_BUSINESS_URL"] = _amazon_q_business_url
    else:
        app.logger.debug(
            "AMAZON_Q_BUSINESS_URL is not a valid URL, default value to False"
        )
        _global_variables["AMAZON_Q_BUSINESS_URL"] = False
    _global_variables["CURRENT_PATH"] = request.path
    return _global_variables


@app.template_filter("from_json")
def from_json(value):
    """Custom filter to parse JSON string into a Python dict."""
    return json.loads(value)


app.jinja_env.filters["from_json"] = from_json
app.jinja_env.filters["folder_name_truncate"] = folder_name_truncate
app.jinja_env.add_extension("jinja2.ext.do")
app.jinja_env.add_extension("jinja2.ext.i18n")
# Collapse internal whitespace/newlines inside {% trans %} blocks before
# extraction. Lets templates indent multi-line strings for readability without
# leaking whitespace into msgids. See docs/I18n.md §5.6 and §12.1.
app.jinja_env.policies["ext.i18n.trimmed"] = True

# Locale-aware Markdown content loader (docs/I18n.md § 12.8).
# Use `{{ localized_markdown("name") | safe }}` in templates to embed
# multi-paragraph prose that is stored under web_interface/content/name.<locale>.md
# instead of hundreds of sentence-fragment msgids in the gettext catalog.
from helpers.content_loader import render_localized_markdown as _render_md  # noqa: E402


def _localized_markdown(name: str) -> str:
    try:
        return _render_md(name, get_locale())
    except Exception:  # pragma: no cover — never fail a render because of doc content
        app.logger.exception("localized_markdown(%r) failed", name)
        return ""


app.jinja_env.globals["localized_markdown"] = _localized_markdown


@app.errorhandler(404)
def page_not_found(_e):
    return redirect("/")


@app.context_processor
def inject_globals():
    # Variables available on all templates
    return {
        "feature_flags": feature_flags.get_effective_flags().get("message"),
        "admin": session.get("sudoers", False),
        "user": session.get("user", ""),
        "languages": LANGUAGES,
        "current_lang": get_locale(),
    }


def setup_logger(name: str, file_path: str):
    _log_folder = os.path.dirname(file_path)
    os.makedirs(_log_folder, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(_log_folder):
        os.chmod(dirpath, 0o750)

    logger = SocaLogger(name=name).timed_rotating_file_handler(
        file_path=file_path,
        backup_count=config.Config.LOG_DAILY_BACKUP_COUNT,
    )
    app.logger.addHandler(logging.getLogger(name))


logger = logging.getLogger("soca_logger")


def _ensure_iam_app_user():
    """
    Aurora IAM-auth bootstrap (BSC5): ensure the dedicated rds_iam application
    role exists BEFORE the runtime pool -- which authenticates as that role with
    short-lived IAM tokens (see config.py do_connect listener) -- connects and
    runs db.create_all().

    Connects ONCE as the admin user (DatabaseAdminSecret secret). This is the ONLY
    place the admin credential is used at runtime; the long-lived app pool never
    touches it. Idempotently:
      * creates the <app_user> LOGIN role,
      * GRANT rds_iam (so it can authenticate via IAM tokens, not a password),
      * grants DB + public-schema privileges and transfers public ownership so
        db.create_all() DDL and runtime CRUD both succeed as <app_user>.

    No-op unless provider == aurora_serverless_v2 AND iam_auth is true (i.e.
    sqlite or the password-fallback path -- where admin IS the runtime user --
    need no separate role). Any failure is fatal (SystemExit): a missing app role
    means the IAM pool cannot connect at all, so failing loudly beats a confusing
    connect-retry loop with an unhelpful auth error.
    """
    import re
    import time as _time
    from utils.config import SocaConfig
    from utils.aws.secretsmanager_client import SocaSecret
    from utils.cast import SocaCastEngine

    def _ssm(_key):
        return SocaConfig(key=_key).get_value().get("message")

    _provider = _ssm("/configuration/Database/provider")
    if (
        _provider is None
        or "CACHE_MISS" in str(_provider)
        or str(_provider).strip() != "aurora_serverless_v2"
    ):
        return  # sqlite / non-aurora provider -- nothing to bootstrap

    # iam_auth defaults to True for the aurora provider unless explicitly false.
    _iam_auth = True
    _iam_raw = _ssm("/configuration/Database/iam_auth")
    if _iam_raw not in (None, "") and "CACHE_MISS" not in str(_iam_raw):
        _cast = SocaCastEngine(data=_iam_raw).cast_as(bool)
        if _cast.get("success"):
            _iam_auth = _cast.get("message") is True
    if not _iam_auth:
        return  # password-fallback mode: admin IS the runtime user, no app role

    _app_user = _ssm("/configuration/Database/app_user") or "edh_app"
    _endpoint = _ssm("/configuration/Database/endpoint")
    _port = _ssm("/configuration/Database/port")
    _database = _ssm("/configuration/Database/name")

    # app_user / database come from SSM and are interpolated into DDL that has no
    # bind parameters -- validate them as plain SQL identifiers (defense in depth).
    _ident = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not _ident.match(str(_app_user)):
        logger.critical(
            f"IAM app-user bootstrap: unsafe app_user identifier "
            f"'{_app_user}'. Web app will not start.\n"
        )
        raise SystemExit(2)
    if not (_endpoint and _port and _database and _ident.match(str(_database))):
        logger.critical(
            "IAM app-user bootstrap: endpoint/port/name missing or invalid "
            "in SSM. Web app will not start.\n"
        )
        raise SystemExit(2)

    _port_cast = SocaCastEngine(data=_port).cast_as(int)
    if _port_cast.get("success") is not True:
        logger.critical(
            f"IAM app-user bootstrap: invalid Database/port '{_port}' in SSM. "
            "Web app will not start.\n"
        )
        raise SystemExit(2)
    _port = _port_cast.get("message")

    try:
        _secret_resp = SocaSecret(secret_id="DatabaseAdminSecret").get_secret()
    except Exception as _e:
        logger.critical(
            f"IAM app-user bootstrap: exception fetching DatabaseAdminSecret "
            f"secret ({_e}). Web app will not start.\n"
        )
        raise SystemExit(2)
    if not _secret_resp.success:
        logger.critical(
            f"IAM app-user bootstrap: could not fetch DatabaseAdminSecret secret: "
            f"{_secret_resp.message}. Web app will not start.\n"
        )
        raise SystemExit(2)
    _creds = _secret_resp.message
    _admin_user = _creds.get("username")
    _admin_pw = _creds.get("password")
    if not (_admin_user and _admin_pw):
        logger.critical(
            "IAM app-user bootstrap: DatabaseAdminSecret secret missing "
            "username/password. Web app will not start.\n"
        )
        raise SystemExit(2)

    import psycopg

    # Aurora can still be warming up right after a fresh deploy -- retry the admin
    # connect with the same ~5 min budget as db.create_all().
    _conn = None
    _max_attempts = 30  # ~5 min @ 10s
    for _attempt in range(1, _max_attempts + 1):
        try:
            _conn = psycopg.connect(
                host=_endpoint,
                port=_port,
                dbname=_database,
                user=_admin_user,
                password=_admin_pw,
                sslmode="require",
                connect_timeout=10,
            )
            break
        except psycopg.OperationalError as _e:
            if _attempt == _max_attempts:
                logger.critical(
                    f"IAM app-user bootstrap: could not connect as admin "
                    f"after {_max_attempts} attempts (~5 min). Last error: {_e}. "
                    "Web app will not start.\n"
                )
                raise SystemExit(2)
            logger.warning(
                f"IAM app-user bootstrap: admin connect attempt "
                f"{_attempt}/{_max_attempts} failed ({type(_e).__name__}); "
                "retrying in 10s...\n"
            )
            _time.sleep(10)

    try:
        _conn.autocommit = True
        with _conn.cursor() as _cur:
            # Idempotent role creation -- CREATE ROLE has no IF NOT EXISTS.
            _cur.execute(
                "DO $$ BEGIN "
                f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{_app_user}') "
                f"THEN CREATE ROLE {_app_user} WITH LOGIN; END IF; END $$;"
            )
            # IAM authentication: membership in rds_iam lets the role authenticate
            # with generate_db_auth_token instead of a password.
            _cur.execute(f"GRANT rds_iam TO {_app_user};")
            _cur.execute(
                f'GRANT ALL PRIVILEGES ON DATABASE "{_database}" TO {_app_user};'
            )
            _cur.execute(f"GRANT ALL ON SCHEMA public TO {_app_user};")
            # Transfer public-schema ownership so create_all DDL (and future
            # migrations) run cleanly as the app user. admin owns public on a
            # fresh cluster, so this succeeds; it is idempotent on re-run.
            _cur.execute(f"ALTER SCHEMA public OWNER TO {_app_user};")
            # Migration case: if the DB was previously populated by the admin
            # user (existing cluster switching to IAM), the pre-existing tables
            # and sequences are owned by admin -- grant the app user full access
            # to them, plus default privileges for anything admin creates later.
            # On a fresh cluster these grant over zero objects (harmless no-op);
            # tables created later by create_all are owned by app_user directly.
            _cur.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA public TO {_app_user};")
            _cur.execute(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {_app_user};")
            _cur.execute(
                f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                f"GRANT ALL ON TABLES TO {_app_user};"
            )
            _cur.execute(
                f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                f"GRANT ALL ON SEQUENCES TO {_app_user};"
            )
        logger.info(
            f"IAM app-user bootstrap: role '{_app_user}' ensured "
            "(rds_iam granted, public schema owned).\n"
        )
    finally:
        _conn.close()


def _warm_db_pool():
    """
    Eagerly open and return `pool_size` connections so the SQLAlchemy pool is
    warm before the first user request. Under IAM auth, establishing a NEW
    connection is expensive (~1.6s cold: token-validated TLS handshake), so we
    pay that cost here, off the request path. Each engine.connect() fires the
    db_iam_auth do_connect listener (minting an IAM token) and completes the
    full handshake; closing returns the connection to the pool warm rather than
    destroying it. No-op for non-PostgreSQL engines (e.g. legacy SQLite).

    Stagger: each worker waits a small random jitter before warming so N workers
    do not open N*pool_size cold connections simultaneously (a 0.5-ACU serverless
    floor can push back with "SSL: unexpected eof" under that burst).
    Retry: each connection is attempted up to 3x with backoff.
    Telemetry: per-connection establish time (ms) -- the first per worker is the
    cold IAM connect (~1.6s), the rest warm (~tens of ms) -- plus a summary line.
    Best-effort: any failure is logged and swallowed -- warming must never block
    or kill a worker (pool_pre_ping covers correctness on lazy reconnect).
    """
    import time as _time
    import random as _random

    try:
        with app.app_context():
            _engine = db.engine
            if not _engine.url.drivername.startswith("postgresql"):
                return  # sqlite / non-aurora -- nothing to warm
            _n = (app.config.get("SQLALCHEMY_ENGINE_OPTIONS", {}) or {}).get(
                "pool_size", 5
            )
            _jitter = _random.uniform(0, 5.0)
            _time.sleep(_jitter)

            _conns = []
            _ok = 0
            _t0 = _time.time()
            for _i in range(_n):
                for _attempt in range(1, 4):  # up to 3 attempts per connection
                    _ct = _time.time()
                    try:
                        _c = _engine.connect()
                        _c.exec_driver_sql("SELECT 1")
                        _conns.append(_c)
                        _ok += 1
                        logger.info(
                            f"warm conn {_i + 1}/{_n} established in "
                            f"{(_time.time() - _ct) * 1000:.0f}ms "
                            f"(attempt {_attempt}).\n"
                        )
                        break
                    except Exception as _e:
                        logger.warning(
                            f"warm conn {_i + 1}/{_n} attempt {_attempt} "
                            f"failed in {(_time.time() - _ct) * 1000:.0f}ms "
                            f"({type(_e).__name__}: {_e}).\n"
                        )
                        if _attempt < 3:
                            _time.sleep(min(2 ** (_attempt - 1), 4))  # 1s, 2s
            # Return warmed connections to the pool (idle, reusable) rather than
            # destroying them.
            for _c in _conns:
                try:
                    _c.close()
                except Exception:
                    pass
            logger.info(
                f"DB pool warm complete: {_ok}/{_n} connections in "
                f"{_time.time() - _t0:.2f}s (jitter {_jitter:.1f}s).\n"
            )
    except Exception as _e:
        logger.warning(f"DB pool warm skipped ({type(_e).__name__}: {_e}).\n")


# uwsgi forks workers AFTER the app is imported, and connections opened before
# the fork are invalid in the children. So warm each worker's pool AFTER the
# fork, on a daemon thread (non-blocking to worker startup). When not running
# under uwsgi (e.g. local `flask run`), the import fails and we simply skip --
# pool_pre_ping still covers correctness; only the pre-warm optimization is lost.
import threading

try:
    from uwsgidecorators import postfork
except ImportError:
    postfork = None

if postfork is not None:

    @postfork
    def _warm_db_pool_postfork():
        threading.Thread(
            target=_warm_db_pool, name="db-pool-warm", daemon=True
        ).start()


with app.app_context():
    csrf = CSRFProtect(app)
    csrf.exempt("api")

    # Register configuration
    app.config.from_object(app_config)

    # Validate feature-flag configuration once at startup. Any misconfig
    # (unknown parent flag, cycle, malformed depends_on) is logged as a
    # warning so operators see the problem in the server log rather than
    # chasing "feature unavailable" errors in the UI. Non-fatal -- the
    # runtime @feature_flag decorator handles every edge case safely.
    feature_flags.validate_feature_flags()

    if app_config.DEBUG is True:
        app.debug = True
        app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

    # Add API
    api = Api(app, decorators=[csrf.exempt])

    # Auth provider can be either openldap, or activedirectory
    api.add_resource(Sudo, "/api/ldap/sudo")
    api.add_resource(Authenticate, "/api/ldap/authenticate")
    api.add_resource(Ids, "/api/ldap/ids")
    api.add_resource(User, "/api/ldap/user")
    api.add_resource(Users, "/api/ldap/users")
    api.add_resource(Group, "/api/ldap/group")
    api.add_resource(Groups, "/api/ldap/groups")
    # Users
    api.add_resource(Reset, "/api/user/reset_password")
    api.add_resource(GetUserResourcesPermissions, "/api/user/resources_permissions")
    api.add_resource(RunRemoteCommand, "/api/user/run_command")
    api.add_resource(
        UserPreferences,
        "/api/user/preferences",
        "/api/user/preferences/<string:key>",
    )
    # Scoped API Tokens
    api.add_resource(ApiKey, "/api/user/api_key")
    api.add_resource(UserTokens, "/api/user/tokens")
    api.add_resource(UserTokenDetail, "/api/user/tokens/<int:token_id>")
    api.add_resource(UserTokenRenew, "/api/user/tokens/<int:token_id>/renew")
    api.add_resource(UserTokenPolicy, "/api/user/tokens/policy")
    api.add_resource(UserTokenAuthenticate, "/api/user/tokens/authenticate")
    api.add_resource(AdminTokens, "/api/admin/tokens")
    api.add_resource(AdminTokenCreate, "/api/admin/tokens/<string:target_user>")
    api.add_resource(AdminTokenRevoke, "/api/admin/tokens/<string:target_user>/<int:token_id>")
    api.add_resource(AdminAuditLog, "/api/admin/audit")
    api.add_resource(AdminTokenPolicy, "/api/admin/tokens/policy")

    # System
    api.add_resource(Files, "/api/system/files")

    # AI Assistant
    api.add_resource(AiAssistantConverse, "/api/ai_assistant/converse")
    api.add_resource(AiAssistantConverseStream, "/api/ai_assistant/converse/stream")
    api.add_resource(AiAssistantUsage, "/api/ai_assistant/usage")
    api.add_resource(AiAssistantMcpServers, "/api/ai_assistant/mcp_servers")

    # Cost Management
    api.add_resource(AwsPrice, "/api/cost_management/pricing")
    api.add_resource(AwsBudgetInfo, "/api/cost_management/budget")
    api.add_resource(AwsBudgets, "/api/cost_management/budgets")

    # Containers
    api.add_resource(ECRRepository, "/api/containers/ecr/repository")
    api.add_resource(EKSListClusters, "/api/containers/eks/list_clusters")
    api.add_resource(EKSJob, "/api/containers/eks/job")
    api.add_resource(EKSJobs, "/api/containers/eks/jobs")
    api.add_resource(BatchJobQueue, "/api/containers/batch/job_queue")
    api.add_resource(BatchJobDefinition, "/api/containers/batch/job_definition")
    api.add_resource(BatchJob, "/api/containers/batch/job")
    api.add_resource(BatchJobs, "/api/containers/batch/jobs")

    # DCV
    api.add_resource(DcvAuthenticator, "/api/dcv/authenticator")
    api.add_resource(DcvSessionEvent, "/api/dcv/session-event")
    api.add_resource(DcvSessionEventRotationTest, "/api/dcv/session-event-rotation-test")
    # SSE streams. Both routes return text/event-stream with Last-Event-ID
    # resume support. The /events/stream route is multiplexed (all the
    # caller's owned sessions); /events/stream/<uuid> is single-session
    # with initial history replay.
    api.add_resource(DcvEventStream, "/api/dcv/events/stream")
    api.add_resource(DcvEventStreamSession, "/api/dcv/events/stream/<string:session_uuid>")
    api.add_resource(ListVirtualDesktops, "/api/dcv/virtual_desktops/list")
    api.add_resource(ListAllVirtualDesktops, "/api/dcv/virtual_desktops/list_all")
    api.add_resource(CreateVirtualDesktop, "/api/dcv/virtual_desktops/create")
    api.add_resource(BootstrapCacheStatus, "/api/admin/bootstrap_cache")
    api.add_resource(BootstrapCacheRefresh, "/api/admin/bootstrap_cache/refresh")
    api.add_resource(DeleteVirtualDesktop, "/api/dcv/virtual_desktops/delete")
    api.add_resource(StopVirtualDesktop, "/api/dcv/virtual_desktops/stop")
    api.add_resource(SaveAndShutdown, "/api/dcv/virtual_desktops/save_and_shutdown")
    api.add_resource(ResumeSavedDesktop, "/api/dcv/virtual_desktops/resume_saved_desktop")
    api.add_resource(VdiResumeOptions, "/api/dcv/virtual_desktops/resume_options")
    api.add_resource(SavedImagesProgress, "/api/dcv/virtual_desktops/saved_images_progress")
    api.add_resource(RecycleSavedDesktop, "/api/dcv/virtual_desktops/recycle_saved_desktop")
    api.add_resource(RecoverSavedDesktop, "/api/dcv/virtual_desktops/recover_saved_desktop")
    api.add_resource(StartVirtualDesktop, "/api/dcv/virtual_desktops/start")
    api.add_resource(ResizeVirtualDesktop, "/api/dcv/virtual_desktops/resize")
    api.add_resource(UpdateVirtualDesktopSchedule, "/api/dcv/virtual_desktops/schedule")
    api.add_resource(
        GetVirtualDesktopsSessionState, "/api/dcv/virtual_desktops/session_state"
    )
    api.add_resource(
        GetVirtualDesktopConnectionFile,
        "/api/dcv/virtual_desktops/connection_file",
    )
    api.add_resource(SoftwareStacksManager, "/api/dcv/virtual_desktops/software_stacks")
    # Golden Image Publish endpoints
    api.add_resource(GoldenImageNominate, "/api/dcv/golden-images/nominate")
    api.add_resource(GoldenImageNominations, "/api/dcv/golden-images/nominations")
    api.add_resource(GoldenImageApprove, "/api/dcv/golden-images/approve")
    api.add_resource(GoldenImageReject, "/api/dcv/golden-images/reject")
    api.add_resource(GoldenImagePublish, "/api/dcv/golden-images/publish")
    api.add_resource(GoldenImageRollback, "/api/dcv/golden-images/<int:stack_id>/rollback")
    api.add_resource(GoldenImageVersions, "/api/dcv/golden-images/<int:stack_id>/versions")
    api.add_resource(BaseImageStatusManager, "/api/dcv/base_image_acceleration/status")
    api.add_resource(
        VdiPoolManager,
        "/api/dcv/virtual_desktops/software_stacks/<int:software_stack_id>/pool",
    )
    api.add_resource(
        VdiPoolSpecRefresh,
        "/api/dcv/virtual_desktops/pool/refresh-specs",
    )
    api.add_resource(
        VdiPoolAvailability,
        "/api/dcv/virtual_desktops/pool_availability",
    )

    # DCV Session Sharing
    api.add_resource(DcvSessionSharingProfiles, "/api/dcv/session_sharing/profiles")
    api.add_resource(DcvSessionSharingProfileDetail, "/api/dcv/session_sharing/profiles/<string:profile_id>")
    api.add_resource(DcvSessionSharingGrants, "/api/dcv/session_sharing/grants")
    api.add_resource(DcvSessionSharingGrantDetail, "/api/dcv/session_sharing/grants/<string:grant_id>")
    api.add_resource(DcvSessionSharingSharedToMe, "/api/dcv/session_sharing/shared_to_me")
    # Hardware Profiles / USB device allowlists (Hardware Profile feature).
    api.add_resource(UsbProfilesManager, "/api/dcv/usb_profiles")
    api.add_resource(UsbProfileDetail, "/api/dcv/usb_profiles/<int:profile_id>")
    api.add_resource(UsbProfileEntriesManager, "/api/dcv/usb_profiles/<int:profile_id>/entries")
    api.add_resource(UsbProfileEntryDetail, "/api/dcv/usb_profiles/entries/<int:entry_id>")
    api.add_resource(UsbFilterStringParse, "/api/dcv/usb_profiles/parse")
    api.add_resource(HardwareProfilesManager, "/api/dcv/hardware_profiles")
    api.add_resource(HardwareProfileDetail, "/api/dcv/hardware_profiles/<int:hp_id>")
    api.add_resource(HardwareProfileBinding, "/api/dcv/hardware_profiles/bind")
    api.add_resource(HardwareProfileBindingsList, "/api/dcv/hardware_profiles/bindings")
    api.add_resource(HardwareProfileSubProfileTypes, "/api/dcv/hardware_profiles/sub_profile_types")
    api.add_resource(HardwareProfilePreview, "/api/dcv/hardware_profiles/preview")
    api.add_resource(ConfigTree, "/api/admin/config/tree")
    api.add_resource(ConfigParams, "/api/admin/config/params")
    api.add_resource(ConfigParamDetail, "/api/admin/config/param")
    api.add_resource(ConfigSearch, "/api/admin/config/search")
    api.add_resource(ConfigHistory, "/api/admin/config/history")
    api.add_resource(ConfigBatch, "/api/admin/config/batch")
    api.add_resource(ConfigActivity, "/api/admin/config/activity")
    api.add_resource(DcvSessionSharingUserSearch, "/api/dcv/session_sharing/users/search")
    api.add_resource(DcvSessionSharingAdminSessions, "/api/dcv/session_sharing/sessions")
    api.add_resource(DcvSessionSharingSettings, "/api/dcv/session_sharing/settings")
    api.add_resource(DcvSessionSharingConnect, "/api/dcv/session_sharing/connect")
    api.add_resource(DcvSessionSharingConnectNonce, "/api/dcv/session_sharing/connect/<string:nonce>")
    api.add_resource(DcvSessionSharingLink, "/api/dcv/session_sharing/link")

    api.add_resource(
        VdiInstanceTypeSpecs,
        "/api/dcv/virtual_desktops/instance_type_specs",
    )
    api.add_resource(
        VdiInstanceTypeSearch,
        "/api/dcv/virtual_desktops/instance_types",
    )
    api.add_resource(
        VirtualDesktopProfilesManager, "/api/dcv/virtual_desktops/profiles"
    )
    api.add_resource(
        VirtualDesktopScreenshot, "/api/dcv/virtual_desktops/screenshot"
    )

    # Applications
    api.add_resource(ListApplications, "/api/applications/list_applications")
    api.add_resource(Application, "/api/applications/application")
    api.add_resource(ExportApplication, "/api/applications/export")
    api.add_resource(ImportApplication, "/api/applications/import")
    # Target Nodes
    api.add_resource(CreateTargetNode, "/api/target_nodes/create")
    api.add_resource(DeleteTargetNode, "/api/target_nodes/delete")
    api.add_resource(StopTargetNode, "/api/target_nodes/stop")
    api.add_resource(StartTargetNode, "/api/target_nodes/start")
    api.add_resource(TargetNodeUserDataManager, "/api/target_nodes/user_data")
    api.add_resource(
        TargetNodeSoftwareStacksManager, "/api/target_nodes/software_stacks"
    )
    api.add_resource(TargetNodeProfilesManager, "/api/target_nodes/profiles")
    api.add_resource(ListTargetNode, "/api/target_nodes/list")
    api.add_resource(GetTargetNodeSessionState, "/api/target_nodes/session_state")
    api.add_resource(UpdateTargetNodeSchedule, "/api/target_nodes/schedule")
    api.add_resource(ResizeTargetNode, "/api/target_nodes/resize")

    # Project
    api.add_resource(ProjectsManager, "/api/projects")

    # Scheduler
    api.add_resource(Job, "/api/scheduler/job")
    api.add_resource(Jobs, "/api/scheduler/jobs")

    # Login Nodes
    api.add_resource(ListLoginNodes, "/api/login_nodes/list")

    # Register views
    app.register_blueprint(index)
    app.register_blueprint(my_api_key)
    app.register_blueprint(my_api_tokens)
    app.register_blueprint(my_account)
    app.register_blueprint(admin_users)
    app.register_blueprint(admin_groups)
    app.register_blueprint(admin_applications)
    app.register_blueprint(admin_virtual_desktops_software_stacks)
    app.register_blueprint(admin_base_image_acceleration)
    app.register_blueprint(admin_virtual_desktops_profiles)
    app.register_blueprint(admin_virtual_desktops_session_sharing)
    app.register_blueprint(admin_virtual_desktops_hardware_profiles)
    app.register_blueprint(admin_golden_images)
    app.register_blueprint(admin_config_editor)
    app.register_blueprint(admin_virtual_desktops_list_all)
    app.register_blueprint(admin_cluster_status_dcv_overview)
    app.register_blueprint(admin_projects)
    app.register_blueprint(file_explorer)
    app.register_blueprint(tail)
    app.register_blueprint(ai_assistant)
    app.register_blueprint(submit_job)
    app.register_blueprint(ssh)
    app.register_blueprint(web_terminal)
    app.register_blueprint(my_jobs)
    app.register_blueprint(virtual_desktops)
    app.register_blueprint(my_activity)
    app.register_blueprint(target_nodes)
    app.register_blueprint(admin_target_nodes_user_data)
    app.register_blueprint(admin_target_nodes_software_stacks)
    app.register_blueprint(admin_target_nodes_profiles)
    app.register_blueprint(admin_token_audit)
    app.register_blueprint(ecr_images)
    app.register_blueprint(containers_batch)
    app.register_blueprint(containers_eks)

    # Exempt the /auth login endpoint from CSRFProtect.
    #
    # Reasoning: CSRF protects authenticated actions from being forged by
    # third-party origins against a victim's logged-in session. The login
    # form has no authenticated session yet — there is nothing for an
    # attacker to forge against. The narrow "login CSRF" threat (forcing a
    # victim to authenticate as the attacker so subsequent activity is
    # logged under the attacker's account) is mitigated by the SameSite=Lax
    # cookie attribute set on SOCA's session cookie, which prevents
    # cross-site form POSTs from including the cookie.
    #
    # Keeping CSRF on /auth created two operational problems with no
    # security upside: (a) all programmatic clients had to drive a hidden
    # GET /login first to mint a token, and (b) a missing token returned
    # 302 + flash, which is silently lossy when scripted clients only
    # check the redirect cookie state.
    csrf.exempt(app.view_functions["index.authenticate"])

    # Logger
    setup_logger("soca_logger", "logs/web_interface.log")
    setup_logger(
        "scheduled_tasks_virtual_desktops_schedule_management",
        "logs/scheduled_tasks/virtual_desktops/schedule_management.log",
    )
    setup_logger(
        "scheduled_tasks_virtual_desktops_session_state_watcher",
        "logs/scheduled_tasks/virtual_desktops/session_state_watcher.log",
    )
    setup_logger(
        "scheduled_tasks_target_nodes_session_state_watcher",
        "logs/scheduled_tasks/target_nodes/session_state_watcher.log",
    )
    setup_logger(
        "scheduled_tasks_target_nodes_schedule_management",
        "logs/scheduled_tasks/target_nodes/scheduled_tasks_target_nodes_schedule_management.log",
    )
    setup_logger(
        "scheduled_tasks_virtual_desktops_session_error_watcher",
        "logs/scheduled_tasks/virtual_desktops/session_error_watcher.log",
    )
    setup_logger(
        "scheduled_tasks_db_backup",
        "logs/scheduled_tasks/db_backup.log",
    )
    setup_logger(
        "scheduled_tasks_cleanup_dcv_event_log",
        "logs/scheduled_tasks/cleanup_dcv_event_log.log",
    )
    setup_logger(
        "scheduled_tasks_cleanup_expired_tokens",
        "logs/scheduled_tasks/cleanup_expired_tokens.log",
    )
    db.app = app
    db.init_app(app)
    # IAM-auth bootstrap (BSC5): ensure the rds_iam app role exists BEFORE the
    # runtime pool (which authenticates as that role) runs create_all. No-op for
    # sqlite / password-fallback providers.
    _ensure_iam_app_user()
    # Aurora cluster may take 8-15 minutes to reach 'available' after CDK deploy.
    # If we're booting right after a fresh deploy, db.create_all() can hit
    # ConnectionRefused / OperationalError. Retry with exponential backoff up to
    # ~5 minutes, then bail with a clear message.
    import time as _time
    from sqlalchemy.exc import OperationalError as _OperationalError
    _max_attempts = 30  # ~5 min @ 10s
    for _attempt in range(1, _max_attempts + 1):
        try:
            db.create_all()
            break
        except _OperationalError as _e:
            if _attempt == _max_attempts:
                logger.critical(
                    f"Could not connect to database after {_max_attempts} attempts "
                    f"(~5 min). Last error: {_e}. Web app will not start.\n"
                )
                raise SystemExit(2)
            logger.warning(
                f"db.create_all() attempt {_attempt}/{_max_attempts} failed "
                f"({type(_e).__name__}); retrying in 10s...\n"
            )
            _time.sleep(10)
    basedir = os.path.abspath(os.path.dirname(__file__))
    # SQLite-only: lock down file permissions on the local database file.
    # When using Aurora PG, db.sqlite will not exist; skip silently.
    _sqlite_path = os.path.join(basedir, "db.sqlite")
    if os.path.exists(_sqlite_path):
        os.chmod(_sqlite_path, stat.S_IWUSR + stat.S_IRUSR)
    app_session = Session(app)

    # Encrypt session payload at rest (defense-in-depth behind the cache ACL): wrap the flask-session serializer with the SM-backed Fernet ring.
    app.session_interface.serializer = EncryptedSerializer(
        app.session_interface.serializer, config.Config._SESSION_ENCRYPTION_KEYS
    )

    # EDH-owned sid signing (current+previous ring, use_signer off) -- closes unsigned-cookie vuln #1, seamless signer rotation, off flask-session's deprecated signer.
    install_signed_session(app, config.Config._SESSION_SIGNER_KEYS)

    # flask-session's DDB backend never enables TTL (self.table_name-before-assign bug); ensure it ourselves so session items auto-expire (bounded growth).
    if config.Config.SESSION_TYPE == "dynamodb":
        install_dynamodb_expires_at(app)
        ensure_dynamodb_ttl(config.Config.SESSION_DYNAMODB_TABLE)

    # now import scheduled tasks
    from scheduled_tasks.virtual_desktops.session_state_watcher import (
        virtual_desktops_session_state_watcher,
    )
    from scheduled_tasks.virtual_desktops.session_error_watcher import (
        virtual_desktops_session_error_watcher,
    )

    from scheduled_tasks.virtual_desktops.schedule_management import (
        virtual_desktops_schedule_management,
        auto_terminate_stopped_instance,
    )
    from scheduled_tasks.target_nodes.session_state_watcher import (
        target_nodes_session_state_watcher,
    )
    from scheduled_tasks.target_nodes.schedule_management import (
        target_nodes_schedule_management,
    )
    from scheduled_tasks.clean_tmp_folders import clean_tmp_folders
    from scheduled_tasks.create_db_backup import backup_db
    from scheduled_tasks.cleanup_dcv_event_log import cleanup_dcv_event_log
    from scheduled_tasks.cleanup_audit_log import cleanup_audit_log
    from scheduled_tasks.cleanup_expired_tokens import cleanup_expired_tokens
    from scheduled_tasks.refresh_pool_specs import refresh_pool_specs
    from scheduled_tasks.refresh_api_path_stats import refresh_api_path_stats

    # Create default content
    soca_samples.insert_default_vdi_profile()
    soca_samples.insert_default_software_stacks()
    soca_samples.insert_default_test_web_based_job_submission_application()
    soca_samples.insert_default_efa_application()
    soca_samples.insert_default_target_host_user_data()
    soca_samples.insert_default_target_node_profile()
    soca_samples.insert_default_projects()

    # Task: Backup DB every 12 hours
    scheduler.add_job(
        backup_db,
        trigger=IntervalTrigger(hours=12),
        id="scheduled_tasks_db_backup",
        replace_existing=True,
    )

    # Task: VDI pool launch_spec convergence sweep every 10 minutes. Re-renders
    # and CAS-writes pool launch_specs whose render inputs (bootstrap templates,
    # cluster config, or a stack's AMI/base_os/root_size) drifted from the
    # stored snapshot, so the reconciler never applies stale bytes. The
    # software-stack edit hook handles the AMI-edit case immediately; this is
    # the catch-all for every drift source. max_instances=1 guards per-process
    # overlap; a DDB lease inside the task provides the cross-host singleton.
    scheduler.add_job(
        refresh_pool_specs,
        args=[app],
        trigger=IntervalTrigger(minutes=10),
        id="refresh_pool_specs",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Auto terminate stopped instances every 30 minutes
    scheduler.add_job(
        auto_terminate_stopped_instance,
        args=[app],
        trigger=IntervalTrigger(minutes=30),
        id="auto_terminate_stopped_instance",
        replace_existing=True,
    )

    # Task: Virtual desktops schedule management
    scheduler.add_job(
        virtual_desktops_schedule_management,
        args=[app],
        trigger=CronTrigger(
            minute="0,16,32,47"
        ),  # every hour , every 16 minutes (as users can adjust schedule every 15 mins)
        id="virtual_desktops_schedule_management",
        replace_existing=True,
    )

    # Task: Virtual desktops session state watcher every 1 minute
    scheduler.add_job(
        virtual_desktops_session_state_watcher,
        args=[app],
        trigger=IntervalTrigger(minutes=1),
        id="virtual_desktops_session_state_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Virtual desktops session error watcher every 5 minutes
    scheduler.add_job(
        virtual_desktops_session_error_watcher,
        args=[app],
        trigger=IntervalTrigger(minutes=5),
        id="virtual_desktops_session_error_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Target Node session state watcher every 1 minute
    scheduler.add_job(
        target_nodes_session_state_watcher,
        args=[app],
        trigger=IntervalTrigger(minutes=1),
        id="target_nodes_session_state_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Target Node schedule management
    scheduler.add_job(
        target_nodes_schedule_management,
        args=[app],
        trigger=CronTrigger(
            minute="0,16,32,47"
        ),  # every hour , every 16 minutes (as users can adjust schedule every 15 mins)
        id="target_nodes_schedule_management",
        replace_existing=True,
    )

    # Task: Clean temp folders every 1 hour
    scheduler.add_job(
        clean_tmp_folders,
        trigger=IntervalTrigger(hours=1),
        id="clean_tmp_folders",
        replace_existing=True,
    )

    # Task: Prune the API audit log every 6 hours. Default 720h (30 days)
    # retention; configurable via SocaConfig key
    # /configuration/Security/api_audit_log_retention_hours.
    scheduler.add_job(
        cleanup_audit_log,
        args=[app],
        trigger=IntervalTrigger(hours=6),
        id="cleanup_audit_log",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Prune the DCV session event log every 1 hour. Default 24h
    # retention; configurable via SocaConfig key
    # /configuration/DcvSessionEventLogRetentionHours.
    scheduler.add_job(
        cleanup_dcv_event_log,
        args=[app],
        trigger=IntervalTrigger(hours=1),
        id="cleanup_dcv_event_log",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Purge expired/revoked tokens every 6 hours. Keeps api_tokens
    # table bounded (session tokens rotate hourly, leaving revoked rows).
    # Default retention: 48h after expiry/revocation.
    scheduler.add_job(
        cleanup_expired_tokens,
        args=[app],
        trigger=IntervalTrigger(hours=6),
        id="cleanup_expired_tokens",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Refresh API path latency stats every 60s (matview) + hourly history.
    scheduler.add_job(
        refresh_api_path_stats,
        args=[app],
        trigger=IntervalTrigger(seconds=60),
        id="refresh_api_path_stats",
        replace_existing=True,
        max_instances=1,
    )

    # Start the scheduler in EXACTLY ONE uWSGI worker.
    if postfork is not None:

        @postfork
        def _start_scheduler_in_worker_one():
            import uwsgi

            if uwsgi.worker_id() == 1:
                scheduler.start()

    else:
        scheduler.start()

if __name__ == "__main__":
    app.run()
