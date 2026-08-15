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

import os
import logging
from datetime import timedelta
import utils.cache.client as utils_cache
from utils.aws.secretsmanager_client import SocaSecret
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.aws.boto3_wrapper import get_boto
from utils.session_keys import get_session_keys
from extensions import db
import sys

logger = logging.getLogger("soca_logger")

basedir = os.path.abspath(os.path.dirname(__file__))


def _resolve_sqlalchemy_uri():
    """
    Resolve the SQLAlchemy DATABASE_URI based on cluster configuration.

    The database is a capability with a selectable provider
    (Config.database.provider), surfaced at runtime as
    /configuration/Database/provider:

      * aurora_serverless_v2 -- build an Aurora PostgreSQL URI from the
        /configuration/Database/{endpoint,port,name} SSM keys + the DatabaseAdminSecret
        secret.
      * sqlite -- legacy local file.

    If the provider is aurora_serverless_v2 but resolution fails (SSM keys
    missing, secret unfetchable, etc.) this RAISES SystemExit. Silent fallback to
    SQLite would let the web app start with empty/stale data -- a worse failure
    mode than failing loudly at startup.
    """
    _sqlite_uri = "sqlite:///" + os.path.join(basedir, "db.sqlite")
    _aurora_provider = "aurora_serverless_v2"

    # Step 1: read the provider selector. If we cannot read SocaConfig at all, we
    # are in a deeply degraded state -- fail loudly rather than guess.
    try:
        _provider = (
            SocaConfig(key="/configuration/Database/provider")
            .get_value()
            .get("message")
        )
    except Exception as _e:
        logger.critical(
            f"Could not read Database/provider from SocaConfig ({_e}). "
            "Web app will not start. Ensure SocaConfig / SSM is reachable."
        )
        raise SystemExit(2)

    # A missing provider key is an operational issue (CDK didn't publish or the
    # key path is wrong) -- fail loudly rather than silently use SQLite.
    if _provider is None or _provider == "" or "CACHE_MISS" in str(_provider):
        logger.critical(
            "SSM key /edh/<cluster>/configuration/Database/provider is missing. "
            "CDK may not have published it, or the key path is wrong. "
            "Web app will not start. Verify with: "
            "aws ssm get-parameters-by-path --path /edh/<cluster>/configuration/Database --recursive"
        )
        raise SystemExit(2)

    _provider = str(_provider).strip()

    # Legacy SQLite provider -- the legitimate local-file path.
    if _provider == "sqlite":
        return _sqlite_uri

    if _provider != _aurora_provider:
        logger.critical(
            f"Unknown Config.database.provider '{_provider}'. "
            f"Expected '{_aurora_provider}' or 'sqlite'. Web app will not start."
        )
        raise SystemExit(2)

    # ----- aurora_serverless_v2 provider. Any failure here is an OPERATIONAL
    # PROBLEM that must be visible to the operator. Do NOT fall back to SQLite. -----
    try:
        _endpoint = (
            SocaConfig(key="/configuration/Database/endpoint")
            .get_value()
            .get("message")
        )
        _port = (
            SocaConfig(key="/configuration/Database/port").get_value().get("message")
        )
        _database = (
            SocaConfig(key="/configuration/Database/name").get_value().get("message")
        )
    except Exception as _e:
        logger.critical(
            f"Database provider is '{_aurora_provider}' but reading "
            f"endpoint/port/name from SocaConfig failed ({_e}). Web app will not start."
        )
        raise SystemExit(2)

    if not (_endpoint and _port and _database):
        logger.critical(
            f"Database provider is '{_aurora_provider}' but endpoint/port/name "
            "not populated in SSM. CDK deploy may not have completed publishing config. "
            "Web app will not start. Verify "
            "/edh/<cluster>/configuration/Database/{endpoint,port,name} are set."
        )
        raise SystemExit(2)

    # ----- Credentials: IAM database authentication (BSC5-preferred) -----
    _app_user = (
        SocaConfig(key="/configuration/Database/app_user").get_value().get("message")
        or "edh_app"
    )
    _iam_auth_raw = (
        SocaConfig(key="/configuration/Database/iam_auth").get_value().get("message")
    )
    _iam_auth = True  # default to IAM for the aurora provider unless explicitly false
    if _iam_auth_raw not in (None, "") and "CACHE_MISS" not in str(_iam_auth_raw):
        _cast = SocaCastEngine(data=_iam_auth_raw).cast_as(bool)
        if _cast.get("success"):
            _iam_auth = _cast.get("message") is True

    if _iam_auth:
        # Connect as the rds_iam app user with short-lived IAM auth tokens (no
        # long-lived password). A do_connect listener mints a fresh token per NEW
        # connection -- token generation is a local SigV4 op, so it's transparent
        # to the pool and immune to password rotation. IAM auth requires TLS.
        from sqlalchemy import event
        from sqlalchemy.engine import Engine
        import db_iam_auth

        _region = (
            os.environ.get("AWS_DEFAULT_REGION")
            or os.environ.get("AWS_REGION")
            or "us-east-2"
        )
        _host = _endpoint
        _rds_resp = get_boto(service_name="rds", region_name=_region)
        if _rds_resp.get("success") is False:
            logger.critical(
                "unable to build RDS client for IAM auth; web app will not start."
            )
            raise SystemExit(2)
        _rds = _rds_resp.get("message")

        _port_cast = SocaCastEngine(data=_port).cast_as(int)
        if _port_cast.get("success") is not True:
            logger.critical(
                f"Database/port '{_port}' is not a valid integer. Web app will not start."
            )
            raise SystemExit(2)
        _port = _port_cast.get("message")

        # The token-injection logic lives in db_iam_auth (stdlib-only) so it is
        # unit-testable off-cluster. It mints a fresh IAM token per new connection
        # to our (host, app_user); any other connection is left untouched.
        event.listen(
            Engine,
            "do_connect",
            db_iam_auth.make_iam_token_injector(
                rds_client=_rds,
                host=_host,
                port=_port,
                user=_app_user,
                region=_region,
            ),
            named=True,
        )

        return f"postgresql+psycopg://{_app_user}@{_host}:{_port}/{_database}?sslmode=require"

    # ----- Fallback: admin password (admin / iam_auth=false legacy path) -----
    # admin credentials live at /edh/<cluster_id>/DatabaseAdminSecret.
    # SocaSecret auto-prefixes /edh/<cluster_id>/ so we pass only the suffix.
    try:
        _secret_resp = SocaSecret(secret_id="DatabaseAdminSecret").get_secret()
    except Exception as _e:
        logger.critical(
            f"Exception fetching DatabaseAdminSecret secret ({_e}). "
            "Web app will not start."
        )
        raise SystemExit(2)

    if not _secret_resp.success:
        logger.critical(
            f"Could not fetch DatabaseAdminSecret secret: {_secret_resp.message}. "
            "Verify the secret exists at /edh/<cluster>/DatabaseAdminSecret and that the "
            "controller's IAM role has secretsmanager:GetSecretValue. "
            "Web app will not start."
        )
        raise SystemExit(2)

    _creds = _secret_resp.message
    _user = _creds.get("username")
    _password = _creds.get("password")
    if not (_user and _password):
        logger.critical(
            "DatabaseAdminSecret secret is missing username or password. "
            "Web app will not start."
        )
        raise SystemExit(2)

    from urllib.parse import quote_plus

    # postgresql+psycopg -> psycopg3 dialect (SQLAlchemy 2.0). psycopg3 does its
    # protocol waiting in Python, so under gevent (planned DCV high-scale WebUI)
    # it can cooperate with the event loop -- unlike psycopg2, whose only gevent
    # shim (psycogreen) is abandoned. sslmode=require -- Aurora enforces TLS.
    return (
        f"postgresql+psycopg://{_user}:{quote_plus(_password)}"
        f"@{_endpoint}:{_port}/{_database}?sslmode=require"
    )


class Config(object):
    cache_config = utils_cache.get_cache_config(is_admin=True).get("message")
    # APP
    DEBUG = False
    USE_PERMANENT_SESSION = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SQLALCHEMY_DATABASE_URI = _resolve_sqlalchemy_uri()
    # Connection pool tuning. Two concerns:
    #   1. uwsgi forks workers; pool_pre_ping detects connections that
    #      were inherited from the parent or silently broken (e.g. Aurora
    #      failover / writer-endpoint shift) and transparently reconnects.
    #   2. Establishing a NEW connection under IAM auth is expensive (~0.5-1.6s
    #      for the token-validated TLS handshake, vs ~20ms for password), so we
    #      want connections to be LONG-LIVED and reused. An established IAM
    #      connection stays valid for its full lifetime even after the 15-min
    #      auth token expires (the token is only checked at connect time), so
    #      there is NO token reason to recycle frequently. pool_recycle is set
    #      purely for connection hygiene; pool_pre_ping is the failover safety net.
    #      (A low recycle like 300s forces constant reconnects and re-pays the
    #      IAM connect cost on interactive requests -- do not lower it.)
    # SQLite ignores these options (no real pool), so they are safe in both modes.
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
        "pool_size": 5,
        "max_overflow": 10,
    }
    _cache_enabled = SocaCastEngine(
        data=cache_config.get("cache_info").get("enabled")
    ).cast_as(bool)
    _cache_ok = (
        _cache_enabled.get("success") is True and _cache_enabled.get("message") is True
    )
    # Session backend knob: redis (default, hardened Valkey) | dynamodb (opt-in,
    # IAM-isolated) | sqlalchemy. Honored as selected -- fail closed on the chosen
    # store, no silent cross-backend fallback.
    _session_backend = (
        SocaConfig(key="/configuration/WebInterface/session_backend")
        .get_value(default="redis", allow_unknown_key=True)
        .message
        or "redis"
    )
    _VALID_SESSION_BACKENDS = ("redis", "dynamodb", "sqlalchemy")
    if _session_backend not in _VALID_SESSION_BACKENDS:
        logger.critical(
            f"Invalid session_backend '{_session_backend}'; must be one of "
            f"{_VALID_SESSION_BACKENDS}; web app will not start (fail closed)."
        )
        sys.exit(1)
    if _session_backend == "dynamodb":
        _ddb_resource = get_boto(service_name="dynamodb", resource=True)
        if _ddb_resource.get("success") is not True:
            logger.critical(
                f"session_backend=dynamodb but DynamoDB resource unavailable "
                f"({_ddb_resource.get('message')}); web app will not start (fail closed)."
            )
            sys.exit(1)
        SESSION_TYPE = "dynamodb"
        SESSION_DYNAMODB = _ddb_resource.get("message")
        # Transient/runtime namespace (edh-<cluster>-rtm-*); flask-session self-creates
        # the table (PK id, TTL attr expiration) on interface init.
        SESSION_DYNAMODB_TABLE = f"{os.environ.get('EDH_CLUSTER_ID', '')}-rtm-sessions"
    elif _session_backend == "redis":
        if not _cache_ok:
            logger.critical(
                "session_backend=redis but the cache is unavailable; web app will "
                "not start (fail closed -- no silent fallback to another store)."
            )
            sys.exit(1)
        SESSION_TYPE = "redis"
        SESSION_REDIS = cache_config.get("cache_client")
    else:
        # session_backend == "sqlalchemy" (validated above). Explicit opt-in only --
        # never an implicit fallback from an unreachable redis/dynamodb backend.
        SESSION_TYPE = "sqlalchemy"
        SESSION_SQLALCHEMY = db
    # CSRF token lifetime. csrf_token_follows_session=true (default) -> the
    # token has no independent expiry and stays valid for the life of the
    # session (WTF_CSRF_TIME_LIMIT=None). When false, csrf_token_lifetime_seconds
    # (>=1, default 3600) is the hard token TTL. The token is always bound to the
    # session secret, so it can never outlive the session.
    _CSRF_DEFAULT_TTL_SECONDS = 3600
    _csrf_follows_raw = SocaConfig(
        key="/configuration/WebInterface/csrf_token_follows_session"
    ).get_value(default="true", allow_unknown_key=True)
    _csrf_follows_cast = SocaCastEngine(
        data=(
            _csrf_follows_raw.get("message")
            if _csrf_follows_raw.get("success") is True
            else "true"
        )
    ).cast_as(bool)
    _csrf_follows_session = (
        _csrf_follows_cast.get("message")
        if _csrf_follows_cast.get("success") is True
        else True
    )
    if _csrf_follows_session is True:
        WTF_CSRF_TIME_LIMIT = None
    else:
        _csrf_ttl_raw = SocaConfig(
            key="/configuration/WebInterface/csrf_token_lifetime_seconds"
        ).get_value(default=str(_CSRF_DEFAULT_TTL_SECONDS), allow_unknown_key=True)
        _csrf_ttl_cast = SocaCastEngine(
            data=(
                _csrf_ttl_raw.get("message")
                if _csrf_ttl_raw.get("success") is True
                else _CSRF_DEFAULT_TTL_SECONDS
            )
        ).cast_as(int)
        if _csrf_ttl_cast.get("success") is True and _csrf_ttl_cast.get("message") >= 1:
            WTF_CSRF_TIME_LIMIT = _csrf_ttl_cast.get("message")
        else:
            # Invalid / non-positive value -> Flask-WTF native default (1h).
            logger.warning(
                "Invalid csrf_token_lifetime_seconds; falling back to default "
                f"{_CSRF_DEFAULT_TTL_SECONDS}s"
            )
            WTF_CSRF_TIME_LIMIT = _CSRF_DEFAULT_TTL_SECONDS
    logger.debug(
        f"Resolved WTF_CSRF_TIME_LIMIT={WTF_CSRF_TIME_LIMIT} "
        f"(csrf_token_follows_session={_csrf_follows_session})"
    )
    # Session signer key: Secrets Manager only (fleet-shared, rotation-ready) -- fail closed, no per-host/ephemeral fallback.
    _session_signer_arn = SocaConfig(
        key="/configuration/WebInterface/SessionSignerSecretArn"
    ).get_value(default=None, allow_unknown_key=True)
    _session_encryption_arn = SocaConfig(
        key="/configuration/WebInterface/SessionEncryptionSecretArn"
    ).get_value(default=None, allow_unknown_key=True)
    _session_keys = get_session_keys(
        signer_secret_id=(
            _session_signer_arn.message if _session_signer_arn.success else None
        ),
        encryption_secret_id=(
            _session_encryption_arn.message if _session_encryption_arn.success else None
        ),
    )
    if _session_keys.get("success") is not True:
        logger.critical(
            f"Unable to load SM-backed session keys ({_session_keys.get('message')}); web app will not start."
        )
        sys.exit(1)
    _signer_cur, _signer_prev = _session_keys.get("message").get("signer")
    SECRET_KEY = _signer_cur
    if _signer_prev:
        SECRET_KEY_FALLBACKS = [
            _signer_prev
        ]  # Flask/CSRF token continuity across signer rotation
    SESSION_USE_SIGNER = False  # EDH signs the sid itself (session_keys.install_signed_session); off the deprecated flask-session path
    _SESSION_SIGNER_KEYS = (
        _signer_cur,
        _signer_prev,
    )  # (current, previous) ring for our sid signer
    _SESSION_ENCRYPTION_KEYS = _session_keys.get("message").get(
        "encryption"
    )  # (current, previous) for the at-rest cipher
    API_ROOT_KEY = os.environ.get("SOCA_FLASK_API_ROOT_KEY", False)
    # File-explorer token cipher: same SM encryption ring (current key encrypts; full ring decrypts across rotation). Retires the ephemeral per-restart SOCA_FLASK_FERNET_KEY.
    SOCA_DATA_SHARING_SYMMETRIC_KEY = _SESSION_ENCRYPTION_KEYS[0]
    TIMEZONE = "UTC"  # Change to match your local timezone if needed. See https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for all TZ
    LOCALIZE_API_RESPONSES = (
        os.environ.get("SOCA_LOCALIZE_API", "true").lower() == "true"
    )  # Set to false to disable i18n for API JSON responses via Accept-Language header

    USER_REGEX_PATTERN = (
        r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$"  # Username must be alphanumeric and - _ .
    )
    # WEB
    APPS_LOCATION = "/apps/"
    USER_HOME = "/data/home"
    CHROOT_USER = False  # if True, user can only access their $HOME directory (aka: USER_HOME/<user>)
    PATH_TO_RESTRICT = [
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/local",
        "/media",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",  # nosec
        "/var",
    ]  # List of folders not accessible via the web ui
    DEFAULT_CACHE_TIME = 120  # 2 minutes. Change this value to optimize performance in case you have a large number of concurrent user
    MAX_UPLOAD_FILE = 5120  # 5 GB
    MAX_UPLOAD_TIMEOUT = 1_800_000  # 30 minutes
    ALLOW_DOWNLOAD_FROM_PORTAL = (
        True  # Give user ability to download files from the web portal
    )
    MAX_SIZE_ONLINE_PREVIEW = 150_000_000  # in bytes (150mb by default), maximum size of file that can be visualized via the web editor
    MAX_ARCHIVE_SIZE = 150_000_000  # in bytes (150mb by default), maximum size of archive generated when downloading multiple files at once
    LOG_DAILY_BACKUP_COUNT = 31  # Keep 15 latest daily backups
    KIBANA_JOB_INDEX = "soca-jobs*"  # Default index to look for /my_activity. Change it something more specific if using more than 1 index with name ~ "job*"

    # UWSGI SETTINGS
    FLASK_HOST = "127.0.0.1"
    FLASK_PROTOCOL = "https://"
    FLASK_PORT = "8443"
    FLASK_ENDPOINT = f"{FLASK_PROTOCOL}{FLASK_HOST}:{FLASK_PORT}"

    # COGNITO
    ENABLE_SSO = False
    COGNITO_OAUTH_AUTHORIZE_ENDPOINT = "https://<YOUR_COGNITO_DOMAIN_NAME>.auth.<YOUR_REGION>.amazoncognito.com/oauth2/authorize"
    COGNITO_OAUTH_TOKEN_ENDPOINT = "https://<YOUR_COGNITO_DOMAIN_NAME>.auth.<YOUR_REGION>.amazoncognito.com/oauth2/token"
    COGNITO_JWS_KEYS_ENDPOINT = "https://cognito-idp.<YOUR_REGION>.amazonaws.com/<YOUR_REGION>_<YOUR_ID>/.well-known/jwks.json"
    COGNITO_APP_SECRET = "<YOUR_APP_SECRET>"
    COGNITO_APP_ID = "<YOUR_APP_ID>"
    COGNITO_ROOT_URL = "<YOUR_WEB_URL>"
    COGNITO_CALLBACK_URL = "<YOUR_CALLBACK_URL>"
    COGNITO_USER_CLAIM = "email"  # Claim containing the SOCA username. If set to email, SOCA will split("@") and consider the first part is the SOCA user. Replace as needed with another claim.

    # DCV Linux
    DCV_LINUX_SESSION_COUNT = 4
    DCV_LINUX_ALLOW_INSTANCE_CHANGE = (
        True  # Allow user to change their instance type if their DCV session is stopped
    )
    DCV_LINUX_STOP_IDLE_SESSION = 0  # In hours. Linux DCV sessions will be stopped/hibernated regardless of schedule to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Linux DCV will be permanently terminated if user/schedule won't restart it within the time specified. 0 to disable

    # DCV Windows
    DCV_WINDOWS_SESSION_COUNT = 4
    DCV_WINDOWS_ALLOW_INSTANCE_CHANGE = (
        True  # Allow user to change their instance type if their DCV session is stopped
    )
    DCV_WINDOWS_STOP_IDLE_SESSION = 0  # In hours. Windows DCV sessions will be stopped/Hibernated regarless of schedule to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Windows DCV will be permanently terminated if user/schedule won't restart it within the time specified. 0 to disable

    DCV_WINDOWS_AUTOLOGON = True  # enable or disable autologon. If disabled user will have to manually input Windows password

    # Grace Period
    # - Will not stop a desktop if it was started within the grace period
    # - Will not start a desktop if it was stopped within  the grace period
    # In other word, even if your schedule is stopped all day, but you manually start your desktop, it will stays up and running for X hours)
    DCV_SCHEDULE_GRACE_PERIOD_IN_HOURS = 2

    DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT = (
        False  # If True, users can only provision instances that support hibernation
    )

    # Hibernation RAM ceilings (V1587014009). AWS enforces an upper RAM bound for
    # EC2 hibernation that differs by OS (Windows is far lower than Linux);
    # exceeding it makes RunInstances / the VDI CloudFormation stack fail at
    # launch. EDH gates an over-RAM hibernation request up front with a clear
    # message instead. Both ceilings are SSM-overridable so the limits can be
    # raised between releases (as AWS lifts them) without a code change. MiB.
    _DCV_HIBERNATE_DEFAULT_RAM_MIB_WINDOWS = 16384  # 16 GiB
    _DCV_HIBERNATE_DEFAULT_RAM_MIB_LINUX = 153600  # 150 GiB

    _hib_win_raw = SocaConfig(
        key="/configuration/DCV/HibernateMaxRamMiBWindows"
    ).get_value(
        default=str(_DCV_HIBERNATE_DEFAULT_RAM_MIB_WINDOWS), allow_unknown_key=True
    )
    _hib_win_cast = SocaCastEngine(
        data=(
            _hib_win_raw.get("message")
            if _hib_win_raw.get("success") is True
            else _DCV_HIBERNATE_DEFAULT_RAM_MIB_WINDOWS
        )
    ).cast_as(int)
    DCV_HIBERNATE_MAX_RAM_MIB_WINDOWS = (
        _hib_win_cast.get("message")
        if _hib_win_cast.get("success") is True and _hib_win_cast.get("message") >= 1
        else _DCV_HIBERNATE_DEFAULT_RAM_MIB_WINDOWS
    )

    _hib_lin_raw = SocaConfig(
        key="/configuration/DCV/HibernateMaxRamMiBLinux"
    ).get_value(
        default=str(_DCV_HIBERNATE_DEFAULT_RAM_MIB_LINUX), allow_unknown_key=True
    )
    _hib_lin_cast = SocaCastEngine(
        data=(
            _hib_lin_raw.get("message")
            if _hib_lin_raw.get("success") is True
            else _DCV_HIBERNATE_DEFAULT_RAM_MIB_LINUX
        )
    ).cast_as(int)
    DCV_HIBERNATE_MAX_RAM_MIB_LINUX = (
        _hib_lin_cast.get("message")
        if _hib_lin_cast.get("success") is True and _hib_lin_cast.get("message") >= 1
        else _DCV_HIBERNATE_DEFAULT_RAM_MIB_LINUX
    )
    DCV_TOKEN_SYMMETRIC_KEY = os.environ[
        "SOCA_DCV_TOKEN_SYMMETRIC_KEY"
    ]  # used to encrypt/decrypt and validate DCV session auth

    DCV_IDLE_CPU_THRESHOLD = 15  # SOCA will NOT hibernate/stop an instance if current CPU usage % is over this value

    # List of DCV session type allowed to be used by the users
    # https://docs.aws.amazon.com/dcv/latest/adminguide/managing-sessions-intro.html
    # default -> console session for Windows, Ubuntu and GPU machines, virtual for everything e;se
    # virtual -> Force Virtual Session
    # console -> Force Console Session
    # note: Windows session can only be console
    DCV_ALLOWED_SESSION_TYPES = ["default", "console", "virtual"]

    DCV_VERIFY_SESSION_HEALTH = True  # if set to True, scheduled_tasks/virtual_desktops/session_state_watcher will try to validate if the DCV Session is correctly running

    DCV_ALLOW_DEFAULT_SCHEDULE_UPDATE = (
        True  # Whether users can override the defualt schedule
    )

    DCV_DEFAULT_SCHEDULE = {
        "monday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "tuesday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "wednesday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "thursday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "friday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "saturday": {
            "start": 0,  # Default Schedule - Stopped all day
            "stop": 0,  # Default Schedule - Stopped all day
        },
        "sunday": {
            "start": 0,  # Default Schedule - Stopped all day
            "stop": 0,  # Default Schedule - Stopped all day
        },
    }

    DCV_BASE_OS = {
        "ubuntu2404": {
            "family": "linux",
            "friendly_name": "Ubuntu 24.04",
            "visible": True,
        },
        "ubuntu2204": {
            "family": "linux",
            "friendly_name": "Ubuntu 22.04",
            "visible": True,
        },
        "amazonlinux2": {
            "family": "linux",
            "friendly_name": "Amazon Linux 2",
            "visible": True,
        },
        "amazonlinux2023": {
            "family": "linux",
            "friendly_name": "Amazon Linux 2023",
            "visible": True,
        },
        "rocky9": {
            "family": "linux",
            "friendly_name": "Rocky Linux 9",
            "visible": True,
        },
        "rocky8": {
            "family": "linux",
            "friendly_name": "Rocky Linux 8",
            "visible": True,
        },
        "rhel9": {
            "family": "linux",
            "friendly_name": "Red Hat Enterprise Linux 9",
            "visible": True,
        },
        "rhel8": {
            "family": "linux",
            "friendly_name": "Red Hat Enterprise Linux 8",
            "visible": True,
        },
        "rhel7": {
            "family": "linux",
            "friendly_name": "Red Hat Enterprise Linux 7",
            "visible": False,
        },
        "centos7": {"family": "linux", "friendly_name": "CentOS 7", "visible": False},
        "windows2019": {
            "family": "windows",
            "friendly_name": "Windows Server 2019",
            "visible": True,
        },
        "windows2022": {
            "family": "windows",
            "friendly_name": "Windows Server 2022",
            "visible": True,
        },
        "windows2025": {
            "family": "windows",
            "friendly_name": "Windows Server 2025",
            "visible": True,
        },
    }

    # Default Instance Type for each AMI
    DCV_DEFAULT_AMI_INSTANCE_TYPES = (
        SocaConfig(key="/configuration/DCVAllowedInstances")
        .get_value(return_as=list)
        .get("message")
    )

    ## Target Nodes
    TARGET_NODE_ALLOW_DEFAULT_SCHEDULE_UPDATE = (
        True  # Whether users can override the default schedule
    )
    TARGET_NODE_SESSION_COUNT = 5  # Maximum number of concurrent target nodes per user
    TARGET_NODE_ALLOW_INSTANCE_CHANGE = (
        True  # Allow user to change their instance type if their target node
    )
    # Grace Period
    # - Will not stop a target node if it was started within the grace period
    # - Will not start a target node if it was stopped within  the grace period
    # In other word, even if your schedule is stopped all day, but you manually start your target node, it will stays up and running for X hours)
    TARGET_NODE_GRACE_PERIOD_IN_HOURS = 2

    TARGET_NODE_DEFAULT_SCHEDULE = {
        "monday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "tuesday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "wednesday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "thursday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "friday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "saturday": {
            "start": 0,  # Default Schedule - Stopped all day
            "stop": 0,  # Default Schedule - Stopped all day
        },
        "sunday": {
            "start": 0,  # Default Schedule - Stopped all day
            "stop": 0,  # Default Schedule - Stopped all day
        },
    }

    # User Directory
    DIRECTORY_AUTH_PROVIDER = (
        SocaConfig(key="/configuration/UserDirectory/provider")
        .get_value()
        .get("message")
    )
    DIRECTORY_GROUP_SEARCH_BASE = (
        SocaConfig(key="/configuration/UserDirectory/group_search_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_PEOPLE_SEARCH_BASE = (
        SocaConfig(key="/configuration/UserDirectory/people_search_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_ADMIN_SEARCH_BASE = (
        SocaConfig(key="/configuration/UserDirectory/admins_search_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_BASE_DN = (
        SocaConfig(key="/configuration/UserDirectory/domain_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_DOMAIN_NAME = (
        SocaConfig(key="/configuration/UserDirectory/domain_name")
        .get_value()
        .get("message")
    )
    DIRECTORY_SERVICE_ID = (
        SocaConfig(key="/configuration/UserDirectory/ad_aws_directory_service_id")
        .get_value()
        .get("message")
    )
    DIRECTORY_NETBIOS = (
        SocaConfig(key="/configuration/UserDirectory/short_name")
        .get_value()
        .get("message")
    )
    DIRECTORY_ENDPOINT = (
        SocaConfig(key="/configuration/UserDirectory/endpoint")
        .get_value()
        .get("message")
    )

    # To identify group/user, group associated to "user" will be named "user<GROUP_NAME_SUFFIX>"
    DIRECTORY_GROUP_NAME_SUFFIX = "socagroup"
    # Fetch Directory service account
    _soca_ds_service_account_secret = (
        SocaConfig(key="/configuration/UserDirectory/service_account_secret_arn")
        .get_value()
        .get("message")
    )
    DIRECTORY_ADMIN_USER_SECRET = SocaSecret(
        secret_id_prefix="", secret_id=_soca_ds_service_account_secret
    ).get_secret()
    if not DIRECTORY_ADMIN_USER_SECRET.success:
        print("Unable to retrieve Directory credentials.", file=sys.stderr)
        sys.exit(1)

    # PBS
    CLUSTER_ID = SocaConfig(key="/configuration/ClusterId").get_value().get("message")

    # SSH
    SSH_PRIVATE_KEY_LOCATION = "tmp/ssh"

    # Amazon Q for Business
    # Add your Amazon Q for Business URL (ex: https://t5i9puav.chat.qbusiness.us-west-2.on.aws/) to display Amazon Q logo in the horizontal bar
    AMAZON_Q_BUSINESS_URL = False

    # Custom Link to be displayed on the Index Page
    # Format: List of dictionary with text and url
    # URL must start with http or https
    # ex: [{ "text": "Internal Wiki", "url": "https://example.com"}, {"text": "Submit a Ticket", "url": "https://example2.com"}]
    INDEX_PAGE_CUSTOM_LINKS = []

    # Custom Link to be displayed on the Login Page
    # Format: List of dictionary with text and url
    # URL must start with http or https
    # ex: [{ "text": "Internal Wiki", "url": "https://example.com"}, {"text": "Submit a Ticket", "url": "https://example2.com"}]
    LOGIN_PAGE_CUSTOM_LINKS = []


app_config = Config()
