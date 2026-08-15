#!/usr/bin/env python3
######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                                #
######################################################################################################################
"""
EDH Webshell Service
====================

Runs on Login Nodes. Accepts WebSocket connections from the SOCA WebUI, validates
the caller's identity against the controller using the existing X-EDH-USER /
X-EDH-TOKEN headers, then attaches the caller to a per-user tmux session via a
PTY. tmux gives the user suspend/resume semantics: closing the browser tab does
not kill the shell, and reconnecting reattaches to the same session.

Design notes
------------
* Auth is transitive: this service does NOT implement authentication itself. It
  propagates the user-supplied X-EDH-USER / X-EDH-TOKEN to the controller's
  /api/login_nodes/list endpoint (which uses @private_api -> validate_token) and only
  proceeds if the controller confirms the pair is valid for that user.
* The process runs as root (required for setuid to the target user) but drops
  privileges immediately after forking the PTY, so the user's shell runs under
  their own uid/gid.
* tmux session name is `edh_<user>` so re-attach is automatic.
* The service listens on 127.0.0.1:7681 by default; the ALB health check and
  ingress rules are configured to route /web_terminal/endpoint/* to this port.

Environment variables
---------------------
EDH_WEBSHELL_LISTEN_HOST          default 0.0.0.0 (ALB target group reaches us directly)
EDH_WEBSHELL_LISTEN_PORT          default 7681
EDH_WEBSHELL_CONTROLLER_URL       required, e.g. https://controller.internal:8443
EDH_WEBSHELL_LOG_LEVEL            default INFO
EDH_WEBSHELL_IDLE_SECONDS         default 1800  (30m) - close after no I/O for this long
EDH_WEBSHELL_MAX_SESSION_SECONDS  default 0     (disabled) - hard wall-clock cap on session lifetime
EDH_WEBSHELL_IDLE_TIMEOUT         deprecated -- previously used as wall-clock cap (misnamed); honoured
                                  as MAX_SESSION_SECONDS for backwards compatibility when set.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import pty
import pwd
import re
import signal
import struct
import subprocess
import sys
import termios
from typing import Optional

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
except ImportError:
    # Don't hard-fail at import time - let the module be importable for
    # unit tests that exercise pure logic like _extract_credentials. The
    # real check is in _main() below, which is only reached at service startup.
    websockets = None  # type: ignore[assignment]
    WebSocketServerProtocol = None  # type: ignore[assignment,misc]

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

# boto3 is used only for CloudWatch metric emission. Import failure is
# non-fatal: metrics just won't be sent. The service and auth still work.
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    boto3 = None  # type: ignore[assignment]
    BotoCoreError = ClientError = Exception  # type: ignore[assignment,misc]

# utmp/wtmp registration so `who`/`w`/`last` see webshell sessions. Module
# is import-safe on non-Linux (returns False from add/remove). See module
# docstring for the rationale.
try:
    from . import webshell_utmp  # type: ignore[import-not-found]
except ImportError:
    try:
        import webshell_utmp  # type: ignore[no-redef]
    except ImportError:
        webshell_utmp = None  # type: ignore[assignment]


LISTEN_HOST = os.environ.get("EDH_WEBSHELL_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("EDH_WEBSHELL_LISTEN_PORT", "7681"))
# Health check is served on a separate HTTP-only port so the ALB can reach
# it with a plain GET /healthz. The main WebSocket port does not speak HTTP
# (the websockets library answers every non-upgrade request with 426).
# Set EDH_WEBSHELL_HEALTH_PORT=0 to disable the health port entirely.
HEALTH_PORT = int(os.environ.get("EDH_WEBSHELL_HEALTH_PORT", "7682"))
CONTROLLER_URL = os.environ.get("EDH_WEBSHELL_CONTROLLER_URL", "").rstrip("/")
# Idle timeout: close a connection after this many seconds of NO I/O on
# either pump (ws->pty or pty->ws). Active terminals never trip this.
# Default: 30 minutes - long enough to step away for coffee, short enough
# that abandoned tabs don't pin sidecar resources forever. The underlying
# tmux session is unaffected (re-attach reconnects).
IDLE_SECONDS = int(os.environ.get("EDH_WEBSHELL_IDLE_SECONDS", "1800"))
# Hard wall-clock cap on a single WebSocket connection regardless of
# activity. 0 disables the cap. Note this does NOT kill the tmux server -
# the user can immediately reconnect to the same session. The legacy
# EDH_WEBSHELL_IDLE_TIMEOUT env var was misnamed (it was actually a
# wall-clock cap, never an idle detector); we honour it as
# MAX_SESSION_SECONDS for backwards compatibility when explicitly set.
_legacy_max = os.environ.get("EDH_WEBSHELL_IDLE_TIMEOUT")
MAX_SESSION_SECONDS = int(
    os.environ.get("EDH_WEBSHELL_MAX_SESSION_SECONDS", _legacy_max or "0")
)
LOG_LEVEL = os.environ.get("EDH_WEBSHELL_LOG_LEVEL", "INFO").upper()

# Control-plane endpoints (list/kill tmux sessions) are NOT served by this
# sidecar. The controller invokes them via SSM Run Command against the
# login-node fleet (see installer/resources/src/helpers/webshell.py and
# source/soca/cluster_manager/web_interface/views/ssh.py). This sidecar
# now only serves the WebSocket terminal and the /healthz endpoint.
#
# Rationale: any IAM permission granted to the login-node EC2 instance
# role is also granted to every shell user via IMDSv2, and any local
# port the sidecar listens on is reachable by every local process. So
# the login node cannot be the trust source for cross-user operations
# like "list/kill another user's tmux session". The controller is the
# only admin-trusted host; it issues SSM Run Command (which AWS-SSM-agent
# executes as root, isolated from user processes) using the controller's
# own IAM identity. A malicious shell user on a login node has no path
# to impersonate the controller because they cannot themselves invoke
# ssm:SendCommand without IAM permission.

# CloudWatch metric emission. Off unless the operator explicitly sets a
# cluster id - we don't want unscoped "EDH/Webshell" metrics polluting
# account-level CloudWatch in shared accounts.
#
# Dimensions emitted:
#   - ClusterId    (e.g. "edh-prod1")
#   - InstanceId   (the login node emitting the metric, from IMDS)
CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")
CW_NAMESPACE = os.environ.get("EDH_WEBSHELL_CW_NAMESPACE", "EDH/Webshell")
METRICS_ENABLED = bool(CLUSTER_ID) and boto3 is not None
_cloudwatch_client = None  # Lazily initialised on first emit
_instance_id_cache: Optional[str] = None

# Username validation: POSIX-compliant, matches what the installer allows
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# Session name validation: matches the client-supplied session label that's
# concatenated into the tmux session name. Allow alnum + _ - and cap length
# so we never produce a tmux session string that trips tmux's own parsing.
# Example client values: "main", "popout-1", "popout-2".
_SESSION_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s [webshell] %(message)s",
)
logger = logging.getLogger("edh_webshell")


# ---------------------------------------------------------------------------
# CloudWatch metrics
# ---------------------------------------------------------------------------
#
# Metric emission is best-effort: any failure (boto3 not installed, no IAM
# permission, network error, throttling) is logged at DEBUG and ignored.
# The service's correctness must not depend on metrics landing.
#
# Metric names:
#   AuthSuccess        (Count) - controller accepted credentials
#   AuthFailure        (Count) - controller rejected credentials
#   AuthError          (Count) - network/transport error talking to controller
#   ConnectionOpened   (Count) - a browser successfully attached a PTY
#   ConnectionClosed   (Count) - a PTY was torn down (for any reason)
#   ActiveSessions     (Count) - gauge of currently-attached browsers


def _get_instance_id() -> Optional[str]:
    """Best-effort IMDSv2 lookup of our instance id. Cached after first call
    so we don't hit IMDS for every metric."""
    global _instance_id_cache
    if _instance_id_cache is not None:
        return _instance_id_cache or None
    if requests is None:
        _instance_id_cache = ""
        return None
    try:
        token_resp = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=1,
        )
        token_resp.raise_for_status()
        iid_resp = requests.get(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token_resp.text},
            timeout=1,
        )
        iid_resp.raise_for_status()
        _instance_id_cache = iid_resp.text.strip()
        return _instance_id_cache
    except Exception as exc:
        logger.debug("IMDS lookup for instance id failed: %s", exc)
        _instance_id_cache = ""
        return None


def _emit_metric(metric_name: str, value: float = 1.0, unit: str = "Count") -> None:
    """Send a single CloudWatch metric data point.

    Best-effort - any failure is swallowed with a DEBUG log. Called from
    sync contexts (it's a quick call) but guarded so it never blocks auth
    or connection handling for more than a few milliseconds.
    """
    if not METRICS_ENABLED:
        return

    global _cloudwatch_client
    if _cloudwatch_client is None:
        try:
            _cloudwatch_client = boto3.client("cloudwatch")
        except (BotoCoreError, ClientError, Exception) as exc:
            logger.debug("failed to initialise CloudWatch client: %s", exc)
            return

    dimensions = [{"Name": "ClusterId", "Value": CLUSTER_ID}]
    iid = _get_instance_id()
    if iid:
        dimensions.append({"Name": "InstanceId", "Value": iid})

    try:
        _cloudwatch_client.put_metric_data(
            Namespace=CW_NAMESPACE,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": value,
                    "Unit": unit,
                    "Dimensions": dimensions,
                }
            ],
        )
    except (BotoCoreError, ClientError) as exc:
        logger.debug("put_metric_data(%s) failed: %s", metric_name, exc)


# In-process session counter. Driven by _handle_connection; emits an
# ActiveSessions gauge periodically via _session_gauge_task.
_active_sessions = 0


class AuthError(Exception):
    """Raised when the caller's EDH credentials cannot be validated."""


class ActivityTracker:
    """Mutable container for the last I/O timestamp on a session.

    Both pump tasks call .bump() on every byte they push or pull, and the
    idle watchdog reads .last_ts to decide whether the session has been
    quiet long enough to close. Using a tiny class (rather than a list or
    closure-cell) keeps the call sites self-documenting.
    """

    __slots__ = ("last_ts",)

    def __init__(self) -> None:
        # asyncio.get_event_loop().time() is monotonic, so we don't have to
        # worry about wall-clock jumps invalidating idle measurements.
        self.last_ts = asyncio.get_event_loop().time()

    def bump(self) -> None:
        self.last_ts = asyncio.get_event_loop().time()


async def _idle_watchdog(
    activity: "ActivityTracker",
    ws: WebSocketServerProtocol,
    *,
    idle_seconds: int,
    max_session_seconds: int,
) -> None:
    """Close `ws` once it has been idle for `idle_seconds`, OR once
    `max_session_seconds` of wall-clock time has elapsed (when set).

    Polls every `min(idle_seconds, 30)` seconds so the worst-case overshoot
    is bounded. A zero/negative idle_seconds disables idle detection (we
    only enforce the wall-clock cap, if any).
    """
    if idle_seconds <= 0 and max_session_seconds <= 0:
        # Nothing to enforce - sleep forever.
        await asyncio.Future()
        return

    loop = asyncio.get_event_loop()
    started_at = loop.time()
    poll_interval = max(1, min(idle_seconds if idle_seconds > 0 else 30, 30))

    while True:
        await asyncio.sleep(poll_interval)
        now = loop.time()
        if idle_seconds > 0 and (now - activity.last_ts) >= idle_seconds:
            logger.info(
                "closing idle session (no I/O for %ds, threshold=%ds)",
                int(now - activity.last_ts),
                idle_seconds,
            )
            try:
                await ws.close(code=4408, reason="idle timeout")
            finally:
                return
        if max_session_seconds > 0 and (now - started_at) >= max_session_seconds:
            logger.info(
                "closing session at wall-clock cap (%ds elapsed, cap=%ds)",
                int(now - started_at),
                max_session_seconds,
            )
            try:
                await ws.close(code=4408, reason="max session duration")
            finally:
                return


def _validate_username(user: str) -> bool:
    """Defensive check: usernames must be POSIX-safe. The controller also
    validates this, but we never want to shell out with user-controlled strings
    without pre-validation."""
    return bool(user and _USERNAME_RE.match(user))


def _authenticate(user: str, token: str) -> None:
    """Call back to the controller to verify the (user, token) pair. The
    controller's /api/user/api_key endpoint requires a valid X-EDH-TOKEN that
    matches the user in the ApiKeys table (see validate_token in
    web_interface/decorators.py).

    Any failure here raises AuthError. We never log the token.
    """
    if not CONTROLLER_URL:
        raise AuthError(
            "webshell service misconfigured: EDH_WEBSHELL_CONTROLLER_URL not set"
        )

    if not _validate_username(user):
        raise AuthError(f"invalid username format")

    if not token or len(token) < 16:
        raise AuthError("missing or malformed token")

    try:
        # We delegate credential validation to the controller by calling an
        # `@private_api`-decorated endpoint - the decorator runs the exact
        # same `validate_token(user, token)` check that every other SOCA
        # API call uses. We hit /api/login_nodes/list because:
        #   1. It's gated on the LOGIN_NODES feature flag, which is also
        #      what controls the webshell itself - so we fail closed when
        #      the feature is disabled instead of letting users in anyway.
        #   2. It has no side effects (GET, enumerates login node IPs).
        #   3. It's cheap (one DescribeInstances call, cached briefly by
        #      the controller).
        # A dedicated /api/user/validate_token endpoint was considered and
        # rejected: it would duplicate decorator logic with no added
        # security. /api/user/api_key CAN NOT be used here because its
        # decorator (@retrieve_api_key) requires X-EDH-PASSWORD, not a
        # token.
        response = requests.get(
            f"{CONTROLLER_URL}/api/login_nodes/list",
            headers={"X-EDH-USER": user, "X-EDH-TOKEN": token},
            timeout=5,
            verify=False,  # nosec - internal VPC traffic, controller uses self-signed cert
        )
    except requests.RequestException as exc:
        logger.error("controller callback failed for user=%s: %s", user, exc)
        _emit_metric("AuthError")
        raise AuthError("controller is unreachable")

    if response.status_code != 200:
        _emit_metric("AuthFailure")
        raise AuthError(
            f"controller rejected credentials (HTTP {response.status_code})"
        )

    try:
        payload = response.json()
    except ValueError:
        _emit_metric("AuthError")
        raise AuthError("controller returned non-JSON response")

    # Strict validation: the payload must be a dict and 'success' must be
    # exactly True (not "False", not 1, not any truthy value). This guards
    # against a bugged or compromised controller returning a non-boolean
    # truthy value like {"success": "false"} that would otherwise pass.
    if not isinstance(payload, dict):
        _emit_metric("AuthError")
        raise AuthError("controller returned non-object JSON response")

    if payload.get("success") is not True:
        _emit_metric("AuthFailure")
        raise AuthError("controller denied credentials")

    # If we reach here, the controller said success=True.
    _emit_metric("AuthSuccess")


def _resolve_user(user: str) -> pwd.struct_passwd:
    """Look up the target user. Raises AuthError if the user does not exist on
    this host (e.g. LDAP lookup failed, user not yet provisioned)."""
    try:
        return pwd.getpwnam(user)
    except KeyError:
        raise AuthError(f"user {user!r} not found on this host")


def _spawn_tmux_pty(
    pw_entry: pwd.struct_passwd, session_label: str = "main"
) -> tuple[int, int]:
    """Fork a new PTY-attached process running `tmux new-session -A -s edh_<user>_<label>`
    as the target user. Returns (pid, master_fd).

    The `-A` flag makes tmux attach to an existing session with that name if one
    exists, or create it otherwise. This is exactly the suspend/resume semantic
    we want: the session outlives the websocket connection.

    `session_label` lets a single user have multiple independent tmux sessions
    (e.g. the inline terminal uses "main", pop-out windows use "popout-1",
    "popout-2", etc.). Caller MUST validate the label with _SESSION_NAME_RE
    before passing it in - we use it directly in the tmux session name.

    We intentionally exec `su - <user> -c 'exec tmux new-session -A -s ...'`
    rather than dropping privileges ourselves and exec'ing tmux directly.
    `su -` opens a full PAM session (pam_unix + pam_loginuid + pam_systemd +
    pam_limits etc.), which:
      * creates a utmp/wtmp entry, so `w`, `who`, and `last` see the user
      * runs the user's login scripts (/etc/profile, ~/.bash_profile, ...)
      * applies PAM resource limits
      * sets HOME/SHELL/USER/LOGNAME the same way sshd does
    This matches the behaviour users expect from `ssh user@login-node`.

    Environment scrubbing is now PAM's job (pam_env clears the environment
    for a login shell), but TERM is one var PAM won't restore -- we inject
    it via `env` on the command line so xterm escape sequences render.
    """
    session_name = f"edh_{pw_entry.pw_name}_{session_label}"

    # tmux invocation that runs inside the user's login shell. We quote the
    # session name by construction: _SESSION_NAME_RE restricts the label to
    # [A-Za-z0-9_-]{1,32} and the username is POSIX-validated upstream, so
    # the resulting session_name contains only characters safe for a shell
    # word (no spaces, quotes, $, backticks, or globs).
    # -f webshell.tmux.conf enables mouse-on (wheel scrolls pane scrollback, not shell history); guard so a missing conf never blocks startup
    _conf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webshell.tmux.conf")
    _conf_flag = f"-f {_conf} " if os.path.exists(_conf) else ""
    tmux_cmd = f"exec tmux {_conf_flag}new-session -A -s {session_name}"

    pid, master_fd = pty.fork()
    if pid == 0:
        # Child process: still root. `su -` performs the privilege drop
        # and PAM session setup. Prefix with `env TERM=xterm-256color`
        # because pam_env does not set TERM on a login shell.
        argv = [
            "env",
            "TERM=xterm-256color",
            "su",
            "-",
            pw_entry.pw_name,
            "-c",
            tmux_cmd,
        ]
        # Strip any inherited variables that could leak info across users.
        # `su -` will reset most of these anyway, but not all shells strip
        # unknown SUDO_* / EDH_* on login. Be explicit.
        for var in (
            "SUDO_USER",
            "SUDO_UID",
            "SUDO_GID",
            "SUDO_COMMAND",
            "EDH_WEBSHELL_CONTROLLER_URL",
            "EDH_WEBSHELL_LOG_LEVEL",
        ):
            os.environ.pop(var, None)

        try:
            os.execvp(argv[0], argv)
        except OSError as exc:
            os.write(2, f"webshell child: failed to exec su: {exc}\n".encode())
        os._exit(1)  # unreachable unless exec fails

    return pid, master_fd


def _set_pty_size(fd: int, rows: int, cols: int) -> None:
    """Tell the PTY that its terminal is `rows` x `cols`. Needed so apps
    like vim/less render correctly after browser resize."""
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass


async def _pump_pty_to_ws(
    master_fd: int,
    ws: WebSocketServerProtocol,
    activity: "ActivityTracker",
) -> None:
    """Read bytes from the PTY master and forward them to the browser.

    Bumps `activity.last_ts` on every successful read so the watchdog can
    distinguish active from idle sessions.
    """
    loop = asyncio.get_event_loop()
    try:
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            activity.bump()
            try:
                await ws.send(data)
            except websockets.exceptions.ConnectionClosed:
                break
    finally:
        pass


async def _pump_ws_to_pty(
    master_fd: int,
    ws: WebSocketServerProtocol,
    activity: "ActivityTracker",
) -> None:
    """Read messages from the browser. Binary payloads are forwarded verbatim as
    keystrokes. JSON text messages are treated as control messages (resize).

    `os.write(master_fd, ...)` is blocking on Linux PTYs (the secondary side
    might be a tmux pipe with a full buffer), so it runs in the default
    executor to keep the asyncio loop responsive for OTHER concurrent
    sessions on this sidecar. Without this, a single user with a stalled
    PTY could starve every other connected webshell session.
    """
    loop = asyncio.get_event_loop()
    async for message in ws:
        if isinstance(message, bytes):
            try:
                await loop.run_in_executor(None, os.write, master_fd, message)
            except OSError:
                break
            activity.bump()
            continue

        # Text frame. Must be a JSON control envelope. Ignore anything else so a
        # malicious client can't smuggle control bytes.
        try:
            envelope = json.loads(message)
        except (ValueError, TypeError):
            logger.debug("ignoring non-JSON text frame")
            continue
        if not isinstance(envelope, dict):
            # JSON allows scalars and arrays as top-level values; only an
            # object can carry a control "type" so anything else is junk.
            logger.debug("ignoring non-object control frame")
            continue

        msg_type = envelope.get("type")
        if msg_type == "resize":
            # Defensive parsing - a malicious or buggy client may send
            # "rows": "abc" or {"rows": [1, 2, 3]}. Bare int() on those
            # raises ValueError / TypeError and would cancel the WS pump
            # task, killing the user's terminal silently.
            def _parse_dim(value, default):
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return default

            rows = _parse_dim(envelope.get("rows"), 24)
            cols = _parse_dim(envelope.get("cols"), 80)
            # Clamp to sane bounds; terminals larger than this are a red flag
            rows = max(1, min(rows, 500))
            cols = max(1, min(cols, 500))
            _set_pty_size(master_fd, rows, cols)
            activity.bump()
        elif msg_type == "ping":
            # Lightweight keepalive - no-op, just proves the session is active
            activity.bump()
            continue
        else:
            logger.debug("unknown control message type: %r", msg_type)


def _extract_credentials(
    headers: "CollectionLike", ws_path: str
) -> tuple[str, str, str]:
    """Extract (user, token, source) from a WebSocket upgrade request.

    Pure function - no I/O. Factored out of _handle_connection so it can be
    unit-tested in isolation.

    Credentials can arrive three ways, in preference order:

        1. Cookie `edh_webshell_auth` - the primary path for browser clients.
           The WebUI sets a short-lived HttpOnly Secure SameSite=Strict
           cookie via /web_terminal/terminal_auth just before the WebSocket opens.
           The ALB forwards cookies on WebSocket upgrades, and cookies do
           NOT appear in URLs or standard ALB access logs.

        2. Request headers X-EDH-USER / X-EDH-TOKEN - for curl tests and
           non-browser clients that can set arbitrary headers.

        3. Query string ?user=...&token=... - last-resort fallback for
           clients that cannot set headers and do not carry the cookie.
           DO NOT use this path in production browsers: query strings may
           be captured by ALB access logs or intermediate proxies.

    Arguments
    ---------
    headers   : dict-like with .get(name, default) - typically ws.request_headers
    ws_path   : str - the path portion of the upgrade request, e.g.
                "/web_terminal/endpoint?user=foo&token=bar"

    Returns
    -------
    (user, token, source) where source is one of:
        - "cookie"
        - "header"
        - "query"
        - "none"     - no credentials found

    The caller is responsible for authenticating (user, token) against the
    controller; this function only extracts them.
    """
    # Path 1: cookie
    cookie_header = headers.get("Cookie", "") or ""
    if cookie_header:
        try:
            from http.cookies import SimpleCookie

            jar = SimpleCookie()
            jar.load(cookie_header)
            if "edh_webshell_auth" in jar:
                raw = jar["edh_webshell_auth"].value
                # Format: "user|token". Split on first '|' only so tokens
                # that happen to contain '|' are preserved.
                if "|" in raw:
                    user, token = raw.split("|", 1)
                    if user and token:
                        return user, token, "cookie"
        except Exception:
            # Malformed cookie - fall through to next auth path
            pass

    # Path 2: headers
    user = headers.get("X-EDH-USER", "") or ""
    token = headers.get("X-EDH-TOKEN", "") or ""
    if user and token:
        return user, token, "header"

    # Path 3: query string (last resort - discouraged in production)
    try:
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(ws_path)
        qs = parse_qs(parsed.query)
        user = (qs.get("user", [""])[0]) or ""
        token = (qs.get("token", [""])[0]) or ""
        if user and token:
            return user, token, "query"
    except Exception:
        pass

    return "", "", "none"


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
#
# The websockets library accepts an optional `process_request` callable that
# runs for every incoming HTTP request BEFORE the WebSocket upgrade. If the
# callable returns an (HTTPStatus, headers, body) tuple, websockets sends
# that as a plain HTTP response and closes the connection. If it returns
# None, the upgrade proceeds normally.
#
# We use this to expose a /healthz endpoint for ALB health checks. The check
# does a lightweight synchronous HTTP GET to the controller to prove the
# auth path is reachable - not just "am I listening?".
#
# Cache the result for a few seconds so a flapping controller doesn't
# DoS itself via health checks, and so the fast path is fast.

_health_cache: dict = {"status": 503, "body": b"starting", "checked_at": 0.0}
_HEALTH_CACHE_TTL_S = 10

# Cached tmux-ok signal. True once `tmux -V` has succeeded at least once.
# We cache positive results (tmux is stable once installed) but re-check on
# every cycle while still False, so recovery is noticed promptly.
# If tmux is removed at runtime from a healthy node, users will see failed
# connections and journalctl will show the real error, but /healthz will
# still report ok. That's accepted: removing tmux from a running host is
# extremely unusual, and users can always fall back to external SSH.
# To force a re-check: `systemctl restart edh-webshell`.
_tmux_ok_cache: bool = False


def _tmux_binary_ok() -> bool:
    """Return True if `tmux -V` runs and exits 0. See cache comment above."""
    global _tmux_ok_cache
    if _tmux_ok_cache:
        return True
    import subprocess

    try:
        # 1s timeout is generous; tmux -V returns instantly on healthy systems.
        completed = subprocess.run(
            ["tmux", "-V"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1,
            check=False,
        )
        if completed.returncode == 0:
            _tmux_ok_cache = True
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("tmux binary check failed: %s", exc)
    return False


def _check_service_health() -> tuple[int, bytes]:
    """Return (http_status, body) describing whether the service is capable
    of handling a new terminal connection. Called from _process_request
    behind a short TTL cache.

    Checks two things that can break independently:

    1. **tmux is on PATH and runnable.** Without tmux, `_spawn_tmux_pty`
       fails at exec() time for every user. If the install.sh tmux step
       failed during bootstrap, OR if a package update removes tmux at
       runtime, this check catches it and the ALB marks the node
       unhealthy.

    2. **The controller is reachable.** If the controller is down or the
       URL is misconfigured, every auth fails. A 503 keeps user traffic
       off this node until the upstream recovers.
    """
    # Check 1: tmux binary is available. Runs first because if tmux is
    # missing we can't serve any user, and we'd rather surface that
    # specifically than mask it behind an upstream error.
    if not _tmux_binary_ok():
        return 503, b"tmux not available - install tmux or restart the service"

    # Check 2: controller reachability.
    if not CONTROLLER_URL:
        return 503, b"CONTROLLER_URL not set"
    if requests is None:
        return 503, b"requests not installed"
    try:
        # Hit /ping which every SOCA controller exposes, not /api/user/api_key
        # which would require auth. If /ping doesn't exist on older
        # controllers, we still accept any <500 as proof that something is
        # listening (auth-level rejection is fine - it proves the service
        # is up).
        r = requests.get(
            f"{CONTROLLER_URL}/ping",
            timeout=2,
            verify=False,  # nosec - internal VPC traffic
        )
        if r.status_code < 500:
            return 200, b"ok"
        return 503, f"controller HTTP {r.status_code}".encode()
    except requests.RequestException as exc:
        return 503, f"controller unreachable: {exc.__class__.__name__}".encode()


# ---------------------------------------------------------------------------
# HTTP health server (secondary port, HTTP-only)
# ---------------------------------------------------------------------------
#
# The main WebSocket port (7681) cannot serve plain HTTP - the websockets
# library answers every non-upgrade request with 426 Upgrade Required,
# which the ALB target group misreads as unhealthy. We run a tiny stdlib
# http.server in a daemon thread on a separate port (7682 default) that
# answers GET /healthz with the same _check_service_health() result used
# elsewhere. State (tmux cache, health cache) is shared in-process.
#
# The health port is HTTP-only, no TLS - the ALB terminates TLS at its
# listener and forwards cleartext to this port inside the VPC.

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time as _time

# -----------------------------------------------------------------------------
# Removed: _constant_time_equal, _SESSION_PREFIX, _TMUX_LIST_FMT,
# _list_user_sessions, _kill_user_session, _is_valid_user.
#
# These helpers backed the now-deleted /sessions and /kill control-plane
# HTTP endpoints. The controller invokes the equivalent operations via SSM
# Run Command, which is executed by AWS-SSM-agent (root-isolated, not
# user-attackable) under the controller's IAM identity. The actual tmux
# enumeration/kill logic lives in the SSM document body shipped from CDK
# (see installer/resources/src/helpers/webshell.py).
# -----------------------------------------------------------------------------


class _HealthHandler(BaseHTTPRequestHandler):
    """Serve only /healthz. Everything else returns 404.

    Historical note: this handler used to also serve /sessions and /kill
    (control-plane operations) gated by a shared HMAC secret read from an
    env file. That design was removed because the login node is multi-
    tenant ground -- any user with shell access could read the env file
    or the SSM secret it was sourced from, then call localhost:7682 with
    the right header to enumerate or kill any other user's tmux sessions.
    The control plane now lives on the controller and reaches login nodes
    via SSM Run Command (see views/ssh.py and helpers/webshell.py).
    """

    # Silence the default per-request access log (journalctl is enough).
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        logger.debug("healthz %s", format % args)

    def do_GET(self):
        if self.path == "/healthz":
            self._serve_health()
            return
        self._not_found()

    def do_POST(self):
        # No POST endpoints on this server. Control-plane operations
        # (was: POST /kill) moved to controller-side SSM Run Command.
        self._not_found()

    # ---------------------------------------------------------------
    # Handlers
    # ---------------------------------------------------------------
    def _serve_health(self):
        # 10-second cache in front of _check_service_health so a flapping
        # ALB health-check schedule doesn't hammer the controller or
        # subprocess-exec tmux per-check.
        now = _time.monotonic()
        if now - _health_cache["checked_at"] > _HEALTH_CACHE_TTL_S:
            status, body = _check_service_health()
            _health_cache.update(status=status, body=body, checked_at=now)

        self.send_response(_health_cache["status"])
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        body = _health_cache["body"]
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.wfile.write(body + b"\n")

    def _not_found(self):
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"not found\n")


def _start_health_server() -> None:
    """Start the health HTTP server on a daemon thread. Non-fatal on
    bind error - the main WS server still starts, but health checks
    won't work and the ALB will mark the target unhealthy. Log loudly
    so an operator notices."""
    if HEALTH_PORT <= 0:
        logger.info("health port disabled (EDH_WEBSHELL_HEALTH_PORT=0)")
        return
    try:
        srv = ThreadingHTTPServer((LISTEN_HOST, HEALTH_PORT), _HealthHandler)
    except OSError as exc:
        logger.error(
            "failed to bind health server on %s:%d: %s - /healthz will not "
            "respond and ALB target group will report unhealthy",
            LISTEN_HOST,
            HEALTH_PORT,
            exc,
        )
        return
    t = threading.Thread(
        target=srv.serve_forever,
        name="edh-health",
        daemon=True,
    )
    t.start()
    logger.info("health server listening on %s:%d/healthz", LISTEN_HOST, HEALTH_PORT)


async def _handle_connection(ws: WebSocketServerProtocol) -> None:
    peer = ws.remote_address
    logger.info("new connection from %s (path=%s)", peer, ws.path)

    user, token, auth_source = _extract_credentials(ws.request_headers, ws.path)

    if auth_source == "query":
        logger.warning(
            "auth via query string from %s - prefer cookie or header auth", peer
        )
    elif auth_source == "none":
        logger.warning("no credentials supplied by %s", peer)

    try:
        # _authenticate uses synchronous `requests.get` (the sidecar runs
        # in its own venv and cannot import SocaHttpClient). A stalled
        # controller would otherwise block this asyncio task and starve
        # every other connected session on this sidecar. Push the call
        # to the default executor so other sessions keep flowing.
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _authenticate, user, token)
    except AuthError as exc:
        logger.warning("auth rejected for %s: %s", peer, exc)
        await ws.close(code=4401, reason="authentication failed")
        return

    try:
        pw_entry = _resolve_user(user)
    except AuthError as exc:
        logger.warning("user lookup failed for %s: %s", user, exc)
        await ws.close(code=4404, reason=str(exc))
        return

    # Parse session label from the WS URL query string (e.g. ?session=main
    # or ?session=popout-1). Empty/missing defaults to "main". Invalid
    # values are rejected so we never shell out with unsanitized strings.
    session_label = "main"
    try:
        from urllib.parse import urlparse, parse_qs

        qs = parse_qs(urlparse(ws.path).query)
        raw = (qs.get("session", [""])[0] or "").strip()
        if raw:
            if not _SESSION_NAME_RE.match(raw):
                logger.warning("rejected invalid session label %r from %s", raw, peer)
                await ws.close(code=4400, reason="invalid session label")
                return
            session_label = raw
    except Exception as exc:
        logger.debug("failed to parse session label: %s", exc)

    logger.info(
        "auth ok for user=%s session=%s, spawning tmux pty", user, session_label
    )

    try:
        pid, master_fd = _spawn_tmux_pty(pw_entry, session_label)
    except OSError as exc:
        logger.exception("failed to spawn pty for user=%s: %s", user, exc)
        await ws.close(code=4500, reason="failed to spawn shell")
        return

    # Register the session in /var/run/utmp so `who`, `w`, and `last`
    # show the webshell user the same way they show ssh users. Each
    # browser tab gets its own pts -> its own utmp slot. Failure here
    # is non-fatal (warning logged); the shell still works.
    pts_path = webshell_utmp.pts_name(master_fd) if webshell_utmp else None
    utmp_registered = False
    if pts_path:
        utmp_registered = webshell_utmp.add_login_entry(pts_path, user, pid)

    # Initial size - the frontend will send a proper resize shortly.
    _set_pty_size(master_fd, 24, 80)

    # Metrics: count this as an opened session and bump the active gauge.
    global _active_sessions
    _active_sessions += 1
    _emit_metric("ConnectionOpened")
    _emit_metric("ActiveSessions", float(_active_sessions), unit="Count")

    activity = ActivityTracker()
    ws_to_pty = asyncio.create_task(_pump_ws_to_pty(master_fd, ws, activity))
    pty_to_ws = asyncio.create_task(_pump_pty_to_ws(master_fd, ws, activity))
    watchdog = asyncio.create_task(
        _idle_watchdog(
            activity,
            ws,
            idle_seconds=IDLE_SECONDS,
            max_session_seconds=MAX_SESSION_SECONDS,
        )
    )

    try:
        # Either pump finishing means the connection is dead. The watchdog
        # finishing means we proactively closed for idle / max-duration; in
        # that case the pumps will then see ConnectionClosed and exit.
        await asyncio.wait(
            {ws_to_pty, pty_to_ws, watchdog},
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        for _t in (ws_to_pty, pty_to_ws, watchdog):
            _t.cancel()
        try:
            os.close(master_fd)
        except OSError:
            pass
        # The user's shell is backed by a tmux session which survives this
        # process; we only need to reap the tmux client that attached to it.
        try:
            os.kill(pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        # Drop the utmp/wtmp entry for this pts. We do this AFTER reaping
        # the child so `who` and `w` don't briefly show the session as
        # already-dead while the tmux client is still tearing down.
        if utmp_registered and pts_path:
            webshell_utmp.remove_login_entry(pts_path, user, pid)
        _active_sessions = max(0, _active_sessions - 1)
        _emit_metric("ConnectionClosed")
        _emit_metric("ActiveSessions", float(_active_sessions), unit="Count")
        logger.info("connection closed for user=%s", user)


async def _main() -> None:
    # Hard-fail here instead of at import time so unit tests can still import
    # the module to exercise pure functions like _extract_credentials.
    if websockets is None:
        sys.stderr.write(
            "FATAL: websockets package is not installed. "
            "Install with: pip install websockets\n"
        )
        sys.exit(1)
    if requests is None:
        sys.stderr.write(
            "FATAL: requests package is not installed. "
            "Install with: pip install requests\n"
        )
        sys.exit(1)

    if os.geteuid() != 0:
        logger.warning(
            "running as uid=%d; setuid() to target users will fail unless this "
            "process has CAP_SETUID. Intended to run as root via systemd.",
            os.geteuid(),
        )

    if not CONTROLLER_URL:
        logger.error("EDH_WEBSHELL_CONTROLLER_URL is not set; refusing to start")
        sys.exit(2)

    logger.info(
        "starting webshell service on %s:%d, controller=%s, idle=%ds, max_session=%ds",
        LISTEN_HOST,
        LISTEN_PORT,
        CONTROLLER_URL,
        IDLE_SECONDS,
        MAX_SESSION_SECONDS,
    )

    # Start the HTTP health server BEFORE the WS server so the ALB target
    # can go healthy as soon as the WS port is accepting connections.
    _start_health_server()

    async with websockets.serve(
        _handle_connection,
        LISTEN_HOST,
        LISTEN_PORT,
        # /healthz is served on a separate HTTP-only port (see
        # _start_health_server). We can't intercept plain HTTP on this
        # port - the websockets library always responds 426 to non-upgrade
        # requests, which the ALB misreads as unhealthy.
        #
        # No TLS here - the ALB terminates TLS and forwards to us in-VPC.
        ping_interval=30,
        ping_timeout=60,
        max_size=10 * 1024 * 1024,  # 10 MiB max frame, plenty for paste
    ):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        logger.info("shutting down")
