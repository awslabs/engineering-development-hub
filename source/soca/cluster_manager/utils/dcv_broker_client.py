# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DCV Session Manager Broker REST client.

Used by SOCA controller in DCV high-scale mode to register session+auth-token
mappings with the broker, so that the DCV server can validate connection
tokens against the broker (per
https://docs.aws.amazon.com/dcv/latest/sm-admin/configure-dcv-server.html ).

The flow is:
  1. SOCA launches a VDI via CFN; bootstrap renders DCV with create-session=false
     (no auto-created console session — see dcv_server.sh.j2 + dcv_session_setup.ps.j2)
  2. SM Agent on the VDI registers with the broker; broker now sees the
     server in describeServers
  3. SOCA controller (via session_state_watcher) calls broker.create_session()
     with Name=<SOCA-UUID>, Owner=<user>, Type=<CONSOLE|VIRTUAL>, and
     Requirements targeting the specific EC2 instance
  4. Broker tells the agent "create this session"; agent runs `dcv create-session`
  5. Broker returns Session record including AuthenticationToken
  6. SOCA stores the broker-issued token in VirtualDesktopSessions.authentication_token
  7. /virtual_desktops uses this token in the connection_string
  8. User connects → DCV server validates via broker → broker confirms

The broker has enable-authorization=false (no inbound auth on its API surface)
and runs in private subnets reachable only from the controller and gateway, so
no bearer token or signing is required for these calls. TLS verification is
disabled because the broker presents a self-signed cert.
"""

import json
import logging
import os
import time
from typing import Optional

import urllib3

from utils.config import SocaConfig
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

# Self-signed broker cert; same posture as the screenshot poller Lambda.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_HTTP = urllib3.PoolManager(cert_reqs="CERT_NONE")
_HEADERS = {"Content-Type": "application/json"}

# Operational metrics for broker API health. Emitted best-effort from every
# call so a degrading broker (5xx / timeouts / latency creep) surfaces a
# CloudWatch signal + admin-page panel instead of only a WebUI log line.
_METRIC_NAMESPACE = "EDH/DCVBroker"


def _emit_broker_metric(path: str, ok: bool, latency_ms: float) -> None:
    """Best-effort CloudWatch emit. Never raises -- broker interaction is the
    primary mission; observability must not mask or block it."""
    try:
        import boto3
        cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message", "unknown")
        )
        dims = [
            {"Name": "ClusterId", "Value": cluster_id},
            {"Name": "Path", "Value": path},
        ]
        boto3.client("cloudwatch").put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[
                {"MetricName": "BrokerApiErrors", "Dimensions": dims,
                 "Value": 0.0 if ok else 1.0, "Unit": "Count"},
                {"MetricName": "BrokerApiLatency", "Dimensions": dims,
                 "Value": latency_ms, "Unit": "Milliseconds"},
            ],
        )
    except Exception:
        pass


class DcvBrokerClient:
    """
    Thin REST client over the broker's client API (port 8443 by default).

    Resilient to broker startup races: each call retries a small number of
    times. Returns SocaResponse so callers can branch on .success without
    catching exceptions everywhere.
    """

    def __init__(self, endpoint: Optional[str] = None, port: Optional[int] = None):
        self._endpoint = endpoint or self._resolve_endpoint()
        self._port = port or self._resolve_client_port()
        self._base = f"https://{self._endpoint}:{self._port}"

    @staticmethod
    def _resolve_endpoint() -> str:
        _val = (
            SocaConfig(key="/dcv/backend_nlb_dns")
            .get_value()
            .get("message", "")
        )
        if not _val:
            raise RuntimeError(
                "DCV broker endpoint not available — /dcv/backend_nlb_dns is unset. "
                "Is the cluster running in high-scale mode?"
            )
        return _val

    @staticmethod
    def _resolve_client_port() -> int:
        _val = (
            SocaConfig(key="/dcv/broker/client_port")
            .get_value()
            .get("message", "8443")
        )
        try:
            return int(_val)
        except (TypeError, ValueError):
            return 8443

    def _post(self, path: str, body, timeout: float = 30.0, retries: int = 3) -> SocaResponse:
        url = f"{self._base}{path}"
        last_err = None
        _t0 = time.monotonic()
        for attempt in range(retries):
            try:
                resp = _HTTP.request(
                    "POST",
                    url,
                    body=json.dumps(body).encode("utf-8"),
                    headers=_HEADERS,
                    timeout=timeout,
                )
                if 200 <= resp.status < 300:
                    _emit_broker_metric(path, True, (time.monotonic() - _t0) * 1000.0)
                    return SocaResponse(
                        success=True,
                        message=json.loads(resp.data.decode("utf-8")),
                    )
                last_err = (
                    f"broker {path} returned HTTP {resp.status}: "
                    f"{resp.data[:300].decode('utf-8', errors='replace')}"
                )
                logger.warning("DcvBrokerClient: %s (attempt %d/%d)", last_err, attempt + 1, retries)
            except Exception as e:
                last_err = f"broker POST {path} raised {type(e).__name__}: {e}"
                logger.warning(
                    "DcvBrokerClient: %s (attempt %d/%d)",
                    last_err,
                    attempt + 1,
                    retries,
                )
        _emit_broker_metric(path, False, (time.monotonic() - _t0) * 1000.0)
        return SocaResponse(success=False, message=last_err or "unknown error")

    def _put(self, path: str, body, timeout: float = 30.0, retries: int = 3) -> SocaResponse:
        url = f"{self._base}{path}"
        last_err = None
        _t0 = time.monotonic()
        for attempt in range(retries):
            try:
                resp = _HTTP.request(
                    "PUT",
                    url,
                    body=json.dumps(body).encode("utf-8"),
                    headers=_HEADERS,
                    timeout=timeout,
                )
                if 200 <= resp.status < 300:
                    _emit_broker_metric(path, True, (time.monotonic() - _t0) * 1000.0)
                    return SocaResponse(
                        success=True,
                        message=json.loads(resp.data.decode("utf-8")),
                    )
                last_err = (
                    f"broker {path} returned HTTP {resp.status}: "
                    f"{resp.data[:300].decode('utf-8', errors='replace')}"
                )
                logger.warning("DcvBrokerClient: %s (attempt %d/%d)", last_err, attempt + 1, retries)
            except Exception as e:
                last_err = f"broker PUT {path} raised {type(e).__name__}: {e}"
                logger.warning(
                    "DcvBrokerClient: %s (attempt %d/%d)", last_err, attempt + 1, retries
                )
        _emit_broker_metric(path, False, (time.monotonic() - _t0) * 1000.0)
        return SocaResponse(success=False, message=last_err or "unknown error")

    def _get(self, path: str, timeout: float = 30.0, retries: int = 3) -> SocaResponse:
        url = f"{self._base}{path}"
        last_err = None
        _t0 = time.monotonic()
        for attempt in range(retries):
            try:
                resp = _HTTP.request("GET", url, headers=_HEADERS, timeout=timeout)
                if 200 <= resp.status < 300:
                    _emit_broker_metric(path, True, (time.monotonic() - _t0) * 1000.0)
                    return SocaResponse(
                        success=True,
                        message=json.loads(resp.data.decode("utf-8")),
                    )
                last_err = (
                    f"broker {path} returned HTTP {resp.status}: "
                    f"{resp.data[:300].decode('utf-8', errors='replace')}"
                )
                logger.warning(
                    "DcvBrokerClient: %s (attempt %d/%d)", last_err, attempt + 1, retries
                )
            except Exception as e:
                last_err = f"broker GET {path} raised {type(e).__name__}: {e}"
                logger.warning(
                    "DcvBrokerClient: %s (attempt %d/%d)",
                    last_err,
                    attempt + 1,
                    retries,
                )
        _emit_broker_metric(path, False, (time.monotonic() - _t0) * 1000.0)
        return SocaResponse(success=False, message=last_err or "unknown error")

    # --- public API ----------------------------------------------------------

    def describe_servers(self, timeout: float = 30.0, retries: int = 3) -> SocaResponse:
        """List DCV servers currently registered with the broker.

        timeout/retries are passthrough to _post so latency-sensitive callers
        (e.g. the synchronous admin overview page) can fast-fail instead of
        blocking on a degrading/cycling broker. Defaults preserve prior behavior.
        """
        return self._post("/describeServers", {}, timeout=timeout, retries=retries)

    def describe_sessions(self, timeout: float = 30.0, retries: int = 3) -> SocaResponse:
        """List sessions currently known to the broker. timeout/retries
        passthrough -- see describe_servers."""
        return self._post("/describeSessions", {}, timeout=timeout, retries=retries)

    def create_session(
        self,
        *,
        name: str,
        owner: str,
        session_type: str,
        instance_id: Optional[str] = None,
        requirements: Optional[str] = None,
        storage_root: Optional[str] = None,
        max_concurrent_clients: Optional[int] = None,
        permissions_file: Optional[str] = None,
    ) -> SocaResponse:
        """
        Register a new session with the broker.

        Broker createSessions is asynchronous: the response returns a
        Session record with State=CREATING and Substate=SESSION_PLACING.
        The broker then places the session on the targeted DCV server,
        which transitions State -> READY over a few seconds. The
        AuthenticationToken used to connect is *not* returned here -- it
        is fetched per-attempt via `get_session_connection_data` once the
        session reaches READY (each call returns a fresh ~1h JWT scoped
        to the (sessionId, user) pair).

        On success returns a SocaResponse with `message` =
            {"Id": "<broker-session-uuid>", "Name": "<session-name>",
             "Owner": "...", "Type": "...", "State": "CREATING",
             "Substate": "SESSION_PLACING"}
        Callers should persist the `Id` field; that is the handle used for
        subsequent `get_session_connection_data` and `delete_session`.

        On failure returns success=False with the broker's FailureReason.

        Either `instance_id` (preferred -- emits the canonical Requirements
        expression) or `requirements` (free-form expression for advanced
        targeting) should be provided. If neither is set the broker
        auto-selects an available server.
        """
        if session_type not in ("CONSOLE", "VIRTUAL"):
            return SocaResponse(
                success=False,
                message=f"invalid session_type {session_type!r}, expected CONSOLE or VIRTUAL",
            )

        request_data = {
            "Name": name,
            "Owner": owner,
            "Type": session_type,
        }
        if instance_id and not requirements:
            # Tags and Host.Aws.EC2InstanceId are NOT exposed as queryable
            # properties in the broker's requirements expression parser
            # (Property server:Tag.instance / server:Host.Aws.EC2InstanceId
            # both rejected at runtime). Pre-resolve to the broker's opaque
            # server Id via describeServers, then target with `server:Id`.
            server_id = self.find_server_id_by_instance(instance_id)
            if not server_id:
                return SocaResponse(
                    success=False,
                    message=(
                        f"DCV server for {instance_id} is not yet registered "
                        "with the broker; will retry"
                    ),
                )
            requirements = f"server:Id = '{server_id}'"
        if requirements:
            request_data["Requirements"] = requirements
        if storage_root:
            request_data["StorageRoot"] = storage_root
        if max_concurrent_clients is not None:
            request_data["MaxConcurrentClients"] = int(max_concurrent_clients)
        if permissions_file:
            request_data["PermissionsFile"] = permissions_file

        result = self._post("/createSessions", [request_data])
        if not result.success:
            return result

        body = result.message or {}
        successful = body.get("SuccessfulList") or []
        unsuccessful = body.get("UnsuccessfulList") or []
        if successful:
            entry = successful[0]
            session = entry.get("Session") or entry
            return SocaResponse(success=True, message=session)
        reason = "no successful list entry"
        if unsuccessful:
            reason = (unsuccessful[0].get("FailureReason") or reason).strip()
        return SocaResponse(success=False, message=f"createSessions failed: {reason}")

    def delete_session(self, *, session_id: str, owner: str) -> SocaResponse:
        """Delete a session previously registered with the broker."""
        result = self._post(
            "/deleteSessions",
            [{"SessionId": session_id, "Owner": owner}],
        )
        if not result.success:
            return result
        body = result.message or {}
        if body.get("SuccessfulList"):
            return SocaResponse(success=True, message=body["SuccessfulList"][0])
        unsuccessful = body.get("UnsuccessfulList") or []
        reason = "no successful list entry"
        if unsuccessful:
            reason = (unsuccessful[0].get("FailureReason") or reason).strip()
        return SocaResponse(success=False, message=f"deleteSessions failed: {reason}")

    def get_session_connection_data(
        self, *, session_id: str, user: str
    ) -> SocaResponse:
        """
        Fetch a one-shot connection token for a specific (session, user)
        pair. The broker returns a fresh ECDSA-signed JWT (`ConnectionToken`)
        scoped to that pair -- a new one is issued on each call (~1h ttl).

        Endpoint: GET /sessionConnectionData/{sessionId}/{user}

        On success returns a SocaResponse with `message` =
            {"Session": {...full broker session record...},
             "ConnectionToken": "<jwt>"}
        On failure returns success=False with the broker error.

        Path-encode-safe inputs only: session_id should be a UUID and user
        should be a plain login (no slashes/spaces). The broker returns 400
        on malformed input.
        """
        from urllib.parse import quote

        path = f"/sessionConnectionData/{quote(session_id, safe='')}/{quote(user, safe='')}"
        return self._get(path)

    def update_session_permissions(
        self, *, session_id: str, owner: str, permissions_content: str
    ) -> SocaResponse:
        """
        Push an updated .perm file to a live session via the broker.

        The broker forwards the permission file to the DCV server's agent,
        which hot-applies it without disconnecting existing users. Permission
        changes take effect immediately for new actions (e.g. input blocked
        if removed from the guest's allow set).

        Args:
            session_id: Broker session ID.
            owner: Session owner (AD username).
            permissions_content: Plain-text .perm file content (NOT base64).
                Example: "[permissions]\\n%owner% allow builtin\\nguest allow display pointer"

        Returns SocaResponse with success=True if the broker accepted the update.
        """
        import base64

        perm_b64 = base64.b64encode(permissions_content.encode()).decode()
        result = self._put(
            "/sessionPermissions",
            [{"SessionId": session_id, "Owner": owner, "PermissionsFile": perm_b64}],
        )
        if not result.success:
            return result
        body = result.message or {}
        if body.get("SuccessfulList"):
            return SocaResponse(success=True, message=body["SuccessfulList"][0])
        unsuccessful = body.get("UnsuccessfulList") or []
        reason = "no successful list entry"
        if unsuccessful:
            reason = (unsuccessful[0].get("FailureReason") or reason).strip()
        return SocaResponse(success=False, message=f"updateSessionPermissions failed: {reason}")

    # --- helpers -------------------------------------------------------------

    def find_session_by_name(self, name: str) -> Optional[dict]:
        """
        Look up an existing broker session that "matches" our SOCA session.
        Returns the broker session record (with Id, State, Owner, ...) or
        None if no match.

        Matching falls through two cases:

        1. Sessions created via broker.createSessions get a broker-assigned
           Id and we set Name=<our SOCA session_uuid>. Match by Name.
        2. Sessions created locally on the DCV host (e.g. by socadcv.service
           running `dcv create-session ... <SOCA-UUID>` at boot) get
           Id=<SOCA-UUID> and Name="" when the SM agent reports them up.
           Match by Id == name.

        Used to make `create_session` idempotent across watcher cycles --
        if a previous cycle (or the local DCV server bootstrap) already
        registered the session, we recover the broker handle without
        trying to create a duplicate (which would fail with
        "no dcv server found for placement" because the server is
        SERVER_FULL with the existing session).
        """
        result = self.describe_sessions()
        if not result.success:
            return None
        for session in (result.message or {}).get("Sessions", []):
            if session.get("Name") == name or session.get("Id") == name:
                return session
        return None

    def find_server_id_by_instance(self, instance_id: str) -> Optional[str]:
        """
        Look up a registered DCV server by its EC2 instance id, matched on the
        broker-native Host.Aws.EC2InstanceId (which the DCV server reports from
        IMDS at registration -- always live). Returns the broker's opaque server
        Id, or None if no match.

        We deliberately do NOT match the SM Agent `instance` tag: it is written
        to a file (conf/tags/instance) that a specialized (Save) AMI bakes, so it
        is stale on every resumed/recycled server and can even collide across
        servers (two live servers advertising the same origin id) -> routing a
        session to the wrong / dead server. Host.Aws.EC2InstanceId cannot go
        stale. IMDS is the source of truth, never a baked file.
        """
        result = self.describe_servers()
        if not result.success:
            return None
        for server in (result.message or {}).get("Servers", []):
            host_aws = (server.get("Host") or {}).get("Aws") or {}
            if host_aws.get("EC2InstanceId") == instance_id:
                return server.get("Id")
        return None

    def is_server_ready(self, instance_id: str) -> bool:
        """True if a DCV server matching this instance (by live
        Host.Aws.EC2InstanceId, never the stale SM Agent `instance` tag) is
        registered + Available."""
        result = self.describe_servers()
        if not result.success:
            return False
        for server in (result.message or {}).get("Servers", []):
            host_aws = (server.get("Host") or {}).get("Aws") or {}
            if host_aws.get("EC2InstanceId") == instance_id:
                return server.get("Availability") == "AVAILABLE"
        return False
