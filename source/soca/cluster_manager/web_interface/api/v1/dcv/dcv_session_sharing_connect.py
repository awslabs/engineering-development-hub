# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DCV Session Sharing -- secure connection nonce endpoint.

Default sharing mode: guest clicks Connect -> EDH generates a single-use
nonce (30s TTL in Valkey) -> guest is redirected to /api/dcv/session_sharing/connect/<nonce>
-> endpoint validates + consumes nonce -> fetches DCV JWT from broker ->
302 redirects to DCV gateway with token. Token never exposed to the user.

Link mode (admin opt-in): returns the DCV URL directly with embedded token.

Routes:
    POST /api/dcv/session_sharing/connect        - Generate nonce (returns nonce URL)
    GET  /api/dcv/session_sharing/connect/<nonce> - Consume nonce, redirect to DCV
    POST /api/dcv/session_sharing/link            - Generate shareable link (link mode)
"""

import logging
import uuid

from flask import redirect, request, session
from flask_restful import Resource

from decorators import private_api
from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

NONCE_TTL_SECONDS = 30
NONCE_KEY_PREFIX = "dcv-session-sharing:nonce:"


def _get_cache_client():
    # is_admin=True selects the write-capable Valkey ACL user; the default
    # (read-only) user cannot SET/DELETE the nonce, which silently fails the
    # store and makes every connect look like "nonce expired or already used".
    from utils.cache.client import SocaCacheClient
    return SocaCacheClient(is_admin=True)


def _get_grant_service():
    from helpers import dcv_session_sharing_store
    return dcv_session_sharing_store.get_grant_service()


def _get_broker_client():
    from utils.dcv_broker_client import DcvBrokerClient
    return DcvBrokerClient()


def _get_frontend_nlb():
    # MUST be the DCV connection-gateway NLB (/dcv/frontend_nlb_dns), the same
    # host the owner-connect path uses. Do NOT use /configuration/NLBLoadBalancerDNSName
    # -- that is the general web NLB and does not serve the DCV web client, so a
    # redirect there yields a blank/spinning tab.
    from utils.config import SocaConfig
    try:
        return SocaConfig(key="/dcv/frontend_nlb_dns").get_value().message or ""
    except Exception:
        return ""


def _link_mode_enabled() -> bool:
    """
    True only when the cluster allows 'link' sharing mode. Link mode embeds the
    DCV token in a URL (admin opt-in); it is OFF unless the cluster admin adds
    'link' to allowed_sharing_modes.
    """
    from utils.config import SocaConfig
    try:
        _raw = SocaConfig(
            key="/configuration/dcv/session_sharing/allowed_sharing_modes"
        ).get_value().message
        if not _raw:
            return False
        _parsed = SocaCastEngine(_raw).as_json()
        _modes = _parsed.message if _parsed.success else []
        return "link" in (_modes or [])
    except Exception:
        return False


class DcvSessionSharingConnect(Resource):
    """Generate a single-use nonce for secure DCV connection."""

    @private_api
    def post(self):
        r"""
        Generate a single-use nonce for secure DCV session connection
        ---
        openapi: 3.1.0
        operationId: createSessionSharingConnectNonce
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - grant_id
                properties:
                  grant_id:
                    type: string
                    description: ID of the active grant to connect to
        responses:
          '201':
            description: Nonce created successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      properties:
                        nonce_url:
                          type: string
                          description: URL path to consume the nonce
          '400':
            description: Missing grant_id
          '403':
            description: Not authorized for this grant
          '404':
            description: Grant not found or inactive
          '500':
            description: Serialization error
          '503':
            description: Cache (Valkey) not available
        """
        cache = _get_cache_client()
        if not cache or not cache.is_enabled().success:
            return SocaError.GENERIC_ERROR(
                helper="Cache (Valkey) not available for session sharing nonce",
                status_code=503,
            ).as_flask()

        data = request.get_json(force=True)
        grant_id = data.get("grant_id")
        if not Validators.is_string_not_empty(grant_id):
            return SocaError.GENERIC_ERROR(
                helper="grant_id is required", status_code=400
            ).as_flask()

        # Verify grant exists and user is the guest
        svc = _get_grant_service()
        grant = svc.get_grant(grant_id) if svc else None
        if not grant or grant.get("status") != "ACTIVE":
            return SocaError.GENERIC_ERROR(
                helper=f"Grant {grant_id} not found or inactive", status_code=404
            ).as_flask()

        username = session.get("user", "")
        if grant.get("guest_username") != username:
            return SocaError.GENERIC_ERROR(
                helper="Not authorized for this grant", status_code=403
            ).as_flask()

        # Generate nonce
        nonce = str(uuid.uuid4())
        nonce_key = f"{NONCE_KEY_PREFIX}{nonce}"
        _payload = SocaCastEngine({
            "grant_id": grant_id,
            "session_id": grant["session_id"],
            "guest_username": grant["guest_username"],
            "owner_username": grant["owner_username"],
        }).serialize_json()
        if not _payload.success:
            return SocaError.GENERIC_ERROR(
                helper="Unable to serialize nonce payload", status_code=500
            ).as_flask()

        cache.set(nonce_key, _payload.message, ex=NONCE_TTL_SECONDS)

        nonce_url = f"/api/dcv/session_sharing/connect/{nonce}"
        return SocaResponse(
            success=True, message={"nonce_url": nonce_url}, status_code=201
        ).as_flask()


class DcvSessionSharingConnectNonce(Resource):
    """Consume a nonce and redirect to DCV gateway."""

    @private_api
    def get(self, nonce):
        r"""
        Consume a nonce and redirect to DCV gateway
        ---
        openapi: 3.1.0
        operationId: consumeSessionSharingConnectNonce
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
          - name: nonce
            in: path
            schema:
              type: string
              format: uuid
            required: true
            description: Single-use nonce (30s TTL)
        responses:
          '302':
            description: Redirect to DCV gateway with connection token
          '403':
            description: Nonce does not belong to the authenticated user
          '410':
            description: Nonce expired or already used
          '502':
            description: Failed to obtain connection token from broker
          '503':
            description: Cache or broker unavailable
        """
        cache = _get_cache_client()
        if not cache or not cache.is_enabled().success:
            return SocaError.GENERIC_ERROR(
                helper="Cache unavailable", status_code=503
            ).as_flask()

        nonce_key = f"{NONCE_KEY_PREFIX}{nonce}"

        # Peek (do NOT consume yet) so a wrong-user / leaked open cannot burn
        # the nonce for the legitimate guest.
        result = cache.get(nonce_key)
        if not result.success:
            return SocaError.GENERIC_ERROR(
                helper="Nonce expired or already used", status_code=410
            ).as_flask()

        # Parse payload (json.loads accepts both str and bytes payloads).
        _parsed = SocaCastEngine(result.message).as_json()
        if not _parsed.success:
            return SocaError.GENERIC_ERROR(
                helper="Corrupt nonce payload", status_code=410
            ).as_flask()
        payload = _parsed.message

        # Guest-identity binding. The nonce is single-use + 30s TTL, but the URL
        # is still bearer-shaped: anyone who obtains it could otherwise redeem it
        # for the guest's connection token. Require the consuming browser to be
        # authenticated as the grant's guest. A forwarded/leaked nonce opened by
        # a different logged-in user -- or by an unauthenticated browser (empty
        # user) -- is denied (403) and the nonce is NOT consumed, so it remains
        # usable by the real guest until its own TTL expires.
        current_user = session.get("user", "")
        if current_user != payload.get("guest_username"):
            logger.warning(
                "nonce consume rejected: authenticated user %r != grant guest %r",
                current_user, payload.get("guest_username"),
            )
            return SocaError.GENERIC_ERROR(
                helper="This share link is not valid for your account",
                status_code=403,
            ).as_flask()

        # Identity verified -- consume now. cache.delete() reports success only
        # when the DEL actually removed the key (count == 1), so a concurrent
        # double-redeem (e.g. double-click) loses the race here and is rejected:
        # single-use is enforced atomically at the consumption point.
        _consumed = cache.delete(nonce_key)
        if not (_consumed and _consumed.success):
            return SocaError.GENERIC_ERROR(
                helper="Nonce expired or already used", status_code=410
            ).as_flask()

        # Audit: record that the guest actually connected (who + when + count).
        # Best-effort -- never block the connect on an audit write.
        try:
            _svc = _get_grant_service()
            if _svc and payload.get("grant_id"):
                _svc.record_connection(payload["grant_id"], current_user)
        except Exception as _audit_err:
            logger.warning(f"connect audit record failed: {_audit_err}")

        # Fetch DCV connection token from broker
        broker = _get_broker_client()
        if not broker:
            return SocaError.GENERIC_ERROR(
                helper="Broker unavailable", status_code=503
            ).as_flask()

        token_result = broker.get_session_connection_data(
            session_id=payload["session_id"],
            user=payload["guest_username"],
        )
        if not token_result.success:
            return SocaError.GENERIC_ERROR(
                helper=f"Failed to get connection token: {token_result.message}",
                status_code=502,
            ).as_flask()

        connection_token = (token_result.message or {}).get("ConnectionToken", "")
        if not connection_token:
            return SocaError.GENERIC_ERROR(
                helper="Empty connection token from broker", status_code=502
            ).as_flask()

        # Build DCV gateway URL and redirect
        frontend_nlb = _get_frontend_nlb()
        dcv_url = (
            f"https://{frontend_nlb}/"
            f"?authToken={connection_token}"
            f"&username={payload['guest_username']}"
            f"#{payload['session_id']}"
        )

        return redirect(dcv_url, code=302)


class DcvSessionSharingLink(Resource):
    """Generate a shareable DCV link (link mode, admin opt-in)."""

    @private_api
    def post(self):
        r"""
        Generate a shareable DCV link with embedded connection token
        ---
        openapi: 3.1.0
        operationId: createSessionSharingLink
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - grant_id
                properties:
                  grant_id:
                    type: string
                    description: ID of the active grant to generate a link for
        responses:
          '200':
            description: DCV link generated successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      properties:
                        dcv_url:
                          type: string
                          description: Full DCV gateway URL with embedded auth token
          '400':
            description: Missing grant_id
          '403':
            description: Not authorized or link sharing not enabled
          '404':
            description: Grant not found or inactive
          '502':
            description: Failed to obtain connection token from broker
          '503':
            description: Broker unavailable
        """
        data = request.get_json(force=True)
        grant_id = data.get("grant_id")
        if not Validators.is_string_not_empty(grant_id):
            return SocaError.GENERIC_ERROR(
                helper="grant_id is required", status_code=400
            ).as_flask()

        svc = _get_grant_service()
        grant = svc.get_grant(grant_id) if svc else None
        if not grant or grant.get("status") != "ACTIVE":
            return SocaError.GENERIC_ERROR(
                helper=f"Grant {grant_id} not found or inactive", status_code=404
            ).as_flask()

        # Authorization: only the grant's guest (or a cluster admin) may mint a
        # connection link for it -- otherwise any authenticated user could
        # extract a DCV token for any active grant by supplying its id.
        username = session.get("user", "")
        is_admin = session.get("sudoers", False) is True
        if not is_admin and grant.get("guest_username") != username:
            return SocaError.GENERIC_ERROR(
                helper="Not authorized for this grant", status_code=403
            ).as_flask()

        # Sharing-mode enforcement: link mode embeds the token in a URL and is
        # OFF unless the cluster admin explicitly allows it. Without this gate a
        # caller could bypass the secure (nonce) hierarchy.
        if not _link_mode_enabled():
            return SocaError.GENERIC_ERROR(
                helper="Link sharing is not enabled for this cluster",
                status_code=403,
            ).as_flask()

        broker = _get_broker_client()
        if not broker:
            return SocaError.GENERIC_ERROR(
                helper="Broker unavailable", status_code=503
            ).as_flask()

        token_result = broker.get_session_connection_data(
            session_id=grant["session_id"],
            user=grant["guest_username"],
        )
        if not token_result.success:
            return SocaError.GENERIC_ERROR(
                helper=f"Failed to get connection token: {token_result.message}",
                status_code=502,
            ).as_flask()

        connection_token = (token_result.message or {}).get("ConnectionToken", "")
        frontend_nlb = _get_frontend_nlb()
        dcv_url = (
            f"https://{frontend_nlb}/"
            f"?authToken={connection_token}"
            f"&username={grant['guest_username']}"
            f"#{grant['session_id']}"
        )

        return SocaResponse(success=True, message={"dcv_url": dcv_url}).as_flask()
