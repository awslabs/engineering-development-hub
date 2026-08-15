# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
SM-backed session key material for the web tier: the Flask session **signer**
(`SECRET_KEY`) and the session-payload **encryption** key.

Both are read from Secrets Manager at BOTH AWSCURRENT and AWSPREVIOUS (the
rotation-overlap window) so the signer can use `SECRET_KEY_FALLBACKS` and the
payload cipher can use a MultiFernet ring -- a key rotation never invalidates
in-flight sessions during the overlap. Mirrors the `_fetch_relay_keys` pattern
(boto via boto3_wrapper; AWSPREVIOUS-missing tolerated on first rotation).
"""

import logging
import base64
import hashlib
import time

from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from itsdangerous import Signer, BadSignature, want_bytes
import types
import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse
from utils.error import SocaError
from utils.aws.secretsmanager_client import SocaSecret
from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")


def _fetch_secret_versions(secret_id):
    """Internal: return (current_bytes, previous_bytes|None) for a secret.

    Same-file helper -- exempt from the SocaResponse return-type rule. Failure
    to read a version leaves it None so the caller can decide (current missing
    is fatal; previous missing just means no rotation has happened yet).
    """
    _current = None
    _previous = None
    _cur = SocaSecret(
        secret_id=secret_id, secret_id_prefix="", version_stage="AWSCURRENT", as_json=False
    ).get_secret()
    if _cur.get("success") is True and _cur.get("message"):
        _current = _cur.get("message").encode()
    else:
        logger.error(f"session key AWSCURRENT fetch failed for {secret_id}: {_cur.get('message')}")
    _prev = SocaSecret(
        secret_id=secret_id, secret_id_prefix="", version_stage="AWSPREVIOUS", as_json=False
    ).get_secret()
    if _prev.get("success") is True and _prev.get("message"):
        _previous = _prev.get("message").encode()
    # else: no AWSPREVIOUS yet (pre-first-rotation) -- expected, leave None.
    return _current, _previous


def _derive_fernet_key(raw):
    """Map arbitrary SM secret bytes to a valid urlsafe-b64 Fernet key (32-byte SHA-256 digest). Lets the SM secret be any random value while the cipher always gets a well-formed key."""
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest())


def get_session_keys(signer_secret_id, encryption_secret_id):
    """
    Return SocaResponse(message={"signer": (cur, prev), "encryption": (cur, prev)})
    with bytes values; prev is None until the first rotation. AWSCURRENT for
    both is required -- a missing current is an error (do not fall back to a
    per-host ephemeral key).
    """
    if not signer_secret_id or not encryption_secret_id:
        return SocaError.GENERIC_ERROR(
            helper="Session signer/encryption secret ARNs are not configured"
        )
    _signer_cur, _signer_prev = _fetch_secret_versions(signer_secret_id)
    _enc_cur, _enc_prev = _fetch_secret_versions(encryption_secret_id)
    if not _signer_cur or not _enc_cur:
        return SocaError.AWS_API_ERROR(
            service_name="secretsmanager",
            helper="Unable to fetch AWSCURRENT for session signer/encryption keys",
        )
    return SocaResponse(
        success=True,
        message={
            "signer": (_signer_cur, _signer_prev),
            "encryption": (
                _derive_fernet_key(_enc_cur),
                _derive_fernet_key(_enc_prev) if _enc_prev else None,
            ),
        },
    )


class EncryptedSerializer:
    """flask-session Serializer wrapper: Fernet-encrypts the serialized session at rest.

    Duck-typed to the flask_session Serializer contract (encode(session)->bytes,
    decode(bytes)->dict), so wrapping app.session_interface.serializer encrypts
    every backend read/write. Encrypts with the current key; decrypts across the
    current+previous ring (rotation-safe). An undecryptable blob (legacy plaintext
    from before cutover, or tampered) returns None -> the backend treats it as no
    session and a fresh one is issued (no 500).
    """

    def __init__(self, inner, encryption_keys):
        _cur, _prev = encryption_keys
        self._inner = inner
        self._fernet = MultiFernet([Fernet(_cur)] + ([Fernet(_prev)] if _prev else []))

    def encode(self, session):
        return self._fernet.encrypt(self._inner.encode(session))

    def decode(self, serialized_data):
        try:
            _plaintext = self._fernet.decrypt(serialized_data)
        except InvalidToken:
            return None
        return self._inner.decode(_plaintext)


# --- EDH-owned session-id signing (independent of flask-session's deprecated use_signer) ---
# flask-session 0.8.0 deprecated SESSION_USE_SIGNER (and _sign/_unsign, "remove in 1.0.0").
# We sign the sid cookie ourselves with an itsdangerous Signer over a [previous, current]
# key ring: sign with current (last key), verify against both -> signer-key rotation is
# seamless (no forced re-login), and we no longer depend on the deprecated flag/methods.
_SID_SALT = "edh-session-sid"


def _edh_sid_signer(interface):
    """Signer over the [previous, current] ring (signs with current, verifies both)."""
    _cur, _prev = interface._edh_signer_keys
    _keys = ([_prev] if _prev else []) + [_cur]
    return Signer(_keys, salt=_SID_SALT, key_derivation="hmac")


def _edh_open_session(self, app, request):
    """flask-session open_session with EDH-owned sid verification (ring, use_signer off)."""
    sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
    if not sid:
        sid = self._generate_sid(self.sid_length)
        return self.session_class(sid=sid, permanent=self.permanent)
    try:
        sid = _edh_sid_signer(self).unsign(sid).decode("utf-8")
    except BadSignature:
        sid = self._generate_sid(self.sid_length)
        return self.session_class(sid=sid, permanent=self.permanent)
    store_id = self._get_store_id(sid)
    saved_session_data = self._retrieve_session_data(store_id)
    if saved_session_data is not None:
        return self.session_class(saved_session_data, sid=sid)
    sid = self._generate_sid(self.sid_length)
    return self.session_class(sid=sid, permanent=self.permanent)


def _edh_save_session(self, app, session, response):
    """flask-session save_session with EDH-owned sid signing (ring, use_signer off)."""
    domain = self.get_cookie_domain(app)
    path = self.get_cookie_path(app)
    name = self.get_cookie_name(app)
    store_id = self._get_store_id(session.sid)
    if session.accessed:
        response.vary.add("Cookie")
    if not session:
        if session.modified:
            self._delete_session(store_id)
            response.delete_cookie(key=name, domain=domain, path=path)
            response.vary.add("Cookie")
        return
    if not self.should_set_storage(app, session):
        return
    self._upsert_session(app.permanent_session_lifetime, session, store_id)
    if not self.should_set_cookie(app, session):
        return
    value = _edh_sid_signer(self).sign(want_bytes(session.sid)).decode("utf-8")
    expires = self.get_expiration_time(app, session)
    httponly = self.get_cookie_httponly(app)
    secure = self.get_cookie_secure(app)
    samesite = (
        self.get_cookie_samesite(app) if self.has_same_site_capability else None
    )
    response.set_cookie(
        key=name,
        value=value,
        expires=expires,
        httponly=httponly,
        domain=domain,
        path=path,
        secure=secure,
        samesite=samesite,
    )
    response.vary.add("Cookie")


def install_signed_session(app, signer_keys):
    """Install EDH-owned sid signing on the live session interface.

    Internal plumbing helper (not an HTTP route) -- binds our open/save_session
    onto app.session_interface and forces use_signer off so flask-session's
    deprecated signer path is never used. signer_keys is the (current, previous)
    bytes tuple from get_session_keys()['signer'].
    """
    _interface = app.session_interface
    _interface.use_signer = False
    _interface._edh_signer_keys = signer_keys
    _interface.open_session = types.MethodType(_edh_open_session, _interface)
    _interface.save_session = types.MethodType(_edh_save_session, _interface)
    return SocaResponse(success=True, message=_interface)


def ensure_dynamodb_ttl(table_name):
    """Guarantee DynamoDB TTL (attr 'expires_at') is enabled on the session table.

    flask-session's DDB backend never actually enables TTL (it calls
    update_time_to_live(TableName=self.table_name) before self.table_name is set;
    the AttributeError is swallowed), so session items would never auto-expire.
    This is a defensive validation invariant, not a workaround: describe TTL and
    enable only if not already ENABLED/ENABLING. Idempotent across workers; harmless
    if upstream later fixes the bug. Best-effort -- TTL is hygiene (bounded growth),
    not an auth gate, so a transient failure logs and continues rather than blocking
    boot. Same-file init helper -- SocaResponse consumed internally, not HTTP-serialized.
    """
    _ddb = utils_boto3.get_boto(service_name="dynamodb")
    if _ddb.get("success") is not True:
        return SocaError.AWS_API_ERROR(
            service_name="dynamodb",
            helper=f"ensure_dynamodb_ttl: client init failed: {_ddb.get('message')}",
        )
    client = _ddb.get("message")
    try:
        _desc = client.describe_time_to_live(TableName=table_name).get(
            "TimeToLiveDescription", {}
        )
        _status = _desc.get("TimeToLiveStatus")
        if _status in ("ENABLED", "ENABLING"):
            _attr = _desc.get("AttributeName")
            if _attr != "expires_at":
                logger.warning(
                    f"ensure_dynamodb_ttl: TTL {_status} on {table_name} but attr is "
                    f"'{_attr}' not 'expires_at' -- manual disable+re-enable needed"
                )
            else:
                logger.debug(f"ensure_dynamodb_ttl: TTL already {_status} on {table_name}")
            return SocaResponse(success=True, message=f"TTL {_status} attr={_attr}")
        client.update_time_to_live(
            TableName=table_name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"},
        )
        logger.info(f"ensure_dynamodb_ttl: enabled TTL (attr 'expires_at') on {table_name}")
        return SocaResponse(success=True, message="TTL enabled")
    except Exception as _e:
        logger.warning(
            f"ensure_dynamodb_ttl: could not confirm/enable TTL on {table_name} "
            f"(non-fatal): {_e.__class__.__name__}: {_e}"
        )
        return SocaResponse(success=True, message="TTL ensure non-fatal")


def _edh_dynamodb_upsert_session(self, session_lifetime, session, store_id):
    """DDB _upsert_session writing `expires_at` (int epoch seconds) instead of the
    library's `expiration` (fractional Decimal) -- aligns the session table with EDH's
    DDB TTL convention. Same encode/store path as the backend; only the expiry attr
    name + value type differ."""
    _cast = SocaCastEngine(
        data=time.time() + session_lifetime.total_seconds()
    ).cast_as(int)
    expires_at = (
        _cast.get("message")
        if _cast.get("success") is True
        else round(time.time() + session_lifetime.total_seconds())
    )
    self.store.update_item(
        Key={"id": store_id},
        UpdateExpression="SET val = :value, expires_at = :exp",
        ExpressionAttributeValues={
            ":value": self.serializer.encode(session),
            ":exp": expires_at,
        },
    )


def install_dynamodb_expires_at(app):
    """DDB-only: override _upsert_session to write `expires_at` (int epoch seconds),
    aligning the session table with EDH's DDB TTL convention (vs flask-session's native
    `expiration`). Bind alongside install_signed_session; pair with ensure_dynamodb_ttl
    (targets `expires_at`). Internal plumbing helper, not an HTTP route."""
    _interface = app.session_interface
    _interface._upsert_session = types.MethodType(_edh_dynamodb_upsert_session, _interface)
    return SocaResponse(success=True, message=_interface)
