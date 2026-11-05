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

"""
Peer-to-peer authentication for the mesh job-routing endpoints.

THE FIRST NON-ADMIN TRUST BOUNDARY IN THIS PACKAGE. Every mesh endpoint shipped
so far is wrapped by `admin_api` and authenticates a human or an API key. The job
endpoints are machine-to-machine: the caller is another cluster's reconciler, and
what it presents is the shared mesh credential rather than an operator identity.

### What the credential is, and what it proves

A single shared bearer token per mesh, held in Secrets Manager, rotated on a
maximum lifetime with an overlap window so a replacement reaches every peer while
the old one is still accepted. That mechanism was decided before this change:
`/configuration/Overlay/peer_probe_token_secret_arn` and the rotation and grace
keys beside it are already registered in the config validator, and
`config_registry.yml` marks the live token `hidden: true` so it can never render
in the configuration editor or in a key-and-value search.

THE SECRET IS PROVISIONED, on the mesh creator. CR-309382292 added the CDK secret
and publishes its ARN under that key, so a creator authenticates a peer by bearer
token today. A JOINER's secret is created carrying an empty `current`, because the
token is shared mesh-wide and a joiner minting its own would produce a value no
peer accepts - so on a joiner the bearer path alone still answers the 503 that says
no token is configured.

Because the token is shared mesh-wide, a valid token proves THE CALLER IS A MEMBER
OF THIS MESH and nothing more. It does not identify which member. Every caller
holds the same secret, so no comparison against it can tell peer A from peer B.

That is stated here because it is easy to read an authenticated request as an
identified one. Any field naming the calling cluster arrives in the request body,
chosen by the caller, so it is usable for correlation and must never be recorded
as though it were verified.

### The second path, and why a joiner works without a token

`source_ip_auth` identifies a peer by the address it sent from, which is sound only
inside the mesh sidecar process: that process binds the WireGuard interface, so the
kernel module has authenticated every packet by Curve25519 before the socket sees
it. `authenticate_peer` tries that path FIRST and does not read the token at all
when it succeeds, which is what makes a joiner reachable before any token reaches
it.

Both paths are kept rather than one replacing the other. The tunnel cannot defend
against a WireGuard ACL a human widened by mistake; the token can. Per-peer
identity is the opposite way round, and only the address supplies it.

### Why a shared token is enough here

A peer that can reach these endpoints can submit a job, and a job is a command
line. So an admitted peer already has code execution on this cluster by design,
and no check reachable from inside this module reduces that. The credential's job
is to keep NON-MEMBERS out, which it does.

### The four outcomes, kept distinct

An operator reading a refusal needs to know which of these happened, and the
prototype collapsed the first two into one message:

  - no secret ARN configured        503, and the mesh job API is genuinely off
  - the secret could not be read    503, but the cause is transient
  - no token presented              401
  - token presented and wrong       403

Reporting an unreachable Secrets Manager as "no token configured" sends an
operator to check configuration that is correct. They are separate messages.
"""

from __future__ import annotations

import hmac
import logging
import time
from typing import Any, Dict, Optional, Tuple

from flask import request

from api.v1.mesh._context import _KEY_ABSENT_MESSAGE
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

AUTH_HEADER = "X-EDH-Mesh-Token"
SECRET_ARN_KEY = "/configuration/Overlay/peer_probe_token_secret_arn"

# The secret is read on every authenticated request, so it is cached. Short,
# because the window is how long a peer keeps being refused after a rotation it
# already received.
SECRET_CACHE_TTL_SECONDS = 60

# Only a successful read is cached. Caching a failure would turn one transient
# Secrets Manager error into a minute of refusals.
_cache: Dict[str, Any] = {"value": None, "expires": 0}


class MeshTokenUnavailable(Exception):
    """The mesh token could not be read, and that is not the same as absent.

    Separate from "not configured" because the two are opposite operator actions:
    one is a cluster with the job API deliberately off, the other is a working
    configuration behind a store that cannot currently be consulted.
    """


def reset_cache() -> None:
    """Drop the cached secret. For tests and for a forced re-read after rotation."""
    _cache["value"] = None
    _cache["expires"] = 0


def _resolve_secret_arn() -> Optional[str]:
    """The configured secret ARN, or None when this cluster has none.

    A missing ARN is a real state rather than an error: a cluster that is in a mesh
    but not participating in job routing has no token, and the endpoints refuse
    rather than failing.

    Read with allow_unknown_key and deliberately WITHOUT a default, for the same
    reason resolve_mesh_id is. A default makes get_value answer success=True
    carrying it for every failure, including a throttled or unreachable store,
    because it catches Exception and substitutes the default. This function passed
    one, so the transient-versus-absent split the rest of this module is built
    around was defeated at its first step: an SSM outage read as "no token
    configured" and sent an operator to check configuration that was correct.
    """
    from utils.config import SocaConfig

    result = SocaConfig(key=SECRET_ARN_KEY).get_value(allow_unknown_key=True)
    if result.get("success") is False:
        message = str(result.get("message") or "")
        if message == _KEY_ABSENT_MESSAGE:
            return None
        raise MeshTokenUnavailable(
            f"could not read {SECRET_ARN_KEY}, so whether this cluster has a mesh "
            f"token is unknown: {message}"
        )
    arn = result.get("message")
    if not arn or arn == "CACHE_MISS":
        return None
    return str(arn).strip() or None


def _token_field(payload: Dict[str, Any], key: str) -> Optional[str]:
    """One token value out of the secret payload, or None when it is absent.

    A present-but-not-a-string value is REFUSED rather than coerced. Coercing it
    would be worse than the AttributeError it replaces: `str(12345)` turns a
    misconfigured secret into a token this cluster then accepts from any peer that
    guesses it, and the operator is never told the secret is malformed.

    Raising keeps a malformed secret inside the same contract the non-object case
    already uses. Without this the `.strip()` below raised AttributeError, which
    `authenticate_peer` does not catch - so the one failure mode this module exists
    to report clearly surfaced as an unhandled 500 instead.
    """
    raw = payload.get(key)
    if raw is not None and not Validators.is_string(raw):
        raise MeshTokenUnavailable(
            f"the mesh token secret field '{key}' is not a string"
        )
    return (raw or "").strip() or None


def read_token_pair(*, force: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    The currently accepted tokens as (current, previous).

    Both are accepted, which is what the rotation overlap is for: the replacement
    is written and distributed while the outgoing token still authenticates, so a
    peer that has not yet picked up the new one is not cut off mid-rotation.

    Returns (None, None) when no ARN is configured. Raises MeshTokenUnavailable
    when an ARN exists and the secret behind it could not be read, because those
    two want different messages and collapsing them is what made the prototype
    report an outage as a configuration gap.
    """
    now = int(time.time())
    if not force and _cache["value"] is not None and _cache["expires"] > now:
        cached = _cache["value"]
        return cached[0], cached[1]

    arn = _resolve_secret_arn()
    if not arn:
        return None, None

    # The shipped Secrets Manager wrapper, not a client of our own. It builds its
    # client through boto3_wrapper (so the solution's user agent, retry config and
    # explicit region pin all still apply), parses the SecretString as JSON, and
    # returns a SocaResponse - so every failure is a value to check rather than an
    # exception to catch. It also names ResourceNotFoundException separately from an
    # unknown fault, which is the transient-versus-misconfigured distinction this
    # function exists to draw, and it does so in the log rather than here.
    #
    # `secret_id_prefix=""` is required and not a detail: the wrapper defaults to
    # prefixing `/edh/$EDH_CLUSTER_ID/`, which is right for a caller passing a bare
    # secret name and wrong for the full ARN the config key holds. With the default
    # left in place every read would look for a secret that does not exist.
    from utils.aws.secretsmanager_client import SocaSecret

    try:
        result = SocaSecret(
            secret_id=arn, secret_id_prefix="", as_json=True
        ).get_secret()
    except Exception as e:  # noqa: BLE001 - the wrapper can raise despite its contract
        # The wrapper reports failures as a SocaResponse, EXCEPT when its client
        # could not be built: it does `get_boto(...).message` unchecked, so the
        # client is the error string, and the `except _sm_client.exceptions...`
        # clause meant to catch that raises AttributeError while evaluating
        # `.exceptions` on a string -- before the catch-all below it is reached.
        # So the documented contract does not hold on that one path, and a
        # region-less cluster would surface an AttributeError out of an endpoint.
        logger.exception("mesh job auth: the secret read raised out of the wrapper")
        raise MeshTokenUnavailable(
            "the mesh token could not be read from Secrets Manager"
        ) from e

    if result.get("success") is False:
        # Logged, not carried into the raised message: the wrapper's helper text
        # names the secret id on every failure path, the ARN contains the account
        # id, and the refusal built from this reaches an unauthenticated caller.
        logger.error(
            "mesh job auth: could not read the mesh token secret: %s",
            result.get("message"),
        )
        raise MeshTokenUnavailable(
            "the mesh token could not be read from Secrets Manager"
        )

    payload = result.get("message")
    if not Validators.is_dict(payload):
        # A non-object secret is a misconfiguration rather than a transient fault,
        # but it is equally unusable, and saying which it is helps.
        raise MeshTokenUnavailable(
            "the mesh token secret does not hold a JSON object"
        )

    current = _token_field(payload, "current")
    previous = _token_field(payload, "previous")
    if current:
        # ONLY a read that yields a usable token is cached. A secret that exists
        # and parses but carries no `current` is not a success to remember: caching
        # it means that after an operator provisions or repairs the token, this
        # cluster goes on refusing every peer with "no token is configured" for the
        # rest of the TTL, with nothing to invalidate it. That undoes the
        # transient-versus-absent distinction this function exists to draw, by
        # treating an absent token as a settled fact rather than a current reading.
        _cache["value"] = (current, previous)
        _cache["expires"] = now + SECRET_CACHE_TTL_SECONDS
    return current, previous


def _matches(provided: str, candidate: Optional[str]) -> bool:
    """Constant-time comparison against one accepted token.

    `hmac.compare_digest` rather than `==` so the comparison does not return early
    on the first differing byte. An empty candidate never matches, so a cluster
    mid-rotation with no previous token cannot be authenticated by presenting an
    empty string.
    """
    if not candidate:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), candidate.encode("utf-8"))


def _source_address_authenticates(source_ip_auth) -> bool:
    """Whether the request's source address belongs to an active peer.

    Answers a yes or no and discards which peer it was. An endpoint that needs the
    identity asks `source_ip_auth` for it directly, which is also what an invariant
    in this package requires: no identity may be reachable through this module's
    result, because for most of its history there was none to have.

    A mesh that cannot be read falls through to the bearer token rather than
    refusing. The lookup raises for exactly this reason - so the caller can tell an
    unreadable mesh from an address no peer owns - and on this path the distinction
    is which of the two gets logged, not whether the request survives. Refusing here
    would make a transient DynamoDB fault cost a cluster the bearer path it
    authenticates with today.
    """
    if not source_ip_auth.trust_wg_source_ip_enabled():
        return False
    try:
        return (
            source_ip_auth.peer_cluster_for_source_ip(request.remote_addr) is not None
        )
    except source_ip_auth.PeerLookupUnavailable as e:
        logger.warning(
            "mesh job auth: the source address could not be evaluated, so this "
            "request falls back to the bearer token: %s",
            e,
        )
        return False


def authenticate_peer() -> Tuple[Optional[str], Optional[Any]]:
    """
    Authenticate a mesh job request.

    Returns (auth_path, error). On success `auth_path` is a non-empty string naming
    how the caller authenticated and `error` is None; on failure `auth_path` is
    None and `error` is a ready-to-return Flask response.

    TWO INDEPENDENT PATHS, and either one is sufficient. The source address is
    tried first and the token is not read at all when it succeeds, which is what
    makes a joiner reachable: a joiner's secret is created carrying an empty
    `current` and stays that way until the mesh creator distributes a token, so
    reading the token first answers 503 before the address is ever considered.

    The address is also the stronger of the two statements. The token is shared
    mesh-wide, so holding it proves only membership; an address inside a peer's
    allocated prefix arrives on an interface the WireGuard kernel module has already
    authenticated by Curve25519, and it names WHICH peer. The token is kept because
    it is what defends against a WireGuard ACL a human widened by mistake, which the
    tunnel cannot defend against itself.

    The success value is deliberately NOT a cluster id. The prototype returned one,
    None-on-success for the bearer path, which made a successful authentication
    indistinguishable from a failed one by the value alone and invited callers to
    fall back to the caller-supplied id in the body as though it were verified. An
    endpoint that wants the verified identity calls `source_ip_auth` for it, where
    the absence of an answer is unambiguous.
    """
    from api.v1.mesh import source_ip_auth

    provided = (request.headers.get(AUTH_HEADER) or "").strip()

    if _source_address_authenticates(source_ip_auth):
        return "wg_source_ip", None

    # Whether the address was even eligible to be checked, which decides what a
    # refusal below is allowed to claim. False in the main web tier, where these
    # routes are not registered and remote_addr is the load balancer.
    _address_was_tried = source_ip_auth.trust_wg_source_ip_enabled()

    try:
        current, previous = read_token_pair()
    except MeshTokenUnavailable as e:
        return None, SocaResponse(
            success=False,
            message=(
                f"the mesh job API cannot authenticate this request: {e}. This is "
                "a transient failure reading a configured secret, not a cluster "
                "with job routing disabled."
            ),
            status_code=503,
        ).as_flask()

    if not current:
        # Saying only "no token is configured" would send an operator to provision
        # one on a cluster whose token is deliberately empty and whose real fault is
        # that the caller's address is not a recognised peer.
        _also = (
            " The source address is also not inside the address plan of any active "
            "peer in this mesh."
            if _address_was_tried
            else ""
        )
        return None, SocaResponse(
            success=False,
            message=(
                "the mesh job API is not enabled on this cluster: no peer probe "
                f"token is configured.{_also}"
            ),
            status_code=503,
        ).as_flask()

    if not provided:
        return None, SocaResponse(
            success=False,
            message=f"missing {AUTH_HEADER} header",
            status_code=401,
        ).as_flask()

    if _matches(provided, current):
        return "bearer", None
    if _matches(provided, previous):
        # Worth a log line of its own: a peer still on the previous token is fine
        # today and will be refused when the overlap closes, and this is the only
        # warning an operator gets before that happens.
        logger.warning(
            "mesh job auth: accepted the PREVIOUS token from %s; that peer has not "
            "picked up the current one and will be refused when the rotation "
            "overlap closes",
            request.remote_addr,
        )
        return "bearer_previous", None

    # The rejected value is never logged. It is a credential, and a near-miss is
    # exactly the thing worth not writing to a log an operator will paste.
    logger.warning("mesh job auth: rejected a request from %s", request.remote_addr)
    return None, SocaResponse(
        success=False,
        message=f"invalid {AUTH_HEADER}",
        status_code=403,
    ).as_flask()
