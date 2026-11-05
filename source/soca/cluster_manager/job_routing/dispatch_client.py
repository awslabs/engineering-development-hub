######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Cross-cluster dispatch transport.

Sends one job to a peer's mesh sidecar over the WireGuard tunnel and reads a
delegated job's state back. This module is TRANSPORT ONLY: given a base URL and a
bearer token it makes the request and maps the response. It decides nothing about
which peer should run a job and nothing about where the token came from.

NO PRODUCTION CALLER YET, deliberately. The receiving end is the mesh sidecar,
which arrives with the auth CR, and so does the token: the peer-probe token and
the question behind it - whether the WireGuard tunnel is sufficient
authentication or the sidecar needs mutual TLS - are unresolved, and answering
them inside a transport module would settle by accident a decision that deserves
its own review. `dispatch()` therefore takes the token as an argument and has no
opinion on its origin. The reconciler beside it is driven by injected callables
for the same reason.

WHY curl RATHER THAN urllib OR requests. The sidecar serves HTTPS from uwsgi on
a bare overlay IP with a self-signed certificate, and the codebase's existing
mesh peer-to-peer path uses curl against exactly that arrangement. That is
inherited rather than chosen here, and it is the reason for the one property this
module works hardest at: a subprocess argument vector is world-readable.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Optional

from utils.validators import Validators

from overlay_daemon.models import Lifecycle, Peer

from .scheduler_drivers.base import JobSpec

logger = logging.getLogger("soca_logger")

# The sidecar's HTTPS port. Deliberately not the peer's `endpoint`, which is the
# WireGuard UDP listener: reaching the sidecar means going THROUGH the tunnel to
# the peer's controller address, not to the tunnel's own socket.
DEFAULT_SIDECAR_PORT = 8444

DISPATCH_PATH = "/api/v1/mesh/jobs/dispatch"
STATE_PATH = "/api/v1/mesh/jobs/{job_id}/state"
CANCEL_PATH = "/api/v1/mesh/jobs/{job_id}/cancel"

AUTH_HEADER = "X-EDH-Mesh-Token"

DEFAULT_TIMEOUT_SECONDS = 10.0

# A scheduler's job id, as the SENDING side is willing to accept it back from a
# peer. Deliberately narrow: this value is interpolated into a request path by
# query_state and cancel_remote, and it is persisted as the only reference to a
# job running right now on another cluster. PBS ids look like "123.controller",
# Slurm and LSF ids are bare integers, so alphanumerics with dot, dash and
# underscore covers every scheduler this mesh supports.
_REMOTE_JOB_ID = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")

# curl's own exit codes, which carry more than the rc != 0 the reference checked.
_CURL_TIMEOUT = 28
_CURL_COULD_NOT_CONNECT = 7
_CURL_COULD_NOT_RESOLVE_HOST = 6


class DispatchError(Exception):
    """A dispatch could not be completed."""


class DispatchTimeout(DispatchError):
    """The peer did not answer within the timeout."""


class DispatchAuthError(DispatchError):
    """The peer rejected the credential. Retrying with the same token cannot help."""


class DispatchUnavailable(DispatchError):
    """The peer could not be reached, or answered with a server error."""


@dataclass(frozen=True)
class DispatchResult:
    """What a peer said about a dispatch."""

    mode: str
    remote_job_id: Optional[str]
    payload: dict


def _curl_config(*, token: str, body_path: Optional[str]) -> str:
    """
    The curl configuration carrying the credential, for delivery on stdin.

    THE POINT OF THIS FUNCTION is that the token must never appear in the argument
    vector. On Linux /proc/<pid>/cmdline is world-readable, so `-H "<header>:
    <token>"` publishes the mesh credential to every user logged in to the
    controller for as long as the request runs - and EDH controllers are shared
    login nodes. That credential authenticates cross-cluster job dispatch, so
    leaking it lets any local user submit work to every peer in the mesh.

    Passed on stdin rather than through a file, so it never reaches a filesystem
    at all.

    A TOKEN CONTAINING A CONTROL CHARACTER IS REFUSED rather than escaped, because
    curl's config format is line-oriented and no escaping is defined for a line
    break inside a value. Measured on curl 8.7.1, the quoted form this function
    emits makes curl reject the whole config ("error encountered when reading a
    file") rather than honouring what follows the newline - so this is not today an
    injection on this version. It is refused anyway for two reasons. The failure
    curl does produce is an opaque non-zero exit that this module maps to
    "the peer is unreachable", which sends an operator to the network when the
    fault is in the credential. And the safety rests entirely on curl's parser
    being strict about an unterminated quote: the same content in an UNQUOTED value
    is honoured in full, verified on the same version, so a later edit that drops
    the quotes turns this straight back into config injection - an attacker-chosen
    `output`, `url` or extra `header`. Refusing the input does not depend on the
    parser's mood.

    Backslash and double quote are still escaped, because those the format does
    define.
    """
    control = {character for character in token if ord(character) < 0x20}
    if control:
        raise DispatchError(
            "the mesh token contains control characters "
            f"({sorted(hex(ord(c)) for c in control)}), which curl's line-oriented "
            "config format cannot carry. Refusing rather than sending it."
        )
    escaped = token.replace("\\", "\\\\").replace('"', '\\"')
    lines = [f'header = "{AUTH_HEADER}: {escaped}"']
    if body_path is not None:
        lines.append('header = "Content-Type: application/json"')
        lines.append(f'data-binary = "@{body_path}"')
    return "\n".join(lines) + "\n"


def _curl(
    *,
    method: str,
    url: str,
    token: str,
    body: Optional[dict] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple:
    """
    Make one request, returning (http_status, body_text).

    The credential goes in on stdin. A request body goes through a 0600 temporary
    file, because stdin is taken: the body is not a secret - it crosses the network
    in a moment - but it can be large enough to matter for an argument vector, and
    a job's command line has no business in the process table either. The file is
    removed whether the request succeeds, fails or times out.
    """
    body_path = None
    try:
        if body is not None:
            handle, body_path = tempfile.mkstemp(prefix="edh-dispatch-", suffix=".json")
            with os.fdopen(handle, "w") as stream:
                json.dump(body, stream)

        argv = [
            "curl",
            "--silent",
            "--insecure",
            "--config",
            "-",
            "--max-time",
            str(int(timeout)),
            "--write-out",
            "\n%{http_code}",
            "--request",
            method,
            url,
        ]
        try:
            completed = subprocess.run(
                argv,
                input=_curl_config(token=token, body_path=body_path),
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
        except subprocess.TimeoutExpired as e:
            raise DispatchTimeout(f"{method} {url} timed out after {timeout}s") from e
        except OSError as e:
            raise DispatchUnavailable(f"{method} {url} could not be run: {e}") from e

        if completed.returncode != 0:
            detail = (completed.stderr or "").strip()[:160]
            # curl reports a --max-time expiry as rc 28 rather than by being
            # killed, so the reference's `rc != 0` mapped every timeout to
            # Unavailable. The reconciler treats the two differently: a timeout is
            # a peer that is probably alive and busy, and unavailable is a peer it
            # may stop waiting on.
            if completed.returncode == _CURL_TIMEOUT:
                raise DispatchTimeout(
                    f"{method} {url} timed out after {timeout}s (curl 28)"
                )
            if completed.returncode in (
                _CURL_COULD_NOT_CONNECT,
                _CURL_COULD_NOT_RESOLVE_HOST,
            ):
                raise DispatchUnavailable(
                    f"{method} {url} unreachable (curl {completed.returncode}): {detail}"
                )
            raise DispatchUnavailable(
                f"{method} {url} failed (curl {completed.returncode}): {detail}"
            )

        unreadable = f"{method} {url}: could not read a status code from the response"
        parts = (completed.stdout or "").rsplit("\n", 1)
        if Validators.is_list_length_not_equal_of(parts, 2):
            raise DispatchUnavailable(unreadable)
        # isascii() is asked alongside isdigit() because the two disagree: for a
        # non-ASCII digit such as "\u00b2" isdigit() is True while int() raises, so
        # isdigit() alone is not the set int() accepts on the line below. curl writes
        # the status itself through --write-out %{http_code}, so this guards the parse
        # rather than anything a peer controls.
        status_text = parts[1].strip()
        if not (status_text.isascii() and status_text.isdigit()):
            raise DispatchUnavailable(unreadable)
        return int(status_text), parts[0]
    finally:
        if body_path is not None:
            try:
                os.unlink(body_path)
            except OSError:
                logger.warning(
                    "dispatch_client: could not remove the request body at %s",
                    body_path,
                )


_JSON_SHAPES = (
    ("an object", Validators.is_dict),
    ("an array", Validators.is_list),
    ("a string", Validators.is_string),
    ("a boolean", Validators.is_bool),
    ("an integer", Validators.is_int),
    ("a number", Validators.is_float),
)


def _json_shape(value: Any) -> str:
    """
    Name a decoded value's shape for a diagnostic, without `type()`.

    JSON vocabulary rather than a Python class name, which is the more apt
    reading for a payload that arrived as JSON: an operator reading the log sees
    "an array", not "list". `Validators` also separates a bool from an int where
    `isinstance` does not - `isinstance(True, int)` is True while
    `Validators.is_bool(True)` is True and `Validators.is_int(True)` is False
    (measured) - so the order of these checks does not have to carry the
    correctness.
    """
    for name, check in _JSON_SHAPES:
        if check(value):
            return name
    return "null" if value is None else "an unrecognised value"


def _decode(status: int, text: str, url: str) -> dict:
    """
    Map a status to a typed error, or return the decoded payload.

    Unwraps the SocaResponse envelope, so a caller reads the same shape whether
    the peer wrapped its answer or not.
    """
    if status in (401, 403):
        raise DispatchAuthError(
            f"{url} rejected the mesh credential with {status}. Retrying with the "
            f"same token will not help."
        )
    if status >= 500:
        raise DispatchUnavailable(f"{url} answered {status}")
    if status != 200:
        raise DispatchError(f"{url} answered {status}: {text[:200]}")
    try:
        data = json.loads(text)
    except ValueError as e:
        raise DispatchError(f"{url} did not answer with JSON") from e
    if not Validators.is_dict(data):
        raise DispatchError(f"{url} answered with {_json_shape(data)}, not an object")
    message = data.get("message")
    return message if Validators.is_dict(message) else data


def _remote_job_id_from(payload: dict, *, mode: str, url: str) -> Optional[str]:
    """
    The peer's job id, or a refusal.

    `DispatchResult.remote_job_id` is annotated `Optional[str]` and was taken
    straight from the peer's JSON, which enforces nothing: an annotation is not a
    check. That value has two consumers that make an unvalidated one consequential.
    It is interpolated into a request path by `query_state` and `cancel_remote`, so
    a peer answering "../../api/v1/mesh/peers" sends the next request somewhere
    other than the job it named; and it is persisted by the ledger as the ONLY
    reference to a job running at that moment on another cluster, so a dict or an
    int there is a delegation that can never be queried or cancelled again.

    Refused rather than coerced. `str()` would turn a dict into "{'a': 1}" and make
    it look like a job id, which is the failure this exists to prevent. That is the
    same reason the ledger passes `state` through `NormalizedState` rather than
    accepting whatever a peer calls a state - a vocabulary this side controls. This
    field had no such check, which is the asymmetry rather than a separate rule.

    A probe queues nothing, so an absent id is correct there and required for a
    submit.
    """
    raw = payload.get("remote_job_id")
    if raw is None:
        if mode == "submit":
            raise DispatchError(
                f"{url} accepted a submit without a remote_job_id, so the job it "
                f"queued could never be queried or cancelled"
            )
        return None
    if not Validators.is_string(raw) or not _REMOTE_JOB_ID.match(raw):
        raise DispatchError(
            f"{url} answered with a remote_job_id this cluster will not use "
            f"({raw!r}): it is interpolated into a request path and stored as the "
            f"only reference to the remote job"
        )
    return raw


def dispatch(
    *,
    base_url: str,
    token: str,
    source_cluster_id: str,
    spec: Optional[JobSpec] = None,
    mode: str = "submit",
    probe_id: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> DispatchResult:
    """
    Ask a peer to run a job, or probe that it would.

    mode="submit" requires a spec and returns the peer's job id. mode="probe"
    carries no spec: the peer acknowledges without queueing anything, which is how
    a caller establishes that dispatch works before committing a user's job to it.
    """
    if mode not in ("submit", "probe"):
        raise DispatchError(f"unknown dispatch mode {mode!r}")

    body: dict[str, Any] = {"mode": mode, "source_cluster_id": source_cluster_id}
    if mode == "probe":
        body["probe_id"] = probe_id or ""
    else:
        if spec is None:
            raise DispatchError("submit mode requires a JobSpec")
        body["job"] = asdict(spec)

    url = base_url.rstrip("/") + DISPATCH_PATH
    status, text = _curl(
        method="POST", url=url, token=token, body=body, timeout=timeout
    )
    payload = _decode(status, text, url)
    # THE MODE IS OURS, NOT THE PEER'S. This function validates `mode` on the way
    # out and then used to prefer `payload["mode"]` on the way back, which threw
    # that validation away: a peer answering a submit with mode="probe" relabelled
    # our own request, and a caller branching on the result to decide whether to
    # record a delegation would be branching on a peer-supplied value rather than
    # on its own intent. We know what we sent. The peer's own answer is still
    # returned whole in `payload`, so nothing is lost by not believing it here.
    return DispatchResult(
        mode=mode,
        remote_job_id=_remote_job_id_from(payload, mode=mode, url=url),
        payload=payload,
    )


def query_state(
    *,
    base_url: str,
    token: str,
    remote_job_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """
    Read a delegated job's normalized state from the peer running it.

    A 404 is reported as absent rather than raised. It is the expected end state
    rather than an error: the peer's scheduler prunes finished jobs, so a job this
    cluster delegated long enough ago is gone from the peer's history, and the
    reconciler needs to tell that apart from a peer that cannot be reached.
    """
    url = base_url.rstrip("/") + STATE_PATH.format(job_id=remote_job_id)
    status, text = _curl(method="GET", url=url, token=token, timeout=timeout)
    if status == 404:
        return {"state": "unknown", "absent": True}
    return _decode(status, text, url)


def cancel_remote(
    *,
    base_url: str,
    token: str,
    remote_job_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> None:
    """
    Cancel a delegated job on the peer running it.

    A 404 is success: the job this cluster wanted stopped is not running.
    """
    url = base_url.rstrip("/") + CANCEL_PATH.format(job_id=remote_job_id)
    status, _text = _curl(method="POST", url=url, token=token, timeout=timeout)
    if status in (401, 403):
        raise DispatchAuthError(f"{url} rejected the mesh credential with {status}")
    if status not in (200, 404):
        raise DispatchUnavailable(f"{url} answered {status}")


def sidecar_base_url(peer: Peer, *, port: int = DEFAULT_SIDECAR_PORT) -> Optional[str]:
    """
    Where a peer's mesh sidecar listens, or None when its row cannot say.

    Derived from the shipped model rather than recomputed. The reference read a
    `mesh_ip` attribute that does not exist on a peer row in this tree and fell
    back to string surgery on cgn_prefix - splitting on "." and replacing the last
    octet with "1" - which `Peer.controller_v4` already does correctly through the
    ipaddress module, and which the reference's own IPv6 sibling got wrong for
    every prefix this system generates.

    `address_plan_error` is the shipped guard, and asking it here matters for the
    same reason it matters in the tunnel: peer rows come from an
    administrator-editable Global Table whose validator defaults a missing prefix
    to an empty string and never rejects a malformed one. Without the guard a
    hand-edited row yields a URL built from nonsense, and the dispatch fails as a
    connection error that names a plausible-looking address.
    """
    reason = peer.address_plan_error
    if reason is not None:
        logger.warning(
            "dispatch_client: no sidecar address for %s because %s",
            peer.cluster_id,
            reason,
        )
        return None
    try:
        address = peer.controller_v4
        ipaddress.IPv4Address(address)
    except ValueError:
        logger.warning(
            "dispatch_client: %s has no usable controller address", peer.cluster_id
        )
        return None
    return f"https://{address}:{int(port)}"


def dispatchable_peers(
    peers: Iterable[Peer], *, self_cluster_id: str
) -> dict:
    """
    The peers a job may be sent to, as cluster id to sidecar base URL.

    Filtered on lifecycle, for the reason the health escalation count is: a
    decommissioned cluster keeps its peer row rather than losing it, so a mesh that
    removed a cluster a year ago still has a row naming its address. Dispatching on
    row presence alone sends a user's job to a controller that is gone, and the
    failure arrives as a timeout that looks like a network problem rather than as
    the routing decision it is.

    This cluster is excluded from its own result. A peer set includes the local
    cluster, and a caller iterating it to find somewhere else to run a job would
    otherwise dispatch to the sidecar on its own controller - which succeeds, and
    parks a stub on the same cluster that is running the real job.
    """
    routes = {}
    for peer in peers:
        if peer.cluster_id == self_cluster_id:
            continue
        if peer.lifecycle != Lifecycle.ACTIVE:
            continue
        url = sidecar_base_url(peer)
        if url is not None:
            routes[peer.cluster_id] = url
    return routes
