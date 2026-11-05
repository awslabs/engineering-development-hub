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
The receiving side of cross-cluster job routing.

  POST /api/v1/mesh/jobs/dispatch          take a routed job, or answer a probe
  GET  /api/v1/mesh/jobs/<job_id>/state     one delegated job's normalized state
  POST /api/v1/mesh/jobs/<job_id>/cancel    cancel a delegated job

The counterpart to `job_routing/dispatch_client.py`, which ships already and is the
only caller these have. Authenticated by `job_auth.authenticate_peer` rather than by
`admin_api`: the caller is a peer cluster's reconciler, not an operator.

The payload rules and the choice of local scheduler are in `_job_intake`, which is
importable without `flask_restful` and therefore testable by calling it. What is
left here is the route layer: authenticate, parse, map an outcome to a status code.

### The probe mode, and why it cannot submit

`mode="probe"` measures the routing path and asks whether a real job would be taken
now. It must never create one, because the origin probes to DECIDE whether to
route, and a probe that queued work would make asking the question change the
answer. So it short-circuits before submit and reports `accepting` instead.

### An absent job is not a finished job, and a failed look is neither

`state` reports `absent` only when the scheduler genuinely has no record. A driver
failure is a failure. The distinction is load-bearing at the other end: the shipped
reconciler reads an absent remote job as completed once it has seen that job
running, and releases the local parked stub on that basis. Answering "absent"
because `qstat` failed would therefore tell the origin cluster that somebody's job
had finished while it may still be running.

### What is deliberately not here

No check that a job id belongs to the peer asking about it. It would buy nothing: a
peer that can reach `dispatch` can submit a command line, so an admitted peer
already has code execution on this cluster by design, and cancelling a job is
strictly less than that. Mesh membership is the boundary, and an ownership check in
front of it would read as a defence while adding none.

### Where the caller's identity comes from

`authenticate_peer` reports HOW a request authenticated, never WHO sent it. On the
source-address path the sender's own address names it, so `_verified_peer` resolves
that and this handler refuses a request whose claimed `source_cluster_id`
contradicts it. On the bearer path there is no identity to have, the claim stands
alone as correlation, and `verified=False` says so in the log.

`state` and `cancel` carry no claimed id, so there is nothing there to check.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict

from flask import request
from flask_restful import Resource, reqparse

from api.v1.mesh._context import mesh_endpoint, resolve_self_cluster_id
from api.v1.mesh._job_intake import (
    MODE_PROBE,
    MODE_SUBMIT,
    MODES,
    DriverUnavailable,
    job_spec_from,
    load_local_driver,
)
from api.v1.mesh.job_auth import authenticate_peer
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _parse_request() -> Dict[str, Any]:
    parser = reqparse.RequestParser()
    parser.add_argument("mode", type=str, default=MODE_SUBMIT, location="json")
    # Verifiable only on the source-address path, where the sender's own address
    # names it. On the bearer path the mesh token is shared, so this stays a claim.
    parser.add_argument("source_cluster_id", type=str, default="", location="json")
    parser.add_argument("probe_id", type=str, default="", location="json")
    parser.add_argument("job", type=dict, default=None, location="json")
    return parser.parse_args(strict=False)


# The one auth path that carries an identity. Named here rather than tested by
# string in the handler so the coupling to job_auth's vocabulary is visible.
_IDENTIFIED_AUTH_PATH = "wg_source_ip"


def _verified_peer(auth_path: str):
    """The calling cluster's id when it was authenticated BY its address, else None.

    Resolved from `source_ip_auth` rather than taken from `authenticate_peer`, whose
    result is deliberately an auth path and never an identity. The lookup is cached
    on the address, so asking a second time inside one request costs nothing.

    None on the bearer path, and that is not a failure: every cluster in the mesh
    holds the same token, so there is genuinely nothing to verify a claim against.
    """
    if auth_path != _IDENTIFIED_AUTH_PATH:
        return None
    from api.v1.mesh import source_ip_auth

    try:
        return source_ip_auth.peer_cluster_for_source_ip(request.remote_addr)
    except source_ip_auth.PeerLookupUnavailable:
        # Authentication already succeeded on this path, so the mesh was readable a
        # moment ago. Losing it between the two reads costs the identity, not the
        # request.
        logger.warning(
            "mesh job dispatch: authenticated by source address but the peer could "
            "not be named on a second read"
        )
        return None


class MeshJobDispatch(Resource):
    """POST /api/v1/mesh/jobs/dispatch"""

    @mesh_endpoint
    def post(self):
        auth_path, error = authenticate_peer()
        if error is not None:
            return error

        received_ms = _now_ms()
        args = _parse_request()
        mode = (args.get("mode") or MODE_SUBMIT).strip()

        if mode not in MODES:
            return SocaResponse(
                success=False,
                message=(
                    f"unknown dispatch mode {mode!r}; this cluster accepts "
                    f"{', '.join(MODES)}. Refused rather than treated as a submit, "
                    "because a caller that believes it probed must not have queued "
                    "work."
                ),
                status_code=400,
            ).as_flask()

        claimed = (args.get("source_cluster_id") or "").strip()
        verified = _verified_peer(auth_path)

        # A contradicted claim is refused rather than quietly corrected. The id is
        # what both clusters correlate this job by, so if the origin believes it
        # dispatched as one cluster and this side records another, the two audit
        # trails disagree and nothing says so. Only reachable when the address named
        # a peer, so the bearer path cannot trip it.
        if verified is not None and claimed and claimed != verified:
            logger.warning(
                "mesh job dispatch: refused; the caller's address belongs to %s and "
                "it called itself %r",
                verified,
                claimed,
            )
            return SocaResponse(
                success=False,
                message=(
                    "this request names a source cluster that does not match the "
                    "cluster its address belongs to. Refused rather than attributed "
                    "to either one."
                ),
                status_code=403,
            ).as_flask()

        # The verified id itself, not whether there was one. A caller may send no
        # claim at all, and on the address path that would otherwise leave the line
        # with no identity on it while one was known - the same loss of a fact this
        # change exists to correct, in the opposite direction. None on the bearer
        # path, where `auth` already says why.
        logger.info(
            "mesh job dispatch: mode=%s auth=%s source=%r verified=%r",
            mode,
            auth_path,
            claimed,
            verified,
        )

        if mode == MODE_PROBE:
            return self._probe(args, received_ms)
        return self._submit(args, received_ms)

    def _probe(self, args: Dict[str, Any], received_ms: int):
        """
        Answer without touching the queues.

        An unresolvable or failing driver reports `accepting: false` rather than
        failing the request: the origin asked whether work would be taken, and "no"
        is a true and useful answer. The reason travels with it, so an operator on
        the origin side is not left guessing why a peer stopped accepting.
        """
        engine = ""
        accepting = False
        reason = None
        try:
            driver = load_local_driver()
            engine = getattr(driver, "engine_name", "")
            accepting = bool(driver.is_accepting())
        except DriverUnavailable as e:
            reason = str(e)
            logger.warning("mesh job probe: no driver to ask: %s", e)
        except Exception as e:  # noqa: BLE001 - a probe answers, it does not 500
            # The class name only, as the submit, state and cancel handlers do. An
            # is_accepting check reaches the scheduler, so its error can carry a
            # path, a queue name or a host, and this answer goes to another cluster.
            reason = e.__class__.__name__
            logger.exception("mesh job probe: the accepting check failed")

        return SocaResponse(
            success=True,
            message={
                "mode": MODE_PROBE,
                "probe_id": args.get("probe_id") or "",
                "remote_cluster_id": resolve_self_cluster_id(),
                "received_ts": received_ms,
                "ack_ts": _now_ms(),
                "driver_engine": engine,
                "accepting": accepting,
                "not_accepting_reason": reason,
            },
        ).as_flask()

    def _submit(self, args: Dict[str, Any], received_ms: int):
        spec, why_not = job_spec_from(args.get("job"))
        if why_not is not None:
            return SocaResponse(
                success=False, message=why_not, status_code=400
            ).as_flask()

        try:
            driver = load_local_driver()
        except DriverUnavailable as e:
            # 503 rather than 502: nothing downstream failed. This cluster cannot
            # take work at all, so the origin should route elsewhere rather than
            # retry against the same peer.
            return SocaResponse(
                success=False, message=str(e), status_code=503
            ).as_flask()

        try:
            remote_job_id = driver.submit(spec)
        except ValueError as e:
            # The driver refuses a spec it cannot emit safely: an environment name
            # that is not a POSIX name, a control character bound for a directive
            # line. That is the caller's payload, so it is a 400 and not a fault
            # here, and the message says which field rather than only that it failed.
            logger.warning("mesh job dispatch: refused a job spec: %s", e)
            return SocaResponse(
                success=False,
                message=f"this job cannot be submitted as sent: {e}",
                status_code=400,
            ).as_flask()
        except Exception as e:  # noqa: BLE001 - one shape for every local fault
            # The class name only. A scheduler error can carry a path, a queue name
            # or a host, and this response goes to another cluster.
            logger.exception("mesh job dispatch: submit failed")
            return SocaResponse(
                success=False,
                message=f"submit failed on this cluster: {e.__class__.__name__}",
                status_code=502,
            ).as_flask()

        logger.info("mesh job dispatch: submitted %s", remote_job_id)
        return SocaResponse(
            success=True,
            message={
                "mode": MODE_SUBMIT,
                "remote_job_id": remote_job_id,
                "remote_cluster_id": resolve_self_cluster_id(),
                "received_ts": received_ms,
                "ack_ts": _now_ms(),
            },
        ).as_flask()


class MeshJobState(Resource):
    """GET /api/v1/mesh/jobs/<job_id>/state"""

    @mesh_endpoint
    def get(self, job_id: str):
        _auth_path, error = authenticate_peer()
        if error is not None:
            return error

        try:
            driver = load_local_driver()
        except DriverUnavailable as e:
            return SocaResponse(
                success=False, message=str(e), status_code=503
            ).as_flask()

        try:
            view = driver.get(job_id)
        except Exception as e:  # noqa: BLE001
            # NOT reported as absent. The origin's reconciler reads an absent job as
            # completed once it has seen the job running, and releases the local
            # parked stub on that reading, so answering "absent" because qstat
            # failed would report a running job as finished.
            logger.exception("mesh job state: could not read %s", job_id)
            return SocaResponse(
                success=False,
                message=(
                    f"could not read the state of {job_id} on this cluster: "
                    f"{e.__class__.__name__}. This is a failure to look, not a "
                    "statement that the job is gone."
                ),
                status_code=502,
            ).as_flask()

        return SocaResponse(
            success=True,
            message={
                "job_id": view.job_id,
                "state": view.state.value,
                "queue": view.queue,
                "exit_code": view.exit_code,
                "annotation": view.annotation,
                "absent": False,
            },
        ).as_flask()


class MeshJobCancel(Resource):
    """POST /api/v1/mesh/jobs/<job_id>/cancel"""

    @mesh_endpoint
    def post(self, job_id: str):
        _auth_path, error = authenticate_peer()
        if error is not None:
            return error

        try:
            driver = load_local_driver()
        except DriverUnavailable as e:
            return SocaResponse(
                success=False, message=str(e), status_code=503
            ).as_flask()

        try:
            driver.cancel(job_id)
        except Exception as e:  # noqa: BLE001
            logger.warning("mesh job cancel: %s failed: %s", job_id, e)
            return SocaResponse(
                success=False,
                message=f"cancel of {job_id} failed: {e.__class__.__name__}",
                status_code=502,
            ).as_flask()

        logger.info("mesh job cancel: cancelled %s", job_id)
        return SocaResponse(
            success=True, message={"job_id": job_id, "cancelled": True}
        ).as_flask()
