# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
The mesh sidecar application.

Serves exactly the P2P routes and a liveness probe:

    POST /api/v1/mesh/jobs/dispatch
    GET  /api/v1/mesh/jobs/<job_id>/state
    POST /api/v1/mesh/jobs/<job_id>/cancel
    GET  /healthz

Launched by `edhmeshsidecar.sh` under uwsgi, bound to this cluster's overlay
address. See that script for the bind, the certificate and the port.

BUILT BY A FACTORY, not at import. The prototype registered its routes and started
a background thread as module-scope side effects, which meant the module could not
be imported without constructing an application and reaching configuration - so
nothing about it could be tested by calling it, the same problem that put
`jobs_dispatch`'s decisions in `_job_intake`. `create_app()` is callable from a
test; `application` at the bottom is what uwsgi loads.

SOCA_MESH_SIDECAR IS SET HERE, and the ordering is load-bearing. It is what
`source_ip_auth.trust_wg_source_ip_enabled()` reads, and it must be set before any
route is registered, because registration imports the handlers that will read it.
Set with an assignment rather than `setdefault`: an inherited empty value would
leave `setdefault` a no-op and silently disable the source-IP trust path in the one
process that is supposed to have it.

PYTHON PATH. Both `cluster_manager` AND `cluster_manager/web_interface` are needed:
the endpoint modules live under `web_interface/api/`, so `api.v1.mesh` resolves only
with the second one, while `overlay_daemon` and `utils` need the first. The
prototype added only `cluster_manager`, which cannot import `api` at all - the web
interface itself gets away with one entry because its launcher chdir's into
`web_interface` first and picks the rest up from the working directory. Relying on
that here would make the application's importability depend on where it was
started from, so both are added explicitly.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Import path, before anything from the tree is imported.
# ---------------------------------------------------------------------------

CLUSTER_MANAGER = Path(
    os.environ.get("EDH_CLUSTER_MANAGER") or Path(__file__).resolve().parents[1]
)
WEB_INTERFACE = CLUSTER_MANAGER / "web_interface"

for _path in (str(CLUSTER_MANAGER), str(WEB_INTERFACE)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# The flag the source-IP trust path reads. Assigned rather than defaulted; see the
# module docstring. Set before create_app registers anything.
SIDECAR_ENV_VAR = "SOCA_MESH_SIDECAR"
os.environ[SIDECAR_ENV_VAR] = "1"

logger = logging.getLogger("soca_logger")


def _configure_logging() -> None:
    """
    A stream handler, once, so uwsgi's log captures this process.

    Guarded on `logger.handlers` because the web interface configures the same named
    logger and a second handler would double every line in a process that somehow
    had both.
    """
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] mesh_sidecar: %(message)s")
        )
        logger.addHandler(handler)


def _cluster_id() -> str:
    """
    This cluster's id, for the liveness body. Empty string when unavailable.

    Through `_context.resolve_self_cluster_id`, which is the one copy of this and
    already decides that a missing value degrades rather than refuses. A local
    re-implementation is what drifted across three modules in the prototype.
    """
    try:
        from api.v1.mesh._context import resolve_self_cluster_id

        return resolve_self_cluster_id()
    except Exception:  # noqa: BLE001 - liveness must answer even unconfigured
        logger.exception("mesh sidecar: could not resolve this cluster's id")
        return ""


def create_app():
    """
    Build the sidecar application.

    Registers the P2P surface and nothing else. `register_admin_routes` is
    deliberately never called here: this process is reachable from every peer in the
    mesh, and an admin route served from it would let any cluster holding the shared
    token approve peers into the mesh. An invariant asserts this module does not
    reference it.
    """
    from flask import Flask, request
    from flask_restful import Api

    _configure_logging()

    app = Flask("edh-mesh-sidecar")
    # Exceptions propagate to the handler's own guard rather than being turned into
    # Flask's HTML error page. Every endpoint here is wrapped by `mesh_endpoint`,
    # which logs the traceback and answers JSON, and a peer parses JSON.
    app.config["PROPAGATE_EXCEPTIONS"] = True

    api = Api(app)

    from api.v1.mesh.route_registration import register_p2p_routes

    registered = register_p2p_routes(api)
    logger.info(
        "mesh sidecar: serving %d peer-to-peer resources; the admin surface is not "
        "registered in this process",
        registered,
    )

    @app.route("/healthz", methods=["GET"])
    def healthz():
        """
        Liveness, unauthenticated by design.

        A peer needs to know this cluster is answering before it has anything to
        authenticate with, and an unreachable-versus-refusing distinction is the
        first thing an operator wants. It is safe to leave open here for one reason
        only: this process binds to the overlay interface, so the only callers are
        clusters already admitted to the mesh.

        The body carries the cluster id so a peer can confirm which cluster answered
        - an overlay address is reassigned when a cluster is decommissioned and its
        site sequence reused. Nothing else is included: no version, no configuration
        and no peer list, because every one of those is a detail this endpoint has no
        reason to hand out.
        """
        return (
            json.dumps(
                {
                    "status": "ok",
                    "sidecar": True,
                    "cluster_id": _cluster_id(),
                }
            ),
            200,
            {"Content-Type": "application/json"},
        )

    @app.before_request
    def _log_request():
        # The source address is the point of logging this at all: on this interface
        # it is the peer's overlay address, which is what source_ip_auth attributes.
        logger.info(
            "%s %s from %s", request.method, request.path, request.remote_addr
        )

    @app.errorhandler(404)
    def _not_found(_error):
        """
        JSON rather than Flask's HTML page.

        Every caller here is another cluster's reconciler, which parses JSON; an
        HTML body makes a wrong path look like a transport fault. The message names
        the sidecar so an operator who reaches this by mistake knows which of the two
        applications answered.
        """
        return (
            json.dumps(
                {
                    "success": False,
                    "message": (
                        "not found on the mesh sidecar. This process serves the "
                        "peer-to-peer mesh routes only; the admin API is on the "
                        "main web interface."
                    ),
                }
            ),
            404,
            {"Content-Type": "application/json"},
        )

    return app


# What uwsgi loads. Built at import because a WSGI server needs a module-scope
# callable, and kept to this one line so everything above stays callable from a test.
application = create_app()
