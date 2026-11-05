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
The mesh admin page.

Deliberately thin. The page load renders a shell and the browser fetches peers,
liveness and audit rows from /api/v1/mesh/*, so there is one source of truth for
what the mesh looks like and the page cannot disagree with the daemon's view of it.

### Why it renders nothing about the mesh itself

The prototype's view passed the bound mesh id into the template so the header
could show it, resolving it with a try/except that returned an empty string on any
failure. That produced a page that rendered a mesh with no id and no explanation,
which reads as "there is no mesh" whether the cluster is unbound, the config store
is unreachable, or something else failed.

Here the page renders and asks the API. The API distinguishes those cases already:
an unbound cluster gets a 409 with a message saying so, and an unreachable store
gets a 503. The page shows whichever it receives, so the operator reads the actual
reason rather than an absence.

### Scope

This page covers the approval path and the quorum path: the peer list, the
lifecycle actions, daemon liveness, the audit log, and the proposals a large mesh
needs before decommission, tombstone or reclaim can be applied. The prototype's
template is the full mesh UI for the whole eight-CR stack, with panels for freeze
state, replicas and probe capacity, none of whose endpoints exist yet. Those arrive
with the CRs that add their APIs, so a button here always has something to call.
"""

import logging

from flask import Blueprint, render_template

import config
from decorators import login_required, admin_only

logger = logging.getLogger("soca_logger")

admin_mesh = Blueprint("admin_mesh", __name__, template_folder="templates")


@admin_mesh.route("/admin/mesh", methods=["GET"])
@login_required
@admin_only
def index():
    """
    Render the shell. Everything about the mesh is fetched client-side.

    Nothing here reads the mesh, so this cannot fail because cross-region is
    disabled or because DynamoDB is unreachable. The page always loads and reports
    what the API said, which is the difference between an operator seeing "this
    cluster is not bound to a mesh" and seeing an empty table.
    """
    return render_template(
        "admin/mesh.html",
        flask_endpoint=config.Config.FLASK_ENDPOINT,
    )
