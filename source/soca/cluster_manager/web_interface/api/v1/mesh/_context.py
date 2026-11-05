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
Which mesh this cluster is bound to.

One copy. The prototype had this function duplicated in its peers, audit and
health modules, and the copies had already drifted: two raised RuntimeError and
one returned an empty string, so the same misconfiguration produced a 500 from one
endpoint and an empty result set from another. A test asserts no module in this
package resolves the mesh id for itself.

Resolved per request rather than at import. The prototype cached table names at
module scope with a fallback to a bare `edh_overlay_*` name when resolution
failed, which is the default CR3 removed on purpose: the pre-namespacing version
of this feature created exactly those names, so such a table can genuinely exist
holding another mesh's stale data, and reading it reports a mesh that is not
there. Resolving per request also means a cluster whose config is fixed starts
working without a uwsgi restart.
"""

from __future__ import annotations


class MeshContextError(Exception):
    """
    Base for "I cannot tell you which mesh this is", carrying its own status.

    The status travels with the exception so a caller maps one type and gets the
    right code, rather than every endpoint growing a second except clause that a
    later endpoint can forget. That omission-by-sibling is the failure this stack
    keeps reproducing.
    """

    status_code = 409


class MeshNotConfigured(MeshContextError):
    """
    The cluster has no mesh binding.

    Not an error in the server: it is the ordinary state of every cluster with
    cross_region disabled, so callers report it as a conflict rather than a
    failure, and never as a 500.
    """

    status_code = 409


class MeshConfigUnavailable(MeshContextError):
    """
    The configuration store could not be read, so the binding is unknown.

    Distinct from MeshNotConfigured because the two are different claims. "You are
    not in a mesh" is a statement about this cluster; "I could not find out" is a
    statement about the config store, and answering the first when the second is
    true tells an operator their mesh is gone during a transient SSM failure.
    """

    status_code = 503


# The literal SocaConfig.get_value returns for a key that genuinely does not
# exist, when called with allow_unknown_key and no default. It is the only signal
# that distinguishes "this cluster is not bound to a mesh" from "the config store
# could not be read", so it is named here rather than inlined, and a test asserts
# it still appears in utils/config.py. If that string changes, the test fails
# loudly instead of this code silently reclassifying every unbound cluster.
_KEY_ABSENT_MESSAGE = "Key does not exist"


def resolve_mesh_id() -> str:
    """
    The mesh id the installer bound this cluster to.

    Imported lazily so importing this module does not require a configured
    cluster, which is what lets the rules be tested without one.

    Called with allow_unknown_key and deliberately WITHOUT a default, and that
    combination is the whole reason this reads the way it does. Passing a default
    makes get_value answer success=True carrying that default for every failure,
    including a throttled or unreachable store, because it catches Exception and
    substitutes the default. An earlier version of this function did pass one and
    checked the success flag, which looked correct and could never fire: the 503
    path below was unreachable and every config failure reported as an unbound
    cluster, which is exactly what the distinction exists to prevent.

    Without a default there are three distinguishable outcomes:

    - success, with a value: the cluster is bound.
    - failure carrying the key-absent sentinel: the cluster is not bound, 409.
    - any other failure: the store could not be read, 503.

    An unrecognised failure resolves to 503 rather than 409 on purpose. Telling an
    operator "you are not in a mesh" during a transient SSM failure is the worse
    error of the two, because it describes a permanent condition that is not true.
    """
    from utils.config import SocaConfig

    result = SocaConfig(key="/configuration/Overlay/mesh_id").get_value(
        allow_unknown_key=True
    )
    if result.get("success") is False:
        message = str(result.get("message") or "")
        if message == _KEY_ABSENT_MESSAGE:
            raise MeshNotConfigured(
                "This cluster is not bound to an overlay mesh. "
                "/configuration/Overlay/mesh_id is unset, which means either "
                "services.cross_region.enabled was false when it was installed, or "
                "the install did not reach the step that binds it."
            )
        raise MeshConfigUnavailable(
            "Could not read /configuration/Overlay/mesh_id, so whether this "
            "cluster is bound to an overlay mesh is unknown. This is a "
            f"configuration store failure rather than a statement about the mesh: "
            f"{message}"
        )
    mesh_id = result.get("message")
    if not mesh_id or mesh_id == "CACHE_MISS":
        raise MeshNotConfigured(
            "This cluster is not bound to an overlay mesh. "
            "/configuration/Overlay/mesh_id resolved to no value, which means "
            "either services.cross_region.enabled was false when it was "
            "installed, or the install did not reach the step that binds it."
        )
    return str(mesh_id)


def resolve_self_cluster_id() -> str:
    """
    This cluster's own id, used to mark which row in a mesh view is us.

    Returns an empty string when unavailable rather than raising, because failing
    to label one row is not a reason to refuse the whole view. That is the one
    place in this package where a missing value degrades instead of refusing, and
    it is deliberate: the caller renders a mesh either way.

    Unlike resolve_mesh_id, this one DOES pass a default, and for a reason rather
    than by omission: every failure mode here wants the same answer, so collapsing
    them is correct. There is deliberately no success check either, because with a
    default get_value cannot report failure, and a check that cannot fail reads as
    protection while providing none.
    """
    from utils.config import SocaConfig

    result = SocaConfig(key="/configuration/ClusterId").get_value(default="")
    cluster_id = result.get("message")
    if not cluster_id or cluster_id == "CACHE_MISS":
        return ""
    return str(cluster_id)


def mesh_endpoint(handler):
    """
    Wrap an endpoint so nothing escapes it as an unhandled exception.

    The boundary invariant, applied here before a review round asks for it. Every
    endpoint in this package enumerates the exceptions it expects, and CR3 spent six
    revisions learning that an enumeration written from the inside cannot be
    finished: reads were translated but not writes, one error type was mapped and
    three others were not. The fix that held was a catch-all at the boundary, and
    this is the same move one layer up.

    What it buys concretely. Without it, an unexpected exception becomes Flask's
    HTML 500 page, and the admin page's fetch handler can only report "HTTP 500"
    because there is no JSON body to read a message from. With it, the operator
    sees that something failed and the log carries the traceback, which is the
    difference between a diagnosable failure and a blank one.

    Deliberately does NOT swallow the exception silently: it is logged at exception
    level with the endpoint's name, so the traceback is preserved in full.
    """
    from functools import wraps

    @wraps(handler)
    def guarded(*args, **kwargs):
        try:
            return handler(*args, **kwargs)
        except Exception:  # noqa: BLE001 - see the docstring
            import logging

            from utils.error import SocaError

            # Logged here rather than left to SocaError, which walks the current
            # frames and so records where the failure was caught. The traceback is
            # what says where it was raised, and that is the part worth having.
            logging.getLogger("soca_logger").exception(
                "unhandled error in mesh endpoint %s",
                getattr(handler, "__qualname__", handler),
            )
            return SocaError.GENERIC_ERROR(
                helper=(
                    "The mesh API failed unexpectedly. The Request ID in this "
                    "message appears against the cause in the web interface log. "
                    "Nothing was changed by this call unless a later message says "
                    "otherwise."
                ),
                status_code=500,
            ).as_flask()

    return guarded
