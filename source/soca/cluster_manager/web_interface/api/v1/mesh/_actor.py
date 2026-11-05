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
Who performed a mesh action, for the audit trail.

One function, because the prototype had three near-identical copies of this in
its fence, freeze and diff-approval modules, each reading slightly different
headers with slightly different fallbacks. Every write path in this package
resolves the actor through here, and a test asserts no module in the package
reads an actor header directly.

The identity comes from `g.authenticated_user`, which `admin_api` sets on every
path that can reach an endpoint here, and never from a request header.

That distinction is the whole point of this module and an earlier version of it
got it wrong. It read `X-EDH-User` straight off the request, which `admin_api`
validates on one of its three paths and does not look at on the other two, so any
caller who could reach the admin API could attribute a transition to somebody
else: an admin authenticated by session cookie could set `X-EDH-User: someone`
and have an approval recorded against them, and a caller holding the root API key
could name any actor at all. The audit log exists so that approving or revoking a
cluster is attributable, and an attributable-looking field that the actor chooses
is worse than no field, because it reads as evidence.

The reason given for reading headers was that Flask's `g.user` is empty on the
header path the admin UI uses. That was true and beside the point: the verified
principal is `g.authenticated_user`, set by `admin_api` before the handler runs,
on all three of its paths. It was available the whole time under another name.
"""

from __future__ import annotations

import re

from flask import g, request

# Set by the overlay daemon when it forwards a daemon-originated event over the
# trusted local socket. Recorded as an annotation on the verified principal, never
# in place of it: a header can say which subsystem prompted an action, but it
# cannot be trusted to say who performed it.
_DAEMON_HEADER = "X-EDH-Actor"

# What an annotation may look like. Subsystem names, not prose: anything else is
# dropped, so a caller cannot write a readable sentence into the field an operator
# reads to decide who did something.
_ANNOTATION_SHAPE = re.compile(r"[A-Za-z0-9._-]{1,64}")

# Used only when no verified principal is present. See actor_from_request.
_FALLBACK_ACTOR = "unattributed"


def actor_from_request() -> str:
    """
    The verified identity that performed this action, for an audit write.

    Never raises and never returns an empty string. An audit append must not fail
    because the caller's identity could not be established, since losing the
    record of a lifecycle transition is worse than recording it against a coarse
    actor, and the transition has already been decided by the time this is called.

    On the fallback, and being precise rather than flattering about it: every
    endpoint in this package is wrapped by `admin_api`, which sets
    `g.authenticated_user` on each of its three paths and refuses the request
    otherwise, and a test in this CR asserts that wrapping holds for every
    endpoint. So the fallback is unreachable through the endpoints as registered.
    It is kept because this function's contract is that it cannot fail, and a
    future caller reached through a different decorator would otherwise raise
    inside an audit write. It is not a security control and does not stand in for
    one.
    """
    verified = (getattr(g, "authenticated_user", "") or "").strip()
    if not verified:
        return _FALLBACK_ACTOR

    # A daemon-originated event is labelled, not renamed. The verified principal
    # stays the subject so the row remains attributable, and the annotation says
    # which subsystem asked, which is what the separate header was for.
    #
    # The annotation is bounded because it is still caller-supplied text landing in
    # an append-only audit row. It is clearly subordinate to the verified subject,
    # but an unbounded value would let a caller write readable prose into the field
    # an operator reads to decide who did something. Anything outside a
    # conservative shape is dropped rather than escaped, since this is decoration
    # and losing it costs nothing.
    daemon = (request.headers.get(_DAEMON_HEADER) or "").strip()
    if daemon and daemon != verified and _ANNOTATION_SHAPE.fullmatch(daemon):
        return f"{verified} (via {daemon})"
    return verified
