# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
The mesh sidecar: a second, minimal web application serving the peer-facing routes.

WHY A SEPARATE PROCESS. The mesh API has two kinds of route. The admin routes
authenticate an operator and are reached through the load balancer. The P2P routes
authenticate another cluster with the shared mesh token and their only legitimate
caller is a peer controller reaching this one over the WireGuard overlay. Serving
both from one application means the peer-facing half is on a public listener, with
the shared token as the only thing in front of code execution on this cluster's
scheduler - which is what CR-307548143 shipped, because there was one application.

This process binds to the overlay interface alone. A P2P route is therefore
unreachable from outside the mesh by CONSTRUCTION rather than by a check inside a
handler, and a caller needs to be on the overlay as well as hold the token.

WHAT LIVES HERE. `app.py` only: the application factory, the route registration
call, and a liveness endpoint. Everything it serves is defined in
`web_interface/api/v1/mesh/`, so there is one implementation of each endpoint and
this package decides only WHERE it is exposed.

The peer-health collector and the aggregated-health view the prototype had in this
package are NOT here. They belong with `capacity` and `probe_capacity` in the
health CR, and the scope guard in tests/cross_region names them.
"""
