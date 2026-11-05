# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
uwsgi entry point for the mesh sidecar.

NOT NAMED wsgi.py, and that is load-bearing rather than a style choice.
edhwebui.sh locates its own processes with an unanchored `ps aux | grep uwsgi |
grep wsgi.py`, so any name ending in wsgi.py would match it: `edhwebui.sh stop`
would kill -9 this process along with the web interface, and `edhwebui.sh status`
would report the web interface running when only the sidecar was.

Kept to the import alone. Everything about the application is in
mesh_sidecar/app.py, which builds it through a factory so it stays callable from a
test.
"""

from mesh_sidecar.app import application  # noqa: F401
