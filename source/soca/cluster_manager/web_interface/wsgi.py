# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# CRITICAL: gevent.monkey.patch_all() MUST be the FIRST thing executed
# before any other module is imported. Patching ssl/socket/select after
# urllib3, botocore, or requests have imported the un-patched stdlib
# modules causes infinite-recursion errors in any HTTPS call that
# crosses the gevent boundary (e.g. SocaHttpClient -> localhost API).
#
# Defense in depth: edhwebui.sh also passes --gevent-early-monkey-patch
# to uwsgi, but if that flag is ever removed or the WSGI module is
# loaded outside uwsgi (e.g. a one-off Flask CLI command), this file's
# patch_all() still runs first.
#
# patch_all() is idempotent -- safe to call when uwsgi has already
# patched. The MonkeyPatchWarning that fires WITHOUT this is the
# canary for the recursion bug.
try:
    from gevent import monkey  # noqa: E402
    if not monkey.is_module_patched("socket"):
        monkey.patch_all()
except ImportError:
    # gevent not installed -- legacy thread-per-request mode
    # (UWSGI_GEVENT_ENABLED=0). The app still imports cleanly.
    pass

from app import app as application

if __name__ == "__main__":
    application.run()
