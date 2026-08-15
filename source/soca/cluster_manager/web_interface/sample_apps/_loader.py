# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sample application asset loader.

Default-shipped Application Profiles (the rows seeded into the
ApplicationProfiles table at first cluster install) used to embed their
form definitions, job script templates, and thumbnail PNGs as inline
base64 strings inside soca_samples.py. That made the file 800KB+ of
opaque blobs — impossible to review, diff, grep, or hand-edit.

This loader inverts that pattern. The source-of-truth files live on
disk under sample_apps/<app_kind>/ as plain readable formats:

    sample_apps/<app_kind>/
        form.json                # formBuilder JSON schema (UTF-8)
        job_<scheduler>.sh.j2    # one wrapper script per scheduler
                                 # (pbs / lsf / slurm)
        thumbnail.png            # icon shown in the WebUI Application list

The loader reads them at install time, base64-encodes them, and returns
strings ready to drop into the ApplicationProfiles row. Each call hits
disk directly; this is fine because the seed runs only once per cluster
install and the assets are small (a few hundred KiB total). No caching
is intentional: an admin who edits a sample-app file on disk and
re-triggers the seed should see their changes immediately.

Per SOCA conventions, all public loader functions return a SocaResponse:
- on success, ``response.success is True`` and ``response.message`` holds
  the encoded asset string ready for storage in ApplicationProfiles.
- on failure, ``response.success is False`` and ``response.message``
  describes the problem. Internally we route failures through
  ``SocaError.GENERIC_ERROR`` so request IDs and trace info show up in
  the standard SOCA error logs.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

# sample_apps/ lives next to soca_samples.py — resolve relative to this file
_SAMPLE_APPS_DIR = Path(__file__).resolve().parent

_SUPPORTED_SCHEDULERS = ("openpbs", "pbspro", "lsf", "slurm")


def _read_file_bytes(app_kind: str, filename: str) -> SocaResponse:
    """Read raw bytes for a sample-app asset and wrap the result.

    Returns SocaResponse(success=True, message=<bytes>) on success.
    Returns a SocaError-derived SocaResponse(success=False, ...) when the
    file is missing — callers must check ``.success`` before consuming
    ``.message``.
    """
    path = _SAMPLE_APPS_DIR / app_kind / filename
    if not path.is_file():
        return SocaError.GENERIC_ERROR(
            helper=(
                f"Sample app asset not found: {path}. "
                f"Expected sample_apps/{app_kind}/{filename}"
            )
        )
    return SocaResponse(success=True, message=path.read_bytes())


def load_form(app_kind: str) -> SocaResponse:
    """Return base64-encoded form.json for the given sample app.

    On success, ``response.message`` is what gets stored in
    ApplicationProfiles.profile_form. The file MUST be valid JSON
    matching the formBuilder schema, but this loader does not validate
    it — keep validation out of the install-time hot path.
    """
    _read_response = _read_file_bytes(app_kind, "form.json")
    if _read_response.get("success") is False:
        return _read_response
    raw = _read_response.get("message")
    return SocaResponse(success=True, message=base64.b64encode(raw).decode("ascii"))


def load_job_template(app_kind: str, scheduler_provider: str) -> SocaResponse:
    """Return base64-encoded job_<scheduler>.sh.j2 for the sample app.

    scheduler_provider is the SocaHpcSchedulerProvider value from
    get_schedulers() — e.g. "openpbs", "pbspro", "lsf", "slurm". The
    PBSPRO and OPENPBS providers share the same job_pbs.sh.j2 template
    because the directives are identical.

    On success, ``response.message`` goes into
    ApplicationProfiles.profile_job and will be Jinja-rendered against
    form-supplied variables at job submission time.
    """
    sched_lower = scheduler_provider.lower()
    if sched_lower in ("openpbs", "pbspro"):
        sched_file = "job_pbs.sh.j2"
    elif sched_lower == "lsf":
        sched_file = "job_lsf.sh.j2"
    elif sched_lower == "slurm":
        sched_file = "job_slurm.sh.j2"
    else:
        return SocaError.GENERIC_ERROR(
            helper=(
                f"Unsupported scheduler provider for sample app {app_kind!r}: "
                f"{scheduler_provider!r}. Expected one of: "
                f"{', '.join(_SUPPORTED_SCHEDULERS)}."
            )
        )
    _read_response = _read_file_bytes(app_kind, sched_file)
    if _read_response.get("success") is False:
        return _read_response
    raw = _read_response.get("message")
    return SocaResponse(success=True, message=base64.b64encode(raw).decode("ascii"))


def load_thumbnail(app_kind: str) -> SocaResponse:
    """Return a 'data:image/png;base64,...' data URI for the thumbnail.

    On success, ``response.message`` is what gets stored in
    ApplicationProfiles.profile_thumbnail. Expects a PNG file at
    sample_apps/<app_kind>/thumbnail.png.
    """
    _read_response = _read_file_bytes(app_kind, "thumbnail.png")
    if _read_response.get("success") is False:
        return _read_response
    raw = _read_response.get("message")
    encoded = base64.b64encode(raw).decode("ascii")
    return SocaResponse(success=True, message=f"data:image/png;base64,{encoded}")
