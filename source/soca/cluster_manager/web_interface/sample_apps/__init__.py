# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sample application assets shipped with EDH/SOCA clusters.

Each subdirectory defines one default Application Profile that is
seeded into the ApplicationProfiles table at first cluster install.
See _loader.py for the loader API.
"""

from sample_apps._loader import (
    load_form,
    load_job_template,
    load_thumbnail,
)

__all__ = [
    "load_form",
    "load_job_template",
    "load_thumbnail",
]
