# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pure helpers for deriving infrastructure identifiers from machine tokens.

The CloudFormation stack name for a VDI / target node is a pure *infrastructure
identifier*. It MUST NOT embed user-controlled free-form strings (e.g. the
user-supplied session name): embedding the session name caused CFN stack-name
collisions when names were rapidly cycled (a stack stuck in DELETE_IN_PROGRESS
holds its name), and would mangle or empty out for emoji / RTL / i18n names.

Identity = ``cluster_id`` + ``session_uuid`` (the uniqueness guarantee, never
truncated). The owner login is included only as a cosmetic, console-groupable
prefix, sanitized to the CFN stack-name charset. The raw session name lives in
the DB ``session_name`` column and the ``edh:JobName`` tag (data plane) -- never
in an infrastructure identifier.
"""

import re

# CloudFormation stack names permit only [A-Za-z0-9-] and must start with a
# letter (the cluster_id prefix satisfies the leading-letter requirement).
_STACK_NAME_ILLEGAL = re.compile(r"[^a-zA-Z0-9-]")


def sanitize_stack_token(value: str) -> str:
    """Strip every character illegal in a CFN stack name from ``value``."""
    return _STACK_NAME_ILLEGAL.sub("", str(value))


def generate_stack_name(cluster_id: str, owner: str, session_uuid: str) -> str:
    """Build the CFN stack name ``{cluster_id}-{sanitized owner}-{session_uuid}``.

    ``session_uuid`` is the uniqueness guarantee and is never truncated. ``owner``
    is sanitized to the CFN charset and is purely cosmetic (console grouping by
    owner). ``cluster_id`` is machine config and is sanitized defensively.
    """
    return (
        f"{sanitize_stack_token(cluster_id)}"
        f"-{sanitize_stack_token(owner)}"
        f"-{session_uuid}"
    )
