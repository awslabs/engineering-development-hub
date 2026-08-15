# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re

# EC2 LaunchTemplate UserData hard cap. Applies to the BASE64-decoded byte
# count (i.e. the raw script bytes), not the base64 string length. AWS
# returns InvalidUserData.Malformed at deploy time if exceeded.
EC2_USER_DATA_CAP_BYTES = 16384

# Soft cap used by assert_user_data_size to fail at synth time before AWS
# rejects. Sized to alarm EARLY (~700 byte headroom above the current
# controller LT baseline of 12300 bytes after remove_text_aggressive).
# Tighter than 16384 - small_buffer because we WANT visibility on drift
# rather than waiting until we're close to the AWS cap. Adjust upward
# only when there's a deliberate reason for the controller LT to grow,
# never silently.
EC2_USER_DATA_SOFT_CAP_BYTES = 13000


def remove_text(text_to_remove: list, data: str) -> str:
    _user_data = data
    for _t in text_to_remove:
        _user_data = re.sub(f"{_t}", "", _user_data, flags=re.IGNORECASE)

    # Remove comments (but keep shebangs)
    _user_data = re.sub(r"^(?!#!)(#.*)$", "", _user_data, flags=re.MULTILINE)

    # Remove leading whitespace (Jinja2 template nesting produces deep indentation)
    _user_data = re.sub(r"^[ \t]+", "", _user_data, flags=re.MULTILINE)

    # Remove blank lines
    _user_data = re.sub(r"^\s*\n", "", _user_data, flags=re.MULTILINE)

    return _user_data


def remove_text_aggressive(text_to_remove: list, data: str) -> str:
    """
    Same as remove_text() but additionally strips INDENTED comment-only
    lines (lines like `  # foo`). The standard remove_text only strips
    column-zero comments; indented function-body comments survive.

    Use ONLY for files where the rendered output is bound by the EC2
    LaunchTemplate UserData 16KB cap and where a heredoc audit has
    confirmed no literal-content body lines start with whitespace + '#'.
    Verified safe for installer/resources/user_data/controller/01_user_data.sh.j2
    and its transitive includes (audit dated 2026-05-28).

    For files that render to S3 (no size cap), prefer remove_text -- the
    extra savings aren't worth the marginal heredoc-audit obligation.
    """
    _user_data = data
    for _t in text_to_remove:
        _user_data = re.sub(f"{_t}", "", _user_data, flags=re.IGNORECASE)

    # NEW: strip indented comment-only lines. Anchored: line must start
    # with one or more spaces/tabs, then a literal '#' (not the '#!'
    # shebang form), then any non-newline content to end-of-line.
    _user_data = re.sub(r"^[ \t]+#(?!!)[^\n]*$", "", _user_data, flags=re.MULTILINE)

    # Remove column-zero comments (but keep shebangs)
    _user_data = re.sub(r"^(?!#!)(#.*)$", "", _user_data, flags=re.MULTILINE)

    # Remove leading whitespace (Jinja2 template nesting produces deep indentation)
    _user_data = re.sub(r"^[ \t]+", "", _user_data, flags=re.MULTILINE)

    # Remove blank lines
    _user_data = re.sub(r"^\s*\n", "", _user_data, flags=re.MULTILINE)

    return _user_data


def assert_user_data_size(data: str, label: str, soft_cap: int = EC2_USER_DATA_SOFT_CAP_BYTES) -> int:
    """
    Assert a rendered UserData fits in the EC2 LaunchTemplate cap with
    headroom. Raises ValueError at synth time if the soft cap is breached
    so we get a clear error here instead of CFN reporting
    InvalidUserData.Malformed at deploy time.

    Returns the byte count for logging.

    Use this wherever a UserData string is about to be base64'd into a
    CfnLaunchTemplate. The soft cap (default 14848 bytes = 16KB - 1.5KB
    headroom) leaves room for per-deploy token substitution variance
    without surprises.
    """
    nbytes = len(data.encode("utf-8"))
    if nbytes > soft_cap:
        raise ValueError(
            f"UserData for {label} is {nbytes} bytes, exceeds soft cap "
            f"of {soft_cap} bytes (EC2 hard cap is {EC2_USER_DATA_CAP_BYTES}). "
            f"Pattern: move bulk to S3-rendered scripts (02_prerequisites, "
            f"03_setup) or apply the S3-asset stub pattern used by login_node "
            f"and DCV broker/gateway. The 16KB cap applies only to the "
            f"LaunchTemplate UserData; S3-rendered bootstrap files have no cap."
        )
    return nbytes


def encode_for_lt(data: str, label: str, soft_cap: int = EC2_USER_DATA_SOFT_CAP_BYTES) -> str:
    """
    Gzip + base64-encode for direct assignment to a CfnLaunchTemplate
    user_data field. cloud-init auto-decompresses gzipped UserData, which
    keeps the LT well under the 16KB cap (every other LT in cdk_construct
    gzips too). Single source of truth -- any LT user_data assignment in
    cdk_construct should go through this helper so the size guard cannot be
    bypassed.

    The 16KB EC2 limit applies to the FINAL (gzip+base64) UserData, so the
    guard checks the encoded size against the hard cap with 1KB headroom for
    per-deploy token-substitution variance. assert_user_data_size remains
    available for callers that want a raw-size drift alarm.
    """
    import base64
    import gzip

    _encoded = base64.b64encode(gzip.compress(data.encode("utf-8"))).decode("utf-8")
    _nbytes = len(_encoded.encode("utf-8"))
    _ceiling = EC2_USER_DATA_CAP_BYTES - 1024
    if _nbytes > _ceiling:
        raise ValueError(
            f"Encoded (gzip+base64) UserData for {label} is {_nbytes} bytes, "
            f"exceeds {_ceiling} (EC2 hard cap {EC2_USER_DATA_CAP_BYTES}, 1KB "
            f"headroom). Move bulk to S3-rendered scripts (02_prerequisites, "
            f"03_setup) or apply the S3-asset stub pattern used by login_node "
            f"and DCV broker/gateway."
        )
    return _encoded