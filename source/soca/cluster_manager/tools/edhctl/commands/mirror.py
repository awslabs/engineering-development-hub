# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
edhctl mirror -- inspect and recover the resources mirror.

The mirror copies external install artifacts into the cluster bucket and rewrites
the SSM keys that name them, so cluster nodes fetch from S3 instead of the public
internet. It runs once, driven by a CloudFormation custom resource at install time.

Why these commands exist. EDH never performs a CloudFormation stack update, so that
custom resource fires exactly once in a cluster's life: there is no CFN-driven way
to run the mirror again. An artifact that failed to mirror therefore stays failed,
and its SSM key holds the upstream URL (or, on a cluster installed before the fix,
nothing at all) for as long as the cluster exists. `recover` is the out-of-band
re-run, `status` reports the last run, and `keys` audits the current state of every
key the mirror owns without needing any log group to still be in retention.

    edhctl mirror status                     what the last run did
    edhctl mirror keys                       per-key: mirrored, upstream-only, absent
    edhctl mirror keys --degraded-only       just the ones not pointing at the mirror
    edhctl mirror recover                    re-run every manifest item
    edhctl mirror recover -k /system/openmpi/url    re-run one artifact
"""

import click

from commands.common import (
    confirm,
    get_cluster_id,
    is_controller_instance,
    print_output,
)
from utils.aws import boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.validators import Validators

# The trigger Lambda blocks for the whole mirror run, bounded by its own 15 minute
# timeout. botocore's default 60s read timeout would abort the client while the run
# continued server-side, so the socket has to outlast the function.
_INVOKE_READ_TIMEOUT_SEC = 960

# Retries are disabled for the invoke: a retried RequestResponse invoke would start a
# SECOND state machine execution mirroring the same items, racing the first one's SSM
# writes. One attempt, long timeout.
_INVOKE_MAX_ATTEMPTS = 1

_RUN_RECORD_KEY = "/_resources_mirroring/last_run"
_MANIFEST_KEY_TEMPLATE = "{cluster_id}/resources_mirroring/manifest.json"

# get_parameters accepts at most 10 names per call.
_SSM_BATCH = 10


@click.group()
def mirror():
    """Inspect and repair resources_mirroring artifacts."""
    pass


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@mirror.command()
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def status(output):
    """Report the outcome of the most recent mirror run."""
    _record = _read_config(_RUN_RECORD_KEY)

    if not _record:
        print_output(
            message=(
                "No mirror run record found.\n"
                "\n"
                "That means one of:\n"
                "  - the cluster was installed with resources_mirroring.method="
                "install-host, so no cloud mirror ran and the installer wrote the "
                "keys directly;\n"
                "  - resources_mirroring was disabled, so the keys hold their "
                "upstream URLs;\n"
                "  - the cluster was installed before the run record existed. Run "
                "'edhctl mirror keys' to audit the keys directly, which does not "
                "depend on the record.\n"
            ),
            output="text",
        )
        return

    if Validators.is_string(_record):
        _parsed = SocaCastEngine(data=_record).as_json()
        if not _parsed.success:
            print_output(
                message=f"Run record is not valid JSON: {_record}",
                error=True,
            )
            return
        _record = _parsed.message

    if output != "text":
        print_output(message=_record, output=output)
        return

    _failed = _record.get("failed_count", 0)
    _lines = [
        f"Status         : {_record.get('status')}",
        f"Completed at   : {_record.get('completed_at')}",
        f"Triggered by   : {_record.get('trigger')}",
        f"Method         : {_record.get('method')}",
        f"Failure mode   : {_record.get('failure_mode')}",
        f"Items in run   : {_record.get('item_count')}",
        f"Failed         : {_failed}",
        f"Counts         : {_record.get('counts')}",
        f"Execution      : {_record.get('execution_arn')}",
    ]
    if _record.get("cause"):
        _lines.append(f"Cause          : {_record.get('cause')}")

    _keys = _record.get("failed_config_keys") or []
    if _keys:
        _lines.append("")
        _lines.append("Config keys that did NOT get mirrored:")
        _lines.extend(f"  {_k}" for _k in _keys)
        if _record.get("failed_config_keys_truncated"):
            _lines.append(f"  ({_record['failed_config_keys_truncated']})")
        _lines.append("")
        _lines.append(
            "These keys hold an upstream URL rather than a mirror URL, so nodes "
            "fetch them over the internet. Fix the cause (egress to the source "
            "domain is the usual one), then run 'edhctl mirror recover'."
        )
    elif _failed:
        _lines.append("")
        _lines.append(
            f"{_failed} artifact(s) failed but carry no config key -- these are GPU "
            "driver objects consumed by a recursive copy of the mirror prefix, so "
            "that prefix is incomplete. Run 'edhctl mirror recover'."
        )

    print_output(message="\n".join(_lines), output="text")


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


@mirror.command()
@click.option(
    "--degraded-only",
    is_flag=True,
    default=False,
    help="Only show keys that are absent or still pointing upstream",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def keys(degraded_only, output):
    """Audit every SSM key the mirror owns, against the manifest.

    Reads the manifest the installer wrote and compares it to what is in SSM right
    now, so it reports the INSTALLED STATE rather than whatever a log group happens
    to still retain. Three outcomes per key:

      mirrored       value starts with s3://, so the node fetches from the mirror
      upstream-only  value is the original internet URL, so mirroring did not take
                     for this artifact (or was disabled)
      absent         no parameter at all -- the consumer gets ParameterNotFound and
                     has no URL to try. Only possible on a cluster installed before
                     the executor began writing a fallback on failure.
    """
    _cluster_id = get_cluster_id()
    _items = _load_manifest(_cluster_id)
    if _items is None:
        return

    _config_keys = sorted({_i.get("config_key") for _i in _items if _i.get("config_key")})
    if not _config_keys:
        print_output(
            message="The manifest contains no items with a config key.", output="text"
        )
        return

    _values, _absent = _read_ssm_values(_config_keys)
    if _values is None:
        return

    _rows = []
    for _key in _config_keys:
        if _key in _absent:
            _state = "absent"
            _value = ""
        else:
            _value = _values.get(_key, "")
            _state = "mirrored" if _value.startswith("s3://") else "upstream-only"
        if degraded_only and _state == "mirrored":
            continue
        _rows.append({"config_key": _key, "state": _state, "value": _value})

    _counts = {"mirrored": 0, "upstream-only": 0, "absent": 0}
    for _key in _config_keys:
        if _key in _absent:
            _counts["absent"] += 1
        elif _values.get(_key, "").startswith("s3://"):
            _counts["mirrored"] += 1
        else:
            _counts["upstream-only"] += 1

    if output != "text":
        print_output(
            message={"counts": _counts, "keys": _rows, "manifest_items": len(_items)},
            output=output,
        )
        return

    _lines = [
        f"Manifest items : {len(_items)} ({len(_config_keys)} with a config key)",
        f"Mirrored       : {_counts['mirrored']}",
        f"Upstream-only  : {_counts['upstream-only']}",
        f"Absent         : {_counts['absent']}",
        "",
    ]
    if not _rows:
        _lines.append("Every key points at the mirror.")
    else:
        _width = max(len(_r["config_key"]) for _r in _rows)
        for _r in _rows:
            _lines.append(
                f"{_r['config_key']:<{_width}}  {_r['state']:<13}  "
                f"{_r['value'][:80]}"
            )
    if _counts["upstream-only"] or _counts["absent"]:
        _lines.append("")
        _lines.append(
            "Fix the cause for the degraded keys, then run 'edhctl mirror recover'. "
            "An upstream-only value is not fatal on its own -- it is also what a "
            "cluster installed with mirroring disabled looks like."
        )

    print_output(message="\n".join(_lines), output="text")


# ---------------------------------------------------------------------------
# recover
# ---------------------------------------------------------------------------


@mirror.command()
@click.option(
    "-k",
    "--key",
    "config_keys",
    multiple=True,
    help=(
        "Config key to re-mirror. Repeatable. Accepts the full SSM name or the "
        "cluster-relative suffix. Omit to re-run every manifest item."
    ),
)
@click.option(
    "--failure-mode",
    type=click.Choice(["soft", "hard"]),
    default=None,
    help="Override the gate mode for this run. Defaults to the cluster's setting.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Report which manifest items would be re-run, and start nothing",
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
    help=(
        "Start the run and return immediately instead of blocking. Nothing is "
        "reported; read the outcome afterwards with 'edhctl mirror status'."
    ),
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def recover(config_keys, failure_mode, dry_run, no_wait, force, output):
    """Re-run the mirror out of band, without CloudFormation.

    Safe to repeat: the executor skips any artifact whose checksum already matches
    and still rewrites that artifact's SSM key on the skip path, so a full re-run
    repairs a missing or degraded key without re-downloading anything that is
    already mirrored.
    """
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host",
            error=True,
        )
        return

    _cluster_id = get_cluster_id()
    _function_name = f"{_cluster_id}-ResourceMirrorTrigger"

    _payload = {"action": "recover"}
    if config_keys:
        _payload["config_keys"] = list(config_keys)
    if failure_mode:
        _payload["failure_mode"] = failure_mode
    if dry_run:
        _payload["dry_run"] = True

    if not dry_run and not force:
        _scope = (
            f"{len(config_keys)} selected config key(s)"
            if config_keys
            else "EVERY item in the manifest"
        )
        print_output(
            message=(
                f"About to re-run the resources mirror for {_scope}.\n"
                f"This starts a Step Functions execution that downloads artifacts "
                f"and rewrites their SSM keys. Already-mirrored artifacts are "
                f"skipped by checksum."
            ),
            output="text",
        )
        if not confirm("Proceed"):
            print_output(message="Aborted.", output="text")
            return

    _resp = utils_boto3.get_boto(
        service_name="lambda",
        read_timeout=_INVOKE_READ_TIMEOUT_SEC,
        max_attempts=_INVOKE_MAX_ATTEMPTS,
    )
    if _resp.get("success") is False:
        print_output(
            message=f"Unable to build a lambda client: {_resp.get('message')}",
            error=True,
        )
        return
    _client = _resp.get("message")

    _serialized = SocaCastEngine(data=_payload).serialize_json()
    if _serialized.get("success") is not True:
        print_output(
            message=f"Unable to serialize the recovery payload: {_serialized.get('message')}",
            error=True,
        )
        return
    _invoke_payload = _serialized.get("message").encode("utf-8")

    if no_wait and not dry_run:
        try:
            _client.invoke(
                FunctionName=_function_name,
                InvocationType="Event",
                Payload=_invoke_payload,
            )
        except Exception as err:
            print_output(
                message=f"Unable to invoke {_function_name}: {err}", error=True
            )
            return
        if output == "text":
            print_output(
                message=(
                    f"Recovery started in the background on {_function_name}.\n"
                    f"Nothing is reported here -- an asynchronous invoke returns no "
                    f"result and surfaces no error. Check the outcome with "
                    f"'edhctl mirror status' once it finishes (minutes, depending on "
                    f"how many artifacts have to be fetched)."
                ),
                output="text",
            )
        return

    # Progress text would precede the structured result on stdout.
    if not no_wait and not dry_run and output == "text":
        print_output(
            message=(
                "Running. This blocks until the mirror finishes, which can take "
                "several minutes."
            ),
            output="text",
        )

    try:
        _raw = _client.invoke(
            FunctionName=_function_name,
            InvocationType="RequestResponse",
            Payload=_invoke_payload,
        )
    except Exception as err:
        print_output(
            message=(
                f"Unable to invoke {_function_name}: {err}\n"
                f"If this timed out, the run may still be in flight -- check "
                f"'edhctl mirror status' before retrying, so you do not start a "
                f"second concurrent execution."
            ),
            error=True,
        )
        return

    if _raw.get("FunctionError"):
        print_output(
            message=(
                f"{_function_name} failed ({_raw.get('FunctionError')}): "
                f"{_raw['Payload'].read().decode('utf-8')[:2000]}"
            ),
            error=True,
        )
        return

    _payload_stream = _raw.get("Payload")
    _parsed = (
        SocaCastEngine(data=_payload_stream.read()).as_json()
        if _payload_stream is not None
        else None
    )
    if _parsed is None or not _parsed.success:
        print_output(
            message=f"Could not parse the response from {_function_name}",
            error=True,
        )
        return
    _result = _parsed.message

    if output != "text":
        print_output(message=_result, output=output)
        return

    _status = _result.get("status")

    if _status == "DRY_RUN":
        _lines = [
            f"Would re-run {_result.get('selected_count')} of "
            f"{_result.get('manifest_count')} manifest item(s), "
            f"failure_mode={_result.get('failure_mode')}.",
        ]
        _selected = _result.get("selected_config_keys") or []
        if _selected:
            _lines.append("")
            _lines.extend(f"  {_k}" for _k in _selected)
        print_output(message="\n".join(_lines), output="text")
        return

    if _status in ("ERROR", "SKIPPED"):
        _msg = _result.get("error", "no detail returned")
        _available = _result.get("available_config_keys")
        if _available:
            _msg = f"{_msg}\n\nConfig keys present in the manifest:\n" + "\n".join(
                f"  {_k}" for _k in _available
            )
        print_output(message=_msg, error=_status == "ERROR", output="text")
        return

    _failed = _result.get("failed_count", 0)
    _lines = [
        f"Execution status : {_status}",
        f"Items in run     : {_result.get('item_count')} of "
        f"{_result.get('manifest_count')} in the manifest",
        f"Failed           : {_failed}",
        f"Execution        : {_result.get('execution_arn')}",
    ]
    if _result.get("cause"):
        _lines.append(f"Cause            : {_result.get('cause')}")

    _failed_keys = _result.get("failed_config_keys") or []
    if _failed_keys:
        _lines.append("")
        _lines.append("Still not mirrored:")
        _lines.extend(f"  {_k}" for _k in _failed_keys)
        _lines.append("")
        _lines.append(
            "The underlying cause has not been fixed. Check the executor log for "
            "the source domain that failed: the log group is "
            f"/edh/{_cluster_id}/ResourceMirrorExecutorLambda/<deployment_id>."
        )
    elif _status == "SUCCEEDED" and not _failed:
        _lines.append("")
        _lines.append("Every selected artifact is mirrored. Verify with "
                      "'edhctl mirror keys'.")

    print_output(message="\n".join(_lines), output="text")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _read_config(key):
    """Return a configuration value, or None when the key is absent or unreadable.

    For an absent key, SocaConfig.get_value(allow_unknown_key=True) returns
    SocaResponse(success=False, message="Key does not exist"), and
    SocaResponse.get("message") hands that string back regardless of success.
    Reading `message` alone therefore turns a missing key into a truthy sentinel,
    so success has to be checked first.
    """
    _resp = SocaConfig(key=key).get_value(allow_unknown_key=True, default=None)
    if _resp.get("success") is not True:
        return None
    return _resp.get("message")


def _load_manifest(cluster_id):
    """Read the installer-written manifest from the cluster bucket.

    Returns the items list, or None after printing the reason it could not be read.
    A missing manifest is a meaningful answer rather than an error: it is what an
    install-host or disabled-mirroring cluster looks like.
    """
    _bucket = _read_config("/configuration/S3Bucket")
    if not _bucket:
        print_output(
            message="Unable to determine the cluster S3 bucket from the configuration.",
            error=True,
        )
        return None

    _key = _MANIFEST_KEY_TEMPLATE.format(cluster_id=cluster_id)

    _resp = utils_boto3.get_boto(service_name="s3")
    if _resp.get("success") is False:
        print_output(
            message=f"Unable to build an s3 client: {_resp.get('message')}", error=True
        )
        return None

    try:
        _body = (
            _resp.get("message").get_object(Bucket=_bucket, Key=_key)["Body"].read()
        )
    except Exception as err:
        print_output(
            message=(
                f"Unable to read the mirror manifest at s3://{_bucket}/{_key}: {err}\n"
                f"A cluster installed with resources_mirroring disabled, or with "
                f"method=install-host, has no manifest -- that is expected and the "
                f"keys are written directly by the installer."
            ),
            output="text",
        )
        return None

    _parsed = SocaCastEngine(data=_body).as_json()
    if not _parsed.success:
        print_output(message="Manifest is not valid JSON.", error=True)
        return None
    _data = _parsed.message

    _items = _data.get("items") if Validators.is_dict(_data) else _data
    if not Validators.is_list(_items):
        print_output(
            message="Manifest must be a list or an object with an items list.",
            error=True,
        )
        return None
    return _items


def _read_ssm_values(config_keys):
    """Read the current value of every config key.

    Returns (values_by_name, absent_names). get_parameters is used rather than the
    cache-backed config reader so the result is the parameter store's own state, and
    because it names absent parameters explicitly in InvalidParameters -- which is
    the distinction that matters here: an absent key and a key holding an upstream
    URL are different faults with different remedies.
    """
    _resp = utils_boto3.get_boto(service_name="ssm")
    if _resp.get("success") is False:
        print_output(
            message=f"Unable to build an ssm client: {_resp.get('message')}", error=True
        )
        return None, None
    _client = _resp.get("message")

    _values = {}
    _absent = set()
    for _start in range(0, len(config_keys), _SSM_BATCH):
        _batch = config_keys[_start : _start + _SSM_BATCH]
        try:
            _page = _client.get_parameters(Names=_batch)
        except Exception as err:
            print_output(
                message=f"Unable to read parameters {_batch}: {err}", error=True
            )
            return None, None
        for _param in _page.get("Parameters", []):
            _values[_param["Name"]] = _param.get("Value", "")
        _absent.update(_page.get("InvalidParameters", []))

    return _values, _absent
