# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import click
import getpass
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from utils.validators import Validators
from botocore.exceptions import ClientError
from commands.common import print_output, get_cluster_id, is_controller_instance
from commands.logs.common import (
    AI_ELIGIBLE_LEVELS,
    get_ai_system_prompt,
    ALERT_SEVERITIES,
    LOG_LEVELS,
    build_boto3_client,
    colorize_timestamped_line,
    parse_time_to_epoch_ms,
    publish_sns_alert,
    render_ai_analysis_stream,
)
from utils.ai_assistant.assistant import SocaAiAssistant

logger = logging.getLogger("soca_logger")


def _resolve_log_groups(
    function_names: list[str], cluster_id: str
) -> dict[str, str]:
    """Resolve function names to their CloudWatch log group names.
    Returns a dict of {log_group_name: function_name}."""
    _lambda_client = build_boto3_client("lambda")
    _log_groups = {}

    for _fn in function_names:
        logger.debug(f"Resolving log group for function: {_fn}")
        _function_name = _fn if _fn.startswith(cluster_id) else f"{cluster_id}-{_fn}"
        try:
            _fn_config = _lambda_client.get_function_configuration(
                FunctionName=_function_name
            )
            _log_group = _fn_config.get("LoggingConfig", {}).get(
                "LogGroup", f"/aws/lambda/{_fn_config['FunctionName']}"
            )
            _log_groups[_log_group] = _function_name
        except ClientError as e:
            logger.warning(
                f"Skipping function {_function_name}: {e.response['Error']['Message']}"
            )

    return _log_groups


def _discover_all_functions(cluster_id: str, timeout: int) -> list[str]:
    """Discover all Lambda functions for a cluster via Resource Groups Tagging API."""
    _client = build_boto3_client("resourcegroupstaggingapi")
    _functions = []
    _pagination_token = None
    _deadline = time.monotonic() + timeout

    while time.monotonic() < _deadline:
        try:
            _kwargs = {
                "TagFilters": [
                    {"Key": "edh:ClusterId", "Values": [cluster_id]},
                ],
                "ResourceTypeFilters": ["lambda:function"],
            }
            if _pagination_token:
                _kwargs["PaginationToken"] = _pagination_token
            _response = _client.get_resources(**_kwargs)
        except ClientError as e:
            logger.error(
                f"Resource Groups Tagging API error: {e.response['Error']['Message']}"
            )
            print_output(
                f"Resource Groups Tagging API error: {e.response['Error']['Message']}",
                error=True,
            )

        for _resource in _response.get("ResourceTagMappingList", []):
            _arn = _resource["ResourceARN"]
            _functions.append(_arn.rsplit(":", 1)[-1])

        _pagination_token = _response.get("PaginationToken", "")
        if not _pagination_token:
            break
    else:
        logger.warning(
            f"Discovery timed out after {timeout}s, found {len(_functions)} functions"
        )

    return _functions


@click.group(name="lambda")
def logs_lambda() -> None:
    pass


@logs_lambda.command()
@click.option(
    "--function-name",
    required=True,
    help="Lambda function name (without the /aws/lambda/ prefix)",
)
@click.option(
    "--log-level",
    type=click.Choice(LOG_LEVELS),
    multiple=True,
    help="Filter logs by level (repeatable, e.g. --log-level ERROR --log-level WARNING)",
)
@click.option(
    "--from",
    "start_time",
    default=None,
    help="Start time: ISO 8601 (e.g. 2024-01-15T10:30:00) or epoch seconds",
)
@click.option(
    "--to",
    "end_time",
    default=None,
    help="End time: ISO 8601 (e.g. 2024-01-15T12:00:00) or epoch seconds",
)
@click.option(
    "--limit",
    type=int,
    default=100,
    help="Maximum number of log events to return (default: 100)",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--ai-assistant",
    is_flag=False,
    flag_value="default",
    default=None,
    help="Invoke Bedrock to analyze errors. Pass a model ID or omit the value to use the default model. Only active with --log-level WARNING/ERROR/CRITICAL.",
)
@click.pass_context
def fetch(
    ctx: click.Context,
    function_name: str,
    limit: int,
    output_format: str,
    log_level: tuple[str, ...] = (),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    ai_assistant: Optional[str] = None,
) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    _cluster_id = get_cluster_id()
    if not function_name.startswith(_cluster_id):
        function_name = f"{_cluster_id}-{function_name}"

    logger.debug(
        f"Fetching logs for function={function_name}, log_level={log_level}, limit={limit}"
    )

    _lambda_client = build_boto3_client("lambda")
    _max_retries = 5
    for _attempt in range(_max_retries):
        try:
            _fn_config = _lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            break
        except ClientError as e:
            _error_code = e.response["Error"]["Code"]
            if _error_code == "TooManyRequestsException":
                if _attempt < _max_retries - 1:
                    _wait = 2 ** _attempt
                    logger.debug(f"Throttled, retrying in {_wait}s (attempt {_attempt + 1}/{_max_retries})")
                    time.sleep(_wait)
                    continue
                print_output(f"Lambda API throttled after {_max_retries} retries", error=True)
                return
            elif _error_code == "ResourceNotFoundException":
                print_output(f"Lambda function not found: {function_name}", error=True)
                return
            else:
                print_output(
                    f"Lambda API error: {e.response['Error']['Message']}",
                    error=True,
                )
                return
        except Exception as e:
            print_output(f"Unexpected error: {e}", error=True)
            return

    _log_group_name = _fn_config.get("LoggingConfig", {}).get(
        "LogGroup", f"/aws/lambda/{_fn_config['FunctionName']}"
    )
    logger.debug(f"Using log group: {_log_group_name}")

    _client = build_boto3_client("logs")

    _kwargs = {
        "logGroupName": _log_group_name,
        "limit": limit,
        "interleaved": True,
    }

    _now = datetime.now(tz=timezone.utc)
    _default_start = _now - timedelta(hours=12)
    _kwargs["startTime"] = parse_time_to_epoch_ms(start_time) if start_time else int(_default_start.timestamp() * 1000)
    _kwargs["endTime"] = parse_time_to_epoch_ms(end_time) if end_time else int(_now.timestamp() * 1000)

    if log_level:
        if Validators.is_list_length_equal_of(log_level, 1):
            _kwargs["filterPattern"] = f'"{log_level[0]}"'
        else:
            _kwargs["filterPattern"] = " ".join(f'?"{lvl}"' for lvl in log_level)

    _events = []
    while Validators.is_list_length_lower_than(_events, limit):
        try:
            _response = _client.filter_log_events(**_kwargs)
        except ClientError as e:
            _error_code = e.response["Error"]["Code"]
            if _error_code == "ResourceNotFoundException":
                print_output(f"Log group not found: {_log_group_name}", error=True)
            else:
                print_output(
                    f"CloudWatch Logs API error: {e.response['Error']['Message']}",
                    error=True,
                )
            break

        _events.extend(_response.get("events", []))
        _next_token = _response.get("nextToken")
        if not _next_token:
            break
        _kwargs["nextToken"] = _next_token

    _events = _events[:limit]
    if not _events:
        print_output("No log events found matching the criteria.")
        return

    logger.debug(f"Retrieved {len(_events)} log events")

    if output_format == "json":
        _json_events = []
        for _event in _events:
            _json_events.append(
                {
                    "timestamp": datetime.fromtimestamp(
                        _event["timestamp"] / 1000, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%S"),
                    "message": _event["message"].rstrip("\n"),
                    "logStreamName": _event.get("logStreamName", ""),
                }
            )
        click.echo(json.dumps(_json_events, indent=4))
    else:
        for _event in _events:
            _ts = datetime.fromtimestamp(
                _event["timestamp"] / 1000, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S")
            _message = _event["message"].rstrip("\n")
            click.echo(f"[{_ts}] {_message}")

    if ai_assistant and set(log_level) & AI_ELIGIBLE_LEVELS:
        click.echo()
        log_texts = [e["message"].rstrip("\n") for e in _events]
        assistant = SocaAiAssistant(username=getpass.getuser())
        stream = assistant.converse_stream("\n".join(log_texts), system_prompt=get_ai_system_prompt("lambda"))
        render_ai_analysis_stream(stream)


@logs_lambda.command(name="list")
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--timeout",
    type=int,
    default=120,
    help="Timeout in seconds (default: 120 seconds)",
)
@click.pass_context
def list_functions(ctx: click.Context, output_format: str, timeout: int) -> None:
    # note: do not use https://docs.aws.amazon.com/boto3/latest/reference/services/lambda/client/list_tags.html
    # as this will not work with tags automatically applied by CloudFormation. Instead, use Resource Groups Tagging API to find all Lambda functions with the edh:ClusterId tag.
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    _client = build_boto3_client("resourcegroupstaggingapi")
    _cluster_id = get_cluster_id()
    logger.info(f"Listing Lambda functions for cluster_id={_cluster_id}")
    _functions = []
    _pagination_token = ""
    _deadline = time.monotonic() + timeout

    while time.monotonic() < _deadline:
        try:
            _kwargs = {
                "TagFilters": [
                    {"Key": "edh:ClusterId", "Values": [_cluster_id]},
                ],
                "ResourceTypeFilters": ["lambda:function"],
            }
            if _pagination_token:
                _kwargs["PaginationToken"] = _pagination_token

            _response = _client.get_resources(**_kwargs)
        except ClientError as e:
            logger.error(
                f"Resource Groups Tagging API error: {e.response['Error']['Message']}"
            )
            print_output(
                f"Resource Groups Tagging API error: {e.response['Error']['Message']}",
                error=True,
            )

        for _resource in _response.get("ResourceTagMappingList", []):
            _arn = _resource["ResourceARN"]
            _fn_name = _arn.rsplit(":", 1)[-1]
            _functions.append(_fn_name)

        _pagination_token = _response.get("PaginationToken", "")
        if not _pagination_token:
            break
    else:
        logger.warning(
            f"Pagination timed out after {timeout} seconds, returning {len(_functions)} partial results"
        )
        print_output(
            f"Pagination timed out after {timeout} seconds. Partial results may be returned.",
            error=True,
        )

    if not _functions:
        logger.info("No Lambda functions found for this cluster")
        print_output("No Lambda functions found for this cluster.")
        return

    logger.info(f"Found {len(_functions)} Lambda functions")

    if output_format == "json":
        click.echo(json.dumps(sorted(_functions), indent=4))
    else:
        for _name in sorted(_functions):
            click.echo(_name)


@logs_lambda.command()
@click.option(
    "--function-name",
    multiple=True,
    help="Lambda function name(s) to watch (repeatable). Defaults to all cluster functions.",
)
@click.option(
    "--log-level",
    type=click.Choice(LOG_LEVELS),
    default=None,
    help="Only show logs at this level or above",
)
@click.option(
    "--interval",
    type=int,
    default=5,
    help="Polling interval in seconds (default: 5)",
)
@click.option(
    "--timeout",
    type=int,
    default=120,
    help="Stop watching after this many seconds (default: 120)",
)
@click.option(
    "--sns-topic-arn",
    default=None,
    help="SNS topic ARN to notify when log events at or above --sns-topic-trigger-log-level are detected. Make sure EDH Controller has sns:Publish permissions for this topic.",
)
@click.option(
    "--sns-topic-trigger-log-level",
    type=click.Choice(ALERT_SEVERITIES),
    default=None,
    help="Minimum log level that triggers an SNS notification (requires --sns-topic-arn)",
)
@click.pass_context
def watch(
    ctx: click.Context,
    function_name: tuple[str, ...],
    interval: int,
    timeout: int,
    log_level: Optional[str] = None,
    sns_topic_arn: Optional[str] = None,
    sns_topic_trigger_log_level: Optional[str] = None,
) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    if bool(sns_topic_arn) != bool(sns_topic_trigger_log_level):
        raise click.UsageError(
            "--sns-topic-arn and --sns-topic-trigger-log-level must be specified together."
        )

    _cluster_id = get_cluster_id()

    if function_name:
        _target_functions = list(function_name)
    else:
        _target_functions = _discover_all_functions(
            _cluster_id, timeout=30
        )
        if not _target_functions:
            print_output("No Lambda functions found for this cluster.")
            return

    _log_groups = _resolve_log_groups(_target_functions, _cluster_id)
    if not _log_groups:
        print_output("No valid log groups resolved.", error=True)

    _severity_order = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    _sns_trigger_threshold = (
        _severity_order.index(sns_topic_trigger_log_level)
        if sns_topic_trigger_log_level
        else None
    )
    _sns_client = build_boto3_client("sns") if sns_topic_arn else None
    if sns_topic_arn:
        logger.info(
            f"SNS alerting enabled, topic={sns_topic_arn}, trigger_level={sns_topic_trigger_log_level}"
        )

    logger.info(
        f"Watching {len(_log_groups)} log group(s), interval={interval}s, timeout={timeout}s"
    )
    click.echo(
        click.style(
            f"Watching {len(_log_groups)} function(s)... (Ctrl+C to stop)", bold=True
        )
    )

    _logs_client = build_boto3_client("logs")
    _last_seen = {_lg: int(time.time() * 1000) for _lg in _log_groups}
    _deadline = time.monotonic() + timeout

    try:
        while time.monotonic() < _deadline:
            for _log_group, _fn_name in _log_groups.items():
                _kwargs = {
                    "logGroupName": _log_group,
                    "startTime": _last_seen[_log_group],
                    "interleaved": True,
                }
                if log_level:
                    _kwargs["filterPattern"] = f'"{log_level}"'

                try:
                    _response = _logs_client.filter_log_events(**_kwargs)
                except ClientError as e:
                    logger.warning(
                        f"Error polling {_log_group}: {e.response['Error']['Message']}"
                    )
                    continue

                for _event in _response.get("events", []):
                    _ts = datetime.fromtimestamp(
                        _event["timestamp"] / 1000, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%S")
                    _message = _event["message"].rstrip("\n")
                    _short_name = (
                        _fn_name.rsplit("-", 1)[-1] if "-" in _fn_name else _fn_name
                    )
                    click.echo(colorize_timestamped_line(_ts, _short_name, _message))
                    _last_seen[_log_group] = _event["timestamp"] + 1

                    if _sns_client and _sns_trigger_threshold is not None:
                        for _sev in _severity_order[_sns_trigger_threshold:]:
                            if _sev in _message:
                                publish_sns_alert(
                                    _sns_client,
                                    sns_topic_arn,
                                    _fn_name,
                                    _ts,
                                    _sev,
                                    _message,
                                )
                                break

            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    click.echo(click.style("\nStopped watching.", bold=True))


@logs_lambda.command()
@click.option(
    "--lines",
    type=int,
    default=50,
    help="Number of log lines to dump for failed functions (default: 50)",
)
@click.option(
    "--timeout",
    type=int,
    default=120,
    help="Timeout in seconds (default: 120)",
)
@click.pass_context
def failed(ctx: click.Context, lines: int, timeout: int) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    _cluster_id = get_cluster_id()
    _all_functions = _discover_all_functions(
        _cluster_id, timeout=timeout
    )
    if not _all_functions:
        print_output("No Lambda functions found for this cluster.")
        return

    _lambda_client = build_boto3_client("lambda")
    _logs_client = build_boto3_client("logs")
    _failures = {}

    for _fn_name in _all_functions:
        try:
            _fn_config = _lambda_client.get_function_configuration(
                FunctionName=_fn_name
            )
        except ClientError as e:
            logger.warning(f"Skipping {_fn_name}: {e.response['Error']['Message']}")
            continue

        _log_group = _fn_config.get("LoggingConfig", {}).get(
            "LogGroup", f"/aws/lambda/{_fn_config['FunctionName']}"
        )

        try:
            _streams_response = _logs_client.describe_log_streams(
                logGroupName=_log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            )
        except ClientError as e:
            logger.warning(
                f"Cannot read log streams for {_fn_name}: {e.response['Error']['Message']}"
            )
            continue

        _log_streams = _streams_response.get("logStreams", [])
        if not _log_streams:
            continue

        _latest_stream = _log_streams[0]["logStreamName"]

        try:
            _events_response = _logs_client.get_log_events(
                logGroupName=_log_group,
                logStreamName=_latest_stream,
                startFromHead=False,
                limit=lines,
            )
        except ClientError as e:
            logger.warning(
                f"Cannot read log events for {_fn_name}: {e.response['Error']['Message']}"
            )
            continue

        _events = _events_response.get("events", [])
        _messages = [_e["message"].rstrip("\n") for _e in _events]
        _full_text = "\n".join(_messages)

        _has_error = any(
            _keyword in _full_text
            for _keyword in (
                "ERROR",
                "FATAL",
                "CRITICAL",
                "Task timed out",
                "Runtime.ExitError",
                "Runtime.HandlerNotFound",
            )
        )

        if _has_error:
            _failures[_fn_name] = _messages

    _result = {
        "failed_lambda": len(_failures),
        "failures": _failures,
    }

    logger.info(
        f"Checked {len(_all_functions)} functions, {_result['failed_lambda']} failed"
    )

    click.echo(json.dumps(_result, indent=4))
