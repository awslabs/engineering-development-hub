# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import click
import json
import logging
import re
from datetime import datetime, timezone
from typing import Literal, Optional

logger = logging.getLogger("soca_logger")
from botocore.client import BaseClient
from commands.common import print_output
import utils.aws.boto3_wrapper as utils_boto3
from botocore.exceptions import ClientError
from utils.validators import Validators


LOG_LEVELS: list[str] = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "red",
    "FATAL": "red",
    "ERROR": "red",
    "WARNING": "yellow",
    "WARN": "yellow",
}

ALERT_SEVERITIES: set[str] = {"CRITICAL", "FATAL", "ERROR"}

TIMESTAMP_PATTERNS: list[re.Pattern] = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
    re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]"),
]


def get_ai_system_prompt(environment: Literal["lambda", "web_interface", "node-bootstrap"]) -> str:
    """Generate a system prompt tailored to the log environment.
    """
    env_context = {
        "lambda": (
            "You are analyzing AWS Lambda function logs. "
            "Source code: https://github.com/awslabs/engineering-development-hub/tree/main/installer/resources/functions "
            "Common issues include timeouts, permission errors, missing environment variables, and dependency failures."
        ),
        "web_interface": (
            "You are analyzing the EDH web interface (Flask/uWSGI) logs. "
            "Source code: https://github.com/awslabs/engineering-development-hub/tree/main/source/soca/cluster_manager/web_interface"
            "Common issues include authentication failures, API errors, database connectivity, and request timeouts."
        ),
        "node-bootstrap": (
            "You are analyzing EC2 node bootstrap logs. "
            "Source code: https://github.com/awslabs/engineering-development-hub/tree/main/source/soca/cluster_node_bootstrap/"
            "Common issues include linux system errors, node bootstrap failures, storage mount problems, and application crashes."
        ),

    }

    return (
        "You are a troubleshooting assistant for Engineering Development Hub (EDH), an AWS-based HPC/VDI platform. "
        "Documentation: https://awslabs.github.io/engineering-development-hub-documentation/ "
        f"{env_context.get(environment, '')} "
        "Review the following log lines and provide a concise analysis of the issue, "
        "potential root causes, and recommended next steps for resolution."
    )

AI_ELIGIBLE_LEVELS: set[str] = {"WARNING", "ERROR", "CRITICAL"}


def build_boto3_client(service_name: str) -> BaseClient:
    response = utils_boto3.get_boto(service_name=service_name)
    if response.get("success") is False:
        print_output(
            f"Unable to create {service_name} client due to {response.get('message')}",
            error=True,
        )
    return response.get("message")


def parse_time_to_epoch_ms(value: str) -> int:
    """Parse a time string into epoch milliseconds."""
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    try:
        return int(value) * 1000
    except ValueError:
        print_output(
            f"Invalid time format: {value}. Use ISO 8601 (e.g. 2024-01-15T10:30:00) or epoch seconds.",
            error=True,
        )


def parse_time_to_datetime(value: str) -> datetime:
    """Parse a time string into a datetime object."""
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except ValueError:
        print_output(
            f"Invalid time format: {value}. Use ISO 8601 (e.g. 2024-01-15T10:30:00) or epoch seconds.",
            error=True,
        )


def parse_timestamp_from_line(line: str) -> datetime | None:
    """Extract a timestamp from a log line."""
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            ts_str = match.group(1)
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None


def colorize_line(line: str, label: str | None = None) -> str:
    """Colorize a log line based on severity keywords.
    If label is provided, prepend it as a cyan tag."""
    color = None
    for keyword, c in SEVERITY_COLORS.items():
        if keyword in line:
            color = c
            break
    if label:
        _label = click.style(f"[{label}]", fg="cyan")
        msg = click.style(line, fg=color) if color else line
        return f"{_label} {msg}"
    return click.style(line, fg=color) if color else line


def colorize_timestamped_line(ts: str, label: str, message: str) -> str:
    """Colorize a log line with a bold timestamp and cyan label."""
    color = None
    for keyword, c in SEVERITY_COLORS.items():
        if keyword in message:
            color = c
            break
    _prefix = click.style(f"[{ts}]", bold=True)
    _label = click.style(f"[{label}]", fg="cyan")
    msg = click.style(message, fg=color) if color else message
    return f"{_prefix} {_label} {msg}"


def publish_sns_alert(
    sns_client: BaseClient,
    topic_arn: str,
    source: str,
    ts: str,
    severity: str,
    message: str,
) -> bool:
    _subject = f"[{severity}] {source} - {ts}"
    if Validators.is_string_length_greater_than(_subject, 100):
        _subject = _subject[:97] + "..."

    _payload = json.dumps(
        {
            "source": source,
            "timestamp": ts,
            "severity": severity,
            "message": message,
        }
    )
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=_subject,
            Message=_payload,
        )
        return True
    except ClientError as e:
        logger.error(f"Failed to publish SNS alert: {e.response['Error']['Message']}")
        return False


def matches_log_level(line: str, log_level: str) -> bool:
    return log_level in line


def render_ai_analysis(analysis: "SocaResponse") -> None:
    """Render AI analysis output to the terminal."""
    if analysis.get("success") is True:
        click.echo()
        click.echo(click.style("--- EDH AI Analysis ---", fg="green", bold=True))
        click.echo(analysis.get("message"))
        click.echo(click.style("--- End ---", fg="green", bold=True))
    else:
        click.echo(click.style(f"AI assistant failed to provide analysis due to {analysis.get('message')}.", fg="red"))


def render_ai_analysis_stream(stream) -> None:
    """Render AI analysis output to the terminal in real-time as chunks arrive."""
    click.echo()
    click.echo(click.style("--- EDH AI Analysis ---", fg="green", bold=True))
    for chunk in stream:
        click.echo(chunk, nl=False)
    click.echo()
    click.echo(click.style("--- End ---", fg="green", bold=True))
