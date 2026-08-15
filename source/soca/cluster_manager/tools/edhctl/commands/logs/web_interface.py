# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import click
import getpass
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

from commands.common import print_output, get_cluster_id, is_controller_instance
from commands.logs.common import (
    AI_ELIGIBLE_LEVELS,
    LOG_LEVELS,
    get_ai_system_prompt,
    colorize_line,
    matches_log_level,
    parse_time_to_datetime,
    parse_timestamp_from_line,
    render_ai_analysis_stream,
)
from utils.ai_assistant.assistant import SocaAiAssistant

_LOG_FILES = {
    "uwsgi": "uwsgi.log",
    "web_interface": "web_interface.log",
}


def _get_log_dir(cluster_id: str) -> Path:
    return Path(f"/opt/edh/{cluster_id}/cluster_manager/web_interface/logs")


@click.group(name="web-interface")
def logs_webinterface() -> None:
    pass


@logs_webinterface.command()
@click.option(
    "--log-file",
    type=click.Choice(list(_LOG_FILES.keys())),
    required=True,
    help="Log file to read",
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
    help="Maximum number of log lines to return (default: 100)",
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
    log_file: str,
    limit: int,
    output_format: str,
    log_level: tuple[str, ...] = (),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    ai_assistant: Optional[str] = None,
) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    cluster_id = get_cluster_id()
    log_dir = _get_log_dir(cluster_id)
    log_path = log_dir / _LOG_FILES[log_file]

    if not log_path.exists():
        print_output(f"Log file not found: {log_path}", error=True)

    logger.debug(f"Reading log file: {log_path}, log_level={log_level}, limit={limit}")

    _now = datetime.now(tz=timezone.utc)
    _start_dt = (
        parse_time_to_datetime(start_time) if start_time else _now - timedelta(hours=12)
    )
    _end_dt = parse_time_to_datetime(end_time) if end_time else _now

    matched_lines = []
    with open(log_path, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            if log_level and not any(matches_log_level(line, lvl) for lvl in log_level):
                continue

            if _start_dt or _end_dt:
                line_ts = parse_timestamp_from_line(line)
                if line_ts:
                    if _start_dt and line_ts < _start_dt:
                        continue
                    if _end_dt and line_ts > _end_dt:
                        continue

            matched_lines.append(line)
            if Validators.is_list_length_greater_equal_than(matched_lines, limit):
                break

    if not matched_lines:
        print_output("No log lines found matching the criteria.")
        return

    logger.debug(f"Retrieved {len(matched_lines)} log lines")

    if output_format == "json":
        click.echo(json.dumps(matched_lines, indent=4))
    else:
        for line in matched_lines:
            click.echo(colorize_line(line))

    if ai_assistant and set(log_level) & AI_ELIGIBLE_LEVELS:
        click.echo()
        assistant = SocaAiAssistant(username=getpass.getuser())
        stream = assistant.converse_stream(
            "\n".join(matched_lines),
            system_prompt=get_ai_system_prompt("web_interface"),
        )
        render_ai_analysis_stream(stream)


@logs_webinterface.command()
@click.option(
    "--log-file",
    type=click.Choice(list(_LOG_FILES.keys())),
    default="web_interface",
    help="Log file to watch (default: web_interface)",
)
@click.option(
    "--log-level",
    type=click.Choice(LOG_LEVELS),
    default=None,
    help="Only show logs at this level",
)
@click.option(
    "--interval",
    type=int,
    default=2,
    help="Polling interval in seconds (default: 2)",
)
@click.option(
    "--timeout",
    type=int,
    default=120,
    help="Stop watching after this many seconds (default: 120)",
)
@click.pass_context
def watch(
    ctx: click.Context,
    log_file: str,
    interval: int,
    timeout: int,
    log_level: Optional[str] = None,
) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    cluster_id = get_cluster_id()
    log_dir = _get_log_dir(cluster_id)
    log_path = log_dir / _LOG_FILES[log_file]

    if not log_path.exists():
        print_output(f"Log file not found: {log_path}", error=True)

    logger.info(f"Watching {log_path}, interval={interval}s, timeout={timeout}s")
    click.echo(click.style(f"Watching {log_path}... (Ctrl+C to stop)", bold=True))

    deadline = time.monotonic() + timeout

    with open(log_path, "r") as f:
        f.seek(0, os.SEEK_END)

        try:
            while time.monotonic() < deadline:
                line = f.readline()
                if not line:
                    time.sleep(interval)
                    continue

                line = line.rstrip("\n")
                if not line:
                    continue

                if log_level and not matches_log_level(line, log_level):
                    continue

                click.echo(colorize_line(line))
        except KeyboardInterrupt:
            pass

    click.echo(click.style("\nStopped watching.", bold=True))


@logs_webinterface.command()
@click.option(
    "--lines",
    type=int,
    default=50,
    help="Number of log lines to check (default: 50)",
)
@click.pass_context
def failed(ctx: click.Context, lines: int) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    cluster_id = get_cluster_id()
    log_dir = _get_log_dir(cluster_id)
    failures = {}

    for name, filename in _LOG_FILES.items():
        log_path = log_dir / filename
        if not log_path.exists():
            logger.warning(f"Log file not found: {log_path}")
            continue

        tail_lines = []
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            _buffer = b""
            _pos = f.tell()

            while Validators.is_list_length_lower_than(tail_lines, lines) and _pos > 0:
                _read_size = min(4096, _pos)
                _pos -= _read_size
                f.seek(_pos)
                _buffer = f.read(_read_size) + _buffer
                tail_lines = _buffer.decode("utf-8", errors="replace").splitlines()

            tail_lines = tail_lines[-lines:]

        full_text = "\n".join(tail_lines)
        has_error = any(
            keyword in full_text
            for keyword in ("ERROR", "FATAL", "CRITICAL", "Traceback", "Exception")
        )

        if has_error:
            failures[name] = tail_lines

    result = {
        "failed_logs": len(failures),
        "failures": failures,
    }

    logger.info(
        f"Checked {len(_LOG_FILES)} log files, {result['failed_logs']} with errors"
    )

    click.echo(json.dumps(result, indent=4))
