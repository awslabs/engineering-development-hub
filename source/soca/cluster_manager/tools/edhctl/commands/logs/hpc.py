# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import click
import getpass
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

from commands.common import print_output, is_controller_instance
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

_HPC_LOG_BASE = Path("/apps/edh/shared/logs/compute_node")



def _resolve_job_log_dir(job_id: str) -> Path | None:
    """Resolve the log directory for a job: <base>/<job_id>/uuid1/uuid2/"""
    job_dir = _HPC_LOG_BASE / job_id
    if not job_dir.exists():
        return None
    for uuid1 in job_dir.iterdir():
        if not uuid1.is_dir():
            continue
        for uuid2 in uuid1.iterdir():
            if uuid2.is_dir():
                return uuid2
    return None


def _discover_nodes(log_dir: Path) -> dict[str, list[Path]]:
    """Discover node subdirectories and their log files.
    Returns {node_name: [log_file_paths]}."""
    nodes = {}
    for entry in sorted(log_dir.iterdir()):
        if entry.is_dir():
            log_files = sorted(
                f for f in entry.iterdir() if f.is_file()
            )
            if log_files:
                nodes[entry.name] = log_files
    return nodes


@click.group(name="hpc")
def logs_hpc() -> None:
    pass


@logs_hpc.command(name="list")
@click.option(
    "--job-id",
    required=True,
    help="HPC job ID",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)",
)
@click.pass_context
def list_logs(ctx: click.Context, job_id: str, output_format: str) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    log_dir = _resolve_job_log_dir(job_id)
    if not log_dir:
        print_output(f"No logs found for job {job_id} under {_HPC_LOG_BASE / job_id}", error=True)
        return

    nodes = _discover_nodes(log_dir)
    if not nodes:
        print_output(f"No node log directories found under {log_dir}")
        return

    logger.debug(f"Found {len(nodes)} node(s) for job {job_id}")

    if output_format == "json":
        result = {
            "job_id": job_id,
            "log_dir": str(log_dir),
            "nodes": {
                node: [f.name for f in files] for node, files in nodes.items()
            },
        }
        click.echo(json.dumps(result, indent=4))
    else:
        click.echo(click.style(f"Job: {job_id}", bold=True))
        click.echo(click.style(f"Path: {log_dir}", dim=True))
        click.echo()
        for node, files in nodes.items():
            click.echo(click.style(f"  {node}/", fg="cyan"))
            for f in files:
                click.echo(f"    {f.name}")


@logs_hpc.command()
@click.option(
    "--job-id",
    required=True,
    help="HPC job ID",
)
@click.option(
    "--node",
    default=None,
    help="Filter by node name (subfolder). If not specified, all nodes are shown.",
)
@click.option(
    "--log-file",
    default=None,
    help="Filter by log file name. If not specified, all log files are read.",
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
    job_id: str,
    limit: int,
    output_format: str,
    node: Optional[str] = None,
    log_file: Optional[str] = None,
    log_level: tuple[str, ...] = (),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    ai_assistant: Optional[str] = None,
) -> None:
    if not is_controller_instance():
        print_output("This command must be run on the controller instance.", error=True)

    log_dir = _resolve_job_log_dir(job_id)
    if not log_dir:
        print_output(f"No logs found for job {job_id} under {_HPC_LOG_BASE / job_id}", error=True)
        return

    nodes = _discover_nodes(log_dir)
    if not nodes:
        print_output(f"No node log directories found under {log_dir}")
        return

    if node:
        if node not in nodes:
            print_output(
                f"Node '{node}' not found. Available nodes: {', '.join(nodes.keys())}",
                error=True,
            )
            return
        nodes = {node: nodes[node]}

    if log_file:
        filtered = {}
        for node_name, files in nodes.items():
            matching = [f for f in files if f.name == log_file]
            if matching:
                filtered[node_name] = matching
        if not filtered:
            print_output(f"Log file '{log_file}' not found in any node directory.", error=True)
            return
        nodes = filtered

    logger.debug(
        f"Fetching HPC logs: job_id={job_id}, log_level={log_level}, limit={limit}, "
        f"nodes={list(nodes.keys())}"
    )

    _now = datetime.now(tz=timezone.utc)
    _start_dt = parse_time_to_datetime(start_time) if start_time else _now - timedelta(hours=12)
    _end_dt = parse_time_to_datetime(end_time) if end_time else _now

    matched_lines = []
    for node_name, files in nodes.items():
        for file_path in files:
            try:
                with open(file_path, "r") as f:
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

                        matched_lines.append((node_name, file_path.name, line))
                        if Validators.is_list_length_greater_equal_than(matched_lines, limit):
                            break
            except OSError as e:
                logger.warning(f"Cannot read {file_path}: {e}")
                continue

            if Validators.is_list_length_greater_equal_than(matched_lines, limit):
                break
        if Validators.is_list_length_greater_equal_than(matched_lines, limit):
            break

    if not matched_lines:
        print_output("No log lines found matching the criteria.")
        return

    logger.debug(f"Retrieved {len(matched_lines)} log lines")

    if output_format == "json":
        json_lines = [
            {"node": n, "file": fname, "message": msg}
            for n, fname, msg in matched_lines
        ]
        click.echo(json.dumps(json_lines, indent=4))
    else:
        for node_name, fname, line in matched_lines:
            label = f"{node_name}/{fname}"
            click.echo(colorize_line(line, label=label))

    if ai_assistant and set(log_level) & AI_ELIGIBLE_LEVELS:
        click.echo()
        log_texts = [f"[{n}/{fname}] {msg}" for n, fname, msg in matched_lines]
        assistant = SocaAiAssistant(username=getpass.getuser())
        stream = assistant.converse_stream("\n".join(log_texts), system_prompt=get_ai_system_prompt("node-bootstrap"))
        render_ai_analysis_stream(stream)


