# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Post-install mirror report — admin eye-candy printed after the endpoint probe.

Renders a digestible dashboard from the S3 mirror prefix (+ optional SFN execution
summary): a headline panel with totals/status/wall-clock, a by-source breakdown,
an "attention" section (URL fallbacks + errors/warnings), the slowest pulls, and
the largest artifacts.

Source domain is derived from the S3 KEY so grouping works even for objects mirrored
by the install-host path (no metadata). Timing + transfer method come from D13
metadata when present (cloud path). Region-aware (D15). Best-effort: never raises.
"""

import logging
import os

import boto3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger("soca_logger")


def _human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def render_mirror_report(mirror_bucket, prefix, region=None, console=None,
                         top_n=5, summary=None, wall_clock_sec=None):
    """Print the mirror dashboard.

    mirror_bucket/prefix locate the artifacts; region is the D15 bucket-region hint.
    summary (optional): EvaluateResults output {counts:{mirrored,skipped,warn,failed},
        failed_targets:[...]} — drives status counts + the errors group.
    wall_clock_sec (optional): SFN execution start->stop wall time.
    Best-effort — never raises into the install flow.
    """
    console = console or Console()
    norm_prefix = prefix if prefix.endswith("/") else prefix + "/"
    try:
        s3 = boto3.client("s3", region_name=region) if region else boto3.client("s3")
        paginator = s3.get_paginator("list_objects_v2")
        arts = []
        for page in paginator.paginate(Bucket=mirror_bucket, Prefix=norm_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith("/") or key.endswith("manifest.json") or obj["Size"] == 0:
                    continue
                rel = key[len(norm_prefix):]
                domain = rel.split("/", 1)[0] if "/" in rel else "(root)"
                meta = s3.head_object(Bucket=mirror_bucket, Key=key).get("Metadata", {})
                arts.append({
                    "name": key.rsplit("/", 1)[-1],
                    "domain": domain,
                    "size": obj["Size"],
                    "method": meta.get("transfer_method") or "install-host",
                    "duration_ms": int(meta.get("download_duration_ms", 0) or 0),
                    "attempts": int(meta.get("attempt_count", 1) or 1),
                    "copy_fallback": (meta.get("copy_fallback", "") == "true"),
                })

        if not arts:
            console.print(Panel(f"No mirrored artifacts under s3://{mirror_bucket}/{norm_prefix}",
                                title="[bold]📦 Resource Mirror[/]", border_style="#888888"))
            return

        total = len(arts)
        total_bytes = sum(a["size"] for a in arts)
        timed = [a for a in arts if a["duration_ms"] > 0]
        agg_ms = sum(a["duration_ms"] for a in timed)
        fallbacks = [a for a in arts if a["attempts"] > 1]
        copy_fellback = [a for a in arts if a.get("copy_fallback")]
        methods = {}
        for a in arts:
            methods[a["method"]] = methods.get(a["method"], 0) + 1
        method_str = " | ".join(f"{k}:{v}" for k, v in sorted(methods.items()))

        counts = (summary or {}).get("counts", {})
        failed_targets = (summary or {}).get("failed_targets", [])

        # ----- headline panel -----
        status = f"[bold green]✅ {counts.get('mirrored', total)} mirrored[/]"
        if counts.get("skipped"):
            status += f" | [bold]⏭ {counts['skipped']} skipped[/]"
        if counts.get("warn"):
            status += f" | [bold yellow]⚠ {counts['warn']} warn[/]"
        if counts.get("failed"):
            status += f" | [bold red]❌ {counts['failed']} failed[/]"
        if fallbacks:
            status += f" | [bold yellow]>> {len(fallbacks)} via fallback URL[/]"
        if copy_fellback:
            status += f" | [bold yellow]-> {len(copy_fellback)} copy->GET/PUT[/]"

        lines = [
            status,
            f"[bold]{total}[/] objects | [bold]{_human_bytes(total_bytes)}[/] | "
            f"[bold]{len({a['domain'] for a in arts})}[/] origins | methods: {method_str}",
        ]
        if wall_clock_sec is not None:
            par = (agg_ms / 1000 / wall_clock_sec) if wall_clock_sec else 0
            lines.append(f"⏱ Total wall-clock: [bold]{wall_clock_sec:.0f}s[/]"
                         + (f" | aggregate pull [bold]{agg_ms/1000:.0f}s[/] "
                            f"([bold]{par:.1f}×[/] parallel speedup)" if timed else ""))
        elif timed:
            lines.append(f"⏱ Aggregate pull time: [bold]{agg_ms/1000:.1f}s[/]")
        lines.append(f"[#4db8ff]s3://{mirror_bucket}/{norm_prefix}[/]"
                     + (f"  [dim](region {region})[/]" if region else ""))
        console.print(Panel("\n".join(lines),
                            title="[bold #e8eef7]📦 Resource Mirror Report[/]",
                            border_style="#00cc66", padding=(1, 3)))

        # ----- attention: fallbacks + errors -----
        if fallbacks or failed_targets or copy_fellback:
            at = Table(title="⚠ Attention", header_style="bold yellow", box=None)
            at.add_column("Artifact / target", overflow="fold", max_width=50)
            at.add_column("Issue")
            for a in fallbacks:
                at.add_row(a["name"], f"[yellow]primary URL failed -> used fallback "
                                      f"(attempt {a['attempts']})[/]")
            for a in copy_fellback:
                at.add_row(a["name"], "[yellow]server-side copy denied -> streamed "
                                      "GET->PUT (copy-restricted bucket)[/]")
            for t in failed_targets:
                at.add_row(t.rsplit("/", 1)[-1], "[red]all URLs failed (on_error=fail)[/]")
            console.print(at)
        
        if os.environ.get("EDH_DEBUG", os.environ.get("SOCA_DEBUG", "0")) == "1":
            # ----- by source -----
            by_dom = {}
            for a in arts:
                d = by_dom.setdefault(a["domain"], {"count": 0, "bytes": 0})
                d["count"] += 1
                d["bytes"] += a["size"]
            t1 = Table(title="By source origin", header_style="bold #4db8ff", box=None)
            t1.add_column("Origin", overflow="fold", max_width=42)
            t1.add_column("Files", justify="right")
            t1.add_column("Size", justify="right")
            for dom, v in sorted(by_dom.items(), key=lambda kv: kv[1]["bytes"], reverse=True):
                t1.add_row(dom, str(v["count"]), _human_bytes(v["bytes"]))
            console.print(t1)

            # ----- slowest pulls (cloud runs only) -----
            if timed:
                t2 = Table(title=f"Top {min(top_n, len(timed))} slowest pulls",
                        header_style="bold #4db8ff", box=None)
                t2.add_column("Artifact", overflow="fold", max_width=42)
                t2.add_column("Method")
                t2.add_column("Pull", justify="right")
                t2.add_column("Size", justify="right")
                for a in sorted(timed, key=lambda a: a["duration_ms"], reverse=True)[:top_n]:
                    t2.add_row(a["name"], a["method"], f"{a['duration_ms']}ms",
                            _human_bytes(a["size"]))
                console.print(t2)

            # ----- largest -----
            t3 = Table(title=f"Top {min(top_n, total)} largest", header_style="bold #4db8ff", box=None)
            t3.add_column("Artifact", overflow="fold", max_width=42)
            t3.add_column("Size", justify="right")
            t3.add_column("Origin", overflow="fold", max_width=28)
            for a in sorted(arts, key=lambda a: a["size"], reverse=True)[:top_n]:
                t3.add_row(a["name"], _human_bytes(a["size"]), a["domain"])
            console.print(t3)

    except Exception as err:
        logger.warning(f"Mirror report skipped: {err}")
        console.print(f"[dim]📦 Resource mirror report unavailable: {err}[/]")
