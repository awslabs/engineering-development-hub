# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Admin -> Cluster Status -> DCV / VDI Overview.

Surfaces operational state of the DCV high-scale plane (broker + agents
+ sessions + CloudWatch metrics) to the cluster admin without requiring
an AWS console session. Read-only.
"""

import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, render_template, request, session

from decorators import admin_only, login_required
from utils.aws.boto3_wrapper import get_boto
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


# Page-render budget. The overview fans out to several independent
# CloudWatch / EC2 / ELB describe calls. We run them concurrently (uwsgi
# runs gevent, so boto3's socket I/O cooperatively yields) and cap each so
# one slow/throttled AWS call can't push the whole page past the ALB idle
# timeout (~60s). Per-section elapsed time is logged to pinpoint slow ones.
_SECTION_BUDGET_S = 20


def _timed_section(name, fn, **kwargs):
    """Run one overview section, logging its elapsed time and degrading to
    an error dict (never raising) so one bad section can't fail the page."""
    import time as _t

    _t0 = _t.monotonic()
    try:
        _out = fn(**kwargs)
        _el = _t.monotonic() - _t0
        logger.info("dcv_overview: section '%s' completed in %.2fs", name, _el)
        if Validators.is_dict(_out):
            _out.setdefault("_elapsed_s", round(_el, 2))
        return _out
    except Exception as _err:  # noqa: BLE001 - section must degrade, not crash the page
        _el = _t.monotonic() - _t0
        logger.warning("dcv_overview: section '%s' failed after %.2fs: %s", name, _el, _err)
        return {"available": False, "error": f"{name} error: {_err}", "_elapsed_s": round(_el, 2)}


def _run_sections(sections):
    """Run overview sections concurrently under gevent with a per-page
    budget; fall back to serial if gevent is unavailable. `sections` maps
    name -> (fn, kwargs). Any section exceeding the budget returns a
    timeout marker so the page still renders within the ALB idle timeout."""
    try:
        import gevent
    except Exception:  # noqa: BLE001 - gevent absent (e.g. unit tests): run serially
        gevent = None

    if gevent is None:
        return {n: _timed_section(n, fn, **kw) for n, (fn, kw) in sections.items()}

    _jobs = {n: gevent.spawn(_timed_section, n, fn, **kw) for n, (fn, kw) in sections.items()}
    gevent.joinall(list(_jobs.values()), timeout=_SECTION_BUDGET_S)
    _out = {}
    for _n, _g in _jobs.items():
        if _g.ready():
            _out[_n] = _g.value if _g.successful() else {"available": False, "error": f"{_n} error: {_g.exception}"}
        else:
            _g.kill(block=False)
            logger.warning("dcv_overview: section '%s' exceeded %ss budget", _n, _SECTION_BUDGET_S)
            _out[_n] = {"available": False, "error": f"{_n} timed out after {_SECTION_BUDGET_S}s"}
    return _out


admin_cluster_status_dcv_overview = Blueprint(
    "admin_cluster_status_dcv_overview",
    __name__,
    template_folder="templates",
)


# CloudWatch metrics emitted by the DCV Session Manager Broker. Namespace
# is hardcoded by the broker to the literal string below; per-cluster
# separation is via the metrics-fleet-name-dimension. See:
# /etc/dcv-session-manager-broker/session-manager-broker.properties.
_BROKER_NAMESPACE = "DCV Session Manager Broker"

# Custom namespace published by the DCV screenshot poller Lambda. Used
# for screenshot-pipeline observability without the admin page needing
# to do its own bucket-listing math. Single dimension: ClusterId.
_SCREENSHOT_NAMESPACE = "EDH/DCVHighScale"

# Time-window presets surfaced in the UI. Each maps to a (minutes,
# period_seconds) pair where period is auto-chosen so that:
#   - the number of datapoints per query stays under CW's 1440 limit
#   - CW's storage-resolution retention covers the window
#     (1-min: 15d, 5-min: 63d, 1-hour: 455d)
# Order matters: rendered as a button group in the same order.
_WINDOW_PRESETS = {
    "1h":  {"minutes": 60,     "period_seconds": 60,    "label": "1 hour"},
    "6h":  {"minutes": 360,    "period_seconds": 60,    "label": "6 hours"},
    "24h": {"minutes": 1440,   "period_seconds": 300,   "label": "24 hours"},
    "7d":  {"minutes": 10080,  "period_seconds": 1800,  "label": "7 days"},
    "30d": {"minutes": 43200,  "period_seconds": 3600,  "label": "30 days"},
    "90d": {"minutes": 129600, "period_seconds": 21600, "label": "90 days"},
}
_DEFAULT_WINDOW = "1h"

# Metrics we surface in the overview. Each entry: (cw_metric_name,
# friendly_label, statistic, unit_label). Names match exactly what the
# DCV Session Manager Broker 2025.0 emits (Title Case With Spaces -- not
# camelCase). Dimensions are: Fleet Name, Broker Address, EC2 Instance
# Id. We query via CW SEARCH expressions scoped to Fleet Name so the
# panel keeps working when broker count > 1.
_METRICS = [
    ("Number Of Ready DCV Servers", "Ready DCV Servers", "Average", "count"),
    ("Number Of DCV Sessions", "Active Sessions", "Average", "count"),
    ("Number Of Console DCV Sessions", "Console Sessions", "Average", "count"),
    ("Number Of Virtual DCV Sessions", "Virtual Sessions", "Average", "count"),
    ("Heap Memory Used", "JVM Heap Used", "Average", "bytes"),
    ("Off Heap Memory Used", "JVM Off-Heap Used", "Average", "bytes"),
    ("Cpu Load", "JVM CPU Load", "Average", "ratio"),
    ("Create Sessions Request Time", "createSessions latency", "Average", "ms"),
    ("Describe Sessions Request Time", "describeSessions latency", "Average", "ms"),
    ("Get Session Connection Data Request Time", "getConnectionData latency", "Average", "ms"),
]


def _is_high_scale_enabled() -> bool:
    return (
        str(
            SocaConfig(key="/dcv/high_scale_enabled")
            .get_value()
            .get("message", "false")
        )
        .lower()
        == "true"
    )


def _broker_snapshot() -> Dict[str, Any]:
    """
    Pull the current broker state via DcvBrokerClient. Returns a dict
    with aggregated counts plus the raw server/session lists for table
    rendering.
    """
    snapshot: Dict[str, Any] = {
        "available": False,
        "error": None,
        "servers": [],
        "sessions": [],
        "totals": {
            "servers": 0,
            "servers_available": 0,
            "servers_unavailable": 0,
            "sessions": 0,
            "sessions_ready": 0,
            "sessions_creating": 0,
            "sessions_other": 0,
        },
        "by_os_family": {},
        "by_unavailability_reason": {},
        "by_session_type": {},
        "by_session_state": {},
    }
    try:
        from utils.dcv_broker_client import DcvBrokerClient

        broker = DcvBrokerClient()
    except Exception as err:
        snapshot["error"] = f"DcvBrokerClient init failed: {err}"
        return snapshot

    # Bounded timeout: this is a SYNCHRONOUS admin page render. A degrading or
    # mid-cycle broker fleet must not stall the page past the ALB idle timeout
    # (~60s) -- fast-fail (5s, 1 try) so the broker panel shows an error while
    # the rest of the page (incl. the ASG sizing control) still renders.
    servers_resp = broker.describe_servers(timeout=5.0, retries=1)
    if not servers_resp.success:
        snapshot["error"] = f"describeServers failed: {servers_resp.message}"
        return snapshot
    sessions_resp = broker.describe_sessions(timeout=5.0, retries=1)
    if not sessions_resp.success:
        snapshot["error"] = f"describeSessions failed: {sessions_resp.message}"
        return snapshot

    servers = (servers_resp.message or {}).get("Servers", []) or []
    sessions = (sessions_resp.message or {}).get("Sessions", []) or []

    by_os = Counter()
    by_reason = Counter()
    avail = 0
    for s in servers:
        host = (s.get("Host") or {})
        os_fam = ((host.get("Os") or {}).get("Family") or "unknown").lower()
        by_os[os_fam] += 1
        if s.get("Availability") == "AVAILABLE":
            avail += 1
        elif s.get("Availability") == "UNAVAILABLE":
            reason = s.get("UnavailabilityReason") or "UNKNOWN"
            by_reason[reason] += 1

    by_state = Counter()
    by_type = Counter()
    sessions_ready = 0
    sessions_creating = 0
    sessions_other = 0
    for sess in sessions:
        state = (sess.get("State") or "UNKNOWN").upper()
        stype = (sess.get("Type") or "UNKNOWN").upper()
        by_state[state] += 1
        by_type[stype] += 1
        if state == "READY":
            sessions_ready += 1
        elif state == "CREATING":
            sessions_creating += 1
        else:
            sessions_other += 1

    # Enrich each broker server record with the SOCA-side `instance_base_os`
    # (e.g. "windows2025", "windows2022", "amazonlinux2023") which is the
    # field we set at create-time. The broker reports Host.Os.Name from a
    # Windows registry call, which conflates Win 11 24H2 with Server 2025
    # (both NT build 10.0.26100). Our DB has the unambiguous label.
    try:
        from models import VirtualDesktopSessions

        _instance_to_os = {}
        # Single sweep -- we have at most a few dozen sessions in the DB.
        for _row in VirtualDesktopSessions.query.filter(
            VirtualDesktopSessions.is_active == True  # noqa: E712
        ).all():
            if _row.instance_id and _row.instance_base_os:
                _instance_to_os[_row.instance_id] = _row.instance_base_os
        for s in servers:
            _ec2 = ((s.get("Host") or {}).get("Aws") or {}).get("EC2InstanceId")
            if _ec2 and _ec2 in _instance_to_os:
                s["SocaInstanceBaseOs"] = _instance_to_os[_ec2]
    except Exception as err:
        logger.warning(
            f"DCV overview: failed to enrich servers with instance_base_os: {err}"
        )

    snapshot.update(
        {
            "available": True,
            "servers": servers,
            "sessions": sessions,
            "totals": {
                "servers": len(servers),
                "servers_available": avail,
                "servers_unavailable": len(servers) - avail,
                "sessions": len(sessions),
                "sessions_ready": sessions_ready,
                "sessions_creating": sessions_creating,
                "sessions_other": sessions_other,
            },
            "by_os_family": dict(by_os),
            "by_unavailability_reason": dict(by_reason),
            "by_session_type": dict(by_type),
            "by_session_state": dict(by_state),
        }
    )
    return snapshot


def _cluster_id() -> Optional[str]:
    return SocaConfig(key="/configuration/ClusterId").get_value().get("message")


def _cloudwatch_series(window_minutes: int = 60, period_seconds: int = 60) -> Dict[str, Any]:
    """
    Pull the last `window_minutes` of CloudWatch data for the broker
    metrics defined in `_METRICS`. Uses get_metric_data with one query
    per metric for clarity (~7 queries; well under the 500/req limit).
    Returns a dict suitable for direct JSON injection into the template.
    """
    out: Dict[str, Any] = {
        "available": False,
        "error": None,
        "window_minutes": window_minutes,
        "period_seconds": period_seconds,
        "series": [],
    }
    cluster_id = _cluster_id()
    if not cluster_id:
        out["error"] = "ClusterId not available"
        return out

    try:
        cw_resp = get_boto(service_name="cloudwatch")
        cw = getattr(cw_resp, "message", None)
        if cw is None:
            out["error"] = f"boto3 cloudwatch client unavailable: {getattr(cw_resp, 'message', cw_resp)}"
            return out
    except Exception as err:
        out["error"] = f"boto3 cloudwatch init failed: {err}"
        return out

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=window_minutes)

    # Use CW SEARCH expressions so we automatically aggregate across
    # all brokers in the fleet. Required because the broker publishes
    # with full dimension set (Fleet Name + Broker Address + EC2
    # Instance Id) and CW's GetMetricData requires either an exact
    # dimension match or a SEARCH wrapper. AVG dedupes the case where
    # multiple brokers report the same DDB-shared gauge value; SUM
    # totals counters across the fleet. Metric names with spaces and
    # the namespace itself are quoted in the search string.
    # Two queries per metric:
    #   q{idx}_per  - raw SEARCH, ReturnData=True. CW returns one
    #                 MetricDataResult per matching broker, all sharing
    #                 this Id but with distinct Label fields populated
    #                 from the dimension values. We reshape these into
    #                 a `members` list keyed by EC2 instance id.
    #   q{idx}_min/_max/_agg - math expressions over the SEARCH for the
    #                 aggregate band. q{idx}_agg is what the headline
    #                 number reads from.
    queries = []
    search_by_idx = {}
    for idx, (metric_name, _label, stat, _unit) in enumerate(_METRICS):
        raw_search = (
            f'SEARCH(\'{{"{_BROKER_NAMESPACE}","Fleet Name","Broker Address","EC2 Instance Id"}} '
            f'MetricName="{metric_name}" "Fleet Name"="{cluster_id}"\', '
            f'\'{stat}\', {period_seconds})'
        )
        search_by_idx[idx] = raw_search
        agg = "AVG" if stat == "Average" else "SUM"
        per_id = f"q{idx}_per"
        queries.append({"Id": per_id, "Expression": raw_search, "ReturnData": True})
        queries.append({"Id": f"q{idx}_agg", "Expression": f"{agg}({per_id})", "ReturnData": True})
        queries.append({"Id": f"q{idx}_min", "Expression": f"MIN({per_id})", "ReturnData": True})
        queries.append({"Id": f"q{idx}_max", "Expression": f"MAX({per_id})", "ReturnData": True})

    try:
        resp = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )
    except Exception as err:
        out["error"] = f"cloudwatch.get_metric_data raised: {err}"
        return out

    # Group results by Id. SEARCH expressions return one MDR per match
    # all sharing the same Id; math expressions return exactly one MDR.
    by_id_list: Dict[str, List[Dict[str, Any]]] = {}
    for r in resp.get("MetricDataResults", []):
        by_id_list.setdefault(r.get("Id"), []).append(r)

    def _xy(r):
        return (
            [t.isoformat() for t in (r.get("Timestamps") or [])],
            list(r.get("Values") or []),
        )

    def _broker_id_from_label(lbl: str) -> str:
        """
        CW labels SEARCH results as "<MetricName> <dim1> <dim2> ..."
        space-joined with the dimension values in the order specified
        in the SEARCH. We always ask for "EC2 Instance Id" last, so the
        trailing token is the instance id when present. Fall back to
        the full label if parsing fails so we never lose a series.
        """
        if not lbl:
            return "unknown"
        parts = lbl.strip().split()
        for p in reversed(parts):
            if p.startswith("i-") and len(p) >= 10:
                return p
        return parts[-1] if parts else "unknown"

    series = []
    for idx, (metric_name, label, stat, unit) in enumerate(_METRICS):
        per_results = by_id_list.get(f"q{idx}_per", []) or []
        agg_results = by_id_list.get(f"q{idx}_agg", []) or []
        min_results = by_id_list.get(f"q{idx}_min", []) or []
        max_results = by_id_list.get(f"q{idx}_max", []) or []

        members = []
        for r in per_results:
            ts, vs = _xy(r)
            if not vs:
                # Skip empty series so members count == active brokers
                continue
            members.append(
                {
                    "id": _broker_id_from_label(r.get("Label", "")),
                    "label": r.get("Label", ""),
                    "timestamps": ts,
                    "values": vs,
                    "latest": vs[-1],
                }
            )

        agg_ts, agg_vs = _xy(agg_results[0]) if agg_results else ([], [])
        min_ts, min_vs = _xy(min_results[0]) if min_results else ([], [])
        max_ts, max_vs = _xy(max_results[0]) if max_results else ([], [])
        latest = agg_vs[-1] if agg_vs else None
        latest_min = min_vs[-1] if min_vs else None
        latest_max = max_vs[-1] if max_vs else None

        # Spread = (max-min)/avg when avg > 0. None when no data or
        # avg=0. Used as a proxy for "are the brokers diverging?". The
        # client renders this in the card subtitle.
        spread = None
        if latest is not None and latest_min is not None and latest_max is not None:
            try:
                if float(latest) > 0:
                    spread = (float(latest_max) - float(latest_min)) / float(latest)
            except (TypeError, ValueError, ZeroDivisionError):
                spread = None

        series.append(
            {
                "metric": metric_name,
                "label": label,
                "stat": stat,
                "unit": unit,
                "members_count": len(members),
                "members": members,
                "aggregate": {
                    "stat": "AVG" if stat == "Average" else "SUM",
                    "timestamps": agg_ts,
                    "values": agg_vs,
                    "latest": latest,
                },
                "min_band": {"timestamps": min_ts, "values": min_vs, "latest": latest_min},
                "max_band": {"timestamps": max_ts, "values": max_vs, "latest": latest_max},
                # Backward-compat fields (existing JS uses these keys).
                "timestamps": agg_ts,
                "values": agg_vs,
                "latest": latest,
                "latest_human": _format_metric_latest(latest, unit),
                "latest_min_human": _format_metric_latest(latest_min, unit),
                "latest_max_human": _format_metric_latest(latest_max, unit),
                "spread": spread,
                "spread_human": (f"{spread * 100:.0f}%" if spread is not None else None),
            }
        )
    out.update({"available": True, "series": series})
    return out



def _humanize_bytes(num):
    """Convert a byte count to a 1-decimal SI-suffixed string."""
    if num is None:
        return None
    n = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _format_metric_latest(value, unit):
    """
    Render the latest CW datapoint into a human-friendly string keyed by
    the metric's unit tag in `_METRICS`. Returns None when value is None
    so the template can fall back to its own placeholder.

    Unit conventions:
      bytes -> B/KB/MB/GB/TB (1 decimal, IEC powers of 1024)
      ratio -> 0-1 fraction rendered as percent (1 decimal)
      ms    -> sub-1ms keeps 2 decimals, else integer milliseconds
      count -> integer
      <other> -> 2 decimals if |v|<1 else integer (sane fallback)
    """
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    if unit == "bytes":
        return _humanize_bytes(v)
    if unit == "ratio":
        return f"{v * 100:.1f}%"
    if unit == "ms":
        return f"{v:.2f} ms" if abs(v) < 1 else f"{v:.0f} ms"
    if unit == "count":
        return f"{v:.0f}"
    return f"{v:.2f}" if abs(v) < 1 else f"{v:.0f}"


def _screenshot_snapshot(window_minutes: int = 60, period_seconds: int = 60) -> Dict[str, Any]:
    """
    Pull screenshot poller metrics from the EDH/DCVHighScale namespace.
    Returns a snapshot suitable for direct render in the admin page.
    Fields:
        latest -> {"objects": int, "bytes": int, "max_age_s": int,
                    "captured": int, "skipped": int, "blank": int,
                    "active_sessions": int, "duration_ms": int,
                    "broker_errors": int}
        bytes_human, max_age_human -> friendly strings
        capture_series -> [(iso_ts, value)] last 60 min for a sparkline
    """
    out: Dict[str, Any] = {
        "available": False,
        "error": None,
        "latest": {},
        "bytes_human": None,
        "max_age_human": None,
        "capture_series": [],
        "window_minutes": window_minutes,
    }
    cluster_id = _cluster_id()
    if not cluster_id:
        out["error"] = "ClusterId not available"
        return out

    try:
        cw = getattr(get_boto(service_name="cloudwatch"), "message", None)
        if cw is None:
            out["error"] = "boto3 cloudwatch client unavailable"
            return out
    except Exception as err:
        out["error"] = f"boto3 cloudwatch init failed: {err}"
        return out

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=window_minutes)
    dims = [{"Name": "ClusterId", "Value": cluster_id}]

    # (metric_name, stat). Most metrics are gauges (last value matters);
    # captured/skipped/blank/broker-errors are counters per cycle which
    # we sum over the window for the headline number and graph.
    metric_specs = [
        ("ScreenshotsBucketObjects", "Maximum"),
        ("ScreenshotsBucketBytes", "Maximum"),
        ("ScreenshotsMaxAgeSeconds", "Maximum"),
        ("ScreenshotsActiveSessions", "Maximum"),
        ("ScreenshotsCaptured", "Sum"),
        ("ScreenshotsSkipped", "Sum"),
        ("ScreenshotsSuppressedBlank", "Sum"),
        ("ScreenshotPollerDuration", "Average"),
        ("ScreenshotsBrokerErrors", "Sum"),
    ]
    queries = []
    for idx, (m, stat) in enumerate(metric_specs):
        queries.append({
            "Id": f"q{idx}",
            "Label": f"{m}|{stat}",
            "MetricStat": {
                "Metric": {
                    "Namespace": _SCREENSHOT_NAMESPACE,
                    "MetricName": m,
                    "Dimensions": dims,
                },
                "Period": period_seconds,
                "Stat": stat,
            },
            "ReturnData": True,
        })
    try:
        resp = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )
    except Exception as err:
        out["error"] = f"cloudwatch.get_metric_data raised: {err}"
        return out

    by_label = {}
    for r in resp.get("MetricDataResults", []):
        by_label[r.get("Label", "")] = r

    def _last(label):
        r = by_label.get(label, {})
        vals = list(r.get("Values") or [])
        return vals[-1] if vals else None

    def _sum(label):
        r = by_label.get(label, {})
        vals = list(r.get("Values") or [])
        return sum(vals) if vals else 0

    latest = {
        "objects": int(_last("ScreenshotsBucketObjects|Maximum") or 0),
        "bytes": int(_last("ScreenshotsBucketBytes|Maximum") or 0),
        "max_age_s": int(_last("ScreenshotsMaxAgeSeconds|Maximum") or 0),
        "active_sessions": int(_last("ScreenshotsActiveSessions|Maximum") or 0),
        "captured_60m": int(_sum("ScreenshotsCaptured|Sum")),
        "skipped_60m": int(_sum("ScreenshotsSkipped|Sum")),
        "blank_60m": int(_sum("ScreenshotsSuppressedBlank|Sum")),
        "duration_ms": int(_last("ScreenshotPollerDuration|Average") or 0),
        "broker_errors_60m": int(_sum("ScreenshotsBrokerErrors|Sum")),
    }
    out["latest"] = latest
    out["bytes_human"] = _humanize_bytes(latest["bytes"])
    out["max_age_human"] = _humanize_duration(latest["max_age_s"])
    # Per-spec time series, ready for client-side Chart.js rendering.
    # Each is a list of (iso_timestamp, value) pairs covering the window.
    def _series(label):
        r = by_label.get(label, {})
        ts = [t.isoformat() for t in (r.get("Timestamps") or [])]
        vs = list(r.get("Values") or [])
        return list(zip(ts, vs))

    out["capture_series"] = _series("ScreenshotsCaptured|Sum")
    out["skipped_series"] = _series("ScreenshotsSkipped|Sum")
    out["blank_series"] = _series("ScreenshotsSuppressedBlank|Sum")
    out["duration_series"] = _series("ScreenshotPollerDuration|Average")
    out["available"] = True
    return out


def _streaming_snapshot(window_minutes: int = 60, period_seconds: int = 60) -> Dict[str, Any]:
    """
    Pull DCV streaming quality metrics from the EDH/DCVStreaming
    namespace. The custom collector on each VDI host publishes:
      - DegradedSessions  (Count) — sessions with frame_loss>5% or latency>100ms
      - ActiveSessions    (Count) — count of active sessions
      - FrameLossRate     (None)  — per-session, dimensioned by SessionOwner
      - NetworkLatencyMs  (Milliseconds)
      - BandwidthInBps    (Bytes/Second)
      - BandwidthOutBps   (Bytes/Second)
      - FrameQuality      (None)
    Snapshot returns headline (degraded ratio + active count) + last-hour
    series for the dashboard's Streaming Health card. We only query the
    {ClusterId}-only dimension here so the call is cheap; per-session
    drill-down lives elsewhere.
    """
    out: Dict[str, Any] = {
        "available": False,
        "error": None,
        "latest": {
            "active_sessions": 0,
            "degraded_sessions": 0,
            "degraded_ratio": 0.0,
            "p95_latency_ms": None,
            "p95_frame_loss": None,
        },
        "active_series": [],
        "degraded_series": [],
        "latency_p95_series": [],
        "frame_loss_p95_series": [],
        "window_minutes": window_minutes,
    }
    cluster_id = _cluster_id()
    if not cluster_id:
        out["error"] = "ClusterId not available"
        return out

    try:
        cw = getattr(get_boto(service_name="cloudwatch"), "message", None)
        if cw is None:
            out["error"] = "boto3 cloudwatch client unavailable"
            return out
    except Exception as err:
        out["error"] = f"boto3 cloudwatch init failed: {err}"
        return out

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=window_minutes)
    cluster_only_dims = [{"Name": "ClusterId", "Value": cluster_id}]

    queries = [
        {
            "Id": "active",
            "Label": "ActiveSessions",
            "MetricStat": {
                "Metric": {
                    "Namespace": "EDH/DCVStreaming",
                    "MetricName": "ActiveSessions",
                    "Dimensions": cluster_only_dims,
                },
                "Period": period_seconds,
                "Stat": "Maximum",
            },
            "ReturnData": True,
        },
        {
            "Id": "degraded",
            "Label": "DegradedSessions",
            "MetricStat": {
                "Metric": {
                    "Namespace": "EDH/DCVStreaming",
                    "MetricName": "DegradedSessions",
                    "Dimensions": cluster_only_dims,
                },
                "Period": period_seconds,
                "Stat": "Maximum",
            },
            "ReturnData": True,
        },
        # Per-session metrics — use a SEARCH for any-dim across the
        # cluster, then p95 across all reporters. Keeps the query
        # simple and scales with session count without us listing
        # owners up front.
        {
            "Id": "lat_p95",
            "Label": "NetworkLatencyMs|p95",
            "Expression": (
                f'SEARCH(\'{{"EDH/DCVStreaming","ClusterId","InstanceId","SessionOwner"}} '
                f'MetricName="NetworkLatencyMs" "ClusterId"="{cluster_id}"\', '
                f'\'p95\', {period_seconds})'
            ),
            "ReturnData": False,
        },
        {
            "Id": "lat_p95_max",
            "Label": "NetworkLatencyMs|p95_max",
            "Expression": "MAX(lat_p95)",
            "ReturnData": True,
        },
        {
            "Id": "fl_p95",
            "Label": "FrameLossRate|p95",
            "Expression": (
                f'SEARCH(\'{{"EDH/DCVStreaming","ClusterId","InstanceId","SessionOwner"}} '
                f'MetricName="FrameLossRate" "ClusterId"="{cluster_id}"\', '
                f'\'p95\', {period_seconds})'
            ),
            "ReturnData": False,
        },
        {
            "Id": "fl_p95_max",
            "Label": "FrameLossRate|p95_max",
            "Expression": "MAX(fl_p95)",
            "ReturnData": True,
        },
    ]

    # Transport breakdown — one query per canonical transport. Each
    # query is filtered to {ClusterId, Transport=X}, so we get a
    # separate series per transport that the UI can stack/bar.
    canonical_transports = ("websocket", "quic", "http", "dvtc")
    for t in canonical_transports:
        queries.append({
            "Id": f"conn_{t}",
            "Label": f"ActiveConnections|{t}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "EDH/DCVStreaming",
                    "MetricName": "ActiveConnections",
                    "Dimensions": [
                        {"Name": "ClusterId", "Value": cluster_id},
                        {"Name": "Transport", "Value": t},
                    ],
                },
                "Period": period_seconds,
                "Stat": "Maximum",
            },
            "ReturnData": True,
        })

    # Sleeping sessions — sessions with 0 active client connections
    queries.append({
        "Id": "sleeping",
        "Label": "SleepingSessions",
        "MetricStat": {
            "Metric": {
                "Namespace": "EDH/DCVStreaming",
                "MetricName": "SleepingSessions",
                "Dimensions": cluster_only_dims,
            },
            "Period": period_seconds,
            "Stat": "Maximum",
        },
        "ReturnData": True,
    })

    try:
        resp = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )
    except Exception as err:
        out["error"] = f"cloudwatch.get_metric_data raised: {err}"
        return out

    by_id = {r["Id"]: r for r in resp.get("MetricDataResults", [])}

    def _xy(rid):
        r = by_id.get(rid, {})
        return (
            [t.isoformat() for t in (r.get("Timestamps") or [])],
            list(r.get("Values") or []),
        )

    a_ts, a_vs = _xy("active")
    d_ts, d_vs = _xy("degraded")
    lp_ts, lp_vs = _xy("lat_p95_max")
    fp_ts, fp_vs = _xy("fl_p95_max")
    sl_ts, sl_vs = _xy("sleeping")

    # Transport breakdown — current latest + last-hour series per transport
    transport_latest = {}
    transport_series = {}
    for t in canonical_transports:
        ts, vs = _xy(f"conn_{t}")
        transport_latest[t] = int(vs[-1]) if vs else 0
        transport_series[t] = list(zip(ts, vs))

    active_now = int(a_vs[-1]) if a_vs else 0
    degraded_now = int(d_vs[-1]) if d_vs else 0
    sleeping_now = int(sl_vs[-1]) if sl_vs else 0
    ratio = (degraded_now / active_now) if active_now > 0 else 0.0
    p95_lat = lp_vs[-1] if lp_vs else None
    p95_fl = fp_vs[-1] if fp_vs else None

    out.update({
        "available": True,
        "latest": {
            "active_sessions": active_now,
            "degraded_sessions": degraded_now,
            "sleeping_sessions": sleeping_now,
            "degraded_ratio": ratio,
            "degraded_ratio_human": f"{ratio * 100:.1f}%",
            "p95_latency_ms": p95_lat,
            "p95_latency_ms_human": (f"{p95_lat:.0f} ms" if p95_lat is not None else None),
            "p95_frame_loss": p95_fl,
            "p95_frame_loss_human": (f"{p95_fl * 100:.1f}%" if p95_fl is not None else None),
            "transport": transport_latest,            # {websocket: 1, quic: 1, http: 0, dvtc: 0}
            "transport_total": sum(transport_latest.values()),
        },
        "active_series": list(zip(a_ts, a_vs)),
        "degraded_series": list(zip(d_ts, d_vs)),
        "sleeping_series": list(zip(sl_ts, sl_vs)),
        "transport_series": transport_series,
        "latency_p95_series": list(zip(lp_ts, lp_vs)),
        "frame_loss_p95_series": list(zip(fp_ts, fp_vs)),
    })
    return out


def _humanize_duration(seconds):
    if seconds is None:
        return "?"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


def _per_instance_health(instance_ids, window_minutes=60, period_seconds=300):
    """
    Pull per-instance health metrics for a list of EC2 instance ids.
    Returns a dict keyed by instance_id with:
      {
        "cpu_pct":  float|None,    # Latest CPUUtilization (EC2 namespace)
        "mem_pct":  float|None,    # Latest mem_used_percent (CWAgent EDH/DCVHighScale)
        "swap_pct": float|None,    # Latest swap_used_percent
        "disk_pct": float|None,    # Latest disk used_percent
        "net_in":   float|None,    # Bytes/s recent
        "net_out":  float|None,
        "cpu_series":  [(iso, val), ...] last hour for sparkline
        "mem_series":  [(iso, val), ...]
        "net_series":  [(iso, val), ...]   # net_in + net_out summed
        "status":      "ok" | "warn" | "danger" | "unknown"
        "status_reason": short string explaining the status
      }
    Cheap: one GetMetricData call per metric per instance, batched.
    Returns {} on any error so the caller falls through gracefully.
    """
    out: Dict[str, Any] = {}
    if not instance_ids:
        return out
    try:
        cw = getattr(get_boto(service_name="cloudwatch"), "message", None)
        if cw is None:
            return out
    except Exception:
        return out

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=window_minutes)
    cluster_id = _cluster_id() or ""

    # Build one big query batch covering all instances * all metrics.
    # Id format: i{idx}_{key} keeps Ids unique and short. Total queries
    # = N_instances * 6 metrics; 8 brokers + 4 gateways + 1 dcv = 13
    # instances → 78 queries, well under the 500/req cap.
    queries = []
    id_to_iid = {}
    for idx, iid in enumerate(instance_ids):
        if not iid:
            continue
        # CPUUtilization comes from the AWS/EC2 namespace by default
        queries.append({
            "Id": f"i{idx}_cpu",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                },
                "Period": period_seconds,
                "Stat": "Average",
            },
            "ReturnData": True,
        })
        # CWAgent memory — EDH/DCVHighScale namespace. The agent
        # publishes these with ONLY {InstanceId} (the literal-string
        # ClusterId in `append_dimensions` is silently dropped by CW
        # Agent — only the built-in ${aws:...} placeholders land as
        # real dimensions). Query with InstanceId alone to match.
        for key, metric_name in (
            ("mem",  "mem_used_percent"),
            ("swap", "swap_used_percent"),
        ):
            queries.append({
                "Id": f"i{idx}_{key}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "EDH/DCVHighScale",
                        "MetricName": metric_name,
                        "Dimensions": [
                            {"Name": "InstanceId", "Value": iid},
                        ],
                    },
                    "Period": period_seconds,
                    "Stat": "Maximum",
                },
                "ReturnData": True,
            })
        # disk_used_percent has additional dims (path, device, fstype)
        # which vary per host (xvda1 / nvme0n1p1 / sda2 etc). Use a
        # SEARCH expression scoped to the root filesystem (path="/")
        # and MAX across whatever device+fstype the host has.
        queries.append({
            "Id": f"i{idx}_disk_search",
            "Expression": (
                f'SEARCH(\'{{"EDH/DCVHighScale","InstanceId","device","fstype","path"}} '
                f'MetricName="disk_used_percent" "InstanceId"="{iid}" "path"="/"\', '
                f'\'Maximum\', {period_seconds})'
            ),
            "ReturnData": False,
        })
        queries.append({
            "Id": f"i{idx}_disk",
            "Expression": f"MAX(i{idx}_disk_search)",
            "ReturnData": True,
        })
        for key, metric_name in (
            ("netin",  "NetworkIn"),
            ("netout", "NetworkOut"),
        ):
            queries.append({
                "Id": f"i{idx}_{key}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EC2",
                        "MetricName": metric_name,
                        "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                    },
                    "Period": period_seconds,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            })
        id_to_iid[idx] = iid

    if not queries:
        return out

    try:
        resp = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )
    except Exception as err:
        logger.warning(f"_per_instance_health: get_metric_data failed: {err}")
        return out

    by_id = {r.get("Id"): r for r in resp.get("MetricDataResults", [])}

    def _series(rid):
        r = by_id.get(rid, {})
        ts = [t.isoformat() for t in (r.get("Timestamps") or [])]
        vs = list(r.get("Values") or [])
        return list(zip(ts, vs))

    def _last(rid):
        r = by_id.get(rid, {})
        vs = list(r.get("Values") or [])
        return vs[-1] if vs else None

    # NetworkIn/Out are reported as Sum of Bytes per period_seconds. We
    # convert to Bytes/sec and combined for the sparkline.
    def _bps_series(idx):
        rin  = by_id.get(f"i{idx}_netin",  {})
        rout = by_id.get(f"i{idx}_netout", {})
        ts = [t.isoformat() for t in (rin.get("Timestamps") or [])]
        v_in  = list(rin.get("Values")  or [])
        v_out = list(rout.get("Values") or [])
        # Pad to the shorter, then sum and normalize to bytes/sec
        n = min(len(v_in), len(v_out))
        return [(ts[i], (v_in[i] + v_out[i]) / max(period_seconds, 1)) for i in range(n)]

    for idx, iid in id_to_iid.items():
        cpu  = _last(f"i{idx}_cpu")
        mem  = _last(f"i{idx}_mem")
        swap = _last(f"i{idx}_swap")
        disk = _last(f"i{idx}_disk")
        netin  = _last(f"i{idx}_netin")
        netout = _last(f"i{idx}_netout")
        net_in_bps  = (netin  / period_seconds) if netin  is not None else None
        net_out_bps = (netout / period_seconds) if netout is not None else None

        # Status classification: red wins, then yellow, then green.
        # Thresholds match the existing fleet alarms (mem 85%, swap >0,
        # disk 80%) and add a CPU-saturated band.
        status = "ok"
        reason = "all metrics nominal"
        if (mem is not None and mem > 85) or (swap is not None and swap > 0) or (disk is not None and disk > 80) or (cpu is not None and cpu > 90):
            status = "danger"
            parts = []
            if mem is not None and mem > 85:   parts.append(f"mem {mem:.0f}%")
            if swap is not None and swap > 0:  parts.append(f"swap {swap:.0f}%")
            if disk is not None and disk > 80: parts.append(f"disk {disk:.0f}%")
            if cpu is not None and cpu > 90:   parts.append(f"cpu {cpu:.0f}%")
            reason = ", ".join(parts) or "threshold breach"
        elif (mem is not None and mem > 70) or (cpu is not None and cpu > 75) or (disk is not None and disk > 70):
            status = "warn"
            parts = []
            if mem is not None and mem > 70:  parts.append(f"mem {mem:.0f}%")
            if cpu is not None and cpu > 75:  parts.append(f"cpu {cpu:.0f}%")
            if disk is not None and disk > 70: parts.append(f"disk {disk:.0f}%")
            reason = ", ".join(parts) or "elevated"
        elif cpu is None and mem is None:
            status = "unknown"
            reason = "no CW data yet"

        out[iid] = {
            "cpu_pct":  cpu,
            "mem_pct":  mem,
            "swap_pct": swap,
            "disk_pct": disk,
            "net_in_bps":  net_in_bps,
            "net_out_bps": net_out_bps,
            "cpu_series":  _series(f"i{idx}_cpu"),
            "mem_series":  _series(f"i{idx}_mem"),
            "net_series":  _bps_series(idx),
            "status":      status,
            "status_reason": reason,
        }
    return out


def _ec2_per_instance_metrics(instance_ids, cw_client, window_minutes=60, period_seconds=300):
    """Pull CPUUtilization, NetworkIn, NetworkOut for a list of instance ids."""
    if not instance_ids:
        return {}
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=window_minutes)
    # Short, COLLISION-FREE Id codes per metric. The 3-char-prefix
    # shortcut would map both NetworkIn and NetworkOut to "net" causing
    # CloudWatch to reject the whole request with InvalidParameterValue
    # ("Identifier 'i0_net' is already used"). Use unambiguous codes
    # instead. Ids must be unique within a single GetMetricData call.
    metric_codes = {
        "CPUUtilization": "cpu",
        "NetworkIn": "nin",
        "NetworkOut": "nout",
    }
    queries = []
    for idx, iid in enumerate(instance_ids):
        for mname, code in metric_codes.items():
            queries.append(
                {
                    "Id": f"i{idx}_{code}",
                    "Label": f"{iid}|{mname}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/EC2",
                            "MetricName": mname,
                            "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                        },
                        "Period": period_seconds,
                        "Stat": "Average" if mname == "CPUUtilization" else "Sum",
                    },
                    "ReturnData": True,
                }
            )
    out = {iid: {} for iid in instance_ids}
    for chunk_start in range(0, len(queries), 500):
        chunk = queries[chunk_start:chunk_start + 500]
        try:
            resp = cw_client.get_metric_data(
                MetricDataQueries=chunk,
                StartTime=start,
                EndTime=end,
                ScanBy="TimestampDescending",
            )
        except Exception as err:
            logger.warning(f"EC2 metric chunk failed: {err}")
            continue
        for r in resp.get("MetricDataResults", []):
            label = r.get("Label", "")
            if "|" not in label:
                continue
            iid, mname = label.split("|", 1)
            values = list(r.get("Values") or [])
            out.setdefault(iid, {})[mname] = values
    return out


def _infrastructure_snapshot(window_minutes: int = 60, period_seconds: int = 60):
    """
    Assemble the Infrastructure tab data: broker + gateway ASG members,
    per-instance EC2 metrics, NLB / target group health, cluster Lambdas
    + their last-N-minute CW metrics.
    """
    snapshot = {
        "available": False,
        "error": None,
        "broker": {"asg_name": None, "desired": 0, "min": 0, "max": 0, "in_service": 0, "instances": []},
        "gateway": {"asg_name": None, "desired": 0, "min": 0, "max": 0, "in_service": 0, "instances": []},
        "load_balancers": [],
        "lambdas": [],
    }
    cluster_id = _cluster_id()
    if not cluster_id:
        snapshot["error"] = "ClusterId not available"
        return snapshot

    try:
        ec2 = getattr(get_boto(service_name="ec2"), "message", None)
        asg = getattr(get_boto(service_name="autoscaling"), "message", None)
        elb = getattr(get_boto(service_name="elbv2"), "message", None)
        lam = getattr(get_boto(service_name="lambda"), "message", None)
        cw = getattr(get_boto(service_name="cloudwatch"), "message", None)
        if not all([ec2, asg, elb, lam, cw]):
            snapshot["error"] = "boto3 client init failed for one of: ec2/asg/elbv2/lambda/cloudwatch"
            return snapshot
    except Exception as err:
        snapshot["error"] = f"boto3 init: {err}"
        return snapshot

    # ---- ASG fleets (broker + gateway). Discover by tag edh:NodeType,
    # falling back to ASG name pattern for clusters whose CDK template
    # didn't tag the ASG (live cluster pre-tagging-fix). The CDK fix
    # adds edh:NodeType=dcv_broker / dcv_gateway tags going forward. ----
    fleet_node_types = {"broker": "dcv_broker", "gateway": "dcv_gateway"}
    fleet_name_patterns = {"broker": "DCVbrokerASG", "gateway": "DCVgatewayASG"}
    discovered_instance_ids = []
    # Fetch all ASGs in the account once; per-fleet match is cheap.
    try:
        all_asgs = []
        paginator = asg.get_paginator("describe_auto_scaling_groups")
        for page in paginator.paginate():
            all_asgs.extend(page.get("AutoScalingGroups", []))
    except Exception as err:
        snapshot["error"] = f"describe_auto_scaling_groups failed: {err}"
        return snapshot

    for fleet, node_type in fleet_node_types.items():
        try:
            matched = []
            name_pattern = fleet_name_patterns[fleet]
            for group in all_asgs:
                tags = {t["Key"]: t["Value"] for t in group.get("Tags", [])}
                # Primary: tag-based match (works post-CDK-fix).
                if (
                    tags.get("edh:ClusterId") == cluster_id
                    and tags.get("edh:NodeType") == node_type
                ):
                    matched.append(group)
                    continue
                # Fallback: name-pattern match for clusters predating the
                # CDK tag fix. CFN-generated names look like
                # "<cluster>-DCVbrokerASG<hash>-<suffix>".
                if (
                    tags.get("edh:ClusterId") == cluster_id
                    and name_pattern in (group.get("AutoScalingGroupName") or "")
                ):
                    matched.append(group)
            if not matched:
                continue
            group = matched[0]
            snapshot[fleet]["asg_name"] = group["AutoScalingGroupName"]
            snapshot[fleet]["desired"] = group.get("DesiredCapacity", 0)
            snapshot[fleet]["min"] = group.get("MinSize", 0)
            snapshot[fleet]["max"] = group.get("MaxSize", 0)
            instance_ids = [i["InstanceId"] for i in group.get("Instances", [])]
            in_service = sum(
                1 for i in group.get("Instances", []) if i.get("LifecycleState") == "InService"
            )
            snapshot[fleet]["in_service"] = in_service
            discovered_instance_ids.extend(instance_ids)
            if instance_ids:
                desc = ec2.describe_instances(InstanceIds=instance_ids)
                instance_records = []
                for r in desc.get("Reservations", []):
                    for inst in r.get("Instances", []):
                        launch = inst.get("LaunchTime")
                        uptime_secs = (
                            int((datetime.now(timezone.utc) - launch).total_seconds())
                            if launch
                            else None
                        )
                        instance_records.append({
                            "instance_id": inst.get("InstanceId"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "az": (inst.get("Placement") or {}).get("AvailabilityZone"),
                            "instance_type": inst.get("InstanceType"),
                            "state": (inst.get("State") or {}).get("Name"),
                            "uptime": _humanize_duration(uptime_secs),
                            "launch_time": launch.isoformat() if launch else None,
                            "cpu_latest": None,
                            "network_in_5m": None,
                            "network_out_5m": None,
                            "network_in_5m_human": None,
                            "network_out_5m_human": None,
                        })
                snapshot[fleet]["instances"] = instance_records
        except Exception as err:
            logger.warning(f"infra: {fleet} fleet probe failed: {err}")

    # ---- Per-instance EC2 metrics for both fleets ----
    if discovered_instance_ids:
        try:
            metrics_by_iid = _ec2_per_instance_metrics(
                discovered_instance_ids, cw,
                window_minutes=window_minutes,
                period_seconds=period_seconds,
            )
            for fleet in ("broker", "gateway"):
                for inst in snapshot[fleet]["instances"]:
                    iid = inst["instance_id"]
                    m = metrics_by_iid.get(iid, {})
                    cpu_vals = m.get("CPUUtilization") or []
                    if cpu_vals:
                        inst["cpu_latest"] = cpu_vals[0]
                    nin_vals = m.get("NetworkIn") or []
                    nout_vals = m.get("NetworkOut") or []
                    if nin_vals:
                        inst["network_in_5m"] = nin_vals[0]
                        inst["network_in_5m_human"] = _humanize_bytes(nin_vals[0])
                    if nout_vals:
                        inst["network_out_5m"] = nout_vals[0]
                        inst["network_out_5m_human"] = _humanize_bytes(nout_vals[0])
        except Exception as err:
            logger.warning(f"infra: per-instance EC2 metrics failed: {err}")

    # ---- Load balancers + Target groups ----
    try:
        lbs = []
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if not (lb.get("LoadBalancerName") or "").startswith(cluster_id):
                    continue
                lbs.append(lb)
        for lb in lbs:
            lb_arn = lb["LoadBalancerArn"]
            entry = {
                "name": lb.get("LoadBalancerName"),
                "type": lb.get("Type"),
                "scheme": lb.get("Scheme"),
                "state": (lb.get("State") or {}).get("Code"),
                "active_flow_count": None,
                "new_flow_count_5m": None,
                "target_groups": [],
            }
            tgs = elb.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
            for tg in tgs:
                tg_arn = tg["TargetGroupArn"]
                health = elb.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
                healthy = sum(1 for h in health if (h.get("TargetHealth") or {}).get("State") == "healthy")
                unhealthy = sum(1 for h in health if (h.get("TargetHealth") or {}).get("State") not in ("healthy", "initial"))
                entry["target_groups"].append({
                    "name": tg["TargetGroupName"],
                    "port": tg.get("Port"),
                    "protocol": tg.get("Protocol"),
                    "healthy": healthy,
                    "unhealthy": unhealthy,
                })
            try:
                ns = "AWS/NetworkELB" if lb.get("Type") == "network" else "AWS/ApplicationELB"
                dim_value = lb_arn.split(":loadbalancer/", 1)[-1]
                end = datetime.now(timezone.utc).replace(microsecond=0)
                start = end - timedelta(minutes=5)
                resp = cw.get_metric_data(
                    MetricDataQueries=[
                        {
                            "Id": "afc",
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": ns,
                                    "MetricName": "ActiveFlowCount",
                                    "Dimensions": [{"Name": "LoadBalancer", "Value": dim_value}],
                                },
                                "Period": 300,
                                "Stat": "Average",
                            },
                            "ReturnData": True,
                        },
                        {
                            "Id": "nfc",
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": ns,
                                    "MetricName": "NewFlowCount",
                                    "Dimensions": [{"Name": "LoadBalancer", "Value": dim_value}],
                                },
                                "Period": 300,
                                "Stat": "Sum",
                            },
                            "ReturnData": True,
                        },
                    ],
                    StartTime=start,
                    EndTime=end,
                )
                by_id = {r["Id"]: r for r in resp.get("MetricDataResults", [])}
                afc_vals = by_id.get("afc", {}).get("Values") or []
                nfc_vals = by_id.get("nfc", {}).get("Values") or []
                if afc_vals:
                    entry["active_flow_count"] = int(afc_vals[-1])
                if nfc_vals:
                    entry["new_flow_count_5m"] = int(sum(nfc_vals))
            except Exception as err:
                logger.debug(f"infra: NLB CW metrics for {lb.get('LoadBalancerName')} failed: {err}")
            snapshot["load_balancers"].append(entry)
    except Exception as err:
        logger.warning(f"infra: load balancer probe failed: {err}")

    # ---- Cluster Lambdas (functions starting with <cluster_id>-) ----
    try:
        fns = []
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                if (fn.get("FunctionName") or "").startswith(cluster_id):
                    fns.append(fn)
        if fns:
            queries = []
            # Lambda metrics use the same period as the rest of the page
            # so one window selection drives everything. Counters (Inv,
            # Err, Thr) are summed across all returned datapoints; Duration
            # is averaged.
            for idx, fn in enumerate(fns):
                fn_name = fn["FunctionName"]
                for mname, stat in (
                    ("Invocations", "Sum"),
                    ("Errors", "Sum"),
                    ("Throttles", "Sum"),
                    ("Duration", "Average"),
                ):
                    queries.append({
                        "Id": f"f{idx}_{mname.lower()[:3]}",
                        "Label": f"{fn_name}|{mname}",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Lambda",
                                "MetricName": mname,
                                "Dimensions": [{"Name": "FunctionName", "Value": fn_name}],
                            },
                            "Period": period_seconds,
                            "Stat": stat,
                        },
                        "ReturnData": True,
                    })
            end = datetime.now(timezone.utc).replace(microsecond=0)
            start = end - timedelta(minutes=window_minutes)
            metrics_by_fn = {fn["FunctionName"]: {} for fn in fns}
            for chunk_start in range(0, len(queries), 500):
                chunk = queries[chunk_start:chunk_start + 500]
                resp = cw.get_metric_data(
                    MetricDataQueries=chunk, StartTime=start, EndTime=end, ScanBy="TimestampDescending"
                )
                for r in resp.get("MetricDataResults", []):
                    label = r.get("Label", "")
                    if "|" not in label:
                        continue
                    fn_name, mname = label.split("|", 1)
                    values = list(r.get("Values") or [])
                    if not values:
                        continue
                    if mname == "Duration":
                        metrics_by_fn.setdefault(fn_name, {})[mname] = sum(values) / len(values)
                    else:
                        metrics_by_fn.setdefault(fn_name, {})[mname] = sum(values)
            for fn in fns:
                fn_name = fn["FunctionName"]
                m = metrics_by_fn.get(fn_name, {})
                # ListFunctions does NOT populate `State` (only GetFunction /
                # GetFunctionConfiguration do), so fetch it per function.
                # Best-effort: leave None (UI shows "?") on denial or error so
                # the panel never breaks if the grant is missing.
                _fn_state = fn.get("State")
                if not _fn_state:
                    try:
                        _fn_state = lam.get_function_configuration(
                            FunctionName=fn_name
                        ).get("State")
                    except Exception as _state_err:  # pylint: disable=broad-except
                        logger.debug(
                            "get_function_configuration(%s) failed: %s",
                            fn_name, _state_err,
                        )
                snapshot["lambdas"].append({
                    "name": fn_name,
                    "runtime": fn.get("Runtime"),
                    "state": _fn_state,
                    "last_modified": (fn.get("LastModified") or "")[:19],
                    "invocations_window": int(m.get("Invocations", 0) or 0),
                    "errors_window": int(m.get("Errors", 0) or 0),
                    "throttles_window": int(m.get("Throttles", 0) or 0),
                    "avg_duration_ms": m.get("Duration"),
                })
    except Exception as err:
        logger.warning(f"infra: lambda probe failed: {err}")

    snapshot["available"] = True
    return snapshot


def _session_path_snapshot(session_uuid: str) -> Dict[str, Any]:
    """
    Build the end-to-end "session path" snapshot for a single SOCA
    session_uuid: client -> gateway fleet -> broker (Ignite cluster
    member that owns the session) -> DCV server (instance) -> tail of
    log lines.

    Read-only across SOCA DB + broker API + EC2 describes.

    The shape returned is:
      {
        "available": bool, "error": str|None,
        "session": {...DB row fields...},
        "broker_view": {...describeSessions entry for this session...},
        "broker_owning": {"node_id": "<ignite locNodeId>", "instance_id": "i-..."|None, "ip": "..."},
        "gateway_fleet": [{"instance_id": ..., "private_ip": ...}, ...],
        "dcv_server": {"ip": ..., "instance_id": ..., "hostname": ...},
        "timing": {...timestamps + durations...},
      }
    """
    out: Dict[str, Any] = {
        "available": False,
        "error": None,
        "session_uuid": session_uuid,
        "session": {},
        "broker_view": {},
        "broker_owning": {},
        "gateway_fleet": [],
        "dcv_server": {},
        "timing": {},
    }

    # 1. SOCA DB row -- accept either the SOCA session_uuid or the
    # broker's session id (which we persist as authentication_token).
    try:
        from models import VirtualDesktopSessions
        _row = VirtualDesktopSessions.query.filter_by(
            session_uuid=session_uuid, is_active=True
        ).first()
        if _row is None:
            _row = VirtualDesktopSessions.query.filter_by(
                authentication_token=session_uuid, is_active=True
            ).first()
        if not _row:
            out["error"] = f"No active SOCA session matching id={session_uuid}"
            return out
        # Re-key the output to the canonical SOCA uuid in case caller
        # passed a broker id.
        out["session_uuid"] = _row.session_uuid
        out["session"] = {
            "session_uuid": _row.session_uuid,
            "session_owner": _row.session_owner,
            "session_state": _row.session_state,
            "session_type": _row.session_type,
            "session_name": _row.session_name,
            "session_id": _row.session_id,
            "broker_session_id": _row.authentication_token,
            "instance_id": _row.instance_id,
            "instance_private_ip": _row.instance_private_ip,
            "instance_private_dns": _row.instance_private_dns,
            "instance_type": _row.instance_type,
            "instance_base_os": _row.instance_base_os,
            "ssm_ping_status": _row.ssm_ping_status,
            "created_on": _row.created_on.isoformat() if _row.created_on else None,
            "session_state_latest_change_time": (
                _row.session_state_latest_change_time.isoformat()
                if _row.session_state_latest_change_time
                else None
            ),
        }
    except Exception as err:
        out["error"] = f"SOCA DB lookup failed: {err}"
        return out

    _broker_session_id = out["session"]["broker_session_id"]

    # 2. Broker view -- describeSessions and find this session.
    try:
        from utils.dcv_broker_client import DcvBrokerClient

        broker = DcvBrokerClient()
        ds = broker.describe_sessions()
        if ds.success:
            for sess in (ds.message or {}).get("Sessions", []) or []:
                if sess.get("Id") == _broker_session_id:
                    _server = sess.get("Server") or {}
                    _aws = _server.get("Aws") or {}
                    out["broker_view"] = {
                        "id": sess.get("Id"),
                        "state": sess.get("State"),
                        "type": sess.get("Type"),
                        "owner": sess.get("Owner"),
                        "creation_time": sess.get("CreationTime"),
                        "last_disconnection_time": sess.get("LastDisconnectionTime"),
                        "num_connections": sess.get("NumOfConnections"),
                        "console_session_count": sess.get("ConsoleSessionCount"),
                    }
                    out["dcv_server"] = {
                        "id": _server.get("Id"),
                        "ip": _server.get("Ip"),
                        "hostname": _server.get("Hostname"),
                        "instance_id": _aws.get("EC2InstanceId"),
                        "availability": _server.get("Availability"),
                        "version": _server.get("Version"),
                    }
                    # The broker that "owns" this session in DDB shared
                    # state. brokerId is an Ignite node UUID; we surface
                    # it as-is and let the breadcrumb correlate to a
                    # broker EC2 InstanceId via Phase 2 log scraping.
                    _br = (
                        sess.get("BrokerReservedProperties")
                        or {}
                    )
                    out["broker_owning"] = {
                        "node_id": _br.get("BrokerId"),
                        "instance_id": None,
                        "ip": None,
                    }
                    break
        else:
            out["error"] = f"describeSessions failed: {ds.message}"
            return out
    except Exception as err:
        out["error"] = f"broker client failed: {err}"
        return out

    # 3. Gateway fleet -- list each gateway instance the client could be
    # routed through. NLB source-IP stickiness pins each client to one
    # gateway, but without flow logs we don't know which one. Return
    # the fleet so the UI can present "all candidates".
    try:
        ec2 = getattr(get_boto(service_name="ec2"), "message", None)
        asg = getattr(get_boto(service_name="autoscaling"), "message", None)
        if ec2 is not None and asg is not None:
            paginator = asg.get_paginator("describe_auto_scaling_groups")
            gateway_iids = []
            cluster_id = _cluster_id() or ""
            for page in paginator.paginate():
                for group in page.get("AutoScalingGroups", []):
                    tags = {t["Key"]: t["Value"] for t in group.get("Tags", [])}
                    if (
                        tags.get("edh:ClusterId") == cluster_id
                        and tags.get("edh:NodeType") == "dcv_gateway"
                    ) or (
                        tags.get("edh:ClusterId") == cluster_id
                        and "DCVgatewayASG" in (group.get("AutoScalingGroupName") or "")
                    ):
                        gateway_iids.extend(
                            i["InstanceId"] for i in group.get("Instances", [])
                        )
            if gateway_iids:
                desc = ec2.describe_instances(InstanceIds=gateway_iids)
                for r in desc.get("Reservations", []):
                    for inst in r.get("Instances", []):
                        out["gateway_fleet"].append({
                            "instance_id": inst.get("InstanceId"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "az": (inst.get("Placement") or {}).get("AvailabilityZone"),
                            "state": (inst.get("State") or {}).get("Name"),
                        })
    except Exception as err:
        logger.warning(f"session_path: gateway lookup failed: {err}")

    # 4. Timing. created_on is from SOCA DB; broker creation_time is
    # the broker's own. Difference shows broker-side creation latency
    # vs DB record (usually small). Active duration is now-created.
    try:
        _created_on = out["session"].get("created_on")
        _broker_created = out["broker_view"].get("creation_time")
        if _created_on:
            _ts = datetime.fromisoformat(_created_on.replace("Z", "+00:00"))
            _now = datetime.now(timezone.utc)
            out["timing"]["active_seconds"] = int((_now - _ts).total_seconds())
            out["timing"]["active_human"] = _humanize_duration(
                out["timing"]["active_seconds"]
            )
        if _created_on and _broker_created:
            _db_ts = datetime.fromisoformat(_created_on.replace("Z", "+00:00"))
            _br_ts = datetime.fromisoformat(_broker_created.replace("Z", "+00:00"))
            out["timing"]["db_to_broker_skew_seconds"] = int(
                abs((_br_ts - _db_ts).total_seconds())
            )
    except Exception as err:
        logger.debug(f"session_path: timing math failed: {err}")

    out["available"] = True

    # Per-instance health: collect every InstanceId in the path and pull
    # CPU/mem/swap/disk/net via _per_instance_health in one batched call.
    # Status classification is rolled up onto the matching node entry so
    # the UI can color-code the breadcrumb cards green/yellow/red.
    try:
        # Discover broker fleet so the breadcrumb has all broker hosts
        # (Ignite session ownership is by Ignite UUID; we surface all
        # brokers + flag the owning node in the UI).
        broker_fleet = []
        try:
            ec2 = getattr(get_boto(service_name="ec2"), "message", None)
            asg = getattr(get_boto(service_name="autoscaling"), "message", None)
            cluster_id = _cluster_id() or ""
            if ec2 is not None and asg is not None:
                paginator = asg.get_paginator("describe_auto_scaling_groups")
                broker_iids = []
                for page in paginator.paginate():
                    for group in page.get("AutoScalingGroups", []):
                        tags = {t["Key"]: t["Value"] for t in group.get("Tags", [])}
                        if (
                            tags.get("edh:ClusterId") == cluster_id
                            and tags.get("edh:NodeType") == "dcv_broker"
                        ) or (
                            tags.get("edh:ClusterId") == cluster_id
                            and "DCVbrokerASG" in (group.get("AutoScalingGroupName") or "")
                        ):
                            broker_iids.extend(
                                i["InstanceId"] for i in group.get("Instances", [])
                            )
                if broker_iids:
                    desc = ec2.describe_instances(InstanceIds=broker_iids)
                    for r in desc.get("Reservations", []):
                        for inst in r.get("Instances", []):
                            broker_fleet.append({
                                "instance_id": inst.get("InstanceId"),
                                "private_ip": inst.get("PrivateIpAddress"),
                                "az": (inst.get("Placement") or {}).get("AvailabilityZone"),
                                "state": (inst.get("State") or {}).get("Name"),
                            })
        except Exception as err:
            logger.warning(f"session_path: broker fleet lookup failed: {err}")
        out["broker_fleet"] = broker_fleet

        # Collect every instance id we need health for
        iids = []
        if out["dcv_server"].get("instance_id"):
            iids.append(out["dcv_server"]["instance_id"])
        for g in out.get("gateway_fleet", []):
            if g.get("instance_id"):
                iids.append(g["instance_id"])
        for b in out.get("broker_fleet", []):
            if b.get("instance_id"):
                iids.append(b["instance_id"])

        health = _per_instance_health(iids)
        out["health"] = health  # raw -- also attach onto each node

        # DCV server status
        if out["dcv_server"].get("instance_id"):
            h = health.get(out["dcv_server"]["instance_id"]) or {}
            out["dcv_server"]["health"] = h
            # Tighten DCV server status: if broker says UNAVAILABLE, that
            # trumps host-metric ok. SSM offline same.
            ds_status = h.get("status", "unknown")
            ds_reason = h.get("status_reason", "")
            if out["dcv_server"].get("availability") == "UNAVAILABLE":
                ds_status = "danger"
                ds_reason = "broker reports UNAVAILABLE"
            elif (out["session"].get("ssm_ping_status") or "").lower() == "connectionlost":
                ds_status = "danger"
                ds_reason = "SSM connection lost"
            out["dcv_server"]["status"] = ds_status
            out["dcv_server"]["status_reason"] = ds_reason

        # Gateway nodes (each gets its own status)
        for g in out.get("gateway_fleet", []):
            h = health.get(g.get("instance_id")) or {}
            g["health"] = h
            g["status"] = h.get("status", "unknown")
            g["status_reason"] = h.get("status_reason", "")

        # Broker nodes
        owning_node_id = (out.get("broker_owning") or {}).get("node_id") or ""
        for b in out.get("broker_fleet", []):
            h = health.get(b.get("instance_id")) or {}
            b["health"] = h
            b["status"] = h.get("status", "unknown")
            b["status_reason"] = h.get("status_reason", "")
            # We can't reliably correlate Ignite node UUID -> EC2 InstanceId
            # from the broker API. Mark the node only if a downstream
            # consumer has done the correlation; currently this stays False.
            b["owns_session"] = False

        # Overall path status: worst of (dcv server, all gateways, all brokers)
        rank = {"ok": 0, "warn": 1, "danger": 2, "unknown": 0}
        worst = "ok"
        for stat in [out["dcv_server"].get("status", "ok")] \
                   + [g.get("status", "ok") for g in out.get("gateway_fleet", [])] \
                   + [b.get("status", "ok") for b in out.get("broker_fleet", [])]:
            if rank.get(stat, 0) > rank.get(worst, 0):
                worst = stat
        out["overall_status"] = worst
    except Exception as err:
        logger.warning(f"session_path: health rollup failed: {err}")
        out.setdefault("overall_status", "unknown")

    return out


@admin_cluster_status_dcv_overview.route(
    "/admin/cluster_status/dcv_session_path/<session_uuid>", methods=["GET"]
)
@login_required
@admin_only
def session_path(session_uuid):
    """JSON endpoint -- per-session breadcrumb for drill-down modal."""
    return jsonify(_session_path_snapshot(session_uuid))


@admin_cluster_status_dcv_overview.route(
    "/admin/cluster_status/dcv_session_path_view/<session_uuid>", methods=["GET"]
)
@login_required
@admin_only
def session_path_view(session_uuid):
    """Full-page version of the session path drill-down. Linked from the
    'Pop out' button in the modal — opens in a new browser window so the
    operator can keep it alongside the dashboard."""
    snapshot = _session_path_snapshot(session_uuid)
    return render_template(
        "admin/cluster_status/dcv_session_path_view.html",
        page="admin_cluster_status_dcv_session_path_view",
        session_uuid=session_uuid,
        snapshot=snapshot,
        snapshot_json=json.dumps(snapshot, default=str),
        cluster_id=_cluster_id() or "",
    )


@admin_cluster_status_dcv_overview.route(
    "/admin/cluster_status/bootstrap_cache", methods=["GET"]
)
@login_required
@admin_only
def bootstrap_cache_status():
    """Session-admin twin of GET /api/admin/bootstrap_cache.

    The overview page is browser/session-authenticated, but the API Resource
    is header-authenticated (X-EDH-USER/TOKEN), so a same-origin fetch from
    the page 401s. Serve the same summary over the session-admin view route
    the rest of this page already uses.
    """
    from api.v1.admin.bootstrap_cache import get_cache_summary

    return get_cache_summary().as_flask()


@admin_cluster_status_dcv_overview.route(
    "/admin/cluster_status/bootstrap_cache/refresh", methods=["POST"]
)
@login_required
@admin_only
def bootstrap_cache_refresh():
    """Session-admin twin of POST /api/admin/bootstrap_cache/refresh."""
    from api.v1.admin.bootstrap_cache import refresh_cache

    return refresh_cache().as_flask()


def _resolve_fleet_asg_name(asg_client, cluster_id: str, fleet: str) -> Optional[str]:
    """Resolve the broker/gateway ASG name for THIS cluster using the same
    tag-based discovery (edh:ClusterId + edh:NodeType) the infra snapshot
    uses, with the legacy name-pattern fallback. Resolving server-side means
    a caller can only ever target this cluster's broker/gateway ASGs -- never
    an arbitrary ASG name.
    """
    node_type = {"broker": "dcv_broker", "gateway": "dcv_gateway"}.get(fleet)
    name_pattern = {"broker": "DCVbrokerASG", "gateway": "DCVgatewayASG"}.get(fleet)
    if not node_type:
        return None
    try:
        paginator = asg_client.get_paginator("describe_auto_scaling_groups")
        for page in paginator.paginate():
            for group in page.get("AutoScalingGroups", []):
                tags = {t["Key"]: t["Value"] for t in group.get("Tags", [])}
                if (
                    tags.get("edh:ClusterId") == cluster_id
                    and tags.get("edh:NodeType") == node_type
                ):
                    return group["AutoScalingGroupName"]
                if (
                    tags.get("edh:ClusterId") == cluster_id
                    and name_pattern in (group.get("AutoScalingGroupName") or "")
                ):
                    return group["AutoScalingGroupName"]
    except Exception as err:  # pylint: disable=broad-except
        logger.warning("resolve %s ASG failed: %s", fleet, err)
    return None


@admin_cluster_status_dcv_overview.route(
    "/admin/cluster_status/dcv_asg_sizing", methods=["POST"]
)
@login_required
@admin_only
def dcv_asg_sizing():
    """Session-admin: resize the broker or gateway ASG (min/desired/max).

    `fleet` is restricted to broker|gateway and the ASG name is resolved
    server-side from this cluster's tagged ASGs -- the client never supplies
    an ASG name, so this can only resize this cluster's broker/gateway fleets.
    Capacities are validated (0 <= min <= desired <= max <= cap) with the cap
    derived from Config.dcv.<fleet>.max_instance_count (hard fallback 50).
    """
    from utils.error import SocaError
    from utils.response import SocaResponse

    _body = request.get_json(silent=True) or {}
    _fleet = (_body.get("fleet") or "").strip().lower()
    if _fleet not in ("broker", "gateway"):
        return SocaError.GENERIC_ERROR(helper="fleet must be 'broker' or 'gateway'").as_flask()

    _vals = {}
    for _k in ("min", "desired", "max"):
        _cast = SocaCastEngine(_body.get(_k)).cast_as(expected_type=int)
        if _cast.get("success") is not True:
            return SocaError.GENERIC_ERROR(helper=f"{_k} must be an integer").as_flask()
        _v = _cast.get("message")
        if _v < 0:
            return SocaError.GENERIC_ERROR(helper=f"{_k} must be >= 0").as_flask()
        _vals[_k] = _v

    if not (_vals["min"] <= _vals["desired"] <= _vals["max"]):
        return SocaError.GENERIC_ERROR(helper="require min <= desired <= max").as_flask()

    # Config-derived fat-finger ceiling; hard fallback when the key is unset.
    _cap = (
        SocaConfig(key=f"/configuration/dcv/{_fleet}/max_instance_count")
        .get_value(default=50, allow_unknown_key=True, return_as=int)
        .get("message", 50)
    )
    if _vals["max"] > _cap:
        return SocaError.GENERIC_ERROR(
            helper=f"max {_vals['max']} exceeds the ceiling {_cap} for the {_fleet} "
                   f"fleet (Config.dcv.{_fleet}.max_instance_count)"
        ).as_flask()

    _asg_resp = get_boto(service_name="autoscaling")
    if _asg_resp.success is not True:
        return SocaError.AWS_API_ERROR(
            service_name="autoscaling",
            helper=f"autoscaling client unavailable: {_asg_resp.message}",
        ).as_flask()
    _asg = _asg_resp.message
    _asg_name = _resolve_fleet_asg_name(_asg, _cluster_id() or "", _fleet)
    if not _asg_name:
        return SocaError.GENERIC_ERROR(
            helper=f"Could not resolve the {_fleet} ASG for this cluster"
        ).as_flask()

    try:
        _asg.update_auto_scaling_group(
            AutoScalingGroupName=_asg_name,
            MinSize=_vals["min"],
            DesiredCapacity=_vals["desired"],
            MaxSize=_vals["max"],
        )
    except Exception as _upd_err:  # pylint: disable=broad-except
        logger.exception("update_auto_scaling_group(%s) failed: %s", _asg_name, _upd_err)
        return SocaError.AWS_API_ERROR(
            service_name="autoscaling",
            helper=f"Failed to update {_fleet} ASG: {_upd_err}",
        ).as_flask()

    logger.info(
        "DCV %s ASG %s resized by %s -> min=%d desired=%d max=%d",
        _fleet, _asg_name, session.get("user", "?"),
        _vals["min"], _vals["desired"], _vals["max"],
    )
    return SocaResponse(
        success=True,
        message={"fleet": _fleet, "asg_name": _asg_name, **_vals},
    ).as_flask()


# ---------------------------------------------------------------------------
# VDI Pools tab (Phase 0: point-in-time snapshot).
#
# Provider seam: get_pool_snapshot() returns a FROZEN contract dict and is the
# ONLY thing the page section + JSON endpoint call. v1 builds it directly from
# live ASG + warm-pool + ledger + config reads. A later v2 swaps the body to a
# Valkey read-through (reconciler-as-collector) with the SAME contract, so the
# source is swappable behind this one function with no UI change. See
# docs/VDIPooling.md "Changeover mechanics".
# ---------------------------------------------------------------------------


def _pool_tag(asg: Dict[str, Any], key: str) -> Optional[str]:
    for _t in asg.get("Tags", []) or []:
        if _t.get("Key") == key:
            return _t.get("Value")
    return None


def _spark_points(values, width=100, height=26, pad=2):
    """Build an SVG polyline `points` string from a numeric series (server-side
    sparkline -- no JS / chart re-init needed; refreshes with the region)."""
    _nums = [float(v) for v in values if v is not None]
    if not _nums:
        return ""
    if len(_nums) == 1:
        _y = height / 2
        return f"0,{_y:.1f} {width},{_y:.1f}"
    _vmax = max(_nums)
    _vmin = min(_nums)
    _rng = (_vmax - _vmin) or 1.0
    _n = len(_nums)
    _pts = []
    for _i, _v in enumerate(_nums):
        _x = _i / (_n - 1) * width
        _y = height - pad - ((_v - _vmin) / _rng) * (height - 2 * pad)
        _pts.append(f"{_x:.1f},{_y:.1f}")
    return " ".join(_pts)


def _pool_claim_series(pool_ids, window_minutes, period_seconds):
    """One GetMetricData over EDH/DCVHighScale (dim pool_id) for the claim
    metrics, summed across pools via metric math -> cluster-wide trend for the
    KPI sparklines. Returns {short: {values, sum, points}} for
    claims/hot/collisions; {} if unavailable."""
    cw = getattr(get_boto(service_name="cloudwatch"), "message", None)
    if cw is None or not pool_ids:
        return {}
    _end = datetime.now(timezone.utc)
    _start = _end - timedelta(minutes=window_minutes)
    _metrics = [("ClaimAttempts", "claims"), ("TierServedHot", "hot"), ("ClaimCollisions", "collisions")]
    _queries = []
    _by_short: Dict[str, List[str]] = {_s: [] for _, _s in _metrics}
    _claims_qid_pool: Dict[str, str] = {}  # m{i}_claims -> pool_id (row sparkline)
    for _i, _pid in enumerate(pool_ids):
        for _mname, _short in _metrics:
            _qid = f"m{_i}_{_short}"
            _by_short[_short].append(_qid)
            if _short == "claims":
                _claims_qid_pool[_qid] = _pid
            _queries.append({
                "Id": _qid,
                "MetricStat": {
                    "Metric": {
                        "Namespace": _SCREENSHOT_NAMESPACE,
                        "MetricName": _mname,
                        "Dimensions": [{"Name": "pool_id", "Value": _pid}],
                    },
                    "Period": int(period_seconds),
                    "Stat": "Sum",
                },
                # per-pool claims returned for the row sparkline; hot/collisions
                # per-pool feed only the cluster SUM expression (hidden).
                "ReturnData": _short == "claims",
            })
    for _short, _ids in _by_short.items():
        if _ids:
            _queries.append({
                "Id": f"sum_{_short}",
                "Expression": f"SUM([{','.join(_ids)}])",
                "Label": _short,
                "ReturnData": True,
            })
    try:
        _resp = cw.get_metric_data(
            MetricDataQueries=_queries,
            StartTime=_start,
            EndTime=_end,
            ScanBy="TimestampAscending",
        )
    except Exception as _err:  # noqa: BLE001
        logger.warning("pool claim series GetMetricData failed: %s", _err)
        return {}
    _out: Dict[str, Any] = {"per_pool": {}}
    for _r in _resp.get("MetricDataResults", []):
        _id = _r.get("Id", "")
        _vals = _r.get("Values", []) or []
        if _id.startswith("sum_"):
            _out[_id[4:]] = {
                "values": _vals,
                "sum": int(sum(_vals)) if _vals else 0,
                "points": _spark_points(_vals),
            }
        elif _id in _claims_qid_pool:
            _out["per_pool"][_claims_qid_pool[_id]] = {
                "claims_sum": int(sum(_vals)) if _vals else 0,
                "claims_points": _spark_points(_vals),
            }
    return _out


def _classify_activity(desc: str, status: str):
    """Map an ASG scaling-activity to (kind, severity) for the event feed."""
    _d = (desc or "").lower()
    _s = status or ""
    if _s in ("Failed", "Cancelled") or "abandon" in _d:
        return ("error", "danger")
    if "terminat" in _d:
        return ("terminate", "warn")
    if "launch" in _d or "starting" in _d:
        return ("launch", "info")
    if "warm" in _d:
        return ("warm", "info")
    return ("activity", "muted")


def _pool_event_log(asg_metas, per_asg: int = 15, total: int = 40):
    """Aggregate recent ASG scaling activities across the pool ASGs into one
    typed, time-sorted feed. Source-agnostic shape (id/ts/kind) so a future
    SSE/Valkey-Stream source can feed the same renderer. Read-only."""
    asg = getattr(get_boto(service_name="autoscaling"), "message", None)
    if asg is None or not asg_metas:
        return []
    _events = []
    for _m in asg_metas:
        if not _m.get("name"):
            continue
        try:
            _r = asg.describe_scaling_activities(
                AutoScalingGroupName=_m["name"], MaxRecords=per_asg
            )
        except Exception as _err:  # noqa: BLE001 - one bad ASG must not kill the feed
            logger.warning("scaling activities failed for %s: %s", _m.get("name"), _err)
            continue
        for _a in _r.get("Activities", []) or []:
            _kind, _sev = _classify_activity(_a.get("Description"), _a.get("StatusCode"))
            _st = _a.get("StartTime")
            _events.append({
                "id": _a.get("ActivityId", ""),
                "ts": _st.isoformat() if hasattr(_st, "isoformat") else str(_st or ""),
                "type": _m.get("type", ""),
                "pool_id": _m.get("pool_id", ""),  # per-card grouping (Phase 2.5)
                "kind": _kind,
                "severity": _sev,
                "status": _a.get("StatusCode", ""),
                "description": (_a.get("Description") or "")[:160],
            })
    _events.sort(key=lambda e: e["ts"], reverse=True)
    return _events[:total]


def _member_state(lifecycle: str):
    """Map an ASG / warm-pool LifecycleState to (display_label, css_class)."""
    _ls = lifecycle or ""
    if _ls == "InService":
        return ("InService", "insvc")
    if _ls.startswith("Warmed:"):
        return (_ls, "warm")            # e.g. Warmed:Stopped / Warmed:Hibernated
    if _ls.startswith("Pending"):
        return (_ls, "pend")
    if _ls.startswith("Terminating") or _ls.startswith("Detaching"):
        return (_ls, "term")
    return (_ls or "\u2014", "muted")


def _pool_members(asg_client, group, warm_size, cap: int = 60):
    """Per-pool member list: InService (+ other in-ASG) instances from the
    describe-ASG result, plus warm-pool instances via describe_warm_pool when
    warm_size > 0. Read-only; a single failure yields a partial list, never
    raises. (claimed-by / uptime are deferred -- claimed hot members are
    detached from the ASG at claim time; see docs/VDIPooling.md.)"""
    _members = []
    for _i in group.get("Instances", []) or []:
        _lbl, _cls = _member_state(_i.get("LifecycleState"))
        _members.append({
            "iid": _i.get("InstanceId", ""),
            "state": _lbl,
            "state_class": _cls,
            "az": _i.get("AvailabilityZone", ""),
        })
    if warm_size and asg_client is not None and group.get("AutoScalingGroupName"):
        try:
            _wp = asg_client.describe_warm_pool(
                AutoScalingGroupName=group["AutoScalingGroupName"]
            )
            for _i in _wp.get("Instances", []) or []:
                _lbl, _cls = _member_state(_i.get("LifecycleState"))
                _members.append({
                    "iid": _i.get("InstanceId", ""),
                    "state": _lbl,
                    "state_class": _cls,
                    "az": _i.get("AvailabilityZone", ""),
                })
        except Exception as _err:  # noqa: BLE001 - one bad warm-pool read is non-fatal
            logger.warning(
                "describe_warm_pool failed for %s: %s",
                group.get("AutoScalingGroupName"), _err,
            )
    _order = {"insvc": 0, "pend": 1, "warm": 2, "term": 3, "muted": 4}
    _members.sort(key=lambda m: _order.get(m["state_class"], 9))
    return _members[:cap]


def _pool_extra_series(pool_ids, window_minutes, period_seconds):
    """Phase 3: per-pool TimeToServe p50/p99 (from the claim-time TimeToServe
    metric) + ReadyNow depth sparkline. The depth gauges (ReadyNow/HotDepth/
    WarmDepth) are emitted by the reconciler in a later (supervised) redeploy;
    absent here this degrades to empty (Q2 hybrid -- client/df fallback). One
    GetMetricData, read-only (cloudwatch:GetMetricData only)."""
    cw = getattr(get_boto(service_name="cloudwatch"), "message", None)
    if cw is None or not pool_ids:
        return {}
    _end = datetime.now(timezone.utc).replace(microsecond=0)
    _start = _end - timedelta(minutes=window_minutes)
    _queries = []
    _map: Dict[str, Any] = {}  # qid -> (pool_id, field)
    for _i, _pid in enumerate(pool_ids):
        for _field, _mname, _stat in (
            ("tts_p50", "TimeToServe", "p50"),
            ("tts_p99", "TimeToServe", "p99"),
            ("ready", "ReadyNow", "Average"),
        ):
            _qid = f"x{_i}_{_field}"
            _map[_qid] = (_pid, _field)
            _queries.append({
                "Id": _qid,
                "MetricStat": {
                    "Metric": {
                        "Namespace": _SCREENSHOT_NAMESPACE,
                        "MetricName": _mname,
                        "Dimensions": [{"Name": "pool_id", "Value": _pid}],
                    },
                    "Period": int(period_seconds),
                    "Stat": _stat,
                },
                "ReturnData": True,
            })
    try:
        _resp = cw.get_metric_data(
            MetricDataQueries=_queries, StartTime=_start, EndTime=_end,
            ScanBy="TimestampAscending",
        )
    except Exception as _err:  # noqa: BLE001
        logger.warning("pool extra series GetMetricData failed: %s", _err)
        return {}
    _out: Dict[str, Any] = {}
    for _r in _resp.get("MetricDataResults", []):
        _pid, _field = _map.get(_r.get("Id", ""), (None, None))
        if not _pid:
            continue
        _vals = _r.get("Values", []) or []
        _slot = _out.setdefault(_pid, {})
        if _field in ("tts_p50", "tts_p99"):
            _slot[_field] = round(_vals[-1], 1) if _vals else None
        elif _field == "ready":
            _slot["ready_points"] = _spark_points(_vals)
    return _out


def _pool_control_health(window_minutes, period_seconds):
    """Phase 4: reconciler + relay control-loop health, CloudWatch-only
    (AWS/Lambda Invocations/Errors/Duration + newest-invocation timestamp, plus
    the relay's own EDH/DCVHighScale DcvEventRelayRejected counter). No new IAM
    -- cloudwatch:GetMetricData (Resource:*) already granted. Read-only;
    degrades to {available:False} so the section/endpoint never break."""
    cw = getattr(get_boto(service_name="cloudwatch"), "message", None)
    _cid = _cluster_id() or ""
    if cw is None or not _cid:
        return {"available": False}
    _recon = f"{_cid}-VdiPoolReconciler"
    _relay = f"{_cid}-DcvEventRelay"
    _end = datetime.now(timezone.utc).replace(microsecond=0)
    _start = _end - timedelta(minutes=window_minutes)
    _q = []
    for _fn, _tag in ((_recon, "rec"), (_relay, "rel")):
        for _m, _stat in (("Invocations", "Sum"), ("Errors", "Sum"), ("Duration", "Average")):
            _q.append({
                "Id": f"{_tag}_{_m.lower()[:3]}",
                "Label": f"{_fn}|{_m}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/Lambda",
                        "MetricName": _m,
                        "Dimensions": [{"Name": "FunctionName", "Value": _fn}],
                    },
                    "Period": int(period_seconds),
                    "Stat": _stat,
                },
                "ReturnData": True,
            })
    _q.append({
        "Id": "rel_rej",
        "Label": "REJ",
        "MetricStat": {
            "Metric": {"Namespace": _SCREENSHOT_NAMESPACE, "MetricName": "DcvEventRelayRejected"},
            "Period": int(period_seconds),
            "Stat": "Sum",
        },
        "ReturnData": True,
    })
    try:
        _resp = cw.get_metric_data(
            MetricDataQueries=_q, StartTime=_start, EndTime=_end,
            ScanBy="TimestampDescending",
        )
    except Exception as _err:  # noqa: BLE001
        logger.warning("pool control health GetMetricData failed: %s", _err)
        return {"available": False}
    _acc: Dict[str, Any] = {_recon: {}, _relay: {}, "rej": 0}
    for _r in _resp.get("MetricDataResults", []):
        _id = _r.get("Id", "")
        _label = _r.get("Label", "")
        _vals = _r.get("Values", []) or []
        _ts = _r.get("Timestamps", []) or []
        if _id == "rel_rej":
            _acc["rej"] = int(sum(_vals)) if _vals else 0
            continue
        if "|" not in _label:
            continue
        _fn, _m = _label.split("|", 1)
        _slot = _acc.setdefault(_fn, {})
        if _m == "Duration":
            _slot["duration_ms"] = round(sum(_vals) / len(_vals), 1) if _vals else None
        else:
            _slot[_m.lower()] = int(sum(_vals)) if _vals else 0
        if _m == "Invocations" and _ts:
            _slot["last_seen"] = _ts[0].isoformat() if hasattr(_ts[0], "isoformat") else str(_ts[0])

    def _mk(_fn, _is_relay=False):
        _s = _acc.get(_fn, {})
        _healthy = (_s.get("errors", 0) == 0)
        if _is_relay and _acc.get("rej", 0) > 0:
            _healthy = False
        return {
            "function": _fn,
            "invocations": _s.get("invocations", 0),
            "errors": _s.get("errors", 0),
            "duration_ms": _s.get("duration_ms"),
            "last_seen": _s.get("last_seen"),
            "healthy": _healthy,
        }

    _relay_h = _mk(_relay, _is_relay=True)
    _relay_h["rejections"] = _acc.get("rej", 0)
    return {
        "available": True,
        "window_minutes": window_minutes,
        "reconciler": _mk(_recon),
        "relay": _relay_h,
    }


def _build_pool_snapshot_direct(window_minutes: int = 60, period_seconds: int = 300) -> Dict[str, Any]:
    """v1 provider body: point-in-time per-pool snapshot from live ASG +
    warm-pool size + ledger ready_now, enriched with config (label / configured
    hot+warm). Read-only; degrades to {available:False,error} (never raises) so
    the section runner and the JSON endpoint both stay safe."""
    _cid = _cluster_id() or ""
    if not _cid:
        return {"available": False, "error": "cluster id unavailable"}

    asg = getattr(get_boto(service_name="autoscaling"), "message", None)
    if asg is None:
        return {"available": False, "error": "autoscaling client unavailable"}

    # 1. Discover pool ASGs by tag. The ASG is ground truth for live state and
    #    includes DRAINING tombstones that are no longer in the config table.
    _groups: List[Dict[str, Any]] = []
    try:
        _pag = asg.get_paginator("describe_auto_scaling_groups")
        for _page in _pag.paginate(
            Filters=[
                {"Name": "tag-key", "Values": ["edh:pool_id"]},
                {"Name": "tag:edh:ClusterId", "Values": [_cid]},
            ]
        ):
            _groups.extend(_page.get("AutoScalingGroups", []) or [])
    except Exception as err:  # noqa: BLE001
        return {"available": False, "error": f"describe_auto_scaling_groups failed: {err}"}

    # 2. Config enrichment (label + configured hot/warm + enabled), read once
    #    per distinct stack via the existing store helper (covers ACTIVE +
    #    PARKED entries; DRAINING tombstones simply have no config entry).
    _entries_by_pool: Dict[str, Dict[str, Any]] = {}
    try:
        from helpers import vdi_pool_store

        _stack_ids = {
            _pool_tag(g, "edh:stack_id") for g in _groups if _pool_tag(g, "edh:stack_id")
        }
        for _sid in _stack_ids:
            _r = vdi_pool_store.get_pool_config(_sid)
            _meta = _r.get("message") if _r.get("success") is True else None
            for _e in (_meta or {}).get("entries", []) if _meta else []:
                _it = (_e.get("instance_type") or "").strip()
                if _it:
                    _entries_by_pool[f"POOL#{_sid}#{_it}"] = _e
    except Exception as err:  # noqa: BLE001 - enrichment is best-effort
        logger.warning("dcv_overview: pool config enrichment failed: %s", err)

    # 3. ledger ready_now per pool, intersected with the broker's live AVAILABLE
    # set so the dashboard shows the true claim-now count, not stale rows.
    try:
        from helpers import vdi_pool_allocator
    except Exception:  # noqa: BLE001
        vdi_pool_allocator = None

    _ready_ids = (
        vdi_pool_allocator.broker_ready_instance_ids()
        if vdi_pool_allocator is not None
        else None
    )

    _pools: List[Dict[str, Any]] = []
    for _g in _groups:
        _pid = _pool_tag(_g, "edh:pool_id")
        _itype = _pool_tag(_g, "edh:instance_type") or ""
        _sid = _pool_tag(_g, "edh:stack_id") or ""
        _status = _pool_tag(_g, "edh:pool_status") or "ACTIVE"
        _insvc = len(
            [i for i in (_g.get("Instances") or []) if i.get("LifecycleState") == "InService"]
        )
        _ready = 0
        _ledger_avail = 0
        if vdi_pool_allocator is not None and _sid and _itype:
            try:
                _ledger_avail, _ready = vdi_pool_allocator.available_breakdown(
                    _sid, _itype, _ready_ids
                )
            except Exception:  # noqa: BLE001
                _ready = _ledger_avail = 0
        # Δ = ledger AVAILABLE rows the broker can't (yet) serve: stale rows
        # (warm/zombie) or members mid broker-registration. Admin diagnostic.
        _stale_delta = max(_ledger_avail - _ready, 0)
        _cfg = _entries_by_pool.get(_pid or "", {})
        _warm = int(_g.get("WarmPoolSize") or 0)
        _mem_list = _pool_members(asg, _g, _warm)
        # Derived display status: the raw tag echoed verbatim is misleading
        # (a removed pool that has finished draining to 0 still tags DRAINING).
        # Map tag + live member count to what the admin actually sees:
        #   PARKED  -> disabled row, kept at 0 (intentionally idle)
        #   EMPTY   -> 0 members (ASG kept; transiently drained, or a removed
        #              pool whose reaper hasn't deleted it yet)
        #   DRAINING-> still > 0 members, genuinely winding down
        #   ACTIVE  -> desired + running members
        _members = _insvc + _warm
        if _status == "PARKED":
            _disp = "PARKED"
        elif _members == 0:
            _disp = "EMPTY"
        elif _status == "DRAINING":
            _disp = "DRAINING"
        else:
            _disp = "ACTIVE"
        _pools.append({
            "pool_id": _pid,
            "stack_id": _sid,
            "instance_type": _itype,
            "label": _cfg.get("label") or "",
            "status": _status,
            "display_status": _disp,
            "hot_insvc": _insvc,
            "ready_now": _ready,
            "ledger_available": _ledger_avail,
            "stale_delta": _stale_delta,
            "warm_size": _warm,
            "desired": int(_g.get("DesiredCapacity") or 0),
            "hot_count": int(_cfg.get("hot_count") or 0),
            "warm_count": int(_cfg.get("warm_count") or 0),
            "asg_name": _g.get("AutoScalingGroupName"),
            "members": _mem_list,
            "members_count": len(_mem_list),
        })

    # stack_name is resolved later in the request greenlet (the SoftwareStacks
    # ORM needs Flask app context, which this gevent section greenlet lacks).
    # Default to the id so the field always exists; the view overwrites it with
    # the friendly name before render (see _apply_pool_stack_names).
    for _p in _pools:
        _p.setdefault("stack_name", _p.get("stack_id"))

    # Within a stack push EMPTY/PARKED pools last so the live (ACTIVE/DRAINING)
    # ones lead. The template's groupby is stable, so this within-stack order is
    # preserved even after it regroups by the resolved stack_name.
    _status_rank = {"ACTIVE": 0, "DRAINING": 1, "PARKED": 2, "EMPTY": 3}
    _pools.sort(key=lambda p: (
        str(p.get("stack_id")),
        _status_rank.get(p.get("display_status"), 5),
        str(p.get("instance_type")),
    ))
    _series = _pool_claim_series(
        [p["pool_id"] for p in _pools if p.get("pool_id")],
        window_minutes,
        period_seconds,
    )
    _pp = (_series or {}).get("per_pool", {})
    for _p in _pools:
        _ppx = _pp.get(_p.get("pool_id"), {})
        _p["claims_points"] = _ppx.get("claims_points", "")
        _p["claims_sum"] = _ppx.get("claims_sum", 0)
    # Phase 3: per-pool TimeToServe p50/p99 + ReadyNow depth (forward-ready).
    _extra = _pool_extra_series(
        [p["pool_id"] for p in _pools if p.get("pool_id")],
        window_minutes,
        period_seconds,
    )
    for _p in _pools:
        _ex = _extra.get(_p.get("pool_id"), {})
        _p["tts_p50"] = _ex.get("tts_p50")
        _p["tts_p99"] = _ex.get("tts_p99")
        _p["ready_points"] = _ex.get("ready_points", "")
    _events = _pool_event_log(
        [{"name": p["asg_name"], "type": p["instance_type"], "pool_id": p["pool_id"]}
         for p in _pools if p.get("asg_name")]
    )
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "direct",
        "pools": _pools,
        "kpis": {
            "pool_count": len(_pools),
            "ready_now": sum(p["ready_now"] for p in _pools),
            "warm": sum(p["warm_size"] for p in _pools),
            "hot_insvc": sum(p["hot_insvc"] for p in _pools),
        },
        "series": _series,   # cluster claim sparklines (claims/hot/collisions)
        "events": _events,   # ASG scaling-activity event log (typed, time-sorted)
        "control": _pool_control_health(window_minutes, period_seconds),  # Phase 4
    }


def _apply_pool_stack_names(pools_snapshot) -> None:
    """Resolve stack_id -> friendly stack_name on a pool snapshot. MUST run in a
    Flask app/request context: the snapshot itself is built in a gevent section
    greenlet that has no app context, so the SoftwareStacks ORM read is done
    here (post-collection, in the request greenlet). Best-effort -- leaves the
    id in place on any failure."""
    try:
        _pools = (pools_snapshot or {}).get("pools") or []
        _ids = [
            int(i) for i in {p.get("stack_id") for p in _pools if p.get("stack_id")}
            if str(i).isdigit()
        ]
        if not _ids:
            return
        from models import SoftwareStacks

        _names = {
            str(_s.id): _s.stack_name
            for _s in SoftwareStacks.query.filter(SoftwareStacks.id.in_(_ids)).all()
        }
        for _p in _pools:
            _n = _names.get(str(_p.get("stack_id")))
            if _n:
                _p["stack_name"] = _n
    except Exception as _err:  # noqa: BLE001 - friendly label is cosmetic
        logger.warning("dcv_overview: stack name resolve failed: %s", _err)


def get_pool_snapshot(window_minutes: int = 60, period_seconds: int = 300) -> Dict[str, Any]:
    """Provider seam for the Pools tab. v1 -> direct live reads. v2 will read a
    Valkey snapshot (reconciler-as-collector) with read-through fallback to
    _build_pool_snapshot_direct() under a staleness guard -- same contract, so
    the swap is invisible to the UI (see docs/VDIPooling.md)."""
    return _build_pool_snapshot_direct(window_minutes, period_seconds)


@admin_cluster_status_dcv_overview.route(
    "/admin/cluster_status/dcv_pools", methods=["GET"]
)
@login_required
@admin_only
def dcv_pools():
    """JSON point-in-time pool snapshot powering the Pools tab + its ~60s
    in-place refresh poll. Frozen contract: {available, generated_at, source,
    pools[], kpis{}, series{}, events[]}."""
    _warg = (request.args.get("window") or _DEFAULT_WINDOW).lower()
    if _warg not in _WINDOW_PRESETS:
        _warg = _DEFAULT_WINDOW
    _w = _WINDOW_PRESETS[_warg]
    _snap = get_pool_snapshot(_w["minutes"], _w["period_seconds"])
    _apply_pool_stack_names(_snap)
    return jsonify(_snap)


@admin_cluster_status_dcv_overview.route(
    "/admin/cluster_status/dcv_overview", methods=["GET"]
)
@login_required
@admin_only
def index():
    high_scale = _is_high_scale_enabled()

    # Time window: query string ?window=1h|6h|24h|7d|30d|90d. Period
    # auto-chosen for each preset to balance granularity vs CW's 1440
    # datapoints-per-query limit and storage-resolution retention.
    _window_arg = (request.args.get("window") or _DEFAULT_WINDOW).lower()
    if _window_arg not in _WINDOW_PRESETS:
        _window_arg = _DEFAULT_WINDOW
    _w = _WINDOW_PRESETS[_window_arg]
    _window_minutes = _w["minutes"]
    _period_seconds = _w["period_seconds"]
    _window_label = _w["label"]

    def _humanize_period(s):
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s // 60}m"
        return f"{s // 3600}h"
    _period_label = _humanize_period(_period_seconds)

    if high_scale:
        # Fan out the independent snapshots concurrently with a per-section
        # budget so a single slow AWS/CloudWatch call can't stall the page
        # past the ALB idle timeout. Each section's elapsed time is logged.
        _secs = _run_sections({
            "broker": (_broker_snapshot, {}),
            "metrics": (_cloudwatch_series, {"window_minutes": _window_minutes, "period_seconds": _period_seconds}),
            "infra": (_infrastructure_snapshot, {"window_minutes": _window_minutes, "period_seconds": _period_seconds}),
            "screenshots": (_screenshot_snapshot, {"window_minutes": _window_minutes, "period_seconds": _period_seconds}),
            "streaming": (_streaming_snapshot, {"window_minutes": _window_minutes, "period_seconds": _period_seconds}),
            "pools": (get_pool_snapshot, {"window_minutes": _window_minutes, "period_seconds": _period_seconds}),
        })
        broker = _secs["broker"]
        metrics = _secs["metrics"]
        infra = _secs["infra"]
        screenshots = _secs["screenshots"]
        streaming = _secs["streaming"]
        pools = _secs["pools"]
        _apply_pool_stack_names(pools)  # ORM name resolve in request app context
    else:
        broker = {
            "available": False,
            "error": "DCV high-scale mode is disabled. Enable it via Config.dcv.high_scale to populate this dashboard.",
        }
        metrics = {"available": False, "error": "high-scale disabled"}
        infra = {"available": False, "error": "high-scale disabled"}
        screenshots = {"available": False, "error": "high-scale disabled"}
        streaming = {"available": False, "error": "high-scale disabled"}
        pools = {"available": False, "error": "high-scale disabled"}

    # Subtle per-load timing surfaced in the page header. Each section dict
    # already carries `_elapsed_s` (stamped by _timed_section). Total is the
    # slowest section, since the sections run concurrently. `timed_out` lists
    # any section that exceeded the per-section budget (retried on refresh).
    _sections_meta = {
        "broker": broker, "metrics": metrics, "infra": infra,
        "screenshots": screenshots, "streaming": streaming,
    }
    _sec_times = {n: (d.get("_elapsed_s") if Validators.is_dict(d) else None) for n, d in _sections_meta.items()}
    _valid_times = [t for t in _sec_times.values() if Validators.is_int(t) or Validators.is_float(t)]
    data_load = {
        "sections": _sec_times,
        "total_s": round(max(_valid_times), 2) if _valid_times else 0,
        "timed_out": [n for n, d in _sections_meta.items() if Validators.is_dict(d) and "timed out" in str(d.get("error") or "")],
    }

    # Default UX preferences: Infrastructure tab first, auto-refresh on.
    # Both can be overridden per-request via query string for power users
    # who want to pin a tab or kill auto-refresh from a saved URL.
    #   ?tab=sessions|infra
    #   ?refresh=on|off|0|1
    _allowed_tabs = ("infra", "sessions", "pools")
    _default_tab = (request.args.get("tab") or "infra").lower()
    if _default_tab not in _allowed_tabs:
        _default_tab = "infra"

    _refresh_arg = (request.args.get("refresh") or "").lower()
    if _refresh_arg in ("0", "off", "false", "no"):
        _auto_refresh_default = False
    elif _refresh_arg in ("1", "on", "true", "yes"):
        _auto_refresh_default = True
    else:
        _auto_refresh_default = True

    return render_template(
        "admin/cluster_status/dcv_overview.html",
        page="admin_cluster_status_dcv_overview",
        high_scale=high_scale,
        broker=broker,
        metrics=metrics,
        metrics_json=json.dumps(metrics, default=str),
        infra=infra,
        screenshots=screenshots,
        screenshots_json=json.dumps(screenshots, default=str),
        streaming=streaming,
        streaming_json=json.dumps(streaming, default=str),
        pools=pools,
        pools_json=json.dumps(pools, default=str),
        broker_namespace=_BROKER_NAMESPACE,
        data_load=data_load,
        cluster_id=_cluster_id() or "",
        default_tab=_default_tab,
        auto_refresh_default=_auto_refresh_default,
        window_key=_window_arg,
        window_label=_window_label,
        window_presets=_WINDOW_PRESETS,
        period_label=_period_label,
    )
