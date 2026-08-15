# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scheduled task: prune the DCV session event log.

The DcvSessionEventLog table is append-only -- the controller writes one
row per accepted event from the relay. The SSE stream endpoint reads from
it for both live updates and the detail-page recent-history timeline.

Retention is set to 24 hours by default so that:
  - operators can reconcile a recent provisioning failure without rebuilding
    the timeline from CloudWatch logs;
  - the table remains bounded on long-lived clusters even when high-scale
    fleets emit thousands of events per day.

Override via SocaConfig key /configuration/DcvSessionEventLogRetentionHours
(integer >= 1). Cap at 168h (7d); larger values are clamped with a warning.

Pattern mirrors cleanup_dcv_event_nonces (planned, similar shape) and
clean_tmp_folders.
"""

import logging
from datetime import datetime, timedelta, timezone

from models import db, DcvSessionEventLog
from utils.config import SocaConfig

logger = logging.getLogger("scheduled_tasks_cleanup_dcv_event_log")

DEFAULT_RETENTION_HOURS = 24
MAX_RETENTION_HOURS = 168  # 7 days


def _retention_hours() -> int:
    """
    Resolve retention window from SocaConfig with safe defaults and clamp.
    Failures fall through to default rather than blocking the cleanup.
    """
    try:
        resp = SocaConfig(
            key="/configuration/DcvSessionEventLogRetentionHours"
        ).get_value(default=str(DEFAULT_RETENTION_HOURS), allow_unknown_key=True)
        raw = resp.message if resp.success else str(DEFAULT_RETENTION_HOURS)
        hours = int(raw)
    except (ValueError, TypeError, AttributeError) as err:
        logger.warning(
            f"Could not parse DcvSessionEventLogRetentionHours; "
            f"falling back to {DEFAULT_RETENTION_HOURS}h: {err}"
        )
        return DEFAULT_RETENTION_HOURS

    if hours < 1:
        logger.warning(
            f"Retention {hours}h below minimum; using 1h instead"
        )
        return 1
    if hours > MAX_RETENTION_HOURS:
        logger.warning(
            f"Retention {hours}h exceeds maximum; clamping to {MAX_RETENTION_HOURS}h"
        )
        return MAX_RETENTION_HOURS
    return hours


def cleanup_dcv_event_log(app) -> None:
    """
    Delete DcvSessionEventLog rows older than the configured retention.
    Runs hourly via the APScheduler IntervalTrigger registered in app.py.
    """
    with app.app_context():
        hours = _retention_hours()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        try:
            deleted = (
                db.session.query(DcvSessionEventLog)
                .filter(DcvSessionEventLog.received_at < cutoff)
                .delete(synchronize_session=False)
            )
            db.session.commit()
            if deleted:
                logger.info(
                    f"cleanup_dcv_event_log: pruned {deleted} rows older "
                    f"than {hours}h"
                )
            else:
                logger.debug(
                    f"cleanup_dcv_event_log: no rows older than {hours}h"
                )
        except Exception as err:
            db.session.rollback()
            logger.error(f"cleanup_dcv_event_log failed: {err}")
