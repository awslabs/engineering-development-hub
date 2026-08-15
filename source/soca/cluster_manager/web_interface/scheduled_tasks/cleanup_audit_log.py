# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scheduled task: prune the API audit log.

The ApiAuditLog table is append-only -- the middleware writes one row per
API request for security auditing and compliance purposes.

Retention is set to 720 hours (30 days) by default so that:
  - operators can investigate recent API usage patterns and security events;
  - the table remains bounded on long-lived clusters even when high-traffic
    environments generate thousands of requests per day.

Override via SocaConfig key /configuration/Security/api_audit_log_retention_hours
(integer >= 1). Cap at 2160h (90 days); larger values are clamped with a warning.

Pattern mirrors cleanup_dcv_event_log (same shape).
"""

import logging
from datetime import datetime, timedelta, timezone

from models import db, ApiAuditLog
from utils.config import SocaConfig

logger = logging.getLogger("scheduled_tasks_cleanup_audit_log")

DEFAULT_RETENTION_HOURS = 720  # 30 days
MAX_RETENTION_HOURS = 2160  # 90 days


def _retention_hours() -> int:
    """
    Resolve retention window from SocaConfig with safe defaults and clamp.
    Failures fall through to default rather than blocking the cleanup.
    """
    try:
        resp = SocaConfig(
            key="/configuration/Security/api_audit_log_retention_hours"
        ).get_value(default=str(DEFAULT_RETENTION_HOURS), allow_unknown_key=True)
        raw = resp.message if resp.success else str(DEFAULT_RETENTION_HOURS)
        hours = int(raw)
    except (ValueError, TypeError, AttributeError) as err:
        logger.warning(
            f"Could not parse api_audit_log_retention_hours; "
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


def cleanup_audit_log(app) -> None:
    """
    Delete ApiAuditLog rows older than the configured retention.
    Runs every 6 hours via the APScheduler IntervalTrigger registered in app.py.
    """
    with app.app_context():
        hours = _retention_hours()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        try:
            deleted = (
                db.session.query(ApiAuditLog)
                .filter(ApiAuditLog.timestamp < cutoff)
                .delete(synchronize_session=False)
            )
            db.session.commit()
            if deleted:
                logger.info(
                    f"cleanup_audit_log: pruned {deleted} rows older "
                    f"than {hours}h"
                )
            else:
                logger.debug(
                    f"cleanup_audit_log: no rows older than {hours}h"
                )
        except Exception as err:
            db.session.rollback()
            logger.error(f"cleanup_audit_log failed: {err}")
