# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scheduled task: purge expired and revoked tokens from api_tokens.

Session tokens rotate every hour, leaving revoked rows behind. User tokens
eventually expire. This task deletes all tokens that are no longer active
(revoked OR expired) and older than a retention window, keeping the table
bounded.

Retention default: 48 hours after expiry/revocation (enough for audit
cross-reference). Configurable via SocaConfig key:
  /configuration/Security/token_cleanup_retention_hours
"""

import logging
from datetime import datetime, timedelta, timezone

from models import db, ApiTokens
from utils.config import SocaConfig

logger = logging.getLogger("scheduled_tasks_cleanup_expired_tokens")

DEFAULT_RETENTION_HOURS = 48


def _retention_hours() -> int:
    try:
        resp = SocaConfig(
            key="/configuration/Security/token_cleanup_retention_hours"
        ).get_value(default=str(DEFAULT_RETENTION_HOURS), allow_unknown_key=True)
        raw = resp.message if resp.success else str(DEFAULT_RETENTION_HOURS)
        hours = int(raw)
    except (ValueError, TypeError, AttributeError) as err:
        logger.warning(
            f"Could not parse token_cleanup_retention_hours; "
            f"falling back to {DEFAULT_RETENTION_HOURS}h: {err}"
        )
        return DEFAULT_RETENTION_HOURS

    if hours < 1:
        return 1
    if hours > 720:
        logger.warning(f"Retention {hours}h exceeds 720h max; clamping")
        return 720
    return hours


def cleanup_expired_tokens(app) -> None:
    """
    Delete api_tokens rows that are expired or revoked beyond the retention window.
    Runs every 6 hours via APScheduler.
    """
    with app.app_context():
        hours = _retention_hours()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        try:
            # Delete revoked tokens older than cutoff
            deleted_revoked = (
                db.session.query(ApiTokens)
                .filter(ApiTokens.revoked_at.isnot(None))
                .filter(ApiTokens.revoked_at < cutoff)
                .delete(synchronize_session=False)
            )

            # Delete expired tokens older than cutoff
            deleted_expired = (
                db.session.query(ApiTokens)
                .filter(ApiTokens.revoked_at.is_(None))
                .filter(ApiTokens.expires_at < cutoff)
                .delete(synchronize_session=False)
            )

            db.session.commit()
            total = deleted_revoked + deleted_expired
            if total:
                logger.info(
                    f"cleanup_expired_tokens: pruned {total} tokens "
                    f"({deleted_revoked} revoked, {deleted_expired} expired) "
                    f"older than {hours}h"
                )
            else:
                logger.debug("cleanup_expired_tokens: nothing to prune")
        except Exception as err:
            db.session.rollback()
            logger.error(f"cleanup_expired_tokens failed: {err}")
