# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Per-user daily token usage tracking and rate limiting via DynamoDB.
"""

from __future__ import annotations

import logging
import time
from datetime import date
from utils.validators import Validators

from utils.error import SocaError
from utils.config import SocaConfig
from utils.response import SocaResponse
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")


class SocaAiAssistantTokenUsage:
    """Per-user daily token usage tracking with cached DDB client and limit.

    Instantiate once per request with a username. Caches the DDB client and
    the configured daily limit so repeated calls (check + increment) don't
    re-fetch them.
    """

    def __init__(self, username: str):
        self._username = username
        self._client = None
        self._limit = None
        self._cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message
        self._token_usage_ddb_table_name = f"{self._cluster_id}-ai-assistant.token-daily-usage"

    def _get_client(self):
        if self._client is None:
            _resp = utils_boto3.get_boto(service_name="dynamodb")
            if _resp.get("success") is False:
                return None
            self._client = _resp.get("message")
        return self._client

    def _get_limit(self) -> SocaResponse:
        if self._limit is None:
            _resp = SocaConfig(
                key="/configuration/AIAssistant/allowed_daily_tokens_per_user"
            ).get_value(return_as=int)
            if _resp.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Failed to get daily token limit: {_resp.get('message')}"
                )
            self._limit = _resp.get("message")
        return SocaResponse(success=True, message=self._limit)

    @property
    def limit(self) -> SocaResponse:
        return self._get_limit()

    def get_current_usage(self) -> SocaResponse:
        """Get the current daily token count for the user. Creates the item with 0 if it doesn't exist."""
        client = self._get_client()
        if client is None:
            return SocaError.GENERIC_ERROR(helper="Failed to connect to DynamoDB")

        today = date.today().isoformat()
        expires_at = int(time.time()) + (90 * 86400)

        try:
            response = client.update_item(
                TableName=self._token_usage_ddb_table_name,
                Key={
                    "username": {"S": self._username},
                    "date": {"S": today},
                },
                UpdateExpression="SET total_tokens = if_not_exists(total_tokens, :zero), expires_at = if_not_exists(expires_at, :ttl)",
                ExpressionAttributeValues={
                    ":zero": {"N": "0"},
                    ":ttl": {"N": str(expires_at)},
                },
                ReturnValues="ALL_NEW",
            )
            used = int(response["Attributes"]["total_tokens"]["N"])
            return SocaResponse(success=True, message=used)
        except Exception as e:
            logger.error(f"Failed to get AI token usage for {self._username}: {e}")
            return SocaError.GENERIC_ERROR(helper=f"Failed to get token usage: {e}")

    def verify_quota_available(self) -> SocaResponse:
        """Pre-flight check. Returns success=True if allowed, success=False if limit exceeded or error."""
        client = self._get_client()
        if client is None:
            return SocaError.GENERIC_ERROR(
                helper="Failed to connect to DynamoDB for token usage tracking"
            )

        limit_resp = self._get_limit()
        if limit_resp.get("success") is False:
            return limit_resp

        limit = limit_resp.get("message")

        today = date.today().isoformat()
        try:
            response = client.get_item(
                TableName=self._token_usage_ddb_table_name,
                Key={
                    "username": {"S": self._username},
                    "date": {"S": today},
                },
                ProjectionExpression="total_tokens",
            )
            item = response.get("Item")
            if item:
                current = int(item["total_tokens"]["N"])
                if Validators.is_int_greater_or_equal(current, limit):
                    return SocaError.GENERIC_ERROR(
                        helper=f"Daily AI token limit exceeded ({limit:,} tokens for {self._username}). Please try again tomorrow."
                    )
                else:
                    logger.info(
                        f"Current AI token usage for {self._username}: {current:,}/{limit:,} tokens"
                    )
                    return SocaResponse(success=True, message=f"Token usage within limit for {self._username}")
            else:
                logger.info(
                    f"No token usage record found for {self._username} today, data will automatically be created on first request."
                )
                return SocaResponse(success=True, message=f"No token usage record found for {self._username} today, data will automatically be created on first request.")
        except Exception as e:
            logger.error(f"Failed to check AI token usage for {self._username}: {e}")
            return SocaError.GENERIC_ERROR(
                helper=f"Failed to check AI token usage for {self._username}"
            )

       

    def increment(self, tokens_used: int) -> SocaResponse:
        """Increment the user's daily token counter.

        Args:
            tokens_used: Number of tokens to add (input + output).

        Returns:
            SocaResponse with success=True (message contains new total),
            or success=False if the update fails.
        """
        client = self._get_client()
        if client is None:
            return SocaError.GENERIC_ERROR(
                helper="Failed to get DynamoDB client for token usage tracking"
            )

        today = date.today().isoformat()
        expires_at = int(time.time()) + (90 * 86400)

        try:
            response = client.update_item(
                TableName=self._token_usage_ddb_table_name,
                Key={
                    "username": {"S": self._username},
                    "date": {"S": today},
                },
                UpdateExpression="SET total_tokens = if_not_exists(total_tokens, :zero) + :inc, expires_at = :ttl",
                ExpressionAttributeValues={
                    ":inc": {"N": str(tokens_used)},
                    ":zero": {"N": "0"},
                    ":ttl": {"N": str(expires_at)},
                },
                ReturnValues="UPDATED_NEW",
            )
            new_total = int(response["Attributes"]["total_tokens"]["N"])
            return SocaResponse(success=True, message=new_total)

        except Exception as e:
            logger.error(f"Failed to update AI token usage for {self._username}: {e}")
            return SocaError.GENERIC_ERROR(helper=f"Token usage tracking failed: {e}")
