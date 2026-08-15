# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import opensearchpy
from utils.error import SocaError
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.validators import Validators
from utils.aws.boto3_wrapper import (
    get_boto,
    get_boto_session_credentials,
    get_boto_session_region,
)
from opensearchpy import OpenSearch, RequestsHttpConnection

from requests_aws4auth import AWS4Auth
from typing import Optional
import os
import sys

logger = logging.getLogger("soca_logger")


def is_initialized(func):
    def wrapper(self, *args, **kwargs):
        if self._conn is None:
            return SocaError.ANALYTICS_ERROR(
                helper="AWS OpenSearch connection not initialized, call SocaAnalyticsClient().initialize() first"
            )
        return func(self, *args, **kwargs)

    return wrapper


class SocaAnalyticsClient:
    def __init__(
        self,
        endpoint: Optional[str] = SocaConfig(key="/configuration/Analytics/endpoint")
        .get_value()
        .get("message"),
        engine: Optional[str] = SocaConfig(key="/configuration/Analytics/engine")
        .get_value()
        .get("message"),
    ):

        self._endpoint = endpoint
        self._engine = engine
        self._conn = None
        # OpenSearch Serverless (AOSS) needs SigV4 signing with the "aoss"
        # service and does not support the scroll API (see search()).
        _engine_cast = SocaCastEngine(engine or "").cast_as(str)
        self._is_serverless = (
            _engine_cast.success
            and _engine_cast.message.lower()
            in {
                "opensearch_serverless",
                "aoss_serverless",
            }
        )

        logger.debug(
            f"Initializing SocaAnalyticsClient engine {self._engine} - endpoint {self._endpoint}"
        )

    @staticmethod
    def is_enabled():
        logger.debug("Checking if Analytics is enabled")
        if (
            SocaConfig(key="/configuration/Analytics/enabled")
            .get_value(return_as=bool)
            .get("message")
            is True
        ):
            return SocaResponse(success=True, message="Analytics is enabled")
        else:
            return SocaResponse(
                success=False, message="Analytics is not enabled on this environment"
            )

    def initialize(
        self,
        headers: dict = {"Content-Type": "application/json"},
        use_ssl: bool = True,
        verify_certs: bool = True,
        ssl_assert_hostname: bool = False,
        ssl_show_warn: bool = False,
        port: int = 443,
    ) -> SocaResponse:

        logger.debug(
            f"Initializing Analytics Client {self._engine} endpoint {self._endpoint}"
        )
        if self.is_enabled().get("success") is False:
            return SocaResponse(
                success=False, message="Analytics is not enabled on this environment"
            )

        _session_region = get_boto_session_region()
        if _session_region.success:
            _region = _session_region.message
        else:
            return SocaError.ANALYTICS_ERROR(helper=_session_region.message)

        _session_credentials = get_boto_session_credentials()
        if _session_credentials.success:
            _temporary_credentials = _session_credentials.message
            # AOSS data-plane requests are signed against the "aoss" service;
            # managed OpenSearch uses "es".
            _service = "aoss" if self._is_serverless else "es"
            _awsauth = AWS4Auth(
                _temporary_credentials.access_key,
                _temporary_credentials.secret_key,
                _region,
                _service,
                session_token=_temporary_credentials.token,
            )
        else:
            return SocaError.ANALYTICS_ERROR(helper=_session_credentials.message)

        # Currently only support AWS4Auth, in the future we could add more HTTP Auth mechanism
        # Change _http_auth to your required Auth if needed
        _http_auth = _awsauth
        try:
            if self._engine in {
                "opensearch",
                "opensearch_serverless",
                "aoss_serverless",
            }:
                # OpenSearch Serverless NextGen (scale-to-zero) collections idle
                # at 0 OCU; the first request after idle triggers a scale-up that
                # can take ~10-20s. The opensearchpy default read timeout is 10s,
                # so a cold-start write/read fails with ConnectionTimeout. Use a
                # longer timeout + retries (retry_on_timeout) so the first request
                # after idle succeeds instead of erroring. Harmless for always-on
                # managed OpenSearch / Classic AOSS.
                self._conn = OpenSearch(
                    [self._endpoint],
                    headers=headers,
                    http_auth=_http_auth,
                    use_ssl=use_ssl,
                    verify_certs=verify_certs,
                    ssl_assert_hostname=ssl_assert_hostname,
                    ssl_show_warn=ssl_show_warn,
                    connection_class=RequestsHttpConnection,
                    timeout=30,
                    max_retries=3,
                    retry_on_timeout=True,
                )
            else:
                logger.warning(f"Analytics Engine {self._engine} is unsupported")
                return SocaError.ANALYTICS_ERROR(helper=f"Analytics Engine {self._engine} is unsupported")

            logger.debug(f"Successfully initialized {self._engine} client")
            return SocaResponse(
                success=True, message=f"{self._engine} client initialized"
            )
        except Exception as err:
            return SocaError.ANALYTICS_ERROR(
                helper=f"Unable to initialize {self._engine} client due to {err}"
            )

    @is_initialized
    def index_exist(self, index: str) -> SocaResponse:
        try:
            if self._conn.indices.exists(index=index):
                return SocaResponse(success=True, message=f"Index {index} exists")
            else:
                return SocaResponse(
                    success=False, message=f"Index {index} does not exists"
                )
        except Exception as err:
            return SocaError.ANALYTICS_ERROR(
                helper=f"Unable to check index {index} due to {err}"
            )

    @is_initialized
    def index(self, index: str, body) -> SocaResponse:
        _index = self._conn.index(index=index, body=body)
        if _index.get("result", False) != "created":
            return SocaError.ANALYTICS_ERROR(
                helper=f"Unable to index {index} with body {body} due to {_index}"
            )
        else:
            logger.debug(f"Successfully indexed {index} with body {body}")
            return SocaResponse(success=True, message="Data indexed correctly")

    @is_initialized
    def search(
        self, index: str, body, scroll: str = "2m", size: int = 1000
    ) -> SocaResponse:
        logger.debug(
            f"Searching {index} with body {body},  scroll {scroll}, size {size}"
        )

        # OpenSearch Serverless (AOSS) does not support the scroll API, so we
        # paginate with from/size instead. Managed OpenSearch keeps scroll.
        if self._is_serverless:
            return self._search_paginated(index=index, body=body, size=size)

        try:
            _search = self._conn.search(
                index=index, scroll=scroll, size=size, body=body
            )
        except opensearchpy.exceptions.NotFoundError as err:
            return SocaError.ANALYTICS_ERROR(
                helper=f"OpenSearch Index {index} not found {err}"
            )
        except Exception as err:
            return SocaError.ANALYTICS_ERROR(helper=f"Unable to search due to {err}")

        try:
            sid = _search["_scroll_id"]
            scroll_size = _search["hits"]["total"]["value"]
            existing_entries = []

            while scroll_size > 0:
                data = [doc for doc in _search["hits"]["hits"]]

                for key in data:
                    existing_entries.append(key["_source"])

                response = self._conn.scroll(scroll_id=sid, scroll=scroll)
                sid = response["_scroll_id"]
                scroll_size = len(response["hits"]["hits"])

            return SocaResponse(success=True, message=existing_entries)

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.ANALYTICS_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )

    def _search_paginated(
        self, index: str, body, size: int = 1000, max_results: int = 10000
    ) -> SocaResponse:
        """
        from/size pagination for analytics engines that do not support the
        scroll API (OpenSearch Serverless / AOSS). Returns the same flat list
        of _source documents as the scroll-based path. Capped at max_results
        (OpenSearch's default index.max_result_window) to avoid unbounded
        deep pagination.
        """
        existing_entries = []
        _from = 0
        try:
            while _from < max_results:
                _search = self._conn.search(
                    index=index, body=body, size=size, from_=_from
                )
                _hits = _search["hits"]["hits"]
                if not _hits:
                    break
                for _doc in _hits:
                    existing_entries.append(_doc["_source"])
                if Validators.is_list_length_lower_than(_hits, size):
                    break
                _from += size
            else:
                logger.warning(
                    f"_search_paginated reached max_results={max_results} for "
                    f"index {index}; results may be truncated"
                )
            return SocaResponse(success=True, message=existing_entries)

        except opensearchpy.exceptions.NotFoundError as err:
            return SocaError.ANALYTICS_ERROR(
                helper=f"OpenSearch Index {index} not found {err}"
            )
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.ANALYTICS_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )
