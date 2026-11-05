# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional
import logging
import config
from requests import get, post, put, delete
from utils.response import SocaResponse
from requests.exceptions import Timeout, ConnectionError

logger = logging.getLogger("soca_logger")


class SocaHttpClient:
    def __init__(
        self,
        endpoint: str,
        timeout: int = 30,
        headers: Optional[dict] = None,
        verify: Optional[
            bool
        ] = False,  # set to True if the SSL certificate is trusted for your endpoint
        expected_return_codes: Optional[
            list
        ] = None,  # list of status code to consider the request as successful
        allow_redirects: Optional[bool] = True,
    ):
        if expected_return_codes is None:
            expected_return_codes = [200]

        self._timeout = timeout
        self._verify = verify
        if not endpoint.startswith(config.Config.FLASK_ENDPOINT):
            if endpoint.startswith("http://") or endpoint.startswith(
                "https://"
            ):  # external URL
                self._url_endpoint = endpoint
            else:
                if endpoint.startswith("/"):
                    self._url_endpoint = f"{config.Config.FLASK_ENDPOINT}{endpoint}"
                else:
                    self._url_endpoint = f"{config.Config.FLASK_ENDPOINT}/{endpoint}"
        else:
            self._url_endpoint = endpoint
        self._expected_return_codes = expected_return_codes
        self._headers = headers
        self._allow_redirects = allow_redirects

    def get(self, params: dict = None):
        return self.return_request("get", params=params)

    def post(self, data: dict = None, files: dict = None):
        return self.return_request("post", params=data, files=files)

    def put(self, data: dict = None, files: dict = None):
        return self.return_request(method="put", params=data, files=files)

    def delete(self, data: dict = None):
        return self.return_request(method="delete", params=data)

    def return_request(self, method: str, params: dict, files: dict = None):
        # Remove X-EDH-TOKEN, password etc from log
        _sanitize_log = [
            "X-EDH-TOKEN",
            "X-SOCA-TOKEN",
            "password",
            "passwd",
            "token",
            "auth",
            "csrf_token",
            "secret"
        ]
        _req_header_to_log = {}
        _req_data_to_log = {}
        if self._headers is not None:
            for k, v in self._headers.items():
                if k in _sanitize_log:
                    _req_header_to_log[k] = "<REDACTED>"
        if params is not None:
            for k, v in params.items():
                if k in _sanitize_log:
                    _req_data_to_log[k] = "<REDACTED>"

        logger.debug(
            f"Received {method} request {self._url_endpoint} headers: {_req_header_to_log}, attrs {_req_data_to_log}"
        )

        if method == "get":
            try:
                _req = get(
                    self._url_endpoint,
                    headers=self._headers,
                    params=params,
                    verify=self._verify,
                    allow_redirects=self._allow_redirects,
                    timeout=self._timeout,
                )
            except Timeout:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.TIMEOUT after {self._timeout} seconds. Endpoint may be down or unreachable.",
                    status_code=None,
                    request=None,
                )
            except ConnectionError:
                return SocaResponse(
                    success=False,
                    message="SocaHttpClient.CONNECTION_ERROR. Endpoint may be down or unreachable. Verify firewall and/or security groups.",
                    status_code=None,
                    request=None,
                )
            except Exception as err:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.ERROR: {err}",
                    status_code=None,
                    request=None,
                )

        elif method == "post":
            try:
                _req = post(
                    self._url_endpoint,
                    headers=self._headers,
                    data=params,
                    verify=self._verify,
                    allow_redirects=self._allow_redirects,
                    files=files,
                    timeout=self._timeout,
                )
            except Timeout:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.TIMEOUT after {self._timeout} seconds. Endpoint may be down or unreachable.",
                    status_code=None,
                    request=None,
                )
            except ConnectionError:
                return SocaResponse(
                    success=False,
                    message="SocaHttpClient.CONNECTION_ERROR. Endpoint may be down or unreachable. Verify firewall and/or security groups.",
                    status_code=None,
                    request=None,
                )
            except Exception as err:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.ERROR: {err}",
                    status_code=None,
                    request=None,
                ) 

        elif method == "put":
            try:
                _req = put(
                    self._url_endpoint,
                    headers=self._headers,
                    data=params,
                    verify=self._verify,
                    allow_redirects=self._allow_redirects,
                    files=files,
                    timeout=self._timeout,
                )
            except Timeout:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.TIMEOUT after {self._timeout} seconds. Endpoint may be down or unreachable.",
                    status_code=None,
                    request=None,
                )
            except ConnectionError:
                return SocaResponse(
                    success=False,
                    message="SocaHttpClient.CONNECTION_ERROR. Endpoint may be down or unreachable.",
                    status_code=None,
                    request=None,
                )
            except Exception as err:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.ERROR: {err}",
                    status_code=None,
                    request=None,
                )
        elif method == "delete":
            try:
                _req = delete(
                    self._url_endpoint,
                    headers=self._headers,
                    data=params,
                    verify=self._verify,
                    allow_redirects=self._allow_redirects,
                    timeout=self._timeout,
                )
            except Timeout:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.TIMEOUT after {self._timeout} seconds. Endpoint may be down or unreachable.",
                    status_code=None,
                    request=None,
                )
            except ConnectionError:
                return SocaResponse(
                    success=False,
                    message="SocaHttpClient.CONNECTION_ERROR. Endpoint may be down or unreachable.",
                    status_code=None,
                    request=None,
                )
            except Exception as err:
                return SocaResponse(
                    success=False,
                    message=f"SocaHttpClient.ERROR: {err}",
                    status_code=None,
                    request=None,
                )
        else:
            return SocaResponse(
                success=False,
                message=f"Unknown {method=}, must be get/post/put/delete",
                status_code=None,
                request=None,
            )

        if _req.status_code in self._expected_return_codes:
            logger.debug(
                f"Success: True as request status code {_req.status_code} is in the expected return codes {self._expected_return_codes}"
            )
            _success = True
        else:
            logger.debug(
                f"Success: False as request status code {_req.status_code} is not in the expected return codes {self._expected_return_codes}"
            )
            _success = False

        try:
            # if response is dict, check if "message" & "success" are present which is usually the response we get from SOCA endpoint ({success: xx, message:yy)}
            # Otherwise, endpoint is probably not SOCA, return response as is
            _json_response = _req.json()
            _message = _json_response.get("message", _json_response)
            if "success" in _json_response.keys():
                if _json_response.get("success") != _success:
                    logger.warning(
                        f"SocaHttpClient detected possible mismatch between request status:  success is {_success} as the response status code {_req.status_code}, expected success cde {self._expected_return_codes} but success key is present in response and is set to the opposite {_json_response}"
                    )
        except ValueError:
            logger.debug(
                "Received request is not a valid JSON, fallback returning as text"
            )
            _message = _req.text

        logger.debug(
            "Returning SocaResponse dict: success %s, message %s, status_code: %s, request: %s",
            _success, _message, _req.status_code, _req,
        )
        return SocaResponse(
            success=_success,
            message=_message,
            status_code=_req.status_code,
            request=_req,
        )
