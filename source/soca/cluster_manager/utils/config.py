# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import logging
from datetime import datetime, timezone
from typing import Type, Optional, Any

from cachetools import TTLCache, cached

import utils.aws.boto3_wrapper as utils_boto3
from utils.cache.client import SocaCacheClient
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.settings.config_checks import SocaConfigKeyVerifier

logger = logging.getLogger("soca_logger")


# ---------------------------------------------------------------------------
# SSM ElastiCache ConfigSync constants
#
# When the feature flag is enabled, every SSM parameter under the cluster
# prefix is mirrored into a single Valkey HASH (one field per param leaf,
# field name = full SSM path, value = SSM Value). This unblocks O(1) path
# queries and removes ~390 SSM API calls per page render. See
# docs/SsmConfigSync.md.
# ---------------------------------------------------------------------------

# Relative hash key, FQDN-prefixed by SocaCacheClient.key_fqdn() at write time.
# The {configuration} hash tag forces Valkey to slot the live hash and the
# Flusher's :_new build key together so RENAME works in cluster mode.
_CONFIG_SYNC_HASH_KEY = "_cache_hashes/{configuration}"

# Reserved field that records when a full SSM walk last completed. Lets
# readers distinguish "hash never populated" from "walked, no params under
# this prefix". Values are ISO-8601 UTC strings.
_CONFIG_SYNC_SENTINEL_FIELD = "__meta:walk_complete_at"

# Prefix marking internal/reserved hash fields. Filtered out of path-query
# result dicts so callers never see synthetic fields.
_CONFIG_SYNC_RESERVED_FIELD_PREFIX = "__meta:"

# Feature flag -- runtime SSM mirror written by the CDK installer at deploy
# time. CDK-time companion: Config.services.ssm_elasticache_config_sync.enabled.
_CONFIG_SYNC_FLAG_KEY_REL = (
    "/configuration/services/ssm_elasticache_config_sync/enabled"
)


@cached(TTLCache(maxsize=4, ttl=60))
def _read_config_sync_flag(cluster_prefix: str) -> bool:
    """
    Read the SSM ElastiCache ConfigSync feature flag directly via boto3
    SSM, bypassing SocaConfig itself to avoid bootstrapping recursion
    (SocaConfig's get_value is the very thing the flag controls).

    Cached at module level for 60s so we don't issue an SSM call per
    SocaConfig() instantiation. A flag toggle takes effect within 60s
    on each worker.

    Defaults to False on missing key or any error -- safe fallback to
    the legacy code path. CDK installer writes True (dev cycle) /
    True at GA when DCV HS is enabled (auto-enable rule).
    """
    flag_key = f"{cluster_prefix}{_CONFIG_SYNC_FLAG_KEY_REL}"
    try:
        ssm = utils_boto3.get_boto(service_name="ssm").message
        resp = ssm.get_parameter(Name=flag_key)
        raw = resp["Parameter"]["Value"]
        return str(raw).strip().lower() in {"true", "1", "yes", "on"}
    except Exception as err:
        # Missing key (during initial install or pre-flag clusters) is
        # the expected case. Log at debug, default to False.
        logger.debug(
            f"ssm_elasticache_config_sync flag not readable at {flag_key}, "
            f"defaulting to False: {err}"
        )
        return False


def _config_sync_iso_now() -> str:
    """Reserved-field timestamp helper. Centralized so format stays
    consistent across writers (path-walk populator, Lambda, flusher)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SocaConfig:
    def __init__(
        self,
        key: str,
        parameter_name_prefix: Optional[
            str
        ] = f"/edh/{os.environ.get('EDH_CLUSTER_ID')}",
        cache_admin: bool = True,
    ):
        self._parameter_name_prefix = parameter_name_prefix
        # Enforce "/" at the beginning of the parameter key name
        self._parameter_name = key if key.startswith("/") else f"/{key}"

        # _full_parameter_name is the parameter key name + specified prefix
        if self._parameter_name.startswith(self._parameter_name_prefix):
            self._full_parameter_name = self._parameter_name
        else:
            self._full_parameter_name = (
                f"{ self._parameter_name_prefix}{self._parameter_name}"
            )

        # _parameter_name_no_prefix is parameter key name without prefix
        self._parameter_name_no_prefix = self._full_parameter_name.split(
            self._parameter_name_prefix
        )[-1]

        # Return whether the parameter key is an entire hierarchy
        self._is_path = True if self._full_parameter_name.endswith("/") else False

        self.cache_admin = cache_admin

        # Init client
        self._cache_client = SocaCacheClient(is_admin=self.cache_admin)
        self._ssm_client = utils_boto3.get_boto(service_name="ssm").message

        # SSM ElastiCache ConfigSync feature flag. Read once per instance,
        # backed by a 60s module-level TTLCache so per-request SocaConfig
        # construction does not pay an SSM round-trip per call.
        self._config_sync_enabled = _read_config_sync_flag(
            self._parameter_name_prefix
        )

    # amazonq-ignore-next-line
    def get_value(
        self,
        cache_result: Optional[bool] = True,  # choose whether to cache the value
        return_as: Optional[Type] = str,  # return result as specific type
        full_key_name: Optional[bool] = False,  # include parameter_name_prefix if True
        default: Optional[Any] = None,  # Return default value if not set
        allow_unknown_key: Optional[
            bool
        ] = False,  # If set to True, will not trigger a SocaError if key does not exist
    # amazonq-ignore-next-line
    ) -> [Any, None]:
        logger.debug(
            f"Trying to retrieve parameter {self._full_parameter_name}, is_path {self._is_path}"
        )
        _cache_enabled = self._cache_client.is_enabled()

        # SSM ElastiCache ConfigSync dispatch.
        # When the feature flag is on AND cache is enabled, route through the
        # HASH-based read path. Otherwise, run the legacy per-key code below
        # verbatim. The flag-on path still falls back to SSM on a hash miss
        # and self-populates -- behaviour is a strict superset of legacy.
        if self._config_sync_enabled and _cache_enabled.success:
            return self._get_value_via_config_sync_hash(
                cache_result=cache_result,
                return_as=return_as,
                full_key_name=full_key_name,
                default=default,
                allow_unknown_key=allow_unknown_key,
            )

        # First, we check if the key we are looking for does not already exist in our cache
        # This only works if they key is not a path
        if not self._is_path:
            if _cache_enabled.success:
                logger.debug(f"Checking if {self._full_parameter_name} exist in Cache")
                _key_in_redis = self._cache_client.get(key=self._full_parameter_name)
                if _key_in_redis.success:
                    logger.debug(
                        f"{self._full_parameter_name} exist in cache. Retrieving value"
                    )
                    _result = SocaCastEngine(_key_in_redis.message).cast_as(
                        expected_type=return_as
                    )
                    if not _result.success:
                        return SocaError.CAST_ERROR(
                            helper=f"Value retrieved on cache but could not cast {_key_in_redis.message} as {return_as} because of {_result.get('message')}"
                        )
                    else:
                        return SocaResponse(success=True, message=_result.message)
                else:
                    logger.debug(f"{self._full_parameter_name} does NOT exist in cache")
            else:
                logger.info("Cache is not enabled, querying SSM directly")

        # If key is not in cache, query SSM
        try:
            if self._is_path:
                _output = {}
                _paginator = self._ssm_client.get_paginator("get_parameters_by_path")
                _response_paginator = _paginator.paginate(
                    Path=self._full_parameter_name, Recursive=True
                )
                if return_as:
                    logger.debug(
                        f"return_as is set but ignored as SSM key ({self._full_parameter_name}) is path and will always return a dict"
                    )

                # amazonq-ignore-next-line
                if default is not None:
                    logger.debug(
                        f"default is set but ignored as SSM key ({self._full_parameter_name}) is path and will always return a dict"
                    )

                for _page in _response_paginator:
                    parameters = _page["Parameters"]
                    if not parameters:
                        logger.info(
                            f"{self._full_parameter_name} not found. Add '/' at the end if this key is a hierarchy tree"
                        )
                        if default is not None:
                            return SocaResponse(success=True, message=default)
                        else:
                            return SocaResponse(success=False, message={})

                    for _entry in parameters:
                        if cache_result:
                            if (
                                self.cache_admin is True
                                and _cache_enabled.success is True
                            ):
                                logger.debug(f"Caching {_entry['Name']} ...  ")
                                self._cache_client.set(
                                    key=_entry["Name"], value=_entry["Value"]
                                )
                            else:
                                logger.debug(
                                    "cache_result is True but cache_admin is False or cache is not enabled, data won't be cached"
                                )

                        _output[
                            (
                                _entry["Name"]
                                if full_key_name
                                else _entry["Name"].split(self._parameter_name_prefix)[
                                    -1
                                ]
                            )
                        ] = _entry["Value"]

                _auto_cast_output = SocaCastEngine(data=_output).autocast(
                    preserve_key_name=full_key_name
                )
                if _auto_cast_output.get("success") is True:
                    _output = _auto_cast_output.get("message")
                else:
                    logger.info("Unable to autocast output, will default to standard result")
                return SocaResponse(success=True, message=_output)
            else:
                _response = self._ssm_client.get_parameter(
                    Name=self._full_parameter_name
                )
                _key_name = _response.get("Parameter").get("Name")
                _key_value = _response.get("Parameter").get("Value")
                if cache_result:
                    if self.cache_admin is True and _cache_enabled.success is True:
                        logger.debug(f"Caching {_key_name} ...  ")
                        self._cache_client.set(
                            key=_key_name,
                            value=_key_value,
                        )
                    else:
                        logger.debug(
                            "cache_result is True but cache_admin is False or cache is not enabled, data won't be cached"
                        )

                _result = SocaCastEngine(_key_value).cast_as(expected_type=return_as)
                if not _result.success:
                    return SocaError.CAST_ERROR(
                        helper=f"Could not cast {_key_value} as {return_as} due to {_result.get('message')}"
                    )
                else:
                    return SocaResponse(success=True, message=_result.message)

        except self._ssm_client.exceptions.ParameterNotFound:
            if default is not None:
                return SocaResponse(success=True, message=default)
            else:
                if allow_unknown_key:
                    # Will not trigger a SocaError
                    return SocaResponse(success=False, message="Key does not exist")
                return SocaError.AWS_API_ERROR(
                    service_name="ssm_parameterstore",
                    helper=f"{self._full_parameter_name} not found. Add '/' at the end if this key is a hierarchy tree",
                )

        except Exception as e:
            if default is not None:
                return SocaResponse(success=True, message=default)
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="ssm_parameterstore",
                    helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {e}",
                )

    # ------------------------------------------------------------------
    # SSM ElastiCache ConfigSync: HASH-based read paths
    #
    # Reached only when self._config_sync_enabled is True AND the cache
    # client is enabled. Falls back to SSM on hash miss/empty and
    # self-populates the hash. Result shape and semantics match the
    # legacy code path one-for-one: SocaCastEngine.cast_as for single
    # keys, autocast for path-query dicts, prefix-stripping per
    # full_key_name, default-on-not-found, allow_unknown_key, etc.
    # ------------------------------------------------------------------

    def _get_value_via_config_sync_hash(
        self,
        cache_result,
        return_as,
        full_key_name,
        default,
        allow_unknown_key,
    ):
        if self._is_path:
            return self._config_sync_path_read(
                cache_result=cache_result,
                full_key_name=full_key_name,
                default=default,
            )
        return self._config_sync_single_read(
            cache_result=cache_result,
            return_as=return_as,
            default=default,
            allow_unknown_key=allow_unknown_key,
        )

    def _config_sync_cast_and_wrap(self, value, return_as):
        """Mirror legacy single-key cast handling so the new path is a
        drop-in replacement."""
        _result = SocaCastEngine(value).cast_as(expected_type=return_as)
        if not _result.success:
            return SocaError.CAST_ERROR(
                helper=(
                    f"Value retrieved on cache but could not cast {value} as "
                    f"{return_as} because of {_result.get('message')}"
                )
            )
        return SocaResponse(success=True, message=_result.message)

    def _config_sync_single_read(
        self, cache_result, return_as, default, allow_unknown_key
    ):
        """HGET hash field. Miss -> SSM GetParameter -> HSET back."""
        _hit = self._cache_client.hget(
            _CONFIG_SYNC_HASH_KEY, self._full_parameter_name
        )
        if _hit.success:
            return self._config_sync_cast_and_wrap(_hit.message, return_as)

        # Miss. Fall back to SSM, write-back to hash if requested.
        try:
            _resp = self._ssm_client.get_parameter(Name=self._full_parameter_name)
            _value = _resp["Parameter"]["Value"]

            if cache_result and self.cache_admin:
                self._cache_client.hset(
                    _CONFIG_SYNC_HASH_KEY, self._full_parameter_name, _value
                )

            return self._config_sync_cast_and_wrap(_value, return_as)

        except self._ssm_client.exceptions.ParameterNotFound:
            if default is not None:
                return SocaResponse(success=True, message=default)
            if allow_unknown_key:
                return SocaResponse(success=False, message="Key does not exist")
            return SocaError.AWS_API_ERROR(
                service_name="ssm_parameterstore",
                helper=(
                    f"{self._full_parameter_name} not found. Add '/' at the "
                    f"end if this key is a hierarchy tree"
                ),
            )
        except Exception as e:
            if default is not None:
                return SocaResponse(success=True, message=default)
            return SocaError.AWS_API_ERROR(
                service_name="ssm_parameterstore",
                helper=(
                    f"Unknown error while trying to retrieve parameter "
                    f"{self._full_parameter_name} due to {e}"
                ),
            )

    def _config_sync_path_read(self, cache_result, full_key_name, default):
        """HGETALL hash + filter by self._full_parameter_name prefix.

        Falls through to SSM walk + hash population when:
        - hash is empty (never populated)
        - hash has no sentinel field (partial population, treat as stale)

        Returns prefix-stripped or full-key-name dict matching legacy
        path-query result shape; runs autocast over the dict like legacy.
        """
        _all_resp = self._cache_client.hgetall(_CONFIG_SYNC_HASH_KEY)
        _all = _all_resp.message if _all_resp.success else {}
        _has_sentinel = _CONFIG_SYNC_SENTINEL_FIELD in _all

        if _all and _has_sentinel:
            _output = {}
            for _name, _value in _all.items():
                if _name.startswith(_CONFIG_SYNC_RESERVED_FIELD_PREFIX):
                    continue
                if not _name.startswith(self._full_parameter_name):
                    continue
                _output[
                    _name
                    if full_key_name
                    else _name.split(self._parameter_name_prefix)[-1]
                ] = _value

            if not _output:
                # Hash populated, no params under this subtree.
                if default is not None:
                    return SocaResponse(success=True, message=default)
                return SocaResponse(success=False, message={})

            # autocast(preserve_key_name=False) (the default) strips the
            # cluster prefix from dict keys -- which is what we want for
            # the default full_key_name=False case. When the caller asks
            # for full_key_name=True, we MUST pass preserve_key_name=True
            # or autocast undoes the choice we made above. Same fix is
            # applied to the legacy path-query branch.
            _auto = SocaCastEngine(data=_output).autocast(
                preserve_key_name=full_key_name
            )
            if _auto.get("success") is True:
                _output = _auto.get("message")
            return SocaResponse(success=True, message=_output)
        return self._config_sync_populate_and_return(
            cache_result=cache_result,
            full_key_name=full_key_name,
            default=default,
        )

    def _config_sync_populate_and_return(
        self, cache_result, full_key_name, default
    ):
        """Walk SSM by self._full_parameter_name (prefix or full key),
        write everything observed to the hash in a single batch + set
        the sentinel timestamp, then return the prefix-scoped subset
        in legacy shape.

        Note: this walks the SUB-prefix the caller asked for, not the
        full cluster prefix. The Lambda is responsible for full-cluster
        backfill. Per-prefix lazy populate keeps cold-path latency
        bounded to the caller's actual scope."""
        _output = {}
        _full_dump = {}

        try:
            _paginator = self._ssm_client.get_paginator(
                "get_parameters_by_path"
            )
            _pages = _paginator.paginate(
                Path=self._full_parameter_name, Recursive=True
            )

            for _page in _pages:
                for _entry in _page.get("Parameters", []):
                    _full_dump[_entry["Name"]] = _entry["Value"]
                    _output[
                        _entry["Name"]
                        if full_key_name
                        else _entry["Name"].split(self._parameter_name_prefix)[-1]
                    ] = _entry["Value"]

            if cache_result and self.cache_admin and _full_dump:
                # Only a full-cluster walk may stamp the completion sentinel; a scoped sub-prefix populate must not mark the hash complete
                if self._full_parameter_name.rstrip("/") == self._parameter_name_prefix.rstrip("/"):
                    _full_dump[_CONFIG_SYNC_SENTINEL_FIELD] = _config_sync_iso_now()
                _hset_resp = self._cache_client.hset_multi(
                    _CONFIG_SYNC_HASH_KEY, _full_dump
                )
                if not _hset_resp.success:
                    logger.warning(
                        f"ConfigSync: hash population failed for "
                        f"{self._full_parameter_name}: {_hset_resp.message}"
                    )

            if not _output:
                if default is not None:
                    return SocaResponse(success=True, message=default)
                return SocaResponse(success=False, message={})

            _auto = SocaCastEngine(data=_output).autocast(
                preserve_key_name=full_key_name
            )
            if _auto.get("success") is True:
                _output = _auto.get("message")
            return SocaResponse(success=True, message=_output)

        except Exception as e:
            if default is not None:
                return SocaResponse(success=True, message=default)
            return SocaError.AWS_API_ERROR(
                service_name="ssm_parameterstore",
                helper=(
                    f"ConfigSync populate failed for "
                    f"{self._full_parameter_name}: {e}"
                ),
            )

    def get_value_history(self, sort: Optional[str] = "desc") -> dict:
        _history = {}
        _sort = sort if sort in ["desc", "asc"] else "desc"  # Desc = newest first

        try:
            # amazonq-ignore-next-line
            _current_parameter_key_value = self.get_value()
            if _current_parameter_key_value.success:
                _get_parameter_history = self._ssm_client.get_parameter_history(
                    Name=self._full_parameter_name
                )
                if _get_parameter_history.get("Parameters"):
                    for _version in _get_parameter_history.get("Parameters"):
                        _history[_version["Version"]] = {
                            "Version": _version["Version"],
                            "Value": _version["Value"],
                            "LastModifiedDate": _version["LastModifiedDate"],
                        }

                if (
                    _get_parameter_history.get("ResponseMetadata").get("HTTPStatusCode")
                    == 200
                ):
                    # amazonq-ignore-next-line
                    if _sort == "asc":
                        return SocaResponse(
                            success=True,
                            message={k: _history[k] for k in sorted(_history)},
                        )
                    else:
                        # desc
                        return SocaResponse(
                            success=True,
                            message={
                                k: _history[k] for k in sorted(_history, reverse=True)
                            },
                        )
                else:
                    return SocaError.AWS_API_ERROR(
                        service_name="ssm_parameterstore",
                        helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {_get_parameter_history}",
                    )
            else:
                return SocaResponse(
                    success=False, message=_current_parameter_key_value.message
                )

        except Exception as e:
            return SocaError.AWS_API_ERROR(
                service_name="ssm_parameterstore",
                helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {e}",
            )

    def set_value(self, value: str) -> [str, bool]:
        _is_valid_value = SocaConfigKeyVerifier(
            key=self._parameter_name_no_prefix
        ).check(value=value)
        if not _is_valid_value.success:
            return _is_valid_value
        try:
            # amazonq-ignore-next-line
            _current_parameter_key_value = self.get_value().get("message")
            if _current_parameter_key_value == value:
                return SocaResponse(
                    success=False,
                    message=f"Value of {self._full_parameter_name} is already {value}",
                )
            else:
                _update_key = self._ssm_client.put_parameter(
                    Name=self._full_parameter_name,
                    Value=value,
                    Type="String",
                    Overwrite=True,
                )
                if _update_key.get("ResponseMetadata").get("HTTPStatusCode") == 200:
                    _cache_enabled = self._cache_client.is_enabled()
                    if self.cache_admin and _cache_enabled.success:
                        self._cache_client.set(key=self._full_parameter_name, value=value)
                        # SSM ElastiCache ConfigSync write-through: also
                        # mirror into the cluster config hash. The Lambda
                        # will see the same ParameterChange event and HSET
                        # again -- idempotent. Doing it here closes the
                        # write-to-read race for in-process callers that
                        # read the value back immediately.
                        if self._config_sync_enabled:
                            self._cache_client.hset(
                                _CONFIG_SYNC_HASH_KEY,
                                self._full_parameter_name,
                                value,
                            )
                    return SocaResponse(success=True, message="Key update successfully")
                else:
                    return SocaError.AWS_API_ERROR(
                        service_name="ssm_parameterstore",
                        helper=f"Unknown error while trying to update parameter {_update_key}",
                    )

        except Exception as e:
            logger.error(
                f"Error: Unknown error while trying to retrieve parameter {self._full_parameter_name}. Trace: {e}"
            )
            return SocaError.AWS_API_ERROR(
                service_name="ssm_parameterstore",
                helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {e}",
            )
