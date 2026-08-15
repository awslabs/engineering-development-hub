# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import redis
from redis.credentials import CredentialProvider
import utils.aws.boto3_wrapper as utils_boto3
from utils.cache.iam_auth import make_cache_token_generator
from utils.error import SocaError
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from typing import Optional
import os
from cachetools import TTLCache, cached

logger = logging.getLogger("soca_logger")


class _ElastiCacheIAMProvider(CredentialProvider):
    """
    redis-py credential provider that mints a fresh ElastiCache IAM connect
    token on every new connection (redis-py calls ``get_credentials`` at connect
    time). No static password is ever stored; token minting is local SigV4
    signing off the refreshable instance/Lambda-role credentials.
    """

    def __init__(self, token_generator):
        self._token_generator = token_generator

    def get_credentials(self):
        return self._token_generator()


class SocaCacheClient:
    def __init__(
        self,
        cache_key_prefix: Optional[str] = f"/edh/{os.environ.get('EDH_CLUSTER_ID')}/",
        is_admin: Optional[bool] = False,
    ):
        self.cache_key_prefix = cache_key_prefix
        self.cache_config = get_cache_config(is_admin=is_admin).get("message")
        logger.debug(f"Building CacheClient for: {self.cache_config}")
        self.cache_client = self.cache_config.get("cache_client")
        self.cache_info = self.cache_config.get("cache_info")
        self.redis = (
            True if self.cache_info.get("engine") in {"valkey", "redis"} else False
        )
        self.ttl_long = self.cache_info.get("ttl/long")
        self.ttl_short = self.cache_info.get("ttl/short")

    def key_fqdn(self, key):
        if isinstance(key, bytes):
            _key = key.decode("utf-8")
        else:
            _key = key

        if _key.startswith(self.cache_key_prefix):
            _sanitized_key = _key
        else:
            _sanitized_key = (
                f"{self.cache_key_prefix}{_key[1:] if _key.startswith('/') else _key}"
            )

        return _sanitized_key

    def is_enabled(self):
        logger.debug("Checking if cache is enabled")
        _is_enabled = SocaCastEngine(data=self.cache_info.get("enabled")).cast_as(bool)
        # Validate cache_info.enabled is a valid bool and its value is True
        if _is_enabled.get("success") is True and _is_enabled.get("message") is True:
            return SocaResponse(success=True, message="Cache is enabled")
        else:
            return SocaResponse(
                success=False, message="Cache is not enabled on this environment"
            )

    def exists(self, key):
        try:
            logger.debug(f"Checking if {key} exist on the cache")
            if self.redis:
                _q = self.cache_client.exists(self.key_fqdn(key))
                if _q == 1:
                    return SocaResponse(success=True, message=f"{key} exists in cache")
                else:
                    return SocaResponse(
                        success=False, message=f"{key} does not exist in cache"
                    )
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to check if {key} exist due to {err}"
            )

    def scan(self, match_pattern: str = "*"):
        try:
            cursor = "0"
            keys = []
            while cursor != 0:
                cursor, batch = self.cache_client.scan(
                    cursor=cursor, match=match_pattern
                )
                keys.extend(batch)

            return SocaResponse(
                success=True, message=[key.decode("utf-8") for key in keys]
            )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to scan cache due to {err}")

    def set(self, key, value, ex=None):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache Set {key=} -> {value=}")
        try:
            if self.redis:
                if not ex:
                    ex = self.ttl_long

                _q = self.cache_client.set(f"{self.key_fqdn(key)}", value, ex=ex)
                if _q:
                    return SocaResponse(
                        success=True, message=f"Key {key} cached successfully"
                    )
                else:
                    return SocaResponse(
                        success=False,
                        message=f"Unable to cache {key}. Redis Response: {_q}",
                    )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to cache {key} due to {err}")

    def delete(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache Delete {key=}")
        try:
            if self.redis:
                if self.exists(self.key_fqdn(key)).success:
                    _q = self.cache_client.delete(f"{self.key_fqdn(key)}")
                    if _q == 1:
                        return SocaResponse(
                            success=True, message=f"Key {key} deleted successfully"
                        )
                    else:
                        return SocaResponse(
                            success=False,
                            message=f"Unable to delete {key}. Redis Response: {_q}",
                        )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to delete {key} due to {err}")

    def get(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache Get {key=}")

        try:
            if self.redis:
                if self.exists(self.key_fqdn(key)).success:
                    return SocaResponse(
                        success=True, message=self.cache_client.get(self.key_fqdn(key))
                    )
                else:
                    logger.info(f"Key {key} does not exist in cache")
                    return SocaResponse(success=False, message="CACHE_MISS")
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to get {key} due to {err}")

    def lrange(self, key, start, end):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache lrange {key=}:  {start}-{end}")
        try:
            _output = []
            if self.redis:
                _range = self.cache_client.lrange(
                    self.key_fqdn(key), start=start, end=end
                )
                if _range:
                    for _item in _range:
                        _output.append(_item.decode("utf-8"))
                return SocaResponse(success=True, message=_output)
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to lrange {key} due to {err}")

    def lpush(self, key, *element):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache lpush {key=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True,
                    message=self.cache_client.lpush(self.key_fqdn(key), *element),
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to lpush {key} due to {err}")

    def rpush(self, key, *element):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache rpush {key=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True,
                    message=self.cache_client.rpush(self.key_fqdn(key), *element),
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to rpush {key} due to {err}")

    def ttl(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache TTL {key=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True, message=self.cache_client.ttl(self.key_fqdn(key))
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to ttl {key} due to {err}")

    def expire(self, key, ttl=0):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache expire {key=} {ttl=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True,
                    message=self.cache_client.expire(self.key_fqdn(key), ttl),
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to expire {key} due to {err}")

    # ------------------------------------------------------------------
    # Hash operations
    #
    # Used by SSM ConfigSync (one HASH per cluster, one field per SSM
    # parameter leaf). Shape of the hash key is always cluster-prefixed
    # via key_fqdn() like every other operation in this client. Field
    # names and values are stored/returned as utf-8 strings (the
    # underlying redis-py client runs with decode_responses=False, so
    # we decode bytes here to give callers a stable str interface).
    # ------------------------------------------------------------------

    @staticmethod
    def _decode(value):
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8")
        return value

    def hset(self, key, field, value):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HSET {key=} {field=}")
        try:
            if self.redis:
                _q = self.cache_client.hset(self.key_fqdn(key), field, value)
                # HSET returns 1 if new field, 0 if updated. Both are success.
                return SocaResponse(
                    success=True,
                    message=f"Field {field} on {key} written (new={_q})",
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to hset {key}.{field} due to {err}"
            )

    def hset_multi(self, key, mapping: dict):
        """
        Atomically set multiple fields on a hash. Equivalent to a single
        HSET command with a mapping argument (replaces the deprecated
        HMSET).
        """
        if not mapping:
            return SocaResponse(success=True, message=f"No fields to write to {key}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HSET multi {key=} fields={len(mapping)}")
        try:
            if self.redis:
                self.cache_client.hset(self.key_fqdn(key), mapping=mapping)
                return SocaResponse(
                    success=True,
                    message=f"{len(mapping)} fields written to {key}",
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to hset_multi {key} due to {err}"
            )

    def hget(self, key, field):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HGET {key=} {field=}")
        try:
            if self.redis:
                _value = self.cache_client.hget(self.key_fqdn(key), field)
                if _value is None:
                    return SocaResponse(success=False, message="CACHE_MISS")
                return SocaResponse(success=True, message=self._decode(_value))
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to hget {key}.{field} due to {err}"
            )

    def hgetall(self, key):
        """
        Returns the entire hash as a dict of utf-8 strings. On missing
        key, returns success=True with an empty dict (matches Redis HGETALL
        semantics). Use exists() if you need to distinguish missing key
        from empty hash.
        """
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HGETALL {key=}")
        try:
            if self.redis:
                _raw = self.cache_client.hgetall(self.key_fqdn(key))
                _decoded = {self._decode(k): self._decode(v) for k, v in _raw.items()}
                return SocaResponse(success=True, message=_decoded)
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to hgetall {key} due to {err}")

    def hdel(self, key, *fields):
        if not fields:
            return SocaResponse(success=True, message=f"No fields to delete from {key}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HDEL {key=} fields={fields}")
        try:
            if self.redis:
                _q = self.cache_client.hdel(self.key_fqdn(key), *fields)
                return SocaResponse(
                    success=True, message=f"Deleted {_q} field(s) from {key}"
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to hdel {key} fields={fields} due to {err}"
            )

    def hexists(self, key, field):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HEXISTS {key=} {field=}")
        try:
            if self.redis:
                _q = self.cache_client.hexists(self.key_fqdn(key), field)
                return SocaResponse(success=bool(_q), message=bool(_q))
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to hexists {key}.{field} due to {err}"
            )

    def hkeys(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HKEYS {key=}")
        try:
            if self.redis:
                _raw = self.cache_client.hkeys(self.key_fqdn(key))
                return SocaResponse(
                    success=True, message=[self._decode(f) for f in _raw]
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to hkeys {key} due to {err}")

    def hlen(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache HLEN {key=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True, message=self.cache_client.hlen(self.key_fqdn(key))
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to hlen {key} due to {err}")

    def rename(self, src, dst):
        """
        Atomic key rename. Used by the SSM ConfigSync flusher to swap a
        freshly-built hash into place without ever leaving the readable
        key empty. RENAME fails (raises) if src does not exist.
        """
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache RENAME {src=} -> {dst=}")
        try:
            if self.redis:
                self.cache_client.rename(self.key_fqdn(src), self.key_fqdn(dst))
                return SocaResponse(
                    success=True, message=f"Renamed {src} to {dst}"
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to rename {src} to {dst} due to {err}"
            )

    def pipeline(self, transaction: bool = True):
        """
        Returns a redis-py pipeline bound to the underlying client. The
        caller is responsible for FQDN-prefixing keys (use key_fqdn()).
        Default transaction=True wraps the batch in MULTI/EXEC.

        Example (build new hash + atomic swap):
            pipe = client.pipeline()
            pipe.hset(client.key_fqdn(tmp_key), mapping=full_dict)
            pipe.rename(client.key_fqdn(tmp_key), client.key_fqdn(target_key))
            pipe.execute()
        """
        if not self.redis:
            return None
        return self.cache_client.pipeline(transaction=transaction)


@cached(TTLCache(maxsize=30, ttl=86400))
def get_cache_config(is_admin: bool = False) -> dict:
    logger.debug(f"Building a cache_client)")
    _cache_info: dict = {}
    _ssm_client = utils_boto3.get_boto(service_name="ssm").message
    _ssm_key_path = f"/edh/{os.environ.get('EDH_CLUSTER_ID')}/configuration/Cache/"

    _ssm_paginator = _ssm_client.get_paginator("get_parameters_by_path")
    _ssm_iterator = _ssm_paginator.paginate(Path=_ssm_key_path, Recursive=True)

    for _page in _ssm_iterator:
        for _p in _page.get("Parameters", []):
            _cache_info[_p.get("Name").replace(_ssm_key_path, "")] = _p.get("Value")

    if (
        SocaCastEngine(data=_cache_info.get("enabled")).cast_as(bool).get("message")
        is True
    ):
        if _cache_info.get("engine") in {"valkey", "redis"}:
            # IAM auth (no static password): mint a SigV4 "connect" token per
            # connection from the instance/Lambda role. Controller/admin path uses
            # the broad controller user; every other path uses the scoped readonly
            # user. UserName == UserId (lowercase) is an ElastiCache IAM constraint.
            _cluster_id = os.environ.get("EDH_CLUSTER_ID", "")
            _user_id = (
                f"{_cluster_id}-controller"
                if is_admin
                else f"{_cluster_id}-readonlyuser"
            ).lower()
            _token_generator = make_cache_token_generator(
                credentials=utils_boto3.get_boto_session_credentials().get("message"),
                cache_name=_cache_info.get("name"),
                user_id=_user_id,
                region=utils_boto3.get_boto_session_region().get("message"),
            ).get("message")
            _cache_client = redis.Redis(
                host=_cache_info.get("endpoint"),
                port=_cache_info.get("port"),
                protocol=3,
                ssl=True,
                ssl_cert_reqs=None,
                decode_responses=False,
                credential_provider=_ElastiCacheIAMProvider(_token_generator),
            )
            logger.debug("Cache client built successfully")
        else:
            _cache_client = None
    else:
        logger.info("Cache not enabled, client is None")
        _cache_client = None

    return SocaResponse(success=True, message={"cache_client": _cache_client, "cache_info": _cache_info})
