# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.validators import Validators
from utils.cache.client import SocaCacheClient
from utils.cache.keys import build_cache_key
import functools
import inspect
import pickle

logger = logging.getLogger("soca_logger")

def _check_response_filter(data, path, expected_value=None):
    """
    Helper to check if a nested path exists in data and optionally matches a value.
    Supports multiple levels of nesting using dot notation and array indexing.

    Args:
        data: The data structure to check (dict, list, SocaResponse, etc.)
        path: Dot-separated path string. Numeric keys are treated as array indices. Examples:
            - "state" (single level)
            - "message.state" (two levels)
            - "message.RootDeviceInfo.State" (three levels)
            - "Images.0.State" (array indexing - first element)
            - "data.attributes.metadata.status" (four levels)
        expected_value: Optional value to match. If None, just checks existence.

    Returns:
        True if path exists (and matches value if provided), False otherwise

    Examples:
        # Dict access
        data = {"message": {"RootDeviceInfo": {"State": "available"}}}
        _check_response_filter(data, "message.RootDeviceInfo.State", "available")  # True
        _check_response_filter(data, "message.RootDeviceInfo.State")  # True (exists)
        _check_response_filter(data, "message.RootDeviceInfo.Missing")  # False

        # Array access
        data = {"Images": [{"State": "available", "ImageId": "ami-123"}]}
        _check_response_filter(data, "Images.0.State", "available")  # True
        _check_response_filter(data, "Images.0.ImageId")  # True (exists)
        _check_response_filter(data, "Images.1.State")  # False (index out of range)
    """
    try:
        current = data
        keys = path.split(".")

        for key in keys:
            # Handle SocaResponse - unwrap to message
            if isinstance(current, SocaResponse):
                current = current.get("message", {})
                # After unwrapping, skip to next key if this was "message"
                if key == "message":
                    continue

            # Try to parse key as integer for array access
            try:
                index = int(key)
                if isinstance(current, (list, tuple)):
                    if 0 <= index < len(current):
                        current = current[index]
                    else:
                        return False  # Index out of range
                else:
                    return False  # Not an array
            except ValueError:
                # Not a number, treat as dict key
                if isinstance(current, dict):
                    if key not in current:
                        return False
                    current = current[key]
                else:
                    return False

        # If we got here, path exists
        if expected_value is not None:
            return current == expected_value
        return True
    except Exception:
        return False


def _encode_json(result: SocaResponse) -> bytes:
    """
    Serialize a SocaResponse as JSON. Raises TypeError when the payload is not
    JSON-safe, which the caller turns into "do not cache" rather than a silent
    fall back to pickle.

    json.dumps directly rather than through SocaCastEngine: as_json() is
    json.loads and cannot serialize, and serialize_json() emits indent=2, which
    would change every stored byte for no gain. The strictness below is the point
    of this function and serialize_json does not offer it.

    Deliberately strict: json.dumps with a default= that stringifies unknown
    objects would round-trip a datetime into a str and hand callers a different
    type than the uncached path returns.
    """
    return json.dumps(
        {
            "success": result.success,
            "message": result.message,
            "status_code": result.status_code,
            "request": result.request,
            "trace": result.trace,
        },
        allow_nan=False,
    ).encode("utf-8")


def _decode_json(payload) -> SocaResponse:
    if Validators.is_bytes(payload):
        payload = payload.decode("utf-8")
    # Through SocaCastEngine per the repo's cast guideline. It returns a
    # SocaError rather than raising, and the caller's contract is that an entry
    # which will not parse is treated as a MISS -- so an unparseable payload is
    # turned back into an exception here rather than being returned as if it were
    # a cached value.
    _parsed = SocaCastEngine(data=payload).as_json()
    if _parsed.get("success") is not True:
        raise ValueError(f"cached entry is not valid JSON: {_parsed.get('message')}")
    _fields = _parsed.get("message")
    return SocaResponse(
        success=_fields["success"],
        message=_fields["message"],
        status_code=_fields.get("status_code"),
        request=_fields.get("request"),
        trace=_fields.get("trace"),
    )


def soca_cache(
    prefix: str,
    ttl: int = None,
    is_admin: bool = True,
    cache_if: callable = None,
    serializer: str = "pickle",
):
    r"""
    Decorator to cache function results in SocaCacheClient using pickle.

    Args:
        prefix: namespace for cache keys
        ttl: override TTL (defaults to SocaCacheClient.ttl_long if not set)
        is_admin: whether to use admin credentials for cache client (change to False is not using the SocaController)
        cache_if: optional callable that receives the result and returns True if it should be cached
        serializer: "pickle" (default) or "json".

            Prefer "json" for any new cached function. A pickled entry couples the
            cache to the interpreter and to the class layout at write time, so an
            EDH upgrade can leave entries that either fail to load or load into a
            changed class, and anything able to write the cache gets code execution
            on read. JSON has neither property.

            "pickle" remains the default because it is not a free swap: JSON
            rewrites datetime and other non-JSON types, and several cached AWS
            responses carry them (describe_capacity_reservations returns EndDate as
            a datetime). Converting one of those to "json" would silently hand
            callers a str where they had a datetime, so each conversion needs its
            payload checked first. With "json", a payload that is not JSON-safe is
            NOT cached and is logged, rather than falling back to pickle.

    /!\ Only cache/return successful SocaResponse /!\

    Examples:
        # Basic usage - cache all successful responses
        @soca_cache(prefix="users", ttl=300)
        def get_user(user_id):
            return SocaResponse(success=True, message={"id": user_id, "name": "John"})

        # Cache only if nested path has specific value
        @soca_cache(prefix="images", cache_if=lambda r: _check_response_filter(r, "message.State", "available"))
        def describe_image(image_id):
            return SocaResponse(success=True, message={"State": "available", "ImageId": image_id})

        # Cache only if array element has specific value (AWS describe_images response)
        @soca_cache(prefix="images", cache_if=lambda r: _check_response_filter(r, "message.Images.0.State", "available"))
        def describe_images(image_id):
            # Returns: SocaResponse with message={"Images": [{"State": "available", ...}]}
            return SocaResponse(success=True, message=ec2_response)

        # Cache only if path exists
        @soca_cache(prefix="nodes", cache_if=lambda r: _check_response_filter(r, "message.state"))
        def get_node_status(node_id):
            return SocaResponse(success=True, message={"state": "running"})

        # Custom condition
        @soca_cache(prefix="data", cache_if=lambda r: r.get("message", {}).get("count", 0) > 0)
        def get_items():
            return SocaResponse(success=True, message={"count": 5, "items": [...]})

        # Invalidate cache for specific arguments
        get_user.invalidate_cache(user_id="123")

        # Invalidate all cached entries for this prefix
        get_user.invalidate_all()
    """
    # Built on first use, not here. This factory body runs at import time of
    # every module carrying a @soca_cache, and SocaCacheClient.__init__ pages
    # SSM, so building it here puts a live AWS call in those import paths.
    _client_holder: list = []

    def _cache_client() -> SocaCacheClient:
        if not _client_holder:
            _client_holder.append(SocaCacheClient(is_admin=is_admin))
        return _client_holder[0]

    def _resolve_ttl():
        """
        Resolve the TTL at CALL time rather than at import time.

        A plain int is returned as-is. A callable is invoked on every write, which
        is what lets an operator retune a window through cluster configuration
        without restarting the controller: the decorator runs once at import, so a
        config value read there would be frozen for the life of the process.

        A callable that raises must not stop the write - fall back to the client
        default rather than losing the cache entry.
        """
        if not callable(ttl):
            return ttl
        try:
            return ttl()
        except Exception as err:  # noqa: BLE001
            logger.warning(f"Callable ttl for {prefix} raised {err}, using default")
            return None

    def decorator(func):
        sig = inspect.signature(func)

        def make_cache_key(*args, **kwargs):
            """Readable key based on the prefix plus the bound arguments."""
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            return build_cache_key(
                prefix=prefix,
                module=func.__module__,
                qualname=func.__qualname__,
                arguments=bound.arguments,
            )

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> SocaResponse:
            cache_key = make_cache_key(*args, **kwargs)
            # Cache hits are logged at DEBUG (they happen on every request); misses,
            # writes and errors stay at INFO / WARNING.
            logger.debug("Trying to fetch %s", cache_key)
            _cache_enabled = _cache_client().is_enabled().success
            if _cache_enabled:
                cached_resp = _cache_client().get(cache_key)
                if (
                    cached_resp.get("success")
                    and cached_resp.get("message") != "CACHE_MISS"
                ):
                    logger.debug("%s found on Cache, trying to deserialize payload", cache_key)
                    try:
                        payload = cached_resp.message
                        if serializer == "json":
                            # Never fall back to pickle here: a json-serialized
                            # entry that will not parse is treated as a miss, so a
                            # crafted payload cannot reach pickle.loads.
                            data = _decode_json(payload)
                        elif Validators.is_bytes(payload):
                            data = pickle.loads(payload)
                        else:
                            data = payload
                        # Lazy: formatting the whole cached object on every hit is costly
                        logger.debug("Cached value: %s", data)
                        logger.debug("Successfully retrieved %s from cache", cache_key)
                        return data  # return the entire SocaResponse
                    except Exception as err:
                        logger.warning(
                            f"Failed to deserialize cache for {cache_key}: {err}"
                        )

            logger.info("%s not available on cache, calling actual function", cache_key)

            result = func(*args, **kwargs)

            # Only cache successful and trusted SocaResponse
            # note: pickle does not handle input serialization, so make sure to only cache data from trusted sources
            should_cache = (
                isinstance(result, SocaResponse) and result.get("success") is True
            )
            if _cache_enabled:
                # Apply additional cache_if condition if provided
                if should_cache and cache_if is not None:
                    try:
                        should_cache = cache_if(result)
                        if not should_cache:
                            logger.warning(
                                f"cache_if condition not met for {cache_key}"
                            )
                    except Exception as err:
                        logger.warning(f"cache_if check failed for {cache_key}: {err}")
                        should_cache = False

                if should_cache:
                    try:
                        logger.debug(f"Caching {cache_key}")
                        _ttl = _resolve_ttl() or _cache_client().ttl_long
                        if serializer == "json":
                            _value = _encode_json(result)
                        else:
                            _value = pickle.dumps(result)
                        _cache_client().set(
                            key=cache_key,
                            value=_value,
                            ex=_ttl,
                        )
                        logger.info(f"Successfully cached {cache_key}")
                    except (TypeError, ValueError) as err:
                        # json serializer and a payload that is not JSON-safe. Do
                        # not cache, and do not quietly pickle it instead.
                        logger.warning(
                            f"{cache_key} not cached: payload is not JSON-serializable ({err})"
                        )
                    except Exception as err:
                        logger.warning(f"Failed to cache {cache_key}: {err}")
                else:
                    logger.warning(
                        "Result is not a successful SocaResponse or cache conditions not met, result wont be cached"
                    )

            return result

        def invalidate_cache(*args, **kwargs):
            cache_key = make_cache_key(*args, **kwargs)
            logger.info(f"Invalidating cache key {cache_key}")
            return _cache_client().delete(cache_key)

        def invalidate_all():
            logger.info(f"Invalidating ALL cache keys for prefix {prefix}")
            # scan() passes the pattern straight to the engine and does NOT apply
            # key_fqdn(), while set() and delete() do. An unscoped pattern therefore
            # matches nothing at all, which is what made this a no-op.
            _pattern = _cache_client().key_fqdn(f"{prefix}:*")
            scan_resp = _cache_client().scan(match_pattern=_pattern)
            if scan_resp.success:
                deleted = 0
                for k in scan_resp.message:
                    _cache_client().delete(k)
                    deleted += 1
                return SocaResponse(success=True, message=f"Deleted {deleted} keys")
            else:
                return SocaResponse(success=False, message="Failed to scan keys")

        wrapper.build_cache_key = make_cache_key
        wrapper.invalidate_cache = invalidate_cache
        wrapper.invalidate_all = invalidate_all

        return wrapper

    return decorator
