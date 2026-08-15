# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
ElastiCache (Valkey/Redis) IAM authentication helper (BSC5: "use IAM-based
authentication wherever supported").

Mirrors the design of ``web_interface/db_iam_auth.py``: dependency-light
(botocore signing primitives + caller-supplied credentials), so the
token-minting logic can be unit tested off-cluster without importing
client.py / redis / SocaConfig.

Co-located with its sole consumer ``utils/cache/client.py``, which wraps the
returned generator in a ``redis.CredentialProvider`` and passes it to
``redis.Redis(...)`` -- keeping the only ``import redis`` in the cache client
module, not here.
"""

from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from utils.response import SocaResponse
import logging

logger = logging.getLogger("soca_logger")

# ElastiCache IAM tokens are SigV4 presigned "connect" requests. AWS caps the
# validity at 900s; auth happens only at connect, so an established pool
# connection outlives token expiry (same rationale as db_iam_auth.py).
_TOKEN_TTL_SECONDS = 900
_SERVICE = "elasticache"


def make_cache_token_generator(credentials, cache_name, user_id, region):
    """
    Build a zero-arg callable that mints a fresh ElastiCache IAM auth token and
    returns ``(user_id, token)`` for use as the redis-py ``(username, password)``
    pair. A new token is minted per call (local SigV4 signing, sub-ms, no network),
    so every new pool connection gets a token comfortably inside the validity
    window and the app is rotation-immune -- there is no stored password.

    IAM auth requires the ElastiCache user's ``UserName == UserId`` (lowercase)
    and TLS; ``user_id`` is that name.

    ``cache_name`` is the ElastiCache **cache name** (serverless cache name, or
    replication group id for node-based clusters) -- NOT the DNS endpoint. The
    presigned "connect" URL is signed against this name; ElastiCache validates
    the signature by cache name, so signing the endpoint host fails auth.

    :param credentials: a botocore Credentials object (refreshable; instance-role
        creds are read live on each call so rotation is transparent)
    :param cache_name: the ElastiCache cache name / replication group id to sign
    :param user_id: the ElastiCache RBAC user id/name to authenticate as
    :param region: AWS region for the signature
    :returns: SocaResponse(message=callable) where the callable is ``() -> tuple[str, str]`` yielding ``(user_id, token)``
    """

    def _mint():
        logger.debug(
            f"Minting ElastiCache IAM token for user={user_id} cache={cache_name} region={region}"
        )
        request = AWSRequest(
            method="GET",
            url=f"https://{cache_name}/",
            params={"Action": "connect", "User": user_id},
        )
        SigV4QueryAuth(
            credentials, _SERVICE, region, expires=_TOKEN_TTL_SECONDS
        ).add_auth(request)
        # ElastiCache expects the presigned request WITHOUT the scheme as the token.
        token = request.prepare().url.removeprefix("https://")
        return user_id, token

    return SocaResponse(success=True, message=_mint)
