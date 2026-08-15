# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Aurora PostgreSQL IAM database authentication helper (BSC5: "use IAM-based
authentication wherever supported").

This module is deliberately dependency-light -- standard library only, plus a
caller-supplied boto3 RDS client -- so the token-injection logic can be unit
tested off-cluster without importing config.py (which drags in flask /
SocaConfig / Valkey and cannot import outside the controller).

config.py wires the returned listener onto the SQLAlchemy Engine via
``event.listen(Engine, "do_connect", make_iam_token_injector(...), named=True)``.
"""


def make_iam_token_injector(rds_client, host, port, user, region):
    """
    Build a SQLAlchemy ``do_connect`` listener (use with ``named=True``) that
    injects a fresh RDS IAM authentication token as the connection password for
    connections whose ``host`` AND ``user`` match the supplied ``(host, user)``.
    Any other connection -- e.g. the legacy SQLite engine, or a admin
    connection on the same host -- is left completely untouched.

    Why mint a fresh token per connection (no cache):
      ``generate_db_auth_token`` is a local SigV4 signing operation (no network
      round-trip, sub-millisecond), so generating one on every new pool
      connection is cheap. The token is valid for 15 minutes (AWS-fixed) but is
      only consumed at connect time; an established connection survives token
      expiry because PostgreSQL authenticates once at connect, not per query.
      Per-connection generation therefore keeps every connect comfortably inside
      the validity window with no staleness bookkeeping.

    Why this makes the app rotation-immune:
      There is no long-lived password embedded in the URI -- the IAM token *is*
      the credential and is regenerated on demand. The ``DatabaseAdminSecret`` secret
      is used only for admin/DB-init and can rotate freely without affecting the
      runtime pool.

    :param rds_client: a boto3 ``rds`` client exposing ``generate_db_auth_token``
    :param host: the Aurora endpoint this app connects to (match key)
    :param port: the Aurora port; expected pre-validated as int by the caller
        (config.py casts it via SocaCastEngine before calling). The int() below
        is a defensive no-op kept so this module stays stdlib-only / off-cluster
        testable without importing SocaCastEngine.
    :param user: the rds_iam application DB user (match key)
    :param region: AWS region for the token signature
    :returns: a callable ``(dialect, conn_rec, cargs, cparams, **kw) -> None``
    """
    _port = int(port)

    def _inject_iam_auth_token(dialect, conn_rec, cargs, cparams, **kw):
        # Only act on connections to OUR Aurora endpoint + app user. Guarding on
        # both host and user means a admin connection (different user) on
        # the same endpoint, and any non-Aurora engine (different host), are both
        # left as-is -- we never overwrite a password we did not set.
        if cparams.get("host") == host and cparams.get("user") == user:
            cparams["password"] = rds_client.generate_db_auth_token(
                DBHostname=host, Port=_port, DBUsername=user, Region=region
            )
        return None

    return _inject_iam_auth_token
