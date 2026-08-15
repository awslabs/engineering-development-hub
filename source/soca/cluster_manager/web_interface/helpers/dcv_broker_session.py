# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Shared broker-session finalization for high-scale VDI desktops.

This is the single place that turns a booted high-scale VDI instance into a
*connectable* session:

  1. confirm the on-host DCV server has registered with the broker
     (programmatic broker API -- DcvBrokerClient.is_server_ready, NOT a log
     grep),
  2. register the session with the broker (create_session) and persist the
     returned broker session Id in `authentication_token`,
  3. stamp the EC2 identity columns (instance_id / private_ip / private_dns).

It is idempotent and safe to call repeatedly: it recovers an already-created
broker session via find_session_by_name and no-ops the create/stamp once the
columns are populated.

Callers:
  * api/v1/dcv/session_event.py  -- PRIMARY, event-driven on `session-ready`
    (plus a short event-kicked retry while the broker server is still
    registering).
  * scheduled_tasks/.../session_state_watcher.py -- BACKSTOP only, for
    sessions whose event was missed (legacy AMIs, dropped SQS message).

Returns a SocaResponse:
  SocaResponse(success=True,  message="ready")   -> broker session exists +
             EC2 fields stamped; caller may promote to `running` (connectable).
  SocaResponse(success=True,  message="pending") -> broker server not
             registered yet (transient); caller should retry shortly. No
             state change made.
  SocaError (success=False)                      -> non-transient failure,
             logged. No state change made.
"""
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.dcv_broker_client import DcvBrokerClient
from utils.aws.boto3_wrapper import get_boto
from utils.response import SocaResponse
from utils.error import SocaError

import logging

# NOTE on return convention: although this module lives under web_interface/,
# it is NOT a Flask request handler -- it is a programmatic helper whose public
# functions (ensure_broker_session, stamp_ec2_identity) return SocaResponse /
# SocaError *result objects* consumed internally via .success / .message by the
# session-ready event handler, the event-kicked retry, and the
# session_state_watcher backstop. They are intentionally returned WITHOUT
# .as_flask(): none of these returns is ever serialized to an HTTP response, and
# wrapping them in a Flask Response would break those callers. This is a
# deliberate exception to the "web_interface returns use .as_flask()" guideline.
logger = logging.getLogger("soca_logger")

_TERMINAL_BROKER_STATES = {"DELETING", "DELETED"}


def _derive_max_collab() -> "int | None":
    _resp = SocaConfig(key="/dcv/max_concurrent_clients").get_value(
        default="10", allow_unknown_key=True
    )
    _raw = _resp.message if _resp.success else "10"
    _cast = SocaCastEngine(_raw).cast_as(expected_type=int)
    return _cast.message if _cast.success is True else None


def _derive_storage_root(os_family: "str | None") -> str:
    _cfg = SocaConfig(key="/system/dcv/session_storage").get_value(
        default="dcv_session_storage", allow_unknown_key=True
    )
    _name = _cfg.message if _cfg.success else "dcv_session_storage"
    _famcast = SocaCastEngine(os_family or "").cast_as(expected_type=str)
    _fam = (_famcast.message if _famcast.success else "").lower()
    return f"C:\\{_name}" if "windows" in _fam else f"%home%/{_name}"


def stamp_ec2_identity(
    session, instance_id, db_scoped_session, *, private_ip=None, private_dns=None
) -> SocaResponse:
    """
    Stamp instance_id / private_ip / private_dns onto the session row as soon
    as the instance is known -- DECOUPLED from broker registration so an admin
    can correlate a still-provisioning session to its EC2 instance in the AWS
    console immediately (instead of minutes later, once the broker registers).

    Idempotent: no-op when all three columns are already populated. Never
    raises. Pass private_ip/private_dns when the caller already has them (the
    watcher resolved them via describe-by-tag) to skip a describe_instances
    round-trip; otherwise they are resolved here from the instance id.

    Returns SocaResponse(success=True) on success/no-op, SocaError on failure.
    """
    try:
        if (
            session.instance_id
            and session.instance_private_ip
            and session.instance_private_dns
        ):
            return SocaResponse(success=True, message="already-stamped")
        _ip, _dns = private_ip, private_dns
        if not (_ip and _dns):
            _boto = get_boto(service_name="ec2")
            if _boto.success is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"stamp_ec2_identity: get_boto(ec2) failed for "
                    f"{instance_id} ({getattr(session, 'session_uuid', '?')})"
                )
            _ec2_client = _boto.message
            _di = _ec2_client.describe_instances(InstanceIds=[instance_id])
            for _res in _di.get("Reservations", []):
                for _inst in _res.get("Instances", []):
                    _d = (_inst.get("PrivateDnsName") or "").split(".")[0]
                    if not _d:
                        continue
                    _ip = _inst.get("PrivateIpAddress")
                    _dns = _d
                    break
                if _dns:
                    break
        if not _dns:
            return SocaError.GENERIC_ERROR(
                helper=f"stamp_ec2_identity: no usable record for {instance_id} "
                f"({getattr(session, 'session_uuid', '?')})"
            )
        session.instance_id = instance_id
        session.instance_private_ip = _ip
        session.instance_private_dns = _dns
        db_scoped_session.commit()
        logger.info(
            f"stamp_ec2_identity: {session.session_uuid} -> "
            f"instance={instance_id} ip={_ip} dns={_dns}"
        )
        return SocaResponse(success=True, message="stamped")
    except Exception as err:
        try:
            db_scoped_session.rollback()
        except Exception:
            pass
        return SocaError.GENERIC_ERROR(
            helper=f"stamp_ec2_identity error for "
            f"{getattr(session, 'session_uuid', '?')}: {err}"
        )


def ensure_broker_session(session, instance_id, db_scoped_session, broker=None) -> SocaResponse:
    """
    Finalize a high-scale VDI session into a connectable state. See module
    docstring. Idempotent. Never raises -- returns a SocaError on failure.
    """
    try:
        _broker = broker or DcvBrokerClient()

        # ---- 1. gate on REAL broker registration (programmatic API) --------
        if not _broker.is_server_ready(instance_id):
            logger.info(
                f"ensure_broker_session: DCV server for {instance_id} not yet "
                f"registered with broker (session={session.session_uuid}); pending"
            )
            return SocaResponse(success=True, message="pending")

        # ---- 2. ensure the broker session exists --------------------------
        if not session.authentication_token:
            # Recover an already-registered session (idempotent across retries
            # / a uwsgi restart between create + commit). Ignore terminal-state
            # records lingering in describeSessions after teardown.
            _existing = _broker.find_session_by_name(session.session_uuid)
            _state = ((_existing or {}).get("State") or "").upper()
            if _existing and _state in _TERMINAL_BROKER_STATES:
                _existing = None

            if _existing:
                _broker_session_id = _existing.get("Id")
                logger.info(
                    f"ensure_broker_session: recovered broker session "
                    f"{_broker_session_id} for {session.session_uuid}"
                )
            else:
                _stype_cast = SocaCastEngine(
                    session.session_type or "console"
                ).cast_as(expected_type=str)
                _session_type = (
                    _stype_cast.message
                    if _stype_cast.success is True
                    else "console"
                ).upper()

                _resp = _broker.create_session(
                    name=session.session_uuid,
                    owner=session.session_owner,
                    session_type=_session_type,
                    instance_id=instance_id,
                    max_concurrent_clients=_derive_max_collab(),
                    storage_root=_derive_storage_root(session.os_family),
                )
                if not _resp.success:
                    # Transient (e.g. broker placing, server just registered) --
                    # let the caller retry.
                    logger.info(
                        f"ensure_broker_session: create_session deferred for "
                        f"{session.session_uuid}: {_resp.message}"
                    )
                    return SocaResponse(success=True, message="pending")
                _broker_session_id = (_resp.message or {}).get("Id")
                if not _broker_session_id:
                    logger.error(
                        f"ensure_broker_session: create_session returned no Id "
                        f"for {session.session_uuid}: {_resp.message}"
                    )
                    return SocaError.GENERIC_ERROR(
                        helper=f"ensure_broker_session: create_session returned "
                        f"no Id for {session.session_uuid}"
                    )
                logger.info(
                    f"ensure_broker_session: registered {session.session_uuid} "
                    f"with broker as {_broker_session_id}"
                )

            session.authentication_token = _broker_session_id

        # ---- 3. stamp EC2 identity if missing -----------------------------
        # Delegated to the shared stamp helper (also used by the watcher and
        # the ec2-running event handler) so identity-stamping lives in one
        # place. By now it is almost always a no-op (the watcher / ec2-running
        # event stamped it minutes earlier); kept here as a backstop.
        _stamp = stamp_ec2_identity(session, instance_id, db_scoped_session)
        if _stamp.success is False:
            # Broker session id is set; a retry will stamp the columns next
            # pass (connect needs private_dns for non-HS; we want them set
            # regardless).
            db_scoped_session.commit()
            return SocaResponse(success=True, message="pending")

        db_scoped_session.commit()
        logger.info(
            f"ensure_broker_session: {session.session_uuid} ready "
            f"(broker_id={session.authentication_token}, "
            f"instance={session.instance_id})"
        )
        return SocaResponse(success=True, message="ready")

    except Exception as err:  # never break the caller
        try:
            db_scoped_session.rollback()
        except Exception:
            pass
        return SocaError.GENERIC_ERROR(
            helper=f"ensure_broker_session error for "
            f"{getattr(session, 'session_uuid', '?')}: {err}"
        )
