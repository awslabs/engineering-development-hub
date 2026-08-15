# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Lazy factory for DCV session-sharing services on the controller.

Mirrors helpers/vdi_pool_store.py: builds boto3 DDB table resources from the
EDH_CLUSTER_ID env var and constructs the profile/grant services on demand,
shared per uWSGI worker. Returns None when the feature is not enabled (no
cluster id / tables absent), so callers can no-op gracefully.
"""

import logging
import os

import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig

logger = logging.getLogger("soca_logger")

_ddb_resource = None
_broker_client = None

_ALLOWED_MODES_SSM = "/configuration/dcv/session_sharing/allowed_sharing_modes"
_ENABLED_SSM = "/configuration/dcv/session_sharing/enabled"
_ALLOW_UNSUP_SSM = "/configuration/dcv/session_sharing/allow_unsupervised_access"

_CONFIG_KEY_TO_SSM = {
    "Config.dcv.session_sharing.allowed_sharing_modes": _ALLOWED_MODES_SSM,
    "Config.dcv.session_sharing.allow_unsupervised_access": _ALLOW_UNSUP_SSM,
    "Config.dcv.session_sharing.enabled": _ENABLED_SSM,
}


def _cluster_id() -> str:
    return os.environ.get("EDH_CLUSTER_ID", "")


def is_enabled() -> bool:
    """True when the feature flag SSM key is 'true'."""
    if not _cluster_id():
        return False
    try:
        from utils.cast import SocaCastEngine
        v = SocaConfig(key=_ENABLED_SSM).get_value().message
        _cast = SocaCastEngine(v).cast_as(bool)
        return bool(_cast.message) if _cast.success else False
    except Exception:
        return False


def _ddb():
    global _ddb_resource
    if _ddb_resource is None:
        _ddb_resource = utils_boto3.get_boto(
            service_name="dynamodb", resource=True
        ).message
    return _ddb_resource


def _grants_table():
    cid = _cluster_id()
    return _ddb().Table(f"{cid}-dcv-session-sharing-grants") if cid else None


def _profiles_table():
    cid = _cluster_id()
    return _ddb().Table(f"{cid}-dcv-session-sharing-profiles") if cid else None


def _broker():
    global _broker_client
    if _broker_client is None:
        from utils.dcv_broker_client import DcvBrokerClient
        _broker_client = DcvBrokerClient()
    return _broker_client


def _config_key_adapter(*, key_name=None, expected_type=None, default=None, required=False):
    """
    Controller-side adapter matching the installer get_config_key signature the
    grant service expects. Routes key_name -> the correct SSM parameter and
    coerces by expected_type. Falls back to default on any miss.
    """
    from utils.validators import Validators
    from utils.cast import SocaCastEngine

    ssm_key = _CONFIG_KEY_TO_SSM.get(key_name)
    if not ssm_key:
        return default
    try:
        v = SocaConfig(key=ssm_key).get_value().message
        if v is None or v == "":
            return default
        if expected_type is bool:
            _cast = SocaCastEngine(v).cast_as(bool)
            return _cast.message if _cast.success else default
        if expected_type is list:
            if Validators.is_list(v):
                return v
            if Validators.is_string(v):
                _json = SocaCastEngine(v).as_json()
                if _json.success and Validators.is_list(_json.message):
                    return _json.message
                # Not JSON (e.g. "none,secure") -> comma-split fallback.
                return [m.strip() for m in v.split(",") if m.strip()]
            return default
        return v
    except Exception:
        return default


def get_profile_service():
    """Build the profile service, or None if the feature is not provisioned."""
    table = _profiles_table()
    if table is None:
        return None
    from utils.dcv_session_sharing_profile_service import (
        DcvSessionSharingProfileService,
    )
    return DcvSessionSharingProfileService(table)


def get_grant_service():
    """Build the grant service, or None if the feature is not provisioned."""
    grants = _grants_table()
    profiles = _profiles_table()
    if grants is None or profiles is None:
        return None
    from utils.dcv_session_sharing_grant_service import (
        DcvSessionSharingGrantService,
    )
    return DcvSessionSharingGrantService(
        grants_table=grants,
        profiles_table=profiles,
        broker_client=_broker(),
        get_config_key=_config_key_adapter,
    )
