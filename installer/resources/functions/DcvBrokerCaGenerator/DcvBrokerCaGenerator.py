# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DcvBrokerCaGenerator -- CloudFormation custom-resource Lambda that mints the
shared CA for the DCV high-scale broker fleet (broker-to-broker Apache Ignite
mTLS) and stores it in Secrets Manager. Runs once at deploy.

Why this exists: the DCV SM Broker self-signs its OWN CA on first boot, so a
fleet of >1 broker can't form the Ignite cluster (each self-signed CA distrusts
the others). This Lambda provisions ONE authoritative CA up front; every broker
installs it read-only before first start (see dcv_broker.sh.j2) so all per-node
keystores chain to a single trust root.

Idempotent: if the secret already holds a CA, it is left untouched. This makes
deploying v2 over a v1 (broker-founded CA) cluster a safe no-op -- the existing
CA is preserved and the fleet is undisturbed.

Validity defaults to 10y (configurable via Config.dcv.broker.ca_validity_days),
which removes the ~2y expiry cliff of the DCV-generated default. Rotation is a
separate (phase-2) concern -- see dcv-broker-ca-lifecycle-spec.md.

Requires the cryptography Lambda layer (Config.lambda_layers.CryptographyVersion).
"""

import datetime
import json
import logging
import os
import ssl
import urllib.request

import boto3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_sm = boto3.client("secretsmanager")

CA_SECRET_ARN = os.environ["CA_SECRET_ARN"]
EDH_CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
CA_VALIDITY_DAYS = int(os.environ.get("CA_VALIDITY_DAYS", "3650"))
CA_KEY_SIZE = int(os.environ.get("CA_KEY_SIZE", "2048"))


def _generate_ca() -> tuple:
    """Mint a self-signed X.509 CA (CA=True, keyCertSign). Returns (pem, key_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=CA_KEY_SIZE)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Engineering Development Hub"),
            x509.NameAttribute(
                NameOID.COMMON_NAME, f"EDH DCV Broker Fleet CA {EDH_CLUSTER_ID}"
            ),
        ]
    )
    _now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now)
        .not_valid_after(_now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        # path_length=0: this CA signs end-entity broker certs directly and
        # must never issue intermediate CAs. Enforcing it cryptographically
        # limits blast radius if the CA key is ever compromised.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    ca_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    ca_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")
    return ca_pem, ca_key


def _secret_has_ca() -> bool:
    try:
        _cur = _sm.get_secret_value(SecretId=CA_SECRET_ARN).get("SecretString", "")
        _d = json.loads(_cur) if _cur else {}
        return bool(_d.get("ca_pem") and _d.get("ca_key"))
    except _sm.exceptions.ResourceNotFoundException:
        return False
    except (json.JSONDecodeError, ValueError):
        return False


def _ensure_ca() -> str:
    if _secret_has_ca():
        logger.info("Shared broker CA already present; leaving untouched (idempotent)")
        return "exists"
    ca_pem, ca_key = _generate_ca()
    _sm.put_secret_value(
        SecretId=CA_SECRET_ARN,
        SecretString=json.dumps({"ca_pem": ca_pem, "ca_key": ca_key}),
    )
    logger.info(
        "Minted shared broker CA (%dd validity, %d-bit) into %s",
        CA_VALIDITY_DAYS,
        CA_KEY_SIZE,
        CA_SECRET_ARN,
    )
    return "created"


def _cfn_respond(event, context, status, data=None, reason=None) -> None:
    """Send a CloudFormation custom-resource response to the pre-signed URL."""
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason or f"See CloudWatch log stream: {context.log_stream_name}",
            "PhysicalResourceId": event.get("PhysicalResourceId")
            or f"dcv-broker-ca-{EDH_CLUSTER_ID}",
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "Data": data or {},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        event["ResponseURL"],
        data=body,
        method="PUT",
        headers={"content-type": "", "content-length": str(len(body))},
    )
    urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context())


def handler(event, context):
    """CFN custom-resource entry point. Create/Update mint-if-absent; Delete retains."""
    _rt = event.get("RequestType")
    try:
        if _rt in ("Create", "Update"):
            _result = _ensure_ca()
            _cfn_respond(event, context, "SUCCESS", {"Ca": _result})
        else:
            # Delete: retain the CA. Brokers (and their issued keystores) may
            # still depend on it; deleting the secret would break a running
            # fleet. The secret is cleaned up with the stack's secret resource.
            _cfn_respond(event, context, "SUCCESS", {"Ca": "retained"})
    except Exception as _e:  # noqa: BLE001 -- must always answer CFN or the stack hangs
        logger.exception("DcvBrokerCaGenerator failed")
        _cfn_respond(event, context, "FAILED", reason=str(_e))
