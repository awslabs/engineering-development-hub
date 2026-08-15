# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
ADComputerCleaner -- EventBridge-triggered Lambda that deletes the
Active Directory computer object for an ephemeral SOCA node when the
underlying EC2 instance enters the `shutting-down` state.

Why this exists
---------------
SOCA nodes join AD with a randomised computer-account name
(SOCA-<10 hex chars>) but adcli also auto-registers a
servicePrincipalName based on the OS hostname
(host/ip-X-X-X-X.<region>.compute.internal). Because the OS hostname
embeds the private IP, the SPN is shared by every instance that ever
holds the same private IP. SOCA has no teardown logic, so terminated
instances leave their AD computer object (and its SPN) behind. When a
new instance reuses the same private IP, realm-join fails with:
    AD error 000021C7 (CONSTRAINT_ATT_TYPE), Att 90303 (servicePrincipalName)

This Lambda removes the prior AD computer object on terminate so the
SPN goes with it, eliminating the cross-tenant collision.

Trigger
-------
EventBridge rule on AWS source `aws.ec2`, detail-type
`EC2 Instance State-change Notification`, state=`shutting-down`.
We use `shutting-down` (not `terminated`) so the SSM agent on the
controller still has time to dispatch adcli before AD propagation;
the EC2 instance itself doesn't need to still exist for cleanup of
the orphan AD object referencing it.

Filtering
---------
Acts only on instances whose EC2 tags satisfy ALL of:
- `edh:ClusterId` == this cluster (set via env var EDH_CLUSTER_ID)
- `edh:NodeType` in {compute_node, login_node, dcv_node}

Controllers are intentionally excluded -- they only terminate during
stack delete, and at that point the directory may also be going away.

Action
------
Retrieves AD service account credentials from Secrets Manager
(secret: /edh/<cluster_id>/UserDirectoryServiceAccount), then sends
an `AWS-RunShellScript` SSM command targeted at the cluster controller
(tag-based selection) that runs `adcli delete-computer` with those
credentials. Fire-and-forget: this Lambda does not poll for the SSM
command result. Operators retain manual `adcli delete-computer` as the
recovery path; the SSM command output is captured in CloudWatch Logs
by the controller's SSM agent regardless.

Idempotency / failure mode
--------------------------
adcli treats a delete of a non-existent computer name as success
(non-zero rc but logged warning). Running the cleanup twice is safe.
EventBridge retries are disabled at the rule level -- this is
best-effort cleanup, not a durable workflow. Any unexpected error is
logged and the Lambda still returns success so EventBridge does not
re-invoke.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

import boto3


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CLUSTER_ID = os.environ["EDH_CLUSTER_ID"]
REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "")
AD_SECRET_ARN = os.environ["AD_SERVICE_ACCOUNT_SECRET_ARN"]

# Node types whose AD object should be deleted on EC2 terminate.
# These are ephemeral by design -- they re-register on every boot.
EPHEMERAL_NODE_TYPES = {"compute_node", "login_node", "dcv_node"}


def _compute_soca_ad_hostname(cluster_id: str, region: str, instance_id: str) -> str:
    """
    Recompute the SOCA AD computer name from instance metadata, mirroring
    the bootstrap-script logic in
    source/soca/cluster_node_bootstrap/templates/linux/user_directory/
    active_directory/join_activedirectory.sh.j2.

    Bash equivalent in the bootstrap:
        local AWS_REGION=$(instance_region)
        HOSTNAME_DATA=$(echo "${EDH_CLUSTER_ID}-${AWS_REGION}-${AWS_INSTANCE_ID}" \
            | openssl dgst -sha1 -binary | xxd -p)
        SHAKE_VALUE=${HOSTNAME_DATA: -10}
        SOCA_AD_HOSTNAME="EDH-${SHAKE_VALUE^^}"

    `echo "..."` adds a trailing newline before piping into openssl, so
    we append "\\n" to match.

    Historical context: prior to the AWS_REGION fix in the bootstrap,
    `${AWS_REGION}` evaluated to empty (it was never `local`-set inside
    join_ad() and the global was not in /etc/environment). The hash was
    therefore sha1("<cluster_id>--<instance_id>\\n"). This Lambda was
    updated in lockstep with the bootstrap fix to use the proper region.

    NetBIOS legacy caps computer names at 15 characters; "EDH-" prefix
    (4) + 10 hex chars = 14, safely under the 15-char cap. The 10-char
    suffix is fixed and MUST match the Windows (ad_join_helpers.ps.j2)
    and Linux (join_activedirectory.sh.j2) derivations exactly.

    Used as a fallback when the EC2 tag `edh:ADComputerName` is not
    present (instance launched before the self-tag bootstrap change
    shipped, or the bootstrap-time create-tags call lost its IAM race).
    """
    payload = f"{cluster_id}-{region}-{instance_id}\n"
    sha1_hex = hashlib.sha1(payload.encode("utf-8")).hexdigest()
    return f"EDH-{sha1_hex[-10:].upper()}"


def _instance_tags(ec2_client, instance_id: str) -> dict[str, str]:
    """
    Return the tag dict for the given instance. EC2 state-change events
    do not embed tags, so we have to call DescribeInstances. A
    `shutting-down` instance is still describable -- the API only
    starts rejecting once it reaches `terminated` and ages out.
    """
    resp = ec2_client.describe_instances(InstanceIds=[instance_id])
    reservations = resp.get("Reservations", [])
    if not reservations:
        return {}
    instances = reservations[0].get("Instances", [])
    if not instances:
        return {}
    return {t["Key"]: t["Value"] for t in (instances[0].get("Tags") or [])}


def _get_ad_credentials() -> tuple[str, str]:
    """
    Retrieve the AD service account username and password from Secrets
    Manager. The secret JSON has the shape:
        {"username": "Admin@domain.name", "password": "<value>"}
    Returns (username_without_realm, password).
    """
    sm = boto3.client("secretsmanager", region_name=REGION)
    resp = sm.get_secret_value(SecretId=AD_SECRET_ARN)
    secret = json.loads(resp["SecretString"])
    username = secret["username"].split("@")[0]
    password = secret["password"]
    return username, password


def _build_delete_command(
    ad_computer_name: str, instance_id: str, username: str, password: str
) -> str:
    """
    Build the bash payload the controller will run via SSM. The script:

      1. Receives AD admin credentials (fetched from Secrets Manager by
         the Lambda) as shell variables interpolated into the script.
      2. Reads the realm domain from `realm list`.
      3. Pipes the password into `adcli delete-computer --stdin-password`.
      4. Always exits 0 -- AD object already absent is logged but not
         fatal, and we don't want EventBridge to misinterpret a
         best-effort cleanup as a hard failure.

    The cluster_id, computer name, username, and password are interpolated
    as bash single-quoted literals. The username and password are
    constrained by Secrets Manager generation rules (no single quotes).
    The instance_id is only used in log messages.
    """
    return f"""set +e
AD_NAME='{ad_computer_name}'
TERM_INSTANCE='{instance_id}'
USER='{username}'
PASS='{password}'

DOMAIN=$(realm list 2>/dev/null | awk '/domain-name/ {{ print $2; exit }}')

if [[ -z "$DOMAIN" ]]; then
  echo "[ADComputerCleaner] Controller is not joined to a realm; cannot delete $AD_NAME"
  exit 0
fi

echo "[ADComputerCleaner] Deleting AD computer object $AD_NAME from $DOMAIN (terminated EC2 $TERM_INSTANCE)"
echo "$PASS" | adcli delete-computer -U "$USER" --stdin-password --domain="$DOMAIN" "$AD_NAME" 2>&1
rc=$?
if [[ $rc -eq 0 ]]; then
  echo "[ADComputerCleaner] AD delete OK: $AD_NAME"
else
  echo "[ADComputerCleaner] AD delete returned rc=$rc for $AD_NAME (likely already absent); not failing"
fi
exit 0
"""


def _send_ssm_delete_command(
    ssm_client, ad_computer_name: str, instance_id: str, username: str, password: str
) -> str:
    """
    Send the delete command to the controller. Targets are tag-based
    so the command lands on whichever instance currently carries
    `edh:NodeType=controller` for this cluster -- this survives a
    controller replacement without the Lambda needing to know its
    instance ID.
    """
    cmd = _build_delete_command(ad_computer_name, instance_id, username, password)
    resp = ssm_client.send_command(
        Targets=[
            {"Key": "tag:edh:ClusterId", "Values": [CLUSTER_ID]},
            {"Key": "tag:edh:NodeType", "Values": ["controller"]},
        ],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [cmd]},
        Comment=f"ADComputerCleaner: delete {ad_computer_name} (term EC2 {instance_id})",
        TimeoutSeconds=120,
    )
    return resp["Command"]["CommandId"]


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    detail = event.get("detail") or {}
    instance_id = detail.get("instance-id")
    state = detail.get("state")

    if not instance_id:
        logger.warning("Event missing detail.instance-id; ignoring: %r", event)
        return {"action": "ignored", "reason": "no_instance_id"}

    logger.info(
        f"Received state-change for {instance_id} state={state} cluster={CLUSTER_ID}"
    )

    ec2 = boto3.client("ec2", region_name=REGION)
    try:
        tags = _instance_tags(ec2, instance_id)
    except Exception as exc:  # pylint: disable=broad-except
        # Race: describe failed (instance already aged out, throttled, etc.).
        # Without tags we can't filter or recover the AD name beyond a
        # bare hash recompute -- but we also don't know if it's our cluster.
        # Bail safely.
        logger.warning(f"DescribeInstances failed for {instance_id}: {exc}")
        return {
            "action": "ignored",
            "reason": "describe_failed",
            "error": str(exc),
        }

    cluster = tags.get("edh:ClusterId")
    node_type = tags.get("edh:NodeType")

    if cluster != CLUSTER_ID:
        return {
            "action": "ignored",
            "reason": "different_cluster",
            "cluster": cluster,
        }

    if node_type not in EPHEMERAL_NODE_TYPES:
        return {
            "action": "ignored",
            "reason": "non_ephemeral_node",
            "node_type": node_type,
        }

    # Resume-From (Saved Desktops): the instance was captured for later resume, so
    # its AD computer object MUST survive termination -- the resumed clone reuses the
    # same machine identity and heals its secure channel with a light password reset
    # rather than a full re-provision. Preserving the object is best-effort; the
    # resume-side heal re-provisions if the object is absent for any reason.
    if tags.get("edh:PreserveAdObject", "").lower() == "true":
        logger.info(
            f"Preserving AD object for {node_type} {instance_id} "
            f"(edh:PreserveAdObject=true); skipping delete."
        )
        return {
            "action": "ignored",
            "reason": "ad_object_preserved",
            "instance_id": instance_id,
        }

    # Prefer the explicit tag set by bootstrap (post-join self-tag) over
    # recomputing the hash. Recompute is a safety net for instances that
    # launched before the self-tag bootstrap change shipped, or in case
    # the self-tag write itself failed.
    ad_name = tags.get("edh:ADComputerName") or _compute_soca_ad_hostname(
        CLUSTER_ID, REGION, instance_id
    )

    logger.info(
        f"Cleaning AD object for terminated {node_type} {instance_id}: "
        f"computer_name={ad_name} source_tag={'edh:ADComputerName' in tags}"
    )

    try:
        username, password = _get_ad_credentials()
    except Exception as exc:
        logger.exception(f"Failed to retrieve AD credentials from Secrets Manager: {exc}")
        return {
            "action": "failed",
            "reason": "secret_fetch_failed",
            "ad_computer_name": ad_name,
            "error": str(exc),
        }

    ssm = boto3.client("ssm", region_name=REGION)
    try:
        command_id = _send_ssm_delete_command(ssm, ad_name, instance_id, username, password)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception(f"SSM SendCommand failed for {ad_name}: {exc}")
        # Best-effort: do not fail the Lambda. EventBridge retry would
        # not help (the cause is likely permissions or controller
        # missing) and would just amplify noise.
        return {
            "action": "failed",
            "reason": "ssm_send_failed",
            "ad_computer_name": ad_name,
            "error": str(exc),
        }

    return {
        "action": "delete_dispatched",
        "ad_computer_name": ad_name,
        "instance_id": instance_id,
        "ssm_command_id": command_id,
    }
