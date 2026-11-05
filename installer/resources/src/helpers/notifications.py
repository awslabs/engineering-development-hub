# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cluster notification infrastructure (SNS topic + email subscriptions).

``scope`` is the construct instance (CDK parent). ``soca_resources`` and
``user_specified_variables`` are passed explicitly; ``get_kms_key_id``,
``get_config_key`` and ``principals_suffix`` (defined in the cdk_construct
module/__main__ scope) are dependency-injected to avoid a circular import.

WHY THIS TOPIC NEEDS A CUSTOMER MANAGED KEY. The topic carries the CloudWatch
alarm actions attached by the DCV, SSM ConfigSync and VDI pool helpers, and
CloudWatch publishes them as the ``cloudwatch`` SERVICE principal rather than as
an IAM principal. The AWS managed key ``alias/aws/sns`` does not allow that
principal ``kms:Decrypt`` or ``kms:GenerateDataKey``, and an AWS managed key
policy cannot be edited. So a topic on ``alias/aws/sns`` accepts every alarm
action and then delivers nothing: CloudWatch records "CloudWatch Alarms does not
have authorization to access the SNS topic encryption key" in the alarm history,
and SNS never sees the message. The failure is silent on both sides, which is why
EDH now creates a key with the required statement instead of defaulting to the
service key.
"""

import logging

from aws_cdk import Aws, RemovalPolicy
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_sns as sns

logger = logging.getLogger("soca_logger")


def _create_notification_key(scope, user_specified_variables, principals_suffix):
    """Create the cluster-owned CMK for the notification topic.

    REMOVAL POLICY IS DESTROY, DELIBERATELY, AND SO IS THE ALIAS. The key
    protects alarm messages, which are ephemeral, so no ciphertext outlives the
    cluster and there is nothing to preserve. The matching pair also matters:
    an alias on DESTROY with a key on RETAIN is how twelve unreferenced CMKs
    accumulated in one test account -- each rebuild moved the alias to the new
    key and left the previous one with no name, no stack tag and a $1/month
    charge. CDK deletes an AWS::KMS::Alias with the stack either way, so the key
    must be DESTROY too or every rebuild of the same cluster orphans one.

    The key policy is NOT passed to the constructor. Doing so replaces CDK's
    default statement granting the account root kms:*, which is what makes the
    key administrable at all and what a key policy must carry to avoid being
    unmanageable. The CloudWatch grant is appended instead, the same way the
    topic's own resource policy is built below.
    """
    _key = kms.Key(
        scope,
        id="SNSClusterNotificationKey",
        description=(
            "CMK for the cluster notification SNS topic in cluster "
            f"{user_specified_variables.cluster_id}. Required because "
            "CloudWatch alarms cannot publish to a topic encrypted with "
            "alias/aws/sns."
        ),
        alias=f"edh/{user_specified_variables.cluster_id}/notification",
        enable_key_rotation=True,
        removal_policy=RemovalPolicy.DESTROY,
    )

    # The statement that makes alarm delivery work. Actions and principal are
    # as AWS documents them for this exact case; kms:GenerateDataKey* covers
    # GenerateDataKey and GenerateDataKeyWithoutPlaintext.
    _key.add_to_resource_policy(
        iam.PolicyStatement(
            sid="AllowCloudWatchAlarmsToUseThisKey",
            effect=iam.Effect.ALLOW,
            actions=["kms:Decrypt", "kms:GenerateDataKey*"],
            resources=["*"],
            principals=[iam.ServicePrincipal(principals_suffix["cloudwatch"])],
            # Scoped to this account so the grant cannot be exercised by a
            # CloudWatch alarm in someone else's account.
            conditions={"StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID}},
        )
    )

    # SNS itself needs the key to encrypt a published message at rest.
    _key.add_to_resource_policy(
        iam.PolicyStatement(
            sid="AllowSnsToUseThisKey",
            effect=iam.Effect.ALLOW,
            actions=["kms:Decrypt", "kms:GenerateDataKey*"],
            resources=["*"],
            principals=[iam.ServicePrincipal(principals_suffix["sns"])],
            conditions={"StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID}},
        )
    )

    logger.debug(
        "Created cluster-owned CMK for the notification topic with the "
        "CloudWatch alarm statement"
    )
    return _key


def setup(
    scope,
    soca_resources,
    user_specified_variables,
    *,
    get_kms_key_id,
    get_config_key,
    principals_suffix,
):
    """Create Cluster Notification Infrastructure."""
    logger.debug("Starting Cluster notification infrastructure")

    _sns_kms_key_id: str = get_kms_key_id(
        config_key_names=[
            "Config.services.notification.kms_key_id",
        ],
        allow_global_default=True,
    )
    logger.debug(f"SNS KMS for Cluster-Notification SNS Topic: {_sns_kms_key_id=}")

    if _sns_kms_key_id:
        # Customer supplied. EDH does not vet its key policy here -- it is not
        # EDH's key and CDK cannot read a policy at synth time. `edhctl
        # notifications list` reports at runtime whether the key is usable.
        _sns_kms_ikey = kms.Key.from_key_arn(
            scope,
            id="SNSClusterNotificationKeyID",
            key_arn=_sns_kms_key_id,
        )
    elif get_config_key(
        key_name="Config.services.notification.create_kms_key",
        expected_type=bool,
        required=False,
        default=True,
    ):
        _sns_kms_ikey = _create_notification_key(
            scope, user_specified_variables, principals_suffix
        )
    else:
        # Explicitly opted out of key creation and supplied no key. The topic
        # falls back to the service key, which means alarm actions are attached
        # and silently deliver nothing. Warn rather than fail: notifications are
        # not the cluster's core function, and failing the install over them
        # would be worse than degraded alarm delivery. The condition is also
        # reported at runtime by `edhctl notifications list`, so it is visible
        # in two places rather than silent.
        logger.warning(
            "Config.services.notification.create_kms_key is false and no "
            "Config.services.notification.kms_key_id (or Config.kms_key_id) is "
            "set, so the cluster notification topic will use alias/aws/sns. "
            "CloudWatch ALARM NOTIFICATIONS WILL NOT BE DELIVERED: that key "
            "policy does not allow the CloudWatch service principal to use the "
            "key and an AWS managed key policy cannot be edited. Set "
            "Config.services.notification.kms_key_id to a customer managed CMK "
            "whose key policy grants cloudwatch.amazonaws.com kms:Decrypt and "
            "kms:GenerateDataKey*, or set create_kms_key back to true."
        )
        _sns_kms_ikey = kms.Key.from_lookup(
            scope,
            id="SNSClusterNotificationKeyID",
            alias_name="alias/aws/sns",
        )

    soca_resources["sns_cluster_notification_key"] = _sns_kms_ikey

    # Create a cluster-notification SNS topic.
    soca_resources["sns_cluster_topic"] = sns.Topic(
        scope,
        id="SNSClusterNotificationTopic",
        display_name=f"{user_specified_variables.cluster_id}-Notification-SNS",
        topic_name=f"{user_specified_variables.cluster_id}-Notification-SNS",
        master_key=_sns_kms_ikey,
        enforce_ssl=True,
    )

    # Allow cloudwatch to send to our topic
    # Note: original SOCA pattern allowed "soca-*" ARNs (legacy
    # branding). EDH clusters use the cluster_id prefix, so the
    # condition needs to accept that too. ArnLike supports a list,
    # so allow both for back-compat.
    soca_resources["sns_cluster_topic"].add_to_resource_policy(
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["sns:Publish"],
            resources=[soca_resources["sns_cluster_topic"].topic_arn],
            principals=[iam.ServicePrincipal(principals_suffix["cloudwatch"])],
            conditions={
                "ArnLike": {
                    "aws:SourceArn": [
                        f"arn:{Aws.PARTITION}:*:*:{Aws.ACCOUNT_ID}:soca-*",
                        f"arn:{Aws.PARTITION}:cloudwatch:*:{Aws.ACCOUNT_ID}:alarm:{user_specified_variables.cluster_id}-*",
                    ]
                }
            },
        )
    )

    #
    #
    _cluster_email: list = user_specified_variables.email_address

    # Check for YAML config _AND_ CLI?
    # Should there be an ability to support multiple email addrs?
    # Comma on CLI, multiple --email , etc.
    # YAML list in config file?
    #
    #
    # Now that we have the topic, subscribe to it
    #

    logger.debug(f"Subscribing emails to Cluster SNS: {_cluster_email}")

    _email_addr_n: int = 0
    for _email_address in _cluster_email:
        logger.debug(f"Subscribing email to Cluster SNS: {_email_address}")
        soca_resources[
            f"sns_cluster_topic_subscription_email_{_email_addr_n}"
        ] = sns.Subscription(
            scope,
            f"{user_specified_variables.cluster_id}-SNSClusterNotificationSubscription{_email_addr_n}",
            protocol=sns.SubscriptionProtocol.EMAIL,
            endpoint=_email_address,
            topic=soca_resources["sns_cluster_topic"],
        )
        _email_addr_n += 1
