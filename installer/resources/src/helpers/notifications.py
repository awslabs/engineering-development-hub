# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cluster notification infrastructure (SNS topic + email subscriptions).

Extracted verbatim from cdk_construct.py. ``scope`` is the
construct instance (CDK parent). ``soca_resources`` and
``user_specified_variables`` are passed explicitly; ``get_kms_key_id`` and
``principals_suffix`` (defined in the cdk_construct module/__main__ scope) are
dependency-injected to avoid a circular import.
"""

import logging

from aws_cdk import Aws
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_sns as sns

logger = logging.getLogger("soca_logger")


def setup(
    scope,
    soca_resources,
    user_specified_variables,
    *,
    get_kms_key_id,
    principals_suffix,
):
    """Create Cluster Notification Infrastructure."""
    logger.debug("Starting Cluster notification infrastructure")

    _sns_kms_key_id: str = get_kms_key_id(
        config_key_names=[
            "Config.services.notification.kms_key_id",  # Should there be an alternate for the SNS Key?
        ],
        allow_global_default=True,
    )
    logger.debug(f"SNS KMS for Cluster-Notification SNS Topic: {_sns_kms_key_id=}")

    if _sns_kms_key_id:
        _sns_kms_ikey = kms.Key.from_key_arn(
            scope,
            id="SNSClusterNotificationKeyID",
            key_arn=_sns_kms_key_id,
        )
    else:
        # Import the service default alias
        _sns_kms_ikey = kms.Key.from_lookup(
            scope,
            id="SNSClusterNotificationKeyID",
            alias_name="alias/aws/sns",
        )
        logger.debug("SNS Topic using service-default KMS key alias/aws/sns")

    # Create a cluster-notification SNS
    # Create CloudWatch/SNS alarm for SNS EFS. This will check BurstCreditBalance and increase allocated throughput to support temporary burst activity if needed
    soca_resources["sns_cluster_topic"] = sns.Topic(
        scope,
        id="SNSClusterNotificationTopic",
        display_name=f"{user_specified_variables.cluster_id}-Notification-SNS",
        topic_name=f"{user_specified_variables.cluster_id}-Notification-SNS",
        master_key=_sns_kms_ikey if _sns_kms_ikey else None,
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
