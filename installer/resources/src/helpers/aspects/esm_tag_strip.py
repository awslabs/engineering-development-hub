# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
EventSourceMappingTagStripAspect -- removes the Tags property from every
AWS::Lambda::EventSourceMapping in partitions whose Lambda service rejects
event-source-mapping tags.

Why: the app applies cluster tags to every taggable resource
(Tags.of(app).add("edh:ClusterId", ...) in cdk_construct.py). Event source
mappings are taggable in the commercial partition, but in GovCloud/China the
Lambda CreateEventSourceMapping API returns
    "Invalid request provided: Tags not supported in request."
which fails the LambdaFleetStack. Stripping the Tags property from just the
ESM resources unblocks the stack; the SQS queue and the consumer Lambda still
carry their tags.

Partition-gated: constructed with the concrete STS-derived partition and only
strips for non-commercial partitions (aws-us-gov, aws-cn, ...). In commercial
(aws) it is a no-op, so ESM tagging is preserved where supported.
"""

import jsii
from aws_cdk import IAspect
from aws_cdk import aws_lambda as aws_lambda
from constructs import IConstruct


@jsii.implements(IAspect)
class EventSourceMappingTagStripAspect:
    """Strip Tags from CfnEventSourceMapping in partitions that don't support it."""

    def __init__(self, partition: str):
        # Commercial ("aws") supports ESM tagging; every other partition
        # (aws-us-gov, aws-cn, ...) rejects it as of this writing.
        self._strip = bool(partition) and partition != "aws"

    def visit(self, node: IConstruct) -> None:
        if not self._strip:
            return
        if isinstance(node, aws_lambda.CfnEventSourceMapping):
            # Applied at synth after TagManager renders Tags, so this reliably
            # removes the property regardless of aspect ordering.
            node.add_property_deletion_override("Tags")
