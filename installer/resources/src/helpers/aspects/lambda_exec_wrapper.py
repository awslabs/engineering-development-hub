# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Set AWS_LAMBDA_EXEC_WRAPPER on functions that attach the boto3 layer."""

import jsii
from aws_cdk import IAspect
from aws_cdk import aws_lambda as aws_lambda
from constructs import IConstruct

WRAPPER_PATH = "/opt/bin/edh-ua-wrapper"


@jsii.implements(IAspect)
class LambdaExecWrapperAspect:
    def __init__(self, boto3_layer_arn: str, wrapper_path: str = WRAPPER_PATH):
        self._boto3_layer_arn = boto3_layer_arn
        self._wrapper_path = wrapper_path

    def visit(self, node: IConstruct) -> None:
        if not self._boto3_layer_arn:
            return
        # Gate on the boto3 layer being attached so a function without the
        # wrapper script is never pointed at a missing wrapper.
        if isinstance(node, aws_lambda.CfnFunction):
            if self._boto3_layer_arn in (node.layers or []):
                node.add_property_override(
                    "Environment.Variables.AWS_LAMBDA_EXEC_WRAPPER",
                    self._wrapper_path,
                )
