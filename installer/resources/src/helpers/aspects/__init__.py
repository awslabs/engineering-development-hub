# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CDK Aspects (cross-cutting synth-time validators) for the SOCA / EDH installer."""

from .cdk_token_guard import CdkTokenGuardAspect
from .esm_tag_strip import EventSourceMappingTagStripAspect
from .lambda_exec_wrapper import LambdaExecWrapperAspect

__all__ = [
    "CdkTokenGuardAspect",
    "EventSourceMappingTagStripAspect",
    "LambdaExecWrapperAspect",
]
