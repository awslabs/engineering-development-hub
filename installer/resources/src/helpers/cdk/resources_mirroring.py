# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CDK helper: resources_mirroring — cloud-side mirror executor.

Provisions (D1-D15):
  - ResourceMirrorExecutor Lambda (one invocation per manifest item; region-aware)
  - ResourceMirrorEvaluate Lambda (D14 whole-step gate terminal state)
  - SFN StateMachine: Inline Map (items passed inline by the trigger) -> EvaluateResults
  - ResourceMirrorTrigger custom-resource Lambda: reads the manifest via boto3 (region
    hint, D15), starts the SFN with items inline, BLOCKS to terminal, maps to CFN
  - Least-priv IAM (ARCC BSC6): scoped actions + resource ARNs, no wildcards

The state machine is deployed from the exact ASL validated in the spot test
(DefinitionBody.from_string) so deployed == tested.
"""

import json

from aws_cdk import (
    Aws,
    Duration,
    CustomResource,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_stepfunctions as sfn,
    aws_logs as logs,
)
from constructs import Construct

FUNCTIONS_DIR = "../functions"  # asset path convention used by cdk_construct.py (from installer/resources/src)


def resources_mirroring(
    scope: Construct,
    cluster_id: str,
    mirror_bucket_name: str,
    manifest_s3_key: str,
    mirror_region: str = None,  # D15: bucket region hint (installer probe)
    failure_mode: str = "hard",  # D14: hard|soft whole-step gate
    max_concurrency: int = 16,  # D7: sweep showed ~16 captures essentially all
    # available parallelism; past that the wall-clock
    # floor is the single largest artifact (long pole),
    # not lane count (Amdahl). Higher = no gain for a
    # typical catalog with one dominant file (e.g. EFA).
    timeout_minutes: int = 15,  # per-item executor timeout
    block_timeout_minutes: int = 15,  # trigger must outlast the whole mirror run
    mirror_s3_sources: bool = True,  # D11
    vpc_config: dict = None,  # D12 placement knob (None = cloud-no-vpc)
    get_lambda_runtime_version=None,  # shared runtime helper (keeps fleet on one version)
):
    # Derive the bucket ARN from the name using the CFN partition token. Aws.PARTITION
    # resolves at deploy time and is correct for aws/aws-cn/aws-us-gov -- never None,
    # and independent of how (or whether) the installer plumbed a partition string.
    mirror_bucket_arn = f"arn:{Aws.PARTITION}:s3:::{mirror_bucket_name}"

    # ---------- Executor Lambda (per-artifact) ----------
    _execution_managed_policy = (
        "service-role/AWSLambdaVPCAccessExecutionRole"
        if vpc_config
        else "service-role/AWSLambdaBasicExecutionRole"
    )
    executor_role = iam.Role(
        scope,
        "ResourceMirrorExecutorRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(_execution_managed_policy)
        ],
    )
    # S3: read/write only the mirror prefix. GetObjectAttributes = native checksum
    # skip/verify; PutObjectTagging = refresh ops tags on skip without rewrite (D13).
    executor_role.add_to_policy(
        iam.PolicyStatement(
            actions=[
                "s3:PutObject",
                "s3:GetObject",
                "s3:HeadObject",
                "s3:CopyObject",
                "s3:GetObjectAttributes",
                "s3:PutObjectTagging",
                "s3:GetObjectTagging",
            ],
            resources=[f"{mirror_bucket_arn}/{cluster_id}/resources_mirroring/*"],
        )
    )
    # SSM: rewrite only owned config keys (D5 pipe-string repoint).
    executor_role.add_to_policy(
        iam.PolicyStatement(
            actions=["ssm:PutParameter"],
            resources=[
                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/edh/{cluster_id}/*"
            ],
        )
    )
    # D11: mirror remote s3:// sources (cross-account read, condition-scoped).
    if mirror_s3_sources:
        executor_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[f"arn:{Aws.PARTITION}:s3:::*/*"],
                conditions={"StringNotEquals": {"s3:ResourceAccount": Aws.ACCOUNT_ID}},
            )
        )

    executor_env = {
        "MIRROR_BUCKET": mirror_bucket_name,
        "CLUSTER_ID": cluster_id,
        "MIRROR_S3_SOURCES": "true" if mirror_s3_sources else "false",
    }
    if mirror_region:  # D15: region-explicit S3 IO
        executor_env["MIRROR_REGION"] = mirror_region

    executor_kwargs = {
        "runtime": get_lambda_runtime_version(),
        "handler": "ResourceMirrorExecutor.handler",
        "code": _lambda.Code.from_asset(f"{FUNCTIONS_DIR}/ResourceMirrorExecutor"),
        "layers": [_l for _l in [scope.soca_resources.get("boto3_layer")] if _l] or None,
        "timeout": Duration.minutes(timeout_minutes),
        "memory_size": 256,
        "role": executor_role,
        "environment": executor_env,
        "log_group": scope.generate_log_group(name="ResourceMirrorExecutorLambda"),
    }
    if vpc_config:  # D12
        executor_kwargs["vpc"] = vpc_config["vpc"]
        executor_kwargs["vpc_subnets"] = vpc_config.get("subnets")
    executor_lambda = _lambda.Function(
        scope,
        "ResourceMirrorExecutor",
        function_name=f"{cluster_id}-ResourceMirrorExecutor",
        **executor_kwargs,
    )

    # ---------- EvaluateResults Lambda (D14 gate terminal state) ----------
    evaluate_lambda = _lambda.Function(
        scope,
        "ResourceMirrorEvaluate",
        function_name=f"{cluster_id}-ResourceMirrorEvaluate",
        runtime=get_lambda_runtime_version(),
        handler="ResourceMirrorEvaluate.handler",
        code=_lambda.Code.from_asset(f"{FUNCTIONS_DIR}/ResourceMirrorEvaluate"),
        layers=[_l for _l in [scope.soca_resources.get("boto3_layer")] if _l] or None,
        timeout=Duration.seconds(30),
        memory_size=128,
        log_group=scope.generate_log_group(name="ResourceMirrorEvaluateLambda"),
    )

    # ---------- SFN: exact validated ASL (items inline -> Map -> EvaluateResults) ----------
    asl = {
        "Comment": "ResourceMirror: items inline (D15) -> Inline Map -> EvaluateResults gate (D14)",
        "StartAt": "MirrorArtifactsMap",
        "States": {
            "MirrorArtifactsMap": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": max_concurrency,
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "MirrorOneArtifact",
                    "States": {
                        "MirrorOneArtifact": {
                            "Type": "Task",
                            "Resource": f"arn:{Aws.PARTITION}:states:::lambda:invoke",
                            "Parameters": {
                                "FunctionName": executor_lambda.function_arn,
                                "Payload.$": "$",
                            },
                            "Retry": [
                                {
                                    "ErrorEquals": ["States.ALL"],
                                    "IntervalSeconds": 10,
                                    "MaxAttempts": 2,
                                    "BackoffRate": 2.0,
                                }
                            ],
                            "Catch": [
                                {
                                    "ErrorEquals": ["States.ALL"],
                                    "ResultPath": "$.error",
                                    "Next": "ItemFailed",
                                }
                            ],
                            "ResultSelector": {"result.$": "$.Payload"},
                            "End": True,
                        },
                        "ItemFailed": {
                            "Type": "Pass",
                            "Parameters": {
                                "status": "failed_caught",
                                "s3_target.$": "$.s3_target",
                                "error.$": "$.error.Cause",
                            },
                            "End": True,
                        },
                    },
                },
                "ResultPath": "$.results",
                "Next": "EvaluateResults",
            },
            "EvaluateResults": {
                "Type": "Task",
                "Resource": f"arn:{Aws.PARTITION}:states:::lambda:invoke",
                "Parameters": {
                    "FunctionName": evaluate_lambda.function_arn,
                    "Payload": {
                        "results.$": "$.results",
                        "failure_mode.$": "$.failure_mode",
                    },
                },
                "ResultSelector": {"summary.$": "$.Payload"},
                "End": True,
            },
        },
    }

    state_machine = sfn.StateMachine(
        scope,
        "ResourceMirrorStateMachine",
        state_machine_name=f"{cluster_id}-ResourceMirror",
        definition_body=sfn.DefinitionBody.from_string(json.dumps(asl)),
        timeout=Duration.minutes(30),
        logs=sfn.LogOptions(
            destination=logs.LogGroup(
                scope,
                "ResourceMirrorSfnLogs",
                log_group_name=f"/aws/vendedlogs/{cluster_id}/states/ResourceMirror",
                retention=logs.RetentionDays.TWO_WEEKS,
            ),
            level=sfn.LogLevel.ERROR,
        ),
    )
    executor_lambda.grant_invoke(state_machine.role)
    evaluate_lambda.grant_invoke(state_machine.role)

    # ---------- Trigger custom-resource Lambda (D9 auto-fire, D15 manifest read, blocking) ----------
    trigger_role = iam.Role(
        scope,
        "ResourceMirrorTriggerRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            )
        ],
    )
    trigger_role.add_to_policy(
        iam.PolicyStatement(
            actions=["states:StartExecution", "states:DescribeExecution"],
            resources=[
                state_machine.state_machine_arn,
                f"arn:{Aws.PARTITION}:states:{Aws.REGION}:{Aws.ACCOUNT_ID}:execution:{cluster_id}-ResourceMirror:*",
            ],
        )
    )
    # D15: trigger reads the manifest object via boto3 (region hint).
    trigger_role.add_to_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[f"{mirror_bucket_arn}/{manifest_s3_key}"],
    ))
    trigger_role.add_to_policy(iam.PolicyStatement(
        actions=["s3:ListBucket"],
        resources=[mirror_bucket_arn],
    ))

    trigger_lambda = _lambda.Function(
        scope,
        "ResourceMirrorTrigger",
        function_name=f"{cluster_id}-ResourceMirrorTrigger",
        runtime=get_lambda_runtime_version(),
        handler="ResourceMirrorTrigger.handler",
        code=_lambda.Code.from_asset(f"{FUNCTIONS_DIR}/ResourceMirrorTrigger"),
        layers=[_l for _l in [scope.soca_resources.get("boto3_layer")] if _l] or None,
        timeout=Duration.minutes(block_timeout_minutes),  # must outlast the mirror run
        memory_size=128,
        role=trigger_role,
        log_group=scope.generate_log_group(name="ResourceMirrorTriggerLambda"),
    )

    # D10/D12: method label
    mirroring_method = "cloud-in-vpc-nat" if vpc_config else "cloud-no-vpc"

    CustomResource(
        scope,
        "ResourceMirrorCustomResource",
        service_token=trigger_lambda.function_arn,
        properties={
            "StateMachineArn": state_machine.state_machine_arn,
            "ManifestBucket": mirror_bucket_name,
            "ManifestKey": manifest_s3_key,
            "BucketRegion": mirror_region or "",
            "FailureMode": failure_mode,
            "MirroringMethod": mirroring_method,
        },
    )

    return state_machine, executor_lambda, evaluate_lambda, trigger_lambda
