#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
LambdaFleetStack — NestedStack containing the ops-automation Lambda fleet.

This NestedStack houses ~18 Lambda functions (and their associated IAM roles,
policies, EventBridge rules, SQS queues, DDB tables, alarms, etc.) that were
previously defined in the parent stack. Moving them here frees ~146 CFN
resources from the parent stack's 500-resource limit.

The helper modules (helpers/dcv.py, helpers/ssm.py, helpers/vdi_pools.py, etc.)
accept a `scope` parameter — to move a Lambda into this nested stack, the
caller simply passes `self` (this NestedStack) instead of the parent stack.

This stack exposes a `soca_resources` dict and `generate_log_group` method
matching the parent stack's interface so helpers work unchanged.
"""

import typing
from typing import Dict, List, Optional, Any

from aws_cdk import (
    Duration,
    NestedStack,
    RemovalPolicy,
    Aws,
    aws_ec2 as ec2,
    aws_dynamodb as dynamodb,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_lambda as aws_lambda,
    aws_lambda_event_sources as lambda_event_sources,
    aws_logs as logs,
    aws_iam as iam,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subscriptions,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    aws_ssm as ssm,
    aws_s3 as s3,
    aws_s3_assets as s3_assets,
    aws_kms as kms,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as sfn_tasks,
)
from aws_cdk.aws_logs import ILogGroup, LogGroup
from constructs import Construct

import logging

logger = logging.getLogger("soca_logger")


class LambdaFleetStack(NestedStack):
    """
    NestedStack containing the EDH ops-automation Lambda fleet.

    Constructed by the parent stack after layers, VPC, SGs, and shared
    infrastructure are ready. Receives references to parent resources
    via constructor kwargs and exposes the same `soca_resources` / helper
    interface the existing helper modules expect.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        # --- Cluster identity ---
        cluster_id: str,
        # --- Shared infrastructure refs from parent ---
        soca_resources: Dict[str, Any],
        # --- Config accessor callables (same signature as parent) ---
        get_config_key,
        get_kms_key_id,
        user_specified_variables,
        principals_suffix,
        get_lambda_runtime_version,
        flatten_parameterstore_config,
        return_ebs_volume_type,
        get_supported_azs_list_by_instance_type=None,
        is_networking_af_enabled=None,
        # --- Optional feature gates (resolved by parent before instantiation) ---
        enable_dcv_high_scale: bool = False,
        enable_bootstrap_cache: bool = True,
        enable_vdi_pools: bool = True,
        enable_session_sharing: bool = True,
        enable_usb_allowlist: bool = False,
        # --- Parent-created resources needed for cross-refs ---
        directory_service_resource_setup: Optional[Dict] = None,
        **kwargs,
    ):
        super().__init__(scope, construct_id, **kwargs)

        self._cluster_id = cluster_id
        self._parent_soca_resources = soca_resources
        self._get_config_key = get_config_key
        self._get_kms_key_id = get_kms_key_id
        self._user_specified_variables = user_specified_variables
        self._principals_suffix = principals_suffix
        self._get_lambda_runtime_version = get_lambda_runtime_version
        self._flatten_parameterstore_config = flatten_parameterstore_config
        self._return_ebs_volume_type = return_ebs_volume_type
        self._get_supported_azs = get_supported_azs_list_by_instance_type
        self._is_networking_af_enabled = is_networking_af_enabled

        self._enable_dcv_high_scale = enable_dcv_high_scale
        self._enable_bootstrap_cache = enable_bootstrap_cache
        self._enable_vdi_pools = enable_vdi_pools
        self._enable_session_sharing = enable_session_sharing
        self._enable_usb_allowlist = enable_usb_allowlist
        self._directory_service_resource_setup = directory_service_resource_setup

        # Expose the same soca_resources dict the helpers expect.
        # This is a REFERENCE to the parent's dict — helpers that read
        # from it (layers, SGs, VPC, etc.) work unchanged. Resources
        # CREATED by helpers within this scope automatically belong to
        # the nested stack's template.
        self.soca_resources = soca_resources

        # Tag reservation Lambda reference (needed by some helpers)
        self.tag_ec2_resource_lambda = None

        # Collect outputs we need to expose back to parent
        self._outputs: Dict[str, str] = {}

        # ----- Build the fleet -----
        self._build()

    # ------------------------------------------------------------------
    # Interface methods matching parent stack (helpers call these)
    # ------------------------------------------------------------------

    def generate_log_group(
        self,
        name: str,
        prefix: str | None = None,
        log_group_class: str | None = None,
        retention: str | None = None,
        removal_policy: str | None = None,
        include_cluster_id: bool | None = True,
    ) -> ILogGroup:
        """
        Generate and return a CloudWatch log group.
        Mirrors the parent stack's generate_log_group.
        """
        _log_prefix = self._get_config_key(
            key_name="Config.services.logging.log_group_prefix",
            expected_type=str,
            required=False,
            default=prefix if prefix else "/edh",
        )

        _log_group_class_str = self._get_config_key(
            key_name="Config.services.logging.log_group_class",
            expected_type=str,
            required=False,
            default=log_group_class.upper() if log_group_class else "STANDARD",
        )
        _log_group_class_enum = logs.LogGroupClass(_log_group_class_str.upper())

        _retention_str = self._get_config_key(
            key_name="Config.services.logging.retention_policy",
            expected_type=str,
            required=False,
            default=retention.upper() if retention else "THREE_YEARS",
        )
        _retention_enum = logs.RetentionDays(_retention_str.upper())

        _removal_str = self._get_config_key(
            key_name="Config.services.logging.removal_policy",
            expected_type=str,
            required=False,
            default=removal_policy.upper() if removal_policy else "RETAIN",
        )
        _removal_enum = RemovalPolicy(_removal_str.upper())

        _include = self._get_config_key(
            key_name="Config.services.logging.log_group_include_cluster_id",
            expected_type=bool,
            required=False,
            default=True,
        ) if include_cluster_id is None else include_cluster_id

        _cluster_id = self._cluster_id
        _log_group_name = (
            f"{_log_prefix}/{_cluster_id}/{name}"
            if _include
            else f"{_log_prefix}/{name}"
        )

        return LogGroup(
            self,
            f"{name}LogGroup",
            log_group_name=_log_group_name,
            log_group_class=_log_group_class_enum,
            retention=_retention_enum,
            removal_policy=_removal_enum,
        )

    def get_log_deployment_id(self) -> str:
        """Return the deployment ID for log group naming (mirrors parent)."""
        return self._get_config_key(
            key_name="Config.deployment_id",
            expected_type=str,
            required=False,
            default="default",
        )

    def is_networking_af_enabled(self, address_family: str):
        """Networking address-family check (mirrors parent)."""
        return self._is_networking_af_enabled(address_family=address_family)

    # ------------------------------------------------------------------
    # Build orchestration
    # ------------------------------------------------------------------

    def _build(self):
        """
        Orchestrate construction of all fleet Lambda functions and their
        associated resources within this nested stack scope.
        """
        if self._enable_bootstrap_cache:
            self._register_bootstrap_cache_cleaner()

        if (
            self._directory_service_resource_setup
            and self._directory_service_resource_setup.get(
                "service_account_secret_arn"
            )
        ):
            self._register_ad_computer_cleaner()

        self._register_resource_cleanup_fleet()

        # Batch B: DCV event relay + screenshot poller + broker CA gen
        self._dcv_event_relay()

        # Batch C: SSM config sync/auditor/flusher
        self._ssm_config_sync()

        # Batch D: VDI launch history (DcvPlacement + CapacityExecutor)
        self._vdi_launch_history()

        # Batch E: VDI pool reconciler + tagger
        if self._enable_vdi_pools:
            self._vdi_pools()

        # Batch F: Session sharing expiry
        if self._enable_session_sharing:
            self._session_sharing()

        # Batch G: USB allowlist resolver
        if self._enable_usb_allowlist:
            self._usb_allowlist_resolver()

    # ------------------------------------------------------------------
    # Batch B-G: delegate to existing helper modules with self as scope
    # ------------------------------------------------------------------

    def _dcv_event_relay(self):
        from helpers import dcv as _helper

        _helper.dcv_event_relay(
            self,
            get_config_key=self._get_config_key,
            get_kms_key_id=self._get_kms_key_id,
            user_specified_variables=self._user_specified_variables,
            principals_suffix=self._principals_suffix,
            get_lambda_runtime_version=self._get_lambda_runtime_version,
            flatten_parameterstore_config=self._flatten_parameterstore_config,
            return_ebs_volume_type=self._return_ebs_volume_type,
        )

    def _ssm_config_sync(self):
        from helpers import ssm as _helper

        _helper.ssm_config_sync(
            self,
            get_config_key=self._get_config_key,
            user_specified_variables=self._user_specified_variables,
            get_lambda_runtime_version=self._get_lambda_runtime_version,
        )

    def _vdi_launch_history(self):
        from helpers import vdi_launch_history as _helper

        _helper.vdi_launch_history(
            self,
            user_specified_variables=self._user_specified_variables,
            get_lambda_runtime_version=self._get_lambda_runtime_version,
        )

    def _vdi_pools(self):
        from helpers import vdi_pools as _helper

        _helper.setup(
            scope=self,
            soca_resources=self.soca_resources,
            user_specified_variables=self._user_specified_variables,
            lambda_runtime=self._get_lambda_runtime_version(),
            get_config_key=self._get_config_key,
        )

    def _session_sharing(self):
        from helpers import dcv_session_sharing as _helper

        _helper.setup(
            scope=self,
            soca_resources=self.soca_resources,
            user_specified_variables=self._user_specified_variables,
            lambda_runtime=self._get_lambda_runtime_version(),
            get_config_key=self._get_config_key,
        )

    def _usb_allowlist_resolver(self):
        if not self.soca_resources.get("database"):
            return
        if "vdi_node_role" not in self.soca_resources:
            return

        from helpers.cdk.usb_allowlist_resolver import (
            build_usb_allowlist_resolver,
        )

        database_name = self._get_config_key(
            key_name="Config.database.aurora_serverless_v2.database_name",
            expected_type=str,
            default="edh",
            required=False,
        )
        build_usb_allowlist_resolver(
            self,
            cluster_id=self._cluster_id,
            database_name=database_name,
            get_lambda_runtime_version=self._get_lambda_runtime_version,
        )

    # ------------------------------------------------------------------
    # Fleet Lambda definitions
    # ------------------------------------------------------------------

    def _register_bootstrap_cache_cleaner(self):
        """
        Weekly aging sweep over the BootstrapTemplateCache S3 prefix.
        Simplest Lambda — no VPC, no SGs, no cross-refs beyond the
        cluster bucket.
        """
        _retention_days = self._get_config_key(
            key_name="Config.feature_flags.BootstrapTemplateCache.cleanup_retention_days",
            required=False,
            expected_type=int,
            default=30,
        )

        _cluster_id = self._cluster_id
        _bucket_name = self._user_specified_variables.bucket
        _cache_prefix = f"{_cluster_id}/bootstrap/cache/"

        _role = iam.Role(
            self,
            "BootstrapCacheCleanerRole",
            description="IAM role for the bootstrap-cache aging Lambda",
            assumed_by=iam.ServicePrincipal(self._principals_suffix["lambda"]),
        )

        _role.attach_inline_policy(
            iam.Policy(
                self,
                "BootstrapCacheCleanerPolicy",
                statements=[
                    iam.PolicyStatement(
                        actions=["s3:ListBucket"],
                        resources=[f"arn:{Aws.PARTITION}:s3:::{_bucket_name}"],
                        conditions={
                            "StringLike": {
                                "s3:prefix": [f"{_cache_prefix}*"],
                            }
                        },
                    ),
                    iam.PolicyStatement(
                        actions=["s3:DeleteObject"],
                        resources=[
                            f"arn:{Aws.PARTITION}:s3:::{_bucket_name}/{_cache_prefix}*"
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources=["*"],
                    ),
                ],
            )
        )

        _lambda = aws_lambda.Function(
            self,
            f"{_cluster_id}-BootstrapCacheCleaner",
            function_name=f"{_cluster_id}-BootstrapCacheCleaner",
            description="Weekly aging sweep over the BootstrapTemplateCache S3 prefix. Deletes entries older than cleanup_retention_days.",
            memory_size=256,
            runtime=typing.cast(
                aws_lambda.Runtime, self._get_lambda_runtime_version()
            ),
            timeout=Duration.minutes(5),
            log_group=self.generate_log_group(name="BootstrapCacheCleanerLambda"),
            role=_role,
            handler="BootstrapCacheCleaner.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/BootstrapCacheCleaner"),
            layers=[_l for _l in [self.soca_resources.get("boto3_layer")] if _l] or None,
            environment={
                "BUCKET": _bucket_name,
                "PREFIX": _cache_prefix,
                "RETENTION_DAYS": str(_retention_days),
            },
            retry_attempts=0,
        )

        events.Rule(
            self,
            "BootstrapCacheCleanerSchedule",
            description=(
                f"Weekly aging sweep of {_cluster_id} bootstrap-template "
                f"cache (retention_days={_retention_days})"
            ),
            enabled=True,
            schedule=events.Schedule.cron(
                minute="0", hour="3", week_day="SUN"
            ),
            targets=[events_targets.LambdaFunction(_lambda)],
        )

        self._bootstrap_cache_cleaner_lambda = _lambda
        return _lambda

    # ------------------------------------------------------------------
    # ADComputerCleaner
    # ------------------------------------------------------------------

    def _register_ad_computer_cleaner(self):
        """
        AD-orphan cleanup pipeline:
          EventBridge (EC2 shutting-down) --> Lambda --> ssm:SendCommand
          on the controller to run adcli delete-computer.
        """
        _cluster_id = self._cluster_id
        _region = self._user_specified_variables.region
        _secret_arn = self._directory_service_resource_setup.get(
            "service_account_secret_arn"
        )

        _role = iam.Role(
            self,
            "ADComputerCleanerRole",
            description="IAM role for the AD computer-object cleanup Lambda",
            assumed_by=iam.ServicePrincipal(self._principals_suffix["lambda"]),
        )
        _role.attach_inline_policy(
            iam.Policy(
                self,
                "ADComputerCleanerPolicy",
                statements=[
                    iam.PolicyStatement(
                        actions=["ec2:DescribeInstances"],
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        actions=["ssm:SendCommand"],
                        resources=[
                            f"arn:{Aws.PARTITION}:ssm:{_region}::document/AWS-RunShellScript",
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=["ssm:SendCommand"],
                        resources=[
                            f"arn:{Aws.PARTITION}:ec2:{_region}:{Aws.ACCOUNT_ID}:instance/*",
                        ],
                        conditions={
                            "StringEquals": {
                                "aws:ResourceTag/edh:ClusterId": _cluster_id,
                                "aws:ResourceTag/edh:NodeType": "controller",
                            }
                        },
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        actions=["secretsmanager:GetSecretValue"],
                        resources=[f"{_secret_arn}"],
                    ),
                ],
            )
        )

        _lambda = aws_lambda.Function(
            self,
            f"{_cluster_id}-ADComputerCleaner",
            function_name=f"{_cluster_id}-ADComputerCleaner",
            description="Deletes the AD computer object on EC2 terminate of ephemeral SOCA nodes (compute, login, dcv) so SPN does not orphan.",
            memory_size=128,
            runtime=typing.cast(
                aws_lambda.Runtime, self._get_lambda_runtime_version()
            ),
            timeout=Duration.minutes(2),
            log_group=self.generate_log_group(name="ADComputerCleanerLambda"),
            role=_role,
            handler="ADComputerCleaner.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/ADComputerCleaner"),
            layers=[_l for _l in [self.soca_resources.get("boto3_layer")] if _l] or None,
            environment={
                "EDH_CLUSTER_ID": _cluster_id,
                "AD_SERVICE_ACCOUNT_SECRET_ARN": _secret_arn,
            },
            retry_attempts=0,
        )

        events.Rule(
            self,
            "ADComputerCleanerRule",
            description=(
                f"Trigger {_cluster_id}-ADComputerCleaner "
                f"on EC2 shutting-down for ephemeral nodes in this cluster"
            ),
            enabled=True,
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=["EC2 Instance State-change Notification"],
                detail={"state": ["shutting-down"]},
            ),
            targets=[events_targets.LambdaFunction(_lambda)],
        )

        self._ad_computer_cleaner_lambda = _lambda
        return _lambda

    # ------------------------------------------------------------------
    # ODCR Cleaner + PlacementGroup Cleaner (SFN orchestration)
    # ------------------------------------------------------------------

    def _register_resource_cleanup_fleet(self):
        """
        Stand up the ODCR + PlacementGroup cleanup pipeline:
          - CapacityReservationCleaner Lambda
          - PlacementGroupCleaner Lambda
          - Step Functions state machine (parallel invocation)
          - EventBridge rules (schedule + CFN event pattern)
          - Direct ODCR Lambda EventBridge triggers (schedule + event)
        """
        _cluster_id = self._cluster_id
        _region = self._user_specified_variables.region

        # Lambdas — roles are pre-created in parent (helpers/iam.py)
        # and available via soca_resources.
        _odcr_cleaner_lambda = aws_lambda.Function(
            self,
            f"{_cluster_id}-CapacityReservationCleaner",
            function_name=f"{_cluster_id}-CapacityReservationCleaner",
            description="Delete idle EC2 capacity reservations deployed by SOCA",
            memory_size=128,
            runtime=typing.cast(
                aws_lambda.Runtime, self._get_lambda_runtime_version()
            ),
            system_log_level_v2=aws_lambda.SystemLogLevel.INFO,
            logging_format=aws_lambda.LoggingFormat.JSON,
            timeout=Duration.minutes(5),
            log_group=self.generate_log_group(
                name="CapacityReservationCleanerLambda"
            ),
            role=self.soca_resources["odcr_cleaner_lambda_role"],
            handler="ODCRCleaner.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/ODCRCleaner"),
            environment={"EDH_CLUSTER_ID": _cluster_id},
            layers=[
                l
                for l in [self.soca_resources.get("boto3_layer")]
                if l
            ],
        )

        _placement_group_cleaner_lambda = aws_lambda.Function(
            self,
            f"{_cluster_id}-PlacementGroupCleaner",
            function_name=f"{_cluster_id}-PlacementGroupCleaner",
            description="Delete idle Placement Group deployed by SOCA",
            memory_size=128,
            runtime=typing.cast(
                aws_lambda.Runtime, self._get_lambda_runtime_version()
            ),
            system_log_level_v2=aws_lambda.SystemLogLevel.INFO,
            logging_format=aws_lambda.LoggingFormat.JSON,
            timeout=Duration.minutes(5),
            log_group=self.generate_log_group(
                name="PlacementGroupCleanerLambda"
            ),
            role=self.soca_resources["placement_group_cleaner_lambda_role"],
            handler="PlacementGroupCleaner.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/PlacementGroupCleaner"),
            environment={"EDH_CLUSTER_ID": _cluster_id},
            layers=[
                l
                for l in [self.soca_resources.get("boto3_layer")]
                if l
            ],
        )

        # Step Functions — parallel cleanup
        odcr_task = sfn_tasks.LambdaInvoke(
            self,
            "RunIdleSOCACapacityReservationCleaner",
            lambda_function=_odcr_cleaner_lambda,
            payload=sfn.TaskInput.from_json_path_at("$"),
            result_path=sfn.JsonPath.DISCARD,
        )

        placement_group_task = sfn_tasks.LambdaInvoke(
            self,
            "RunIdleSOCAPlacementGroupCleaner",
            lambda_function=_placement_group_cleaner_lambda,
            payload=sfn.TaskInput.from_json_path_at("$"),
            result_path=sfn.JsonPath.DISCARD,
        )

        parallel_cleanup = sfn.Parallel(self, "CleanupResourcesInParallel")
        parallel_cleanup.branch(odcr_task)
        parallel_cleanup.branch(placement_group_task)

        cleanup_state_machine = sfn.StateMachine(
            self,
            "SOCAResourceCleanupStateMachine",
            state_machine_name=f"{_cluster_id}-IdleResourcesCleanup",
            definition_body=sfn.DefinitionBody.from_chainable(
                parallel_cleanup
            ),
            timeout=Duration.minutes(5),
        )

        _odcr_cleaner_lambda.grant_invoke(cleanup_state_machine.role)
        _placement_group_cleaner_lambda.grant_invoke(
            cleanup_state_machine.role
        )

        # EventBridge: trigger SFN on schedule
        events.Rule(
            self,
            "SOCAJobResourceCleanupSchedule",
            description="Trigger SOCA Idle Resources Cleanup Step Function on schedule",
            enabled=True,
            schedule=events.Schedule.cron(minute="*/5"),
            targets=[
                events_targets.SfnStateMachine(
                    cleanup_state_machine,
                    input=events.RuleTargetInput.from_object(
                        {"trigger": "schedule"}
                    ),
                )
            ],
        )

        # EventBridge: trigger SFN on CFN failure events
        events.Rule(
            self,
            "SOCAJobResourceCleanupEvent",
            description="Trigger SOCA Idle Resources Cleanup Step Function via custom CloudFormation events",
            enabled=True,
            event_pattern=events.EventPattern(
                source=["aws.cloudformation"],
                detail_type=["CloudFormation Stack Status Change"],
                detail={
                    "status-details": {
                        "status": [
                            "CREATE_FAILED",
                            "DELETE_IN_PROGRESS",
                            "ROLLBACK_IN_PROGRESS",
                        ]
                    },
                    "stack-id": [
                        {
                            "wildcard": f"arn:*:cloudformation:{_region}:{Aws.ACCOUNT_ID}:stack/{_cluster_id}-*/*"
                        }
                    ],
                },
            ),
            targets=[
                events_targets.SfnStateMachine(
                    cleanup_state_machine,
                    input=events.RuleTargetInput.from_object(
                        {
                            "stack_id": events.EventField.from_path(
                                "$.detail.stack-id"
                            ),
                            "status": events.EventField.from_path(
                                "$.detail.status-details.status"
                            ),
                            "trigger": "cloudformation",
                        }
                    ),
                )
            ],
        )

        self._odcr_cleaner_lambda = _odcr_cleaner_lambda
        self._placement_group_cleaner_lambda = _placement_group_cleaner_lambda
        self._cleanup_state_machine = cleanup_state_machine
