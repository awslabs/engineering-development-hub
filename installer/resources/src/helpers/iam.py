#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

from aws_cdk import Aws, aws_iam as iam

import json

import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

# IAM roles for the cluster

logger = logging.getLogger("soca_logger")


def iam_roles(
    scope,
    *,
    get_config_key=None,
    user_specified_variables=None,
    principals_suffix=None,
    get_service_principal_url_suffix=None,
):
    """
    Configure IAM roles & policies for the various resources
    """
    # Specify if customers want to re-use existing IAM role for controller/compute nodes/spotfleet
    if user_specified_variables.controller_role_name:
        use_existing_roles = True
    else:
        use_existing_roles = False

    # Create IAM roles
    scope.soca_resources["backup_role"] = iam.Role(
        scope,
        "BackupRole",
        description="IAM role to manage AWS Backup & Restore jobs",
        assumed_by=iam.ServicePrincipal(principals_suffix["backup"]),
    )

    scope.soca_resources["solution_metrics_lambda_role"] = iam.Role(
        scope,
        "SolutionMetricsLambdaRole",
        description="IAM role assigned to the SolutionMetrics Lambda function",
        assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
    )

    scope.soca_resources["odcr_cleaner_lambda_role"] = iam.Role(
        scope,
        "CapacityReservationLambdaRole",
        description="IAM role assigned to the ODCR Cleaner Lambda function",
        assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
    )

    scope.soca_resources["placement_group_cleaner_lambda_role"] = iam.Role(
        scope,
        "PlacementGroupCleanerLambdaRole",
        description="IAM role assigned to the Placement Group Cleaner Lambda function",
        assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
    )

    scope.soca_resources["nested_virt_launcher_lambda_role"] = iam.Role(
        scope,
        "NestedVirtLauncherLambdaRole",
        description="IAM role assigned to the NestedVirtLauncher Lambda function",
        assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
    )

    if not use_existing_roles:
        # Create Controller/ComputeNode/SpotFleet roles if not specified by the user
        scope.soca_resources["controller_role"] = iam.Role(
            scope,
            "ControllerRole",
            description="IAM role assigned to the controller host",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal(principals_suffix["ssm"]),
                iam.ServicePrincipal(principals_suffix["ec2"]),
            ),
        )
        # Controller-wide DynamoDB access. The controller (web tier) is the
        # cluster's privileged orchestrator and touches nearly every EDH table
        # (pools, launch history, notifications, session sharing, ...). Rather
        # than have each feature bolt on its own per-table grant (whack-a-mole +
        # IAM bloat), grant the controller a single cluster-prefixed wildcard.
        # All EDH tables are named <cluster_id>-* (the cluster_id value already
        # carries any environment prefix, e.g. edh-share1), so the trailing
        # hyphen keeps this scoped to THIS cluster (edh-share1-* does not match
        # edh-share10-*). NOTE: this is a CONTROLLER-WIDE grant. Lambdas and
        # other roles stay per-table scoped to least privilege.
        scope.soca_resources["controller_role"].attach_inline_policy(
            iam.Policy(
                scope,
                "ControllerDynamoDbClusterAccess",
                statements=[
                    iam.PolicyStatement(
                        actions=[
                            "dynamodb:Query",
                            "dynamodb:Scan",
                            "dynamodb:GetItem",
                            "dynamodb:BatchGetItem",
                            "dynamodb:PutItem",
                            "dynamodb:UpdateItem",
                            "dynamodb:DeleteItem",
                            "dynamodb:BatchWriteItem",
                            "dynamodb:DescribeTable",
                        ],
                        resources=[
                            f"arn:{Aws.PARTITION}:dynamodb:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/{user_specified_variables.cluster_id}-*",
                            f"arn:{Aws.PARTITION}:dynamodb:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/{user_specified_variables.cluster_id}-*/index/*",
                        ],
                    ),
                    # Transient app-managed tables ({cluster_id}-rtm-*) get full lifecycle; infra tables (Statement 1) stay data-plane-only so the app cannot create/drop them.
                    iam.PolicyStatement(
                        actions=[
                            "dynamodb:CreateTable",
                            "dynamodb:DeleteTable",
                            "dynamodb:UpdateTimeToLive",
                            "dynamodb:DescribeTimeToLive",
                            "dynamodb:TagResource",
                        ],
                        resources=[
                            f"arn:{Aws.PARTITION}:dynamodb:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/{user_specified_variables.cluster_id}-rtm-*",
                            f"arn:{Aws.PARTITION}:dynamodb:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/{user_specified_variables.cluster_id}-rtm-*/index/*",
                        ],
                    ),
                ],
            )
        )
        scope.soca_resources["compute_node_role"] = iam.Role(
            scope,
            "ComputeNodeRole",
            description="IAM role assigned to the compute nodes",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal(principals_suffix["ssm"]),
                iam.ServicePrincipal(principals_suffix["ec2"]),
            ),
        )

        # VDI (eVDI/DCV virtual desktop) nodes get their own dedicated role,
        # split out from the compute-node role they historically shared. VDIs
        # are full HPC-complex participants (they run PBS/LSF scheduler
        # clients), so the role base policy (Vdi.json) is currently a copy of
        # ComputeNode.json -- but owning a separate identity lets VDI and
        # compute permissions diverge over time without cross-contamination
        # (BSC6 least-privilege: one role per workload).
        scope.soca_resources["vdi_node_role"] = iam.Role(
            scope,
            "VdiNodeRole",
            description="IAM role assigned to the VDI (eVDI/DCV) nodes",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal(principals_suffix["ssm"]),
                iam.ServicePrincipal(principals_suffix["ec2"]),
            ),
        )

        scope.soca_resources["target_node_role"] = iam.Role(
            scope,
            "TargetNodeRole",
            description="IAM role assigned to the target nodes",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal(principals_suffix["ssm"]),
                iam.ServicePrincipal(principals_suffix["ec2"]),
            ),
        )

        scope.soca_resources["spot_fleet_role"] = iam.Role(
            scope,
            "SpotFleetRole",
            description="IAM role to manage SpotFleet requests",
            assumed_by=iam.ServicePrincipal(principals_suffix["spotfleet"]),
        )
        scope.soca_resources["spot_fleet_role"].add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AmazonEC2SpotFleetTaggingRole"
            )
        )
        #
        # LoginNode Role
        #
        scope.soca_resources["login_node_role"] = iam.Role(
            scope,
            "LoginNodeRole",
            description="IAM role assigned to the login nodes",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal(principals_suffix["ssm"]),
                iam.ServicePrincipal(principals_suffix["ec2"]),
            ),
        )

        # Do we need our DCV high-scale IAM roles?
        if get_config_key(
            key_name="Config.dcv.high_scale",
            required=False,
            expected_type=bool,
            default=False,
        ):
            logger.debug("Creating DCV High Scale roles...")
            for _dcv_host_type in ("broker", "gateway"):
                logger.debug(
                    f"Creating IAM role for DCV host type: {_dcv_host_type}"
                )
                scope.soca_resources[f"dcv_{_dcv_host_type}_role"] = iam.Role(
                    scope,
                    f"Dcv{_dcv_host_type.capitalize()}Role",
                    description=f"IAM role assigned to DCV {_dcv_host_type} hosts",
                    assumed_by=iam.CompositePrincipal(
                        iam.ServicePrincipal(principals_suffix["ssm"]),
                        iam.ServicePrincipal(principals_suffix["ec2"]),
                    ),
                )
                # Make sure the Admin can SSM to the DCV Infrastructure
                scope.soca_resources[
                    f"dcv_{_dcv_host_type}_role"
                ].add_managed_policy(
                    iam.ManagedPolicy.from_aws_managed_policy_name(
                        "AmazonSSMManagedInstanceCore"
                    )
                )
                # DCV High-scale instance profiles
                logger.debug(
                    f"Creating Instance profile for DCV host {_dcv_host_type}"
                )
                scope.soca_resources[f"dcv_{_dcv_host_type}_instance_profile"] = (
                    iam.CfnInstanceProfile(
                        scope,
                        f"Dcv{_dcv_host_type.capitalize()}InstanceProfile",
                        roles=[
                            scope.soca_resources[
                                f"dcv_{_dcv_host_type}_role"
                            ].role_name
                        ],
                    )
                )

        # Instance Profiles
        scope.soca_resources["compute_node_instance_profile"] = (
            iam.CfnInstanceProfile(
                scope,
                "ComputeNodeInstanceProfile",
                roles=[scope.soca_resources["compute_node_role"].role_name],
            )
        )

        scope.soca_resources["vdi_node_instance_profile"] = (
            iam.CfnInstanceProfile(
                scope,
                "VdiNodeInstanceProfile",
                roles=[scope.soca_resources["vdi_node_role"].role_name],
            )
        )

        scope.soca_resources["target_node_instance_profile"] = (
            iam.CfnInstanceProfile(
                scope,
                "TargetNodeInstanceProfile",
                roles=[scope.soca_resources["target_node_role"].role_name],
            )
        )

    else:
        # Reference existing Controller/ComputeNode/SpotFleet roles
        scope.soca_resources["controller_role"] = iam.Role.from_role_arn(
            scope,
            "ControllerRole",
            role_arn=user_specified_variables.controller_role_arn,
        )
        scope.soca_resources["compute_node_role"] = iam.Role.from_role_arn(
            scope,
            "ComputeNodeRole",
            role_arn=user_specified_variables.compute_node_role_arn,
        )
        scope.soca_resources["spot_fleet_role"] = iam.Role.from_role_arn(
            scope,
            "SpotFleetRole",
            role_arn=user_specified_variables.spotfleet_role_arn,
        )
        scope.soca_resources["compute_node_instance_profile"] = (
            iam.CfnInstanceProfile(
                scope,
                "ComputeNodeInstanceProfile",
                roles=[user_specified_variables.compute_node_role_name],
            )
        )

        # BYO-role path: we do not fabricate a separate managed VDI role when
        # the operator supplies their own roles. VDIs continue to share the
        # operator-supplied compute-node role/profile, preserving pre-split
        # behavior. The VdiNode* config keys therefore resolve to the same
        # values as the ComputeNode* keys for these deployments.
        scope.soca_resources["vdi_node_role"] = scope.soca_resources[
            "compute_node_role"
        ]
        scope.soca_resources["vdi_node_instance_profile"] = scope.soca_resources[
            "compute_node_instance_profile"
        ]

    # Add SSM Managed Policy
    for _role in [
        "controller_role",
        "compute_node_role",
        "vdi_node_role",
        "login_node_role",
        "target_node_role",
    ]:
        if _role not in scope.soca_resources:
            logger.debug(f"Skipping SSM Managed Policy for {_role} (not created)")
            continue
        logger.debug(f"Adding SSM Managed Policy to {_role}")
        scope.soca_resources[_role].add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonSSMManagedInstanceCore"
            )
        )

    # Generate IAM inline policies
    policy_substitutes = {
        "%%AWS_ACCOUNT_ID%%": Aws.ACCOUNT_ID,
        "%%AWS_PARTITION%%": Aws.PARTITION,
        "%%AWS_URL_SUFFIX%%": get_service_principal_url_suffix(),
        "%%AWS_REGION%%": (
            "*"
            if user_specified_variables.region.startswith("eusc-")
            else Aws.REGION
        ),
        "%%BUCKET%%": user_specified_variables.bucket,
        "%%COMPUTE_NODE_ROLE_ARN%%": (
            scope.soca_resources["compute_node_role"].role_arn
            if not user_specified_variables.compute_node_role_arn
            else user_specified_variables.compute_node_role_arn
        ),
        "%%SCHEDULER_ROLE_ARN%%": (
            scope.soca_resources["controller_role"].role_arn
            if not user_specified_variables.controller_role_arn
            else user_specified_variables.controller_role_arn
        ),
        "%%SPOTFLEET_ROLE_ARN%%": (
            scope.soca_resources["spot_fleet_role"].role_arn
            if not user_specified_variables.spotfleet_role_arn
            else user_specified_variables.spotfleet_role_arn
        ),
        "%%TARGET_NODE_ROLE_ARN%%": (
            scope.soca_resources["target_node_role"].role_arn
            if "target_node_role" in scope.soca_resources
            else ""
        ),
        "%%VPC_ID%%": scope.soca_resources["vpc"].vpc_id,
        "%%CLUSTER_ID%%": user_specified_variables.cluster_id,
        "%%VERSION%%": get_config_key("Config.version"),
    }

    policy_templates = {
        "BackupPolicy": {
            "template": "../policies/Backup.json",
            "attach_to_role": "backup_role",
        },
        "SolutionMetricsLambdaPolicy": {
            "template": "../policies/SolutionMetricsLambda.json",
            "attach_to_role": "solution_metrics_lambda_role",
        },
        "ODCRCleanerLambdaPolicy": {
            "template": "../policies/ODCRCleanerLambda.json",
            "attach_to_role": "odcr_cleaner_lambda_role",
        },
        "PlacementGroupCleanerLambdaPolicy": {
            "template": "../policies/PlacementGroupCleanerLambda.json",
            "attach_to_role": "placement_group_cleaner_lambda_role",
        },
        "NestedVirtLauncherLambdaPolicy": {
            "template": "../policies/NestedVirtLauncherLambda.json",
            "attach_to_role": "nested_virt_launcher_lambda_role",
        },
    }

    if not use_existing_roles:
        policy_templates["ComputeNodePolicy"] = {
            "template": "../policies/ComputeNode.json",
            "attach_to_role": "compute_node_role",
        }
        policy_templates["VdiNodePolicy"] = {
            "template": "../policies/Vdi.json",
            "attach_to_role": "vdi_node_role",
        }
        policy_templates["TargetNodePolicy"] = {
            "template": "../policies/TargetNode.json",
            "attach_to_role": "target_node_role",
        }

        # Controller permissions split across 4 managed policies (each
        # has its own 6144-byte cap, decoupled from the 10240-byte
        # inline aggregate). Buckets are semantic, not just byte-balanced.
        policy_templates["ControllerEC2ReadPolicy"] = {
            "template": "../policies/ControllerEC2Read.json",
            "attach_to_role": "controller_role",
            "policy_type": "managed",
        }
        policy_templates["ControllerEC2WritePolicy"] = {
            "template": "../policies/ControllerEC2Write.json",
            "attach_to_role": "controller_role",
            "policy_type": "managed",
        }
        policy_templates["ControllerNetworkingPolicy"] = {
            "template": "../policies/ControllerNetworking.json",
            "attach_to_role": "controller_role",
            "policy_type": "managed",
        }
        policy_templates["ControllerServicesPolicy"] = {
            "template": "../policies/ControllerServices.json",
            "attach_to_role": "controller_role",
            "policy_type": "managed",
        }
        policy_templates["SpotFleetPolicy"] = {
            "template": "../policies/SpotFleet.json",
            "attach_to_role": "spot_fleet_role",
        }
        policy_templates["LoginNodePolicy"] = {
            "template": "../policies/LoginNode.json",
            "attach_to_role": "login_node_role",
        }

        if get_config_key(
            key_name="Config.dcv.high_scale",
            required=False,
            expected_type=bool,
            default=False,
        ):
            logger.debug("Attaching IAM Policies for DCV hosts ...")
            for _dcv_host_type in ("broker", "gateway"):
                policy_templates[f"Dcv{_dcv_host_type.capitalize()}Policy"] = {
                    "template": f"../policies/DCV/Dcv{_dcv_host_type.capitalize()}.json",
                    "attach_to_role": f"dcv_{_dcv_host_type}_role",
                }
                logger.debug(
                    f"Attaching IAM Policies for DCV host type {_dcv_host_type}: {policy_templates[f'Dcv{_dcv_host_type.capitalize()}Policy']}"
                )

    else:
        # Append required policies if IAM specified by user have not been generated by SOCA
        if user_specified_variables.controller_role_from_previous_soca_deployment:
            policy_templates["ControllerPolicyNewCluster"] = {
                "template": "../policies/ControllerAppendToExistingRole.json",
                "attach_to_role": "controller_role",
            }
        else:
            # Same 4-way split for user-supplied roles.
            policy_templates["ControllerEC2ReadPolicy"] = {
                "template": "../policies/ControllerEC2Read.json",
                "attach_to_role": "controller_role",
                "policy_type": "managed",
            }
            policy_templates["ControllerEC2WritePolicy"] = {
                "template": "../policies/ControllerEC2Write.json",
                "attach_to_role": "controller_role",
                "policy_type": "managed",
            }
            policy_templates["ControllerNetworkingPolicy"] = {
                "template": "../policies/ControllerNetworking.json",
                "attach_to_role": "controller_role",
                "policy_type": "managed",
            }
            policy_templates["ControllerServicesPolicy"] = {
                "template": "../policies/ControllerServices.json",
                "attach_to_role": "controller_role",
                "policy_type": "managed",
            }

        if (
            not user_specified_variables.compute_node_role_from_previous_soca_deployment
        ):
            policy_templates["ComputeNodePolicy"] = {
                "template": "../policies/ComputeNode.json",
                "attach_to_role": "compute_node_role",
            }

        if (
            not user_specified_variables.spotfleet_role_from_previous_soca_deployment
        ):
            policy_templates["SpotFleetPolicy"] = {
                "template": "../policies/SpotFleet.json",
                "attach_to_role": "spot_fleet_role",
            }

    # Create all policies and attach them to their respective role
    for policy_name, policy_data in policy_templates.items():
        with open(policy_data["template"]) as json_file:
            policy_content = json_file.read()

        for k, v in policy_substitutes.items():
            policy_content = policy_content.replace(k, v)

        # if "LoginNodePolicy" in policy_name:
        #    print(policy_content)
        #    exit(1)
        _policy_doc = iam.PolicyDocument.from_json(json.loads(policy_content))
        _logical_id = f"{user_specified_variables.cluster_id}-{policy_name}"
        _target_role = scope.soca_resources[policy_data["attach_to_role"]]

        # Default is inline (AWS::IAM::Policy); "managed" opts into
        # AWS::IAM::ManagedPolicy with its own 6144-byte cap.
        if policy_data.get("policy_type") == "managed":
            iam.ManagedPolicy(
                scope,
                _logical_id,
                document=_policy_doc,
                roles=[_target_role],
            )
        else:
            _inline_policy = iam.Policy(scope, _logical_id, document=_policy_doc)
            _target_role.attach_inline_policy(_inline_policy)
            if policy_data["attach_to_role"] == "backup_role":
                # handle for BackupSelection DependsOn (lets IAM propagate the role trust)
                scope.soca_resources["backup_policy"] = _inline_policy
