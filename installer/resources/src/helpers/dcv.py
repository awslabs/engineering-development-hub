#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Do not trigger cdk deploy manually, Instead run ./edh_installer.sh.
All variables will be retrieved dynamically
"""

import os
import typing
from aws_cdk import (
    Duration,
    Tags,
    Aws,
    CustomResource,
    CfnOutput,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_autoscaling as autoscaling,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_events as events,
    aws_events_targets,
    aws_lambda as aws_lambda,
    aws_iam as iam,
    aws_certificatemanager as acm,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subscriptions,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    aws_lambda_event_sources as lambda_event_sources,
    aws_ssm as ssm,
    aws_s3 as s3,
    aws_kms as kms,
    Annotations,
)

import json
from types import SimpleNamespace

from helpers import (
    security_groups as security_groups_helper,
    user_data as user_data_helper,
    aoss as aoss_helper,
)
import pathlib
import logging


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one

logger = logging.getLogger("soca_logger")


def dcv_infrastructure(
    scope,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    principals_suffix=None,
    get_lambda_runtime_version=None,
    flatten_parameterstore_config=None,
    return_ebs_volume_type=None,
):
    """
    Create DCV High-Scale (HS) infrastructure components. This is required for larger (>100) DCV Sessions in the environment.
    """

    # Create DCV Infrastructure - covers several items with different needs
    # session_manager - internal nlb
    # broker - internal nlb
    # gateway - external / internal nlb (depending on the deployment that the cluster uses)

    logger.debug("Entering DCV High Scale infrastructure")

    # CloudWatch Agent config -- shared across broker + gateway. Stored
    # in SSM Parameter Store so the agent on each host can fetch it
    # via `amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c
    # ssm:<param-name>` from UserData. Keeping the config out of the
    # AMI means a config change ships via a parameter overwrite +
    # `fetch-config` SSM Run Command -- no instance roll required.
    # Metrics flow into the EDH/DCVHighScale namespace alongside the
    # screenshot poller's metrics so the admin status page reads
    # everything from one place.
    #
    # IMPORTANT: CW Agent's `append_dimensions` only honors the four
    # built-in `${aws:...}` placeholders (InstanceId, InstanceType,
    # ImageId, AutoScalingGroupName). Arbitrary literal values like
    # ClusterId are SILENTLY DROPPED. Earlier versions of this config
    # passed `"ClusterId": <literal>` and the dimension never landed,
    # which left the host-level alarms (DcvHosts-MemHigh, -SwapInUse,
    # -DiskHigh) querying a non-existent dimension and never firing.
    # We use AutoScalingGroupName instead -- the ASG name contains
    # the cluster id as a substring so the alarms can SEARCH by it.
    _cwagent_config = {
        "agent": {
            "metrics_collection_interval": 60,
            "logfile": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log",
        },
        "metrics": {
            "namespace": "EDH/DCVHighScale",
            "append_dimensions": {
                "InstanceId": "${aws:InstanceId}",
                "AutoScalingGroupName": "${aws:AutoScalingGroupName}",
            },
            "aggregation_dimensions": [
                ["AutoScalingGroupName"],
                [],  # also aggregate fleet-wide for cross-ASG dashboards
            ],
            "metrics_collected": {
                "mem": {
                    "measurement": [
                        "mem_used_percent",
                        "mem_available_percent",
                        "mem_total",
                    ],
                    "metrics_collection_interval": 60,
                },
                "swap": {
                    "measurement": ["swap_used_percent"],
                    "metrics_collection_interval": 60,
                },
                "disk": {
                    "measurement": ["used_percent"],
                    "resources": ["/"],
                    "metrics_collection_interval": 60,
                },
                "procstat": [
                    {
                        "pattern": "dcv-session-manager-broker|dcv-connection-gateway|java.*broker",
                        "measurement": [
                            "cpu_usage",
                            "memory_rss",
                            "memory_vms",
                            "num_threads",
                            "num_fds",
                        ],
                        "metrics_collection_interval": 60,
                    }
                ],
            },
        },
    }
    scope.soca_resources["dcv_cwagent_param"] = ssm.StringParameter(
        scope,
        "DCVCloudWatchAgentConfig",
        parameter_name=(
            f"/edh/{user_specified_variables.cluster_id}/cwagent/dcv-host-config"
        ),
        string_value=json.dumps(_cwagent_config),
        description="CloudWatch Agent config for DCV broker + gateway hosts",
        tier=ssm.ParameterTier.STANDARD,
    )

    # Grant the broker + gateway + DCV-VDI IAM roles permission to:
    #   - PutMetricData into the EDH/DCVHighScale namespace (cwagent
    #     publishes mem/swap/disk/procstat there)
    #   - PutMetricData into the EDH/DCVStreaming namespace (the
    #     VDI-side custom collector publishes per-session frame
    #     loss / latency / bandwidth there)
    #   - GetParameter on the cwagent config param so the agent can
    #     fetch-config at boot
    #   - DescribeTags so the agent can resolve {aws:InstanceId}
    # Customer-managed (not inline) because the same exact policy
    # attaches to broker + gateway + VDI roles -- one source of
    # truth, visible in IAM inventory, version-tracked. Mirrors the
    # 4-way managed-policy split done for the controller role in
    # CR-276014713.
    #
    # The VDI-host attachment is conditional: skip when the operator
    # supplied a customer-managed role (we don't mutate external
    # roles). In that case the operator must add the
    # PutMetricData/GetParameter statements themselves.
    #
    # NOTE: VDIs now run as the dedicated vdi_node_role (split out from
    # compute_node_role). DCV streaming metrics are emitted by DCV
    # servers (VDIs), not HPC compute exec nodes, so this grant attaches
    # to vdi_node_role only. In the BYO-role path vdi_node_role aliases
    # the operator-supplied compute_node_role (imported, unmanaged), so
    # the compute_node_role_arn check is the correct managed/BYO signal.
    _broker_role = scope.soca_resources.get("dcv_broker_role")
    _gateway_role = scope.soca_resources.get("dcv_gateway_role")
    _vdi_role = scope.soca_resources.get("vdi_node_role")
    _vdi_role_is_managed = not getattr(user_specified_variables, "compute_node_role_arn", None)
    _attach_to = [r for r in (_broker_role, _gateway_role) if r is not None]
    if _vdi_role is not None and _vdi_role_is_managed:
        _attach_to.append(_vdi_role)
    if _attach_to:
        scope.soca_resources["dcv_cwagent_managed_policy"] = iam.ManagedPolicy(
            scope,
            "DCVCloudWatchAgentManagedPolicy",
            managed_policy_name=(
                f"{user_specified_variables.cluster_id}-DCVCloudWatchAgent"
            ),
            description=(
                "CloudWatch Agent + DCV streaming-metrics collector "
                "permissions for DCV broker / gateway / VDI hosts "
                "(PutMetricData scoped to EDH/DCVHighScale + "
                "EDH/DCVStreaming, ssm:GetParameter on the cwagent "
                "config, ec2:DescribeTags)"
            ),
            statements=[
                iam.PolicyStatement(
                    actions=["cloudwatch:PutMetricData"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "cloudwatch:namespace": [
                                "EDH/DCVHighScale",
                                "EDH/DCVStreaming",
                            ]
                        }
                    },
                ),
                iam.PolicyStatement(
                    actions=["ssm:GetParameter", "ssm:GetParameters"],
                    resources=[
                        scope.soca_resources["dcv_cwagent_param"].parameter_arn,
                    ],
                ),
                iam.PolicyStatement(
                    actions=["ec2:DescribeTags"],
                    resources=["*"],
                ),
            ],
            roles=_attach_to,
        )

    for _dcv_node_type in ("dcv_broker", "dcv_gateway"):
        _dcv_config = f"Config.{_dcv_node_type.replace('_', '.')}"         
        logger.debug(
            f"Creating DCV Node {_dcv_node_type} items using DCV configuration {_dcv_config} ..."
        )

        # Get our desired list of instances
        _dcv_desired_instance_type: list = get_config_key(
            key_name=f"{_dcv_config}.instance_type",
            expected_type=list,
            required=False,
            default=["m5.large"],  # This is very purposely something that is compatible with most regions
        )

        # select_best_instance probes regional availability and returns the
        # (instance_type, arch, arch-matched AMI) triple (m5.large/x86_64
        # fallback) -- single source of truth for DCV node arch + AMI.
        logger.debug(
            f"Query instance availability for {_dcv_desired_instance_type}"
        )

        _dcv_selected_instance, _dcv_selected_arch, _dcv_instance_ami = (
            scope.select_best_instance(
                instance_list=_dcv_desired_instance_type,
                region=user_specified_variables.region,
                fallback_instance="m5.large",
            )
        )

        # Allow for AMI override in the config by DCV function type
        _dcv_desired_ami: str = get_config_key(
            key_name=f"{_dcv_config}.ami.{_dcv_selected_arch}",
            expected_type=str,
            required=False,  # Fallback to default if needed
            default=_dcv_instance_ami,
        )

        logger.debug(
            f"Creating DCV Node type - {_dcv_node_type} items using DCV configuration {_dcv_config}  Instance_Type: {_dcv_selected_instance}  Arch: {_dcv_selected_arch}  AMI: {_dcv_desired_ami} ..."
        )

        # We manually replace the variable with the relevant ParameterStore as all ParamStore hierarchy is created at the very end of this CDK
        _user_data_variables = {
            "/configuration/BaseOS": user_specified_variables.base_os,
            "/configuration/ClusterId": user_specified_variables.cluster_id,
            "/configuration/UserDirectory/provider": get_config_key(
                key_name="Config.directoryservice.provider"
            ),
            "/configuration/Region": user_specified_variables.region,
            "/configuration/Networking/EnableIPv6": scope.is_networking_af_enabled(
                address_family="ipv6"
            ),
            "/configuration/Version": "26.4.0",
            "/configuration/CustomAMI": _dcv_desired_ami,  # arch-matched DCV AMI
            "/configuration/S3Bucket": user_specified_variables.bucket,
            "/configuration/Cache/enabled": scope.cache_info.get("enabled"),
            "/configuration/Cache/port": scope.cache_info.get("port"),
            "/configuration/Cache/endpoint": scope.cache_info.get("endpoint"),
            "/job/NodeType": _dcv_node_type,
            "/job/BaseOS": user_specified_variables.base_os,
        }

        # add all System hierarchy
        _parameter_store_keys = flatten_parameterstore_config(
            get_config_key(key_name="Parameters", expected_type=dict)
        )
        for (
            _ssm_parameter_key,
            _ssm_parameter_value,
        ) in _parameter_store_keys.items():
            _user_data_variables[f"/{_ssm_parameter_key}"] = _ssm_parameter_value


        _user_data = user_data_helper.remove_text_aggressive(
                text_to_remove=[
                    "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                    "# SPDX-License-Identifier: Apache-2.0",
                ],
                data=scope.jinja2_env.get_template(
                    f"user_data/dcv/01_user_data.sh.j2"
                ).render(
                    context=_user_data_variables,
                    ns=SimpleNamespace(template_already_included=[]),
                )
            )

        os.makedirs(
                f"{pathlib.Path.cwd().parent}/upload_to_s3/{user_specified_variables.cluster_id}/{user_specified_variables.region}/bootstrap/{_dcv_node_type}",
                exist_ok=True,
            )

        # Because of size limitation, scripts needed during bootstrap are stored on s3
        _templates_to_render = [
                f"user_data/dcv/{_dcv_node_type}/02_setup",
                "templates/linux/system_packages/install_required_packages",
            ]

        for template in _templates_to_render:
            _t = user_data_helper.remove_text(
                    text_to_remove=[
                        "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                        "# SPDX-License-Identifier: Apache-2.0",
                    ],
                    data=scope.jinja2_env.get_template(f"{template}.sh.j2").render(
                        context=_user_data_variables,
                        ns=SimpleNamespace(template_already_included=[]),
                    ),
                )
            with open(
                    f"{pathlib.Path.cwd().parent}/upload_to_s3/{user_specified_variables.cluster_id}/{user_specified_variables.region}/bootstrap/{_dcv_node_type}/{template.split('/')[-1]}.sh",
                    "w",
                ) as f:
                    f.write(_t)

        _volume_type = return_ebs_volume_type(
            volume_string=get_config_key(
                key_name=f"{_dcv_config}.volume_type",
                required=False,
                default="gp3",
                expected_type=str,
            ).lower()
        )
        scope.soca_resources[f"{_dcv_node_type}_lt"] = ec2.LaunchTemplate(
            scope,
            f"{_dcv_node_type}-LT",
            machine_image=ec2.MachineImage.generic_linux(
                {user_specified_variables.region: _dcv_desired_ami}
            ),
            instance_type=ec2.InstanceType(_dcv_selected_instance),
            key_pair=ec2.KeyPair.from_key_pair_attributes(
                scope,
                f"{_dcv_node_type}-KeyPair",
                key_pair_name=user_specified_variables.ssh_keypair,
            ),
            require_imdsv2=True,
            role=scope.soca_resources[f"{_dcv_node_type}_role"],
            block_devices=[
                ec2.BlockDevice(
                    device_name=scope.return_ebs_volume_name(
                        base_os=user_specified_variables.base_os
                    ),
                    volume=ec2.BlockDeviceVolume(
                        ebs_device=ec2.EbsDeviceProps(
                            encrypted=True,
                            volume_size=get_config_key(
                                key_name=f"{_dcv_config}.volume_size",
                                expected_type=int,
                            ),
                            volume_type=_volume_type,
                        )
                    ),
                )
            ],
            security_group=scope.soca_resources[f"{_dcv_node_type}_sg"],
        )

        scope.soca_resources[f"{_dcv_node_type}_lt"].node.default_child.add_property_override(
            "LaunchTemplateData.UserData",
            user_data_helper.encode_for_lt(_user_data, label=f"{_dcv_node_type}-LT"),
        )

        # DCV broker + gateway sit behind dual-stack NLBs with IPv6 target groups; give them an IPv6 address at boot
        if scope.is_networking_af_enabled(address_family="ipv6"):
            _dcv_lt_node = scope.soca_resources[
                f"{_dcv_node_type}_lt"
            ].node.default_child
            # Explicit ENI array (SG moves into it; NetworkInterfaces can't coexist with top-level SecurityGroupIds)
            _dcv_lt_node.add_property_override(
                "LaunchTemplateData.NetworkInterfaces",
                [
                    {
                        "DeviceIndex": 0,
                        "Ipv6AddressCount": 1,
                        "PrimaryIpv6": True,
                        "Groups": [
                            scope.soca_resources[
                                f"{_dcv_node_type}_sg"
                            ].security_group_id
                        ],
                    }
                ],
            )
            _dcv_lt_node.add_property_deletion_override(
                "LaunchTemplateData.SecurityGroupIds"
            )


        # Both broker and gateway are backend compute; only the
        # public-facing frontend NLB lives in public subnets (see
        # _inet_facing branch below). Compute always private.
        _subnet_type = ec2.SubnetType.PRIVATE_WITH_EGRESS

        # Target capacity for the ASG once the cdk_completed sentinel
        # is set. Until then, the ASG stays at 0/0 and the
        # AsgCapacityBumper Custom Resource bumps it up post-deploy.
        # Cleaner ops logs (no "ParameterNotFound" SSM-poll noise on
        # bootstrap) and a deterministic CFN dependency graph.
        _dcv_target_count = get_config_key(
            key_name=f"{_dcv_config}.instance_count", expected_type=int
        )

        # Allow scale-up to 2x the configured target. The ASG starts
        # at desired=0 (gated by sentinel), gets bumped to the target
        # by AsgCapacityBumper, and can grow up to 2x via the CPU
        # scale-up policy below. Operators can override max via
        # Config.dcv.high_scale.<node>.max_instance_count.
        _dcv_max_count = get_config_key(
            key_name=f"{_dcv_config}.max_instance_count",
            expected_type=int,
            required=False,
            default=max(_dcv_target_count * 2, _dcv_target_count + 2),
        )

        scope.soca_resources[f"{_dcv_node_type}_asg"] = (
            autoscaling.AutoScalingGroup(
                scope,
                f"{_dcv_node_type}-ASG",
                vpc=scope.soca_resources["vpc"],
                launch_template=scope.soca_resources[f"{_dcv_node_type}_lt"],
                max_capacity=_dcv_max_count,
                min_capacity=0,
                desired_capacity=0,
                vpc_subnets=ec2.SubnetSelection(subnet_type=_subnet_type),
            )
        )
        Annotations.of(scope.soca_resources[f"{_dcv_node_type}_asg"]).acknowledge_warning(
            id="@aws-cdk/aws-autoscaling:desiredCapacitySet",
            message="DesiredCapacity is OK to reset",
        )
        # Tag the ASG so cluster_status / admin tooling can discover
        # broker vs gateway fleets by tag (matches login_node ASG
        # convention: edh:NodeType=login_node). Without this the
        # /admin/cluster_status/dcv_overview Infrastructure tab can't
        # find the fleets.
        Tags.of(scope.soca_resources[f"{_dcv_node_type}_asg"]).add(
            key="edh:NodeType", value=f"{_dcv_node_type}"
        )
        Tags.of(scope.soca_resources[f"{_dcv_node_type}_asg"]).add(
            key="Name",
            value=f"{user_specified_variables.cluster_id}-{_dcv_node_type}",
        )
        # Ensure ASG waits for IAM policies to be fully attached before launching instances
        # CDK depends on the role but not on policies added via add_managed_policy/attach_inline_policy
        scope.soca_resources[f"{_dcv_node_type}_asg"].node.add_dependency(
            scope.soca_resources[f"{_dcv_node_type}_role"]
        )

        # Bump ASG MinSize+DesiredCapacity from 0 to the target only
        # after cdk_completed sentinel is written. This guarantees
        # bootstrap scripts on the launching instances see a fully
        # populated /edh/<cluster>/* SSM tree and never log
        # "ParameterNotFound" warnings during normal startup. See
        # docs/DCVHighScale.md for the gating rationale.
        scope._register_asg_capacity_bumper(
            cr_id=f"{_dcv_node_type}-ASG-CapacityBumper",
            asg=scope.soca_resources[f"{_dcv_node_type}_asg"],
            target_min=_dcv_target_count,
            target_desired=_dcv_target_count,
        )

        # Target-tracking scale-up on CPU utilisation. Disable
        # scale-in (DisableScaleIn=True) so the policy never
        # automatically removes capacity -- shrinking would interrupt
        # active sessions. Operators bump max_size up; ASG fleet
        # decreases only via explicit operator action / capacity
        # config change.
        scope.soca_resources[f"{_dcv_node_type}_asg"].scale_on_cpu_utilization(
            f"{_dcv_node_type}-CPU60",
            target_utilization_percent=60,
            cooldown=Duration.minutes(5),
            estimated_instance_warmup=Duration.minutes(5),
            disable_scale_in=True,
        )

        # Per-node-type ports:
        #   gateway: 8443 (client HTTPS/QUIC + health 8989)
        #   broker:  8443 (client API) + 8445 (agent registration)
        #   manager: 8443 (API)
        _dcv_port_map = {
            "dcv_gateway": {"listen": 8443, "health": 8989},
            "dcv_broker": {"listen": 8443, "health": 8443},
        }
        _port = _dcv_port_map[_dcv_node_type]["listen"]
        _health_port = _dcv_port_map[_dcv_node_type]["health"]
        _protocol = elbv2.Protocol.TCP

        scope.soca_resources[f"{_dcv_node_type}_tg"] = (
            elbv2.NetworkTargetGroup(
                scope,
                f"{user_specified_variables.cluster_id}-{_dcv_node_type}-TG",
                port=_port,
                protocol=elbv2.Protocol.TCP_UDP if _dcv_node_type == "dcv_gateway" else _protocol,
                target_type=elbv2.TargetType.INSTANCE,
                ip_address_type=(
                    elbv2.TargetGroupIpAddressType.IPV6
                    if scope.is_networking_af_enabled(address_family="ipv6")
                    else elbv2.TargetGroupIpAddressType.IPV4
                ),
                vpc=scope.soca_resources["vpc"],
                targets=[scope.soca_resources[f"{_dcv_node_type}_asg"]],
                target_group_name=f"{user_specified_variables.cluster_id}-{_dcv_node_type.replace('_', '-')}", # note: no _ allowed
                health_check=elbv2.HealthCheck(
                    port=str(_health_port), protocol=elbv2.Protocol.TCP
                ),
                connection_termination=True,
            )
        )

        # Enable source IP stickiness on all DCV NLB target groups.
        #   - gateway (TCP_UDP 8443): required for QUIC -- a single
        #     QUIC stream is bound to a 5-tuple and cannot survive
        #     load-balancing across gateway instances.
        #   - broker  (TCP 8443): keeps clients/admins on a stable
        #     broker for the duration of a session (DDB shared
        #     state makes this best-effort, not strict).
        #   - broker-agent (TCP 8445): persistent agent->broker
        #     channel; reconnects should land on the same broker
        #     to avoid agent state churn.
        #   - broker-gateway (TCP 8447): persistent gateway->broker
        #     gRPC; reconnects should be sticky for the same reason.
        scope.soca_resources[f"{_dcv_node_type}_tg"].set_attribute(
            "stickiness.enabled", "true"
        )
        scope.soca_resources[f"{_dcv_node_type}_tg"].set_attribute(
            "stickiness.type", "source_ip"
        )

        # Broker also needs an agent-facing target group on port 8445
        if _dcv_node_type == "dcv_broker":
            scope.soca_resources["dcv_broker_agent_tg"] = (
                elbv2.NetworkTargetGroup(
                    scope,
                    f"{user_specified_variables.cluster_id}-DCV-broker-agent-TG",
                    port=8445,
                    protocol=_protocol,
                    target_type=elbv2.TargetType.INSTANCE,
                    ip_address_type=(
                        elbv2.TargetGroupIpAddressType.IPV6
                        if scope.is_networking_af_enabled(address_family="ipv6")
                        else elbv2.TargetGroupIpAddressType.IPV4
                    ),
                    vpc=scope.soca_resources["vpc"],
                    targets=[scope.soca_resources["dcv_broker_asg"]],
                    target_group_name=f"{user_specified_variables.cluster_id}-DCV-broker-agent",
                    health_check=elbv2.HealthCheck(
                        port="8443", protocol=_protocol
                    ),
                    connection_termination=True,
                )
            )
            scope.soca_resources["dcv_broker_gateway_tg"] = (
                elbv2.NetworkTargetGroup(
                    scope,
                    f"{user_specified_variables.cluster_id}-DCV-broker-gateway-TG",
                    port=8447,
                    protocol=_protocol,
                    target_type=elbv2.TargetType.INSTANCE,
                    ip_address_type=(
                        elbv2.TargetGroupIpAddressType.IPV6
                        if scope.is_networking_af_enabled(address_family="ipv6")
                        else elbv2.TargetGroupIpAddressType.IPV4
                    ),
                    vpc=scope.soca_resources["vpc"],
                    targets=[scope.soca_resources["dcv_broker_asg"]],
                    target_group_name=f"{user_specified_variables.cluster_id}-DCV-broker-gw",
                    health_check=elbv2.HealthCheck(
                        port="8443", protocol=_protocol
                    ),
                    connection_termination=True,
                )
            )
            # Apply source-IP stickiness to the auxiliary broker TGs
            # too. See the rationale on the primary TG block above.
            for _aux_tg_key in ("dcv_broker_agent_tg", "dcv_broker_gateway_tg"):
                scope.soca_resources[_aux_tg_key].set_attribute(
                    "stickiness.enabled", "true"
                )
                scope.soca_resources[_aux_tg_key].set_attribute(
                    "stickiness.type", "source_ip"
                )

    # Create NLBs
    # Frontend NLB: gateway (client-facing, potentially internet-facing)
    # Backend NLB: broker + manager (internal only)
    for _dcv_nlb in ("frontend", "backend"):
        _inet_facing: bool = False
        if (
            _dcv_nlb == "frontend"
            and user_specified_variables.deployment_mode == "public"
        ):
            _inet_facing = True

        logger.debug(
            f"Creating DCV NLB for {_dcv_nlb} / Inet Facing: {_inet_facing}"
        )

        _nlb_subnet_type = ec2.SubnetType.PRIVATE_WITH_EGRESS
        if _inet_facing:
            _nlb_subnet_type = ec2.SubnetType.PUBLIC

        _dcv_nlb_isubnets: list = []
        if user_specified_variables.vpc_id:
            _dcv_nlb_src = (
                user_specified_variables.public_subnets
                if _inet_facing
                else user_specified_variables.private_subnets
            )
            for _i, _sn in enumerate(_dcv_nlb_src):
                _sn_id = _sn.split(",")[0]
                _isub = ec2.Subnet.from_subnet_id(
                    scope, f"DCV-{_dcv_nlb}-NLB-Subnet{_i}", subnet_id=_sn_id
                )
                Annotations.of(_isub).acknowledge_warning(
                    id="@aws-cdk/aws-ec2:noSubnetRouteTableId",
                    message="RouteTableId will not be processed",
                )
                _dcv_nlb_isubnets.append(_isub)
            _dcv_nlb_subnet_sel = ec2.SubnetSelection(subnets=_dcv_nlb_isubnets)
        else:
            _dcv_nlb_subnet_sel = ec2.SubnetSelection(subnet_type=_nlb_subnet_type)

        scope.soca_resources[f"dcv_{_dcv_nlb}_nlb"] = elbv2.NetworkLoadBalancer(
            scope,
            f"SOCA-DCV-{_dcv_nlb}-NLB",
            load_balancer_name=f"{user_specified_variables.cluster_id}-dcv-{_dcv_nlb}-nlb",
            vpc=scope.soca_resources["vpc"],
            # Each DCV NLB gets its own dedicated SG (frontend vs
            # backend). Replaces the earlier placeholder of
            # compute_node_sg, which mixed two unrelated concerns
            # (compute traffic and NLB ingress).
            security_groups=[
                scope.soca_resources[f"dcv_{_dcv_nlb}_nlb_sg"]
            ],
            internet_facing=_inet_facing,
            vpc_subnets=_dcv_nlb_subnet_sel,
            # Cross-zone load balancing keeps the NLB ENI in any AZ
            # able to forward to a healthy target in any other AZ.
            # Critical when fleet count < AZ count -- otherwise the
            # NLB DNS resolves to ENIs in AZs with no targets and
            # ~1/(numAZs) of new connections fail. Inter-AZ data
            # transfer cost is negligible for control-plane traffic
            # (DCV streaming traffic flows gateway -> DCV server
            # directly and does not traverse the NLB).
            cross_zone_enabled=True,
            # Both DCV NLBs dual-stack when IPv6 is enabled. Frontend's TCP_UDP listener pairs with the IPv6 gateway target group; backend keeps IPv4 target groups (TCP-only, allowed on dual-stack).
            ip_address_type=(
                elbv2.IpAddressType.DUAL_STACK
                if scope.is_networking_af_enabled(address_family="ipv6")
                else elbv2.IpAddressType.IPV4
            ),
            # A UDP/TCP_UDP listener on a dual-stack NLB requires IPv6 source-NAT prefixes (frontend/QUIC only)
            enable_prefix_for_ipv6_source_nat=(
                _inet_facing
                and scope.is_networking_af_enabled(address_family="ipv6")
            ),
        )

        if not user_specified_variables.os_endpoint and scope.soca_resources.get("os_domain"):
            scope.soca_resources[f"dcv_{_dcv_nlb}_nlb"].node.add_dependency(
                scope.soca_resources["os_domain"]
            )

        CfnOutput(
            scope,
            f"DCV_{_dcv_nlb}-NLB",
            value=f"{scope.soca_resources[f'dcv_{_dcv_nlb}_nlb'].load_balancer_dns_name}",
        )

    # Frontend NLB listener — gateway on 443 (TCP+UDP/QUIC)
    scope.soca_resources["dcv_frontend_nlb"].add_listener(
        "DCV-Frontend-443",
        port=443,
        protocol=elbv2.Protocol.TCP_UDP,
        default_target_groups=[scope.soca_resources["dcv_gateway_tg"]],
    )

    # Backend NLB listeners — broker client API, broker agent, manager API
    scope.soca_resources["dcv_backend_nlb"].add_listener(
        "DCV-Backend-Broker-8443",
        port=8443,
        protocol=elbv2.Protocol.TCP,
        default_target_groups=[scope.soca_resources["dcv_broker_tg"]],
    )
    scope.soca_resources["dcv_backend_nlb"].add_listener(
        "DCV-Backend-Broker-Agent-8445",
        port=8445,
        protocol=elbv2.Protocol.TCP,
        default_target_groups=[scope.soca_resources["dcv_broker_agent_tg"]],
    )
    scope.soca_resources["dcv_backend_nlb"].add_listener(
        "DCV-Backend-Broker-Gateway-8447",
        port=8447,
        protocol=elbv2.Protocol.TCP,
        default_target_groups=[scope.soca_resources["dcv_broker_gateway_tg"]],
    )

    # Shared broker-to-broker (Apache Ignite) mTLS CA for the broker fleet.
    # NOT required for clustering -- brokers cluster fine with their own
    # self-signed CAs (the SG self-ingress on the Ignite ports is what
    # enables clustering). This is an operator-controlled, consistent CA
    # with a configurable validity (default 10y, vs the DCV self-signed
    # ~2y) and a single rotation point. Toggle via Config.dcv.broker.shared_ca;
    # when disabled, no secret/generator is created and brokers use the DCV
    # self-signed CA. When enabled, minted once at deploy by
    # DcvBrokerCaGenerator; brokers install it read-only before first start
    # (fallback: self-signed). See dcv_broker.sh.j2 + functions/DcvBrokerCaGenerator/.
    _shared_ca_enabled = get_config_key(
        key_name="Config.dcv.broker.shared_ca",
        required=False,
        default=True,
        expected_type=bool,
    )
    scope.soca_resources["dcv_broker_ca_secret"] = None
    if _shared_ca_enabled:
        scope.soca_resources["dcv_broker_ca_secret"] = secretsmanager.Secret(
            scope,
            "DcvBrokerSharedCa",
            secret_name=f"/edh/{user_specified_variables.cluster_id}/dcv/broker/shared_ca",
            description=(
                "Operator-controlled shared CA (cert + key) for the DCV "
                "high-scale broker fleet's broker-to-broker Ignite mTLS. "
                "Minted at deploy by DcvBrokerCaGenerator for trust-root "
                "consistency + a 10y validity; clustering does not require it."
            ),
        )
        # Brokers are READ-ONLY consumers of the shared CA (the generator
        # Lambda is the sole writer). Gateway role does NOT get this.
        scope.soca_resources["dcv_broker_ca_secret"].grant_read(
            scope.soca_resources["dcv_broker_role"]
        )

    # DcvBrokerCaGenerator -- custom-resource Lambda that mints the shared
    # CA into the secret once at deploy (idempotent: no-op if already set,
    # so it is a safe rolling upgrade over a v1 broker-founded CA). Needs
    # the cryptography layer; skip wiring if the layer is disabled (the
    # broker bootstrap then waits/falls back).
    _ca_layer = scope.soca_resources.get("cryptography_layer")
    if _shared_ca_enabled and _ca_layer is not None:
        _ca_gen_role = iam.Role(
            scope,
            "DcvBrokerCaGeneratorRole",
            description="Role for the DCV broker shared-CA generator Lambda",
            assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )
        # Sole writer of the shared-CA secret (also reads to stay idempotent).
        scope.soca_resources["dcv_broker_ca_secret"].grant_read(_ca_gen_role)
        scope.soca_resources["dcv_broker_ca_secret"].grant_write(_ca_gen_role)

        _ca_gen_lambda = aws_lambda.Function(
            scope,
            "DcvBrokerCaGenerator",
            function_name=f"{user_specified_variables.cluster_id}-DcvBrokerCaGenerator",
            description="Mint the shared broker-to-broker mTLS CA for the DCV high-scale fleet",
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            architecture=aws_lambda.Architecture.X86_64,
            handler="DcvBrokerCaGenerator.handler",
            code=aws_lambda.Code.from_asset("../functions/DcvBrokerCaGenerator"),
            layers=[_l for _l in [_ca_layer, scope.soca_resources.get("boto3_layer")] if _l] or None,
            timeout=Duration.minutes(2),
            memory_size=256,
            role=_ca_gen_role,
            log_group=scope.generate_log_group(name="DcvBrokerCaGeneratorLambda"),
            environment={
                "CA_SECRET_ARN": scope.soca_resources[
                    "dcv_broker_ca_secret"
                ].secret_arn,
                "EDH_CLUSTER_ID": user_specified_variables.cluster_id,
                "CA_VALIDITY_DAYS": str(
                    get_config_key(
                        key_name="Config.dcv.broker.ca_validity_days",
                        required=False,
                        default=3650,
                        expected_type=int,
                    )
                ),
                "CA_KEY_SIZE": str(
                    get_config_key(
                        key_name="Config.dcv.broker.ca_key_size",
                        required=False,
                        default=2048,
                        expected_type=int,
                    )
                ),
            },
        )
        _ca_cr = CustomResource(
            scope,
            "DcvBrokerCaInit",
            service_token=_ca_gen_lambda.function_arn,
            properties={
                # Re-run if validity/key-size change (CFN diffs properties).
                "ca_validity_days": str(
                    get_config_key(
                        key_name="Config.dcv.broker.ca_validity_days",
                        required=False,
                        default=3650,
                        expected_type=int,
                    )
                ),
            },
        )
        # Lambda (and its secret grants) must exist before the CR invokes it.
        _ca_cr.node.add_dependency(_ca_gen_lambda)
        _ca_cr.node.add_dependency(scope.soca_resources["dcv_broker_ca_secret"])
    else:
        if not _shared_ca_enabled:
            logger.info(
                "Config.dcv.broker.shared_ca is false -- no shared-CA "
                "secret/generator; brokers use the DCV self-signed CA "
                "(clustering is unaffected)"
            )
        else:
            logger.warning(
                "Config.lambda_layers.CryptographyVersion is empty -- "
                "DcvBrokerCaGenerator not wired; brokers fall back to the "
                "DCV self-signed CA (clustering still works)"
            )

    # Store DCV infrastructure endpoints in SSM for UserData discovery
    _dcv_ssm_prefix = f"/edh/{user_specified_variables.cluster_id}/dcv"
    _dcv_ssm_params = {
        "backend_nlb_dns": scope.soca_resources[
            "dcv_backend_nlb"
        ].load_balancer_dns_name,
        "frontend_nlb_dns": scope.soca_resources[
            "dcv_frontend_nlb"
        ].load_balancer_dns_name,
        "broker/client_port": "8443",
        "broker/agent_port": "8445",
        "broker/gateway_port": "8447",
        "broker/connect_session_token_duration_minutes": str(get_config_key(
            key_name="Config.dcv.broker.connect_session_token_duration_minutes",
            required=False,
            default=720,
            expected_type=int,
        )),
        "broker/target_group_arn": scope.soca_resources[
            "dcv_broker_tg"
        ].target_group_arn,
        "high_scale_enabled": "true",
        "screenshot/privacy_mode": str(get_config_key(
            key_name="Config.dcv.screenshot.privacy_mode",
            required=False,
            default=False,
            expected_type=bool,
        )).lower(),
        # Surface the screenshot refresh interval to the controller's
        # web UI so the browser-side thumbnail refresh cadence matches
        # the Lambda polling cadence (no point fetching new presigned
        # URLs faster than the underlying object updates).
        "screenshot/refresh_seconds": str(get_config_key(
            key_name="Config.dcv.screenshot.refresh_seconds",
            required=False,
            default=120,
            expected_type=int,
        )),
    }
    # ARN of the shared broker CA secret -- only published when the shared
    # CA is enabled. Its presence is the broker's signal to install the
    # fleet CA; absent -> broker uses the DCV self-signed CA (clusters fine).
    if scope.soca_resources.get("dcv_broker_ca_secret") is not None:
        _dcv_ssm_params["broker/ca_secret_arn"] = scope.soca_resources[
            "dcv_broker_ca_secret"
        ].secret_arn
    _bulk_dcv_params = {
        f"{_dcv_ssm_prefix}/{k}": str(v)
        for k, v in _dcv_ssm_params.items()
    }
    # Values include CDK tokens (load_balancer_dns_name, target_group_arn)
    # so route through resolved_params for deploy-time resolution.
    scope._write_bulk_ssm_params(
        "BulkSSMDcvParams",
        resolved_params=_bulk_dcv_params,
    )

    logger.debug("Completed DCV High-Scale infrastructure creation")

    # DCV Screenshot Poller Lambda (if screenshots enabled)
    if get_config_key(
        key_name="Config.dcv.screenshot.enabled",
        required=False,
        expected_type=bool,
        default=False,
    ):
        _screenshot_refresh = get_config_key(
            key_name="Config.dcv.screenshot.refresh_seconds",
            required=False,
            expected_type=int,
            default=120,
        )
        _screenshot_retention_days = get_config_key(
            key_name="Config.dcv.screenshot.terminated_retention_days",
            required=False,
            expected_type=int,
            default=3,
        )

        # ---------------- Screenshot bucket (mode-selectable) ----------------
        # Config.dcv.screenshot.bucket_mode: "dedicated" | "cluster" | "existing"
        #   dedicated -> SOCA creates a hardened, dedicated bucket (BPA + TLS-only
        #                policy + lifecycle + KMS/SSE).
        #   cluster   -> reuse the shared cluster (install) bucket under a prefix.
        #                No new bucket/policy; works when the install role can't
        #                create buckets or set bucket policies (SCPs).
        #   existing  -> import a pre-created bucket (operator owns hardening). For
        #                a customer-managed CMK the key policy must allow the SOCA
        #                controller + poller role ARNs (SOCA can't set a key policy
        #                it doesn't own).
        _ss_mode = (get_config_key(
            key_name="Config.dcv.screenshot.bucket_mode",
            required=False, default="dedicated", expected_type=str,
        ) or "dedicated").strip().lower()
        _ss_manage_policy = get_config_key(
            key_name="Config.dcv.screenshot.manage_bucket_policy",
            required=False, default=True, expected_type=bool,
        )
        _ss_existing_bucket = get_config_key(
            key_name="Config.dcv.screenshot.existing_bucket",
            required=False, default=None, expected_type=str,
        )
        _ss_prefix_cfg = get_config_key(
            key_name="Config.dcv.screenshot.bucket_prefix",
            required=False, default=None, expected_type=str,
        )

        # KMS (shared): reuse a configured S3 CMK, else SSE-S3.
        _ss_kms_key_id = get_kms_key_id(
            config_key_names=["Config.services.s3.kms_key_id"],
            allow_global_default=True,
        )
        _ss_kms_key = (
            kms.Key.from_key_arn(scope, "DcvScreenshotBucketKey", key_arn=_ss_kms_key_id)
            if _ss_kms_key_id else None
        )

        def _ss_norm_prefix(_p):
            # Normalize to "" or "prefix/" (no leading slash, single trailing).
            _p = (_p or "").strip().strip("/")
            return f"{_p}/" if _p else ""

        if _ss_mode == "cluster":
            _ss_bucket_name = user_specified_variables.bucket
            _ss_bucket = s3.Bucket.from_bucket_name(
                scope, "DcvScreenshotClusterBucket", _ss_bucket_name
            )
            _ss_prefix = _ss_norm_prefix(
                _ss_prefix_cfg or f"{user_specified_variables.cluster_id}/dcv/screenshots"
            )
            _ss_created = False
        elif _ss_mode == "existing":
            if not _ss_existing_bucket:
                raise ValueError(
                    "Config.dcv.screenshot.bucket_mode is 'existing' but "
                    "Config.dcv.screenshot.existing_bucket is not set"
                )
            _ss_bucket_name = _ss_existing_bucket
            _ss_bucket = s3.Bucket.from_bucket_name(
                scope, "DcvScreenshotExistingBucket", _ss_bucket_name
            )
            _ss_prefix = _ss_norm_prefix(_ss_prefix_cfg)
            _ss_created = False
        else:
            if _ss_mode != "dedicated":
                raise ValueError(
                    f"Config.dcv.screenshot.bucket_mode must be "
                    f"'dedicated', 'cluster', or 'existing' (got '{_ss_mode}')"
                )
            # Account+deploy-suffixed name: globally unique, greppable by
            # cluster_id, and collision-free on CREATE retry (fresh deployment_id).
            _ss_bucket_name = (
                f"{user_specified_variables.cluster_id}-dcv-screenshots-"
                f"{Aws.ACCOUNT_ID}-{scope.deployment_id[:8]}"
            )
            _ss_bucket = s3.Bucket(
                scope,
                "DcvScreenshotBucket",
                bucket_name=_ss_bucket_name,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                encryption=(s3.BucketEncryption.KMS if _ss_kms_key else s3.BucketEncryption.S3_MANAGED),
                encryption_key=_ss_kms_key,
                versioned=False,  # ephemeral; lifecycle handles retention
                # TLS-only deny bucket policy. Skipped when manage_bucket_policy
                # is false (install role lacks s3:PutBucketPolicy); BPA + lifecycle
                # are creation-time and still applied.
                enforce_ssl=_ss_manage_policy,
                removal_policy=RemovalPolicy.RETAIN,
                auto_delete_objects=False,
                lifecycle_rules=[
                    s3.LifecycleRule(
                        id="ExpireScreenshots",
                        enabled=True,
                        expiration=Duration.days(_screenshot_retention_days),
                        abort_incomplete_multipart_upload_after=Duration.days(1),
                    ),
                ],
            )
            _ss_prefix = _ss_norm_prefix(_ss_prefix_cfg)
            _ss_created = True

        scope.soca_resources["dcv_screenshot_bucket"] = _ss_bucket
        # Resolved ARNs (prefix-scoped) reused for both controller + poller IAM.
        _ss_list_arn = f"arn:{Aws.PARTITION}:s3:::{_ss_bucket_name}"
        _ss_obj_arn = f"arn:{Aws.PARTITION}:s3:::{_ss_bucket_name}/{_ss_prefix}*"
        CfnOutput(
            scope,
            "DcvScreenshotBucketName",
            value=_ss_bucket_name,
            description="S3 bucket holding DCV session screenshot thumbnails",
        )
        # Controller read access (head_object + presign). For a SOCA-created
        # bucket grant_read is simplest; for cluster/existing use explicit
        # prefix-scoped statements (+ KMS decrypt when a CMK is configured).
        _ctrl_role = scope.soca_resources.get("controller_role")
        if _ctrl_role is not None:
            if _ss_created:
                _ss_bucket.grant_read(_ctrl_role)
            else:
                _ctrl_role.add_to_policy(iam.PolicyStatement(
                    actions=["s3:GetObject", "s3:GetObjectTagging"],
                    resources=[_ss_obj_arn],
                ))
                _ss_list_stmt = iam.PolicyStatement(
                    actions=["s3:ListBucket"], resources=[_ss_list_arn],
                )
                if _ss_prefix:
                    _ss_list_stmt.add_conditions({"StringLike": {"s3:prefix": [f"{_ss_prefix}*"]}})
                _ctrl_role.add_to_policy(_ss_list_stmt)
                if _ss_kms_key is not None:
                    _ss_kms_key.grant_decrypt(_ctrl_role)
        # Publish bucket name (+ prefix when set) to SSM for the controller
        # web app. s3_prefix uses "~" (SOCA null convention) when empty
        # since SSM rejects empty string values; the controller endpoint
        # treats "~" as no-prefix (flat keys in dedicated bucket mode).
        _ss_ssm_params = {
            f"/edh/{user_specified_variables.cluster_id}/dcv/screenshot/s3_bucket":
                _ss_bucket_name,
            f"/edh/{user_specified_variables.cluster_id}/dcv/screenshot/retention_days":
                str(_screenshot_retention_days),
            f"/edh/{user_specified_variables.cluster_id}/dcv/screenshot/s3_prefix":
                _ss_prefix if _ss_prefix else "~",
        }
        scope._write_bulk_ssm_params(
            "BulkSSMDcvScreenshotBucket",
            resolved_params=_ss_ssm_params,
        )

        # IAM role for screenshot poller Lambda
        _screenshot_lambda_role = iam.Role(
            scope,
            "DcvScreenshotPollerRole",
            description="IAM role for DCV Screenshot Poller Lambda",
            assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
            ],
        )
        _screenshot_lambda_role.attach_inline_policy(
            iam.Policy(
                scope,
                f"{user_specified_variables.cluster_id}-DcvScreenshotPollerPolicy",
                statements=[
                    # S3 access scoped to the resolved screenshot bucket +
                    # prefix (dedicated/cluster/existing). Object actions on
                    # the prefix; ListBucket on the bucket.
                    iam.PolicyStatement(
                        actions=[
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:DeleteObject",
                            "s3:ListBucket",
                            "s3:PutObjectTagging",
                            "s3:GetObjectTagging",
                            "s3:GetLifecycleConfiguration",
                        ],
                        resources=[
                            _ss_list_arn,
                            _ss_obj_arn,
                        ],
                    ),
                    # cloudwatch:PutMetricData has no resource-level
                    # ARN support (AWS limitation) -- use a namespace
                    # condition for least privilege.
                    iam.PolicyStatement(
                        actions=["cloudwatch:PutMetricData"],
                        resources=["*"],
                        conditions={
                            "StringEquals": {
                                "cloudwatch:namespace": "EDH/DCVHighScale"
                            }
                        },
                    ),
                ],
            )
        )
        # If the bucket uses a CMK, grant the Lambda role decrypt/
        # encrypt on the key. SSE-S3 does not need this.
        if _ss_kms_key is not None:
            _ss_kms_key.grant_encrypt_decrypt(_screenshot_lambda_role)

        _screenshot_lambda = aws_lambda.Function(
            scope,
            f"{user_specified_variables.cluster_id}-DcvScreenshotPoller",
            function_name=f"{user_specified_variables.cluster_id}-DcvScreenshotPoller",
            description="Poll DCV broker for session screenshots and cache in S3",
            memory_size=256,
            runtime=typing.cast(
                aws_lambda.Runtime, get_lambda_runtime_version()
            ),
            system_log_level_v2=aws_lambda.SystemLogLevel.INFO,
            logging_format=aws_lambda.LoggingFormat.JSON,
            timeout=Duration.minutes(5),
            log_group=scope.generate_log_group(name="DcvScreenshotPollerLambda"),
            role=_screenshot_lambda_role,
            handler="DcvScreenshotPoller.lambda_handler",
            code=aws_lambda.Code.from_asset(
                "../functions/DcvScreenshotPoller"
            ),
            environment={
                "EDH_CLUSTER_ID": user_specified_variables.cluster_id,
                "SCREENSHOTS_BUCKET": _ss_bucket_name,
                "SCREENSHOTS_PREFIX": _ss_prefix,
                # Retention for the separate daily "expire" pass (see the
                # DcvScreenshotExpireSchedule rule below, created only for
                # cluster/existing modes). The poll cycle never deletes.
                "SCREENSHOT_RETENTION_DAYS": str(_screenshot_retention_days),
                "BROKER_ENDPOINT": scope.soca_resources[
                    "dcv_backend_nlb"
                ].load_balancer_dns_name,
                "BROKER_PORT": "8443",
                "MAX_WIDTH": str(
                    get_config_key(
                        key_name="Config.dcv.screenshot.max_width",
                        required=False,
                        expected_type=int,
                        default=800,
                    )
                ),
                "MAX_HEIGHT": str(
                    get_config_key(
                        key_name="Config.dcv.screenshot.max_height",
                        required=False,
                        expected_type=int,
                        default=600,
                    )
                ),
            },
            vpc=scope.soca_resources["vpc"],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            # Dedicated SG for the Lambda ENI -- least privilege.
            # Allow_all_outbound covers backend NLB:8443, S3, KMS,
            # CloudWatch via the VPC endpoints / NAT path. No
            # ingress (Lambda ENIs do not accept inbound traffic).
            security_groups=[
                scope.soca_resources["dcv_screenshot_lambda_sg"]
            ],
            layers=[
                l
                for l in [scope.soca_resources.get("boto3_layer")]
                if l
            ],
        )
        # Surface on soca_resources so alarms wired AFTER this method
        # (e.g. _dcv_high_scale_alarms) can reference it.
        scope.soca_resources["dcv_screenshot_lambda"] = _screenshot_lambda

        # Convert seconds to EventBridge rate expression
        # Rule starts DISABLED — broker bootstrap enables it after verification
        _rate_minutes = max(1, _screenshot_refresh // 60)
        _screenshot_rule = events.Rule(
            scope,
            "DcvScreenshotPollerSchedule",
            rule_name=f"{user_specified_variables.cluster_id}-DcvScreenshotPoller",
            description="Trigger DCV Screenshot Poller Lambda on a schedule",
            enabled=False,
            schedule=events.Schedule.rate(Duration.minutes(_rate_minutes)),
            targets=[
                aws_events_targets.LambdaFunction(_screenshot_lambda)
            ],
        )

        logger.debug(
            f"DCV Screenshot Poller configured: refresh={_screenshot_refresh}s (schedule disabled until broker bootstrap)"
        )

        # Daily "expire" pass -- a separate, low-frequency cleanup process
        # (distinct from the screenshot poll cycle). Only cluster/existing
        # modes need it: the dedicated bucket's S3 lifecycle rule is its
        # expiry mechanism. Invokes the SAME Lambda with {"action":"expire"}.
        if not _ss_created:
            events.Rule(
                scope,
                "DcvScreenshotExpireSchedule",
                rule_name=f"{user_specified_variables.cluster_id}-DcvScreenshotExpire",
                description="Daily cleanup of terminated DCV screenshots (cluster/existing bucket modes)",
                enabled=True,  # cleanup is independent of broker readiness (no-op when no aged orphans)
                schedule=events.Schedule.rate(Duration.days(1)),
                targets=[
                    aws_events_targets.LambdaFunction(
                        _screenshot_lambda,
                        event=events.RuleTargetInput.from_object({"action": "expire"}),
                    )
                ],
            )


def dcv_event_relay(
    scope,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    principals_suffix=None,
    get_lambda_runtime_version=None,
    flatten_parameterstore_config=None,
    return_ebs_volume_type=None,
):
    """
    DCV session-event relay: SQS queue + Lambda + auto-rotating relay key.

    Architecture (see docs/DCVEventRelay.md for the full design):

      VDI         (aws sqs send-message; IAM allow on this single queue
        |          ARN only; SQS attaches AWS-attested SenderId)
        v
      SQS queue   {cluster_id}-dcv-session-events
        |  (event source mapping; AWS-managed long-poll;
        |   sub-second latency; no polling cost)
        v
      Lambda      DcvEventRelay -- stdlib-only pre-screen, extract
        |         SenderId from message attributes, cross-check vs
        |         body.instance_id, sign canonical-string HMAC with
        |         AWSCURRENT relay key, POST controller with
        |         X-EDH-Attested-Instance header
        v
      Controller  /api/dcv/session-event -- re-validates relay HMAC,
                  attested instance, body schema, freshness, nonce
                  dedup, then mutates session state

    Resources created:

      - SQS queue + dead-letter queue. IAM grants sqs:SendMessage on
        the queue ARN to vdi_node_role and target_node_role only.
        The AWS-attested SenderId attribute (= role-id:i-XXX) is the
        anti-forgery primitive: a VDI cannot publish events claiming
        to be a different VDI because SQS sets SenderId from the
        SigV4 caller identity.
      - SecretsManager secret holding the 64-byte relay HMAC key,
        auto-rotated every 90 days via DcvEventRelayRotation Lambda.
        IAM on the secret restricts GetSecretValue to AWSCURRENT
        (Lambda) and AWSCURRENT/AWSPREVIOUS (controller) staging
        labels only. Prior orphan versions stay walled off.
      - Two Lambdas: relay (SQS event-source-mapping target) +
        rotation (SM-invoked).
      - SSM parameters published for SocaConfig:
          /configuration/DcvEventRelaySecretArn
          /configuration/DcvSessionEventsQueueUrl
          /configuration/ControllerWebUIUrl   (https://<dns>:8443)
      - CloudWatch alarms on Rejected metric thresholds.
    """
    logger.debug("Configuring DCV Event Relay")
    _cluster_id: str = user_specified_variables.cluster_id
    _region: str = user_specified_variables.region

    # ----- 1. SQS queue + DLQ ------------------------------------------
    # Dead-letter queue catches poison messages after 5 receive attempts
    # so a buggy publisher cannot infinitely block the live queue.
    _dlq = sqs.Queue(
        scope,
        "DcvSessionEventsDlq",
        queue_name=f"{_cluster_id}-dcv-session-events-dlq",
        retention_period=Duration.days(14),
        encryption=sqs.QueueEncryption.SQS_MANAGED,
        enforce_ssl=True,
    )
    _queue = sqs.Queue(
        scope,
        "DcvSessionEventsQueue",
        queue_name=f"{_cluster_id}-dcv-session-events",
        # SOCA event freshness window is 5 min; messages older than
        # that fail the controller's freshness check anyway, so a
        # short retention plus DLQ keeps backlog bounded.
        retention_period=Duration.minutes(15),
        visibility_timeout=Duration.seconds(60),
        receive_message_wait_time=Duration.seconds(20),  # long-poll
        encryption=sqs.QueueEncryption.SQS_MANAGED,
        enforce_ssl=True,
        dead_letter_queue=sqs.DeadLetterQueue(
            queue=_dlq,
            max_receive_count=5,
        ),
    )
    scope.soca_resources["dcv_session_events_queue"] = _queue

    # ----- 2. Relay HMAC key in SecretsManager (auto-rotating) ---------
    # Auto-generated 64-byte key; SM excludes any control chars from
    # rotation Lambda's createSecret step (it uses our token_bytes).
    _relay_secret = secretsmanager.Secret(
        scope,
        "DcvEventRelaySecret",
        secret_name=f"/edh/{_cluster_id}/dcv-event-relay-key",
        description="HMAC-SHA256 transport-auth key for DCV event relay Lambda to controller",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            # 64 raw bytes encoded in 86 chars of base64 -- matches
            # the rotation Lambda's token_bytes(64) format.
            password_length=64,
            exclude_punctuation=False,
            include_space=False,
            require_each_included_type=False,
        ),
    )
    scope.soca_resources["dcv_event_relay_secret"] = _relay_secret

    # ----- 3. Rotation Lambda ------------------------------------------
    _rotation_role = iam.Role(
        scope,
        "DcvEventRelayRotationRole",
        description="IAM role for the DcvEventRelay rotation Lambda",
        assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        # VPC-attached (testSecret POSTs to the controller's private
        # IP): needs ENI create/describe/delete in the private subnets.
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
    )
    _rotation_role.attach_inline_policy(
        iam.Policy(
            scope,
            "DcvEventRelayRotationPolicy",
            statements=[
                iam.PolicyStatement(
                    sid="RotateOwnSecret",
                    actions=[
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:UpdateSecretVersionStage",
                    ],
                    resources=[_relay_secret.secret_arn],
                ),
                iam.PolicyStatement(
                    sid="ReadControllerUrlParam",
                    actions=["ssm:GetParameter"],
                    resources=[
                        f"arn:{Aws.PARTITION}:ssm:{_region}:{Aws.ACCOUNT_ID}:parameter/edh/{_cluster_id}/configuration/ControllerWebUIUrl"
                    ],
                ),
                iam.PolicyStatement(
                    sid="LogsCommon",
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
    _rotation_lambda = aws_lambda.Function(
        scope,
        f"{_cluster_id}-DcvEventRelayRotation",
        function_name=f"{_cluster_id}-DcvEventRelayRotation",
        description="SecretsManager rotation handler for DCV event-relay HMAC key (4-step: create/set/test/finish)",
        memory_size=128,
        runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        timeout=Duration.minutes(2),
        log_group=scope.generate_log_group(name="DcvEventRelayRotationLambda"),
        role=_rotation_role,
        handler="DcvEventRelayRotation.handler",
        code=aws_lambda.Code.from_asset("../functions/DcvEventRelayRotation"),
        layers=[_l for _l in [scope.soca_resources.get("boto3_layer")] if _l] or None,
        environment={
            "EDH_CLUSTER_ID": _cluster_id,
            "CONTROLLER_URL_PARAM": f"/edh/{_cluster_id}/configuration/ControllerWebUIUrl",
        },
        retry_attempts=0,
        # VPC-attached so testSecret can reach the controller's RFC1918
        # private IP on :8443. Reuses the relay Lambda SG (allow_all
        # _outbound + existing controller :8443 ingress rule).
        vpc=scope.soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[scope.soca_resources["dcv_event_relay_lambda_sg"]],
    )
    # Attach rotation schedule. AWS-managed rotation invokes our
    # Lambda with the standard 4-step contract; 90-day cadence per
    # design doc.
    _relay_secret.add_rotation_schedule(
        "DcvEventRelayRotationSchedule",
        rotation_lambda=_rotation_lambda,
        automatically_after=Duration.days(90),
    )

    # ----- 4. Relay Lambda (SQS event-source-mapping target) ----------
    _relay_role = iam.Role(
        scope,
        "DcvEventRelayRole",
        description="IAM role for the DcvEventRelay Lambda (SQS-driven)",
        assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        # VPC-attached Lambda: needs ENI create/describe/delete to
        # provision its network interface in the private subnets.
        # Same pattern as DcvScreenshotPollerRole.
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
    )
    _relay_role.attach_inline_policy(
        iam.Policy(
            scope,
            "DcvEventRelayPolicy",
            statements=[
                iam.PolicyStatement(
                    sid="ReadRelayKeyAwsCurrentOnly",
                    actions=["secretsmanager:GetSecretValue"],
                    resources=[_relay_secret.secret_arn],
                    # Relay Lambda only ever signs with AWSCURRENT.
                    # Tighter than controller side (which also reads
                    # AWSPREVIOUS to span rotation overlap).
                    conditions={
                        "ForAnyValue:StringEquals": {
                            "secretsmanager:VersionStage": ["AWSCURRENT"]
                        }
                    },
                ),
                iam.PolicyStatement(
                    sid="ReadControllerUrlParam",
                    actions=["ssm:GetParameter"],
                    resources=[
                        f"arn:{Aws.PARTITION}:ssm:{_region}:{Aws.ACCOUNT_ID}:parameter/edh/{_cluster_id}/configuration/ControllerWebUIUrl"
                    ],
                ),
                iam.PolicyStatement(
                    sid="ConsumeSessionEventsQueue",
                    actions=[
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes",
                    ],
                    resources=[_queue.queue_arn],
                ),
                iam.PolicyStatement(
                    sid="EmitMetrics",
                    actions=["cloudwatch:PutMetricData"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "cloudwatch:namespace": "EDH/DCVEventRelay",
                        }
                    },
                ),
                iam.PolicyStatement(
                    sid="LogsCommon",
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
    scope.soca_resources["dcv_event_relay_role"] = _relay_role
    _relay_lambda = aws_lambda.Function(
        scope,
        f"{_cluster_id}-DcvEventRelay",
        function_name=f"{_cluster_id}-DcvEventRelay",
        description="SQS-driven pre-screen + canonical-string HMAC + relay of DCV session-events to controller",
        memory_size=256,
        runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        timeout=Duration.seconds(30),
        log_group=scope.generate_log_group(name="DcvEventRelayLambda"),
        role=_relay_role,
        handler="DcvEventRelay.handler",
        code=aws_lambda.Code.from_asset("../functions/DcvEventRelay"),
        layers=[_l for _l in [scope.soca_resources.get("boto3_layer")] if _l] or None,
        environment={
            "EDH_CLUSTER_ID": _cluster_id,
            "EDH_CONTROLLER_URL": f"https://{scope.soca_resources['controller_instance'].attr_private_ip}:8443",
            "EDH_RELAY_SECRET_ARN": _relay_secret.secret_arn,
        },
        retry_attempts=0,
        # VPC-attached so the Lambda can reach the controller's RFC1918
        # private IP. Without this the Lambda runs in AWS-managed VPC
        # and POSTs time out (no route to 10.x). Same pattern as
        # DcvScreenshotPoller. Dedicated SG, allow_all_outbound covers
        # the controller HTTPS hop (8443) plus SecretsManager VPC
        # endpoint for the relay key fetch. No inbound: Lambda ENIs
        # do not accept inbound traffic.
        vpc=scope.soca_resources["vpc"],
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        security_groups=[scope.soca_resources["dcv_event_relay_lambda_sg"]],
    )
    scope.soca_resources["dcv_event_relay_lambda"] = _relay_lambda

    # Allow the relay Lambda's SG to reach the controller's WebUI on
    # TCP/8443. Without this the Lambda's POST times out at the
    # controller_sg ingress and SQS messages just sit in the queue.
    security_groups_helper.create_ingress_rule(
        security_group=scope.soca_resources["controller_sg"],
        peer=scope.soca_resources["dcv_event_relay_lambda_sg"],
        connection=ec2.Port.tcp(8443),
        description="DcvEventRelay Lambda to controller WebUI (TCP/8443)",
    )

    # SQS event source mapping -- AWS-managed long-poll, batched up to
    # 10 messages per invocation. Failed records returned via
    # batchItemFailures so SQS retries only those, not the whole batch.
    _relay_lambda.add_event_source(
        lambda_event_sources.SqsEventSource(
            _queue,
            batch_size=10,
            max_batching_window=Duration.seconds(0),  # respond immediately
            report_batch_item_failures=True,
        )
    )

    # ----- 5. VDI role grants: sqs:SendMessage on this queue only ------
    # vdi_node_role (high-scale VDIs, split out from compute_node_role)
    # and target_node_role (legacy) host VDIs that publish events.
    # Tightly scoped to this single queue ARN; SQS sets the SenderId
    # attribute from SigV4 so a VDI cannot impersonate another.
    for _role_key in ("vdi_node_role", "target_node_role"):
        _role = scope.soca_resources.get(_role_key)
        if _role is None:
            continue
        _role.attach_inline_policy(
            iam.Policy(
                scope,
                f"DcvEventRelayPublish{_role_key.replace('_', '')}",
                statements=[
                    iam.PolicyStatement(
                        sid="PublishDcvSessionEvents",
                        actions=["sqs:SendMessage"],
                        resources=[_queue.queue_arn],
                    )
                ],
            )
        )

    # ----- 6. SocaConfig SSM parameters --------------------------------
    # Controller WebUI URL: we synthesize from the existing
    # ControllerPrivateDnsName param. Default WebUI port is 8443.
    ssm.StringParameter(
        scope,
        "DcvControllerWebUIUrlParam",
        parameter_name=f"/edh/{_cluster_id}/configuration/ControllerWebUIUrl",
        string_value=f"https://{scope.soca_resources['controller_instance'].attr_private_ip}:8443",
        description="HTTPS URL the DcvEventRelay Lambda hits to deliver validated session-events",
    )
    ssm.StringParameter(
        scope,
        "DcvSessionEventsQueueUrlParam",
        parameter_name=f"/edh/{_cluster_id}/configuration/DcvSessionEventsQueueUrl",
        string_value=_queue.queue_url,
        description="SQS queue URL where VDIs publish DCV session-events via aws sqs send-message",
    )
    ssm.StringParameter(
        scope,
        "DcvEventRelaySecretArnParam",
        parameter_name=f"/edh/{_cluster_id}/configuration/DcvEventRelaySecretArn",
        string_value=_relay_secret.secret_arn,
        description="SecretsManager ARN for DCV event-relay HMAC key (Lambda-controller transport auth)",
    )

    # ----- 7. CloudWatch alarms on Rejected metric ---------------------
    # 5+ rejections in 5 min anywhere -- something is misbehaving.
    cloudwatch.Alarm(
        scope,
        "DcvEventRelayRejectedAlarm",
        alarm_name=f"{_cluster_id}-DcvEventRelay-Rejected",
        alarm_description="DCV event-relay rejected events spike (controller and Lambda combined)",
        metric=cloudwatch.Metric(
            namespace="EDH/DCVEventRelay",
            metric_name="Rejected",
            statistic="Sum",
            period=Duration.minutes(5),
            dimensions_map={"ClusterId": _cluster_id},
        ),
        threshold=5,
        evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    # Forgery-shaped alarm: a body_instance_mismatch rejection means a
    # VDI tried to publish an event with a body.instance_id that did
    # NOT match its AWS-attested SenderId. Legitimate VDIs cannot
    # produce this; any hit is potentially an active spoofing attempt.
    cloudwatch.Alarm(
        scope,
        "DcvEventRelayInstanceForgeryAlarm",
        alarm_name=f"{_cluster_id}-DcvEventRelay-InstanceForgery",
        alarm_description="DCV event-relay rejected an event for body/SenderId mismatch -- possible spoofing attempt",
        metric=cloudwatch.Metric(
            namespace="EDH/DCVEventRelay",
            metric_name="Rejected",
            statistic="Sum",
            period=Duration.minutes(1),
            dimensions_map={
                "ClusterId": _cluster_id,
                "Reason": "body_instance_mismatch",
            },
        ),
        threshold=1,
        evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )

    # ----- 8. Phase 2: EC2 state-change EventBridge rule ---------------
    # Forwards EC2 "running" state-change events to the same Lambda.
    # The Lambda filters by the EC2's edh:ClusterId tag (matches via
    # DescribeInstances at runtime) so a single account can host
    # multiple clusters without cross-talk.
    events.Rule(
        scope,
        "DcvEventRelayEc2StateRunningRule",
        rule_name=f"{_cluster_id}-ec2-state-running",
        description=(
            f"Forward EC2 state=running events to DcvEventRelay Lambda "
            f"for cluster {_cluster_id} (lights the ec2-running grid timeline dot)"
        ),
        event_pattern=events.EventPattern(
            source=["aws.ec2"],
            detail_type=["EC2 Instance State-change Notification"],
            detail={"state": ["running"]},
        ),
        targets=[aws_events_targets.LambdaFunction(_relay_lambda)],
    )

    # ----- 9. Phase 3: per-cluster CFN events SNS topic ----------------
    # CloudFormation publishes stack lifecycle events here when
    # create_virtual_desktop sets NotificationARNs on its create_stack
    # call. The same Lambda subscribes and forwards
    # CREATE_IN_PROGRESS for the stack itself as the stack-launching
    # checkpoint.
    _cfn_events_topic = sns.Topic(
        scope,
        "DcvEventRelayCfnEventsTopic",
        topic_name=f"{_cluster_id}-cfn-events",
        display_name=f"{_cluster_id} CFN stack lifecycle events",
    )
    _cfn_events_topic.add_subscription(
        sns_subscriptions.LambdaSubscription(_relay_lambda)
    )
    # Allow the AWS account to publish to this topic so any IAM
    # principal (including CloudFormation when create_stack is invoked
    # by a user/role with notification permissions) can deliver
    # events. CloudFormation publishes as the calling principal, not
    # as a service principal, so this is account-scoped.
    _cfn_events_topic.add_to_resource_policy(
        iam.PolicyStatement(
            sid="AllowAccountPublish",
            effect=iam.Effect.ALLOW,
            principals=[iam.AccountRootPrincipal()],
            actions=["sns:Publish"],
            resources=[_cfn_events_topic.topic_arn],
        )
    )
    # Expose the topic ARN to the controller via SSM so
    # create_virtual_desktop.py can read it at request time and pass
    # NotificationARNs on the create_stack call. Resolved at create
    # time (not boot) so a topic added via hot-patch is picked up
    # immediately on the next VDI request.
    ssm.StringParameter(
        scope,
        "DcvEventRelayCfnEventsTopicArnParam",
        parameter_name=f"/edh/{_cluster_id}/configuration/CfnEventsTopicArn",
        string_value=_cfn_events_topic.topic_arn,
        description=(
            "SNS topic ARN for CloudFormation stack lifecycle events. "
            "create_virtual_desktop.py passes this in NotificationARNs "
            "on every CFN create_stack call."
        ),
    )

    # ----- 10. Lambda IAM for the new infra-event paths ----------------
    # EventBridge EC2 events arrive without tags; Lambda must call
    # DescribeInstances to read edh:ClusterId / edh:SessionUuid.
    # SNS CFN events deliver stack ARN; Lambda calls DescribeStacks to
    # read tags. Both are read-only across all resources in the
    # account/region.
    _relay_lambda.role.attach_inline_policy(
        iam.Policy(
            scope,
            "DcvEventRelayInfraReadPolicy",
            statements=[
                iam.PolicyStatement(
                    sid="DescribeInstancesForEc2RunningEvent",
                    effect=iam.Effect.ALLOW,
                    actions=["ec2:DescribeInstances"],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    sid="DescribeStacksForCfnLaunchingEvent",
                    effect=iam.Effect.ALLOW,
                    actions=["cloudformation:DescribeStacks"],
                    resources=["*"],
                ),
            ],
        )
    )

    logger.debug(
        f"DCV Event Relay configured: queue={_queue.queue_name} "
        f"secret_arn={_relay_secret.secret_arn} "
        f"rotation=90d auto"
    )


def _dcv_high_scale_alarms(
    scope,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    principals_suffix=None,
    get_lambda_runtime_version=None,
    flatten_parameterstore_config=None,
    return_ebs_volume_type=None,
):
    """
    Create CloudWatch alarms for the DCV high-scale screenshot pipeline
    and broker/gateway host health.

    Backed by:
      - EDH/DCVHighScale custom namespace (poller Lambda + cwagent)
      - DCV Session Manager Broker namespace (broker JVM)

    Alarm actions route to the existing cluster SNS topic so admin
    email subscribers get notified.
    """
    if not get_config_key(
        key_name="Config.dcv.high_scale_enabled",
        expected_type=bool,
        required=False,
        default=False,
    ):
        return
    topic = scope.soca_resources.get("sns_cluster_topic")
    screenshot_lambda = scope.soca_resources.get("dcv_screenshot_lambda")
    if topic is None or screenshot_lambda is None:
        logger.debug(
            "Skipping DCV HS alarms: SNS topic or screenshot lambda missing"
        )
        return

    _ns = "EDH/DCVHighScale"
    _dims = {"ClusterId": user_specified_variables.cluster_id}

    broker_err_metric = cloudwatch.Metric(
        namespace=_ns,
        metric_name="ScreenshotsBrokerErrors",
        dimensions_map=_dims,
        statistic="Sum",
        period=Duration.minutes(2),
    )

    broker_err_alarm = cloudwatch.Alarm(
        scope,
        "DcvScreenshotsBrokerErrorsAlarm",
        alarm_name=f"{user_specified_variables.cluster_id}-DcvScreenshots-BrokerErrors",
        alarm_description=(
            "DCV screenshot poller could not reach the broker on any "
            "cycle in the last 4 minutes. Screenshots will go stale "
            "for users until the broker returns. Check broker ASG "
            "and backend NLB health."
        ),
        metric=broker_err_metric,
        threshold=0,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluation_periods=2,
        datapoints_to_alarm=2,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    broker_err_alarm.add_alarm_action(cw_actions.SnsAction(topic))
    broker_err_alarm.add_ok_action(cw_actions.SnsAction(topic))

    # NOTE: a MaxAge alarm was previously here. Removed because the
    # signal overlapped with the bucket lifecycle expiration policy
    # (sessions sitting at lock screens / idle hit MaxAge before the
    # lifecycle deletes the object, which isn't operationally
    # actionable). Revisit when we have a per-session "active but no
    # fresh frame" signal that distinguishes stuck sessions from
    # idle ones.

    # Host-level alarms backed by the CloudWatch Agent (cwagent
    # publishes mem_used_percent, swap_used_percent, disk
    # used_percent into the EDH/DCVHighScale namespace).
    #
    # Cluster scoping: CW Agent's `append_dimensions` only honors
    # the four built-in `${aws:...}` placeholders. We use
    # AutoScalingGroupName as the per-fleet key. CloudWatch Alarms
    # do NOT support SEARCH expressions (only dashboards do), so we
    # emit one alarm per (metric × fleet) using the exact ASG name
    # as the dimension. That's also more useful operationally:
    # the alarm name tells you which fleet is breaching.
    _host_alarm_specs = [
        {
            "metric": "mem_used_percent",
            "suffix": "MemHigh",
            "period": Duration.minutes(5),
            "threshold": 85,
            "stat": "Maximum",
            "datapoints": 2,
            "desc_template": (
                "{role} fleet host exceeded 85% memory used for "
                "10 min. JVM heap exhaustion or OOM-killer risk. "
                "Inspect -Xmx tuning or scale out."
            ),
        },
        {
            "metric": "swap_used_percent",
            "suffix": "SwapInUse",
            "period": Duration.minutes(1),
            "threshold": 0,
            "stat": "Maximum",
            "datapoints": 2,
            "desc_template": (
                "{role} fleet host using swap. Latency-sensitive "
                "services must never swap. Reboot the offending "
                "host or scale out."
            ),
        },
        {
            "metric": "disk_used_percent",
            "suffix": "DiskHigh",
            "period": Duration.minutes(5),
            "threshold": 80,
            "stat": "Maximum",
            "datapoints": 2,
            "desc_template": (
                "{role} fleet host root disk over 80% used. Logs "
                "or heap dumps may be filling up. Rotate or expand "
                "the volume."
            ),
        },
    ]
    for _role in ("broker", "gateway"):
        _asg = scope.soca_resources.get(f"dcv_{_role}_asg")
        if _asg is None:
            continue
        _asg_name = _asg.auto_scaling_group_name  # CDK token, resolves at deploy
        for _spec in _host_alarm_specs:
            _alarm_id = f"DcvHosts{_role.capitalize()}{_spec['suffix']}Alarm"
            _alarm_name = (
                f"{user_specified_variables.cluster_id}-DcvHosts-"
                f"{_role.capitalize()}-{_spec['suffix']}"
            )
            _alarm = cloudwatch.Alarm(
                scope,
                _alarm_id,
                alarm_name=_alarm_name,
                alarm_description=_spec["desc_template"].format(
                    role=_role.capitalize(),
                ),
                metric=cloudwatch.Metric(
                    namespace=_ns,
                    metric_name=_spec["metric"],
                    dimensions_map={"AutoScalingGroupName": _asg_name},
                    statistic=_spec["stat"],
                    period=_spec["period"],
                ),
                threshold=_spec["threshold"],
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                evaluation_periods=_spec["datapoints"],
                datapoints_to_alarm=_spec["datapoints"],
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            )
            _alarm.add_alarm_action(cw_actions.SnsAction(topic))
            _alarm.add_ok_action(cw_actions.SnsAction(topic))
            scope.soca_resources[_alarm_id] = _alarm

    # ----------------------------------------------------------------
    # Broker fleet JVM divergence alarms
    # ----------------------------------------------------------------
    # The DCV Session Manager Broker publishes per-broker JVM
    # gauges (Heap Memory Used, Off Heap Memory Used, Cpu Load)
    # under the literal namespace "DCV Session Manager Broker"
    # with dimensions (Fleet Name, Broker Address, EC2 Instance
    # Id). Per-cluster scoping is via Fleet Name == cluster_id.
    #
    # A pure AVG across the fleet hides the failure case where
    # one broker is GC-thrashing while peers idle. We alarm on the
    # spread (MAX-MIN)/AVG via CW math so divergence is paged
    # operationally even though the dashboard shows it visually.
    #
    # Threshold rationale:
    #   - Heap: 0.40 (40%). With a healthy 2-broker fleet sharing
    #     traffic via NLB source-IP stickiness, heap usage is
    #     within 20-30% of each other in steady state. 40%+ for
    #     10 min means traffic skew or a GC pathology.
    #   - Cpu Load: 0.50. JVM CPU load is jumpier; only alarm on
    #     sustained, large divergence.
    _broker_ns = "DCV Session Manager Broker"
    _fleet_search_template = (
        f'SEARCH(\'{{"{_broker_ns}","Fleet Name","Broker Address","EC2 Instance Id"}} '
        f'MetricName="%METRIC%" "Fleet Name"="{user_specified_variables.cluster_id}"\', '
        f'\'Average\', 60)'
    )

    for _spec in (
        {
            "id": "DcvBrokerJvmHeapDivergenceAlarm",
            "name": f"{user_specified_variables.cluster_id}-DcvBroker-JvmHeapDivergence",
            "broker_metric": "Heap Memory Used",
            "threshold": 0.40,
            "datapoints": 10,  # 10 of last 10 minutes
            "desc": (
                "Per-broker JVM heap divergence (max-min)/avg "
                "exceeded 40% for 10 min. One broker is carrying "
                "disproportionate load or has a GC pathology while "
                "peers are idle. NLB source-IP stickiness can "
                "concentrate traffic; check broker logs and "
                "consider scaling out."
            ),
        },
        {
            "id": "DcvBrokerJvmCpuDivergenceAlarm",
            "name": f"{user_specified_variables.cluster_id}-DcvBroker-JvmCpuDivergence",
            "broker_metric": "Cpu Load",
            "threshold": 0.50,
            "datapoints": 10,
            "desc": (
                "Per-broker JVM CPU load divergence (max-min)/avg "
                "exceeded 50% for 10 min. One broker is busy while "
                "peers idle. Indicates traffic skew or a stuck "
                "broker request. Check broker logs and NLB target "
                "balance."
            ),
        },
    ):
        _search = _fleet_search_template.replace("%METRIC%", _spec["broker_metric"])
        _div_alarm = cloudwatch.Alarm(
            scope,
            _spec["id"],
            alarm_name=_spec["name"],
            alarm_description=_spec["desc"],
            metric=cloudwatch.MathExpression(
                expression=f"IF(AVG(m) > 0, (MAX(m) - MIN(m)) / AVG(m), 0)",
                using_metrics={"m": cloudwatch.MathExpression(
                    expression=_search,
                    period=Duration.minutes(1),
                    label=f"{_spec['broker_metric']} per-broker",
                )},
                period=Duration.minutes(1),
                label=f"{_spec['broker_metric']} fleet spread",
            ),
            threshold=_spec["threshold"],
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            evaluation_periods=_spec["datapoints"],
            datapoints_to_alarm=_spec["datapoints"],
            # Single-broker fleets emit no spread; treat as not breaching
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        _div_alarm.add_alarm_action(cw_actions.SnsAction(topic))
        _div_alarm.add_ok_action(cw_actions.SnsAction(topic))
        scope.soca_resources[_spec["id"]] = _div_alarm

    # ----------------------------------------------------------------
    # Broker cluster split-brain alarms (server / session count spread)
    # ----------------------------------------------------------------
    # When the broker fleet is properly Ignite-clustered, every broker
    # shares state, so each reports the SAME fleet-wide counts. If the
    # cluster splits (e.g. broker-to-broker mTLS / discovery failure),
    # brokers see only their own subset and the per-broker counts
    # DIVERGE -- a silent failure that still "works" for single-broker
    # traffic but breaks the screenshot poller / WebUI fleet view.
    #
    # We alarm on the RAW spread (MAX-MIN) of the native per-broker
    # count metrics: clustered => spread 0; split => spread >= 1.
    # 10-of-10-min sustained so a freshly-joining broker syncing its
    # Ignite state (~1-2 min) doesn't false-fire, and single-broker
    # fleets (one series, spread 0) never fire.
    for _cspec in (
        {
            "id": "DcvBrokerServerCountDivergenceAlarm",
            "name": f"{user_specified_variables.cluster_id}-DcvBroker-ServerCountDivergence",
            "broker_metric": "Number Of DCV Servers",
            "desc": (
                "Per-broker 'Number Of DCV Servers' diverges across the "
                "fleet for 10 min -- the brokers are NOT sharing cluster "
                "state (Ignite split-brain). Clustered brokers report "
                "identical server counts. Check broker-to-broker mTLS / "
                "discovery (SG self-ingress on 47100/47500, shared CA) and "
                "broker logs for 'missing SSL configuration on remote node' "
                "/ 'Failed to ping node'."
            ),
        },
        {
            "id": "DcvBrokerSessionCountDivergenceAlarm",
            "name": f"{user_specified_variables.cluster_id}-DcvBroker-SessionCountDivergence",
            "broker_metric": "Number Of DCV Sessions",
            "desc": (
                "Per-broker 'Number Of DCV Sessions' diverges across the "
                "fleet for 10 min -- brokers are not sharing session state "
                "(Ignite split-brain). Same root causes as "
                "ServerCountDivergence; the screenshot poller / WebUI will "
                "see an inconsistent session list depending on which broker "
                "the NLB routes to."
            ),
        },
    ):
        _csearch = _fleet_search_template.replace("%METRIC%", _cspec["broker_metric"])
        _cdiv_alarm = cloudwatch.Alarm(
            scope,
            _cspec["id"],
            alarm_name=_cspec["name"],
            alarm_description=_cspec["desc"],
            metric=cloudwatch.MathExpression(
                # Raw spread (not a ratio): any whole-unit divergence
                # between brokers is a split-brain signal.
                expression="MAX(m) - MIN(m)",
                using_metrics={"m": cloudwatch.MathExpression(
                    expression=_csearch,
                    period=Duration.minutes(1),
                    label=f"{_cspec['broker_metric']} per-broker",
                )},
                period=Duration.minutes(1),
                label=f"{_cspec['broker_metric']} fleet spread",
            ),
            threshold=0,  # > 0 => >= 1 for integer counts => split
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            evaluation_periods=10,
            datapoints_to_alarm=10,
            # Single-broker fleets emit one series (spread 0); also a
            # joining broker briefly diverges -- 10/10 min absorbs it.
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        _cdiv_alarm.add_alarm_action(cw_actions.SnsAction(topic))
        _cdiv_alarm.add_ok_action(cw_actions.SnsAction(topic))
        scope.soca_resources[_cspec["id"]] = _cdiv_alarm

    # ----------------------------------------------------------------
    # Broker keystore / CA expiry alarm (native "Days until expiry")
    # ----------------------------------------------------------------
    # The broker natively publishes "Days until expiry" per keystore
    # (client/agent/gateway/broker-to-broker) per broker. A silent CA
    # expiry breaks broker-to-broker mTLS (and client/agent/gateway TLS)
    # -- the DCV self-signed default is only ~2y. We alarm on the MIN
    # across all keystores/brokers for the fleet so the soonest-expiring
    # cert pages with ~30 days lead time.
    _ca_search = (
        f'SEARCH(\'{{"{_broker_ns}","Fleet Name","Broker Address","EC2 Instance Id",'
        f'"Keystore Name","Alias"}} MetricName="Days until expiry" '
        f'"Fleet Name"="{user_specified_variables.cluster_id}"\', \'Minimum\', 300)'
    )
    _ca_expiry_alarm = cloudwatch.Alarm(
        scope,
        "DcvBrokerCertExpiryAlarm",
        alarm_name=f"{user_specified_variables.cluster_id}-DcvBroker-CertExpiry",
        alarm_description=(
            "A DCV broker keystore (client / agent / gateway / "
            "broker-to-broker) is within 30 days of expiry. Expiry "
            "silently breaks broker TLS -- including the broker-to-broker "
            "mTLS the Ignite cluster needs. Rotate the shared broker CA "
            "(see dcv-broker-ca-lifecycle-spec.md) before it lapses."
        ),
        metric=cloudwatch.MathExpression(
            expression="MIN(m)",
            using_metrics={"m": cloudwatch.MathExpression(
                expression=_ca_search,
                period=Duration.minutes(5),
                label="Days until expiry (per keystore)",
            )},
            period=Duration.minutes(5),
            label="Soonest keystore expiry (days)",
        ),
        threshold=30,
        comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluation_periods=3,
        datapoints_to_alarm=3,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    _ca_expiry_alarm.add_alarm_action(cw_actions.SnsAction(topic))
    _ca_expiry_alarm.add_ok_action(cw_actions.SnsAction(topic))
    scope.soca_resources["dcv_broker_cert_expiry"] = _ca_expiry_alarm

    # ----------------------------------------------------------------
    # Broker Ignite cluster-health alarm (positive, cause-agnostic)
    # ----------------------------------------------------------------
    # The dcv_broker_cluster_monitor collector on each broker reads the
    # broker's in-process Ignite topology via local JVM attach + JMX
    # (ClusterMetricsMXBeanImpl.TotalServerNodes) and publishes
    # BrokerClusterHealthy = 1 if (server nodes seen >= healthy brokers in
    # the discovery TG) else 0, to EDH/DCVHighScale {ClusterId, InstanceId}.
    #
    # Unlike the count-divergence alarms (which DynamoDB-backed session
    # state can mask), this is a POSITIVE health signal straight from
    # Ignite: a broker split off the cluster for ANY reason (mTLS,
    # discovery, network, GC) reports fewer peers than are alive ->
    # healthy=0 -> alarm. No log-pattern matching, no known-failure list.
    # MIN across the fleet: if ANY broker is unhealthy, page.
    _cluster_health_search = (
        f'SEARCH(\'{{EDH/DCVHighScale,ClusterId,InstanceId}} '
        f'MetricName="BrokerClusterHealthy" ClusterId="{user_specified_variables.cluster_id}"\', '
        f'\'Minimum\', 60)'
    )
    _cluster_health_alarm = cloudwatch.Alarm(
        scope,
        "DcvBrokerClusterHealthAlarm",
        alarm_name=f"{user_specified_variables.cluster_id}-DcvBroker-ClusterHealth",
        alarm_description=(
            "A DCV broker reports fewer Ignite server nodes than there are "
            "healthy brokers in the fleet for 10 min -- the broker is split "
            "off the cluster (cause-agnostic: mTLS, discovery, network, GC, "
            "etc.). Read directly from the broker's in-process Ignite "
            "topology (TotalServerNodes) by dcv_broker_cluster_monitor. "
            "Investigate broker-to-broker connectivity (SG 47100/47500) and "
            "discovery; a split fleet degrades cross-broker messaging."
        ),
        metric=cloudwatch.MathExpression(
            expression="MIN(m)",
            using_metrics={"m": cloudwatch.MathExpression(
                expression=_cluster_health_search,
                period=Duration.minutes(1),
                label="BrokerClusterHealthy per-broker",
            )},
            period=Duration.minutes(1),
            label="Fleet min cluster health (1=ok,0=split)",
        ),
        threshold=1,
        comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
        evaluation_periods=10,
        datapoints_to_alarm=10,
        # No data (collector not yet reporting / broker restarting) is not
        # a split -- TG/process alarms cover a down broker.
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    _cluster_health_alarm.add_alarm_action(cw_actions.SnsAction(topic))
    _cluster_health_alarm.add_ok_action(cw_actions.SnsAction(topic))
    scope.soca_resources["dcv_broker_cluster_health"] = _cluster_health_alarm


    # ----------------------------------------------------------------
    # DCV streaming quality alarms (per-session frame loss + latency)
    # ----------------------------------------------------------------
    # The custom DCV streaming collector on each VDI host publishes:
    #   - DegradedSessions (Count)  — # sessions where frame_loss>5%
    #                                 OR latency>100ms in the cycle
    #   - ActiveSessions   (Count)  — # active sessions per host
    # under namespace EDH/DCVStreaming with dimension {ClusterId}.
    # Two alarms:
    #   1. Absolute count: 5+ degraded sessions for 5 min
    #   2. Ratio:          >10% of active sessions degraded for 5 min
    # Both fire — different thresholds catch different fleet sizes.
    _streaming_ns = "EDH/DCVStreaming"
    _streaming_dims = {"ClusterId": user_specified_variables.cluster_id}

    streaming_abs_alarm = cloudwatch.Alarm(
        scope,
        "DcvStreamingDegradedAbsAlarm",
        alarm_name=f"{user_specified_variables.cluster_id}-DcvStreaming-DegradedAbs",
        alarm_description=(
            "5 or more DCV sessions reporting frame loss > 5% or "
            "network latency > 100ms for 5 consecutive minutes. "
            "Investigate fleet-wide network or GPU-driver issues "
            "before users report it."
        ),
        metric=cloudwatch.Metric(
            namespace=_streaming_ns,
            metric_name="DegradedSessions",
            dimensions_map=_streaming_dims,
            statistic="Maximum",
            period=Duration.minutes(1),
        ),
        threshold=4,  # > 4 means >= 5
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluation_periods=5,
        datapoints_to_alarm=5,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    streaming_abs_alarm.add_alarm_action(cw_actions.SnsAction(topic))
    streaming_abs_alarm.add_ok_action(cw_actions.SnsAction(topic))

    streaming_ratio_alarm = cloudwatch.Alarm(
        scope,
        "DcvStreamingDegradedRatioAlarm",
        alarm_name=f"{user_specified_variables.cluster_id}-DcvStreaming-DegradedRatio",
        alarm_description=(
            "More than 10% of active DCV sessions reporting frame "
            "loss > 5% or network latency > 100ms for 5 consecutive "
            "minutes. Catches incident scope on small fleets where "
            "the absolute alarm doesn't fire."
        ),
        metric=cloudwatch.MathExpression(
            expression="IF(active > 0, (degraded / active) * 100, 0)",
            using_metrics={
                "degraded": cloudwatch.Metric(
                    namespace=_streaming_ns,
                    metric_name="DegradedSessions",
                    dimensions_map=_streaming_dims,
                    statistic="Maximum",
                    period=Duration.minutes(1),
                ),
                "active": cloudwatch.Metric(
                    namespace=_streaming_ns,
                    metric_name="ActiveSessions",
                    dimensions_map=_streaming_dims,
                    statistic="Maximum",
                    period=Duration.minutes(1),
                ),
            },
            period=Duration.minutes(1),
            label="Degraded session ratio (%)",
        ),
        threshold=10,  # 10 percent
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluation_periods=5,
        datapoints_to_alarm=5,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )
    streaming_ratio_alarm.add_alarm_action(cw_actions.SnsAction(topic))
    streaming_ratio_alarm.add_ok_action(cw_actions.SnsAction(topic))
    scope.soca_resources["dcv_streaming_degraded_abs"] = streaming_abs_alarm
    scope.soca_resources["dcv_streaming_degraded_ratio"] = streaming_ratio_alarm

    scope.soca_resources["dcv_screenshot_alarm_broker_errors"] = broker_err_alarm


def viewer(
    scope,
    *,
    get_config_key=None,
    get_kms_key_id=None,
    user_specified_variables=None,
    principals_suffix=None,
    get_lambda_runtime_version=None,
    flatten_parameterstore_config=None,
    return_ebs_volume_type=None,
):
    # Create the ALB. It's used to forward HTTP/S traffic to DCV hosts, Web UI and Analytics back-end

    # FIXME TODO - duplicate with NLB
    _alb_public_bool: bool = (
        True if user_specified_variables.deployment_mode == "public" else False
    )

    logger.debug(f"ALB / Cluster Entry Point Public?: {_alb_public_bool}")

    _alb_subnets_list: list = []
    _source_subnets: list = []

    # Did we use existing resources?
    if user_specified_variables.vpc_id:
        # Existing resources
        logger.debug(
            f"Using imported VPC Subnets for ALB from VPC {user_specified_variables.vpc_id}"
        )
        if _alb_public_bool:
            _source_subnets = user_specified_variables.public_subnets
        else:
            _source_subnets = user_specified_variables.private_subnets

        for _subnet in _source_subnets:
            _subnet_id: str = _subnet.split(",")[0]
            _subnet_az: str = _subnet.split(",")[1]
            _alb_subnets_list.append(_subnet_id)
            logger.debug(
                f"Adding existing subnet for ALB: {_subnet_id} / AZ: {_subnet_az}"
            )

    else:
        # SOCA created the VPC
        logger.debug("Using SOCA created VPC Subnets for ALB")
        if _alb_public_bool:
            logger.debug("Adding SOCA created public subnets")
            for _soca_sn in scope.soca_resources["vpc"].public_subnets:
                logger.debug(
                    f"Adding SOCA created public subnet: {_soca_sn.subnet_id}"
                )
                _source_subnets.append(_soca_sn.subnet_id)
        else:
            logger.debug("Adding SOCA created private subnets")
            for _soca_sn in scope.soca_resources["vpc"].private_subnets:
                logger.debug(
                    f"Adding SOCA created private subnet: {_soca_sn.subnet_id}"
                )
                _source_subnets.append(_soca_sn.subnet_id)

        logger.debug(f"Scanning Source subnets: {_source_subnets}")
        # TODO - still needed?
        for _subnet in _source_subnets:
            logger.debug(f"Adding ALB subnet: {_subnet}")
            _alb_subnets_list.append(_subnet)
            logger.debug(f"Adding existing subnet for ALB: {_subnet}")

    logger.debug(
        f"Final subnets for ALB: {_alb_subnets_list} / Public: {_alb_public_bool}"
    )

    # Convert our subnet list to a list of ISubnets
    _alb_isubnets_list: list = []

    for _i, _subnet in enumerate(_alb_subnets_list):
        _i_subnet_entry = ec2.Subnet.from_subnet_id(
            scope,
            f"ALBSubnet{_i}",
            subnet_id=_subnet,
        )
        Annotations.of(_i_subnet_entry).acknowledge_warning(
            id="@aws-cdk/aws-ec2:noSubnetRouteTableId",
            message="RouteTableId will not be processed",
        )
        _alb_isubnets_list.append(_i_subnet_entry)

    logger.debug(f"Final ISubnets for ALB: {_alb_isubnets_list}")

    scope.soca_resources["alb"] = elbv2.ApplicationLoadBalancer(
        scope,
        f"{user_specified_variables.cluster_id}-ELBv2Viewer",
        load_balancer_name=f"{user_specified_variables.cluster_id}-viewer",
        security_group=scope.soca_resources["alb_sg"],
        http2_enabled=True,
        vpc=scope.soca_resources["vpc"],
        drop_invalid_header_fields=True,
        internet_facing=(
            True if user_specified_variables.deployment_mode == "public" else False
        ),
        vpc_subnets=ec2.SubnetSelection(subnets=_alb_isubnets_list),
        ip_address_type=(
            elbv2.IpAddressType.DUAL_STACK
            if scope.is_networking_af_enabled(address_family="ipv6")
            else elbv2.IpAddressType.IPV4
        ),
    )

    # TODO - FIXME - customize port via config
    soca_webui_target_group = elbv2.ApplicationTargetGroup(
        scope,
        f"{user_specified_variables.cluster_id}-SOCAWebUITargetGroup",
        port=8443,
        target_type=elbv2.TargetType.INSTANCE,
        protocol=elbv2.ApplicationProtocol.HTTPS,
        vpc=scope.soca_resources["vpc"],
        target_group_name=f"{user_specified_variables.cluster_id}-SOCAWebUI",
        targets=[
            elbv2_targets.InstanceIdTarget(
                instance_id=scope.soca_resources[
                    "controller_instance"
                ].attr_instance_id,
                port=8443,
            )
        ],
        health_check=elbv2.HealthCheck(
            port="8443", protocol=elbv2.Protocol.HTTPS, path="/ping"
        ),
    )

    scope.soca_resources["alb"].add_listener(
        "HTTPListener",
        port=80,
        open=False,
        protocol=elbv2.ApplicationProtocol.HTTP,
        default_action=elbv2.ListenerAction.redirect(
            protocol="HTTPS",
            host="#{host}",
            path="/#{path}",
            permanent=True,
            port="443",
            query="#{query}",
        ),
    )

    _configured_ssl_policy_name: str = get_config_key(
        key_name="Config.network.alb_tls_policy",
        required=False,
        default="ELBSecurityPolicy-TLS13-1-2-2021-06",
        expected_type=str,
    )

    logger.debug(f"Using SSL policy name: {_configured_ssl_policy_name}")

    scope.soca_resources["https_listener"] = elbv2.ApplicationListener(
        scope,
        "HTTPSListener",
        load_balancer=scope.soca_resources["alb"],
        port=443,
        open=False,
        protocol=elbv2.ApplicationProtocol.HTTPS,
        certificates=[
            acm.Certificate.from_certificate_arn(
                scope,
                "ImportACM",
                certificate_arn=user_specified_variables.tls_certificate,
            )
        ],
        default_action=elbv2.ListenerAction.forward(
            target_groups=[soca_webui_target_group]
        ),
    )

    # Use a CDK escape hatch to set the SSL policy
    # per the docs page versus Enum lookup via CDK
    # https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
    _https_cdk_override = scope.soca_resources["https_listener"].node.default_child
    _https_cdk_override.add_property_override(
        "SslPolicy", _configured_ssl_policy_name
    )

    # Determine our Analytics configuration based on the selected engine
    if (
        get_config_key(key_name="Config.analytics.enabled", expected_type=bool)
        is True
    ):
        if get_config_key("Config.analytics.engine") in {"opensearch"}:
            scope.viewer_analytics_opensearch()
        elif get_config_key("Config.analytics.engine") in {
            "opensearch_serverless",
            "aoss_serverless",
        }:
            aoss_helper.add_dashboard_output(
                scope=scope, soca_resources=scope.soca_resources
            )

    CfnOutput(
        scope,
        "WebUserInterface",
        value=f"https://{scope.soca_resources['alb'].load_balancer_dns_name}/",
    )
