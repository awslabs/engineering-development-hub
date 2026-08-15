######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                                #
######################################################################################################################
"""
CDK helper for the OpenSearch Serverless (AOSS) analytics collection.

Creates the in-VPC AOSS collection used for job/host analytics, plus its
required encryption policy, network policy, VPC endpoint, and data-access
policy. The data-access policy is created with the native CfnAccessPolicy
(the instance role ARNs are known at synth time from iam_roles()), so no
custom-resource Lambda is needed.

Usage from cdk_construct.py:

    from helpers import aoss as aoss_helper
    ...
    aoss_helper.create_collection(
        scope=self,
        soca_resources=self.soca_resources,
        user_specified_variables=user_specified_variables,
        get_config_key=get_config_key,
    )

Ordering: must be called AFTER iam_roles() and security_groups(). It reads the
vpc, the controller/compute/login/target security groups, and the
controller/compute/login IAM roles from soca_resources. The helper validates
this and raises RuntimeError naming the missing resource if called too early.
"""

import json
import logging
from typing import Any, Callable, Dict, Optional

import boto3

from aws_cdk import Annotations, Aws, CfnOutput, CustomResource, Duration, Tags
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda
from aws_cdk import aws_opensearchserverless as opensearchserverless

from helpers import security_groups as security_groups_helper

logger = logging.getLogger("soca_logger")

# Resources this helper reads from soca_resources. Listed here so the ordering
# check in create_collection() can produce a clear error if called too early.
_REQUIRED_RESOURCES = (
    "vpc",
    "controller_sg",
    "compute_node_sg",
    "vdi_node_sg",
    "login_node_sg",
    "target_node_sg",
    "controller_role",
    "compute_node_role",
    "vdi_node_role",
    "login_node_role",
)


def _find_existing_aoss_data_vpce(user_specified_variables: Any) -> Optional[str]:
    """
    Return the id of an existing private-DNS aoss-data interface VPC endpoint in
    the target (existing) VPC, or None.

    AWS permits only ONE private-DNS endpoint per service per VPC, and the
    aoss-data private DNS (*.aoss.<region>.on.aws) is region-wide -- a single
    endpoint serves every collection in the region. So multiple SOCA clusters
    sharing a VPC must reference one shared endpoint rather than each creating
    its own (the 2nd+ create fails with "conflicting DNS domain"). Best-effort
    synth-time lookup; on any error returns None and the caller creates one.
    """
    try:
        _region = user_specified_variables.region
        _ec2 = boto3.client("ec2", region_name=_region)
        _resp = _ec2.describe_vpc_endpoints(
            Filters=[
                {"Name": "vpc-id", "Values": [user_specified_variables.vpc_id]},
                {
                    "Name": "service-name",
                    "Values": [f"com.amazonaws.{_region}.aoss-data"],
                },
            ]
        )
        for _ep in _resp.get("VpcEndpoints", []):
            if _ep.get("PrivateDnsEnabled") and _ep.get("State") in (
                "available",
                "pending",
                "pendingAcceptance",
            ):
                return _ep["VpcEndpointId"]
    except Exception as _err:  # noqa: BLE001 - best effort, fall back to create
        logger.warning(
            f"Could not look up existing aoss-data VPC endpoint "
            f"(will create one): {_err}"
        )
    return None


def _create_vpce(
    scope,
    soca_resources: Dict[str, Any],
    user_specified_variables: Any,
    scale_to_zero: bool,
) -> None:
    """
    Deploy a VPC endpoint (and its security group) for the AOSS data plane.

    The endpoint type depends on the collection generation:

    * NextGen (scale_to_zero=True) collections expose ``.on.aws`` endpoints and
      require a STANDARD EC2 interface VPC endpoint on the
      ``com.amazonaws.<region>.aoss-data`` service with private DNS enabled. The
      AOSS-managed ``AWS::OpenSearchServerless::VpcEndpoint`` does NOT serve
      ``.on.aws`` hostnames, so in-VPC clients would resolve them to public IPs
      and hit 403 under a private (AllowFromPublic=false) network policy.
    * Classic (scale_to_zero=False) collections expose ``aoss.amazonaws.com``
      endpoints and use the OpenSearch Serverless-managed VPC endpoint, which
      provisions the ``*.<region>.aoss.amazonaws.com`` private hosted zone.

    Either way the resulting ``vpce-`` id is stored in
    ``soca_resources['os_vpce_id']`` and registered in the collection's network
    policy SourceVPCEs, so the network boundary stays private.
    """

    # Reuse path (NextGen + existing VPC): only ONE private-DNS endpoint per
    # service per VPC is allowed, and the aoss-data private DNS is region-wide
    # (serves every collection). If the existing VPC already has a private-DNS
    # aoss-data endpoint (e.g. another SOCA cluster sharing the VPC created it),
    # reference it instead of creating a second one (which CFN rejects with
    # "conflicting DNS domain"). The per-cluster network/data policies are
    # name-based, so sharing the endpoint is correct.
    if scale_to_zero and user_specified_variables.vpc_id:
        _existing_vpce_id = _find_existing_aoss_data_vpce(user_specified_variables)
        if _existing_vpce_id:
            logger.info(
                f"Reusing existing private-DNS aoss-data VPC endpoint "
                f"{_existing_vpce_id} in VPC {user_specified_variables.vpc_id}"
            )
            soca_resources["os_vpce"] = None
            soca_resources["os_vpce_id"] = _existing_vpce_id
            return

    # Create a Security Group for the VPC Endpoint
    soca_resources["os_vpce_sg"] = security_groups_helper.create_security_groups(
        scope=scope,
        construct_id="AOSSVPCEndpointSG",
        vpc=soca_resources["vpc"],
        allow_all_outbound=True,
        allow_all_ipv6_outbound=scope.is_networking_af_enabled(address_family="ipv6"),
        description="Security Group for AOSS Serverless VPC Endpoint",
    )

    Tags.of(soca_resources["os_vpce_sg"]).add(
        key="Name", value=f"{user_specified_variables.cluster_id}-AOSSSG"
    )

    for _peer_sg in [
        "compute_node_sg",
        "vdi_node_sg",
        "controller_sg",
        "login_node_sg",
        "target_node_sg",
    ]:
        security_groups_helper.create_ingress_rule(
            security_group=soca_resources["os_vpce_sg"],
            peer=soca_resources[_peer_sg],
            connection=ec2.Port.tcp(443),
            description=f"Allow {_peer_sg}",
        )

    soca_resources["os_vpce_sg"].node.add_dependency(
        soca_resources["controller_sg"],
        soca_resources["compute_node_sg"],
        soca_resources["vdi_node_sg"],
        soca_resources["login_node_sg"],
        soca_resources["target_node_sg"],
    )

    # Existing VPCs imported via Vpc.from_lookup() do not reliably populate
    # private_subnets, so use the operator-supplied subnet list
    # ("subnet-id,az" entries). For SOCA-created VPCs use the construct's
    # private subnets directly.
    if user_specified_variables.vpc_id:
        _vpce_subnet_entries = [
            _s.split(",") for _s in user_specified_variables.private_subnets
        ]
        _vpce_subnet_ids = [_e[0] for _e in _vpce_subnet_entries]
        # The standard interface endpoint (NextGen) needs ISubnet objects with
        # an AZ. Operator subnets are "subnet-id,az", so the AZ is available.
        # Interface VPC endpoints do not use subnet route tables, so the
        # operator-supplied list carries no route_table_id. from_subnet_attributes
        # then emits a benign "@aws-cdk/aws-ec2:noSubnetRouteTableId" warning that
        # is FATAL under `cdk synth --strict` (which install_soca.py uses).
        # Acknowledge it per-subnet -- the endpoint genuinely needs no route table.
        _vpce_subnets = []
        for _i, _e in enumerate(_vpce_subnet_entries):
            if len(_e) <= 1:
                continue
            _sn = ec2.Subnet.from_subnet_attributes(
                scope,
                f"AOSSVPCESubnet{_i}",
                subnet_id=_e[0],
                availability_zone=_e[1],
            )
            Annotations.of(_sn).acknowledge_warning(
                "@aws-cdk/aws-ec2:noSubnetRouteTableId",
                "AOSS interface VPC endpoint does not use subnet route tables",
            )
            _vpce_subnets.append(_sn)
    else:
        _vpce_subnet_ids = [
            _s.subnet_id for _s in soca_resources["vpc"].private_subnets
        ]
        _vpce_subnets = list(soca_resources["vpc"].private_subnets)

    if scale_to_zero:
        # NextGen: standard aoss-data interface endpoint + private DNS so the
        # *.aoss.<region>.on.aws hostnames resolve to the endpoint ENIs.
        soca_resources["os_vpce"] = ec2.InterfaceVpcEndpoint(
            scope,
            "AOSSVPCEndpoint",
            vpc=soca_resources["vpc"],
            service=ec2.InterfaceVpcEndpointAwsService("aoss-data"),
            subnets=ec2.SubnetSelection(subnets=_vpce_subnets),
            security_groups=[soca_resources["os_vpce_sg"]],
            private_dns_enabled=True,
            # We attach our own least-privilege SG (443 from node SGs only);
            # do not let CDK open the whole VPC CIDR to the endpoint.
            open=False,
        )
        soca_resources["os_vpce_id"] = soca_resources["os_vpce"].vpc_endpoint_id
    else:
        # Classic: OpenSearch Serverless-managed VPC endpoint for the
        # *.<region>.aoss.amazonaws.com hostnames.
        soca_resources["os_vpce"] = opensearchserverless.CfnVpcEndpoint(
            scope,
            "AOSSVPCEndpoint",
            name=f"{user_specified_variables.cluster_id.lower()}-analytics",
            subnet_ids=_vpce_subnet_ids,
            vpc_id=soca_resources["vpc"].vpc_id,
            security_group_ids=[soca_resources["os_vpce_sg"].security_group_id],
        )
        soca_resources["os_vpce_id"] = soca_resources["os_vpce"].attr_id

    # Wait for deps
    soca_resources["os_vpce"].node.add_dependency(soca_resources["vpc"])
    soca_resources["os_vpce"].node.add_dependency(soca_resources["os_vpce_sg"])
    soca_resources["os_vpce"].node.add_dependency(
        soca_resources["controller_sg"],
        soca_resources["compute_node_sg"],
        soca_resources["vdi_node_sg"],
        soca_resources["login_node_sg"],
        soca_resources["target_node_sg"],
    )


def create_collection(
    scope,
    soca_resources: Dict[str, Any],
    user_specified_variables: Any,
    get_config_key: Callable,
    get_lambda_runtime_version: Callable = None,
) -> None:
    """
    Create an OpenSearch Serverless collection for analytics, with its
    encryption / network / data-access policies and VPC endpoint.
    """

    _missing = [_r for _r in _REQUIRED_RESOURCES if not soca_resources.get(_r)]
    if _missing:
        raise RuntimeError(
            f"aoss_helper.create_collection called out of order; "
            f"missing soca_resources: {_missing}"
        )

    # Scale-to-zero (NextGen) selects both the collection-creation path and the
    # VPC-endpoint type, so read it before creating the endpoint.
    _scale_to_zero: bool = get_config_key(
        key_name="Config.analytics.aoss.scale_to_zero",
        expected_type=bool,
        required=False,
        default=False,
    )
    # Create the AOSS VPC endpoint. _create_vpce() handles both SOCA-created and
    # existing (operator-supplied) VPCs, and selects the NextGen (standard
    # aoss-data interface endpoint) vs Classic (AOSS-managed) endpoint type.
    logger.debug(f"Creating VPC-Endpoint for AOSS Serverless ({_scale_to_zero=})")
    _create_vpce(scope, soca_resources, user_specified_variables, _scale_to_zero)

    # Create a serverless collection
    # TODO - this may need more sanitizing based on the AOSS rules
    sanitized_domain: str = user_specified_variables.cluster_id.lower()

    _standby_replicas: str = get_config_key(
        key_name="Config.analytics.aoss.standby_replicas",
        expected_type=str,
        required=False,
        default="DISABLED",
    ).upper()

    _serverless_public_access: bool = get_config_key(
        key_name="Config.analytics.aoss.public_access",
        expected_type=bool,
        required=False,
        default=False,
    )

    _max_indexing_ocu: int = get_config_key(
        key_name="Config.analytics.aoss.max_indexing_ocu",
        expected_type=int,
        required=False,
        default=2,
    )
    _max_search_ocu: int = get_config_key(
        key_name="Config.analytics.aoss.max_search_ocu",
        expected_type=int,
        required=False,
        default=2,
    )

    if _standby_replicas not in {"ENABLED", "DISABLED"}:
        logger.warning(
            f"Config.analytics.aoss.standby_replicas must be either ENABLED or "
            f"DISABLED. Detected {_standby_replicas}. Falling back to DISABLED..."
        )
        _standby_replicas = "DISABLED"

    if _serverless_public_access not in {True, False}:
        logger.warning(
            f"Config.analytics.aoss.public_access must be True/False. Detected "
            f"{_serverless_public_access}. Reverting to False"
        )
        _serverless_public_access = False

    logger.debug(
        f"AOSS Serverless - {_standby_replicas=} / {_serverless_public_access=} "
        f"/ {_scale_to_zero=} / {_max_indexing_ocu=} / {_max_search_ocu=}"
    )

    # First we create the encryption policy
    soca_resources["os_encryption_policy"] = opensearchserverless.CfnSecurityPolicy(
        scope,
        "AOSSEncryptionPolicy",
        type="encryption",
        name=f"{sanitized_domain}-encryption-policy",
        description=f"{sanitized_domain} encryption policy",
        policy=json.dumps(
            {
                "Rules": [
                    {
                        "Resource": [f"collection/{sanitized_domain}-analytics"],
                        "ResourceType": "collection",
                    }
                ],
                "AWSOwnedKey": True,
            }
        ),
    )
    logger.debug(
        f"Created AOSS encryption policy: {soca_resources['os_encryption_policy']}"
    )

    # Second, our Network Access policy
    soca_resources["os_network_policy"] = opensearchserverless.CfnSecurityPolicy(
        scope,
        "AOSSNetworkPolicy",
        type="network",
        name=f"{sanitized_domain}-network-policy",
        description=f"{sanitized_domain} network policy",
        policy=json.dumps(
            [
                {
                    "Rules": [
                        {
                            "Resource": [f"collection/{sanitized_domain}-analytics"],
                            "ResourceType": "collection",
                        },
                        {
                            "Resource": [f"collection/{sanitized_domain}-analytics"],
                            "ResourceType": "dashboard",
                        },
                    ],
                    "AllowFromPublic": _serverless_public_access,
                    "SourceVPCEs": [soca_resources["os_vpce_id"]],
                }
            ]
        ),
    )

    # Third - the Data access policy. AOSS data-access policies reference the
    # collection by NAME, so the collection need not exist yet; we create the
    # policy before the collection so both the Classic and NextGen paths share
    # it. Instance role ARNs are known at synth time (iam_roles() runs first).
    _data_access_principals = list(
        dict.fromkeys(
            [
                soca_resources["controller_role"].role_arn,
                soca_resources["compute_node_role"].role_arn,
                soca_resources["vdi_node_role"].role_arn,
                soca_resources["login_node_role"].role_arn,
            ]
        )
    )
    soca_resources["os_access_policy"] = opensearchserverless.CfnAccessPolicy(
        scope,
        "AOSSDataAccessPolicy",
        name=f"{sanitized_domain}-data-policy",
        type="data",
        policy=scope.to_json_string(
            [
                {
                    "Description": f"{sanitized_domain} data policy",
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [f"collection/{sanitized_domain}-analytics"],
                            "Permission": [
                                "aoss:CreateCollectionItems",
                                "aoss:DeleteCollectionItems",
                                "aoss:DescribeCollectionItems",
                                "aoss:UpdateCollectionItems",
                            ],
                        },
                        {
                            "ResourceType": "index",
                            "Resource": [f"index/{sanitized_domain}-analytics/*"],
                            "Permission": [
                                "aoss:CreateIndex",
                                "aoss:DeleteIndex",
                                "aoss:DescribeIndex",
                                "aoss:UpdateIndex",
                                "aoss:ReadDocument",
                                "aoss:WriteDocument",
                            ],
                        },
                    ],
                    "Principal": _data_access_principals,
                }
            ]
        ),
    )

    # Fourth - the collection. Everything it needs must exist first.
    # os_vpce is None when we reused a pre-existing shared aoss-data endpoint
    # (no construct to depend on in that case).
    _collection_deps = [
        _d
        for _d in (
            soca_resources["os_encryption_policy"],
            soca_resources["os_network_policy"],
            soca_resources["os_access_policy"],
            soca_resources.get("os_vpce"),
        )
        if _d is not None
    ]
    if _scale_to_zero:
        # NextGen scale-to-zero (min OCU = 0) is NOT creatable via CloudFormation
        # (CfnCollectionGroup has no `generation` field and rejects min OCU = 0),
        # so a custom-resource Lambda drives the boto3 control-plane calls
        # (create_collection_group generation=NEXTGEN min OCU=0 + create_collection).
        _create_collection_via_lambda(
            scope,
            soca_resources,
            user_specified_variables,
            get_lambda_runtime_version=get_lambda_runtime_version,
            sanitized_domain=sanitized_domain,
            max_indexing_ocu=_max_indexing_ocu,
            max_search_ocu=_max_search_ocu,
            standby_replicas=_standby_replicas,
            depends_on=_collection_deps,
        )
    else:
        # Classic standalone collection (always-on, ~2-OCU floor).
        soca_resources["os_domain"] = opensearchserverless.CfnCollection(
            scope,
            "AOSSCollection",
            name=f"{sanitized_domain}-analytics",
            description=f"{sanitized_domain} analytics collection",
            type="SEARCH",
            standby_replicas=_standby_replicas,
            # FIXME TODO - Tags
        )
        for _dep in (
            soca_resources["os_encryption_policy"],
            soca_resources["os_network_policy"],
            soca_resources["os_vpce"],
        ):
            soca_resources["os_domain"].node.add_dependency(_dep)
        soca_resources["os_collection_arn"] = soca_resources["os_domain"].attr_arn

    # AOSS data-plane access requires TWO grants: the fine-grained data-access
    # policy above AND an identity-based IAM grant of aoss:APIAccessAll on the
    # collection. Without APIAccessAll the node roles get 403 Forbidden on
    # WriteDocument/ReadDocument even though SigV4 init and the data-access
    # principal are correct. Scope to this collection's ARN (BSC6 least-privilege).
    _collection_arn = soca_resources["os_collection_arn"]
    for _role_key in ("controller_role", "compute_node_role", "vdi_node_role", "login_node_role"):
        soca_resources[_role_key].add_to_policy(
            iam.PolicyStatement(
                actions=["aoss:APIAccessAll"],
                resources=[_collection_arn],
            )
        )


def add_dashboard_output(scope, soca_resources: Dict[str, Any]) -> None:
    """
    Emit the AOSS dashboard endpoint as a CloudFormation output. Called from
    the viewer() flow once the collection (os_domain) has been created.
    """
    # NextGen (custom-resource) path: os_domain is a CustomResource with no
    # attr_dashboard_endpoint, and NextGen does not expose a per-collection
    # dashboard endpoint. Skip the output in that case.
    if soca_resources.get("os_collection_endpoint") is not None:
        logger.debug("NextGen AOSS collection: skipping dashboard CfnOutput")
        return
    logger.debug("Adding AOSS dashboard CfnOutput")
    CfnOutput(
        scope,
        "AnalyticsDashboard",
        value=f"https://{soca_resources['os_domain'].attr_dashboard_endpoint}",
    )


def _create_collection_via_lambda(
    scope,
    soca_resources: Dict[str, Any],
    user_specified_variables: Any,
    *,
    get_lambda_runtime_version: Callable = None,
    sanitized_domain: str,
    max_indexing_ocu: int,
    max_search_ocu: int,
    standby_replicas: str,
    depends_on: list,
) -> None:
    """
    Create the AOSS NextGen collection group + collection via a custom-resource
    Lambda (boto3 generation=NEXTGEN, min OCU = 0). CloudFormation's
    CfnCollectionGroup cannot select NextGen (no `generation` field, rejects
    min OCU = 0), so this Lambda is the working path until aws-cdk-lib adds
    support. Sets soca_resources['os_domain'] to the custom resource and
    soca_resources['os_collection_endpoint'] to its (full https) endpoint output.
    Requires the boto3 >=1.43.22 Lambda layer for the `generation` parameter.
    """
    _fn = aws_lambda.Function(
        scope,
        "AOSSCollectionLambda",
        function_name=f"{user_specified_variables.cluster_id}-AOSSCollection",
        description=f"Create NextGen AOSS collection for {user_specified_variables.cluster_id}",
        runtime=get_lambda_runtime_version(),
        handler="AOSSCollectionLambda.lambda_handler",
        code=aws_lambda.Code.from_asset("../functions/AOSSCollectionLambda"),
        timeout=Duration.minutes(14),
        memory_size=128,
        log_group=scope.generate_log_group(name="AOSSCollection"),
        # boto3 1.43.x layer provides create_collection_group(generation=...)
        layers=[_l for _l in [soca_resources.get("boto3_layer")] if _l],
    )
    # BSC6 least-privilege: specific AOSS control-plane actions only (no wildcard
    # actions, no admin). These control-plane actions are account-level and do
    # not support resource-level scoping, so resource is "*".
    _fn.add_to_role_policy(
        iam.PolicyStatement(
            actions=[
                "aoss:CreateCollection",
                "aoss:CreateCollectionGroup",
                "aoss:BatchGetCollection",
                "aoss:BatchGetCollectionGroup",
                "aoss:ListCollections",
                "aoss:ListCollectionGroups",
                "aoss:DeleteCollection",
                "aoss:DeleteCollectionGroup",
                "aoss:UpdateCollectionGroup",
                # NextGen: adding/removing a collection to/from a group is a
                # distinct action from CreateCollection (required when
                # collectionGroupName is set).
                "aoss:AddCollectionToCollectionGroup",
                "aoss:RemoveCollectionFromCollectionGroup",
            ],
            resources=["*"],
        )
    )

    _fn.add_to_role_policy(
        iam.PolicyStatement(
            actions=["iam:CreateServiceLinkedRole"],
            resources=[f"arn:{Aws.PARTITION}:iam::*:role/aws-service-role/observability.aoss.amazonaws.com/AWSServiceRoleForAmazonOpenSearchServerless"],
            conditions={
                "StringEquals": {
                    "iam:AWSServiceName": "observability.aoss.amazonaws.com"
                }
            },
        )
    )

    soca_resources["aoss_collection_lambda"] = _fn

    _cr = CustomResource(
        scope,
        "AOSSCollectionResource",
        service_token=_fn.function_arn,
        properties={
            "ClusterId": user_specified_variables.cluster_id,
            "CollectionName": f"{sanitized_domain}-analytics",
            "CollectionGroupName": f"{sanitized_domain}-cg",
            "CollectionType": "SEARCH",
            "StandbyReplicas": standby_replicas,
            "MaxIndexingOcu": max_indexing_ocu,
            "MaxSearchOcu": max_search_ocu,
        },
    )
    for _dep in depends_on:
        _cr.node.add_dependency(_dep)

    # The custom resource stands in for the analytics "domain" so the existing
    # `.node.add_dependency(os_domain)` wiring downstream keeps working. The
    # Lambda returns the full https endpoint as the CollectionEndpoint attribute.
    soca_resources["os_domain"] = _cr
    soca_resources["os_collection_endpoint"] = _cr.get_att_string("CollectionEndpoint")
    soca_resources["os_collection_arn"] = _cr.get_att_string("CollectionArn")
