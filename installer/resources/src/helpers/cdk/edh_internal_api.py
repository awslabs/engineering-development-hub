# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
EDH internal HTTP API -- a single shared, IAM-authorized API Gateway v2 HTTP API
that fronts in-VPC backend Lambdas for boot-time / control-plane callers which
authenticate with SigV4 using their instance or service role. Callers reach it
with `curl --aws-sigv4 aws:amz:<region>:execute-api`.

Why shared: the "SigV4-attested caller -> private Lambda over HTTPS" pattern is
reusable (the USB allowlist resolver is the first consumer). New features add a
route via add_iam_lambda_route() rather than each minting its own endpoint --
one API, one auth model, one place to grant execute-api:Invoke.

Why an HTTP API route (not a Lambda Function URL): Function URLs are not a
supported resource type in every partition (GovCloud/China). An IAM-auth HTTP
API route is partition-portable and preserves the exact attested-caller model:
under payload format 2.0 the SigV4 caller ARN arrives at
requestContext.authorizer.iam.userArn -- the same field the Function URL used --
so backend handlers need no change.

L1 Cfn* constructs are used because aws-cdk-lib 2.251.0 ships the HTTP API L2
constructs only in the alpha packages (not a dependency of this installer).
"""

import json
import logging

from aws_cdk import Aws
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs

logger = logging.getLogger("soca_logger")

# Cache key on scope.soca_resources so the API is created exactly once.
_INTERNAL_API_KEY = "edh_internal_api"

# Per-cluster tunables (Config.feature_flags.InternalApi.*). Defaults apply when
# the key is absent or get_config_key isn't injected, so the shared factory
# still works for any caller.
_DEFAULT_LOG_RETENTION_DAYS = 90
_DEFAULT_THROTTLE_RATE = 50
_DEFAULT_THROTTLE_BURST = 25
_DEFAULT_DETAILED_METRICS = True

# CloudWatch Logs only accepts a fixed set of retention day-counts. Map each to
# its RetentionDays member so an operator-supplied AccessLogRetentionDays can be
# snapped to the nearest allowed value -- RetentionDays.value is the member name
# (a str), not an int, so an explicit table is required.
_RETENTION_DAYS_TO_ENUM = {
    1: logs.RetentionDays.ONE_DAY,
    3: logs.RetentionDays.THREE_DAYS,
    5: logs.RetentionDays.FIVE_DAYS,
    7: logs.RetentionDays.ONE_WEEK,
    14: logs.RetentionDays.TWO_WEEKS,
    30: logs.RetentionDays.ONE_MONTH,
    60: logs.RetentionDays.TWO_MONTHS,
    90: logs.RetentionDays.THREE_MONTHS,
    120: logs.RetentionDays.FOUR_MONTHS,
    150: logs.RetentionDays.FIVE_MONTHS,
    180: logs.RetentionDays.SIX_MONTHS,
    365: logs.RetentionDays.ONE_YEAR,
    400: logs.RetentionDays.THIRTEEN_MONTHS,
    545: logs.RetentionDays.EIGHTEEN_MONTHS,
    731: logs.RetentionDays.TWO_YEARS,
    1096: logs.RetentionDays.THREE_YEARS,
    1827: logs.RetentionDays.FIVE_YEARS,
    2192: logs.RetentionDays.SIX_YEARS,
    2557: logs.RetentionDays.SEVEN_YEARS,
    2922: logs.RetentionDays.EIGHT_YEARS,
    3288: logs.RetentionDays.NINE_YEARS,
    3653: logs.RetentionDays.TEN_YEARS,
}


def _snap_retention_days(days: int):
    """Snap a requested day-count DOWN to the nearest CloudWatch-allowed value."""
    _allowed = sorted(_RETENTION_DAYS_TO_ENUM)
    _pick = _allowed[0]
    for _d in _allowed:
        if _d <= days:
            _pick = _d
        else:
            break
    return _RETENTION_DAYS_TO_ENUM[_pick]


def _api_int_setting(get_config_key, suffix, default, minimum, maximum) -> int:
    """Read Config.feature_flags.InternalApi.<suffix> as a bounded int; fall back
    to default on absence, wrong type, or out-of-range (mirrors the ODCR settle
    guard so a fat-fingered value can never wedge the stage)."""
    if get_config_key is None:
        return default
    _val = get_config_key(
        key_name=f"Config.feature_flags.InternalApi.{suffix}",
        expected_type=int,
        required=False,
        default=default,
    )
    if isinstance(_val, bool) or not isinstance(_val, int):
        return default
    if _val < minimum or _val > maximum:
        return default
    return _val


def get_or_create_internal_api(scope, cluster_id: str, *, get_config_key=None):
    """Return the shared EDH internal HTTP API (CfnApi), creating it (plus its
    auto-deploy $default stage) once per stack. Subsequent callers reuse it.

    Per-cluster tunables via Config.feature_flags.InternalApi.*:
    AccessLogRetentionDays (default 90), ThrottleRateLimit (50),
    ThrottleBurstLimit (25), DetailedMetricsEnabled (True). IPv6 dualstack is
    gated on Networking.EnableIPv6 (scope.is_networking_af_enabled), consistent
    with the cluster ELBs, VPC endpoints, and DCV target groups. Pass
    get_config_key (dependency-injected from cdk_construct) to honor overrides;
    without it the defaults apply."""
    existing = scope.soca_resources.get(_INTERNAL_API_KEY)
    if existing is not None:
        return existing

    # Dualstack endpoint when the cluster has IPv6 enabled -- same flag every
    # other AF-aware resource keys off, so the internal API isn't the odd one out.
    _ipv6_enabled = scope.is_networking_af_enabled(address_family="ipv6")

    _retention_days = _api_int_setting(
        get_config_key, "AccessLogRetentionDays", _DEFAULT_LOG_RETENTION_DAYS, 1, 3653
    )
    _throttle_rate = _api_int_setting(
        get_config_key, "ThrottleRateLimit", _DEFAULT_THROTTLE_RATE, 1, 10000
    )
    _throttle_burst = _api_int_setting(
        get_config_key, "ThrottleBurstLimit", _DEFAULT_THROTTLE_BURST, 1, 5000
    )
    _detailed_metrics = _DEFAULT_DETAILED_METRICS
    if get_config_key is not None:
        _dm = get_config_key(
            key_name="Config.feature_flags.InternalApi.DetailedMetricsEnabled",
            expected_type=bool,
            required=False,
            default=_DEFAULT_DETAILED_METRICS,
        )
        _detailed_metrics = _dm if isinstance(_dm, bool) else _DEFAULT_DETAILED_METRICS

    api = apigwv2.CfnApi(
        scope,
        f"{cluster_id}-InternalApi",
        name=f"{cluster_id}-internal",
        protocol_type="HTTP",
        ip_address_type="dualstack" if _ipv6_enabled else "ipv4",
        description=(
            "EDH internal IAM-auth HTTP API fronting in-VPC backend Lambdas "
            "for SigV4 (instance/service role) callers."
        ),
    )

    # Dedicated, retained access-log group. The /aws/vendedlogs/ prefix lets
    # API Gateway auto-provision the CloudWatch Logs delivery permission (no
    # account-level CloudWatch role -- that's REST/v1 only -- and no manual
    # resource policy). Retention is bounded so the audit trail doesn't grow
    # unbounded. Tagging (edh:ClusterId / edh:Version / custom_tags) is applied
    # to every taggable resource by the app-level Tags.of(app) aspect in
    # cdk_construct -- no per-construct tagging needed here.
    access_log_group = logs.LogGroup(
        scope,
        f"{cluster_id}-InternalApiAccessLogs",
        log_group_name=f"/aws/vendedlogs/{cluster_id}/apigw/internal",
        retention=_snap_retention_days(_retention_days),
    )

    # JSON access log. Capture the SigV4 caller identity ($context.identity.*)
    # so every boot-time invocation is auditable to the exact instance/service
    # role -- the audit control for the attested-caller model -- plus request
    # outcome and integration error for troubleshooting.
    _access_log_format = json.dumps(
        {
            "requestId": "$context.requestId",
            "ip": "$context.identity.sourceIp",
            "requestTime": "$context.requestTime",
            "httpMethod": "$context.httpMethod",
            "routeKey": "$context.routeKey",
            "status": "$context.status",
            "protocol": "$context.protocol",
            "responseLatency": "$context.responseLatency",
            "responseLength": "$context.responseLength",
            "callerArn": "$context.identity.userArn",
            "callerAccount": "$context.identity.accountId",
            "integrationStatus": "$context.integration.status",
            "integrationError": "$context.integrationErrorMessage",
        }
    )

    # $default stage with auto-deploy: added routes go live without an explicit
    # deployment, and the invoke URL has no stage path segment.
    apigwv2.CfnStage(
        scope,
        f"{cluster_id}-InternalApiStage",
        api_id=api.ref,
        stage_name="$default",
        auto_deploy=True,
        access_log_settings=apigwv2.CfnStage.AccessLogSettingsProperty(
            destination_arn=access_log_group.log_group_arn,
            format=_access_log_format,
        ),
        # Per-route CloudWatch metrics (4xx/5xx/latency/count) for alarming, and
        # a throttle cap -- these are low-volume boot-time callers, so a tight
        # ceiling protects the backend Lambda from a runaway loop without ever
        # touching legitimate traffic. All three are config-tunable per cluster.
        default_route_settings=apigwv2.CfnStage.RouteSettingsProperty(
            detailed_metrics_enabled=_detailed_metrics,
            throttling_burst_limit=_throttle_burst,
            throttling_rate_limit=_throttle_rate,
        ),
    )
    scope.soca_resources[_INTERNAL_API_KEY] = api
    logger.debug(f"Created shared EDH internal HTTP API '{cluster_id}-internal'")
    return api


def add_iam_lambda_route(
    scope,
    cluster_id: str,
    api,
    route_key: str,
    handler,
    invoker_roles,
    construct_prefix: str,
):
    """Attach an AWS_IAM-authorized route backed by an AWS_PROXY Lambda
    integration to the shared internal API.

    - route_key: HTTP API route key. Use a versioned, category-scoped path so
      routes stay organized as consumers are added, e.g.
      "ANY /v1/dcv/usb-allowlist" (version "/v1", category "/dcv", then the name)
      -- never a bare root path like "/usb-allowlist".
    - handler: the backend aws_lambda.Function.
    - invoker_roles: iterable of iam.IRole granted execute-api:Invoke on the route.
    - construct_prefix: unique id prefix for this route's constructs.

    Returns the route path (leading "/...") so the caller can build the full
    invoke URL as f"{api.attr_api_endpoint}{route_path}".
    """
    integration = apigwv2.CfnIntegration(
        scope,
        f"{cluster_id}-{construct_prefix}Integration",
        api_id=api.ref,
        integration_type="AWS_PROXY",
        integration_uri=handler.function_arn,
        integration_method="POST",  # AWS_PROXY always invokes Lambda via POST
        payload_format_version="2.0",
    )

    apigwv2.CfnRoute(
        scope,
        f"{cluster_id}-{construct_prefix}Route",
        api_id=api.ref,
        route_key=route_key,
        authorization_type="AWS_IAM",
        target=f"integrations/{integration.ref}",
    )

    # "ANY /v1/dcv/usb-allowlist" -> "/v1/dcv/usb-allowlist"
    route_path = route_key.split(" ", 1)[1] if " " in route_key else route_key

    # execute-api ARN for this route across all stages/methods:
    #   arn:<partition>:execute-api:<region>:<account>:<api-id>/<stage>/<method>/<path>
    route_execute_arn = (
        f"arn:{Aws.PARTITION}:execute-api:{Aws.REGION}:{Aws.ACCOUNT_ID}:"
        f"{api.ref}/*/*{route_path}"
    )

    # Allow API Gateway to invoke the backend Lambda for this route.
    handler.add_permission(
        f"{construct_prefix}ApiInvoke",
        principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
        action="lambda:InvokeFunction",
        source_arn=route_execute_arn,
    )

    # Grant SigV4 callers execute-api:Invoke on the route.
    for _role in invoker_roles:
        _role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["execute-api:Invoke"],
                resources=[route_execute_arn],
            )
        )

    logger.debug(
        f"Added IAM route '{route_key}' -> {handler.function_arn} on "
        f"'{cluster_id}-internal'"
    )
    return route_path
