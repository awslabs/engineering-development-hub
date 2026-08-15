######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                                #
######################################################################################################################
"""
CDK helper for the in-browser SSH terminal (webshell) feature.

Adds an ALB target group + listener rule forwarding /web_terminal/endpoint* to the
edh-webshell service running on Login Nodes, plus a security-group ingress
rule allowing the WebUI ALB to reach that service.

Usage from cdk_construct.py:

    from helpers import webshell as webshell_helper
    ...
    webshell_helper.setup_webshell(
        scope=self,
        soca_resources=self.soca_resources,
        user_specified_variables=user_specified_variables,
        get_config_key=get_config_key,
    )

Ordering: this must be called AFTER both login_nodes() (which creates
login_node_asg and login_node_sg) and viewer() (which creates https_listener
and alb). The helper validates this and raises RuntimeError with the name
of the missing resource if called out of order.
"""

import logging
from typing import Any, Callable, Dict

from aws_cdk import Aws, Duration
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_ssm as ssm
from constructs import Construct

from helpers import security_groups as security_groups_helper

logger = logging.getLogger("soca_logger")

# Resources this helper reads from soca_resources. Listed here so the
# ordering check below can produce a clear error message if any is missing.
_REQUIRED_RESOURCES = (
    "vpc",
    "alb",
    "login_node_asg",
    "login_node_sg",
    "https_listener",
    # controller_role is required for the SSM Run Command grant. The control
    # plane (list/kill tmux sessions) is invoked by the controller via
    # ssm:SendCommand against pre-registered documents created below; the
    # controller's IAM role needs ssm:SendCommand and ssm:GetCommandInvocation.
    "controller_role",
)


# ---------------------------------------------------------------------------
# SSM Run Command documents for the webshell control plane
#
# The login node sidecar does NOT serve the list/kill endpoints over HTTP.
# Doing so would require a shared secret reachable by every shell user on
# the multi-tenant login node. Instead, the controller (admin-trusted)
# invokes these SSM documents via ssm:SendCommand. AWS-SSM-agent on each
# login node executes the document body as root (isolated from user
# processes -- no shell user has ssm:SendCommand permission so they cannot
# impersonate the controller).
#
# Both documents take a `User` parameter that the controller derives from
# the authenticated Flask session, never from request input. The `Label`
# parameter for the kill document is regex-validated both by the document
# and by the controller as defence-in-depth.
# ---------------------------------------------------------------------------

_LIST_SESSIONS_BASH = r"""#!/bin/bash
set -euo pipefail
USER="{{ User }}"
# Defence-in-depth: re-validate the parameter shape inside the document
# body. The CFN-side allowedPattern catches most cases; this catches a
# theoretical case where someone bypassed CFN to register a malformed doc.
if [[ ! "$USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "ERROR: invalid user format" >&2
  exit 1
fi
if ! id -u "$USER" >/dev/null 2>&1; then
  # User has no account on this node yet -- not an error, just no sessions.
  exit 0
fi
# tmux -F emits one line per session with pipe-separated fields. The
# `?session_attached,1,0` ternary normalises the "attached" field to
# "0" or "1" for the controller parser. The grep filter ensures we only
# return webshell-managed sessions (named `edh_<user>_<label>`); tmux
# already runs as the user so it cannot see other users' tmux servers,
# but the prefix filter guards against a user creating a non-webshell
# tmux session that happens to start with `edh_`.
sudo -u "$USER" tmux list-sessions \
    -F '#{session_name}|#{session_created}|#{session_last_attached}|#{?session_attached,1,0}|#{session_windows}' \
    2>/dev/null \
  | grep "^edh_${USER}_" \
  || true
"""

_KILL_SESSION_BASH = r"""#!/bin/bash
set -euo pipefail
USER="{{ User }}"
LABEL="{{ Label }}"
if [[ ! "$USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "ERROR: invalid user format" >&2
  exit 1
fi
if [[ ! "$LABEL" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
  echo "ERROR: invalid label format" >&2
  exit 1
fi
if ! id -u "$USER" >/dev/null 2>&1; then
  # User has no account on this node; nothing to kill. Idempotent success.
  echo "ok"
  exit 0
fi
SESSION="edh_${USER}_${LABEL}"
# tmux kill-session is idempotent -- it errors if the session doesn't
# exist, which we deliberately swallow because the desired end state
# ("session is gone") is achieved either way. This makes broadcast-kill
# from the controller safe: only one of N login nodes will have the
# session, the rest no-op.
sudo -u "$USER" tmux kill-session -t "$SESSION" 2>&1 | grep -v "can't find session" || true
echo "ok"
"""


def _build_list_sessions_document_content() -> Dict[str, Any]:
    """SSM document content for listing a user's webshell sessions.

    Schema 2.2 (Linux shell). The bash body in `runCommand` is the
    document's only step. Output is captured by SSM and returned to the
    caller via GetCommandInvocation.StandardOutputContent.
    """
    return {
        "schemaVersion": "2.2",
        "description": (
            "List a SOCA user's tmux webshell sessions on a login node. "
            "Invoked by the SOCA controller via ssm:SendCommand."
        ),
        "parameters": {
            "User": {
                "type": "String",
                "description": "POSIX username whose webshell sessions to list",
                "allowedPattern": r"^[a-z_][a-z0-9_-]{0,31}$",
                "maxChars": 32,
            },
        },
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "listWebshellSessions",
                "inputs": {
                    "runCommand": [_LIST_SESSIONS_BASH],
                },
            }
        ],
    }


def _build_kill_session_document_content() -> Dict[str, Any]:
    """SSM document content for killing a user's webshell session."""
    return {
        "schemaVersion": "2.2",
        "description": (
            "Kill a SOCA user's tmux webshell session on a login node. "
            "Invoked by the SOCA controller via ssm:SendCommand. Idempotent: "
            "succeeds whether or not the named session existed on this node."
        ),
        "parameters": {
            "User": {
                "type": "String",
                "description": "POSIX username whose webshell session to kill",
                "allowedPattern": r"^[a-z_][a-z0-9_-]{0,31}$",
                "maxChars": 32,
            },
            "Label": {
                "type": "String",
                "description": "Webshell session label (suffix of `edh_<user>_<label>`)",
                "allowedPattern": r"^[a-zA-Z0-9_-]{1,32}$",
                "maxChars": 32,
            },
        },
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "killWebshellSession",
                "inputs": {
                    "runCommand": [_KILL_SESSION_BASH],
                },
            }
        ],
    }


def _wire_control_plane_via_ssm(
    scope: Construct,
    soca_resources: Dict[str, Any],
    cluster_id: str,
) -> None:
    """Register the two webshell SSM documents and grant the controller
    role least-privilege permission to invoke them against this cluster's
    login nodes only.

    Document names are namespaced with the cluster id so multiple SOCA
    deployments in the same account get isolated documents and IAM grants.
    """
    list_doc_name = f"{cluster_id}-WebshellListSessions"
    kill_doc_name = f"{cluster_id}-WebshellKillSession"

    list_doc = ssm.CfnDocument(
        scope,
        f"{cluster_id}-WebshellListSessionsDoc",
        document_type="Command",
        document_format="JSON",
        name=list_doc_name,
        target_type="/AWS::EC2::Instance",
        content=_build_list_sessions_document_content(),
    )
    kill_doc = ssm.CfnDocument(
        scope,
        f"{cluster_id}-WebshellKillSessionDoc",
        document_type="Command",
        document_format="JSON",
        name=kill_doc_name,
        target_type="/AWS::EC2::Instance",
        content=_build_kill_session_document_content(),
    )
    # Track the documents in soca_resources so other helpers / tests can
    # find them without re-deriving the name.
    soca_resources["webshell_list_sessions_document_name"] = list_doc_name
    soca_resources["webshell_kill_session_document_name"] = kill_doc_name

    # Document ARN format:
    #   arn:aws:ssm:<region>:<account>:document/<name>
    list_doc_arn = f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:document/{list_doc_name}"
    kill_doc_arn = f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:document/{kill_doc_name}"

    # Grant ssm:SendCommand on both documents AND on EC2 instance ARNs in
    # this cluster's login-node fleet only. SendCommand requires resource
    # access on BOTH the document and the target instance(s); both are
    # required, so two-resource grants are needed.
    soca_resources["controller_role"].add_to_policy(
        iam.PolicyStatement(
            sid="WebshellSendCommandDocuments",
            actions=["ssm:SendCommand"],
            resources=[list_doc_arn, kill_doc_arn],
        )
    )
    soca_resources["controller_role"].add_to_policy(
        iam.PolicyStatement(
            sid="WebshellSendCommandInstances",
            actions=["ssm:SendCommand"],
            resources=[
                f"arn:{Aws.PARTITION}:ec2:{Aws.REGION}:{Aws.ACCOUNT_ID}:instance/*"
            ],
            conditions={
                "StringEquals": {
                    # Only allow targeting login nodes of THIS cluster --
                    # not other clusters in the same account, not other
                    # node types in this cluster.
                    "aws:ResourceTag/edh:NodeType": "login_node",
                    "aws:ResourceTag/edh:ClusterId": cluster_id,
                }
            },
        )
    )

    # ssm:GetCommandInvocation does not support resource-level policies
    # (per https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssystemsmanager.html);
    # AWS only supports it at "*". This is an AWS limitation, not a
    # least-privilege concession on our part. The grant is still bounded
    # because SendCommand is locked down above -- the controller can only
    # poll invocations of commands it itself issued.
    soca_resources["controller_role"].add_to_policy(
        iam.PolicyStatement(
            sid="WebshellGetCommandInvocation",
            actions=["ssm:GetCommandInvocation"],
            resources=["*"],
        )
    )

    logger.info(
        f"Webshell control plane: SSM documents {list_doc_name} + {kill_doc_name} "
        f"registered; controller role granted SendCommand on documents and on "
        f"login_node instances in cluster {cluster_id}."
    )


def setup_webshell(
    scope: Construct,
    soca_resources: Dict[str, Any],
    user_specified_variables: Any,
    get_config_key: Callable,
) -> None:
    """Wire up the webshell ALB target group, listener rule, and SG ingress.

    Parameters
    ----------
    scope
        The CDK construct scope (typically the Stack).
    soca_resources
        The SOCA resource dictionary. Reads vpc/alb/login_node_asg/
        login_node_sg/https_listener; writes webshell_target_group.
    user_specified_variables
        The global user-specified-variables namespace (used for cluster_id).
    get_config_key
        A reference to the config-lookup function. Accepts at minimum
        `key_name`, `expected_type`, `required`, `default`.

    Returns
    -------
    None. Side effects only: creates CDK resources and populates
    soca_resources["webshell_target_group"] on success.
    """
    # Defensive ordering check: surface a clear error if called before the
    # resources we need are created, rather than a cryptic KeyError.
    #
    # NOTE: this is the CDK installer layer, which does not import
    # `utils.error.SocaError` (that lives in the cluster_manager runtime,
    # not the install-time codebase). install_model.py and cdk_construct.py
    # raise ValueError for the same class of misconfiguration, so we
    # follow that local convention instead.
    missing = [r for r in _REQUIRED_RESOURCES if r not in soca_resources]
    if missing:
        raise ValueError(
            f"setup_webshell called before {missing[0]} exists in soca_resources. "
            "Ensure login_nodes() and viewer() run before webshell setup."
        )

    _webshell_port: int = get_config_key(
        key_name="Config.webshell.port",
        expected_type=int,
        required=False,
        default=7681,
    )
    _webshell_health_port: int = get_config_key(
        key_name="Config.webshell.health_port",
        expected_type=int,
        required=False,
        default=7682,
    )
    cluster_id = user_specified_variables.cluster_id
    logger.debug(
        f"Webshell - adding ALB target group for cluster {cluster_id} "
        f"on port {_webshell_port} (health on {_webshell_health_port})"
    )

    # Target group for the webshell service on each Login Node. Traffic
    # goes to the WebSocket port; health check goes to the separate HTTP
    # health port (the WS port returns 426 to plain HTTP).
    _webshell_target_group = elbv2.ApplicationTargetGroup(
        scope,
        f"{cluster_id}-WebshellTargetGroup",
        port=_webshell_port,
        target_type=elbv2.TargetType.INSTANCE,
        protocol=elbv2.ApplicationProtocol.HTTP,
        vpc=soca_resources["vpc"],
        target_group_name=f"{cluster_id}-Webshell",
        targets=[soca_resources["login_node_asg"]],
        health_check=elbv2.HealthCheck(
            port=str(_webshell_health_port),
            protocol=elbv2.Protocol.HTTP,
            path="/healthz",
            # /healthz returns 200 only if BOTH tmux is runnable AND the
            # controller is reachable, so an unhealthy login node surfaces
            # as an unhealthy target in the ALB console.
            healthy_http_codes="200",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(5),
            healthy_threshold_count=2,
            unhealthy_threshold_count=3,
        ),
        # Long deregistration delay so in-flight terminal sessions have
        # time to finish cleanly during login node rollouts.
        deregistration_delay=Duration.seconds(30),
    )

    # Listener rule at the existing HTTPS listener. Priority 100 is safely
    # below any other WebUI rules (which typically don't specify priority,
    # so CDK picks them after explicit ones).
    #
    # Path pattern is `/web_terminal/endpoint` (exact match, no wildcard). The
    # WebSocket client connects to exactly /web_terminal/endpoint?session=<label>;
    # query strings are not part of ALB path matching so exact-match
    # routes the WS path correctly. We deliberately do NOT use the wildcard
    # form `/web_terminal/endpoint*` because that also matches /web_terminal/terminal_auth,
    # which is a controller-side cookie-priming endpoint that must be
    # served by the WebUI Flask app, not by the login-node sidecar.
    soca_resources["https_listener"].add_action(
        "WebshellRule",
        priority=100,
        conditions=[
            elbv2.ListenerCondition.path_patterns(["/web_terminal/endpoint"]),
        ],
        action=elbv2.ListenerAction.forward(target_groups=[_webshell_target_group]),
    )

    # Allow the ALB SG to reach both the webshell WS port AND the health
    # port on Login Nodes. Without the health port rule, health checks
    # fail with "Request timed out".
    security_groups_helper.create_ingress_rule(
        security_group=soca_resources["login_node_sg"],
        peer=soca_resources["alb"].connections.security_groups[0],
        connection=ec2.Port.tcp(_webshell_port),
        description="Webshell WebSocket traffic from the WebUI ALB",
    )
    security_groups_helper.create_ingress_rule(
        security_group=soca_resources["login_node_sg"],
        peer=soca_resources["alb"].connections.security_groups[0],
        connection=ec2.Port.tcp(_webshell_health_port),
        description="Webshell health-check traffic from the WebUI ALB",
    )

    soca_resources["webshell_target_group"] = _webshell_target_group

    # Wire the controller-side control plane (list/kill tmux sessions) via
    # SSM Run Command. This replaces the earlier design that had the login
    # node sidecar serve those endpoints with a shared HMAC secret -- a
    # design that could not enforce "only the controller can call this"
    # because shell users on the login node would have read access to any
    # secret the sidecar held. SSM Run Command moves the trust boundary to
    # the controller's IAM identity, which regular users cannot impersonate.
    _wire_control_plane_via_ssm(
        scope=scope,
        soca_resources=soca_resources,
        cluster_id=cluster_id,
    )
