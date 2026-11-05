# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
edhctl notifications -- manage the cluster notification SNS topic.

The installer creates one SNS topic per cluster, named
``<cluster_id>-Notification-SNS``, and subscribes whatever was passed to
``--email-address`` at install time. The topic receives the CloudWatch alarm
actions attached by the DCV, SSM ConfigSync and VDI pool helpers.

Why these commands exist. The install-time address is not stored in the cluster
configuration and nothing reads it at runtime: it exists only as
``AWS::SNS::Subscription`` resources in the CloudFormation template. Because EDH
never performs a stack update, there is no CFN-driven way to change who gets
cluster alarms after install, and no config key to set. Until now the only route
was hand-built AWS CLI calls against an ARN the admin had to assemble.

    edhctl notifications list                      who receives cluster alarms
    edhctl notifications subscribe -e a@b.com      add a recipient
    edhctl notifications unsubscribe -e a@b.com    remove a recipient
    edhctl notifications test                      publish a message to the topic

A new email subscription receives nothing until someone opens the confirmation
mail from SNS and clicks the link. `list` reports that state per subscription,
and `test` is how an admin proves delivery actually works rather than assuming
it from a successful subscribe call.
"""

import logging
import sys
from datetime import datetime, timezone

import click
from botocore.exceptions import BotoCoreError, ClientError

from commands.common import (
    confirm,
    get_cluster_id,
    is_controller_instance,
    print_output,
)
from utils.aws import boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

# Suffix the installer appends to the cluster id when naming the topic. Keep in
# step with installer/resources/src/helpers/notifications.py, which sets both
# topic_name and display_name to this.
_TOPIC_NAME_SUFFIX = "-Notification-SNS"

# ListSubscriptionsByTopic reports this literal in place of an ARN for a
# subscription whose endpoint owner has not yet clicked the confirmation link.
# Such a subscription has no ARN at all, so it cannot be passed to Unsubscribe.
_PENDING_ARN = "PendingConfirmation"

# ListSubscriptionsByTopic returns at most 100 per call.
_LIST_PAGE_SIZE = 100

# SNS truncates a Subject past 100 characters and rejects some control
# characters outright. Built subjects are clipped to this.
_MAX_SUBJECT_LEN = 100


def _client_error_detail(err: ClientError | BotoCoreError) -> str:
    """Return a readable detail for a botocore exception.

    Handles both halves of botocore's exception tree. A ClientError carries the
    code and message the service returned, which is what an operator needs. A
    BotoCoreError -- a connection, endpoint or credential failure -- has no
    response at all, and its str() is the readable sentence botocore wrote for
    exactly that purpose.

    Read out of err.response rather than cast from the exception. SocaCastEngine
    would not help here: cast_as(str) on anything that is not already a str runs
    the same str() this replaces, so it is a second cast over the same value
    rather than a validation step. The response fields are guarded instead,
    because a cast cannot tell an absent code from a present one -- both
    str(None) and SocaCastEngine(None).cast_as(str) succeed with the literal
    "None", which would be reported to the operator as a real SNS error code.
    """
    _response = getattr(err, "response", None)
    if not Validators.is_dict(_response):
        return str(err) or "The SNS call failed without naming a cause."
    _error = _response.get("Error", {})
    _code = _error.get("Code", "")
    _message = _error.get("Message", "")
    if not Validators.is_string(_code):
        _code = ""
    if not Validators.is_string(_message):
        _message = ""
    if Validators.is_string_not_empty(_code) and Validators.is_string_not_empty(
        _message
    ):
        return f"{_code}: {_message}"
    return _code or _message or "SNS rejected the call without naming a cause."


def _error_code(err: ClientError | BotoCoreError) -> str:
    """Return the service error code, or "" when the exception carries none.

    A BotoCoreError has no response, so every code comparison in this module
    goes through here rather than reading err.response directly. Returning ""
    rather than raising is what makes a connection failure fall through to the
    generic handler instead of being mistaken for a named SNS condition.
    """
    _response = getattr(err, "response", None)
    if not Validators.is_dict(_response):
        return ""
    _code = _response.get("Error", {}).get("Code", "")
    return _code if Validators.is_string(_code) else ""


def _sns_client(output: str = "text"):
    """Return an SNS client, exiting with a readable message if it cannot be built.

    output is threaded through every helper that can exit so a command invoked
    with --output json emits JSON on its failure paths too. print_output writes
    to stdout, so an unthreaded error path puts prose into the stream a caller
    is parsing. Defaulted to text for the commands that take no --output.
    """
    _response = utils_boto3.get_boto(service_name="sns")
    if _response.get("success") is False:
        print_output(
            message=f"Unable to create SNS client due to {_response.get('message')}",
            output=output,
            error=True,
        )
    return _response.get("message")


def _account_id(output: str = "text") -> str:
    """Read the cluster's AWS account id from the cluster configuration.

    No cast here: SocaConfig.get_value takes return_as=str by default and runs
    the value through SocaCastEngine itself, so the message is already a str on
    the success path. A missing key does not reach this line -- get_value
    answers SocaError.AWS_API_ERROR, which carries success=False, and
    print_output(error=True) exits.
    """
    _response = SocaConfig(key="/configuration/AWSAccountId").get_value()
    if _response.get("success") is not True:
        print_output(
            message=(
                "Unable to read /configuration/AWSAccountId from the cluster "
                f"configuration: {_response.get('message')}"
            ),
            output=output,
            error=True,
        )
    return _response.get("message").strip()


def _topic_arn(client, output: str = "text") -> str:
    """
    Build the cluster topic ARN.

    Derived rather than looked up: sns:ListTopics is an account-scoped action
    that requires Resource "*", which the EDH controller role deliberately does
    not hold -- its SNS grant is scoped to arn:<partition>:sns:<region>:<account>:edh-*
    by resource tag. The name is fixed by the installer, so the ARN is
    deterministic. Region and partition come from the client itself so the ARN
    can never disagree with the endpoint the call is made against.
    """
    return (
        f"arn:{client.meta.partition}:sns:{client.meta.region_name}:"
        f"{_account_id(output=output)}:{get_cluster_id()}{_TOPIC_NAME_SUFFIX}"
    )


def _require_controller(output: str = "text") -> None:
    if not is_controller_instance():
        print_output(
            message=(
                "This command must be run on the controller instance: the SNS "
                "grant for the cluster topic is on the controller IAM role."
            ),
            output=output,
            error=True,
        )


def _assert_topic_exists(client, topic_arn: str, output: str = "text") -> None:
    """
    Confirm the topic is really there before acting on it.

    Without this, a cluster installed with Config.services.notification.enabled
    set to false reports a bare NotFound from whichever call ran first, which
    reads as a permissions problem rather than as a disabled feature.
    """
    try:
        client.get_topic_attributes(TopicArn=topic_arn)
    except (ClientError, BotoCoreError) as err:
        _code = _error_code(err)
        if _code in ("NotFound", "InvalidParameter", "ResourceNotFoundException"):
            print_output(
                message=(
                    f"Cluster notification topic not found: {topic_arn}\n"
                    "\n"
                    "Either the cluster was installed with "
                    "Config.services.notification.enabled set to false, so no "
                    "topic was created, or the topic was deleted after install. "
                    "EDH performs no stack updates, so a deleted topic is not "
                    "recreated and the CloudWatch alarms that target it have no "
                    "destination."
                ),
                output=output,
                error=True,
            )
        if _code in ("AuthorizationError", "AccessDenied", "AccessDeniedException"):
            print_output(
                message=(
                    f"Not authorized to read {topic_arn}.\n"
                    "\n"
                    "The controller role's SNS grant is scoped to "
                    f"arn:{client.meta.partition}:sns:{client.meta.region_name}:"
                    "<account>:edh-* by resource tag, so a cluster whose id does "
                    "not start with 'edh-' falls outside it. The installer forces "
                    "that prefix now, but a cluster installed before it did keeps "
                    "the id it was given, and its own controller cannot manage its "
                    "notification topic. Use administrator credentials for such a "
                    "cluster."
                ),
                output=output,
                error=True,
            )
        print_output(
            message=(
                "Unable to read the cluster notification topic: "
                f"{_client_error_detail(err)}"
            ),
            output=output,
            error=True,
        )


def _list_subscriptions(client, topic_arn: str, output: str = "text") -> list:
    """Return every subscription on the topic, following pagination."""
    _subscriptions = []
    _next_token = None
    try:
        while True:
            _kwargs = {"TopicArn": topic_arn}
            if _next_token:
                _kwargs["NextToken"] = _next_token
            _page = client.list_subscriptions_by_topic(**_kwargs)
            _subscriptions.extend(_page.get("Subscriptions", []))
            _next_token = _page.get("NextToken")
            if not _next_token:
                break
    except (ClientError, BotoCoreError) as err:
        print_output(
            message=(
                f"Unable to list subscriptions on {topic_arn}: "
                f"{_client_error_detail(err)}"
            ),
            output=output,
            error=True,
        )
    return _subscriptions


def _is_pending(subscription: dict) -> bool:
    return subscription.get("SubscriptionArn", "") == _PENDING_ARN


def _match_email(subscriptions: list, email: str) -> list:
    """Return the email subscriptions whose endpoint matches, case-insensitively."""
    _wanted = email.strip().lower()
    return [
        _s
        for _s in subscriptions
        if _s.get("Protocol") in ("email", "email-json")
        and Validators.is_string(_s.get("Endpoint"))
        and _s["Endpoint"].strip().lower() == _wanted
    ]


def _report_kms_denial(err: ClientError | BotoCoreError, topic_arn: str) -> bool:
    """
    Print what to grant when a publish is refused for KMS reasons, and report
    whether that is what happened.

    The topic is encrypted -- with alias/aws/sns by default, or with the CMK
    named by Config.services.notification.kms_key_id. A principal that holds
    sns:Publish but cannot use the key gets a KMS error from SNS rather than an
    SNS one, which does not say what is missing.

    A BotoCoreError reaches this too and answers False: it carries no error
    code, so the connection failure falls through to the generic handler rather
    than being reported as an encryption problem.
    """
    _code = _error_code(err)
    if "KMS" not in _code:
        return False

    print_output(
        message=(
            f"SNS refused the publish for an encryption reason ({_code}).\n"
            "\n"
            f"The topic {topic_arn} is encrypted. Publishing needs "
            "kms:GenerateDataKey* and kms:Decrypt on the key, in addition to "
            "sns:Publish on the topic. If the cluster sets "
            "Config.services.notification.kms_key_id, grant those on that CMK "
            "to the controller role and allow the role in the CMK's own key "
            "policy.\n"
            "\n"
            "The CloudWatch alarms that target this topic publish as a service "
            "principal and are unaffected by this -- only direct publishes from "
            "the controller are."
        ),
        error=True,
    )
    return True


@click.group()
def notifications():
    """Manage the cluster notification SNS topic and its recipients."""
    pass


@notifications.command(name="list")
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def list_subscriptions(output):
    """List who currently receives cluster notifications."""
    _require_controller(output=output)
    _client = _sns_client(output=output)
    _arn = _topic_arn(_client, output=output)
    _assert_topic_exists(_client, _arn, output=output)

    _subscriptions = _list_subscriptions(_client, _arn, output=output)

    _rows = [
        {
            "protocol": _s.get("Protocol"),
            "endpoint": _s.get("Endpoint"),
            "confirmed": "no" if _is_pending(_s) else "yes",
            "subscription_arn": _s.get("SubscriptionArn"),
        }
        for _s in _subscriptions
    ]

    if output != "text":
        print_output(
            message={"topic_arn": _arn, "subscriptions": _rows},
            output=output,
        )
        return

    _lines = [f"Topic : {_arn}", ""]

    if not _rows:
        _lines.append(
            "No subscriptions. Every CloudWatch alarm that targets this topic "
            "currently notifies nobody."
        )
        print_output(message="\n".join(_lines), output="text")
        return

    _width = max(len(_r["protocol"] or "") for _r in _rows)
    _width = max(_width, len("PROTOCOL"))
    _lines.append(f"{'PROTOCOL'.ljust(_width)}  CONFIRMED  ENDPOINT")
    for _r in _rows:
        _lines.append(
            f"{(_r['protocol'] or '').ljust(_width)}  "
            f"{_r['confirmed'].ljust(9)}  {_r['endpoint']}"
        )

    _pending = [_r for _r in _rows if _r["confirmed"] == "no"]
    if _pending:
        _lines.append("")
        _lines.append(
            f"{len(_pending)} subscription(s) are not confirmed and receive "
            "nothing. The endpoint owner has to open the confirmation mail from "
            "SNS and click its link. Until then the subscription has no ARN, so "
            "it cannot be removed by ARN either -- it expires on its own after "
            "three days."
        )

    print_output(message="\n".join(_lines), output="text")


@notifications.command()
@click.option(
    "-e",
    "--email",
    required=True,
    multiple=True,
    help="Email address to subscribe. Repeat for several addresses.",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def subscribe(email, output):
    """Add an email recipient for cluster notifications."""
    _require_controller(output=output)
    _client = _sns_client(output=output)
    _arn = _topic_arn(_client, output=output)
    _assert_topic_exists(_client, _arn, output=output)

    _existing = _list_subscriptions(_client, _arn, output=output)
    _results = []

    # Addresses already handled in THIS invocation. --email is multiple=True and
    # _existing is read once before the loop, so without this a repeated address
    # matches neither occurrence against _existing and subscribes twice, leaving
    # two pending subscriptions for one address -- the exact state the
    # already_subscribed branch below exists to prevent. Compared casefolded,
    # because that is how _match_email compares against the topic.
    _seen = set()

    for _email in email:
        _address = _email.strip()
        if not Validators.is_string_not_empty(_address) or "@" not in _address:
            _results.append(
                {
                    "email": _email,
                    "status": "rejected",
                    "detail": "Not an email address.",
                }
            )
            continue

        if _address.lower() in _seen:
            _results.append(
                {
                    "email": _address,
                    "status": "skipped",
                    "detail": "Named more than once in this command.",
                }
            )
            continue
        _seen.add(_address.lower())

        _match = _match_email(_existing, _address)
        if _match:
            # Re-subscribing an already-pending address sends a second
            # confirmation mail and leaves two pending subscriptions, neither
            # removable by ARN. Say what state it is in instead.
            _results.append(
                {
                    "email": _address,
                    "status": "already_subscribed",
                    "detail": (
                        "Already subscribed but not confirmed."
                        if _is_pending(_match[0])
                        else "Already subscribed and confirmed."
                    ),
                }
            )
            continue

        try:
            _response = _client.subscribe(
                TopicArn=_arn,
                Protocol="email",
                Endpoint=_address,
                ReturnSubscriptionArn=True,
            )
        except (ClientError, BotoCoreError) as err:
            _results.append(
                {
                    "email": _address,
                    "status": "failed",
                    "detail": _client_error_detail(err),
                }
            )
            continue

        _results.append(
            {
                "email": _address,
                "status": "subscribed",
                "detail": (
                    "Confirmation mail sent. The address receives nothing until "
                    "its owner clicks the link."
                ),
                "subscription_arn": _response.get("SubscriptionArn"),
            }
        )

    if output != "text":
        print_output(message={"topic_arn": _arn, "results": _results}, output=output)
    else:
        _lines = [f"Topic : {_arn}", ""]
        for _r in _results:
            _lines.append(f"{_r['email']}: {_r['status']} -- {_r['detail']}")
        print_output(message="\n".join(_lines), output="text")

    if any(_r["status"] in ("failed", "rejected") for _r in _results):
        sys.exit(1)


@notifications.command()
@click.option(
    "-e",
    "--email",
    default=None,
    help="Email address to remove.",
)
@click.option(
    "-a",
    "--subscription-arn",
    default=None,
    help="Subscription ARN to remove. Use for a non-email protocol.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt.",
)
def unsubscribe(email, subscription_arn, force):
    """Remove a recipient of cluster notifications."""
    _require_controller()

    if bool(email) == bool(subscription_arn):
        print_output(
            message="Specify exactly one of --email or --subscription-arn.",
            error=True,
        )

    _client = _sns_client()
    _arn = _topic_arn(_client)
    _assert_topic_exists(_client, _arn)

    if email:
        _match = _match_email(_list_subscriptions(_client, _arn), email)
        if not _match:
            print_output(
                message=f"{email} is not subscribed to {_arn}.",
                error=True,
            )
        if Validators.is_list_length_greater_than(_match, 1):
            print_output(
                message=(
                    f"{email} has {len(_match)} subscriptions on this topic. "
                    "Remove them by ARN with --subscription-arn; "
                    "'edhctl notifications list' prints each one."
                ),
                error=True,
            )
        if _is_pending(_match[0]):
            print_output(
                message=(
                    f"{email} is subscribed but has never confirmed, so SNS has "
                    "not issued an ARN for it and there is nothing to "
                    "unsubscribe. An unconfirmed subscription receives nothing "
                    "and SNS drops it three days after the confirmation mail "
                    "was sent."
                ),
                error=True,
            )
        _target = _match[0]["SubscriptionArn"]
        _label = f"{email} ({_target})"
    else:
        _target = subscription_arn
        _label = _target

    if not force:
        click.echo(
            "Removing a subscription created at install time removes a "
            "CloudFormation-managed resource, which leaves the cluster stack in "
            "drift. EDH performs no stack updates, so nothing reconciles that "
            "and nothing recreates the subscription."
        )
        if not confirm(f"Unsubscribe {_label} from cluster notifications?"):
            print_output(message="Aborted.", output="text")
            return

    try:
        _client.unsubscribe(SubscriptionArn=_target)
    except (ClientError, BotoCoreError) as err:
        print_output(
            message=f"Unable to unsubscribe {_label}: {_client_error_detail(err)}",
            error=True,
        )

    print_output(message=f"Unsubscribed {_label}.", output="text")


@notifications.command()
@click.option(
    "-m",
    "--message",
    default=None,
    help="Message body. Defaults to a generated test message.",
)
def test(message):
    """Publish a message to the topic to prove delivery works."""
    _require_controller()
    _client = _sns_client()
    _arn = _topic_arn(_client)
    _assert_topic_exists(_client, _arn)

    _subscriptions = _list_subscriptions(_client, _arn)
    _confirmed = [_s for _s in _subscriptions if not _is_pending(_s)]
    _pending = [_s for _s in _subscriptions if _is_pending(_s)]

    if not _confirmed:
        print_output(
            message=(
                f"No confirmed subscriptions on {_arn}, so a published message "
                "would reach nobody and prove nothing.\n"
                + (
                    f"{len(_pending)} unconfirmed subscription(s) are waiting on "
                    "their endpoint owner to click the link in the mail SNS "
                    "sent.\n"
                    if _pending
                    else ""
                )
                + "Add a recipient with 'edhctl notifications subscribe -e "
                "<address>'."
            ),
            error=True,
        )

    _cluster_id = get_cluster_id()
    _timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _body = message or (
        f"Test notification from EDH cluster {_cluster_id}, published at "
        f"{_timestamp} by 'edhctl notifications test'. Delivery of this message "
        "confirms that CloudWatch alarms targeting this topic can reach you."
    )

    _subject = f"[TEST] EDH {_cluster_id} notification check"
    if Validators.is_string_length_greater_than(_subject, _MAX_SUBJECT_LEN):
        _subject = _subject[: _MAX_SUBJECT_LEN - 3] + "..."

    try:
        _response = _client.publish(
            TopicArn=_arn,
            Subject=_subject,
            Message=_body,
        )
    except (ClientError, BotoCoreError) as err:
        if _report_kms_denial(err, _arn):
            return
        print_output(
            message=f"Unable to publish to {_arn}: {_client_error_detail(err)}",
            error=True,
        )

    _lines = [
        f"Published to {_arn}",
        f"Message id   : {_response.get('MessageId')}",
        "",
        f"Delivered to {len(_confirmed)} confirmed subscription(s):",
    ]
    _lines.extend(
        f"  {_s.get('Protocol')}  {_s.get('Endpoint')}" for _s in _confirmed
    )
    if _pending:
        _lines.append("")
        _lines.append(
            f"Not delivered to {len(_pending)} unconfirmed subscription(s):"
        )
        _lines.extend(
            f"  {_s.get('Protocol')}  {_s.get('Endpoint')}" for _s in _pending
        )

    print_output(message="\n".join(_lines), output="text")
