# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from botocore.exceptions import ClientError
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from datetime import datetime, timezone

logger = logging.getLogger("soca_logger")
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


class SocaCfnClient:
    def __init__(self, stack_name: str):
        self._stack_name = stack_name
        self._describe_stack = None

    def _call_cfn(
        self, action: str, ignore_missing_stack: bool = False, **kwargs
    ) -> SocaResponse:
        """Generic CloudFormation API caller with consistent error handling."""
        try:
            method = getattr(client_cfn, action)
            response = method(**kwargs)
            return SocaResponse(success=True, message=response)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            if error_code == "ValidationError":
                if "does not exist" in error_message and ignore_missing_stack is True:
                    return SocaResponse(
                        success=True,
                        message=f"Stack does not exist but {ignore_missing_stack=} is True.",
                    )

                return SocaError.AWS_API_ERROR(
                    service_name="cloudformation",
                    helper=f"ValidationError during '{action}' for {self._stack_name}: {error_message}",
                )

            elif error_code == "AlreadyExistsException":
                return SocaError.AWS_API_ERROR(
                    service_name="cloudformation",
                    helper=f"{self._stack_name} already exists. Use a different name or wait if recently deleted.",
                )
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="cloudformation",
                    helper=f"ClientError during '{action}' for {self._stack_name}: {e}",
                )
        except Exception as err:
            return SocaError.AWS_API_ERROR(
                service_name="cloudformation",
                helper=f"Unexpected error during '{action}' for {self._stack_name}: {err}",
            )

    def stack_has_errors(self) -> SocaResponse:
        """If True, returns a list of Stack Error(s)"""
        logger.info(f"Checking CloudFormation stack {self._stack_name} events")
        resp = self._call_cfn(
            action="describe_stack_events", StackName=self._stack_name
        )
        if resp.get("success") is False:
            return resp  # already a SocaError

        events = resp.message.get("StackEvents", [])
        failed_events = [
            f"{e['LogicalResourceId']} ({e['ResourceStatus']}): {e.get('ResourceStatusReason', 'No reason provided')}"
            for e in events
            if "FAILED" in e["ResourceStatus"]
        ]
        if failed_events:
            logger.error(f"Stack {self._stack_name} failed: {failed_events}")
            return SocaResponse(success=True, message=failed_events)

        logger.info(f"Stack {self._stack_name} completed successfully")
        return SocaResponse(
            success=False, message=f"No errors detected on stack {self._stack_name}"
        )

    def delete_stack(self, ignore_missing_stack: bool = False) -> SocaResponse:
        logger.info(f"Deleting CloudFormation stack {self._stack_name}")
        resp = self._call_cfn(
            action="delete_stack",
            ignore_missing_stack=ignore_missing_stack,
            StackName=self._stack_name,
        )
        if resp.get("success") is True:
            return SocaResponse(
                success=True,
                message=f"Stack {self._stack_name} deleted successfully",
            )
        else:
            return resp  # already a SocaError

    def create_stack(
        self, template_body: str, tags: dict, on_failure: str = "DO_NOTHING",
        notification_arns: list = None,
    ) -> SocaResponse:
        logger.info(
            f"Creating CloudFormation stack {self._stack_name}, tags={tags}, on_failure={on_failure}"
        )
        logger.debug(f"Template body: {template_body}")

        if on_failure not in ["DELETE", "ROLLBACK", "DO_NOTHING"]:
            return SocaError.GENERIC_ERROR(
                "on_failure must be DELETE, ROLLBACK, or DO_NOTHING"
            )

        _kwargs = dict(
            action="create_stack",
            StackName=self._stack_name,
            TemplateBody=template_body,
            Tags=tags,
            OnFailure=on_failure,
        )
        # NotificationARNs subscribes one or more SNS topics to receive
        # stack lifecycle events (CREATE_IN_PROGRESS / CREATE_COMPLETE /
        # ROLLBACK_*). Optional -- omit if no per-cluster topic is set up.
        if notification_arns:
            _cast = SocaCastEngine(notification_arns).cast_as(list)
            if _cast.get("success") is not True:
                logger.warning(
                    f"Ignoring notification_arns; could not cast to list: {notification_arns!r}"
                )
            else:
                _kwargs["NotificationARNs"] = _cast.get("message")

        resp = self._call_cfn(**_kwargs)
        if resp.get("success") is True:
            return SocaResponse(
                success=True,
                message=f"Stack {self._stack_name} created successfully",
            )
        else:
            return resp  # already a SocaError

    def __describe_stack(self) -> bool:
        resp = self._call_cfn(action="describe_stacks", StackName=self._stack_name)
        if not resp.get("success"):
            return False
        else:
            self._describe_stack = resp.message
            return True

    def is_stack_older_than(
        self, minutes: int = 30, force_describe: bool = False
    ) -> SocaResponse:
        if self._describe_stack is None or force_describe is True:
            if not self.__describe_stack():
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to describe stack {self._stack_name}"
                )

        stack_info = self._describe_stack["Stacks"][0]
        creation_time = stack_info["CreationTime"]

        current_time = datetime.now(timezone.utc)
        time_difference = (current_time - creation_time).total_seconds() / 60

        if time_difference > minutes:
            return SocaResponse(
                success=True,
                message=f"Stack {self._stack_name} was created {int(time_difference)} minutes ago",
            )

        return SocaResponse(
            success=False,
            message=f"Stack {self._stack_name} was created {int(time_difference)} minutes ago",
        )

    def get_tags(self, force_describe: bool = False):
        if self._describe_stack is None or force_describe is True:
            if not self.__describe_stack():
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to describe stack {self._stack_name}"
                )

        stack_info = self._describe_stack["Stacks"][0]

        _tags = {t["Key"]: t["Value"] for t in stack_info.get("Tags", [])}
        return SocaResponse(success=True, message=_tags)
