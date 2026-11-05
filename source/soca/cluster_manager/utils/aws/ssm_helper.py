# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import botocore
from typing import Optional, Literal, List
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ec2_helper import describe_instances, describe_instances_paginate
from utils.cache.decorator import soca_cache
from utils.error import SocaError
from utils.response import SocaResponse
from utils.config import SocaConfig

client_ssm = utils_boto3.get_boto(service_name="ssm").message
logger = logging.getLogger("soca_logger")

# ssm:SendCommand documents InstanceIds as "Array Members: Minimum number of 0
# items. Maximum number of 50 items." Named rather than inlined so a test
# reads the real bound instead of restating it.
SEND_COMMAND_MAX_INSTANCES = 50


@soca_cache(prefix="edh:webui:aws:ssm:get_ami_id_from_alias", ttl=86400)
def get_ami_id_from_alias(
    alias_name: str,
) -> SocaResponse:
    """

    This helper will automatically fetch the latest version of a specific AMI. This is particularly useful for Windows as
    Windows AMI are now expired automatically every 3 months:

    AWS Windows AMIs are publicly available for three months after they are released.
    Within 10 days after the release of new AMIs, AWS changes access for AMIs that are more than three months old to make them private.

    Source: https://docs.aws.amazon.com/ec2/latest/windows-ami-reference/windows-ami-versions.html

    Because of that, we cannot hardcode AMI ID anymore, and launching Windows VDI will need to call this function to get the most recent Windows AMI

    eg: Instead of registering a Software Stack with `ami-xxxx`, you will register it with `/aws/service/ami-windows-latest/Windows_Server-2025-English-Full-Base`"
    """

    logger.info(f"Get AMI ID for {alias_name=}")

    try:
        _fetch_ami_id = client_ssm.get_parameter(
            Name=alias_name,
        )

        logger.debug(f"get_ami_alias for {alias_name}: {_fetch_ami_id}")
        _ami_id = _fetch_ami_id["Parameter"]["Value"]
        # Received results for this alias, we just validate this is a correct AMI ID
        if _ami_id.startswith("ami-"):
            return SocaResponse(success=True, message=_ami_id)
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get AMI ID for {alias_name}. Received Result: {_ami_id}"
            )

    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to get_parameter for {alias_name} due to {e}"
        )

    except Exception as e:
        return SocaError.GENERIC_ERROR(helper=f"Unable to run get_parameter due to {e}")


def describe_instance_platforms(instance_ids: List[str]) -> SocaResponse:
    """
    PingStatus and PlatformType per instance, for callers that must not send a
    shell script to a Windows node or to an instance the SSM agent cannot reach.
    An instance absent from the response has no registered agent, so it is
    reported as Unknown rather than omitted -- a caller filtering on this needs
    to tell "not reachable" apart from "not asked about".
    """
    _result = {}
    try:
        _paginator = client_ssm.get_paginator("describe_instance_information")
        for _page in _paginator.paginate(
            Filters=[{"Key": "InstanceIds", "Values": instance_ids}]
        ):
            for _info in _page.get("InstanceInformationList", []):
                _result[_info.get("InstanceId")] = {
                    "ping_status": _info.get("PingStatus", "Unknown"),
                    "platform_type": _info.get("PlatformType", "Unknown"),
                }
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run describe_instance_information due to {err}"
        )

    for _iid in instance_ids:
        if _iid not in _result:
            _result[_iid] = {"ping_status": "Unknown", "platform_type": "Unknown"}

    return SocaResponse(success=True, message=_result)


def execute_ssm_document(
    document_name: str,
    parameters: dict,
    timeout: int = 30,
    max_attempts: int = 3,
    node_type: Optional[Literal["login_node", "dcv_node", "compute_node"]] = None,
    instance_ids: Optional[List[str]] = None,
) -> SocaResponse:

    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().get("message")

    # ensure SSM is only executed on nodes that belong to this EDH environment
    _filters = [
        {"Name": "tag:edh:ClusterId", "Values": [_cluster_id]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ]

    if instance_ids and node_type:
        return SocaError.GENERIC_ERROR(
            helper="You cannot set both instance_ids and node_type"
        )

    if not instance_ids and not node_type:
        return SocaError.GENERIC_ERROR(
            helper="You must set either instance_ids or node_type"
        )

    if node_type:
        _filters.append({"Name": "tag:edh:NodeType", "Values": [node_type]})

    if instance_ids:
        _get_instances = describe_instances(
            instance_ids=instance_ids,
            filters=_filters,
        )
    else:
        _get_instances = describe_instances_paginate(
            filters=_filters,
        )

    if not _get_instances.get("success"):
        logger.warning(
            f"Failed to validate instance cluster ownership: {_get_instances.get('message')}",
        )
        return SocaError.GENERIC_ERROR(
            helper="Failed to validate instance cluster ownership"
        )
    else:
        if instance_ids:
            # Cross-check the caller's list against what the FILTERED describe
            # actually returned. Without this the ids were passed straight
            # through to send_command, so the ownership check this function
            # exists to perform did nothing on this branch.
            #
            # Note the shape difference: describe_instances returns the raw
            # boto3 response, so verified ids live under
            # Reservations[].Instances[], while describe_instances_paginate
            # below yields a flat list of instance dicts.
            _verified = {
                _i.get("InstanceId")
                for _r in (_get_instances.get("message") or {}).get("Reservations", [])
                for _i in _r.get("Instances", [])
            }
            _foreign = [_i for _i in instance_ids if _i not in _verified]
            if _foreign:
                logger.warning(
                    f"Refusing to run {document_name}: {_foreign} did not match "
                    f"cluster {_cluster_id} with the running-state filter"
                )
                return SocaError.GENERIC_ERROR(
                    helper=f"Instances {_foreign} do not belong to cluster {_cluster_id}"
                )
        else:
            # instance ids will be fetched based on the node_type filter, we need to extract instance ids from the describe_instances_paginate result
            instance_ids = []
            for ec2_instance in _get_instances.get("message", []):
                instance_ids.append(ec2_instance.get("InstanceId"))

    logger.info(f"Validated {instance_ids} to run SSM document {document_name}")
    if not instance_ids:
        return SocaError.GENERIC_ERROR(
            helper="No valid instances found belonging to this cluster"
        )

    if len(document_name) > 128:
        return SocaError.GENERIC_ERROR(
            helper=f"SSM document name exceeds 128 characters: {document_name}"
        )

    # ssm:SendCommand documents InstanceIds as "Maximum number of 50 items",
    # so one call cannot carry a whole node type. The always-on types this is
    # usually pointed at are one or two nodes, but an operator targeting
    # compute_node or dcv_node passes that limit easily and the API rejects
    # the request for every node in the group at once. Batch instead, and keep
    # one result row per instance so the caller's view is unchanged.
    results = []
    for _batch_start in range(0, len(instance_ids), SEND_COMMAND_MAX_INSTANCES):
        _batch = instance_ids[
            _batch_start : _batch_start + SEND_COMMAND_MAX_INSTANCES
        ]
        try:
            send_resp = client_ssm.send_command(
                InstanceIds=_batch,
                DocumentName=document_name,
                Parameters=parameters,
                TimeoutSeconds=timeout,
            )
        except Exception as err:
            logger.error(
                f"ssm:SendCommand({document_name}) on {len(_batch)} of "
                f"{len(instance_ids)} nodes failed: {err}"
            )
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to run SSM {document_name} due to {err}"
            )

        command_id = send_resp["Command"]["CommandId"]
        waiter = client_ssm.get_waiter("command_executed")
        for _iid in _batch:
            try:
                waiter.wait(
                    CommandId=command_id,
                    InstanceId=_iid,
                    WaiterConfig={"Delay": 1, "MaxAttempts": max_attempts},
                )
            except Exception:
                # WaiterError fires on both timeout and non-Success terminal
                # state. Either way we still want the invocation detail
                # (stderr, partial stdout) for logging and the API response,
                # so don't bail here -- fall through to GetCommandInvocation.
                pass
            try:
                inv = client_ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=_iid
                )
            except Exception as exc:
                logger.warning(
                    f"ssm:GetCommandInvocation({command_id}, {_iid}) failed: {exc}"
                )
                continue
            results.append(
                {
                    "instance_id": _iid,
                    "status": inv.get("Status", "Unknown"),
                    "stdout": inv.get("StandardOutputContent", "") or "",
                    "stderr": inv.get("StandardErrorContent", "") or "",
                }
            )
    logger.info(f"SSM document {document_name} execution results: {results}")
    return SocaResponse(success=True, message=results)
