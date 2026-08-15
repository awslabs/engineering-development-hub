######################################################################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import os
import sys
import random

if os.environ.get("EDH_CLUSTER_ID", None) is None:
    print(
        "EDH_CLUSTER_ID not found, did you run 'source /etc/environment' and  source '/opt/edh/<REPLACE_WITH_YOUR_CLUSTER_Id>/python/latest/edh_python.env' before calling this script?"
    )
    sys.exit(1)

import utils.aws.boto3_wrapper as utils_boto3_wrapper

from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.error import SocaError
from utils.logger import SocaLogger

from utils.aws.ec2_helper import describe_instances_paginate

from utils.datamodels.soca_dcv import SocaDCVInstance

# Ownership tag applied to every ALB rule this module creates. The cleanup
# loop only considers rules that carry this tag, so other features can
# safely add their own rules to the same listener without being clobbered
# on the next reconcile. When adding a new feature that shares this
# listener, do NOT reuse this tag key - pick a different edh:ManagedBy
# value (e.g. webshell, bulktransfer) so each subsystem owns its own rules.
DCV_ALB_MANAGED_BY_TAG_KEY = "edh:ManagedBy"
DCV_ALB_MANAGED_BY_TAG_VALUE = "dcv_alb_manager"


def get_ec2_dcv_instances(cluster_id: str) -> SocaResponse | SocaError:
    _instance_list = []

    logger.info(f"Fetching DCV instances for cluster_id: {cluster_id}")
    _get_dcv_ec2_instances = describe_instances_paginate(
        filters=[
            {
                "Name": "instance-state-name",
                "Values": [
                    "running",
                ],
            },
            {"Name": "tag:edh:NodeType", "Values": ["dcv_node"]},
            {"Name": "tag:edh:ClusterId", "Values": [cluster_id]},
        ]
    )

    if _get_dcv_ec2_instances.get("success") is False:
        return SocaError.GENERIC_ERROR(
            error_message=f"Unable to describe DCV EC2 instances with error: {_get_dcv_ec2_instances.get('message')}"
        )

    else:
        for _ec2_instance in _get_dcv_ec2_instances.get("message"):
            _private_dns = _ec2_instance.get("PrivateDnsName", "").split(".")[0]
            if _private_dns:
                _instance_list.append(
                    SocaDCVInstance(
                        private_dns=_private_dns,
                        alb_rule=f"/{_private_dns}/*",
                        instance_id=_ec2_instance.get("InstanceId"),
                    )
                )
            else:
                logger.warning(
                    f"private_dns is empty for instance {_ec2_instance.get('InstanceId')}, skipping ..."
                )

    logger.info(f"Found {len(_instance_list)} DCV instances")
    logger.debug(f"found DCV instances {_instance_list}")
    return SocaResponse(success=True, message=_instance_list)


def register_instance_to_target_group(
    target_group_arn: str, instance_id: str
) -> SocaResponse | SocaError:
    logger.info(f"Registering {instance_id=} to {target_group_arn=}")
    try:
        register_ec2 = elbv2_client.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {
                    "Id": instance_id,
                },
            ],
        )

        if register_ec2["ResponseMetadata"]["HTTPStatusCode"] == 200:
            logger.info(f"{instance_id=} registered successfully")
            return SocaResponse(success=True, message=True)
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"EC2 instance {instance_id} not registered to target group {target_group_arn}: {register_ec2}"
            )

    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to register {instance_id=} to {target_group_arn=} because of {err}"
        )


def create_new_target_group(
    instance_dns: str, vpc_id: str, cluster_id: str
) -> SocaResponse | SocaError:
    logger.info(f"Creating new target group for {instance_dns}")
    try:
        new_target_group = elbv2_client.create_target_group(
            Name=f"edh-{instance_dns}",
            Protocol="HTTPS",
            Port=8443,
            VpcId=vpc_id,
            HealthCheckProtocol="HTTPS",
            HealthCheckPort="8443",
            HealthCheckEnabled=True,
            HealthCheckPath=f"/{instance_dns}/",
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=2,
            UnhealthyThresholdCount=2,
            Matcher={"HttpCode": "200"},
            TargetType="instance",
        )
        if new_target_group["ResponseMetadata"]["HTTPStatusCode"] == 200:
            elbv2_client.add_tags(
                ResourceArns=[
                    new_target_group["TargetGroups"][0]["TargetGroupArn"],
                ],
                Tags=[
                    {"Key": "edh:ClusterId", "Value": cluster_id},
                ],
            )
            logger.info(f"Successfully created target group for {instance_dns}")
            target_group_arn = new_target_group.get("TargetGroups", [])[0].get(
                "TargetGroupArn", None
            )

            if target_group_arn is None:
                return SocaError.GENERIC_ERROR(
                    helper=f"Target Group created but unable to retrieve the GroupArn: {new_target_group}"
                )

            return SocaResponse(
                success=True,
                message=target_group_arn,
            )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"create_target_group returned non HTTP 200: {new_target_group}"
            )
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to create target group for {instance_dns} because of {err}"
        )


def create_new_alb_rule(
    instance_dns: str, target_group_arn: str, current_priority_rules, listener_arn: str
) -> SocaResponse | SocaError:
    #
    min_priority = 10_000
    max_priority = 40_000
    logger.info(f"About to add new ALB rule for {instance_dns}")
    logger.debug(f"List of rules already taken {current_priority_rules}")
    available_rules = list(
        set(range(min_priority, max_priority + 1)) - set(current_priority_rules)
    )
    if not available_rules:
        return SocaError.GENERIC_ERROR(
            error_message="No more available priority rules. You may need to clean up your ALB rules."
        )

    priority = random.choice(available_rules)
    logger.info(f"Found Available priority for this rule: {priority}")
    try:
        new_target_group = elbv2_client.create_rule(
            ListenerArn=listener_arn,
            Priority=int(priority),
            Conditions=[{"Field": "path-pattern", "Values": [f"/{instance_dns}/*"]}],
            Actions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
            # Tag the rule so future reconcile cycles (and other features
            # that share this listener, e.g. the webshell /web_terminal/endpoint*
            # rule) know this rule is ours and can be safely cleaned up
            # when the backing DCV instance is gone. Rules without this
            # tag are left alone - see get_current_listener_rules.
            Tags=[
                {
                    "Key": DCV_ALB_MANAGED_BY_TAG_KEY,
                    "Value": DCV_ALB_MANAGED_BY_TAG_VALUE,
                },
            ],
        )
        logger.info("Rule created successfully")
        return SocaResponse(success=True, message=new_target_group)
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to create ALB rule because of {err}"
        )


def get_current_listener_rules(listener_arn: str) -> SocaResponse | SocaError:
    """Return (rules, priority_taken) for the listener.

    * `rules` contains ONLY rules that this module owns (tagged with
      DCV_ALB_MANAGED_BY_TAG_KEY = DCV_ALB_MANAGED_BY_TAG_VALUE). This is
      what the cleanup loop iterates over - unowned rules belonging to
      other features (e.g. /web_terminal/endpoint* for the webshell) are left alone.

    * `priority_taken` contains priorities of ALL non-default rules,
      regardless of ownership, so `create_new_alb_rule` doesn't try to
      reuse a priority already claimed by another feature.
    """
    logger.info(f"Fetching all listener rules for {listener_arn=}")
    rules = {}
    priority_taken = []
    try:
        all_rules = elbv2_client.describe_rules(ListenerArn=listener_arn)["Rules"]
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            error_message=f"Unable to describe rules from listener {listener_arn} with error: {err}"
        )

    # Collect priorities first (regardless of ownership) so we don't race
    # another feature's rule on rule creation.
    candidate_arns = []
    for rule in all_rules:
        if rule["Priority"] in ("default", "1"):
            continue
        priority_taken.append(int(rule["Priority"]))
        candidate_arns.append(rule["RuleArn"])

    # Batch describe_tags - one API call for up to 20 rules. The API
    # accepts up to 20 ARNs per call (ELBv2 API quota); chunk if we ever
    # exceed that.
    owned_arns = set()
    if candidate_arns:
        try:
            for chunk_start in range(0, len(candidate_arns), 20):
                chunk = candidate_arns[chunk_start : chunk_start + 20]
                tag_resp = elbv2_client.describe_tags(ResourceArns=chunk)
                for td in tag_resp.get("TagDescriptions", []):
                    arn = td.get("ResourceArn")
                    for t in td.get("Tags", []):
                        if (
                            t.get("Key") == DCV_ALB_MANAGED_BY_TAG_KEY
                            and t.get("Value") == DCV_ALB_MANAGED_BY_TAG_VALUE
                        ):
                            owned_arns.add(arn)
                            break
        except Exception as err:
            # FAIL-SAFE: if tag lookup fails we cannot tell our rules from
            # rules owned by other features (e.g. the webshell `/web_terminal/endpoint`
            # rule). Treating every non-default rule as ours - the legacy
            # behaviour - would let the cleanup loop delete those foreign
            # rules and break the other feature.
            #
            # Returning an explicit error here aborts this reconcile cycle.
            # The DCV instances stay routable until the next cycle (their
            # rules survive untouched). Operator can investigate and the
            # next cycle will retry once permissions / network recover.
            return SocaError.GENERIC_ERROR(
                error_message=(
                    f"Unable to describe_tags for {len(candidate_arns)} ALB "
                    f"rules on {listener_arn}: {err}. Refusing to reconcile "
                    f"because we cannot distinguish DCV-owned rules from "
                    f"rules owned by other features (e.g. webshell). The "
                    f"reconcile will retry on the next scheduled run."
                )
            )

    # Only include owned rules in the cleanup candidate set.
    for rule in all_rules:
        if rule["RuleArn"] not in owned_arns:
            continue
        condition_list = []
        for condition in rule["Conditions"]:
            for value in condition["Values"]:
                condition_list.append(value)
        rules[rule["RuleArn"]] = condition_list

    logger.info(
        f"Found {len(rules)} owned rules (of {len(candidate_arns)} non-default/non-1) in {listener_arn}"
    )
    logger.debug(
        f"found current listener rules for {listener_arn}: {rules=} / {priority_taken=}"
    )
    return SocaResponse(
        success=True, message={"rules": rules, "priority_taken": priority_taken}
    )


def get_current_target_groups(alb_arn: str) -> SocaResponse | SocaError:
    _target_groups = {}
    logger.info(f"Getting current target groups for ELB {alb_arn}")

    try:
        elb_paginator = elbv2_client.get_paginator("describe_target_groups")
        elb_iterator = elb_paginator.paginate(LoadBalancerArn=alb_arn)
        for _page in elb_iterator:
            for _tg in _page.get("TargetGroups", {}):
                if _tg:
                    logger.debug(f"Found target group {_tg['TargetGroupName']}")
                    _target_groups[_tg["TargetGroupName"]] = _tg["TargetGroupArn"]
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            error_message=f"Unable to retrieve target groups from ELB {alb_arn} with error: {err}"
        )

    logger.info(f"Found {len(_target_groups)} target groups assigned to {alb_arn}")
    logger.debug(f"Found {_target_groups} assigned to {alb_arn}")
    return SocaResponse(success=True, message=_target_groups)


def delete_target_groups(target_group_arn: str) -> bool:
    logger.info(f"Deleting target group: {target_group_arn}")
    try:
        elbv2_client.delete_target_group(TargetGroupArn=target_group_arn)
        logger.info(f"Successfully deleted {target_group_arn}")
        return True
    except Exception as err:
        logger.error(f"Unable to delete {target_group_arn=} because of {err}")
    return False


def delete_rule(rule_arn: str) -> bool:
    logger.info(f"Deleting ELB rule {rule_arn}")
    try:
        elbv2_client.delete_rule(RuleArn=rule_arn)
        logger.info(f"Successfully deleted {rule_arn}")
        return True
    except Exception as err:
        logger.error(f"Unable to delete {rule_arn=} because of {err}")
    return False


def return_alb_https_listener(alb_arn: str) -> SocaResponse | SocaError:
    logger.debug(f"Retrieving HTTPS listener ARN from ALB: {alb_arn}")
    try:
        _get_https_listener_arn = False
        for listener in elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)[
            "Listeners"
        ]:
            logger.debug(f"Received describe_listeners response {listener}")
            if listener["Port"] == 443:
                _get_https_listener_arn = listener["ListenerArn"]
        if _get_https_listener_arn is not False:
            return SocaResponse(success=True, message=_get_https_listener_arn)
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"{alb_arn} found but unable to find an HTTPS listener."
            )
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            error_message=f"Unable to get listener ARN from ALB {alb_arn} with error: {err}"
        )


if __name__ == "__main__":
    cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    vpc_id = SocaConfig(key="/configuration/VpcId").get_value().get("message")
    alb_arn = (
        SocaConfig(key="/configuration/LoadBalancerArn").get_value().get("message")
    )

    logger = SocaLogger(name="soca_logger").timed_rotating_file_handler(
        file_path=f"/opt/edh/{cluster_id}/cluster_manager/orchestrator/logs/dcv_alb_manager.log"
    )

    elbv2_client = utils_boto3_wrapper.get_boto(service_name="elbv2").message
    ec2_client = utils_boto3_wrapper.get_boto(service_name="ec2").message

    # In DCV high-scale mode the broker + gateway (NLB) handle session
    # routing, so the per-VDI ALB target-group/rule mechanism this script
    # manages is not used. Exit as a no-op to avoid creating orphaned
    # per-instance target groups on high-scale clusters.
    _high_scale_resp = SocaConfig(key="/dcv/high_scale_enabled").get_value()
    if _high_scale_resp.get("success") is not True:
        logger.warning(
            f"Unable to read /dcv/high_scale_enabled ({_high_scale_resp.get('message')}); "
            "continuing with per-VDI ALB management."
        )
    elif str(_high_scale_resp.get("message")).lower() == "true":
        logger.info(
            "DCV high-scale mode enabled; per-VDI ALB management is not used. Exiting no-op."
        )
        sys.exit(0)

    # Step 1 - Verify if HTTPS listener exist
    if (_get_alb_https_listener := return_alb_https_listener(alb_arn=alb_arn)).get(
        "success"
    ) is True:
        listener_arn = _get_alb_https_listener.get("message")
    else:
        logger.fatal(f"Unable to find HTTPS listener for {alb_arn}")
        sys.exit(1)

    # Step 2 - Find all DCV machines
    if (_get_dcv_instances := get_ec2_dcv_instances(cluster_id=cluster_id)).get(
        "success"
    ) is True:
        dcv_instances = _get_dcv_instances.get("message")
    else:
        logger.fatal(f"Unable to fetch DCV instances")
        sys.exit(1)

    # Step 3 - Fetch all Target Groups
    if (_get_current_target_groups := get_current_target_groups(alb_arn=alb_arn)).get(
        "success"
    ) is True:
        current_target_groups = _get_current_target_groups.get("message")
    else:
        logger.fatal(f"Unable to fetch target groups")
        sys.exit(1)

    # Step 4 - Get all current ALB Rules

    if (
        _get_current_https_listener_rules := get_current_listener_rules(
            listener_arn=listener_arn
        )
    ).get("success") is True:
        alb_listener_rules = _get_current_https_listener_rules.get("message")
    else:
        logger.fatal(f"Unable to fetch HTTPS listener rules")
        sys.exit(1)

    alb_rules = alb_listener_rules["rules"]
    alb_rules_dns = []
    for entry in alb_rules.values():
        alb_rules_dns.append(entry[0])
    alb_priority_taken = alb_listener_rules["priority_taken"]

    # First, let's add any new instance to ALB. Create TG/Rules if needed
    logger.info(f"Checking if new DCV hosts need to be added to {alb_arn} ...")
    for dcv_instance in dcv_instances:
        logger.debug(f"Checking {dcv_instance}")
        if dcv_instance.alb_rule in alb_rules_dns:
            logger.info(
                f"{dcv_instance.private_dns} already registered to the load balancer. skipping"
            )
        else:
            logger.info(
                f"{dcv_instance.private_dns} not in load balancer. Adding new entry ... "
            )
            if dcv_instance.private_dns not in current_target_groups.keys():
                logger.info(
                    "Target Group does not exist, creating Target Group first ..."
                )
                _create_new_target_group = create_new_target_group(
                    instance_dns=dcv_instance.private_dns,
                    vpc_id=vpc_id,
                    cluster_id=cluster_id,
                )
                if _create_new_target_group.get("success") is True:
                    new_registration = register_instance_to_target_group(
                        target_group_arn=_create_new_target_group.get("message"),
                        instance_id=dcv_instance.instance_id,
                    )
                    if new_registration.get("success") is True:
                        _new_alb_rule = create_new_alb_rule(
                            instance_dns=dcv_instance.private_dns,
                            target_group_arn=_create_new_target_group.get("message"),
                            current_priority_rules=alb_priority_taken,
                            listener_arn=listener_arn,
                        )
                        if _new_alb_rule.get("success") is False:
                            logger.error("Unable to create ALB rule")
                    else:
                        logger.error(
                            f"Unable to register Instance {dcv_instance} to {_create_new_target_group.get('message')} because of {new_registration.get('message')}"
                        )
                else:
                    logger.error(
                        f"Unable to create target group: {_create_new_target_group}"
                    )

            else:
                logger.info("Target Group already exist")
                existing_target_group = current_target_groups[dcv_instance.private_dns]
                new_registration = register_instance_to_target_group(
                    target_group_arn=existing_target_group,
                    instance_id=dcv_instance.instance_id,
                )
                if new_registration.get("success") is True:
                    create_new_alb_rule(
                        instance_dns=dcv_instance.private_dns,
                        target_group_arn=existing_target_group,
                        current_priority_rules=alb_priority_taken,
                        listener_arn=listener_arn,
                    )
                else:
                    logger.error(
                        f"Unable to register Instance {dcv_instance} to {existing_target_group} because of {new_registration.get('message')}"
                    )

    logger.info("Check Complete")
    # Then, let's do some cleaning
    logger.info("Cleaning old rules start ...")
    for current_rule in alb_rules_dns:
        # transform /ip-180-0-172-39/* in ip-180-0-172-39
        instance_dns = current_rule.replace("/", "").replace("*", "")
        if not any(i.private_dns == instance_dns for i in dcv_instances):
            logger.info(
                f"{current_rule} is pointing to an EC2 resource which does not exist anymore"
            )
            for rule_arn, rule_path in alb_rules.items():
                try:
                    if current_rule in rule_path:
                        if delete_rule(rule_arn=rule_arn):
                            tg_arn_to_delete = current_target_groups[
                                f"edh-{instance_dns}"
                            ]
                            if (
                                delete_target_groups(target_group_arn=tg_arn_to_delete)
                                is False
                            ):
                                logger.error(f"Unable to delete {tg_arn_to_delete}")
                        else:
                            logger.error(f"Unable to delete {rule_arn}")
                except Exception as err:
                    logger.warning("Target Group is already deleted, skipping ")

    logger.info("Cleaning complete")
