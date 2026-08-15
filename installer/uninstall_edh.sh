#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0   

#
# Uninstall an EDH (Engineering Design Hub) cluster and clean up all associated AWS resources.
#
# This script removes backup vaults, log groups, CloudFormation stacks, Aurora DB clusters,
# NLBs, and S3 data associated with the specified cluster. Destructive operations (backup
# deletion, S3 deletion) require interactive confirmation unless --force is specified.
#
# Prerequisites:
#   - AWS CLI configured with credentials that have sufficient permissions
#   - jq installed
#
# Usage:
#   ./uninstall_edh.sh --cluster-name <name> --region <region> --s3-bucket <bucket> [--force]
#
# Examples:
#   # Interactive mode (prompts before deleting backups and S3 data)
#   ./uninstall_edh.sh --cluster-name my-cluster --region us-east-1 --s3-bucket my-bucket
#
#   # Non-interactive mode (skip all confirmation prompts)
#   ./uninstall_edh.sh --cluster-name my-cluster --region us-east-1 --s3-bucket my-bucket --force


for cmd in aws jq; do
    if ! command -v "${cmd}" &> /dev/null; then
        echo "Error: '${cmd}' is required but not installed."
        exit 1
    fi
done

FORCE=false

function usage() {
    echo "usage: $0 --cluster-name <name> --region <region> --s3-bucket <bucket> [--force]"
    echo ""
    echo "Required:"
    echo "  --cluster-name    Name of the SOCA cluster to uninstall"
    echo "  --region          AWS region where the cluster is deployed"
    echo "  --s3-bucket       S3 bucket name used by the cluster"
    echo ""
    echo "Optional:"
    echo "  --force           Skip confirmation prompts for destructive operations"
    exit 1
}

function confirm() {
    local prompt="${1}"
    if [[ "${FORCE}" == "true" ]]; then
        echo "!!! WARNING: ${prompt} (--force: proceeding without confirmation)"
        return 0
    fi
    echo ""
    echo "!!! WARNING: ${prompt}"
    read -r -p "Type 'yes' to confirm: " response
    if [[ "${response}" != "yes" ]]; then
        echo "Skipped."
        return 1
    fi
    return 0
}

EDH_CLUSTER_NAME=""
EDH_DEPLOYMENT_REGION=""
EDH_BUCKET_NAME=""

while [[ $# -gt 0 ]]; do
    case "${1}" in
        --cluster-name)
            EDH_CLUSTER_NAME="${2}"
            shift 2
            ;;
        --region)
            EDH_DEPLOYMENT_REGION="${2}"
            shift 2
            ;;
        --s3-bucket)
            EDH_BUCKET_NAME="${2}"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: ${1}"
            usage
            ;;
    esac
done

if [[ -z "${EDH_CLUSTER_NAME}" || -z "${EDH_DEPLOYMENT_REGION}" || -z "${EDH_BUCKET_NAME}" ]]; then
    echo "Error: --cluster-name, --region, and --s3-bucket are required."
    usage
fi

echo ""
echo "This script will uninstall the EDH cluster '${EDH_CLUSTER_NAME}' in region '${EDH_DEPLOYMENT_REGION}'."
echo ""
echo "It will delete all resources that prevent CloudFormation from successfully deleting the stack, including:"
echo "  - Backup vault recovery points"
echo "  - CloudWatch log groups"
echo "  - Associated CloudFormation child stacks"
echo "  - Associated AutoScaling Group"
echo "  - Associated AWS Secrets"
echo "  - VPC Endpoints if the VPC was created by EDH"
echo "  - NAT Gateways if the VPC was created by EDH"
echo "  - Elastic IPs associated with the cluster"
echo "  - DynamoDB tables associated with the cluster"
echo "  - Termination/deletion protection on Aurora DB, NLB, and the main stack"
echo ""
echo "Once complete, it will delete the CloudFormation stack and S3 data."
echo ""

if ! confirm "Proceed with uninstalling cluster '${EDH_CLUSTER_NAME}'?"; then
    exit 0
fi

echo "============ Deleting Backup Vault ============"
VAULT_NAME="${EDH_CLUSTER_NAME}-BackupVault"
if ! aws backup list-backup-vaults --region ${EDH_DEPLOYMENT_REGION} --query 'BackupVaultList[*].BackupVaultName' --region ${EDH_DEPLOYMENT_REGION} | grep ${VAULT_NAME} &> /dev/null; then
    echo "${VAULT_NAME} doesn't exist. May have already been deleted."
else
  recovery_point_arns=($(aws backup list-recovery-points-by-backup-vault --region ${EDH_DEPLOYMENT_REGION}  --backup-vault-name ${VAULT_NAME} --query 'RecoveryPoints[*].RecoveryPointArn' --output text))
  num="${#recovery_point_arns[@]}"
  if [[ $num == 0 ]]; then
    echo "No recovery points found"
  else
    echo "Deleting $num recovery points from ${VAULT_NAME}"
    for recovery_point_arn in "${recovery_point_arns[@]}"; do
        echo "Deleting $recovery_point_arn"
        aws backup delete-recovery-point --region ${EDH_DEPLOYMENT_REGION}  --backup-vault-name ${VAULT_NAME} --recovery-point-arn $recovery_point_arn
    done
  fi
fi

echo "============ Deleting CloudWatch Log Groups ============"

# Delete this cluster's CloudWatch Log Groups found under a search prefix.
#   $1 = --log-group-name-prefix to enumerate and delete.
# Both the native (/soca/<cluster>/) and vended (/aws/vendedlogs/<cluster>/)
# hierarchies are cluster-first, so a plain prefix is already cluster-scoped --
# no cross-cluster match is possible. Safe when the prefix yields no groups.
delete_cluster_log_groups() {
    local _prefix="$1"
    aws logs describe-log-groups \
        --log-group-name-prefix "${_prefix}" \
        --region "${EDH_DEPLOYMENT_REGION}" \
        --query "join('\n', logGroups[].logGroupName)" \
        --output text | while read -r log_group; do
        if [[ -n "${log_group}" ]]; then
            echo "Deleting log group: ${log_group}"
            aws logs delete-log-group --log-group-name "${log_group}" --region "${EDH_DEPLOYMENT_REGION}"
        fi
    done
}

# Native cluster log groups. Current EDH prefix is /edh/<cluster>/... (from
# generate_log_group); /soca/<cluster>/ is the legacy prefix, swept too so
# older clusters are covered.
delete_cluster_log_groups "/edh/${EDH_CLUSTER_NAME}/"
delete_cluster_log_groups "/soca/${EDH_CLUSTER_NAME}/"
# Vended-log delivery groups (API Gateway access logs, Step Functions, and any
# future service). These MUST live under the AWS-reserved /aws/vendedlogs/
# prefix (CloudWatch Logs auto-authorizes service delivery there), and EDH names
# them cluster-first as /aws/vendedlogs/<cluster>/<service>/<thing>, so this
# single cluster-scoped prefix cleans them all.
delete_cluster_log_groups "/aws/vendedlogs/${EDH_CLUSTER_NAME}/"
# Lambda DEFAULT log groups (/aws/lambda/<cluster>-<fn>). EDH-owned Lambdas now
# use custom /edh/<cluster>/ groups, but CDK-generated helper/provider Lambdas
# (and legacy-cluster functions) still land here under the flat <cluster>-<fn>
# naming; the trailing '-' keeps the prefix cluster-safe (edh-gw1 won't match
# edh-gw1rc5-).
delete_cluster_log_groups "/aws/lambda/${EDH_CLUSTER_NAME}-"

# Delete VPC Endpoints for GuardDuty only if the VPC was created by eDH
echo "============  Delete VPC Endpoint automatically ============ "
GUARDDUTY_SERVICE_NAME="com.amazonaws.${EDH_DEPLOYMENT_REGION}.guardduty-data"

# Fetch the VPC ID associated with the given VPC name
VPC_ID=$(aws ec2 describe-vpcs --region ${EDH_DEPLOYMENT_REGION}  \
    --filters "Name=tag:Name,Values=${EDH_CLUSTER_NAME}-VPC" \
    --query "Vpcs[*].VpcId" \
    --output text)

# Check if the VPC exists
if [[ -z "$VPC_ID" ]]; then
    echo "No VPC found with the name: $VPC_NAME"
else
    # Fetch the VPC endpoint ID for GuardDuty
    VPC_ENDPOINT_ID=$(aws ec2 describe-vpc-endpoints --region ${EDH_DEPLOYMENT_REGION}  \
        --filters "Name=service-name,Values=${GUARDDUTY_SERVICE_NAME}" "Name=vpc-id,Values=${VPC_ID}" \
        --query "VpcEndpoints[*].VpcEndpointId" \
        --output text)

    # Check if the VPC endpoint exists
    if [[ -z "$VPC_ENDPOINT_ID" ]]; then
        echo "No VPC endpoint found for service: ${GUARDDUTY_SERVICE_NAME}"
    else
        echo "Found VPC endpoint: $VPC_ENDPOINT_ID"
        # Delete the VPC endpoint
        aws ec2 delete-vpc-endpoints --region ${EDH_DEPLOYMENT_REGION} --vpc-endpoint-ids "$VPC_ENDPOINT_ID"  &> /dev/null

        if [[ $? -eq 0 ]]; then
            echo "Successfully deleted VPC endpoint: $VPC_ENDPOINT_ID"
        else
            echo "Failed to delete VPC endpoint: $VPC_ENDPOINT_ID"
            exit 1
        fi
    fi
fi


# Delete NAT Gateways only if the VPC was created by eDH
echo "============ Delete NAT Gateways ============"
if [[ -z "$VPC_ID" ]]; then
    echo "No VPC found, skipping NAT Gateway deletion."
else
    NAT_GATEWAY_IDS=$(aws ec2 describe-nat-gateways --region ${EDH_DEPLOYMENT_REGION} \
        --filter "Name=vpc-id,Values=${VPC_ID}" "Name=state,Values=available" \
        --query "NatGateways[*].NatGatewayId" \
        --output text)

    if [[ -z "$NAT_GATEWAY_IDS" ]]; then
        echo "No NAT Gateways found in VPC: ${VPC_ID}"
    else
        for NAT_GW_ID in ${NAT_GATEWAY_IDS}; do
            echo "Deleting NAT Gateway: ${NAT_GW_ID}"
            aws ec2 delete-nat-gateway --region ${EDH_DEPLOYMENT_REGION} --nat-gateway-id "${NAT_GW_ID}" &> /dev/null
            if [[ $? -eq 0 ]]; then
                echo "Successfully deleted NAT Gateway: ${NAT_GW_ID}"
            else
                echo "Failed to delete NAT Gateway: ${NAT_GW_ID}"
            fi
        done

        # Wait for all NAT Gateways to reach 'deleted' state
        for NAT_GW_ID in ${NAT_GATEWAY_IDS}; do
            echo "Waiting for NAT Gateway ${NAT_GW_ID} to be deleted..."
            for i in $(seq 1 60); do
                STATE=$(aws ec2 describe-nat-gateways --region "${EDH_DEPLOYMENT_REGION}" \
                    --nat-gateway-ids "${NAT_GW_ID}" \
                    --query "NatGateways[0].State" --output text 2>/dev/null)
                if [[ "${STATE}" == "deleted" ]]; then
                    echo "NAT Gateway ${NAT_GW_ID} deleted."
                    break
                fi
                sleep 5
            done
        done
    fi
fi


echo "============ Releasing Elastic IPs ============"
EIP_ALLOCATIONS=$(aws ec2 describe-addresses --region "${EDH_DEPLOYMENT_REGION}" \
    --filters "Name=tag:edh:ClusterId,Values=${EDH_CLUSTER_NAME}" \
    --query "Addresses[*].[AllocationId,PublicIp,AssociationId]" \
    --output text)

if [[ -z "${EIP_ALLOCATIONS}" ]]; then
    echo "No Elastic IPs found with tag edh:ClusterId=${EDH_CLUSTER_NAME}"
else
    while read -r ALLOC_ID PUBLIC_IP ASSOC_ID; do
        if [[ -n "${ASSOC_ID}" && "${ASSOC_ID}" != "None" ]]; then
            echo "Disassociating EIP ${PUBLIC_IP} (${ASSOC_ID})"
            aws ec2 disassociate-address --region "${EDH_DEPLOYMENT_REGION}" --association-id "${ASSOC_ID}"
        fi
        echo "Releasing Elastic IP: ${PUBLIC_IP} (${ALLOC_ID})"
        if aws ec2 release-address --region "${EDH_DEPLOYMENT_REGION}" --allocation-id "${ALLOC_ID}"; then
            echo "Successfully released Elastic IP: ${PUBLIC_IP}"
        else
            echo "Failed to release Elastic IP: ${PUBLIC_IP}"
        fi
    done <<< "${EIP_ALLOCATIONS}"
fi


echo "============ Deleting CloudFormation stacks associated to this cluster ============"
EDH_STACKS=$(aws cloudformation describe-stacks --region "${EDH_DEPLOYMENT_REGION}" \
    --query "Stacks[?contains(Tags[?Key=='edh:ClusterId'].Value, '${EDH_CLUSTER_NAME}')]" \
    --output json)

echo "${EDH_STACKS}" | jq -c '.[]' | while read -r STACK; do
    STACK_NAME=$(echo "${STACK}" | jq -r '.StackName')
    echo "Processing ${STACK_NAME}"

    if [[ "${STACK_NAME}" == "CDKToolkit" ]] || [[ "${STACK_NAME}" == "${EDH_CLUSTER_NAME}" ]]; then
        echo "Skipping stack: ${STACK_NAME}"
    else
        echo "Deleting stack: ${STACK_NAME}"
        aws cloudformation delete-stack --region "${EDH_DEPLOYMENT_REGION}" --stack-name "${STACK_NAME}"
    fi
done


echo "============ Removing Termination Protection ============"

echo "Remove deletion protection for Aurora DB cluster"
AURORA_CLUSTER_ID=$(aws rds describe-db-clusters --region "${EDH_DEPLOYMENT_REGION}" \
    --query "DBClusters[?contains(TagList[?Key=='edh:ClusterId'].Value, '${EDH_CLUSTER_NAME}')].DBClusterIdentifier | [0]" \
    --output text)

if [[ -z "${AURORA_CLUSTER_ID}" || "${AURORA_CLUSTER_ID}" == "None" ]]; then
    echo "No Aurora DB cluster found with tag edh:ClusterId=${EDH_CLUSTER_NAME}"
else
    echo "Disabling deletion protection for Aurora cluster: ${AURORA_CLUSTER_ID}"
    aws rds modify-db-cluster --region "${EDH_DEPLOYMENT_REGION}" \
        --db-cluster-identifier "${AURORA_CLUSTER_ID}" \
        --no-deletion-protection \
        --apply-immediately &> /dev/null
fi

echo "Remove termination protection for NLB"
NLB_NAME="${EDH_CLUSTER_NAME}-nlb"
NLB_ARN=$(aws elbv2 describe-load-balancers --region "${EDH_DEPLOYMENT_REGION}" \
    --names "${NLB_NAME}" \
    --query "LoadBalancers[0].LoadBalancerArn" \
    --output text 2>/dev/null)

if [[ -z "${NLB_ARN}" || "${NLB_ARN}" == "None" ]]; then
    echo "No NLB found with the name: ${NLB_NAME}"
else
    echo "Disabling termination protection for ${NLB_ARN}"
    aws elbv2 modify-load-balancer-attributes --region "${EDH_DEPLOYMENT_REGION}" \
        --load-balancer-arn "${NLB_ARN}" \
        --attributes "Key=deletion_protection.enabled,Value=false" &> /dev/null
fi

echo "Remove termination protection for the main CloudFormation stack"
aws cloudformation update-termination-protection --region "${EDH_DEPLOYMENT_REGION}" \
    --stack-name "${EDH_CLUSTER_NAME}" \
    --no-enable-termination-protection &> /dev/null


echo "============ Deleting Auto Scaling Groups ============"
ASG_NAMES=$(aws autoscaling describe-auto-scaling-groups --region "${EDH_DEPLOYMENT_REGION}" \
    --query "AutoScalingGroups[?contains(Tags[?Key=='edh:ClusterId'].Value, '${EDH_CLUSTER_NAME}')].AutoScalingGroupName" \
    --output text)

if [[ -z "${ASG_NAMES}" ]]; then
    echo "No Auto Scaling Groups found with tag edh:ClusterId=${EDH_CLUSTER_NAME}"
else
    for ASG_NAME in ${ASG_NAMES}; do
        echo "Deleting Auto Scaling Group: ${ASG_NAME}"
        aws autoscaling delete-auto-scaling-group --region "${EDH_DEPLOYMENT_REGION}" \
            --auto-scaling-group-name "${ASG_NAME}" \
            --force-delete &> /dev/null
        if [[ $? -eq 0 ]]; then
            echo "Successfully deleted Auto Scaling Group: ${ASG_NAME}"
        else
            echo "Failed to delete Auto Scaling Group: ${ASG_NAME}"
        fi
    done
fi

echo "============ Deleting Secrets ============"
SECRET_ARNS=$(aws secretsmanager list-secrets --region "${EDH_DEPLOYMENT_REGION}" \
    --filters "Key=tag-key,Values=edh:ClusterId" "Key=tag-value,Values=${EDH_CLUSTER_NAME}" \
    --query "SecretList[*].ARN" \
    --output text)

if [[ -z "${SECRET_ARNS}" ]]; then
    echo "No secrets found with tag edh:ClusterId=${EDH_CLUSTER_NAME}"
else
    for SECRET_ARN in ${SECRET_ARNS}; do
        echo "Deleting secret: ${SECRET_ARN}"
        aws secretsmanager delete-secret --region "${EDH_DEPLOYMENT_REGION}" \
            --secret-id "${SECRET_ARN}" \
            --force-delete-without-recovery &> /dev/null
        if [[ $? -eq 0 ]]; then
            echo "Successfully deleted secret: ${SECRET_ARN}"
        else
            echo "Failed to delete secret: ${SECRET_ARN}"
        fi
    done
fi

echo "============ Deleting DynamoDB Tables ============"
TAGGED_TABLES=$(aws resourcegroupstaggingapi get-resources --region "${EDH_DEPLOYMENT_REGION}" \
    --resource-type-filters "dynamodb:table" \
    --tag-filters "Key=edh:ClusterId,Values=${EDH_CLUSTER_NAME}" \
    --query "ResourceTagMappingList[*].ResourceARN" \
    --output text)

PREFIX_TABLES=$(aws dynamodb list-tables --region "${EDH_DEPLOYMENT_REGION}" \
    --query "TableNames[?starts_with(@, '${EDH_CLUSTER_NAME}.dcv-broker.')]" \
    --output text)

DDB_TABLES=""
if [[ -n "${TAGGED_TABLES}" ]]; then
    for ARN in ${TAGGED_TABLES}; do
        TABLE_NAME="${ARN##*/}"
        DDB_TABLES="${DDB_TABLES} ${TABLE_NAME}"
    done
fi
if [[ -n "${PREFIX_TABLES}" ]]; then
    DDB_TABLES="${DDB_TABLES} ${PREFIX_TABLES}"
fi

DDB_TABLES=$(echo "${DDB_TABLES}" | tr ' ' '\n' | sort -u | tr '\n' ' ')

if [[ -z "$(echo "${DDB_TABLES}" | tr -d ' ')" ]]; then
    echo "No DynamoDB tables found for cluster ${EDH_CLUSTER_NAME}"
else
    for TABLE_NAME in ${DDB_TABLES}; do
        echo "Deleting DynamoDB table: ${TABLE_NAME}"
        aws dynamodb delete-table --region "${EDH_DEPLOYMENT_REGION}" \
            --table-name "${TABLE_NAME}" &> /dev/null
        if [[ $? -eq 0 ]]; then
            echo "Successfully deleted DynamoDB table: ${TABLE_NAME}"
        else
            echo "Failed to delete DynamoDB table: ${TABLE_NAME}"
        fi
    done
fi

echo "============ Deleting CloudFormation Stack ${EDH_CLUSTER_NAME} ============"
if confirm "This will permanently delete your EDH environment ${EDH_CLUSTER_NAME}. This action cannot be undone."; then
    aws cloudformation delete-stack --region "${EDH_DEPLOYMENT_REGION}" --stack-name "${EDH_CLUSTER_NAME}"
fi

echo "============ Deleting S3 Data ============"
if confirm "This will permanently delete all data at s3://${EDH_BUCKET_NAME}/${EDH_CLUSTER_NAME}/. This action cannot be undone."; then
    echo "Deleting s3://${EDH_BUCKET_NAME}/${EDH_CLUSTER_NAME}/"
    aws s3 rm "s3://${EDH_BUCKET_NAME}/${EDH_CLUSTER_NAME}/" --recursive
fi
