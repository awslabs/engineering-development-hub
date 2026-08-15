# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Golden Image Sysprep Engine.

Verifies whether a Windows AMI has been sysprepped, and if not,
auto-runs EC2Launch sysprep on a throwaway instance, then captures
a new (sysprepped) AMI.

Linux images skip this entirely.

Flow:
  1. Launch m7i-flex.large from the AMI in a private subnet (SSM-managed)
  2. Wait for SSM to report the instance as managed (~60s)
  3. SSM RunCommand: check Sysprep_succeeded.tag
  4a. If sysprepped → terminate instance, return original AMI
  4b. If NOT sysprepped → SSM RunCommand: EC2Launch sysprep --shutdown
      → wait for instance to stop → CreateImage → terminate → return new AMI
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

import utils.aws.boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.config import SocaConfig
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

_SYSPREP_RUN_COMMAND = (
    '& "C:\\ProgramData\\Amazon\\EC2Launch\\EC2Launch.exe" sysprep --shutdown'
)

# Default timeouts (seconds). Overridable via SocaConfig keys under
# /configuration/GoldenImage/Sysprep/*. Customers with large images
# (200+ GB, heavy installed software) may need to increase these
# significantly beyond the defaults.
_DEFAULT_SSM_WAIT_TIMEOUT = 600
_DEFAULT_IMAGE_WAIT_TIMEOUT = 3600
_DEFAULT_STOP_WAIT_TIMEOUT = 1200
_POLL_INTERVAL = 15


def _get_timeout(config_key: str, default: int) -> int:
    """Read a timeout value from SocaConfig, falling back to default."""
    try:
        _val = SocaConfig(key=config_key).get_value().get("message")
        if _val:
            _c = SocaCastEngine(_val).cast_as(expected_type=int)
            if _c.get("success") is True:
                return _c.get("message")
    except Exception:
        pass
    return default


def _ssm_wait_timeout() -> int:
    return _get_timeout("/configuration/GoldenImage/Windows/Sysprep/SsmWaitTimeout", _DEFAULT_SSM_WAIT_TIMEOUT)


def _image_wait_timeout() -> int:
    return _get_timeout("/configuration/GoldenImage/Windows/Sysprep/ImageWaitTimeout", _DEFAULT_IMAGE_WAIT_TIMEOUT)


def _stop_wait_timeout() -> int:
    return _get_timeout("/configuration/GoldenImage/Windows/Sysprep/StopWaitTimeout", _DEFAULT_STOP_WAIT_TIMEOUT)


@dataclass
class SysprepResult:
    """Result of the sysprep verification/execution."""
    success: bool
    ami_id: str  # final AMI to publish (original or newly created)
    status: str  # verified_clean | auto_sysprepped | error
    message: str = ""


def verify_and_sysprep(ami_id: str, os_family: str) -> SocaResponse:
    """Main entry point. Returns a SocaResponse whose message carries
    {ami_id, status, detail} -- the AMI to publish and the sysprep status.

    For Linux: immediately returns status=skipped_linux with the original AMI.
    For Windows: launches a throwaway, checks sysprep state, auto-runs if needed.
    """
    if os_family != "windows":
        return SocaResponse(
            success=True,
            message={
                "ami_id": ami_id,
                "status": "skipped_linux",
                "detail": "Linux images do not require sysprep",
            },
        )

    try:
        _r = _windows_sysprep_flow(ami_id)
    except Exception as err:
        logger.error(f"Sysprep engine error for {ami_id}: {err}")
        return SocaResponse(
            success=False,
            message={"ami_id": ami_id, "status": "error", "detail": str(err)},
        )
    return SocaResponse(
        success=_r.success,
        message={"ami_id": _r.ami_id, "status": _r.status, "detail": _r.message},
    )


def _windows_sysprep_flow(ami_id: str) -> SysprepResult:
    """Run the full sysprep check/execute flow for a Windows AMI."""
    _resp_ec2 = utils_boto3.get_boto(service_name="ec2")
    if not _resp_ec2.get("success"):
        raise RuntimeError("Failed to get boto3 ec2 client")
    client_ec2 = _resp_ec2.get("message")
    _resp_ssm = utils_boto3.get_boto(service_name="ssm")
    if not _resp_ssm.get("success"):
        raise RuntimeError("Failed to get boto3 ssm client")
    client_ssm = _resp_ssm.get("message")

    # Resolve infrastructure parameters
    _subnet_id = _get_private_subnet()
    _instance_profile_arn = _get_instance_profile_arn()
    _security_group_id = _get_controller_sg()

    if not _subnet_id or not _instance_profile_arn:
        return SysprepResult(
            success=False,
            ami_id=ami_id,
            status="error",
            message="Cannot resolve subnet or instance profile for sysprep verification",
        )

    instance_id = None
    new_ami_id = None
    try:
        # Step 1: Launch throwaway instance
        instance_id = _launch_throwaway(
            client_ec2, ami_id, _subnet_id, _instance_profile_arn, _security_group_id
        )
        logger.info(f"Sysprep engine: launched throwaway {instance_id} from {ami_id}")

        # Step 2: Wait for SSM
        _wait_for_ssm(client_ssm, instance_id)
        logger.info(f"Sysprep engine: SSM online for {instance_id}")

        # Step 3: Always sysprep (boot de-generalizes; detection can't prove sealed).
        logger.info(f"Sysprep engine: running EC2Launch sysprep on {instance_id}")
        _run_sysprep(client_ssm, client_ec2, instance_id)

        # Step 5: Wait for instance to stop (EC2Launch shuts down after sysprep)
        _wait_for_stopped(client_ec2, instance_id)
        logger.info(f"Sysprep engine: {instance_id} stopped after sysprep")

        # Step 6: CreateImage from the stopped instance
        new_ami_id = _create_image(client_ec2, instance_id, ami_id)
        logger.info(f"Sysprep engine: created sysprepped AMI {new_ami_id}")

        # Step 7: Wait for AMI to become available
        _wait_for_image(client_ec2, new_ami_id)

        # Step 8: Terminate
        _terminate_instance(client_ec2, instance_id)

        return SysprepResult(
            success=True,
            ami_id=new_ami_id,
            status="auto_sysprepped",
            message=f"Auto-sysprepped: new AMI {new_ami_id} (source: {ami_id})",
        )

    except Exception as err:
        # Best-effort cleanup: deregister orphaned AMI + delete backing snapshots
        if new_ami_id:
            try:
                _imgs = client_ec2.describe_images(ImageIds=[new_ami_id])
                _snap_ids = [
                    bdm["Ebs"]["SnapshotId"]
                    for bdm in _imgs["Images"][0].get("BlockDeviceMappings", [])
                    if "Ebs" in bdm and "SnapshotId" in bdm["Ebs"]
                ]
                client_ec2.deregister_image(ImageId=new_ami_id)
                logger.warning(f"Sysprep engine: deregistered orphaned AMI {new_ami_id}")
                for _sid in _snap_ids:
                    try:
                        client_ec2.delete_snapshot(SnapshotId=_sid)
                        logger.warning(f"Sysprep engine: deleted orphan snapshot {_sid}")
                    except Exception:
                        logger.warning(f"Sysprep engine: failed to delete snapshot {_sid}")
            except Exception:
                logger.warning(f"Sysprep engine: failed to cleanup orphaned AMI {new_ami_id}")
        if instance_id:
            try:
                _terminate_instance(client_ec2, instance_id)
            except Exception:
                pass
        raise


def _get_private_subnet() -> Optional[str]:
    """First private subnet from cluster config (stored as a list, not CSV)."""
    try:
        _r = SocaConfig(key="/configuration/PrivateSubnets").get_value(return_as=list)
        _subnets = _r.get("message") if _r.get("success") is True else None
        if _subnets:
            _c = SocaCastEngine(_subnets[0]).cast_as(expected_type=str)
            return _c.get("message", "").strip() if _c.get("success") is True else None
    except Exception:
        pass
    return None


def _get_instance_profile_arn() -> Optional[str]:
    """Get the VDI node instance profile ARN."""
    try:
        return SocaConfig(key="/configuration/VdiNodeInstanceProfileArn").get_value().get("message")
    except Exception:
        pass
    return None


def _get_controller_sg() -> Optional[str]:
    """Get the controller security group (allows SSM + internal traffic)."""
    try:
        return SocaConfig(key="/configuration/ControllerSecurityGroup").get_value().get("message")
    except Exception:
        pass
    return None


def _launch_throwaway(client_ec2, ami_id: str, subnet_id: str,
                      instance_profile_arn: str, security_group_id: Optional[str]) -> str:
    """Launch a m7i-flex.large throwaway instance from the AMI."""
    _params = {
        "ImageId": ami_id,
        "InstanceType": "m7i-flex.large",
        "MinCount": 1,
        "MaxCount": 1,
        "SubnetId": subnet_id,
        "IamInstanceProfile": {"Arn": instance_profile_arn},
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "edh-sysprep-verify"},
                    {"Key": "edh:Purpose", "Value": "sysprep-verification"},
                    {"Key": "edh:Ephemeral", "Value": "true"},
                ],
            }
        ],
        "InstanceInitiatedShutdownBehavior": "stop",
    }
    if security_group_id:
        _params["SecurityGroupIds"] = [security_group_id]

    _response = client_ec2.run_instances(**_params)
    return _response["Instances"][0]["InstanceId"]


def _wait_for_ssm(client_ssm, instance_id: str):
    """Wait until SSM reports the instance as managed."""
    _deadline = time.time() + _ssm_wait_timeout()
    while time.time() < _deadline:
        try:
            _resp = client_ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            if _resp.get("InstanceInformationList"):
                _info = _resp["InstanceInformationList"][0]
                if _info.get("PingStatus") == "Online":
                    return
        except Exception:
            pass
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"SSM did not come online for {instance_id} within timeout")


def _run_sysprep(client_ssm, client_ec2, instance_id: str):
    """Run EC2Launch sysprep --shutdown; fail fast if the command errors while still running."""
    _resp = client_ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={"commands": [_SYSPREP_RUN_COMMAND]},
        TimeoutSeconds=300,
    )
    _command_id = _resp["Command"]["CommandId"]
    _deadline = time.time() + 120
    while time.time() < _deadline:
        time.sleep(5)
        try:
            _inv = client_ssm.get_command_invocation(CommandId=_command_id, InstanceId=instance_id)
        except client_ssm.exceptions.InvocationDoesNotExist:
            continue
        _status = _inv["Status"]
        _state = client_ec2.describe_instances(
            InstanceIds=[instance_id]
        )["Reservations"][0]["Instances"][0]["State"]["Name"]
        # Box shutting down (or command Success) means sysprep took hold.
        if _state in ("stopping", "stopped") or _status == "Success":
            return
        if _status in ("Failed", "Cancelled", "TimedOut"):
            raise RuntimeError(
                f"Sysprep command failed: {_inv.get('StandardErrorContent') or _inv.get('StatusDetails')}"
            )
    return


def _wait_for_stopped(client_ec2, instance_id: str):
    """Wait for the instance to reach 'stopped' state."""
    _deadline = time.time() + _stop_wait_timeout()
    while time.time() < _deadline:
        _resp = client_ec2.describe_instances(InstanceIds=[instance_id])
        _state = _resp["Reservations"][0]["Instances"][0]["State"]["Name"]
        if _state == "stopped":
            return
        if _state in ("terminated", "shutting-down"):
            raise RuntimeError(f"Instance {instance_id} terminated unexpectedly during sysprep")
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"Instance {instance_id} did not stop within timeout")


def _create_image(client_ec2, instance_id: str, source_ami_id: str) -> str:
    """Create an AMI from the stopped (sysprepped) instance."""
    _name = f"edh-golden-sysprepped-{int(time.time())}"
    _resp = client_ec2.create_image(
        InstanceId=instance_id,
        Name=_name,
        Description=f"Auto-sysprepped golden image (source: {source_ami_id})",
        NoReboot=True,
        TagSpecifications=[
            {
                "ResourceType": "image",
                "Tags": [
                    {"Key": "Name", "Value": _name},
                    {"Key": "edh:GoldenImage", "Value": "true"},
                    {"Key": "edh:SourceAmi", "Value": source_ami_id},
                    {"Key": "edh:SysprepStatus", "Value": "auto_sysprepped"},
                ],
            }
        ],
    )
    return _resp["ImageId"]


def _wait_for_image(client_ec2, ami_id: str):
    """Wait for the AMI to become available."""
    _deadline = time.time() + _image_wait_timeout()
    while time.time() < _deadline:
        _resp = client_ec2.describe_images(ImageIds=[ami_id])
        _state = _resp["Images"][0]["State"]
        if _state == "available":
            return
        if _state == "failed":
            raise RuntimeError(f"AMI {ami_id} creation failed")
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"AMI {ami_id} did not become available within timeout")


def _terminate_instance(client_ec2, instance_id: str):
    """Terminate the throwaway instance."""
    client_ec2.terminate_instances(InstanceIds=[instance_id])
    logger.info(f"Sysprep engine: terminated throwaway {instance_id}")
