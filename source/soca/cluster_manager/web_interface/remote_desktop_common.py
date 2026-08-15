######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import logging
from utils.config import SocaConfig
import utils.aws.boto3_wrapper as utils_boto3
from models import VirtualDesktopSessions
import config

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def max_concurrent_desktop_limit_reached(os_family: str, session_owner: str) -> bool:
    """
    Return True if the user can launch a virtual desktop, assuming user has not already reached the max number of VDI associated to his/her profile
    """

    logger.debug(
        f"Validating if {session_owner} has not reached the number of max session"
    )

    _max_dcv_session_count = (
        config.Config.DCV_LINUX_SESSION_COUNT
        if os_family == "linux"
        else config.Config.DCV_WINDOWS_SESSION_COUNT
    )
    logger.debug(f"Max DCV Session Count: {_max_dcv_session_count} for {os_family}")

    _find_live_session = VirtualDesktopSessions.query.filter(
        VirtualDesktopSessions.is_active == True,
        VirtualDesktopSessions.os_family == os_family,
        VirtualDesktopSessions.session_owner == session_owner,
    ).count()

    logger.debug(f"Found {_find_live_session} active session(s) for {os_family}")

    if _find_live_session >= _max_dcv_session_count:
        return True
    else:
        return False


def generate_default_dcv_amis() -> dict:
    logger.debug(f"Generating generate_default_dcv_amis list")

    # Retrieve CustomAMIMap
    _get_all_soca_base_os = (
        SocaConfig(key="/configuration/CustomAMIMap")
        .get_value(return_as=dict)
        .get("message")
    )
    # Remove Empty
    _get_non_empty_soca_base_os = {
        arch: {k: v for k, v in ami_dict.items() if v}
        for arch, ami_dict in _get_all_soca_base_os.items()
    }

    _supported_dcv_base_os = config.Config.DCV_BASE_OS.keys()
    for arch in _get_non_empty_soca_base_os:
        distros_to_remove = []

        for _distro in _get_non_empty_soca_base_os[arch].keys():
            if _distro not in _supported_dcv_base_os:
                logger.debug(
                    f"Removing {_distro} from the list of default DCV AMIs as it is not supported"
                )
                distros_to_remove.append(_distro)

        # Remove after iteration
        for _distro in distros_to_remove:
            del _get_non_empty_soca_base_os[arch][_distro]

    return _get_non_empty_soca_base_os


def get_arch_for_instance_type(instancetype: str) -> str:
    """
    Return the architecture of the given instance type
    """
    logger.debug(f"Retrieving architecture for instance type: {instancetype}")
    _found_arch = None
    _resp = client_ec2.describe_instance_types(InstanceTypes=[instancetype])
    _instance_info = _resp.get("InstanceTypes", {})
    for _i in _instance_info:
        _instance_name = _i.get("InstanceType", None)
        # This shouldn't happen with an exact-match search
        if _instance_name != instancetype:
            continue

        _proc_info = _i.get("ProcessorInfo", {})
        if _proc_info:
            _arch = sorted(_proc_info.get("SupportedArchitectures", []))
            _found_arch = _arch[0]

    return _found_arch
