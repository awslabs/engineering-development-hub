# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0  

from enum import Enum


class SocaLinuxBaseOS(str, Enum):
    AMAZON_LINUX_2 = "amazonlinux2"
    AMAZON_LINUX_2023 = "amazonlinux2023"
    AMAZON_LINUX_2027 = "amazonlinux2027"
    RHEL_8 = "rhel8"
    RHEL_9 = "rhel9"
    ROCKY_8 = "rocky8"
    ROCKY_9 = "rocky9"
    UBUNTU_22_04 = "ubuntu2204"
    UBUNTU_24_04 = "ubuntu2404"
   
    # Note: Legacy BaseOS
    # RHEL_7 = "rhel7"
    # CENTOS_7 = "centos7"


class SocaWindowsBaseOS(str, Enum):
    WINDOWS_SERVER_2019 = "windows2019"
    WINDOWS_SERVER_2022 = "windows2022"
    WINDOWS_SERVER_2025 = "windows2025"