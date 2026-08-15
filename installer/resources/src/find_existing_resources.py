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

import sys
import os
import re

installer_path = "/".join(os.path.dirname(os.path.abspath(__file__)).split("/")[:-3])
sys.path.append(installer_path)
from installer.resources.src.prompt import get_input as get_input
import os
from rich import print
from rich.console import Console
from rich.table import Table
from collections import defaultdict
from helpers.installer.i18n import _

try:
    import boto3
    import ipaddress

except ImportError:
    print(
        "boto3 extension is required. Run 'pip install boto3 ipaddress' and try again"
    )
    sys.exit(1)


class FindExistingResource:
    def __init__(self, region, client_ip):
        self.region = region
        self.client_ip = client_ip
        # Route through the shared-session cache in helpers.boto3_wrapper
        # so credential resolution happens once per profile for the
        # whole installer process. See SOCA_BOTO3_SHARED_SESSION.
        from helpers.boto3_wrapper import get_shared_session
        session = get_shared_session()
        self.ec2 = session.client("ec2", region_name=self.region)
        self.efs = session.client("efs", region_name=self.region)
        self.fsx = session.client("fsx", region_name=self.region)
        self.ds = session.client("ds", region_name=self.region)
        self.es = session.client("es", region_name=self.region)
        self.iam = session.client("iam", region_name=self.region)
        self.pcs = session.client("pcs", region_name=self.region)
        self.sts = session.client("sts", region_name=self.region)
        self.install_parameters = {}
        self.cache = {}
        self.console = Console(record=True)



    def find_vpc(self, address_families: list[str]):
        """
        Find existing VPC in our account and populate some data structures.
        address_families represents the address families that we are interested in.
        """

        # Determine our AccountID

        _sts_caller_identity: dict = self.sts.get_caller_identity()
        _local_account_id: str = _sts_caller_identity.get("Account", "")

        vpc_table = Table(title=f"Select the VPC # in {self.region} region for SOCA deployment", show_lines=True, highlight=True)
        for _col_name in ["#", "VPC ID", "VPC Name", "VPC CIDRs", "Information"]:
            vpc_table.add_column(_col_name, justify="center")

        try:
            vpcs_by_name = {}
            vpc_paginator = self.ec2.get_paginator("describe_vpcs")
            vpc_iterator = vpc_paginator.paginate(
                Filters=[
                    {
                        "Name": "state",
                        "Values": ["available"],
                    },
                ]
            )

            for page in vpc_iterator:
                for vpc in page["Vpcs"]:
                    resource_name: str = vpc.get("VpcId", "")
                    if "Tags" in vpc.keys():
                        for tag in vpc["Tags"]:
                            if tag["Key"] == "Name":
                                resource_name = tag["Value"]
                    # WARNING - This would previously skip unnamed VPCs
                    # which could include the default VPC
                    # Instead - we set the name to the vpcID above just in case
                    if not resource_name:
                        continue
                    vpcs_by_name[resource_name] = vpc
            vpcs = {}
            count = 1
            # List of VPCs that match the required attributes (VPC attributes)
            _vpc_allowed_list: list = []

            for resource_name in sorted(vpcs_by_name):
                vpc = vpcs_by_name[resource_name]

                _pri_ipv4_cidr: str = vpc.get("CidrBlock", "")

                # Retain our discovered CIDRs by AF for later
                _cidr_for_vpc_by_af: dict = {
                    "IP_V4": [],
                    "IP_V6": []
                }

                if vpc.get('CidrBlockAssociationSet', {}):
                    for _association in vpc.get('CidrBlockAssociationSet', {}):
                        if _association.get('CidrBlockState', {}).get('State', 'unknown-state').lower() == 'associated':
                            if _association.get('CidrBlock') == _pri_ipv4_cidr:
                                _cidr_info: str = "(Primary)"
                            else:
                                _cidr_info: str = ""
                            _cidr_for_vpc_by_af["IP_V4"].append(_association.get('CidrBlock'))

                #
                # This should only be considered when enabled for IPv6
                #
                if "ipv6" in address_families and vpc.get('Ipv6CidrBlockAssociationSet', {}):
                    for _association in vpc.get('Ipv6CidrBlockAssociationSet', {}):
                        if _association.get('Ipv6CidrBlockState', {}).get('State', 'unknown-state').lower() == 'associated':
                            _cidr_for_vpc_by_af["IP_V6"].append(_association.get('Ipv6CidrBlock'))

                #
                # Combine our address-family into a single display
                # This won't display IPv6 CIDRs if we are not enabled for IPv6 on the command line
                # This helps to avoid confusion (by showing IPv6 CIDRs if it is disabled)
                #
                _cidr_str: str = '\n'.join([*_cidr_for_vpc_by_af["IP_V4"], *_cidr_for_vpc_by_af["IP_V6"]])

                _info_txt_list: list = []
                _vpc_id_str: str = ""
                if vpc.get("VpcId", ""):
                    _vpc_id_str = vpc.get("VpcId", "")
                # Include some VPC information for easier ident of the VPC
                _vpc_owner_id: str = vpc.get("OwnerId", "")

                # Should we only display this if it is not the account that we are working in?
                if _vpc_owner_id:
                    _vpc_id_str = f"{_vpc_id_str}\nOwner ID: {_vpc_owner_id}"
                    # determine if we are a shared VPC
                    if _local_account_id != _vpc_owner_id:
                        _info_txt_list.append(f"[bold yellow]Shared VPC[/]")
                _vpc_bpa_igw_setting_str: str = vpc.get("BlockPublicAccessStates", {}).get("InternetGatewayBlockMode", "")
                if _vpc_bpa_igw_setting_str:
                    _info_txt_list.append(f"[bold green]IGW-Block Mode: {_vpc_bpa_igw_setting_str}[/]")

                _vpc_default_bool: bool = vpc.get("IsDefault", False)
                if _vpc_default_bool:
                    _info_txt_list.append(f"[bold green]Default VPC[/]")

                _vpc_tenancy_setting_str: str = vpc.get("InstanceTenancy", "")
                if _vpc_tenancy_setting_str:
                    _info_txt_list.append(f"[bold green]Tenancy: {_vpc_tenancy_setting_str}[/]")


                # check VPC for some required attributes
                _vpc_allowed: bool = True
                _vpc_attributes: dict = {
                    "enableDnsSupport": False,
                    "enableDnsHostnames": False,
                }

                for _vpc_attribute in _vpc_attributes:
                    _vpc_cap = _vpc_attribute[0].upper() + _vpc_attribute[1:]  # enableDnsSupport -> EnableDnsSupport (to match JSON values)
                    _vpc_attribute_support: dict = self.ec2.describe_vpc_attribute(
                        VpcId=vpc.get("VpcId", ""),
                        Attribute=_vpc_attribute,
                    )
                    # print(f"DEBUG - Checking VPC for {_vpc_cap} - {_vpc_attribute_support}")
                    _vpc_attributes[_vpc_attribute] = _vpc_attribute_support.get(_vpc_cap, {}).get("Value", False)
                    if not _vpc_attributes[_vpc_attribute]:
                        _info_txt_list.append(f"[bold red]Error-{_vpc_attribute} missing[/]")
                        _vpc_allowed = False

                # print(f"DEBUG VPC CIDR BY AF: {_cidr_for_vpc_by_af=}")

                vpcs[count] = {
                    "id": vpc["VpcId"],
                    "description": f"{resource_name if resource_name else ''} {vpc['VpcId']} {vpc['CidrBlock']}",
                    "cidr": vpc["CidrBlock"],  # This is the primary IP_V4 CIDR only
                    "cidr_ipv6": str(_cidr_for_vpc_by_af["IP_V6"]),  # FIXME TODO
                    # "cidr_by_af": _cidr_for_vpc_by_af,
                    "dns_support":  _vpc_attributes["enableDnsSupport"],
                    "dns_hostnames": _vpc_attributes["enableDnsHostnames"],
                }

                vpc_table.add_row(
        f"[green]{count}[/green]",
                    f"[cyan]{_vpc_id_str}[/cyan]",
                    f"[magenta]{resource_name}[/magenta]",
                    str(_cidr_str),
                    "\n".join(_info_txt_list),
                )

                if _vpc_allowed:
                    _vpc_allowed_list.append(count)

                count += 1

            print(vpc_table)

            # Only allow selection of valid VPCs (that have properly configured VPC attributes)
            if not _vpc_allowed_list:
                print(f"[red]" + _("FATAL ERROR: Unable to locate any valid VPCs in region {region}. Please see the VPC Table for specific errors.").format(region=self.region) + "[default]")
                sys.exit(1)

            allowed_choices = list(_vpc_allowed_list)

            choice = get_input(
                prompt=_(f"Choose the VPC you want to use?"),
                specified_value=None,
                expected_answers=allowed_choices,
                expected_type=int,
                show_expected_answers=True
            )
            return {"success": True, "message": vpcs[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def find_elasticsearch(self, vpc_id):
        try:
            es: dict = {}
            count: int = 1
            # No Paginator support 27 Sep 2024
            for _analytics_cluster in self.es.list_domain_names(EngineType="OpenSearch").get("DomainNames", []):
                _domain_name = _analytics_cluster.get("DomainName", "")
                if not _domain_name:
                    continue

                _domain_info = self.es.describe_elasticsearch_domain(
                    DomainName=_domain_name
                )

                _domain_status: dict = _domain_info.get("DomainStatus", {})

                if not _domain_status:
                    continue

                _domain_created: bool = _domain_status.get("Created", False)
                _domain_deleted: bool = _domain_status.get("Deleted", False)
                _domain_upgrade_processing: bool = _domain_status.get("UpgradeProcessing", False)
                _domain_version: str = _domain_status.get("ElasticsearchVersion", "")

                if _domain_created and not _domain_deleted and not _domain_upgrade_processing:
                    _endpoint = None
                    _domain_vpc: str = _domain_status.get("VPCOptions", {}).get("VPCId", "")

                    # No VPC info
                    if not _domain_vpc:
                        continue

                    # Not our VPC
                    if _domain_vpc != vpc_id:
                        continue

                    for scope, endpoint in _domain_status.get("Endpoints", {}).items():
                        _endpoint = endpoint
                    if not _endpoint:
                        # The domain is not ready for us - no endpoints found
                        continue

                    es[count] = {
                        "name": _domain_name,
                        "engine": _analytics_cluster.get("EngineType", "unknown-engine"),
                        "version": _domain_version,
                        "endpoint": _endpoint
                    }
                    # Only increment the count in the loop for valid domain listings
                    count += 1

            if count <= 0:
                # This happens when you select existing resources but there are none found
                # So we have to error at this stage.
                print(f"[red]" + _("FATAL ERROR: Unable to locate any valid Analytics engines in region {region} - VPC {vpc_id}. Please confirm and try again or re-run and select 'new' to create a new one.").format(region=self.region, vpc_id=vpc_id) + "[default]")
                sys.exit(1)

            print(
                f"\n====== What [misty_rose3]OpenSearch cluster[default] do you want to use? [region: {self.region}, vpc: {vpc_id}] ======\n"
            )

            _opensearch_table = Table(show_header=True, show_lines=True, header_style="bold")
            _opensearch_table.add_column("ID", justify="center")
            _opensearch_table.add_column("Name", justify="center")
            _opensearch_table.add_column("Engine", justify="center")
            _opensearch_table.add_column("Endpoint", justify="center")

            for key, value in es.items():
                _opensearch_table.add_row(
                    str(key),
                    value.get('name'),
                    value.get('version'),
                    value.get('endpoint')
                )
                # print(f"    {key} > {value.get('name')} ({value.get('engine')}) via {value.get('endpoint')}")

            print(_opensearch_table)

            allowed_choices = list(es.keys())
            choice = get_input(
                prompt=_(f"Choose the OpenSearch Cluster you want to use?"),
                specified_value=None,
                expected_answers=allowed_choices,
                expected_type=int,
                show_expected_answers=False,
            )

            return {"success": True, "message": es[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def find_directory_services(self, vpc_id):
        try:
            print(
                f"\n====== What [misty_rose3]Directory Services (Microsoft AD)[default] do you want to use? [region: {self.region}, vpc: {vpc_id}] ======\n"
            )
            ds = {}

            count = 1

            ds_paginator = self.ds.get_paginator("describe_directories")
            ds_iterator = ds_paginator.paginate()
            for page in ds_iterator:
                for directory in page["DirectoryDescriptions"]:
                    # skip directories in flux
                    if directory.get("Stage", "unknown-stage").upper() not in {
                        "ACTIVE"
                    }:
                        continue

                    if directory["VpcSettings"]["VpcId"] == vpc_id:
                        ds[count] = {
                            "id": directory["DirectoryId"],
                            "name": directory["Name"],
                            "netbios": directory["ShortName"],
                            "dns": directory["DnsIpAddrs"],
                            "description": f"{directory['Name']} (Domain: {directory['ShortName']}, Id: {directory['DirectoryId']})",
                        }
                        count += 1
            [
                print("    {:2} > {}".format(key, value["description"]))
                for key, value in ds.items()
            ]
            allowed_choices = list(ds.keys())
            choice = get_input(
                _(f"Choose the directory you want to use?"), None, allowed_choices, int
            )
            return {"success": True, "message": ds[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_subnets(self, vpc_id: str, environment: str, selected_subnets=None, address_families=list[str]):
        """
        Get the subnets in a given VPC.
        Can use address_families to filter the display based on the subnet address family
        """


        subnet_table = Table(
            title=f"Select Subnet # in {self.region} / VPC {vpc_id} for SOCA deployment",
            show_lines=True,
            highlight=True
        )

        for _col_name in ('#', 'Subnet ID', 'Name', 'CIDRs', 'Availability Zone', 'Features'):
            subnet_table.add_column(_col_name, justify="center")

        if selected_subnets is None:
            selected_subnets = []
        try:
            if environment == "private":
                print(
                    f"\n====== Select [misty_rose3]3 subnets to use for your compute nodes (private subnets preferably) [default] ======\n"
                )
            else:
                print(
                    f"\n====== Select [misty_rose3]3 subnets to use for the main Scheduler and Load Balancer (public subnets preferably) [default] ======\n"
                )

            subnets_by_name = {}
            subnet_paginator = self.ec2.get_paginator("describe_subnets")
            subnet_iterator = subnet_paginator.paginate(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    },
                    #
                    # Eventually this filter needs to be removed
                    # for IPv6-only subnets
                    {
                        "Name": "ipv6-native",
                        "Values": ["false"]
                    },
                    {
                        "Name": "state",
                        "Values": ["available"],
                    },
                ]
            )
            for page in subnet_iterator:
                for subnet in page.get("Subnets", []):
                    _subnet_id: str = subnet.get("SubnetId", "")
                    _subnet_name: str = _subnet_id
                    if "Tags" in subnet.keys():
                        for _tag in subnet["Tags"]:
                            if _tag["Key"] == "Name":
                                _subnet_name = _tag["Value"]
                                break
                    if not _subnet_id:
                        continue
                    # This inserts a quick SubnetName into our dict for sorting purposes later
                    subnet["SubnetName"] = _subnet_name if _subnet_name else _subnet_id
                    subnets_by_name[_subnet_id] = subnet
            subnets = {}
            count = 1

            # print(f"DEBUG: pre-sort: {subnets_by_name=}")
            # Sort subnets so visually-related entries are adjacent in
            # the picker table. Sort keys, in priority order:
            #
            #   1. Numeric-aware (natural) lowercased Name tag --
            #      groups subnets with related names, and orders
            #      numeric suffixes correctly (e.g.
            #      private-1 < private-2 < private-10, not the
            #      lexicographic private-1 < private-10 < private-2).
            #      Falls back to SubnetId when a Name tag is absent.
            #   2. Availability Zone -- within a Name-group, subnets
            #      line up by AZ (us-east-2a, -2b, -2c) for predictable
            #      multi-AZ selection.
            #   3. SubnetId -- final tie-breaker so the order is stable
            #      across picker invocations even with duplicate names
            #      and AZs.
            #
            # The natural-sort key is produced by splitting the name on
            # runs of digits and converting digit runs to int; this is
            # the standard "zero-dep natsort" idiom and avoids adding
            # the `natsort` library as an installer dependency.
            def _natural_key(_name: str) -> list:
                return [
                    int(_part) if _part.isdigit() else _part.lower()
                    for _part in re.split(r"(\d+)", _name)
                ]

            subnets_by_name: dict = dict(
                sorted(
                    subnets_by_name.items(),
                    key=lambda _sn: (
                        _natural_key(_sn[1].get("SubnetName") or _sn[0]),
                        _sn[1].get("AvailabilityZone", ""),
                        _sn[0],
                    ),
                )
            )
            # print(f"DEBUG: post-sorting subnets_by_name: {subnets_by_name=}")

            for resource_name in subnets_by_name:
                subnet = subnets_by_name[resource_name]

                # What should we list as the Name?
                # Name tag is pref - but fallback to the ID if needed
                _subnet_name: str = resource_name
                if "Tags" in subnet.keys():
                    for _tag in subnet["Tags"]:
                        if _tag["Key"] == "Name":
                            print(f"Found a Name tag for a subnet: {resource_name} - {_tag['Value']}")
                            _subnet_name = _tag["Value"]

                if (
                    f"{subnet['SubnetId']},{subnet['AvailabilityZone']}"
                    not in selected_subnets
                ):

                    # Collect some metadata on the subnet
                    _available_ips = subnet.get("AvailableIpAddressCount", 0)

                    is_default = True if subnet.get("DefaultForAz", False) else False

                    outpost_arn = subnet.get("OutpostArn", "")
                    is_outpost = True if outpost_arn else False
                    outpost_str = f"Outpost" if is_outpost else ""

                    # Collect IPv6 CIDR
                    _ipv6_cidrs: list = []
                    if "ipv6" in address_families:
                        for association in subnet.get("Ipv6CidrBlockAssociationSet", []):
                            if association.get("Ipv6CidrBlockState", {}).get("State", "unknown") != "associated":
                                continue
                            _ipv6_cidrs.append(association['Ipv6CidrBlock'])

                    #
                    # Join the string
                    # Without IPv6 enabled - do not display the IPv6 CIDRs to avoid confusion
                    #
                    _ipv6_cidr = "\n".join(_ipv6_cidrs) if len(_ipv6_cidrs) else ""
                    _cidr_str = f"{subnet['CidrBlock']} ({_available_ips} free)\n{_ipv6_cidr}"

                    _owner_str: str = subnet['OwnerId']
                    _az_str: str = f"AZ: {subnet['AvailabilityZone']}\nAZ-ID: {subnet['AvailabilityZoneId']}"
                    subnet_description = f"{resource_name if resource_name else ''} {_cidr_str}, AZ: {_az_str} {outpost_str}"

                    subnets[count] = {
                        "id": subnet["SubnetId"],
                        "availability_zone": subnet["AvailabilityZone"],
                        "availability_zone_id": subnet["AvailabilityZoneId"],
                        "is_outpost": is_outpost,
                        "description": subnet_description,
                    }

                    # Populate some feature notes for the subnet
                    _feature_list: list = []
                    if is_default:
                        _feature_list.append("Default")

                    # Mark subnets where we see SOCA in the name
                    if "soca" in resource_name.lower():
                        _feature_list.append("SOCA")

                    if is_outpost:
                        outpost_arn = outpost_arn.split("/")[1]
                        _feature_list.append(f"Outpost:\n{outpost_arn}")

                    subnet_table.add_row(
                        f"[green]{count}[/green]",
                        f"[cyan]{subnet['SubnetId']}\nOwner: {_owner_str}[/cyan]",
                        f"[magenta]{_subnet_name}[/magenta]",
                        _cidr_str,
                        f"[yellow]{_az_str}[/yellow]",
                        "\n".join(_feature_list),
                    )
                    count += 1

            print(subnet_table)

            selected_subnets_count = get_input(
                prompt=_(f"How many of these subnets do you want to use?"),
                specified_value=None,
                expected_answers=list(range(1, count)),
                expected_type=int,
                show_default_answer=False,
                show_expected_answers=False,
            )
            while selected_subnets_count < 2:
                print(
                    f"[red] You must use at least 2 subnets for high availability [default]"
                )
                selected_subnets_count = get_input(
                    prompt=_(f"How many of these subnets do you want to use?"),
                    specified_value=None,
                    expected_answers=list(range(1, count)),
                    expected_type=int,
                )

            selected_subnets = []
            while len(selected_subnets) != selected_subnets_count:
                allowed_choices = list(subnets.keys())
                if len(allowed_choices) == 0:
                    return {"success": False, "message": f"Not enough subnets available in VPC {vpc_id}"}
                choice = get_input(
                    prompt=_(f"Choose your subnet #{len(selected_subnets) + 1} ?"),
                    specified_value=None,
                    expected_answers=allowed_choices,
                    expected_type=int,
                    show_default_answer=False,
                    show_expected_answers=False
                )

                selected_subnets.append(
                    f"{subnets[choice]['id']},{subnets[choice]['availability_zone']}"
                )
                del subnets[choice]
            return {"success": True, "message": selected_subnets}

        except Exception as err:
            return {"success": False, "message": str(err)}


    def get_fs(self, environment: str, vpc_id: str, filesystems: dict, selected_fs=None) -> dict:

        fs_table = Table(
            title=f"Select the VPC File system for {environment}",
            show_lines=True,
            highlight=True
        )
        # for _col_name in ["#", "Type", "ID", "Name", "Size", "DNSName", "Features"]:
        for _col_name in ["#", "Type", "ID", "Name", "Size", "Features"]:
            fs_table.add_column(_col_name, justify="center")

        # print(f"DEBUG - Filesystems passed to get_fs(): {filesystems}")

        if not filesystems:
            return {"success": False, "message": f"No filesystems found in VPC {vpc_id}"}

        if selected_fs is None:
            selected_fs = []
        # else:
        #     print(f"DEBUG - Selected FSes: {selected_fs}")

        # Make a nice table with the FSes passed to us
        _fs_type_str: str = ''
        for _key, _value in filesystems.items():
            _fs_type = _value["fs_type"]
            _fs_family: str = ''
            _fs_subfamily: str = ''
            # Handle 'fsx_ontap' and 'fsx_openzfs' examples
            if '_' in _fs_type:
                _fs_family, _fs_subfamily = _fs_type.lower().split("_")[0:2]
                # Properly list FSx
                _fs_family = _fs_family.replace("fsx", "FSx")
                _fs_subfamily = _fs_subfamily.replace('lustre', 'Lustre')
                _fs_subfamily = _fs_subfamily.replace('openzfs', 'OpenZFS')
                _fs_subfamily = _fs_subfamily.replace('ontap', 'ONTAP')
            else:
                # efs -> EFS
                _fs_family = _fs_type.upper()
                _fs_subfamily = ''

            _fs_type_str = f"{_fs_family}"
            _fs_type_str += f"/{_fs_subfamily}" if _fs_subfamily else ""

            fs_table.add_row(
                f"[green]{_key}[/green]",
                _fs_type_str,
                _value.get("id", ""),
                _value.get("name", ""),
                _value.get("size", ""),
                # DNSName makes the table span very large
                # _value.get("dns_name", ""),
                _value.get("features", "")
            )

        print(fs_table)

        try:
            print(
                f"\n====== What [misty_rose3]Filesystem[default] do you want to use for [misty_rose3]{environment}[default]? [region: {self.region}, vpc: {vpc_id}]  ======\n"
            )

            count = 1

            allowed_choices = list(filesystems.keys())
            choice = get_input(
                prompt=_(f"Choose the filesystem to use for {environment}?"),
                specified_value=None,
                expected_answers=allowed_choices,
                expected_type=int,
            )

            # Use fully qualified name when we can
            _dns_name: str = filesystems.get(choice).get("dns_name", "")

            return {
                "success": True,
                "message": _dns_name if _dns_name else filesystems[choice]["id"],
                "provider": filesystems[choice]["fs_type"].lower(),
            }

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_security_groups(self, vpc_id: str, environment: str, scheduler_sg=None):
        """
        Present the user with a list of security groups to be used for a particular SOCA role in the cluster.
        """

        _sg_table = Table(title=f"Select the Security Group # in {self.region} region for {environment} role", show_lines=True, highlight=True)
        for _col_name in ["#", "Security Group ID", "Name", "Information"]:
            _sg_table.add_column(_col_name, justify="center")

        if not scheduler_sg:
            scheduler_sg = []

        try:
            # print(
            #     f"\n====== Choose the [misty_rose3]security group to use for the {environment}[default] (Region: {self.region}, VPC {vpc_id}) ======\n"
            # )

            sgs_by_name: dict = {}
            _sg_paginator = self.ec2.get_paginator("describe_security_groups")
            _sg_iterator = _sg_paginator.paginate(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    },
                ]
            )

            for _page in _sg_iterator:
                for _sg in _page.get("SecurityGroups", []):
                    # This is very noisy
                    # print(f"DEBUG - Considering SG: {_sg=}")
                    _resource_name: str = ""
                    if "Tags" in _sg.keys():
                        for _tag in _sg.get("Tags", []):
                            if _tag["Key"] == "Name":
                                _resource_name = _tag.get("Value", "")
                    if not _resource_name:
                        # This simply means there is no Name tag. Default to the ID
                        # so the user can still select it
                        _resource_name = _sg.get('GroupId', "unknown-group-ID")
                        # continue
                    sgs_by_name[_resource_name] = _sg


            # Build up the Table display

            sgs: dict = {}
            count: int = 1
            for _resource_name in sorted(sgs_by_name):
                _sg = sgs_by_name[_resource_name]
                if _sg["GroupId"] not in scheduler_sg:

                    sgs[count] = {
                        "id": f"{_sg['GroupId']}",
                        # "description": f"{_resource_name if _resource_name else ''} {_sg['GroupId']} {_sg['GroupName']}",
                    }

                    count += 1
                    _sg_info_list: list = []

                    _sg_descr_list: list = [_sg.get("GroupName", "")]

                    if _sg.get("Description", ""):
                        _sg_descr_list.append(f" ({_sg.get('Description', '')})")

                    # See if we see a prior SOCA cluster via our Tags
                    for _tag in _sg.get("Tags", []):
                        if _tag.get("Key", "") == "edh:ClusterId":
                            if _tag.get("Value", ""):
                                _sg_info_list.append(f"[green]SOCA\n{_tag.get('Value', '')}[default]")

                    _sg_table.add_row(
                        f"[green]{count}[/green]",
                        f"[cyan]{_sg['GroupId']}[/cyan]",
                        f"[magenta]{''.join(_sg_descr_list) if _sg_descr_list else _sg['GroupId']}[/magenta]",
                        "\n".join(_sg_info_list),
                    )


            print(_sg_table)

            allowed_choices = list(sgs.keys())

            choice = get_input(
                prompt=_(f"What security group do you want to use for {environment.upper()}"),
                specified_value=None,
                expected_answers=allowed_choices,
                expected_type=int,
            )
            return {"success": True, "message": sgs[choice]["id"]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_iam_roles(self, environment, selected_roles=None):
        if selected_roles is None:
            selected_roles = []
        try:
            print(
                f"\n====== Choose the [misty_rose3]IAM role to use for the {environment.upper()}[default] ======\n"
            )
            roles = {}
            count = 1

            iam_paginator = self.iam.get_paginator("list_roles")
            iam_iterator = iam_paginator.paginate()
            for page in iam_iterator:
                for role in page["Roles"]:
                    if role["RoleName"] not in selected_roles:
                        roles[count] = {
                            "arn": f"{role['Arn']}",
                            "name": role["RoleName"],
                            "description": f"{role['RoleName']} - {role['Description'] if 'Description' in role.keys() else ''}",
                        }
                        count += 1

            [
                print("    {} > {}".format(key, value["description"]))
                for key, value in roles.items()
            ]
            allowed_choices = list(roles.keys())
            choice = get_input(
                _(f"What IAM Role for you want to use for {environment.upper()}"),
                None,
                allowed_choices,
                int,
            )
            return {"success": True, "message": roles[choice]}

        except Exception as err:
            print(err)
            return {"success": False, "message": str(err)}

    def get_rules_for_security_group(self, sg_ids) -> dict:
        try:
            rules = {}
            for sg_id in sg_ids:
                for page in self.ec2.get_paginator(
                    "describe_security_groups"
                ).paginate():
                    for sg in page["SecurityGroups"]:
                        sg_rules = []
                        if sg["GroupId"] != sg_id:
                            continue
                        if "IpPermissions" in sg.keys():
                            for permission in sg["IpPermissions"]:
                                if "FromPort" in permission.keys():
                                    from_port = permission["FromPort"]
                                    to_port = permission["ToPort"]
                                else:
                                    # IpProtocol = -1 -> All Traffic
                                    from_port = 0
                                    to_port = 65535

                                approved_ips = []

                                if permission["IpRanges"].__len__() > 0:
                                    for r in permission["IpRanges"]:
                                        if "CidrIp" in r.keys():
                                            approved_ips.append(r["CidrIp"])

                                if permission["UserIdGroupPairs"].__len__() > 0:
                                    for g in permission["UserIdGroupPairs"]:
                                        if "GroupId" in g.keys():
                                            approved_ips.append(g["GroupId"])

                                sg_rules.append(
                                    {
                                        "from_port": from_port,
                                        "to_port": to_port,
                                        "approved_ips": approved_ips,
                                        "type": "ingress",
                                    }
                                )
                                rules[sg_id] = sg_rules

                        if "IpPermissionsEgress" in sg.keys():
                            for permission in sg["IpPermissionsEgress"]:
                                if "FromPort" in permission.keys():
                                    from_port = permission["FromPort"]
                                    to_port = permission["ToPort"]
                                else:
                                    # IpProtocol = -1 -> All Traffic
                                    from_port = 0
                                    to_port = 65535

                                approved_ips = []

                                if permission["IpRanges"].__len__() > 0:
                                    for r in permission["IpRanges"]:
                                        if "CidrIp" in r.keys():
                                            approved_ips.append(r["CidrIp"])

                                if permission["UserIdGroupPairs"].__len__() > 0:
                                    for g in permission["UserIdGroupPairs"]:
                                        if "GroupId" in g.keys():
                                            approved_ips.append(g["GroupId"])

                                sg_rules.append(
                                    {
                                        "from_port": from_port,
                                        "to_port": to_port,
                                        "approved_ips": approved_ips,
                                        "type": "egress",
                                    }
                                )
                                rules[sg_id] = sg_rules

            return {"success": True, "message": rules}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_fs_security_groups(self, cfn_params):
        try:
            filesystems = {}
            efs_ids = []
            fsx_ids = []
            sgs = []

            for fs_mount in {"fs_apps", "fs_data"}:
                fs_mount_provider = cfn_params.get(
                    f"{fs_mount}_provider", "unknown-provider"
                )

                if fs_mount_provider.lower() == "efs":
                    efs_ids.append(cfn_params[fs_mount])
                elif fs_mount_provider.lower() in {"fsx_lustre", "fsx_openzfs"}:
                    fsx_ids.append(cfn_params[fs_mount])
                else:
                    print(f"ERROR: Do not know about provider: {fs_mount_provider}")

            for efs_id in efs_ids:
                for mount in self.efs.describe_mount_targets(
                    FileSystemId=efs_id.split(".")[0]
                )["MountTargets"]:
                    for sg in self.efs.describe_mount_target_security_groups(
                        MountTargetId=mount["MountTargetId"]
                    )["SecurityGroups"]:
                        if sg not in sgs:
                            sgs.append(sg)

                filesystems[efs_id] = sgs

            for fsx_id in fsx_ids:
                for network_interface in self.fsx.describe_file_systems(
                    FileSystemIds=[fsx_id]
                )["FileSystems"][0]["NetworkInterfaceIds"]:
                    for groups in self.ec2.describe_network_interface_attribute(
                        Attribute="groupSet", NetworkInterfaceId=network_interface
                    )["Groups"]:
                        sg = groups["GroupId"]
                        if sg not in sgs:
                            sgs.append(sg)

                filesystems[fsx_id] = sgs

            return {"success": True, "message": filesystems}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def validate_sg_rules(self, cfn_params, check_fs=True):
        security_groups: list = []
        try:
            # Begin Verify Security Group Rules
            print(
                f"\n====== Please wait a little as we [misty_rose3]validate your security group rules [default] ======\n"
            )

            for _sg_name in {'scheduler_sg', 'compute_node_sg', 'vpc_endpoint_sg'}:
                if cfn_params.get(_sg_name, ''):
                    # print(f"DEBUG - Adding fetch for SG: {_sg_name}")
                    security_groups.append(cfn_params.get(_sg_name))

            sg_rules = {'message': 'Unknown Error'}

            eval_required = False
            if len(security_groups):
                eval_required = True
                # print(f"DEBUG - Fetching Security groups for evaluation: {security_groups}")
                sg_rules = self.get_rules_for_security_group(security_groups)
                # print(f"DEBUG - sg_rules Now: {sg_rules}")
            else:
                pass
                # print(f"DEBUG - No Security groups to evaluate")

            if check_fs:
                # print(f"DEBUG - Getting Filesystem SG: {cfn_params}")
                fs_sg = self.get_fs_security_groups(cfn_params)
                # print(f"DEBUG - FS-SG Now: {fs_sg}")

            if eval_required is True and not sg_rules.get("success", False):
                print(f"[red]Error: {sg_rules['message']} [default]")
                sys.exit(1)

            # Skip the rest if we are generating the SGs
            if not eval_required:
                return {"success": True, "message": ""}

            scheduler_sg_rules = sg_rules["message"][cfn_params["scheduler_sg"]]
            compute_node_sg_rules = sg_rules["message"][
                cfn_params["compute_node_sg"]
            ]
            vpc_endpoint_sg_rules = sg_rules["message"].get(
                cfn_params.get("vpc_endpoint_sg", None), None
            )

            errors = {
                "SCHEDULER_SG_IN_COMPUTE": {
                    "status": False,
                    "error": f"Compute Node SG must allow all TCP traffic from Scheduler SG",
                    "resolution": f"Add new rule on {cfn_params['compute_node_sg']} that allow TCP ports '0-65535' for {cfn_params['scheduler_sg']}",
                },
                "COMPUTE_SG_IN_SCHEDULER": {
                    "status": False,
                    "error": f"Scheduler SG must allow all TCP traffic from Compute Node SG",
                    "resolution": f"Add a new rule on {cfn_params['scheduler_sg']} that allow TCP ports '0-65535' for {cfn_params['compute_node_sg']}",
                },
                "CLIENT_IP_HTTPS_IN_SCHEDULER": {
                    "status": False,
                    "error": f"Client IP must be allowed for port 443 (80 optional) on Scheduler SG",
                    "resolution": f"Add two rules on {cfn_params['scheduler_sg']} that allow TCP ports 80 and 443 for {self.client_ip}",
                },
                "CLIENT_IP_SSH_IN_SCHEDULER": {
                    "status": False,
                    "error": f"Client IP must be allowed for port 22 (SSH) on Scheduler SG",
                    "resolution": f"Add one rule on {cfn_params['scheduler_sg']} that allow TCP port 22 for {self.client_ip}",
                },
                "SCHEDULER_SG_EQUAL_COMPUTE": {
                    "status": False,
                    "error": "Scheduler SG and Compute SG must be different",
                    "resolution": "You must choose two different security groups",
                },
                "COMPUTE_SG_EGRESS_EFA": {
                    "status": False,
                    "error": "Compute SG must reference egress traffic to itself for EFA",
                    "resolution": f"Add a new (EGRESS) rule on {cfn_params['compute_node_sg']} that allow TCP ports '0-65535' for {cfn_params['compute_node_sg']}. Make sure you configure EGRESS rule and not INGRESS",
                }
            }
            # status == True means that the check passed
            if "vpc_endpoint_sg" in cfn_params:
                errors["COMPUTE_EGRESS_TO_VPC_ENDPOINTS"] = {
                    "status": False,
                    "error": "Compute SG must allow port 443 egress to the vpc endpoints security group",
                    "resolution": f"Add a new (EGRESS) rule on {cfn_params['compute_node_sg']} that allows TCP port '443' for {cfn_params['vpc_endpoint_sg']}. Make sure you configure EGRESS rule and not INGRESS",
                }
                errors["VPC_ENDPOINTS_INGRESS_FROM_COMPUTE"] = {
                    "status": False,
                    "error": "vpc Endpoints SG must allow port 443 ingress from the Compute SG",
                    "resolution": f"Add a new (INGRESS) rule on {cfn_params['vpc_endpoint_sg']} that allows TCP port '443' from {cfn_params['compute_node_sg']}. Make sure you configure INGRESS rule and not EGRESS",
                }
                errors["SCHEDULER_EGRESS_TO_VPC_ENDPOINTS"] = {
                    "status": False,
                    "error": "Scheduler SG must allow port 443 egress to the vpc endpoints security group",
                    "resolution": f"Add a new (EGRESS) rule on {cfn_params['scheduler_sg']} that allows TCP port '443' for {cfn_params['vpc_endpoint_sg']}. Make sure you configure EGRESS rule and not INGRESS",
                }
                errors["VPC_ENDPOINTS_INGRESS_FROM_SCHEDULER"] = {
                    "status": False,
                    "error": "vpc Endpoints SG must allow port 443 ingress from the Scheduler SG",
                    "resolution": f"Add a new (INGRESS) rule on {cfn_params['vpc_endpoint_sg']} that allows TCP port '443' from {cfn_params['scheduler_sg']}. Make sure you configure INGRESS rule and not EGRESS",
                }

            if check_fs:
                errors["FS_APP_SG"] = {
                    "status": False,
                    "error": f"SG assigned to EFS App {cfn_params['fs_apps']} must allow Scheduler SG and Compute SG",
                    "resolution": f"Add {cfn_params['scheduler_sg']} and {cfn_params['compute_node_sg']} on your EFS Apps {cfn_params['fs_apps']}",
                }

                errors["FS_DATA_SG"] = {
                    "status": False,
                    "error": f"SG assigned to EFS App {cfn_params['fs_data']} must allow Scheduler SG and Compute SG",
                    "resolution": f"Add {cfn_params['scheduler_sg']} and {cfn_params['compute_node_sg']} on your EFS Data {cfn_params['fs_data']}",
                }

            # Verify Scheduler Rules
            for rules in scheduler_sg_rules:
                if rules["from_port"] == 0 and rules["to_port"] == 65535:
                    for rule in rules["approved_ips"]:
                        if cfn_params["compute_node_sg"] in rule:
                            errors["COMPUTE_SG_IN_SCHEDULER"]["status"] = True

                if rules["from_port"] == 443 or rules["from_port"] == 22:
                    for rule in rules["approved_ips"]:
                        client_ip_netmask = 32
                        if client_ip_netmask == "32":
                            if ipaddress.IPv4Address(
                                self.client_ip
                            ) in ipaddress.IPv4Network(rule):
                                if rules["from_port"] == 443:
                                    errors["CLIENT_IP_HTTPS_IN_SCHEDULER"][
                                        "status"
                                    ] = True
                                if rules["from_port"] == 22:
                                    errors["CLIENT_IP_SSH_IN_SCHEDULER"][
                                        "status"
                                    ] = True
                        else:
                            if self.client_ip in rule:
                                if rules["from_port"] == 443:
                                    errors["CLIENT_IP_HTTPS_IN_SCHEDULER"][
                                        "status"
                                    ] = True
                                if rules["from_port"] == 22:
                                    errors["CLIENT_IP_SSH_IN_SCHEDULER"][
                                        "status"
                                    ] = True
            # Verify Compute Node Rules
            for rules in compute_node_sg_rules:
                if rules["from_port"] == 0 and rules["to_port"] == 65535:
                    for rule in rules["approved_ips"]:
                        if cfn_params["scheduler_sg"] in rule:
                            errors["SCHEDULER_SG_IN_COMPUTE"]["status"] = True

                        if rules["type"] == "egress":
                            if cfn_params["compute_node_sg"] in rule:
                                errors["COMPUTE_SG_EGRESS_EFA"]["status"] = True
            # Verify VPC Endpoint Rules
            if "vpc_endpoint_sg" in cfn_params:
                for rule in compute_node_sg_rules:
                    # Make sure compute node allows egress to vpc endpoints
                    if rule["type"] != "egress":
                        continue
                    for approved_ip in rule["approved_ips"]:
                        if rule["from_port"] <= 443 <= rule["to_port"]:
                            if cfn_params["vpc_endpoint_sg"] in approved_ip:
                                errors["COMPUTE_EGRESS_TO_VPC_ENDPOINTS"][
                                    "status"
                                ] = True
                for rule in scheduler_sg_rules:
                    # Make sure scheduler allows egress to vpc endpoints
                    if rule["type"] != "egress":
                        continue
                    for approved_ip in rule["approved_ips"]:
                        if rule["from_port"] <= 443 <= rule["to_port"]:
                            if cfn_params["vpc_endpoint_sg"] in approved_ip:
                                errors["SCHEDULER_EGRESS_TO_VPC_ENDPOINTS"][
                                    "status"
                                ] = True
                for rule in vpc_endpoint_sg_rules:
                    # Make sure endpoints allow ingress from compute nodes and scheduler
                    if rule["type"] != "ingress":
                        continue
                    for approved_ip in rule["approved_ips"]:
                        if rule["from_port"] <= 443 <= rule["to_port"]:
                            if cfn_params["scheduler_sg"] in approved_ip:
                                errors["VPC_ENDPOINTS_INGRESS_FROM_SCHEDULER"][
                                    "status"
                                ] = True
                            if cfn_params["compute_node_sg"] in approved_ip:
                                errors["VPC_ENDPOINTS_INGRESS_FROM_COMPUTE"][
                                    "status"
                                ] = True

            if check_fs:
                if (
                    cfn_params["scheduler_sg"]
                    in fs_sg["message"][cfn_params["fs_apps"]]
                    and cfn_params["compute_node_sg"]
                    in fs_sg["message"][cfn_params["fs_apps"]]
                ):
                    errors["FS_APP_SG"]["status"] = True

                if (
                    cfn_params["scheduler_sg"]
                    in fs_sg["message"][cfn_params["fs_data"]]
                    and cfn_params["compute_node_sg"]
                    in fs_sg["message"][cfn_params["fs_data"]]
                ):
                    errors["FS_DATA_SG"]["status"] = True

            if cfn_params["scheduler_sg"] != cfn_params["compute_node_sg"]:
                errors["SCHEDULER_SG_EQUAL_COMPUTE"]["status"] = True

            sg_errors = {}

            confirm_sg_settings = False
            for error_id, error_info in errors.items():
                if error_info["status"] is False:
                    if check_fs is False and "EFS" in error_id:
                        pass
                    else:
                        print(
                            f"[yellow]ATTENTION!! {error_info['error']} [default]\nHow to solve: {error_info['resolution']}\n"
                        )
                        sg_errors[error_info["error"]] = error_info["resolution"]
                        confirm_sg_settings = True

            if confirm_sg_settings:
                choice = get_input(
                    _("Your security groups may not be configured correctly. Verify them and determine if the warnings listed above are false-positive.\n Do you still want to continue with the installation?"),
                    None,
                    ["yes", "no"],
                    str,
                )
                if choice.lower() == "no":
                    sys.exit(1)
            else:
                print(
                    f"[green] Security Groups seem to be configured correctly[default]"
                )

            return {"success": True, "message": ""}

        except Exception as _e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(f"{exc_type} {fname} {exc_tb.tb_lineno}")
            return {
                "success": False,
                "message": f"{exc_type} {fname} {exc_tb.tb_lineno}",
            }
