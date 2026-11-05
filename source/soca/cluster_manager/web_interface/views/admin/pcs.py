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

"""
Admin-only page to manage AWS PCS cluster creation.

Deliberately thin and API-less: the view drives SocaAWSPCSClient directly, server
side, on the admin's behalf. There is no /api layer in front of it yet, so this is
the fastest path to a working "create / status / delete a PCS cluster" screen for
operators. When a proper REST surface exists, the POST handlers here should be
reduced to thin proxies the way the mesh admin page already is.

SocaAWSPCSClient is per-cluster (its constructor takes a single cluster_name and it
exposes no list_clusters), so the page manages one named cluster at a time rather
than rendering a fleet-wide list.
"""

import ast
import datetime
import grp
import json
import logging
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, render_template, request, redirect, flash
from flask_babel import gettext as _

from decorators import login_required, admin_only, feature_flag
from utils.aws.pcs_client import SocaAWSPCSClient
from utils.config import SocaConfig
from utils.validators import Validators
from remote_desktop_common import get_arch_for_instance_type

logger = logging.getLogger("soca_logger")

admin_pcs = Blueprint("admin_pcs", __name__, template_folder="templates")

# Kept in sync with SocaAWSPCSClient.create_cluster() so the form only offers values
# the client / PCS actually accept.
_PCS_SIZES = ["SMALL", "MEDIUM", "LARGE"]
# Slurm versions offered when creating a cluster from EDH (simple and JSON paths)
_PCS_SLURM_VERSIONS = ["25.11", "26.05"]

# Default Linux base OSes offered on the launch-template / compute-node-group forms whose
# AMI can be resolved from the EDH AMI mapping (/configuration/CustomAMIMap). Ordered dict:
# base_os key -> human label. The base OS is always required (it drives the EDH bootstrap
# package set); when the operator leaves the AMI ID field blank the default AMI for that OS is
# resolved from the mapping (per architecture), otherwise the typed AMI ID overrides it.
_PCS_DEFAULT_BASE_OS = {
    "amazonlinux2023": "Amazon Linux 2023",
    "rhel9": "RHEL 9",
    "rhel8": "RHEL 8",
    "rocky9": "Rocky Linux 9",
    "rocky8": "Rocky Linux 8",
}


def _resolve_ami_from_base_os(base_os, instance_type=None, arch=None):
    """
    Resolve an AMI id from the EDH AMI mapping (/configuration/CustomAMIMap) for the given
    base OS and CPU architecture. The mapping is keyed as {arch: {base_os: ami_id}}. The
    architecture is taken from the explicit arch argument when provided (e.g. the launch
    template form, which has no instance type), otherwise it is resolved from instance_type.
    Returns (ami_id, None) on success or (None, error_message) on failure.
    """
    if base_os not in _PCS_DEFAULT_BASE_OS:
        return None, _("Unsupported base OS: ") + str(base_os)
    if arch:
        _arch = arch
    elif instance_type:
        try:
            _arch = get_arch_for_instance_type(instance_type)
        except Exception as err:
            logger.error(f"Unable to resolve architecture for {instance_type}: {err}")
            _arch = None
        if not _arch:
            return None, (
                _("Unable to resolve the CPU architecture for instance type ") + str(instance_type)
            )
    else:
        return None, _("An instance type or architecture is required to resolve the AMI.")
    _ami_map = (
        SocaConfig(key="/configuration/CustomAMIMap").get_value(return_as=dict).get("message")
    ) or {}
    _ami_id = (_ami_map.get(_arch) or {}).get(base_os)
    if not _ami_id:
        return None, (
            _("No AMI found in the EDH AMI mapping for ")
            + str(base_os)
            + _(" on architecture ")
            + str(_arch)
            + _(". Provide a custom AMI id instead.")
        )
    return _ami_id, None

# Keys accepted in the raw-JSON create form. Must match the keyword arguments of
# SocaAWSPCSClient.create_cluster() (clusterName is derived from the cluster_name field,
# not the blob), so we can reject typos with a clear message instead of a 500.
_ALLOWED_CREATE_KWARGS = {
    "subnet_ids",
    "security_group_ids",
    "size",
    "scheduler",
    "network_type",
    "slurm_configuration",
    "client_token",
    "tags",
}

# Same idea for SocaAWSPCSClient.create_compute_node_group(). The cluster is supplied by
# context (the detail page), so the blob carries only the node group arguments. The
# required set are the parameters that have no default and would otherwise raise TypeError.
_ALLOWED_CNG_KWARGS = {
    "group_name",
    "launch_template_id",
    "instance_types",
    "desired_capacity",
    "ami_id",
    "launch_template_version",
    "instance_profile_arn",
    "subnet_ids",
    "purchase_option",
    "min_instance_count",
    "max_instance_count",
    "spot_options",
    "slurm_configuration",
    "node_lifecycle_actions",
    # EDH bootstrap for PCS nodes runs as a nodeBootstrapped lifecycle action on the node group
    # (not launch-template UserData). When edh_bootstrap is enabled and node_lifecycle_actions is
    # not otherwise provided, the client renders + uploads the bootstrap and registers it.
    "edh_bootstrap",
    # Base OS to render the EDH bootstrap for. Without it the client falls back to
    # /configuration/BaseOS (the EDH controller's OS), which may mismatch the node's AMI (e.g. an
    # AL2023 node running the RHEL9 package set). Value must be one of the keys in
    # _PCS_DEFAULT_BASE_OS (e.g. "amazonlinux2023").
    "edh_base_os",
    "client_token",
    "tags",
}
# ami_id is intentionally NOT required: the AMI (and matching EDH bootstrap) lives on the launch
# template, so PCS inherits the template's ImageId when the node group omits it. It stays in
# _ALLOWED_CNG_KWARGS so an operator can still override the image per node group via the JSON tab.
_REQUIRED_CNG_KWARGS = {
    "group_name",
    "launch_template_id",
    "instance_types",
    "min_instance_count",
    "max_instance_count",
}

# Same idea for SocaAWSPCSClient.create_queue(). Only queue_name is required (it has no
# default and PCS needs it); the rest map straight onto the client's keyword arguments.
_ALLOWED_QUEUE_KWARGS = {
    "queue_name",
    "compute_node_group_ids",
    "slurm_configuration",
    "client_token",
    "tags",
}
_REQUIRED_QUEUE_KWARGS = {
    "queue_name",
}

# Same idea for SocaAWSPCSClient.create_launch_template(). No key is required here: the
# client enforces the "exactly one of launch_template_data / launch_template_data_path"
# rule itself and returns a SocaError we surface, and it defaults the name and security
# groups from the cluster when omitted.
_ALLOWED_LT_KWARGS = {
    "template_name",
    "security_group_ids",
    "launch_template_data",
    "launch_template_data_path",
    "tags",
    "instance_tags",
}

# Cost-allocation tags the simple forms expose as plain fields. These are stamped on the EC2
# instances / EBS volumes PCS launches (via the launch template's LaunchTemplateData
# TagSpecifications) so spend can be grouped by them in Cost Explorer / the CUR. Maps the HTML
# form field name -> the AWS tag key. Activate them as user-defined cost allocation tags in the
# Billing console for them to show up as cost dimensions.
_PCS_COST_TAG_FIELDS = {
    "cost_team": "edh:PCS:team",
    "cost_department": "edh:PCS:department",
    "cost_project": "edh:PCS:project",
    "cost_user": "edh:PCS:user",
}


def _collect_cost_tags(form):
    """Pull the cost-allocation tag fields out of a submitted form into a {tag_key: value} dict."""
    _tags = {}
    for _field, _key in _PCS_COST_TAG_FIELDS.items():
        _val = (form.get(_field) or "").strip()
        if _val:
            _tags[_key] = _val
    return _tags


def _parse_json_payload(raw, allowed, required=None):
    """
    Parse and validate a pasted JSON blob against allowed/required key sets.

    Returns (payload_dict, None) on success or (None, error_message) when the blob is
    empty, not valid JSON, not an object, carries unknown keys, or is missing a required
    key -- so callers can flash a precise reason instead of raising a 500.
    """
    if not raw or not raw.strip():
        return None, _("The JSON payload is empty.")
    try:
        _payload = json.loads(raw)
    except ValueError as err:
        return None, _("Invalid JSON: ") + str(err)
    if not isinstance(_payload, dict):
        return None, _("The JSON payload must be an object mapping arguments.")
    _unknown = set(_payload) - allowed
    if _unknown:
        return None, (
            _("Unsupported key(s) in JSON: ")
            + ", ".join(sorted(_unknown))
            + _(". Allowed keys: ")
            + ", ".join(sorted(allowed))
        )
    if required:
        _missing = required - set(_payload)
        if _missing:
            return None, _("Missing required key(s): ") + ", ".join(sorted(_missing))
    return _payload, None


def _split_csv(raw):
    """Turn a comma/space separated form field into a clean list (or None when empty)."""
    if not raw:
        return None
    _items = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
    return _items or None


# ISO 8601 timestamp as returned by PCS / EC2 (e.g. 2026-05-01T12:34:56.123456Z or
# 2026-05-01 12:34:56+02:00). Parsed by hand rather than with datetime.fromisoformat, which only
# accepts "Z" and arbitrary fraction lengths from Python 3.11.
_PCS_ISO_DATETIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?"
    r"\s*(Z|[+-]\d{2}(?::?\d{2})?)?$",
    re.IGNORECASE,
)


@admin_pcs.app_template_filter("pcs_datetime")
def pcs_datetime(value):
    """
    Jinja filter: render a datetime (or ISO 8601 string, "Z" or +/-HH:MM offset) as
    "YYYY-MM-DD HH:MM UTC". Naive values are assumed to be UTC. Empty values render as "-";
    anything that cannot be parsed is returned unchanged. Never raises, so a malformed
    timestamp from the API can never break a page.
    """
    try:
        # None, "" and a Jinja Undefined (missing key) are all falsy
        if not value:
            return "-"
        if isinstance(value, datetime.datetime):
            _dt = value
        elif isinstance(value, datetime.date):
            _dt = datetime.datetime(value.year, value.month, value.day)
        else:
            _match = _PCS_ISO_DATETIME_RE.match(str(value).strip())
            if not _match:
                return value
            _y, _mo, _d, _h, _mi, _s, _frac, _tz = _match.groups()
            _dt = datetime.datetime(
                int(_y),
                int(_mo),
                int(_d),
                int(_h or 0),
                int(_mi or 0),
                int(_s or 0),
                int((_frac or "0")[:6].ljust(6, "0")),
            )
            if _tz and _tz.upper() != "Z":
                _sign = -1 if _tz[0] == "-" else 1
                _digits = _tz[1:].replace(":", "")
                _offset = datetime.timedelta(
                    hours=int(_digits[:2]), minutes=int(_digits[2:4] or 0)
                )
                _dt = _dt.replace(tzinfo=datetime.timezone(_sign * _offset))
            else:
                _dt = _dt.replace(tzinfo=datetime.timezone.utc)
        if _dt.tzinfo is None:
            _dt = _dt.replace(tzinfo=datetime.timezone.utc)
        return _dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return value


def _resolve_cluster_id_and_name(client, fallback):
    """
    Resolve (cluster_id, display_name) for a client, used by the sub-pages (queue / compute
    node group / launch template) so their links and form fields reference the PCS cluster id
    while breadcrumbs still show the friendly name. `fallback` is the identifier from the URL
    (already an id in normal navigation); it is returned for both when the describe fails, so a
    transient error never breaks the page. A lightweight describe (no queue/CNG listing) is used.
    """
    try:
        _get = client.get_cluster(list_queues=False, list_compute_node_groups=False)
        if _get.get("success") is True:
            _cluster = (_get.get("message") or {}).get("cluster", {})
            return (_cluster.get("id") or fallback, _cluster.get("name") or fallback)
    except Exception as err:
        logger.warning(f"Unable to resolve cluster id/name for {fallback}: {err}")
    return fallback, fallback


@admin_pcs.route("/admin/pcs", methods=["GET"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def index():
    """List the PCS clusters owned by this EDH environment, plus the create form."""
    _clusters = []
    _list = SocaAWSPCSClient.list_clusters()
    if _list.get("success") is True:
        _clusters = _list.get("message") or []
        # Always show newest clusters first. createdAt is an ISO8601 string (or a datetime);
        # str() gives a stable, chronologically-sortable key and tolerates a missing value.
        _clusters.sort(key=lambda c: str(c.get("createdAt") or ""), reverse=True)
    else:
        flash(
            _("Unable to list PCS clusters: ") + str(_list.get("message")),
            "error",
        )

    # Pre-populate the Simple form's subnet dropdown with the EDH private subnets (the same
    # source create_cluster defaults to). PCS accepts a single subnet, so this is a single-select.
    _private_subnets = (
        SocaConfig(key="/configuration/PrivateSubnets")
        .get_value(return_as=list)
        .get("message")
        or []
    )

    # Pre-fill the Simple form's security groups with the EDH compute node security group (the
    # same default create_cluster applies when the field is left empty).
    _default_security_group = (
        SocaConfig(key="/configuration/ComputeNodeSecurityGroup")
        .get_value()
        .get("message")
        or ""
    )

    return render_template(
        "admin/pcs/index.html",
        page="admin_pcs",
        clusters=_clusters,
        pcs_sizes=_PCS_SIZES,
        pcs_slurm_versions=_PCS_SLURM_VERSIONS,
        private_subnets=_private_subnets,
        default_security_group=_default_security_group,
        # Fresh idempotency token per page render, posted back by the create form.
        create_client_token=uuid.uuid4().hex,
        # Region for the AWS PCS console link. Non-fatal: blank falls back to the console default.
        aws_region=SocaConfig(key="/configuration/Region").get_value().get("message")
        or "",
    )


def _check_slurm_key_permissions(key_path):
    """
    Check the exported Slurm key the way the PCS Connect "Key permissions" step configures it, so
    the page can tell whether that step is done. Returns the list of problems (empty = done):
      - the slurm group exists, and owns the key (group-readable) and its directory (traversable)
      - pcs/ is not group/world-writable, and pcs/ + its two parents are traversable by others (o+x)
    """
    _issues = []
    try:
        _slurm_gid = grp.getgrnam("slurm").gr_gid
    except KeyError:
        return ["the slurm group does not exist on the EDH controller"]
    _key = os.stat(key_path)
    _key_dir = os.path.dirname(key_path)
    _dir = os.stat(_key_dir)
    if _key.st_gid != _slurm_gid or not _key.st_mode & 0o040:
        _issues.append(f"{key_path} is not group-readable by slurm")
    if _dir.st_gid != _slurm_gid or not _dir.st_mode & 0o010:
        _issues.append(f"{_key_dir} is not group-traversable by slurm")
    _pcs_dir = os.path.dirname(_key_dir)
    if os.stat(_pcs_dir).st_mode & 0o022:
        _issues.append(f"{_pcs_dir} is group/world-writable")
    _parent = _pcs_dir
    for _level in range(3):  # pcs/, shared/, /apps/edh/<cluster_id>
        if not os.stat(_parent).st_mode & 0o001:
            _issues.append(f"{_parent} is not traversable by others")
        _parent = os.path.dirname(_parent)
    return _issues


@admin_pcs.route("/admin/pcs/detail/<pcs_cluster_name>", methods=["GET"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def detail(pcs_cluster_name):
    """Show a single cluster with its queues and compute node groups."""
    _cluster_name = (pcs_cluster_name or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect("/admin/pcs")

    _get = _client.get_cluster(list_queues=True, list_compute_node_groups=True)
    if _get.get("success") is False:
        flash(
            _("Unable to retrieve PCS cluster ")
            + _cluster_name
            + ": "
            + str(_get.get("message")),
            "error",
        )
        return redirect("/admin/pcs")

    _info = _get.get("message") or {}
    _cluster = _info.get("cluster", {})

    # All URLs and form fields reference the PCS cluster id; the friendly name is display-only.
    # The route accepts either (PCS clusterIdentifier takes name-or-id), so links stay id-based.
    _cluster_id = _cluster.get("id") or _cluster_name
    _display_name = _cluster.get("name") or _cluster_name

    # Slurm client connection info for the Connect tab, read straight from the describe above
    # (no extra GetCluster): the SLURMCTLD endpoint only exists once the cluster is ACTIVE, so
    # None hides the section otherwise. IPv6-only clusters expose ipv6Address instead.
    _is_active = _cluster.get("status") == "ACTIVE"
    _client_info = None
    if _is_active:
        _slurmctld = next(
            (_e for _e in _cluster.get("endpoints") or [] if _e.get("type") == "SLURMCTLD"),
            None,
        )
        _slurmctld_ip = _slurmctld and (
            _slurmctld.get("privateIpAddress") or _slurmctld.get("ipv6Address")
        )
        if _slurmctld_ip:
            _client_info = {
                "cluster_name": _cluster.get("name"),
                "cluster_id": _cluster.get("id"),
                "slurmctld": {"ip": _slurmctld_ip, "port": _slurmctld.get("port")},
            }

    # The lookups below only feed tabs that are disabled until the cluster is ACTIVE, so skip
    # them otherwise. They are independent, so run them concurrently. Each one is non-fatal;
    # flash() needs the request context, so errors are flashed here, after the workers are done.
    #  - Launch templates: EC2 resources, not part of the PCS describe; only EDH-tagged ones.
    #  - Instances PCS provisioned for this cluster (aws:pcs:cluster-id tag).
    #  - IAM instance profiles PCS accepts (AWSPCS* role or /aws-pcs/ path), for the CNG form.
    _lookups = {}
    if _is_active:
        _lookups = {
            "launch_templates": _client.list_launch_templates,
            "instances": _client.list_cluster_instances,
            "instance_profiles": _client.list_pcs_instance_profiles,
        }
    _results = {}
    if _lookups:
        with ThreadPoolExecutor(max_workers=len(_lookups)) as _pool:
            _futures = {_k: _pool.submit(_fn) for _k, _fn in _lookups.items()}
        for _k, _future in _futures.items():
            try:
                _results[_k] = _future.result()
            except Exception as err:
                logger.error(f"PCS detail lookup {_k} failed for {_cluster_name}: {err}")
                _results[_k] = {"success": False, "message": str(err)}

    # Where "Export Slurm key to EDH" writes the shared Slurm key on the controller. Surfaced in
    # the connection details so the client node setup can reference the exact (root-only) path.
    _edh_cluster_id = _client._edh_cluster_id_value()
    _slurm_key_export_dir = (
        f"/apps/edh/{_edh_cluster_id}/shared/pcs/{_cluster_id}" if _edh_cluster_id else ""
    )
    _slurm_key_export_path = (
        f"{_slurm_key_export_dir}/slurm.key" if _slurm_key_export_dir else ""
    )
    # Whether the key was already exported, so the Connect tab can show it as done instead of
    # offering the (one-time) export again. Non-fatal: a stat failure (e.g. the web UI cannot
    # traverse the root-only directory) is reported as not exported.
    try:
        _slurm_key_exported = bool(_slurm_key_export_path) and os.path.isfile(
            _slurm_key_export_path
        )
    except Exception as err:
        logger.warning(f"Unable to check {_slurm_key_export_path}: {err}")
        _slurm_key_exported = False

    # Whether the key permissions step is done (Connect tab step 2). Non-fatal: any stat failure
    # is reported as not done, with the reason shown on the step.
    _slurm_key_permissions_ok = False
    _slurm_key_permissions_issues = []
    if _slurm_key_exported:
        try:
            _slurm_key_permissions_issues = _check_slurm_key_permissions(_slurm_key_export_path)
            _slurm_key_permissions_ok = not _slurm_key_permissions_issues
        except Exception as err:
            logger.warning(f"Unable to check the permissions of {_slurm_key_export_path}: {err}")
            _slurm_key_permissions_issues = [str(err)]

    def _k_ok(_key):
        return (_results.get(_key) or {}).get("success") is True

    _launch_templates = []
    if _k_ok("launch_templates"):
        _launch_templates = _results["launch_templates"].get("message") or []
    elif "launch_templates" in _results:
        flash(
            _("Unable to list launch templates: ") + str(_results["launch_templates"].get("message")),
            "error",
        )

    _instances = []
    if _k_ok("instances"):
        _instances = _results["instances"].get("message") or []
    elif "instances" in _results:
        flash(
            _("Unable to list running instances: ") + str(_results["instances"].get("message")),
            "error",
        )

    _instance_profiles = []
    if _k_ok("instance_profiles"):
        _instance_profiles = _results["instance_profiles"].get("message") or []
    elif "instance_profiles" in _results:
        flash(
            _("Unable to list IAM instance profiles: ") + str(_results["instance_profiles"].get("message")),
            "error",
        )

    # Pre-fill the launch template SSH key pair field with the EDH default key pair
    # (/configuration/SSHKeyPair), the same key EDH uses for its own nodes. The operator can
    # override or clear it. Non-fatal: fall back to blank when it cannot be resolved.
    _default_ssh_keypair = (
        SocaConfig(key="/configuration/SSHKeyPair").get_value().get("message") or ""
    )

    # Region drives the AWS PCS installer S3 URLs shown in the "Build Minimal PCS AMI" section
    # (the aws-pcs-repo-<region> bucket is regional). Non-fatal: fall back to blank so the section
    # renders a placeholder rather than erroring.
    _aws_region = (
        SocaConfig(key="/configuration/Region").get_value().get("message") or ""
    )

    # Whether PCS compute nodes realm-join Active Directory (flag ON) or just sync AD users
    # locally (flag OFF/absent). Surfaced in the Create Compute Node Group form so the operator
    # knows how users will land on the nodes before choosing a desired capacity. Only meaningful
    # when the UserDirectory provider is Active Directory. Non-fatal: default to False.
    _user_directory_provider = (
        SocaConfig(key="/configuration/UserDirectory/provider").get_value().get("message") or ""
    )
    _join_pcs_nodes_to_ad = str(
        SocaConfig(key="/configuration/FeatureFlags/Hpc/JoinPCSNodesToAD")
        .get_value()
        .get("message")
    ).lower() in ("true", "1", "yes")

    # Whether new virtual desktop / login nodes onboard every registered PCS cluster at bootstrap
    # (templates/linux/scheduler/aws_pcs/configure_client.sh.j2). Shown on the Connect tab.
    # Non-fatal: default to False.
    _auto_onboard_client = str(
        SocaConfig(key="/configuration/services/aws_pcs/auto_onboard_client")
        .get_value()
        .get("message")
    ).lower() in ("true", "1", "yes")

    # Register with EDH status for the Connect steps (only shown once the cluster is ACTIVE).
    # Non-fatal: an unreadable registration is shown as "not registered".
    _pcs_registration = None
    if _is_active:
        try:
            _pcs_registration = _get_pcs_scheduler_registration(_cluster.get("id"))
        except Exception as err:
            logger.warning(f"Unable to read the EDH scheduler registration of {_cluster_name}: {err}")

    return render_template(
        "admin/pcs/detail.html",
        page="admin_pcs_detail",
        cluster_id=_cluster_id,
        # Not cluster_name: that context-processor global is the EDH cluster id shown in the
        # menu bar, and a render_template kwarg of the same name would override it.
        pcs_cluster_name=_display_name,
        cluster=_cluster,
        queues=_info.get("queues") or [],
        compute_node_groups=_info.get("compute_node_groups") or [],
        launch_templates=_launch_templates,
        instances=_instances,
        instance_profiles=_instance_profiles,
        client=_client_info,
        slurm_key_export_path=_slurm_key_export_path,
        slurm_key_export_dir=_slurm_key_export_dir,
        slurm_key_exported=_slurm_key_exported,
        slurm_key_permissions_ok=_slurm_key_permissions_ok,
        slurm_key_permissions_issues=_slurm_key_permissions_issues,
        edh_cluster_id=_edh_cluster_id,
        base_os_choices=_PCS_DEFAULT_BASE_OS,
        default_ssh_keypair=_default_ssh_keypair,
        aws_region=_aws_region,
        user_directory_provider=_user_directory_provider,
        join_pcs_nodes_to_ad=_join_pcs_nodes_to_ad,
        auto_onboard_client=_auto_onboard_client,
        pcs_registration=_pcs_registration,
    )


@admin_pcs.route("/admin/pcs/export_secret/<cluster_name>", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def export_secret(cluster_name):
    """
    Export this PCS cluster's shared SLURM auth key from Secrets Manager onto the EDH
    Controller filesystem at /apps/edh/<edh_cluster_id>/shared/pcs/<pcs_id>/slurm.key.

    The key and its parent directory are written root-only (dir 0700, file 0600, owned by
    root) -- group and other get no access. The operator must explicitly grant read access
    to any user they want to allow to use the key. Requires the cluster to be ACTIVE.
    """
    _cluster_name = (cluster_name or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    # Land back on the Connect tab, where the Prerequisite shows the export state.
    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-connect"

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _export = _client.export_slurm_key_to_edh()
    if _export.get("success") is False:
        flash(
            _("Unable to export the Slurm key for ")
            + _cluster_name
            + ": "
            + str(_export.get("message")),
            "error",
        )
        return redirect(_detail_url)

    _key_path = (_export.get("message") or {}).get("slurm_key_path", "")
    flash(
        _(
            "Slurm key exported to %(path)s. The file and its directory are restricted "
            "to root only. The shared filesystem (EFS/NFS) does not support POSIX ACLs, so "
            "grant read access with a shared group instead: group-own the key and its "
            "directory, make the key group-readable (chmod 0640) and the directory "
            "group-traversable (chmod 0710), then add each allowed user (or the account sackd "
            "runs as) to that group. See the Prerequisite on the Connect tab."
        )
        % {"path": _key_path},
        "success",
    )
    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/create", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create():
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _size = request.form.get("size") or "SMALL"
    if _size not in _PCS_SIZES:
        flash(_("Invalid cluster size: ") + _size, "error")
        return redirect("/admin/pcs")

    _slurm_version = request.form.get("slurm_version") or "26.05"
    if _slurm_version not in _PCS_SLURM_VERSIONS:
        flash(_("Invalid Slurm version: ") + _slurm_version, "error")
        return redirect("/admin/pcs")

    _subnet_ids = _split_csv(request.form.get("subnet_ids"))
    _security_group_ids = _split_csv(request.form.get("security_group_ids"))

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:  # SocaAWSPCSClient raises RuntimeError on a bad boto client
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect("/admin/pcs")

    # client_token is generated once per page render (hidden form field), so a double-submit
    # of the same form does not create two clusters (PCS treats matching tokens as the same
    # idempotent request), while a resubmit after fixing an error / a re-create of the same
    # name from a freshly loaded page gets a new token instead of IdempotentParameterMismatch.
    _client_token = (request.form.get("client_token") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{8,100}", _client_token):
        _client_token = uuid.uuid4().hex
    _create = _client.create_cluster(
        subnet_ids=_subnet_ids,
        security_group_ids=_security_group_ids,
        size=_size,
        scheduler={"type": "SLURM", "version": _slurm_version},
        client_token=_client_token,
    )

    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("PCS cluster ")
            + _cluster_name
            + _(" creation initiated (id: ")
            + str(_msg.get("id", "unknown"))
            + ").",
            "success",
        )
        # Creation takes several minutes: land on the detail page, which auto-refreshes while
        # the cluster is CREATING. The detail route accepts the cluster name or id.
        return redirect("/admin/pcs/detail/" + _cluster_name)

    flash(
        _("Unable to create PCS cluster ")
        + _cluster_name
        + ": "
        + str(_create.get("message")),
        "error",
    )
    return redirect("/admin/pcs")


@admin_pcs.route("/admin/pcs/create_json", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create_json():
    """
    Create a cluster from a pasted JSON blob mapped straight onto create_cluster()'s
    keyword arguments. The cluster name still comes from its own field (create_cluster
    derives clusterName from it), so the blob only carries the rest of the request.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _payload, _err = _parse_json_payload(
        request.form.get("raw_json"), _ALLOWED_CREATE_KWARGS
    )
    if _err:
        flash(_err, "error")
        return redirect("/admin/pcs")

    # Same Slurm version restriction as the simple form (no scheduler = create_cluster default)
    _scheduler = _payload.get("scheduler")
    if _scheduler is not None:
        _json_version = (
            str(_scheduler.get("version")) if Validators.is_dict(_scheduler) else ""
        )
        if _json_version not in _PCS_SLURM_VERSIONS:
            flash(
                _("Invalid Slurm version: ")
                + _json_version
                + _(". Supported versions: ")
                + ", ".join(_PCS_SLURM_VERSIONS),
                "error",
            )
            return redirect("/admin/pcs")

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect("/admin/pcs")

    _create = _client.create_cluster(**_payload)
    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("PCS cluster ")
            + _cluster_name
            + _(" creation initiated (id: ")
            + str(_msg.get("id", "unknown"))
            + ").",
            "success",
        )
        # Same as the simple form: follow the (auto-refreshing) creation on the detail page.
        return redirect("/admin/pcs/detail/" + _cluster_name)

    flash(
        _("Unable to create PCS cluster ")
        + _cluster_name
        + ": "
        + str(_create.get("message")),
        "error",
    )
    return redirect("/admin/pcs")


@admin_pcs.route("/admin/pcs/create_compute_node_group", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create_compute_node_group():
    """
    Create a compute node group on a cluster from a pasted JSON blob mapped onto
    create_compute_node_group()'s keyword arguments. The cluster comes from the
    cluster_name field (posted by the detail page); the blob carries the node group.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-groups"

    _payload, _err = _parse_json_payload(
        request.form.get("raw_json"), _ALLOWED_CNG_KWARGS, required=_REQUIRED_CNG_KWARGS
    )
    if _err:
        flash(_err, "error")
        return redirect(_detail_url)

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _create = _client.create_compute_node_group(**_payload)
    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("Compute node group ")
            + str(_msg.get("name", _payload.get("group_name", "")))
            + _(" creation initiated (id: ")
            + str(_msg.get("id", "unknown"))
            + ").",
            "success",
        )
    else:
        flash(
            _("Unable to create compute node group on ")
            + _cluster_name
            + ": "
            + str(_create.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/create_compute_node_group_simple", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create_compute_node_group_simple():
    """
    Create a compute node group from the simple HTML form on the detail page, the
    form-driven counterpart to create_compute_node_group(). Covers the required
    arguments plus the common optional ones; anything more advanced goes through the
    JSON tab. instance_types and subnet_ids are comma/space separated fields.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-groups"

    _group_name = (request.form.get("group_name") or "").strip()
    _launch_template_id = (request.form.get("launch_template_id") or "").strip()
    _instance_types = _split_csv(request.form.get("instance_types"))
    _min_raw = (request.form.get("min_instance_count") or "").strip()
    _max_raw = (request.form.get("max_instance_count") or "").strip()

    # The AMI (and its matching EDH bootstrap) is defined on the launch template, so the compute
    # node group does not set one -- PCS inherits the launch template's ImageId.
    if not (_group_name and _launch_template_id and _instance_types and _min_raw and _max_raw):
        flash(
            _("Group name, launch template, instance types, minimum and maximum instance count are required."),
            "error",
        )
        return redirect(_detail_url)

    try:
        _min_instance_count = int(_min_raw)
        _max_instance_count = int(_max_raw)
    except ValueError:
        flash(_("Minimum and maximum instance count must be whole numbers."), "error")
        return redirect(_detail_url)

    if _min_instance_count < 0 or _max_instance_count < 1 or _max_instance_count < _min_instance_count:
        flash(
            _("Instance counts must satisfy 0 <= minimum <= maximum, with a maximum of at least 1."),
            "error",
        )
        return redirect(_detail_url)

    _kwargs = {
        "group_name": _group_name,
        "launch_template_id": _launch_template_id,
        "instance_types": _instance_types,
        "min_instance_count": _min_instance_count,
        "max_instance_count": _max_instance_count,
    }
    # Launch template version is optional; the client defaults to "$Latest" when omitted.
    _launch_template_version = (request.form.get("launch_template_version") or "").strip()
    if _launch_template_version:
        _kwargs["launch_template_version"] = _launch_template_version
    _purchase_option = (request.form.get("purchase_option") or "").strip()
    if _purchase_option:
        _kwargs["purchase_option"] = _purchase_option
    _subnet_ids = _split_csv(request.form.get("subnet_ids"))
    if _subnet_ids:
        _kwargs["subnet_ids"] = _subnet_ids
    # Custom AMI is an optional launch-template override; when omitted PCS inherits the launch
    # template's ImageId. Must match the instance types' architecture (validated by EC2 at launch).
    _ami_id = (request.form.get("ami_id") or "").strip()
    if _ami_id:
        _kwargs["ami_id"] = _ami_id
    # Instance profile ARN is optional; the client defaults to the EDH compute node instance
    # profile from SSM when omitted. PCS requires the profile's role to be PCS-scoped.
    _instance_profile_arn = (request.form.get("instance_profile_arn") or "").strip()
    if _instance_profile_arn:
        _kwargs["instance_profile_arn"] = _instance_profile_arn

    # EDH bootstrap runs as a nodeBootstrapped lifecycle action on the node group (mounts the
    # shared filesystems + configures the user directory before slurmd). When enabled the client
    # renders + uploads it and registers the action; edh_base_os pins the package set to the
    # node's AMI OS (defaults to /configuration/BaseOS when omitted).
    if request.form.get("edh_bootstrap") == "on":
        _kwargs["edh_bootstrap"] = True
        _edh_base_os = (request.form.get("edh_base_os") or "").strip()
        if _edh_base_os:
            _kwargs["edh_base_os"] = _edh_base_os

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _create = _client.create_compute_node_group(**_kwargs)
    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("Compute node group ")
            + str(_msg.get("name", _group_name))
            + _(" creation initiated (id: ")
            + str(_msg.get("id", "unknown"))
            + ").",
            "success",
        )
    else:
        flash(
            _("Unable to create compute node group on ")
            + _cluster_name
            + ": "
            + str(_create.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/create_launch_template_simple", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create_launch_template_simple():
    """
    Create a launch template from the simple HTML form on the detail page, the
    form-driven counterpart to create_launch_template(). The launch template fully defines the
    image: the Base OS (which drives the EDH bootstrap package set) and the AMI (ImageId). The
    compute node group inherits this AMI, so it does not set one itself. Security groups and the
    template name still default from the cluster when omitted.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-launch-templates"

    _template_name_input = (request.form.get("template_name") or "").strip()
    if not _template_name_input:
        flash(_("A launch template name is required."), "error")
        return redirect(_detail_url)

    # The operator supplies a PCS-ready AMI directly (it must already carry the PCS agent + Slurm,
    # see working-with_ami_custom.html). The AMI id is therefore REQUIRED -- there is no base OS to
    # resolve a default AMI from anymore.
    _image_id = (request.form.get("image_id") or "").strip()
    if not _image_id:
        flash(_("An AMI ID is required."), "error")
        return redirect(_detail_url)

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    # Namespace the template name as "<cluster-id>-<operator name>-PCSNODE" so templates from this
    # EDH environment are self-describing, never collide with another cluster's, and are clearly
    # identifiable as PCS compute node templates. The cluster id is the EDH ClusterId
    # (/configuration/ClusterId); if it cannot be resolved we fall back to
    # "<operator name>-PCSNODE" rather than block the create.
    _edh_cluster_id = _client._edh_cluster_id_value()
    if _edh_cluster_id:
        _template_name = f"{_edh_cluster_id}-{_template_name_input}-PCSNODE"
    else:
        _template_name = f"{_template_name_input}-PCSNODE"

    # Assemble the inline LaunchTemplateData. The AMI lives here (not on the compute node group) and
    # is used as-is: its architecture is whatever the image already is (EC2 enforces it against the
    # instance types at launch). There is no instance type here -- that is chosen per compute node
    # group. Key pair and security groups are omitted too; the client defaults the SGs from the
    # cluster.
    _launch_template_data = {"ImageId": _image_id}

    # Optional SSH key pair. When the operator names an existing EC2 key pair, bake it into the
    # launch template as KeyName so nodes launched from it accept SSH with that key. Left blank the
    # nodes launch with no key pair (access is expected via SSM Session Manager), so the field is
    # omitted entirely rather than sent empty.
    _key_name = (request.form.get("key_name") or "").strip()
    if _key_name:
        _launch_template_data["KeyName"] = _key_name

    # Optional On-Demand Capacity Reservation. When an operator supplies a reservation id, target it
    # explicitly so nodes launched from this template draw from that reserved capacity. Left blank we
    # omit CapacityReservationSpecification entirely (EC2 default is "open", i.e. use any matching
    # reservation), rather than forcing a preference.
    _capacity_reservation_id = (request.form.get("capacity_reservation_id") or "").strip()
    if _capacity_reservation_id:
        _launch_template_data["CapacityReservationSpecification"] = {
            "CapacityReservationTarget": {
                "CapacityReservationId": _capacity_reservation_id
            }
        }

    # Optional Elastic Fabric Adapter (EFA). When requested, add an EFA-typed primary network
    # interface (DeviceIndex/NetworkCardIndex 0). The security groups resolved by the client are
    # attached to this interface's Groups there (EC2 rejects a top-level SecurityGroupIds alongside
    # NetworkInterfaces). EFA needs the EFA driver pre-baked into the AMI and an EFA-capable instance
    # type on the compute node group; both are the operator's responsibility.
    _enable_efa = (request.form.get("enable_efa") or "").strip().lower() in (
        "1",
        "true",
        "on",
        "yes",
    )
    if _enable_efa:
        _launch_template_data["NetworkInterfaces"] = [
            {"DeviceIndex": 0, "NetworkCardIndex": 0, "InterfaceType": "efa"}
        ]

    # Optional additional EBS data volumes (up to 2). Each is defined by a device name, size (GiB)
    # and volume type; a volume is only added when a size is provided for that slot. Volumes are
    # encrypted at rest by default (standard practice) and deleted on instance termination so they
    # do not linger as orphaned cost. A bad size (non-numeric or <= 0) is a hard error rather than
    # silently dropped.
    _block_device_mappings = []
    _default_ebs_devices = {"1": "/dev/sdb", "2": "/dev/sdc"}
    for _slot in ("1", "2"):
        _size_raw = (request.form.get(f"ebs_size_{_slot}") or "").strip()
        if not _size_raw:
            continue
        try:
            _size = int(_size_raw)
            if _size <= 0:
                raise ValueError
        except ValueError:
            flash(
                _("EBS volume %(slot)s size must be a positive whole number of GiB.")
                % {"slot": _slot},
                "error",
            )
            return redirect(_detail_url)
        _device = (
            request.form.get(f"ebs_device_{_slot}") or ""
        ).strip() or _default_ebs_devices[_slot]
        _vol_type = (request.form.get(f"ebs_type_{_slot}") or "gp3").strip()
        _encrypted = (
            request.form.get(f"ebs_encrypted_{_slot}") or "on"
        ).strip().lower() in ("1", "true", "on", "yes")
        _block_device_mappings.append(
            {
                "DeviceName": _device,
                "Ebs": {
                    "VolumeSize": _size,
                    "VolumeType": _vol_type,
                    "DeleteOnTermination": True,
                    "Encrypted": _encrypted,
                },
            }
        )
    if _block_device_mappings:
        _launch_template_data["BlockDeviceMappings"] = _block_device_mappings

    _kwargs = {"launch_template_data": _launch_template_data, "template_name": _template_name}
    # Name the provisioned EC2 instances after the launch template so they are identifiable in the
    # EC2 console (PCS itself does not set an instance Name tag). Cost-allocation tags: propagate to
    # the launched instances/volumes (instance_tags) so Cost Explorer can group by them, and also
    # stamp the launch template resource itself (tags). The Name tag can still be overridden by a
    # cost tag field if one ever maps to "Name".
    _cost_tags = _collect_cost_tags(request.form)
    _instance_tags = {"Name": _template_name}
    _instance_tags.update(_cost_tags)
    _kwargs["instance_tags"] = _instance_tags
    if _cost_tags:
        _kwargs["tags"] = dict(_cost_tags)

    # NOTE: the launch template no longer carries the EDH bootstrap. For PCS nodes the bootstrap
    # runs as a nodeBootstrapped lifecycle action configured on the compute node group -- see the
    # edh_bootstrap toggle in create_compute_node_group_simple.

    _create = _client.create_launch_template(**_kwargs)
    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("Launch template ")
            + str(_msg.get("name", _template_name))
            + _(" created (id: ")
            + str(_msg.get("id", "unknown"))
            + _(", version: ")
            + str(_msg.get("latest_version", "unknown"))
            + ").",
            "success",
        )
    else:
        flash(
            _("Unable to create launch template on ")
            + _cluster_name
            + ": "
            + str(_create.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/create_queue_simple", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create_queue_simple():
    """
    Create a queue from the simple HTML form on the detail page (queue name plus the
    compute node groups to attach), the form-driven counterpart to create_queue(). The
    cluster comes from the cluster_name field; compute_node_group_ids arrives as a
    multi-select, so we read every selected value.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-queues"

    _queue_name = (request.form.get("queue_name") or "").strip()
    if not _queue_name:
        flash(_("A queue name is required."), "error")
        return redirect(_detail_url)

    # getlist so a multi-select of node groups comes through as a list; empty when none picked.
    _compute_node_group_ids = [
        g for g in request.form.getlist("compute_node_group_ids") if g.strip()
    ] or None

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _create = _client.create_queue(
        queue_name=_queue_name,
        compute_node_group_ids=_compute_node_group_ids,
    )
    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("Queue ")
            + str(_msg.get("name", _queue_name))
            + _(" creation initiated (id: ")
            + str(_msg.get("id", "unknown"))
            + ").",
            "success",
        )
    else:
        flash(
            _("Unable to create queue on ")
            + _cluster_name
            + ": "
            + str(_create.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/create_queue", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create_queue():
    """
    Create a queue on a cluster from a pasted JSON blob mapped onto create_queue()'s
    keyword arguments. The cluster comes from the cluster_name field (posted by the
    detail page); the blob carries only the queue arguments.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-queues"

    _payload, _err = _parse_json_payload(
        request.form.get("raw_json"), _ALLOWED_QUEUE_KWARGS, required=_REQUIRED_QUEUE_KWARGS
    )
    if _err:
        flash(_err, "error")
        return redirect(_detail_url)

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _create = _client.create_queue(**_payload)
    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("Queue ")
            + str(_msg.get("name", _payload.get("queue_name", "")))
            + _(" creation initiated (id: ")
            + str(_msg.get("id", "unknown"))
            + ").",
            "success",
        )
    else:
        flash(
            _("Unable to create queue on ")
            + _cluster_name
            + ": "
            + str(_create.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/create_launch_template", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def create_launch_template():
    """
    Create an EC2 launch template from a pasted JSON blob mapped onto
    create_launch_template()'s keyword arguments. The cluster comes from the
    cluster_name field (posted by the detail page) so the client can default the
    template name and security groups from it; the blob carries the rest. The client
    requires exactly one of launch_template_data / launch_template_data_path and
    returns a SocaError otherwise, which we surface as-is.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-launch-templates"

    _payload, _err = _parse_json_payload(
        request.form.get("raw_json"), _ALLOWED_LT_KWARGS
    )
    if _err:
        flash(_err, "error")
        return redirect(_detail_url)

    # NOTE: the launch template no longer carries the EDH bootstrap. For PCS nodes the bootstrap
    # runs as a nodeBootstrapped lifecycle action configured on the compute node group.

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _create = _client.create_launch_template(**_payload)
    if _create.get("success") is True:
        _msg = _create.get("message") or {}
        flash(
            _("Launch template ")
            + str(_msg.get("name", _payload.get("template_name", "")))
            + _(" created (id: ")
            + str(_msg.get("id", "unknown"))
            + _(", version: ")
            + str(_msg.get("latest_version", "unknown"))
            + ").",
            "success",
        )
    else:
        flash(
            _("Unable to create launch template on ")
            + _cluster_name
            + ": "
            + str(_create.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/queue/<pcs_cluster_name>/<queue_identifier>", methods=["GET"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def queue_detail(pcs_cluster_name, queue_identifier):
    """
    Show a single queue: its details plus a form to sync which compute node groups are
    attached and a delete button. The multi-select is pre-checked with the queue's
    currently attached groups, so submitting sets the exact desired set (PCS replaces the
    association wholesale).
    """
    _cluster_name = (pcs_cluster_name or "").strip()
    _queue_identifier = (queue_identifier or "").strip()
    if not _cluster_name or not _queue_identifier:
        flash(_("A cluster name and queue are required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-queues"

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _get = _client.get_queue(_queue_identifier)
    if _get.get("success") is False:
        flash(
            _("Unable to retrieve queue ")
            + _queue_identifier
            + ": "
            + str(_get.get("message")),
            "error",
        )
        return redirect(_detail_url)

    _queue = _get.get("message") or {}
    # The ids currently attached to the queue, used to pre-select the sync multi-select.
    _attached_ids = [
        c.get("computeNodeGroupId")
        for c in _queue.get("computeNodeGroupConfigurations", [])
        if c.get("computeNodeGroupId")
    ]

    # All node groups on the cluster, so the operator can attach ones not yet on the queue.
    _all_groups = []
    _list_groups = _client.list_compute_node_groups()
    if _list_groups.get("success") is True:
        _all_groups = _list_groups.get("message") or []

    _cluster_id, _display_name = _resolve_cluster_id_and_name(_client, _cluster_name)

    return render_template(
        "admin/pcs/queue.html",
        cluster_id=_cluster_id,
        pcs_cluster_name=_display_name,
        queue=_queue,
        attached_ids=_attached_ids,
        compute_node_groups=_all_groups,
    )


def _parse_slurm_custom_settings(raw):
    """
    Turn the queue Slurm-settings textarea (one `parameterName=parameterValue` per line) into
    the slurmCustomSettings list PCS expects: [{"parameterName": ..., "parameterValue": ...}].

    Returns (settings_list, None) on success or (None, error_message) when a non-blank line has
    no `=` or an empty parameter name. An all-blank textarea yields an empty list, which clears
    the queue's custom settings.
    """
    _settings = []
    for _lineno, _line in enumerate((raw or "").splitlines(), start=1):
        _stripped = _line.strip()
        if not _stripped:
            continue
        if "=" not in _stripped:
            return None, (
                _("Line ")
                + str(_lineno)
                + _(" is not in parameterName=parameterValue form: ")
                + _stripped
            )
        _name, _value = _stripped.split("=", 1)
        _name = _name.strip()
        if not _name:
            return None, _("Line ") + str(_lineno) + _(" has an empty parameter name.")
        _settings.append({"parameterName": _name, "parameterValue": _value.strip()})
    return _settings, None


@admin_pcs.route("/admin/pcs/update_queue", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def update_queue():
    """
    Edit a queue from the queue detail page. The form's `section` field says which part of the
    queue is being changed, so each form only touches its own field and leaves the rest
    untouched (the client treats a None argument as "leave unchanged"):

      * section == "slurm": update the queue's Slurm custom settings only.
      * otherwise (compute node groups): sync the attached compute node groups. The
        compute_node_group_ids multi-select carries the FULL desired set, so this both attaches
        and detaches; an empty selection detaches every group.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    _queue_identifier = (request.form.get("queue_identifier") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-queues"
    _queue_url = "/admin/pcs/queue/" + _cluster_name + "/" + _queue_identifier

    if not _queue_identifier:
        flash(_("A queue is required."), "error")
        return redirect(_detail_url)

    _section = (request.form.get("section") or "compute_node_groups").strip()

    _update_kwargs = {"queue_identifier": _queue_identifier}
    _success_msg = ""

    if _section == "slurm":
        # Slurm custom settings only; leave the compute node group association untouched.
        _settings, _parse_err = _parse_slurm_custom_settings(
            request.form.get("slurm_custom_settings")
        )
        if _parse_err is not None:
            flash(_("Invalid Slurm settings: ") + _parse_err, "error")
            return redirect(_queue_url)
        _update_kwargs["slurm_configuration"] = {"slurmCustomSettings": _settings}
        _success_msg = (
            _("Queue ")
            + _queue_identifier
            + _(" updated; Slurm custom settings now: ")
            + (str(len(_settings)) + _(" setting(s)") if _settings else _("none"))
            + "."
        )
    else:
        # Full desired set: send the (possibly empty) list so groups can be detached as well as
        # attached. getlist keeps every selected option from the multi-select.
        _compute_node_group_ids = [
            g for g in request.form.getlist("compute_node_group_ids") if g.strip()
        ]
        _update_kwargs["compute_node_group_ids"] = _compute_node_group_ids
        _success_msg = (
            _("Queue ")
            + _queue_identifier
            + _(" updated; compute node groups now: ")
            + (", ".join(_compute_node_group_ids) if _compute_node_group_ids else _("none"))
            + "."
        )

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_queue_url)

    _update = _client.update_queue(**_update_kwargs)
    if _update.get("success") is True:
        flash(_success_msg, "success")
    else:
        flash(
            _("Unable to update queue ")
            + _queue_identifier
            + ": "
            + str(_update.get("message")),
            "error",
        )

    return redirect(_queue_url)


@admin_pcs.route("/admin/pcs/delete_queue", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def delete_queue():
    """Delete a queue from a cluster (posted from the queues tab or the queue detail page)."""
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    _queue_identifier = (request.form.get("queue_identifier") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-queues"

    if not _queue_identifier:
        flash(_("A queue is required."), "error")
        return redirect(_detail_url)

    # Destructive: the confirmation checkbox is also enforced server-side, not only in the browser.
    if request.form.get("confirm_delete") != "on":
        flash(
            _("Deletion aborted: tick the confirmation checkbox to delete ") + _queue_identifier + ".",
            "error",
        )
        return redirect(_detail_url)

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _delete = _client.delete_queue(_queue_identifier)
    if _delete.get("success") is True:
        flash(str(_delete.get("message")), "success")
    else:
        flash(
            _("Unable to delete queue ")
            + _queue_identifier
            + ": "
            + str(_delete.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route(
    "/admin/pcs/compute_node_group/<pcs_cluster_name>/<compute_node_group_identifier>",
    methods=["GET"],
)
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def compute_node_group_detail(pcs_cluster_name, compute_node_group_identifier):
    """
    Show a single compute node group: its details plus a delete button. Mirrors the queue
    detail page. Delete is guarded by the edh:ClusterId tag in the client, so only groups
    this EDH environment created can be removed.
    """
    _cluster_name = (pcs_cluster_name or "").strip()
    _cng_identifier = (compute_node_group_identifier or "").strip()
    if not _cluster_name or not _cng_identifier:
        flash(_("A cluster name and compute node group are required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-groups"

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _get = _client.get_compute_node_group(_cng_identifier)
    if _get.get("success") is False:
        flash(
            _("Unable to retrieve compute node group ")
            + _cng_identifier
            + ": "
            + str(_get.get("message")),
            "error",
        )
        return redirect(_detail_url)

    _cluster_id, _display_name = _resolve_cluster_id_and_name(_client, _cluster_name)

    _cng = _get.get("message") or {}

    # No amiId on the group: it boots the AMI of its launch template, show that one instead
    _launch_template_ami_id = ""
    _cng_lt = _cng.get("customLaunchTemplate") or {}
    if not _cng.get("amiId") and _cng_lt.get("id"):
        _lt_ami = _client.get_launch_template_image_id(
            _cng_lt.get("id"), _cng_lt.get("version")
        )
        if _lt_ami.get("success") is True:
            _launch_template_ami_id = _lt_ami.get("message") or ""
        else:
            logger.warning(
                f"Unable to retrieve the launch template AMI for compute node group {_cng_identifier}: {_lt_ami.get('message')}"
            )

    return render_template(
        "admin/pcs/compute_node_group.html",
        cluster_id=_cluster_id,
        pcs_cluster_name=_display_name,
        compute_node_group=_cng,
        launch_template_ami_id=_launch_template_ami_id,
    )


@admin_pcs.route("/admin/pcs/delete_compute_node_group", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def delete_compute_node_group():
    """Delete a compute node group from a cluster (posted from the compute node group page)."""
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    _cng_identifier = (request.form.get("compute_node_group_identifier") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-groups"

    if not _cng_identifier:
        flash(_("A compute node group is required."), "error")
        return redirect(_detail_url)

    # Destructive: the confirmation checkbox is also enforced server-side, not only in the browser.
    if request.form.get("confirm_delete") != "on":
        flash(
            _("Deletion aborted: tick the confirmation checkbox to delete ") + _cng_identifier + ".",
            "error",
        )
        return redirect(_detail_url)

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _delete = _client.delete_compute_node_group(_cng_identifier)
    if _delete.get("success") is True:
        flash(str(_delete.get("message")), "success")
    else:
        flash(
            _("Unable to delete compute node group ")
            + _cng_identifier
            + ": "
            + str(_delete.get("message")),
            "error",
        )

    return redirect(_detail_url)


@admin_pcs.route("/admin/pcs/update_compute_node_group", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def update_compute_node_group():
    """
    Update a compute node group from its detail page. Only the fields the admin fills in are
    sent; blank fields leave the current value untouched. Instance types are not updatable on
    an existing group, so they are not exposed here. Ownership is validated by the edh:ClusterId
    tag in the client, so only groups this EDH environment created can be updated.
    """
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    _cng_identifier = (request.form.get("compute_node_group_identifier") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-groups"
    _cng_url = "/admin/pcs/compute_node_group/" + _cluster_name + "/" + _cng_identifier

    if not _cng_identifier:
        flash(_("A compute node group is required."), "error")
        return redirect(_detail_url)

    # Read only the fields the admin actually filled in; a blank field means "leave unchanged".
    _ami_id = (request.form.get("ami_id") or "").strip() or None
    _launch_template_version = (
        request.form.get("launch_template_version") or ""
    ).strip() or None
    _purchase_option = (request.form.get("purchase_option") or "").strip() or None
    _subnet_ids = [
        s.strip() for s in (request.form.get("subnet_ids") or "").split(",") if s.strip()
    ] or None

    # Scaling bounds are optional numbers; reject anything non-numeric rather than sending it on.
    def _parse_int(field_name):
        _raw = (request.form.get(field_name) or "").strip()
        if not _raw:
            return None, None
        try:
            return int(_raw), None
        except ValueError:
            return None, _("must be a whole number")

    _min_instance_count, _min_err = _parse_int("min_instance_count")
    _max_instance_count, _max_err = _parse_int("max_instance_count")
    if _min_err is not None:
        flash(_("Minimum instance count ") + _min_err + ".", "error")
        return redirect(_cng_url)
    if _max_err is not None:
        flash(_("Maximum instance count ") + _max_err + ".", "error")
        return redirect(_cng_url)

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_cng_url)

    _update = _client.update_compute_node_group(
        compute_node_group_identifier=_cng_identifier,
        ami_id=_ami_id,
        subnet_ids=_subnet_ids,
        launch_template_version=_launch_template_version,
        purchase_option=_purchase_option,
        min_instance_count=_min_instance_count,
        max_instance_count=_max_instance_count,
    )
    if _update.get("success") is True:
        flash(
            _("Compute node group ") + _cng_identifier + _(" update initiated."),
            "success",
        )
    else:
        flash(
            _("Unable to update compute node group ")
            + _cng_identifier
            + ": "
            + str(_update.get("message")),
            "error",
        )

    return redirect(_cng_url)


@admin_pcs.route(
    "/admin/pcs/launch_template/<pcs_cluster_name>/<launch_template_id>", methods=["GET"]
)
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def launch_template_detail(pcs_cluster_name, launch_template_id):
    """
    Show a single EC2 launch template: its details plus a delete button. Mirrors the queue
    detail page. The get/delete are scoped to the edh:ClusterId tag, so only templates this
    EDH environment created can be viewed/removed here.
    """
    _cluster_name = (pcs_cluster_name or "").strip()
    _launch_template_id = (launch_template_id or "").strip()
    if not _cluster_name or not _launch_template_id:
        flash(_("A cluster name and launch template are required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-launch-templates"

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _get = _client.get_launch_template(_launch_template_id)
    if _get.get("success") is False:
        flash(
            _("Unable to retrieve launch template ")
            + _launch_template_id
            + ": "
            + str(_get.get("message")),
            "error",
        )
        return redirect(_detail_url)

    _cluster_id, _display_name = _resolve_cluster_id_and_name(_client, _cluster_name)

    # Compute node groups of this cluster that boot from this launch template, so the page can
    # warn before a delete. list_compute_node_groups only returns summaries (no
    # customLaunchTemplate), so each group is described; scoped to the current cluster to keep
    # it to one call per group. Non-fatal: any failure leaves the list empty (or partial).
    _used_by_compute_node_groups = []
    try:
        _list_groups = _client.list_compute_node_groups()
        if _list_groups.get("success") is True:
            for _summary in _list_groups.get("message") or []:
                _group_id = _summary.get("id")
                if not _group_id:
                    continue
                _group_get = _client.get_compute_node_group(_group_id)
                if _group_get.get("success") is not True:
                    logger.warning(
                        f"Unable to describe compute node group {_group_id} while checking launch template {_launch_template_id} usage: {_group_get.get('message')}"
                    )
                    continue
                _group = _group_get.get("message") or {}
                if (_group.get("customLaunchTemplate") or {}).get("id") == _launch_template_id:
                    _used_by_compute_node_groups.append(
                        {
                            "cluster_name": _display_name,
                            "cluster_id": _cluster_id,
                            "id": _group_id,
                            "name": _group.get("name") or _summary.get("name") or _group_id,
                        }
                    )
        else:
            logger.warning(
                f"Unable to list compute node groups while checking launch template {_launch_template_id} usage: {_list_groups.get('message')}"
            )
    except Exception as err:
        logger.warning(
            f"Unable to check which compute node groups use launch template {_launch_template_id}: {err}"
        )

    return render_template(
        "admin/pcs/launch_template.html",
        cluster_id=_cluster_id,
        pcs_cluster_name=_display_name,
        launch_template=_get.get("message") or {},
        used_by_compute_node_groups=_used_by_compute_node_groups,
    )


@admin_pcs.route("/admin/pcs/delete_launch_template", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def delete_launch_template():
    """Delete an EC2 launch template (posted from the launch template detail page)."""
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    _launch_template_id = (request.form.get("launch_template_id") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    _detail_url = "/admin/pcs/detail/" + _cluster_name + "#nav-launch-templates"

    if not _launch_template_id:
        flash(_("A launch template is required."), "error")
        return redirect(_detail_url)

    # Destructive: the confirmation checkbox is also enforced server-side, not only in the browser.
    if request.form.get("confirm_delete") != "on":
        flash(
            _("Deletion aborted: tick the confirmation checkbox to delete ") + _launch_template_id + ".",
            "error",
        )
        return redirect(_detail_url)

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect(_detail_url)

    _delete = _client.delete_launch_template(_launch_template_id)
    if _delete.get("success") is True:
        flash(
            _("Deleted launch template ") + _launch_template_id + ".",
            "success",
        )
    else:
        flash(
            _("Unable to delete launch template ")
            + _launch_template_id
            + ": "
            + str(_delete.get("message")),
            "error",
        )

    return redirect(_detail_url)


def _as_dict(value):
    """Scheduler config values may come back as a dict (autocast) or as their str()/JSON form."""
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        return ast.literal_eval(str(value))
    except (ValueError, SyntaxError):
        return json.loads(str(value))


def _is_disabled(cfg):
    return cfg.get("enabled") in (False, "false", "False")


def _iter_pcs_scheduler_registrations(pcs_cluster_id):
    """
    Yield (ssm_key, config) for every aws_pcs scheduler registered for pcs_cluster_id (edhctl pcs
    register / the Register with EDH tab), enabled or not. config comes from the prefix read, which
    autocasts values: fine to inspect, NOT to write back (see _disable_pcs_scheduler_registrations).
    """
    if not pcs_cluster_id:
        return
    _all = SocaConfig(key="/configuration/HPC/schedulers/").get_value(return_as=dict)
    if _all.get("success") is not True:
        return  # no scheduler registered at all
    for _key, _value in (_all.get("message") or {}).items():
        try:
            _cfg = _as_dict(_value)
            if _cfg.get("provider") != "aws_pcs":
                continue
            if _as_dict(_cfg.get("slurm_configuration")).get("pcs_cluster_id") != pcs_cluster_id:
                continue
        except Exception as err:
            logger.warning(f"Unable to parse scheduler registration {_key}: {err}")
            continue
        yield _key, _cfg


def _get_pcs_scheduler_registration(pcs_cluster_id):
    """
    Registration status for the PCS Connect tab: {"identifier": str, "enabled": bool} for this
    cluster's aws_pcs scheduler (an enabled one wins over a disabled one), or None if not registered.
    """
    _found = None
    for _key, _cfg in _iter_pcs_scheduler_registrations(pcs_cluster_id):
        _entry = {
            "identifier": _cfg.get("identifier") or _key.split("/")[-1],
            "enabled": not _is_disabled(_cfg),
        }
        if _entry["enabled"]:
            return _entry
        _found = _found or _entry
    return _found


def _disable_pcs_scheduler_registrations(pcs_cluster_id):
    """
    Set enabled=False on every aws_pcs scheduler registered for pcs_cluster_id, so new virtual
    desktop / login nodes stop trying to onboard a deleted cluster. Disabling rather than deleting
    the SSM key keeps it reversible. Returns (disabled identifiers, errors).
    """
    _disabled, _errors = [], []
    for _key, _cfg in _iter_pcs_scheduler_registrations(pcs_cluster_id):
        if _is_disabled(_cfg):
            continue
        try:
            # The prefix read autocasts values (e.g. slurm_version "25.10" -> 25.1): re-read the key
            # as its raw string before rewriting it.
            _raw = SocaConfig(key=_key).get_value(return_as=str)
            if _raw.get("success") is not True:
                _errors.append(f"{_key}: {_raw.get('message')}")
                continue
            _raw_cfg = ast.literal_eval(_raw.get("message"))
            _raw_cfg["enabled"] = False
            _set = SocaConfig(key=_key).set_value(str(_raw_cfg))
            if _set.get("success") is True:
                _disabled.append(_raw_cfg.get("identifier") or _key.split("/")[-1])
            else:
                _errors.append(f"{_key}: {_set.get('message')}")
        except Exception as err:
            _errors.append(f"{_key}: {err}")
    return _disabled, _errors


@admin_pcs.route("/admin/pcs/delete", methods=["POST"])
@login_required
@admin_only
@feature_flag(flag_name="PCS", mode="view")
def delete():
    _cluster_name = (request.form.get("cluster_name") or "").strip()
    if not _cluster_name:
        flash(_("A cluster name is required."), "error")
        return redirect("/admin/pcs")

    # Destructive: require the confirmation checkbox so a stray click cannot tear down a
    # live cluster. No cascade: PCS refuses the delete while queues or compute node groups remain.
    if request.form.get("confirm_delete") != "on":
        flash(
            _("Deletion aborted: tick the confirmation checkbox to delete ") + _cluster_name + ".",
            "error",
        )
        return redirect("/admin/pcs/detail/" + _cluster_name + "#nav-overview")

    try:
        _client = SocaAWSPCSClient(cluster_name=_cluster_name)
    except Exception as err:
        logger.error(f"Unable to init PCS client for {_cluster_name}: {err}")
        flash(_("Unable to initialize the PCS client: ") + str(err), "error")
        return redirect("/admin/pcs")

    _delete = _client.delete_cluster()
    if _delete.get("success") is True:
        flash(str(_delete.get("message")), "success")
        # Stop auto-onboarding the deleted cluster on new virtual desktops / login nodes, when the
        # admin kept "Also disable its EDH registration" ticked in the delete modal (default).
        _disabled, _errors = [], []
        if request.form.get("disable_registration") == "on":
            _disabled, _errors = _disable_pcs_scheduler_registrations(_client.cluster_identifier)
        if _disabled:
            flash(
                _("Disabled the EDH scheduler registration(s): ")
                + ", ".join(_disabled)
                + _(". New nodes will no longer be onboarded to this cluster."),
                "success",
            )
        for _err in _errors:
            logger.error(f"Unable to disable PCS scheduler registration: {_err}")
            flash(_("Unable to disable the EDH scheduler registration ") + _err, "error")
    else:
        flash(
            _("Unable to delete PCS cluster ")
            + _cluster_name
            + ": "
            + str(_delete.get("message")),
            "error",
        )

    return redirect("/admin/pcs")
