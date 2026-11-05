# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging

from pydantic import BaseModel, ValidationInfo, field_validator, model_validator
from typing import Optional
from pathlib import Path
from enum import Enum
from utils.config import SocaConfig
from utils.cast import SocaCastEngine


logger = logging.getLogger("soca_logger")


class SchedulerMirroringTarget:
    # This is under active development for HPC hybrid use cases

    scheduler_endpoint: str  # IP/DNS of the source scheduler
    ssh_user: str  # User to use to establish an SSH connection to the source scheduler
    ssh_private_key_path: (
        str  # SSH key to use to establish an SSH connection to the source scheduler
    )
    queues: list  # List of queues to monitor on the source scheduler
    spooler_dir_path: str  # Path to the spooler

class SocaHpcSchedulerLSFConfig(BaseModel):
    lsf_top: str  # Absolute path to the root directory where LSF will be installed (e.g., /opt/lsf/). This directory must not already exist.
    version: str  # LSF version in Major.Minor format (e.g., 10.1 for LSF 10.1.0.14). Verify by checking an existing installation (e.g., /opt/lsf/<version>) or the installer filename (e.g., lsf10.1_lsfinstall_linux_x86_64.tar.Z).

class SocaHpcSchedulerPBSConfig(BaseModel):
    pbs_exec: str  # Root directory where PBS binaries and libraries will be installed (e.g., /opt/pbs). This directory must not already exist.
    pbs_home: str  # Directory for PBS runtime and spool files (e.g., /var/spool/pbs). This directory must not already exist.

class SocaHpcSchedulerSlurmConfig(BaseModel):
    # AWS PCS only: sackd socket of this cluster (e.g. /run/slurm-<pcs_cluster_id>/sack.socket). Each PCS cluster runs its own sackd, so several PCS clusters can be registered on the same host.
    sack_socket_path: Optional[str] = None
    install_prefix_path: str  # Root directory for Slurm installation, including bin, sbin, lib, and log directories (e.g., /opt/slurm). This directory must not already exist.
    install_sysconfig_path: str  # Directory containing Slurm configuration files (e.g., slurm.conf, slurm.key) (e.g., /etc/slurm). This directory must not already exist._sysconfig_path: str  # Path to slurm.conf, slurm.key (e.g: /etc/slurm) - Make sure this path does not already exist

class SocaHpcSchedulerProvider(str, Enum):
    # Stable
    OPENPBS = "openpbs"
    PBSPRO = "pbspro"

    # Preview - Not suitable for production workloads yet
    LSF = "lsf"
    SLURM = "slurm"
    AWS_PCS = "aws_pcs"  # AWS ParallelCluster Scheduler (PCS)
    # Following providers are not yet supported
    # AWS_BATCH = "awsbatch"


def get_schedulers(
    scheduler_identifiers: list[str] = None, return_disabled_schedulers: bool = False
) -> list[SocaHpcScheduler]:

    logger.debug("Retrieving all enabled schedulers")

    # Returns all enabled schedulers by default. Limit the list by specifying a scheduler_identifiers list
    _scheduler_ssm_prefix = "/configuration/HPC/schedulers/"
    _find_scheduler_config = SocaConfig(key=_scheduler_ssm_prefix).get_value(
        return_as=dict
    )

    _schedulers = []
    if _find_scheduler_config.get("success") is True:
        for _ssm_key, _scheduler_configuration in _find_scheduler_config.get(
            "message"
        ).items():
            logger.debug(f"Validating {_ssm_key=}: {_scheduler_configuration}")
            _scheduler_configuration_as_dict = SocaCastEngine(
                data=_scheduler_configuration
            ).autocast(
                type_overrides={"lsf_configuration.version": str}
            )  # enforce lsf_configuration to str

            if _scheduler_configuration_as_dict.get("success") is False:
                logger.error(
                    f"Unable to validate {_ssm_key=} due to {_scheduler_configuration_as_dict.get('message')}"
                )
                break
            else:
                _scheduler_configuration = _scheduler_configuration_as_dict.get(
                    "message"
                )
                if not isinstance(_scheduler_configuration, dict):
                    logger.error(
                        f"Unable to validate {_scheduler_configuration=} as valid dictionary due. Verify syntax Jobs won't be monitored"
                    )
                    break
                try:
                    _scheduler = SocaHpcScheduler(
                        endpoint=_scheduler_configuration.get("endpoint", None),
                        provider=_scheduler_configuration.get("provider", None),
                        enabled=_scheduler_configuration.get("enabled", None),
                        binary_folder_paths=_scheduler_configuration.get(
                            "binary_folder_paths", None
                        ),
                        soca_managed_nodes_provisioning=_scheduler_configuration.get(
                            "soca_managed_nodes_provisioning", None
                        ),
                        identifier=_scheduler_configuration.get("identifier", None),
                        lsf_configuration=_scheduler_configuration.get(
                            "lsf_configuration", None
                        ),
                        pbs_configuration=_scheduler_configuration.get(
                            "pbs_configuration", None
                        ),
                        slurm_configuration=_scheduler_configuration.get(
                            "slurm_configuration", None
                        ),
                    )
                    if (
                        scheduler_identifiers
                        and _scheduler.identifier not in scheduler_identifiers
                    ):
                        logger.debug(
                            f"{_scheduler.identifier} not in the scheduler allow list {scheduler_identifiers}. Skipping ..."
                        )
                        continue

                    if not _scheduler.enabled:
                        logger.warning(f"{_scheduler=} does not seems to be enabled ")
                        if return_disabled_schedulers:
                            _schedulers.append(_scheduler)

                    else:
                        logger.debug(
                            f"{_scheduler=} has valid configuration. Nodes/Jobs will be monitored"
                        )
                        _schedulers.append(_scheduler)

                except Exception as e:
                    logger.error(
                        f"Unable to validate Scheduler {_scheduler_configuration=} because of {e}, skipping ..."
                    )
    else:
        logger.error(
            f"Unable to find SSM /configuration/HPC/schedulers config due to {_find_scheduler_config.get('message')}"
        )

    logger.debug(f"Scheduler List: {_schedulers=}")
    return _schedulers


class SocaHpcScheduler(BaseModel):
    
    # Scheduler Provider
    provider: SocaHpcSchedulerProvider = None

    # Whether this scheduler will be monitored
    enabled: bool = None

    # Endpoint can be anything (IP, DNS, local name) as long as it can resolves
    endpoint: str = None

    # Must be unique accross other schedulers registered to your SOCA environment
    identifier: str = None

    # This flag determines whether SOCA is responsible for managing host registration with the scheduler.
    # Enabling it requires that the SOCA Controller has the necessary permissions to update scheduler settings and network access to the scheduler host if running on-premises.
    # If this flag is True, SOCA will try to install and configure the scheduler client on all provisioned nodes based on the pbs/lsf_slurm_configuration values
    soca_managed_nodes_provisioning: bool = None

    # Path(s) to the scheduler binaries.
    #
    # These paths will be added to the $PATH environment variable for all subprocess
    #
    # You can specify multiple directories using ':' as a separator.
    # Example:
    #   /custom/bin:/custom2/bin:/custom3/bin
    binary_folder_paths: Optional[str] = ""

    # Required extra configuration if provider is LSF
    lsf_configuration: Optional[SocaHpcSchedulerLSFConfig] = None

    # Required extra configuration if provider is Slurm
    slurm_configuration: Optional[SocaHpcSchedulerSlurmConfig] = None

    # Required extra configuration if provider is PBS
    pbs_configuration: Optional[SocaHpcSchedulerPBSConfig] = None

    # Force SOCA to poll a specific queue on a remote scheduler and provision capacity
    # based on incoming job requests.
    #
    # Example:
    #   A user submits a job to a designated queue on the remote scheduler.
    #   SOCA detects the request, provisions the necessary capacity for that queue,
    #   and executes the job on AWS
    #
    # Note:
    #   This feature is not currently supported.
    mirroring_scheduler: Optional[SocaHpcScheduler] = None

    @model_validator(mode="after")
    def _validate_model(self):
        if not self.endpoint.strip():
            raise ValueError("endpoint cannot be empty")

        if not self.identifier.strip():
            raise ValueError("identifier cannot be empty")

        if (
            self.provider == SocaHpcSchedulerProvider.LSF
            and self.lsf_configuration is None
        ):
            raise ValueError("lsf_configuration is required when provider is LSF.")

        if (
            self.provider in [SocaHpcSchedulerProvider.SLURM, SocaHpcSchedulerProvider.AWS_PCS]
            and self.slurm_configuration is None
        ):
            raise ValueError("slurm_configuration is required when provider is Slurm or PCS.")

        if (
            self.provider
            in [SocaHpcSchedulerProvider.PBSPRO, SocaHpcSchedulerProvider.OPENPBS]
            and self.pbs_configuration is None
        ):
            raise ValueError("pbs_configuration is required when provider is PBS.")
    
        # Required binaries for each scheduler
        SCHEDULER_BINARIES = {
            SocaHpcSchedulerProvider.OPENPBS: [
                "qmgr",
                "qstat",
                "qalter",
                "pbsnodes",
                "qsub",
                "qdel",
            ],
            SocaHpcSchedulerProvider.PBSPRO: [
                "qmgr",
                "qstat",
                "qalter",
                "pbsnodes",
                "qsub",
                "qdel",
            ],
            SocaHpcSchedulerProvider.LSF: [
                "bjobs",
                "bmod",
                "bsub",
                "bqueues",
                "bkill",
                "lshosts",
            ],
            SocaHpcSchedulerProvider.SLURM: [
                "sbatch",
                "squeue",
                "sinfo",
                "scancel",
                "scontrol",
            ],
            SocaHpcSchedulerProvider.AWS_PCS: [
                "sbatch",
                "squeue",
                "sinfo",
                "scancel",
                "scontrol",
            ],
        }

        provider = self.provider
        if not provider or provider not in SCHEDULER_BINARIES:
            raise ValueError(
                f"Unable to validate required binary: Unknown or missing scheduler provider: {provider}"
            )

        required_bins = SCHEDULER_BINARIES[provider]

        if provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
            SocaHpcSchedulerProvider.SLURM,
            SocaHpcSchedulerProvider.AWS_PCS,
        ]:
            # Expand paths and check existence
            paths = [
                Path(p).expanduser()
                for p in (self.binary_folder_paths or "").split(":")
                if p
            ]

            if self.provider == SocaHpcSchedulerProvider.AWS_PCS:
                # AWS PCS always installs Slurm under /opt/aws/pcs/ (e.g.
                # /opt/aws/pcs/scheduler/slurm-<version>/bin), so reject any binary
                # path outside that tree.
                _bad_pcs_paths = [
                    str(path)
                    for path in paths
                    if not str(path).startswith("/opt/aws/pcs/")
                ]
                if _bad_pcs_paths:
                    raise ValueError(
                        "For AWS PCS, binary_folder_paths must be located under "
                        "/opt/aws/pcs/ (e.g. /opt/aws/pcs/scheduler/slurm-<version>/bin):\n"
                        f"{''.join(f' - {p}\n' for p in _bad_pcs_paths)}"
                    )

            _invalid_paths = [
                (
                    f"{path} (does not exist)"
                    if not path.exists()
                    else f"{path} (not a directory)" if not path.is_dir() else None
                )
                for path in paths
            ]
            _invalid_paths = [p for p in _invalid_paths if p]

            if _invalid_paths:
                raise ValueError(
                    f"Invalid binary_folder_paths:\n{''.join(f' - {p}\n' for p in _invalid_paths)}"
                    "Ensure each path exists and is a directory."
                )

            # Check required binaries exist in at least one path
            missing_bins = [
                bin_name
                for bin_name in required_bins
                if not any((path / bin_name).exists() for path in paths)
            ]
            if missing_bins:
                raise ValueError(
                    f"The following required binaries for {provider.value} are missing:\n"
                    f"{''.join(f' - {b}\n' for b in missing_bins)}"
                )

        elif provider == SocaHpcSchedulerProvider.LSF:

            if not Path(f"{self.lsf_configuration.lsf_top}/conf/profile.lsf").exists():
                raise ValueError(
                    f"Unable to find {self.lsf_configuration.lsf_top}/conf/profile.lsf"
                )

            _bin_path_hierarchy = (
                Path(self.lsf_configuration.lsf_top) / self.lsf_configuration.version
            )
            _all_lsf_files = [
                p.name for p in _bin_path_hierarchy.rglob("*") if p.is_file()
            ]
            for _f in required_bins:
                if _f in _all_lsf_files:
                    continue
                else:
                    raise ValueError(f"Unable to find {_f} in {_bin_path_hierarchy}")

        return self
