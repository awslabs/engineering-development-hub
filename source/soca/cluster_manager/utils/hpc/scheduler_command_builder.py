# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from abc import ABC, abstractmethod

import logging
import re
import shlex
from typing import Optional
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider

logger = logging.getLogger("soca_logger")


class SocaHpcBaseJobCommandBuilder(ABC):
    """
    This class build LSF/PBS/Slurm command and ensure the command point to the correct Scheduler configuration
    This is useful when you have multiple scheduler clients installed on your SOCA Controller
    Recommended to always use these helpers and never call commands such as `bjobs / qstat / squeues ...` directly
    """

    def __init__(self, scheduler_info: SocaHpcScheduler):
        self.scheduler_info = scheduler_info

    # Each subclass must define its scheduler provider and setup environment command
    @property
    @abstractmethod
    def provider(self) -> str:
        pass

    @property
    @abstractmethod
    def load_scheduler_environment(self) -> str:
        pass

    # Common command builder
    def _build_cmd(self, command: str, args: Optional[str] = None) -> str:
        """
        Builds a shell-safe command string for execution.
        This output is meant to be send to SocaSubprocessClient
        """
        if args:
            command += " " + " ".join(shlex.quote(a) for a in shlex.split(args))

        if self.scheduler_info.provider != self.provider:
            logger.error(
                f"{self.__class__.__name__} only supports {self.provider}, "
                f"but got {self.scheduler_info.provider}"
            )
            return ""

        _cmd = (
            f"bash -c {shlex.quote(f'{self.load_scheduler_environment} && {command}')}"
        )

        # For reference: SocaSubprocessClient(command=_cmd).run()
        logger.debug(f"{self.__class__.__name__} Run Command: {_cmd}")

        return _cmd

    def normalize_job_name(self, job_name: str) -> str:
        """Sanitize a job name for use in a scheduler directive."""
        if not job_name:
            return job_name
        # A quote, space or shell metacharacter would otherwise break out of a
        # directive such as `#BSUB -J "name[1-10]"` and append further options.
        return re.sub(r"[^A-Za-z0-9._-]", "_", job_name)


class SocaHpcPBSJobCommandBuilder(SocaHpcBaseJobCommandBuilder):
    @property
    def provider(self) -> str:
        if self.scheduler_info.provider == SocaHpcSchedulerProvider.PBSPRO:
            return SocaHpcSchedulerProvider.PBSPRO
        elif self.scheduler_info.provider == SocaHpcSchedulerProvider.OPENPBS:
            return SocaHpcSchedulerProvider.OPENPBS

    @property
    def load_scheduler_environment(self) -> str:
        # PATH is set explicitly: pbs.conf carries PBS_EXEC but never touches PATH, and
        # EDH installs PBS under a per-cluster prefix that is on no default PATH. Without
        # this, every bare command below resolves only in a shell that already happens to
        # have PBS on PATH -- so a cron or a service unit gets "command not found".
        _pbs_exec = self.scheduler_info.pbs_configuration.pbs_exec
        return (
            f"export PBS_CONF_FILE={_pbs_exec}/pbs.conf"
            f" && source {_pbs_exec}/pbs.conf"
            f" && export PATH={_pbs_exec}/bin:{_pbs_exec}/sbin:$PATH"
        )

    def qstat(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qstat", args)

    def qsub(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qsub", args)

    def qalter(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qalter", args)

    def qdel(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qdel", args)

    def qhold(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qhold", args)

    def qrls(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qrls", args)

    def pbsnodes(self, args: Optional[str] = None) -> str:
        return self._build_cmd("pbsnodes", args)

    def qmgr(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qmgr", args)

    def normalize_job_name(self, job_name: str) -> str:
        """Sanitize a job name for PBS `-N`; qsub/qalter reject chars outside PBS's set."""
        _normalized = super().normalize_job_name(job_name)
        if not _normalized:
            return _normalized
        # PBS additionally requires the first char to be alphanumeric.
        if not _normalized[0].isalnum():
            _normalized = f"j{_normalized}"
        return _normalized[:230]  # stay within PBS Pro's job-name length ceiling


class SocaHpcLSFJobCommandBuilder(SocaHpcBaseJobCommandBuilder):
    @property
    def provider(self) -> str:
        return SocaHpcSchedulerProvider.LSF

    @property
    def load_scheduler_environment(self) -> str:
        return (
            f"source {self.scheduler_info.lsf_configuration.lsf_top}/conf/profile.lsf"
        )

    def bjobs(self, args: Optional[str] = None) -> str:
        return self._build_cmd("bjobs", args)

    def bsub(self, args: Optional[str] = None) -> str:
        return self._build_cmd("bsub", args)

    def bmod(self, args: Optional[str] = None) -> str:
        return self._build_cmd("bmod", args)

    def bkill(self, args: Optional[str] = None) -> str:
        return self._build_cmd("bkill", args)

    def bhosts(self, args: Optional[str] = None) -> str:
        return self._build_cmd("bhosts", args)

    def lshosts(self, args: Optional[str] = None) -> str:
        return self._build_cmd("lshosts", args)


class SocaHpcSlurmJobCommandBuilder(SocaHpcBaseJobCommandBuilder):
    @property
    def provider(self) -> str:
        return SocaHpcSchedulerProvider.SLURM

    @property
    def load_scheduler_environment(self) -> str:
        # Same reason as PBS above: exporting SLURM_CONF alone leaves sbatch/squeue/etc
        # unresolvable, because EDH installs Slurm under a per-cluster prefix.
        _slurm = self.scheduler_info.slurm_configuration
        return (
            f"export SLURM_CONF={_slurm.install_sysconfig_path}/slurm.conf"
            f" && export PATH={_slurm.install_prefix_path}/bin:"
            f"{_slurm.install_prefix_path}/sbin:$PATH"
        )

    def sbatch(self, args: Optional[str] = None) -> str:
        return self._build_cmd("sbatch", args)

    def scontrol(self, args: Optional[str] = None) -> str:
        return self._build_cmd("scontrol", args)

    def scancel(self, args: Optional[str] = None) -> str:
        return self._build_cmd("scancel", args)

    def squeue(self, args: Optional[str] = None) -> str:
        return self._build_cmd("squeue", args)


class SocaHpcPCSJobCommandBuilder(SocaHpcBaseJobCommandBuilder):
    """
    Client must be configured with PCS Slurm
    https://docs.aws.amazon.com/pcs/latest/userguide/working-with_ami_custom_install-slurm.html
    """

    @property
    def provider(self) -> str:
        return SocaHpcSchedulerProvider.AWS_PCS

    @property
    def load_scheduler_environment(self) -> str:
        # One sackd runs per PCS cluster (RuntimeDirectory=slurm-<pcs_cluster_id>), same model as
        # https://docs.aws.amazon.com/pcs/latest/userguide/multi-cluster-login-script-code.html
        # SLURM_CONF / SLURM_SACK_SOCKET point the Slurm client at this cluster's sackd. Both are
        # optional so a PCS scheduler registered before this change keeps the host default sackd.
        _pcs = self.scheduler_info.slurm_configuration
        _env = (
            f"export PATH={_pcs.install_prefix_path}/bin:"
            f"{_pcs.install_prefix_path}/sbin:$PATH"
        )
        if _pcs.sack_socket_path:
            _env += (
                f" && export SLURM_CONF={_pcs.install_sysconfig_path}/slurm.conf"
                f" && export SLURM_SACK_SOCKET={_pcs.sack_socket_path}"
            )
        return _env

    def sbatch(self, args: Optional[str] = None) -> str:
        return self._build_cmd("sbatch", args)

    def scontrol(self, args: Optional[str] = None) -> str:
        return self._build_cmd("scontrol", args)

    def scancel(self, args: Optional[str] = None) -> str:
        return self._build_cmd("scancel", args)

    def squeue(self, args: Optional[str] = None) -> str:
        return self._build_cmd("squeue", args)
