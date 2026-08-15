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

        _cmd = f"bash -c {shlex.quote(f'{self.load_scheduler_environment} && {command}')}"

        # For reference: SocaSubprocessClient(command=_cmd).run()
        logger.debug(f"{self.__class__.__name__} Run Command: {_cmd}")

        return _cmd

    def normalize_job_name(self, job_name: str) -> str:
        """Return the job name unchanged. Scheduler-specific builders override to sanitize."""
        return job_name


class SocaHpcPBSJobCommandBuilder(SocaHpcBaseJobCommandBuilder):
    @property
    def provider(self) -> str:
        if self.scheduler_info.provider == SocaHpcSchedulerProvider.PBSPRO:
            return SocaHpcSchedulerProvider.PBSPRO
        elif self.scheduler_info.provider == SocaHpcSchedulerProvider.OPENPBS:
            return SocaHpcSchedulerProvider.OPENPBS

    @property
    def load_scheduler_environment(self) -> str:
        return f"export PBS_CONF_FILE={self.scheduler_info.pbs_configuration.pbs_exec}/pbs.conf && source {self.scheduler_info.pbs_configuration.pbs_exec}/pbs.conf"

    def qstat(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qstat", args)

    def qsub(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qsub", args)

    def qalter(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qalter", args)

    def qdel(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qdel", args)

    def pbsnodes(self, args: Optional[str] = None) -> str:
        return self._build_cmd("pbsnodes", args)

    def qmgr(self, args: Optional[str] = None) -> str:
        return self._build_cmd("qmgr", args)

    def normalize_job_name(self, job_name: str) -> str:
        """Sanitize a job name for PBS `-N`; qsub/qalter reject chars outside PBS's set."""
        if not job_name:
            return job_name
        # PBS accepts alphanumerics plus . _ - ; the first char must be alphanumeric.
        _normalized = re.sub(r"[^A-Za-z0-9._-]", "_", job_name)
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
        return f"export SLURM_CONF={self.scheduler_info.slurm_configuration.install_sysconfig_path}/slurm.conf"

    def sbatch(self, args: Optional[str] = None) -> str:
        return self._build_cmd("sbatch", args)

    def scontrol(self, args: Optional[str] = None) -> str:
        return self._build_cmd("scontrol", args)

    def scancel(self, args: Optional[str] = None) -> str:
        return self._build_cmd("scancel", args)

    def squeue(self, args: Optional[str] = None) -> str:
        return self._build_cmd("squeue", args)
