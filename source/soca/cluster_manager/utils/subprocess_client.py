# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import subprocess
import shlex
import pwd
import logging
import grp
import os
from typing import Optional, Callable
import base64
from utils.error import SocaError
from utils.response import SocaResponse


logger = logging.getLogger("soca_logger")


class SocaSubprocessClient:
    def __init__(self, run_command: str, run_as: Optional[str] = None):
        self._command = run_command
        self._run_as = run_as

    def _make_demote_fn(self) -> Optional[Callable[[], None]]:
        """Return a preexec_fn that sets UID/GID/groups for the given username."""
        pw = pwd.getpwnam(self._run_as)
        target_uid = pw.pw_uid
        target_gid = pw.pw_gid
        groups = [g.gr_gid for g in grp.getgrall() if self._run_as in g.gr_mem]

        def demote():
            try:
                if groups:
                    os.setgroups(groups)
            except Exception as e:
                logger.debug(f"setgroups failed for {self._run_as}: {e}")
            # Use atomic calls if available
            if hasattr(os, "setresgid"):
                os.setresgid(target_gid, target_gid, target_gid)
            else:
                os.setgid(target_gid)
            if hasattr(os, "setresuid"):
                os.setresuid(target_uid, target_uid, target_uid)
            else:
                os.setuid(target_uid)

        return demote

    def run(
        self,
        capture_output: Optional[bool] = True,
        text: Optional[bool] = True,
        shell: Optional[bool] = False,
        cwd: Optional[str] = None,
        timeout: Optional[int] = 30,
        universal_newlines: Optional[bool] = None,  # cannot be set with text = True
        stdin: Optional[int] = None,  # subprocess.PIPE / DEVNULL are int sentinels
        stdout: Optional[int] = None,  # subprocess.PIPE / DEVNULL are int sentinels
        stderr: Optional[int] = None,  # subprocess.STDOUT is an int sentinel
        env: Optional[dict] = None,
        non_fatal_rcs: Optional[list[int]] = None,
    ) -> dict:
        """
        Execute the shell command.

        Args:
            capture_output (bool): Whether to capture the output.
            text (bool): Whether to return output as a string vs byte.
            shell (bool): Whether to run the command in the shell. Be careful when you use this.
            cwd (str): The current working directory.
            timeout (int): The timeout in seconds.
            universal_newlines (bool): Whether to use universal newlines.
            stdin (subprocess.PIPE or subprocess.DEVNULL): The input stream.
            stdout (subprocess.PIPE or subprocess.DEVNULL): The output stream.
            stderr (subprocess.STDOUT): The error stream.
            env (str): The environment variables.
            non_fatal_rcs(list of ints): non-zero return codes that are considered non-fatal.

        Returns:
            dict: The result of the command.
        """
        if non_fatal_rcs is None:
            non_fatal_rcs: list = []

        logger.info(
            f"Running Subprocess command {self._command}, capture_output: {capture_output}, text: {text}, shell: {shell}"
        )
        logger.debug(f"Subprocess Command info: {locals()}")

        # sanitize log for output and pass them as base64 hash
        # encode _env in base64 to avoid breaking sequences such as 'BASH_FUNC_which%%': f'() {  ( alias;\n eval ${which_declare} ) | /usr/bin/which --tty-only --read-alias --read-functions --show-tilde --show-dot "$@"\n}

        _env_log = {
            k: ("REDACTED" if k.startswith("SOCA_") else v)
            for k, v in (env or {}).items()
        }
        _encoded_env_log = base64.b64encode(str(_env_log).encode("utf-8")).decode(
            "utf-8"
        )

        if text in [True, False] and universal_newlines is not None:
            return SocaError.SUBPROCESS_ERROR(
                command=self._command,
                stdout="",
                stderr="",
                env=_encoded_env_log,
                returncode=-1,
                helper=f"You cannot set both text and universal_newlines as they are mutually exclusive",
            )

        try:
            if self._run_as:
                logger.info(
                    f"Command must run as specific user : {self._run_as}, creating preexec_fn .."
                )

                try:
                    preexec_fn = self._make_demote_fn()
                except KeyError:
                    return SocaError.SUBPROCESS_ERROR(
                        command="preexec_fn",
                        stdout="",
                        stderr=f"Unable to demote to user {self._run_as} because this user does not seems to exist. Validate sssd.conf",
                        env=_encoded_env_log,
                        returncode=1,
                        helper=f"Unable to demote to user {self._run_as} because this user does not seems to exist. Validate sssd.conf",
                    )

                except Exception as e:
                    return SocaError.SUBPROCESS_ERROR(
                        command="preexec_fn",
                        stdout="",
                        stderr=f"Failed to create preexec_fn for user {self._run_as}: {e}",
                        env=_encoded_env_log,
                        returncode=1,
                        helper=f"Failed to create preexec_fn for user {self._run_as}: {e}",
                    )
                logger.debug(f"preexec_fn created for user {self._run_as}")
            else:
                preexec_fn = None

            if shell:
                logger.warning(
                    f"Running command in shell mode is dangerous. Make sure you sanitized the command ({self._command}) correctly"
                )
                _run_cmd = self._command
            else:
                _run_cmd = shlex.split(self._command)

            # Normalize capture_output into explicit PIPE streams before calling
            # subprocess.run(). The WebUI runs under gevent (SSE), and gevent's
            # monkey-patched subprocess.run() raises ValueError if stdout/stderr are
            # present *at all* -- even as None -- alongside capture_output; stdlib
            # only rejects non-None values. Passing explicit stdout/stderr and never
            # passing capture_output is correct under both stdlib and gevent.
            _stdout_arg = stdout
            _stderr_arg = stderr
            if capture_output:
                if _stdout_arg is None:
                    _stdout_arg = subprocess.PIPE
                if _stderr_arg is None:
                    _stderr_arg = subprocess.PIPE

            try:
                _process = subprocess.run(
                    _run_cmd,
                    stdin=stdin,
                    stdout=_stdout_arg,
                    stderr=_stderr_arg,
                    text=text,
                    env=env,
                    shell=shell,
                    cwd=cwd,
                    timeout=timeout,
                    universal_newlines=universal_newlines,
                    preexec_fn=preexec_fn,
                )  # nosec

                logger.debug(f"Subprocess command {_process}")

                _stdout = _process.stdout
                _stderr = _process.stderr
                _returncode = _process.returncode
                logger.debug(f"Subprocess command result {_process}")

            except subprocess.CalledProcessError as e:
                return SocaError.SUBPROCESS_ERROR(
                    command=self._command,
                    stdout="",
                    stderr=f"{e.stderr.decode()}",
                    returncode=-1,
                    env=_encoded_env_log,
                    helper=f"{self._command} failed: ",
                )

        except Exception as e:
            return SocaError.SUBPROCESS_ERROR(
                command=self._command,
                stdout="",
                stderr=f"{e}",
                env=_encoded_env_log,
                returncode=-1,
                helper=f"Unable to run {self._command}",
            )

        if _stderr or _returncode != 0:
            if _returncode in non_fatal_rcs:
                return SocaResponse(
                    success=True,
                    message={
                        "command": self._command,
                        "stdout": _stdout,
                        "stderr": _stderr,
                        "env": _encoded_env_log,
                        "returncode": _returncode,
                        "helper": "Command ran with nonfatal returncode",
                    },
                )
            else:
                return SocaError.SUBPROCESS_ERROR(
                    command=self._command,
                    stdout="",
                    stderr=_stderr,
                    env=_encoded_env_log,
                    returncode=_returncode,
                    helper=f"{self._command} has returned an error",
                )
        else:
            return SocaResponse(
                success=True,
                message={
                    "command": self._command,
                    "stdout": _stdout,
                    "stderr": _stderr,
                    "returncode": _returncode,
                    "env": _encoded_env_log,
                    "helper": "Command ran successfully",
                },
            )
