# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import logging.handlers
import sys
from typing import Optional
import os
import inspect
import fcntl
import time


class PathTruncatingFormatter(logging.Formatter):
    def format(self, record):
        # custom_pathname return anything after /opt/edh/<cluster_id>/
        _truncate_after = f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID')}/"
        start_pos = record.pathname.find(_truncate_after) + len(_truncate_after)
        record.custom_pathname = record.pathname[start_pos:]

        # Traverse the call stack to get the call chain
        call_stack = inspect.stack()
        call_chain = []
        for frame_info in call_stack:
            filename = frame_info.filename
            function_name = frame_info.function
            # Only track SOCA cluster_manager files, and drop Python libs and logger.py
            if (
                f"{_truncate_after}cluster_manager" in filename
                and "utils/logger.py" not in filename
            ):
                start_pos = filename.find(_truncate_after) + len(_truncate_after)
                truncated_path = filename[start_pos:]
                call_chain.append(f"{truncated_path}:{function_name}")

        # Combine call chain
        record.call_chain = " > ".join(call_chain[::-1])

        return super(PathTruncatingFormatter, self).format(record)


def _read_float(path: str):
    try:
        with open(path) as _fh:
            return float(_fh.read().strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def _write_float(path: str, value: float):
    try:
        with open(path, "w") as _fh:
            _fh.write(repr(value))
    except OSError:
        pass


class _ForkSafeRotationMixin:
    """Make stdlib rotating handlers safe under uwsgi's multi-worker (fork) model.

    The stdlib RotatingFileHandler / TimedRotatingFileHandler open the log stream
    once; under uwsgi the app is loaded in the primary and the fd is INHERITED by
    every forked worker. When one worker rotates (rename + reopen), the others keep
    writing to the old (now renamed/deleted) inode -> rotated files that keep growing,
    held-open (deleted) handles, and rename races (V1734085998).

    This mixin adds, using only the stdlib:
      - fork-aware reopen: if the pid changed since the stream opened, reopen so each
        worker gets its OWN fd (de-shares the inherited descriptor).
      - adopt-on-change: on emit, if the base path's inode changed underneath us
        (another worker rotated), reopen and pick up the fresh file.
      - coordinated rollover: doRollover takes an exclusive fcntl.flock; a
        redundant-rollover guard (subclass-defined) means exactly ONE worker performs
        the rename per period and every other would-be rotator just adopts the result.
    """

    def _init_mp(self):
        self._pid = os.getpid()
        self._ino = self._stream_ino()
        self._lockpath = self.baseFilename + ".rotlock"

    def _stream_ino(self):
        try:
            return os.fstat(self.stream.fileno()).st_ino
        except Exception:
            return None

    def _reopen(self):
        try:
            if self.stream:
                self.stream.close()
        except Exception:
            pass
        self.stream = self._open()
        self._ino = self._stream_ino()
        self._pid = os.getpid()

    def emit(self, record):
        try:
            if os.getpid() != self._pid:
                self._reopen()
            else:
                try:
                    _disk_ino = os.stat(self.baseFilename).st_ino
                    if self._ino is not None and _disk_ino != self._ino:
                        self._reopen()
                except FileNotFoundError:
                    self._reopen()
        except Exception:
            # never let logging bookkeeping crash the caller
            pass
        super().emit(record)

    # --- subclass hooks ---
    def _already_rotated(self, now: float) -> bool:
        """Return True if another worker already rotated for this period."""
        raise NotImplementedError

    def _note_rotation(self, now: float):
        """Record that this worker performed the rotation (owner path)."""

    def _post_adopt(self, now: float):
        """Fix up per-worker scheduling after adopting someone else's rotation."""

    def doRollover(self):
        _lf = open(self._lockpath, "w")
        try:
            fcntl.flock(_lf, fcntl.LOCK_EX)      # serialize would-be rotators
            _now = time.time()
            if self._already_rotated(_now):
                # someone already rotated this period -> adopt the fresh file, no rename
                self._reopen()
                self._post_adopt(_now)
            else:
                # we own the rotation: exactly one rename happens here
                super().doRollover()
                self._ino = self._stream_ino()
                self._pid = os.getpid()
                self._note_rotation(_now)
        finally:
            try:
                fcntl.flock(_lf, fcntl.LOCK_UN)
            finally:
                _lf.close()


class MultiProcessTimedRotatingFileHandler(
    _ForkSafeRotationMixin, logging.handlers.TimedRotatingFileHandler
):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lastrollpath = self.baseFilename + ".lastroll"
        self._init_mp()

    def _already_rotated(self, now: float) -> bool:
        _last = _read_float(self._lastrollpath)
        # self.interval is in seconds (stdlib sets it from when/interval)
        return _last is not None and (now - _last) < self.interval

    def _note_rotation(self, now: float):
        _write_float(self._lastrollpath, now)

    def _post_adopt(self, now: float):
        self.rolloverAt = self.computeRollover(int(now))


class MultiProcessRotatingFileHandler(
    _ForkSafeRotationMixin, logging.handlers.RotatingFileHandler
):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._init_mp()

    def _already_rotated(self, now: float) -> bool:
        # if the base file is already back under the size threshold, another worker
        # rotated it -> adopt instead of renaming again
        try:
            return self.maxBytes > 0 and os.path.getsize(self.baseFilename) < self.maxBytes
        except OSError:
            return False


class SocaLogger:
    def __init__(
        self,
        name: str = "soca_logger",
        level: Optional[int] = None,
        formatter: Optional[str] = None,
    ):
        """
        Constructor for SocaLogger.

        Note: All SOCA scripts expects name to be soca_logger

        Parameters:
        name (str):  # Name of the logger. ! IMPORTANT: All SOCA scripts expects soca_logger !
        level (int / logging.Level): Minimum logging level to be captured, default to INFO, enable debug via export SOCA_DEBUG=1
        formatter (int): Optional: Enforce a customized formatter
        """
        self._logger = logging.getLogger(name)
        _soca_debug = os.environ.get("EDH_DEBUG", os.environ.get("SOCA_DEBUG", "0"))
        if str(_soca_debug) in ["true", "on", "1", "yes", "enabled"]:
            _debug = True
        else:
            _debug = False

        if level is None:
            if _debug:
                self._level = logging.DEBUG
            else:
                self._level = logging.INFO
        else:
            self._level = level

        self._logger.setLevel(self._level)
        if not formatter:
            if _debug or self._level == logging.DEBUG:
                _format = "[%(asctime)s] [%(levelname)s] [%(lineno)d] [%(custom_pathname)s] [%(call_chain)s] [%(funcName)s] [%(message)s]"
            else:
                # call_chain is left empty when debug is disabled to avoid un-necessary text.
                _format = "[%(asctime)s] [%(levelname)s] [%(lineno)d] [%(custom_pathname)s] [] [%(funcName)s] [%(message)s]"
            self._formatter = PathTruncatingFormatter(_format)
        else:
            self._formatter = logging.Formatter(formatter)

    def stdout_handler(self):
        _handler = logging.StreamHandler(sys.stdout)
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def file_handler(self, file_path: str):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        _handler = logging.FileHandler(file_path)
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def rotating_file_handler(
        self, file_path: str, max_bytes: int = 1024 * 1024 * 50, backup_count: int = 5
    ):  # create chunk of 50 mb
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        _handler = MultiProcessRotatingFileHandler(
            file_path, maxBytes=max_bytes, backupCount=backup_count
        )
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def timed_rotating_file_handler(
        self,
        file_path: str,
        when: str = "W0",  # https://docs.python.org/3/library/logging.handlers.html#logging.handlers.TimedRotatingFileHandler
        interval: int = 1,
        backup_count: int = 5,
    ):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        _handler = MultiProcessTimedRotatingFileHandler(
            file_path, when=when, interval=interval, backupCount=backup_count
        )
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def get_logger(self):
        return self._logger
