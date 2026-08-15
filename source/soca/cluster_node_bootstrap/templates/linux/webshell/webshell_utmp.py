######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                                #
######################################################################################################################
"""
EDH Webshell utmp/wtmp helper.

Why this module exists
----------------------
The webshell sidecar wraps each browser tab in `su - <user> -c 'tmux ...'`
inside a fresh PTY. `su(1)` on modern util-linux distros (Amazon Linux, RHEL,
Ubuntu) is intentionally compiled WITHOUT utmp support, so it never registers
the session in /var/run/utmp. PAM's pam_loginuid touches /proc/self/loginuid
but does not write utmp either. Result: `who`, `w`, and `last` are all blind
to webshell sessions, even though the user has a real interactive shell.

This module adds the missing utmp entry from Python, the same way sshd's
loginrec.c does it: open /var/run/utmp, splice in a USER_PROCESS entry for
the spawned PTY, append to /var/log/wtmp for `last` history, and emit a
matching DEAD_PROCESS entry on session teardown.

We use ctypes against libc's setutxent/pututxline/endutxent rather than
writing the raw struct ourselves -- libc takes the file lock for us and
handles the seek-to-matching-id semantics that pututxline guarantees.

Struct layout
-------------
The Linux glibc `struct utmpx` is defined in <utmpx.h> as:

    struct utmpx {
        short int ut_type;            // login type (USER_PROCESS / DEAD_PROCESS)
        pid_t     ut_pid;             // pid of the process that owns the entry
        char      ut_line[32];        // device name, e.g. "pts/3"
        char      ut_id[4];           // inittab id (last chars of ut_line)
        char      ut_user[32];        // login username
        char      ut_host[256];       // remote host, we set "webshell"
        struct __exit_status ut_exit; // (term, exit) for DEAD_PROCESS
        int32_t   ut_session;         // session id, we leave 0
        struct {
            int32_t tv_sec;
            int32_t tv_usec;
        } ut_tv;                      // timestamp
        int32_t   ut_addr_v6[4];      // remote IPv4/IPv6, optional
        char      __glibc_reserved[20];
    };

ctypes adds the 2-byte pad between ut_type and ut_pid automatically;
sizeof(utmpx) on 64-bit Linux is 384 bytes which matches the kernel.
"""

from __future__ import annotations

import ctypes
import logging
import os
import time
from ctypes import c_char, c_int, c_short, Structure
from typing import Optional

logger = logging.getLogger(__name__)

# Per glibc bits/utmpx.h
_UT_LINESIZE = 32
_UT_NAMESIZE = 32
_UT_HOSTSIZE = 256

# ut_type values from <utmpx.h>
USER_PROCESS = 7
DEAD_PROCESS = 8


class _ExitStatus(Structure):
    _fields_ = [
        ("e_termination", c_short),
        ("e_exit", c_short),
    ]


class _Timeval(Structure):
    # On Linux utmpx, tv_sec/tv_usec are int32 (NOT time_t/suseconds_t) so
    # the layout is identical between 32- and 64-bit kernels.
    _fields_ = [
        ("tv_sec", c_int),
        ("tv_usec", c_int),
    ]


class Utmpx(Structure):
    _fields_ = [
        ("ut_type", c_short),
        ("ut_pid", c_int),
        ("ut_line", c_char * _UT_LINESIZE),
        ("ut_id", c_char * 4),
        ("ut_user", c_char * _UT_NAMESIZE),
        ("ut_host", c_char * _UT_HOSTSIZE),
        ("ut_exit", _ExitStatus),
        ("ut_session", c_int),
        ("ut_tv", _Timeval),
        ("ut_addr_v6", c_int * 4),
        ("__glibc_reserved", c_char * 20),
    ]


# Lazy-initialised libc handle. We don't want import to fail on non-Linux
# systems (developer macOS workstations, the unit-test runner) -- only the
# actual add/remove calls need libc. _libc() returns None on platforms where
# utmp doesn't apply, and callers no-op gracefully.
_libc_handle: Optional[ctypes.CDLL] = None
_libc_init_attempted = False


def _libc() -> Optional[ctypes.CDLL]:
    global _libc_handle, _libc_init_attempted
    if _libc_init_attempted:
        return _libc_handle
    _libc_init_attempted = True
    try:
        lib = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError as exc:
        logger.warning("utmp: libc.so.6 not loadable (%s); skipping utmp updates", exc)
        return None

    # setutxent: void setutxent(void)
    lib.setutxent.argtypes = []
    lib.setutxent.restype = None
    # endutxent: void endutxent(void)
    lib.endutxent.argtypes = []
    lib.endutxent.restype = None
    # pututxline: struct utmpx *pututxline(const struct utmpx *)
    lib.pututxline.argtypes = [ctypes.POINTER(Utmpx)]
    lib.pututxline.restype = ctypes.POINTER(Utmpx)
    # updwtmpx: void updwtmpx(const char *wtmpx_file, const struct utmpx *)
    lib.updwtmpx.argtypes = [ctypes.c_char_p, ctypes.POINTER(Utmpx)]
    lib.updwtmpx.restype = None
    # ptsname: char *ptsname(int fd)  -- returns "/dev/pts/N" for the master
    lib.ptsname.argtypes = [ctypes.c_int]
    lib.ptsname.restype = ctypes.c_char_p

    _libc_handle = lib
    return _libc_handle


def pts_name(master_fd: int) -> Optional[str]:
    """Return the secondary pts path (e.g. "/dev/pts/3") for a given master fd, or
    None on platforms / kernels where ptsname is unavailable."""
    lib = _libc()
    if lib is None:
        return None
    try:
        raw = lib.ptsname(master_fd)
    except OSError:
        return None
    if not raw:
        return None
    return raw.decode("ascii", errors="replace")


def _build_entry(
    ut_type: int,
    pts_path: str,
    user: str,
    pid: int,
    host: str = "webshell",
) -> Utmpx:
    """Construct a populated Utmpx struct ready for pututxline / updwtmpx.

    pts_path is the full secondary path ("/dev/pts/3"). ut_line is stored
    without the leading "/dev/" so it matches sshd's convention and `who`
    renders as expected. ut_id is the trailing 4 chars of ut_line so
    pututxline can match an existing record on session-end.
    """
    line = pts_path.removeprefix("/dev/").encode("ascii", errors="replace")[: _UT_LINESIZE - 1]
    # ut_id matches the trailing 4 chars of ut_line (sshd convention).
    if len(line) >= 4:
        ut_id = line[-4:]
    else:
        ut_id = line.ljust(4, b"\x00")

    now = time.time()
    sec = int(now)
    usec = int((now - sec) * 1_000_000)

    entry = Utmpx()
    entry.ut_type = ut_type
    entry.ut_pid = pid
    entry.ut_line = line
    entry.ut_id = ut_id
    entry.ut_user = user.encode("ascii", errors="replace")[: _UT_NAMESIZE - 1]
    entry.ut_host = host.encode("ascii", errors="replace")[: _UT_HOSTSIZE - 1]
    entry.ut_exit = _ExitStatus(0, 0)
    entry.ut_session = 0
    entry.ut_tv = _Timeval(sec, usec)
    for i in range(4):
        entry.ut_addr_v6[i] = 0
    return entry


def add_login_entry(pts_path: str, user: str, pid: int, host: str = "webshell") -> bool:
    """Register a USER_PROCESS entry for `user` on `pts_path` in /var/run/utmp,
    and append a matching record to /var/log/wtmp so `last` shows it.

    Returns True on success, False on any failure (logs a warning). Failure
    is non-fatal: the shell still works, it just won't appear in `who`/`w`.
    """
    lib = _libc()
    if lib is None:
        return False
    try:
        entry = _build_entry(USER_PROCESS, pts_path, user, pid, host)
        lib.setutxent()
        try:
            res = lib.pututxline(ctypes.byref(entry))
            if not res:
                err = ctypes.get_errno()
                logger.warning(
                    "utmp: pututxline failed for user=%s pts=%s errno=%d",
                    user, pts_path, err,
                )
                return False
        finally:
            lib.endutxent()
        # /var/log/wtmp gives `last` its history. updwtmpx is glibc-only
        # but present on every Linux distro we care about.
        try:
            lib.updwtmpx(b"/var/log/wtmp", ctypes.byref(entry))
        except OSError as exc:
            logger.warning("utmp: updwtmpx wtmp failed: %s", exc)
        logger.info(
            "utmp: added USER_PROCESS user=%s line=%s pid=%d",
            user, entry.ut_line.decode(errors="replace"), pid,
        )
        return True
    except Exception:
        logger.exception("utmp: unexpected failure in add_login_entry")
        return False


def remove_login_entry(pts_path: str, user: str, pid: int) -> bool:
    """Mark the utmp entry for `pts_path` as DEAD_PROCESS so `who`/`w`
    drop it. Also appends a DEAD_PROCESS record to /var/log/wtmp so `last`
    knows when the session ended (logout time column).

    Matches the existing entry by ut_id (trailing 4 chars of ut_line).
    Returns True on success.
    """
    lib = _libc()
    if lib is None:
        return False
    try:
        entry = _build_entry(DEAD_PROCESS, pts_path, user, pid)
        # USER_PROCESS retains user/host info; DEAD_PROCESS clears them
        # per the utmp man page, leaving only ut_id/ut_line/ut_pid/ut_tv
        # so `who` correctly hides the slot.
        entry.ut_user = b""
        entry.ut_host = b""
        lib.setutxent()
        try:
            res = lib.pututxline(ctypes.byref(entry))
            if not res:
                err = ctypes.get_errno()
                logger.warning(
                    "utmp: pututxline DEAD failed for pts=%s errno=%d",
                    pts_path, err,
                )
                return False
        finally:
            lib.endutxent()
        try:
            lib.updwtmpx(b"/var/log/wtmp", ctypes.byref(entry))
        except OSError as exc:
            logger.warning("utmp: updwtmpx wtmp DEAD failed: %s", exc)
        logger.info(
            "utmp: marked DEAD_PROCESS line=%s pid=%d",
            entry.ut_line.decode(errors="replace"), pid,
        )
        return True
    except Exception:
        logger.exception("utmp: unexpected failure in remove_login_entry")
        return False


