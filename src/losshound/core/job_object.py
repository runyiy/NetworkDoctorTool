"""Windows Job Object helper.

Assigning the current process to a Job Object configured with
``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` ensures that every child process
(``cmd.exe``, ``ping.exe``, ``tracert.exe``, ``netsh.exe``, ...) is
terminated automatically when the parent Python process exits, even on
hard kills. Without this, child processes spawned via ``subprocess`` can
outlive the GUI and show up as remnants in Task Manager.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from ctypes import wintypes

logger = logging.getLogger(__name__)

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JobObjectExtendedLimitInformation = 9

_job_handle = None  # module-level to keep the handle alive


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def install_kill_on_close_job() -> bool:
    """Tie all child processes to the current process lifetime.

    Returns True on success. Best-effort: silently returns False on
    non-Windows platforms or if the current process is already in a
    job that doesn't allow nesting.
    """
    global _job_handle
    if sys.platform != "win32":
        return False
    if _job_handle is not None:
        return True

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            logger.debug("CreateJobObjectW failed: %s", ctypes.get_last_error())
            return False

        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        # Only KILL_ON_JOB_CLOSE. Breakaway flags would let child
        # processes escape the job, which is the opposite of what we want.
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        ok = kernel32.SetInformationJobObject(
            job,
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            logger.debug(
                "SetInformationJobObject failed: %s", ctypes.get_last_error()
            )
            return False

        ok = kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess())
        if not ok:
            err = ctypes.get_last_error()
            logger.debug(
                "AssignProcessToJobObject failed: %s "
                "(process may already be in a non-nesting job)", err,
            )
            return False

        _job_handle = job
        logger.info("Installed kill-on-close Job Object for child processes")
        return True
    except Exception:
        logger.debug("Job Object install raised", exc_info=True)
        return False
