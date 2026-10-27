"""Thread-interruption-safe subprocess runner.

Allows background worker QThreads to kill long-running command lines
(like ping or traceroute) cleanly and immediately when the thread or
application is requested to shut down.
"""
from __future__ import annotations

import logging
import subprocess
import sys
import time
from PySide6.QtCore import QThread

from losshound.core.windows_commands import windows_command

logger = logging.getLogger(__name__)

# Windows creation flags: hide console windows and isolate child process groups
# so interruption cleanup can terminate ping/tracert trees reliably.
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
CREATE_NEW_PROCESS_GROUP = (
    subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
)
PROCESS_CREATION_FLAGS = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    """Terminate a process and, on Windows, any child commands it spawned."""
    if proc.poll() is not None:
        return

    if sys.platform == "win32":
        try:
            result = subprocess.run(
                windows_command(["taskkill", "/F", "/T", "/PID", str(proc.pid)]),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
                creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    logger.debug(
                        "taskkill returned success but PID %s is still alive; falling back",
                        proc.pid,
                    )
                if proc.poll() is not None:
                    return
            else:
                logger.debug(
                    "taskkill failed for PID %s with exit code %s; falling back",
                    proc.pid,
                    result.returncode,
                )
        except (OSError, subprocess.SubprocessError):
            logger.debug("taskkill failed for PID %s; falling back", proc.pid)

    proc.terminate()
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_subprocess_interruptible(
    args: list[str], timeout_sec: float, *, encoding: str | None = None,
) -> tuple[str, str, int]:
    """Run an external command via subprocess.Popen in a thread-interruption-safe way.

    Checks for QThread interruption requests every 50ms and kills the process
    immediately if one is detected.

    Raises:
        InterruptedError: If thread interruption was requested.
        subprocess.TimeoutExpired: If the process runs longer than timeout_sec.
    """
    proc = subprocess.Popen(
        windows_command(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding=encoding,
        errors="replace",
        creationflags=PROCESS_CREATION_FLAGS,
    )
    start_time = time.monotonic()

    try:
        while True:
            # Check if process is finished
            ret = proc.poll()
            if ret is not None:
                stdout, stderr = proc.communicate()
                return stdout, stderr, ret

            # Check QThread interruption
            current_thread = QThread.currentThread()
            if current_thread and current_thread.isInterruptionRequested():
                _terminate_process_tree(proc)
                raise InterruptedError("Subprocess terminated due to thread interruption request.")

            # Check timeout
            if time.monotonic() - start_time > timeout_sec:
                _terminate_process_tree(proc)
                raise subprocess.TimeoutExpired(args, timeout_sec)

            time.sleep(0.05)
    except BaseException:
        # Guarantee cleanup on ordinary failures and control-flow exceptions
        # such as KeyboardInterrupt and GeneratorExit.
        if proc.poll() is None:
            _terminate_process_tree(proc)
        raise
