"""Explicit Windows DNS-cache adapter; importing this module changes nothing.

There is deliberately no startup wiring, command argument API, shell, elevation,
localized-output parser, cache backup, rollback, or native fallback executor.
"""
from __future__ import annotations

import math
import sys
import threading
import time
from types import SimpleNamespace

MODE = "windows_dns_cache"
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
STATUSES = frozenset({"succeeded", "failed", "permission_denied", "cancelled",
                      "timed_out", "execution_error", "cleanup_failed", "unsupported"})


def _load_native():
    """Load native facilities only for an explicitly invoked native command."""
    import _winapi
    import ctypes
    from ctypes import wintypes
    from subprocess import STARTUPINFO
    from losshound.core.session_process import _OwnedJob
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ResumeThread.argtypes = (wintypes.HANDLE,)
    kernel.ResumeThread.restype = wintypes.DWORD
    return _winapi, kernel, _OwnedJob, STARTUPINFO


def _finite(value):
    return type(value) in {int, float} and math.isfinite(value)


def _cancelled(event):
    return event is not None and event.is_set()


def _error_fields(exc):
    return {name: value if type(value := getattr(exc, name, None)) is int else None
            for name in ("errno", "winerror")}


def _permission_error(exc):
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {5, 740}


def _result(status="execution_error", stage="validation"):
    return {"status": status, "command_started": False, "exit_code": None,
            "stage": stage, "cleanup_errors": [], "cleanup_confirmed": False,
            "errno": None, "winerror": None}


def _cleanup(api, process_handle, thread_handle, job, deadline, clock, result):
    """Reap only this owned process/job; never resume an unassigned child."""
    errors = result["cleanup_errors"]
    def record(stage, exc):
        fields = _error_fields(exc)
        errors.append(f"{stage}:{type(exc).__name__}:errno={fields['errno']}:winerror={fields['winerror']}")

    if process_handle is not None:
        terminate = job is None
        if job is not None:
            try:
                terminate = bool(job.active_count())
            except Exception as exc:
                record("job_query", exc)
                terminate = True
        if terminate:
            try:
                if job is not None:
                    job.terminate()
                else:
                    # Assignment failed: this process is still suspended.
                    api.TerminateProcess(process_handle, 1)
            except Exception as exc:
                record("job_terminate" if job is not None else "process_terminate", exc)
                if job is not None:
                    try:
                        api.TerminateProcess(process_handle, 1)
                    except Exception as fallback:
                        record("process_terminate_fallback", fallback)
        try:
            while True:
                remaining = max(0.0, deadline - clock())
                wait_ms = 0 if remaining <= 0 else max(1, min(50, math.ceil(remaining * 1000)))
                outcome = api.WaitForSingleObject(process_handle, wait_ms)
                if outcome == WAIT_OBJECT_0:
                    if result["exit_code"] is None:
                        result["exit_code"] = api.GetExitCodeProcess(process_handle)
                    break
                if outcome != WAIT_TIMEOUT:
                    raise OSError("Unexpected process wait result")
                if clock() >= deadline:
                    errors.append("process_not_reaped_by_deadline")
                    break
        except Exception as exc:
            record("process_reap", exc)
        if job is not None:
            try:
                while job.active_count():
                    remaining = deadline - clock()
                    if remaining <= 0:
                        errors.append("owned_job_active_at_deadline")
                        break
                    time.sleep(min(0.01, remaining))
            except Exception as exc:
                record("job_reap", exc)
    if job is not None:
        try:
            # _OwnedJob.close does not expose ctypes CloseHandle's BOOL result.
            # Use the checked _winapi call, then prevent a second handle close.
            handle = job.handle
            if handle is not None:
                api.CloseHandle(handle)
                job.handle = None
            job.close()
        except Exception as exc:
            record("job_close", exc)
    for label, handle in (("thread_close", thread_handle), ("process_close", process_handle)):
        if handle is not None:
            try:
                api.CloseHandle(handle)
            except Exception as exc:
                record(label, exc)
    result["cleanup_confirmed"] = not errors


class NativeDnsCommandRunner:
    """Run exactly the trusted Windows ipconfig /flushdns command, on demand."""
    __slots__ = ()

    @property
    def simulation_only(self):
        return False

    def run(self, *, cancel_event, clock, deadline):
        result = _result()
        result["cleanup_confirmed"] = True  # No resources have been created yet.
        started = clock()
        if not _finite(started) or not _finite(deadline):
            return result
        deadline = min(deadline, started + 60.0)
        if _cancelled(cancel_event):
            result.update(status="cancelled", stage="before_launch")
            return result
        if started >= deadline:
            result.update(status="timed_out", stage="before_launch")
            return result
        if sys.platform != "win32":
            result.update(status="unsupported", stage="platform")
            return result
        api = job = process_handle = thread_handle = None
        # Cleanup remains inside the supplied absolute deadline.
        operation_deadline = deadline - min(2.0, (deadline - started) * 0.2)
        try:
            result["stage"] = "native_support"
            api, kernel, job_type, startup_info_type = _load_native()
            from subprocess import list2cmdline
            from losshound.core.windows_commands import windows_command
            result["stage"] = "resolve_command"
            command = windows_command(["ipconfig", "/flushdns"])
            if _cancelled(cancel_event) or clock() >= operation_deadline:
                result.update(status="cancelled" if _cancelled(cancel_event) else "timed_out",
                              stage="before_launch")
            else:
                result["stage"] = "create_process"
                process_handle, thread_handle, pid, _tid = api.CreateProcess(
                    command[0], list2cmdline(command), None, None, False,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None, startup_info_type())
                result["cleanup_confirmed"] = False
                result["stage"] = "job_assignment"
                job = job_type(SimpleNamespace(_handle=process_handle, pid=pid))
                result["stage"] = "before_resume"
                if _cancelled(cancel_event) or clock() >= operation_deadline:
                    result["status"] = "cancelled" if _cancelled(cancel_event) else "timed_out"
                else:
                    result["stage"] = "resume_thread"
                    try:
                        previous_count = kernel.ResumeThread(thread_handle)
                    except Exception:
                        result["command_started"] = None
                        raise
                    if previous_count == 0xffffffff:
                        import ctypes
                        raise ctypes.WinError(ctypes.get_last_error())
                    if previous_count != 1:
                        result["command_started"] = None if previous_count == 0 else False
                        raise OSError("Unexpected primary-thread suspension count")
                    result["command_started"] = True
                    result["stage"] = "wait"
                    while True:
                        if _cancelled(cancel_event):
                            result["status"] = "cancelled"
                            break
                        remaining = operation_deadline - clock()
                        if remaining <= 0:
                            result["status"] = "timed_out"
                            break
                        wait = api.WaitForSingleObject(process_handle, max(1, min(50, int(remaining * 1000))))
                        if wait == WAIT_OBJECT_0:
                            result["stage"] = "exit_code"
                            result["exit_code"] = api.GetExitCodeProcess(process_handle)
                            result["status"] = "succeeded" if result["exit_code"] == 0 else "failed"
                            break
                        if wait != WAIT_TIMEOUT:
                            raise OSError("Unexpected process wait result")
        except Exception as exc:
            result.update(status="permission_denied" if _permission_error(exc) else "execution_error",
                          **_error_fields(exc))
        finally:
            if api is not None:
                _cleanup(api, process_handle, thread_handle, job, deadline, clock, result)
        if result["cleanup_errors"]:
            result.setdefault("operation_status", result["status"])
            result.update(status="cleanup_failed", stage="cleanup")
        result["duration_seconds"] = max(0.0, clock() - started)
        if clock() > deadline and result["status"] != "cleanup_failed":
            result.setdefault("operation_status", result["status"])
            result.update(status="timed_out", stage="result_preparation")
        return result


class WindowsDnsCacheExecutor:
    """One confirmed action through an explicitly supplied fixed-command runner."""
    __slots__ = ("_run", "_simulation_only", "_lock", "_consumed")

    def __init__(self, command_runner):
        flag = getattr(command_runner, "simulation_only", None)
        if type(command_runner) is not NativeDnsCommandRunner and flag is not True:
            raise TypeError("An exact native runner or explicit trusted simulation runner is required")
        bound = getattr(command_runner, "run", None)
        if not callable(bound) or getattr(bound, "__self__", None) is not command_runner:
            raise TypeError("Runner must provide its bound run method")
        self._run = bound
        self._simulation_only = type(command_runner) is not NativeDnsCommandRunner
        self._lock = threading.Lock()
        self._consumed = False

    @property
    def mode(self):
        return MODE

    @property
    def simulation_only(self):
        return self._simulation_only

    def execute(self, request, *, request_id, confirmation, cancel_event=None,
                clock=time.monotonic, absolute_deadline=None):
        with self._lock:
            if self._consumed:
                raise RuntimeError("One DNS-cache action per executor; no retry or reuse")
            self._consumed = True
        started = clock()
        from losshound.core.repair import RepairRequest, DNS_CACHE_FLUSH
        if type(request) is not RepairRequest or request.action != DNS_CACHE_FLUSH:
            raise ValueError("Only the single DNS-cache action is allowed")
        if (type(request_id) is not str or not request_id or type(confirmation) is not dict
                or confirmation.get("status") != "confirmed"
                or type(confirmation.get("request_id")) is not str
                or confirmation["request_id"] != request_id
                or type(confirmation.get("action")) is not str
                or confirmation["action"] != DNS_CACHE_FLUSH
                or type(confirmation.get("execution_mode")) is not str
                or confirmation["execution_mode"] != MODE
                or any(confirmation.get(key) is not True for key in
                       ("accepted", "acknowledge_impact", "acknowledge_no_restore"))):
            raise ValueError("A matching explicit confirmation and all acknowledgements are required")
        if not _finite(started) or (absolute_deadline is not None and not _finite(absolute_deadline)):
            raise ValueError("An absolute finite execution deadline is required")
        deadline = min(started + 60.0, absolute_deadline if absolute_deadline is not None else started + 60.0)
        result = _result()
        result["cleanup_confirmed"] = True  # Pre-run cancellation has no owned resources.
        if _cancelled(cancel_event):
            result.update(status="cancelled", stage="before_runner")
        elif clock() >= deadline:
            result.update(status="timed_out", stage="before_runner")
        else:
            observed_operation = None
            invalid_outcome = False
            try:
                raw = self._run(cancel_event=cancel_event, clock=clock, deadline=deadline)
                if type(raw) is not dict or raw.get("status") not in STATUSES:
                    raise ValueError("Runner returned an unsupported result")
                original = raw.get("operation_status")
                observed_operation = original if type(original) is str and original in STATUSES else raw["status"]
                terminal = raw["status"] if raw["status"] in {"succeeded", "failed"} else observed_operation
                if terminal in {"succeeded", "failed"} and (
                        raw.get("command_started") is not True or type(raw.get("exit_code")) is not int
                        or (raw["exit_code"] == 0) != (terminal == "succeeded")):
                    # Inconsistent facts are not a successfully observed operation.
                    observed_operation = None
                    invalid_outcome = True
                    raise ValueError("Runner terminal status contradicts command-start or exit-code facts")
                if "command_started" not in raw or (raw["command_started"] is not None
                                                       and type(raw["command_started"]) is not bool):
                    raise ValueError("Runner command-start fact is invalid")
                errors = raw.get("cleanup_errors")
                if type(errors) is not list or any(type(value) is not str for value in errors):
                    raise ValueError("Runner cleanup facts are missing or invalid")
                result = {key: raw.get(key, default) for key, default in _result().items()}
                result["operation_status"] = observed_operation
                result["cleanup_errors"] = list(errors)
                result["cleanup_confirmed"] = (raw.get("cleanup_confirmed") is True and not errors
                                                 and raw["status"] != "cleanup_failed")
                if not result["cleanup_confirmed"]:
                    if not errors:
                        result["cleanup_errors"].append("runner_cleanup_unconfirmed")
                    result.update(status="cleanup_failed", stage="cleanup")
            except Exception as exc:
                error_status = "permission_denied" if _permission_error(exc) else "execution_error"
                result.update(status="execution_error" if invalid_outcome else "cleanup_failed",
                              operation_status=observed_operation or error_status,
                              command_started=None, stage="runner_result", cleanup_confirmed=False,
                              cleanup_errors=["runner_result_or_exception_cleanup_unconfirmed"],
                              **_error_fields(exc))
        result.update(execution_mode=MODE, simulation_only=self.simulation_only,
                      system_change_performed=False if self.simulation_only or result["command_started"] is False else None)
        finished = clock()
        result["duration_seconds"] = max(0.0, finished - started)
        if finished > deadline and result["status"] != "cleanup_failed":
            result.setdefault("operation_status", result["status"])
            result.update(status="timed_out", stage="result_preparation")
        return result
