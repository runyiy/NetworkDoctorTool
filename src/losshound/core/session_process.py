"""Owned, read-only Windows probe processes for bounded S1 sessions.

Each worker waits for its request until the parent assigns a private
kill-on-close Job Object. Cancellation terminates only that probe tree.
No shared Python/Qt thread is terminated, and this module imports no Qt.
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import uuid

MAX_CLEANUP_SECONDS = 2.0
_POLL_SECONDS = 0.05
_MAX_DIAGNOSTIC_BYTES = 4096


def _bounded_text(value):
    if isinstance(value, bytes):
        return value[:_MAX_DIAGNOSTIC_BYTES].decode("utf-8", errors="replace")
    return str(value)[:_MAX_DIAGNOSTIC_BYTES]


def _diagnostics(stage, exc=None, *, stdout=None, stderr=None, **details):
    """Retain bounded tool provenance; errors never establish network health."""
    data = {"stage": stage, **details}
    if exc is not None:
        data.update(exception_type=type(exc).__name__,
                    exception_message=_bounded_text(exc),
                    errno=getattr(exc, "errno", None),
                    winerror=getattr(exc, "winerror", None))
        if stdout is None:
            stdout = getattr(exc, "stdout", None)
        if stderr is None:
            stderr = getattr(exc, "stderr", None)
    for name, value in (("stdout", stdout), ("stderr", stderr)):
        if value is not None:
            data[name] = _bounded_text(value)
            data[name + "_truncated"] = len(value) > _MAX_DIAGNOSTIC_BYTES
            if isinstance(value, bytes):
                data[name + "_raw_base64"] = base64.b64encode(
                    value[:_MAX_DIAGNOSTIC_BYTES]).decode("ascii")
    return data


def _native_failure(stage, code):
    """Attribute a native error to the API that returned its status."""
    message = ctypes.FormatError(code) if hasattr(ctypes, "FormatError") else str(code)
    exc = OSError(code, message)
    exc.winerror = code
    exc.probe_stage = stage
    return exc


def _result(outcome, *, data=None, error=None, packets_sent=None,
            packets_received=None, rtt_ms=None):
    return dict(outcome=outcome, data=data or {}, error=error,
                packets_sent=packets_sent, packets_received=packets_received,
                rtt_ms=rtt_ms)


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BASIC_LIMIT(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class _EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BASIC_LIMIT), ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _ACCOUNTING(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD)]


class _OwnedJob:
    def __init__(self, process):
        self.handle = None
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        api = self.api
        api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        api.CreateJobObjectW.restype = wintypes.HANDLE
        api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                               ctypes.c_void_p, wintypes.DWORD]
        api.SetInformationJobObject.restype = wintypes.BOOL
        api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        api.AssignProcessToJobObject.restype = wintypes.BOOL
        api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        api.TerminateJobObject.restype = wintypes.BOOL
        api.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                 ctypes.c_void_p, wintypes.DWORD,
                                                 ctypes.c_void_p]
        api.QueryInformationJobObject.restype = wintypes.BOOL
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        self.name = "Local\\Losshound-S1-" + uuid.uuid4().hex
        handle = api.CreateJobObjectW(None, self.name)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            limits = _EXTENDED_LIMIT()
            limits.BasicLimitInformation.LimitFlags = 0x2000
            if not api.SetInformationJobObject(handle, 9, ctypes.byref(limits),
                                               ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not api.AssignProcessToJobObject(handle, int(process._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.handle = handle
        finally:
            if self.handle is None:
                api.CloseHandle(handle)

    def terminate(self):
        if self.handle and not self.api.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def active_count(self):
        if not self.handle:
            raise OSError("Probe job handle is already closed")
        accounting = _ACCOUNTING()
        if not self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(accounting),
                                                  ctypes.sizeof(accounting), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return accounting.ActiveProcesses

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


class WindowsProbeProvider:
    """Single-owner provider; all deadlines use the controller's monotonic clock."""

    def __init__(self, clock=time.monotonic, extended_diagnostics=False):
        if not isinstance(extended_diagnostics, bool):
            raise ValueError("Extended diagnostics must be an explicit boolean")
        self.clock = clock
        self.extended_diagnostics = extended_diagnostics
        self.cleanup_deadline = None
        self.cleanup_errors = []
        self.started_pids = []
        self._active = []

    def set_cleanup_deadline(self, deadline):
        if not math.isfinite(deadline):
            raise ValueError("Cleanup deadline must be finite")
        self.cleanup_deadline = deadline

    @property
    def active_pids(self):
        return [proc.pid for proc, _job in self._active if proc.poll() is None]

    def read_network(self, deadline, cancel_event):
        return self._run("network2" if self.extended_diagnostics else "network", "", deadline, cancel_event, timeout=5.0)

    def probe(self, protocol, target, deadline, cancel_event):
        from losshound.core.session_protocols import PROBE_PROTOCOLS, validate_target
        if protocol not in PROBE_PROTOCOLS:
            return _result("unsupported", error="Unsupported read-only probe protocol")
        try:
            validate_target(protocol, target)
        except (ValueError, TypeError, UnicodeError) as exc:
            return _result("execution_error", error=str(exc), data={"stage": "probe_target_validation"})
        return self._run(protocol, target, deadline, cancel_event, timeout=2.0)

    @staticmethod
    def _command():
        executable = str(Path(sys.executable).resolve(strict=True))
        if getattr(sys, "frozen", False):
            return [executable, "--s1-probe-worker"]
        return [executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker"]

    def _stop(self, proc, job, deadline):
        """Terminate/reap this owned tree and check its job has no active members."""
        errors = []
        try:
            if job is not None:
                job.terminate()
            elif proc.poll() is None:
                # Unassigned workers never received stdin and cannot probe.
                proc.kill()
            remaining = max(0.0, deadline - self.clock())
            if remaining:
                try:
                    proc.communicate(timeout=remaining)
                except subprocess.TimeoutExpired:
                    errors.append(f"Probe PID {proc.pid} did not exit before cleanup deadline")
            elif proc.poll() is None:
                errors.append(f"Probe PID {proc.pid} was still exiting at cleanup deadline")
            if job is not None:
                while self.clock() < deadline and job.active_count():
                    time.sleep(min(0.01, max(0.0, deadline - self.clock())))
                if job.active_count():
                    errors.append(f"Probe PID {proc.pid} job still had active processes")
        except OSError as exc:
            errors.append(f"Probe PID {proc.pid} cleanup failed: {type(exc).__name__}: {_bounded_text(exc)}")
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError as kill_error:
                    errors.append(f"Probe PID {proc.pid} kill failed: {type(kill_error).__name__}: {_bounded_text(kill_error)}")
        finally:
            if job is not None:
                job.close()
            if proc.poll() is not None:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
        self.cleanup_errors.extend(errors)

    def _run(self, protocol, target, deadline, cancel_event, timeout):
        if not math.isfinite(deadline):
            return _result("execution_error", error="Collection deadline must be finite")
        if cancel_event.is_set():
            return _result("cancelled", error="Session cancelled before probe launch")
        if self.clock() >= deadline:
            return _result("not_attempted", error="Collection deadline reached")
        if sys.platform != "win32":
            return _result("unsupported", error="Windows probe provider requires Windows")
        operation_deadline = min(deadline, self.clock() + timeout)
        cleanup_end = min(self.cleanup_deadline or deadline,
                          operation_deadline + MAX_CLEANUP_SECONDS)
        proc = job = None
        outcome, error = "execution_error", "Probe worker failed"
        stage, stdout, stderr, details = "worker_launch", None, None, {}
        if protocol in {"network", "network2"}:
            details["context_status"] = "UNKNOWN"
        try:
            proc = subprocess.Popen(self._command(), stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, encoding="utf-8", errors="replace",
                                    shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
            self.started_pids.append(proc.pid)
            self._active.append((proc, None))
            # Fail closed if nested jobs are unavailable. No request was sent.
            stage = "worker_job_assignment"
            job = _OwnedJob(proc)
            self._active[-1] = (proc, job)
            payload = json.dumps({"protocol": protocol, "target": target, "job_name": job.name,
                                  "timeout_ms": max(1, int(min(1.0, timeout / 2) * 1000))})
            first = True
            stage = "worker_response"
            while self.clock() < operation_deadline:
                if cancel_event.is_set():
                    outcome, error = "cancelled", "Session cancelled during probe"
                    break
                try:
                    stdout, stderr = proc.communicate(
                        input=payload if first else None,
                        timeout=min(_POLL_SECONDS, max(0.001, operation_deadline-self.clock())))
                    first = False
                    if proc.returncode != 0:
                        details["exit_code"] = proc.returncode
                        error = f"Probe worker exited {proc.returncode}"
                        break
                    if len(stdout) > 2_000_000:
                        error = "Probe worker response exceeded limit"
                        break
                    stage = "worker_response_json"
                    reply = json.loads(stdout)
                    if not isinstance(reply, dict) or reply.get("outcome") not in {
                        "success", "reply_timeout", "unreachable", "execution_error",
                        "unsupported", "skipped", "cancelled", "not_attempted"}:
                        error = "Invalid probe worker response"
                        break
                    return reply
                except subprocess.TimeoutExpired as exc:
                    stdout, stderr = exc.stdout, exc.stderr
                    first = False
            else:
                error = "Probe execution deadline reached; network outcome unknown"
            if cancel_event.is_set():
                outcome, error = "cancelled", "Session cancelled during probe"
            return _result(outcome, error=error,
                           data=_diagnostics(stage, stdout=stdout, stderr=stderr, **details))
        except (OSError, ValueError, TypeError) as exc:
            return _result("execution_error",
                           error=f"Probe execution failed at {stage}: {type(exc).__name__}: {_bounded_text(exc)}",
                           data=_diagnostics(stage, exc, stdout=stdout, stderr=stderr, **details))
        finally:
            if proc is not None:
                cleanup_end = min(cleanup_end, self.clock() + MAX_CLEANUP_SECONDS)
                self._stop(proc, job, cleanup_end)
                self._active = [(p, j if j is not None and j.handle else None)
                                for p, j in self._active if p is not proc or p.poll() is None]

    def close(self, deadline):
        for proc, job in list(self._active):
            self._stop(proc, job, min(deadline, self.clock()+MAX_CLEANUP_SECONDS))
        self._active = [(p, j if j is not None and j.handle else None)
                        for p, j in self._active if p.poll() is None]
        return list(self.cleanup_errors)


def _trusted_imports():
    # -I -S excludes site-packages; add only this source tree to reuse the
    # existing stdlib-only Windows helpers. Never consult CWD/PYTHONPATH.
    if not getattr(sys, "frozen", False):
        source = str(Path(__file__).resolve().parents[2])
        if source not in sys.path:
            sys.path.insert(0, source)
    from losshound.core.windows_commands import windows_command
    return windows_command


_NETWORK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
try {
$S1Stage = 'Get-NetAdapter'
$adapters = @(Get-NetAdapter -IncludeHidden | Sort-Object InterfaceGuid |
    Select-Object InterfaceGuid,ifIndex,Name,InterfaceType,Status,MacAddress)
$S1Stage = 'Get-NetIPAddress'
$addresses = @(Get-NetIPAddress | Sort-Object AddressFamily,InterfaceIndex,IPAddress |
    Select-Object AddressFamily,InterfaceIndex,IPAddress,PrefixLength,AddressState,SkipAsSource)
$S1Stage = 'Get-NetRoute'
$routes = @(Get-NetRoute | Sort-Object AddressFamily,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric |
    Select-Object AddressFamily,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
$S1Stage = 'Get-NetIPInterface'
$interfaces = @(Get-NetIPInterface | Sort-Object AddressFamily,InterfaceIndex |
    Select-Object AddressFamily,InterfaceIndex,InterfaceMetric,ConnectionState)
$S1Stage = 'Get-DnsClientServerAddress'
$dns = @(Get-DnsClientServerAddress | Sort-Object AddressFamily,InterfaceIndex |
    Select-Object AddressFamily,InterfaceIndex,ServerAddresses)
$S1Stage = 'network_context_serialization'
$defaults = foreach ($route in $routes) {
    if ($route.DestinationPrefix -eq '0.0.0.0/0' -and $route.NextHop -ne '0.0.0.0') {
        $ipif = $interfaces | Where-Object {$_.InterfaceIndex -eq $route.InterfaceIndex -and $_.AddressFamily -eq $route.AddressFamily} | Select-Object -First 1
        [pscustomobject]@{Gateway=$route.NextHop;Metric=([int]$route.RouteMetric+[int]$ipif.InterfaceMetric)}
    }
}
$gateway = ($defaults | Sort-Object Metric | Select-Object -First 1).Gateway
[pscustomobject]@{adapters=$adapters;addresses=$addresses;routes=$routes;interfaces=$interfaces;dns=$dns;gateway=$gateway} |
    ConvertTo-Json -Compress -Depth 6
} catch {
    $failure = [ordered]@{
        stage = $S1Stage
        exception_type = $_.Exception.GetType().FullName
        exception_message = $_.Exception.Message
        hresult = $_.Exception.HResult
        winerror = $_.Exception.NativeErrorCode
        fully_qualified_error_id = $_.FullyQualifiedErrorId
        category = [string]$_.CategoryInfo
        error_record = ($_ | Out-String)
    }
    [Console]::Error.WriteLine(($failure | ConvertTo-Json -Compress -Depth 3))
    exit 1
}
""".strip()


class _GUID(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_ubyte * 16)]


class _WLAN_INTERFACE(ctypes.Structure):
    _fields_ = [("guid", _GUID), ("description", ctypes.c_wchar * 256),
                ("state", wintypes.DWORD)]


class _SSID(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("value", ctypes.c_ubyte * 32)]


class _ASSOCIATION(ctypes.Structure):
    _fields_ = [("ssid", _SSID), ("bss_type", wintypes.DWORD),
                ("bssid", ctypes.c_ubyte * 6), ("phy_type", wintypes.DWORD),
                ("phy_index", wintypes.DWORD), ("signal", wintypes.DWORD),
                ("rx_rate", wintypes.DWORD), ("tx_rate", wintypes.DWORD)]


class _SECURITY(ctypes.Structure):
    _fields_ = [("enabled", wintypes.BOOL), ("one_x", wintypes.BOOL),
                ("authentication", wintypes.DWORD), ("cipher", wintypes.DWORD)]


class _CONNECTION(ctypes.Structure):
    _fields_ = [("state", wintypes.DWORD), ("mode", wintypes.DWORD),
                ("profile", ctypes.c_wchar * 256), ("association", _ASSOCIATION),
                ("security", _SECURITY)]


def _wifi_identity(include_signals=False):
    """Read one WLAN connection; dynamic observations are opt-in and not identity."""
    api = ctypes.WinDLL("wlanapi", use_last_error=True)
    api.WlanOpenHandle.argtypes = [wintypes.DWORD, ctypes.c_void_p,
                                   ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.HANDLE)]
    api.WlanOpenHandle.restype = wintypes.DWORD
    api.WlanEnumInterfaces.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_void_p)]
    api.WlanEnumInterfaces.restype = wintypes.DWORD
    api.WlanQueryInterface.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID),
                                       wintypes.DWORD, ctypes.c_void_p,
                                       ctypes.POINTER(wintypes.DWORD),
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(wintypes.DWORD)]
    api.WlanQueryInterface.restype = wintypes.DWORD
    api.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    api.WlanFreeMemory.restype = None
    api.WlanCloseHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    api.WlanCloseHandle.restype = wintypes.DWORD
    handle, version = wintypes.HANDLE(), wintypes.DWORD()
    code = api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle))
    if code == 1062:  # WLAN service inactive on a wired-only machine
        return []
    if code:
        raise _native_failure("WlanOpenHandle", code)
    interfaces = ctypes.c_void_p()
    try:
        code = api.WlanEnumInterfaces(handle, None, ctypes.byref(interfaces))
        if code:
            raise _native_failure("WlanEnumInterfaces", code)
        count = ctypes.cast(interfaces, ctypes.POINTER(wintypes.DWORD))[0]
        identities = []
        for index in range(count):
            address = interfaces.value + 8 + index * ctypes.sizeof(_WLAN_INTERFACE)
            interface = ctypes.cast(address, ctypes.POINTER(_WLAN_INTERFACE)).contents
            identity = {"guid": bytes(interface.guid.bytes).hex(), "state": interface.state}
            if interface.state == 1:
                data, size, value_type = ctypes.c_void_p(), wintypes.DWORD(), wintypes.DWORD()
                code = api.WlanQueryInterface(handle, ctypes.byref(interface.guid), 7, None,
                                              ctypes.byref(size), ctypes.byref(data),
                                              ctypes.byref(value_type))
                if code:
                    raise _native_failure("WlanQueryInterface", code)
                try:
                    if size.value < ctypes.sizeof(_CONNECTION):
                        raise OSError("WLAN connection structure was incomplete")
                    connection = ctypes.cast(data, ctypes.POINTER(_CONNECTION)).contents
                    association = connection.association
                    if association.ssid.length > 32:
                        raise OSError("WLAN SSID length was invalid")
                    identity.update(ssid_hex=bytes(association.ssid.value[:association.ssid.length]).hex(),
                                    bssid=":".join(f"{byte:02x}" for byte in association.bssid))
                    if include_signals:
                        quality = int(association.signal)
                        identity["signal_quality"] = quality if 0 <= quality <= 100 else None
                finally:
                    api.WlanFreeMemory(data)
            identities.append(identity)
        return sorted(identities, key=lambda item: item["guid"])
    finally:
        if interfaces.value:
            api.WlanFreeMemory(interfaces)
        api.WlanCloseHandle(handle, None)


def _wifi_observations(context, wifi):
    """Associate native GUID bytes with this snapshot's existing adapter indexes."""
    indexes = {}
    for adapter in context.get("adapters", []):
        if not isinstance(adapter, dict):
            continue
        try:
            guid = uuid.UUID(str(adapter["InterfaceGuid"]).strip("{}"))
            index = adapter.get("ifIndex", adapter.get("InterfaceIndex"))
            if isinstance(index, int) and not isinstance(index, bool) and index > 0:
                indexes[guid.bytes_le.hex()] = index
        except (KeyError, ValueError, TypeError, AttributeError):
            continue
    observations = []
    for item in wifi:
        if not isinstance(item, dict):
            continue
        quality = item.get("signal_quality")
        if isinstance(quality, bool) or not isinstance(quality, int) or not 0 <= quality <= 100:
            quality = None
        observations.append({"interface_index": indexes.get(item.get("guid")),
            "guid": item.get("guid"), "state": item.get("state"), "signal_quality": quality})
    return observations


def _network(include_signals=False):
    stage, proc = "network_command_resolution", None
    try:
        command = _trusted_imports()
        args = command(["powershell", "-NoProfile", "-NonInteractive",
                        "-Command", _NETWORK_SCRIPT])
        stage = "network_query"
        # Keep original bytes: PowerShell error encoding can differ from its
        # UTF-8 JSON stdout. Lossy text alone would discard the native evidence.
        proc = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=4.0, creationflags=subprocess.CREATE_NO_WINDOW,
                              shell=False)
        if proc.returncode != 0:
            data = _diagnostics(stage, stdout=proc.stdout, stderr=proc.stderr,
                                exit_code=proc.returncode, context_status="UNKNOWN")
            try:
                failure = json.loads(proc.stderr)
                if isinstance(failure, dict):
                    data["powershell_error"] = {
                        key: _bounded_text(value) if isinstance(value, (str, bytes)) else value
                        for key, value in failure.items()
                        if value is None or isinstance(value, (str, bytes, int, float, bool))
                    }
                    if isinstance(failure.get("stage"), str):
                        data["stage"] = _bounded_text(failure["stage"])
                    for key in ("exception_type", "exception_message", "winerror"):
                        data[key] = data["powershell_error"].get(key)
                    data["errno"] = None
            except (ValueError, TypeError, UnicodeError):
                pass
            return _result("execution_error",
                           error=f"Windows network context UNKNOWN: query failed at {data['stage']}",
                           data=data)
        stage = "network_json"
        context = json.loads(proc.stdout)
        if not isinstance(context, dict) or not isinstance(context.get("adapters"), list):
            return _result("execution_error", error="Windows network context UNKNOWN: incomplete identity",
                           data=_diagnostics("network_context_validation", stdout=proc.stdout,
                                             stderr=proc.stderr, context_status="UNKNOWN"))
        # Privacy denial makes context UNKNOWN, rather than reusing an old key.
        stage = "wifi_identity"
        wifi = _wifi_identity(include_signals=True) if include_signals else _wifi_identity()
        observations = _wifi_observations(context, wifi) if include_signals else None
        # The S1 identity vocabulary stays identical; never hash quality/rates.
        context["wifi"] = [
            {key: item[key] for key in ("guid", "state", "ssid_hex", "bssid") if key in item}
            for item in wifi
        ] if include_signals else wifi
        stage = "network_identity_hash"
        identity = hashlib.sha256(json.dumps(context, sort_keys=True, ensure_ascii=True,
                                            separators=(",", ":")).encode()).hexdigest()
        if include_signals:
            context["wifi_observations"] = observations
        return _result("success", data={"identity": identity, "context_status": "KNOWN", **context})
    except Exception as exc:
        stage = getattr(exc, "probe_stage", stage)
        data = _diagnostics(stage, exc, stdout=proc.stdout if proc else None,
                            stderr=proc.stderr if proc else None, context_status="UNKNOWN")
        return _result("execution_error",
                       error=f"Windows network context UNKNOWN at {stage}: {type(exc).__name__}: {_bounded_text(exc)}",
                       data=data)


def _icmp(target, timeout_ms):
    try:
        if ipaddress.ip_address(target).version == 6:
            _trusted_imports()
            from losshound.core.session_protocols import icmp6_probe
            return icmp6_probe(target, timeout_ms)
        ipaddress.IPv4Address(target)
    except ValueError:
        return _result("unsupported", error="ICMP requires an IPv4 or IPv6 literal")
    stage, handle, api = "icmp_native_import", None, None
    try:
        _trusted_imports()
        # Reuse the existing stdlib ctypes ABI, not its Qt interruption wrapper.
        from losshound.core import icmp_ping as native
        api = native._iphlpapi
        if api is None:
            return _result("unsupported", error="Native Windows ICMP is unavailable",
                           data={"stage": "icmp_native_load"})
        stage = "IcmpCreateFile"
        handle = api.IcmpCreateFile()
        if handle in (None, native._INVALID_HANDLE_VALUE):
            code = ctypes.get_last_error()
            handle = None
            exc = _native_failure(stage, code)
            return _result("execution_error",
                           error=f"IcmpCreateFile failed: {_bounded_text(exc)}; network outcome UNKNOWN",
                           data=_diagnostics(stage, exc, native_status=code))
        reply_size = ctypes.sizeof(native._ICMP_ECHO_REPLY) + len(native._PAYLOAD) + 8
        buffer = ctypes.create_string_buffer(reply_size)
        address = struct.unpack("<L", socket.inet_aton(target))[0]
        started = time.perf_counter()
        stage = "IcmpSendEcho"
        replies = api.IcmpSendEcho(handle, address, native._PAYLOAD, len(native._PAYLOAD),
                                   None, buffer, reply_size, timeout_ms)
        if replies:
            reply = ctypes.cast(buffer, ctypes.POINTER(native._ICMP_ECHO_REPLY)).contents
            status = reply.Status
            if status == 0:
                rtt = float(reply.RoundTripTime) or min(0.9, (time.perf_counter()-started)*1000)
                return _result("success", packets_sent=1, packets_received=1,
                               rtt_ms=rtt, data={"stage": stage, "native_status": 0})
        else:
            status = ctypes.get_last_error()
        if status == 11010:
            return _result("reply_timeout", packets_sent=1, packets_received=0,
                           data={"stage": stage, "native_status": status})
        if status in {11002, 11003, 11004, 11005, 11009, 11013}:
            return _result("unreachable", data={"stage": stage, "native_status": status},
                           error="Native ICMP returned an unreachable/prohibited status")
        exc = _native_failure(stage, status)
        return _result("execution_error",
                       data=_diagnostics(stage, exc, native_status=status),
                       error=f"Native ICMP execution failed: {_bounded_text(exc)}; sent count is unknown")
    except Exception as exc:
        return _result("execution_error",
                       error=f"Native ICMP failed at {stage}: {type(exc).__name__}: {_bounded_text(exc)}",
                       data=_diagnostics(stage, exc))
    finally:
        if api is not None and handle is not None:
            api.IcmpCloseHandle(handle)


def _dns(target, family=socket.AF_INET):
    target = target.strip()
    if (not target or len(target) > 253 or
            any(character in target for character in "\r\n\x00 /\\")):
        return _result("execution_error", error="Invalid DNS hostname",
                       data={"stage": "dns_target_validation"})
    normalized = target.rstrip(".").lower()
    scope = "localhost" if normalized == "localhost" or normalized.endswith(".localhost") else "non_localhost"
    try:
        if ipaddress.ip_address(normalized).is_loopback:
            scope = "localhost"
    except ValueError:
        pass
    details = {"source": "os_resolver", "target_scope": scope, "resolver_result_only": True,
               "family": "IPv6" if family == socket.AF_INET6 else "IPv4"}
    started = time.perf_counter()
    try:
        records = socket.getaddrinfo(target, None, family)
        addresses = sorted({record[4][0] for record in records})
        return _result("success", data={**details, "stage": "getaddrinfo", "addresses": addresses,
                                        "resolution_time_ms": (time.perf_counter()-started)*1000})
    except socket.gaierror as exc:
        # Name-not-found is a resolver result, never an observed packet loss.
        # Temporary, permission and system failures remain tool errors.
        not_found = {11001, getattr(socket, "EAI_NONAME", None)}
        outcome = "unreachable" if exc.errno in not_found else "execution_error"
        return _result(outcome,
                       data=_diagnostics("getaddrinfo", exc, resolver_error=exc.errno, **details),
                       error=f"OS resolver error: {_bounded_text(exc)}")
    except Exception as exc:
        return _result("execution_error",
                       data=_diagnostics("getaddrinfo", exc, **details),
                       error=f"OS resolver execution failed: {type(exc).__name__}: {_bounded_text(exc)}")


def _repair_frozen_streams():
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetStdHandle.argtypes = [wintypes.DWORD]
    kernel.GetStdHandle.restype = wintypes.HANDLE
    for name, identifier, flags, mode in (
        ("stdin", -10, os.O_RDONLY, "r"), ("stdout", -11, os.O_WRONLY, "w")):
        if getattr(sys, name) is None:
            handle = kernel.GetStdHandle(identifier & 0xFFFFFFFF)
            if not handle or handle == ctypes.c_void_p(-1).value:
                raise OSError("Probe worker has no inherited pipe")
            fd = msvcrt.open_osfhandle(handle, flags | os.O_BINARY)
            setattr(sys, name, os.fdopen(fd, mode, encoding="utf-8", errors="replace"))



def _verify_private_job(name):
    """A direct invocation is not a bounded session and must not probe."""
    prefix = "Local\\Losshound-S1-"
    if (not isinstance(name, str) or not name.startswith(prefix)
            or len(name) != len(prefix) + 32
            or any(character not in "0123456789abcdef" for character in name[len(prefix):])):
        return False
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.OpenJobObjectW.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel.IsProcessInJob.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    job = kernel.OpenJobObjectW(0x0004, False, name)  # JOB_OBJECT_QUERY
    if not job:
        return False
    try:
        contained = wintypes.BOOL()
        return bool(kernel.IsProcessInJob(kernel.GetCurrentProcess(), job, ctypes.byref(contained))
                    and contained.value)
    finally:
        # Do not hold a child-side job handle during probes: the parent must be
        # the final handle owner for KILL_ON_JOB_CLOSE on abrupt parent exit.
        kernel.CloseHandle(job)

def worker_main():
    """Strict one-request worker; accepts no executable/script input."""
    stage = "worker_stream_setup"
    try:
        _repair_frozen_streams()
        stage = "worker_request_validation"
        raw = sys.stdin.read(8193)
        if len(raw) > 8192:
            raise ValueError("Oversized request")
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {"protocol", "target", "timeout_ms", "job_name"}:
            raise ValueError("Invalid request shape")
        protocol, target, timeout_ms = (request["protocol"], request["target"], request["timeout_ms"])
        _trusted_imports()
        from losshound.core.session_protocols import (PROBE_PROTOCOLS, MAX_TARGET_LENGTH,
            validate_target, tcp_probe, http_probe)
        if (protocol not in PROBE_PROTOCOLS | {"network", "network2"} or not isinstance(target, str)
                or len(target) > MAX_TARGET_LENGTH or isinstance(timeout_ms, bool)
                or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= 1000):
            raise ValueError("Invalid request values")
        if protocol in {"network", "network2"}:
            if target:
                raise ValueError("Network snapshot target must be empty")
        else:
            validate_target(protocol, target)
        stage = "worker_job_verification"
        if sys.platform != "win32":
            result = _result("unsupported", error="Windows probes require Windows")
        elif not _verify_private_job(request["job_name"]):
            result = _result("execution_error", error="Probe worker is not owned by a bounded session")
        elif protocol in {"network", "network2"}:
            stage = "network"
            result = _network(include_signals=True) if protocol == "network2" else _network()
        elif protocol == "icmp":
            stage = "icmp"
            result = _icmp(target, timeout_ms)
        elif protocol in {"dns", "dns6"}:
            stage = "getaddrinfo"
            result = _dns(target, socket.AF_INET6 if protocol == "dns6" else socket.AF_INET)
        elif protocol in {"tcp", "tcp6"}:
            stage = "tcp"
            result = tcp_probe(target, socket.AF_INET6 if protocol == "tcp6" else socket.AF_INET, timeout_ms)
        else:
            stage = "http"
            result = http_probe(target, socket.AF_INET6 if protocol.endswith("6") else socket.AF_INET, timeout_ms)
    except Exception as exc:
        result = _result("execution_error",
                         error=f"Worker failed at {stage}: {type(exc).__name__}: {_bounded_text(exc)}",
                         data=_diagnostics(stage, exc))
    if sys.stdout is None:
        return 2
    sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit(2)
    raise SystemExit(worker_main())





