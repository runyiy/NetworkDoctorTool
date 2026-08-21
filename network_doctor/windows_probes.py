from __future__ import annotations

from dataclasses import dataclass
import json
import re
import socket
import subprocess
import threading
from collections.abc import Callable, Sequence
from typing import Any

from network_doctor.models import AdapterInfo, PingStats


class ProbeUnavailable(RuntimeError):
    """Raised when a probe cannot be run in the current environment."""


PING_TIME_RE = re.compile(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
PERCENT_RE = re.compile(r":\s*(\d{1,3})\s*%")

_ADAPTER_SCRIPT = """$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$rows = foreach ($config in Get-NetIPConfiguration) {
    if ($config.NetAdapter.Status -ne 'Up' -or -not $config.NetAdapter.HardwareInterface) { continue }
    $ipv4Interface = Get-NetIPInterface -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Name = [string]$config.InterfaceAlias
        Kind = if ([string]$config.NetAdapter.MediaType -match '802.11|Wireless') { 'Wi-Fi' } else { 'Ethernet' }
        Connected = $true
        Enabled = $true
        IPv4 = @($config.IPv4Address | ForEach-Object { $_.IPAddress })
        DhcpEnabled = (@($ipv4Interface | ForEach-Object { [string]$_.Dhcp }) -contains 'Enabled')
        Gateway = [string](@($config.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) | Select-Object -First 1)
        Dns = @($config.DNSServer.ServerAddresses)
    }
}
@($rows) | ConvertTo-Json -Depth 4 -Compress
"""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _as_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def run_command(args: Sequence[str], timeout_seconds: float) -> CommandResult:
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return CommandResult(completed.returncode, _as_text(completed.stdout), _as_text(completed.stderr))
    except subprocess.TimeoutExpired as exc:
        return CommandResult(-1, _as_text(exc.stdout), _as_text(exc.stderr), timed_out=True)
    except OSError as exc:
        return CommandResult(-1, "", str(exc))


def parse_ping_output(output: str, target: str, sent: int) -> PingStats:
    latencies = []
    for line in output.splitlines():
        if "ttl=" not in line.lower():
            continue
        match = PING_TIME_RE.search(line)
        if match:
            latencies.append(float(match.group(1)))
    return PingStats(target=target, sent=sent, latencies_ms=tuple(latencies))


def parse_wifi_signal(output: str) -> int | None:
    match = PERCENT_RE.search(output)
    return int(match.group(1)) if match else None


def _string_tuple(value: object) -> tuple[str, ...]:
    values = value if isinstance(value, (list, tuple)) else (value,)
    return tuple(item for item in values if isinstance(item, str) and item)


def parse_adapter_json(output: str) -> tuple[AdapterInfo, ...]:
    if not output.strip():
        return ()

    try:
        decoded = json.loads(output)
    except json.JSONDecodeError:
        return ()

    records = decoded if isinstance(decoded, list) else [decoded]
    adapters = []
    for record in records:
        if not isinstance(record, dict):
            continue
        name = record.get("Name")
        kind = record.get("Kind")
        if not isinstance(name, str) or not name or not isinstance(kind, str) or not kind:
            continue

        dhcp_enabled = record.get("DhcpEnabled")
        adapters.append(
            AdapterInfo(
                name=name,
                kind=kind,
                connected=record.get("Connected") is True,
                enabled=record.get("Enabled") is True,
                ipv4_addresses=_string_tuple(record.get("IPv4")),
                dhcp_enabled=dhcp_enabled if isinstance(dhcp_enabled, bool) else None,
                gateway=record.get("Gateway") if isinstance(record.get("Gateway"), str) else None,
                dns_servers=_string_tuple(record.get("Dns")),
            )
        )
    return tuple(adapters)


class WindowsProbes:
    def __init__(
        self,
        command_runner: Callable[[Sequence[str], float], CommandResult] = run_command,
        create_connection: Callable[..., Any] = socket.create_connection,
        getaddrinfo: Callable[..., Any] = socket.getaddrinfo,
    ) -> None:
        self._command_runner = command_runner
        self._create_connection = create_connection
        self._getaddrinfo = getaddrinfo

    def collect_adapters(self) -> tuple[AdapterInfo, ...]:
        result = self._command_runner(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _ADAPTER_SCRIPT],
            10.0,
        )
        return parse_adapter_json(result.stdout)

    def ping(self, target: str, count: int, timeout_ms: int) -> PingStats:
        result = self._command_runner(
            ["ping.exe", "-n", str(count), "-w", str(timeout_ms), target],
            count * timeout_ms / 1000 + 2,
        )
        return parse_ping_output(result.stdout, target, sent=count)

    def tcp_reachable(self, endpoints: Sequence[tuple[str, int]], timeout_seconds: float) -> bool:
        for endpoint in endpoints:
            try:
                connection = self._create_connection(endpoint, timeout_seconds)
            except OSError:
                continue
            connection.close()
            return True
        return False

    def resolve(self, hostname: str, timeout_seconds: float) -> Any | None:
        result: dict[str, Any] = {}
        completed = threading.Event()

        def lookup() -> None:
            try:
                result["value"] = self._getaddrinfo(hostname, None)
            except OSError:
                result["value"] = None
            finally:
                completed.set()

        thread = threading.Thread(target=lookup, daemon=True)
        thread.start()
        if not completed.wait(timeout_seconds):
            return None
        return result.get("value")

    def wifi_signal(self) -> int | None:
        result = self._command_runner(["netsh.exe", "wlan", "show", "interfaces"], 5.0)
        return parse_wifi_signal(result.stdout)
