"""Locale-independent Windows active-network discovery.

Windows command text is localized, so parsing ``ipconfig`` and ``netsh`` labels
can select the wrong adapter or fail outside English installations. This module
queries PowerShell objects and consumes compact JSON instead. Callers retain
their legacy parsers as a compatibility fallback for stripped-down systems.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from dataclasses import dataclass

from losshound.core.windows_commands import windows_command

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ActiveNetworkInterface:
    interface_alias: str
    interface_index: int
    gateway: str
    ipv4_address: str
    prefix_length: int
    dns_servers: tuple[str, ...]
    dhcp_enabled: bool
    connected: bool
    link_speed_mbps: float
    mac_address: str = ""


_ACTIVE_INTERFACE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
    Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' }
$candidates = foreach ($route in $routes) {
    $ipif = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex
    [pscustomobject]@{
        Route = $route
        Interface = $ipif
        Metric = [int]$route.RouteMetric + [int]$ipif.InterfaceMetric
    }
}
$best = $candidates | Sort-Object Metric | Select-Object -First 1
if ($best) {
    $route = $best.Route
    $ipif = $best.Interface
    $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex |
        Where-Object { $_.IPAddress -notlike '169.254.*' -and -not $_.SkipAsSource } |
        Select-Object -First 1
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex
    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    [pscustomobject]@{
        InterfaceAlias = [string]$route.InterfaceAlias
        InterfaceIndex = [int]$route.InterfaceIndex
        Gateway = [string]$route.NextHop
        IPv4Address = [string]$ip.IPAddress
        PrefixLength = [int]$ip.PrefixLength
        DnsServers = @($dns.ServerAddresses)
        DhcpEnabled = [bool]($ipif.Dhcp -eq 'Enabled')
        Connected = [bool]($adapter.Status -eq 'Up')
        LinkSpeedMbps = if ($adapter) { [double]$adapter.ReceiveLinkSpeed / 1000000 } else { 0 }
        MacAddress = if ($adapter) { [string]$adapter.MacAddress } else { '' }
    } | ConvertTo-Json -Compress -Depth 3
}
""".strip()


def _parse_interface_json(output: str | bytes) -> ActiveNetworkInterface | None:
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    if not output or not output.strip():
        return None
    try:
        raw = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(raw, dict):
        return None

    try:
        alias = raw.get("InterfaceAlias", "")
        gateway = raw.get("Gateway", "")
        address = raw.get("IPv4Address", "")
        index = raw.get("InterfaceIndex", 0)
        prefix = raw.get("PrefixLength", 0)
        dns_raw = raw.get("DnsServers", [])
        if isinstance(dns_raw, str):
            dns_raw = [dns_raw]
        if not (
            isinstance(alias, str)
            and isinstance(gateway, str)
            and isinstance(address, str)
            and isinstance(index, int)
            and isinstance(prefix, int)
            and isinstance(dns_raw, list)
            and all(isinstance(item, str) for item in dns_raw)
        ):
            return None
        if not alias or not gateway or gateway == "0.0.0.0" or not address:
            return None
        speed = raw.get("LinkSpeedMbps", 0.0)
        if not isinstance(speed, (int, float)) or isinstance(speed, bool):
            speed = 0.0
        return ActiveNetworkInterface(
            interface_alias=alias,
            interface_index=index,
            gateway=gateway,
            ipv4_address=address,
            prefix_length=prefix,
            dns_servers=tuple(dns_raw),
            dhcp_enabled=raw.get("DhcpEnabled") is True,
            connected=raw.get("Connected") is True,
            link_speed_mbps=max(0.0, float(speed)),
            mac_address=(
                raw.get("MacAddress", "")
                if isinstance(raw.get("MacAddress", ""), str)
                else ""
            ),
        )
    except (TypeError, ValueError):
        return None


def get_active_network_interface(timeout: float = 8.0) -> ActiveNetworkInterface | None:
    """Return the interface owning the lowest-metric IPv4 default route."""
    if sys.platform != "win32":
        return None
    try:
        result = subprocess.run(
            windows_command([
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _ACTIVE_INTERFACE_SCRIPT,
            ]),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("Active-interface PowerShell query failed: %s", exc)
        return None
    if result.returncode != 0:
        logger.debug(
            "Active-interface PowerShell query exited %s: %s",
            result.returncode,
            (result.stderr or "")[:200],
        )
        return None
    return _parse_interface_json(result.stdout)


__all__ = ["ActiveNetworkInterface", "get_active_network_interface"]
