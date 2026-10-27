"""Network performance optimizer for Windows.

Provides DNS benchmarking, TCP/IP stack tuning, adapter optimisation,
MTU discovery, and various Windows network tweaks.  All changes can be
backed up before applying and restored later.

Most write operations require Administrator privileges.  When running
without elevation the optimizer will skip admin-only steps and record
them in the returned results so the caller can inform the user.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import logging
import os
import re
import subprocess
import time
import winreg
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from losshound.core.read_only_policy import reject_network_modification
from losshound.core.windows_commands import windows_command
from losshound.core.dns_bench import (
    DNS_SERVERS,
    DnsBenchmarkResult,
    benchmark_all as _dns_benchmark_all,
)

logger = logging.getLogger(__name__)

# Prevent console windows from flashing during subprocess calls.
_CREATE_NO_WINDOW: int = 0x08000000

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class OptimizeResult:
    """Outcome of a single optimisation action.

    Status values
    -------------
    Applied        – change was made and verified.
    Verified       – setting already had the desired value; no change needed.
    No change      – operation ran but before == after (nothing changed).
    Skipped        – intentionally skipped (e.g. no admin rights).
    Failed         – the command or operation returned an error.
    Unsupported    – the OS / adapter does not support this setting.
    Reboot required – change written but needs a reboot to take effect.
    """

    name: str
    success: bool
    before: str
    after: str
    needs_admin: bool
    error: Optional[str] = None
    # --- extended fields ---
    status: str = ""           # one of the documented status values
    note: str = ""             # human-readable explanation (always populated)
    command: str = ""          # exact command / operation attempted
    command_exit_code: Optional[int] = None  # process return code
    verification: str = ""     # result of post-apply verification
    reboot_required: bool = False


@dataclass
class TcpSettings:
    """Snapshot of TCP global parameters."""

    auto_tuning_level: str = "unknown"
    congestion_provider: str = "unknown"
    ecn_capability: str = "unknown"
    rss: str = "unknown"
    dca: str = "unknown"
    timestamps: str = "unknown"


@dataclass
class AdapterInfo:
    """Description of the active network adapter."""

    name: str
    interface_index: int
    ip_address: str
    mac_address: str
    speed: str


@dataclass
class AdapterBackup:
    """Snapshot of adapter-level settings."""

    name: str
    power_management_enabled: Optional[bool] = None
    interrupt_moderation_enabled: Optional[bool] = None
    rsc_enabled: Optional[bool] = None
    lso_enabled: Optional[bool] = None
    eee_enabled: Optional[str] = None


@dataclass(frozen=True)
class DnsState:
    """Adapter-scoped IPv4 DNS configuration.

    ``automatic`` is ``True`` for DHCP-provided DNS, ``False`` for a static
    server list, and ``None`` when Windows did not expose enough information
    to distinguish the two safely.  ``detected`` is deliberately separate
    from an empty server list because DHCP can legitimately have no lease yet.
    """

    adapter_name: str
    servers: tuple[str, ...] = ()
    automatic: Optional[bool] = None
    detected: bool = False


@dataclass(frozen=True)
class _DnsWriteOutcome:
    """Internal result from an adapter-scoped DNS write and read-back."""

    success: bool
    after: DnsState
    commands: tuple[tuple[str, ...], ...]
    command_exit_code: Optional[int]
    error: Optional[str]
    verification: str
    changed: bool = False


@dataclass
class BackupData:
    """Complete settings snapshot for later restoration."""

    timestamp: str
    tcp_settings: TcpSettings
    dns_servers: tuple[str, str]
    mtu: int
    network_throttling: Optional[int]
    nagle_disabled: bool
    nagle_interface_guid: Optional[str] = None
    adapter: Optional[AdapterBackup] = None
    tcp_heuristics: str = "unknown"
    system_responsiveness: Optional[int] = None
    fast_send_datagram_threshold: Optional[int] = None
    tcp_del_ack_ticks: Optional[int] = None
    # DNS metadata added in v0.1.3.  The original two-item ``dns_servers``
    # field remains for backwards compatibility with existing backup files.
    dns_adapter_name: str = ""
    dns_automatic: Optional[bool] = None
    dns_server_list: tuple[str, ...] = ()
    # Presence flags let restore distinguish "value absent" from "backup
    # could not read it".  Guessing here can create registry overrides that
    # did not exist before optimisation.
    network_throttling_present: Optional[bool] = None
    system_responsiveness_present: Optional[bool] = None
    fast_send_datagram_threshold_present: Optional[bool] = None
    nagle_tcp_ack_frequency: Optional[int] = None
    nagle_tcp_ack_frequency_present: Optional[bool] = None
    nagle_tcp_no_delay: Optional[int] = None
    nagle_tcp_no_delay_present: Optional[bool] = None
    tcp_del_ack_ticks_present: Optional[bool] = None


@dataclass
class OptimizeReport:
    """Aggregate report returned by :meth:`NetworkOptimizer.optimize_all`."""

    results: list[OptimizeResult]
    backup: BackupData
    admin: bool
    summary: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BACKUP_DIR = Path(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
) / "Losshound"
_BACKUP_FILE = _BACKUP_DIR / "optimizer_backup.json"


def _sanitize_adapter_name(name: str) -> str:
    """Sanitize the network adapter name to prevent command injection."""
    # Allow alphanumeric, spaces, hyphens, underscores, parentheses, brackets, braces, dots, and plus signs
    if re.match(r"^[a-zA-Z0-9_\-\s\(\)\[\]\.\{\}\+]+$", name):
        return name
    # Clean if not matching: strip double quotes and shell control characters, and double single quotes for PowerShell
    cleaned = re.sub(r'["&|;<>]', '', name)
    return cleaned.replace("'", "''")


def _coerce_registry_dword_value(value: object) -> str | None:
    """Return a safe numeric registry value string, or None for tampered input."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"\d{1,10}", value.strip()):
        number = int(value.strip())
    else:
        return None
    if 0 <= number <= 0xFFFFFFFF:
        return str(number)
    return None


def _is_ipv4_address(value: object) -> bool:
    """Return whether *value* is a canonical, usable IPv4 address string."""
    if not isinstance(value, str) or not value:
        return False
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except ipaddress.AddressValueError:
        return False


def _read_registry_dword_snapshot(
    key_path: str,
    value_name: str,
) -> tuple[Optional[bool], Optional[int]]:
    """Read a DWORD while preserving absent-vs-unreadable state.

    Returns ``(True, value)`` when present, ``(False, None)`` when the value is
    definitely absent, and ``(None, None)`` when it could not be read safely.
    """
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ,
        ) as key:
            try:
                value, value_type = winreg.QueryValueEx(key, value_name)
            except FileNotFoundError:
                return False, None
    except FileNotFoundError:
        return False, None
    except OSError:
        return None, None

    if value_type != winreg.REG_DWORD or isinstance(value, bool):
        return None, None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None, None
    if not 0 <= number <= 0xFFFFFFFF:
        return None, None
    return True, number


def _parse_bool_setting(val: str) -> str:
    """Robust locale-independent parser for enabled/disabled settings."""
    val_lower = val.lower()
    if any(x in val_lower for x in ("dis", "devre", "deaktiv", "off", "no", "false", "0")):
        return "disabled"
    if any(x in val_lower for x in ("en", "akt", "on", "yes", "true", "1", "etk")):
        return "enabled"
    return val.strip().lower()


def _run(
    cmd: list[str],
    *,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess with common defaults using list arguments (no shell)."""
    return subprocess.run(
        windows_command(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=_CREATE_NO_WINDOW,
    )



def _parse_netsh_table(output: str) -> dict[str, str]:
    """Parse ``key : value`` lines from netsh output into a dict."""
    result: dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key and value:
                result[key] = value
    return result


# ---------------------------------------------------------------------------
# Value normalisation & result helpers
# ---------------------------------------------------------------------------

_VALUE_DISPLAY: dict[str, str] = {
    # TCP auto-tuning
    "normal": "Normal",
    "disabled": "Disabled",
    "highlyrestricted": "Highly Restricted",
    "restricted": "Restricted",
    "experimental": "Experimental",
    # Congestion provider
    "ctcp": "CTCP (Compound TCP)",
    "cubic": "CUBIC",
    "dctcp": "DCTCP",
    "newreno": "NewReno",
    "none": "None (default)",
    "default": "Default",
    # ECN / RSS / DCA / timestamps
    "enabled": "Enabled",
    # Boolean-like
    "true": "Enabled",
    "false": "Disabled",
    "1": "Enabled",
    "0": "Disabled",
    # Adapter states
    "unsupported": "Unsupported",
    # Cache states
    "cached": "Cached",
    "flushed": "Flushed",
}


def _normalize_value(raw: str) -> str:
    """Return a human-friendly version of a raw setting value."""
    if not raw:
        return "--"
    stripped = raw.strip()
    # Check for registry hex constants
    if stripped.lower() in ("0xffffffff", "4294967295", "-1"):
        return "Disabled (0xFFFFFFFF)"
    # Exact lookup (case-insensitive)
    display = _VALUE_DISPLAY.get(stripped.lower())
    if display:
        return display
    # Already readable — title-case single words, leave the rest
    if " " not in stripped and stripped.isalpha():
        return stripped.capitalize()
    return stripped


def _values_equal(left: str, right: str) -> bool:
    """Compare raw settings after the same display normalisation users see."""
    return _normalize_value(left).strip().casefold() == _normalize_value(right).strip().casefold()


def _make_result(
    *,
    name: str,
    success: bool,
    before: str,
    after: str,
    needs_admin: bool,
    error: Optional[str] = None,
    note: str = "",
    command: str = "",
    command_exit_code: Optional[int] = None,
    verification: str = "",
    reboot_required: bool = False,
    desired: str = "",
) -> OptimizeResult:
    """Build an :class:`OptimizeResult` with correct *status* and *note*.

    Rules
    -----
    * Failed → ``after`` is cleared unless *verification* proves it changed.
    * A supplied *desired* value must match the observed *after* value before
      an operation can be successful.
    * ``before == desired == after`` and success → Verified.
    * ``before == after`` without a desired value → No change.
    * ``needs_admin`` and not success and "Administrator" in error → Skipped.
    * ``"unsupported"`` / ``"not found"`` in error → Unsupported.
    * *reboot_required* → Reboot required.
    """
    # Normalise display values
    before_display = _normalize_value(before)
    after_display = _normalize_value(after)
    desired_display = _normalize_value(desired) if desired else ""

    # A successful process exit is not proof that Windows accepted a setting.
    # Enforce read-back agreement centrally so callers cannot accidentally
    # report an unchanged-but-wrong value as "Verified".  Comparing the
    # display forms also handles equivalent values such as 0xFFFFFFFF and
    # 4294967295.
    if success and desired and not _values_equal(after, desired):
        success = False
        mismatch = (
            f"Verification failed: expected {desired_display}, "
            f"observed {after_display}"
        )
        error = error or mismatch
        note = mismatch

    # --- Derive status ---
    status: str
    if success:
        if desired and _values_equal(before, desired) and _values_equal(after, desired):
            status = "Verified"
            after_display = before_display  # nothing actually changed
            if not note or "reboot" in note.lower():
                note = f"Already optimized (set to {before_display})"
        elif not desired and _values_equal(before, after) and before.strip():
            status = "No change"
            if not note:
                note = f"No change (still {before_display})"
        elif reboot_required:
            status = "Reboot required"
        else:
            status = "Applied"
    else:
        # Determine failure flavour
        err_lower = (error or "").lower()
        if "skipped" in err_lower:
            status = "Skipped"
            after_display = "--"
            if not note:
                note = error or "Skipped"
        elif needs_admin and ("administrator" in err_lower or "privilege" in err_lower):
            status = "Skipped"
            after_display = "--"
            if not note:
                note = "Requires Administrator privileges"
        elif any(x in err_lower for x in ("unsupported", "not found", "not recognized", "not support", "does not support", "does not expose")):
            status = "Unsupported"
            after_display = "--"
            if not note:
                note = error or "Not supported on this system"
        else:
            status = "Failed"
            # Don't show a misleading "after" unless independently verified
            if not verification:
                after_display = "--"
            if not note:
                note = error or "Unknown error"

    # Final note fallback
    if not note:
        if status == "Applied":
            note = f"Changed from {before_display} to {after_display}"
        elif status == "Reboot required":
            note = f"Set to {after_display}; reboot needed to activate"

    return OptimizeResult(
        name=name,
        success=success,
        before=before_display,
        after=after_display,
        needs_admin=needs_admin,
        error=error,
        status=status,
        note=note,
        command=command,
        command_exit_code=command_exit_code,
        verification=verification,
        reboot_required=reboot_required,
    )


# ---------------------------------------------------------------------------
# NetworkOptimizer
# ---------------------------------------------------------------------------


class NetworkOptimizer:
    """Façade for all Windows network optimisation operations."""

    # ------------------------------------------------------------------
    # Admin check
    # ------------------------------------------------------------------

    @staticmethod
    def check_admin() -> bool:
        """Return ``True`` if the current process has Administrator rights."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False

    # ------------------------------------------------------------------
    # DNS benchmark & optimiser
    # ------------------------------------------------------------------

    def benchmark_dns(
        self, servers: list[str] | None = None
    ) -> list[DnsBenchmarkResult]:
        """Benchmark DNS servers and return results sorted fastest-first."""
        return _dns_benchmark_all(servers=servers)

    @staticmethod
    def _dns_state_display(state: DnsState) -> str:
        if not state.detected:
            return "Unavailable"
        if state.automatic is True:
            mode = "Automatic (DHCP)"
        elif state.automatic is False:
            mode = "Static"
        else:
            mode = "Mode unknown"
        servers = ", ".join(state.servers) if state.servers else "no IPv4 servers"
        return f"{mode}: {servers}"

    def _get_dns_state(self, adapter_name: str | None = None) -> DnsState:
        """Read IPv4 DNS state for exactly one adapter.

        PowerShell supplies locale-independent JSON and the registry-backed
        DHCP/static mode.  The adapter-scoped ``netsh`` fallback intentionally
        leaves the mode unknown when it cannot be established safely.
        """
        requested_name = adapter_name or self._active_adapter_name()
        adapter = _sanitize_adapter_name(requested_name)
        if not adapter:
            return DnsState(adapter_name="", detected=False)

        ps_command = (
            f"$adapter = Get-NetAdapter -Name '{adapter}' -ErrorAction Stop; "
            "$servers = @(Get-DnsClientServerAddress "
            "-InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 "
            "-ErrorAction Stop | Select-Object -ExpandProperty ServerAddresses); "
            "$guid = ([guid]$adapter.InterfaceGuid).ToString('B'); "
            "$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $guid; "
            "$reg = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue; "
            "$automatic = if ($null -eq $reg) { $null } else { "
            "[string]::IsNullOrWhiteSpace([string]$reg.NameServer) }; "
            "[PSCustomObject]@{ AdapterName = $adapter.Name; Servers = $servers; "
            "Automatic = $automatic } | ConvertTo-Json -Compress"
        )
        try:
            result = _run(["powershell", "-NoProfile", "-Command", ps_command])
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    raw_servers = data.get("Servers", [])
                    if isinstance(raw_servers, str):
                        raw_servers = [raw_servers]
                    servers = tuple(
                        server for server in raw_servers
                        if _is_ipv4_address(server)
                    ) if isinstance(raw_servers, list) else ()
                    automatic_raw = data.get("Automatic")
                    automatic = automatic_raw if isinstance(automatic_raw, bool) else None
                    actual_name = _sanitize_adapter_name(
                        str(data.get("AdapterName") or adapter),
                    )
                    return DnsState(
                        adapter_name=actual_name,
                        servers=servers,
                        automatic=automatic,
                        detected=True,
                    )
        except Exception as exc:
            logger.debug("PowerShell DNS detection failed for %s: %s", adapter, exc)

        try:
            result = _run([
                "netsh", "interface", "ipv4", "show", "dnsservers",
                f"name={adapter}",
            ])
            output_lower = (result.stdout + result.stderr).lower()
            if result.returncode != 0 or any(
                marker in output_lower
                for marker in ("not found", "no interface", "cannot find")
            ):
                return DnsState(adapter_name=adapter, detected=False)
            servers = tuple(
                address for address in re.findall(
                    r"\b\d{1,3}(?:\.\d{1,3}){3}\b", result.stdout,
                )
                if _is_ipv4_address(address)
            )
            automatic: Optional[bool] = None
            if "dhcp" in output_lower:
                automatic = True
            elif "static" in output_lower:
                automatic = False
            return DnsState(
                adapter_name=adapter,
                servers=servers,
                automatic=automatic,
                detected=True,
            )
        except Exception as exc:
            logger.warning("Failed to detect DNS for adapter %s: %s", adapter, exc)
            return DnsState(adapter_name=adapter, detected=False)

    def get_current_dns(
        self,
        adapter_name: str | None = None,
    ) -> tuple[str, str]:
        """Return primary/secondary IPv4 DNS for one adapter.

        When *adapter_name* is omitted, the active adapter is selected first.
        No server from any other adapter is considered.
        """
        state = self._get_dns_state(adapter_name)
        primary = state.servers[0] if state.servers else ""
        secondary = state.servers[1] if len(state.servers) > 1 else ""
        return primary, secondary

    def _write_dns_state(self, desired: DnsState) -> _DnsWriteOutcome:
        """Write and verify a complete DNS state on its named adapter."""
        reject_network_modification("optimizer._write_dns_state")
        adapter = desired.adapter_name
        if not adapter or _sanitize_adapter_name(adapter) != adapter:
            return _DnsWriteOutcome(
                success=False,
                after=DnsState(adapter_name=adapter, detected=False),
                commands=(), command_exit_code=None,
                error="Unsafe or missing DNS adapter name",
                verification="", changed=False,
            )
        if desired.automatic is None:
            return _DnsWriteOutcome(
                success=False,
                after=DnsState(adapter_name=adapter, detected=False),
                commands=(), command_exit_code=None,
                error="DNS source mode is unknown; refusing an inexact write",
                verification="", changed=False,
            )
        if len(desired.servers) > 16 or any(
            not _is_ipv4_address(server) for server in desired.servers
        ):
            return _DnsWriteOutcome(
                success=False,
                after=DnsState(adapter_name=adapter, detected=False),
                commands=(), command_exit_code=None,
                error="Invalid backed-up DNS server list",
                verification="", changed=False,
            )

        commands: list[list[str]] = []
        if desired.automatic:
            commands.append([
                "netsh", "interface", "ipv4", "set", "dnsservers",
                f"name={adapter}", "source=dhcp",
            ])
        else:
            if not desired.servers:
                return _DnsWriteOutcome(
                    success=False,
                    after=DnsState(adapter_name=adapter, detected=False),
                    commands=(), command_exit_code=None,
                    error="Static DNS backup contains no servers",
                    verification="", changed=False,
                )
            commands.append([
                "netsh", "interface", "ipv4", "set", "dnsservers",
                f"name={adapter}", "source=static",
                f"address={desired.servers[0]}", "register=primary", "validate=no",
            ])
            for index, server in enumerate(desired.servers[1:], start=2):
                commands.append([
                    "netsh", "interface", "ipv4", "add", "dnsservers",
                    f"name={adapter}", f"address={server}",
                    f"index={index}", "validate=no",
                ])

        error: Optional[str] = None
        exit_code: Optional[int] = None
        changed = False
        for command in commands:
            try:
                proc = _run(command)
                exit_code = proc.returncode
                if proc.returncode != 0:
                    detail = proc.stderr.strip() or proc.stdout.strip()
                    error = detail or f"DNS command exited with code {proc.returncode}"
                    break
                changed = True
            except Exception as exc:
                error = str(exc)
                break

        after = self._get_dns_state(adapter)
        verification = (
            f"Post-apply DNS read on {adapter}: {self._dns_state_display(after)}"
            if after.detected else ""
        )
        adapter_matches = (
            after.detected
            and after.adapter_name.casefold() == adapter.casefold()
        )
        if desired.automatic:
            state_matches = adapter_matches and after.automatic is True
        else:
            state_matches = (
                adapter_matches
                and after.automatic is False
                and after.servers == desired.servers
            )
        if error is None and not state_matches:
            error = (
                f"DNS verification failed for adapter {adapter}: expected "
                f"{self._dns_state_display(desired)}, observed "
                f"{self._dns_state_display(after)}"
            )
        return _DnsWriteOutcome(
            success=error is None and state_matches,
            after=after,
            commands=tuple(tuple(command) for command in commands),
            command_exit_code=exit_code,
            error=error,
            verification=verification,
            changed=changed,
        )

    def apply_dns(self, primary: str, secondary: str) -> OptimizeResult:
        """Set and verify DNS on the active adapter (requires admin)."""
        reject_network_modification("optimizer.apply_dns")
        name = "Set DNS servers"
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True, error="Administrator privileges required",
            )

        from losshound.core.dns_bench import query_dns_server
        from losshound.core.validation import validate_target

        adapter = self._active_adapter_name()
        before = self._get_dns_state(adapter)
        before_str = self._dns_state_display(before)
        desired_servers = (primary,) + ((secondary,) if secondary else ())
        desired = DnsState(
            adapter_name=adapter,
            servers=desired_servers,
            automatic=False,
            detected=True,
        )
        desired_str = self._dns_state_display(desired)

        if not before.detected or before.automatic is None:
            return _make_result(
                name=name, success=False, before=before_str, after="",
                needs_admin=True,
                error=(
                    "Could not capture the active adapter's DHCP/static DNS "
                    "state; DNS was left unchanged"
                ),
            )

        # ``netsh`` accepts IP addresses here, not arbitrary validated hostnames.
        if not validate_target(primary) or not _is_ipv4_address(primary):
            return _make_result(
                name=name, success=False, before=before_str, after="",
                needs_admin=True, error=f"Invalid primary DNS target: {primary!r}",
            )
        if secondary and (
            not validate_target(secondary) or not _is_ipv4_address(secondary)
        ):
            return _make_result(
                name=name, success=False, before=before_str, after="",
                needs_admin=True, error=f"Invalid secondary DNS target: {secondary!r}",
            )

        # Pre-test both resolvers before changing any system state.
        if query_dns_server(primary, "google.com", timeout=2.0) is None:
            return _make_result(
                name=name, success=False, before=before_str, after="",
                needs_admin=True,
                error=(
                    f"DNS validation failed: primary server {primary} did not "
                    "respond to UDP query"
                ),
            )
        if secondary and query_dns_server(
            secondary, "google.com", timeout=2.0,
        ) is None:
            return _make_result(
                name=name, success=False, before=before_str, after="",
                needs_admin=True,
                error=(
                    f"DNS validation failed: secondary server {secondary} did "
                    "not respond to UDP query"
                ),
            )

        outcome = self._write_dns_state(desired)
        final_after = outcome.after
        error = outcome.error
        note = (
            f"DNS set and verified on {adapter}"
            if outcome.success else "DNS change was not verified"
        )
        verification = outcome.verification
        command_parts = [" ".join(command) for command in outcome.commands]

        # A secondary-command failure otherwise leaves a half-applied static
        # list.  Restore the exact captured DHCP/static state before returning.
        if not outcome.success and outcome.changed:
            rollback = self._write_dns_state(before)
            command_parts.extend(
                f"rollback: {' '.join(command)}" for command in rollback.commands
            )
            final_after = rollback.after
            verification = "; ".join(
                part for part in (
                    outcome.verification,
                    f"Rollback {rollback.verification}"
                    if rollback.verification else "",
                ) if part
            )
            if rollback.success:
                note = "DNS change failed; original DNS state restored and verified"
                error = f"{error or 'DNS change failed'}; rollback succeeded"
            else:
                note = "DNS change and automatic rollback both failed"
                error = (
                    f"{error or 'DNS change failed'}; rollback failed: "
                    f"{rollback.error or 'verification unavailable'}"
                )

        return _make_result(
            name=name, success=outcome.success,
            before=before_str, after=self._dns_state_display(final_after),
            desired=desired_str,
            needs_admin=True, error=error,
            command=" && ".join(command_parts),
            command_exit_code=outcome.command_exit_code,
            verification=verification,
            note=note,
        )

    # ------------------------------------------------------------------
    # TCP/IP stack
    # ------------------------------------------------------------------

    def get_tcp_heuristics(self) -> str:
        """Read the TCP Window Scaling heuristics state via ``netsh``."""
        try:
            result = _run(["netsh", "interface", "tcp", "show", "heuristics"])
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, _, value = line.partition(":")
                    if "heuristics" in key.lower():
                        return _parse_bool_setting(value)
            return "unknown"
        except Exception as exc:
            logger.warning("Failed to read TCP heuristics: %s", exc)
            return "unknown"

    def disable_tcp_heuristics(self) -> OptimizeResult:
        """Disable TCP Window Scaling heuristics (requires admin)."""
        reject_network_modification("optimizer.disable_tcp_heuristics")
        name = "Disable TCP heuristics"
        cmd_args = ["netsh", "interface", "tcp", "set", "heuristics", "disabled"]
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
                command=" ".join(cmd_args),
            )
        before = self.get_tcp_heuristics()
        try:
            proc = _run(cmd_args)
            ok = proc.returncode == 0
            after = self.get_tcp_heuristics()
            verified = after.lower() == "disabled"
            return _make_result(
                name=name, success=verified,
                before=before, after=after,
                desired="disabled",
                needs_admin=True,
                error=proc.stderr.strip() if not ok else None,
                command=" ".join(cmd_args),
                verification=f"Heuristics check: {after}",
                note="Prevents Windows from automatically modifying TCP auto-tuning values" if verified else "",
            )
        except Exception as exc:
            return _make_result(
                name=name, success=False,
                before=before, after="",
                needs_admin=True, error=str(exc),
                command=" ".join(cmd_args),
            )

    def get_tcp_settings(self) -> TcpSettings:
        """Read current TCP global parameters via PowerShell or netsh."""
        settings = TcpSettings()
        
        # 1. Try to read from PowerShell JSON (locale-independent)
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-NetTCPSetting -SettingName Internet | ForEach-Object { "
                "[PSCustomObject]@{ "
                "CongestionProvider = $PSItem.CongestionProvider.ToString(); "
                "AutoTuningLevelLocal = $PSItem.AutoTuningLevelLocal.ToString(); "
                "EcnCapability = $PSItem.EcnCapability.ToString(); "
                "Timestamps = $PSItem.Timestamps.ToString(); "
                "ScalingHeuristics = $PSItem.ScalingHeuristics.ToString() "
                "} } | ConvertTo-Json"
            ]
            result = _run(cmd)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                settings.auto_tuning_level = data.get("AutoTuningLevelLocal", "unknown").lower()
                settings.congestion_provider = data.get("CongestionProvider", "unknown").lower()
                settings.ecn_capability = data.get("EcnCapability", "unknown").lower()
                settings.timestamps = data.get("Timestamps", "unknown").lower()
        except Exception as exc:
            logger.warning("Failed to read TCP settings via PowerShell: %s", exc)

        # 2. Try to get RSS and DCA from netsh (global parameters),
        # falling back to our robust locale-independent parser if needed.
        # Also fall back to netsh for auto-tuning, congestion_provider, ecn_capability, timestamps
        # if they are still "unknown".
        try:
            result = _run(["netsh", "interface", "tcp", "show", "global"])

            for line in result.stdout.splitlines():
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                
                # Check for keys using keywords
                if "rss" in key or "scaling" in key:
                    settings.rss = _parse_bool_setting(value)
                elif "dca" in key or "direct cache" in key:
                    settings.dca = _parse_bool_setting(value)
                elif "auto-tuning" in key or "tuning" in key:
                    if settings.auto_tuning_level == "unknown":
                        settings.auto_tuning_level = value.strip().lower()
                elif "congestion" in key or "addon" in key or "add-on" in key:
                    if settings.congestion_provider == "unknown":
                        settings.congestion_provider = value.lower()
                elif "ecn" in key:
                    if settings.ecn_capability == "unknown":
                        settings.ecn_capability = _parse_bool_setting(value)
                elif "timestamp" in key or "rfc 1323" in key:
                    if settings.timestamps == "unknown":
                        settings.timestamps = _parse_bool_setting(value)
        except Exception as exc:
            logger.warning("Failed to read TCP settings via netsh: %s", exc)

        return settings

    def optimize_tcp(self) -> list[OptimizeResult]:
        """Apply optimal TCP/IP stack settings.  Returns one result per tweak."""
        reject_network_modification("optimizer.optimize_tcp")
        results: list[OptimizeResult] = []
        if not self.check_admin():
            for label in (
                "TCP auto-tuning", "Congestion provider",
                "ECN capability", "RSS", "DCA", "TCP timestamps",
            ):
                results.append(_make_result(
                    name=label, success=False, before="", after="",
                    needs_admin=True,
                    error="Administrator privileges required",
                ))
            return results

        current = self.get_tcp_settings()

        # (label, command_list, current_value, desired_value, note_on_apply)
        tweaks: list[tuple[str, list[str], str, str, str]] = [
            (
                "TCP auto-tuning",
                ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
                current.auto_tuning_level,
                "normal",
                "Sets receive window auto-tuning to Normal for optimal throughput",
            ),
            (
                "Congestion provider",
                ["netsh", "int", "tcp", "set", "supplemental", "template=Internet", "congestionprovider=cubic"],
                current.congestion_provider,
                "cubic",
                "Switches to CUBIC congestion control for modern high-bandwidth performance",
            ),
            (
                "ECN capability",
                ["netsh", "int", "tcp", "set", "global", "ecncapability=enabled"],
                current.ecn_capability,
                "enabled",
                "Enables Explicit Congestion Notification to reduce packet loss",
            ),
            (
                "RSS",
                ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
                current.rss,
                "enabled",
                "Enables Receive-Side Scaling for multi-core packet processing",
            ),
            (
                "DCA",
                ["netsh", "int", "tcp", "set", "global", "dca=enabled"],
                current.dca,
                "enabled",
                "Enables Direct Cache Access to reduce CPU cache misses",
            ),
            (
                "TCP timestamps",
                ["netsh", "int", "tcp", "set", "global", "timestamps=enabled"],
                current.timestamps,
                "enabled",
                "Enables RFC 1323 timestamps for better RTT measurement",
            ),
        ]

        for label, command, before, desired, apply_note in tweaks:
            try:
                proc = _run(command)
                command_ok = proc.returncode == 0
                error = None
                if not command_ok:
                    error = proc.stderr.strip() or proc.stdout.strip()
                    error = error or f"Command exited with code {proc.returncode}"

                # Verify by re-reading TCP settings
                verified_settings = self.get_tcp_settings()
                field_map = {
                    "TCP auto-tuning": "auto_tuning_level",
                    "Congestion provider": "congestion_provider",
                    "ECN capability": "ecn_capability",
                    "RSS": "rss",
                    "DCA": "dca",
                    "TCP timestamps": "timestamps",
                }
                field = field_map.get(label, "")
                actual_after = (
                    getattr(verified_settings, field, "unknown")
                    if field else "unknown"
                )
                verification = f"Post-apply read: {actual_after}"

                # Detect unsupported
                out_lower = (proc.stdout + proc.stderr).lower()
                if "not found" in out_lower or "not recognized" in out_lower:
                    error = error or proc.stdout.strip()
                    command_ok = False

                verified = command_ok and _values_equal(actual_after, desired)
                if command_ok and not verified:
                    error = (
                        f"Post-apply verification failed: expected {desired}, "
                        f"observed {actual_after}"
                    )

                results.append(_make_result(
                    name=label, success=verified,
                    before=before, after=actual_after,
                    desired=desired,
                    needs_admin=True, error=error,
                    command=" ".join(command),
                    command_exit_code=proc.returncode,
                    verification=verification,
                    note=apply_note if verified else "",
                ))
            except Exception as exc:
                logger.error("TCP tweak '%s' failed: %s", label, exc)
                results.append(_make_result(
                    name=label, success=False,
                    before=before, after="",
                    needs_admin=True, error=str(exc),
                    command=" ".join(command),
                ))

        return results

    # ------------------------------------------------------------------
    # Network adapter
    # ------------------------------------------------------------------

    def get_active_adapter(self) -> AdapterInfo:
        """Detect the active network adapter via PowerShell.

        Prioritizes the adapter bound to the default IPv4 gateway route.
        """
        try:
            result = _run(
                [
                    "powershell", "-NoProfile", "-Command",
                    (
                        "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                        "-ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1; "
                        "$adapter = $null; "
                        "if ($route) { "
                        "    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue; "
                        "} "
                        "if (-not $adapter) { "
                        "    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1; "
                        "} "
                        "if ($adapter) { "
                        "    $adapter | Select-Object Name, InterfaceIndex, MacAddress, LinkSpeed | ConvertTo-Json "
                        "}"
                    ),
                ],
            )
            data = json.loads(result.stdout)
            # Fetch IP address separately
            ip_result = _run(
                [
                    "powershell", "-NoProfile", "-Command",
                    (
                        f"(Get-NetIPAddress -InterfaceIndex {data['InterfaceIndex']} "
                        "-AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress"
                    ),
                ],
            )
            ip_addr = ip_result.stdout.strip().splitlines()[0] if ip_result.stdout.strip() else ""
            return AdapterInfo(
                name=_sanitize_adapter_name(data.get("Name", "")),
                interface_index=int(data.get("InterfaceIndex", 0)),
                ip_address=ip_addr,
                mac_address=data.get("MacAddress", ""),
                speed=data.get("LinkSpeed", ""),
            )
        except Exception as exc:
            logger.warning("Failed to detect active adapter: %s", exc)
            # Fallback: try ipconfig parsing
            return AdapterInfo(
                name=self._active_adapter_name(),
                interface_index=0,
                ip_address="",
                mac_address="",
                speed="",
            )

    def _active_adapter_name(self) -> str:
        """Best-effort adapter name detection for use in netsh commands."""
        # Prefer the shared structured route query.  It considers route and
        # interface metrics together and never parses localized status text.
        try:
            from losshound.core.windows_network import (
                get_active_network_interface,
            )

            active = get_active_network_interface()
            if active and active.interface_alias:
                return _sanitize_adapter_name(active.interface_alias)
        except Exception as exc:
            logger.debug("Structured active-adapter detection failed: %s", exc)

        try:
            result = _run(
                [
                    "powershell", "-NoProfile", "-Command",
                    (
                        "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                        "-ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1; "
                        "$adapter = $null; "
                        "if ($route) { "
                        "    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue; "
                        "} "
                        "if (-not $adapter) { "
                        "    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1; "
                        "} "
                        "if ($adapter) { "
                        "    $adapter.Name "
                        "}"
                    ),
                ],
            )
            name = result.stdout.strip()
            if name:
                return _sanitize_adapter_name(name)
        except Exception:
            pass

        # Fallback: parse netsh
        try:
            result = _run(
                ["netsh", "interface", "show", "interface"],
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and any(x in parts[1].lower() for x in ("connected", "bağlı", "verbunden", "conectado")):
                    return _sanitize_adapter_name(" ".join(parts[3:]))
        except Exception:
            pass
        return "Ethernet"

    def optimize_adapter(
        self,
        *,
        include_interrupt_moderation: bool = False,
    ) -> list[OptimizeResult]:
        """Optimise the active network adapter settings."""
        reject_network_modification("optimizer.optimize_adapter")
        results: list[OptimizeResult] = []
        if not self.check_admin():
            for label in ("Adapter power management", "Interrupt moderation"):
                results.append(_make_result(
                    name=label,
                    success=False, before="", after="",
                    needs_admin=True,
                    error="Administrator privileges required",
                ))
            return results

        adapter = self.get_active_adapter()

        # --- Power management ---
        pm_cmd = (
            f"Disable-NetAdapterPowerManagement "
            f"-Name '{adapter.name}' "
            f"-ErrorAction Stop"
        )
        try:
            # Check if power management is supported / readable
            pm_check_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"$pm = Get-NetAdapterPowerManagement -Name '{adapter.name}' "
                f"-ErrorAction SilentlyContinue; "
                f"if ($pm) {{ $pm.AllowComputerToTurnOffDevice }} "
                f"else {{ 'NOT_SUPPORTED' }}",
            ])
            pm_before_raw = pm_check_proc.stdout.strip()

            # Detect if battery is present (indicates a laptop / portable device)
            battery_check = _run([
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue"
            ])
            is_laptop = bool(battery_check.stdout.strip())

            if pm_before_raw == "NOT_SUPPORTED" or not pm_before_raw:
                results.append(_make_result(
                    name="Adapter power management",
                    success=False,
                    before="--", after="--",
                    needs_admin=True,
                    error="Adapter does not support power management control",
                    command=pm_cmd,
                    command_exit_code=pm_check_proc.returncode,
                    note=f"Adapter '{adapter.name}' does not expose this setting",
                ))
            elif is_laptop:
                results.append(_make_result(
                    name="Adapter power management",
                    success=False,
                    before=pm_before_raw, after=pm_before_raw,
                    needs_admin=True,
                    error="Skipped on battery-powered device",
                    command=pm_cmd,
                    note="Skipped to prevent battery drain on laptop",
                ))
            else:
                pm_before = pm_before_raw

                proc = _run(
                    ["powershell", "-NoProfile", "-Command", pm_cmd],
                )
                ok = proc.returncode == 0
                error = proc.stderr.strip() or None if not ok else None

                # Detect unsupported from stderr
                err_lower = (proc.stderr or "").lower()
                if "not found" in err_lower or "not recognized" in err_lower or "not supported" in err_lower:
                    ok = False
                    error = proc.stderr.strip()

                # Verify
                pm_after_proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-NetAdapterPowerManagement -Name '{adapter.name}' "
                    f"-ErrorAction SilentlyContinue).AllowComputerToTurnOffDevice",
                ])
                pm_after = pm_after_proc.stdout.strip() or pm_before
                verification = f"Post-apply read: {pm_after}"

                results.append(_make_result(
                    name="Adapter power management",
                    success=ok,
                    before=pm_before, after=pm_after if ok else pm_before,
                    desired="disabled",
                    needs_admin=True, error=error,
                    command=pm_cmd,
                    command_exit_code=proc.returncode,
                    verification=verification,
                    note="Prevents adapter sleep to maintain low-latency connection" if ok else "",
                ))
        except Exception as exc:
            results.append(_make_result(
                name="Adapter power management",
                success=False, before="unknown", after="",
                needs_admin=True, error=str(exc),
                command=pm_cmd,
            ))

        if not include_interrupt_moderation:
            results.append(_make_result(
                name="Interrupt moderation",
                success=False, before="", after="",
                needs_admin=True,
                error="Skipped: interrupt moderation changes are opt-in",
                note=(
                    "Skipped by default; disabling interrupt moderation can "
                    "increase CPU interrupts and worsen lag under load"
                ),
            ))
            return results

        # --- Interrupt moderation ---
        im_cmd = (
            f"Set-NetAdapterAdvancedProperty "
            f"-Name '{adapter.name}' "
            f"-RegistryKeyword '*InterruptModeration' "
            f"-RegistryValue 0 "
            f"-ErrorAction Stop"
        )
        try:
            # First check if this adapter even exposes the property.
            im_check_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"$p = Get-NetAdapterAdvancedProperty -Name '{adapter.name}' "
                f"-RegistryKeyword '*InterruptModeration' "
                f"-ErrorAction SilentlyContinue; "
                f"if ($p) {{ $p.RegistryValue }} else {{ 'NOT_SUPPORTED' }}",
            ])
            im_before_raw = im_check_proc.stdout.strip()

            if im_before_raw == "NOT_SUPPORTED" or not im_before_raw:
                results.append(_make_result(
                    name="Interrupt moderation",
                    success=False,
                    before="--", after="--",
                    needs_admin=True,
                    error="Adapter does not expose *InterruptModeration property",
                    command=im_cmd,
                    command_exit_code=im_check_proc.returncode,
                    note=f"Adapter '{adapter.name}' does not support this setting",
                ))
                return results

            im_before = im_before_raw

            proc = _run(
                ["powershell", "-NoProfile", "-Command", im_cmd],
            )
            ok = proc.returncode == 0
            error = proc.stderr.strip() or None if not ok else None

            err_lower = (proc.stderr or "").lower()
            if "not found" in err_lower or "not supported" in err_lower:
                ok = False
                error = proc.stderr.strip()

            # Verify by re-reading the property
            im_after_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"(Get-NetAdapterAdvancedProperty -Name '{adapter.name}' "
                f"-RegistryKeyword '*InterruptModeration' "
                f"-ErrorAction SilentlyContinue).RegistryValue",
            ])
            im_after = im_after_proc.stdout.strip() or im_before
            verification = f"Post-apply read: {im_after}"

            # Cross-check: if command said OK but value didn't change and
            # it wasn't already 0, something went wrong.
            if ok and im_after != "0" and im_before != "0":
                ok = False
                error = f"Command exited 0 but value stayed at {im_after}"

            results.append(_make_result(
                name="Interrupt moderation",
                success=ok,
                before=im_before, after=im_after if ok else im_before,
                desired="0",
                needs_admin=True, error=error,
                command=im_cmd,
                command_exit_code=proc.returncode,
                verification=verification,
                note="Disables interrupt coalescing for lowest latency" if ok else "",
            ))
        except Exception as exc:
            results.append(_make_result(
                name="Interrupt moderation",
                success=False, before="unknown", after="",
                needs_admin=True, error=str(exc),
                command=im_cmd,
            ))

        return results

    def optimize_winsock_datagram_threshold(self) -> OptimizeResult:
        """Set Winsock FastSendDatagramThreshold to 1500 (requires admin)."""
        reject_network_modification("optimizer.optimize_winsock_datagram_threshold")
        name = "Set FastSendDatagramThreshold"
        cmd_desc = r"Set registry HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters\FastSendDatagramThreshold = 1500"
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
                command=cmd_desc,
            )

        # First read current
        key_path = r"SYSTEM\CurrentControlSet\Services\AFD\Parameters"
        before_str = "default (1024)"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, "FastSendDatagramThreshold")
                before_str = str(val)
        except OSError:
            pass

        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(
                    key, "FastSendDatagramThreshold", 0,
                    winreg.REG_DWORD, 1500,
                )

            # Verify
            after_str = "Unknown"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, "FastSendDatagramThreshold")
                after_str = str(val)

            verified = val == 1500
            return _make_result(
                name=name, success=verified,
                before=before_str, after=after_str,
                desired="1500",
                needs_admin=True,
                command=cmd_desc,
                verification=f"Registry read-back: {after_str}",
                reboot_required=True,
                note="Enables Winsock fast datagram path for standard MTU size packets; reboot recommended" if verified else f"Verification read: {after_str}",
            )
        except OSError as exc:
            return _make_result(
                name=name, success=False,
                before=before_str, after="",
                needs_admin=True, error=str(exc),
                command=cmd_desc,
            )

    def optimize_eee(self, disable: bool = True) -> OptimizeResult:
        """Enable or disable Energy Efficient Ethernet (EEE) on the active adapter (requires admin)."""
        reject_network_modification("optimizer.optimize_eee")
        name = "Disable Energy Efficient Ethernet (EEE)" if disable else "Enable Energy Efficient Ethernet (EEE)"
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
            )

        adapter = self.get_active_adapter()
        if not adapter.name:
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True, error="No active adapter name found",
            )

        # Find property registry keyword
        try:
            kw_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"$p = Get-NetAdapterAdvancedProperty -Name '{adapter.name}' -ErrorAction SilentlyContinue "
                f"| Where-Object {{ $_.RegistryKeyword -eq '*EEE' -or $_.RegistryKeyword -eq 'EEE' }}; "
                f"if ($p) {{ $p.RegistryKeyword }} else {{ '' }}",
            ])
            kw = kw_proc.stdout.strip()
            if not kw:
                return _make_result(
                    name=name, success=False, before="--", after="--",
                    needs_admin=True,
                    error="Adapter does not expose EEE property",
                    note=f"Adapter '{adapter.name}' does not support EEE",
                )

            # Get current value
            val_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"(Get-NetAdapterAdvancedProperty -Name '{adapter.name}' -RegistryKeyword '{kw}' -ErrorAction SilentlyContinue).RegistryValue",
            ])
            before_val = val_proc.stdout.strip()

            target_val = "0" if disable else "1"
            cmd = f"Set-NetAdapterAdvancedProperty -Name '{adapter.name}' -RegistryKeyword '{kw}' -RegistryValue {target_val}"
            proc = _run(["powershell", "-NoProfile", "-Command", cmd])
            ok = proc.returncode == 0

            # Verify
            verify_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"(Get-NetAdapterAdvancedProperty -Name '{adapter.name}' -RegistryKeyword '{kw}' -ErrorAction SilentlyContinue).RegistryValue",
            ])
            after_val = verify_proc.stdout.strip()
            verified = ok and after_val == target_val

            return _make_result(
                name=name, success=verified,
                before=before_val, after=after_val,
                desired=target_val,
                needs_admin=True,
                command=cmd,
                command_exit_code=proc.returncode,
                verification=f"Registry keyword value: {after_val}",
                note="Disables physical ethernet power-state delays" if (verified and disable) else "",
            )
        except Exception as exc:
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True, error=str(exc),
            )

    def optimize_rsc(self, disable: bool = True) -> OptimizeResult:
        """Enable or disable Receive Segment Coalescing (RSC) on the active adapter (requires admin)."""
        reject_network_modification("optimizer.optimize_rsc")
        name = "Disable Receive Segment Coalescing (RSC)" if disable else "Enable Receive Segment Coalescing (RSC)"
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
            )

        adapter = self.get_active_adapter()
        if not adapter.name:
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True, error="No active adapter name found",
            )

        # Check if RSC is supported
        try:
            check_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"$r = Get-NetAdapterRsc -Name '{adapter.name}' -ErrorAction SilentlyContinue; "
                f"if ($r) {{ $r.IPv4Enabled }} else {{ 'NOT_SUPPORTED' }}"
            ])
            check_val = check_proc.stdout.strip().lower()
            if check_val == "not_supported" or not check_val:
                return _make_result(
                    name=name, success=False, before="--", after="--",
                    needs_admin=True,
                    error="Adapter does not support RSC",
                )

            before_status = "Enabled" if check_val == "true" else "Disabled"
            cmd = (
                f"Disable-NetAdapterRsc -Name '{adapter.name}' -IPv4 -IPv6 -ErrorAction Stop"
                if disable else
                f"Enable-NetAdapterRsc -Name '{adapter.name}' -IPv4 -IPv6 -ErrorAction Stop"
            )

            proc = _run(["powershell", "-NoProfile", "-Command", cmd])
            ok = proc.returncode == 0

            # Verify
            verify_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"(Get-NetAdapterRsc -Name '{adapter.name}' -ErrorAction SilentlyContinue).IPv4Enabled"
            ])
            verify_val = verify_proc.stdout.strip().lower()
            verified = ok and (verify_val == "false" if disable else verify_val == "true")
            after_status = "Disabled" if verify_val == "false" else ("Enabled" if verify_val == "true" else "Unknown")

            return _make_result(
                name=name, success=verified,
                before=before_status, after=after_status,
                desired="Disabled" if disable else "Enabled",
                needs_admin=True,
                command=cmd,
                command_exit_code=proc.returncode,
                verification=f"IPv4Enabled: {verify_val}",
                note="Disables packet coalescing to avoid processing delay and jitter" if (verified and disable) else "",
            )
        except Exception as exc:
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True, error=str(exc),
            )

    def optimize_lso(self, disable: bool = True) -> OptimizeResult:
        """Enable or disable Large Send Offload (LSO) on the active adapter (requires admin)."""
        reject_network_modification("optimizer.optimize_lso")
        name = "Disable Large Send Offload (LSO)" if disable else "Enable Large Send Offload (LSO)"
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
            )

        adapter = self.get_active_adapter()
        if not adapter.name:
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True, error="No active adapter name found",
            )

        # Check if LSO is supported
        try:
            check_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"$l = Get-NetAdapterLso -Name '{adapter.name}' -ErrorAction SilentlyContinue; "
                f"if ($l) {{ $l.IPv4Enabled }} else {{ 'NOT_SUPPORTED' }}"
            ])
            check_val = check_proc.stdout.strip().lower()
            if check_val == "not_supported" or not check_val:
                return _make_result(
                    name=name, success=False, before="--", after="--",
                    needs_admin=True,
                    error="Adapter does not support LSO",
                )

            before_status = "Enabled" if check_val == "true" else "Disabled"
            cmd = (
                f"Disable-NetAdapterLso -Name '{adapter.name}' -IPv4 -IPv6 -ErrorAction Stop"
                if disable else
                f"Enable-NetAdapterLso -Name '{adapter.name}' -IPv4 -IPv6 -ErrorAction Stop"
            )

            proc = _run(["powershell", "-NoProfile", "-Command", cmd])
            ok = proc.returncode == 0

            # Verify
            verify_proc = _run([
                "powershell", "-NoProfile", "-Command",
                f"(Get-NetAdapterLso -Name '{adapter.name}' -ErrorAction SilentlyContinue).IPv4Enabled"
            ])
            verify_val = verify_proc.stdout.strip().lower()
            verified = ok and (verify_val == "false" if disable else verify_val == "true")
            after_status = "Disabled" if verify_val == "false" else ("Enabled" if verify_val == "true" else "Unknown")

            return _make_result(
                name=name, success=verified,
                before=before_status, after=after_status,
                desired="Disabled" if disable else "Enabled",
                needs_admin=True,
                command=cmd,
                command_exit_code=proc.returncode,
                verification=f"IPv4Enabled: {verify_val}",
                note="Disables segmentation offloading to guarantee consistent packet timing" if (verified and disable) else "",
            )
        except Exception as exc:
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True, error=str(exc),
            )

    # ------------------------------------------------------------------
    # Windows network tweaks
    # ------------------------------------------------------------------

    def flush_dns_cache(self) -> OptimizeResult:
        """Flush the Windows DNS resolver cache."""
        reject_network_modification("optimizer.flush_dns_cache")
        cmd_args = ["ipconfig", "/flushdns"]
        try:
            proc = _run(cmd_args)
            ok = proc.returncode == 0
            return _make_result(
                name="Flush DNS cache", success=ok,
                before="cached", after="flushed" if ok else "cached",
                needs_admin=False,
                error=proc.stderr.strip() or None if not ok else None,
                command=" ".join(cmd_args),
                command_exit_code=proc.returncode,
                note="DNS resolver cache cleared" if ok else "",
            )
        except Exception as exc:
            return _make_result(
                name="Flush DNS cache", success=False,
                before="cached", after="",
                needs_admin=False, error=str(exc),
                command=" ".join(cmd_args),
            )

    def flush_arp_cache(self) -> OptimizeResult:
        """Flush the ARP cache (requires admin)."""
        reject_network_modification("optimizer.flush_arp_cache")
        name = "Flush ARP cache"
        cmd_args = ["netsh", "interface", "ip", "delete", "arpcache"]
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
                command=" ".join(cmd_args),
            )
        try:
            proc = _run(cmd_args)
            ok = proc.returncode == 0
            return _make_result(
                name=name, success=ok,
                before="cached", after="flushed" if ok else "cached",
                needs_admin=True,
                error=proc.stderr.strip() or None if not ok else None,
                command=" ".join(cmd_args),
                command_exit_code=proc.returncode,
                note="ARP cache cleared; stale MAC mappings removed" if ok else "",
            )
        except Exception as exc:
            return _make_result(
                name=name, success=False,
                before="cached", after="",
                needs_admin=True, error=str(exc),
                command=" ".join(cmd_args),
            )

    def get_system_responsiveness(self) -> int | None:
        """Read the ``SystemResponsiveness`` value from the registry."""
        key_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile"
        )
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "SystemResponsiveness")
                return int(value)
        except OSError:
            return None

    def apply_system_responsiveness(self, value: int) -> OptimizeResult:
        """Configure SystemResponsiveness in registry (requires admin)."""
        reject_network_modification("optimizer.apply_system_responsiveness")
        name = "Set system responsiveness"
        reg_path = (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile\SystemResponsiveness"
        )
        cmd_desc = f"Set registry {reg_path} = {value}"
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
                command=cmd_desc,
            )

        before_val = self.get_system_responsiveness()
        before_str = str(before_val) if before_val is not None else "default"
        key_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile"
        )
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(
                    key, "SystemResponsiveness", 0,
                    winreg.REG_DWORD, value,
                )

            # Verify
            after_val = self.get_system_responsiveness()
            after_str = str(after_val) if after_val is not None else "default"
            verified = after_val == value

            return _make_result(
                name=name, success=verified,
                before=before_str, after=after_str,
                desired=str(value),
                needs_admin=True,
                command=cmd_desc,
                verification=f"Registry read-back: {after_str}",
                reboot_required=True,
                note=f"Prioritizes multimedia/gaming resources (set to {value}%); reboot recommended"
                     if verified else f"Write succeeded but verification read: {after_str}",
            )
        except OSError as exc:
            return _make_result(
                name=name, success=False,
                before=before_str, after="",
                needs_admin=True, error=str(exc),
                command=cmd_desc,
            )

    def benchmark_optimal_responsiveness(
        self,
        target: str | None = None,
        progress_callback = None,
    ) -> tuple[int, dict[int, tuple[float, float]]]:
        """Test candidate SystemResponsiveness values (20, 10, 0) and find the best performing one.

        Temporarily sets the SystemResponsiveness registry value to each candidate,
        runs 10 pings to calculate average RTT and jitter, and scores using:
        Score = Average RTT + 2 * Jitter. Lower score is better.

        Restores the original setting after testing.

        Returns
        -------
        best_candidate: int
            The candidate with the lowest score.
        stats: dict[int, tuple[float, float]]
            Map of candidate -> (avg_latency_ms, jitter_ms).
        """
        reject_network_modification("optimizer.benchmark_optimal_responsiveness")
        if not self.check_admin():
            raise PermissionError("Administrator privileges required for benchmarking responsiveness.")

        from losshound.core.gateway import detect_gateway
        from losshound.core.ping import ping

        try:
            from PySide6.QtCore import QThread
            def is_interrupted():
                t = QThread.currentThread()
                return t.isInterruptionRequested() if t else False
        except (ImportError, AttributeError, TypeError):
            is_interrupted = lambda: False

        ping_target = target or detect_gateway() or "8.8.8.8"

        original_val = self.get_system_responsiveness()
        if original_val is None:
            original_val = 20  # Windows default

        candidates = [20, 10, 0]
        results: dict[int, tuple[float, float]] = {}

        try:
            for val in candidates:
                if is_interrupted():
                    raise InterruptedError("Interruption requested during responsiveness benchmark.")

                if progress_callback:
                    progress_callback(f"Testing SystemResponsiveness = {val} against {ping_target}...")

                # Apply temporarily
                self.apply_system_responsiveness(val)
                # Wait briefly for OS thread scheduler / network stack to adjust
                time.sleep(0.5)

                if is_interrupted():
                    raise InterruptedError("Interruption requested during responsiveness benchmark.")

                # Warmup ping to establish routing/ARP entries
                ping(ping_target, count=1, timeout_ms=1000)

                if is_interrupted():
                    raise InterruptedError("Interruption requested during responsiveness benchmark.")

                # Run 10 pings
                res = ping(ping_target, count=10, timeout_ms=1000)

                avg_lat = res.rtt_avg if (res.rtt_avg is not None) else 999.0
                jitter = res.rtt_jitter if (res.rtt_jitter is not None) else 999.0

                results[val] = (avg_lat, jitter)
        finally:
            # Restore original
            self.apply_system_responsiveness(original_val)

        # Score candidates: Score = Avg Latency + 2 * Jitter
        best_candidate = 20
        best_score = float("inf")
        for val, (avg_lat, jitter) in results.items():
            score = avg_lat + 2 * jitter
            if score < best_score:
                best_score = score
                best_candidate = val

        return best_candidate, results

    def get_network_throttling_index(self) -> int | None:
        """Read the ``NetworkThrottlingIndex`` value from the registry."""
        key_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile"
        )
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "NetworkThrottlingIndex")
                return int(value)
        except OSError:
            return None

    def disable_network_throttling(self) -> OptimizeResult:
        """Set ``NetworkThrottlingIndex`` to ``0xFFFFFFFF`` (requires admin)."""
        reject_network_modification("optimizer.disable_network_throttling")
        name = "Disable network throttling"
        reg_path = (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile\NetworkThrottlingIndex"
        )
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
                command=f"Set registry {reg_path} = 0xFFFFFFFF",
            )

        key_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile"
        )
        before_val = self.get_network_throttling_index()
        before_str = str(before_val) if before_val is not None else "default"
        cmd_desc = f"Set registry {reg_path} = 0xFFFFFFFF"
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(
                    key, "NetworkThrottlingIndex", 0,
                    winreg.REG_DWORD, 0xFFFFFFFF,
                )

            # Verify
            after_val = self.get_network_throttling_index()
            after_str = str(after_val) if after_val is not None else "default"
            verified = after_val is not None and (after_val == 0xFFFFFFFF or after_val == -1)

            return _make_result(
                name=name, success=verified,
                before=before_str, after=after_str,
                desired="0xFFFFFFFF",
                needs_admin=True,
                command=cmd_desc,
                verification=f"Registry read-back: {after_str}",
                note="Removes 10-packet-per-ms throttle on non-multimedia traffic"
                     if verified else f"Write succeeded but verification read: {after_str}",
            )
        except OSError as exc:
            return _make_result(
                name=name, success=False,
                before=before_str, after="",
                needs_admin=True, error=str(exc),
                command=cmd_desc,
            )

    def optimize_nagle(self) -> OptimizeResult:
        """Disable Nagle's algorithm for the active adapter (requires admin).

        Sets ``TcpAckFrequency`` and ``TCPNoDelay`` to ``1`` in the
        registry for the interface that owns the current default gateway.
        """
        reject_network_modification("optimizer.optimize_nagle")
        name = "Disable Nagle's algorithm"
        cmd_desc = "Set registry TcpAckFrequency=1, TCPNoDelay=1"
        if not self.check_admin():
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
                command=cmd_desc,
            )

        base_path = (
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        )
        try:
            # Find the sub-key whose DhcpDefaultGateway or DefaultGateway is
            # non-empty — that's the active interface.
            target_guid: str | None = None
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as base:
                idx = 0
                while True:
                    try:
                        guid = winreg.EnumKey(base, idx)
                    except OSError:
                        break
                    idx += 1
                    try:
                        with winreg.OpenKey(base, guid) as sub:
                            for val_name in (
                                "DhcpDefaultGateway", "DefaultGateway",
                            ):
                                try:
                                    gw, _ = winreg.QueryValueEx(sub, val_name)
                                    if gw and any(g for g in gw if g):
                                        target_guid = guid
                                        break
                                except OSError:
                                    continue
                    except OSError:
                        continue
                    if target_guid:
                        break

            if not target_guid:
                return _make_result(
                    name=name, success=False,
                    before="", after="",
                    needs_admin=True,
                    error="Could not identify active network interface in registry",
                    command=cmd_desc,
                    note="No interface with a default gateway found in registry",
                )

            iface_path = f"{base_path}\\{target_guid}"
            reg_full = f"HKLM\\{iface_path}"
            cmd_desc = f"Set {reg_full}\\TcpAckFrequency=1, TCPNoDelay=1, TcpDelAckTicks=0"

            # Read current state
            nagle_before = "Enabled (default)"
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, iface_path, 0,
                    winreg.KEY_READ,
                ) as key:
                    try:
                        nd, _ = winreg.QueryValueEx(key, "TCPNoDelay")
                        ack, _ = winreg.QueryValueEx(key, "TcpAckFrequency")
                        ticks = 2
                        try:
                            ticks, _ = winreg.QueryValueEx(key, "TcpDelAckTicks")
                        except OSError:
                            pass
                        if nd == 1 and ack == 1 and ticks == 0:
                            nagle_before = "Disabled"
                    except OSError:
                        pass
            except OSError:
                pass

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, iface_path, 0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(
                    key, "TcpAckFrequency", 0, winreg.REG_DWORD, 1,
                )
                winreg.SetValueEx(
                    key, "TCPNoDelay", 0, winreg.REG_DWORD, 1,
                )
                winreg.SetValueEx(
                    key, "TcpDelAckTicks", 0, winreg.REG_DWORD, 0,
                )

            # Verify
            nagle_after = "Unknown"
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, iface_path, 0,
                    winreg.KEY_READ,
                ) as key:
                    nd, _ = winreg.QueryValueEx(key, "TCPNoDelay")
                    ack, _ = winreg.QueryValueEx(key, "TcpAckFrequency")
                    ticks = 2
                    try:
                        ticks, _ = winreg.QueryValueEx(key, "TcpDelAckTicks")
                    except OSError:
                        pass
                    if nd == 1 and ack == 1 and ticks == 0:
                        nagle_after = "Disabled"
                    else:
                        nagle_after = f"TCPNoDelay={nd}, TcpAckFrequency={ack}, TcpDelAckTicks={ticks}"
            except OSError:
                nagle_after = "Written (unverified)"

            return _make_result(
                name=name, success=True,
                before=nagle_before,
                after=nagle_after,
                desired="Disabled",
                needs_admin=True,
                command=cmd_desc,
                verification=f"Registry read-back: {nagle_after}",
                reboot_required=True,
                note="Disables TCP delay mechanisms and delayed ACK timer for lowest latency; reboot recommended",
            )
        except OSError as exc:
            return _make_result(
                name=name, success=False,
                before="", after="",
                needs_admin=True, error=str(exc),
                command=cmd_desc,
            )

    # ------------------------------------------------------------------
    # MTU optimiser
    # ------------------------------------------------------------------

    def get_current_mtu(self) -> int:
        """Read the current MTU for the active adapter."""
        try:
            adapter = self._active_adapter_name()
            result = _run(
                ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            )
            for line in result.stdout.splitlines():
                if adapter.lower() in line.lower():
                    parts = line.split()
                    for part in parts:
                        if part.isdigit():
                            mtu = int(part)
                            if 500 <= mtu <= 9000:
                                return mtu
        except Exception as exc:
            logger.warning("Failed to read MTU: %s", exc)
        return 1500  # sensible default

    def find_optimal_mtu(self, target: str = "8.8.8.8") -> Optional[int]:
        """Binary-search for the largest MTU that does not cause fragmentation.

        Uses ``ping -f -l <size>`` to test.  The returned value includes
        the 28-byte IP+ICMP header overhead.
        """
        from losshound.core.validation import validate_target
        if not validate_target(target):
            logger.warning("Invalid MTU target: %r", target)
            return None

        low = 1252  # payload size (MTU 1280 - 28)
        high = 1472  # payload size (MTU 1500 - 28)
        best: Optional[int] = None

        while low <= high:
            mid = (low + high) // 2
            # ``ping -f -l`` sends a payload of *mid* bytes.
            # The actual MTU = payload + 28 (20 IP + 8 ICMP header).
            try:
                proc = _run(["ping", "-n", "1", "-f", "-l", str(mid), "-w", "2000", target])
                stdout = proc.stdout
            except Exception:
                break

            stdout_lower = stdout.lower()
            # Check for a successful reply (ttl= is universal across languages)
            has_reply = "ttl=" in stdout_lower or "reply from" in stdout_lower or "antwort von" in stdout_lower or "réponse de" in stdout_lower or "respuesta de" in stdout_lower or "cevap" in stdout_lower
            
            # Check for fragmentation needed
            needs_frag = (
                "fragment" in stdout_lower
                or "df" in stdout_lower
                or "parça" in stdout_lower
                or "parca" in stdout_lower
                or "must be" in stdout_lower
            ) and not has_reply

            if has_reply:
                best = mid
                low = mid + 1
            elif needs_frag:
                high = mid - 1
            else:
                # Timeout or other failure — shrink
                high = mid - 1

        if best is None:
            logger.warning("MTU discovery was inconclusive; leaving current MTU unchanged")
            return None

        optimal_mtu = best + 28  # add IP+ICMP header
        logger.info("Optimal MTU detected: %d (payload %d + 28)", optimal_mtu, best)
        return optimal_mtu

    def apply_mtu(self, mtu: int) -> OptimizeResult:
        """Set the MTU on the active adapter (requires admin)."""
        reject_network_modification("optimizer.apply_mtu")
        name = "Set MTU"
        adapter = self._active_adapter_name()
        cmd_args = [
            "netsh", "interface", "ipv4", "set", "subinterface",
            adapter, f"mtu={mtu}", "store=persistent"
        ]
        if not self.check_admin():
            return _make_result(
                name=name, success=False,
                before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
                command=" ".join(cmd_args),
            )

        before_mtu = self.get_current_mtu()
        try:
            proc = _run(cmd_args)
            ok = proc.returncode == 0 or "ok" in proc.stdout.lower()
            error = proc.stderr.strip() or None if not ok else None

            # Verify
            after_mtu = self.get_current_mtu()
            verification = f"Post-apply MTU read: {after_mtu}"

            return _make_result(
                name=name, success=ok,
                before=str(before_mtu), after=str(after_mtu) if ok else str(before_mtu),
                desired=str(mtu),
                needs_admin=True, error=error,
                command=" ".join(cmd_args),
                command_exit_code=proc.returncode,
                verification=verification,
                note=f"MTU optimised via ping fragmentation test"
                     if ok and after_mtu != before_mtu
                     else f"MTU already optimal at {before_mtu}"
                     if ok and after_mtu == before_mtu
                     else "",
            )
        except Exception as exc:
            return _make_result(
                name=name, success=False,
                before=str(before_mtu), after="",
                needs_admin=True, error=str(exc),
                command=cmd,
            )

    # ------------------------------------------------------------------
    # Backup & restore
    # ------------------------------------------------------------------

    def create_backup(self) -> BackupData:
        """Snapshot all current settings so they can be restored later."""
        # Check if backup file exists and is valid
        if _BACKUP_FILE.is_file():
            existing = self._load_backup()
            if existing is not None:
                logger.info("Pristine backup already exists, preserving it: %s", _BACKUP_FILE)
                return existing
            else:
                # Corrupt backup exists, back it aside
                corrupt_path = _BACKUP_FILE.with_suffix(".json.corrupt")
                try:
                    if corrupt_path.is_file():
                        corrupt_path.unlink()
                    _BACKUP_FILE.rename(corrupt_path)
                    logger.warning("Corrupt backup file found at %s. Moved to %s.", _BACKUP_FILE, corrupt_path)
                except Exception as exc:
                    logger.error("Failed to move corrupt backup file %s: %s", _BACKUP_FILE, exc)

        tcp = self.get_tcp_settings()
        dns_state = self._get_dns_state()
        dns = (
            dns_state.servers[0] if dns_state.servers else "",
            dns_state.servers[1] if len(dns_state.servers) > 1 else "",
        )
        mtu = self.get_current_mtu()
        multimedia_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile"
        )
        throttling_present, throttling = _read_registry_dword_snapshot(
            multimedia_path, "NetworkThrottlingIndex",
        )
        responsiveness_present, system_responsiveness = (
            _read_registry_dword_snapshot(
                multimedia_path, "SystemResponsiveness",
            )
        )

        # Check Nagle state and record the interface GUID
        nagle_disabled = False
        nagle_guid: str | None = None
        base_path = (
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        )
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as base:
                idx = 0
                while True:
                    try:
                        guid = winreg.EnumKey(base, idx)
                    except OSError:
                        break
                    idx += 1
                    try:
                        with winreg.OpenKey(base, guid) as sub:
                            for val_name in (
                                "DhcpDefaultGateway", "DefaultGateway",
                            ):
                                try:
                                    gw, _ = winreg.QueryValueEx(sub, val_name)
                                    if gw and any(g for g in gw if g):
                                        nagle_guid = guid
                                        break
                                except OSError:
                                    continue
                    except OSError:
                        continue
                    if nagle_guid:
                        break
        except OSError:
            pass

        # Preserve exact presence and values for all Nagle-related overrides.
        nagle_ack_present: Optional[bool] = None
        nagle_ack: Optional[int] = None
        nagle_no_delay_present: Optional[bool] = None
        nagle_no_delay: Optional[int] = None
        tcp_del_ack_ticks_present: Optional[bool] = None
        tcp_del_ack_ticks: Optional[int] = None
        if nagle_guid:
            iface_path = f"{base_path}\\{nagle_guid}"
            nagle_ack_present, nagle_ack = _read_registry_dword_snapshot(
                iface_path, "TcpAckFrequency",
            )
            nagle_no_delay_present, nagle_no_delay = (
                _read_registry_dword_snapshot(iface_path, "TCPNoDelay")
            )
            tcp_del_ack_ticks_present, tcp_del_ack_ticks = (
                _read_registry_dword_snapshot(iface_path, "TcpDelAckTicks")
            )
            nagle_disabled = (
                nagle_ack_present is True and nagle_ack == 1
                and nagle_no_delay_present is True and nagle_no_delay == 1
                and tcp_del_ack_ticks_present is True
                and tcp_del_ack_ticks == 0
            )

        # Check FastSendDatagramThreshold state
        afd_path = r"SYSTEM\CurrentControlSet\Services\AFD\Parameters"
        fast_send_present, fast_send_datagram_threshold = (
            _read_registry_dword_snapshot(
                afd_path, "FastSendDatagramThreshold",
            )
        )

        # Snapshot adapter settings
        adapter_backup = self._backup_adapter_settings()

        tcp_heuristics = self.get_tcp_heuristics()

        backup = BackupData(
            timestamp=datetime.now(timezone.utc).isoformat(),
            tcp_settings=tcp,
            dns_servers=dns,
            mtu=mtu,
            network_throttling=throttling,
            nagle_disabled=nagle_disabled,
            nagle_interface_guid=nagle_guid,
            adapter=adapter_backup,
            tcp_heuristics=tcp_heuristics,
            system_responsiveness=system_responsiveness,
            fast_send_datagram_threshold=fast_send_datagram_threshold,
            tcp_del_ack_ticks=tcp_del_ack_ticks,
            dns_adapter_name=(
                dns_state.adapter_name if dns_state.detected else ""
            ),
            dns_automatic=(
                dns_state.automatic if dns_state.detected else None
            ),
            dns_server_list=(
                dns_state.servers if dns_state.detected else ()
            ),
            network_throttling_present=throttling_present,
            system_responsiveness_present=responsiveness_present,
            fast_send_datagram_threshold_present=fast_send_present,
            nagle_tcp_ack_frequency=nagle_ack,
            nagle_tcp_ack_frequency_present=nagle_ack_present,
            nagle_tcp_no_delay=nagle_no_delay,
            nagle_tcp_no_delay_present=nagle_no_delay_present,
            tcp_del_ack_ticks_present=tcp_del_ack_ticks_present,
        )

        # Persist to disk
        self._save_backup(backup)
        logger.info("Created settings backup at %s", _BACKUP_FILE)
        return backup

    def _backup_adapter_settings(self) -> AdapterBackup | None:
        """Snapshot current adapter power management and interrupt moderation."""
        try:
            adapter = self.get_active_adapter()
            name = adapter.name
            if not name:
                return None

            # Power management state
            power_enabled: bool | None = None
            try:
                proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-NetAdapterPowerManagement -Name '{name}' "
                    f"-ErrorAction SilentlyContinue).AllowComputerToTurnOffDevice",
                ])
                val = proc.stdout.strip().lower()
                if val in ("enabled", "true"):
                    power_enabled = True
                elif val in ("disabled", "false", "unsupported"):
                    power_enabled = False
            except Exception:
                pass

            # Interrupt moderation state
            int_mod_enabled: bool | None = None
            try:
                proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-NetAdapterAdvancedProperty -Name '{name}' "
                    f"-RegistryKeyword '*InterruptModeration' "
                    f"-ErrorAction SilentlyContinue).RegistryValue",
                ])
                val = proc.stdout.strip()
                if val == "1":
                    int_mod_enabled = True
                elif val == "0":
                    int_mod_enabled = False
            except Exception:
                pass

            # RSC state
            rsc_enabled: bool | None = None
            try:
                proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-NetAdapterRsc -Name '{name}' -ErrorAction SilentlyContinue).IPv4Enabled",
                ])
                val = proc.stdout.strip().lower()
                if val == "true":
                    rsc_enabled = True
                elif val == "false":
                    rsc_enabled = False
            except Exception:
                pass

            # LSO state
            lso_enabled: bool | None = None
            try:
                proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-NetAdapterLso -Name '{name}' -ErrorAction SilentlyContinue).IPv4Enabled",
                ])
                val = proc.stdout.strip().lower()
                if val == "true":
                    lso_enabled = True
                elif val == "false":
                    lso_enabled = False
            except Exception:
                pass

            # EEE state
            eee_enabled: str | None = None
            try:
                proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"$p = Get-NetAdapterAdvancedProperty -Name '{name}' -ErrorAction SilentlyContinue "
                    f"| Where-Object {{ $_.RegistryKeyword -eq '*EEE' -or $_.RegistryKeyword -eq 'EEE' }}; "
                    f"if ($p) {{ $p.RegistryValue }} else {{ '' }}",
                ])
                val = proc.stdout.strip()
                if val:
                    eee_enabled = val
            except Exception:
                pass

            return AdapterBackup(
                name=name,
                power_management_enabled=power_enabled,
                interrupt_moderation_enabled=int_mod_enabled,
                rsc_enabled=rsc_enabled,
                lso_enabled=lso_enabled,
                eee_enabled=eee_enabled,
            )
        except Exception as exc:
            logger.warning("Failed to backup adapter settings: %s", exc)
            return None

    @staticmethod
    def _save_backup(backup: BackupData) -> None:
        _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        data = asdict(backup)
        # tuple -> list for JSON, will be restored on load
        data["dns_servers"] = list(data["dns_servers"])
        data["dns_server_list"] = list(data["dns_server_list"])
        tmp_file = _BACKUP_FILE.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_file, _BACKUP_FILE)
        except Exception as exc:
            if tmp_file.is_file():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass
            raise exc

    @staticmethod
    def _load_backup() -> BackupData | None:
        if not _BACKUP_FILE.is_file():
            return None
        try:
            with open(_BACKUP_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            tcp = TcpSettings(**data.pop("tcp_settings"))
            data["tcp_settings"] = tcp
            data["dns_servers"] = tuple(data["dns_servers"])
            data["dns_server_list"] = tuple(data.get("dns_server_list", ()))
            # Handle adapter sub-object
            adapter_raw = data.pop("adapter", None)
            if adapter_raw and isinstance(adapter_raw, dict):
                if "rsc_enabled" not in adapter_raw:
                    adapter_raw["rsc_enabled"] = None
                if "lso_enabled" not in adapter_raw:
                    adapter_raw["lso_enabled"] = None
                if "eee_enabled" not in adapter_raw:
                    adapter_raw["eee_enabled"] = None
                data["adapter"] = AdapterBackup(**adapter_raw)
            else:
                data["adapter"] = None
            if "tcp_heuristics" not in data:
                data["tcp_heuristics"] = "unknown"
            if "system_responsiveness" not in data:
                data["system_responsiveness"] = None
            if "fast_send_datagram_threshold" not in data:
                data["fast_send_datagram_threshold"] = None
            if "tcp_del_ack_ticks" not in data:
                data["tcp_del_ack_ticks"] = None
            for field_name, default in (
                ("dns_adapter_name", ""),
                ("dns_automatic", None),
                ("network_throttling_present", None),
                ("system_responsiveness_present", None),
                ("fast_send_datagram_threshold_present", None),
                ("nagle_tcp_ack_frequency", None),
                ("nagle_tcp_ack_frequency_present", None),
                ("nagle_tcp_no_delay", None),
                ("nagle_tcp_no_delay_present", None),
                ("tcp_del_ack_ticks_present", None),
            ):
                data.setdefault(field_name, default)
            return BackupData(**data)
        except Exception as exc:
            logger.warning("Failed to load backup: %s", exc)
            return None

    def restore_backup(self, backup: BackupData | None = None) -> list[OptimizeResult]:
        """Restore **all** settings from a backup.

        If *backup* is ``None`` the most recent on-disk backup is used.
        Every setting that was changed by :meth:`optimize_all` is reverted:
        DNS, MTU, all TCP globals, network throttling, Nagle's algorithm,
        adapter power management, and interrupt moderation.
        """
        reject_network_modification("optimizer.restore_backup")
        results: list[OptimizeResult] = []
        loaded_from_disk = backup is None

        if backup is None:
            backup = self._load_backup()
        if backup is None:
            results.append(_make_result(
                name="Restore backup", success=False,
                before="", after="",
                needs_admin=False,
                error="No backup found",
                note="Run Optimize first to create a backup",
            ))
            return results

        is_admin = self.check_admin()

        def _need_admin(name: str) -> OptimizeResult:
            return _make_result(
                name=name, success=False, before="", after="",
                needs_admin=True,
                error="Administrator privileges required",
            )

        def _restore_dword(
            *,
            name: str,
            key_path: str,
            value_name: str,
            present: Optional[bool],
            value: Optional[int],
            reboot_required: bool = False,
        ) -> OptimizeResult:
            """Restore one registry DWORD exactly and verify its presence."""
            if not is_admin:
                return _need_admin(name)
            if not isinstance(present, bool):
                return _make_result(
                    name=name, success=False, before="", after="",
                    needs_admin=True,
                    error=(
                        f"Backup does not record whether {value_name} existed; "
                        "refusing an inexact registry restore"
                    ),
                )
            safe_value = (
                _coerce_registry_dword_value(value) if present else None
            )
            if present and safe_value is None:
                return _make_result(
                    name=name, success=False, before="", after="",
                    needs_admin=True,
                    error=f"Invalid backed-up DWORD value for {value_name}",
                )

            before_present, before_value = _read_registry_dword_snapshot(
                key_path, value_name,
            )

            def _display(
                is_present: Optional[bool], current_value: Optional[int],
            ) -> str:
                if is_present is True:
                    return str(current_value)
                if is_present is False:
                    return "Not set (default)"
                return "Unreadable"

            before_display = _display(before_present, before_value)
            desired_display = str(value) if present else "Not set (default)"
            command = (
                f"Set registry {value_name} = {safe_value}"
                if present else f"Delete registry override {value_name}"
            )
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                    winreg.KEY_SET_VALUE,
                ) as key:
                    if present:
                        winreg.SetValueEx(
                            key, value_name, 0, winreg.REG_DWORD,
                            int(safe_value),
                        )
                    else:
                        try:
                            winreg.DeleteValue(key, value_name)
                        except FileNotFoundError:
                            pass
                after_present, after_value = _read_registry_dword_snapshot(
                    key_path, value_name,
                )
                verified = (
                    after_present is True and after_value == int(safe_value)
                    if present else after_present is False
                )
                after_display = _display(after_present, after_value)
                error = None
                if not verified:
                    error = (
                        f"Registry verification failed for {value_name}: "
                        f"expected {desired_display}, observed {after_display}"
                    )
                return _make_result(
                    name=name, success=verified,
                    before=before_display, after=after_display,
                    desired=desired_display,
                    needs_admin=True, error=error,
                    command=command,
                    verification=f"Registry read-back: {after_display}",
                    reboot_required=reboot_required,
                    note="Restored exact backed-up registry state" if verified else "",
                )
            except OSError as exc:
                return _make_result(
                    name=name, success=False,
                    before=before_display, after="",
                    needs_admin=True, error=str(exc), command=command,
                )

        # --- DNS ---
        dns_adapter = backup.dns_adapter_name or (
            backup.adapter.name if backup.adapter else ""
        )
        legacy_dns = tuple(server for server in backup.dns_servers if server)
        dns_servers = backup.dns_server_list or legacy_dns
        dns_metadata_present = bool(
            dns_adapter or dns_servers or backup.dns_automatic is not None
        )
        if dns_metadata_present:
            if not is_admin:
                results.append(_need_admin("Restore DNS"))
            elif not dns_adapter or _sanitize_adapter_name(dns_adapter) != dns_adapter:
                results.append(_make_result(
                    name="Restore DNS", success=False,
                    before="", after="", needs_admin=True,
                    error=(
                        "Backup does not contain a safe DNS adapter identity; "
                        "refusing to restore a different adapter"
                    ),
                ))
            elif not isinstance(backup.dns_automatic, bool):
                results.append(_make_result(
                    name="Restore DNS", success=False,
                    before="", after="", needs_admin=True,
                    error=(
                        "Backup does not record whether DNS was automatic or "
                        "static; refusing an inexact restore"
                    ),
                ))
            else:
                before_dns = self._get_dns_state(dns_adapter)
                if (
                    not before_dns.detected
                    or before_dns.adapter_name.casefold() != dns_adapter.casefold()
                ):
                    results.append(_make_result(
                        name="Restore DNS", success=False,
                        before=self._dns_state_display(before_dns), after="",
                        needs_admin=True,
                        error=(
                            f"Backed-up DNS adapter {dns_adapter!r} is not "
                            "available; no other adapter was modified"
                        ),
                    ))
                else:
                    desired_dns = DnsState(
                        adapter_name=dns_adapter,
                        servers=tuple(dns_servers),
                        automatic=backup.dns_automatic,
                        detected=True,
                    )
                    dns_outcome = self._write_dns_state(desired_dns)
                    if desired_dns.automatic:
                        desired_dns_display = "Automatic (DHCP)"
                        after_dns_display = (
                            "Automatic (DHCP)"
                            if dns_outcome.after.automatic is True
                            else self._dns_state_display(dns_outcome.after)
                        )
                    else:
                        desired_dns_display = self._dns_state_display(desired_dns)
                        after_dns_display = self._dns_state_display(
                            dns_outcome.after,
                        )
                    results.append(_make_result(
                        name="Restore DNS", success=dns_outcome.success,
                        before=self._dns_state_display(before_dns),
                        after=after_dns_display,
                        desired=desired_dns_display,
                        needs_admin=True,
                        error=dns_outcome.error,
                        command=" && ".join(
                            " ".join(command)
                            for command in dns_outcome.commands
                        ),
                        command_exit_code=dns_outcome.command_exit_code,
                        verification=dns_outcome.verification,
                        note=(
                            "Restored DNS mode and server order on the "
                            "backed-up adapter"
                            if dns_outcome.success else ""
                        ),
                    ))

        # --- MTU ---
        if is_admin:
            results.append(self.apply_mtu(backup.mtu))
        else:
            results.append(_need_admin("Restore MTU"))

        # --- All TCP global settings ---
        tcp_tweaks: list[tuple[str, list[str], str]] = [
            (
                "Restore TCP auto-tuning",
                ["netsh", "int", "tcp", "set", "global", f"autotuninglevel={backup.tcp_settings.auto_tuning_level}"],
                backup.tcp_settings.auto_tuning_level,
            ),
            (
                "Restore congestion provider",
                ["netsh", "int", "tcp", "set", "supplemental", "template=Internet", f"congestionprovider={backup.tcp_settings.congestion_provider}"],
                backup.tcp_settings.congestion_provider,
            ),
            (
                "Restore ECN",
                ["netsh", "int", "tcp", "set", "global", f"ecncapability={backup.tcp_settings.ecn_capability}"],
                backup.tcp_settings.ecn_capability,
            ),
            (
                "Restore RSS",
                ["netsh", "int", "tcp", "set", "global", f"rss={backup.tcp_settings.rss}"],
                backup.tcp_settings.rss,
            ),
            (
                "Restore DCA",
                ["netsh", "int", "tcp", "set", "global", f"dca={backup.tcp_settings.dca}"],
                backup.tcp_settings.dca,
            ),
            (
                "Restore TCP timestamps",
                ["netsh", "int", "tcp", "set", "global", f"timestamps={backup.tcp_settings.timestamps}"],
                backup.tcp_settings.timestamps,
            ),
        ]
        tcp_restore_fields = {
            "Restore TCP auto-tuning": "auto_tuning_level",
            "Restore congestion provider": "congestion_provider",
            "Restore ECN": "ecn_capability",
            "Restore RSS": "rss",
            "Restore DCA": "dca",
            "Restore TCP timestamps": "timestamps",
        }

        for label, cmd_args, value in tcp_tweaks:
            if not value or value == "unknown":
                continue
            if not is_admin:
                results.append(_need_admin(label))
                continue
            try:
                proc = _run(cmd_args)
                command_ok = proc.returncode == 0
                error = None
                if not command_ok:
                    error = proc.stderr.strip() or proc.stdout.strip()
                    error = error or f"Command exited with code {proc.returncode}"
                after_settings = self.get_tcp_settings()
                field_name = tcp_restore_fields[label]
                actual_after = getattr(after_settings, field_name, "unknown")
                verified = command_ok and _values_equal(actual_after, value)
                if command_ok and not verified:
                    error = (
                        f"Restore verification failed: expected {value}, "
                        f"observed {actual_after}"
                    )
                results.append(_make_result(
                    name=label, success=verified,
                    before="current", after=actual_after,
                    desired=value,
                    needs_admin=True, error=error,
                    command=" ".join(cmd_args),
                    command_exit_code=proc.returncode,
                    verification=f"Post-restore read: {actual_after}",
                    note="Restored to backed-up value" if verified else "",
                ))
            except Exception as exc:
                results.append(_make_result(
                    name=label, success=False,
                    before="current", after="",
                    needs_admin=True, error=str(exc),
                    command=" ".join(cmd_args),
                ))

        # --- Network throttling ---
        multimedia_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia"
            r"\SystemProfile"
        )
        throttling_present = backup.network_throttling_present
        if throttling_present is None and backup.network_throttling is not None:
            # A value in a legacy backup proves that the DWORD existed.
            throttling_present = True
        results.append(_restore_dword(
            name="Restore network throttling",
            key_path=multimedia_path,
            value_name="NetworkThrottlingIndex",
            present=throttling_present,
            value=backup.network_throttling,
        ))

        # --- Nagle's algorithm ---
        if backup.nagle_interface_guid:
            guid = backup.nagle_interface_guid
            exact_flags = (
                backup.nagle_tcp_ack_frequency_present,
                backup.nagle_tcp_no_delay_present,
                backup.tcp_del_ack_ticks_present,
            )
            if not re.fullmatch(r"\{?[0-9A-Fa-f-]{36}\}?", guid):
                results.append(_make_result(
                    name="Restore Nagle registry state", success=False,
                    before="", after="", needs_admin=True,
                    error="Invalid backed-up network interface GUID",
                ))
            elif not all(isinstance(flag, bool) for flag in exact_flags):
                results.append(_make_result(
                    name="Restore Nagle registry state", success=False,
                    before="", after="", needs_admin=True,
                    error=(
                        "Backup lacks exact presence metadata for Nagle registry "
                        "values; no values were guessed or deleted"
                    ),
                ))
            else:
                iface_path = (
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                    rf"\Interfaces\{guid}"
                )
                for result_name, value_name, present, value in (
                    (
                        "Restore Nagle TcpAckFrequency",
                        "TcpAckFrequency",
                        backup.nagle_tcp_ack_frequency_present,
                        backup.nagle_tcp_ack_frequency,
                    ),
                    (
                        "Restore Nagle TCPNoDelay",
                        "TCPNoDelay",
                        backup.nagle_tcp_no_delay_present,
                        backup.nagle_tcp_no_delay,
                    ),
                    (
                        "Restore Nagle TcpDelAckTicks",
                        "TcpDelAckTicks",
                        backup.tcp_del_ack_ticks_present,
                        backup.tcp_del_ack_ticks,
                    ),
                ):
                    results.append(_restore_dword(
                        name=result_name,
                        key_path=iface_path,
                        value_name=value_name,
                        present=present,
                        value=value,
                        reboot_required=True,
                    ))

        # --- FastSendDatagramThreshold ---
        fast_send_present = backup.fast_send_datagram_threshold_present
        if (
            fast_send_present is None
            and backup.fast_send_datagram_threshold is not None
        ):
            fast_send_present = True
        results.append(_restore_dword(
            name="Restore FastSendDatagramThreshold",
            key_path=r"SYSTEM\CurrentControlSet\Services\AFD\Parameters",
            value_name="FastSendDatagramThreshold",
            present=fast_send_present,
            value=backup.fast_send_datagram_threshold,
            reboot_required=True,
        ))

        # --- Adapter power management ---
        if backup.adapter and backup.adapter.name:
            adapter_name = _sanitize_adapter_name(backup.adapter.name)

            if backup.adapter.power_management_enabled is True:
                pm_cmd = (
                    f"Enable-NetAdapterPowerManagement "
                    f"-Name '{adapter_name}' "
                    f"-ErrorAction SilentlyContinue"
                )
                if not is_admin:
                    results.append(_need_admin("Restore adapter power management"))
                else:
                    try:
                        proc = _run([
                            "powershell", "-NoProfile", "-Command", pm_cmd,
                        ])
                        ok = proc.returncode == 0
                        results.append(_make_result(
                            name="Restore adapter power management",
                            success=ok,
                            before="Disabled", after="Enabled" if ok else "Disabled",
                            needs_admin=True,
                            error=proc.stderr.strip() or None if not ok else None,
                            command=pm_cmd,
                            command_exit_code=proc.returncode,
                            note="Restored to backed-up value" if ok else "",
                        ))
                    except Exception as exc:
                        results.append(_make_result(
                            name="Restore adapter power management",
                            success=False,
                            before="Disabled", after="",
                            needs_admin=True, error=str(exc),
                            command=pm_cmd,
                        ))

            if backup.adapter.interrupt_moderation_enabled is True:
                im_cmd = (
                    f"Set-NetAdapterAdvancedProperty "
                    f"-Name '{adapter_name}' "
                    f"-RegistryKeyword '*InterruptModeration' "
                    f"-RegistryValue 1 "
                    f"-ErrorAction SilentlyContinue"
                )
                if not is_admin:
                    results.append(_need_admin("Restore interrupt moderation"))
                else:
                    try:
                        proc = _run([
                            "powershell", "-NoProfile", "-Command", im_cmd,
                        ])
                        ok = proc.returncode == 0
                        results.append(_make_result(
                            name="Restore interrupt moderation",
                            success=ok,
                            before="Disabled", after="Enabled" if ok else "Disabled",
                            needs_admin=True,
                            error=proc.stderr.strip() or None if not ok else None,
                            command=im_cmd,
                            command_exit_code=proc.returncode,
                            note="Restored to backed-up value" if ok else "",
                        ))
                    except Exception as exc:
                        results.append(_make_result(
                            name="Restore interrupt moderation",
                            success=False,
                            before="Disabled", after="",
                            needs_admin=True, error=str(exc),
                            command=im_cmd,
                        ))

            # --- Adapter RSC Restore ---
            if getattr(backup.adapter, "rsc_enabled", None) is not None:
                rsc_cmd = (
                    f"Enable-NetAdapterRsc -Name '{adapter_name}' -IPv4 -IPv6 -ErrorAction SilentlyContinue"
                    if backup.adapter.rsc_enabled else
                    f"Disable-NetAdapterRsc -Name '{adapter_name}' -IPv4 -IPv6 -ErrorAction SilentlyContinue"
                )
                if not is_admin:
                    results.append(_need_admin("Restore RSC"))
                else:
                    try:
                        proc = _run(["powershell", "-NoProfile", "-Command", rsc_cmd])
                        ok = proc.returncode == 0
                        results.append(_make_result(
                            name="Restore RSC", success=ok,
                            before="current", after="Enabled" if backup.adapter.rsc_enabled else "Disabled",
                            needs_admin=True,
                            error=proc.stderr.strip() or None if not ok else None,
                            command=rsc_cmd,
                            command_exit_code=proc.returncode,
                        ))
                    except Exception as exc:
                        results.append(_make_result(
                            name="Restore RSC", success=False,
                            before="current", after="",
                            needs_admin=True, error=str(exc),
                            command=rsc_cmd,
                        ))

            # --- Adapter LSO Restore ---
            if getattr(backup.adapter, "lso_enabled", None) is not None:
                lso_cmd = (
                    f"Enable-NetAdapterLso -Name '{adapter_name}' -IPv4 -IPv6 -ErrorAction SilentlyContinue"
                    if backup.adapter.lso_enabled else
                    f"Disable-NetAdapterLso -Name '{adapter_name}' -IPv4 -IPv6 -ErrorAction SilentlyContinue"
                )
                if not is_admin:
                    results.append(_need_admin("Restore LSO"))
                else:
                    try:
                        proc = _run(["powershell", "-NoProfile", "-Command", lso_cmd])
                        ok = proc.returncode == 0
                        results.append(_make_result(
                            name="Restore LSO", success=ok,
                            before="current", after="Enabled" if backup.adapter.lso_enabled else "Disabled",
                            needs_admin=True,
                            error=proc.stderr.strip() or None if not ok else None,
                            command=lso_cmd,
                            command_exit_code=proc.returncode,
                        ))
                    except Exception as exc:
                        results.append(_make_result(
                            name="Restore LSO", success=False,
                            before="current", after="",
                            needs_admin=True, error=str(exc),
                            command=lso_cmd,
                        ))

            # --- Adapter EEE Restore ---
            eee_raw = getattr(backup.adapter, "eee_enabled", None)
            if eee_raw is not None:
                eee_value = _coerce_registry_dword_value(eee_raw)
                if eee_value is None:
                    results.append(_make_result(
                        name="Restore EEE", success=False,
                        before="current", after="",
                        needs_admin=True,
                        error="Invalid backed-up EEE registry value",
                        note="Skipped a tampered or corrupt backup value",
                    ))
                elif not is_admin:
                    results.append(_need_admin("Restore EEE"))
                else:
                    try:
                        kw_proc = _run([
                            "powershell", "-NoProfile", "-Command",
                            f"$p = Get-NetAdapterAdvancedProperty -Name '{adapter_name}' -ErrorAction SilentlyContinue "
                            f"| Where-Object {{ $_.RegistryKeyword -eq '*EEE' -or $_.RegistryKeyword -eq 'EEE' }}; "
                            f"if ($p) {{ $p.RegistryKeyword }} else {{ '' }}",
                        ])
                        kw = kw_proc.stdout.strip()
                        if kw:
                            eee_cmd = f"Set-NetAdapterAdvancedProperty -Name '{adapter_name}' -RegistryKeyword '{kw}' -RegistryValue {eee_value}"
                            proc = _run(["powershell", "-NoProfile", "-Command", eee_cmd])
                            ok = proc.returncode == 0
                            results.append(_make_result(
                                name="Restore EEE", success=ok,
                                before="current", after=f"Value {eee_value}",
                                needs_admin=True,
                                error=proc.stderr.strip() or None if not ok else None,
                                command=eee_cmd,
                                command_exit_code=proc.returncode,
                            ))
                        else:
                            results.append(_make_result(
                                name="Restore EEE", success=False,
                                before="current", after="",
                                needs_admin=True, error="EEE property not found on adapter",
                            ))
                    except Exception as exc:
                        results.append(_make_result(
                            name="Restore EEE", success=False,
                            before="current", after="",
                            needs_admin=True, error=str(exc),
                        ))

        # --- TCP Heuristics ---
        if backup.tcp_heuristics and backup.tcp_heuristics != "unknown":
            if not is_admin:
                results.append(_need_admin("Restore TCP heuristics"))
            else:
                cmd_args = ["netsh", "interface", "tcp", "set", "heuristics", backup.tcp_heuristics]
                try:
                    proc = _run(cmd_args)
                    ok = proc.returncode == 0
                    after = self.get_tcp_heuristics()
                    verified = after.lower() == backup.tcp_heuristics.lower()
                    results.append(_make_result(
                        name="Restore TCP heuristics", success=verified,
                        before="current", after=after,
                        desired=backup.tcp_heuristics,
                        needs_admin=True,
                        error=proc.stderr.strip() if not ok else None,
                        command=" ".join(cmd_args),
                        verification=f"Heuristics check: {after}",
                        note="Restored to backed-up value" if verified else "",
                    ))
                except Exception as exc:
                    results.append(_make_result(
                        name="Restore TCP heuristics", success=False,
                        before="current", after="",
                        needs_admin=True, error=str(exc),
                        command=" ".join(cmd_args),
                    ))

        # --- System Responsiveness ---
        responsiveness_present = backup.system_responsiveness_present
        if (
            responsiveness_present is None
            and backup.system_responsiveness is not None
        ):
            responsiveness_present = True
        results.append(_restore_dword(
            name="Restore system responsiveness",
            key_path=multimedia_path,
            value_name="SystemResponsiveness",
            present=responsiveness_present,
            value=backup.system_responsiveness,
            reboot_required=True,
        ))

        # A retryable backup is more valuable than premature cleanup.  Delete
        # it only when every attempted step both succeeded and supplied an
        # independent read-back.  Unsupported or command-only results are not
        # considered restored.
        all_succeeded = bool(results) and all(
            res.success and bool(res.verification) for res in results
        )
        if all_succeeded and loaded_from_disk and _BACKUP_FILE.is_file():
            try:
                _BACKUP_FILE.unlink()
            except Exception as exc:
                logger.warning("Failed to delete backup file after restore: %s", exc)

        return results

    # ------------------------------------------------------------------
    # Status check
    # ------------------------------------------------------------------

    def get_optimization_status(self) -> dict:
        """Return the current state of all optimisable settings."""
        tcp = self.get_tcp_settings()
        dns = self.get_current_dns()
        mtu = self.get_current_mtu()
        throttling = self.get_network_throttling_index()
        heuristics = self.get_tcp_heuristics()
        responsiveness = self.get_system_responsiveness()

        # Check current TcpDelAckTicks in active interface
        tcp_del_ack_ticks: int | None = None
        base_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as base:
                idx = 0
                while True:
                    try:
                        guid = winreg.EnumKey(base, idx)
                    except OSError:
                        break
                    idx += 1
                    try:
                        with winreg.OpenKey(base, guid) as sub:
                            for val_name in ("DhcpDefaultGateway", "DefaultGateway"):
                                try:
                                    gw, _ = winreg.QueryValueEx(sub, val_name)
                                    if gw and any(g for g in gw if g):
                                        try:
                                            ticks, _ = winreg.QueryValueEx(sub, "TcpDelAckTicks")
                                            tcp_del_ack_ticks = int(ticks)
                                        except OSError:
                                            pass
                                        break
                                except OSError:
                                    continue
                    except OSError:
                        continue
        except OSError:
            pass

        # Check current FastSendDatagramThreshold
        fast_send_datagram_threshold: int | None = None
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\AFD\Parameters", 0,
                winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "FastSendDatagramThreshold")
                fast_send_datagram_threshold = int(val)
        except OSError:
            pass

        # Check adapter settings
        rsc_disabled: bool | None = None
        lso_disabled: bool | None = None
        eee_disabled: bool | None = None

        try:
            adapter = self.get_active_adapter()
            if adapter.name:
                # Check RSC
                proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-NetAdapterRsc -Name '{adapter.name}' -ErrorAction SilentlyContinue).IPv4Enabled",
                ])
                val = proc.stdout.strip().lower()
                if val == "true":
                    rsc_disabled = False
                elif val == "false":
                    rsc_disabled = True

                # Check LSO
                proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-NetAdapterLso -Name '{adapter.name}' -ErrorAction SilentlyContinue).IPv4Enabled",
                ])
                val = proc.stdout.strip().lower()
                if val == "true":
                    lso_disabled = False
                elif val == "false":
                    lso_disabled = True

                # Check EEE
                # Find keyword first
                kw_proc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"$p = Get-NetAdapterAdvancedProperty -Name '{adapter.name}' -ErrorAction SilentlyContinue "
                    f"| Where-Object {{ $_.RegistryKeyword -eq '*EEE' -or $_.RegistryKeyword -eq 'EEE' }}; "
                    f"if ($p) {{ $p.RegistryKeyword }} else {{ '' }}",
                ])
                kw = kw_proc.stdout.strip()
                if kw:
                    val_proc = _run([
                        "powershell", "-NoProfile", "-Command",
                        f"(Get-NetAdapterAdvancedProperty -Name '{adapter.name}' -RegistryKeyword '{kw}' -ErrorAction SilentlyContinue).RegistryValue",
                    ])
                    val = val_proc.stdout.strip()
                    if val == "0":
                        eee_disabled = True
                    elif val in ("1", "2", "3"):
                        eee_disabled = False
        except Exception:
            pass

        return {
            "admin": self.check_admin(),
            "tcp": asdict(tcp),
            "dns_primary": dns[0],
            "dns_secondary": dns[1],
            "mtu": mtu,
            "network_throttling_index": throttling,
            "tcp_heuristics": heuristics,
            "system_responsiveness": responsiveness,
            "fast_send_datagram_threshold": fast_send_datagram_threshold,
            "tcp_del_ack_ticks": tcp_del_ack_ticks,
            "rsc_disabled": rsc_disabled,
            "lso_disabled": lso_disabled,
            "eee_disabled": eee_disabled,
            "backup_exists": _BACKUP_FILE.is_file(),
        }

    # ------------------------------------------------------------------
    # Full optimise
    # ------------------------------------------------------------------

    def optimize_all(
        self,
        *,
        skip_dns: bool = False,
        skip_mtu: bool = False,
        apply_dns: bool = False,
        optimize_eee: bool = False,
        optimize_rsc: bool = False,
        optimize_lso: bool = False,
    ) -> OptimizeReport:
        """Run all optimisations and return a comprehensive report.

        A backup of the current settings is created first.

        Parameters
        ----------
        skip_dns:
            If ``True``, do not benchmark or change DNS servers.
        skip_mtu:
            If ``True``, do not discover or change MTU.
        apply_dns:
            If ``True``, allow DNS server changes when benchmarks show a clear
            improvement. Defaults to ``False`` because public DNS can hurt VPN,
            split-DNS, or CDN routing setups.
        """
        reject_network_modification("optimizer.optimize_all")
        is_admin = self.check_admin()
        results: list[OptimizeResult] = []

        # --- Backup ---
        backup = self.create_backup()

        # --- DNS ---
        if not skip_dns:
            current_primary, current_secondary = self.get_current_dns()
            current_dns = [
                s for s in (current_primary, current_secondary)
                if s
            ]

            if not apply_dns:
                results.append(_make_result(
                    name="DNS optimization",
                    success=False,
                    before=", ".join(current_dns), after="",
                    needs_admin=False,
                    error="Skipped: DNS changes require explicit opt-in",
                    note=(
                        "Skipped automatic DNS switching; changing DNS can "
                        "break VPN/split-DNS or worsen CDN routing"
                    ),
                ))
            else:
                logger.info("Running DNS benchmark ...")
                servers = list(dict.fromkeys(current_dns + list(DNS_SERVERS.keys())))
                dns_results = self.benchmark_dns(servers=servers)
                reliable = [
                    r for r in dns_results
                    if r.success_rate >= 0.8 and r.avg_ms != float("inf")
                ]
                if reliable:
                    best = reliable[0]
                    current_results = [
                        r for r in reliable if r.server in set(current_dns)
                    ]
                    current_best = min(
                        current_results,
                        key=lambda r: r.avg_ms,
                        default=None,
                    )

                    clear_improvement = True
                    if current_best is not None:
                        gain_ms = current_best.avg_ms - best.avg_ms
                        required_gain = max(5.0, current_best.avg_ms * 0.15)
                        clear_improvement = gain_ms >= required_gain

                    if best.server in current_dns:
                        results.append(_make_result(
                            name="DNS optimization",
                            success=True,
                            before=", ".join(current_dns),
                            after=", ".join(current_dns),
                            desired=", ".join(current_dns),
                            needs_admin=False,
                            note="Current DNS already benchmarks fastest enough",
                        ))
                    elif not clear_improvement:
                        results.append(_make_result(
                            name="DNS optimization",
                            success=False,
                            before=", ".join(current_dns), after="",
                            needs_admin=False,
                            error="Skipped: DNS benchmark improvement was not clear",
                            note="Skipped DNS change because the measured gain was too small",
                        ))
                    else:
                        secondary = ""
                        for r in reliable:
                            if r.server != best.server and r.name != best.name:
                                secondary = r.server
                                break
                        results.append(self.apply_dns(best.server, secondary))
                else:
                    results.append(_make_result(
                        name="DNS optimization",
                        success=False,
                        before=", ".join(current_dns), after="",
                        needs_admin=False,
                        error="No reliable DNS servers found during benchmark",
                        note="All tested DNS servers had <80% success rate",
                    ))

        # --- TCP ---
        results.extend(self.optimize_tcp())
        results.append(self.optimize_winsock_datagram_threshold())

        # --- Adapter ---
        results.extend(self.optimize_adapter(include_interrupt_moderation=False))
        if optimize_eee:
            results.append(self.optimize_eee(disable=True))
        if optimize_rsc:
            results.append(self.optimize_rsc(disable=True))
        if optimize_lso:
            results.append(self.optimize_lso(disable=True))

        # --- Flush caches ---
        dns_changed = any(
            r.name == "Set DNS servers" and r.status == "Applied"
            for r in results
        )
        if dns_changed:
            results.append(self.flush_dns_cache())
        else:
            results.append(_make_result(
                name="Flush DNS cache",
                success=False,
                before="", after="",
                needs_admin=False,
                error="Skipped: DNS cache flush is only needed after DNS changes",
                note="Skipped DNS cache flush because DNS servers were not changed",
            ))

        results.append(_make_result(
            name="Flush ARP cache",
            success=False,
            before="", after="",
            needs_admin=True,
            error="Skipped: ARP cache flush is a manual repair action",
            note="Skipped ARP flush to avoid a short LAN hiccup",
        ))

        # --- Network throttling ---
        results.append(self.disable_network_throttling())

        # --- Nagle ---
        results.append(self.optimize_nagle())

        # --- TCP Heuristics ---
        results.append(self.disable_tcp_heuristics())

        # --- System Responsiveness ---
        results.append(self.apply_system_responsiveness(10))

        # --- MTU ---
        if not skip_mtu:
            logger.info("Discovering optimal MTU ...")
            optimal_mtu = self.find_optimal_mtu()
            if optimal_mtu is None:
                results.append(_make_result(
                    name="Set MTU",
                    success=False,
                    before="", after="",
                    needs_admin=False,
                    error="Skipped: MTU discovery had no successful probe",
                    note="Skipped MTU change because probe results were inconclusive",
                ))
            else:
                results.append(self.apply_mtu(optimal_mtu))

        # --- Summary ---
        total = len(results)
        applied = sum(1 for r in results if r.status == "Applied")
        verified = sum(1 for r in results if r.status == "Verified")
        no_change = sum(1 for r in results if r.status == "No change")
        skipped = sum(1 for r in results if r.status == "Skipped")
        failed = sum(1 for r in results if r.status == "Failed")
        unsupported = sum(1 for r in results if r.status == "Unsupported")
        reboot = sum(1 for r in results if r.status == "Reboot required")

        skipped_admin = sum(
            1 for r in results
            if r.status == "Skipped" and ("admin" in (r.note or "").lower() or "privilege" in (r.note or "").lower())
        )
        skipped_other = skipped - skipped_admin

        parts: list[str] = []
        if applied:
            parts.append(f"{applied} applied")
        if verified:
            parts.append(f"{verified} already optimal")
        if reboot:
            parts.append(f"{reboot} need reboot")
        if skipped_admin:
            parts.append(f"{skipped_admin} skipped (requires Administrator)")
        if skipped_other:
            parts.append(f"{skipped_other} skipped")
        if failed:
            parts.append(f"{failed} failed")
        if unsupported:
            parts.append(f"{unsupported} unsupported")
        summary = f"{total} optimisations: " + ", ".join(parts) + "." if parts else f"{total} optimisations processed."

        logger.info("Optimisation complete: %s", summary)

        return OptimizeReport(
            results=results,
            backup=backup,
            admin=is_admin,
            summary=summary,
        )
