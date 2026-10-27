"""Manage the Windows Firewall rule required for LAN device discovery.

We need inbound UDP responses on the well-known discovery ports (mDNS, LLMNR,
SSDP, NetBIOS) for our LAN scan to receive friendly device names. On Public
network profiles Windows blocks these by default for any unprivileged
executable, which is why a Losshound LAN scan returns mostly vendor-fallback
names without this rule in place.

The rule we create is intentionally narrow:
  - Scoped to *this single executable* (Program filter), not "all of Python"
  - UDP only, inbound only
  - Specific ports: 5353 (mDNS), 5355 (LLMNR), 1900 (SSDP), 137 (NetBIOS-NS)

It is created only when the app is already running with administrator
privileges (the run_as_admin.bat launcher handles elevation). If the user
re-installs Losshound to a different path, the old rule is replaced.
"""
from __future__ import annotations

import logging
import subprocess
import sys

from losshound.core.read_only_policy import reject_network_modification
from losshound.core.windows_commands import windows_command

logger = logging.getLogger(__name__)

_RULE_NAME = "Losshound-LAN-Discovery-UDP"
_RULE_DISPLAY_NAME = "Losshound LAN Discovery"
_RULE_GROUP = "Losshound"
_DISCOVERY_PORTS = "5353,5355,1900,137"  # mDNS, LLMNR, SSDP, NetBIOS-NS


def _is_running_as_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _current_executable() -> str:
    """Return the packaged Losshound executable, never a shared Python host.

    A firewall rule scoped to ``python.exe`` would also apply to every other
    script launched by that interpreter. Source checkouts therefore refuse to
    create the rule; only a frozen Losshound build has a safely unique program
    identity.
    """
    if not getattr(sys, "frozen", False):
        return ""
    return sys.executable or ""


def _run_powershell(script: str, timeout: float = 15.0) -> tuple[int, str, str]:
    reject_network_modification("firewall._run_powershell")
    creationflags = 0
    if sys.platform == "win32":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(
        windows_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]),
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=creationflags,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def ensure_lan_discovery_firewall_rules() -> bool:
    """Idempotently ensure the LAN-discovery firewall rule exists for this executable.

    Returns True if the rule is in place (created or already present), False if
    we couldn't or wouldn't set it up (not Windows, not admin, PowerShell error).
    """
    reject_network_modification("firewall.ensure_lan_discovery_firewall_rules")
    if sys.platform != "win32":
        return False

    if not _is_running_as_admin():
        logger.info(
            "Skipping firewall rule setup: not running as administrator. "
            "Multicast LAN-discovery responses may be dropped on Public networks."
        )
        return False

    exe = _current_executable()
    if not exe:
        logger.warning(
            "Skipping firewall setup: a packaged Losshound executable is required "
            "so the rule is never scoped to a shared Python interpreter"
        )
        return False

    # Read the program filter currently associated with our named rule (if any).
    check_script = (
        f"$r = Get-NetFirewallRule -Name '{_RULE_NAME}' -ErrorAction SilentlyContinue; "
        f"if ($r) {{ "
        f"  $app = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue; "
        f"  if ($app) {{ $app.Program }} "
        f"}}"
    )
    try:
        code, out, _ = _run_powershell(check_script)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Firewall rule check failed: %s", exc)
        return False

    existing_program = out if code == 0 else ""
    if existing_program and existing_program.lower() == exe.lower():
        logger.debug("Firewall rule '%s' already exists for %s", _RULE_NAME, exe)
        return True

    if existing_program:
        logger.info(
            "Replacing stale Losshound firewall rule (was for %r, now %r)",
            existing_program, exe,
        )
        try:
            _run_powershell(
                f"Remove-NetFirewallRule -Name '{_RULE_NAME}' -ErrorAction SilentlyContinue"
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Failed to remove stale firewall rule: %s", exc)
            return False

    # PowerShell single-quote literal: embedded ' is escaped as ''
    escaped_exe = exe.replace("'", "''")
    create_script = (
        f"New-NetFirewallRule "
        f"-Name '{_RULE_NAME}' "
        f"-DisplayName '{_RULE_DISPLAY_NAME}' "
        f"-Group '{_RULE_GROUP}' "
        f"-Direction Inbound "
        f"-Action Allow "
        f"-Protocol UDP "
        f"-LocalPort {_DISCOVERY_PORTS} "
        f"-Program '{escaped_exe}' "
        f"-Profile Any "
        f"-Description 'Allows Losshound to receive mDNS/LLMNR/SSDP/NetBIOS responses for LAN device discovery. Scoped to one specific executable.' "
        f"-ErrorAction Stop | Out-Null"
    )
    try:
        code, out, err = _run_powershell(create_script)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Firewall rule creation failed: %s", exc)
        return False

    if code == 0:
        logger.info("Created firewall rule %r scoped to %s", _RULE_DISPLAY_NAME, exe)
        return True

    logger.warning(
        "Failed to create firewall rule %r (exit %d): %s",
        _RULE_DISPLAY_NAME, code, err or out,
    )
    return False


def remove_lan_discovery_firewall_rules() -> bool:
    """Remove the LAN-discovery firewall rule if present.

    Returns True if the rule is no longer there (removed or never existed),
    False on failure or insufficient privileges. Safe to call repeatedly.
    """
    reject_network_modification("firewall.remove_lan_discovery_firewall_rules")
    if sys.platform != "win32":
        return False

    if not _is_running_as_admin():
        logger.info("Skipping firewall rule removal: not running as administrator.")
        return False

    # Remove-NetFirewallRule with -ErrorAction SilentlyContinue exits 0 even when
    # the rule doesn't exist, which is exactly the idempotent behavior we want.
    try:
        code, out, err = _run_powershell(
            f"Remove-NetFirewallRule -Name '{_RULE_NAME}' -ErrorAction SilentlyContinue"
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Firewall rule removal failed: %s", exc)
        return False

    if code == 0:
        logger.info("Removed firewall rule %r (or it was already absent)", _RULE_DISPLAY_NAME)
        return True

    logger.warning(
        "Failed to remove firewall rule %r (exit %d): %s",
        _RULE_DISPLAY_NAME, code, err or out,
    )
    return False


def apply_firewall_preference(enabled: bool) -> bool:
    """Reconcile the firewall rule to match the user's preference.

    Called at startup with the persisted preference, and again from Settings
    whenever the user toggles the checkbox. Idempotent.
    """
    reject_network_modification("firewall.apply_firewall_preference")
    if enabled:
        return ensure_lan_discovery_firewall_rules()
    return remove_lan_discovery_firewall_rules()
