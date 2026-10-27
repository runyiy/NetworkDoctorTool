"""Per-application QoS (Quality of Service) policy manager for Windows.

Uses PowerShell New-NetQosPolicy / Get-NetQosPolicy / Remove-NetQosPolicy
to create DSCP-based traffic prioritization rules.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path, PureWindowsPath
from losshound.core.read_only_policy import reject_network_modification
from losshound.core.config import _app_data_dir
from losshound.core.subprocess_runner import run_subprocess_interruptible

logger = logging.getLogger(__name__)

# DSCP priority presets (higher = more priority in most routers)
PRIORITY_PRESETS = {
    "Realtime":    46,  # EF  — VoIP, gaming
    "High":        34,  # AF41 — video streaming, competitive gaming
    "Normal":      0,   # Best effort (default)
    "Low":         10,  # AF11 — background downloads, updates
    "Bulk":        8,   # CS1  — torrents, backups
}

AUTO_MITIGATION_PRESET = "Bulk"
AUTO_MITIGATION_PREFIX = "LagMitigation"

_RULE_NAME_RE = re.compile(r"^[a-zA-Z0-9_ \-]{1,64}$")
_APP_NAME_RE = re.compile(r"^[a-zA-Z0-9_ \-\.]+$")
_DSCP_MIN = 0
_DSCP_MAX = 63

PRESET_DESCRIPTIONS = {
    "Realtime": "Lowest latency — VoIP, competitive gaming, remote desktop",
    "High": "Prioritized — video calls, streaming, important apps",
    "Normal": "Default best-effort — web browsing, general apps",
    "Low": "Deprioritized — background downloads, auto-updates",
    "Bulk": "Lowest priority — torrents, large backups",
}


@dataclass
class _CommandResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


def _run(cmd: list[str], timeout: int = 15) -> _CommandResult:
    try:
        stdout, stderr, returncode = run_subprocess_interruptible(cmd, timeout)
        return _CommandResult(stdout=stdout, stderr=stderr, returncode=returncode)
    except subprocess.TimeoutExpired:
        return _CommandResult(
            stderr=f"Command timed out after {timeout} seconds",
            returncode=124,
        )


@dataclass
class QosRule:
    """A single QoS policy rule."""
    name: str
    app_path: str           # e.g. "chrome.exe" or full path
    priority_preset: str    # key in PRIORITY_PRESETS
    dscp_value: int
    active: bool = True
    note: str = ""


@dataclass
class QosResult:
    """Result of applying/removing a QoS rule."""
    rule_name: str
    success: bool
    action: str             # "created", "removed", "updated", "failed"
    message: str = ""


def _app_name_from_path(app_path: str) -> str:
    raw = app_path.strip()
    if "\\" in raw or "/" in raw:
        return PureWindowsPath(raw).name
    return raw


def _safe_rule_fragment(app_name: str) -> str:
    stem = PureWindowsPath(app_name).stem or app_name
    fragment = re.sub(r"[^a-zA-Z0-9_ \-]", "_", stem).strip(" _-")
    if not fragment:
        fragment = "App"
    max_len = 64 - len(AUTO_MITIGATION_PREFIX) - 1
    return fragment[:max_len]


def _coerce_dscp_value(value: object) -> int | None:
    """Return a valid DSCP integer, or None for tampered/corrupt values."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        dscp = value
    elif isinstance(value, str) and value.strip().isdigit():
        dscp = int(value.strip())
    else:
        return None
    if _DSCP_MIN <= dscp <= _DSCP_MAX:
        return dscp
    return None


def build_lag_mitigation_rule(app_path: str) -> QosRule:
    """Build the low-priority QoS rule used for lag-attribution suspects."""
    app_name = _app_name_from_path(app_path)
    fragment = _safe_rule_fragment(app_name)
    preset = AUTO_MITIGATION_PRESET
    return QosRule(
        name=f"{AUTO_MITIGATION_PREFIX}_{fragment}",
        app_path=app_name,
        priority_preset=preset,
        dscp_value=PRIORITY_PRESETS[preset],
        note="Auto-created from lag attribution",
    )


def check_admin() -> bool:
    """Check if running with admin privileges."""
    proc = _run([
        "powershell", "-NoProfile", "-Command",
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]"
        "::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    ])
    return proc.stdout.strip().lower() == "true"


def get_existing_policies() -> list[dict]:
    """List all current NetQosPolicy entries."""
    proc = _run([
        "powershell", "-NoProfile", "-Command",
        "Get-NetQosPolicy | Select-Object Name, AppPathNameMatchCondition, "
        "DSCPAction, ThrottleRateActionBitsPerSecond, PriorityValue8021Action "
        "| ConvertTo-Json -Depth 3",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        return []


def apply_rule(rule: QosRule) -> QosResult:
    """Create or update a QoS policy for an application."""
    # Validate rule name against command injection/LPE
    reject_network_modification("qos.apply_rule")
    if not _RULE_NAME_RE.match(rule.name):
        return QosResult(
            rule_name=rule.name,
            success=False,
            action="failed",
            message="Invalid rule name: only alphanumeric, spaces, hyphens, and underscores allowed",
        )

    # Extract just the exe name from full path and validate
    app_name = _app_name_from_path(rule.app_path)
    if not _APP_NAME_RE.match(app_name) or "'" in app_name or ";" in app_name:
        return QosResult(
            rule_name=rule.name,
            success=False,
            action="failed",
            message="Invalid application path or name",
        )

    dscp_value = _coerce_dscp_value(rule.dscp_value)
    if dscp_value is None:
        return QosResult(
            rule_name=rule.name,
            success=False,
            action="failed",
            message="Invalid DSCP value: must be an integer from 0 to 63",
        )

    if not check_admin():
        return QosResult(
            rule_name=rule.name,
            success=False,
            action="failed",
            message="Administrator privileges required to create QoS policies",
        )

    policy_name = f"Losshound_{rule.name}"

    # Remove existing policy with same name first
    _run([
        "powershell", "-NoProfile", "-Command",
        f"Remove-NetQosPolicy -Name '{policy_name}' -Confirm:$false "
        f"-ErrorAction SilentlyContinue",
    ])

    # Create new policy
    proc = _run([
        "powershell", "-NoProfile", "-Command",
        f"New-NetQosPolicy -Name '{policy_name}' "
        f"-AppPathNameMatchCondition '{app_name}' "
        f"-DSCPAction {dscp_value} "
        f"-PolicyStore ActiveStore "
        f"-ErrorAction Stop",
    ])

    if proc.returncode == 0:
        return QosResult(
            rule_name=rule.name,
            success=True,
            action="created",
            message=f"QoS policy applied: {app_name} -> DSCP {dscp_value} ({rule.priority_preset})",
        )
    else:
        error = proc.stderr.strip() or proc.stdout.strip()
        return QosResult(
            rule_name=rule.name,
            success=False,
            action="failed",
            message=error[:200],
        )


def remove_rule(rule_name: str) -> QosResult:
    """Remove a Losshound QoS policy."""
    reject_network_modification("qos.remove_rule")
    if not check_admin():
        return QosResult(
            rule_name=rule_name,
            success=False,
            action="failed",
            message="Administrator privileges required",
        )

    # Validate rule name against command injection/LPE
    if not _RULE_NAME_RE.match(rule_name):
        return QosResult(
            rule_name=rule_name,
            success=False,
            action="failed",
            message="Invalid rule name",
        )

    policy_name = f"Losshound_{rule_name}"
    proc = _run([
        "powershell", "-NoProfile", "-Command",
        f"Remove-NetQosPolicy -Name '{policy_name}' -Confirm:$false -ErrorAction Stop",
    ])

    if proc.returncode == 0:
        return QosResult(
            rule_name=rule_name, success=True, action="removed",
            message=f"Policy '{policy_name}' removed",
        )
    else:
        error = proc.stderr.strip() or proc.stdout.strip()
        return QosResult(
            rule_name=rule_name, success=False, action="failed",
            message=error[:200],
        )


def remove_all_losshound_policies() -> list[QosResult]:
    """Remove all QoS policies created by Losshound."""
    reject_network_modification("qos.remove_all_losshound_policies")
    policies = get_existing_policies()
    results = []
    for p in policies:
        name = p.get("Name", "")
        if name.startswith("Losshound_"):
            short_name = name[len("Losshound_"):]
            results.append(remove_rule(short_name))
    return results


# ------------------------------------------------------------------
# Persistent rule storage (JSON file)
# ------------------------------------------------------------------

_RULES_FILE = "qos_rules.json"


def _rules_path() -> Path:
    return _app_data_dir() / _RULES_FILE


def load_saved_rules() -> list[QosRule]:
    """Load saved QoS rules from disk."""
    path = _rules_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return []

        rules: list[QosRule] = []
        for r in data:
            try:
                if not isinstance(r, dict):
                    raise ValueError("rule entry must be an object")

                name = r["name"]
                app_path = r["app_path"]
                priority_preset = r["priority_preset"]
                active = r.get("active", True)
                note = r.get("note", "")

                if not isinstance(name, str) or not _RULE_NAME_RE.match(name):
                    raise ValueError("invalid rule name")
                if not isinstance(app_path, str):
                    raise ValueError("invalid application path")
                app_name = _app_name_from_path(app_path)
                if not _APP_NAME_RE.match(app_name) or "'" in app_name or ";" in app_name:
                    raise ValueError("invalid application path")
                if not isinstance(priority_preset, str) or priority_preset not in PRIORITY_PRESETS:
                    raise ValueError("invalid priority preset")
                if not isinstance(active, bool):
                    raise ValueError("invalid active flag")
                if not isinstance(note, str):
                    raise ValueError("invalid note")

                dscp_value = _coerce_dscp_value(r["dscp_value"])
                if dscp_value is None:
                    raise ValueError("invalid DSCP value")
                rules.append(
                    QosRule(
                        name=name,
                        app_path=app_path,
                        priority_preset=priority_preset,
                        dscp_value=dscp_value,
                        active=active,
                        note=note,
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Skipping invalid QoS rule: %s", exc)
        return rules
    except (json.JSONDecodeError, KeyError) as exc:
        logger.warning("Failed to load QoS rules: %s", exc)
        return []


def save_rules(rules: list[QosRule]) -> None:
    """Persist QoS rules to disk."""
    data = [asdict(r) for r in rules]
    _rules_path().write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )


def apply_all_active_rules() -> list[QosResult]:
    """Apply all saved rules that are marked active."""
    reject_network_modification("qos.apply_all_active_rules")
    rules = load_saved_rules()
    results = []
    for rule in rules:
        if rule.active:
            results.append(apply_rule(rule))
    return results
