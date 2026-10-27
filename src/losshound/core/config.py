from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILENAME = "config.default.json"
USER_CONFIG_FILENAME = "config.json"


def _app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    path = Path(base) / "Losshound"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class DiagnosisConfig:
    gateway_loss_threshold: float = 20.0
    public_loss_threshold: float = 20.0
    dns_failure_threshold: float = 0.5
    latency_warning_ms: float = 150.0
    jitter_warning_ms: float = 50.0
    route_change_sensitivity: int = 3
    timeout_burst_threshold: int = 3
    min_observations: int = 3
    window_minutes: int = 10


@dataclass
class AlertsConfig:
    """Tray-alert engine configuration."""
    enabled: bool = True
    categories: list[str] = field(default_factory=lambda: [
        "lan_issue", "isp_wan_issue", "dns_issue",
        "intermittent", "upstream_route_issue",
    ])
    min_duration_seconds: int = 30
    snooze_seconds: int = 600
    debounce_seconds: int = 60
    discord_webhook_url: Optional[str] = None
    generic_webhook_url: Optional[str] = None


@dataclass
class AppConfig:
    ping_interval_seconds: int = 30
    dns_interval_seconds: int = 60
    route_interval_seconds: int = 300
    history_retention_hours: int = 24
    public_ping_targets: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    dns_test_hostnames: list[str] = field(default_factory=lambda: ["google.com", "chatgpt.com"])
    tracert_target: str = "8.8.8.8"
    tracert_max_hops: int = 20
    ping_count: int = 4
    ping_timeout_ms: int = 2000
    auto_benchmark_interval_minutes: int = 0
    close_to_tray: bool = False
    pdf_default_dir: Optional[str] = None
    # Legacy preference retained for config compatibility; ignored by S1.
    # Previously requested a Windows Firewall rule (UDP inbound on
    # 5353/5355/1900/137, scoped to this exe only) so multicast LAN-discovery
    # responses are not dropped on Public network profiles.
    # S1 never reconciles this preference or changes Windows Firewall state.
    lan_discovery_firewall_enabled: bool = False
    lan_http_scan_enabled: bool = False
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    diagnosis: DiagnosisConfig = field(default_factory=DiagnosisConfig)
    log_level: str = "INFO"

    def to_dict(self) -> dict:
        return asdict(self)


_ALERT_CATEGORIES = {
    "lan_issue",
    "isp_wan_issue",
    "dns_issue",
    "intermittent",
    "upstream_route_issue",
}
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}


def _value(
    data: dict,
    name: str,
    default,
    predicate,
    *,
    transform=None,
):
    """Return a validated config value, otherwise the supplied default."""
    if name not in data:
        return default
    candidate = data[name]
    if predicate(candidate):
        return transform(candidate) if transform else candidate
    logger.warning("Ignoring invalid config value for %s", name)
    return default


def _is_int(value, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _is_number(value, minimum: float, maximum: float) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and minimum <= float(value) <= maximum
    )


def _valid_targets(value) -> bool:
    if not isinstance(value, list) or not value:
        return False
    from losshound.core.validation import validate_target

    return all(isinstance(item, str) and validate_target(item) for item in value)


def _sanitize_diagnosis(raw) -> DiagnosisConfig:
    defaults = DiagnosisConfig()
    if not isinstance(raw, dict):
        if raw is not None:
            logger.warning("Ignoring invalid diagnosis config: expected an object")
        raw = {}
    return DiagnosisConfig(
        gateway_loss_threshold=_value(
            raw, "gateway_loss_threshold", defaults.gateway_loss_threshold,
            lambda v: _is_number(v, 0.0, 100.0), transform=float,
        ),
        public_loss_threshold=_value(
            raw, "public_loss_threshold", defaults.public_loss_threshold,
            lambda v: _is_number(v, 0.0, 100.0), transform=float,
        ),
        dns_failure_threshold=_value(
            raw, "dns_failure_threshold", defaults.dns_failure_threshold,
            lambda v: _is_number(v, 0.0, 1.0), transform=float,
        ),
        latency_warning_ms=_value(
            raw, "latency_warning_ms", defaults.latency_warning_ms,
            lambda v: _is_number(v, 1.0, 60_000.0), transform=float,
        ),
        jitter_warning_ms=_value(
            raw, "jitter_warning_ms", defaults.jitter_warning_ms,
            lambda v: _is_number(v, 0.0, 10_000.0), transform=float,
        ),
        route_change_sensitivity=_value(
            raw, "route_change_sensitivity", defaults.route_change_sensitivity,
            lambda v: _is_int(v, 1, 255),
        ),
        timeout_burst_threshold=_value(
            raw, "timeout_burst_threshold", defaults.timeout_burst_threshold,
            lambda v: _is_int(v, 1, 100),
        ),
        min_observations=_value(
            raw, "min_observations", defaults.min_observations,
            lambda v: _is_int(v, 1, 1_000),
        ),
        window_minutes=_value(
            raw, "window_minutes", defaults.window_minutes,
            lambda v: _is_int(v, 1, 1_440),
        ),
    )


def _sanitize_alerts(raw) -> AlertsConfig:
    defaults = AlertsConfig()
    if not isinstance(raw, dict):
        if raw is not None:
            logger.warning("Ignoring invalid alerts config: expected an object")
        raw = {}

    categories = _value(
        raw,
        "categories",
        list(defaults.categories),
        lambda v: isinstance(v, list)
        and all(isinstance(item, str) and item in _ALERT_CATEGORIES for item in v),
        transform=list,
    )
    optional_string = lambda v: v is None or isinstance(v, str)
    return AlertsConfig(
        enabled=_value(raw, "enabled", defaults.enabled, lambda v: isinstance(v, bool)),
        categories=categories,
        min_duration_seconds=_value(
            raw, "min_duration_seconds", defaults.min_duration_seconds,
            lambda v: _is_int(v, 0, 86_400),
        ),
        snooze_seconds=_value(
            raw, "snooze_seconds", defaults.snooze_seconds,
            lambda v: _is_int(v, 0, 604_800),
        ),
        debounce_seconds=_value(
            raw, "debounce_seconds", defaults.debounce_seconds,
            lambda v: _is_int(v, 0, 86_400),
        ),
        discord_webhook_url=_value(
            raw, "discord_webhook_url", defaults.discord_webhook_url, optional_string,
        ),
        generic_webhook_url=_value(
            raw, "generic_webhook_url", defaults.generic_webhook_url, optional_string,
        ),
    )


def _sanitize_config(data: dict) -> AppConfig:
    defaults = AppConfig()
    optional_string = lambda v: v is None or isinstance(v, str)
    return AppConfig(
        ping_interval_seconds=_value(
            data, "ping_interval_seconds", defaults.ping_interval_seconds,
            lambda v: _is_int(v, 5, 600),
        ),
        dns_interval_seconds=_value(
            data, "dns_interval_seconds", defaults.dns_interval_seconds,
            lambda v: _is_int(v, 10, 3_600),
        ),
        route_interval_seconds=_value(
            data, "route_interval_seconds", defaults.route_interval_seconds,
            lambda v: _is_int(v, 30, 86_400),
        ),
        history_retention_hours=_value(
            data, "history_retention_hours", defaults.history_retention_hours,
            lambda v: _is_int(v, 1, 8_760),
        ),
        public_ping_targets=_value(
            data, "public_ping_targets", list(defaults.public_ping_targets),
            _valid_targets, transform=list,
        ),
        dns_test_hostnames=_value(
            data, "dns_test_hostnames", list(defaults.dns_test_hostnames),
            _valid_targets, transform=list,
        ),
        tracert_target=_value(
            data, "tracert_target", defaults.tracert_target,
            lambda v: isinstance(v, str) and _valid_targets([v]),
        ),
        tracert_max_hops=_value(
            data, "tracert_max_hops", defaults.tracert_max_hops,
            lambda v: _is_int(v, 1, 255),
        ),
        ping_count=_value(
            data, "ping_count", defaults.ping_count,
            lambda v: _is_int(v, 1, 100),
        ),
        ping_timeout_ms=_value(
            data, "ping_timeout_ms", defaults.ping_timeout_ms,
            lambda v: _is_int(v, 100, 60_000),
        ),
        auto_benchmark_interval_minutes=_value(
            data, "auto_benchmark_interval_minutes",
            defaults.auto_benchmark_interval_minutes,
            lambda v: _is_int(v, 0, 525_600),
        ),
        close_to_tray=_value(
            data, "close_to_tray", defaults.close_to_tray,
            lambda v: isinstance(v, bool),
        ),
        pdf_default_dir=_value(
            data, "pdf_default_dir", defaults.pdf_default_dir, optional_string,
        ),
        lan_discovery_firewall_enabled=_value(
            data, "lan_discovery_firewall_enabled",
            defaults.lan_discovery_firewall_enabled,
            lambda v: isinstance(v, bool),
        ),
        lan_http_scan_enabled=_value(
            data, "lan_http_scan_enabled", defaults.lan_http_scan_enabled,
            lambda v: isinstance(v, bool),
        ),
        alerts=_sanitize_alerts(data.get("alerts")),
        diagnosis=_sanitize_diagnosis(data.get("diagnosis")),
        log_level=_value(
            data, "log_level", defaults.log_level,
            lambda v: isinstance(v, str) and v.upper() in _LOG_LEVELS,
            transform=str.upper,
        ),
    )


def _find_default_config() -> Optional[Path]:
    """Prefer the bundled/source default before the working-directory fallback."""
    bundle_root = getattr(sys, "_MEIPASS", None)
    root = Path(bundle_root) if bundle_root is not None else Path(__file__).resolve().parents[3]
    candidates = [root / DEFAULT_CONFIG_FILENAME, Path.cwd() / DEFAULT_CONFIG_FILENAME]
    for p in candidates:
        if p.is_file():
            return p
    return None


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from file, falling back to defaults."""
    data = {}

    if config_path and Path(config_path).is_file():
        source = Path(config_path)
    else:
        user_config = _app_data_dir() / USER_CONFIG_FILENAME
        if user_config.is_file():
            source = user_config
        else:
            source = _find_default_config()

    if source:
        try:
            with open(source, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data = loaded
            else:
                logger.warning("Ignoring config: root must be a JSON object")
            logger.info("Loaded config")
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load config: %s", type(exc).__name__)

    return _sanitize_config(data)


def save_config(config: AppConfig, config_path: Optional[str] = None) -> Path:
    """Save configuration to file."""
    if config_path:
        dest = Path(config_path)
    else:
        dest = _app_data_dir() / USER_CONFIG_FILENAME

    dest.parent.mkdir(parents=True, exist_ok=True)
    # Write beside the destination and replace atomically so a crash cannot
    # leave a half-written configuration file behind.
    temp_dest = dest.with_name(f"{dest.name}.tmp")
    try:
        with open(temp_dest, "w", encoding="utf-8") as f:
            json.dump(config.to_dict(), f, indent=4)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_dest, dest)
    finally:
        try:
            temp_dest.unlink(missing_ok=True)
        except OSError:
            logger.debug("Could not remove temporary config file %s", temp_dest)
    logger.info("Saved config to %s", dest)
    return dest
