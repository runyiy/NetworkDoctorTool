import json
import tempfile
from pathlib import Path

from losshound.core.config import AppConfig, DiagnosisConfig, load_config, save_config


def test_default_config():
    config = AppConfig()
    assert config.ping_interval_seconds == 30
    assert config.public_ping_targets == ["1.1.1.1", "8.8.8.8"]
    assert config.diagnosis.gateway_loss_threshold == 20.0
    assert config.lan_discovery_firewall_enabled is False


def test_load_config_from_file():
    data = {
        "ping_interval_seconds": 15,
        "public_ping_targets": ["9.9.9.9"],
        "diagnosis": {
            "gateway_loss_threshold": 30.0,
        },
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(data, f)
        path = f.name

    config = load_config(path)
    assert config.ping_interval_seconds == 15
    assert config.public_ping_targets == ["9.9.9.9"]
    assert config.diagnosis.gateway_loss_threshold == 30.0
    # Defaults for unspecified values
    assert config.dns_interval_seconds == 60


def test_load_config_missing_file():
    config = load_config("/nonexistent/path/config.json")
    # Should return defaults
    assert config.ping_interval_seconds == 30


def test_save_and_reload():
    config = AppConfig(ping_interval_seconds=10)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        path = f.name

    save_config(config, path)
    reloaded = load_config(path)
    assert reloaded.ping_interval_seconds == 10


def test_config_to_dict():
    config = AppConfig()
    d = config.to_dict()
    assert isinstance(d, dict)
    assert "ping_interval_seconds" in d
    assert "diagnosis" in d
    assert isinstance(d["diagnosis"], dict)


def test_load_config_rejects_non_object_root(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('["not", "an", "object"]', encoding="utf-8")

    config = load_config(str(path))

    assert config == AppConfig()


def test_load_config_ignores_invalid_types_and_ranges(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "ping_interval_seconds": -5,
        "dns_interval_seconds": "fast",
        "public_ping_targets": ["8.8.8.8 & calc.exe"],
        "route_interval_seconds": 120,
        "lan_discovery_firewall_enabled": "yes",
        "log_level": "debug",
        "diagnosis": {
            "gateway_loss_threshold": "high",
            "timeout_burst_threshold": 7,
        },
        "alerts": [],
    }), encoding="utf-8")

    config = load_config(str(path))

    assert config.ping_interval_seconds == 30
    assert config.dns_interval_seconds == 60
    assert config.public_ping_targets == ["1.1.1.1", "8.8.8.8"]
    assert config.route_interval_seconds == 120
    assert config.lan_discovery_firewall_enabled is False
    assert config.log_level == "DEBUG"
    assert config.diagnosis.gateway_loss_threshold == 20.0
    assert config.diagnosis.timeout_burst_threshold == 7
    assert config.alerts == AppConfig().alerts


def test_save_config_is_atomic_and_cleans_temp_file(tmp_path):
    path = tmp_path / "config.json"

    save_config(AppConfig(ping_interval_seconds=15), str(path))

    assert load_config(str(path)).ping_interval_seconds == 15
    assert not path.with_name("config.json.tmp").exists()
