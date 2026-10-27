import json
import tempfile
import unittest
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


class PackagedConfigTests(unittest.TestCase):
    def test_frozen_default_comes_from_bundle_before_working_directory(self):
        from unittest import mock
        import sys
        from losshound.core import config as module

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / 'bundle'
            cwd = root / 'cwd'
            bundle.mkdir()
            cwd.mkdir()
            (bundle / 'config.default.json').write_text(
                json.dumps({'public_ping_targets': ['192.0.2.10']}), encoding='utf-8')
            (cwd / 'config.default.json').write_text(
                json.dumps({'public_ping_targets': ['192.0.2.20']}), encoding='utf-8')
            with mock.patch.object(sys, '_MEIPASS', str(bundle), create=True), \
                 mock.patch.object(sys, 'frozen', True, create=True), \
                 mock.patch.object(module, '__file__', str(bundle / 'losshound' / 'core' / 'config.py')), \
                 mock.patch.object(module.Path, 'cwd', return_value=cwd), \
                 mock.patch.object(module, '_app_data_dir', return_value=root / 'user'):
                self.assertEqual(module._find_default_config(), bundle / 'config.default.json')
                self.assertEqual(module.load_config().public_ping_targets, ['192.0.2.10'])

    def test_source_default_path_and_explicit_user_override_are_preserved(self):
        from unittest import mock
        import sys
        from losshound.core import config as module

        source_default = Path(module.__file__).resolve().parents[3] / 'config.default.json'
        with mock.patch.object(sys, '_MEIPASS', None, create=True):
            self.assertEqual(module._find_default_config(), source_default)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            explicit = root / 'chosen.json'
            explicit.write_text(json.dumps({'public_ping_targets': ['192.0.2.30']}), encoding='utf-8')
            with mock.patch.object(sys, '_MEIPASS', str(root / 'bundle'), create=True), \
                 mock.patch.object(module, '_find_default_config', side_effect=AssertionError('Explicit config must win')):
                self.assertEqual(module.load_config(str(explicit)).public_ping_targets, ['192.0.2.30'])


class ConfigLogPrivacyTests(unittest.TestCase):
    def test_config_status_logs_do_not_include_private_source_path(self):
        from losshound.core import config as module

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'synthetic-private-config-name.json'
            for content in ('{}', '[]', '{'):
                with self.subTest(content=content):
                    source.write_text(content, encoding='utf-8')
                    with self.assertLogs(module.logger, level='INFO') as logs:
                        self.assertEqual(module.load_config(str(source)), AppConfig())
                    public = '\n'.join(logs.output)
                    self.assertNotIn(str(source), public)
                    self.assertNotIn(source.name, public)

    def test_config_read_error_logs_category_without_arbitrary_exception_text(self):
        from unittest import mock
        from losshound.core import config as module

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'synthetic-private-config-name.json'
            source.write_text('{}', encoding='utf-8')
            with mock.patch('builtins.open', side_effect=OSError('synthetic-private-error-detail')), \
                 self.assertLogs(module.logger, level='WARNING') as logs:
                self.assertEqual(module.load_config(str(source)), AppConfig())
            public = '\n'.join(logs.output)
            self.assertIn('OSError', public)
            self.assertNotIn(str(source), public)
            self.assertNotIn('synthetic-private-error-detail', public)
