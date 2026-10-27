import os

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from losshound.core.config import AppConfig, DiagnosisConfig
from losshound.gui.settings_tab import SettingsTab


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_settings_preserve_hidden_config_fields(qapp):
    config = AppConfig(
        log_level="DEBUG",
        diagnosis=DiagnosisConfig(
            dns_failure_threshold=0.35,
            timeout_burst_threshold=9,
        ),
    )
    tab = SettingsTab(config)

    rebuilt = tab._build_config()

    assert rebuilt.log_level == "DEBUG"
    assert rebuilt.diagnosis.timeout_burst_threshold == 9
    assert rebuilt.diagnosis.dns_failure_threshold == pytest.approx(0.35)


def test_dns_failure_threshold_is_presented_as_percent(qapp):
    tab = SettingsTab(
        AppConfig(diagnosis=DiagnosisConfig(dns_failure_threshold=0.5))
    )

    assert tab._dns_fail.value() == pytest.approx(50.0)
    tab._dns_fail.setValue(25.0)
    assert tab._build_config().diagnosis.dns_failure_threshold == pytest.approx(0.25)
