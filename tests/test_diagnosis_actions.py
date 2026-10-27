import os
from datetime import datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from losshound.core.models import Diagnosis, DiagnosisCategory
from losshound.gui.main_window import _dashboard_actions_for_diagnosis


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _diag(category: DiagnosisCategory) -> Diagnosis:
    return Diagnosis(
        timestamp=datetime.now(),
        category=category,
        summary="summary",
        explanation="explanation",
        confidence="medium",
    )


def test_dns_issue_offers_dns_benchmark_action():
    actions = _dashboard_actions_for_diagnosis(_diag(DiagnosisCategory.DNS_ISSUE))
    assert [action["key"] for action in actions] == ["dns_benchmark"]


def test_lan_or_intermittent_offers_wifi_channel_action():
    lan_actions = _dashboard_actions_for_diagnosis(_diag(DiagnosisCategory.LAN_ISSUE))
    intermittent_actions = _dashboard_actions_for_diagnosis(
        _diag(DiagnosisCategory.INTERMITTENT)
    )

    assert [action["key"] for action in lan_actions] == ["wifi_channel"]
    assert [action["key"] for action in intermittent_actions] == ["wifi_channel"]


def test_bad_bufferbloat_grade_offers_qos_action():
    actions = _dashboard_actions_for_diagnosis(
        _diag(DiagnosisCategory.HEALTHY),
        bufferbloat_grade="F",
    )

    assert [action["key"] for action in actions] == ["open_qos"]
    assert "F" in actions[0]["detail"]


def test_dashboard_action_panel_emits_key(qapp, mock_dashboard_interface):
    from losshound.gui.dashboard import DashboardTab

    dashboard = DashboardTab()
    emitted: list[str] = []
    dashboard.diagnosis_action_requested.connect(emitted.append)
    dashboard.set_diagnosis_actions([
        {
            "key": "dns_benchmark",
            "label": "Benchmark DNS",
            "detail": "test",
            "kind": "primary",
        }
    ])

    dashboard.diagnosis_actions_panel._buttons["dns_benchmark"].click()

    assert emitted == ["dns_benchmark"]
