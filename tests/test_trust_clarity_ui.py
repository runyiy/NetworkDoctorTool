import os
from datetime import datetime

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from losshound.core.config import AppConfig, DiagnosisConfig
from losshound.core.models import (
    Diagnosis,
    DiagnosisCategory,
    Observation,
    PingResult,
)


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _diagnosis(category: DiagnosisCategory, summary: str = "Network state") -> Diagnosis:
    return Diagnosis(
        timestamp=datetime.now(),
        category=category,
        summary=summary,
        explanation="Diagnostic detail",
        confidence="medium",
    )


def _observation(*, public_loss: float = 0.0, public_rtt: float = 20.0) -> Observation:
    now = datetime.now()
    return Observation(
        timestamp=now,
        gateway_ip="192.168.1.1",
        gateway_ping=PingResult(
            target="192.168.1.1",
            timestamp=now,
            packets_sent=4,
            packets_received=4,
            loss_percent=0.0,
            rtt_avg=2.0,
            rtt_jitter=0.5,
        ),
        public_pings=[
            PingResult(
                target="1.1.1.1",
                timestamp=now,
                packets_sent=4,
                packets_received=4,
                loss_percent=public_loss,
                rtt_avg=public_rtt,
                rtt_jitter=2.0,
            )
        ],
    )


def test_dashboard_starts_collecting_and_restores_truthful_state(qapp, mock_dashboard_interface):
    from losshound.gui.dashboard import DashboardTab

    dashboard = DashboardTab()
    banner = dashboard.status_panel.banner

    assert banner._level == "collecting"
    assert banner._headline.text() == "HEALTH: COLLECTING"
    assert "baseline" in banner._explanation.text().lower()

    dashboard.update_diagnosis(_diagnosis(DiagnosisCategory.HEALTHY, "Stable"))
    assert banner._level == "healthy"

    dashboard.set_monitor_state("paused", "Readings frozen")
    assert banner._level == "paused"
    assert "PAUSED" in banner._headline.text()

    dashboard.set_monitor_state("running")
    assert banner._level == "healthy"
    dashboard.shutdown()


def test_dashboard_labels_and_configured_loss_threshold(qapp, mock_dashboard_interface):
    from losshound.gui.dashboard import DashboardTab

    config = AppConfig(
        diagnosis=DiagnosisConfig(
            public_loss_threshold=20.0,
            latency_warning_ms=150.0,
        )
    )
    dashboard = DashboardTab(config)

    assert dashboard.public_target_card._title == "PUBLIC TARGET"
    assert dashboard.packet_loss_card._title == "PACKET LOSS"
    assert dashboard.latency_card._sub_columns == ("MIN", "AVG", "MAX")
    assert dashboard.jitter_card._sub_columns == ("MIN", "AVG", "MAX")
    assert "Session" in dashboard.system_panel.rows

    dashboard.update_observation(_observation(public_loss=10.0))
    assert dashboard.public_target_card._sub_values[1].property("status") == "healthy"

    strict = AppConfig(
        diagnosis=DiagnosisConfig(
            public_loss_threshold=5.0,
            latency_warning_ms=150.0,
        )
    )
    dashboard.update_config(strict)
    dashboard.update_observation(_observation(public_loss=10.0))
    assert dashboard.public_target_card._sub_values[1].property("status") == "error"
    dashboard.shutdown()


def test_alerts_exclude_routine_health_and_dedupe_repeats(qapp, mock_dashboard_interface):
    from losshound.gui.dashboard import DashboardTab

    dashboard = DashboardTab()
    dashboard.update_diagnosis(_diagnosis(DiagnosisCategory.HEALTHY, "Stable"))
    assert dashboard.alerts_panel._rows == []
    assert dashboard.events_panel._table.rowCount() == 1

    issue = _diagnosis(DiagnosisCategory.DNS_ISSUE, "Resolver failures")
    dashboard.update_diagnosis(issue)
    dashboard.update_diagnosis(issue)
    assert len(dashboard.alerts_panel._rows) == 1

    dashboard.update_diagnosis(_diagnosis(DiagnosisCategory.HEALTHY, "Recovered"))
    dashboard.update_diagnosis(issue)
    assert len(dashboard.alerts_panel._rows) == 2
    dashboard.shutdown()


def test_header_actions_follow_pause_state_and_remain_accessible(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from losshound.gui.widgets import LosshoundHeader

    header = LosshoundHeader()
    header.show()
    calls = []
    header.run_now_clicked.connect(lambda: calls.append("run"))
    header.pause_clicked.connect(lambda: calls.append("pause"))
    assert header._run_btn.text() == "Run check"
    assert header._pause_btn.text() == "Pause monitor"
    assert header._pause_btn.accessibleName() == "Pause monitoring"
    QTest.mouseClick(header._run_btn, Qt.MouseButton.LeftButton)
    QTest.mouseClick(header._pause_btn, Qt.MouseButton.LeftButton)
    assert calls == ["run", "pause"]

    header.set_paused(True)
    assert header._pause_btn.text() == "Resume monitor"
    assert header._pause_btn.accessibleName() == "Resume monitoring"
    assert not header._run_btn.isEnabled()
    QTest.mouseClick(header._run_btn, Qt.MouseButton.LeftButton)
    assert calls == ["run", "pause"]
    header._pause_btn.setFocus()
    QTest.keyClick(header._pause_btn, Qt.Key.Key_Space)
    assert calls == ["run", "pause", "pause"]

    header.set_paused(False)
    assert header._run_btn.isEnabled()
    assert header._pause_btn.accessibleName() == "Pause monitoring"
    QTest.mouseClick(header._run_btn, Qt.MouseButton.LeftButton)
    assert calls[-1] == "run"
    header.close()


def test_all_tabs_fit_or_scroll_at_minimum_width(qapp):
    from losshound.gui.painted import LosshoundTabBar

    tabs = LosshoundTabBar()
    names = [
        "Dashboard", "History", "Routes", "Optimizer", "QoS", "Score",
        "WiFi", "LAN Monitor", "Drops", "Settings", "Export",
    ]
    for name in names:
        tabs.addTab(name)

    total_hint = sum(tabs.tabSizeHint(i).width() for i in range(tabs.count()))
    assert total_hint <= 1200
    assert tabs.usesScrollButtons()
    assert tabs.accessibleName() == "Primary navigation"


def test_resume_caption_fits_after_parent_styles_are_applied(qapp):
    from PySide6.QtWidgets import QStyle, QStyleOptionButton, QVBoxLayout, QWidget
    from losshound.gui.theme import get_dark_stylesheet
    from losshound.gui.widgets import LosshoundHeader

    # Production applies QSS to MainWindow, then reparents the new header.
    window = QWidget()
    window.setStyleSheet(get_dark_stylesheet())
    header = LosshoundHeader()
    QVBoxLayout(window).addWidget(header)
    window.resize(1200, 120)
    window.show()
    widths = []
    try:
        for paused in (False, True, False):
            header.set_paused(paused)
            button = header._pause_btn
            button.setFocus()
            qapp.processEvents()
            option = QStyleOptionButton()
            button.initStyleOption(option)
            contents = button.style().subElementRect(
                QStyle.SubElement.SE_PushButtonContents, option, button,
            )
            assert contents.width() >= button.fontMetrics().horizontalAdvance(button.text())
            widths.append(button.width())
        assert len(set(widths)) == 1
    finally:
        window.close()


def test_focus_styles_cover_primary_keyboard_controls():
    from losshound.gui.theme import get_dark_stylesheet

    stylesheet = get_dark_stylesheet()
    assert "QPushButton:focus" in stylesheet
    assert "QComboBox:focus" in stylesheet
    assert "QCheckBox:focus" in stylesheet
    assert "QTableWidget:focus" in stylesheet


def test_tray_uses_configured_thresholds(qapp):
    from losshound.gui.tray import TrayIcon

    relaxed = AppConfig(
        diagnosis=DiagnosisConfig(
            public_loss_threshold=20.0,
            latency_warning_ms=150.0,
        )
    )
    tray = TrayIcon(config=relaxed)
    observation = _observation(public_loss=10.0)
    tray.update_observation(observation)
    assert tray._last_status == "healthy"

    strict = AppConfig(
        diagnosis=DiagnosisConfig(
            public_loss_threshold=5.0,
            latency_warning_ms=150.0,
        )
    )
    tray.update_config(strict)
    tray.update_observation(observation)
    assert tray._last_status == "error"


def test_countdown_marks_running_data_stale(monkeypatch):
    import losshound.gui.main_window as main_window

    class Recorder:
        def __init__(self):
            self.states = []
            self.messages = []

        def set_countdown(self, value):
            self.countdown = value

        def set_monitor_state(self, state, *args):
            self.states.append((state, *args))

        def set_status_text(self, text):
            self.messages.append(text)

    class Harness:
        _paused = False
        _seconds_until_next = 1
        _current_interval = 10
        _last_observation_monotonic = 10.0
        _monitor_ui_state = "running"
        _status_bar = Recorder()
        _dashboard = Recorder()
        _tray = Recorder()

    monkeypatch.setattr(main_window.time, "monotonic", lambda: 40.0)
    harness = Harness()
    main_window.MainWindow._tick_countdown(harness)

    assert harness._monitor_ui_state == "stale"
    assert harness._status_bar.states[-1][0] == "stale"
    assert harness._dashboard.states[-1][0] == "stale"
    assert harness._tray.states[-1][0] == "stale"
