"""Losshound's existing visual shell with the S1 read-only session entry.

Legacy continuous monitoring and mutation tabs are deliberately not imported or
constructed. Persisted legacy settings cannot enable startup modifications.
"""
from __future__ import annotations

import time

from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QMainWindow, QVBoxLayout

from losshound.core.config import AppConfig
from losshound.core.models import Diagnosis, DiagnosisCategory
from losshound.core.session_process import MAX_CLEANUP_SECONDS
from losshound.gui.branding import app_icon
from losshound.gui.painted import TexturedSurface
from losshound.gui.session_panel import SessionPanel
from losshound.gui.theme import get_dark_stylesheet
from losshound.gui.widgets import LosshoundHeader


# Retained pure mapping for historical report/presentation compatibility only.
# S1 does not display these actions or connect them to any command dispatcher.
def _dashboard_actions_for_diagnosis(
    diag: Diagnosis,
    bufferbloat_grade: str = "",
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []

    if diag.category == DiagnosisCategory.DNS_ISSUE:
        actions.append({
            "key": "dns_benchmark",
            "label": "Benchmark DNS",
            "detail": "Run DNS benchmark and suggest the fastest reliable resolver.",
            "kind": "primary",
        })

    if diag.category in (DiagnosisCategory.LAN_ISSUE, DiagnosisCategory.INTERMITTENT):
        actions.append({
            "key": "wifi_channel",
            "label": "Check WiFi Channel",
            "detail": "Scan visible WiFi networks and suggest a better channel if signal is weak.",
            "kind": "primary",
        })

    if bufferbloat_grade.upper() in ("D", "F"):
        actions.append({
            "key": "open_qos",
            "label": "Open QoS",
            "detail": f"Latest load benchmark bufferbloat grade is {bufferbloat_grade.upper()}.",
            "kind": "warning",
        })

    return actions


class MainWindow(QMainWindow):
    def __init__(self, config: AppConfig, duration_seconds: int = 60):
        super().__init__()
        self._config = config
        self._close_pending = False
        self.setWindowTitle("Losshound - Network Diagnosis")
        self.setWindowIcon(app_icon())
        self.setMinimumSize(1000, 650)
        self.resize(1200, 800)
        self.setStyleSheet(get_dark_stylesheet())

        central = TexturedSurface()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._header = LosshoundHeader()
        # These legacy monitor controls are replaced by Start/Cancel below;
        # neither continuous monitoring nor legacy settings is an S1 entry.
        self._header._pause_btn.hide()
        self._header._run_btn.hide()
        layout.addWidget(self._header)
        self._session = SessionPanel(config, duration_seconds, self)
        self._session.cleanup_finished.connect(self._on_cleanup_finished)
        layout.addWidget(self._session, 1)
        # No automatic collection, tray monitoring, database migration, status
        # workers or mutation tabs are started while constructing the window.

    def closeEvent(self, event: QCloseEvent) -> None:
        self._close_pending = True
        if not self._session.begin_shutdown():
            # The worker still owns its processes. Keep both Qt objects alive
            # until actual QThread.finished, not until a report is emitted.
            event.ignore()
            return
        event.accept()

    def _on_cleanup_finished(self) -> None:
        if self._close_pending:
            QTimer.singleShot(0, self.close)

    def shutdown_all(self) -> bool:
        # aboutToQuit cannot defer through the event loop. Cancellation is
        # cooperative; the controller's process cleanup is bounded. Failure is
        # surfaced rather than hidden by QThread.terminate().
        timeout_ms = int(MAX_CLEANUP_SECONDS * 1000) + 250
        clean = self._session.wait_for_shutdown(timeout_ms)
        if not clean:
            self._session._state.setText(
                "Cleanup has not completed; session worker is still retained."
            )
        return clean

    def _open_tab(self, target) -> None:
        """Retained read-only navigation helper for historical page widgets."""
        tabs = getattr(self, "_tabs", None)
        if tabs is not None:
            for index in range(tabs.count()):
                if tabs.widget(index) is target:
                    tabs.setCurrentIndex(index)
                    return

    def _tick_countdown(self) -> None:
        """Legacy presentation-only helper; S1 does not schedule this timer."""
        if self._paused:
            self._status_bar.set_countdown(0)
            return
        self._seconds_until_next = max(0, self._seconds_until_next - 1)
        self._status_bar.set_countdown(self._seconds_until_next)
        if self._last_observation_monotonic is not None and self._monitor_ui_state == "running":
            elapsed = time.monotonic() - self._last_observation_monotonic
            if elapsed >= max(15.0, self._current_interval * 2.5):
                self._monitor_ui_state = "stale"
                message = f"No fresh reading for {int(elapsed)} seconds"
                self._dashboard.set_monitor_state("stale", message)
                self._status_bar.set_monitor_state("stale")
                self._status_bar.set_status_text(message)
                self._tray.set_monitor_state("stale", message)
