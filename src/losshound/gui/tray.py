"""System tray icon with live network status and notifications."""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Signal
from PySide6.QtGui import QAction, QColor, QIcon, QPainter
from PySide6.QtWidgets import QMenu, QSystemTrayIcon, QWidget

from losshound.core.config import AppConfig
from losshound.core.models import Diagnosis, DiagnosisCategory, Observation
from losshound.gui.branding import losshound_pixmap

logger = logging.getLogger(__name__)


def _create_status_icon(color: str, size: int = 64) -> QIcon:
    """Create a branded tray icon with a small status bar."""
    pixmap = losshound_pixmap(size)

    painter = QPainter(pixmap)
    painter.setBrush(QColor(color))
    painter.setPen(QColor(color))
    margin = max(3, size // 10)
    height = max(4, size // 10)
    painter.drawRect(margin, size - margin - height, size - 2 * margin, height)
    painter.end()

    return QIcon(pixmap)


# Pre-built icons for each status
_ICONS = {
    "healthy":  "#75c884",  # green
    "warning":  "#d9b65f",  # yellow
    "error":    "#e06363",  # red
    "unknown":  "#788596",  # grey
}


class TrayIcon(QSystemTrayIcon):
    """System tray icon that shows network health at a glance.

    Signals
    -------
    show_requested:
        Emitted when the user clicks "Show Window" in the tray menu.
    quit_requested:
        Emitted when the user clicks "Quit" in the tray menu.
    """

    show_requested = Signal()
    quit_requested = Signal()

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        engine: "Optional[object]" = None,
        config: AppConfig | None = None,
    ):
        super().__init__(parent)
        self._last_status = "unknown"
        self._notifications_enabled = True
        self._engine = engine
        self._config = config or AppConfig()

        # Build icons
        self._status_icons = {
            key: _create_status_icon(color)
            for key, color in _ICONS.items()
        }

        self.setIcon(self._status_icons["unknown"])
        self.setToolTip("Losshound — Starting up...")

        # Context menu
        menu = QMenu()

        self._status_action = QAction("Status: starting...", menu)
        self._status_action.setEnabled(False)
        menu.addAction(self._status_action)

        menu.addSeparator()

        show_action = QAction("Show Window", menu)
        show_action.triggered.connect(self.show_requested.emit)
        menu.addAction(show_action)

        self._notif_action = QAction("Disable Notifications", menu)
        self._notif_action.triggered.connect(self._toggle_notifications)
        menu.addAction(self._notif_action)

        snooze_action = QAction("Snooze alerts", menu)
        snooze_action.triggered.connect(self._snooze_clicked)
        menu.addAction(snooze_action)

        self._recent_menu = QMenu("Recent Alerts", menu)
        self._recent_menu.aboutToShow.connect(self._refresh_recent_alerts)
        menu.addMenu(self._recent_menu)

        menu.addSeparator()

        quit_action = QAction("Quit", menu)
        quit_action.triggered.connect(self.quit_requested.emit)
        menu.addAction(quit_action)

        self.setContextMenu(menu)

        # Double-click to show
        self.activated.connect(self._on_activated)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_requested.emit()

    def _toggle_notifications(self):
        self._notifications_enabled = not self._notifications_enabled
        self._notif_action.setText(
            "Enable Notifications" if not self._notifications_enabled
            else "Disable Notifications"
        )

    def update_observation(self, obs: Observation):
        """Update tray icon and tooltip from a live observation."""
        losses: list[float] = []
        rtts: list[float] = []
        jitters: list[float] = []
        diagnosis = self._config.diagnosis
        loss_error = False

        if obs.gateway_ping:
            losses.append(obs.gateway_ping.loss_percent)
            loss_error = (
                obs.gateway_ping.timed_out
                or obs.gateway_ping.loss_percent >= diagnosis.gateway_loss_threshold
            )
            if obs.gateway_ping.rtt_avg is not None:
                rtts.append(obs.gateway_ping.rtt_avg)
            if obs.gateway_ping.rtt_jitter is not None:
                jitters.append(obs.gateway_ping.rtt_jitter)

        for p in obs.public_pings:
            losses.append(p.loss_percent)
            loss_error = loss_error or p.timed_out or (
                p.loss_percent >= diagnosis.public_loss_threshold
            )
            if p.rtt_avg is not None:
                rtts.append(p.rtt_avg)
            if p.rtt_jitter is not None:
                jitters.append(p.rtt_jitter)

        avg_loss = sum(losses) / len(losses) if losses else 0
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0
        avg_jitter = sum(jitters) / len(jitters) if jitters else 0

        dns_warning = False
        if obs.dns_results:
            failures = sum(1 for result in obs.dns_results if not result.resolved)
            dns_warning = (
                failures / len(obs.dns_results)
                >= diagnosis.dns_failure_threshold
            )

        if loss_error:
            status = "error"
        elif (
            any(rtt >= diagnosis.latency_warning_ms for rtt in rtts)
            or any(jitter >= diagnosis.jitter_warning_ms for jitter in jitters)
            or dns_warning
        ):
            status = "warning"
        elif losses:
            status = "healthy"
        else:
            status = "unknown"

        self._last_status = status
        self.setIcon(self._status_icons[status])

        # Tooltip
        loss_str = f"{avg_loss:.0f}%" if losses else "N/A"
        rtt_str = f"{avg_rtt:.0f}ms" if rtts else "N/A"
        jitter_str = f"{avg_jitter:.0f}ms" if jitters else "N/A"
        tip = (
            f"Losshound — Loss: {loss_str} | Latency: {rtt_str} | "
            f"Jitter: {jitter_str}"
        )
        self.setToolTip(tip)
        self._status_action.setText(f"Loss: {loss_str} | Latency: {rtt_str}")

    def update_config(self, config: AppConfig) -> None:
        self._config = config

    def set_monitor_state(self, state: str, detail: str = "") -> None:
        icon_state, label = {
            "collecting": ("unknown", "Collecting baseline"),
            "running": ("unknown", "Waiting for next reading"),
            "paused": ("warning", "Monitoring paused"),
            "stale": ("warning", "Data stale"),
            "error": ("error", "Monitor error"),
        }.get(state, ("unknown", "Starting"))
        self._last_status = state
        self.setIcon(self._status_icons[icon_state])
        message = detail or label
        self.setToolTip(f"Losshound — {message}")
        self._status_action.setText(f"Status: {message}")

    def show_event(self, event):
        """Render an AlertEvent as a Windows toast notification."""
        if not self._notifications_enabled:
            return

        if event.is_resolution:
            icon = QSystemTrayIcon.MessageIcon.Information
        elif event.severity == "critical":
            icon = QSystemTrayIcon.MessageIcon.Critical
        else:
            icon = QSystemTrayIcon.MessageIcon.Warning

        self.showMessage(
            f"Losshound — {event.title}",
            event.message,
            icon,
            5000,
        )

    def _snooze_clicked(self):
        if self._engine is None:
            return
        seconds = self._engine.snooze()
        minutes = max(1, round(seconds / 60))
        self.showMessage(
            "Losshound",
            f"Alerts snoozed for {minutes} minute{'s' if minutes != 1 else ''}.",
            QSystemTrayIcon.MessageIcon.Information, 2500,
        )

    def _refresh_recent_alerts(self):
        self._recent_menu.clear()
        rows = self._engine.recent_alerts(10) if self._engine is not None else []
        if not rows:
            placeholder = QAction("(no alerts)", self._recent_menu)
            placeholder.setEnabled(False)
            self._recent_menu.addAction(placeholder)
            return
        for r in rows:
            label = f"{r.timestamp[:19]} — {r.title}"
            if r.resolved_at:
                label += " ✓"
            act = QAction(label, self._recent_menu)
            act.setEnabled(False)
            self._recent_menu.addAction(act)
