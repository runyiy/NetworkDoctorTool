from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from losshound import __version__
from losshound.gui.branding import losshound_pixmap
from losshound.gui.diagnostic_widgets import style_action
from losshound.gui.painted import (
    BracketedPanel,
    LiveDot,
    Sparkline,
)
from losshound.gui.palette import (
    FONT_CHROME_FAMILIES,
    FONT_MONO_FAMILIES,
    c,
    chrome_font,
    label_font,
    mono_font,
    qc,
)


# ---------------------------------------------------------------------------
# Top-of-window header
# ---------------------------------------------------------------------------


class MonitorToggleButton(QPushButton):
    """Reserve both captions using the final styled font, including DPI changes."""

    def sizeHint(self):
        hint = super().sizeHint()
        metrics = self.fontMetrics()
        longest = max(metrics.horizontalAdvance(text) for text in (
            "Pause monitor", "Resume monitor",
        ))
        hint.setWidth(
            hint.width() + max(0, longest - metrics.horizontalAdvance(self.text())) + 4
        )
        return hint


class LosshoundHeader(QWidget):
    """Brand rail with monitoring actions; Settings lives in page navigation."""

    pause_clicked = Signal()
    run_now_clicked = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("losshound-header")
        self.setFixedHeight(84)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)

        row = QHBoxLayout(self)
        row.setContentsMargins(24, 12, 24, 12)
        row.setSpacing(16)

        # Brand block (logo + wordmark)
        mark = QLabel(self)
        mark.setPixmap(losshound_pixmap(56))
        mark.setFixedSize(60, 60)
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(mark)

        text_stack = QVBoxLayout()
        text_stack.setContentsMargins(0, 0, 0, 0)
        text_stack.setSpacing(0)

        title = QLabel("Losshound")
        title.setStyleSheet(
            f"color: {c('text_primary')}; "
            f"font-family: {FONT_CHROME_FAMILIES}; "
            "font-size: 31px; font-weight: 700; letter-spacing: 1px;"
        )
        text_stack.addWidget(title)

        subtitle = QLabel("Network Diagnosis")
        subtitle.setStyleSheet(
            f"color: {c('info')}; "
            f"font-family: {FONT_CHROME_FAMILIES}; "
            "font-size: 11px; font-weight: 500; letter-spacing: 3px;"
        )
        subtitle.setText("NETWORK DIAGNOSIS")
        text_stack.addWidget(subtitle)
        row.addLayout(text_stack)

        row.addStretch()

        # One compact action group; no duplicate Settings shortcut.
        actions = QHBoxLayout()
        actions.setSpacing(10)
        self._pause_btn = MonitorToggleButton("Pause monitor")
        self._pause_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pause_btn.setAutoDefault(False)
        self._pause_btn.clicked.connect(self.pause_clicked.emit)
        actions.addWidget(self._pause_btn)

        self._run_btn = QPushButton("Run check")
        self._run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._run_btn.setAutoDefault(False)
        self._run_btn.setAccessibleName("Run network check")
        self._run_btn.clicked.connect(self.run_now_clicked.emit)
        actions.addWidget(self._run_btn)
        row.addLayout(actions)
        self.set_paused(False)

    def set_paused(self, paused: bool) -> None:
        self._pause_btn.setText(
            "Resume monitor" if paused else "Pause monitor"
        )
        self._pause_btn.setAccessibleName(
            "Resume monitoring" if paused else "Pause monitoring"
        )
        self._pause_btn.setToolTip(
            "Resume live monitoring"
            if paused
            else "Pause monitoring and freeze the current readings"
        )
        style_action(self._pause_btn, "primary" if paused else "default")
        style_action(self._run_btn, "default" if paused else "primary")
        self._run_btn.setEnabled(not paused)
        self._run_btn.setToolTip(
            "Resume monitoring to run a check" if paused else "Run a monitoring check now"
        )

    def paintEvent(self, event):  # type: ignore[override]
        painter = QPainter(self)
        # Paint a semi-transparent dark overlay so dots flow behind it softly
        painter.fillRect(self.rect(), QColor(2, 3, 3, 140))
        # Bottom separator line.
        pen = QPen(qc("border"))
        pen.setWidth(1)
        pen.setCosmetic(True)
        painter.setPen(pen)
        painter.drawLine(0, self.height() - 1, self.width(), self.height() - 1)


# ---------------------------------------------------------------------------
# Old TelemetryHeader — kept for other tabs that still import it.
# Recolored to use mint/info tokens; behavior unchanged.
# ---------------------------------------------------------------------------


class TelemetryHeader(QFrame):
    """Hard-edged section header used by diagnostic tool tabs."""

    def __init__(
        self,
        title: str,
        subtitle: str,
        module: str,
        state: str = "READY",
        accent: str | None = None,
        parent=None,
    ):
        super().__init__(parent)
        accent = accent or c("mint")
        self.setObjectName("telemetry-header")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(f"""
            QFrame#telemetry-header {{
                background-color: {c('bg_panel')};
                border: 1px solid {c('border')};
                border-left: 3px solid {accent};
                border-radius: 0;
            }}
            QLabel#telemetry-title {{
                color: {c('text_primary')};
                font-family: {FONT_CHROME_FAMILIES};
                font-size: 20px;
                font-weight: 600;
            }}
            QLabel#telemetry-subtitle {{
                color: {c('info')};
                font-family: {FONT_CHROME_FAMILIES};
                font-size: 11px;
                letter-spacing: 1.5px;
            }}
            QLabel#telemetry-meta {{
                color: {accent};
                font-family: {FONT_MONO_FAMILIES};
                font-size: 10px;
                font-weight: 600;
                padding: 6px 10px;
                border: 1px solid {c('border')};
                background-color: {c('bg_panel_inner')};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        copy = QVBoxLayout()
        copy.setContentsMargins(0, 0, 0, 0)
        copy.setSpacing(3)

        title_label = QLabel(title)
        title_label.setObjectName("telemetry-title")
        copy.addWidget(title_label)

        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("telemetry-subtitle")
        subtitle_label.setWordWrap(True)
        copy.addWidget(subtitle_label)
        layout.addLayout(copy, 1)

        meta = QLabel(f"MODULE  {module}\nSTATE   {state}")
        meta.setObjectName("telemetry-meta")
        meta.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(meta)


# ---------------------------------------------------------------------------
# MetricCard — hero number + sub-row, inside a BracketedPanel.
# ---------------------------------------------------------------------------


class MetricCard(BracketedPanel):
    """A metric card with a title, hero number, optional sparkline, and sub-row.

    Backwards-compatible signature: ``MetricCard(title)`` and
    ``card.set_value(text, detail, status)`` still work for existing callers,
    but new layouts can use ``set_hero``/``set_sub_columns``/``push_sample``
    for richer rendering.
    """

    STATUS_TOKEN = {
        "healthy": "mint",
        "neutral": "text_primary",
        "warning": "warn",
        "error": "error",
    }

    def __init__(
        self,
        title: str,
        sub_columns: tuple[str, ...] = ("RTT", "LOGS"),
        sparkline: bool = False,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(title=title, parent=parent)
        self.setMinimumHeight(124)
        self.setMaximumHeight(145)

        layout = self.layout()
        layout.setContentsMargins(14, 30, 14, 0)
        layout.setSpacing(0)

        # Vertical breathing space above the hero so it sits below the title.
        layout.addStretch(1)

        # Hero row
        self._hero = QLabel("--")
        self._hero.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hero.setAccessibleName(f"{title} current value")
        self._hero.setProperty("status", "collecting")
        hero_font = mono_font(38, QFont.Weight.Light)
        self._hero.setFont(hero_font)
        self._hero.setStyleSheet(
            f"color: {c('text_primary')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 40px; font-weight: 300;"
        )
        layout.addWidget(self._hero)

        # Optional sparkline trail
        self._spark: Optional[Sparkline] = None
        if sparkline:
            layout.addItem(QSpacerItem(0, 6, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed))
            self._spark = Sparkline(capacity=30, height=14)
            layout.addWidget(self._spark)

        layout.addStretch(1)

        # Sub-row: pairs of (label, value) spread evenly across the panel.
        self._sub_columns = sub_columns
        self._sub_values: list[QLabel] = []
        sub_frame = QFrame()
        sub_frame.setObjectName("metric-subframe")
        sub_frame.setStyleSheet(
            f"QFrame#metric-subframe {{"
            f"  background: transparent;"
            f"  border-top: 1px solid {c('border')};"
            f"}}"
        )
        sub_row = QHBoxLayout(sub_frame)
        sub_row.setContentsMargins(2, 8, 2, 10)
        sub_row.setSpacing(8)
        for idx, name in enumerate(sub_columns):
            if idx > 0:
                separator = QFrame()
                separator.setObjectName("metric-subseparator")
                separator.setFixedWidth(1)
                separator.setStyleSheet(
                    f"QFrame#metric-subseparator {{"
                    f"  background-color: {c('border_faint')};"
                    f"  border: none;"
                    f"}}"
                )
                sub_row.addWidget(separator)

            col = QVBoxLayout()
            col.setSpacing(2)
            col.setContentsMargins(0, 0, 0, 0)
            label = QLabel(name.upper())
            label.setStyleSheet(
                f"color: {c('info_dim')}; "
                f"font-family: {FONT_CHROME_FAMILIES}; "
                "font-size: 10px; font-weight: 600; letter-spacing: 1.8px;"
            )
            col.addWidget(label)

            value = QLabel("--")
            value.setAccessibleName(f"{title} {name}")
            value.setProperty("status", "collecting")
            value.setStyleSheet(
                f"color: {c('mint')}; "
                f"font-family: {FONT_MONO_FAMILIES}; "
                "font-size: 13px; font-weight: 500;"
            )
            self._sub_values.append(value)
            col.addWidget(value)
            sub_row.addLayout(col, 1)
        layout.addWidget(sub_frame)

    # ------------------------------------------------------------------ API
    def set_hero(self, text: str, status: str = "neutral") -> None:
        self._hero.setText(text)
        self._hero.setProperty("status", status)
        self._hero.setAccessibleDescription(f"Status: {status}")
        size = 27 if len(text) > 15 else (31 if len(text) > 11 else 36)
        self._hero.setFont(mono_font(size, QFont.Weight.Light))
        token = self.STATUS_TOKEN.get(status, "text_primary")
        self._hero.setStyleSheet(
            f"color: {c(token)}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            f"font-size: {size}px; font-weight: 300;"
        )

    def set_sub(self, idx: int, value: str, status: str = "healthy") -> None:
        if 0 <= idx < len(self._sub_values):
            token = self.STATUS_TOKEN.get(status, "mint")
            label = self._sub_values[idx]
            label.setText(value)
            label.setProperty("status", status)
            label.setAccessibleDescription(f"Status: {status}")
            label.setStyleSheet(
                f"color: {c(token)}; "
                f"font-family: {FONT_MONO_FAMILIES}; "
                "font-size: 12px; font-weight: 500;"
            )

    def push_sample(self, value: Optional[float]) -> None:
        if self._spark is not None:
            self._spark.push(value)

    # ----------------------------- Legacy compatibility ------------------
    def set_value(self, value: str, detail: str = "", status: str = "neutral") -> None:
        """Legacy single-line update. Splits *detail* on ``|`` to fill sub columns."""
        self.set_hero(value, status)
        if detail:
            parts = [p.strip() for p in detail.split("|")]
            for i, part in enumerate(parts):
                self.set_sub(i, part, status if status != "neutral" else "healthy")


# ---------------------------------------------------------------------------
# StatusBanner — used inside the StatusPanel.
# ---------------------------------------------------------------------------


class StatusBanner(QFrame):
    """Compact HEALTH banner with a coloured outline and pulsing live dot."""

    LEVELS = {
        "collecting": ("info", "HEALTH: COLLECTING", "Building a reliable baseline"),
        "healthy":    ("mint", "HEALTH: MONITORING", "Network is stable"),
        "warning":    ("warn", "HEALTH: WARN", "Anomalies detected"),
        "error":      ("error", "HEALTH: ALERT", "Connectivity issue"),
        "paused":     ("warn", "MONITOR: PAUSED", "Readings are frozen"),
        "stale":      ("warn", "DATA: STALE", "No fresh readings received"),
    }

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("status-banner")
        self.setMinimumHeight(86)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        self.setAccessibleName("Network health status")

        self._headline = QLabel("HEALTH: COLLECTING")
        self._headline.setStyleSheet(
            f"color: {c('info')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 13px; font-weight: 700; letter-spacing: 1.5px;"
        )
        layout.addWidget(self._headline)

        self._explanation = QLabel("Building a reliable baseline")
        self._explanation.setStyleSheet(
            f"color: {c('text_secondary')}; "
            f"font-family: {FONT_CHROME_FAMILIES}; "
            "font-size: 11px;"
        )
        self._explanation.setWordWrap(True)
        layout.addWidget(self._explanation)

        # Bottom row: "Monitoring..." + uptime + live dot
        bottom = QHBoxLayout()
        bottom.setContentsMargins(0, 4, 0, 0)
        bottom.setSpacing(6)

        self._uptime_label = QLabel("Monitoring…")
        self._uptime_label.setStyleSheet(
            f"color: {c('text_secondary')}; "
            f"font-family: {FONT_CHROME_FAMILIES}; "
            "font-size: 10px;"
        )
        bottom.addWidget(self._uptime_label)
        bottom.addStretch()

        self._uptime_value = QLabel("00:00:00")
        self._uptime_value.setStyleSheet(
            f"color: {c('text_primary')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 11px;"
        )
        bottom.addWidget(self._uptime_value)

        self._dot = LiveDot("mint", 8)
        bottom.addWidget(self._dot)

        layout.addLayout(bottom)

        self._level = "collecting"
        self._apply_level()

    def update_status(self, summary: str, explanation: str, category: str):
        level_map = {
            "healthy": "healthy",
            "lan_issue": "error",
            "isp_wan_issue": "error",
            "dns_issue": "warning",
            "upstream_route_issue": "warning",
            "intermittent": "warning",
            "unknown": "collecting",
        }
        level = level_map.get(category, "collecting")
        _token, _default_head, default_sub = self.LEVELS[level]
        # Headline stays anchored to the level so the panel reads as a
        # status indicator, not a rolling log. The diagnosis copy goes to
        # the subtitle.
        self.set_state(level, summary or explanation or default_sub)

    def set_state(self, level: str, message: str = "") -> None:
        """Apply a truthful monitor/diagnosis state to the banner."""
        if level not in self.LEVELS:
            level = "collecting"
        self._level = level
        _token, headline, default_sub = self.LEVELS[level]
        self._headline.setText(headline)
        self._explanation.setText(message or default_sub)
        self._apply_level()

    def set_uptime(self, text: str) -> None:
        self._uptime_value.setText(text)

    def _apply_level(self) -> None:
        token, _, _ = self.LEVELS[self._level]
        accent = c(token)
        self._headline.setStyleSheet(
            f"color: {accent}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 13px; font-weight: 700; letter-spacing: 1.5px;"
        )
        self._dot.set_color(token)
        if self._level in {"paused", "stale"}:
            self._dot.stop()
        else:
            self._dot.start()
        self.setAccessibleDescription(
            f"{self._headline.text()}. {self._explanation.text()}"
        )
        # Transparent inside, mint outline so the dashboard texture flows
        # behind the banner and only the border reads as a frame.
        self.setStyleSheet(
            f"QFrame#status-banner {{"
            f"  background: transparent;"
            f"  border: 1px solid {accent};"
            f"}}"
        )


# ---------------------------------------------------------------------------
# KeyValueRow — used inside Targets / System panels.
# ---------------------------------------------------------------------------


class KeyValueRow(QWidget):
    """One-line row: key on the left, mono value on the right, optional dot."""

    def __init__(
        self,
        key: str,
        value: str = "—",
        with_dot: bool = False,
        dot_token: str = "mint",
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 1, 0, 1)
        layout.setSpacing(8)

        self._key = QLabel(key)
        self._key.setStyleSheet(
            f"color: {c('text_secondary')}; "
            f"font-family: {FONT_CHROME_FAMILIES}; "
            "font-size: 11px;"
        )
        layout.addWidget(self._key)
        layout.addStretch()

        self._value = QLabel(value)
        self._value.setStyleSheet(
            f"color: {c('text_primary')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 11px;"
        )
        layout.addWidget(self._value)

        self._dot: Optional[LiveDot] = None
        if with_dot:
            self._dot = LiveDot(dot_token, 7)
            self._dot.setAccessibleName(f"{key} status")
            layout.addWidget(self._dot)
        self.setAccessibleName(key)
        self.setAccessibleDescription(f"{key}: {value}")

    def set_value(self, text: str) -> None:
        self._value.setText(text)
        self.setAccessibleDescription(f"{self._key.text()}: {text}")

    def set_dot(self, token: str) -> None:
        if self._dot is not None:
            self._dot.set_color(token)
            state = {
                "mint": "healthy",
                "warn": "warning",
                "error": "unreachable",
                "text_dim": "waiting for data",
            }.get(token, token.replace("_", " "))
            self._dot.setAccessibleDescription(state)
            self.setAccessibleDescription(
                f"{self._key.text()}: {self._value.text()}; status {state}"
            )


# ---------------------------------------------------------------------------
# MonitorStatusBar — bottom strip with monitoring stats.
# ---------------------------------------------------------------------------


def _footer_separator() -> QFrame:
    line = QFrame()
    line.setFixedWidth(1)
    line.setFixedHeight(22)
    line.setStyleSheet(
        f"QFrame {{ background-color: {c('border_faint')}; border: none; }}"
    )
    return line


class MonitorStatusBar(QFrame):
    """The footer status strip styled like the reference."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("monitor-statusbar")
        self.setAccessibleName("Monitoring status")
        self.setFixedHeight(32)
        self.setStyleSheet(
            f"QFrame#monitor-statusbar {{"
            f"  background-color: {c('bg_window')};"
            f"  border-top: 1px solid {c('border')};"
            f"}}"
        )

        row = QHBoxLayout(self)
        row.setContentsMargins(18, 4, 18, 4)
        row.setSpacing(14)

        # Left cluster
        self._mon_label = QLabel("Monitoring:")
        self._mon_label.setStyleSheet(
            f"color: {c('text_secondary')}; "
            f"font-family: {FONT_CHROME_FAMILIES}; "
            "font-size: 11px;"
        )
        row.addWidget(self._mon_label)

        self._mon_value = QLabel("STARTING")
        self._mon_value.setStyleSheet(
            f"color: {c('info')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 11px; font-weight: 600;"
        )
        row.addWidget(self._mon_value)

        self._mon_dot = LiveDot("info", 7)
        row.addWidget(self._mon_dot)

        row.addWidget(_footer_separator())

        self._items: dict[str, QLabel] = {}
        for key, default in [
            ("interval", "Interval: --"),
            ("targets", "Targets: --"),
            ("duration", "Duration: Continuous"),
            ("threads", "Threads: --"),
        ]:
            label = QLabel(default)
            label.setStyleSheet(
                f"color: {c('text_secondary')}; "
                f"font-family: {FONT_CHROME_FAMILIES}; "
                "font-size: 11px;"
            )
            row.addWidget(label)
            self._items[key] = label
            if key in {"targets", "threads"}:
                row.addWidget(_footer_separator())

        self._status_message = QLabel("")
        self._status_message.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self._status_message.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._status_message.setStyleSheet(
            f"color: {c('text_dim')}; "
            f"font-family: {FONT_CHROME_FAMILIES}; "
            "font-size: 10px;"
        )
        row.addWidget(self._status_message, 1)

        # Right cluster: countdown + DB + version
        self._countdown = QLabel("")
        self._countdown.setStyleSheet(
            f"color: {c('info')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 11px;"
        )
        row.addWidget(self._countdown)

        self._db_label = QLabel("DB: history.db")
        self._db_label.setStyleSheet(
            f"color: {c('text_secondary')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 11px;"
        )
        row.addWidget(self._db_label)
        row.addWidget(_footer_separator())

        self._version_label = QLabel(f"v{__version__}")
        self._version_label.setStyleSheet(
            f"color: {c('text_dim')}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 11px;"
        )
        row.addWidget(self._version_label)

    def set_monitoring(self, on: bool) -> None:
        self.set_monitor_state("running" if on else "paused")

    def set_monitor_state(self, state: str) -> None:
        label, token = {
            "running": ("ON", "mint"),
            "collecting": ("STARTING", "info"),
            "paused": ("PAUSED", "warn"),
            "error": ("ERROR", "error"),
            "stale": ("STALE", "warn"),
        }.get(state, ("STARTING", "info"))
        self._mon_value.setText(label)
        self._mon_value.setStyleSheet(
            f"color: {c(token)}; "
            f"font-family: {FONT_MONO_FAMILIES}; "
            "font-size: 11px; font-weight: 600;"
        )
        self._mon_dot.set_color(token)
        if state in {"paused", "stale"}:
            self._mon_dot.stop()
        else:
            self._mon_dot.start()
        self.setAccessibleDescription(f"Monitoring state: {label.lower()}")

    def set_interval(self, seconds: float) -> None:
        self._items["interval"].setText(f"Interval: {seconds:.1f}s")

    def set_targets(self, count: int) -> None:
        self._items["targets"].setText(f"Targets: {count}")

    def set_threads(self, count: int) -> None:
        self._items["threads"].setText(f"Threads: {count}")

    def set_countdown(self, seconds: int) -> None:
        if seconds > 0:
            self._countdown.setText(f"Next check in {seconds}s")
        else:
            self._countdown.setText("")

    def set_status_text(self, text: str) -> None:
        self._status_message.setText(text)
        self._status_message.setToolTip(text)


# ---------------------------------------------------------------------------
# Backwards-compat alias
# ---------------------------------------------------------------------------

# main_window.py still imports BrandHeader from this module today; alias so
# the old name keeps working until the import site is updated.
BrandHeader = LosshoundHeader
