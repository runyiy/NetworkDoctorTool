"""WiFi Diagnostics tab — channel scan, signal analysis, interference detection."""

from __future__ import annotations

import logging
import math

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QProgressBar, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from losshound.core.wifi_diag import (
    WifiDiagReport, WifiNetwork, run_wifi_diagnostics, format_wifi_report,
)
from losshound.core.load_benchmark import (
    LoadBenchmarkSnapshot, run_load_benchmark, save_load_snapshot,
    format_load_snapshot, get_latest_load_snapshot,
)
from losshound.gui.widgets import TelemetryHeader
from losshound.gui.diagnostic_widgets import ReadingTile, compact_table, page_style, style_action

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------

class _WifiScanWorker(QThread):
    """Run WiFi diagnostics in background."""

    finished = Signal(object)  # WifiDiagReport
    progress = Signal(str)

    def run(self):
        try:
            self.progress.emit("Scanning WiFi networks...")
            report = run_wifi_diagnostics()
            self.finished.emit(report)
        except Exception as exc:
            logger.error("WiFi scan failed: %s", exc)
            self.finished.emit(None)


class _BufferbloatWorker(QThread):
    """Run bufferbloat test (load benchmark) in background."""

    finished = Signal(object)  # LoadBenchmarkSnapshot
    progress = Signal(str)

    def run(self):
        try:
            snapshot = run_load_benchmark(
                label="bufferbloat-check",
                progress_callback=lambda msg: self.progress.emit(msg),
            )
            save_load_snapshot(snapshot)
            self.finished.emit(snapshot)
        except Exception as exc:
            logger.error("Bufferbloat test failed: %s", exc)
            self.finished.emit(None)


class _LoadLastBufferbloatWorker(QThread):
    """Background worker to load the last bufferbloat snapshot on startup without blocking the GUI."""
    finished = Signal(object)

    def run(self):
        try:
            snapshot = get_latest_load_snapshot()
            self.finished.emit(snapshot)
        except Exception:
            self.finished.emit(None)


# ---------------------------------------------------------------------------
# WiFi & Bufferbloat Tab
# ---------------------------------------------------------------------------

class WifiTab(QWidget):
    """WiFi diagnostics and bufferbloat detection tab."""

    def shutdown(self):
        from losshound.gui._shutdown import stop_qthread
        stop_qthread(getattr(self, "_worker", None))
        stop_qthread(getattr(self, "_load_worker", None))

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._load_worker = None

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content.setObjectName("wifi-page")
        content.setStyleSheet(page_style("wifi-page"))
        main_layout = QVBoxLayout(content)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        main_layout.addWidget(TelemetryHeader(
            "WiFi Diagnostics & Bufferbloat",
            "Scan nearby radios, inspect signal quality, and measure latency under load.",
            "WIFI",
            "SCAN READY",
            "#62c7d8",
        ))

        # --- Action buttons ---
        btn_group = QWidget()
        btn_layout = QHBoxLayout(btn_group)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(10)
        self._status_label = QLabel("Ready to scan nearby WiFi networks")
        self._status_label.setTextFormat(Qt.TextFormat.PlainText)
        self._status_label.setWordWrap(True)
        btn_layout.addWidget(self._status_label, 1)

        self._wifi_scan_btn = QPushButton("Scan WiFi")
        style_action(self._wifi_scan_btn, "primary")
        self._wifi_scan_btn.clicked.connect(self._on_wifi_scan)
        btn_layout.addWidget(self._wifi_scan_btn)

        self._bufferbloat_btn = QPushButton("Test Bufferbloat")
        style_action(self._bufferbloat_btn)
        self._bufferbloat_btn.setToolTip(
            "Tests if your latency spikes under load (~60s). "
            "This is the most important test for gaming quality."
        )
        self._bufferbloat_btn.clicked.connect(self._on_bufferbloat_test)
        btn_layout.addWidget(self._bufferbloat_btn)

        main_layout.addWidget(btn_group)

        # --- Progress ---
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFormat("Idle")
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(4)
        self._progress_bar.hide()
        main_layout.addWidget(self._progress_bar)

        # --- WiFi status cards ---
        wifi_status_group = QGroupBox("WiFi connection")
        wifi_status_layout = QVBoxLayout(wifi_status_group)
        wifi_status_layout.setContentsMargins(0, 4, 0, 0)
        self._wifi_state_label = QLabel("Run a scan to read your WiFi connection. The load test also works over Ethernet.")
        self._wifi_state_label.setWordWrap(True)
        wifi_status_layout.addWidget(self._wifi_state_label)
        self._wifi_status_grid = QGridLayout()
        self._wifi_status_grid.setSpacing(12)
        wifi_status_layout.addLayout(self._wifi_status_grid)

        self._wifi_cards: dict[str, ReadingTile] = {}
        card_defs = [
            ("ssid", "SSID"),
            ("signal", "Signal"),
            ("channel", "Channel"),
            ("speed", "Speed"),
            ("radio", "Radio Type"),
            ("band", "Band"),
        ]
        for i, (key, label) in enumerate(card_defs):
            card = ReadingTile(label)
            self._wifi_cards[key] = card
            row, col = divmod(i, 3)
            self._wifi_status_grid.addWidget(card, row, col)

        main_layout.addWidget(wifi_status_group)

        # --- Bufferbloat result ---
        bb_group = QGroupBox("Latency under load · bufferbloat")
        bb_layout = QGridLayout(bb_group)
        bb_layout.setContentsMargins(0, 4, 0, 0)
        bb_layout.setHorizontalSpacing(20)

        self._bb_grade_label = QLabel("--")
        self._bb_grade_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._bb_grade_label.setMinimumWidth(120)
        self._bb_grade_label.setStyleSheet(
            "font-family: 'Consolas'; font-size: 56px; color: #90a4b2; padding: 12px;"
        )
        bb_layout.addWidget(self._bb_grade_label, 0, 0)

        self._bb_detail_label = QLabel(
            "No load-test result yet.\n"
            "Test Bufferbloat downloads data for about 60 seconds to measure latency under load. "
            "Your connection will be busy during the test."
        )
        self._bb_detail_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._bb_detail_label.setTextFormat(Qt.TextFormat.PlainText)
        self._bb_detail_label.setWordWrap(True)
        self._bb_detail_label.setStyleSheet("color: #8f9aaa; padding: 8px; font-size: 13px;")
        bb_layout.addWidget(self._bb_detail_label, 0, 1)
        bb_layout.setColumnStretch(1, 1)
        self._bb_metrics_widget = QWidget()
        bb_metrics_layout = QHBoxLayout(self._bb_metrics_widget)
        bb_metrics_layout.setContentsMargins(0, 0, 0, 0)
        bb_metrics_layout.setSpacing(12)
        self._bb_metrics = {}
        for key, title in (("idle", "Idle latency"), ("loaded", "Under load"),
                           ("increase", "Latency increase"), ("speed", "Download speed")):
            tile = ReadingTile(title)
            bb_metrics_layout.addWidget(tile, 1)
            self._bb_metrics[key] = tile
        bb_layout.addWidget(self._bb_metrics_widget, 1, 0, 1, 2)
        self._bb_metrics_widget.hide()

        main_layout.addWidget(bb_group)

        # --- Visible networks table ---
        nets_group = QGroupBox("Visible networks")
        nets_layout = QVBoxLayout(nets_group)
        nets_layout.setContentsMargins(0, 4, 0, 0)
        self._nets_empty = QLabel("Nearby networks appear here after a scan.")
        nets_layout.addWidget(self._nets_empty)

        self._nets_table = QTableWidget(0, 6)
        self._nets_table.setHorizontalHeaderLabels([
            "SSID", "Signal", "Channel", "Band", "Radio", "Auth",
        ])
        self._nets_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch,
        )
        self._nets_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._nets_table.setAlternatingRowColors(True)
        compact_table(self._nets_table, self._nets_empty)
        nets_layout.addWidget(self._nets_table)
        main_layout.addWidget(nets_group)

        # --- Channel congestion table ---
        ch_group = QGroupBox("Channel congestion")
        ch_layout = QVBoxLayout(ch_group)
        ch_layout.setContentsMargins(0, 4, 0, 0)
        self._ch_empty = QLabel("A scan shows which channels nearby networks use.")
        ch_layout.addWidget(self._ch_empty)

        self._ch_table = QTableWidget(0, 4)
        self._ch_table.setHorizontalHeaderLabels([
            "Channel", "Band", "Networks", "Avg Signal",
        ])
        self._ch_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch,
        )
        self._ch_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._ch_table.setAlternatingRowColors(True)
        compact_table(self._ch_table, self._ch_empty)
        ch_layout.addWidget(self._ch_table)
        main_layout.addWidget(ch_group)

        # --- Issues & recommendation ---
        advice_group = QGroupBox("Findings and recommendations")
        advice_layout = QVBoxLayout(advice_group)
        advice_layout.setContentsMargins(0, 4, 0, 0)

        self._advice_label = QLabel("Run a WiFi scan to check for issues.")
        self._advice_label.setWordWrap(True)
        self._advice_label.setTextFormat(Qt.TextFormat.PlainText)
        self._advice_label.setStyleSheet("color: #8f9aaa; padding: 8px; font-size: 13px;")
        advice_layout.addWidget(self._advice_label)

        main_layout.addWidget(advice_group)

        main_layout.addStretch()

        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        # Load latest bufferbloat result if available
        self._load_last_bufferbloat()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_card(self, key: str, title: str, value: str, color: str = "#d8dee9"):
        card = self._wifi_cards.get(key)
        if card:
            card.set_reading(title, value, color)

    def _show_progress(self, message: str):
        self._status_label.setText(message)
        self._progress_bar.setFormat(message)

    def _set_busy(self, busy: bool, message: str = ""):
        self._wifi_scan_btn.setEnabled(not busy)
        self._bufferbloat_btn.setEnabled(not busy)
        self._show_progress(message or ("Working..." if busy else "Ready"))
        self._progress_bar.setVisible(busy)
        if busy:
            self._progress_bar.setRange(0, 0)
            self._progress_bar.setFormat(message or "Working...")
        else:
            self._progress_bar.setRange(0, 1)
            self._progress_bar.setValue(1)
            self._progress_bar.setFormat(message or "Done")

    def _signal_color(self, pct: int) -> str:
        if pct >= 80:
            return "#75c884"
        if pct >= 60:
            return "#62c7d8"
        if pct >= 40:
            return "#d9b65f"
        if pct >= 20:
            return "#c98652"
        return "#e06363"

    def _grade_color(self, grade: str) -> str:
        return {
            "A": "#75c884",
            "B": "#62c7d8",
            "C": "#d9b65f",
            "D": "#c98652",
            "F": "#e06363",
        }.get(grade.upper(), "#d8dee9")

    # ------------------------------------------------------------------
    # WiFi scan
    # ------------------------------------------------------------------

    def _on_wifi_scan(self):
        self._set_busy(True, "Scanning WiFi networks...")
        self._worker = _WifiScanWorker()
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_wifi_scan_done)
        self._worker.start()

    def _on_wifi_scan_done(self, report: WifiDiagReport | None):
        self._worker = None
        if report is None:
            self._set_busy(False, "WiFi scan failed")
            QMessageBox.warning(self, "Error", "WiFi scan failed. Check logs.")
            return

        self._set_busy(
            False,
            f"Found {len(report.visible_networks)} networks — "
            f"Signal: {report.signal_quality}",
        )
        self._display_wifi_report(report)

    def _display_wifi_report(self, report: WifiDiagReport):
        """Update all WiFi display widgets."""
        # Status cards
        if report.interface and report.interface.state.lower() == "connected":
            iface = report.interface
            self._wifi_state_label.setText("Current WiFi connection · readings from the latest scan")
            sig_color = self._signal_color(iface.signal_pct)
            self._update_card("ssid", "SSID", iface.ssid or "--")
            self._update_card(
                "signal", "Signal",
                f"{iface.signal_pct}% ({report.signal_quality})",
                sig_color,
            )
            self._update_card("channel", "Channel", f"{iface.channel} ({iface.band})")
            self._update_card("speed", "Speed", f"{iface.speed_mbps:.0f} Mbps")
            self._update_card("radio", "Radio", iface.radio_type or "--")
            self._update_card("band", "Band", iface.band or "--")
        else:
            self._wifi_state_label.setText("No connected WiFi interface reported. You can still test latency under load over Ethernet.")
            for key, card in self._wifi_cards.items():
                card.set_reading(card.title_label.text(), "Not connected" if key == "ssid" else "--", "#90a4b2")

        # Networks table
        sorted_nets = sorted(report.visible_networks, key=lambda n: -n.signal_pct)
        self._nets_table.setRowCount(len(sorted_nets))
        self._nets_empty.setText("No visible networks were reported by the latest scan.")
        for row, net in enumerate(sorted_nets):
            items = [
                QTableWidgetItem(net.ssid),
                QTableWidgetItem(f"{net.signal_pct}%"),
                QTableWidgetItem(str(net.channel)),
                QTableWidgetItem(net.band),
                QTableWidgetItem(net.radio_type),
                QTableWidgetItem(net.auth),
            ]
            sig_color = self._signal_color(net.signal_pct)
            items[1].setForeground(QColor(sig_color))

            # Highlight current network
            if report.interface and net.ssid == report.interface.ssid:
                for item in items:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)

            for col, item in enumerate(items):
                if col >= 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._nets_table.setItem(row, col, item)

        # Channel congestion
        self._ch_table.setRowCount(len(report.channel_congestion))
        self._ch_empty.setText("No channel data was reported by the latest scan.")
        for row, ch in enumerate(report.channel_congestion):
            is_current = (report.interface and report.interface.state.lower() == "connected"
                          and ch.channel == report.interface.channel and ch.band == report.interface.band)
            ch_text = f"{ch.channel}" + (" (you)" if is_current else "")
            items = [
                QTableWidgetItem(ch_text),
                QTableWidgetItem(ch.band),
                QTableWidgetItem(str(ch.network_count)),
                QTableWidgetItem(f"{ch.avg_signal:.0f}%"),
            ]
            if is_current:
                for item in items:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                    item.setForeground(QColor("#62c7d8"))

            for col, item in enumerate(items):
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._ch_table.setItem(row, col, item)

        # Issues & recommendation
        lines = []
        if report.issues:
            for issue in report.issues:
                lines.append(f"\u26a0  {issue}")
            lines.append("")
        lines.append(f"\u2192  {report.recommendation}")

        color = "#75c884" if not report.issues else (
            "#e06363" if len(report.issues) >= 3 else "#d9b65f"
        )
        self._advice_label.setText("\n".join(lines))
        self._advice_label.setStyleSheet(
            f"color: {color}; padding: 8px; font-size: 13px;"
        )

    # ------------------------------------------------------------------
    # Bufferbloat
    # ------------------------------------------------------------------

    def _on_bufferbloat_test(self):
        reply = QMessageBox.question(
            self, "Test Bufferbloat",
            "This will download files while measuring your latency\n"
            "to detect bufferbloat. Takes about 60 seconds.\n\n"
            "Your connection will be briefly saturated.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._set_busy(True, "Testing bufferbloat (this takes ~60s)...")
        self._worker = _BufferbloatWorker()
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_bufferbloat_done)
        self._worker.start()

    def _on_bufferbloat_done(self, snapshot: LoadBenchmarkSnapshot | None):
        self._worker = None
        if snapshot is None:
            self._set_busy(False, "Bufferbloat test failed")
            QMessageBox.warning(self, "Error", "Bufferbloat test failed. Check logs.")
            return

        grade = snapshot.bufferbloat.grade
        if grade == "N/A":
            self._set_busy(
                False,
                "Bufferbloat unavailable — the test received no usable latency samples",
            )
        else:
            self._set_busy(
                False,
                f"Bufferbloat grade: {grade} — "
                f"+{snapshot.bufferbloat.latency_increase_pct:.0f}% latency under load",
            )
        self._display_bufferbloat(snapshot)

    def _display_bufferbloat(self, snapshot: LoadBenchmarkSnapshot):
        bb = snapshot.bufferbloat
        grade = bb.grade
        color = self._grade_color(grade)

        self._bb_grade_label.setText(grade)
        self._bb_grade_label.setStyleSheet(
            f"font-family: 'Consolas'; font-size: 56px; color: {color}; padding: 12px;"
        )

        if grade == "N/A" or not (
            math.isfinite(bb.idle_latency_ms)
            and math.isfinite(bb.loaded_latency_ms)
        ):
            self._bb_metrics_widget.hide()
            self._bb_detail_label.setText(
                "No successful latency samples were received, so Losshound did not "
                "assign a bufferbloat grade.\n\n"
                f"Idle packet loss: {snapshot.idle.loss_pct:.0f}%\n"
                f"Loaded packet loss: {snapshot.loaded.loss_pct:.0f}%\n\n"
                "Check connectivity, then run the test again."
            )
            self._bb_detail_label.setStyleSheet(
                f"color: {color}; padding: 8px; font-size: 13px;"
            )
            return

        explanations = {
            "A": "Excellent. Latency barely increases under load.",
            "B": "Good. Slight latency increase but still very usable.",
            "C": "Fair. Noticeable lag spikes when downloading.",
            "D": "Poor. Significant lag when network is busy. Gaming will suffer.",
            "F": "Terrible. Connection becomes nearly unusable under load.",
        }
        explanation = explanations.get(grade, "")

        advice = ""
        if grade in ("C", "D", "F"):
            advice = (
                "\n\nTo fix bufferbloat:\n"
                "  1. Enable SQM/QoS on your router (fq_codel is best)\n"
                "  2. Set bandwidth limits slightly below your max speed\n"
                "  3. Check if your router firmware supports OpenWrt/DD-WRT"
            )

        self._bb_metrics_widget.show()
        for key, title, value in (
            ("idle", "Idle latency", f"{bb.idle_latency_ms:.1f} ms"),
            ("loaded", "Under load", f"{bb.loaded_latency_ms:.1f} ms"),
            ("increase", "Latency increase", f"{bb.latency_increase_ms:+.1f} ms ({bb.latency_increase_pct:+.0f}%)"),
            ("speed", "Download speed", f"{snapshot.throughput.speed_mbps:.1f} Mbps"),
        ):
            self._bb_metrics[key].set_reading(title, value, color if key == "increase" else "#eef3f5")
        detail = f"Last test: {snapshot.timestamp[:19].replace('T', ' ')}\n{explanation}{advice}"

        self._bb_detail_label.setText(detail)
        self._bb_detail_label.setStyleSheet(
            f"color: {color}; padding: 8px; font-size: 13px;"
        )

    def _load_last_bufferbloat(self):
        """Load the most recent bufferbloat result on startup in the background."""
        self._load_worker = _LoadLastBufferbloatWorker()
        self._load_worker.finished.connect(self._on_last_bufferbloat_loaded)
        self._load_worker.start()

    def _on_last_bufferbloat_loaded(self, snapshot: LoadBenchmarkSnapshot | None):
        if snapshot:
            self._display_bufferbloat(snapshot)
