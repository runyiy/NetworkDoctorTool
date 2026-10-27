"""Drop Analyzer tab — real-time connectivity monitoring to diagnose outages."""

from __future__ import annotations

import logging

from PySide6.QtCore import QElapsedTimer, QThread, QTimer, Signal, Slot, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QProgressBar, QPushButton, QScrollArea, QSpinBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from losshound.core.drop_analyzer import (
    ConnSample, DropAnalysisReport, run_drop_analysis,
)
from losshound.core.gateway import detect_gateway
from losshound.gui.theme import button_style
from losshound.gui.widgets import TelemetryHeader

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

class _DropAnalyzeWorker(QThread):
    """Run drop analysis in a background thread."""

    report_ready = Signal(object)   # Keep QThread.finished for native thread exit.
    progress = Signal(str)
    scan_started = Signal()
    sample_ready = Signal(object)

    def __init__(self, gateway: str, wan_target: str,
                 duration: int, interval: float, parent=None):
        super().__init__(parent)
        self._gateway = gateway
        self._wan_target = wan_target
        self._duration = duration
        self._interval = interval
        self._stop_requested = False

    def run(self):
        try:
            self.progress.emit("Detecting gateway...")
            gw = self._gateway or detect_gateway()
            if not gw:
                self.progress.emit("Could not detect gateway")
                self.report_ready.emit(None)
                return

            self.progress.emit(f"Monitoring (GW: {gw})...")
            self.scan_started.emit()
            report = run_drop_analysis(
                gateway=gw,
                wan_target=self._wan_target,
                duration_seconds=self._duration,
                poll_interval=self._interval,
                progress_callback=lambda msg: self.progress.emit(msg),
                stop_check=lambda: self._stop_requested,
                sample_callback=self.sample_ready.emit,
            )
            self.report_ready.emit(report)
        except Exception as exc:
            logger.error("Drop analysis failed: %s", exc)
            self.progress.emit(f"Error: {exc}")
            self.report_ready.emit(None)

    def request_stop(self):
        self._stop_requested = True
        self.requestInterruption()


# ---------------------------------------------------------------------------
# Drop Analyzer Tab
# ---------------------------------------------------------------------------

class DropTab(QWidget):
    """Connectivity drop analyzer tab."""

    def shutdown(self):
        self._refresh_timer.stop()
        from losshound.gui._shutdown import stop_qthread
        worker = getattr(self, "_worker", None)
        if worker is not None:
            try:
                worker.request_stop()
            except Exception:
                pass
        # Active-interface discovery has an 8-second bounded Windows query.
        stop_qthread(worker, wait_ms=10000)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: _DropAnalyzeWorker | None = None
        self._stopping = False
        self._completion_message = "Analysis finished"
        self._sample_count = 0
        self._live_drop_count = 0
        self._in_drop = False
        self._scan_clock = QElapsedTimer()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(1000)
        self._refresh_timer.timeout.connect(self._refresh_countdown)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        main_layout = QVBoxLayout(content)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        main_layout.addWidget(TelemetryHeader(
            "Connectivity Drop Analyzer",
            "Poll gateway, WAN, DNS, and link state to classify outages as they happen.",
            "DROPS",
            "ARMED",
            "#62c7d8",
        ))

        # --- Controls ---
        ctrl_group = QGroupBox("Scan Settings")
        ctrl_layout = QHBoxLayout(ctrl_group)
        ctrl_layout.setSpacing(12)

        # Duration
        dur_label = QLabel("Duration:")
        ctrl_layout.addWidget(dur_label)
        self._duration_combo = QComboBox()
        self._duration_combo.addItems([
            "1 minute", "2 minutes", "5 minutes", "10 minutes", "30 minutes", "1 hour",
        ])
        self._duration_combo.setCurrentIndex(1)  # 2 minutes default
        ctrl_layout.addWidget(self._duration_combo)

        # Poll interval
        int_label = QLabel("Poll every:")
        ctrl_layout.addWidget(int_label)
        self._interval_spin = QSpinBox()
        self._interval_spin.setRange(1, 30)
        self._interval_spin.setValue(3)
        self._interval_spin.setSuffix("s")
        ctrl_layout.addWidget(self._interval_spin)

        ctrl_layout.addStretch()

        # Start / Stop buttons
        self._start_btn = QPushButton("Start Monitoring")
        self._start_btn.setStyleSheet(button_style("primary"))
        self._start_btn.setMinimumHeight(42)
        self._start_btn.clicked.connect(self._on_start)
        ctrl_layout.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet(button_style("danger"))
        self._stop_btn.setMinimumHeight(42)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop)
        ctrl_layout.addWidget(self._stop_btn)

        main_layout.addWidget(ctrl_group)

        # --- Progress ---
        # Native Windows busy bars do not reliably paint their text.
        self._status_label = QLabel("Idle — press Start to begin monitoring")
        self._status_label.setWordWrap(True)
        main_layout.addWidget(self._status_label)
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFormat("Idle — press Start to begin monitoring")
        main_layout.addWidget(self._progress_bar)

        # --- Verdict banner ---
        self._verdict_frame = QFrame()
        self._verdict_frame.setObjectName("drop-verdict")
        self._verdict_frame.setStyleSheet("""
            QFrame#drop-verdict {
                background-color: #1b2028;
                border: 1px solid #3a4350;
                border-left: 4px solid #3a4350;
                border-radius: 0px;
            }
        """)
        verdict_layout = QVBoxLayout(self._verdict_frame)
        verdict_layout.setContentsMargins(18, 12, 18, 12)
        verdict_layout.setSpacing(4)

        self._verdict_label = QLabel("--")
        self._verdict_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._verdict_label.setStyleSheet(
            "font-size: 20px; font-weight: bold; color: #4a5565; "
            "background: transparent; border: none; padding: 0;"
        )
        self._verdict_label.setWordWrap(True)
        verdict_layout.addWidget(self._verdict_label)

        self._confidence_label = QLabel("")
        self._confidence_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._confidence_label.setStyleSheet(
            "font-family: 'Cascadia Mono', 'Consolas', monospace; "
            "font-size: 11px; color: #788596; background: transparent; "
            "border: none; padding: 0;"
        )
        verdict_layout.addWidget(self._confidence_label)

        main_layout.addWidget(self._verdict_frame)

        # --- Status cards ---
        cards_group = QGroupBox("Connection Status")
        self._cards_grid = QGridLayout(cards_group)
        self._cards_grid.setSpacing(8)

        self._cards: dict[str, QLabel] = {}
        card_defs = [
            ("conn_type", "Connection"),
            ("link", "Link State"),
            ("gateway", "Gateway"),
            ("wan", "WAN / Internet"),
            ("dns", "DNS"),
            ("drops", "Drop Episodes"),
        ]
        for i, (key, label) in enumerate(card_defs):
            card = self._make_card(label)
            self._cards[key] = card
            row, col = divmod(i, 3)
            self._cards_grid.addWidget(card, row, col)

        main_layout.addWidget(cards_group)

        # --- Drop episodes table ---
        drops_group = self._drops_group = QGroupBox("Drop Episodes")
        drops_layout = QVBoxLayout(drops_group)

        self._drops_table = QTableWidget(0, 7)
        self._drops_table.setHorizontalHeaderLabels([
            "Time", "Duration", "Link", "Gateway", "WAN", "DNS", "Classification",
        ])
        self._drops_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch,
        )
        self._drops_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._drops_table.setAlternatingRowColors(True)
        self._drops_table.setStyleSheet("QTableWidget { alternate-background-color: #252538; }")
        drops_layout.addWidget(self._drops_table)

        main_layout.addWidget(drops_group)

        # --- Timeline table ---
        self._timeline_group = QGroupBox("Connectivity Timeline")
        timeline_layout = QVBoxLayout(self._timeline_group)

        self._timeline_table = QTableWidget(0, 6)
        self._timeline_table.setHorizontalHeaderLabels([
            "Time", "Link", "Gateway", "GW RTT", "WAN", "WAN RTT",
        ])
        self._timeline_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch,
        )
        self._timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._timeline_table.setAlternatingRowColors(True)
        self._timeline_table.setStyleSheet("QTableWidget { alternate-background-color: #252538; }")
        self._timeline_table.setMaximumHeight(250)
        timeline_layout.addWidget(self._timeline_table)

        main_layout.insertWidget(main_layout.indexOf(drops_group), self._timeline_group)

        # --- Event log ---
        events_group = QGroupBox("Network Event Log (last 3 hours)")
        events_layout = QVBoxLayout(events_group)

        self._events_table = QTableWidget(0, 4)
        self._events_table.setHorizontalHeaderLabels([
            "Time", "Source", "Event ID", "Description",
        ])
        self._events_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch,
        )
        self._events_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._events_table.setAlternatingRowColors(True)
        self._events_table.setStyleSheet("QTableWidget { alternate-background-color: #252538; }")
        self._events_table.setMaximumHeight(200)
        events_layout.addWidget(self._events_table)

        main_layout.addWidget(events_group)

        # --- Recommendations ---
        recs_group = QGroupBox("Recommendations")
        recs_layout = QVBoxLayout(recs_group)

        self._recs_label = QLabel("Start a scan to analyze your connection.")
        self._recs_label.setWordWrap(True)
        self._recs_label.setStyleSheet("color: #8f9aaa; padding: 8px; font-size: 13px;")
        recs_layout.addWidget(self._recs_label)

        main_layout.addWidget(recs_group)

        main_layout.addStretch()

        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_card(self, label: str) -> QLabel:
        card = QLabel(f"{label}\n--")
        card.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card.setStyleSheet("""
            background-color: #1b2028;
            border: 1px solid #3a4350;
            border-radius: 0px;
            padding: 12px;
            font-size: 12px;
            color: #d8dee9;
        """)
        card.setMinimumHeight(70)
        card.setWordWrap(True)
        return card

    def _update_card(self, key: str, title: str, value: str, color: str = "#d8dee9"):
        card = self._cards.get(key)
        if card:
            card.setText(f"{title}\n{value}")
            card.setStyleSheet(f"""
                background-color: #1b2028;
                border: 1px solid #3a4350;
                border-radius: 0px;
                padding: 12px;
                font-size: 12px;
                color: {color};
            """)

    def _duration_seconds(self) -> int:
        mapping = {
            0: 60, 1: 120, 2: 300, 3: 600, 4: 1800, 5: 3600,
        }
        return mapping.get(self._duration_combo.currentIndex(), 120)

    def _set_busy(self, busy: bool, message: str = ""):
        self._start_btn.setEnabled(not busy)
        self._stop_btn.setEnabled(busy)
        self._duration_combo.setEnabled(not busy)
        self._interval_spin.setEnabled(not busy)
        self._status_label.setText(message)
        if busy:
            self._progress_bar.setRange(0, self._duration_seconds())
            self._progress_bar.setFormat(message or "Monitoring...")
        else:
            self._refresh_timer.stop()
            self._progress_bar.setRange(0, 1)
            self._progress_bar.setValue(1 if self._sample_count else 0)
            self._progress_bar.setFormat(message or "Done")

    def _reset_readings(self):
        self._sample_count = self._live_drop_count = 0
        self._in_drop = False
        self._scan_clock.invalidate()
        self._progress_bar.setValue(0)
        self._verdict_label.setText("Collecting live readings")
        self._verdict_label.setStyleSheet(
            "font-size: 20px; font-weight: bold; color: #62c7d8; "
            "background: transparent; border: none; padding: 0;"
        )
        self._style_verdict("#62c7d8", "#17212b", "#315469")
        self._confidence_label.setText(
            "Stops automatically after the selected duration. Stop ends early and keeps completed samples."
        )
        self._confidence_label.setWordWrap(True)
        for key, title in (
            ("conn_type", "Connection"), ("link", "Link State"),
            ("gateway", "Gateway"), ("wan", "WAN / Internet"),
            ("dns", "DNS — last check"), ("drops", "Drop Episodes — live"),
        ):
            self._update_card(key, title, "Waiting for first sample", "#788596")
        for table in (self._timeline_table, self._drops_table, self._events_table):
            table.setRowCount(0)
        self._timeline_group.setTitle("Connectivity Timeline — latest 40 samples (live)")
        self._drops_group.setTitle("Drop Episodes — classification after scan")
        self._recs_label.setText("Drop classifications, event logs, and recommendations appear when the scan ends.")
        self._recs_label.setStyleSheet("color: #8f9aaa; padding: 8px; font-size: 13px;")

    @Slot()
    def _on_scan_started(self):
        if self._stopping:
            return
        self._scan_clock.start()
        self._refresh_timer.start()
        self._refresh_countdown()

    @Slot()
    def _refresh_countdown(self):
        if self._stopping or not self._scan_clock.isValid():
            return
        duration = self._duration_seconds()
        elapsed = min(duration, self._scan_clock.elapsed() // 1000)
        remaining = duration - elapsed
        self._progress_bar.setValue(elapsed)
        message = (
            f"{remaining // 60}:{remaining % 60:02d} remaining"
            if remaining else "Finishing current check and preparing report..."
        )
        self._progress_bar.setFormat(message)

    @Slot(object)
    def _on_sample(self, sample: ConnSample):
        self._sample_count += 1
        bad = not (sample.link_up and sample.gateway_reachable and sample.wan_reachable)
        if bad and not self._in_drop:
            self._live_drop_count += 1
        self._in_drop = bad
        self._update_card("conn_type", "Connection", sample.connection_type.upper(), "#62c7d8")
        for key, title, ok, rtt in (
            ("link", "Link State — latest", sample.link_up, None),
            ("gateway", "Gateway — latest", sample.gateway_reachable, sample.gateway_rtt_ms),
            ("wan", "WAN / Internet — latest", sample.wan_reachable, sample.wan_rtt_ms),
        ):
            value = ("UP" if key == "link" else "OK") if ok else ("DOWN" if key == "link" else "LOST")
            if ok and rtt is not None:
                value += f" · {rtt:.1f} ms"
            self._update_card(key, title, value, "#75c884" if ok else "#e06363")
        if sample.dns_checked:
            self._update_card(
                "dns", "DNS — last check",
                f"{'OK' if sample.dns_ok else 'FAILED'} · {sample.timestamp:%H:%M:%S}",
                "#75c884" if sample.dns_ok else "#e06363",
            )
        self._update_card("drops", "Drop Episodes — live", str(self._live_drop_count),
                          "#d9b65f" if self._live_drop_count else "#75c884")
        if not self._stopping:
            self._status_label.setText(
                f"Monitoring — {self._sample_count} samples · Latest reading {sample.timestamp:%H:%M:%S}"
            )
        table = self._timeline_table
        if table.rowCount() >= 40:
            table.removeRow(0)
        row = table.rowCount()
        table.insertRow(row)
        values = (
            sample.timestamp.strftime("%H:%M:%S"), "UP" if sample.link_up else "DOWN",
            "OK" if sample.gateway_reachable else "LOST",
            f"{sample.gateway_rtt_ms:.1f} ms" if sample.gateway_rtt_ms is not None else "--",
            "OK" if sample.wan_reachable else "LOST",
            f"{sample.wan_rtt_ms:.1f} ms" if sample.wan_rtt_ms is not None else "--",
        )
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if col in (1, 2, 4):
                item.setForeground(QColor("#75c884" if value in ("UP", "OK") else "#e06363"))
            table.setItem(row, col, item)
        table.scrollToBottom()

    # ------------------------------------------------------------------
    # Start / Stop
    # ------------------------------------------------------------------

    def _on_start(self):
        # A result can arrive before its native thread finishes exiting.
        if self._worker is not None:
            return
        gw = detect_gateway()
        if not gw:
            self._verdict_label.setText("Could not detect gateway")
            self._verdict_label.setStyleSheet(
                "font-size: 20px; font-weight: bold; color: #e06363; "
                "background: transparent; border: none; padding: 0;"
            )
            self._style_verdict("#e06363", "#2d1b1d", "#73353a")
            return

        duration = self._duration_seconds()
        interval = self._interval_spin.value()

        self._stopping = False
        self._completion_message = "Analysis finished"
        self._reset_readings()
        self._set_busy(True, f"Monitoring for {duration}s...")
        self._worker = _DropAnalyzeWorker(
            gateway=gw,
            wan_target="8.8.8.8",
            duration=duration,
            interval=float(interval),
            parent=self,
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.scan_started.connect(self._on_scan_started)
        self._worker.sample_ready.connect(self._on_sample)
        self._worker.report_ready.connect(self._on_finished)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _on_stop(self):
        if self._worker and self._worker.isRunning():
            self._stopping = True
            self._refresh_timer.stop()
            self._worker.request_stop()
            self._set_busy(True, "Stopping...")
            self._stop_btn.setEnabled(False)

    @Slot(str)
    def _on_progress(self, msg: str):
        if not self._stopping:
            self._status_label.setText(msg)

    def _style_verdict(self, text_color: str, bg: str, border: str):
        self._verdict_frame.setStyleSheet(f"""
            QFrame#drop-verdict {{
                background-color: {bg};
                border: 1px solid {border};
                border-left: 4px solid {text_color};
                border-radius: 0px;
            }}
        """)

    @Slot(object)
    def _on_finished(self, report: DropAnalysisReport | None):
        # Display the result, but retain ownership until QThread.finished.
        self._refresh_timer.stop()
        self._stop_btn.setEnabled(False)
        if report is None:
            self._completion_message = "Analysis failed"
            self._verdict_label.setText("Analysis failed — check logs")
            self._style_verdict("#e06363", "#2d1b1d", "#73353a")
            return

        drop_count = len(report.drops)
        state = "Stopped" if self._stopping else "Done"
        self._completion_message = (
            f"{state} — {report.total_samples} samples, {drop_count} drops detected"
        )
        self._display_report(report)

    @Slot()
    def _on_worker_finished(self):
        worker = self.sender()
        if worker is self._worker:
            self._worker = None
            self._set_busy(False, self._completion_message)
        if worker is not None:
            worker.deleteLater()

    def show_forensics_episode(self, episode) -> None:
        """Display an automatic scheduler-triggered forensic capture."""
        # Automatic captures are persisted separately; do not overwrite live readings.
        if self._worker is not None:
            return
        self._set_busy(False, f"Auto forensics captured: {episode.cause}")
        self._display_report(episode.report)

        cause_labels = {
            "wifi_roam": "WIFI ROAM / CHANNEL CHANGE",
            "gateway_reboot": "GATEWAY / ROUTER REBOOT",
            "isp": "ISP / WAN DROP",
            "inconclusive": "INCONCLUSIVE DROP",
        }
        self._verdict_label.setText(
            f"{cause_labels.get(episode.cause, episode.cause.upper())}: "
            f"{episode.summary}"
        )
        self._confidence_label.setText(
            f"Auto capture  |  Confidence: {episode.confidence}  |  "
            f"Gateway: {episode.gateway_ip}  |  Timeout streak: {episode.timeout_streak}"
        )

    # ------------------------------------------------------------------
    # Display results
    # ------------------------------------------------------------------

    def _display_report(self, report: DropAnalysisReport):
        # --- Verdict banner ---
        verdict_colors = {
            "high": ("#e06363", "#2d1b1d", "#73353a"),
            "medium": ("#d9b65f", "#2b2518", "#6d5623"),
            "low": ("#62c7d8", "#17212b", "#315469"),
        }
        text_color, bg, border = verdict_colors.get(
            report.confidence, ("#d8dee9", "#1b2028", "#3a4350")
        )

        # If no drops, use green
        if report.samples and not report.drops:
            text_color, bg, border = "#75c884", "#111a14", "#315a3c"

        self._verdict_label.setText(report.verdict)
        self._verdict_label.setStyleSheet(
            f"font-size: 20px; font-weight: bold; color: {text_color}; "
            "background: transparent; border: none; padding: 0;"
        )
        self._confidence_label.setText(
            f"Confidence: {report.confidence}  |  "
            f"Connection: {report.connection_type}  |  "
            f"Duration: {report.scan_duration_seconds:.0f}s"
            + (f"  |  Pattern: {report.drop_regularity}" if report.drop_regularity else "")
        )
        self._style_verdict(text_color, bg, border)

        # --- Status cards ---
        total = report.total_samples
        gw_fails = sum(1 for s in report.samples if not s.gateway_reachable)
        wan_fails = sum(1 for s in report.samples if not s.wan_reachable)
        link_fails = sum(1 for s in report.samples if not s.link_up)
        dns_samples = [s for s in report.samples if s.dns_checked]
        dns_fails = sum(1 for s in dns_samples if not s.dns_ok)

        self._update_card(
            "conn_type", "Connection",
            report.connection_type.upper(),
            "#62c7d8",
        )
        self._update_card(
            "link", "Link State",
            f"UP ({total - link_fails}/{total})" if link_fails == 0
            else f"FLAPPED ({link_fails} drops)",
            "#75c884" if link_fails == 0 else "#e06363",
        )
        self._update_card(
            "gateway", "Gateway",
            f"OK ({total - gw_fails}/{total})" if gw_fails == 0
            else f"FAILED {gw_fails}x",
            "#75c884" if gw_fails == 0 else "#e06363",
        )
        self._update_card(
            "wan", "WAN / Internet",
            f"OK ({total - wan_fails}/{total})" if wan_fails == 0
            else f"FAILED {wan_fails}x",
            "#75c884" if wan_fails == 0 else (
                "#d9b65f" if wan_fails < total * 0.1 else "#e06363"
            ),
        )
        self._update_card(
            "dns", "DNS",
            f"OK ({len(dns_samples)}/{len(dns_samples)} checks)" if dns_fails == 0
            else f"FAILED {dns_fails}x",
            "#75c884" if dns_fails == 0 else "#d9b65f",
        )
        self._update_card(
            "drops", "Drop Episodes",
            str(len(report.drops)),
            "#75c884" if len(report.drops) == 0 else (
                "#d9b65f" if len(report.drops) <= 2 else "#e06363"
            ),
        )
        if not total:
            for key, title in (("link", "Link State"), ("gateway", "Gateway"),
                               ("wan", "WAN / Internet"), ("drops", "Drop Episodes")):
                self._update_card(key, title, "No samples", "#788596")
        if not dns_samples:
            self._update_card("dns", "DNS", "Not checked", "#788596")

        # --- Drop episodes table ---
        self._drops_group.setTitle("Drop Episodes")
        pattern_labels = {
            "link_flap": "LINK FLAP",
            "full_outage": "FULL OUTAGE",
            "isp_wan_issue": "ISP / WAN",
            "gateway_issue": "GATEWAY",
            "rf_interference": "RF INTERFERENCE",
            "dns_issue": "DNS ONLY",
            "unknown": "UNKNOWN",
        }
        pattern_colors = {
            "link_flap": "#e06363",
            "full_outage": "#e06363",
            "isp_wan_issue": "#c98652",
            "gateway_issue": "#c98652",
            "rf_interference": "#62c7d8",
            "dns_issue": "#d9b65f",
            "unknown": "#788596",
        }

        self._drops_table.setRowCount(len(report.drops))
        for row, drop in enumerate(report.drops):
            t = drop.start.strftime("%H:%M:%S")
            dur = f"{drop.duration_seconds:.0f}s" if drop.duration_seconds > 0 else "<3s"
            link = "DOWN" if drop.link_lost else "ok"
            gw = "LOST" if drop.gateway_lost else "ok"
            wan = "LOST" if drop.wan_lost else "ok"
            dns = "FAIL" if drop.dns_lost else "ok"
            pat = pattern_labels.get(drop.pattern, drop.pattern)
            pat_color = pattern_colors.get(drop.pattern, "#d8dee9")

            items = [
                QTableWidgetItem(t),
                QTableWidgetItem(dur),
                QTableWidgetItem(link),
                QTableWidgetItem(gw),
                QTableWidgetItem(wan),
                QTableWidgetItem(dns),
                QTableWidgetItem(pat),
            ]

            # Color the problem cells red
            for idx, (val, item) in enumerate(zip(
                [None, None, link, gw, wan, dns, None], items
            )):
                if val in ("DOWN", "LOST", "FAIL"):
                    item.setForeground(QColor("#e06363"))
                elif val == "ok":
                    item.setForeground(QColor("#75c884"))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # Color the classification
            items[6].setForeground(QColor(pat_color))
            font = items[6].font()
            font.setBold(True)
            items[6].setFont(font)

            for col, item in enumerate(items):
                self._drops_table.setItem(row, col, item)

        # --- Timeline table (show samples, chunked) ---
        self._timeline_group.setTitle("Connectivity Timeline — scan summary")
        samples = report.samples
        chunk_size = max(1, len(samples) // 40)
        chunks = [samples[i:i + chunk_size] for i in range(0, len(samples), chunk_size)]

        self._timeline_table.setRowCount(len(chunks))
        for row, chunk in enumerate(chunks):
            ts = chunk[0].timestamp.strftime("%H:%M:%S")
            link_ok = all(s.link_up for s in chunk)
            gw_ok = all(s.gateway_reachable for s in chunk)
            wan_ok = all(s.wan_reachable for s in chunk)

            gw_rtts = [s.gateway_rtt_ms for s in chunk if s.gateway_rtt_ms is not None]
            wan_rtts = [s.wan_rtt_ms for s in chunk if s.wan_rtt_ms is not None]
            gw_rtt_str = f"{sum(gw_rtts)/len(gw_rtts):.0f}ms" if gw_rtts else "--"
            wan_rtt_str = f"{sum(wan_rtts)/len(wan_rtts):.0f}ms" if wan_rtts else "--"

            items = [
                QTableWidgetItem(ts),
                QTableWidgetItem("UP" if link_ok else "DOWN"),
                QTableWidgetItem("OK" if gw_ok else "LOST"),
                QTableWidgetItem(gw_rtt_str),
                QTableWidgetItem("OK" if wan_ok else "LOST"),
                QTableWidgetItem(wan_rtt_str),
            ]

            # Colors
            items[1].setForeground(QColor("#75c884" if link_ok else "#e06363"))
            items[2].setForeground(QColor("#75c884" if gw_ok else "#e06363"))
            items[4].setForeground(QColor("#75c884" if wan_ok else "#e06363"))

            for col, item in enumerate(items):
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._timeline_table.setItem(row, col, item)

        # --- Event log ---
        events = report.events[:25]
        self._events_table.setRowCount(len(events))
        for row, evt in enumerate(events):
            items = [
                QTableWidgetItem(evt.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
                QTableWidgetItem(evt.source),
                QTableWidgetItem(str(evt.event_id)),
                QTableWidgetItem(evt.description[:60]),
            ]
            for col, item in enumerate(items):
                if col >= 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._events_table.setItem(row, col, item)

        # --- Recommendations ---
        if report.recommendations:
            recs_text = "\n".join(
                f"{i}. {r}" for i, r in enumerate(report.recommendations, 1)
            )
            rec_color = "#e06363" if report.drops else "#75c884"
            self._recs_label.setText(recs_text)
            self._recs_label.setStyleSheet(
                f"color: {rec_color}; padding: 8px; font-size: 13px;"
            )
        else:
            self._recs_label.setText("No issues found." if total else "No samples collected; start another scan.")
            self._recs_label.setStyleSheet(
                "color: #75c884; padding: 8px; font-size: 13px;"
            )
