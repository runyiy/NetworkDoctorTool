"""Score & Trends tab — network quality scoring with historical analysis."""

from __future__ import annotations

import logging
from datetime import datetime
from html import escape

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QProgressBar, QPushButton, QScrollArea,
    QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from losshound.core.benchmark import BenchmarkSnapshot, run_benchmark, save_snapshot
from losshound.core.scoring import NetworkScore, SubScore, format_score, score_snapshot
from losshound.core.trending import TrendSummary, analyze_trends, format_trends
from losshound.gui.theme import button_style
from losshound.gui.widgets import TelemetryHeader
from losshound.storage.history import HistoryStore

logger = logging.getLogger(__name__)


_PAGE_STYLE = """
    QWidget#score-page QLabel {
        font-family: 'Segoe UI', sans-serif;
        font-size: 13px;
        color: #aebbc6;
        background: transparent;
        border: none;
    }
    QWidget#score-page QGroupBox {
        border: none;
        border-top: 1px solid #28333b;
        margin-top: 22px;
        padding: 18px 0 0 0;
    }
    QWidget#score-page QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 12px 0 0;
        color: #aebbc6;
        font-family: 'Segoe UI', sans-serif;
        font-size: 14px;
        font-weight: 600;
        letter-spacing: 0;
        text-transform: none;
    }
    QFrame#score-overview {
        background: #101a20;
        border: 1px solid #30434d;
        border-left: 3px solid #62c7d8;
    }
    QFrame#score-metric {
        background: #101519;
        border: 1px solid #27333b;
    }
    QWidget#score-page QTableWidget {
        background: #080c0e;
        alternate-background-color: #101619;
        border: none;
        font-family: 'Consolas', monospace;
        font-size: 13px;
        selection-background-color: #203640;
    }
    QWidget#score-page QHeaderView::section {
        background: #080c0e;
        color: #90a4b2;
        border: none;
        border-bottom: 1px solid #28333b;
        font-family: 'Segoe UI', sans-serif;
        font-size: 12px;
        font-weight: 600;
        text-transform: none;
        letter-spacing: 0;
        padding: 8px;
    }
"""


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------

class _ScoreWorker(QThread):
    """Run a benchmark and compute network score."""

    finished = Signal(object, object)  # (BenchmarkSnapshot, NetworkScore)
    progress = Signal(str)

    def run(self):
        try:
            self.progress.emit("Running benchmark for score...")
            snapshot = run_benchmark(
                label="score", ping_count=20,
                progress_callback=lambda msg: self.progress.emit(msg),
            )
            save_snapshot(snapshot)
            score = score_snapshot(snapshot)
            self.finished.emit(snapshot, score)
        except Exception as exc:
            logger.error("Score benchmark failed: %s", exc)
            self.finished.emit(None, None)


class _TrendsWorker(QThread):
    """Load history and run trend analysis."""

    finished = Signal(object, list)  # (TrendSummary, list[dict])

    def __init__(self, hours: int = 168):
        super().__init__()
        self._hours = hours

    def run(self):
        try:
            store = HistoryStore()
            benchmarks = store.get_benchmarks(hours=self._hours)
            store.close()
            summary = analyze_trends(benchmarks, hours=self._hours)
            self.finished.emit(summary, benchmarks)
        except Exception as exc:
            logger.error("Trend analysis failed: %s", exc)
            self.finished.emit(None, [])


# ---------------------------------------------------------------------------
# Score & Trends Tab
# ---------------------------------------------------------------------------

class ScoreTab(QWidget):
    """Network quality score and historical trends tab."""

    def shutdown(self):
        from losshound.gui._shutdown import stop_qthread
        stop_qthread(getattr(self, "_worker", None))

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content.setObjectName("score-page")
        content.setStyleSheet(_PAGE_STYLE)
        main_layout = QVBoxLayout(content)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        main_layout.addWidget(TelemetryHeader(
            "Network Score & Trends",
            "Score network quality for gaming and real-time use, then track degradation over time.",
            "SCORE",
            "HISTORY",
            "#62c7d8",
        ))

        # --- Action buttons ---
        btn_group = QWidget()
        btn_layout = QHBoxLayout(btn_group)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(10)
        self._status_label = QLabel("Ready for a benchmark")
        self._status_label.setWordWrap(True)
        btn_layout.addWidget(self._status_label, 1)

        self._score_btn = QPushButton("Run Score Benchmark")
        self._score_btn.setStyleSheet(button_style("primary") + """
            QPushButton { background: #17343c; border-color: #62c7d8;
                font-family: 'Segoe UI'; font-size: 13px; letter-spacing: 0;
                text-transform: none; padding: 9px 16px; }
            QPushButton:hover { background: #234955; }
        """)
        self._score_btn.setMinimumHeight(40)
        self._score_btn.clicked.connect(self._on_run_score)
        btn_layout.addWidget(self._score_btn)

        self._trends_btn = QPushButton("Refresh Trends")
        self._trends_btn.setStyleSheet(button_style("default") + """
            QPushButton { font-family: 'Segoe UI'; font-size: 13px;
                letter-spacing: 0; text-transform: none; padding: 9px 16px; }
        """)
        self._trends_btn.setMinimumHeight(40)
        self._trends_btn.clicked.connect(self._on_refresh_trends)
        btn_layout.addWidget(self._trends_btn)

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

        # --- Score display ---
        score_group = QWidget()
        score_layout = QHBoxLayout(score_group)
        score_layout.setContentsMargins(0, 0, 0, 0)
        score_layout.setSpacing(12)

        # Left: Main Score Card
        self._main_score_card = QFrame()
        self._main_score_card.setObjectName("score-overview")
        self._main_score_card.setFixedWidth(240)

        main_card_layout = QVBoxLayout(self._main_score_card)
        main_card_layout.setContentsMargins(22, 22, 22, 22)
        main_card_layout.setSpacing(8)

        title_label = QLabel("OVERALL SCORE")
        title_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        title_label.setStyleSheet("""
            font-size: 12px;
            font-weight: 600;
            color: #90a4b2;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        """)
        main_card_layout.addWidget(title_label)
        main_card_layout.addStretch()

        # Big score number
        self._score_label = QLabel("--")
        self._score_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._score_label.setStyleSheet(
            "font-size: 76px; font-weight: 600; color: #90a4b2; padding: 0; font-family: 'Consolas';"
        )
        score_number = QHBoxLayout()
        score_number.setSpacing(8)
        score_number.addWidget(self._score_label)
        scale_label = QLabel("/ 100")
        scale_label.setStyleSheet("font-size: 16px; color: #90a4b2; padding-bottom: 16px;")
        score_number.addWidget(scale_label, 1, Qt.AlignmentFlag.AlignBottom)
        main_card_layout.addLayout(score_number)

        self._grade_label = QLabel("Run benchmark to score")
        self._grade_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._grade_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #8f9aaa; padding: 4px;")
        self._grade_label.setWordWrap(True)
        main_card_layout.addWidget(self._grade_label)
        main_card_layout.addStretch()
        self._score_timestamp = QLabel("Your next benchmark appears here.")
        self._score_timestamp.setWordWrap(True)
        self._score_timestamp.setStyleSheet("font-size: 12px; color: #90a4b2;")
        main_card_layout.addWidget(self._score_timestamp)

        score_layout.addWidget(self._main_score_card)

        # Right: Sub-score cards grid
        self._subscore_grid = QGridLayout()
        self._subscore_grid.setSpacing(12)
        self._subscore_cards: dict[str, QFrame] = {}
        self._subscore_columns = 3
        score_layout.addLayout(self._subscore_grid, 1)
        self._metrics_empty = QLabel("See what shapes your score\n\nRun a benchmark to measure latency, jitter, packet loss, DNS, and TCP connection time.")
        self._metrics_empty.setWordWrap(True)
        self._metrics_empty.setStyleSheet("font-size: 15px; color: #90a4b2; padding: 24px;")
        self._subscore_grid.addWidget(self._metrics_empty, 0, 0, 1, 3)

        main_layout.addWidget(score_group)

        # --- History table ---
        history_group = QGroupBox("Recent benchmarks")
        history_layout = QVBoxLayout(history_group)
        history_layout.setContentsMargins(0, 4, 0, 0)
        self._history_empty = QLabel("No benchmarks yet. Run your first benchmark to establish a baseline.")
        history_layout.addWidget(self._history_empty)

        self._history_table = QTableWidget(0, 7)
        self._history_table.setHorizontalHeaderLabels([
            "Date / time", "Label", "Score", "Grade", "Latency", "Jitter", "Loss",
        ])
        self._history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._history_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._history_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._history_table.verticalHeader().setVisible(False)
        self._history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._history_table.setAlternatingRowColors(True)
        self._configure_table(self._history_table)
        self._history_table.hide()
        history_layout.addWidget(self._history_table)
        main_layout.addWidget(history_group)

        # --- Patterns / alerts ---
        patterns_group = QWidget()
        patterns_layout = QVBoxLayout(patterns_group)
        patterns_layout.setContentsMargins(0, 0, 0, 0)

        self._patterns_label = QLabel("Run a few benchmarks over time to detect patterns.")
        self._patterns_label.setWordWrap(True)
        self._patterns_label.setStyleSheet("color: #8f9aaa; padding: 8px; font-size: 13px;")
        patterns_layout.addWidget(self._patterns_label)

        main_layout.addWidget(patterns_group)

        # --- Metric trend table ---
        metric_group = QGroupBox("Metric trends · last 7 days")
        metric_layout = QVBoxLayout(metric_group)
        metric_layout.setContentsMargins(0, 4, 0, 0)
        self._metric_empty = QLabel("Metric comparisons appear after your first benchmark.")
        metric_layout.addWidget(self._metric_empty)

        self._metric_table = QTableWidget(0, 6)
        self._metric_table.setHorizontalHeaderLabels([
            "Metric", "Current", "Average", "Best", "Worst", "Trend",
        ])
        self._metric_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._metric_table.verticalHeader().setVisible(False)
        self._metric_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._metric_table.setAlternatingRowColors(True)
        self._configure_table(self._metric_table)
        self._metric_table.hide()
        metric_layout.addWidget(self._metric_table)
        main_layout.addWidget(metric_group)

        main_layout.addStretch()

        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        # Load trends on startup
        self._on_refresh_trends()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _configure_table(table: QTableWidget):
        table.setShowGrid(False)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.verticalHeader().setDefaultSectionSize(34)
        table.horizontalHeader().setMinimumSectionSize(72)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    @staticmethod
    def _fit_table(table: QTableWidget, max_rows: int = 6):
        rows = min(table.rowCount(), max_rows)
        height = table.horizontalHeader().sizeHint().height() + sum(
            table.rowHeight(row) for row in range(rows)
        ) + 4
        # Reserve room for horizontal scrolling at small window sizes.
        height += table.horizontalScrollBar().sizeHint().height()
        table.setFixedHeight(height)
        table.setVisible(table.rowCount() > 0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        columns = 2 if self.width() < 1120 else 3
        if columns == self._subscore_columns:
            return
        self._subscore_columns = columns
        for i, card in enumerate(self._subscore_cards.values()):
            self._subscore_grid.removeWidget(card)
            self._subscore_grid.addWidget(card, i // columns, i % columns)

    @staticmethod
    def _display_time(timestamp: str) -> str:
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone()
            return parsed.strftime("%d %b %Y · %H:%M")
        except (ValueError, TypeError, AttributeError):
            return str(timestamp or "--")

    def _set_overall(self, value: float, grade: str, rating: str):
        color = self._score_color(value)
        self._score_label.setText(f"{value:.0f}")
        self._score_label.setStyleSheet(
            f"font-size: 76px; font-weight: 600; color: {color}; "
            "padding: 0; font-family: 'Consolas';"
        )
        self._grade_label.setText(f"Grade {grade} · {rating}")
        self._grade_label.setStyleSheet(f"font-size: 17px; font-weight: 600; color: {color};")

    def _show_progress(self, message: str):
        self._status_label.setText(message)
        self._progress_bar.setFormat(message)

    def _set_busy(self, busy: bool, message: str = ""):
        self._score_btn.setEnabled(not busy)
        self._trends_btn.setEnabled(not busy)
        self._progress_bar.setVisible(busy)
        self._show_progress(message or ("Working..." if busy else "Ready"))
        if busy:
            self._progress_bar.setRange(0, 0)
            self._progress_bar.setFormat(message or "Working...")
        else:
            self._progress_bar.setRange(0, 1)
            self._progress_bar.setValue(1)
            self._progress_bar.setFormat(message or "Done")

    def _score_color(self, score: float) -> str:
        """Return a hex color for a score value."""
        if score >= 90:
            return "#75c884"  # green
        if score >= 75:
            return "#62c7d8"  # blue
        if score >= 60:
            return "#d9b65f"  # yellow
        if score >= 40:
            return "#c98652"  # orange
        return "#e06363"      # red

    # ------------------------------------------------------------------
    # Score actions
    # ------------------------------------------------------------------

    def _on_run_score(self):
        if self._worker is not None and self._worker.isRunning():
            return  # already running, ignore the click
        self._set_busy(True, "Running score benchmark...")
        self._worker = _ScoreWorker()
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_score_done)
        self._worker.start()

    def _on_score_done(self, snapshot, score: NetworkScore | None):
        self._worker = None
        if score is None:
            self._set_busy(False, "Score benchmark failed")
            QMessageBox.warning(self, "Error", "Score benchmark failed. Check logs.")
            return

        self._set_busy(False, f"Score: {score.overall:.0f}/100 ({score.grade})")
        self._display_score(score)
        self._on_refresh_trends()

    def _display_score(self, score: NetworkScore):
        """Update the score display widgets."""
        self._set_overall(score.overall, score.grade, score.rating)
        self._score_timestamp.setText(f"Last benchmark\n{self._display_time(score.timestamp)}")
        self._metrics_empty.setVisible(not score.sub_scores)

        # Clear old sub-score cards
        for card in self._subscore_cards.values():
            self._subscore_grid.removeWidget(card)
            card.deleteLater()
        self._subscore_cards.clear()

        # Create new sub-score cards
        for i, sub in enumerate(score.sub_scores):
            card = self._make_metric_card(sub)
            row, col = divmod(i, self._subscore_columns)
            self._subscore_grid.addWidget(card, row, col)
            self._subscore_cards[sub.name] = card

    def _make_metric_card(self, sub: SubScore) -> QFrame:
        card = QFrame()
        card.setObjectName("score-metric")
        card.setMinimumHeight(142)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(8)
        title = QLabel(sub.name)
        title.setStyleSheet("font-size: 13px; color: #aebbc6; font-weight: 600;")
        layout.addWidget(title)

        estimated = sub.name == "Bufferbloat" and "est." in sub.raw_unit
        value, unit = f"{sub.raw_value:.1f}", sub.raw_unit
        if estimated:
            value, unit = f"{sub.value:.0f}", "/ 100 estimated"
        elif sub.name == "Bufferbloat":
            value, unit = f"{sub.raw_value:+.0f}", "% under load"

        reading = QLabel(
            f"<span style='font-family: Consolas; font-size: 30px; color: #eef3f5;'>{escape(value)}</span>"
            f" <span style='font-family: Segoe UI; font-size: 13px; color: #90a4b2;'>{escape(unit)}</span>"
        )
        reading.setObjectName("metric-reading")
        reading.setWordWrap(True)
        layout.addWidget(reading)
        color = self._score_color(sub.value)
        caption = f"{sub.rating} · score {sub.value:.0f}/100"
        if estimated:
            caption = f"{sub.rating} · inferred from jitter and loss"
        detail = QLabel(caption)
        detail.setObjectName("metric-detail")
        detail.setWordWrap(True)
        detail.setStyleSheet(f"font-size: 12px; color: {color};")
        layout.addWidget(detail)
        rail = QProgressBar()
        rail.setRange(0, 100)
        rail.setValue(round(sub.value))
        rail.setTextVisible(False)
        rail.setFixedHeight(3)
        rail.setStyleSheet(f"""
            QProgressBar {{ background: #263139; border: none; }}
            QProgressBar::chunk {{ background: {color}; border: none; }}
        """)
        layout.addWidget(rail)
        return card

    # ------------------------------------------------------------------
    # Trends
    # ------------------------------------------------------------------

    def _on_refresh_trends(self):
        if self._worker is not None and self._worker.isRunning():
            return  # already running, ignore the click
        self._show_progress("Loading saved benchmarks...")
        self._worker = _TrendsWorker(hours=168)
        self._worker.finished.connect(self._on_trends_done)
        self._worker.start()

    def _on_trends_done(self, summary: TrendSummary | None, benchmarks: list[dict]):
        # The result signal does not mean the native thread has exited yet.
        # Keep its reference for the next action's isRunning() guard and shutdown.
        if summary is None:
            self._show_progress("Could not load benchmark history. Try Refresh Trends.")
            return

        noun = "benchmark" if summary.snapshot_count == 1 else "benchmarks"
        self._show_progress(f"{summary.snapshot_count} {noun} recorded · Last 7 days")

        self._populate_history_table(benchmarks)
        self._populate_metric_table(summary)
        self._populate_patterns(summary)

        # Load the latest full snapshot to compute sub-scores and display the full score dashboard
        from losshound.core.benchmark import get_latest_snapshot
        from losshound.core.scoring import score_snapshot
        
        latest_snap = get_latest_snapshot()
        if latest_snap:
            try:
                score = score_snapshot(latest_snap)
                self._display_score(score)
            except Exception as exc:
                logger.warning("Failed to score latest snapshot on trends done: %s", exc)
        elif summary.current_score is not None:
            grade = "A" if summary.current_score >= 90 else (
                "B" if summary.current_score >= 75 else (
                    "C" if summary.current_score >= 60 else (
                        "D" if summary.current_score >= 40 else "F"
                    )
                )
            )
            self._set_overall(summary.current_score, grade, "Last benchmark")

    def _populate_history_table(self, benchmarks: list[dict]):
        """Fill the history table with benchmark entries."""
        # Show most recent 30
        entries = benchmarks[-30:]
        entries.reverse()  # newest first

        self._history_table.setRowCount(len(entries))
        for row, b in enumerate(entries):
            ts = self._display_time(b.get("timestamp", ""))
            label = b.get("label", "--") or "--"
            score_val = b.get("overall_score")
            grade = b.get("grade") or "--"
            lat = f"{b['avg_latency_ms']:.1f}ms" if b.get("avg_latency_ms") is not None else "--"
            jit = f"{b['avg_jitter_ms']:.1f}ms" if b.get("avg_jitter_ms") is not None else "--"
            loss = f"{b['avg_loss_pct']:.1f}%" if b.get("avg_loss_pct") is not None else "--"

            items = [
                QTableWidgetItem(ts),
                QTableWidgetItem(label),
                QTableWidgetItem(f"{score_val:.0f}" if score_val is not None else "--"),
                QTableWidgetItem(grade),
                QTableWidgetItem(lat),
                QTableWidgetItem(jit),
                QTableWidgetItem(loss),
            ]

            # Color the score
            if score_val is not None:
                color = self._score_color(score_val)
                from PySide6.QtGui import QColor
                items[2].setForeground(QColor(color))
                items[3].setForeground(QColor(color))

            for col, item in enumerate(items):
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._history_table.setItem(row, col, item)
        self._history_empty.setVisible(not entries)
        self._fit_table(self._history_table, max_rows=5)

    def _populate_metric_table(self, summary: TrendSummary):
        """Fill the metric trend table."""
        metrics = list(summary.metric_summaries.values())
        self._metric_table.setRowCount(len(metrics))

        from PySide6.QtGui import QColor
        colors = {"improving": "#75c884", "degrading": "#e06363", "stable": "#aebbc6"}
        names = {"latency": "Latency (ms)", "jitter": "Jitter (ms)", "loss": "Packet loss (%)",
                 "dns": "DNS (ms)", "tcp": "TCP connect (ms)", "score": "Score (/100)"}

        for row, mt in enumerate(metrics):
            cur = f"{mt.current:.1f}" if mt.current is not None else "--"
            items = [
                QTableWidgetItem(names.get(mt.metric, mt.metric.capitalize())),
                QTableWidgetItem(cur),
                QTableWidgetItem(f"{mt.average:.1f}"),
                QTableWidgetItem(f"{mt.best:.1f}"),
                QTableWidgetItem(f"{mt.worst:.1f}"),
                QTableWidgetItem(mt.trend_direction.capitalize() if summary.snapshot_count > 1 else "Baseline"),
            ]

            items[5].setForeground(QColor(colors.get(mt.trend_direction, "#aebbc6")))

            for col, item in enumerate(items):
                if col >= 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._metric_table.setItem(row, col, item)
        self._metric_empty.setVisible(not metrics)
        self._fit_table(self._metric_table)

    def _populate_patterns(self, summary: TrendSummary):
        """Summarize patterns without an empty panel or unsupported HTML boxes."""
        if summary.patterns:
            lines = []
            for pattern in summary.patterns:
                lines.append(
                    f"<b>{escape(pattern.metric.upper())}</b> · {escape(pattern.description)} "
                    f"<span style='color: #90a4b2;'>(confidence {pattern.confidence:.0%})</span>"
                )
            text = "<br/><br/>".join(lines)
        elif summary.snapshot_count >= 5:
            text = "<b>No concerning patterns detected</b> · Based on the recorded benchmarks."
        elif summary.snapshot_count:
            needed = 5 - summary.snapshot_count
            text = (
                f"<b>Building your baseline</b> · {summary.snapshot_count} of 5 benchmarks recorded. "
                f"Run {needed} more over time to look for patterns."
            )
        else:
            text = "<b>Start a baseline</b> · Benchmarks taken over time help reveal changes in your connection."
        self._patterns_label.setText(text)
        self._patterns_label.setStyleSheet(
            "padding: 12px 16px; font-size: 13px; color: #aebbc6; "
            "background: #101a20; border: none; border-left: 2px solid #62c7d8;"
        )
