"""Optimizer tab — one-click network performance tuning with DNS benchmarking."""

from __future__ import annotations

import logging
from dataclasses import asdict
from functools import partial

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QProgressBar, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from losshound.core.benchmark import (
    BenchmarkReport,
    BenchmarkSnapshot,
    compare_snapshots,
    get_latest_snapshot,
    run_benchmark,
    save_snapshot,
)
from losshound.core.dns_bench import DnsBenchmarkResult
from losshound.core.optimizer import (
    NetworkOptimizer, OptimizeReport, OptimizeResult,
)
from losshound.gui.widgets import TelemetryHeader
from losshound.gui.diagnostic_widgets import ReadingTile, compact_table, page_style, style_action
from losshound.gui.optimization_preview import OptimizationPreview

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------

class _DnsBenchmarkWorker(QThread):
    """Run DNS benchmark in a background thread."""

    finished = Signal(list)  # list[DnsBenchmarkResult]
    progress = Signal(str)

    def run(self):
        try:
            opt = NetworkOptimizer()
            self.progress.emit("Benchmarking DNS servers...")
            results = opt.benchmark_dns()
            self.finished.emit(results)
        except Exception as exc:
            logger.error("DNS benchmark failed: %s", exc)
            self.finished.emit([])


class _OptimizeWorker(QThread):
    """Run full optimization in a background thread."""

    finished = Signal(object)  # OptimizeReport
    progress = Signal(str)

    def __init__(
        self,
        skip_dns: bool = False,
        skip_mtu: bool = False,
        apply_dns: bool = False,
        optimize_eee: bool = False,
        optimize_rsc: bool = False,
        optimize_lso: bool = False,
    ):
        super().__init__()
        self._skip_dns = skip_dns
        self._skip_mtu = skip_mtu
        self._apply_dns = apply_dns
        self._optimize_eee = optimize_eee
        self._optimize_rsc = optimize_rsc
        self._optimize_lso = optimize_lso

    def run(self):
        try:
            opt = NetworkOptimizer()
            self.progress.emit("Creating backup...")
            self.progress.emit("Optimizing network stack...")
            report = opt.optimize_all(
                skip_dns=self._skip_dns,
                skip_mtu=self._skip_mtu,
                apply_dns=self._apply_dns,
                optimize_eee=self._optimize_eee,
                optimize_rsc=self._optimize_rsc,
                optimize_lso=self._optimize_lso,
            )
            self.finished.emit(report)
        except Exception as exc:
            logger.error("Optimization failed: %s", exc)
            self.finished.emit(None)


class _RestoreWorker(QThread):
    """Restore settings from backup in a background thread."""

    finished = Signal(list)  # list[OptimizeResult]
    progress = Signal(str)

    def run(self):
        try:
            opt = NetworkOptimizer()
            self.progress.emit("Restoring backup...")
            results = opt.restore_backup()
            self.finished.emit(results)
        except Exception as exc:
            logger.error("Restore failed: %s", exc)
            self.finished.emit([])


class _BenchmarkWorker(QThread):
    """Run network benchmark in a background thread."""

    finished = Signal(object)  # BenchmarkSnapshot
    progress = Signal(str)

    def __init__(self, label: str = "snapshot"):
        super().__init__()
        self._label = label

    def run(self):
        try:
            snapshot = run_benchmark(
                label=self._label,
                ping_count=20,
                progress_callback=lambda msg: self.progress.emit(msg),
            )
            save_snapshot(snapshot)
            self.finished.emit(snapshot)
        except Exception as exc:
            logger.error("Benchmark failed: %s", exc)
            self.finished.emit(None)


class _StatusWorker(QThread):
    """Fetch current optimization status in background."""

    finished = Signal(dict)

    def run(self):
        try:
            opt = NetworkOptimizer()
            status = opt.get_optimization_status()
            self.finished.emit(status)
        except Exception as exc:
            logger.error("Status check failed: %s", exc)
            self.finished.emit({})


class _AutoTuneResponsivenessWorker(QThread):
    """Run System Responsiveness benchmarking in a background thread."""

    finished = Signal(tuple)  # tuple[int, dict[int, tuple[float, float]]]
    progress = Signal(str)

    def run(self):
        try:
            opt = NetworkOptimizer()
            best_val, results = opt.benchmark_optimal_responsiveness(
                progress_callback=lambda msg: self.progress.emit(msg)
            )
            self.finished.emit((best_val, results))
        except Exception as exc:
            logger.error("Auto-tuning responsiveness failed: %s", exc)
            self.finished.emit((20, {}))


# ---------------------------------------------------------------------------
# Optimizer Tab
# ---------------------------------------------------------------------------

class OptimizerTab(QWidget):
    """Network performance optimizer tab."""

    def shutdown(self):
        from losshound.gui._shutdown import stop_qthread
        stop_qthread(getattr(self, "_worker", None))

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content.setObjectName("optimizer-page")
        content.setStyleSheet(page_style("optimizer-page"))
        main_layout = QVBoxLayout(content)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        main_layout.addWidget(TelemetryHeader(
            "Network Performance Optimizer",
            "Tune TCP/IP, benchmark DNS, optimize MTU, and manage Windows throttling from one console.",
            "OPTIMIZER",
            "ADMIN READY" if NetworkOptimizer.check_admin() else "LIMITED",
            "#62c7d8",
        ))

        # --- Admin status ---
        self._admin_label = QLabel()
        self._admin_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._admin_label.setWordWrap(True)
        main_layout.addWidget(self._admin_label)
        self._update_admin_label()

        # --- Action buttons ---
        btn_group = QWidget()
        btn_layout = QGridLayout(btn_group)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(10)
        btn_layout.addWidget(QLabel("Measure"), 0, 0)
        btn_layout.addWidget(QLabel("Settings"), 1, 0)
        btn_layout.setColumnStretch(5, 1)

        self._optimize_btn = QPushButton("Review Changes…")
        style_action(self._optimize_btn, "primary")
        self._optimize_btn.clicked.connect(self._on_optimize_all)
        btn_layout.addWidget(self._optimize_btn, 1, 1, Qt.AlignmentFlag.AlignLeft)

        self._dns_bench_btn = QPushButton("Benchmark DNS")
        style_action(self._dns_bench_btn)
        self._dns_bench_btn.clicked.connect(self._on_dns_benchmark)
        btn_layout.addWidget(self._dns_bench_btn, 0, 4, Qt.AlignmentFlag.AlignLeft)

        self._restore_btn = QPushButton("Revert All Changes")
        style_action(self._restore_btn, "danger")
        self._restore_btn.setToolTip(
            "Undo ALL optimizations and restore your original network settings"
        )
        self._restore_btn.clicked.connect(self._on_restore)
        btn_layout.addWidget(self._restore_btn, 1, 3, Qt.AlignmentFlag.AlignLeft)

        self._status_btn = QPushButton("Check Status")
        style_action(self._status_btn)
        self._status_btn.clicked.connect(self._on_check_status)
        btn_layout.addWidget(self._status_btn, 1, 2, Qt.AlignmentFlag.AlignLeft)

        # Row 2: Benchmark buttons
        self._bench_before_btn = QPushButton("Benchmark Before")
        style_action(self._bench_before_btn)
        self._bench_before_btn.setToolTip(
            "Run a full network benchmark BEFORE optimization to measure baseline"
        )
        self._bench_before_btn.clicked.connect(lambda: self._on_benchmark("before"))
        btn_layout.addWidget(self._bench_before_btn, 0, 1, Qt.AlignmentFlag.AlignLeft)

        self._bench_after_btn = QPushButton("Benchmark After")
        style_action(self._bench_after_btn)
        self._bench_after_btn.setToolTip(
            "Run a full network benchmark AFTER optimization to measure improvement"
        )
        self._bench_after_btn.clicked.connect(lambda: self._on_benchmark("after"))
        btn_layout.addWidget(self._bench_after_btn, 0, 2, Qt.AlignmentFlag.AlignLeft)
        self._compare_btn = QPushButton("Compare Before vs After")
        style_action(self._compare_btn)
        self._compare_btn.setToolTip("Compare your before and after benchmarks")
        self._compare_btn.clicked.connect(self._on_compare)
        btn_layout.addWidget(self._compare_btn, 0, 3, Qt.AlignmentFlag.AlignLeft)

        main_layout.addWidget(btn_group)

        # --- Responsiveness controls ---
        resp_group = QGroupBox("System responsiveness")
        resp_layout = QHBoxLayout(resp_group)
        resp_layout.setSpacing(12)

        resp_layout.addWidget(QLabel("Profile"))
        self._resp_combo = QComboBox()
        self._resp_combo.addItem("20% - Standard (Default)", 20)
        self._resp_combo.addItem("10% - Optimized (Gaming/Multimedia)", 10)
        self._resp_combo.addItem("0% - Pure Latency Priority", 0)
        self._resp_combo.setMinimumHeight(36)
        self._resp_combo.setMaximumWidth(360)
        self._resp_combo.setStyleSheet("""
            QComboBox {
                background: #141822;
                border: 1px solid #20293a;
                border-radius: 0px;
                padding: 4px 8px;
                color: #d8dee9;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #141822;
                border: 1px solid #20293a;
                selection-background-color: #20293a;
                color: #d8dee9;
            }
        """)
        resp_layout.addWidget(self._resp_combo)

        self._resp_apply_btn = QPushButton("Apply Selected Profile")
        style_action(self._resp_apply_btn, "primary")
        self._resp_apply_btn.clicked.connect(self._on_apply_responsiveness)
        resp_layout.addWidget(self._resp_apply_btn)

        self._resp_autotune_btn = QPushButton("Auto-Tune Profile")
        style_action(self._resp_autotune_btn)
        self._resp_autotune_btn.setToolTip("Benchmark latency and jitter for 20%, 10%, and 0% to find the optimal setting for your network stack")
        self._resp_autotune_btn.clicked.connect(self._on_autotune_responsiveness)
        resp_layout.addWidget(self._resp_autotune_btn)
        resp_layout.addStretch()

        main_layout.addWidget(resp_group)

        # --- Advanced Adapter Tweaks Group ---
        adapter_group = QGroupBox("Optional adapter changes")
        adapter_layout = QVBoxLayout(adapter_group)
        adapter_layout.setSpacing(8)
        adapter_hint = QLabel("Selected options are included in Review Changes before you apply them.")
        adapter_hint.setWordWrap(True)
        adapter_layout.addWidget(adapter_hint)

        cb_style = """
            QCheckBox {
                color: #d8dee9;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                background-color: #141822;
                border: 1px solid #20293a;
            }
            QCheckBox::indicator:checked {
                background-color: #75c884;
                border: 1px solid #75c884;
            }
            QCheckBox::indicator:hover {
                border: 1px solid #75c884;
            }
        """

        self._eee_checkbox = QCheckBox("Disable Energy Efficient Ethernet (EEE)")
        self._eee_checkbox.setToolTip("Keeps physical ethernet link active, preventing power-state latency. (Reboot recommended)")
        self._eee_checkbox.setStyleSheet(cb_style)
        adapter_layout.addWidget(self._eee_checkbox)

        self._rsc_checkbox = QCheckBox("Disable Receive Segment Coalescing (RSC)")
        self._rsc_checkbox.setToolTip("Disables hardware packet buffering to reduce processing delay and jitter.")
        self._rsc_checkbox.setStyleSheet(cb_style)
        adapter_layout.addWidget(self._rsc_checkbox)

        self._lso_checkbox = QCheckBox("Disable Large Send Offload (LSO)")
        self._lso_checkbox.setToolTip("Prevents the network adapter driver from batching outbound packets, ensuring immediate transmission.")
        self._lso_checkbox.setStyleSheet(cb_style)
        adapter_layout.addWidget(self._lso_checkbox)

        main_layout.addWidget(adapter_group)

        # --- Progress ---
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # indeterminate
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFormat("Idle")
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(4)
        self._progress_bar.hide()
        self._status_label = QLabel("Ready to check settings or run a benchmark")
        self._status_label.setTextFormat(Qt.TextFormat.PlainText)
        self._status_label.setWordWrap(True)
        main_layout.insertWidget(main_layout.indexOf(btn_group) + 1, self._status_label)
        main_layout.insertWidget(main_layout.indexOf(btn_group) + 2, self._progress_bar)

        # --- Current status cards ---
        status_group = QGroupBox("Current settings")
        self._status_grid = QGridLayout(status_group)
        self._status_grid.setSpacing(12)

        self._status_cards: dict[str, ReadingTile] = {}
        card_defs = [
            ("admin", "Privileges"),
            ("tcp_tuning", "TCP Auto-Tuning"),
            ("congestion", "Congestion Provider"),
            ("ecn", "ECN"),
            ("rss", "RSS"),
            ("heuristics", "TCP Heuristics"),
            ("responsiveness", "System Responsiveness"),
            ("dns", "DNS Servers"),
            ("mtu", "MTU"),
            ("throttling", "Network Throttling"),
        ]
        for i, (key, label) in enumerate(card_defs):
            card = ReadingTile(label)
            self._status_cards[key] = card
            row, col = divmod(i, 4)
            self._status_grid.addWidget(card, row, col)

        main_layout.addWidget(status_group)

        # --- DNS Benchmark results table ---
        dns_group = QGroupBox("DNS benchmark results")
        dns_layout = QVBoxLayout(dns_group)
        self._dns_empty = QLabel("Benchmark DNS to compare response time and reliability across providers.")
        self._dns_empty.setWordWrap(True)
        dns_layout.addWidget(self._dns_empty)
        self._dns_table = QTableWidget(0, 6)
        self._dns_table.setHorizontalHeaderLabels([
            "Rank", "Server", "Provider", "Avg (ms)", "Min (ms)", "Success %",
        ])
        self._dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._dns_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._dns_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._dns_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._dns_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._dns_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._dns_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._dns_table.verticalHeader().setVisible(False)
        self._dns_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._dns_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        compact_table(self._dns_table, self._dns_empty)
        self._dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._dns_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._dns_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        dns_layout.addWidget(self._dns_table)
        main_layout.addWidget(dns_group)

        # --- Optimization results table ---
        results_group = QGroupBox("Optimization results")
        results_layout = QVBoxLayout(results_group)
        self._results_empty = QLabel("Applied, skipped, and failed changes appear here after an optimization.")
        self._results_empty.setWordWrap(True)
        results_layout.addWidget(self._results_empty)

        self._results_table = QTableWidget(0, 5)
        self._results_table.setHorizontalHeaderLabels([
            "Optimization", "Status", "Before", "After", "Note",
        ])
        self._results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        compact_table(self._results_table, self._results_empty)
        results_layout.addWidget(self._results_table)
        main_layout.addWidget(results_group)

        # --- Benchmark comparison table ---
        bench_group = QGroupBox("Before and after comparison")
        bench_layout = QVBoxLayout(bench_group)

        self._bench_table = QTableWidget(0, 4)
        self._bench_table.setHorizontalHeaderLabels([
            "Metric", "Before", "After", "Change",
        ])
        self._bench_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._bench_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._bench_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._bench_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._bench_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._bench_table.verticalHeader().setVisible(False)
        self._bench_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._bench_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        bench_layout.addWidget(self._bench_table)

        self._bench_summary_label = QLabel("")
        self._bench_summary_label.setWordWrap(True)
        self._bench_summary_label.setStyleSheet(
            "padding: 8px; font-size: 13px; color: #d8dee9;"
        )
        bench_layout.addWidget(self._bench_summary_label)
        # The summary also explains partially completed comparisons.
        compact_table(self._bench_table, None)
        self._bench_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        main_layout.addWidget(bench_group)
        for group in content.findChildren(QGroupBox):
            group.layout().setContentsMargins(0, 4, 0, 0)

        main_layout.addStretch()

        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        # Initial status check
        self._on_check_status()
        self._update_bench_display()
        self._load_saved_optimization_results()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_admin_label(self):
        is_admin = NetworkOptimizer.check_admin()
        if is_admin:
            self._admin_label.setText("Administrator session · network setting changes are available.")
            self._admin_label.setStyleSheet(
                "color: #75c884; padding: 10px 14px; background: #101a20; border-left: 2px solid #62c7d8;"
            )
        else:
            self._admin_label.setText(
                "Standard user session · diagnostics and previews are available. Applying settings requires Administrator."
            )
            self._admin_label.setStyleSheet(
                "color: #b7c4cc; padding: 10px 14px; background: #101a20; border-left: 2px solid #62c7d8;"
            )

    def _show_progress(self, message: str):
        self._status_label.setText(message)
        self._progress_bar.setFormat(message)

    def _set_busy(self, busy: bool, message: str = ""):
        """Toggle button states and progress bar."""
        self._optimize_btn.setEnabled(not busy)
        self._dns_bench_btn.setEnabled(not busy)
        self._restore_btn.setEnabled(not busy)
        self._status_btn.setEnabled(not busy)
        self._bench_before_btn.setEnabled(not busy)
        self._bench_after_btn.setEnabled(not busy)
        self._compare_btn.setEnabled(not busy)
        self._resp_combo.setEnabled(not busy)
        self._resp_apply_btn.setEnabled(not busy)
        self._resp_autotune_btn.setEnabled(not busy)
        for checkbox in (self._eee_checkbox, self._rsc_checkbox, self._lso_checkbox):
            checkbox.setEnabled(not busy)
        self._show_progress(message or ("Working..." if busy else "Ready"))
        self._progress_bar.setVisible(busy)

        if busy:
            self._progress_bar.setRange(0, 0)  # indeterminate
            self._progress_bar.setFormat(message or "Working...")
        else:
            self._progress_bar.setRange(0, 1)
            self._progress_bar.setValue(1)
            self._progress_bar.setFormat(message or "Done")

    def _update_status_card(self, key: str, title: str, value: str, status: str = "neutral"):
        card = self._status_cards.get(key)
        if not card:
            return

        colors = {
            "healthy": "#75c884",
            "warning": "#d9b65f",
            "error": "#e06363",
            "neutral": "#d8dee9",
        }
        color = colors.get(status, "#d8dee9")
        card.set_reading(title, value, color)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_optimize_all(self):
        if self._worker is not None and self._worker.isRunning():
            return  # already running, ignore the click
        # Freeze the reviewed selection before entering the modal event loop.
        options = dict(
            optimize_eee=self._eee_checkbox.isChecked(),
            optimize_rsc=self._rsc_checkbox.isChecked(),
            optimize_lso=self._lso_checkbox.isChecked(),
        )
        preview = OptimizationPreview(
            options, is_admin=NetworkOptimizer.check_admin(), parent=self,
        )
        accepted = preview.exec() == QDialog.DialogCode.Accepted
        preview.deleteLater()
        if not accepted or not NetworkOptimizer.check_admin():
            return

        self._set_busy(True, "Optimizing network...")
        self._worker = _OptimizeWorker(
            skip_dns=True, apply_dns=False, skip_mtu=False, **options,
        )
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_optimize_done)
        self._worker.start()

    def _on_optimize_done(self, report: OptimizeReport | None):
        self._worker = None
        if report is None:
            self._set_busy(False, "Optimization failed")
            QMessageBox.warning(self, "Error", "Optimization failed. Check logs for details.")
            return

        self._set_busy(False, report.summary)
        self._populate_results_table(report.results)
        self._save_optimization_results(report.results)
        self._on_check_status()  # refresh status cards

        QMessageBox.information(
            self, "Optimization Complete",
            f"{report.summary}\n\n"
            "Review the results above. Revert All Changes uses the saved original backup; "
            "check its results for any settings that could not be restored.",
        )

    def _on_dns_benchmark(self):
        if self._worker is not None and self._worker.isRunning():
            return  # already running, ignore the click
        self._set_busy(True, "Benchmarking DNS servers...")
        self._worker = _DnsBenchmarkWorker()
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_dns_benchmark_done)
        self._worker.start()

    def _on_dns_benchmark_done(self, results: list[DnsBenchmarkResult]):
        self._worker = None
        if not results:
            self._set_busy(False, "DNS benchmark failed")
            return

        self._set_busy(False, f"DNS benchmark complete — fastest: {results[0].name}")
        self._populate_dns_table(results)

    def _on_restore(self):
        if self._worker is not None and self._worker.isRunning():
            return  # already running, ignore the click
        reply = QMessageBox.question(
            self, "Revert All Changes",
            "Restore the network settings recorded in the original backup?\n\n"
            "This can replace changes made since that backup, including DNS, TCP/IP, "
            "MTU, and adapter settings. It is not limited to the latest batch.\n\n"
            "Administrator privileges are required for most settings. Review the "
            "results for skipped or failed restores; some settings need a reboot.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._set_busy(True, "Reverting all changes...")
        self._worker = _RestoreWorker()
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_restore_done)
        self._worker.start()

    def _on_restore_done(self, results: list[OptimizeResult]):
        self._worker = None
        if not results:
            self._set_busy(False, "Revert failed — no backup found")
            QMessageBox.warning(
                self, "Revert",
                "No backup found. You need to run Optimize first before you can revert.",
            )
            return

        succeeded = sum(1 for r in results if r.success)
        skipped = sum(
            1 for r in results
            if not r.success and r.needs_admin and r.error and "Administrator" in r.error
        )
        self._set_busy(False, f"Reverted {succeeded}/{len(results)} settings")
        self._populate_results_table(results)
        self._save_optimization_results(results)
        self._on_check_status()

        msg = f"Reverted {succeeded}/{len(results)} settings to their original values."
        if skipped:
            msg += f"\n\n{skipped} settings could not be reverted (requires Administrator)."
        QMessageBox.information(self, "Revert Complete", msg)

    def _on_check_status(self):
        if self._worker is not None and self._worker.isRunning():
            return  # already running, ignore the click
        self._show_progress("Reading current network settings...")
        self._worker = _StatusWorker()
        self._worker.finished.connect(self._on_status_done)
        self._worker.start()

    def _on_status_done(self, status: dict):
        # Result delivery can precede run() returning. Keep the worker until
        # the next action replaces it after isRunning() becomes false.
        if not status:
            self._show_progress("Could not read settings. Try Check Status again.")
            return
        self._show_progress("Current settings updated")

        # Admin
        is_admin = status.get("admin", False)
        self._update_status_card(
            "admin", "Privileges",
            "Administrator" if is_admin else "Standard User",
            "healthy" if is_admin else "warning",
        )

        # TCP settings
        tcp = status.get("tcp", {})

        tuning = tcp.get("auto_tuning_level", "unknown")
        self._update_status_card(
            "tcp_tuning", "TCP Auto-Tuning", tuning,
            "healthy" if tuning.lower() == "normal" else "warning",
        )

        congestion = tcp.get("congestion_provider", "unknown")
        self._update_status_card(
            "congestion", "Congestion Provider", congestion,
            "healthy" if "ctcp" in congestion.lower() else "neutral",
        )

        ecn = tcp.get("ecn_capability", "unknown")
        self._update_status_card(
            "ecn", "ECN", ecn,
            "healthy" if ecn.lower() == "enabled" else "neutral",
        )

        rss = tcp.get("rss", "unknown")
        self._update_status_card(
            "rss", "RSS", rss,
            "healthy" if rss.lower() == "enabled" else "neutral",
        )

        # DNS
        primary = status.get("dns_primary", "")
        secondary = status.get("dns_secondary", "")
        dns_text = primary or "auto"
        if secondary:
            dns_text += f"\n{secondary}"
        self._update_status_card("dns", "DNS Servers", dns_text, "neutral")

        # MTU
        mtu = status.get("mtu", 1500)
        self._update_status_card(
            "mtu", "MTU", str(mtu),
            "healthy" if 1400 <= mtu <= 1500 else "warning",
        )

        # Throttling
        throttling = status.get("network_throttling_index")
        if throttling is None:
            thr_text = "default"
            thr_status = "warning"
        elif throttling == 0xFFFFFFFF or throttling == -1:
            thr_text = "disabled"
            thr_status = "healthy"
        else:
            thr_text = f"enabled ({throttling})"
            thr_status = "warning"
        self._update_status_card("throttling", "Network Throttling", thr_text, thr_status)

        # TCP Heuristics
        heuristics = status.get("tcp_heuristics", "unknown")
        heur_status = "healthy" if heuristics == "disabled" else "neutral"
        self._update_status_card("heuristics", "TCP Heuristics", heuristics, heur_status)

        # System Responsiveness
        responsiveness = status.get("system_responsiveness")
        if responsiveness is None:
            resp_text = "default (20%)"
            resp_status = "neutral"
        else:
            resp_text = f"{responsiveness}%"
            resp_status = "healthy" if responsiveness == 10 else ("warning" if responsiveness == 0 else "neutral")
        self._update_status_card("responsiveness", "System Responsiveness", resp_text, resp_status)

        if responsiveness is not None:
            idx = self._resp_combo.findData(responsiveness)
            if idx >= 0:
                self._resp_combo.setCurrentIndex(idx)

        # Update advanced checkboxes from current status
        self._eee_checkbox.setChecked(status.get("eee_disabled") is True)
        self._rsc_checkbox.setChecked(status.get("rsc_disabled") is True)
        self._lso_checkbox.setChecked(status.get("lso_disabled") is True)

    # ------------------------------------------------------------------
    # Benchmark actions
    # ------------------------------------------------------------------

    def _on_benchmark(self, label: str):
        if self._worker is not None and self._worker.isRunning():
            return  # already running, ignore the click
        self._set_busy(True, f"Running {label} benchmark (this takes ~60s)...")
        self._active_benchmark_label = label
        self._worker = _BenchmarkWorker(label=label)
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_benchmark_done)
        self._worker.start()

    def _on_benchmark_done(self, snapshot: BenchmarkSnapshot | None):
        label = getattr(self, "_active_benchmark_label", "benchmark")
        self._worker = None
        if snapshot is None:
            self._set_busy(False, "Benchmark failed")
            QMessageBox.warning(self, "Benchmark", "Benchmark failed. Check logs.")
            return

        self._set_busy(
            False,
            f"{label.upper()} benchmark complete — "
            f"latency: {snapshot.avg_latency_ms:.1f}ms, "
            f"jitter: {snapshot.avg_jitter_ms:.1f}ms"
            if snapshot.avg_latency_ms and snapshot.avg_jitter_ms
            else f"{label.upper()} benchmark complete",
        )

        self._update_bench_display()

        msg = (
            f"Benchmark '{label}' saved!\n\n"
            f"  Avg latency:  {snapshot.avg_latency_ms:.1f} ms\n"
            f"  Avg jitter:   {snapshot.avg_jitter_ms:.1f} ms\n"
            f"  Avg loss:     {snapshot.avg_loss_pct:.1f}%\n"
            f"  Avg DNS:      {snapshot.avg_dns_ms:.1f} ms\n"
            f"  Avg TCP:      {snapshot.avg_tcp_ms:.1f} ms"
            if all(v is not None for v in [
                snapshot.avg_latency_ms, snapshot.avg_jitter_ms,
                snapshot.avg_loss_pct, snapshot.avg_dns_ms, snapshot.avg_tcp_ms,
            ])
            else f"Benchmark '{label}' saved!"
        )

        if label == "before":
            msg += "\n\nUse 'Review Changes' to inspect the proposed settings, then benchmark again if you apply them."
        elif label == "after":
            msg += "\n\nClick 'Compare Before vs After' to see the difference!"

        QMessageBox.information(self, "Benchmark Complete", msg)

    def _on_compare(self):
        before = get_latest_snapshot("before")
        after = get_latest_snapshot("after")

        if not before:
            QMessageBox.warning(
                self, "Compare",
                "No 'before' benchmark found.\n"
                "Click 'Benchmark BEFORE' first.",
            )
            return
        if not after:
            QMessageBox.warning(
                self, "Compare",
                "No 'after' benchmark found.\n"
                "Click 'Benchmark AFTER' first.",
            )
            return

        self._update_bench_display()

    def _update_bench_display(self):
        """Load latest snapshots and update comparison table."""
        before = get_latest_snapshot("before")
        after = get_latest_snapshot("after")

        if not before and not after:
            self._bench_table.setRowCount(0)
            self._bench_summary_label.setText("No benchmark data available. Run Benchmark BEFORE/AFTER to begin.")
            return

        def _fmt(val, suffix="ms"):
            return f"{val:.1f}{suffix}" if val is not None else "N/A"

        def _change(diff, pct, lower_better=True):
            if diff is None:
                return "", "neutral"
            sign = "+" if diff > 0 else ""
            text = f"{sign}{diff:.1f}ms ({sign}{pct:.1f}%)" if pct is not None else f"{sign}{diff:.1f}"
            if pct is not None and abs(pct) >= 2:
                if (diff < 0) == lower_better:
                    return text, "healthy"
                return text, "error"
            return text, "neutral"

        rows = []

        if before and after:
            report = compare_snapshots(before, after)
            b = report.before
            a = report.after
            d = report.delta

            rows = [
                ("Avg Latency", _fmt(b.avg_latency_ms), _fmt(a.avg_latency_ms),
                 *_change(d.latency_delta_ms, d.latency_pct_change)),
                ("Avg Jitter", _fmt(b.avg_jitter_ms), _fmt(a.avg_jitter_ms),
                 *_change(d.jitter_delta_ms, d.jitter_pct_change)),
                ("Avg Packet Loss", _fmt(b.avg_loss_pct, "%"), _fmt(a.avg_loss_pct, "%"),
                 *(lambda: (
                     f"{'+' if d.loss_delta_pct > 0 else ''}{d.loss_delta_pct:.1f}pp",
                     "healthy" if d.loss_delta_pct < -0.5 else ("error" if d.loss_delta_pct > 0.5 else "neutral"),
                 ) if d.loss_delta_pct is not None else ("N/A", "neutral"))()),
                ("Avg DNS Resolve", _fmt(b.avg_dns_ms), _fmt(a.avg_dns_ms),
                 *_change(d.dns_delta_ms, d.dns_pct_change)),
                ("Avg TCP Connect", _fmt(b.avg_tcp_ms), _fmt(a.avg_tcp_ms),
                 *_change(d.tcp_delta_ms, d.tcp_pct_change)),
            ]

            # Add per-target ping rows
            after_map = {p.target: p for p in a.ping_results}
            for bp in b.ping_results:
                ap = after_map.get(bp.target)
                b_ms = _fmt(bp.avg_ms)
                a_ms = _fmt(ap.avg_ms) if ap else "N/A"
                if bp.avg_ms is not None and ap and ap.avg_ms is not None:
                    diff = ap.avg_ms - bp.avg_ms
                    pct = (diff / bp.avg_ms * 100.0) if bp.avg_ms else 0
                    change_text, change_status = _change(diff, pct)
                else:
                    change_text, change_status = "N/A", "neutral"
                rows.append((f"  Ping {bp.target}", b_ms, a_ms, change_text, change_status))

            self._bench_summary_label.setText(f"Result: {report.summary}")
        else:
            # We have either only before or only after
            snap = before or after
            is_before = before is not None

            # Helper for individual values
            def get_val(metric_name):
                return getattr(snap, metric_name, None)

            rows = [
                ("Avg Latency", _fmt(get_val("avg_latency_ms")) if is_before else "N/A", "N/A" if is_before else _fmt(get_val("avg_latency_ms")), "", "neutral"),
                ("Avg Jitter", _fmt(get_val("avg_jitter_ms")) if is_before else "N/A", "N/A" if is_before else _fmt(get_val("avg_jitter_ms")), "", "neutral"),
                ("Avg Packet Loss", _fmt(get_val("avg_loss_pct"), "%") if is_before else "N/A", "N/A" if is_before else _fmt(get_val("avg_loss_pct"), "%"), "", "neutral"),
                ("Avg DNS Resolve", _fmt(get_val("avg_dns_ms")) if is_before else "N/A", "N/A" if is_before else _fmt(get_val("avg_dns_ms")), "", "neutral"),
                ("Avg TCP Connect", _fmt(get_val("avg_tcp_ms")) if is_before else "N/A", "N/A" if is_before else _fmt(get_val("avg_tcp_ms")), "", "neutral"),
            ]

            for p in snap.ping_results:
                p_val = _fmt(p.avg_ms)
                rows.append((
                    f"  Ping {p.target}",
                    p_val if is_before else "N/A",
                    "N/A" if is_before else p_val,
                    "",
                    "neutral"
                ))

            label_name = "BEFORE" if is_before else "AFTER"
            self._bench_summary_label.setText(
                f"Showing {label_name} benchmark from {snap.timestamp[:19].replace('T', ' ')}. "
                f"Run the other benchmark to see comparison."
            )

        colors = {
            "healthy": QColor("#75c884"),
            "error": QColor("#e06363"),
            "neutral": QColor("#aebbc6"),
        }

        self._bench_table.setRowCount(len(rows))
        for row_idx, (metric, before_val, after_val, change_text, status) in enumerate(rows):
            items = [
                QTableWidgetItem(metric),
                QTableWidgetItem(before_val),
                QTableWidgetItem(after_val),
                QTableWidgetItem(change_text),
            ]
            # Color the change column
            items[3].setForeground(colors.get(status, QColor("#aebbc6")))
            # Bold aggregate rows
            if not metric.startswith("  "):
                for item in items:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)

            for col, item in enumerate(items):
                if col > 0:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._bench_table.setItem(row_idx, col, item)

    # ------------------------------------------------------------------
    # Table population
    # ------------------------------------------------------------------

    def _populate_dns_table(self, results: list[DnsBenchmarkResult]):
        self._dns_table.setRowCount(len(results))
        for row, r in enumerate(results):
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            server_item = QTableWidgetItem(r.server)
            name_item = QTableWidgetItem(r.name)

            avg_item = QTableWidgetItem(
                f"{r.avg_ms:.1f}" if r.avg_ms != float("inf") else "N/A",
            )
            avg_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            min_item = QTableWidgetItem(
                f"{r.min_ms:.1f}" if r.min_ms != float("inf") else "N/A",
            )
            min_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            success_item = QTableWidgetItem(f"{r.success_rate * 100:.0f}%")
            success_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # Color-code the row based on ranking
            if row == 0:
                for item in (rank_item, server_item, name_item, avg_item, min_item, success_item):
                    item.setForeground(QColor("#75c884"))
            elif r.success_rate < 0.5:
                for item in (rank_item, server_item, name_item, avg_item, min_item, success_item):
                    item.setForeground(QColor("#e06363"))

            self._dns_table.setItem(row, 0, rank_item)
            self._dns_table.setItem(row, 1, server_item)
            self._dns_table.setItem(row, 2, name_item)
            self._dns_table.setItem(row, 3, avg_item)
            self._dns_table.setItem(row, 4, min_item)
            self._dns_table.setItem(row, 5, success_item)

    def _populate_results_table(self, results: list[OptimizeResult]):
        _STATUS_COLORS = {
            "Applied": QColor("#75c884"),
            "Verified": QColor("#62c7d8"),
            "No change": QColor("#aebbc6"),
            "Skipped": QColor("#d9b65f"),
            "Failed": QColor("#e06363"),
            "Unsupported": QColor("#d9b65f"),
            "Reboot required": QColor("#c98652"),
        }

        self._results_table.setRowCount(len(results))
        for row, r in enumerate(results):
            name_item = QTableWidgetItem(r.name)

            # Use the new status field; fall back to legacy logic for
            # results that haven't been migrated yet.
            status_text = r.status
            if not status_text:
                if r.success:
                    status_text = "Applied"
                elif r.needs_admin and r.error and "Administrator" in r.error:
                    status_text = "Skipped"
                else:
                    status_text = "Failed"

            color = _STATUS_COLORS.get(status_text, QColor("#aebbc6"))
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(color)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            before_item = QTableWidgetItem(r.before or "--")
            before_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            after_item = QTableWidgetItem(r.after or "--")
            after_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            note_item = QTableWidgetItem(r.note or r.error or "")

            self._results_table.setItem(row, 0, name_item)
            self._results_table.setItem(row, 1, status_item)
            self._results_table.setItem(row, 2, before_item)
            self._results_table.setItem(row, 3, after_item)
            self._results_table.setItem(row, 4, note_item)

    def _save_optimization_results(self, results: list[OptimizeResult]) -> None:
        try:
            import json
            from losshound.core.optimizer import _BACKUP_DIR
            _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            file_path = _BACKUP_DIR / "optimizer_results.json"
            data = [asdict(r) for r in results]
            with open(file_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as exc:
            logger.warning("Failed to save optimization results: %s", exc)

    def _load_saved_optimization_results(self):
        try:
            import json
            from losshound.core.optimizer import _BACKUP_DIR, OptimizeResult
            file_path = _BACKUP_DIR / "optimizer_results.json"
            if file_path.is_file():
                with open(file_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                results = [OptimizeResult(**r) for r in data]
                self._populate_results_table(results)
        except Exception as exc:
            logger.warning("Failed to load optimization results: %s", exc)

    def _on_apply_responsiveness(self):
        if not NetworkOptimizer.check_admin():
            QMessageBox.warning(
                self, "Admin Required",
                "Administrator privileges are required to change system responsiveness."
            )
            return

        val = self._resp_combo.currentData()
        reply = QMessageBox.question(
            self, "Change Responsiveness",
            f"Are you sure you want to change the System Responsiveness profile to {val}%?\n"
            "This will write directly to HKLM registry.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        opt = NetworkOptimizer()
        res = opt.apply_system_responsiveness(val)
        if res.success:
            QMessageBox.information(
                self, "Success",
                f"System Responsiveness successfully set to {val}%."
            )
        else:
            QMessageBox.warning(
                self, "Error",
                f"Failed to change responsiveness: {res.error or 'Unknown error'}"
            )
        self._on_check_status()

    def _on_autotune_responsiveness(self):
        if not NetworkOptimizer.check_admin():
            QMessageBox.warning(
                self, "Admin Required",
                "Administrator privileges are required to auto-tune system responsiveness."
            )
            return

        self._set_busy(True, "Starting auto-tune responsiveness benchmark...")
        self._worker = _AutoTuneResponsivenessWorker()
        self._worker.progress.connect(self._show_progress)
        self._worker.finished.connect(self._on_autotune_done)
        self._worker.start()

    def _on_autotune_done(self, result: tuple[int, dict[int, tuple[float, float]]]):
        self._worker = None
        best_val, results = result
        self._set_busy(False, "Auto-tune benchmark complete")

        if not results:
            QMessageBox.warning(
                self, "Auto-Tune Failed",
                "System responsiveness benchmarking failed or was interrupted."
            )
            return

        msg = "Responsiveness profile benchmark results:\n\n"
        for val, (avg_lat, jitter) in results.items():
            msg += f"  - Profile {val}%: Avg Latency = {avg_lat:.2f} ms, Jitter = {jitter:.2f} ms\n"

        msg += f"\nThe optimal profile based on RTT and jitter is: {best_val}%.\n\nDo you want to apply this optimal profile?"

        reply = QMessageBox.question(
            self, "Apply Auto-Tune Result",
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            opt = NetworkOptimizer()
            res = opt.apply_system_responsiveness(best_val)
            if res.success:
                QMessageBox.information(
                    self, "Success",
                    f"Successfully applied the optimal profile: {best_val}%."
                )
            else:
                QMessageBox.warning(
                    self, "Error",
                    f"Failed to apply the optimal profile: {res.error or 'Unknown error'}"
                )
            self._on_check_status()
