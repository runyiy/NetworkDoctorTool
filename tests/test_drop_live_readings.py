"""Live Drop readings must arrive before completion without stale success states."""
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta
from types import SimpleNamespace

from PySide6.QtWidgets import QApplication

from losshound.core.drop_analyzer import ConnSample, DropAnalysisReport
from losshound.gui import drop_tab


def _sample(**changes):
    return replace(ConnSample(
        datetime(2026, 9, 5, 13, 0, 0), True, "ethernet", 1000,
        0, "", 0, True, 1.5, True, 35.0, False,
    ), **changes)


def _pump_until(app, condition):
    deadline = time.monotonic() + 2
    while not condition() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.001)
    assert condition()


def test_live_samples_arrive_before_completion_and_restart_clears_results(monkeypatch):
    app = QApplication.instance() or QApplication([])
    allow_samples, finish = threading.Event(), threading.Event()
    samples = [_sample(), _sample(
        timestamp=datetime(2026, 9, 5, 13, 0, 3),
        wan_reachable=False, wan_rtt_ms=None, dns_ok=True, dns_checked=False,
    )]

    def analysis(**kwargs):
        allow_samples.wait(3)
        for sample in samples:
            kwargs["sample_callback"](sample)
        finish.wait(3)
        return DropAnalysisReport(
            3, "ethernet", 2, samples, [], [], "Controlled final report", "low", [], [], None,
        )

    monkeypatch.setattr(drop_tab, "detect_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(drop_tab, "run_drop_analysis", analysis)
    tab = drop_tab.DropTab()
    try:
        tab._on_start()
        worker = tab._worker
        _pump_until(app, lambda: tab._refresh_timer.isActive())
        assert "remaining" in tab._progress_bar.format()
        assert tab._progress_bar.maximum() == 120
        allow_samples.set()
        _pump_until(app, lambda: tab._timeline_table.rowCount() == 2)
        assert worker.isRunning()
        assert "2 samples" in tab._status_label.text()
        assert "LOST" in tab._cards["wan"].text()
        # A skipped DNS poll must not turn the previous failure green.
        assert "FAILED" in tab._cards["dns"].text()
        assert "13:00:00" in tab._cards["dns"].text()
        assert tab._cards["drops"].text().endswith("1")
        assert tab._timeline_table.item(1, 4).text() == "LOST"
        assert tab._verdict_label.text() == "Collecting live readings"
        tab.show_forensics_episode(SimpleNamespace(cause="isp"))
        assert "2 samples" in tab._status_label.text()
        assert "LOST" in tab._cards["wan"].text()
        finish.set()
        _pump_until(app, lambda: tab._worker is None)
        assert tab._status_label.text().startswith("Done — 2 samples")
        assert not tab._refresh_timer.isActive()
        assert tab._start_btn.isEnabled()
        assert tab._verdict_label.text() == "Controlled final report"

        allow_samples.clear()
        finish.clear()
        tab._on_start()
        _pump_until(app, lambda: tab._refresh_timer.isActive())
        assert tab._timeline_table.rowCount() == 0
        assert tab._sample_count == 0
        assert "Waiting for first sample" in tab._cards["wan"].text()
        assert tab._verdict_label.text() == "Collecting live readings"
        tab._on_stop()
        assert not tab._refresh_timer.isActive()
        assert tab._status_label.text() == "Stopping..."
        assert not tab._start_btn.isEnabled()
    finally:
        allow_samples.set()
        finish.set()
        tab.shutdown()
        app.processEvents()


def test_live_history_is_bounded_counts_episodes_and_finishing_keeps_controls_locked():
    app = QApplication.instance() or QApplication([])
    tab = drop_tab.DropTab()
    try:
        tab._reset_readings()
        tab._set_busy(True, "Monitoring...")
        for i in range(45):
            tab._on_sample(_sample(
                timestamp=datetime(2026, 9, 5, 13, 0, 0) + timedelta(seconds=i),
                wan_reachable=i not in (1, 2, 7), dns_ok=True,
            ))
        assert tab._timeline_table.rowCount() == 40
        assert tab._timeline_table.item(0, 0).text() == "13:00:05"
        assert tab._sample_count == 45
        assert tab._cards["drops"].text().endswith("2")
        tab._scan_clock = SimpleNamespace(isValid=lambda: True, elapsed=lambda: 121000)
        tab._refresh_countdown()
        assert "Finishing current check" in tab._progress_bar.format()
        assert not tab._start_btn.isEnabled()
        assert tab._stop_btn.isEnabled()
    finally:
        tab.shutdown()
        app.processEvents()


def test_final_dns_counts_only_real_checks_and_empty_scan_has_no_success_claim():
    app = QApplication.instance() or QApplication([])
    tab = drop_tab.DropTab()
    try:
        samples = [_sample(dns_ok=True), _sample(dns_checked=False)]
        report = DropAnalysisReport(3, "ethernet", 2, samples, [], [], "No drops", "low", [], [], None)
        tab._display_report(report)
        assert tab._cards["dns"].text() == "DNS\nOK (1/1 checks)"
        tab._display_report(replace(report, total_samples=0, samples=[], verdict="Insufficient data"))
        assert "No samples" in tab._cards["wan"].text()
        assert "Not checked" in tab._cards["dns"].text()
        assert "No issues found" not in tab._recs_label.text()
    finally:
        tab.shutdown()
        app.processEvents()
