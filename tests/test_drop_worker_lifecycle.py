"""Drop Stop/results must not release or replace a running native thread."""
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication

from losshound.core.drop_analyzer import DropAnalysisReport
from losshound.gui import drop_tab


def _pump_until(app, condition):
    deadline = time.monotonic() + 2
    while not condition() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.001)
    assert condition()


@pytest.mark.parametrize("stop,result", [(True, "report"), (False, "report"), (False, "error")])
def test_drop_worker_owned_and_controls_disabled_until_native_exit(monkeypatch, stop, result):
    app = QApplication.instance() or QApplication([])
    release_result, release_exit = threading.Event(), threading.Event()
    monkeypatch.setattr(drop_tab, "detect_gateway", lambda: "192.168.1.1")

    def run(worker):
        release_result.wait(5)
        report = None if result == "error" else DropAnalysisReport(
            1.0, "ethernet", 0, [], [], [], "Insufficient data", "low", [], [], None,
        )
        signal = getattr(worker, "report_ready", worker.finished)
        signal.emit(report)
        release_exit.wait(5)

    monkeypatch.setattr(drop_tab._DropAnalyzeWorker, "run", run)
    tab = drop_tab.DropTab()
    tab._on_start()
    worker = tab._worker  # Keep broken code from aborting the test process.
    try:
        _pump_until(app, worker.isRunning)
        if stop:
            tab._on_stop()
            assert not tab._start_btn.isEnabled()
            assert not tab._stop_btn.isEnabled()
        release_result.set()
        expected = "Analysis failed — check logs" if result == "error" else "Insufficient data"
        _pump_until(app, lambda: tab._verdict_label.text() == expected)
        assert worker.isRunning()
        assert tab._worker is worker
        assert not tab._start_btn.isEnabled()
        tab._on_start()
        assert tab._worker is worker
    finally:
        release_result.set()
        release_exit.set()
        worker.wait(2000)
        app.processEvents()
        tab.shutdown()
    _pump_until(app, lambda: tab._worker is None)
    assert tab._start_btn.isEnabled()
    assert not tab._stop_btn.isEnabled()


def test_automatic_forensics_cannot_unlock_a_stopping_manual_scan(monkeypatch):
    app = QApplication.instance() or QApplication([])
    release = threading.Event()
    monkeypatch.setattr(drop_tab, "detect_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(drop_tab._DropAnalyzeWorker, "run", lambda worker: release.wait(5))
    tab = drop_tab.DropTab()
    displayed = []
    monkeypatch.setattr(tab, "_display_report", displayed.append)
    tab._on_start()
    worker = tab._worker
    try:
        _pump_until(app, worker.isRunning)
        tab._on_stop()
        tab.show_forensics_episode(SimpleNamespace(
            cause="isp", report=None, summary="Controlled automatic capture",
            confidence="low", gateway_ip="192.168.1.1", timeout_streak=2,
        ))
        assert not tab._start_btn.isEnabled()
        assert not tab._stop_btn.isEnabled()
        assert displayed == []
        tab._on_start()
        assert tab._worker is worker
    finally:
        release.set()
        worker.wait(2000)
        app.processEvents()
        tab.shutdown()


def test_shutdown_requests_cooperative_stop_and_retains_worker(monkeypatch):
    app = QApplication.instance() or QApplication([])
    stopped = threading.Event()
    monkeypatch.setattr(drop_tab, "detect_gateway", lambda: "192.168.1.1")

    def run(worker):
        deadline = time.monotonic() + 2
        while not worker.isInterruptionRequested() and time.monotonic() < deadline:
            time.sleep(0.001)
        stopped.set()

    monkeypatch.setattr(drop_tab._DropAnalyzeWorker, "run", run)
    tab = drop_tab.DropTab()
    tab._on_start()
    worker = tab._worker
    _pump_until(app, worker.isRunning)
    tab.shutdown()
    assert stopped.is_set()
    assert not worker.isRunning()
    app.processEvents()
    assert tab._worker is None


def test_repeated_start_stop_cycles_use_distinct_workers(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(drop_tab, "detect_gateway", lambda: "192.168.1.1")

    def analysis(**kwargs):
        deadline = time.monotonic() + 2
        while not kwargs["stop_check"]() and time.monotonic() < deadline:
            time.sleep(0.001)
        return DropAnalysisReport(0.1, "ethernet", 0, [], [], [], "Insufficient data", "low", [], [], None)

    monkeypatch.setattr(drop_tab, "run_drop_analysis", analysis)
    tab = drop_tab.DropTab()
    try:
        previous = None
        for _ in range(3):
            tab._on_start()
            worker = tab._worker
            assert worker is not previous
            _pump_until(app, worker.isRunning)
            tab._on_stop()
            tab._on_stop()
            _pump_until(app, lambda: tab._worker is None)
            assert tab._start_btn.isEnabled()
            assert tab._progress_bar.format().startswith("Stopped")
            previous = worker
    finally:
        tab.shutdown()
