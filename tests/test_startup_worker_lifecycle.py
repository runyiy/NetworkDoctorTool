"""Startup query results must not release a QThread before run() exits."""
import os
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from losshound.gui.optimizer_tab import OptimizerTab, _StatusWorker
from losshound.gui.score_tab import ScoreTab, _TrendsWorker


@pytest.mark.parametrize("kind", ["status", "trends"])
def test_startup_query_retains_worker_during_result_delivery(tmp_path, monkeypatch, kind):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    release = threading.Event()
    received = []
    tab_type, worker_type, handler, refresh = (
        (OptimizerTab, _StatusWorker, "_on_status_done", "_on_check_status")
        if kind == "status"
        else (ScoreTab, _TrendsWorker, "_on_trends_done", "_on_refresh_trends")
    )
    original_handler = getattr(tab_type, handler)

    def on_result(tab, *args):
        original_handler(tab, *args)
        received.append(True)

    def run(worker):
        worker.finished.emit({}) if kind == "status" else worker.finished.emit(None, [])
        release.wait(5)

    monkeypatch.setattr(tab_type, handler, on_result)
    monkeypatch.setattr(worker_type, "run", run)
    tab = tab_type()
    worker = tab._worker
    try:
        deadline = time.monotonic() + 2
        while not received and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.001)
        assert received
        assert worker.isRunning()
        assert tab._worker is worker
        getattr(tab, refresh)()
        assert tab._worker is worker
    finally:
        release.set()
        worker.wait(2000)
        app.processEvents()
        tab.shutdown()
