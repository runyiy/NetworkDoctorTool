"""Report delivery can precede the underlying QThread's termination."""
import os
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from losshound.gui.export_tab import ExportTab, _IspPdfWorker, _IspReportWorker
from losshound.storage.history import HistoryStore


@pytest.mark.parametrize("result_kind", ["isp", "pdf", "error"])
def test_report_worker_stays_owned_until_thread_finishes(tmp_path, monkeypatch, result_kind):
    app = QApplication.instance() or QApplication([])
    release = threading.Event()
    worker_type = _IspPdfWorker if result_kind == "pdf" else _IspReportWorker
    output = tmp_path / "report.pdf"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(output), ""))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    monkeypatch.setattr(os, "startfile", lambda *a, **k: None, raising=False)

    def run(worker):
        if result_kind == "error":
            worker.error.emit("controlled report failure")
        else:
            signal = getattr(worker, "report_ready", worker.finished)
            signal.emit((output, "") if result_kind == "pdf" else "Controlled ISP report")
        # Hold the native thread open after delivering the result, reproducing
        # the interval in which the GUI previously dropped its last reference.
        release.wait(5)

    monkeypatch.setattr(worker_type, "run", run)
    with HistoryStore(tmp_path / "history.db") as history:
        tab = ExportTab(history)
        try:
            (tab._generate_pdf if result_kind == "pdf" else tab._generate_isp)()
            worker = tab._thread  # Keep the old implementation from aborting pytest.
            deadline = time.monotonic() + 2
            expected = {"isp": "Controlled ISP report", "pdf": "PDF saved to:", "error": "Report generation failed:"}[result_kind]
            while expected not in tab._preview.toPlainText() and time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.001)
            assert expected in tab._preview.toPlainText()
            assert worker.isRunning()
            assert tab._thread is worker
            tab._generate_isp()
            assert tab._thread is worker, "Do not replace a thread that is still exiting"
        finally:
            release.set()
            worker.wait(2000)
            app.processEvents()
            tab.shutdown()
        assert tab._thread is None


def test_quick_report_error_does_not_release_active_isp_worker(tmp_path):
    app = QApplication.instance() or QApplication([])
    with HistoryStore(tmp_path / "history.db") as history:
        tab = ExportTab(history)
        worker = _IspReportWorker(history._db_path, 24)
        tab._thread = worker
        tab._on_report_error("quick report failed")
        assert tab._thread is worker
        tab.shutdown()
