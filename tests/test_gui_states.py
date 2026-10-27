import os

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from losshound.gui.export_tab import ExportTab
from losshound.gui.history_tab import HistoryTab
from losshound.gui.lan_tab import LANTab
from losshound.gui.route_tab import RouteTab
from losshound.storage.history import HistoryStore


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def history(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    yield store
    store.close()


def _finish_initial_query(tab, qapp):
    worker = getattr(tab, "_worker", None) or getattr(tab, "_query_worker", None)
    if worker is not None:
        worker.wait(2_000)
        qapp.processEvents()


def test_history_distinguishes_empty_and_error_states(qapp, history):
    tab = HistoryTab(history)
    _finish_initial_query(tab, qapp)

    assert "No diagnoses" in tab._state.text()

    tab._on_refresh_error("database locked")
    assert "couldn't be loaded" in tab._state.text()
    assert "database locked" in tab._state.text()
    tab.shutdown()


def test_route_history_distinguishes_empty_and_error_states(qapp, history):
    tab = RouteTab(history)
    _finish_initial_query(tab, qapp)

    assert "at least two route samples" in tab._changes_state.text()

    tab._on_changes_error("database locked")
    assert "couldn't be loaded" in tab._changes_state.text()
    tab.shutdown()


def test_export_actions_enable_only_after_compatible_report(qapp, history):
    tab = ExportTab(history)

    assert not tab._copy_btn.isEnabled()
    assert not tab._txt_btn.isEnabled()
    assert not tab._json_btn.isEnabled()

    tab._on_quick_report_done({
        "generated_at": "2026-07-09T12:00:00",
        "diagnoses": [],
        "observations": [],
        "latest_route": [],
    })

    assert tab._copy_btn.isEnabled()
    assert tab._txt_btn.isEnabled()
    assert tab._json_btn.isEnabled()

    tab._on_report_error("database locked")
    assert not tab._copy_btn.isEnabled()
    assert "failed" in tab._preview.toPlainText().lower()


def test_lan_errors_are_visible_instead_of_empty_tables(qapp, history):
    tab = LANTab(history)
    _finish_initial_query(tab, qapp)

    tab._on_db_error("database locked")
    assert "couldn't be updated" in tab._status_label.text()

    tab._on_connections_error("netstat unavailable")
    assert "couldn't be loaded" in tab._conn_state.text()
    tab.shutdown()
