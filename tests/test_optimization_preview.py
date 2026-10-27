"""The settings shown for approval must be the settings passed to the worker."""
from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog

from losshound.gui import optimizer_tab
from losshound.gui.optimization_preview import OptimizationPreview, planned_changes


@pytest.fixture
def tab(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(optimizer_tab.OptimizerTab, "_on_check_status", lambda self: None)
    monkeypatch.setattr(optimizer_tab.OptimizerTab, "_load_saved_optimization_results", lambda self: None)
    monkeypatch.setattr(optimizer_tab, "get_latest_snapshot", lambda label: None)
    monkeypatch.setattr(optimizer_tab.NetworkOptimizer, "check_admin", lambda: True)
    worker = MagicMock()
    worker.isRunning.return_value = False
    factory = MagicMock(return_value=worker)
    monkeypatch.setattr(optimizer_tab, "_OptimizeWorker", factory)
    page = optimizer_tab.OptimizerTab()
    yield page, factory
    page.shutdown()
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


@pytest.mark.parametrize("choice", ["cancel", "escape", "enter", "apply"])
def test_only_explicit_apply_dispatches_the_reviewed_options(tab, choice):
    page, factory = tab
    page._eee_checkbox.setChecked(True)
    page._lso_checkbox.setChecked(True)
    inspected, errors = [], []

    def interact():
        dialog = QApplication.activeModalWidget()
        try:
            assert isinstance(dialog, OptimizationPreview)
            names = [dialog._table.item(row, 0).text() for row in range(dialog._table.rowCount())]
            assert "Energy Efficient Ethernet (EEE)" in names
            assert "Large Send Offload (LSO)" in names
            assert "Receive Segment Coalescing (RSC)" not in names
            factory.assert_not_called()
            inspected.append(True)
            # Even a programmatic change during the modal loop must not alter approval.
            page._eee_checkbox.setChecked(False)
            page._rsc_checkbox.setChecked(True)
            if choice == "apply":
                QTest.mouseClick(dialog._apply, Qt.MouseButton.LeftButton)
            elif choice == "cancel":
                QTest.mouseClick(dialog._cancel, Qt.MouseButton.LeftButton)
            else:
                QTest.keyClick(dialog, Qt.Key.Key_Escape if choice == "escape" else Qt.Key.Key_Return)
        except Exception as exc:
            errors.append(exc)
            if dialog is not None:
                dialog.reject()

    QTimer.singleShot(0, interact)
    page._on_optimize_all()
    assert not errors, errors
    assert inspected
    if choice == "apply":
        factory.assert_called_once_with(
            skip_dns=True, apply_dns=False, skip_mtu=False,
            optimize_eee=True, optimize_rsc=False, optimize_lso=True,
        )
        factory.return_value.start.assert_called_once()
    else:
        factory.assert_not_called()


def test_standard_user_can_preview_but_cannot_start_changes(tab, monkeypatch):
    page, factory = tab
    monkeypatch.setattr(optimizer_tab.NetworkOptimizer, "check_admin", lambda: False)
    inspected = []

    def attempt_accept():
        dialog = QApplication.activeModalWidget()
        inspected.append(not dialog._apply.isEnabled())
        # Even a programmatic accept must not bypass the handler's privilege check.
        dialog.accept()

    QTimer.singleShot(0, attempt_accept)
    page._on_optimize_all()
    assert inspected == [True]
    factory.assert_not_called()


@pytest.mark.parametrize("selected", [(), ("eee",), ("rsc",), ("lso",), ("eee", "rsc", "lso")])
def test_preview_includes_only_selected_optional_changes(selected):
    rows = dict(planned_changes({f"optimize_{key}": True for key in selected}))
    for key, name in (
        ("eee", "Energy Efficient Ethernet (EEE)"),
        ("rsc", "Receive Segment Coalescing (RSC)"),
        ("lso", "Large Send Offload (LSO)"),
    ):
        assert (name in rows) == (key in selected)
    assert "inconclusive" in rows["MTU"]
    assert "10%" in rows["System responsiveness"]
