"""Connection changes and compact tables must not leave misleading readings."""
import sys

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QLabel, QTableWidget

from losshound.gui.diagnostic_widgets import compact_table












def test_compact_table_retains_rows_and_disconnects_safely_at_destruction(monkeypatch):
    app = QApplication.instance() or QApplication([])
    errors = []
    monkeypatch.setattr(sys, "excepthook", lambda kind, value, tb: errors.append(value))
    table, empty = QTableWidget(0, 2), QLabel("No results")
    empty.setParent(table)
    compact_table(table, empty)
    assert table.isHidden()
    table.setRowCount(30)
    table.show()
    app.processEvents()
    assert table.rowCount() == 30
    assert table.verticalScrollBar().maximum() > 0
    assert empty.isHidden()
    table.setRowCount(0)
    assert table.isHidden()
    assert not empty.isHidden()
    table.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
    assert errors == []
