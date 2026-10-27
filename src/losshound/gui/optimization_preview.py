"""Read-only confirmation of the GUI optimizer's requested operations."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from losshound.gui.diagnostic_widgets import page_style, style_action


class _PreviewTable(QTableWidget):
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.resizeRowsToContents()


def planned_changes(options: dict[str, bool]) -> list[tuple[str, str]]:
    """Targets used by optimize_all; MTU and adapter support are conditional."""
    rows = [
        ("TCP receive-window auto-tuning", "Normal"),
        ("Internet congestion provider", "CUBIC"),
        ("Explicit Congestion Notification (ECN)", "Enabled"),
        ("Receive-Side Scaling (RSS)", "Enabled"),
        ("Direct Cache Access (DCA)", "Enabled, if supported"),
        ("TCP timestamps", "Enabled"),
        ("Winsock datagram threshold", "FastSendDatagramThreshold = 1500; reboot required"),
        ("Adapter power management", "Disabled, if supported; skipped on devices with a battery"),
        ("Windows network throttling", "Disabled (NetworkThrottlingIndex = 0xFFFFFFFF)"),
        ("TCP delay / Nagle settings", "TCPNoDelay = 1; TcpAckFrequency = 1; TcpDelAckTicks = 0"),
        ("TCP heuristics", "Disabled"),
        ("System responsiveness", "10% (the fixed target for this batch)"),
        ("MTU", "Probe 8.8.8.8 and apply the discovered value; skip if inconclusive"),
    ]
    for key, label in (
        ("optimize_eee", "Energy Efficient Ethernet (EEE)"),
        ("optimize_rsc", "Receive Segment Coalescing (RSC)"),
        ("optimize_lso", "Large Send Offload (LSO)"),
    ):
        if options.get(key, False):
            rows.append((label, "Disabled, if supported (selected option)"))
    return rows


class OptimizationPreview(QDialog):
    """Opening this dialog performs no probes, backup writes, or setting changes."""

    def __init__(self, options: dict[str, bool], *, is_admin: bool, parent=None):
        super().__init__(parent)
        self.setObjectName("optimization-preview")
        self.setWindowTitle("Review network changes")
        self.setMinimumSize(780, 570)
        self.resize(960, 720)
        self.setStyleSheet(page_style("optimization-preview") + """
            QDialog#optimization-preview { background: #080c0e; }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        title = QLabel("Review network changes")
        title.setStyleSheet("font-size: 23px; font-weight: 600; color: #eef3f5;")
        layout.addWidget(title)
        intro = QLabel(
            "These are requested targets, not confirmed improvements. Windows-wide TCP settings "
            "and the active adapter are affected. Unsupported settings may be skipped."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        if not is_admin:
            access = QLabel(
                "Preview only: applying these settings requires Administrator. "
                "You can still run diagnostics in the current session."
            )
            access.setWordWrap(True)
            access.setStyleSheet("color: #dfbd69; background: #201c12; padding: 10px;")
            layout.addWidget(access)

        rows = planned_changes(options)
        self._table = _PreviewTable(len(rows), 2)
        self._table.setAccessibleName("Requested network changes")
        self._table.setHorizontalHeaderLabels(["Setting", "Requested target / condition"])
        self._table.verticalHeader().hide()
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)
        self._table.setWordWrap(True)
        self._table.setTextElideMode(Qt.TextElideMode.ElideNone)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for row, values in enumerate(rows):
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self._table.setItem(row, col, item)
        self._table.horizontalHeader().sectionResized.connect(self._table.resizeRowsToContents)
        self._table.resizeRowsToContents()
        layout.addWidget(self._table, 1)

        scope = QLabel(
            "DNS servers, DNS/ARP caches, and interrupt moderation stay unchanged. "
            "Unchecked adapter options are excluded."
        )
        scope.setWordWrap(True)
        layout.addWidget(scope)
        detail = QLabel(
            "A first-run backup is saved before applying changes; an existing original backup is kept. "
            "Adapter changes can briefly interrupt connectivity, and some settings require a reboot. "
            "Use Benchmark Before and Benchmark After to measure the result."
        )
        detail.setWordWrap(True)
        detail.setStyleSheet("color: #90a4b2;")
        layout.addWidget(detail)
        actions = QHBoxLayout()
        actions.addStretch()
        self._cancel = QPushButton("Cancel")
        self._apply = QPushButton("Apply listed changes")
        style_action(self._cancel)
        style_action(self._apply, "primary")
        self._apply.setEnabled(is_admin)
        self._apply.setAutoDefault(False)
        self._cancel.setDefault(True)
        self._cancel.clicked.connect(self.reject)
        self._apply.clicked.connect(self.accept)
        actions.addWidget(self._cancel)
        actions.addWidget(self._apply)
        layout.addLayout(actions)
        self._cancel.setFocus()
