from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPushButton, QScrollArea, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)
 
from losshound.core.models import Observation, RouteSnapshot
from losshound.core.route_monitor import diff_routes
from losshound.storage.history import HistoryStore
from losshound.gui.db_workers import DbQueryWorker
from losshound.gui.diagnostic_widgets import compact_table, page_style, style_action
 
 
class RouteTab(QWidget):
    def shutdown(self):
        from losshound.gui._shutdown import stop_qthread
        stop_qthread(self._worker)
 
    def __init__(self, history: HistoryStore, parent=None):
        super().__init__(parent)
        self._history = history
        self._current_route: RouteSnapshot | None = None
        self._worker: DbQueryWorker | None = None
        self.setObjectName("routes-page")
        self.setStyleSheet(page_style("routes-page") + """
            QWidget#routes-page QTableWidget {
                background: transparent; alternate-background-color: transparent;
            }
        """)
 
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; }")
 
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        copy = QVBoxLayout()
        copy.setSpacing(5)
        title = QLabel("Routes & changes")
        title.setStyleSheet("font-size: 23px; font-weight: 600; color: #eef3f5;")
        subtitle = QLabel("Inspect scheduled traces and compare route changes from the last 24 hours.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #90a4b2;")
        copy.addWidget(title)
        copy.addWidget(subtitle)
        heading.addLayout(copy, 1)
        self._refresh_btn = QPushButton("Refresh History")
        style_action(self._refresh_btn)
        self._refresh_btn.setToolTip("Reload saved route history. The current route follows scheduled monitor checks.")
        self._refresh_btn.clicked.connect(self._load_changes)
        heading.addWidget(self._refresh_btn)
        layout.addLayout(heading)
 
        # Current route header
        header_label = QLabel("Current route")
        header_label.setStyleSheet("font-size: 15px; font-weight: 600; color: #8ad4ec; padding-top: 12px;")
        layout.addWidget(header_label)
 
        self._route_info = QLabel("Waiting for tracert data...")
        self._route_info.setTextFormat(Qt.TextFormat.PlainText)
        self._route_info.setWordWrap(True)
        self._route_info.setStyleSheet("color: #aebbc6;")
        layout.addWidget(self._route_info)
 
        # Route hops table
        self._hops_table = QTableWidget(0, 5)
        self._hops_table.setHorizontalHeaderLabels([
            "Hop", "IP Address", "RTT 1", "RTT 2", "RTT 3",
        ])
        self._hops_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._hops_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._hops_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._hops_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._hops_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._hops_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._hops_table.verticalHeader().setVisible(False)
        self._hops_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._hops_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        compact_table(self._hops_table, None, max_rows=8)
        self._hops_table.setAccessibleName("Current route hops")
        layout.addWidget(self._hops_table)
        probe_hint = QLabel("* means no reply to that probe. Current route updates with the scheduled trace.")
        probe_hint.setWordWrap(True)
        probe_hint.setStyleSheet("color: #90a4b2;")
        layout.addWidget(probe_hint)
 
        # Route changes section
        changes_label = QLabel("Route changes · last 24 hours")
        changes_label.setStyleSheet("font-size: 15px; font-weight: 600; color: #8ad4ec; padding-top: 12px;")
        layout.addWidget(changes_label)

        self._changes_state = QLabel("Loading route history…")
        self._changes_state.setWordWrap(True)
        self._changes_state.setTextFormat(Qt.TextFormat.PlainText)
        self._changes_state.setProperty("role", "muted")
        layout.addWidget(self._changes_state)
 
        self._changes_table = QTableWidget(0, 3)
        self._changes_table.setHorizontalHeaderLabels([
            "Time", "Changed Hops", "Significance",
        ])
        self._changes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._changes_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._changes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._changes_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._changes_table.verticalHeader().setVisible(False)
        self._changes_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._changes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        compact_table(self._changes_table, None)
        self._changes_table.setAccessibleName("Route changes over the last 24 hours")
        layout.addWidget(self._changes_table)
        layout.addStretch()
 
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        
        self._load_changes()
 
    def update_route(self, obs: Observation):
        if obs.route_snapshot:
            self._current_route = obs.route_snapshot
            self._display_route(obs.route_snapshot)
 
    def _display_route(self, snap: RouteSnapshot):
        self._route_info.setText(
            f"Target: {snap.target} | "
            f"Hops: {len(snap.hops)} | "
            f"Status: {'Complete' if snap.completed else 'Incomplete'} | "
            f"Time: {snap.timestamp.strftime('%H:%M:%S')}"
        )
 
        self._hops_table.setRowCount(0)
        for hop in snap.hops:
            row = self._hops_table.rowCount()
            self._hops_table.insertRow(row)
 
            hop_item = QTableWidgetItem(str(hop.hop_number))
            hop_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._hops_table.setItem(row, 0, hop_item)
 
            self._hops_table.setItem(row, 1, QTableWidgetItem(hop.ip or "*"))
 
            for i, rtt in enumerate(hop.rtt_samples[:3]):
                text = f"{rtt:.1f} ms" if rtt is not None else "*"
                rtt_item = QTableWidgetItem(text)
                rtt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._hops_table.setItem(row, 2 + i, rtt_item)
 
    def _load_changes(self):
        if self._worker is not None and self._worker.isRunning():
            return

        self._changes_state.setText("Loading route history…")
        self._changes_state.setVisible(True)
        self._refresh_btn.setEnabled(False)
 
        self._worker = DbQueryWorker(
            self._history._db_path,
            lambda store: store.get_route_snapshots(hours=24),
            self,
        )
        self._worker.finished.connect(self._on_changes_loaded)
        self._worker.error.connect(self._on_changes_error)
        self._worker.start()
 
    def _on_changes_loaded(self, snapshots: list[RouteSnapshot]):
        self._refresh_btn.setEnabled(True)
        self._changes_table.setRowCount(0)
 
        if len(snapshots) < 2:
            self._changes_state.setText(
                "No route comparison yet. Losshound needs at least two route samples."
            )
            self._changes_state.setVisible(True)
            return
 
        for i in range(1, len(snapshots)):
            rd = diff_routes(snapshots[i - 1], snapshots[i])
            if not rd.changed_hops:
                continue
 
            row = self._changes_table.rowCount()
            self._changes_table.insertRow(row)
 
            time_item = QTableWidgetItem(rd.new_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
            time_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._changes_table.setItem(row, 0, time_item)
 
            self._changes_table.setItem(
                row, 1,
                QTableWidgetItem(
                    f"Hops {', '.join(str(h) for h in rd.changed_hops)}"
                ),
            )
            sig = "Significant" if rd.is_significant else "Minor"
            sig_item = QTableWidgetItem(sig)
            sig_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if rd.is_significant:
                sig_item.setForeground(QColor("#e06363"))
            else:
                sig_item.setForeground(QColor("#788596"))
            self._changes_table.setItem(row, 2, sig_item)

        if self._changes_table.rowCount() == 0:
            self._changes_state.setText("No route changes detected in the last 24 hours.")
            self._changes_state.setVisible(True)
        else:
            self._changes_state.setVisible(False)

    def _on_changes_error(self, message: str):
        self._refresh_btn.setEnabled(True)
        self._changes_table.setRowCount(0)
        detail = (message or "Unknown database error")[:180]
        self._changes_state.setText(
            f"Route history couldn't be loaded: {detail}\nSelect Refresh History to try again."
        )
        self._changes_state.setVisible(True)
