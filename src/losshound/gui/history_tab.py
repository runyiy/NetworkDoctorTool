from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from losshound.storage.history import HistoryStore
from losshound.gui.db_workers import DbQueryWorker
from losshound.gui.diagnostic_widgets import page_style, style_action


class HistoryTab(QWidget):
    def shutdown(self):
        from losshound.gui._shutdown import stop_qthread
        stop_qthread(self._worker)

    def __init__(self, history: HistoryStore, parent=None):
        super().__init__(parent)
        self._history = history
        self._worker: DbQueryWorker | None = None
        self.setObjectName("history-page")
        self.setStyleSheet(page_style("history-page") + """
            QWidget#history-page QTableWidget {
                background: transparent; alternate-background-color: transparent;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        copy = QVBoxLayout()
        copy.setSpacing(5)
        title = QLabel("Diagnosis history")
        title.setStyleSheet("font-size: 23px; font-weight: 600; color: #eef3f5;")
        subtitle = QLabel("Review the latest 200 diagnoses and the evidence behind them.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #90a4b2;")
        copy.addWidget(title)
        copy.addWidget(subtitle)
        heading.addLayout(copy, 1)
        self._refresh_btn = QPushButton("Refresh History")
        style_action(self._refresh_btn)
        self._refresh_btn.clicked.connect(self._refresh)
        heading.addWidget(self._refresh_btn)
        layout.addLayout(heading)

        # Controls row
        controls = QHBoxLayout()
        controls.setSpacing(12)
        filter_label = QLabel("Show")
        controls.addWidget(filter_label)

        self._filter = QComboBox()
        self._filter.setMinimumWidth(180)
        self._filter.setMinimumHeight(40)
        self._filter.setAccessibleName("Filter diagnosis history")
        filter_label.setBuddy(self._filter)
        self._filter.addItems([
            "All", "Healthy", "LAN Issue", "ISP/WAN Issue",
            "DNS Issue", "Route Issue", "Intermittent",
        ])
        self._filter.currentIndexChanged.connect(self._refresh)
        controls.addWidget(self._filter)

        controls.addStretch()

        self._count = QLabel("")
        self._count.setStyleSheet("color: #90a4b2;")
        controls.addWidget(self._count)

        layout.addLayout(controls)

        self._state = QLabel("Loading diagnosis history…")
        self._state.setTextFormat(Qt.TextFormat.PlainText)
        self._state.setWordWrap(True)
        self._state.setProperty("role", "muted")
        layout.addWidget(self._state)

        # Table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels([
            "Date / Time", "Status", "Summary", "Confidence", "Details",
        ])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setShowGrid(False)
        self._table.setWordWrap(False)
        self._table.verticalHeader().setDefaultSectionSize(42)
        self._table.horizontalHeader().setMinimumSectionSize(90)
        self._table.setAccessibleName("Diagnosis history")
        layout.addWidget(self._table, 1)

        self._refresh()

    def _refresh(self):
        if self._worker is not None and self._worker.isRunning():
            return

        self._state.setText("Loading diagnosis history…")
        self._state.setVisible(True)
        self._count.setText("")
        self._refresh_btn.setEnabled(False)

        self._worker = DbQueryWorker(
            self._history._db_path,
            lambda store: store.get_recent_diagnoses(200),
            self,
        )
        self._worker.finished.connect(self._on_refresh_done)
        self._worker.error.connect(self._on_refresh_error)
        self._worker.start()

    def _on_refresh_done(self, entries: list[dict]):
        self._refresh_btn.setEnabled(True)
        self._table.setRowCount(0)

        filter_text = self._filter.currentText()
        filter_map = {
            "Healthy": "healthy",
            "LAN Issue": "lan_issue",
            "ISP/WAN Issue": "isp_wan_issue",
            "DNS Issue": "dns_issue",
            "Route Issue": "upstream_route_issue",
            "Intermittent": "intermittent",
        }

        for entry in entries:
            if filter_text != "All":
                cat = filter_map.get(filter_text)
                if cat and entry["category"] != cat:
                    continue

            row = self._table.rowCount()
            self._table.insertRow(row)

            ts = entry["timestamp"]
            if "T" in ts:
                date_part, time_part = ts.split("T")
                ts = f"{date_part}  {time_part[:8]}"

            ts_item = QTableWidgetItem(ts)
            ts_item.setToolTip(entry["timestamp"])
            ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, ts_item)

            cat_item = QTableWidgetItem(entry["category"].replace("_", " ").title())
            cat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            color_map = {
                "healthy": "#75c884",
                "lan_issue": "#e06363",
                "isp_wan_issue": "#e06363",
                "dns_issue": "#d9b65f",
                "upstream_route_issue": "#d9b65f",
                "intermittent": "#d9b65f",
                "unknown": "#788596",
            }
            cat_item.setForeground(QColor(color_map.get(entry["category"], "#d8dee9")))
            self._table.setItem(row, 1, cat_item)

            summary_item = QTableWidgetItem(entry["summary"])
            summary_item.setToolTip(
                entry["summary"] + ("\n\n" + entry["explanation"] if entry.get("explanation") else "")
            )
            self._table.setItem(row, 2, summary_item)

            conf_item = QTableWidgetItem(entry["confidence"])
            conf_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 3, conf_item)

            # Build detail string from evidence
            ev = entry.get("evidence", {})
            detail_parts = []
            if ev.get("gateway_loss_avg") is not None:
                detail_parts.append(f"GW: {ev['gateway_loss_avg']}%")
            if ev.get("public_loss_avg") is not None:
                detail_parts.append(f"Pub: {ev['public_loss_avg']}%")
            if ev.get("dns_fail_rate") is not None:
                detail_parts.append(f"DNS fail: {ev['dns_fail_rate']:.0%}")
            details = " | ".join(detail_parts)
            detail_item = QTableWidgetItem(details)
            detail_item.setToolTip(details)
            self._table.setItem(row, 4, detail_item)

        # Scroll to bottom (latest)
        self._count.setText(f"{self._table.rowCount()} shown · {len(entries)} recent diagnoses")
        if self._table.rowCount() > 0:
            self._state.setVisible(False)
            self._table.scrollToBottom()
        else:
            self._state.setText(
                "No diagnoses match this filter yet. Keep monitoring or choose another filter."
            )
            self._state.setVisible(True)

    def _on_refresh_error(self, message: str):
        self._refresh_btn.setEnabled(True)
        self._count.setText("")
        self._table.setRowCount(0)
        detail = (message or "Unknown database error")[:180]
        self._state.setText(
            f"History couldn't be loaded: {detail}\nSelect Refresh to try again."
        )
        self._state.setVisible(True)
