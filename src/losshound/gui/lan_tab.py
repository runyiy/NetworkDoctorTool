from __future__ import annotations

import logging
from PySide6.QtCore import QThread, QTimer, Qt, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QProgressBar, QPushButton, QSplitter, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QGroupBox,
    QMessageBox,
)

from losshound.core.lan_monitor import lookup_vendor
from losshound.core.local_monitor import get_active_connections
from losshound.storage.history import HistoryStore
from losshound.gui.db_workers import DbQueryWorker, DbWriteWorker
from losshound.gui.palette import c

logger = logging.getLogger(__name__)


class LanScanWorker(QThread):
    """Background worker for LAN subnet discovery sweep to prevent GUI lag."""
    scan_complete = Signal(list)
    error = Signal(str)

    def __init__(self, history: HistoryStore, enable_http_scan: bool = False):
        super().__init__()
        self._history = history
        self._enable_http_scan = enable_http_scan

    def run(self):
        try:
            from losshound.core.lan_monitor import scan_local_network
            with HistoryStore(self._history._db_path) as thread_safe_history:
                devices = scan_local_network(
                    thread_safe_history,
                    enable_http_scan=self._enable_http_scan,
                )
            self.scan_complete.emit(devices)
        except Exception as exc:
            logger.exception("LAN Scan worker failed")
            self.error.emit(str(exc))


class ConnectionRefreshWorker(QThread):
    """Background worker to fetch local network connections to prevent main thread blocking."""
    connections_ready = Signal(list)
    error = Signal(str)

    def run(self):
        try:
            conns = get_active_connections()
            self.connections_ready.emit(conns)
        except Exception as exc:
            logger.warning("Background connection refresh failed: %s", exc)
            self.error.emit(str(exc))


class LANTab(QWidget):
    def __init__(self, history: HistoryStore, config=None, parent=None):
        super().__init__(parent)
        self._history = history
        self._config = config
        self._scan_in_progress = False
        self._query_worker: DbQueryWorker | None = None
        self._write_worker: DbWriteWorker | None = None

        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # Splitter to allow resizing of top and bottom sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter)

        # -------------------------------------------------------------
        # Section 1: Connected Devices (LAN)
        # -------------------------------------------------------------
        devices_box = QGroupBox("Connected Devices (LAN)")
        devices_layout = QVBoxLayout(devices_box)
        devices_layout.setContentsMargins(12, 16, 12, 12)
        devices_layout.setSpacing(10)

        info_label = QLabel(
            "Tip: double-click a hostname to set a custom name. Generic names mean a device name "
            "could not be resolved; they do not identify a router problem. Check the device or "
            "your router's device list to confirm its identity. Keep guest/client isolation enabled "
            "unless you intentionally want those devices to communicate."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #788596; font-size: 11px; padding: 2px 0;")
        devices_layout.addWidget(info_label)

        # Controls Row
        controls_layout = QHBoxLayout()
        self._scan_btn = QPushButton("Scan Now")
        self._scan_btn.clicked.connect(self._start_scan)
        controls_layout.addWidget(self._scan_btn)
        
        self._reset_btn = QPushButton("Clear History")
        self._reset_btn.clicked.connect(self._clear_devices)
        controls_layout.addWidget(self._reset_btn)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # Indeterminate loading bar
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(12)
        self._progress.setVisible(False)
        controls_layout.addWidget(self._progress)

        self._status_label = QLabel("Click Scan to search for local devices.")
        self._status_label.setStyleSheet("color: #788596;")
        controls_layout.addWidget(self._status_label)
        controls_layout.addStretch()
        
        devices_layout.addLayout(controls_layout)

        # Devices Table
        self._devices_table = QTableWidget(0, 6)
        self._devices_table.setHorizontalHeaderLabels([
            "Hostname", "IP Address", "MAC Address", "Vendor", "Status", "Authorization"
        ])
        self._devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._devices_table.verticalHeader().setVisible(False)
        self._devices_table.verticalHeader().setDefaultSectionSize(36)
        # Only the Hostname column is editable (per-cell flag controls actual edit permission)
        self._devices_table.setEditTriggers(
            QTableWidget.EditTrigger.DoubleClicked | QTableWidget.EditTrigger.EditKeyPressed
        )
        self._devices_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._devices_table.itemChanged.connect(self._on_hostname_edited)
        self._suppress_item_changed = False
        devices_layout.addWidget(self._devices_table)
        
        splitter.addWidget(devices_box)

        # -------------------------------------------------------------
        # Section 2: Active Local Connections
        # -------------------------------------------------------------
        connections_box = QGroupBox("Active Local Connections")
        connections_layout = QVBoxLayout(connections_box)
        connections_layout.setContentsMargins(12, 16, 12, 12)
        connections_layout.setSpacing(10)

        # Connections Filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by Process / Site:"))
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Search...")
        self._filter_input.textChanged.connect(self._display_connections)
        filter_layout.addWidget(self._filter_input)
        filter_layout.addStretch()
        
        connections_layout.addLayout(filter_layout)

        self._conn_state = QLabel("Open this tab to load active local connections.")
        self._conn_state.setWordWrap(True)
        self._conn_state.setProperty("role", "muted")
        connections_layout.addWidget(self._conn_state)

        # Connections Table
        self._conn_table = QTableWidget(0, 6)
        self._conn_table.setHorizontalHeaderLabels([
            "Process", "Protocol", "Local Port", "Remote IP", "Resolved Site / Host", "State"
        ])
        self._conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._conn_table.verticalHeader().setVisible(False)
        self._conn_table.verticalHeader().setDefaultSectionSize(36)
        self._conn_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._conn_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        connections_layout.addWidget(self._conn_table)

        splitter.addWidget(connections_box)

        # Set splitter sizes (even split initially)
        splitter.setSizes([300, 300])

        # -------------------------------------------------------------
        # Timers & Workers Initialization
        # -------------------------------------------------------------
        self._scan_worker = None
        self._conn_worker = None
        self._conn_refresh_in_progress = False
 
        # Refresh local connections only while this tab is visible. The timer
        # is kept gentle so subprocess and reverse-DNS work do not compete
        # with the user's connection.
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_connections)
        self._refresh_timer.setInterval(10000)
 
        # Initial loads
        self._refresh_devices_table()

    def update_config(self, config) -> None:
        self._config = config

    def showEvent(self, event):
        super().showEvent(event)
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()
        self._refresh_connections()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._refresh_timer.stop()

    def shutdown(self):
        """Cleanly terminate the scan and connection workers on app shutdown."""
        from losshound.gui._shutdown import stop_qthread
        self._refresh_timer.stop()
        stop_qthread(self._query_worker)
        stop_qthread(self._write_worker)

        if self._scan_worker and self._scan_worker.isRunning():
            self._scan_worker.quit()
            self._scan_worker.wait(1000)
            if self._scan_worker.isRunning():
                self._scan_worker.terminate()
                
        if self._conn_worker and self._conn_worker.isRunning():
            self._conn_worker.quit()
            self._conn_worker.wait(1000)
            if self._conn_worker.isRunning():
                self._conn_worker.terminate()

    # -----------------------------------------------------------------
    # LAN Scan Logic
    # -----------------------------------------------------------------
    def _start_scan(self):
        if self._scan_in_progress:
            return

        self._scan_in_progress = True
        self._scan_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText("Scanning subnet (sending pings & checking ARP)...")

        # Launch scanning on a background thread
        enable_http_scan = False
        if self._config:
            enable_http_scan = self._config.lan_http_scan_enabled
        self._scan_worker = LanScanWorker(self._history, enable_http_scan=enable_http_scan)
        self._scan_worker.scan_complete.connect(self._on_scan_complete)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    @Slot(list)
    def _on_scan_complete(self, devices: list):
        self._scan_in_progress = False
        self._scan_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._status_label.setText(f"Scan complete. Found {len(devices)} active devices.")
        self._refresh_devices_table()

    def _on_scan_error(self, message: str):
        self._scan_in_progress = False
        self._scan_btn.setEnabled(True)
        self._progress.setVisible(False)
        detail = (message or "Unknown scan error")[:180]
        self._status_label.setText(f"LAN scan failed: {detail}. Try again.")

    def _clear_devices(self):
        reply = QMessageBox.question(
            self, "Confirm Reset",
            "Are you sure you want to clear all discovered LAN devices from history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._status_label.setText("Clearing device list...")
            self._write_worker = DbWriteWorker(
                self._history._db_path,
                lambda store: store.clear_discovered_devices(),
                self,
            )
            self._write_worker.finished.connect(self._on_clear_complete)
            self._write_worker.error.connect(self._on_db_error)
            self._write_worker.start()

    def _on_clear_complete(self):
        self._refresh_devices_table()
        self._status_label.setText("Device list cleared. Click Scan Now to discover active devices.")

    def _refresh_devices_table(self):
        if self._query_worker is not None and self._query_worker.isRunning():
            return

        self._query_worker = DbQueryWorker(
            self._history._db_path,
            lambda store: store.get_devices(),
            self,
        )
        self._query_worker.finished.connect(self._on_devices_loaded)
        self._query_worker.error.connect(self._on_db_error)
        self._query_worker.start()

    def _on_devices_loaded(self, devices: list[dict]):
        # Suppress itemChanged signals while we repopulate so they're not mistaken for user edits
        self._suppress_item_changed = True
        try:
            self._devices_table.setRowCount(0)

            color_map = {
                "authorized": "#75c884",   # Soft green
                "suspicious": "#e06363",   # Soft red
                "unknown": "#788596",      # Grey
            }

            editable_flags = (
                Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsEditable
            )
            readonly_flags = Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled

            for dev in devices:
                row = self._devices_table.rowCount()
                self._devices_table.insertRow(row)

                # Columns: Hostname, IP Address, MAC Address, Vendor, Status, Authorization
                display_name = dev.get("custom_name") or dev["hostname"] or "Unknown"
                hostname_item = QTableWidgetItem(display_name)
                hostname_item.setFlags(editable_flags)
                # Stash the MAC so the edit handler knows which device this row belongs to
                hostname_item.setData(Qt.ItemDataRole.UserRole, dev["mac_address"])
                if not dev["is_active"]:
                    hostname_item.setForeground(QColor(c("text_dim")))
                hostname_item.setToolTip("Double-click to set a custom name. Clear the text to revert to auto-detected hostname.")
                self._devices_table.setItem(row, 0, hostname_item)

                ip_item = QTableWidgetItem(dev["ip_address"])
                ip_item.setFlags(readonly_flags)
                if not dev["is_active"]:
                    ip_item.setForeground(QColor(c("text_dim")))
                self._devices_table.setItem(row, 1, ip_item)

                mac_item = QTableWidgetItem(dev["mac_address"])
                mac_item.setFlags(readonly_flags)
                if not dev["is_active"]:
                    mac_item.setForeground(QColor(c("text_dim")))
                self._devices_table.setItem(row, 2, mac_item)

                vendor_item = QTableWidgetItem(dev["vendor"] or "Unknown")
                vendor_item.setFlags(readonly_flags)
                if not dev["is_active"]:
                    vendor_item.setForeground(QColor(c("text_dim")))
                self._devices_table.setItem(row, 3, vendor_item)

                status_text = dev["status"].upper()
                if not dev["is_active"]:
                    status_text += " (OFFLINE)"
                status_item = QTableWidgetItem(status_text)
                status_item.setFlags(readonly_flags)
                status_item.setForeground(QColor(color_map.get(dev["status"], "#d8dee9")))
                self._devices_table.setItem(row, 4, status_item)

                # Dropdown for Authorization Action
                auth_combo = QComboBox()
                auth_combo.addItems(["Unknown", "Authorized", "Suspicious"])

                # Match current status
                index_map = {"unknown": 0, "authorized": 1, "suspicious": 2}
                auth_combo.setCurrentIndex(index_map.get(dev["status"], 0))

                # Avoid using cell lambda variables directly in slot to prevent closure issues
                mac_addr = dev["mac_address"]
                auth_combo.currentIndexChanged.connect(
                    lambda idx, m=mac_addr: self._on_auth_changed(m, idx)
                )
                self._devices_table.setCellWidget(row, 5, auth_combo)
        finally:
            self._suppress_item_changed = False

        if not devices:
            self._status_label.setText("No saved devices yet. Select Scan Now to discover them.")

    def _on_db_error(self, message: str):
        detail = (message or "Unknown database error")[:180]
        self._status_label.setText(f"LAN data couldn't be updated: {detail}. Try again.")

    @Slot(QTableWidgetItem)
    def _on_hostname_edited(self, item):
        if self._suppress_item_changed:
            return
        if item.column() != 0:
            return
        mac = item.data(Qt.ItemDataRole.UserRole)
        if not mac:
            return
        new_text = item.text().strip()
        
        self._write_worker = DbWriteWorker(
            self._history._db_path,
            lambda store: store.set_device_custom_name(mac, new_text or None),
            self,
        )
        self._write_worker.finished.connect(self._refresh_devices_table)
        self._write_worker.error.connect(self._on_db_error)
        self._write_worker.start()
        logger.info("Custom name for %s set to %r", mac, new_text or None)

    def _on_auth_changed(self, mac: str, index: int):
        status_map = {0: "unknown", 1: "authorized", 2: "suspicious"}
        new_status = status_map.get(index, "unknown")
        
        self._write_worker = DbWriteWorker(
            self._history._db_path,
            lambda store: store.update_device_status(mac, new_status),
            self,
        )
        self._write_worker.finished.connect(self._refresh_devices_table)
        self._write_worker.error.connect(self._on_db_error)
        self._write_worker.start()
        logger.info("Device %s authorization status changed to %s", mac, new_status)

    # -----------------------------------------------------------------
    # Local Connections Tracking Logic
    # -----------------------------------------------------------------
    def _refresh_connections(self):
        """Query current local process connection status in background thread to prevent lag."""
        if self._conn_refresh_in_progress:
            return
        self._conn_refresh_in_progress = True
        
        self._conn_worker = ConnectionRefreshWorker(self)
        self._conn_worker.connections_ready.connect(self._on_connections_ready)
        self._conn_worker.error.connect(self._on_connections_error)
        self._conn_worker.start()

    @Slot(list)
    def _on_connections_ready(self, conns: list):
        self._conn_refresh_in_progress = False
        self._all_connections = conns
        self._display_connections()
        self._conn_state.setText(
            "No active local connections found."
            if not conns
            else f"Showing {len(conns)} active local connections."
        )

    def _on_connections_error(self, message: str):
        self._conn_refresh_in_progress = False
        self._conn_table.setRowCount(0)
        detail = (message or "Unknown connection error")[:180]
        self._conn_state.setText(
            f"Connections couldn't be loaded: {detail}. This view will retry automatically."
        )

    def _display_connections(self):
        """Filter and render connections list based on filter query."""
        self._conn_table.setRowCount(0)
        filter_text = self._filter_input.text().lower()

        if not hasattr(self, "_all_connections"):
            return

        for conn in self._all_connections:
            proc = conn["process"]
            resolved = conn["resolved_name"]

            # Filter logic
            if filter_text:
                if filter_text not in proc.lower() and filter_text not in resolved.lower() and filter_text not in conn["remote_ip"]:
                    continue

            row = self._conn_table.rowCount()
            self._conn_table.insertRow(row)

            # Columns: Process, Protocol, Local Port, Remote IP, Resolved Site / Host, State
            self._conn_table.setItem(row, 0, QTableWidgetItem(f"{proc} (PID: {conn['pid']})"))
            self._conn_table.setItem(row, 1, QTableWidgetItem(conn["protocol"]))
            self._conn_table.setItem(row, 2, QTableWidgetItem(conn["local_address"].rpartition(":")[2]))
            self._conn_table.setItem(row, 3, QTableWidgetItem(conn["remote_ip"]))
            
            site_item = QTableWidgetItem(resolved)
            # Highlight resolved domain names instead of bare IPs
            if resolved != conn["remote_ip"]:
                site_item.setForeground(QColor("#62c7d8"))  # Accent cyan color
            self._conn_table.setItem(row, 4, site_item)
            
            state_item = QTableWidgetItem(conn["state"])
            if conn["state"] == "ESTABLISHED":
                state_item.setForeground(QColor("#75c884"))  # Green
            self._conn_table.setItem(row, 5, state_item)
