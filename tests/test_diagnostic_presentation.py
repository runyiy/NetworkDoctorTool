"""Connection changes and compact tables must not leave misleading readings."""
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication, QLabel, QTableWidget

from losshound.core.wifi_diag import WifiDiagReport, WifiInterface, ChannelCongestion
from losshound.gui.diagnostic_widgets import compact_table
from losshound.gui.wifi_tab import WifiTab


@pytest.fixture
def wifi(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(WifiTab, "_load_last_bufferbloat", lambda self: None)
    tab = WifiTab()
    yield tab
    tab.shutdown()
    tab.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def _report():
    iface = WifiInterface("WiFi", "connected", "<b>Guest & friends</b>", "", 1, 84, 866,
                          "802.11ax", "WPA2-Personal", "5GHz", 5.0)
    return WifiDiagReport(iface, [], [], 1, 1, "No recommendation", "Excellent", [])


@pytest.mark.parametrize("missing_interface", [True, False])
def test_wifi_disconnect_clears_previous_connection_and_names_remain_plain_text(wifi, missing_interface):
    report = _report()
    wifi._display_wifi_report(report)
    ssid = wifi._wifi_cards["ssid"].value_label
    assert ssid.text() == report.interface.ssid
    assert ssid.textFormat() == Qt.TextFormat.PlainText
    interface = None if missing_interface else replace(report.interface, state="disconnected")
    wifi._display_wifi_report(replace(report, interface=interface))
    assert ssid.text() == "Not connected"
    assert wifi._wifi_cards["signal"].value_label.text() == "--"
    assert "No connected WiFi" in wifi._wifi_state_label.text()


def test_current_channel_matches_both_band_and_number_even_without_network_rows(wifi):
    report = _report()
    channels = [ChannelCongestion(1, band, 1, 50, 50, []) for band in ("2.4GHz", "5GHz")]
    wifi._display_wifi_report(replace(report, channel_congestion=channels))
    assert wifi._ch_table.item(0, 0).text() == "1"
    assert wifi._ch_table.item(1, 0).text() == "1 (you)"


def test_unavailable_load_result_hides_previous_measured_values(wifi):
    result = SimpleNamespace(
        timestamp="2026-09-05T10:00:00", throughput=SimpleNamespace(speed_mbps=94.3),
        bufferbloat=SimpleNamespace(grade="B", idle_latency_ms=42.6, loaded_latency_ms=54.2,
                                   latency_increase_ms=11.6, latency_increase_pct=27.2),
        idle=SimpleNamespace(loss_pct=0), loaded=SimpleNamespace(loss_pct=0),
    )
    wifi._display_bufferbloat(result)
    assert not wifi._bb_metrics_widget.isHidden()
    result.bufferbloat.grade = "N/A"
    wifi._display_bufferbloat(result)
    assert wifi._bb_metrics_widget.isHidden()
    assert "No successful latency samples" in wifi._bb_detail_label.text()


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
