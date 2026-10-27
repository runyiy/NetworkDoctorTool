from datetime import datetime
from unittest.mock import patch

from losshound.core import drop_analyzer
from losshound.core.drop_analyzer import (
    ConnSample,
    DropAnalysisReport,
    GatewayStateSnapshot,
    WifiStateSnapshot,
    classify_drop_forensics,
)
from losshound.core.windows_network import ActiveNetworkInterface


def test_active_route_interface_supplies_its_own_link_speed():
    active = ActiveNetworkInterface(
        interface_alias="Wi-Fi",
        interface_index=7,
        gateway="192.168.1.1",
        ipv4_address="192.168.1.50",
        prefix_length=24,
        dns_servers=("1.1.1.1",),
        dhcp_enabled=True,
        connected=True,
        link_speed_mbps=866.7,
    )
    with patch.object(
        drop_analyzer,
        "get_active_network_interface",
        return_value=active,
    ), patch.object(drop_analyzer, "_run") as run_mock:
        result = drop_analyzer._get_active_nic_info()

    assert result == ("wifi", True, 866.7)
    run_mock.assert_not_called()


def test_disconnected_interface_is_not_mistaken_for_connected():
    netsh_output = """
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Disconnected   Dedicated        Wi-Fi
"""
    with patch.object(
        drop_analyzer,
        "get_active_network_interface",
        return_value=None,
    ), patch.object(
        drop_analyzer,
        "_run",
        return_value=drop_analyzer._CommandResult(stdout=netsh_output),
    ):
        assert drop_analyzer._get_active_nic_info() == ("wifi", False, 0.0)


def test_active_interface_speed_comes_from_matching_adapter():
    netsh_output = """
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Disconnected   Dedicated        Wi-Fi
Enabled        Connected      Dedicated        Ethernet 2
"""
    wmic_output = """
Node,NetConnectionID,Speed
HOST,Wi-Fi,866000000
HOST,Ethernet 2,1000000000
"""
    with patch.object(
        drop_analyzer,
        "get_active_network_interface",
        return_value=None,
    ), patch.object(
        drop_analyzer,
        "_run",
        side_effect=[
            drop_analyzer._CommandResult(stdout=netsh_output),
            drop_analyzer._CommandResult(stdout=wmic_output),
        ],
    ):
        assert drop_analyzer._get_active_nic_info() == ("ethernet", True, 1000.0)


def _sample(gateway=True, wan=True, link=True, connection_type="ethernet"):
    return ConnSample(
        timestamp=datetime.now(),
        link_up=link,
        connection_type=connection_type,
        speed_mbps=100.0 if link else 0.0,
        wifi_signal_pct=70 if connection_type == "wifi" else 0,
        wifi_ssid="home" if connection_type == "wifi" else "",
        wifi_channel=6 if connection_type == "wifi" else 0,
        gateway_reachable=gateway,
        gateway_rtt_ms=2.0 if gateway else None,
        wan_reachable=wan,
        wan_rtt_ms=20.0 if wan else None,
        dns_ok=True,
    )


def _report(samples, connection_type="ethernet"):
    return DropAnalysisReport(
        scan_duration_seconds=3.0,
        connection_type=connection_type,
        total_samples=len(samples),
        samples=samples,
        drops=[],
        events=[],
        verdict="test report",
        confidence="medium",
        details=[],
        recommendations=[],
        drop_regularity=None,
    )


def _gateway(reachable=True):
    return GatewayStateSnapshot(
        gateway_ip="192.168.1.1",
        reachable=reachable,
        rtt_ms=2.0 if reachable else None,
    )


def test_drop_forensics_classifies_isp_when_gateway_stays_up():
    cause, confidence, summary = classify_drop_forensics(
        _report([_sample(gateway=True, wan=False), _sample(gateway=True, wan=False)]),
        None,
        None,
        _gateway(True),
        _gateway(True),
    )

    assert cause == "isp"
    assert confidence in {"medium", "high"}
    assert "Gateway stayed reachable" in summary


def test_drop_forensics_classifies_gateway_reboot_when_gateway_and_wan_drop():
    cause, confidence, summary = classify_drop_forensics(
        _report([_sample(gateway=False, wan=False), _sample(gateway=False, wan=False)]),
        None,
        None,
        _gateway(True),
        _gateway(True),
    )

    assert cause == "gateway_reboot"
    assert confidence == "medium"
    assert "Gateway and WAN dropped together" in summary


def test_drop_forensics_classifies_wifi_roam_on_bssid_or_channel_change():
    before = WifiStateSnapshot(
        connected=True,
        ssid="home",
        bssid="aa:bb:cc:00:00:01",
        signal_pct=72,
        channel=1,
        band="2.4GHz",
    )
    after = WifiStateSnapshot(
        connected=True,
        ssid="home",
        bssid="aa:bb:cc:00:00:02",
        signal_pct=48,
        channel=6,
        band="2.4GHz",
    )

    cause, confidence, summary = classify_drop_forensics(
        _report([_sample(connection_type="wifi")], connection_type="wifi"),
        before,
        after,
        _gateway(True),
        _gateway(True),
    )

    assert cause == "wifi_roam"
    assert confidence == "high"
    assert "channel 1->6" in summary
