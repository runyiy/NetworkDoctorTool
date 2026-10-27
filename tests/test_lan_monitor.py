import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from pathlib import Path

from losshound.core.lan_monitor import (
    get_local_network_info,
    get_subnet_ips,
    is_lan_scoped_ip,
    lookup_vendor,
    resolve_hostname_safe,
    parse_arp_table,
    scan_local_network,
)
from losshound.core.local_monitor import (
    get_pid_to_process_name,
    get_active_connections,
)

# Mock inputs
MOCK_ARP_OUTPUT = """
Interface: 192.168.1.100 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           1c-3b-f3-ea-bb-cc     dynamic   
  192.168.1.102         04-d9-f5-12-34-56     dynamic   
  192.168.1.255         ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
"""

MOCK_TASKLIST_OUTPUT = """
"System Idle Process","0","Services","0","8 K"
"System","4","Services","0","3,876 K"
"chrome.exe","4888","Console","1","248,312 K"
"""

MOCK_NETSTAT_OUTPUT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       988
  TCP    192.168.1.100:54321    142.250.74.46:443      ESTABLISHED     4888
  TCP    [::]:135               [::]:0                 LISTENING       988
  UDP    0.0.0.0:5353           *:*                                    2140
"""


def test_get_local_network_info():
    mock_res = MagicMock()
    from tests.conftest import IPCONFIG_OUTPUT
    mock_res.stdout = IPCONFIG_OUTPUT.encode("cp850")
    
    with patch("subprocess.run", return_value=mock_res):
        info = get_local_network_info()
        assert info["ip"] == "192.168.1.100"
        assert info["mask"] == "255.255.255.0"


def test_get_subnet_ips():
    ips = get_subnet_ips("192.168.1.100")
    assert len(ips) == 253  # 1 to 254 excluding 100
    assert "192.168.1.1" in ips
    assert "192.168.1.100" not in ips
    assert ips[0] == "192.168.1.1"
    assert ips[-1] == "192.168.1.254"


def test_get_subnet_ips_honors_subnet_mask():
    ips = get_subnet_ips("192.168.1.10", "255.255.255.252")
    assert ips == ["192.168.1.9"]


def test_lookup_vendor():
    assert lookup_vendor("1c:3b:f3:ea:bb:cc") == "HP"
    assert lookup_vendor("04-d9-f5-12-34-56") == "ASUS"
    assert lookup_vendor("00-00-00-00-00-00") == "Unknown"


def test_is_lan_scoped_ip():
    assert is_lan_scoped_ip("192.168.1.1")
    assert is_lan_scoped_ip("10.0.0.5")
    assert is_lan_scoped_ip("172.16.4.20")
    assert is_lan_scoped_ip("169.254.1.10")
    assert not is_lan_scoped_ip("8.8.8.8")
    assert not is_lan_scoped_ip("224.0.0.251")
    assert not is_lan_scoped_ip("example.com")


def test_resolve_hostname_safe():
    with patch("socket.gethostbyaddr") as reverse_dns, \
         patch("losshound.core.lan_monitor.resolve_mdns_name", return_value="router.local"), \
         patch("losshound.core.lan_monitor.resolve_llmnr_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_netbios_name", return_value=""):
        name = resolve_hostname_safe("192.168.1.1")
        assert name == "router.local"
        reverse_dns.assert_not_called()
        
    with patch("socket.gethostbyaddr") as reverse_dns, \
         patch("losshound.core.lan_monitor.resolve_mdns_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_llmnr_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_netbios_name", return_value=""):
        name = resolve_hostname_safe("192.168.1.99")
        assert name == ""
        reverse_dns.assert_not_called()


def test_resolve_hostname_safe_skips_public_reverse_dns():
    with patch("socket.gethostbyaddr") as reverse_dns, \
         patch("losshound.core.lan_monitor.resolve_mdns_name") as mdns, \
         patch("losshound.core.lan_monitor.resolve_llmnr_name") as llmnr, \
         patch("losshound.core.lan_monitor.resolve_netbios_name") as netbios:
        name = resolve_hostname_safe("8.8.8.8")
        assert name == ""
        reverse_dns.assert_not_called()
        mdns.assert_not_called()
        llmnr.assert_not_called()
        netbios.assert_not_called()


def test_resolve_mdns_name():
    from losshound.core.lan_monitor import resolve_mdns_name
    
    mock_socket = MagicMock()
    mock_payload = b"\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
    mock_payload += b"\x03107\x011\x03168\x03192\x07in-addr\x04arpa\x00\x00\x0c\x00\x01"
    mock_payload += b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\xff\x00\x13"
    mock_payload += b"\x0btest-device\x05local\x00"
    
    mock_socket.recvfrom.return_value = (mock_payload, ("192.168.1.107", 5353))
    
    with patch("socket.socket", return_value=mock_socket):
        name = resolve_mdns_name("192.168.1.107")
        assert name == "test-device"


def test_parse_arp_table():
    mock_res = MagicMock()
    mock_res.stdout = MOCK_ARP_OUTPUT.encode("cp850")
    
    with patch("subprocess.run", return_value=mock_res):
        devices = parse_arp_table("192.168.1.100")
        assert len(devices) == 2
        assert devices[0]["ip"] == "192.168.1.1"
        assert devices[0]["mac"] == "1C-3B-F3-EA-BB-CC"
        assert devices[1]["ip"] == "192.168.1.102"
        assert devices[1]["mac"] == "04-D9-F5-12-34-56"


def test_scan_local_network():
    mock_ipconfig = MagicMock()
    from tests.conftest import IPCONFIG_OUTPUT
    mock_ipconfig.stdout = IPCONFIG_OUTPUT.encode("cp850")
    
    mock_arp = MagicMock()
    mock_arp.stdout = MOCK_ARP_OUTPUT.encode("cp850")
    
    def mock_subprocess_run(args, *argv, **kwargs):
        if Path(args[0]).stem.lower() == "ipconfig":
            return mock_ipconfig
        elif Path(args[0]).stem.lower() == "arp":
            return mock_arp
        # For pings inside the sweep
        return MagicMock()
        
    # Mocking HistoryStore
    mock_history = MagicMock()
    mock_history.get_devices.return_value = []
    
    with patch("subprocess.run", side_effect=mock_subprocess_run), \
         patch("socket.gethostbyaddr") as reverse_dns, \
         patch("losshound.core.lan_monitor.resolve_mdns_name", return_value="test-device"), \
         patch("losshound.core.lan_monitor.resolve_llmnr_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_netbios_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_http_title", return_value=""), \
         patch("losshound.core.lan_monitor.scan_ssdp", return_value={}):
         
        devices = scan_local_network(mock_history)
        
        assert len(devices) == 2
        assert devices[0]["mac_address"] == "1C-3B-F3-EA-BB-CC"
        assert devices[0]["vendor"] == "HP"
        assert devices[0]["hostname"] == "test-device"
        reverse_dns.assert_not_called()
        
        # Verify db interaction
        assert mock_history.save_device.call_count == 2
        assert mock_history.save_alert.call_count == 2  # Both devices are new


def test_get_pid_to_process_name():
    mock_res = MagicMock()
    mock_res.stdout = MOCK_TASKLIST_OUTPUT.encode("cp850")
    
    with patch("subprocess.run", return_value=mock_res):
        pid_map = get_pid_to_process_name()
        assert pid_map[0] == "System Idle Process"
        assert pid_map[4] == "System"
        assert pid_map[4888] == "chrome.exe"


def test_get_active_connections():
    from losshound.core.local_monitor import _HOSTNAME_CACHE
    _HOSTNAME_CACHE.clear()

    mock_tasklist = MagicMock()
    mock_tasklist.stdout = MOCK_TASKLIST_OUTPUT.encode("cp850")
    
    mock_netstat = MagicMock()
    mock_netstat.stdout = MOCK_NETSTAT_OUTPUT.encode("cp850")
    
    def mock_subprocess_run(args, *argv, **kwargs):
        if Path(args[0]).stem.lower() == "tasklist":
            return mock_tasklist
        elif Path(args[0]).stem.lower() == "netstat":
            return mock_netstat
        return MagicMock()
        
    with patch("subprocess.run", side_effect=mock_subprocess_run), \
         patch("socket.gethostbyaddr", return_value=("google.com", [], [])) as reverse_dns:
         
        conns = get_active_connections()
        
        assert len(conns) == 1
        assert conns[0]["process"] == "chrome.exe"
        assert conns[0]["protocol"] == "TCP"
        assert conns[0]["remote_ip"] == "142.250.74.46"
        assert conns[0]["remote_port"] == "443"
        assert conns[0]["state"] == "ESTABLISHED"
        assert conns[0]["resolved_name"] == "google.com"
        reverse_dns.assert_called_once()


def test_scan_local_network_fallbacks():
    mock_ipconfig = MagicMock()
    from tests.conftest import IPCONFIG_OUTPUT
    mock_ipconfig.stdout = IPCONFIG_OUTPUT.encode("cp850")
    
    mock_arp = MagicMock()
    mock_arp.stdout = MOCK_ARP_OUTPUT.encode("cp850")
    
    def mock_subprocess_run(args, *argv, **kwargs):
        if Path(args[0]).stem.lower() == "ipconfig":
            return mock_ipconfig
        elif Path(args[0]).stem.lower() == "arp":
            return mock_arp
        return MagicMock()
        
    mock_history = MagicMock()
    mock_history.get_devices.return_value = []
    
    with patch("subprocess.run", side_effect=mock_subprocess_run), \
         patch("socket.gethostbyaddr") as reverse_dns, \
         patch("losshound.core.lan_monitor.resolve_mdns_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_netbios_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_llmnr_name", return_value=""), \
         patch("losshound.core.lan_monitor.resolve_http_title", return_value=""), \
         patch("losshound.core.lan_monitor.scan_ssdp", return_value={}):
         
        devices = scan_local_network(mock_history)
        
        # devices[0] has mac 1C-3B-F3-EA-BB-CC (HP) -> should fall back to "HP Device"
        # devices[1] has mac 04-D9-F5-12-34-56 (ASUS) -> should fall back to "ASUS Device"
        assert devices[0]["hostname"] == "HP Device"
        assert devices[1]["hostname"] == "ASUS Device"
        reverse_dns.assert_not_called()


def test_resolve_llmnr_name():
    from losshound.core.lan_monitor import resolve_llmnr_name
    
    mock_socket = MagicMock()
    # Simulating standard LLMNR DNS response: ID=0x1234, ANCOUNT=1, PTR record pointing to "win-pc"
    mock_payload = b"\x12\x34\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
    mock_payload += b"\x03107\x011\x03168\x03192\x07in-addr\x04arpa\x00\x00\x0c\x00\x01"
    mock_payload += b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\xff\x00\x08"
    mock_payload += b"\x06win-pc\x00"
    
    mock_socket.recvfrom.return_value = (mock_payload, ("192.168.1.107", 5355))
    
    with patch("socket.socket", return_value=mock_socket):
        name = resolve_llmnr_name("192.168.1.107")
        assert name == "win-pc"


def test_resolve_http_title():
    from losshound.core.lan_monitor import resolve_http_title

    body = b"<html><head><TITLE>MalFormed\nRouter Title </TITLE></head></html>"
    with patch("losshound.core.lan_monitor.fetch_device_document", return_value=body) as fetch:
        title = resolve_http_title("192.168.1.1")
        assert title == "MalFormed Router Title"
    fetch.assert_called_once_with("http://192.168.1.1/", device_ip="192.168.1.1")


def test_resolve_http_title_follows_meta_refresh():
    """Routers often serve a meta-refresh stub at / -- we should follow it once."""
    from losshound.core.lan_monitor import resolve_http_title

    # First response: meta-refresh stub with no <title>
    stub = (
        b'<html><head>'
        b'<meta http-equiv="refresh" content="0; URL=/webpages/index.html" />'
        b'</head></html>'
    )

    # Second response: the redirected page has a real title
    real = b"<html><head><title>TP-Link Router</title></head></html>"

    with patch("losshound.core.lan_monitor.fetch_device_document", side_effect=[stub, real]) as fetch:
        title = resolve_http_title("192.168.1.1")
        assert title == "TP-Link Router"
    assert fetch.call_count == 2
    fetch.assert_called_with("http://192.168.1.1/webpages/index.html", device_ip="192.168.1.1")


def test_resolve_http_title_meta_refresh_must_be_same_host():
    """Don't follow meta-refresh to an external host (avoid being redirected to a public site)."""
    from losshound.core.lan_monitor import resolve_http_title

    stub = (
        b'<html><head>'
        b'<meta http-equiv="refresh" content="0; URL=http://evil.example.com/" />'
        b'</head></html>'
    )

    with patch("losshound.core.lan_monitor.fetch_device_document", return_value=stub) as fetch:
        title = resolve_http_title("192.168.1.1")
        assert title == ""
    assert fetch.call_count == 2  # HTTP and HTTPS roots only.
    assert all(call.kwargs["device_ip"] == "192.168.1.1" for call in fetch.call_args_list)


def test_resolve_http_title_skips_public_ip():
    from losshound.core.lan_monitor import resolve_http_title

    with patch("losshound.core.lan_monitor.fetch_device_document") as fetch:
        assert resolve_http_title("8.8.8.8") == ""
        fetch.assert_not_called()


def test_scan_ssdp():
    import socket
    from losshound.core.lan_monitor import scan_ssdp
    
    mock_socket = MagicMock()
    # Simple SSDP M-SEARCH response packet with LOCATION header
    mock_response_pkt = (
        b"HTTP/1.1 200 OK\r\n"
        b"LOCATION: http://192.168.1.190:8008/device-desc.xml\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )
    mock_socket.recvfrom.side_effect = [
        (mock_response_pkt, ("192.168.1.190", 1900)),
        socket.timeout("timeout")
    ]
    
    body = b"<device><friendlyName>Google Nest Mini</friendlyName></device>"
    
    with patch("socket.socket", return_value=mock_socket), \
         patch("losshound.core.lan_monitor.fetch_device_document", return_value=body) as fetch:
        names = scan_ssdp()
        assert names.get("192.168.1.190") == "Google Nest Mini"
    fetch.assert_called_once_with("http://192.168.1.190:8008/device-desc.xml", device_ip="192.168.1.190", timeout=2.0)


def test_scan_ssdp_ignores_public_location():
    import socket
    from losshound.core.lan_monitor import scan_ssdp

    mock_socket = MagicMock()
    mock_response_pkt = (
        b"HTTP/1.1 200 OK\r\n"
        b"LOCATION: http://8.8.8.8/device-desc.xml\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )
    mock_socket.recvfrom.side_effect = [
        (mock_response_pkt, ("192.168.1.190", 1900)),
        socket.timeout("timeout")
    ]

    with patch("socket.socket", return_value=mock_socket), \
         patch("losshound.core.lan_monitor.fetch_device_document") as fetch:
        assert scan_ssdp() == {}
        fetch.assert_not_called()
