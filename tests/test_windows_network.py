import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from losshound.core.windows_network import (
    _parse_interface_json,
    get_active_network_interface,
)


def _payload(**overrides):
    data = {
        "InterfaceAlias": "Ethernet 2",
        "InterfaceIndex": 17,
        "Gateway": "192.168.50.1",
        "IPv4Address": "192.168.50.20",
        "PrefixLength": 24,
        "DnsServers": ["1.1.1.1", "8.8.8.8"],
        "DhcpEnabled": True,
        "Connected": True,
        "LinkSpeedMbps": 1000.0,
        "MacAddress": "00-11-22-33-44-55",
    }
    data.update(overrides)
    return json.dumps(data)


def test_parse_active_interface_json():
    state = _parse_interface_json(_payload())

    assert state is not None
    assert state.interface_alias == "Ethernet 2"
    assert state.gateway == "192.168.50.1"
    assert state.dns_servers == ("1.1.1.1", "8.8.8.8")
    assert state.dhcp_enabled is True
    assert state.link_speed_mbps == 1000.0
    assert state.mac_address == "00-11-22-33-44-55"


def test_parse_active_interface_rejects_incomplete_or_invalid_json():
    assert _parse_interface_json("not json") is None
    assert _parse_interface_json(_payload(Gateway="")) is None
    assert _parse_interface_json(_payload(InterfaceIndex="17")) is None


def test_active_interface_query_uses_locale_independent_json():
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=_payload(), stderr="",
    )
    with patch("subprocess.run", return_value=completed) as run:
        state = get_active_network_interface()

    assert state is not None
    command = run.call_args.args[0]
    assert Path(command[0]).is_absolute()
    assert Path(command[0]).name.lower() == "powershell.exe"
    assert "ConvertTo-Json" in command[-1]


def test_active_interface_query_handles_command_failure():
    completed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="Get-NetRoute failed",
    )
    with patch("subprocess.run", return_value=completed):
        assert get_active_network_interface() is None
