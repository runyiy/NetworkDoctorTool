import sys
from unittest.mock import patch

import pytest

from losshound.core import icmp_ping
from losshound.core.ping import ping

needs_native_icmp = pytest.mark.skipif(
    sys.platform != "win32" or not icmp_ping.available(),
    reason="Native ICMP API only available on Windows",
)


@needs_native_icmp
def test_send_echoes_loopback():
    rtts = icmp_ping.send_echoes("127.0.0.1", count=2, timeout_ms=1000, interval_s=0.05)
    assert len(rtts) == 2
    for rtt in rtts:
        assert 0.0 < rtt < 100.0


@needs_native_icmp
def test_send_echoes_unroutable_returns_no_rtts():
    # TEST-NET-1 (RFC 5737) — never routable, every probe is a loss.
    rtts = icmp_ping.send_echoes("192.0.2.1", count=2, timeout_ms=200, interval_s=0.05)
    assert rtts == []


@needs_native_icmp
def test_ping_uses_native_path_for_ipv4_literal():
    with patch("losshound.core.ping.run_subprocess_interruptible") as mock_run:
        result = ping("127.0.0.1", count=2, timeout_ms=1000)

    mock_run.assert_not_called()
    assert result.packets_sent == 2
    assert result.packets_received == 2
    assert result.loss_percent == 0.0
    assert result.rtt_avg is not None
    assert result.is_healthy


def test_ping_falls_back_to_subprocess_for_hostname():
    with patch("losshound.core.ping.run_subprocess_interruptible") as mock_run:
        mock_run.return_value = (
            "Reply from 1.2.3.4: bytes=32 time=12ms TTL=118", "", 0
        )
        result = ping("example.com", count=1, timeout_ms=1000)

    mock_run.assert_called_once()
    assert result.packets_received == 1
    assert result.rtt_avg == 12.0


def test_ping_falls_back_when_native_unavailable():
    with patch("losshound.core.icmp_ping.available", return_value=False), \
         patch("losshound.core.ping.run_subprocess_interruptible") as mock_run:
        mock_run.return_value = (
            "Reply from 8.8.8.8: bytes=32 time=9ms TTL=118", "", 0
        )
        result = ping("8.8.8.8", count=1, timeout_ms=1000)

    mock_run.assert_called_once()
    assert result.packets_received == 1


def test_invalid_target_short_circuits():
    result = ping("bad target; rm", count=4)
    assert result.error == "Invalid target"
    assert result.loss_percent == 100.0
