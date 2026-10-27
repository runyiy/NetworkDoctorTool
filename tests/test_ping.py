from datetime import datetime

from losshound.core.ping import _parse_ping_output
from tests.conftest import PING_SUCCESS_OUTPUT, PING_PARTIAL_LOSS_OUTPUT, PING_TIMEOUT_OUTPUT


def test_parse_success():
    result = _parse_ping_output(PING_SUCCESS_OUTPUT, "1.1.1.1", datetime.now(), 4)
    assert result.packets_sent == 4
    assert result.packets_received == 4
    assert result.loss_percent == 0.0
    assert result.rtt_min == 11.0
    assert result.rtt_max == 13.0
    assert result.rtt_avg == 12.0
    assert not result.timed_out
    assert result.is_healthy


def test_parse_partial_loss():
    result = _parse_ping_output(PING_PARTIAL_LOSS_OUTPUT, "8.8.8.8", datetime.now(), 4)
    assert result.packets_sent == 4
    assert result.packets_received == 2
    assert result.loss_percent == 50.0
    assert result.rtt_avg == 14.5
    assert not result.timed_out
    assert not result.is_healthy


def test_parse_timeout():
    result = _parse_ping_output(PING_TIMEOUT_OUTPUT, "192.168.1.1", datetime.now(), 4)
    assert result.packets_sent == 4
    assert result.packets_received == 0
    assert result.loss_percent == 100.0
    assert result.rtt_avg is None
    assert result.timed_out
    assert not result.is_healthy

def test_parse_jitter():
    result = _parse_ping_output(PING_SUCCESS_OUTPUT, "1.1.1.1", datetime.now(), 4)
    # RTT values: 12, 11, 13, 12 -> diffs: 1, 2, 1 -> mean = 1.333
    assert result.rtt_jitter is not None
    assert 1.0 <= result.rtt_jitter <= 2.0


def test_ping_builds_arg_list():
    """The subprocess fallback must call ping.exe directly, no shell wrapping."""
    from unittest.mock import patch
    from losshound.core.ping import ping

    with patch("losshound.core.ping.run_subprocess_interruptible") as mock_run, \
         patch("losshound.core.icmp_ping.available", return_value=False):
        mock_run.return_value = ("time=12ms time=11ms time=13ms time=12ms", "", 0)
        ping("8.8.8.8", count=4, timeout_ms=2000)

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert isinstance(args, list)
        assert args[0] == "ping"
        assert "-n" in args
        assert "8.8.8.8" in args
        # Check there is no cmd or shell wrapping
        assert "cmd" not in args
        assert "cmd.exe" not in args
        assert "/c" not in args


def test_parse_non_english_ping_output():
    # Simulated Turkish Windows ping output where "statistics" is "istatistiği" (does not contain "stat")
    turkish_output = (
        "8.8.8.8 adresinden yanit: bayt=32 sure=10ms TTL=118\n"
        "8.8.8.8 adresinden yanit: bayt=32 sure=12ms TTL=118\n"
        "8.8.8.8 adresinden yanit: bayt=32 sure=11ms TTL=118\n"
        "8.8.8.8 adresinden yanit: bayt=32 sure=9ms TTL=118\n"
        "\n"
        "8.8.8.8 icin Ping istatistigi:\n"
        "    Paket: Giden = 4, Gelen = 4, Kaybolan = 0 (%0 kayip),\n"
        "Tahmini yuvarlak dur-kalk sureleri milisaniye cinsinden:\n"
        "    En kucuk = 9ms, En buyuk = 12ms, Ortalama = 10ms\n"
    )
    result = _parse_ping_output(turkish_output, "8.8.8.8", datetime.now(), 4)
    # The average 10ms from the footer should NOT be counted because the footer lines do not have "ttl"
    assert result.packets_sent == 4
    assert result.packets_received == 4
    assert result.loss_percent == 0.0
    assert result.rtt_min == 9.0
    assert result.rtt_max == 12.0
    assert result.rtt_avg == 10.5


