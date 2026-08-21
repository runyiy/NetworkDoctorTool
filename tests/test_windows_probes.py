import threading
import time

import pytest

from network_doctor.windows_probes import (
    CommandResult,
    WindowsProbes,
    parse_adapter_json,
    parse_ping_output,
    parse_wifi_signal,
)


def test_ping_parser_keeps_successful_english_replies_when_one_packet_is_lost():
    """Catches a parser that treats a nonzero loss as a total ping failure."""
    output = """Reply from 1.1.1.1: bytes=32 time=18ms TTL=57
Request timed out.
Reply from 1.1.1.1: bytes=32 time=25ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57"""

    stats = parse_ping_output(output, "1.1.1.1", sent=4)

    assert stats.latencies_ms == (18.0, 25.0, 1.0)
    assert stats.packet_loss_percent == 25.0


def test_ping_parser_extracts_chinese_reply_times_without_translating_output():
    """Catches a parser coupled to English ping reply labels."""
    output = """来自 192.168.1.1 的回复: 字节=32 时间=3ms TTL=64
请求超时。
来自 192.168.1.1 的回复: 字节=32 时间<1ms TTL=64"""

    stats = parse_ping_output(output, "192.168.1.1", sent=3)

    assert stats.latencies_ms == (3.0, 1.0)


def test_wifi_signal_parser_returns_the_percent_number_not_other_interface_numbers():
    """Catches a parser that returns an incidental number instead of signal percent."""
    output = """    BSSID                  : 12:34:56:78:90:12
    Signal                 : 74%
    Channel                : 6
"""

    assert parse_wifi_signal(output) == 74


def test_adapter_json_accepts_one_object_and_normalizes_scalar_network_values():
    """Catches a parser that assumes PowerShell always emits an array."""
    output = (
        '{"Name":"Wi-Fi","Kind":"Wi-Fi","Connected":true,"Enabled":true,'
        '"IPv4":"192.168.1.4","DhcpEnabled":true,"Gateway":"192.168.1.1",'
        '"Dns":["1.1.1.1"]}'
    )

    adapters = parse_adapter_json(output)

    assert adapters[0].ipv4_addresses == ("192.168.1.4",)
    assert adapters[0].dns_servers == ("1.1.1.1",)


def test_ping_uses_windows_count_and_timeout_flags_when_a_reply_arrives():
    """Catches a probe that omits Windows ping limits or discards partial success."""
    calls = []

    def fake_runner(args, timeout_seconds):
        calls.append((args, timeout_seconds))
        return CommandResult(1, "Reply from 1.1.1.1: time=12ms TTL=57", "")

    probes = WindowsProbes(command_runner=fake_runner)

    result = probes.ping("1.1.1.1", count=4, timeout_ms=1000)

    assert calls == [(["ping.exe", "-n", "4", "-w", "1000", "1.1.1.1"], pytest.approx(6.0))]
    assert result.reachable is True
    assert result.latencies_ms == (12.0,)


def test_tcp_reachable_returns_false_after_every_injected_connection_failure():
    """Catches a probe that leaks a socket exception instead of reporting no reachability."""
    attempted = []

    def failing_connection(endpoint, timeout_seconds):
        attempted.append((endpoint, timeout_seconds))
        raise OSError("refused")

    result = WindowsProbes(create_connection=failing_connection).tcp_reachable(
        [("1.1.1.1", 443), ("8.8.8.8", 53)], timeout_seconds=0.25
    )

    assert result is False
    assert attempted == [(("1.1.1.1", 443), 0.25), (("8.8.8.8", 53), 0.25)]


def test_tcp_reachable_stops_after_the_first_successful_injected_connection():
    """Catches a probe that keeps opening sockets after reachability is established."""
    attempted = []

    class SuccessfulConnection:
        def close(self):
            attempted.append("closed")

    def connection_with_first_success(endpoint, timeout_seconds):
        attempted.append(endpoint)
        return SuccessfulConnection()

    result = WindowsProbes(create_connection=connection_with_first_success).tcp_reachable(
        [("1.1.1.1", 443), ("8.8.8.8", 53)], timeout_seconds=0.25
    )

    assert result is True
    assert attempted == [("1.1.1.1", 443), "closed"]


def test_resolve_returns_none_when_the_injected_lookup_raises_an_os_error():
    """Catches a probe that exposes DNS lookup errors to its caller."""
    def failing_lookup(hostname, port):
        raise OSError("DNS unavailable")

    result = WindowsProbes(getaddrinfo=failing_lookup).resolve("example.test", timeout_seconds=0.1)

    assert result is None


def test_resolve_returns_none_after_a_bounded_wait_for_a_stuck_lookup():
    """Catches a resolver that invokes a blocking getaddrinfo call on the caller thread."""
    started = threading.Event()
    release = threading.Event()

    def stuck_lookup(hostname, port):
        started.set()
        release.wait()
        return [(2, 1, 6, "", ("127.0.0.1", 0))]

    try:
        start = time.monotonic()
        result = WindowsProbes(getaddrinfo=stuck_lookup).resolve("example.test", timeout_seconds=0.05)
        elapsed = time.monotonic() - start
    finally:
        release.set()

    assert started.is_set()
    assert result is None
    assert elapsed < 0.25


def test_collect_adapters_runs_noninteractive_powershell_and_parses_its_json():
    """Catches a collector that invokes an interactive shell or ignores its JSON result."""
    calls = []

    def fake_runner(args, timeout_seconds):
        calls.append((args, timeout_seconds))
        return CommandResult(
            0,
            '[{"Name":"Ethernet","Kind":"Ethernet","Connected":true,"Enabled":true,'
            '"IPv4":["10.0.0.4"],"DhcpEnabled":false,"Gateway":"10.0.0.1","Dns":[]}]',
            "",
        )

    adapters = WindowsProbes(command_runner=fake_runner).collect_adapters()

    assert calls[0][0][:5] == ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
    assert len(calls[0][0]) == 6
    assert calls[0][1] == pytest.approx(10.0)
    assert adapters[0].name == "Ethernet"
    assert adapters[0].gateway == "10.0.0.1"


def test_wifi_signal_uses_netsh_output_and_returns_no_signal_when_absent():
    """Catches a probe that does not use the WLAN command or guesses a missing signal."""
    calls = []

    def fake_runner(args, timeout_seconds):
        calls.append((args, timeout_seconds))
        return CommandResult(1, "There is no wireless interface on the system.", "")

    signal = WindowsProbes(command_runner=fake_runner).wifi_signal()

    assert signal is None
    assert calls == [(["netsh.exe", "wlan", "show", "interfaces"], pytest.approx(5.0))]
