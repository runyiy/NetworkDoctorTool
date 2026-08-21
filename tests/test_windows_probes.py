import socket
import subprocess
import threading
import time

import pytest

import network_doctor.windows_probes as windows_probes
from network_doctor.models import PingStats
from network_doctor.windows_probes import (
    CommandResult,
    ProbeUnavailable,
    WindowsProbes,
    parse_adapter_json,
    parse_ping_output,
    parse_wifi_signal,
    run_command,
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


@pytest.mark.parametrize("value", [101, 999])
def test_wifi_signal_parser_rejects_percentages_above_one_hundred(value):
    """Catches malformed netsh percentages crossing into diagnostic evidence."""
    assert parse_wifi_signal(f"Signal : {value}%") is None


def test_adapter_json_accepts_one_object_and_normalizes_scalar_network_values():
    """Catches a parser that assumes PowerShell always emits an array."""
    output = (
        '{"Name":"Wi-Fi","Kind":"Wi-Fi","Connected":true,"Enabled":true,'
        '"IPv4":"192.168.1.4","IPv6":"2001:db8::4",'
        '"DhcpEnabled":true,"Gateway":"192.168.1.1",'
        '"Dns":["1.1.1.1"]}'
    )

    adapters = parse_adapter_json(output)

    assert adapters[0].ipv4_addresses == ("192.168.1.4",)
    assert adapters[0].ipv6_addresses == ("2001:db8::4",)
    assert adapters[0].dns_servers == ("1.1.1.1",)


@pytest.mark.parametrize("output", ["", "   \n\t", "not JSON"])
def test_adapter_json_returns_no_adapters_for_empty_or_malformed_documents(output):
    """Catches a parser that raises or invents an adapter for unusable JSON."""
    assert parse_adapter_json(output) == ()


def test_adapter_json_keeps_valid_list_records_and_ignores_malformed_entries():
    """Catches a parser that rejects a JSON array or lets malformed records through."""
    output = """[
        {"Name":"Ethernet","Kind":"Ethernet","Connected":true,"Enabled":true,
         "IPv4":["10.0.0.4","10.0.0.5"],"DhcpEnabled":false,
         "Gateway":"10.0.0.1","Dns":["1.1.1.1","8.8.8.8"]},
        {"Name":"missing kind"},
        42
    ]"""

    adapters = parse_adapter_json(output)

    assert len(adapters) == 1
    assert adapters[0].name == "Ethernet"
    assert adapters[0].ipv4_addresses == ("10.0.0.4", "10.0.0.5")
    assert adapters[0].dns_servers == ("1.1.1.1", "8.8.8.8")


def test_run_command_decodes_timeout_output_before_a_ping_parser_consumes_it(monkeypatch):
    """Catches byte timeout output that would make the text ping parser raise TypeError."""
    def timed_out_process(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            args[0], kwargs["timeout"], output=b"Reply from 1.1.1.1: time=12ms TTL=57", stderr=b"timed out"
        )

    monkeypatch.setattr(windows_probes.subprocess, "run", timed_out_process)

    result = run_command(["ping.exe", "1.1.1.1"], timeout_seconds=1.0)

    assert result.stdout == "Reply from 1.1.1.1: time=12ms TTL=57"
    assert result.stderr == "timed out"
    assert result.timed_out is True
    assert parse_ping_output(result.stdout, "1.1.1.1", sent=1).latencies_ms == (12.0,)


def test_run_command_returns_unavailable_evidence_when_process_launch_raises_os_error(monkeypatch):
    """Catches built-in command launch errors that otherwise escape the probe boundary."""
    def unavailable_process(*args, **kwargs):
        raise OSError("ping.exe unavailable")

    monkeypatch.setattr(windows_probes.subprocess, "run", unavailable_process)

    result = run_command(["ping.exe", "1.1.1.1"], timeout_seconds=1.0)

    assert result == CommandResult(-1, "", "ping.exe unavailable")


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


def test_ping_uses_explicit_ipv6_flag_for_an_ipv6_path():
    """Catches an IPv6 diagnostic silently following Windows' default address family."""
    calls = []

    def fake_runner(args, timeout_seconds):
        calls.append((args, timeout_seconds))
        return CommandResult(0, "Reply from 2001:4860:4860::8888: time=42ms TTL=116", "")

    result = WindowsProbes(command_runner=fake_runner).ping(
        "2001:4860:4860::8888", count=10, timeout_ms=1000, address_family=6
    )

    assert calls == [
        (
            [
                "ping.exe",
                "-6",
                "-n",
                "10",
                "-w",
                "1000",
                "2001:4860:4860::8888",
            ],
            pytest.approx(12.0),
        )
    ]
    assert result.latencies_ms == (42.0,)


def test_tcp_reachable_returns_false_after_every_injected_connection_failure():
    """Catches a probe that leaks a socket exception instead of reporting no reachability."""
    attempted = []

    def failing_connection(endpoint, timeout_seconds):
        attempted.append((endpoint, timeout_seconds))
        raise ConnectionRefusedError("refused")

    result = WindowsProbes(create_connection=failing_connection).tcp_reachable(
        [("1.1.1.1", 443), ("8.8.8.8", 53)], timeout_seconds=0.25
    )

    assert result is False
    assert attempted == [(("1.1.1.1", 443), 0.25), (("8.8.8.8", 53), 0.25)]


def test_tcp_reachable_returns_unavailable_for_local_permission_failure():
    """Catches a local socket-permission failure being misreported as remote unreachability."""
    def permission_denied(endpoint, timeout_seconds):
        raise PermissionError("access denied")

    result = WindowsProbes(create_connection=permission_denied).tcp_reachable(
        [("1.1.1.1", 443)], timeout_seconds=0.25
    )

    assert result is None


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


def test_resolve_returns_false_for_a_completed_dns_name_failure():
    """Catches a negative DNS answer being collapsed into unavailable evidence."""
    def missing_name(hostname, port):
        raise socket.gaierror(socket.EAI_NONAME, "name not known")

    result = WindowsProbes(getaddrinfo=missing_name).resolve(
        "missing.example", timeout_seconds=0.1
    )

    assert result is False


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


@pytest.mark.parametrize(
    "result",
    [
        CommandResult(-1, "", "powershell.exe unavailable"),
        CommandResult(-1, "", "", timed_out=True),
        CommandResult(1, "", "PowerShell failed"),
        CommandResult(0, "not JSON", ""),
        CommandResult(0, "{}", ""),
        CommandResult(0, "[42]", ""),
    ],
)
def test_collect_adapters_marks_command_or_parser_failures_as_unavailable(result):
    """Catches PowerShell failures being misread as evidence that no adapter is connected."""
    probes = WindowsProbes(command_runner=lambda args, timeout_seconds: result)

    with pytest.raises(ProbeUnavailable):
        probes.collect_adapters()


def test_collect_adapters_returns_no_adapters_for_successful_empty_stdout():
    """Catches the production zero-row PowerShell output being treated as a probe failure."""
    probes = WindowsProbes(
        command_runner=lambda args, timeout_seconds: CommandResult(0, "", "")
    )

    assert probes.collect_adapters() == ()


@pytest.mark.parametrize(
    "result",
    [
        CommandResult(-1, "", "ping.exe unavailable"),
        CommandResult(-1, "", "", timed_out=True),
    ],
)
def test_ping_marks_command_launch_or_timeout_failure_as_unavailable(result):
    """Catches an unstarted or timed-out ping being treated as a real zero-reply probe."""
    probes = WindowsProbes(command_runner=lambda args, timeout_seconds: result)

    with pytest.raises(ProbeUnavailable):
        probes.ping("1.1.1.1", count=4, timeout_ms=1000)


def test_ping_keeps_legitimate_nonzero_no_reply_result_as_network_evidence():
    """Catches a probe that labels an executed, zero-reply ping as an unavailable command."""
    probes = WindowsProbes(
        command_runner=lambda args, timeout_seconds: CommandResult(
            1, "Request timed out.\n", ""
        )
    )

    result = probes.ping("1.1.1.1", count=4, timeout_ms=1000)

    assert result == PingStats("1.1.1.1", 4, ())


def test_wifi_signal_uses_successful_netsh_output_and_returns_no_signal_when_absent():
    """Catches a probe that does not use the WLAN command or guesses a missing signal."""
    calls = []

    def fake_runner(args, timeout_seconds):
        calls.append((args, timeout_seconds))
        return CommandResult(0, "There is no wireless interface on the system.", "")

    signal = WindowsProbes(command_runner=fake_runner).wifi_signal()

    assert signal is None
    assert calls == [(["netsh.exe", "wlan", "show", "interfaces"], pytest.approx(5.0))]


@pytest.mark.parametrize(
    "result",
    [
        CommandResult(-1, "Signal : 74%", "netsh.exe unavailable"),
        CommandResult(-1, "Signal : 74%", "", timed_out=True),
        CommandResult(1, "Signal : 74%", "netsh failed"),
    ],
)
def test_wifi_signal_marks_launch_timeout_or_nonzero_results_unavailable(result):
    """Catches partial netsh stdout being parsed after the command did not complete successfully."""
    probes = WindowsProbes(command_runner=lambda args, timeout_seconds: result)

    with pytest.raises(ProbeUnavailable):
        probes.wifi_signal()
