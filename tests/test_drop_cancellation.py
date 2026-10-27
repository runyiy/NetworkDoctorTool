from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from losshound.core import drop_analyzer, subprocess_runner


def _controlled_probes(monkeypatch):
    state = SimpleNamespace(now=0.0, stopped=False, pings=0, events=0)
    monkeypatch.setattr(drop_analyzer.time, "monotonic", lambda: state.now)

    def advance(seconds):
        state.now += seconds

    monkeypatch.setattr(drop_analyzer.time, "sleep", advance)
    monkeypatch.setattr(drop_analyzer, "_get_active_nic_info", lambda: ("ethernet", True, 1000.0))
    monkeypatch.setattr(drop_analyzer, "_quick_ping", lambda *args: (True, 2.0))
    monkeypatch.setattr(drop_analyzer, "_quick_dns", lambda: True)

    def events(**kwargs):
        state.events += 1
        return []

    monkeypatch.setattr(drop_analyzer, "_get_network_events", events)
    return state


def test_stop_before_first_sample_does_not_start_any_queries(monkeypatch):
    state = _controlled_probes(monkeypatch)
    nic = MagicMock()
    monkeypatch.setattr(drop_analyzer, "_get_active_nic_info", nic)
    report = drop_analyzer.run_drop_analysis("192.168.1.1", stop_check=lambda: True)
    assert report.total_samples == 0
    assert report.verdict == "Insufficient data"
    assert state.events == 0
    nic.assert_not_called()


def test_stop_during_ping_keeps_completed_samples_and_skips_event_queries(monkeypatch):
    state = _controlled_probes(monkeypatch)

    def ping(*args):
        state.pings += 1
        if state.pings == 3:
            state.stopped = True
            raise InterruptedError("controlled child cancellation")
        return True, 2.0

    monkeypatch.setattr(drop_analyzer, "_quick_ping", ping)
    live_samples = []
    report = drop_analyzer.run_drop_analysis(
        "192.168.1.1", duration_seconds=10, poll_interval=1, stop_check=lambda: state.stopped,
        sample_callback=live_samples.append,
    )
    assert report.total_samples == 1
    assert report.samples[0].gateway_reachable
    assert live_samples == report.samples
    assert state.events == 0
    assert report.events == []


def test_timed_scan_emits_samples_before_report_and_marks_periodic_dns(monkeypatch):
    state = _controlled_probes(monkeypatch)
    live_samples, progress = [], []
    dns = MagicMock(side_effect=[False, True])
    monkeypatch.setattr(drop_analyzer, "_quick_dns", dns)

    def events(**kwargs):
        # Updates must have arrived before final event-log collection begins.
        assert len(live_samples) == 6
        assert progress[-1] == "Preparing report from 6 samples..."
        assert state.now >= 6
        return []

    monkeypatch.setattr(drop_analyzer, "_get_network_events", events)
    report = drop_analyzer.run_drop_analysis(
        "192.168.1.1", duration_seconds=6, poll_interval=1,
        sample_callback=live_samples.append, progress_callback=progress.append,
    )
    assert report.samples == live_samples
    assert report.total_samples == 6
    assert [s.dns_checked for s in live_samples] == [True, False, False, False, False, True]
    assert live_samples[0].dns_ok is False
    assert live_samples[-1].dns_ok is True
    assert dns.call_count == 2
    assert 6 <= report.scan_duration_seconds < 6.3


def test_stop_between_probes_starts_no_further_ping_or_dns(monkeypatch):
    state = _controlled_probes(monkeypatch)

    def nic():
        state.stopped = True
        return "ethernet", True, 1000.0

    probe = MagicMock()
    monkeypatch.setattr(drop_analyzer, "_get_active_nic_info", nic)
    monkeypatch.setattr(drop_analyzer, "_quick_ping", probe)
    monkeypatch.setattr(drop_analyzer, "_quick_dns", probe)
    report = drop_analyzer.run_drop_analysis("192.168.1.1", stop_check=lambda: state.stopped)
    assert report.total_samples == 0
    assert state.events == 0
    probe.assert_not_called()


def test_stop_during_event_query_still_returns_collected_samples(monkeypatch):
    state = _controlled_probes(monkeypatch)

    def events(**kwargs):
        state.stopped = True
        raise InterruptedError("controlled event query cancellation")

    monkeypatch.setattr(drop_analyzer, "_get_network_events", events)
    report = drop_analyzer.run_drop_analysis(
        "192.168.1.1", duration_seconds=1, poll_interval=1, stop_check=lambda: state.stopped,
    )
    assert report.total_samples == 1
    assert report.events == []


def test_unrelated_interruption_is_not_swallowed(monkeypatch):
    _controlled_probes(monkeypatch)
    monkeypatch.setattr(drop_analyzer, "_quick_ping", MagicMock(side_effect=InterruptedError))
    with pytest.raises(InterruptedError):
        drop_analyzer.run_drop_analysis("192.168.1.1", stop_check=lambda: False)


def test_drop_dns_and_event_queries_reach_trusted_windows_executables(monkeypatch):
    proc = MagicMock()
    proc.poll.return_value = 0
    proc.communicate.side_effect = [("Address: 192.0.2.1\n", ""), ("", ""), ("", "")]
    popen = MagicMock(return_value=proc)
    monkeypatch.setattr(subprocess_runner.subprocess, "Popen", popen)
    assert drop_analyzer._quick_dns("example.com") is True
    assert drop_analyzer._get_network_events() == []
    commands = [Path(call.args[0][0]) for call in popen.call_args_list]
    assert [command.name.lower() for command in commands] == ["nslookup.exe", "wevtutil.exe", "wevtutil.exe"]
    assert all(command.is_absolute() for command in commands)
