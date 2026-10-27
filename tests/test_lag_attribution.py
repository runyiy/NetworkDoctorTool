import sys

import pytest

from losshound.core.lag_attribution import (
    ProcessSuspect,
    ThroughputSample,
    build_suspects,
    decide_verdict,
    sample_throughput,
    throughput_available,
)


def _conn(process="steam.exe", pid=100, state="ESTABLISHED",
          remote_ip="1.2.3.4", resolved_name="cdn.steam.com", proto="TCP"):
    return {
        "process": process,
        "pid": str(pid),
        "protocol": proto,
        "local_address": "192.168.1.5:50000",
        "remote_ip": remote_ip,
        "remote_port": "443",
        "state": state,
        "resolved_name": resolved_name,
    }


def test_suspects_ranked_by_connection_count():
    conns = (
        [_conn("steam.exe", 100)] * 5
        + [_conn("chrome.exe", 200)] * 3
        + [_conn("discord.exe", 300)] * 1
    )
    suspects = build_suspects(conns, own_pid=999)
    assert [s.process for s in suspects] == ["steam.exe", "chrome.exe", "discord.exe"]
    assert suspects[0].connection_count == 5
    assert suspects[0].top_remote == "cdn.steam.com"


def test_suspects_exclude_own_process_and_unknowns():
    conns = [
        _conn("python.exe", pid=555),
        _conn("Unknown", pid=1),
        _conn("chrome.exe", pid=200),
    ]
    suspects = build_suspects(conns, own_pid=555)
    assert [s.process for s in suspects] == ["chrome.exe"]


def test_suspects_skip_non_established_tcp_but_keep_udp():
    conns = [
        _conn("chrome.exe", state="TIME_WAIT"),
        _conn("game.exe", state="", proto="UDP"),
    ]
    suspects = build_suspects(conns, own_pid=999)
    assert [s.process for s in suspects] == ["game.exe"]


def test_verdict_local_saturation_by_utilization():
    sample = ThroughputSample(
        down_mbps=80.0, up_mbps=2.0, link_speed_mbps=100.0, utilization_pct=80.0
    )
    suspects = [ProcessSuspect("steam.exe", 100, 12)]
    verdict, detail = decide_verdict(sample, suspects)
    assert verdict == "local_saturation"
    assert "steam.exe" in detail


def test_verdict_local_saturation_by_absolute_throughput():
    # No link speed known (common on WiFi virtual adapters) — absolute floor.
    sample = ThroughputSample(down_mbps=90.0, up_mbps=5.0)
    verdict, _ = decide_verdict(sample, [])
    assert verdict == "local_saturation"


def test_verdict_external_when_link_quiet():
    sample = ThroughputSample(down_mbps=0.4, up_mbps=0.1,
                              link_speed_mbps=1000.0, utilization_pct=0.04)
    verdict, detail = decide_verdict(sample, [])
    assert verdict == "external"
    assert "external" in detail


def test_verdict_inconclusive_between_thresholds():
    sample = ThroughputSample(down_mbps=15.0, up_mbps=3.0,
                              link_speed_mbps=1000.0, utilization_pct=1.5)
    verdict, _ = decide_verdict(sample, [])
    assert verdict == "inconclusive"


def test_verdict_inconclusive_without_sample():
    verdict, _ = decide_verdict(None, [])
    assert verdict == "inconclusive"


def test_verdict_saturation_against_known_line_capacity():
    # 27 Mbps on a 2.5GbE LAN looks tiny, but on a 35 Mbps line it's 77%.
    sample = ThroughputSample(down_mbps=27.0, up_mbps=0.2,
                              link_speed_mbps=2500.0, utilization_pct=1.1)
    verdict, detail = decide_verdict(sample, [], capacity_mbps=35.0)
    assert verdict == "local_saturation"
    assert "% of your line" in detail


def test_verdict_capacity_needs_minimum_throughput():
    # 77% of a 3 Mbps line is still only ~2 Mbps — too little to blame.
    sample = ThroughputSample(down_mbps=2.2, up_mbps=0.1)
    verdict, _ = decide_verdict(sample, [], capacity_mbps=3.0)
    assert verdict == "external"


@pytest.mark.skipif(
    sys.platform != "win32" or not throughput_available(),
    reason="GetIfTable only available on Windows",
)
def test_sample_throughput_live():
    sample = sample_throughput(interval_s=0.25)
    assert sample.down_mbps >= 0.0
    assert sample.up_mbps >= 0.0
    # An active machine always has at least one operational interface.
    assert sample.interface != ""
