from dataclasses import replace

import pytest

from network_doctor.analysis import analyze, format_report, jitter_label, latency_label, loss_label
from network_doctor.models import AdapterInfo, CheckState, PingStats, ProbeSnapshot


def healthy_snapshot() -> ProbeSnapshot:
    adapter = AdapterInfo(
        name="Wi-Fi",
        kind="Wi-Fi",
        connected=True,
        enabled=True,
        ipv4_addresses=("192.168.1.20",),
        dhcp_enabled=True,
        gateway="192.168.1.1",
        dns_servers=("1.1.1.1",),
        wifi_signal_percent=80,
    )
    return ProbeSnapshot(
        adapters=(adapter,),
        active_adapter=adapter,
        gateway_ping=PingStats("192.168.1.1", 4, (2.0, 3.0, 2.0, 3.0)),
        internet_pings=(
            PingStats("1.1.1.1", 6, (30.0,) * 6),
            PingStats("8.8.8.8", 6, (32.0,) * 6),
        ),
        tcp_reachable=None,
        dns_results=(("example.com", True), ("cloudflare.com", True)),
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [(49.99, "优秀"), (50, "良好"), (70, "略高"), (150, "较高"), (300, "非常高")],
)
def test_latency_label_changes_at_each_documented_boundary(value, expected):
    assert latency_label(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(14.99, "稳定"), (15, "轻微波动"), (30, "存在波动"), (60, "波动明显"), (100, "非常不稳定")],
)
def test_jitter_label_changes_at_each_documented_boundary(value, expected):
    assert jitter_label(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, "正常"), (1, "偶发丢包"), (5, "连接不稳定"), (25, "严重丢包")],
)
def test_loss_label_changes_at_each_documented_boundary(value, expected):
    assert loss_label(value) == expected


def test_no_connected_adapter_is_the_primary_problem():
    report = analyze(replace(healthy_snapshot(), adapters=(), active_adapter=None))

    assert report.overall is CheckState.ERROR
    assert report.primary_problem == "未连接到可用网络适配器"


def test_missing_ipv4_is_the_primary_problem_for_active_adapter():
    adapter = replace(healthy_snapshot().active_adapter, ipv4_addresses=())

    report = analyze(replace(healthy_snapshot(), active_adapter=adapter))

    assert report.overall is CheckState.ERROR
    assert report.primary_problem == "未获取到 IPv4 地址"


def test_apipa_has_priority_over_missing_gateway():
    adapter = replace(
        healthy_snapshot().active_adapter,
        ipv4_addresses=("169.254.10.20",),
        gateway=None,
    )

    report = analyze(replace(healthy_snapshot(), active_adapter=adapter))

    assert report.overall is CheckState.ERROR
    assert report.primary_problem == "DHCP 获取地址失败"


def test_missing_gateway_is_the_primary_problem_after_valid_ipv4():
    adapter = replace(healthy_snapshot().active_adapter, gateway=None)

    report = analyze(replace(healthy_snapshot(), active_adapter=adapter))

    assert report.overall is CheckState.ERROR
    assert report.primary_problem == "缺少默认网关"


def test_unreachable_gateway_is_the_primary_problem():
    snapshot = replace(
        healthy_snapshot(),
        gateway_ping=PingStats("192.168.1.1", 4, ()),
    )

    report = analyze(snapshot)

    assert report.overall is CheckState.ERROR
    assert report.primary_problem == "默认网关无法访问"


def test_internet_failure_requires_false_public_ping_and_tcp_evidence():
    snapshot = replace(
        healthy_snapshot(),
        internet_pings=(PingStats("1.1.1.1", 6, ()), PingStats("8.8.8.8", 6, ())),
        tcp_reachable=False,
    )

    report = analyze(snapshot)

    assert report.overall is CheckState.ERROR
    assert report.primary_problem == "互联网连接可能异常"


def test_unavailable_public_evidence_is_not_reported_as_internet_failure():
    snapshot = replace(
        healthy_snapshot(),
        internet_pings=(PingStats("1.1.1.1", 0, ()), PingStats("8.8.8.8", 0, ())),
        tcp_reachable=None,
    )

    report = analyze(snapshot)

    assert report.overall is CheckState.UNAVAILABLE
    assert report.primary_problem == "无法完成明确判断"


def test_dns_failure_requires_reachable_internet_path():
    snapshot = replace(
        healthy_snapshot(),
        dns_results=(("example.com", False), ("cloudflare.com", False)),
    )

    assert analyze(snapshot).primary_problem == "DNS 服务可能异常"


def test_secondary_wifi_warning_is_preserved():
    adapter = replace(healthy_snapshot().active_adapter, wifi_signal_percent=42)

    report = analyze(replace(healthy_snapshot(), active_adapter=adapter))

    assert any(finding.title == "Wi-Fi 信号较弱" for finding in report.findings)


def test_gateway_latency_at_twenty_ms_is_a_secondary_warning():
    snapshot = replace(
        healthy_snapshot(),
        gateway_ping=PingStats("192.168.1.1", 4, (20.0,) * 4),
    )

    report = analyze(snapshot)

    assert any(
        finding.title == "默认网关延迟较高" and finding.state is CheckState.WARNING
        for finding in report.findings
    )


def test_high_public_latency_is_a_quality_warning():
    snapshot = replace(
        healthy_snapshot(),
        internet_pings=(
            PingStats("1.1.1.1", 6, (70.0,) * 6),
            PingStats("8.8.8.8", 6, (70.0,) * 6),
        ),
    )

    report = analyze(snapshot)

    assert report.overall is CheckState.WARNING
    assert report.primary_problem == "网络质量需要关注"


def test_healthy_result_includes_excellent_quality_grade():
    report = analyze(healthy_snapshot())

    assert report.overall is CheckState.OK
    assert report.primary_problem == "未发现明显网络问题"
    assert report.quality_grade == "优秀"


def test_format_report_contains_required_sections_and_plain_text_markers():
    text = format_report(analyze(healthy_snapshot()))

    assert "总体结论" in text
    assert "最可能的问题" in text
    assert "关键检测结果" in text
    assert "建议操作" in text
    assert "[正常]" in text
    assert "1. " in text
    assert "\x1b[" not in text
