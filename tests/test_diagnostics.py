import socket

import pytest

from network_doctor.analysis import analyze
from network_doctor.diagnostics import collect_snapshot, run_diagnosis
from network_doctor.models import AdapterInfo, CheckState, DiagnosisReport, PingStats
from network_doctor.windows_probes import CommandResult, ProbeUnavailable, WindowsProbes


class FakeProbes:
    """Complete external-probe boundary fake with deterministic network evidence."""

    def __init__(
        self,
        *,
        public_replies=True,
        public_unavailable=(),
        tcp_result=False,
        adapters=None,
        adapter_error=None,
    ):
        self.calls = []
        self.public_replies = public_replies
        self.public_unavailable = frozenset(public_unavailable)
        self.tcp_result = tcp_result
        self.adapter_error = adapter_error
        self.adapters = adapters or (
            AdapterInfo(
                name="Wi-Fi",
                kind="Wi-Fi",
                connected=True,
                enabled=True,
                ipv4_addresses=("192.168.1.20",),
                dhcp_enabled=True,
                gateway="192.168.1.1",
                dns_servers=("1.1.1.1",),
            ),
        )

    def collect_adapters(self):
        self.calls.append("collect_adapters")
        if self.adapter_error:
            raise self.adapter_error
        return self.adapters

    def wifi_signal(self):
        self.calls.append("wifi_signal")
        return 80

    def ping(self, target, count, timeout_ms):
        self.calls.append(f"ping:{target}")
        if target in self.public_unavailable:
            raise ProbeUnavailable(f"{target} ping unavailable")
        replies = (3.0,) * count if target == "192.168.1.1" or self.public_replies else ()
        return PingStats(target, count, replies)

    def tcp_reachable(self, endpoints, timeout_seconds):
        self.calls.append("tcp_reachable")
        return self.tcp_result

    def resolve(self, hostname, timeout_seconds):
        self.calls.append(f"resolve:{hostname}")
        return True


def test_collect_snapshot_runs_near_to_far_and_reports_progress():
    """Catches a collector that reorders probes or reports a snapshot before analysis progress."""
    probes = FakeProbes()
    progress = []

    snapshot = collect_snapshot(probes, lambda text, percent: progress.append((text, percent)))

    assert probes.calls == [
        "collect_adapters",
        "wifi_signal",
        "ping:192.168.1.1",
        "ping:1.1.1.1",
        "ping:8.8.8.8",
        "resolve:example.com",
        "resolve:cloudflare.com",
    ]
    assert progress[0] == ("正在检查网络适配器……", 10)
    assert progress[-1] == ("正在分析结果……", 95)
    assert snapshot.active_adapter.name == "Wi-Fi"
    assert snapshot.active_adapter.wifi_signal_percent == 80
    assert snapshot.tcp_reachable is None
    assert snapshot.dns_results == (("example.com", True), ("cloudflare.com", True))


def test_collect_snapshot_uses_tcp_fallback_after_both_public_pings_have_no_replies():
    """Catches a collector that declares public failure without TCP fallback evidence."""
    probes = FakeProbes(public_replies=False)

    snapshot = collect_snapshot(probes)

    assert probes.calls == [
        "collect_adapters",
        "wifi_signal",
        "ping:192.168.1.1",
        "ping:1.1.1.1",
        "ping:8.8.8.8",
        "tcp_reachable",
    ]
    assert snapshot.internet_pings == (
        PingStats("1.1.1.1", 6, ()),
        PingStats("8.8.8.8", 6, ()),
    )
    assert snapshot.tcp_reachable is False


def test_successful_tcp_fallback_continues_to_both_dns_checks():
    """Catches TCP success ending collection before the independent DNS stage."""
    probes = FakeProbes(public_replies=False, tcp_result=True)

    snapshot = collect_snapshot(probes)

    assert probes.calls[-3:] == [
        "tcp_reachable",
        "resolve:example.com",
        "resolve:cloudflare.com",
    ]
    assert snapshot.tcp_reachable is True
    assert snapshot.dns_results == (
        ("example.com", True),
        ("cloudflare.com", True),
    )
    assert any(
        finding.state is CheckState.OK and finding.title == "TCP 连通性"
        for finding in analyze(snapshot).findings
    )


@pytest.mark.parametrize(
    "unavailable_targets",
    [("8.8.8.8",), ("1.1.1.1", "8.8.8.8")],
)
def test_collect_snapshot_uses_tcp_when_no_public_ping_succeeds_and_preserves_targets(
    unavailable_targets,
):
    """Catches unavailable public Ping commands suppressing fallback or losing target identity."""
    probes = FakeProbes(
        public_replies=False,
        public_unavailable=unavailable_targets,
        tcp_result=False,
    )

    snapshot = collect_snapshot(probes)

    assert "tcp_reachable" in probes.calls
    assert [(ping.target, ping.sent) for ping in snapshot.internet_pings] == [
        ("1.1.1.1", 0 if "1.1.1.1" in unavailable_targets else 6),
        ("8.8.8.8", 0 if "8.8.8.8" in unavailable_targets else 6),
    ]
    assert {
        check for check in snapshot.unavailable_checks if check.startswith("公网 Ping")
    } == {f"公网 Ping {target}" for target in unavailable_targets}


def test_successful_public_ping_does_not_hide_the_other_unavailable_target():
    """Catches partial Ping evidence being graded healthy without an unavailable finding."""
    probes = FakeProbes(public_unavailable=("8.8.8.8",))

    report = run_diagnosis(probes)

    assert "tcp_reachable" not in probes.calls
    assert "resolve:example.com" in probes.calls
    assert report.overall is CheckState.UNAVAILABLE
    assert report.quality_grade is None
    assert any(
        finding.state is CheckState.UNAVAILABLE and "8.8.8.8" in finding.title
        for finding in report.findings
    )


def test_definitive_tcp_failure_can_diagnose_internet_fault_without_inventing_ping_failures():
    """Catches aggregate TCP failure being ignored when both Ping commands are unavailable."""
    report = run_diagnosis(
        FakeProbes(
            public_unavailable=("1.1.1.1", "8.8.8.8"),
            tcp_result=False,
        )
    )

    assert report.primary_problem == "互联网连接可能异常"
    assert sum(
        finding.state is CheckState.UNAVAILABLE and "公网 Ping" in finding.title
        for finding in report.findings
    ) == 2
    assert not any(
        finding.state is CheckState.ERROR and "Ping" in finding.title
        for finding in report.findings
    )
    assert any(
        finding.state is CheckState.ERROR and finding.title == "TCP 连通性"
        for finding in report.findings
    )


def test_unavailable_tcp_fallback_is_preserved_and_rendered_explicitly():
    """Catches an inconclusive TCP fallback disappearing from snapshot and report evidence."""
    probes = FakeProbes(public_replies=False, tcp_result=None)

    snapshot = collect_snapshot(probes)
    report = analyze(snapshot)

    assert snapshot.tcp_reachable is None
    assert "TCP 连通性" in snapshot.unavailable_checks
    assert report.overall is CheckState.UNAVAILABLE
    assert any(
        finding.state is CheckState.UNAVAILABLE and finding.title == "TCP 连通性"
        for finding in report.findings
    )


def test_collect_snapshot_contains_unavailable_adapter_evidence_after_adapter_stage_failure():
    """Catches an unavailable adapter probe escaping instead of producing explicit evidence."""
    probes = FakeProbes(adapter_error=ProbeUnavailable("PowerShell unavailable"))

    snapshot = collect_snapshot(probes)

    assert snapshot.active_adapter is None
    assert "网络适配器" in snapshot.unavailable_checks
    assert snapshot.gateway_ping is None
    assert snapshot.internet_pings == ()
    assert snapshot.tcp_reachable is None
    assert snapshot.dns_results == ()


def test_collect_snapshot_prefers_connected_adapter_with_routable_ipv4_and_gateway():
    """Catches selection of an earlier connected adapter that cannot reach a routed network."""
    link_local = AdapterInfo(
        name="Ethernet",
        kind="Ethernet",
        connected=True,
        enabled=True,
        ipv4_addresses=("169.254.1.2",),
        gateway=None,
    )
    routed = AdapterInfo(
        name="Wi-Fi",
        kind="Wi-Fi",
        connected=True,
        enabled=True,
        ipv4_addresses=("192.168.1.20",),
        gateway="192.168.1.1",
    )

    snapshot = collect_snapshot(FakeProbes(adapters=(link_local, routed)))

    assert snapshot.active_adapter.name == "Wi-Fi"


def test_run_diagnosis_composes_collection_and_analysis_for_healthy_network():
    """Catches run_diagnosis returning raw probe data or bypassing the analyzer."""
    report = run_diagnosis(FakeProbes())

    assert isinstance(report, DiagnosisReport)
    assert report.primary_problem == "未发现明显网络问题"


def test_run_diagnosis_preserves_unavailable_adapter_command_as_inconclusive():
    """Catches a failed adapter command crossing orchestration as a disconnected-adapter fault."""
    report = run_diagnosis(
        WindowsProbes(
            command_runner=lambda args, timeout_seconds: CommandResult(
                -1, "", "powershell.exe unavailable"
            )
        )
    )

    assert report.primary_problem == "无法完成明确判断"


def test_real_dns_failures_reach_the_dns_fault_rule_through_orchestration():
    """Catches completed getaddrinfo failures being reported as unavailable DNS checks."""
    adapter_json = (
        '[{"Name":"Wi-Fi","Kind":"Wi-Fi","Connected":true,"Enabled":true,'
        '"IPv4":["192.168.1.20"],"DhcpEnabled":true,'
        '"Gateway":"192.168.1.1","Dns":["1.1.1.1"]}]'
    )

    def successful_network_commands(args, timeout_seconds):
        if args[0] == "powershell.exe":
            return CommandResult(0, adapter_json, "")
        if args[0] == "netsh.exe":
            return CommandResult(0, "Signal : 80%", "")
        count = int(args[2])
        replies = "\n".join(
            f"Reply from {args[-1]}: time=3ms TTL=57" for _ in range(count)
        )
        return CommandResult(0, replies, "")

    def missing_name(hostname, port):
        raise socket.gaierror(socket.EAI_NONAME, "name not known")

    report = run_diagnosis(
        WindowsProbes(
            command_runner=successful_network_commands,
            getaddrinfo=missing_name,
        )
    )

    assert report.primary_problem == "DNS 服务可能异常"
    assert any(finding.title == "DNS 解析" for finding in report.findings)


def test_wifi_timeout_remains_visible_after_the_other_real_probes_complete():
    """Catches timed-out netsh evidence being hidden by otherwise healthy observations."""
    adapter_json = (
        '[{"Name":"Wi-Fi","Kind":"Wi-Fi","Connected":true,"Enabled":true,'
        '"IPv4":["192.168.1.20"],"DhcpEnabled":true,'
        '"Gateway":"192.168.1.1","Dns":["1.1.1.1"]}]'
    )

    def commands_with_wifi_timeout(args, timeout_seconds):
        if args[0] == "powershell.exe":
            return CommandResult(0, adapter_json, "")
        if args[0] == "netsh.exe":
            return CommandResult(-1, "Signal : 80%", "", timed_out=True)
        count = int(args[2])
        replies = "\n".join(
            f"Reply from {args[-1]}: time=3ms TTL=57" for _ in range(count)
        )
        return CommandResult(0, replies, "")

    report = run_diagnosis(
        WindowsProbes(
            command_runner=commands_with_wifi_timeout,
            getaddrinfo=lambda hostname, port: [(2, 1, 6, "", ("127.0.0.1", 0))],
        )
    )

    assert report.overall is CheckState.UNAVAILABLE
    assert report.quality_grade == "优秀"
    assert any(
        finding.state is CheckState.UNAVAILABLE and finding.title == "Wi-Fi 信号"
        for finding in report.findings
    )


def test_unexpected_public_probe_failure_preserves_the_partial_report():
    """Catches a late probe bug discarding adapter, IPv4, gateway, and later DNS evidence."""
    class PartiallyFailingProbes(FakeProbes):
        def ping(self, target, count, timeout_ms):
            if target == "1.1.1.1":
                self.calls.append(f"ping:{target}")
                raise RuntimeError("unexpected parser failure")
            return super().ping(target, count, timeout_ms)

    report = run_diagnosis(PartiallyFailingProbes())

    assert report.overall is CheckState.UNAVAILABLE
    assert any(finding.title == "网络适配器" for finding in report.findings)
    assert any(finding.title == "IPv4 地址" for finding in report.findings)
    assert any(finding.title == "默认网关连通性" for finding in report.findings)
    assert any(
        finding.state is CheckState.UNAVAILABLE and "1.1.1.1" in finding.title
        for finding in report.findings
    )
    assert any(finding.title == "DNS 解析" for finding in report.findings)
