from network_doctor.diagnostics import collect_snapshot, run_diagnosis
from network_doctor.models import AdapterInfo, DiagnosisReport, PingStats
from network_doctor.windows_probes import ProbeUnavailable


class FakeProbes:
    """Complete external-probe boundary fake with deterministic network evidence."""

    def __init__(self, *, public_replies=True, adapters=None, adapter_error=None):
        self.calls = []
        self.public_replies = public_replies
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
        replies = (3.0,) * count if target == "192.168.1.1" or self.public_replies else ()
        return PingStats(target, count, replies)

    def tcp_reachable(self, endpoints, timeout_seconds):
        self.calls.append("tcp_reachable")
        return False

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
