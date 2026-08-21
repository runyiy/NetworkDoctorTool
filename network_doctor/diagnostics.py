from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from ipaddress import IPv4Address, ip_address

from network_doctor.analysis import analyze
from network_doctor.models import AdapterInfo, DiagnosisReport, PingStats, ProbeSnapshot
from network_doctor.windows_probes import WindowsProbes


PUBLIC_TARGETS = ("1.1.1.1", "8.8.8.8")
DNS_TARGETS = ("example.com", "cloudflare.com")
TCP_ENDPOINTS = (("1.1.1.1", 443), ("8.8.8.8", 443))
GATEWAY_PING_COUNT = 4
PUBLIC_PING_COUNT = 6
PING_TIMEOUT_MS = 1000
TCP_TIMEOUT_SECONDS = 2.0
DNS_TIMEOUT_SECONDS = 2.0

ProgressCallback = Callable[[str, int], None]


def _has_routable_ipv4(adapter: AdapterInfo) -> bool:
    for value in adapter.ipv4_addresses:
        try:
            address = ip_address(value)
        except ValueError:
            continue
        if isinstance(address, IPv4Address) and not address.is_link_local:
            return True
    return False


def _select_active_adapter(adapters: tuple[AdapterInfo, ...]) -> AdapterInfo | None:
    candidates = tuple(adapter for adapter in adapters if adapter.enabled and adapter.connected)
    for adapter in candidates:
        if _has_routable_ipv4(adapter) and adapter.gateway:
            return adapter
    return candidates[0] if candidates else None


def _notify(callback: ProgressCallback | None, text: str, percent: int) -> None:
    if callback is not None:
        callback(text, percent)


def collect_snapshot(
    probes: WindowsProbes,
    on_progress: ProgressCallback | None = None,
) -> ProbeSnapshot:
    """Collect bounded local-to-public evidence without inferring failed probes."""
    unavailable_checks: list[str] = []
    adapters: tuple[AdapterInfo, ...] = ()
    active_adapter: AdapterInfo | None = None
    gateway_ping: PingStats | None = None
    internet_pings: list[PingStats] = []
    tcp_reachable: bool | None = None
    dns_results: list[tuple[str, bool | None]] = []

    def unavailable(name: str) -> None:
        if name not in unavailable_checks:
            unavailable_checks.append(name)

    _notify(on_progress, "正在检查网络适配器……", 10)
    try:
        adapters = tuple(probes.collect_adapters())
    except Exception:
        unavailable("网络适配器")
    else:
        active_adapter = _select_active_adapter(adapters)

    if active_adapter is not None and active_adapter.kind == "Wi-Fi":
        _notify(on_progress, "正在检查 Wi-Fi 信号……", 20)
        try:
            signal = probes.wifi_signal()
        except Exception:
            unavailable("Wi-Fi 信号")
        else:
            active_adapter = replace(active_adapter, wifi_signal_percent=signal)

    if active_adapter is not None and active_adapter.gateway:
        _notify(on_progress, "正在测试默认网关……", 35)
        try:
            gateway_ping = probes.ping(
                active_adapter.gateway, GATEWAY_PING_COUNT, PING_TIMEOUT_MS
            )
        except Exception:
            unavailable("默认网关")

    if gateway_ping is not None and gateway_ping.reachable:
        _notify(on_progress, "正在测试互联网连通性……", 55)
        for target in PUBLIC_TARGETS:
            try:
                internet_pings.append(
                    probes.ping(target, PUBLIC_PING_COUNT, PING_TIMEOUT_MS)
                )
            except Exception as error:
                internet_pings.append(PingStats(target, 0, error=str(error)))
                unavailable(f"公网 Ping {target}")

        if not any(ping.reachable for ping in internet_pings):
            _notify(on_progress, "正在进行 TCP 连通性检测……", 70)
            try:
                tcp_reachable = probes.tcp_reachable(TCP_ENDPOINTS, TCP_TIMEOUT_SECONDS)
            except Exception:
                unavailable("TCP 连通性")
            else:
                if tcp_reachable is None:
                    unavailable("TCP 连通性")

        if any(ping.reachable for ping in internet_pings) or tcp_reachable is True:
            _notify(on_progress, "正在测试 DNS 解析……", 85)
            for hostname in DNS_TARGETS:
                try:
                    result = probes.resolve(hostname, DNS_TIMEOUT_SECONDS)
                except Exception:
                    unavailable("DNS 解析")
                    dns_results.append((hostname, None))
                else:
                    dns_results.append((hostname, None if result is None else bool(result)))

    _notify(on_progress, "正在分析结果……", 95)
    return ProbeSnapshot(
        adapters=adapters,
        active_adapter=active_adapter,
        gateway_ping=gateway_ping,
        internet_pings=tuple(internet_pings),
        tcp_reachable=tcp_reachable,
        dns_results=tuple(dns_results),
        unavailable_checks=tuple(unavailable_checks),
    )


def run_diagnosis(
    probes: WindowsProbes | None = None,
    on_progress: ProgressCallback | None = None,
) -> DiagnosisReport:
    """Collect current network evidence and analyze it into a report."""
    return analyze(collect_snapshot(probes or WindowsProbes(), on_progress))
