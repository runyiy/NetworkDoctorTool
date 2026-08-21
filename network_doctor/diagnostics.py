from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from ipaddress import IPv4Address, IPv6Address, ip_address

from network_doctor.analysis import analyze
from network_doctor.models import AdapterInfo, DiagnosisReport, PingStats, ProbeSnapshot
from network_doctor.windows_probes import WindowsProbes


IPV4_PUBLIC_TARGETS = ("1.1.1.1", "8.8.8.8")
IPV6_PUBLIC_TARGETS = ("2606:4700:4700::1111", "2001:4860:4860::8888")
PUBLIC_TARGETS = IPV4_PUBLIC_TARGETS
DNS_TARGETS = ("example.com", "cloudflare.com")
TCP_ENDPOINTS = (("1.1.1.1", 443), ("8.8.8.8", 443))
GATEWAY_PING_COUNT = 4
PUBLIC_PING_COUNT = 10
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


def _has_global_ipv6(adapter: AdapterInfo) -> bool:
    for value in adapter.ipv6_addresses:
        try:
            address = ip_address(value)
        except ValueError:
            continue
        if isinstance(address, IPv6Address) and address.is_global:
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


def _collect_public_pings(
    probes: WindowsProbes,
    include_ipv6: bool,
) -> tuple[list[PingStats], list[PingStats], list[str]]:
    """Run independent public targets together while preserving report order."""
    specs: list[tuple[str, str, int | None]] = [
        ("IPv4", target, None) for target in IPV4_PUBLIC_TARGETS
    ]
    if include_ipv6:
        specs.extend(("IPv6", target, 6) for target in IPV6_PUBLIC_TARGETS)

    def ping_one(spec: tuple[str, str, int | None]) -> tuple[PingStats, str | None]:
        family, target, address_family = spec
        try:
            if address_family is None:
                result = probes.ping(target, PUBLIC_PING_COUNT, PING_TIMEOUT_MS)
            else:
                result = probes.ping(
                    target,
                    PUBLIC_PING_COUNT,
                    PING_TIMEOUT_MS,
                    address_family=address_family,
                )
        except Exception as error:
            return PingStats(target, 0, error=str(error)), f"{family} 公网 Ping {target}"
        return result, None

    with ThreadPoolExecutor(max_workers=len(specs)) as executor:
        results = tuple(executor.map(ping_one, specs))

    ipv4_pings: list[PingStats] = []
    ipv6_pings: list[PingStats] = []
    unavailable_checks: list[str] = []
    for (family, _target, _address_family), (ping, unavailable_name) in zip(specs, results):
        (ipv4_pings if family == "IPv4" else ipv6_pings).append(ping)
        if unavailable_name is not None:
            unavailable_checks.append(unavailable_name)
    return ipv4_pings, ipv6_pings, unavailable_checks


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
    ipv6_pings: list[PingStats] = []
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
        has_global_ipv6 = active_adapter is not None and _has_global_ipv6(active_adapter)
        progress_text = (
            "正在分别测试 IPv4 和 IPv6 连通性……"
            if has_global_ipv6
            else "正在测试 IPv4 互联网连通性……"
        )
        _notify(on_progress, progress_text, 55)
        internet_pings, ipv6_pings, public_unavailable = _collect_public_pings(
            probes, has_global_ipv6
        )
        for name in public_unavailable:
            unavailable(name)

        if not any(ping.reachable for ping in internet_pings):
            _notify(on_progress, "正在进行 TCP 连通性检测……", 70)
            try:
                tcp_reachable = probes.tcp_reachable(TCP_ENDPOINTS, TCP_TIMEOUT_SECONDS)
            except Exception:
                unavailable("TCP 连通性")
            else:
                if tcp_reachable is None:
                    unavailable("TCP 连通性")

        if (
            any(ping.reachable for ping in internet_pings)
            or any(ping.reachable for ping in ipv6_pings)
            or tcp_reachable is True
        ):
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
        ipv6_pings=tuple(ipv6_pings),
    )


def run_diagnosis(
    probes: WindowsProbes | None = None,
    on_progress: ProgressCallback | None = None,
) -> DiagnosisReport:
    """Collect current network evidence and analyze it into a report."""
    return analyze(collect_snapshot(probes or WindowsProbes(), on_progress))
