from ipaddress import IPv4Address, ip_address

from network_doctor.models import (
    AdapterInfo,
    CheckState,
    DiagnosisReport,
    Finding,
    PingStats,
    ProbeSnapshot,
)


def latency_label(value: float | None) -> str:
    if value is None:
        return "无法检测"
    if value < 50:
        return "优秀"
    if value < 70:
        return "良好"
    if value < 150:
        return "略高"
    if value < 300:
        return "较高"
    return "非常高"


def jitter_label(value: float | None) -> str:
    if value is None:
        return "无法检测"
    if value < 15:
        return "稳定"
    if value < 30:
        return "轻微波动"
    if value < 60:
        return "存在波动"
    if value < 100:
        return "波动明显"
    return "非常不稳定"


def loss_label(value: float) -> str:
    if value == 0:
        return "正常"
    if value < 5:
        return "偶发丢包"
    if value < 25:
        return "连接不稳定"
    return "严重丢包"


def _public_stats(pings: tuple[PingStats, ...]) -> PingStats:
    return PingStats(
        target="公共网络",
        sent=sum(ping.sent for ping in pings),
        latencies_ms=tuple(latency for ping in pings for latency in ping.latencies_ms),
    )


def _ipv4_addresses(adapter: AdapterInfo) -> tuple[IPv4Address, ...]:
    addresses: list[IPv4Address] = []
    for address in adapter.ipv4_addresses:
        try:
            parsed = ip_address(address)
        except ValueError:
            continue
        if isinstance(parsed, IPv4Address):
            addresses.append(parsed)
    return tuple(addresses)


def _recommendations(primary_problem: str) -> tuple[str, ...]:
    recommendations = {
        "未连接到可用网络适配器": (
            "确认 Wi-Fi 已连接到正确的网络，或检查网线是否插牢。",
            "确认网络适配器没有被禁用。",
        ),
        "未获取到 IPv4 地址": (
            "检查路由器的 DHCP 服务是否正常。",
            "重新连接 Wi-Fi 或重新插拔网线后再次诊断。",
        ),
        "DHCP 获取地址失败": (
            "重新连接网络，确认路由器的 DHCP 服务已启用。",
            "如问题持续，请重启路由器后再次获取地址。",
        ),
        "缺少默认网关": (
            "检查 DHCP 和本地网络配置是否完整。",
            "重新连接网络后再次诊断。",
        ),
        "默认网关无法访问": (
            "靠近路由器或检查网线、路由器 LAN 端口。",
            "确认路由器已通电并正常工作。",
        ),
        "互联网连接可能异常": (
            "检查路由器的 WAN 状态以及光猫/调制解调器指示灯。",
            "如设备正常但仍无法上网，请联系网络运营商。",
        ),
        "DNS 服务可能异常": (
            "检查路由器或系统中的 DNS 设置。",
            "可在确认网络正常后，手动更换为可靠的 DNS 服务器。",
        ),
        "网络质量需要关注": (
            "靠近路由器并减少 Wi-Fi 干扰源后重新测试。",
            "检查网线、路由器负载和网络设备状态。",
        ),
        "无法完成明确判断": (
            "稍后重新诊断，确认网络适配器和检测权限正常。",
            "如问题持续，请记录本报告并联系网络管理员或运营商。",
        ),
        "未发现明显网络问题": (
            "当前网络连接正常；如偶发问题再次出现，可重新运行诊断。",
        ),
    }
    return recommendations[primary_problem]


def _report(
    overall: CheckState,
    primary_problem: str,
    findings: list[Finding],
    quality_grade: str | None = None,
) -> DiagnosisReport:
    return DiagnosisReport(
        overall=overall,
        primary_problem=primary_problem,
        findings=tuple(findings),
        recommendations=_recommendations(primary_problem),
        quality_grade=quality_grade,
    )


def _append_wifi_finding(adapter: AdapterInfo, findings: list[Finding]) -> None:
    if adapter.kind != "Wi-Fi":
        return
    signal = adapter.wifi_signal_percent
    if signal is None:
        findings.append(Finding(CheckState.UNAVAILABLE, "Wi-Fi 信号", "未能读取 Wi-Fi 信号强度。"))
    elif signal < 50:
        findings.append(Finding(CheckState.WARNING, "Wi-Fi 信号较弱", f"当前信号强度为 {signal}%。"))
    elif signal < 70:
        findings.append(Finding(CheckState.OK, "Wi-Fi 信号", f"当前信号强度为 {signal}%，一般。"))
    else:
        findings.append(Finding(CheckState.OK, "Wi-Fi 信号", f"当前信号强度为 {signal}%，良好。"))


def _append_gateway_findings(snapshot: ProbeSnapshot, findings: list[Finding]) -> str:
    ping = snapshot.gateway_ping
    if ping is None or ping.sent == 0:
        findings.append(Finding(CheckState.UNAVAILABLE, "默认网关连通性", "未获得默认网关的有效检测结果。"))
        return "unavailable"
    if not ping.reachable:
        findings.append(Finding(CheckState.ERROR, "默认网关无法访问", "默认网关没有返回 Ping 响应。"))
        return "unreachable"

    findings.append(Finding(CheckState.OK, "默认网关连通性", "默认网关可以访问。"))
    latency = ping.average_latency_ms
    if latency is not None and latency >= 20:
        findings.append(Finding(CheckState.WARNING, "默认网关延迟较高", f"平均延迟为 {latency:.2f} ms。"))
    return "reachable"


def _append_public_quality_findings(
    stats: PingStats, findings: list[Finding]
) -> tuple[bool, str | None]:
    if stats.packet_loss_percent is None:
        findings.append(Finding(CheckState.UNAVAILABLE, "公网质量", "未发送公网 Ping 探测，无法计算质量指标。"))
        return False, None

    has_warning = False
    loss = stats.packet_loss_percent
    loss_state = CheckState.OK if loss == 0 else CheckState.WARNING
    findings.append(Finding(loss_state, "公网丢包", f"丢包率为 {loss:.2f}%，{loss_label(loss)}。"))
    has_warning = loss_state is CheckState.WARNING

    latency = stats.average_latency_ms
    if latency is None:
        findings.append(Finding(CheckState.UNAVAILABLE, "公网延迟", "没有成功的公网 Ping 响应。"))
    else:
        latency_state = CheckState.WARNING if latency >= 70 else CheckState.OK
        findings.append(
            Finding(latency_state, "公网延迟", f"平均延迟为 {latency:.2f} ms，{latency_label(latency)}。")
        )
        has_warning = has_warning or latency_state is CheckState.WARNING

    jitter = stats.jitter_ms
    if jitter is None:
        findings.append(Finding(CheckState.UNAVAILABLE, "公网抖动", "成功响应不足两次，无法计算抖动。"))
    else:
        jitter_state = CheckState.WARNING if jitter >= 30 else CheckState.OK
        findings.append(
            Finding(jitter_state, "公网抖动", f"抖动为 {jitter:.2f} ms，{jitter_label(jitter)}。")
        )
        has_warning = has_warning or jitter_state is CheckState.WARNING

    if latency is None or jitter is None:
        return has_warning, None
    if loss == 0 and latency < 50 and jitter < 15:
        return has_warning, "优秀"
    if loss == 0 and latency < 70 and jitter < 30:
        return has_warning, "良好"
    return True, None


def analyze(snapshot: ProbeSnapshot) -> DiagnosisReport:
    """Apply ordered, side-effect-free rules to a completed probe snapshot."""
    findings: list[Finding] = []
    adapter = snapshot.active_adapter
    if adapter is None or not (adapter.enabled and adapter.connected):
        if "网络适配器" in snapshot.unavailable_checks:
            findings.append(
                Finding(CheckState.UNAVAILABLE, "网络适配器", "未能完成网络适配器检测。")
            )
            return _report(CheckState.UNAVAILABLE, "无法完成明确判断", findings)
        findings.append(Finding(CheckState.ERROR, "网络适配器未连接", "未找到已启用且已连接的网络适配器。"))
        return _report(CheckState.ERROR, "未连接到可用网络适配器", findings)

    findings.append(Finding(CheckState.OK, "网络适配器", f"正在使用 {adapter.name}。"))
    _append_wifi_finding(adapter, findings)
    addresses = _ipv4_addresses(adapter)
    if not addresses:
        findings.append(Finding(CheckState.ERROR, "IPv4 地址", "未获取到可用的 IPv4 地址。"))
        return _report(CheckState.ERROR, "未获取到 IPv4 地址", findings)

    findings.append(Finding(CheckState.OK, "IPv4 地址", "已获取 IPv4 地址。"))
    if any(address.is_link_local for address in addresses):
        findings.append(Finding(CheckState.ERROR, "APIPA 地址", "检测到 169.254.x.x 自动私有地址。"))
        return _report(CheckState.ERROR, "DHCP 获取地址失败", findings)

    if not adapter.gateway:
        findings.append(Finding(CheckState.ERROR, "默认网关", "未获取到默认网关。"))
        return _report(CheckState.ERROR, "缺少默认网关", findings)

    gateway_status = _append_gateway_findings(snapshot, findings)
    if gateway_status == "unavailable":
        return _report(CheckState.UNAVAILABLE, "无法完成明确判断", findings)
    if gateway_status == "unreachable":
        return _report(CheckState.ERROR, "默认网关无法访问", findings)

    public_stats = _public_stats(snapshot.internet_pings)
    any_public_reply = any(ping.reachable for ping in snapshot.internet_pings)
    public_path_reachable = any_public_reply or snapshot.tcp_reachable is True
    explicit_public_ping_failure = all(
        any(
            ping.target == target and ping.sent > 0 and not ping.reachable
            for ping in snapshot.internet_pings
        )
        for target in ("1.1.1.1", "8.8.8.8")
    )
    all_public_evidence_false = explicit_public_ping_failure and snapshot.tcp_reachable is False

    if all_public_evidence_false:
        _append_public_quality_findings(public_stats, findings)
        return _report(CheckState.ERROR, "互联网连接可能异常", findings)
    if not public_path_reachable:
        _append_public_quality_findings(public_stats, findings)
        return _report(CheckState.UNAVAILABLE, "无法完成明确判断", findings)

    quality_warning, quality_grade = _append_public_quality_findings(public_stats, findings)
    dns_values = tuple(result for _, result in snapshot.dns_results)
    if len(dns_values) >= 2 and all(result is False for result in dns_values):
        findings.append(Finding(CheckState.ERROR, "DNS 解析", "两个测试域名都无法解析。"))
        return _report(CheckState.ERROR, "DNS 服务可能异常", findings, quality_grade)
    if any(result is False for result in dns_values):
        findings.append(Finding(CheckState.WARNING, "DNS 解析", "部分测试域名无法解析。"))
        quality_warning = True
    elif not dns_values or any(result is None for result in dns_values):
        findings.append(Finding(CheckState.UNAVAILABLE, "DNS 解析", "DNS 检测结果不完整。"))
    else:
        findings.append(Finding(CheckState.OK, "DNS 解析", "测试域名均可正常解析。"))

    if quality_warning or any(finding.state is CheckState.WARNING for finding in findings):
        return _report(CheckState.WARNING, "网络质量需要关注", findings, quality_grade)
    if any(finding.state is CheckState.UNAVAILABLE for finding in findings):
        return _report(CheckState.UNAVAILABLE, "无法完成明确判断", findings, quality_grade)
    return _report(CheckState.OK, "未发现明显网络问题", findings, quality_grade)


def format_report(report: DiagnosisReport) -> str:
    """Render a diagnosis report as portable, color-free plain text."""
    lines = [
        "总体结论",
        f"[{report.overall.value}] {report.primary_problem}",
        "",
        "最可能的问题",
        report.primary_problem,
    ]
    if report.quality_grade is not None:
        lines.extend(("", f"网络质量等级：{report.quality_grade}"))

    lines.extend(("", "关键检测结果"))
    if report.findings:
        lines.extend(
            f"[{finding.state.value}] {finding.title}：{finding.detail}"
            for finding in report.findings
        )
    else:
        lines.append("[无法检测] 没有可显示的检测结果。")

    lines.extend(("", "建议操作"))
    lines.extend(
        f"{index}. {recommendation}"
        for index, recommendation in enumerate(report.recommendations, start=1)
    )
    return "\n".join(lines)
from ipaddress import IPv4Address, ip_address

from network_doctor.models import (
    AdapterInfo,
    CheckState,
    DiagnosisReport,
    Finding,
    PingStats,
    ProbeSnapshot,
)
