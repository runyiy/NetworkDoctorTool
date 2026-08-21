from dataclasses import dataclass
from enum import Enum
from statistics import fmean


class CheckState(str, Enum):
    OK = "正常"
    WARNING = "提示"
    ERROR = "异常"
    UNAVAILABLE = "无法检测"


@dataclass(frozen=True)
class AdapterInfo:
    name: str
    kind: str
    connected: bool
    enabled: bool
    ipv4_addresses: tuple[str, ...] = ()
    ipv6_addresses: tuple[str, ...] = ()
    dhcp_enabled: bool | None = None
    gateway: str | None = None
    dns_servers: tuple[str, ...] = ()
    wifi_signal_percent: int | None = None


@dataclass(frozen=True)
class PingStats:
    target: str
    sent: int
    latencies_ms: tuple[float, ...] = ()
    error: str | None = None

    @property
    def packet_loss_percent(self) -> float | None:
        if self.sent == 0:
            return None
        return round((self.sent - len(self.latencies_ms)) / self.sent * 100, 2)

    @property
    def average_latency_ms(self) -> float | None:
        if not self.latencies_ms:
            return None
        return round(fmean(self.latencies_ms), 2)

    @property
    def jitter_ms(self) -> float | None:
        if len(self.latencies_ms) < 2:
            return None
        return fmean(
            abs(current - previous)
            for previous, current in zip(self.latencies_ms, self.latencies_ms[1:])
        )

    @property
    def reachable(self) -> bool:
        return bool(self.latencies_ms)


@dataclass(frozen=True)
class ProbeSnapshot:
    adapters: tuple[AdapterInfo, ...]
    active_adapter: AdapterInfo | None
    gateway_ping: PingStats | None
    internet_pings: tuple[PingStats, ...]
    tcp_reachable: bool | None
    dns_results: tuple[tuple[str, bool | None], ...]
    unavailable_checks: tuple[str, ...] = ()
    ipv6_pings: tuple[PingStats, ...] = ()


@dataclass(frozen=True)
class Finding:
    state: CheckState
    title: str
    detail: str


@dataclass(frozen=True)
class DiagnosisReport:
    overall: CheckState
    primary_problem: str
    findings: tuple[Finding, ...]
    recommendations: tuple[str, ...]
    quality_grade: str | None = None
