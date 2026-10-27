from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class DiagnosisCategory(str, Enum):
    HEALTHY = "healthy"
    LAN_ISSUE = "lan_issue"
    ISP_WAN_ISSUE = "isp_wan_issue"
    DNS_ISSUE = "dns_issue"
    UPSTREAM_ROUTE_ISSUE = "upstream_route_issue"
    INTERMITTENT = "intermittent"
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        labels = {
            "healthy": "Connection Healthy",
            "lan_issue": "LAN Issue Likely",
            "isp_wan_issue": "ISP / WAN Issue Likely",
            "dns_issue": "DNS Issue Likely",
            "upstream_route_issue": "Upstream Route Issue Likely",
            "intermittent": "Intermittent Instability",
            "unknown": "Collecting Data...",
        }
        return labels.get(self.value, self.value)


@dataclass
class PingResult:
    target: str
    timestamp: datetime
    packets_sent: int
    packets_received: int
    loss_percent: float
    rtt_min: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_max: Optional[float] = None
    rtt_jitter: Optional[float] = None
    timed_out: bool = False
    error: Optional[str] = None

    @property
    def is_healthy(self) -> bool:
        return self.loss_percent < 5.0 and not self.timed_out


@dataclass
class DnsResult:
    hostname: str
    timestamp: datetime
    resolved: bool
    resolved_ip: Optional[str] = None
    resolution_time_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class RouteHop:
    hop_number: int
    ip: Optional[str] = None
    rtt_samples: list[Optional[float]] = field(default_factory=list)

    @property
    def is_responsive(self) -> bool:
        return self.ip is not None


@dataclass
class RouteSnapshot:
    target: str
    timestamp: datetime
    hops: list[RouteHop] = field(default_factory=list)
    completed: bool = True
    error: Optional[str] = None

    @property
    def responsive_ips(self) -> list[Optional[str]]:
        return [h.ip for h in self.hops]


@dataclass
class RouteDiff:
    old_timestamp: datetime
    new_timestamp: datetime
    changed_hops: list[int] = field(default_factory=list)
    hops_added: int = 0
    hops_removed: int = 0
    is_significant: bool = False


@dataclass
class Observation:
    """One complete round of all tests."""
    timestamp: datetime
    gateway_ip: Optional[str]
    gateway_ping: Optional[PingResult] = None
    public_pings: list[PingResult] = field(default_factory=list)
    dns_results: list[DnsResult] = field(default_factory=list)
    route_snapshot: Optional[RouteSnapshot] = None


@dataclass
class Diagnosis:
    timestamp: datetime
    category: DiagnosisCategory
    summary: str
    explanation: str
    confidence: str  # "high", "medium", "low"
    evidence: dict = field(default_factory=dict)


@dataclass
class AlertRow:
    id: int
    timestamp: str
    category: str
    severity: str
    title: str
    message: str
    resolved_at: Optional[str] = None


def _serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def observation_to_json(obs: Observation) -> str:
    return json.dumps(asdict(obs), default=_serialize_datetime)


def diagnosis_to_json(diag: Diagnosis) -> str:
    return json.dumps(asdict(diag), default=_serialize_datetime)
