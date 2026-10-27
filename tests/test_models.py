import json
from datetime import datetime

from losshound.core.models import (
    Diagnosis,
    DiagnosisCategory,
    DnsResult,
    Observation,
    PingResult,
    RouteHop,
    RouteSnapshot,
    observation_to_json,
    diagnosis_to_json,
)


def test_ping_result_healthy():
    pr = PingResult(
        target="1.1.1.1", timestamp=datetime.now(),
        packets_sent=4, packets_received=4, loss_percent=0.0,
        rtt_avg=12.0,
    )
    assert pr.is_healthy


def test_ping_result_unhealthy():
    pr = PingResult(
        target="1.1.1.1", timestamp=datetime.now(),
        packets_sent=4, packets_received=0, loss_percent=100.0,
        timed_out=True,
    )
    assert not pr.is_healthy


def test_diagnosis_category_display():
    assert DiagnosisCategory.HEALTHY.display_name == "Connection Healthy"
    assert DiagnosisCategory.LAN_ISSUE.display_name == "LAN Issue Likely"
    assert DiagnosisCategory.DNS_ISSUE.display_name == "DNS Issue Likely"


def test_route_hop_responsive():
    hop = RouteHop(hop_number=1, ip="192.168.1.1", rtt_samples=[1.0, 1.0, 1.0])
    assert hop.is_responsive

    hop2 = RouteHop(hop_number=2, ip=None, rtt_samples=[None, None, None])
    assert not hop2.is_responsive


def test_observation_serialization():
    now = datetime.now()
    obs = Observation(
        timestamp=now,
        gateway_ip="192.168.1.1",
        gateway_ping=PingResult(
            target="192.168.1.1", timestamp=now,
            packets_sent=4, packets_received=4, loss_percent=0.0,
        ),
        public_pings=[
            PingResult(
                target="1.1.1.1", timestamp=now,
                packets_sent=4, packets_received=4, loss_percent=0.0,
            ),
        ],
        dns_results=[
            DnsResult(
                hostname="google.com", timestamp=now,
                resolved=True, resolved_ip="142.250.80.46",
                resolution_time_ms=15.0,
            ),
        ],
    )
    raw = observation_to_json(obs)
    data = json.loads(raw)
    assert data["gateway_ip"] == "192.168.1.1"
    assert len(data["public_pings"]) == 1
    assert len(data["dns_results"]) == 1


def test_diagnosis_serialization():
    diag = Diagnosis(
        timestamp=datetime.now(),
        category=DiagnosisCategory.HEALTHY,
        summary="Connection healthy",
        explanation="All checks passing.",
        confidence="high",
        evidence={"gateway_loss_avg": 0.0},
    )
    raw = diagnosis_to_json(diag)
    data = json.loads(raw)
    assert data["category"] == "healthy"
    assert data["evidence"]["gateway_loss_avg"] == 0.0
