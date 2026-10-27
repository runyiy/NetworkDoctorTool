"""Tests for the diagnosis engine — the core logic of Losshound."""

from datetime import datetime

from losshound.core.config import DiagnosisConfig
from losshound.core.diagnosis import diagnose
from losshound.core.models import (
    DiagnosisCategory,
    DnsResult,
    Observation,
    PingResult,
)


def _make_obs(
    gw_loss: float = 0.0,
    pub_loss: float = 0.0,
    dns_ok: bool = True,
    gw_timeout: bool = False,
) -> Observation:
    now = datetime.now()
    return Observation(
        timestamp=now,
        gateway_ip="192.168.1.1",
        gateway_ping=PingResult(
            target="192.168.1.1", timestamp=now,
            packets_sent=4,
            packets_received=0 if gw_timeout else int(4 * (1 - gw_loss / 100)),
            loss_percent=gw_loss,
            rtt_avg=10.0 if not gw_timeout else None,
            timed_out=gw_timeout,
        ),
        public_pings=[
            PingResult(
                target="1.1.1.1", timestamp=now,
                packets_sent=4,
                packets_received=int(4 * (1 - pub_loss / 100)),
                loss_percent=pub_loss,
                rtt_avg=20.0 if pub_loss < 100 else None,
                timed_out=pub_loss >= 100,
            ),
        ],
        dns_results=[
            DnsResult(
                hostname="google.com", timestamp=now,
                resolved=dns_ok,
                resolved_ip="142.250.80.46" if dns_ok else None,
                resolution_time_ms=15.0 if dns_ok else None,
                error=None if dns_ok else "failed",
            ),
        ],
    )


def _config():
    return DiagnosisConfig()


def test_insufficient_data():
    obs = [_make_obs()]  # Only 1, need 3
    diag = diagnose(obs, _config())
    assert diag.category == DiagnosisCategory.UNKNOWN


def test_healthy():
    obs = [_make_obs() for _ in range(5)]
    diag = diagnose(obs, _config())
    assert diag.category == DiagnosisCategory.HEALTHY
    assert diag.confidence == "high"


def test_lan_issue():
    obs = [_make_obs(gw_loss=50, pub_loss=100, dns_ok=False) for _ in range(5)]
    diag = diagnose(obs, _config())
    assert diag.category == DiagnosisCategory.LAN_ISSUE


def test_isp_wan_issue():
    obs = [_make_obs(gw_loss=0, pub_loss=80, dns_ok=False) for _ in range(5)]
    diag = diagnose(obs, _config())
    assert diag.category == DiagnosisCategory.ISP_WAN_ISSUE


def test_dns_issue():
    obs = [_make_obs(gw_loss=0, pub_loss=0, dns_ok=False) for _ in range(5)]
    diag = diagnose(obs, _config())
    assert diag.category == DiagnosisCategory.DNS_ISSUE


def test_intermittent():
    obs = [_make_obs(gw_loss=5, pub_loss=5) for _ in range(5)]
    diag = diagnose(obs, _config())
    assert diag.category == DiagnosisCategory.INTERMITTENT


def test_evidence_included():
    obs = [_make_obs() for _ in range(5)]
    diag = diagnose(obs, _config())
    assert "gateway_loss_avg" in diag.evidence
    assert "public_loss_avg" in diag.evidence
    assert "dns_fail_rate" in diag.evidence
    assert "observations_count" in diag.evidence


def test_gateway_timeout_is_lan_issue():
    obs = [_make_obs(gw_loss=100, gw_timeout=True, pub_loss=100, dns_ok=False) for _ in range(5)]
    diag = diagnose(obs, _config())
    assert diag.category == DiagnosisCategory.LAN_ISSUE
