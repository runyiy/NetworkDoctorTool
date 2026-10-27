from __future__ import annotations

import logging
import statistics
from datetime import datetime
from typing import Optional

from losshound.core.config import DiagnosisConfig
from losshound.core.models import (
    Diagnosis,
    DiagnosisCategory,
    Observation,
    RouteDiff,
    RouteSnapshot,
)
from losshound.core.route_monitor import diff_routes

logger = logging.getLogger(__name__)


def diagnose(
    observations: list[Observation],
    config: DiagnosisConfig,
    route_history: Optional[list[RouteSnapshot]] = None,
) -> Diagnosis:
    """
    Run the rule-based diagnosis engine over recent observations.

    Decision logic (priority order):
    1. Insufficient data -> UNKNOWN
    2. Gateway unreachable -> LAN_ISSUE
    3. Gateway OK, public unreachable -> ISP_WAN_ISSUE
    4. Gateway OK, public OK, DNS failing -> DNS_ISSUE
    5. Gateway OK, route unstable -> UPSTREAM_ROUTE_ISSUE
    6. Intermittent loss bursts -> INTERMITTENT
    7. Everything OK -> HEALTHY
    """
    now = datetime.now()

    if len(observations) < config.min_observations:
        return Diagnosis(
            timestamp=now,
            category=DiagnosisCategory.UNKNOWN,
            summary="Collecting data...",
            explanation=f"Need at least {config.min_observations} observations. "
                        f"Have {len(observations)} so far.",
            confidence="low",
        )

    # Compute aggregates
    gw_losses = []
    gw_rtts = []
    pub_losses = []
    pub_rtts = []
    dns_failures = 0
    dns_total = 0
    timeout_streak = 0
    max_timeout_streak = 0

    for obs in observations:
        if obs.gateway_ping:
            gw_losses.append(obs.gateway_ping.loss_percent)
            if obs.gateway_ping.rtt_avg is not None:
                gw_rtts.append(obs.gateway_ping.rtt_avg)
            if obs.gateway_ping.timed_out:
                timeout_streak += 1
                max_timeout_streak = max(max_timeout_streak, timeout_streak)
            else:
                timeout_streak = 0

        for pp in obs.public_pings:
            pub_losses.append(pp.loss_percent)
            if pp.rtt_avg is not None:
                pub_rtts.append(pp.rtt_avg)

        for dr in obs.dns_results:
            dns_total += 1
            if not dr.resolved:
                dns_failures += 1

    gw_loss_avg = statistics.mean(gw_losses) if gw_losses else 100.0
    pub_loss_avg = statistics.mean(pub_losses) if pub_losses else 100.0
    gw_rtt_avg = statistics.mean(gw_rtts) if gw_rtts else None
    pub_rtt_avg = statistics.mean(pub_rtts) if pub_rtts else None
    dns_fail_rate = dns_failures / dns_total if dns_total > 0 else 0.0

    gw_reachable = gw_loss_avg < config.gateway_loss_threshold
    pub_reachable = pub_loss_avg < config.public_loss_threshold
    dns_healthy = dns_fail_rate < config.dns_failure_threshold

    # Route stability
    route_changes = 0
    if route_history and len(route_history) >= 2:
        for i in range(1, len(route_history)):
            rd = diff_routes(route_history[i - 1], route_history[i])
            if rd.is_significant:
                route_changes += 1
    route_stable = route_changes < config.route_change_sensitivity

    # Evidence dict for transparency
    evidence = {
        "gateway_loss_avg": round(gw_loss_avg, 1),
        "gateway_rtt_avg": round(gw_rtt_avg, 1) if gw_rtt_avg else None,
        "public_loss_avg": round(pub_loss_avg, 1),
        "public_rtt_avg": round(pub_rtt_avg, 1) if pub_rtt_avg else None,
        "dns_fail_rate": round(dns_fail_rate, 3),
        "route_changes": route_changes,
        "max_timeout_streak": max_timeout_streak,
        "observations_count": len(observations),
    }

    # Rule cascade
    if not gw_reachable:
        return _make(
            now, DiagnosisCategory.LAN_ISSUE,
            "LAN issue likely",
            f"Gateway showing {gw_loss_avg:.0f}% packet loss. "
            "Local network connectivity appears degraded.",
            _confidence(gw_loss_avg, config.gateway_loss_threshold),
            evidence,
        )

    if gw_reachable and not pub_reachable:
        return _make(
            now, DiagnosisCategory.ISP_WAN_ISSUE,
            "ISP / WAN instability likely",
            f"Gateway is stable ({gw_loss_avg:.0f}% loss), but public IP tests "
            f"show {pub_loss_avg:.0f}% loss. This suggests an issue beyond "
            "your local network.",
            _confidence(pub_loss_avg, config.public_loss_threshold),
            evidence,
        )

    if gw_reachable and pub_reachable and not dns_healthy:
        return _make(
            now, DiagnosisCategory.DNS_ISSUE,
            "DNS issue likely",
            f"Internet is reachable (public IP loss {pub_loss_avg:.0f}%), "
            f"but DNS resolution is failing ({dns_fail_rate:.0%} failure rate). "
            "DNS servers may be unreachable or misconfigured.",
            _confidence(dns_fail_rate * 100, config.dns_failure_threshold * 100),
            evidence,
        )

    if gw_reachable and not route_stable:
        return _make(
            now, DiagnosisCategory.UPSTREAM_ROUTE_ISSUE,
            "Upstream route instability likely",
            f"Route path changed significantly {route_changes} time(s) recently "
            "while gateway remained stable. Upstream routing instability likely.",
            "medium",
            evidence,
        )

    # Check for intermittent issues
    has_some_loss = pub_loss_avg > 2.0 or gw_loss_avg > 2.0
    has_burst = max_timeout_streak >= config.timeout_burst_threshold

    if has_burst or (has_some_loss and gw_reachable and pub_reachable):
        return _make(
            now, DiagnosisCategory.INTERMITTENT,
            "Intermittent packet loss detected",
            f"Connection is generally reachable but showing signs of instability. "
            f"Gateway loss: {gw_loss_avg:.0f}%, Public loss: {pub_loss_avg:.0f}%, "
            f"Max timeout streak: {max_timeout_streak}.",
            "medium",
            evidence,
        )

    # All healthy
    latency_note = ""
    if pub_rtt_avg and pub_rtt_avg > config.latency_warning_ms:
        latency_note = f" Note: latency is elevated ({pub_rtt_avg:.0f} ms)."

    return _make(
        now, DiagnosisCategory.HEALTHY,
        "Connection healthy",
        f"All checks passing. Gateway loss: {gw_loss_avg:.0f}%, "
        f"Public loss: {pub_loss_avg:.0f}%, "
        f"DNS failure rate: {dns_fail_rate:.0%}.{latency_note}",
        "high",
        evidence,
    )


def _make(
    ts: datetime, cat: DiagnosisCategory, summary: str,
    explanation: str, confidence: str, evidence: dict,
) -> Diagnosis:
    return Diagnosis(
        timestamp=ts,
        category=cat,
        summary=summary,
        explanation=explanation,
        confidence=confidence,
        evidence=evidence,
    )


def _confidence(value: float, threshold: float) -> str:
    """Estimate confidence based on how far past the threshold we are."""
    ratio = value / threshold if threshold > 0 else 1.0
    if ratio >= 2.0:
        return "high"
    if ratio >= 1.3:
        return "medium"
    return "low"
