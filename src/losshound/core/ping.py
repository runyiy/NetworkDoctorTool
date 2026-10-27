from __future__ import annotations

import ipaddress
import logging
import re
import statistics
import subprocess
from datetime import datetime
from typing import Optional

from losshound.core import icmp_ping
from losshound.core.models import PingResult
from losshound.core.subprocess_runner import run_subprocess_interruptible
from losshound.core.validation import validate_target

logger = logging.getLogger(__name__)


def _is_ipv4_literal(target: str) -> bool:
    try:
        ipaddress.IPv4Address(target)
        return True
    except ValueError:
        return False


def ping(target: str, count: int = 4, timeout_ms: int = 2000) -> PingResult:
    """Ping a target: native ICMP for IPv4 literals, subprocess fallback."""
    now = datetime.now()

    if not validate_target(target):
        logger.warning("Invalid ping target: %r", target)
        return PingResult(
            target=target, timestamp=now,
            packets_sent=count, packets_received=0,
            loss_percent=100.0, timed_out=False,
            error="Invalid target",
        )

    # Preferred path: kernel ICMP API. No process spawn, no locale-dependent
    # parsing. Hostnames still go through ping.exe, which resolves them.
    if icmp_ping.available() and _is_ipv4_literal(target):
        try:
            rtts = icmp_ping.send_echoes(target, count=count, timeout_ms=timeout_ms)
            return _build_ping_result(rtts, target, now, count)
        except InterruptedError:
            raise
        except OSError as exc:
            logger.debug(
                "Native ICMP ping to %s failed (%s); falling back to ping.exe",
                target, exc,
            )

    args = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    process_timeout = (count * timeout_ms / 1000) + 10

    try:
        output, _, _ = run_subprocess_interruptible(
            args,
            process_timeout,
        )
    except subprocess.TimeoutExpired:
        return PingResult(
            target=target, timestamp=now,
            packets_sent=count, packets_received=0,
            loss_percent=100.0, timed_out=True,
            error="Process timed out",
        )
    except OSError as exc:
        return PingResult(
            target=target, timestamp=now,
            packets_sent=count, packets_received=0,
            loss_percent=100.0, timed_out=True,
            error=str(exc),
        )

    return _parse_ping_output(output, target, now, count)


def _parse_ping_output(
    output: str, target: str, timestamp: datetime, count: int
) -> PingResult:
    """Parse Windows ping output into a PingResult in a locale-independent way."""
    # Split the output at the start of the summary block (e.g. "statistics", "istatistik", etc.)
    # to avoid matching statistics averages.
    parts = re.split(r"stat", output, flags=re.IGNORECASE)
    replies_section = parts[0] if parts else output

    # Extract all reply RTT values. Windows ping replies contain time=Xms or time<1ms
    # regardless of locale (e.g. time=, süre=, zeit=, etc. are followed by '=' or '<').
    # For robustness, we only count RTTs on lines containing "ttl".
    rtts = []
    for line in replies_section.splitlines():
        if "ttl" in line.lower():
            match = re.search(r"[=<]\s*(\d+)\s*ms", line, re.IGNORECASE)
            if match:
                rtts.append(float(match.group(1)))

    return _build_ping_result(rtts, target, timestamp, count)


def _build_ping_result(
    rtts: list[float], target: str, timestamp: datetime, count: int
) -> PingResult:
    """Aggregate per-probe RTTs into a PingResult (shared by both ping paths)."""
    received = min(count, len(rtts))
    loss_pct = ((count - received) / count * 100.0) if count > 0 else 100.0
    loss_pct = max(0.0, min(100.0, loss_pct))

    rtt_min: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_max: Optional[float] = None
    jitter: Optional[float] = None

    if rtts:
        rtt_min = min(rtts)
        rtt_max = max(rtts)
        rtt_avg = sum(rtts) / len(rtts)

    if len(rtts) >= 2:
        diffs = [abs(rtts[i+1] - rtts[i]) for i in range(len(rtts)-1)]
        jitter = statistics.mean(diffs)

    timed_out = received == 0

    return PingResult(
        target=target,
        timestamp=timestamp,
        packets_sent=count,
        packets_received=received,
        loss_percent=loss_pct,
        rtt_min=rtt_min,
        rtt_avg=rtt_avg,
        rtt_max=rtt_max,
        rtt_jitter=jitter,
        timed_out=timed_out,
    )

