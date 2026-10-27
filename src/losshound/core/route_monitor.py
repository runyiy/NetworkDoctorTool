from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from datetime import datetime
from typing import Optional

from losshound.core.models import RouteHop, RouteSnapshot, RouteDiff
from losshound.core.subprocess_runner import run_subprocess_interruptible
from losshound.core.validation import validate_target

logger = logging.getLogger(__name__)

_RE_HOP_LINE = re.compile(r"^\s*(\d+)\s+(.+)$")
_RE_IP = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
_RE_RTT = re.compile(r"(\d+)\s*ms|(<1)\s*ms")
_RE_BRACKETED_IP = re.compile(r"\[(\d+\.\d+\.\d+\.\d+)\]")


def trace_route(
    target: str, max_hops: int = 20, timeout_ms: int = 3000
) -> RouteSnapshot:
    """Run tracert and parse the output into a RouteSnapshot."""
    now = datetime.now()
    
    if not validate_target(target):
        logger.warning("Invalid tracert target: %r", target)
        return RouteSnapshot(
            target=target, timestamp=now,
            completed=False, error="Invalid target",
        )

    args = ["tracert", "-d", "-w", str(timeout_ms), "-h", str(max_hops), target]
    process_timeout = max_hops * (timeout_ms / 1000) + 30

    try:
        output, _, _ = run_subprocess_interruptible(
            args,
            process_timeout,
        )
    except subprocess.TimeoutExpired:
        return RouteSnapshot(
            target=target, timestamp=now,
            completed=False, error="Tracert timed out",
        )
    except OSError as exc:
        return RouteSnapshot(
            target=target, timestamp=now,
            completed=False, error=str(exc),
        )

    return _parse_tracert_output(output, target, now)


def _parse_tracert_output(
    output: str, target: str, timestamp: datetime
) -> RouteSnapshot:
    """Parse Windows tracert output into a RouteSnapshot."""
    hops: list[RouteHop] = []

    for line in output.splitlines():
        match = _RE_HOP_LINE.match(line)
        if not match:
            continue

        hop_num = int(match.group(1))
        rest = match.group(2)

        # Extract RTT samples
        rtt_samples: list[Optional[float]] = []
        for rtt_match in _RE_RTT.finditer(rest):
            if rtt_match.group(2):  # "<1 ms"
                rtt_samples.append(0.5)
            elif rtt_match.group(1):
                rtt_samples.append(float(rtt_match.group(1)))

        # If we see "*" tokens, they are timeouts
        star_count = rest.count("*")
        while len(rtt_samples) + star_count < 3 and star_count > 0:
            star_count -= 1
        for _ in range(3 - len(rtt_samples)):
            rtt_samples.append(None)

        rtt_samples = rtt_samples[:3]

        # Extract IP
        ip_match = _RE_IP.search(rest)
        ip = ip_match.group(1) if ip_match else None

        hops.append(RouteHop(hop_number=hop_num, ip=ip, rtt_samples=rtt_samples))

    try:
        destination_ip = str(ipaddress.IPv4Address(target))
    except ipaddress.AddressValueError:
        # For hostname targets, tracert prints the resolved destination in
        # square brackets in its header even with ``-d`` enabled.
        destination_ip = None
        for match in _RE_BRACKETED_IP.finditer(output):
            try:
                destination_ip = str(ipaddress.IPv4Address(match.group(1)))
                break
            except ipaddress.AddressValueError:
                continue

    # A responsive final hop is not necessarily the requested destination;
    # tracert can stop at max_hops immediately after an unrelated router.
    completed = (
        bool(hops)
        and destination_ip is not None
        and hops[-1].ip == destination_ip
    )

    return RouteSnapshot(
        target=target,
        timestamp=timestamp,
        hops=hops,
        completed=completed,
    )


def diff_routes(old: RouteSnapshot, new: RouteSnapshot) -> RouteDiff:
    """Compare two route snapshots and identify meaningful changes."""
    old_ips = old.responsive_ips
    new_ips = new.responsive_ips

    max_len = max(len(old_ips), len(new_ips))
    changed_hops: list[int] = []

    for i in range(max_len):
        old_ip = old_ips[i] if i < len(old_ips) else None
        new_ip = new_ips[i] if i < len(new_ips) else None

        # Skip if both are timeouts
        if old_ip is None and new_ip is None:
            continue
        if old_ip != new_ip:
            changed_hops.append(i + 1)

    hops_added = max(0, len(new_ips) - len(old_ips))
    hops_removed = max(0, len(old_ips) - len(new_ips))

    # Significant if multiple hops changed or total hop count shifted a lot
    is_significant = (
        len(changed_hops) >= 2
        or abs(hops_added - hops_removed) >= 3
    )

    return RouteDiff(
        old_timestamp=old.timestamp,
        new_timestamp=new.timestamp,
        changed_hops=changed_hops,
        hops_added=hops_added,
        hops_removed=hops_removed,
        is_significant=is_significant,
    )
