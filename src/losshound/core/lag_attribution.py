"""Blame-the-process: attribute latency spikes to local traffic when possible.

When the monitor sees RTTs jump or loss appear, this module answers the
question "is it *us* or *them*?":

1. Samples interface byte counters twice (GetIfTable, no admin needed) to
   measure current down/up throughput and link utilization on the busiest
   interface. The busiest single interface is used instead of a sum so
   virtual adapters (vEthernet/WSL bridges) don't double-count traffic.
2. Snapshots active connections grouped by process (netstat/tasklist via
   local_monitor) to rank likely culprits.
3. Issues an honest verdict: local saturation, external, or inconclusive.

Per-process byte counters on Windows require ETW or admin rights, so the
suspect ranking is a heuristic (connection counts), stated as "likely".
"""
from __future__ import annotations

import ctypes
import logging
import os
import sys
import time
from collections import Counter
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

_IF_TYPE_SOFTWARE_LOOPBACK = 24
# MIB_IF_OPER_STATUS: 4 = connected, 5 = operational
_MIN_OPER_STATUS = 4
_ERROR_INSUFFICIENT_BUFFER = 122

# Verdict thresholds. When the user's line capacity is known (from load
# benchmark history), saturation is judged against it; the absolute and
# utilization checks are fallbacks for when it isn't.
SATURATION_CAPACITY_FRACTION = 0.6
SATURATION_CAPACITY_MIN_MBPS = 10.0
SATURATION_UTILIZATION_PCT = 60.0
SATURATION_ABS_MBPS = 50.0
QUIET_LINK_MBPS = 5.0

# GetIfTable lists WFP/QoS filter shims as separate rows that mirror the
# physical NIC's counters but often report junk link speeds.
_PSEUDO_INTERFACE_MARKERS = ("filter", "-0000", "qos packet scheduler")


class _MIB_IFROW(ctypes.Structure):
    _fields_ = [
        ("wszName", ctypes.c_wchar * 256),
        ("dwIndex", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
        ("dwMtu", wintypes.DWORD),
        ("dwSpeed", wintypes.DWORD),
        ("dwPhysAddrLen", wintypes.DWORD),
        ("bPhysAddr", ctypes.c_ubyte * 8),
        ("dwAdminStatus", wintypes.DWORD),
        ("dwOperStatus", wintypes.DWORD),
        ("dwLastChange", wintypes.DWORD),
        ("dwInOctets", wintypes.DWORD),
        ("dwInUcastPkts", wintypes.DWORD),
        ("dwInNUcastPkts", wintypes.DWORD),
        ("dwInDiscards", wintypes.DWORD),
        ("dwInErrors", wintypes.DWORD),
        ("dwInUnknownProtos", wintypes.DWORD),
        ("dwOutOctets", wintypes.DWORD),
        ("dwOutUcastPkts", wintypes.DWORD),
        ("dwOutNUcastPkts", wintypes.DWORD),
        ("dwOutDiscards", wintypes.DWORD),
        ("dwOutErrors", wintypes.DWORD),
        ("dwOutQLen", wintypes.DWORD),
        ("dwDescrLen", wintypes.DWORD),
        ("bDescr", ctypes.c_char * 256),
    ]


_iphlpapi = None
if sys.platform == "win32":
    try:
        _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        _iphlpapi.GetIfTable.restype = wintypes.DWORD
        _iphlpapi.GetIfTable.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.BOOL,
        ]
    except OSError as exc:  # pragma: no cover - iphlpapi ships with Windows
        logger.warning("iphlpapi unavailable, throughput sampling disabled: %s", exc)
        _iphlpapi = None


def throughput_available() -> bool:
    return _iphlpapi is not None


@dataclass
class ThroughputSample:
    """Measured link throughput on the busiest active interface."""

    down_mbps: float
    up_mbps: float
    interface: str = ""
    link_speed_mbps: Optional[float] = None
    utilization_pct: Optional[float] = None


@dataclass
class ProcessSuspect:
    """A process ranked as a likely contributor to network load."""

    process: str
    pid: int
    connection_count: int
    top_remote: str = ""


@dataclass
class LagAttribution:
    """A latency/loss event attributed to a probable cause."""

    timestamp: datetime
    trigger: str                 # "latency" | "loss"
    baseline_rtt_ms: Optional[float]
    spike_rtt_ms: Optional[float]
    throughput: Optional[ThroughputSample]
    verdict: str                 # "local_saturation" | "external" | "inconclusive"
    suspects: list[ProcessSuspect] = field(default_factory=list)
    summary: str = ""


def _get_if_rows() -> list[_MIB_IFROW]:
    if _iphlpapi is None:
        raise OSError("iphlpapi not available")

    size = wintypes.ULONG(0)
    _iphlpapi.GetIfTable(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value)
    ret = _iphlpapi.GetIfTable(buf, ctypes.byref(size), False)
    if ret != 0:
        raise OSError(f"GetIfTable failed with code {ret}")

    num_entries = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
    row_size = ctypes.sizeof(_MIB_IFROW)
    base = ctypes.sizeof(wintypes.DWORD)

    rows = []
    for i in range(num_entries):
        offset = base + i * row_size
        if offset + row_size > size.value:
            break
        rows.append(_MIB_IFROW.from_buffer_copy(buf, offset))
    return rows


def _read_counters() -> dict[int, tuple[int, int, float, str]]:
    """Per-interface (in_octets, out_octets, speed_bps, description)."""
    counters = {}
    for row in _get_if_rows():
        if row.dwType == _IF_TYPE_SOFTWARE_LOOPBACK:
            continue
        if row.dwOperStatus < _MIN_OPER_STATUS:
            continue
        descr = row.bDescr[: row.dwDescrLen].decode("ascii", errors="ignore")
        counters[row.dwIndex] = (
            row.dwInOctets, row.dwOutOctets, float(row.dwSpeed), descr,
        )
    return counters


def sample_throughput(interval_s: float = 1.0) -> ThroughputSample:
    """Measure current throughput on the busiest active interface.

    Raises OSError when the interface table cannot be read.
    """
    first = _read_counters()
    start = time.perf_counter()
    time.sleep(interval_s)
    second = _read_counters()
    elapsed = time.perf_counter() - start

    candidates: list[tuple[float, float, float, str]] = []
    for index, (in2, out2, speed, descr) in second.items():
        if index not in first:
            continue
        in1, out1, _, _ = first[index]
        # DWORD counters wrap at 4 GiB; masking handles a single wrap.
        d_in = (in2 - in1) & 0xFFFFFFFF
        d_out = (out2 - out1) & 0xFFFFFFFF
        down_mbps = (d_in * 8) / (elapsed * 1_000_000)
        up_mbps = (d_out * 8) / (elapsed * 1_000_000)
        candidates.append((down_mbps, up_mbps, speed, descr))

    def _is_pseudo(descr: str) -> bool:
        lowered = descr.lower()
        return any(marker in lowered for marker in _PSEUDO_INTERFACE_MARKERS)

    physical = [c for c in candidates if not _is_pseudo(c[3])]
    pool = physical or candidates
    best = max(pool, key=lambda c: c[0] + c[1], default=None)

    if best is None:
        return ThroughputSample(down_mbps=0.0, up_mbps=0.0)

    down_mbps, up_mbps, speed_bps, descr = best
    link_speed_mbps = speed_bps / 1_000_000 if speed_bps > 0 else None
    utilization = None
    if link_speed_mbps:
        utilization = max(down_mbps, up_mbps) / link_speed_mbps * 100.0

    return ThroughputSample(
        down_mbps=down_mbps,
        up_mbps=up_mbps,
        interface=descr,
        link_speed_mbps=link_speed_mbps,
        utilization_pct=utilization,
    )


def build_suspects(
    connections: list[dict],
    own_pid: Optional[int] = None,
    max_suspects: int = 3,
) -> list[ProcessSuspect]:
    """Rank processes by active connection count (heuristic culprit list)."""
    if own_pid is None:
        own_pid = os.getpid()

    by_proc: dict[str, dict] = {}
    for conn in connections:
        try:
            pid = int(conn.get("pid", 0))
        except (TypeError, ValueError):
            continue
        if pid == own_pid:
            continue
        name = conn.get("process") or "Unknown"
        if name.lower() in ("unknown", "system idle process"):
            continue
        state = (conn.get("state") or "").upper()
        # UDP rows have no state; for TCP only count established flows.
        if state and state != "ESTABLISHED":
            continue

        entry = by_proc.setdefault(
            name, {"count": 0, "pid": pid, "remotes": Counter()}
        )
        entry["count"] += 1
        remote = conn.get("resolved_name") or conn.get("remote_ip") or ""
        if remote:
            entry["remotes"][remote] += 1

    ranked = sorted(by_proc.items(), key=lambda kv: kv[1]["count"], reverse=True)
    return [
        ProcessSuspect(
            process=name,
            pid=data["pid"],
            connection_count=data["count"],
            top_remote=data["remotes"].most_common(1)[0][0] if data["remotes"] else "",
        )
        for name, data in ranked[:max_suspects]
    ]


def decide_verdict(
    sample: Optional[ThroughputSample],
    suspects: list[ProcessSuspect],
    capacity_mbps: Optional[float] = None,
) -> tuple[str, str]:
    """Classify a spike as local saturation, external, or inconclusive.

    *capacity_mbps* is the user's measured line speed (from load benchmark
    history). The LAN link is usually much faster than the WAN line, so
    when capacity is known it is the primary saturation yardstick.
    """
    if sample is None:
        return "inconclusive", "Could not read link throughput"

    total = sample.down_mbps + sample.up_mbps
    line_pct: Optional[float] = None
    if capacity_mbps and capacity_mbps > 1:
        line_pct = total / capacity_mbps * 100.0

    saturated = (
        (line_pct is not None
         and total >= SATURATION_CAPACITY_MIN_MBPS
         and line_pct >= SATURATION_CAPACITY_FRACTION * 100.0)
        or (sample.utilization_pct is not None
            and sample.utilization_pct >= SATURATION_UTILIZATION_PCT)
        or total >= SATURATION_ABS_MBPS
    )

    if saturated:
        if suspects:
            top = suspects[0]
            blame = f"likely {top.process} ({top.connection_count} conns)"
        else:
            blame = "a local app"
        line_note = (
            f" (~{min(line_pct, 100.0):.0f}% of your line)"
            if line_pct is not None else ""
        )
        return (
            "local_saturation",
            f"local traffic {sample.down_mbps:.0f} down / {sample.up_mbps:.0f} up "
            f"Mbps{line_note} - {blame}",
        )

    if total < QUIET_LINK_MBPS:
        return (
            "external",
            f"link quiet ({total:.1f} Mbps) - looks external (ISP or route)",
        )

    return (
        "inconclusive",
        f"moderate local traffic ({sample.down_mbps:.0f} down / {sample.up_mbps:.0f} up Mbps), cause unclear",
    )


def attribute_lag(
    trigger: str,
    baseline_rtt_ms: Optional[float],
    spike_rtt_ms: Optional[float],
    sample_interval_s: float = 1.0,
) -> LagAttribution:
    """Run the full attribution: throughput sample + suspect ranking + verdict."""
    now = datetime.now()

    sample: Optional[ThroughputSample] = None
    if throughput_available():
        try:
            sample = sample_throughput(sample_interval_s)
        except OSError as exc:
            logger.debug("Throughput sampling failed: %s", exc)

    suspects: list[ProcessSuspect] = []
    try:
        from losshound.core.local_monitor import get_active_connections

        suspects = build_suspects(get_active_connections())
    except Exception as exc:
        logger.debug("Connection snapshot failed: %s", exc)

    capacity_mbps: Optional[float] = None
    try:
        from losshound.core.load_benchmark import get_latest_load_snapshot

        snapshot = get_latest_load_snapshot()
        if snapshot and snapshot.speed_mbps > 1:
            capacity_mbps = snapshot.speed_mbps
    except Exception as exc:
        logger.debug("Line capacity lookup failed: %s", exc)

    verdict, detail = decide_verdict(sample, suspects, capacity_mbps)

    if trigger == "loss":
        prefix = "Packet loss"
    elif baseline_rtt_ms and spike_rtt_ms:
        prefix = f"Lag spike ({spike_rtt_ms:.0f}ms vs {baseline_rtt_ms:.0f}ms normal)"
    else:
        prefix = "Lag spike"

    return LagAttribution(
        timestamp=now,
        trigger=trigger,
        baseline_rtt_ms=baseline_rtt_ms,
        spike_rtt_ms=spike_rtt_ms,
        throughput=sample,
        verdict=verdict,
        suspects=suspects,
        summary=f"{prefix}: {detail}",
    )
