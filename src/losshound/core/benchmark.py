"""Network performance benchmarking.

Runs a comprehensive suite of network tests — ping latency, jitter, packet
loss, DNS resolution, and TCP connection time — and produces a comparable
snapshot.  Two snapshots (e.g. *before* and *after* optimisation) can be
diffed to show the real-world improvement.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import statistics
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from losshound.core.dns_bench import (
    DNS_SERVERS,
    TEST_DOMAINS,
    query_dns_server,
)
from losshound.core.ping import ping

logger = logging.getLogger(__name__)

_DATA_DIR = Path(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
) / "Losshound"
_BENCH_FILE = _DATA_DIR / "benchmark_history.json"

# Targets
_PING_TARGETS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
_TCP_TARGETS = [
    ("google.com", 443),
    ("cloudflare.com", 443),
    ("github.com", 443),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PingBench:
    """Ping results for a single target."""

    target: str
    avg_ms: Optional[float] = None
    min_ms: Optional[float] = None
    max_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    loss_pct: float = 100.0


@dataclass
class DnsBench:
    """DNS resolution benchmark for a single server."""

    server: str
    name: str
    avg_ms: float
    success_rate: float


@dataclass
class TcpBench:
    """TCP handshake time to a target."""

    host: str
    port: int
    connect_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class BenchmarkSnapshot:
    """Complete network performance snapshot."""

    timestamp: str
    label: str  # e.g. "before" or "after"
    ping_results: list[PingBench]
    dns_results: list[DnsBench]
    tcp_results: list[TcpBench]

    # Aggregates (computed)
    avg_latency_ms: Optional[float] = None
    avg_jitter_ms: Optional[float] = None
    avg_loss_pct: Optional[float] = None
    avg_dns_ms: Optional[float] = None
    avg_tcp_ms: Optional[float] = None


@dataclass
class BenchmarkDelta:
    """Comparison between two snapshots."""

    latency_delta_ms: Optional[float] = None
    latency_pct_change: Optional[float] = None
    jitter_delta_ms: Optional[float] = None
    jitter_pct_change: Optional[float] = None
    loss_delta_pct: Optional[float] = None
    dns_delta_ms: Optional[float] = None
    dns_pct_change: Optional[float] = None
    tcp_delta_ms: Optional[float] = None
    tcp_pct_change: Optional[float] = None


@dataclass
class BenchmarkReport:
    """Full before/after comparison report."""

    before: BenchmarkSnapshot
    after: BenchmarkSnapshot
    delta: BenchmarkDelta
    summary: str


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark(
    label: str = "snapshot",
    ping_count: int = 20,
    ping_targets: list[str] | None = None,
    dns_servers: list[str] | None = None,
    tcp_targets: list[tuple[str, int]] | None = None,
    progress_callback=None,
) -> BenchmarkSnapshot:
    """Run a full network performance benchmark.

    Parameters
    ----------
    label:
        Human-readable label (e.g. ``"before"`` or ``"after"``).
    ping_count:
        Number of pings per target (more = more accurate).
    ping_targets:
        IPs to ping.  Defaults to Cloudflare, Google, Quad9.
    dns_servers:
        DNS servers to test.  Defaults to top 6 public servers.
    tcp_targets:
        ``(host, port)`` pairs for TCP handshake tests.
    progress_callback:
        Optional ``callable(str)`` for status updates.
    """
    if ping_targets is None:
        ping_targets = _PING_TARGETS
    if dns_servers is None:
        dns_servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "76.76.2.0", "94.140.14.14"]
    if tcp_targets is None:
        tcp_targets = _TCP_TARGETS

    def _progress(msg: str):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    # --- Ping tests ---
    _progress("Running ping tests...")
    ping_results: list[PingBench] = []
    for target in ping_targets:
        _progress(f"  Pinging {target} ({ping_count} packets)...")
        result = ping(target, count=ping_count, timeout_ms=2000)
        ping_results.append(PingBench(
            target=target,
            avg_ms=result.rtt_avg,
            min_ms=result.rtt_min,
            max_ms=result.rtt_max,
            jitter_ms=result.rtt_jitter,
            loss_pct=result.loss_percent,
        ))

    # --- DNS tests ---
    _progress("Running DNS benchmark...")
    dns_results: list[DnsBench] = []
    for server in dns_servers:
        _progress(f"  Testing DNS {server}...")
        latencies: list[float] = []
        total = 0
        for domain in TEST_DOMAINS:
            for _ in range(2):  # 2 rounds per domain
                total += 1
                t = query_dns_server(server, domain, timeout=2.0)
                if t is not None:
                    latencies.append(t)

        avg = statistics.mean(latencies) if latencies else float("inf")
        rate = len(latencies) / total if total else 0.0
        dns_results.append(DnsBench(
            server=server,
            name=DNS_SERVERS.get(server, "Custom"),
            avg_ms=avg,
            success_rate=rate,
        ))

    # --- TCP handshake tests ---
    _progress("Running TCP connection tests...")
    tcp_results: list[TcpBench] = []
    for host, port in tcp_targets:
        _progress(f"  Connecting to {host}:{port}...")
        timings: list[float] = []
        error: str | None = None
        for _ in range(3):  # 3 attempts
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                start = time.perf_counter()
                sock.connect((host, port))
                elapsed = (time.perf_counter() - start) * 1000.0
                timings.append(elapsed)
                sock.close()
            except Exception as exc:
                error = str(exc)
                try:
                    sock.close()
                except Exception:
                    pass

        tcp_results.append(TcpBench(
            host=host,
            port=port,
            connect_ms=statistics.mean(timings) if timings else None,
            error=error if not timings else None,
        ))

    # --- Compute aggregates ---
    valid_latencies = [p.avg_ms for p in ping_results if p.avg_ms is not None]
    valid_jitters = [p.jitter_ms for p in ping_results if p.jitter_ms is not None]
    valid_losses = [p.loss_pct for p in ping_results]
    valid_dns = [d.avg_ms for d in dns_results if d.avg_ms != float("inf")]
    valid_tcp = [t.connect_ms for t in tcp_results if t.connect_ms is not None]

    snapshot = BenchmarkSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        label=label,
        ping_results=ping_results,
        dns_results=dns_results,
        tcp_results=tcp_results,
        avg_latency_ms=statistics.mean(valid_latencies) if valid_latencies else None,
        avg_jitter_ms=statistics.mean(valid_jitters) if valid_jitters else None,
        avg_loss_pct=statistics.mean(valid_losses) if valid_losses else None,
        avg_dns_ms=statistics.mean(valid_dns) if valid_dns else None,
        avg_tcp_ms=statistics.mean(valid_tcp) if valid_tcp else None,
    )

    _progress("Benchmark complete.")
    return snapshot


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_snapshots(
    before: BenchmarkSnapshot,
    after: BenchmarkSnapshot,
) -> BenchmarkReport:
    """Compare two snapshots and produce a report with deltas."""

    def _delta(b: float | None, a: float | None):
        if b is None or a is None:
            return None, None
        diff = a - b
        pct = (diff / b * 100.0) if b != 0 else 0.0
        return diff, pct

    lat_d, lat_p = _delta(before.avg_latency_ms, after.avg_latency_ms)
    jit_d, jit_p = _delta(before.avg_jitter_ms, after.avg_jitter_ms)
    dns_d, dns_p = _delta(before.avg_dns_ms, after.avg_dns_ms)
    tcp_d, tcp_p = _delta(before.avg_tcp_ms, after.avg_tcp_ms)

    loss_d = None
    if before.avg_loss_pct is not None and after.avg_loss_pct is not None:
        loss_d = after.avg_loss_pct - before.avg_loss_pct

    delta = BenchmarkDelta(
        latency_delta_ms=lat_d,
        latency_pct_change=lat_p,
        jitter_delta_ms=jit_d,
        jitter_pct_change=jit_p,
        loss_delta_pct=loss_d,
        dns_delta_ms=dns_d,
        dns_pct_change=dns_p,
        tcp_delta_ms=tcp_d,
        tcp_pct_change=tcp_p,
    )

    # Build summary
    improvements: list[str] = []
    regressions: list[str] = []
    unchanged: list[str] = []

    def _classify(name: str, diff: float | None, pct: float | None, lower_is_better: bool = True):
        if diff is None or pct is None:
            unchanged.append(name)
            return
        threshold = 2.0  # % change needed to count
        if abs(pct) < threshold:
            unchanged.append(f"{name} (~0%)")
        elif (diff < 0) == lower_is_better:
            improvements.append(f"{name} {abs(pct):.1f}% better")
        else:
            regressions.append(f"{name} {abs(pct):.1f}% worse")

    _classify("Latency", lat_d, lat_p)
    _classify("Jitter", jit_d, jit_p)
    _classify("DNS", dns_d, dns_p)
    _classify("TCP connect", tcp_d, tcp_p)

    if loss_d is not None:
        if abs(loss_d) < 0.5:
            unchanged.append("Packet loss (~0%)")
        elif loss_d < 0:
            improvements.append(f"Packet loss {abs(loss_d):.1f}pp less")
        else:
            regressions.append(f"Packet loss {loss_d:.1f}pp more")

    parts: list[str] = []
    if improvements:
        parts.append("Improved: " + ", ".join(improvements))
    if regressions:
        parts.append("Regressed: " + ", ".join(regressions))
    if unchanged:
        parts.append("Unchanged: " + ", ".join(unchanged))

    summary = ". ".join(parts) if parts else "No measurable changes."

    return BenchmarkReport(
        before=before,
        after=after,
        delta=delta,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_snapshot(snapshot: BenchmarkSnapshot) -> None:
    """Append a snapshot to the benchmark history file and SQLite store."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    snap_dict = asdict(snapshot)

    # JSON file (legacy, capped at 20)
    history: list[dict] = []
    if _BENCH_FILE.is_file():
        try:
            with open(_BENCH_FILE, "r", encoding="utf-8") as fh:
                history = json.load(fh)
        except Exception:
            history = []

    history.append(snap_dict)
    history = history[-20:]

    with open(_BENCH_FILE, "w", encoding="utf-8") as fh:
        json.dump(history, fh, indent=2)

    # SQLite store (primary, unlimited history)
    try:
        from losshound.core.scoring import score_snapshot
        from losshound.storage.history import HistoryStore

        score = score_snapshot(snapshot)
        store = HistoryStore()
        store.save_benchmark(snap_dict, score=score.overall, grade=score.grade)
        store.close()
    except Exception as exc:
        logger.warning("Failed to save benchmark to SQLite: %s", exc)


def load_snapshots() -> list[BenchmarkSnapshot]:
    """Load all saved snapshots."""
    if not _BENCH_FILE.is_file():
        return []
    try:
        with open(_BENCH_FILE, "r", encoding="utf-8") as fh:
            history = json.load(fh)
        snapshots = []
        for data in history:
            data["ping_results"] = [PingBench(**p) for p in data.get("ping_results", [])]
            data["dns_results"] = [DnsBench(**d) for d in data.get("dns_results", [])]
            data["tcp_results"] = [TcpBench(**t) for t in data.get("tcp_results", [])]
            snapshots.append(BenchmarkSnapshot(**data))
        return snapshots
    except Exception as exc:
        logger.warning("Failed to load benchmark history: %s", exc)
        return []


def get_latest_snapshot(label: str | None = None) -> BenchmarkSnapshot | None:
    """Get the most recent snapshot, optionally filtered by label."""
    snapshots = load_snapshots()
    if label:
        snapshots = [s for s in snapshots if s.label == label]
    return snapshots[-1] if snapshots else None


# ---------------------------------------------------------------------------
# CLI formatting
# ---------------------------------------------------------------------------

def format_snapshot(snap: BenchmarkSnapshot) -> str:
    """Format a snapshot for terminal display."""
    lines: list[str] = []
    lines.append(f"Benchmark: {snap.label} ({snap.timestamp[:19]})")
    lines.append("=" * 65)

    # Ping results
    lines.append("")
    lines.append("  PING RESULTS")
    lines.append(f"  {'Target':<18} {'Avg ms':<10} {'Min ms':<10} {'Max ms':<10} {'Jitter':<10} {'Loss':<8}")
    lines.append(f"  {'-'*18} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*8}")
    for p in snap.ping_results:
        avg = f"{p.avg_ms:.1f}" if p.avg_ms is not None else "N/A"
        mn = f"{p.min_ms:.1f}" if p.min_ms is not None else "N/A"
        mx = f"{p.max_ms:.1f}" if p.max_ms is not None else "N/A"
        jit = f"{p.jitter_ms:.1f}" if p.jitter_ms is not None else "N/A"
        loss = f"{p.loss_pct:.1f}%"
        lines.append(f"  {p.target:<18} {avg:<10} {mn:<10} {mx:<10} {jit:<10} {loss:<8}")

    # DNS results
    lines.append("")
    lines.append("  DNS RESULTS")
    lines.append(f"  {'Server':<18} {'Provider':<22} {'Avg ms':<10} {'Success':<8}")
    lines.append(f"  {'-'*18} {'-'*22} {'-'*10} {'-'*8}")
    for d in snap.dns_results:
        avg = f"{d.avg_ms:.1f}" if d.avg_ms != float("inf") else "N/A"
        rate = f"{d.success_rate * 100:.0f}%"
        lines.append(f"  {d.server:<18} {d.name:<22} {avg:<10} {rate:<8}")

    # TCP results
    lines.append("")
    lines.append("  TCP CONNECTION TESTS")
    lines.append(f"  {'Host':<22} {'Port':<8} {'Connect ms':<12} {'Status':<12}")
    lines.append(f"  {'-'*22} {'-'*8} {'-'*12} {'-'*12}")
    for t in snap.tcp_results:
        ms = f"{t.connect_ms:.1f}" if t.connect_ms is not None else "N/A"
        status = "OK" if t.connect_ms is not None else t.error or "Failed"
        lines.append(f"  {t.host:<22} {t.port:<8} {ms:<12} {status:<12}")

    # Aggregates
    lines.append("")
    lines.append("  SUMMARY")
    lines.append(f"    Avg latency:      {snap.avg_latency_ms:.1f} ms" if snap.avg_latency_ms else "    Avg latency:      N/A")
    lines.append(f"    Avg jitter:       {snap.avg_jitter_ms:.1f} ms" if snap.avg_jitter_ms else "    Avg jitter:       N/A")
    lines.append(f"    Avg packet loss:  {snap.avg_loss_pct:.1f}%" if snap.avg_loss_pct is not None else "    Avg packet loss:  N/A")
    lines.append(f"    Avg DNS resolve:  {snap.avg_dns_ms:.1f} ms" if snap.avg_dns_ms else "    Avg DNS resolve:  N/A")
    lines.append(f"    Avg TCP connect:  {snap.avg_tcp_ms:.1f} ms" if snap.avg_tcp_ms else "    Avg TCP connect:  N/A")

    return "\n".join(lines)


def format_comparison(report: BenchmarkReport) -> str:
    """Format a before/after comparison for terminal display."""
    b = report.before
    a = report.after
    d = report.delta

    lines: list[str] = []
    lines.append("BEFORE vs AFTER OPTIMIZATION")
    lines.append("=" * 65)

    def _fmt(val: float | None, suffix: str = "ms") -> str:
        if val is None:
            return "N/A"
        return f"{val:.1f}{suffix}"

    def _delta_str(diff: float | None, pct: float | None, suffix: str = "ms", lower_better: bool = True) -> str:
        if diff is None:
            return ""
        sign = "+" if diff > 0 else ""
        arrow = ""
        if pct is not None and abs(pct) >= 2:
            if (diff < 0) == lower_better:
                arrow = " [BETTER]"
            else:
                arrow = " [WORSE]"
        return f"{sign}{diff:.1f}{suffix} ({sign}{pct:.1f}%){arrow}"

    lines.append("")
    lines.append(f"  {'Metric':<22} {'Before':<14} {'After':<14} {'Change':<30}")
    lines.append(f"  {'-'*22} {'-'*14} {'-'*14} {'-'*30}")

    lines.append(f"  {'Avg Latency':<22} {_fmt(b.avg_latency_ms):<14} {_fmt(a.avg_latency_ms):<14} {_delta_str(d.latency_delta_ms, d.latency_pct_change):<30}")
    lines.append(f"  {'Avg Jitter':<22} {_fmt(b.avg_jitter_ms):<14} {_fmt(a.avg_jitter_ms):<14} {_delta_str(d.jitter_delta_ms, d.jitter_pct_change):<30}")

    loss_delta = ""
    if d.loss_delta_pct is not None:
        sign = "+" if d.loss_delta_pct > 0 else ""
        tag = ""
        if abs(d.loss_delta_pct) >= 0.5:
            tag = " [BETTER]" if d.loss_delta_pct < 0 else " [WORSE]"
        loss_delta = f"{sign}{d.loss_delta_pct:.1f}pp{tag}"
    lines.append(f"  {'Avg Packet Loss':<22} {_fmt(b.avg_loss_pct, '%'):<14} {_fmt(a.avg_loss_pct, '%'):<14} {loss_delta:<30}")

    lines.append(f"  {'Avg DNS Resolve':<22} {_fmt(b.avg_dns_ms):<14} {_fmt(a.avg_dns_ms):<14} {_delta_str(d.dns_delta_ms, d.dns_pct_change):<30}")
    lines.append(f"  {'Avg TCP Connect':<22} {_fmt(b.avg_tcp_ms):<14} {_fmt(a.avg_tcp_ms):<14} {_delta_str(d.tcp_delta_ms, d.tcp_pct_change):<30}")

    # Per-target ping comparison
    lines.append("")
    lines.append("  PER-TARGET PING COMPARISON")
    lines.append(f"  {'Target':<18} {'Before':<14} {'After':<14} {'Change':<20}")
    lines.append(f"  {'-'*18} {'-'*14} {'-'*14} {'-'*20}")
    after_map = {p.target: p for p in a.ping_results}
    for bp in b.ping_results:
        ap = after_map.get(bp.target)
        b_ms = _fmt(bp.avg_ms)
        a_ms = _fmt(ap.avg_ms) if ap else "N/A"
        change = ""
        if bp.avg_ms is not None and ap and ap.avg_ms is not None:
            diff = ap.avg_ms - bp.avg_ms
            pct = (diff / bp.avg_ms * 100.0) if bp.avg_ms else 0
            sign = "+" if diff > 0 else ""
            tag = " ok" if diff <= 0 else ""
            change = f"{sign}{diff:.1f}ms ({sign}{pct:.1f}%){tag}"
        lines.append(f"  {bp.target:<18} {b_ms:<14} {a_ms:<14} {change:<20}")

    lines.append("")
    lines.append(f"  Result: {report.summary}")

    return "\n".join(lines)
