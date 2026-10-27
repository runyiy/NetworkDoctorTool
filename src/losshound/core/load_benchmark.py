"""Network performance benchmarking UNDER LOAD.

This is where the real optimization impact shows up.  Tests:

1. **Latency under load** — Ping while simultaneously downloading.
   Congestion-control and traffic-shaping changes are most visible here.

2. **Bufferbloat score** — How much latency increases under load vs idle.
   This is the #1 metric for gaming/VoIP quality.

3. **Download throughput** — Raw download speed measurement.

4. **Small UDP responsiveness** — DNS-query response time and loss.
"""

from __future__ import annotations

import json
import logging
import math
import os
import socket
import statistics
import struct
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DATA_DIR = Path(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
) / "Losshound"
_LOAD_BENCH_FILE = _DATA_DIR / "load_benchmark_history.json"

# Public files to download for load generation. Large files sustain one
# connection for the whole load window (small files cause reconnect churn
# that throttles throughput). Cloudflare appears twice on purpose: each list
# entry gets its own download thread, and speed.cloudflare.com is built for
# parallel speed-test streams. (tele2/hetzner mirrors died — verified 2026-07.)
# Note: speed.cloudflare.com rejects bytes >= 100000000 with a 403.
_DOWNLOAD_URLS = [
    "https://speed.cloudflare.com/__down?bytes=90000000",
    "https://speed.cloudflare.com/__down?bytes=90000000",
    "http://proof.ovh.net/files/100Mb.dat",
    "http://ipv4.download.thinkbroadband.com/50MB.zip",
]

_PING_TARGET = "1.1.1.1"
_PING_COUNT_IDLE = 20
_PING_COUNT_LOADED = 30


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class IdleLatency:
    """Latency measurements with no network load."""

    avg_ms: float
    min_ms: float
    max_ms: float
    jitter_ms: float
    loss_pct: float
    samples: int


@dataclass
class LoadedLatency:
    """Latency measurements while network is under load."""

    avg_ms: float
    min_ms: float
    max_ms: float
    jitter_ms: float
    loss_pct: float
    samples: int


@dataclass
class BufferbloatResult:
    """Bufferbloat assessment."""

    idle_latency_ms: float
    loaded_latency_ms: float
    latency_increase_ms: float
    latency_increase_pct: float
    grade: str  # A, B, C, D, F, or N/A when latency is unavailable


@dataclass
class ThroughputResult:
    """Download throughput measurement."""

    bytes_downloaded: int
    duration_seconds: float
    speed_mbps: float
    url: str


@dataclass
class SmallPacketResult:
    """Small UDP DNS-query responsiveness and loss."""

    avg_rtt_ms: float
    min_rtt_ms: float
    max_rtt_ms: float
    packets_sent: int
    packets_received: int
    loss_pct: float


@dataclass
class LoadBenchmarkSnapshot:
    """Complete load benchmark snapshot."""

    timestamp: str
    label: str
    idle: IdleLatency
    loaded: LoadedLatency
    bufferbloat: BufferbloatResult
    throughput: ThroughputResult
    small_packet: SmallPacketResult

    # Quick summary numbers
    bufferbloat_grade: str = ""
    speed_mbps: float = 0.0
    latency_increase_pct: float = 0.0


@dataclass
class LoadBenchmarkDelta:
    """Comparison between two load benchmark snapshots."""

    idle_latency_delta_ms: Optional[float] = None
    loaded_latency_delta_ms: Optional[float] = None
    loaded_latency_pct_change: Optional[float] = None
    bufferbloat_increase_delta: Optional[float] = None  # pp change
    speed_delta_mbps: Optional[float] = None
    speed_pct_change: Optional[float] = None
    small_packet_delta_ms: Optional[float] = None
    small_packet_pct_change: Optional[float] = None
    before_grade: str = ""
    after_grade: str = ""


@dataclass
class LoadBenchmarkReport:
    """Full before/after load benchmark comparison."""

    before: LoadBenchmarkSnapshot
    after: LoadBenchmarkSnapshot
    delta: LoadBenchmarkDelta
    summary: str


# ---------------------------------------------------------------------------
# Ping helpers (raw ICMP for concurrent use)
# ---------------------------------------------------------------------------

def _ping_continuous(
    target: str,
    duration_seconds: float,
    results: list[float],
    stop_event: threading.Event,
    interval: float = 0.5,
):
    """Ping a target continuously, appending RTT values to *results*.

    Uses subprocess ping one-at-a-time for reliability on Windows.
    """
    import subprocess
    from losshound.core.validation import validate_target
    from losshound.core.windows_commands import windows_command

    if not validate_target(target):
        return

    deadline = time.monotonic() + duration_seconds
    _CREATE_NO_WINDOW = 0x08000000

    while time.monotonic() < deadline and not stop_event.is_set():
        try:
            proc = subprocess.run(
                windows_command(["ping", "-n", "1", "-w", "2000", target]),
                capture_output=True, text=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            import re
            match = re.search(r"[=<]\s*(\d+)\s*ms", proc.stdout, re.IGNORECASE)
            if match:
                results.append(float(match.group(1)))
            else:
                results.append(-1)  # timeout/loss marker
        except Exception:
            results.append(-1)

        # Brief sleep between pings
        remaining = deadline - time.monotonic()
        if remaining > interval:
            stop_event.wait(interval)


def _download_file(url: str, result_holder: dict, stop_event: threading.Event):
    """Download a file, storing bytes read and duration in result_holder."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Losshound/1.0 NetworkBenchmark",
        })
        start = time.perf_counter()
        total_bytes = 0

        # Short socket timeout so a download thread blocked in read() exits
        # quickly once the benchmark ends, instead of eating bandwidth for
        # seconds after the stop event is set.
        with urllib.request.urlopen(req, timeout=5) as resp:
            while not stop_event.is_set():
                chunk = resp.read(8192)
                if not chunk:
                    break
                total_bytes += len(chunk)

        duration = time.perf_counter() - start
        result_holder["bytes"] = total_bytes
        result_holder["duration"] = duration
        result_holder["url"] = url
        result_holder["success"] = True
    except Exception as exc:
        logger.warning("Download from %s failed: %s", url, exc)
        result_holder["success"] = False
        result_holder["error"] = str(exc)


def _generate_load(urls: list[str], duration: float, stop_event: threading.Event, result_holder: dict):
    """Download from multiple URLs simultaneously to generate network load."""
    start = time.perf_counter()
    deadline = start + duration
    results: list[dict] = []
    results_lock = threading.Lock()

    def download_loop(url: str) -> None:
        total_bytes = 0
        best_speed = 0.0

        while not stop_event.is_set() and time.perf_counter() < deadline:
            dl_result: dict = {}
            _download_file(url, dl_result, stop_event)
            if not dl_result.get("success"):
                break

            bytes_read = dl_result.get("bytes", 0)
            total_bytes += bytes_read
            dl_dur = max(dl_result.get("duration", 0.001), 0.001)
            best_speed = max(best_speed, (bytes_read * 8) / (dl_dur * 1_000_000))

        with results_lock:
            results.append({
                "bytes": total_bytes,
                "best_speed": best_speed,
                "url": url,
            })

    threads = [
        threading.Thread(
            target=download_loop,
            args=(url,),
            name=f"LosshoundLoadDownload-{i + 1}",
            daemon=True,
        )
        for i, url in enumerate(urls)
    ]

    for thread in threads:
        thread.start()

    while time.perf_counter() < deadline and not stop_event.is_set():
        if all(not thread.is_alive() for thread in threads):
            break
        stop_event.wait(0.2)

    stop_event.set()
    for thread in threads:
        thread.join(timeout=2)

    total_duration = time.perf_counter() - start
    with results_lock:
        completed = list(results)
    total_bytes = sum(result.get("bytes", 0) for result in completed)
    best = max(completed, key=lambda result: result.get("best_speed", 0.0), default={})
    result_holder["total_bytes"] = total_bytes
    result_holder["total_duration"] = total_duration
    result_holder["best_speed"] = best.get("best_speed", 0.0)
    result_holder["best_url"] = best.get("url", "")


# ---------------------------------------------------------------------------
# Small packet test
# ---------------------------------------------------------------------------

def _small_packet_test(
    target: str = "1.1.1.1",
    port: int = 53,
    count: int = 50,
) -> SmallPacketResult:
    """Send valid UDP DNS queries and measure response time and loss.

    This is a general small-datagram responsiveness check; TCP stream
    coalescing behavior is outside its scope.
    """
    from losshound.core.dns_bench import build_dns_query
    import random

    rtts: list[float] = []
    sent = 0
    received = 0

    for i in range(count):
        sent += 1
        query_id = random.randint(0, 0xFFFF)
        packet = build_dns_query("example.com", query_id)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(2.0)
            start = time.perf_counter()
            sock.sendto(packet, (target, port))
            data, _ = sock.recvfrom(512)
            elapsed = (time.perf_counter() - start) * 1000.0
            received += 1
            rtts.append(elapsed)
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

        # Minimal delay between packets
        time.sleep(0.02)

    if not rtts:
        return SmallPacketResult(
            avg_rtt_ms=float("inf"),
            min_rtt_ms=float("inf"),
            max_rtt_ms=float("inf"),
            packets_sent=sent,
            packets_received=0,
            loss_pct=100.0,
        )

    return SmallPacketResult(
        avg_rtt_ms=statistics.mean(rtts),
        min_rtt_ms=min(rtts),
        max_rtt_ms=max(rtts),
        packets_sent=sent,
        packets_received=received,
        loss_pct=((sent - received) / sent) * 100.0 if sent else 0.0,
    )


# ---------------------------------------------------------------------------
# Bufferbloat grading
# ---------------------------------------------------------------------------

def _grade_bufferbloat(increase_pct: float) -> str:
    """Grade bufferbloat on an A–F scale.

    Based on industry standards (DSLReports, Waveform):
    - A: < 5% increase (excellent)
    - B: 5–30% (good)
    - C: 30–60% (fair)
    - D: 60–200% (poor)
    - F: > 200% (terrible)
    """
    if increase_pct < 5:
        return "A"
    elif increase_pct < 30:
        return "B"
    elif increase_pct < 60:
        return "C"
    elif increase_pct < 200:
        return "D"
    else:
        return "F"


def _summarize_latency(rtts: list[float], result_type):
    """Build an idle/loaded latency result without inventing RTT samples."""
    valid = [rtt for rtt in rtts if rtt >= 0 and math.isfinite(rtt)]
    attempted = len(rtts)
    loss_pct = (
        ((attempted - len(valid)) / attempted) * 100.0
        if attempted
        else 100.0
    )

    if not valid:
        return result_type(
            avg_ms=float("inf"),
            min_ms=float("inf"),
            max_ms=float("inf"),
            jitter_ms=float("inf"),
            loss_pct=100.0,
            samples=0,
        )

    return result_type(
        avg_ms=statistics.mean(valid),
        min_ms=min(valid),
        max_ms=max(valid),
        jitter_ms=statistics.mean(
            [abs(valid[i + 1] - valid[i]) for i in range(len(valid) - 1)]
        ) if len(valid) >= 2 else 0.0,
        loss_pct=loss_pct,
        samples=len(valid),
    )


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------

def run_load_benchmark(
    label: str = "snapshot",
    progress_callback=None,
) -> LoadBenchmarkSnapshot:
    """Run a full load benchmark.

    1. Measure idle latency (ping with no load)
    2. Start downloads to saturate the connection
    3. Measure latency WHILE downloading (loaded latency)
    4. Compute bufferbloat score
    5. Run small packet responsiveness test
    """

    def _progress(msg: str):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    # ── Step 1: Idle latency ──────────────────────────────────
    _progress("Step 1/4: Measuring idle latency...")

    idle_rtts: list[float] = []
    stop = threading.Event()
    _ping_continuous(_PING_TARGET, duration_seconds=12, results=idle_rtts,
                     stop_event=stop, interval=0.5)

    idle = _summarize_latency(idle_rtts, IdleLatency)
    if idle.samples:
        _progress(f"  Idle latency: {idle.avg_ms:.1f}ms avg, {idle.jitter_ms:.1f}ms jitter")
    else:
        _progress("  Idle latency unavailable (100% packet loss)")

    # ── Step 2: Latency under load ────────────────────────────
    _progress("Step 2/4: Measuring latency under load (downloading)...")

    loaded_rtts: list[float] = []
    dl_result: dict = {}
    stop_load = threading.Event()
    stop_ping = threading.Event()

    # Run download and pings concurrently. Daemon so a hard shutdown
    # of the GUI doesn't block on the interpreter waiting for them.
    load_thread = threading.Thread(
        target=_generate_load,
        args=(_DOWNLOAD_URLS, 20, stop_load, dl_result),
        daemon=True,
    )
    ping_thread = threading.Thread(
        target=_ping_continuous,
        args=(_PING_TARGET, 20, loaded_rtts, stop_ping, 0.5),
        daemon=True,
    )

    load_thread.start()
    # Small delay so download has time to start saturating
    time.sleep(2)
    ping_thread.start()

    load_thread.join(timeout=30)
    stop_load.set()
    stop_ping.set()
    ping_thread.join(timeout=5)
    load_thread.join(timeout=2)
    if load_thread.is_alive():
        logger.warning("Load generator did not stop within cleanup window")

    loaded = _summarize_latency(loaded_rtts, LoadedLatency)
    if loaded.samples:
        _progress(f"  Loaded latency: {loaded.avg_ms:.1f}ms avg, {loaded.jitter_ms:.1f}ms jitter")
    else:
        _progress("  Loaded latency unavailable (100% packet loss)")

    # ── Step 3: Bufferbloat calculation ───────────────────────
    latency_available = idle.samples > 0 and loaded.samples > 0
    if latency_available:
        latency_increase_ms = loaded.avg_ms - idle.avg_ms
        latency_increase_pct = (
            latency_increase_ms / idle.avg_ms * 100.0
            if idle.avg_ms > 0
            else float("inf")
        )
        grade = _grade_bufferbloat(latency_increase_pct)
    else:
        latency_increase_ms = float("inf")
        latency_increase_pct = float("inf")
        grade = "N/A"

    bufferbloat = BufferbloatResult(
        idle_latency_ms=idle.avg_ms,
        loaded_latency_ms=loaded.avg_ms,
        latency_increase_ms=latency_increase_ms,
        latency_increase_pct=latency_increase_pct,
        grade=grade,
    )
    if latency_available:
        _progress(f"  Bufferbloat grade: {grade} ({latency_increase_pct:.0f}% increase)")
    else:
        _progress("  Bufferbloat grade unavailable (latency probes had no replies)")

    # ── Throughput ────────────────────────────────────────────
    total_bytes = dl_result.get("total_bytes", 0)
    total_dur = dl_result.get("total_duration", 1)
    best_speed = dl_result.get("best_speed", 0)
    best_url = dl_result.get("best_url", "")
    speed_mbps = (total_bytes * 8) / (total_dur * 1_000_000) if total_dur > 0 else 0

    throughput = ThroughputResult(
        bytes_downloaded=total_bytes,
        duration_seconds=total_dur,
        speed_mbps=speed_mbps,
        url=best_url,
    )
    _progress(f"  Download speed: {speed_mbps:.2f} Mbps")

    # ── Step 4: Small packet responsiveness ───────────────────
    _progress("Step 3/4: Testing small packet responsiveness...")

    small = _small_packet_test(count=50)
    if small.packets_received:
        _progress(f"  Small packet RTT: {small.avg_rtt_ms:.1f}ms avg")
    else:
        _progress("  Small packet RTT unavailable (100% packet loss)")

    _progress("Step 4/4: Computing results...")

    snapshot = LoadBenchmarkSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        label=label,
        idle=idle,
        loaded=loaded,
        bufferbloat=bufferbloat,
        throughput=throughput,
        small_packet=small,
        bufferbloat_grade=grade,
        speed_mbps=speed_mbps,
        latency_increase_pct=latency_increase_pct,
    )

    _progress("Load benchmark complete!")
    return snapshot


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_load_snapshots(
    before: LoadBenchmarkSnapshot,
    after: LoadBenchmarkSnapshot,
) -> LoadBenchmarkReport:
    """Compare two load benchmark snapshots."""

    def _delta(b: float | None, a: float | None):
        if (
            b is None or a is None or b == 0
            or not math.isfinite(b) or not math.isfinite(a)
        ):
            return None, None
        diff = a - b
        pct = (diff / b * 100.0)
        return diff, pct

    idle_d, _ = _delta(before.idle.avg_ms, after.idle.avg_ms)
    loaded_d, loaded_p = _delta(before.loaded.avg_ms, after.loaded.avg_ms)
    speed_d, speed_p = _delta(before.speed_mbps, after.speed_mbps)
    small_d, small_p = _delta(before.small_packet.avg_rtt_ms, after.small_packet.avg_rtt_ms)

    bb_delta = None
    if (
        before.latency_increase_pct is not None
        and after.latency_increase_pct is not None
        and math.isfinite(before.latency_increase_pct)
        and math.isfinite(after.latency_increase_pct)
    ):
        bb_delta = after.latency_increase_pct - before.latency_increase_pct

    delta = LoadBenchmarkDelta(
        idle_latency_delta_ms=idle_d,
        loaded_latency_delta_ms=loaded_d,
        loaded_latency_pct_change=loaded_p,
        bufferbloat_increase_delta=bb_delta,
        speed_delta_mbps=speed_d,
        speed_pct_change=speed_p,
        small_packet_delta_ms=small_d,
        small_packet_pct_change=small_p,
        before_grade=before.bufferbloat_grade,
        after_grade=after.bufferbloat_grade,
    )

    # Build summary
    improvements: list[str] = []
    regressions: list[str] = []

    if loaded_d is not None and loaded_p is not None:
        if loaded_p < -5:
            improvements.append(f"Loaded latency {abs(loaded_p):.0f}% better")
        elif loaded_p > 5:
            regressions.append(f"Loaded latency {loaded_p:.0f}% worse")

    if bb_delta is not None:
        if bb_delta < -5:
            improvements.append(f"Bufferbloat {abs(bb_delta):.0f}pp less")
        elif bb_delta > 5:
            regressions.append(f"Bufferbloat {bb_delta:.0f}pp more")

    if speed_p is not None:
        if speed_p > 5:
            improvements.append(f"Speed {speed_p:.0f}% faster")
        elif speed_p < -5:
            regressions.append(f"Speed {abs(speed_p):.0f}% slower")

    if small_p is not None:
        if small_p < -5:
            improvements.append(f"Small packet RTT {abs(small_p):.0f}% faster")
        elif small_p > 5:
            regressions.append(f"Small packet RTT {small_p:.0f}% slower")

    grade_change = ""
    if before.bufferbloat_grade != after.bufferbloat_grade:
        grade_change = f"Bufferbloat grade: {before.bufferbloat_grade} -> {after.bufferbloat_grade}. "

    parts = [grade_change] if grade_change else []
    if improvements:
        parts.append("Improved: " + ", ".join(improvements) + ".")
    if regressions:
        parts.append("Regressed: " + ", ".join(regressions) + ".")
    if not improvements and not regressions:
        parts.append("No significant changes measured.")

    return LoadBenchmarkReport(
        before=before,
        after=after,
        delta=delta,
        summary=" ".join(parts),
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _json_safe(value):
    """Convert non-finite measurements to JSON ``null`` recursively."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _restore_unavailable_measurements(data: dict) -> None:
    """Map persisted ``null`` measurements back to the in-memory sentinel."""
    if data.get("latency_increase_pct") is None:
        data["latency_increase_pct"] = float("inf")
    fields_by_section = {
        "idle": ("avg_ms", "min_ms", "max_ms", "jitter_ms"),
        "loaded": ("avg_ms", "min_ms", "max_ms", "jitter_ms"),
        "bufferbloat": (
            "idle_latency_ms", "loaded_latency_ms",
            "latency_increase_ms", "latency_increase_pct",
        ),
        "small_packet": ("avg_rtt_ms", "min_rtt_ms", "max_rtt_ms"),
    }
    for section, fields in fields_by_section.items():
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for field in fields:
            if values.get(field) is None:
                values[field] = float("inf")


def save_load_snapshot(snapshot: LoadBenchmarkSnapshot) -> None:
    """Append a snapshot to the load benchmark history."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    history: list[dict] = []
    if _LOAD_BENCH_FILE.is_file():
        try:
            with open(_LOAD_BENCH_FILE, "r", encoding="utf-8") as fh:
                history = json.load(fh)
        except Exception:
            history = []

    history.append(_json_safe(asdict(snapshot)))
    history = history[-20:]

    temp_path = _LOAD_BENCH_FILE.with_suffix(".json.tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, indent=2, allow_nan=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, _LOAD_BENCH_FILE)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            logger.debug("Could not remove temporary benchmark history %s", temp_path)


def load_load_snapshots() -> list[LoadBenchmarkSnapshot]:
    """Load all saved load benchmark snapshots."""
    if not _LOAD_BENCH_FILE.is_file():
        return []
    try:
        with open(_LOAD_BENCH_FILE, "r", encoding="utf-8") as fh:
            history = json.load(fh)
        snapshots = []
        for data in history:
            _restore_unavailable_measurements(data)
            data["idle"] = IdleLatency(**data["idle"])
            data["loaded"] = LoadedLatency(**data["loaded"])
            data["bufferbloat"] = BufferbloatResult(**data["bufferbloat"])
            data["throughput"] = ThroughputResult(**data["throughput"])
            data["small_packet"] = SmallPacketResult(**data["small_packet"])
            snapshots.append(LoadBenchmarkSnapshot(**data))
        return snapshots
    except Exception as exc:
        logger.warning("Failed to load benchmark history: %s", exc)
        return []


def get_latest_load_snapshot(label: str | None = None) -> LoadBenchmarkSnapshot | None:
    """Get the most recent load snapshot, optionally by label."""
    snapshots = load_load_snapshots()
    if label:
        snapshots = [s for s in snapshots if s.label == label]
    return snapshots[-1] if snapshots else None


# ---------------------------------------------------------------------------
# CLI formatting
# ---------------------------------------------------------------------------

def format_load_snapshot(snap: LoadBenchmarkSnapshot) -> str:
    """Format a load benchmark for terminal display."""
    def _latency_line(result) -> str:
        if result.samples == 0 or not math.isfinite(result.avg_ms):
            return (
                f"    Unavailable  Loss: {result.loss_pct:.1f}%  "
                f"({result.samples} samples)"
            )
        return (
            f"    Avg: {result.avg_ms:.1f}ms  Min: {result.min_ms:.1f}ms  "
            f"Max: {result.max_ms:.1f}ms  Jitter: {result.jitter_ms:.1f}ms  "
            f"Loss: {result.loss_pct:.1f}%  ({result.samples} samples)"
        )

    lines: list[str] = []
    lines.append(f"Load Benchmark: {snap.label} ({snap.timestamp[:19]})")
    lines.append("=" * 65)

    lines.append("")
    lines.append("  IDLE LATENCY (no load)")
    lines.append(_latency_line(snap.idle))

    lines.append("")
    lines.append("  LOADED LATENCY (while downloading)")
    lines.append(_latency_line(snap.loaded))

    lines.append("")
    bb = snap.bufferbloat
    lines.append(f"  BUFFERBLOAT — Grade: {bb.grade}")
    if math.isfinite(bb.latency_increase_ms) and math.isfinite(bb.latency_increase_pct):
        lines.append(f"    Latency increase under load: +{bb.latency_increase_ms:.1f}ms "
                     f"(+{bb.latency_increase_pct:.0f}%)")
    else:
        lines.append("    Latency increase under load: Unavailable")
    lines.append(f"    {_bufferbloat_explanation(bb.grade)}")

    lines.append("")
    lines.append(f"  THROUGHPUT")
    lines.append(f"    Download speed: {snap.throughput.speed_mbps:.2f} Mbps "
                 f"({snap.throughput.bytes_downloaded / 1024 / 1024:.1f} MB in "
                 f"{snap.throughput.duration_seconds:.1f}s)")

    lines.append("")
    sp = snap.small_packet
    lines.append("  SMALL UDP DNS RESPONSIVENESS")
    if sp.packets_received and math.isfinite(sp.avg_rtt_ms):
        lines.append(f"    Avg RTT: {sp.avg_rtt_ms:.1f}ms  Min: {sp.min_rtt_ms:.1f}ms  "
                     f"Max: {sp.max_rtt_ms:.1f}ms  Loss: {sp.loss_pct:.1f}%")
    else:
        lines.append(f"    Unavailable  Loss: {sp.loss_pct:.1f}%")

    return "\n".join(lines)


def format_load_comparison(report: LoadBenchmarkReport) -> str:
    """Format a before/after load benchmark comparison."""
    b = report.before
    a = report.after
    d = report.delta

    lines: list[str] = []
    lines.append("LOAD BENCHMARK: BEFORE vs AFTER")
    lines.append("=" * 65)

    def _fmt(val, suffix="ms"):
        if val is None or val == float("inf"):
            return "N/A"
        return f"{val:.1f}{suffix}"

    def _change(diff, pct, lower_better=True):
        if diff is None:
            return "", "  "
        sign = "+" if diff > 0 else ""
        tag = ""
        if pct is not None and abs(pct) >= 5:
            tag = " BETTER" if (diff < 0) == lower_better else " WORSE"
        return f"{sign}{diff:.1f} ({sign}{pct:.0f}%){tag}" if pct else f"{sign}{diff:.1f}"

    def _grade_change(before: str, after: str) -> str:
        rank = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
        if before not in rank or after not in rank:
            return "UNAVAILABLE"
        if rank[after] < rank[before]:
            return "IMPROVED!"
        if rank[after] == rank[before]:
            return "SAME"
        return "WORSE"

    lines.append("")
    lines.append(f"  {'Metric':<28} {'Before':<14} {'After':<14} {'Change'}")
    lines.append(f"  {'-'*28} {'-'*14} {'-'*14} {'-'*25}")

    lines.append(f"  {'Idle Latency':<28} {_fmt(b.idle.avg_ms):<14} {_fmt(a.idle.avg_ms):<14} "
                 f"{_change(d.idle_latency_delta_ms, None)}")
    lines.append(f"  {'Loaded Latency':<28} {_fmt(b.loaded.avg_ms):<14} {_fmt(a.loaded.avg_ms):<14} "
                 f"{_change(d.loaded_latency_delta_ms, d.loaded_latency_pct_change)}")
    lines.append(f"  {'Bufferbloat Grade':<28} {b.bufferbloat_grade:<14} {a.bufferbloat_grade:<14} "
                 f"{_grade_change(b.bufferbloat_grade, a.bufferbloat_grade)}")
    lines.append(f"  {'Latency Increase Under Load':<28} {_fmt(b.latency_increase_pct, '%'):<14} {_fmt(a.latency_increase_pct, '%'):<14} "
                 f"{_change(d.bufferbloat_increase_delta, None)}")
    lines.append(f"  {'Download Speed':<28} {_fmt(b.speed_mbps, ' Mbps'):<14} {_fmt(a.speed_mbps, ' Mbps'):<14} "
                 f"{_change(d.speed_delta_mbps, d.speed_pct_change, lower_better=False)}")
    lines.append(f"  {'Small Packet RTT':<28} {_fmt(b.small_packet.avg_rtt_ms):<14} {_fmt(a.small_packet.avg_rtt_ms):<14} "
                 f"{_change(d.small_packet_delta_ms, d.small_packet_pct_change)}")

    lines.append("")
    lines.append(f"  {'Loaded Jitter':<28} {_fmt(b.loaded.jitter_ms):<14} {_fmt(a.loaded.jitter_ms):<14}")
    lines.append(f"  {'Loaded Packet Loss':<28} {_fmt(b.loaded.loss_pct, '%'):<14} {_fmt(a.loaded.loss_pct, '%'):<14}")

    lines.append("")
    lines.append(f"  Result: {report.summary}")

    return "\n".join(lines)


def _bufferbloat_explanation(grade: str) -> str:
    """Human-readable explanation of a bufferbloat grade."""
    explanations = {
        "A": "Excellent! Your latency barely increases under load. Great for gaming.",
        "B": "Good. Slight latency increase under load but still very usable.",
        "C": "Fair. Noticeable lag spikes when downloading. Room for improvement.",
        "D": "Poor. Significant lag when network is busy. Gaming/VoIP will suffer.",
        "F": "Terrible. Your connection becomes nearly unusable under load.",
        "N/A": "Unavailable because one or both latency phases received no replies.",
    }
    return explanations.get(grade, "")
