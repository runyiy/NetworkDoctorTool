import json
import math
import threading
import time

from losshound.core import load_benchmark


def _unavailable_snapshot():
    inf = float("inf")
    return load_benchmark.LoadBenchmarkSnapshot(
        timestamp="2026-07-09T12:00:00+00:00",
        label="all-loss",
        idle=load_benchmark.IdleLatency(inf, inf, inf, inf, 100.0, 0),
        loaded=load_benchmark.LoadedLatency(inf, inf, inf, inf, 100.0, 0),
        bufferbloat=load_benchmark.BufferbloatResult(inf, inf, inf, inf, "N/A"),
        throughput=load_benchmark.ThroughputResult(0, 0.0, 0.0, ""),
        small_packet=load_benchmark.SmallPacketResult(inf, inf, inf, 1, 0, 100.0),
        bufferbloat_grade="N/A",
        speed_mbps=0.0,
        latency_increase_pct=inf,
    )


def test_all_loss_is_unavailable_instead_of_receiving_an_a(monkeypatch):
    def fake_ping(target, duration_seconds, results, stop_event, interval=0.5):
        results.extend([-1.0, -1.0, -1.0, -1.0])

    def fake_load(urls, duration, stop_event, result_holder):
        result_holder.update(
            total_bytes=0,
            total_duration=0.01,
            best_speed=0.0,
            best_url="",
        )

    unavailable_small_packet = load_benchmark.SmallPacketResult(
        avg_rtt_ms=float("inf"),
        min_rtt_ms=float("inf"),
        max_rtt_ms=float("inf"),
        packets_sent=1,
        packets_received=0,
        loss_pct=100.0,
    )
    monkeypatch.setattr(load_benchmark, "_ping_continuous", fake_ping)
    monkeypatch.setattr(load_benchmark, "_generate_load", fake_load)
    monkeypatch.setattr(
        load_benchmark,
        "_small_packet_test",
        lambda count: unavailable_small_packet,
    )
    monkeypatch.setattr(load_benchmark.time, "sleep", lambda _seconds: None)

    snapshot = load_benchmark.run_load_benchmark(label="all-loss")

    assert snapshot.idle.loss_pct == 100.0
    assert snapshot.loaded.loss_pct == 100.0
    assert snapshot.idle.samples == 0
    assert snapshot.loaded.samples == 0
    assert math.isinf(snapshot.idle.avg_ms)
    assert math.isinf(snapshot.loaded.avg_ms)
    assert snapshot.bufferbloat.grade == "N/A"
    assert snapshot.bufferbloat_grade == "N/A"

    rendered = load_benchmark.format_load_snapshot(snapshot)
    assert "Unavailable" in rendered
    assert "100.0%" in rendered
    assert "infms" not in rendered


def test_latency_summary_counts_only_real_replies():
    summary = load_benchmark._summarize_latency(
        [12.0, -1.0, 0.0, -1.0],
        load_benchmark.IdleLatency,
    )

    assert summary.samples == 2
    assert summary.loss_pct == 50.0
    assert summary.min_ms == 0.0
    assert summary.max_ms == 12.0


def test_unavailable_measurements_persist_as_strict_json(tmp_path, monkeypatch):
    history_path = tmp_path / "load_benchmark_history.json"
    monkeypatch.setattr(load_benchmark, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(load_benchmark, "_LOAD_BENCH_FILE", history_path)

    load_benchmark.save_load_snapshot(_unavailable_snapshot())

    raw = history_path.read_text(encoding="utf-8")
    assert "Infinity" not in raw
    assert json.loads(raw)[0]["idle"]["avg_ms"] is None
    restored = load_benchmark.load_load_snapshots()[0]
    assert math.isinf(restored.idle.avg_ms)
    assert restored.idle.samples == 0
    assert restored.bufferbloat.grade == "N/A"


def test_generate_load_downloads_concurrently(monkeypatch):
    """All URLs must download in parallel — that's the point of a load test."""
    lock = threading.Lock()
    active: set[str] = set()
    peak_concurrency = 0

    def fake_download(url, result_holder, stop_event):
        nonlocal peak_concurrency
        with lock:
            active.add(url)
            peak_concurrency = max(peak_concurrency, len(active))
        time.sleep(0.15)
        with lock:
            active.discard(url)
        result_holder.update(bytes=1000, duration=0.15, url=url, success=True)

    monkeypatch.setattr(load_benchmark, "_download_file", fake_download)

    stop = threading.Event()
    holder: dict = {}
    load_benchmark._generate_load(["u1", "u2", "u3"], 0.5, stop, holder)

    assert peak_concurrency == 3
    assert holder["total_bytes"] >= 3000
    assert holder["best_speed"] > 0
    assert holder["best_url"] in {"u1", "u2", "u3"}
    # The generator signals its workers to stop once the deadline passes.
    assert stop.is_set()


def test_generate_load_respects_deadline(monkeypatch):
    def fake_download(url, result_holder, stop_event):
        # Simulate a download that polls the stop event like the real one.
        end = time.perf_counter() + 10
        while time.perf_counter() < end and not stop_event.is_set():
            time.sleep(0.02)
        result_holder.update(bytes=10, duration=0.1, url=url, success=True)

    monkeypatch.setattr(load_benchmark, "_download_file", fake_download)

    stop = threading.Event()
    holder: dict = {}
    start = time.perf_counter()
    load_benchmark._generate_load(["u1", "u2"], 0.4, stop, holder)
    elapsed = time.perf_counter() - start

    # Deadline 0.4s + join grace; nowhere near the 10s the download wanted.
    assert elapsed < 3.0
    assert holder["total_bytes"] == 20


def test_generate_load_handles_failing_url(monkeypatch):
    def fake_download(url, result_holder, stop_event):
        if url == "bad":
            result_holder.update(success=False, error="boom")
        else:
            result_holder.update(bytes=500, duration=0.1, url=url, success=True)
        time.sleep(0.05)

    monkeypatch.setattr(load_benchmark, "_download_file", fake_download)

    stop = threading.Event()
    holder: dict = {}
    load_benchmark._generate_load(["bad", "good"], 0.3, stop, holder)

    assert holder["total_bytes"] >= 500
    assert holder["best_url"] == "good"
