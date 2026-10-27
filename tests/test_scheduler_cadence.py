import threading
import time
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import QCoreApplication, QThread, QTimer

from losshound.core.config import AppConfig
from losshound.core.models import Diagnosis, DiagnosisCategory, PingResult
from losshound.core.scheduler import (
    FAST_INTERVAL_SECONDS,
    RECOVERY_CYCLES,
    MonitorWorker,
)


@pytest.fixture(scope="module")
def qapp():
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])
    return app


def _ping(loss: float = 0.0, timed_out: bool = False) -> PingResult:
    return PingResult(
        target="1.1.1.1",
        timestamp=datetime.now(),
        packets_sent=4,
        packets_received=0 if timed_out else 4,
        loss_percent=loss,
        timed_out=timed_out,
    )


def _worker(qapp) -> MonitorWorker:
    config = AppConfig()
    worker = MonitorWorker(config, MagicMock())
    worker._ping_timer = QTimer()
    worker._ping_timer.setInterval(config.ping_interval_seconds * 1000)
    return worker


def test_loss_densifies_sampling(qapp):
    worker = _worker(qapp)
    emitted: list[int] = []
    worker.cadence_changed.connect(emitted.append)

    worker._update_cadence(_ping(loss=25.0), [_ping()])

    assert worker._fast_mode
    assert worker._ping_timer.interval() == FAST_INTERVAL_SECONDS * 1000
    assert emitted == [FAST_INTERVAL_SECONDS]


def test_public_timeout_densifies_sampling(qapp):
    worker = _worker(qapp)
    worker._update_cadence(_ping(), [_ping(), _ping(timed_out=True, loss=100.0)])
    assert worker._fast_mode


def test_recovery_after_clean_streak(qapp):
    worker = _worker(qapp)
    emitted: list[int] = []
    worker.cadence_changed.connect(emitted.append)

    worker._update_cadence(_ping(loss=50.0), [])
    assert worker._fast_mode

    # One clean cycle is not enough; a relapse resets the streak.
    worker._update_cadence(_ping(), [_ping()])
    worker._update_cadence(_ping(loss=50.0), [])
    assert worker._fast_mode
    for _ in range(RECOVERY_CYCLES - 1):
        worker._update_cadence(_ping(), [_ping()])
    assert worker._fast_mode

    worker._update_cadence(_ping(), [_ping()])
    assert not worker._fast_mode
    assert worker._ping_timer.interval() == worker._config.ping_interval_seconds * 1000
    assert emitted[-1] == worker._config.ping_interval_seconds


def test_healthy_cycles_never_touch_cadence(qapp):
    worker = _worker(qapp)
    emitted: list[int] = []
    worker.cadence_changed.connect(emitted.append)

    for _ in range(5):
        worker._update_cadence(_ping(), [_ping(), _ping()])

    assert not worker._fast_mode
    assert emitted == []


def test_fast_interval_never_exceeds_configured(qapp):
    worker = _worker(qapp)
    worker._config.ping_interval_seconds = 3  # user already faster than fast mode
    worker._update_cadence(_ping(loss=100.0, timed_out=True), [])
    assert worker._ping_timer.interval() == 3 * 1000


def test_fast_cycle_reuses_cached_gateway_instead_of_rediscovering(
    qapp, monkeypatch
):
    import losshound.core.scheduler as scheduler

    worker = _worker(qapp)
    worker._fast_mode = True
    worker._gateway_ip = "192.168.1.1"
    worker._last_dns_check_monotonic = time.monotonic()
    worker._config.public_ping_targets = ["1.1.1.1"]
    worker._run_ping_probes = MagicMock(return_value=[_ping(), _ping()])
    detect_gateway = MagicMock(side_effect=AssertionError("must use cached gateway"))
    monkeypatch.setattr(scheduler, "detect_gateway", detect_gateway)

    worker._run_ping_cycle()

    detect_gateway.assert_not_called()
    worker._run_ping_probes.assert_called_once()


def test_ping_targets_run_concurrently_in_cancellable_qthreads(
    qapp, monkeypatch
):
    import losshound.core.scheduler as scheduler

    barrier = threading.Barrier(3)

    def fake_ping(target, count, timeout_ms):
        barrier.wait(timeout=1.0)
        return PingResult(
            target=target,
            timestamp=datetime.now(),
            packets_sent=count,
            packets_received=count,
            loss_percent=0.0,
        )

    monkeypatch.setattr(scheduler, "ping", fake_ping)
    worker = _worker(qapp)
    results = worker._run_ping_probes(
        ["192.168.1.1", "1.1.1.1", "8.8.8.8"],
        count=1,
        timeout_ms=1000,
        deadline=time.monotonic() + 2.0,
    )

    assert [result.target for result in results] == [
        "192.168.1.1",
        "1.1.1.1",
        "8.8.8.8",
    ]


def test_probe_deadline_cancels_stragglers_and_records_timeout(qapp, monkeypatch):
    import losshound.core.scheduler as scheduler

    def fake_ping(target, count, timeout_ms):
        while not QThread.currentThread().isInterruptionRequested():
            time.sleep(0.005)
        raise InterruptedError

    monkeypatch.setattr(scheduler, "ping", fake_ping)
    worker = _worker(qapp)
    started = time.monotonic()
    results = worker._run_ping_probes(
        ["1.1.1.1", "8.8.8.8"],
        count=2,
        timeout_ms=2000,
        deadline=started + 0.1,
    )

    assert time.monotonic() - started < 1.0
    assert all(result.timed_out for result in results)
    assert all(result.loss_percent == 100.0 for result in results)
    assert all("deadline" in result.error.lower() for result in results)


def test_mark_stopped_interrupts_in_flight_parallel_probes(qapp, monkeypatch):
    import losshound.core.scheduler as scheduler

    probes_started = threading.Event()

    def fake_ping(target, count, timeout_ms):
        probes_started.set()
        while not QThread.currentThread().isInterruptionRequested():
            time.sleep(0.005)
        raise InterruptedError

    monkeypatch.setattr(scheduler, "ping", fake_ping)
    worker = _worker(qapp)

    def stop_when_started():
        assert probes_started.wait(timeout=1.0)
        worker.mark_stopped()

    stopper = threading.Thread(target=stop_when_started, daemon=True)
    stopper.start()
    started = time.monotonic()
    with pytest.raises(InterruptedError):
        worker._run_ping_probes(
            ["1.1.1.1", "8.8.8.8"],
            count=2,
            timeout_ms=2000,
            deadline=started + 5.0,
        )
    stopper.join(timeout=1.0)

    assert time.monotonic() - started < 1.0


# --------------------------------------------------------- Lag spike detection

def _pub(rtt: float) -> PingResult:
    return PingResult(
        target="1.1.1.1",
        timestamp=datetime.now(),
        packets_sent=4,
        packets_received=4,
        loss_percent=0.0,
        rtt_avg=rtt,
    )


def test_baseline_learned_from_healthy_cycles(qapp):
    worker = _worker(qapp)
    worker._maybe_attribute_lag(_ping(), [_pub(20.0), _pub(30.0)])
    assert worker._rtt_baseline == 25.0

    # EMA moves slowly toward new values.
    worker._maybe_attribute_lag(_ping(), [_pub(35.0), _pub(35.0)])
    assert 25.0 < worker._rtt_baseline < 35.0


def test_spike_detected_only_beyond_factor_and_floor(qapp):
    worker = _worker(qapp)
    worker._rtt_baseline = 25.0

    assert not worker._is_rtt_spike(45.0)   # < 2x
    assert not worker._is_rtt_spike(None)
    assert worker._is_rtt_spike(60.0)       # > max(50, 55)

    # High baseline: absolute floor prevents 2x of tiny values triggering.
    worker._rtt_baseline = 10.0
    assert not worker._is_rtt_spike(21.0)   # > 2x but < baseline + 30
    assert worker._is_rtt_spike(41.0)


def test_spike_does_not_pollute_baseline(qapp):
    worker = _worker(qapp)
    worker._rtt_baseline = 25.0
    with_spike = [_pub(200.0)]
    worker._maybe_attribute_lag(_ping(), with_spike)
    assert worker._rtt_baseline == 25.0  # spike cycle skipped by EMA

    # An attribution run was started for the spike.
    assert worker._attr_worker is not None
    worker._attr_worker.requestInterruption()
    worker._attr_worker.wait(5000)


def test_attribution_throttled_by_cooldown(qapp):
    worker = _worker(qapp)
    worker._rtt_baseline = 25.0
    worker._maybe_attribute_lag(_ping(), [_pub(200.0)])
    first_worker = worker._attr_worker
    assert first_worker is not None

    worker._maybe_attribute_lag(_ping(), [_pub(200.0)])
    assert worker._attr_worker is first_worker  # no second launch

    first_worker.requestInterruption()
    first_worker.wait(5000)


# ------------------------------------------------------ Drop forensics trigger

class _FakeSignal:
    def __init__(self):
        self.callbacks = []

    def connect(self, callback):
        self.callbacks.append(callback)


class _FakeDropForensicsThread:
    created = []

    def __init__(self, gateway, wan_target, timeout_streak):
        self.gateway = gateway
        self.wan_target = wan_target
        self.timeout_streak = timeout_streak
        self.forensics_ready = _FakeSignal()
        self.finished = _FakeSignal()
        self.started = False
        self.running = False
        self.created.append(self)

    def isRunning(self):
        return self.running

    def start(self):
        self.started = True
        self.running = True


def _diag_with_streak(streak: int) -> Diagnosis:
    return Diagnosis(
        timestamp=datetime.now(),
        category=DiagnosisCategory.INTERMITTENT,
        summary="Intermittent packet loss detected",
        explanation="test",
        confidence="medium",
        evidence={"max_timeout_streak": streak},
    )


def test_timeout_burst_starts_drop_forensics(qapp, monkeypatch):
    import losshound.core.scheduler as scheduler

    _FakeDropForensicsThread.created = []
    monkeypatch.setattr(scheduler, "DropForensicsThread", _FakeDropForensicsThread)
    worker = _worker(qapp)
    worker._gateway_ip = "192.168.1.1"
    worker._config.public_ping_targets = ["9.9.9.9"]

    worker._maybe_run_drop_forensics(
        _diag_with_streak(worker._config.diagnosis.timeout_burst_threshold)
    )

    assert len(_FakeDropForensicsThread.created) == 1
    created = _FakeDropForensicsThread.created[0]
    assert created.gateway == "192.168.1.1"
    assert created.wan_target == "9.9.9.9"
    assert created.started is True


def test_drop_forensics_ignores_short_timeout_streak(qapp, monkeypatch):
    import losshound.core.scheduler as scheduler

    _FakeDropForensicsThread.created = []
    monkeypatch.setattr(scheduler, "DropForensicsThread", _FakeDropForensicsThread)
    worker = _worker(qapp)
    worker._gateway_ip = "192.168.1.1"

    worker._maybe_run_drop_forensics(
        _diag_with_streak(worker._config.diagnosis.timeout_burst_threshold - 1)
    )

    assert _FakeDropForensicsThread.created == []
