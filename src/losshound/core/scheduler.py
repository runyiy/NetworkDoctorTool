from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QObject, QMetaObject, QThread, QTimer, Qt, Signal, Slot

from losshound.core.config import AppConfig
from losshound.core.diagnosis import diagnose
from losshound.core.dns_checks import check_dns
from losshound.core.drop_analyzer import DropForensicsEpisode, run_drop_forensics
from losshound.core.gateway import detect_gateway
from losshound.core.lag_attribution import LagAttribution, attribute_lag
from losshound.core.models import (
    Diagnosis,
    DnsResult,
    Observation,
    PingResult,
    RouteSnapshot,
)
from losshound.core.ping import ping
from losshound.core.route_monitor import trace_route
from losshound.storage.history import HistoryStore

logger = logging.getLogger(__name__)

# Adaptive cadence: when a cycle sees loss/timeouts, sample every
# FAST_INTERVAL_SECONDS with a lighter probe count to capture the burst
# shape; return to the configured interval after RECOVERY_CYCLES clean
# cycles in a row.
FAST_INTERVAL_SECONDS = 5
FAST_PING_COUNT = 2
RECOVERY_CYCLES = 3
_FAST_CYCLE_SLACK_SECONDS = 0.25
_FAST_DNS_BUDGET_SECONDS = 1.0

# Lag attribution: a cycle whose average public RTT exceeds the healthy
# baseline by both the factor and the absolute floor counts as a spike.
# Attribution runs are throttled by the cooldown.
LAG_SPIKE_FACTOR = 2.0
LAG_SPIKE_MIN_DELTA_MS = 30.0
LAG_ATTRIBUTION_COOLDOWN_S = 120
_BASELINE_EMA_ALPHA = 0.2

# Disconnect forensics: when the diagnosis window sees a timeout burst, run a
# short rapid-poll capture to classify WiFi roam vs gateway reboot vs ISP/WAN.
DROP_FORENSICS_DURATION_S = 30
DROP_FORENSICS_POLL_INTERVAL_S = 1.0
DROP_FORENSICS_COOLDOWN_S = 300


class DropForensicsThread(QThread):
    """Run automatic disconnect forensics off the monitor loop."""

    forensics_ready = Signal(object)  # DropForensicsEpisode

    def __init__(
        self,
        gateway: str,
        wan_target: str,
        timeout_streak: int,
        parent=None,
    ):
        super().__init__(parent)
        self._gateway = gateway
        self._wan_target = wan_target
        self._timeout_streak = timeout_streak

    def run(self):
        try:
            if self.isInterruptionRequested():
                return
            episode = run_drop_forensics(
                gateway=self._gateway,
                wan_target=self._wan_target,
                timeout_streak=self._timeout_streak,
                duration_seconds=DROP_FORENSICS_DURATION_S,
                poll_interval=DROP_FORENSICS_POLL_INTERVAL_S,
                stop_check=self.isInterruptionRequested,
            )
            if not self.isInterruptionRequested():
                self.forensics_ready.emit(episode)
        except (InterruptedError, KeyboardInterrupt):
            logger.info("Drop forensics interrupted during thread shutdown.")
        except Exception:
            logger.exception("Error in drop forensics")


class LagAttributionThread(QThread):
    """Run lag attribution (throughput sample + netstat) off the monitor loop."""

    attribution_ready = Signal(object)  # LagAttribution

    def __init__(self, trigger: str, baseline_ms, spike_ms, parent=None):
        super().__init__(parent)
        self._trigger = trigger
        self._baseline_ms = baseline_ms
        self._spike_ms = spike_ms

    def run(self):
        try:
            if self.isInterruptionRequested():
                return
            attribution = attribute_lag(
                self._trigger, self._baseline_ms, self._spike_ms
            )
            if not self.isInterruptionRequested():
                self.attribution_ready.emit(attribution)
        except (InterruptedError, KeyboardInterrupt):
            logger.info("Lag attribution interrupted during thread shutdown.")
        except Exception:
            # Attribution is best-effort; never surface errors to the user.
            logger.exception("Error in lag attribution")


class RouteCheckThread(QThread):
    """Run tracert in its own QThread so monitoring timers stay responsive."""

    route_ready = Signal(object)  # RouteSnapshot
    error_occurred = Signal(str)

    def __init__(self, target: str, max_hops: int, parent=None):
        super().__init__(parent)
        self._target = target
        self._max_hops = max_hops

    def run(self):
        try:
            if self.isInterruptionRequested():
                return
            snap = trace_route(self._target, max_hops=self._max_hops)
            if not self.isInterruptionRequested():
                self.route_ready.emit(snap)
        except (InterruptedError, KeyboardInterrupt):
            logger.info("Route check interrupted during thread shutdown.")
        except Exception as exc:
            if not self.isInterruptionRequested():
                logger.exception("Error in route check")
                self.error_occurred.emit(str(exc))


class _PingProbeThread(QThread):
    """Run one target's ping in an independently cancellable QThread."""

    def __init__(self, target: str, count: int, timeout_ms: int, parent=None):
        super().__init__(parent)
        self.target = target
        self.count = count
        self.timeout_ms = timeout_ms
        self.result: Optional[PingResult] = None
        self.error: Optional[Exception] = None
        self.interrupted = False

    def run(self):
        try:
            self.result = ping(
                self.target,
                count=self.count,
                timeout_ms=self.timeout_ms,
            )
        except (InterruptedError, KeyboardInterrupt):
            self.interrupted = True
        except Exception as exc:
            self.error = exc


class MonitorWorker(QObject):
    """Background worker that runs network tests on timers."""

    observation_ready = Signal(object)  # Observation
    diagnosis_ready = Signal(object)    # Diagnosis
    error_occurred = Signal(str)
    cadence_changed = Signal(int)       # effective ping interval, seconds
    lag_attribution_ready = Signal(object)  # LagAttribution
    drop_forensics_ready = Signal(object)   # DropForensicsEpisode

    def __init__(self, config: AppConfig, history: HistoryStore):
        super().__init__()
        self._config = config
        self._history = history
        self._gateway_ip: Optional[str] = None
        self._last_route: Optional[RouteSnapshot] = None
        self._last_dns_check_monotonic: Optional[float] = None
        self._route_worker: Optional[RouteCheckThread] = None
        self._stopped = False
        self._fast_mode = False
        self._healthy_streak = 0
        self._rtt_baseline: Optional[float] = None
        self._attr_worker: Optional[LagAttributionThread] = None
        self._last_attribution_monotonic: Optional[float] = None
        self._drop_worker: Optional[DropForensicsThread] = None
        self._last_drop_forensics_monotonic: Optional[float] = None
        self._probe_workers: list[_PingProbeThread] = []

    @Slot()
    def start_timers(self):
        """Set up and start the periodic timers."""
        # Ping + DNS timer
        self._ping_timer = QTimer(self)
        self._ping_timer.timeout.connect(self._run_ping_cycle)
        self._ping_timer.start(self._config.ping_interval_seconds * 1000)

        # Route timer (separate, longer interval)
        self._route_timer = QTimer(self)
        self._route_timer.timeout.connect(self._run_route_check)
        self._route_timer.start(self._config.route_interval_seconds * 1000)

        # Auto mini-benchmark timer. A non-positive interval disables it
        # instead of creating a zero-delay timer that loops continuously.
        self._bench_timer: Optional[QTimer] = None
        self._configure_bench_timer()

        # Prune timer (hourly)
        self._prune_timer = QTimer(self)
        self._prune_timer.timeout.connect(self._prune)
        self._prune_timer.start(3600 * 1000)

        # Run after the thread event loop starts, so queued stop/config calls
        # are always able to reach this worker.
        QTimer.singleShot(0, self._run_ping_cycle)
        QTimer.singleShot(0, self._run_route_check)
        QTimer.singleShot(0, self._prune)

        # Delay auto-benchmark by 2 minutes so startup isn't slow.
        if self._bench_timer and self._bench_timer.isActive():
            QTimer.singleShot(120_000, self._run_auto_benchmark)

    @Slot()
    def stop(self):
        self._stopped = True
        self._interrupt_probe_workers()
        if hasattr(self, "_ping_timer"):
            self._ping_timer.stop()
        if hasattr(self, "_route_timer"):
            self._route_timer.stop()
        if getattr(self, "_bench_timer", None):
            self._bench_timer.stop()
        if hasattr(self, "_prune_timer"):
            self._prune_timer.stop()
        if self._route_worker and self._route_worker.isRunning():
            self._route_worker.requestInterruption()
            if not self._route_worker.wait(3000):
                logger.warning("Route check thread did not stop cleanly; terminating")
                self._route_worker.terminate()
                self._route_worker.wait(1000)
        if self._attr_worker and self._attr_worker.isRunning():
            self._attr_worker.requestInterruption()
            if not self._attr_worker.wait(2000):
                logger.warning("Lag attribution thread did not stop cleanly; terminating")
                self._attr_worker.terminate()
                self._attr_worker.wait(1000)
        if self._drop_worker and self._drop_worker.isRunning():
            self._drop_worker.requestInterruption()
            if not self._drop_worker.wait(1500):
                logger.warning("Drop forensics thread did not stop cleanly; terminating")
                self._drop_worker.terminate()
                self._drop_worker.wait(500)

    def mark_stopped(self) -> None:
        """Thread-safe shutdown flag set before queued stop work runs."""
        self._stopped = True
        self._interrupt_probe_workers()
        if self._route_worker and self._route_worker.isRunning():
            self._route_worker.requestInterruption()
        if self._attr_worker and self._attr_worker.isRunning():
            self._attr_worker.requestInterruption()
        if self._drop_worker and self._drop_worker.isRunning():
            self._drop_worker.requestInterruption()

    def _interrupt_probe_workers(self) -> None:
        for worker in tuple(self._probe_workers):
            if worker.isRunning():
                worker.requestInterruption()

    @Slot(object)
    def update_config(self, config: AppConfig):
        self._config = config
        if hasattr(self, "_ping_timer"):
            effective = self._effective_ping_interval()
            self._ping_timer.setInterval(effective * 1000)
            self.cadence_changed.emit(effective)
        if hasattr(self, "_route_timer"):
            self._route_timer.setInterval(config.route_interval_seconds * 1000)
        self._configure_bench_timer()

    @Slot()
    def run_now(self):
        self._run_ping_cycle()

    def _configure_bench_timer(self) -> None:
        interval_minutes = self._config.auto_benchmark_interval_minutes
        timer = getattr(self, "_bench_timer", None)

        if interval_minutes <= 0:
            if timer is not None:
                timer.stop()
            return

        interval_ms = int(interval_minutes * 60 * 1000)
        if timer is None:
            timer = QTimer(self)
            timer.timeout.connect(self._run_auto_benchmark)
            self._bench_timer = timer

        timer.start(interval_ms)

    def _dns_due(self) -> bool:
        interval = max(1, self._config.dns_interval_seconds)
        last_check = self._last_dns_check_monotonic
        return last_check is None or (time.monotonic() - last_check) >= interval

    def _effective_ping_interval(self) -> int:
        if self._fast_mode:
            return min(FAST_INTERVAL_SECONDS, self._config.ping_interval_seconds)
        return self._config.ping_interval_seconds

    def _cycle_unhealthy(self, gw_ping, pub_pings) -> bool:
        if gw_ping is not None and (gw_ping.timed_out or gw_ping.loss_percent > 0):
            return True
        return any(pp.timed_out or pp.loss_percent > 0 for pp in pub_pings)

    def _update_cadence(self, gw_ping, pub_pings) -> None:
        """Densify sampling while the connection is misbehaving."""
        if not hasattr(self, "_ping_timer"):
            return

        if self._cycle_unhealthy(gw_ping, pub_pings):
            self._healthy_streak = 0
            if not self._fast_mode:
                self._fast_mode = True
                effective = self._effective_ping_interval()
                self._ping_timer.setInterval(effective * 1000)
                self.cadence_changed.emit(effective)
                logger.info(
                    "Loss detected — sampling densified to every %ss", effective
                )
        elif self._fast_mode:
            self._healthy_streak += 1
            if self._healthy_streak >= RECOVERY_CYCLES:
                self._fast_mode = False
                self._healthy_streak = 0
                effective = self._effective_ping_interval()
                self._ping_timer.setInterval(effective * 1000)
                self.cadence_changed.emit(effective)
                logger.info(
                    "Stability restored — sampling back to every %ss", effective
                )

    @staticmethod
    def _cycle_rtt(pub_pings) -> Optional[float]:
        rtts = [pp.rtt_avg for pp in pub_pings if pp.rtt_avg is not None]
        return sum(rtts) / len(rtts) if rtts else None

    def _is_rtt_spike(self, cycle_rtt: Optional[float]) -> bool:
        if cycle_rtt is None or self._rtt_baseline is None:
            return False
        threshold = max(
            self._rtt_baseline * LAG_SPIKE_FACTOR,
            self._rtt_baseline + LAG_SPIKE_MIN_DELTA_MS,
        )
        return cycle_rtt > threshold

    def _maybe_attribute_lag(self, gw_ping, pub_pings) -> None:
        """Detect a lag/loss event and kick off attribution (throttled)."""
        cycle_rtt = self._cycle_rtt(pub_pings)
        unhealthy = self._cycle_unhealthy(gw_ping, pub_pings)
        spike = self._is_rtt_spike(cycle_rtt)

        if not unhealthy and not spike and cycle_rtt is not None:
            # Learn the healthy baseline only from clean cycles.
            if self._rtt_baseline is None:
                self._rtt_baseline = cycle_rtt
            else:
                self._rtt_baseline = (
                    (1 - _BASELINE_EMA_ALPHA) * self._rtt_baseline
                    + _BASELINE_EMA_ALPHA * cycle_rtt
                )
            return

        if not unhealthy and not spike:
            return

        now = time.monotonic()
        if (
            self._last_attribution_monotonic is not None
            and now - self._last_attribution_monotonic < LAG_ATTRIBUTION_COOLDOWN_S
        ):
            return
        if self._attr_worker and self._attr_worker.isRunning():
            return

        self._last_attribution_monotonic = now
        trigger = "loss" if unhealthy else "latency"
        worker = LagAttributionThread(trigger, self._rtt_baseline, cycle_rtt)
        worker.attribution_ready.connect(self._on_lag_attribution)
        worker.finished.connect(self._on_attr_thread_finished)
        self._attr_worker = worker
        worker.start()

    @Slot(object)
    def _on_lag_attribution(self, attribution: LagAttribution):
        if self._stopped or QThread.currentThread().isInterruptionRequested():
            return
        logger.info("Lag attribution: %s", attribution.summary)
        self.lag_attribution_ready.emit(attribution)

    @Slot()
    def _on_attr_thread_finished(self):
        worker = self.sender()
        if worker is self._attr_worker:
            self._attr_worker = None
        if worker is not None:
            worker.deleteLater()

    def _maybe_run_drop_forensics(self, diag: Diagnosis) -> None:
        """Kick off a short capture when the diagnosis window sees a burst."""
        if self._stopped:
            return
        if not self._gateway_ip:
            return

        try:
            timeout_streak = int(diag.evidence.get("max_timeout_streak", 0) or 0)
        except (TypeError, ValueError):
            timeout_streak = 0
        if timeout_streak < self._config.diagnosis.timeout_burst_threshold:
            return

        now = time.monotonic()
        if (
            self._last_drop_forensics_monotonic is not None
            and now - self._last_drop_forensics_monotonic < DROP_FORENSICS_COOLDOWN_S
        ):
            return
        if self._drop_worker and self._drop_worker.isRunning():
            return

        self._last_drop_forensics_monotonic = now
        wan_target = self._config.public_ping_targets[0] if self._config.public_ping_targets else "8.8.8.8"
        worker = DropForensicsThread(
            self._gateway_ip,
            wan_target,
            timeout_streak,
        )
        worker.forensics_ready.connect(self._on_drop_forensics)
        worker.finished.connect(self._on_drop_thread_finished)
        self._drop_worker = worker
        worker.start()

    @Slot(object)
    def _on_drop_forensics(self, episode: DropForensicsEpisode):
        if self._stopped or QThread.currentThread().isInterruptionRequested():
            return
        logger.info("Drop forensics: %s", episode.summary)
        self._history.save_drop_forensics(episode)
        self.drop_forensics_ready.emit(episode)

    @Slot()
    def _on_drop_thread_finished(self):
        worker = self.sender()
        if worker is self._drop_worker:
            self._drop_worker = None
        if worker is not None:
            worker.deleteLater()

    @staticmethod
    def _probe_timeout_result(target: str, count: int, error: str) -> PingResult:
        return PingResult(
            target=target,
            timestamp=datetime.now(),
            packets_sent=count,
            packets_received=0,
            loss_percent=100.0,
            timed_out=True,
            error=error,
        )

    def _monitor_interrupted(self) -> bool:
        thread = QThread.currentThread()
        return self._stopped or bool(thread and thread.isInterruptionRequested())

    def _run_ping_probes(
        self,
        targets: list[str],
        count: int,
        timeout_ms: int,
        deadline: Optional[float] = None,
    ) -> list[PingResult]:
        """Ping targets concurrently while preserving QThread cancellation.

        A Python thread pool would lose the monitor QThread's interruption
        contract.  Giving each target its own QThread lets both the native
        ICMP and subprocess paths observe ``requestInterruption()``.
        """
        if not targets:
            return []

        effective_timeout_ms = max(1, timeout_ms)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return [
                    self._probe_timeout_result(
                        target, count, "Fast-cycle probe deadline reached"
                    )
                    for target in targets
                ]
            # A target may consume the timeout once per echo.  All targets run
            # in parallel, so only divide the remaining wall-time by count.
            deadline_timeout_ms = max(1, int((remaining * 1000) / max(1, count)))
            effective_timeout_ms = min(effective_timeout_ms, deadline_timeout_ms)

        workers = [
            _PingProbeThread(target, count, effective_timeout_ms)
            for target in targets
        ]
        self._probe_workers = workers
        deadline_reached = False

        try:
            for worker in workers:
                worker.start()

            while any(worker.isRunning() for worker in workers):
                if self._monitor_interrupted():
                    raise InterruptedError(
                        "Ping probes aborted due to monitor interruption request."
                    )
                if deadline is not None and time.monotonic() >= deadline:
                    deadline_reached = True
                    break
                for worker in workers:
                    if worker.isRunning():
                        worker.wait(20)
        finally:
            # This is also the deadline cleanup path.  Never drop the final
            # Python reference while a QThread is still running.
            for worker in workers:
                if worker.isRunning():
                    worker.requestInterruption()
            while any(worker.isRunning() for worker in workers):
                for worker in workers:
                    if worker.isRunning():
                        worker.wait(25)
            self._probe_workers = []

        if self._monitor_interrupted():
            raise InterruptedError(
                "Ping probes aborted due to monitor interruption request."
            )

        results: list[PingResult] = []
        for worker in workers:
            if worker.error is not None:
                raise worker.error
            if worker.result is not None:
                results.append(worker.result)
                continue
            message = (
                "Fast-cycle probe deadline reached"
                if deadline_reached
                else "Ping probe interrupted"
            )
            results.append(self._probe_timeout_result(worker.target, count, message))
        return results

    @Slot()
    def _run_ping_cycle(self):
        """Run gateway ping, public pings, and DNS checks."""
        if self._stopped:
            return

        try:
            now = datetime.now()
            cycle_started = time.monotonic()
            started_in_fast_mode = self._fast_mode

            # Gateway discovery may invoke Windows management commands.  A
            # fast cycle already has the gateway from the cycle that detected
            # loss, so reuse it instead of spending the five-second sampling
            # budget rediscovering the same local route.
            if not started_in_fast_mode or not self._gateway_ip:
                self._gateway_ip = detect_gateway()

            # Lighter probe count while sampling densely, so fast cycles
            # finish well within the fast interval.
            ping_count = (
                FAST_PING_COUNT
                if started_in_fast_mode
                else self._config.ping_count
            )

            dns_due = self._dns_due()
            cycle_deadline: Optional[float] = None
            probe_deadline: Optional[float] = None
            if started_in_fast_mode:
                cycle_deadline = (
                    cycle_started
                    + FAST_INTERVAL_SECONDS
                    - _FAST_CYCLE_SLACK_SECONDS
                )
                probe_deadline = cycle_deadline
                if dns_due and self._config.dns_test_hostnames:
                    probe_deadline -= _FAST_DNS_BUDGET_SECONDS

            public_targets = list(self._config.public_ping_targets)
            targets = ([self._gateway_ip] if self._gateway_ip else []) + public_targets
            probe_results = self._run_ping_probes(
                targets,
                count=ping_count,
                timeout_ms=self._config.ping_timeout_ms,
                deadline=probe_deadline,
            )

            result_index = 0
            gw_ping = None
            if self._gateway_ip:
                gw_ping = probe_results[0]
                result_index = 1
            pub_pings = probe_results[result_index:]

            self._update_cadence(gw_ping, pub_pings)
            self._maybe_attribute_lag(gw_ping, pub_pings)

            # DNS checks
            dns_results: list[DnsResult] = []
            if dns_due:
                hostnames = list(self._config.dns_test_hostnames)
                for index, hostname in enumerate(hostnames):
                    if self._monitor_interrupted():
                        raise InterruptedError(
                            "DNS checks aborted due to monitor interruption request."
                        )

                    if cycle_deadline is None:
                        result = check_dns(hostname)
                    else:
                        remaining = cycle_deadline - time.monotonic()
                        if remaining <= 0:
                            # No measurement is better than recording a
                            # deadline skip as a false DNS failure.
                            break
                        remaining_hosts = len(hostnames) - index
                        timeout = max(0.001, remaining / remaining_hosts)
                        result = check_dns(hostname, timeout=timeout)
                    dns_results.append(result)
                if dns_results or not hostnames:
                    self._last_dns_check_monotonic = time.monotonic()

            # Build observation
            obs = Observation(
                timestamp=now,
                gateway_ip=self._gateway_ip,
                gateway_ping=gw_ping,
                public_pings=pub_pings,
                dns_results=dns_results,
                route_snapshot=self._last_route,
            )

            self._history.save_observation(obs)
            self.observation_ready.emit(obs)

            # Run diagnosis
            recent = self._history.get_recent_observations(
                self._config.diagnosis.window_minutes
            )
            route_history = self._history.get_route_snapshots(hours=1)

            diag = diagnose(recent, self._config.diagnosis, route_history)
            self._history.save_diagnosis(diag)
            self.diagnosis_ready.emit(diag)
            self._maybe_run_drop_forensics(diag)

        except (InterruptedError, KeyboardInterrupt):
            logger.info("Ping cycle interrupted during thread shutdown.")
        except Exception as exc:
            if self._stopped or (QThread.currentThread() and QThread.currentThread().isInterruptionRequested()):
                return
            logger.exception("Error in ping cycle")
            self.error_occurred.emit(str(exc))

    @Slot()
    def _run_route_check(self):
        """Start a tracert check (skips if one is already running)."""
        if self._stopped:
            return

        if self._route_worker and self._route_worker.isRunning():
            logger.debug("Tracert already in progress, skipping")
            return

        worker = RouteCheckThread(
            self._config.tracert_target,
            self._config.tracert_max_hops,
        )
        worker.route_ready.connect(self._on_route_snapshot)
        worker.error_occurred.connect(self._on_route_error)
        worker.finished.connect(self._on_route_thread_finished)
        self._route_worker = worker
        worker.start()

    @Slot(object)
    def _on_route_snapshot(self, snap: RouteSnapshot):
        if self._stopped or QThread.currentThread().isInterruptionRequested():
            return
        self._last_route = snap
        self._history.save_route_snapshot(snap)

    @Slot(str)
    def _on_route_error(self, msg: str):
        if self._stopped or QThread.currentThread().isInterruptionRequested():
            return
        self.error_occurred.emit(msg)

    @Slot()
    def _on_route_thread_finished(self):
        worker = self.sender()
        if worker is self._route_worker:
            self._route_worker = None
        if worker is not None:
            worker.deleteLater()

    def _run_auto_benchmark(self):
        """Run a lightweight auto-benchmark and save to history for trending."""
        if self._stopped:
            return

        try:
            from losshound.core.benchmark import run_benchmark, save_snapshot

            logger.info("Running auto mini-benchmark")
            ping_targets = self._config.public_ping_targets[:1] or ["1.1.1.1"]
            snapshot = run_benchmark(
                label="auto",
                ping_count=max(1, min(self._config.ping_count, 4)),
                ping_targets=ping_targets,
                dns_servers=[],
                tcp_targets=[],
            )
            save_snapshot(snapshot)
            logger.info("Auto mini-benchmark complete — score data saved")
        except Exception as exc:
            logger.debug("Auto benchmark error: %s", exc)

    def _prune(self):
        try:
            self._history.prune(self._config.history_retention_hours)
        except Exception as exc:
            logger.debug("Prune error: %s", exc)


class MonitorThread(QThread):
    """Thread that hosts the MonitorWorker."""

    observation_ready = Signal(object)
    diagnosis_ready = Signal(object)
    error_occurred = Signal(str)
    cadence_changed = Signal(int)
    lag_attribution_ready = Signal(object)
    drop_forensics_ready = Signal(object)
    config_update_requested = Signal(object)
    run_now_requested = Signal()

    def __init__(self, config: AppConfig, history: HistoryStore, parent=None):
        super().__init__(parent)
        self._config = config
        self._history = history
        self._worker: Optional[MonitorWorker] = None

    def run(self):
        thread_safe_history = HistoryStore(self._history._db_path)
        try:
            self._worker = MonitorWorker(self._config, thread_safe_history)
            self._worker.observation_ready.connect(self.observation_ready.emit)
            self._worker.diagnosis_ready.connect(self.diagnosis_ready.emit)
            self._worker.error_occurred.connect(self.error_occurred.emit)
            self._worker.cadence_changed.connect(self.cadence_changed.emit)
            self._worker.lag_attribution_ready.connect(self.lag_attribution_ready.emit)
            self._worker.drop_forensics_ready.connect(self.drop_forensics_ready.emit)
            self.config_update_requested.connect(
                self._worker.update_config,
                Qt.ConnectionType.QueuedConnection,
            )
            self.run_now_requested.connect(
                self._worker.run_now,
                Qt.ConnectionType.QueuedConnection,
            )
            self._worker.start_timers()
            self.exec()
        finally:
            if self._worker:
                self._worker.stop()
            thread_safe_history.close()

    def stop(self):
        if not self.isRunning():
            return

        self.requestInterruption()
        if self._worker:
            self._worker.mark_stopped()
            try:
                QMetaObject.invokeMethod(
                    self._worker,
                    "stop",
                    Qt.ConnectionType.QueuedConnection,
                )
            except RuntimeError:
                logger.debug("Monitor worker was already gone during shutdown")
        self.quit()
        # In-flight ping/tracert subprocesses are killed within ~2s of the
        # interruption request, and the worker's own stop() chains waits for
        # the route (3s+1s), attribution (2s+1s), and drop-forensics (1.5s+0.5s)
        # threads — up to ~9s worst case, so the outer window must exceed that
        # before the hard terminate. The Job Object kills any straggler
        # subprocess children when the interpreter exits.
        if not self.wait(12000):
            logger.warning("MonitorThread did not stop cleanly; terminating")
            self.terminate()
            self.wait(1000)

    def update_config(self, config: AppConfig):
        self._config = config
        if self._worker:
            self.config_update_requested.emit(config)

    def run_now(self):
        if self._worker:
            self.run_now_requested.emit()
