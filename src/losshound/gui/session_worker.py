"""Qt adapter for one bounded, read-only diagnostic session.

The controller owns and reaps its probe processes. This adapter only requests
cancellation; it never terminates a QThread or reports cleanup before run exits.
"""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import QThread, Signal

from losshound.core.session import SessionController, SessionRequest


class SessionWorker(QThread):
    progress = Signal(object)
    report_ready = Signal(object)
    failed = Signal(str)

    def __init__(self, request: SessionRequest, parent=None):
        super().__init__(parent)
        self.request = request
        self.cancel_event = threading.Event()
        # Thread scheduling and GUI setup consume this same immutable budget.
        self.started_monotonic: float = time.monotonic()

    def cancel(self) -> None:
        if not self.cancel_event.is_set():
            self.cancel_event.requested_monotonic = time.monotonic()
        self.cancel_event.set()

    def run(self) -> None:
        try:
            report = SessionController(self.request).run(
                cancel_event=self.cancel_event,
                on_progress=self.progress.emit,
                absolute_deadline=self.started_monotonic + self.request.duration_seconds,
            )
            self.report_ready.emit(report)
        except Exception as exc:
            # Controller failures are tool failures, never network loss or health.
            self.failed.emit(type(exc).__name__)


def _require_simulation(controller, operation):
    from losshound.core.repair import RepairController
    if type(controller) is not RepairController:
        raise TypeError("An exact repair controller is required")
    if type(operation) is not str or operation not in {"simulate", "verify"}:
        raise ValueError("Choose one simulation or independent verification operation")
    request = controller.record().get("request")
    if (type(request) is not dict or request.get("execution_mode") != "simulation"
            or request.get("simulation_only") is not True):
        raise ValueError("The GUI repair worker accepts simulation mode only")


class SimulatedRepairWorker(QThread):
    """Run one simulation or a separately selected read-only verification."""
    progress = Signal(object)
    report_ready = Signal(object)
    failed = Signal(str)

    def __init__(self, controller, operation="simulate", parent=None):
        started = time.monotonic()
        _require_simulation(controller, operation)
        super().__init__(parent)
        self.controller = controller
        self.operation = operation
        self.request = controller.verification_request
        self.cancel_event = threading.Event()
        self.started_monotonic: float = started

    def cancel(self) -> None:
        if not self.cancel_event.is_set():
            self.cancel_event.requested_monotonic = time.monotonic()
        self.cancel_event.set()

    def run(self) -> None:
        try:
            _require_simulation(self.controller, self.operation)
            if self.operation == "simulate":
                result = self.controller.execute(
                    self.cancel_event, clock=time.monotonic,
                    absolute_deadline=self.started_monotonic + 60,
                )
            else:
                # Only this worker thread constructs and uses read-only probes.
                from losshound.core.session_process import WindowsProbeProvider
                from losshound.core.session_context import WindowsContextObserver
                provider = WindowsProbeProvider(clock=time.monotonic,
                                                extended_diagnostics=self.request.extended_diagnostics)
                observer = WindowsContextObserver(clock=time.monotonic)
                result = self.controller.verify(
                    provider=provider, context_observer=observer,
                    clock=time.monotonic, cancel_event=self.cancel_event,
                    on_progress=self.progress.emit,
                    absolute_deadline=self.started_monotonic + self.request.duration_seconds,
                )
            self.report_ready.emit(result)
        except Exception as exc:
            self.failed.emit(type(exc).__name__)
