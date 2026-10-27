"""One bounded, read-only diagnostic session for the command line."""

from __future__ import annotations

import json
import signal
import sys
import threading
import time
from typing import TYPE_CHECKING

from losshound.core.session import SessionController, SessionRequest
from losshound.core.session_output import BoundedSessionOutput

if TYPE_CHECKING:
    from losshound.core.config import AppConfig
    from losshound.core.session import SessionReport


def run_cli(config: AppConfig, *, duration_seconds: int = 60,
            extended_diagnostics: bool = False, website_urls: tuple[str, ...] = (),
            ipv6_targets: tuple[str, ...] | None = None,
            tcp_targets: tuple[str, ...] | None = None) -> SessionReport:
    """One absolute budget covers child startup, collection, output and cleanup.

    Legacy cadence/benchmark/firewall preferences are not consulted. Ctrl+C
    requests cancellation; no shared thread is terminated. Even a blocked
    console or redirected output sink cannot hold collection/cleanup open.
    """
    optional = {}
    if ipv6_targets is not None:
        optional["ipv6_targets"] = ipv6_targets
    if tcp_targets is not None:
        optional["tcp_targets"] = tcp_targets
    request = SessionRequest(
        duration_seconds=duration_seconds,
        ping_targets=tuple(config.public_ping_targets),
        dns_hostnames=tuple(config.dns_test_hostnames),
        extended_diagnostics=extended_diagnostics, website_urls=website_urls, **optional,
    )
    controller = SessionController(request)
    cancel_event = threading.Event()
    previous_handler = None
    handler_installed = False

    def cancel(_signum, _frame):
        if not cancel_event.is_set():
            cancel_event.requested_monotonic = time.monotonic()
        cancel_event.set()

    if threading.current_thread() is threading.main_thread():
        previous_handler = signal.signal(signal.SIGINT, cancel)
        handler_installed = True

    started = time.monotonic()
    deadline = started + duration_seconds
    output = BoundedSessionOutput(sys.stdout, sys.stderr, deadline)
    last_progress_at = float("-inf")

    def progress(value):
        # Internal callbacks must remain nonblocking. Whole progress messages
        # may be skipped when the owned output child's control pipe is full.
        nonlocal last_progress_at
        now = time.monotonic()
        if now - last_progress_at < 1.0 and value.phase not in {"cleanup", "finished"}:
            return
        last_progress_at = now
        output.progress(
            f"{value.phase}: {max(0.0, value.remaining_seconds):.1f}s remaining; "
            f"{value.completed_count} checks completed"
        )
        if output.errors:
            cancel_event.set()

    report = None
    try:
        if not output.start():
            cancel_event.set()
        output.progress(
            f"Losshound {'extended' if extended_diagnostics else 'S1'} read-only session; total budget {duration_seconds}s. "
            "Ctrl+C cancels and cleans up. No repair will run."
        )
        report = controller.run(
            cancel_event=cancel_event, on_progress=progress, absolute_deadline=deadline,
            output_reserve_seconds=min(0.5, duration_seconds * 0.05),
        )
        report.output_errors = list(output.errors)
        if report.output_errors and report.status != "cleanup_failed":
            report.status = "output_error"
        report.duration_seconds = max(0.0, time.monotonic() - started)
        if extended_diagnostics:
            from losshound.core.session_report import redact_report
            prepared_json = json.dumps(redact_report(report.to_dict()), ensure_ascii=False,
                                       indent=2, allow_nan=False)
        else:
            prepared_json = report.to_json()
        delivered = output.finish(prepared_json)
        report.output_errors = list(output.errors)
        if not delivered and not report.output_errors:
            report.output_errors.append("CLI report delivery was not confirmed")
        if time.monotonic() > deadline:
            report.output_errors.append("CLI total budget exceeded; bounded completion was not established")
        if report.output_errors and report.status != "cleanup_failed":
            report.status = "output_error"
        report.duration_seconds = max(0.0, time.monotonic() - started)
        return report
    finally:
        output.close()
        if report is not None:
            report.output_errors = list(dict.fromkeys([*report.output_errors, *output.errors]))
            if report.output_errors and report.status != "cleanup_failed":
                report.status = "output_error"
        if handler_installed:
            signal.signal(signal.SIGINT, previous_handler)
