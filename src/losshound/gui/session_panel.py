"""Existing bounded-session panel: S2 presentation and simulation-only S3 controls."""
from __future__ import annotations

import json
import math
import time
from pathlib import Path

from PySide6.QtCore import QTimer, Signal, Slot, Qt
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from losshound.core.config import AppConfig
from losshound.core.session import SessionRequest
from losshound.core.session_report import redact_report
from losshound.gui.session_worker import SessionWorker, SimulatedRepairWorker
from losshound.gui.theme import button_style


_OUTCOMES = {
    "success": "Response received",
    "reply_timeout": "No reply within this check",
    "unreachable": "Connection or resolution failed",
    "execution_error": "Tool error; network outcome UNKNOWN",
    "unsupported": "Unsupported; not tested",
    "skipped": "Skipped; not tested",
    "cancelled": "Cancelled; incomplete",
    "not_attempted": "Not tested",
}
_SCOPES = {"local": "This device", "wifi": "Wi-Fi link", "gateway": "Gateway path",
           "wan_or_isp": "Upstream / ISP (suspected)", "dns": "Name resolution",
           "target": "Requested site / service", "unknown": "UNKNOWN"}


def _redacted_snapshot(raw):
    # Configuration may name an unsampled short hostname which is absent from
    # evidence aliases. Do not export the raw target list in a compound record.
    snapshot = dict(raw)
    omitted = snapshot.pop("baseline_request", None) is not None
    safe = redact_report(snapshot)
    if omitted:
        safe["redaction"]["removed_fields"].append("baseline_request")
    return safe


def _refs(values):
    return ", ".join("E" + str(value) for value in values) if values else "None recorded"


def format_session_report(snapshot):
    """Presentation of an already-redacted existing report, never diagnosis."""
    lines = [f"Session: {snapshot.get('status', 'UNKNOWN')}",
             "A response is evidence, not proof of health. Missing checks remain UNKNOWN."]
    rows = snapshot.get("evidence") or []
    for family in ("IPv4", "IPv6"):
        lines.append("\n" + family + " checks")
        for row in rows:
            if row.get("protocol") != "network":
                continue
            data = row.get("data") or {}
            summary = ((data.get("diagnostics") or {}).get("families") or {}).get(family) or {}
            status = summary.get("status") or "UNKNOWN"
            qualifier = "confirmed" if row.get("comparable") is True else "not comparable"
            lines.append(f"  E{row.get('sequence', '?')} local snapshot: {status} ({qualifier}; no connectivity verdict)")
            addresses = [str(item.get("address", "UNKNOWN")) for item in summary.get("addresses", [])]
            lines.append("    Addresses: " + (", ".join(addresses) if addresses else "UNKNOWN / not recorded"))
            route = summary.get("default_route")
            if isinstance(route, dict):
                lines.append("    Default gateway: " + str(route.get("gateway", "UNKNOWN")))
                lines.append("    Source address candidate (not actual route proof): " +
                             str(route.get("source_address_candidate", "UNKNOWN")))
            else:
                lines.append("    Default route: UNKNOWN / no confirmed route summary")
        for name, protocols in (("DNS", {"dns", "dns6"}), ("ICMP", {"icmp"}),
                                ("TCP", {"tcp", "tcp6"}),
                                ("HTTP(S)", {"http", "http6", "https", "https6"})):
            selected = [row for row in rows if row.get("family") == family
                        and row.get("protocol") in protocols]
            if not selected:
                lines.append(f"  {name}: NOT TESTED / no recorded result")
            for row in selected:
                data = row.get("data") or {}
                outcome = _OUTCOMES.get(row.get("outcome"), "UNKNOWN")
                note = "" if row.get("comparable") is True else "; not comparable"
                code = data.get("http_status")
                if code is not None:
                    note += f"; HTTP {code} (service health is separate)"
                category = data.get("error_category")
                if category:
                    note += f"; category: {category}"
                lines.append(f"  E{row.get('sequence', '?')} {name} {row.get('target', '')}: {outcome}{note}")
    lines.append("\nFault scope and evidence")
    analysis = snapshot.get("analysis") or {}
    findings = analysis.get("findings") or []
    if not findings:
        lines.append("UNKNOWN: insufficient comparable evidence; no health or cause conclusion.")
    for finding in findings:
        scope = _SCOPES.get(finding.get("scope"), "UNKNOWN")
        lines.append(f"\n{scope} | confidence: {finding.get('confidence') or 'unknown'} (qualitative)")
        lines.append(str(finding.get("explanation") or "UNKNOWN: no explanation available"))
        lines.append("Support: " + _refs(finding.get("supporting_evidence", finding.get("evidence_sequences"))))
        lines.append("Counterevidence: " + _refs(finding.get("contradictions")))
        for label, key in (("Alternative", "alternatives"), ("Limitation", "limitations"),
                           ("Advice", "recommendations")):
            lines.extend(label + ": " + str(value) for value in finding.get(key, []))
    for item in analysis.get("intermittent") or []:
        lines.append("\nIntermittent observations in this limited window")
        lines.append(str(item.get("explanation") or "A comparable response sequence varied; persistence is unknown."))
        lines.append("Support: " + _refs(item.get("supporting_evidence", item.get("evidence_sequences"))))
        lines.extend("Limitation: " + str(value) for value in item.get("limitations", []))
    lines.extend("Limitation: " + str(value) for value in analysis.get("limitations", []))
    if snapshot.get("incomplete"):
        lines.append("\nUnfinished checks (redacted):")
        lines.extend(str(value) for value in snapshot["incomplete"])
    if snapshot.get("cleanup_errors") or snapshot.get("output_errors"):
        lines.append("Tool / cleanup errors recorded; this is not a successful complete session.")
    lines.append("\nEvidence numbers refer only to this session.")
    return "\n".join(lines)


def format_repair_record(snapshot):
    """Only simulation records are presented by this GUI."""
    request, execution = snapshot.get("request") or {}, snapshot.get("execution") or {}
    if request.get("execution_mode") != "simulation" or request.get("simulation_only") is not True:
        raise ValueError("Native repair records are unavailable in this GUI")
    if execution.get("simulation_only") is not True or execution.get("system_change_performed") is not False:
        raise ValueError("A simulation record must not claim a real system change")
    verification, comparison = snapshot.get("verification") or {}, snapshot.get("comparison") or {}
    lines = ["SIMULATION ONLY - no real DNS cache clearing",
             "Only plan: clear the Windows local DNS resolver cache.",
             str(request.get("impact", "")), str(request.get("no_restore_warning", "")),
             "Confirmation: " + str((snapshot.get("confirmation") or {}).get("status", "not_confirmed")),
             "Simulated operation result: " + str(execution.get("status", "UNKNOWN")),
             "Independent verification: " + str(verification.get("status", "not_started")),
             "Observed change: " + str(comparison.get("status", "inconclusive")),
             "Causality and permanent recovery remain unproven."]
    lines.extend("Reason: " + str(value) for value in comparison.get("reasons", []))
    for item in comparison.get("comparisons") or []:
        lines.append(f"{item.get('family', 'UNKNOWN')} {item.get('protocol', '')}: {item.get('change', 'inconclusive')}")
        lines.append("Before: " + _refs(item.get("before_sequences")) + "; after: " + _refs(item.get("after_sequences")))
    lines.extend("Limitation: " + str(value) for value in comparison.get("limitations", []))
    if verification.get("report") is not None:
        lines.append("\nIndependent verification evidence (its E numbers belong to a separate session):")
        lines.append(format_session_report(verification["report"]))
    return "\n".join(lines)


class SessionPanel(QWidget):
    cleanup_finished = Signal()

    def __init__(self, config: AppConfig, duration_seconds: int = 60, parent=None):
        super().__init__(parent)
        SessionRequest(duration_seconds=duration_seconds)
        self._config = config
        self._worker = None
        self._worker_kind = None
        self._report = self._active_request = None
        self._repair_controller = self._repair_record = None
        self._closing = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 18, 24, 18)
        title = QLabel("READ-ONLY NETWORK DIAGNOSIS")
        title.setObjectName("section-title")
        layout.addWidget(title)
        description = QLabel(
            "IPv4/IPv6 and independent protocol checks share one finite budget, including cleanup. "
            "No network settings are changed. Verification repeats the completed diagnosis targets.")
        description.setWordWrap(True)
        layout.addWidget(description)
        websites = QHBoxLayout()
        websites.addWidget(QLabel("Website for next diagnosis (optional)"))
        self._website_input = QLineEdit()
        self._website_input.setPlaceholderText("https://example.com/")
        self._website_input.setAccessibleName("Optional HTTP or HTTPS diagnosis target")
        websites.addWidget(self._website_input)
        layout.addLayout(websites)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Diagnostic budget"))
        self._duration = QSpinBox()
        self._duration.setRange(1, 300)
        self._duration.setSuffix(" seconds")
        self._duration.setValue(duration_seconds)
        self._duration.setAccessibleName("Diagnostic total budget in seconds")
        controls.addWidget(self._duration)
        self._start_btn = QPushButton("Start diagnosis")
        self._start_btn.setStyleSheet(button_style("primary"))
        self._start_btn.clicked.connect(self.start_session)
        controls.addWidget(self._start_btn)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self.cancel_session)
        controls.addWidget(self._cancel_btn)
        controls.addStretch()
        self._save_btn = QPushButton("Save redacted JSON")
        self._save_btn.clicked.connect(self._save_report)
        controls.addWidget(self._save_btn)
        layout.addLayout(controls)
        self._remaining = QLabel(f"Remaining: {duration_seconds} seconds")
        layout.addWidget(self._remaining)
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        layout.addWidget(self._progress)
        self._state = QLabel("Ready. No checks have run; no background monitoring is active.")
        self._state.setWordWrap(True)
        layout.addWidget(self._state)
        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setPlaceholderText("Protocol evidence, fault explanations and uncertainty appear here.")
        layout.addWidget(self._preview, 1)

        repair_note = QLabel(
            "DNS cache plan: simulation only. The original cache cannot be restored exactly. "
            "Real repair is unavailable; diagnosis never starts a repair.")
        repair_note.setWordWrap(True)
        layout.addWidget(repair_note)
        repair_controls = QHBoxLayout()
        self._simulate_btn = QPushButton("Preview and confirm simulation")
        self._simulate_btn.clicked.connect(self.simulate_repair)
        repair_controls.addWidget(self._simulate_btn)
        repair_controls.addWidget(QLabel("Independent verification budget"))
        self._verify_duration = QSpinBox()
        self._verify_duration.setRange(1, 300)
        self._verify_duration.setSuffix(" seconds")
        self._verify_duration.setValue(60)
        self._verify_duration.setAccessibleName("Independent verification total budget in seconds")
        repair_controls.addWidget(self._verify_duration)
        self._verify_btn = QPushButton("Run independent verification")
        self._verify_btn.clicked.connect(self.verify_repair)
        repair_controls.addWidget(self._verify_btn)
        self._real_repair_btn = QPushButton("Real repair unavailable")
        self._real_repair_btn.setEnabled(False)
        # There is deliberately no signal connection or real-repair handler.
        repair_controls.addWidget(self._real_repair_btn)
        layout.addLayout(repair_controls)
        self._repair_preview = QPlainTextEdit()
        self._repair_preview.setReadOnly(True)
        self._repair_preview.setPlaceholderText("SIMULATION ONLY. No repair or verification has run.")
        layout.addWidget(self._repair_preview, 1)

        self._display_timer = QTimer(self)
        self._display_timer.setInterval(200)
        self._display_timer.timeout.connect(self._tick_display)
        self._update_controls()

    @property
    def is_running(self):
        return self._worker is not None

    def _update_controls(self):
        idle = not self.is_running and not self._closing
        baseline = (self._report is not None and self._active_request is not None
                    and self._report.status in {"completed", "deadline"}
                    and not getattr(self._report, "cleanup_errors", [])
                    and not getattr(self._report, "output_errors", []))
        self._start_btn.setEnabled(idle)
        self._cancel_btn.setEnabled(self.is_running and not self._worker.cancel_event.is_set())
        self._duration.setEnabled(idle)
        self._website_input.setEnabled(idle)
        self._save_btn.setEnabled(idle and (self._report is not None or self._repair_record is not None))
        self._simulate_btn.setEnabled(idle and baseline and self._repair_controller is None)
        self._verify_duration.setEnabled(idle and baseline and self._repair_controller is None)
        pending = (self._repair_record or {}).get("verification", {}).get("status") == "pending"
        self._verify_btn.setEnabled(idle and self._repair_controller is not None and pending)
        self._real_repair_btn.setEnabled(False)

    def _source_is_current(self):
        source = self.sender()
        return source is None or source is self._worker

    def _start_worker(self, worker, kind):
        self._worker, self._worker_kind = worker, kind
        self._update_controls()
        self._progress.setValue(0)
        connection = Qt.ConnectionType.QueuedConnection
        worker.progress.connect(self._on_progress, connection)
        worker.report_ready.connect(self._on_worker_result, connection)
        worker.failed.connect(self._on_error, connection)
        worker.finished.connect(self._on_worker_finished, connection)
        self._display_timer.start()
        worker.start()

    def start_session(self):
        if self._closing or self.is_running:
            return
        try:
            url = self._website_input.text().strip()
            request = SessionRequest(
                duration_seconds=self._duration.value(),
                ping_targets=tuple(self._config.public_ping_targets),
                dns_hostnames=tuple(self._config.dns_test_hostnames),
                extended_diagnostics=True, website_urls=(url,) if url else ())
            worker = SessionWorker(request, self)
        except (TypeError, ValueError) as exc:
            self._state.setText(f"Cannot start session: {type(exc).__name__}")
            return
        self._active_request, self._report = request, None
        self._repair_controller = self._repair_record = None
        self._preview.clear()
        self._repair_preview.clear()
        self._state.setText("Collecting read-only multi-protocol evidence...")
        self._start_worker(worker, "diagnosis")

    def cancel_session(self):
        if self._worker is None:
            return
        self._worker.cancel()
        self._cancel_btn.setEnabled(False)
        self._state.setText("Cancelling: stopping owned probes and preparing partial evidence...")

    def _tick_display(self):
        worker = self._worker
        if worker is None:
            return
        budget = 60 if self._worker_kind == "simulate" else worker.request.duration_seconds
        elapsed = max(0.0, time.monotonic() - worker.started_monotonic)
        self._remaining.setText(f"Remaining: {math.ceil(max(0.0, budget - elapsed))} seconds")
        self._progress.setValue(min(99, int(elapsed * 100 / budget)))

    @Slot(object)
    def _on_progress(self, progress):
        if not self._source_is_current() or self._worker is None:
            return
        self._remaining.setText(f"Remaining: {max(0, math.ceil(progress.remaining_seconds))} seconds")
        if not self._worker.cancel_event.is_set():
            self._state.setText(f"{progress.phase}: {progress.completed_count} evidence items collected.")

    @Slot(object)
    def _on_worker_result(self, value):
        if not self._source_is_current() or self._worker is None:
            return
        if self._worker_kind == "diagnosis":
            self._on_report(value)
        else:
            self._on_repair_result(value)

    def _on_report(self, report):
        try:
            safe = _redacted_snapshot(report.to_dict())
            rendered = format_session_report(safe)
        except Exception as exc:
            self._report = None
            self._set_error(f"Report presentation error: {type(exc).__name__}")
            return
        self._report = report  # Raw current-session evidence is retained only for comparison.
        self._preview.setPlainText(rendered)
        self._state.setText(f"Session {report.status}. Conclusions are limited to this observation window.")
        self._save_btn.setEnabled(False)

    def _on_repair_result(self, record):
        try:
            raw = json.loads(json.dumps(record, allow_nan=False))
            rendered = format_repair_record(_redacted_snapshot(raw))
        except Exception as exc:
            self._repair_record = None
            self._set_error(f"Simulation result unavailable: {type(exc).__name__}")
            return
        self._repair_record = raw
        self._repair_preview.setPlainText(rendered)
        self._state.setText("SIMULATION ONLY. No real DNS cache clearing; independent observations are separate.")
        self._save_btn.setEnabled(False)

    def _set_error(self, message):
        self._state.setText(message)
        self._save_btn.setEnabled(False)

    @Slot(str)
    def _on_error(self, message):
        if self._source_is_current():
            self._set_error("Tool error: " + message)

    @Slot()
    def _on_worker_finished(self):
        if not self._source_is_current() or self._worker is None:
            return
        worker, kind = self._worker, self._worker_kind
        self._worker = self._worker_kind = None
        self._display_timer.stop()
        self._progress.setValue(100)
        self._update_controls()
        if kind == "diagnosis" and self._report is not None:
            remaining = max(0.0, self._report.budget_seconds - self._report.duration_seconds)
            self._remaining.setText(f"Remaining at finish: {math.ceil(remaining)} seconds")
        elif kind in {"simulate", "verify"}:
            self._remaining.setText("Worker finished. No real repair was performed.")
        worker.deleteLater()
        self.cleanup_finished.emit()

    def simulate_repair(self):
        if (self.is_running or self._closing or self._repair_controller is not None
                or not self._simulate_btn.isEnabled()):
            return
        # Only this explicit action creates a repair request. No native executor
        # is imported, selected from settings, or accepted through this interface.
        from losshound.core.repair import RepairController, RepairRequest, SimulatedRepairExecutor
        try:
            controller = RepairController(
                RepairRequest(verification_seconds=self._verify_duration.value()),
                self._active_request, self._report, executor=SimulatedRepairExecutor())
            offer = controller.prepare()
            answer = QMessageBox.question(
                self, "Confirm simulation only",
                offer["impact"] + "\n\n" + offer["no_restore_warning"] + "\n\n" + offer["permissions"]
                + f"\nIndependent verification budget: {offer['verification_seconds']} seconds."
                + "\n\nAcknowledge the impact and inability to restore exactly, and run the simulation?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            accepted = answer == QMessageBox.StandardButton.Yes
            controller.confirm(offer["request_id"], accepted=accepted,
                               acknowledge_impact=accepted, acknowledge_no_restore=accepted)
            self._repair_controller = controller
            if not accepted:
                self._on_repair_result(controller.record())
                self._update_controls()
                return
            worker = SimulatedRepairWorker(controller, operation="simulate", parent=self)
        except Exception as exc:
            self._set_error(f"Cannot prepare simulation: {type(exc).__name__}")
            self._update_controls()
            return
        self._state.setText("SIMULATION ONLY: running the separately confirmed data-only operation...")
        self._start_worker(worker, "simulate")

    def verify_repair(self):
        if self.is_running or self._closing or not self._verify_btn.isEnabled():
            return
        try:
            worker = SimulatedRepairWorker(self._repair_controller, operation="verify", parent=self)
        except Exception as exc:
            self._set_error(f"Cannot start verification: {type(exc).__name__}")
            return
        self._state.setText("Read-only independent verification. No repair will run.")
        self._start_worker(worker, "verify")

    def begin_shutdown(self):
        self._closing = True
        self.cancel_session()
        self._update_controls()
        return not self.is_running

    def wait_for_shutdown(self, timeout_ms):
        self.begin_shutdown()
        worker = self._worker
        return worker is None or worker.wait(max(0, timeout_ms))

    def _save_report(self):
        if self.is_running or self._closing or (self._report is None and self._repair_record is None):
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save redacted evidence", "diagnostic-evidence.json", "JSON (*.json)")
        if not filename:
            return
        try:
            raw = self._repair_record if self._repair_record is not None else self._report.to_dict()
            prepared = json.dumps(_redacted_snapshot(raw), ensure_ascii=False, indent=2, allow_nan=False)
            Path(filename).write_text(prepared, encoding="utf-8")
        except (OSError, TypeError, ValueError):
            QMessageBox.warning(self, "Save failed", "The redacted evidence could not be saved.")
