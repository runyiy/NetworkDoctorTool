"""Bounded diagnostic presentation with local languages; simulation only."""
from __future__ import annotations

import json
import math
import time
from pathlib import Path

from PySide6.QtCore import QTimer, Signal, Slot, Qt
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from losshound.core.config import AppConfig
from losshound.core.session import SessionRequest
from losshound.core.session_report import redact_report
from losshound.core.session_summary import build_user_summary
from losshound.gui.i18n import (
    LANGUAGES, has_message, install_standard_button_translator,
    load_language_preference, save_language_preference, translate,
)
from losshound.gui.session_worker import SessionWorker, SimulatedRepairWorker
from losshound.gui.theme import button_style


def _redacted_snapshot(raw):
    snapshot = dict(raw)
    omitted = snapshot.pop("baseline_request", None) is not None
    safe = redact_report(snapshot)
    if omitted:
        safe["redaction"]["removed_fields"].append("baseline_request")
    return safe


def _refs(values, language="en"):
    refs = ["E" + str(value) for value in values or [] if type(value) is int and value > 0]
    return ", ".join(refs) if refs else translate(language, "refs.none")


def _code(language, prefix, value, fallback="unknown"):
    key = prefix + "." + value if type(value) is str else ""
    return translate(language, key if has_message(key) else prefix + "." + fallback)


def _safe_parameters(message):
    # Summary parameters are counts, never targets, identities or exception text.
    return {key: value for key, value in (message.get("params") or {}).items()
            if type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 1000000}


def format_user_summary(model, language="zh-CN"):
    """Render the original-facts view model without deriving network verdicts."""
    t = lambda key, **params: translate(language, key, **params)
    lines = [t("summary.heading.overall"),
             t(model["overall"]["message_id"], **_safe_parameters(model["overall"]))]
    coverage = model.get("coverage") or {}
    for key in coverage.get("message_ids", [coverage.get("message_id")]):
        if key:
            lines.append(t(key, **_safe_parameters(coverage)))
    for reason in coverage.get("reason_codes") or []:
        if reason == "reason_unavailable":
            lines.append(t("detail.unfinished_unknown"))
        elif reason != "multiple_epochs":
            lines.append(t("summary.coverage.reason", reason=_code(language, "reason", reason)))
    lines += ["", t("summary.heading.parts")]
    groups = model.get("groups") or []
    website_items = [item for group in groups for item in group.get("observations", [])
                     if item.get("part") == "website"]
    all_websites_untested = bool(website_items) and all(
        item.get("message_id") == "summary.website.not_tested" for item in website_items)
    supported = []
    for group in groups:
        family = group.get("family") if group.get("family") in {"IPv4", "IPv6"} else "?"
        epoch = group.get("epoch_id") if type(group.get("epoch_id")) is int else "?"
        lines.append(t("summary.group" if type(group.get("epoch_id")) is int else "summary.group.unknown", epoch=epoch, family=family))
        for item in group.get("observations") or []:
            if item.get("part") == "website" and all_websites_untested:
                continue
            lines.append("  " + t("summary.part." + item["part"]) + ": " +
                         t(item["message_id"], **_safe_parameters(item)))
            if any(item.get("params", {}).get(key, 0) for key in ("tool_errors", "not_tested", "excluded")):
                lines.append("    " + t("summary.observation.coverage", **_safe_parameters(item)))
        supported += [(group, item) for item in group.get("findings") or []
                      if item.get("scope") != "unknown"]
    if all_websites_untested:
        lines.append(t("summary.part.website") + ": " + t("summary.website.not_tested"))
    lines += ["", t("summary.heading.cause")]
    if not supported:
        lines.append(t("summary.no_cause"))
    for group, finding in supported:
        lines.append(t("summary.group", epoch=group["epoch_id"], family=group["family"]) + ": " +
                     t(finding.get("message_id")) + " (" +
                     _code(language, "confidence", finding.get("confidence")) + ")")
    lines += ["", t("summary.heading.next")]
    for index, item in enumerate((model.get("next_steps") or [])[:3], 1):
        context = ""
        if type(item.get("epoch_id")) is int and item.get("family") in {"IPv4", "IPv6"}:
            context = t("summary.group", epoch=item["epoch_id"], family=item["family"]) + ": "
        lines.append(str(index) + ". " + context + t(item["message_id"], **_safe_parameters(item)))
    return "\n".join(lines)


def _message_details(lines, finding, language):
    t = lambda key, **params: translate(language, key, **params)
    lines.append(t(finding.get("message_id")))
    lines.append(t("detail.support", refs=_refs(finding.get("supporting_evidence", finding.get("evidence_sequences")), language)))
    lines.append(t("detail.counter", refs=_refs(finding.get("contradictions"), language)))
    for label, ids_key, old_key in (
            ("detail.alternative", "alternative_message_ids", "alternatives"),
            ("detail.limitation", "limitation_message_ids", "limitations"),
            ("detail.advice", "recommendation_message_ids", "recommendations")):
        ids = finding.get(ids_key) or []
        if ids:
            lines.extend(t(label, text=t(key)) for key in ids)
        elif finding.get(old_key):
            # Legacy text has no stable language/semantic ID. Never parse or echo
            # arbitrary diagnostic text, in either language.
            lines.append(t(label, text=t("detail.unavailable")))


def format_session_report(snapshot, language="en"):
    """Technical presentation of an already-redacted report, never diagnosis."""
    t = lambda key, **params: translate(language, key, **params)
    lines = [t("detail.session", status=_code(language, "status", snapshot.get("status"))), t("detail.caution")]
    rows = snapshot.get("evidence") or []
    for family in ("IPv4", "IPv6"):
        lines.append("\n" + t("detail.checks", family=family))
        for row in rows:
            if row.get("protocol") != "network":
                continue
            data = row.get("data") or {}
            summary = ((data.get("diagnostics") or {}).get("families") or {}).get(family) or {}
            qualifier = t("detail.confirmed" if row.get("comparable") is True else "detail.not_comparable")
            lines.append(t("detail.snapshot", sequence=row.get("sequence", "?"),
                           status=_code(language, "status", summary.get("status")), qualifier=qualifier))
            addresses = [str(item.get("address", "?")) for item in summary.get("addresses", [])]
            lines.append(t("detail.addresses", addresses=", ".join(addresses) if addresses else t("detail.no_addresses")))
            route = summary.get("default_route")
            if isinstance(route, dict):
                lines.append(t("detail.gateway", gateway=str(route.get("gateway", "?"))))
                lines.append(t("detail.source", source=str(route.get("source_address_candidate", "?"))))
            else:
                lines.append(t("detail.route_unknown"))
        for name, protocols in (("DNS", {"dns", "dns6"}), ("ICMP", {"icmp"}),
                                ("TCP", {"tcp", "tcp6"}), ("HTTP(S)", {"http", "http6", "https", "https6"})):
            selected = [row for row in rows if row.get("family") == family and row.get("protocol") in protocols]
            if not selected:
                lines.append(t("detail.protocol_missing", protocol=name))
            for row in selected:
                data = row.get("data") or {}
                outcome = _code(language, "outcome", row.get("outcome"), "unknown")
                note = "" if row.get("comparable") is True else t("detail.not_comparable_note")
                code = data.get("http_status")
                if type(code) is int and 100 <= code <= 599:
                    note += t("detail.http_note", code=code)
                if data.get("error_category"):
                    note += t("detail.category_note", category=_code(language, "reason", data["error_category"]))
                lines.append(f"  E{row.get('sequence', '?')} {name} {row.get('target', '')}: {outcome}{note}")
    lines.append("\n" + t("detail.faults"))
    analysis = snapshot.get("analysis") or {}
    if not analysis.get("findings"):
        lines.append(t("detail.no_finding"))
    for finding in analysis.get("findings") or []:
        family = finding.get("family") if finding.get("family") in {"IPv4", "IPv6"} else "?"
        epoch = finding.get("epoch_id") if type(finding.get("epoch_id")) is int else "?"
        lines.append(t("summary.group", epoch=epoch, family=family))
        lines.append("\n" + t("detail.confidence", scope=_code(language, "scope", finding.get("scope")),
                              confidence=_code(language, "confidence", finding.get("confidence"))))
        _message_details(lines, finding, language)
    for item in analysis.get("intermittent") or []:
        family = item.get("family") if item.get("family") in {"IPv4", "IPv6"} else "?"
        epoch = item.get("epoch_id") if type(item.get("epoch_id")) is int else "?"
        lines.append(t("summary.group", epoch=epoch, family=family))
        lines.append("\n" + t("detail.intermittent"))
        _message_details(lines, item, language)
    limit_ids = analysis.get("limitation_message_ids") or []
    if limit_ids:
        lines.extend(t("detail.limitation", text=t(key)) for key in limit_ids)
    elif analysis.get("limitations"):
        lines.append(t("detail.limitation", text=t("detail.unavailable")))
    if snapshot.get("incomplete"):
        lines += ["\n" + t("detail.unfinished"), t("detail.unfinished_unknown")]
    if snapshot.get("cleanup_errors") or snapshot.get("output_errors"):
        lines.append(t("detail.cleanup_errors"))
    lines.append("\n" + t("detail.refs_session"))
    return "\n".join(lines)


def format_repair_record(snapshot, language="en", *, include_details=True):
    """Only simulation records are presentable by this GUI."""
    request, execution = snapshot.get("request") or {}, snapshot.get("execution") or {}
    if request.get("execution_mode") != "simulation" or request.get("simulation_only") is not True:
        raise ValueError("Native repair records are unavailable in this GUI")
    if execution.get("simulation_only") is not True or execution.get("system_change_performed") is not False:
        raise ValueError("A simulation record must not claim a real system change")
    if request.get("action") != "flush_windows_dns_cache":
        raise ValueError("Unknown simulation action")
    t = lambda key, **params: translate(language, key, **params)
    verification, comparison = snapshot.get("verification") or {}, snapshot.get("comparison") or {}
    lines = [t("repair.heading")]
    if include_details:
        lines += [t("repair.plan"), t("repair.impact"), t("repair.no_restore")]
    for label, value in (("repair.confirmation", (snapshot.get("confirmation") or {}).get("status")),
                         ("repair.execution", execution.get("status")),
                         ("repair.verification", verification.get("status")),
                         ("repair.change", comparison.get("status"))):
        lines.append(t(label, status=_code(language, "status", value)))
    lines.append(t("repair.causality"))
    for value in comparison.get("reasons", []):
        key = "repair.reason." + value if type(value) is str else ""
        lines.append(t("repair.reason", reason=t(key)))
    if include_details:
        for item in comparison.get("comparisons") or []:
            family = item.get("family") if item.get("family") in {"IPv4", "IPv6"} else "?"
            protocol = item.get("protocol") if item.get("protocol") in {"icmp", "dns", "dns6", "tcp", "tcp6", "http", "http6", "https", "https6"} else "?"
            lines.append(f"{family} {protocol}: " + _code(language, "repair.change", item.get("change"), "inconclusive"))
            lines.append(t("repair.before_after", before=_refs(item.get("before_sequences"), language), after=_refs(item.get("after_sequences"), language)))
        lines.extend(t("detail.limitation", text=t(key)) for key in (
            "repair.limit.system", "repair.limit.continuity", "repair.limit.cause", "repair.limit.cache"))
        if verification.get("report") is not None:
            lines += ["\n" + t("repair.evidence"), format_session_report(verification["report"], language)]
    return "\n".join(lines)


_ERROR_KINDS = {"Exception", "ValueError", "TypeError", "OSError", "RuntimeError", "PermissionError", "TimeoutError", "AssertionError", "MemoryError"}


def _error_kind(value):
    return value if type(value) is str and value in _ERROR_KINDS else "Exception"


class SessionPanel(QWidget):
    cleanup_finished = Signal()
    language_changed = Signal(str)

    def __init__(self, config: AppConfig, duration_seconds: int = 60, parent=None):
        super().__init__(parent)
        SessionRequest(duration_seconds=duration_seconds)
        self._config = config
        self._worker = self._worker_kind = None
        self._report = self._active_request = None
        self._repair_controller = self._repair_record = None
        self._summary_model = self._verification_summary_model = None
        self._closing = False
        self._language = load_language_preference()
        self._state_message, self._state_parameters = "state.ready", {}
        self._remaining_message, self._remaining_parameters = "remaining.current", {"seconds": duration_seconds}
        self._preference_saved = True
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 18, 24, 18)
        language_row = QHBoxLayout()
        self._title = QLabel()
        self._title.setObjectName("section-title")
        language_row.addWidget(self._title)
        language_row.addStretch()
        self._language_label = QLabel()
        language_row.addWidget(self._language_label)
        self._language_combo = QComboBox()
        self._language_combo.addItem("简体中文", "zh-CN")
        self._language_combo.addItem("English", "en")
        self._language_combo.currentIndexChanged.connect(self._on_language_selected)
        language_row.addWidget(self._language_combo)
        layout.addLayout(language_row)
        self._description = QLabel()
        self._description.setWordWrap(True)
        layout.addWidget(self._description)
        self._preference_note = QLabel()
        self._preference_note.setWordWrap(True)
        self._preference_note.hide()
        layout.addWidget(self._preference_note)
        websites = QHBoxLayout()
        self._website_label = QLabel()
        websites.addWidget(self._website_label)
        self._website_input = QLineEdit()
        self._website_input.setPlaceholderText("https://example.com/")
        websites.addWidget(self._website_input)
        layout.addLayout(websites)
        controls = QHBoxLayout()
        self._budget_label = QLabel()
        controls.addWidget(self._budget_label)
        self._duration = QSpinBox()
        self._duration.setRange(1, 300)
        self._duration.setValue(duration_seconds)
        controls.addWidget(self._duration)
        self._start_btn = QPushButton()
        self._start_btn.setStyleSheet(button_style("primary"))
        self._start_btn.clicked.connect(self.start_session)
        controls.addWidget(self._start_btn)
        self._cancel_btn = QPushButton()
        self._cancel_btn.clicked.connect(self.cancel_session)
        controls.addWidget(self._cancel_btn)
        controls.addStretch()
        self._save_btn = QPushButton()
        self._save_btn.clicked.connect(self._save_report)
        controls.addWidget(self._save_btn)
        layout.addLayout(controls)
        self._remaining = QLabel()
        layout.addWidget(self._remaining)
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        layout.addWidget(self._progress)
        self._state = QLabel()
        self._state.setWordWrap(True)
        layout.addWidget(self._state)
        self._summary_label = QLabel()
        layout.addWidget(self._summary_label)
        self._summary_preview = QPlainTextEdit()
        self._summary_preview.setReadOnly(True)
        self._summary_preview.setMinimumHeight(130)
        layout.addWidget(self._summary_preview, 1)
        self._details_btn = QPushButton()
        self._details_btn.setCheckable(True)
        self._details_btn.setChecked(False)
        self._details_btn.toggled.connect(self._toggle_details)
        layout.addWidget(self._details_btn)
        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setMaximumHeight(220)
        self._preview.hide()
        layout.addWidget(self._preview, 1)
        self._repair_note = QLabel()
        self._repair_note.setWordWrap(True)
        layout.addWidget(self._repair_note)
        repair_controls = QHBoxLayout()
        self._simulate_btn = QPushButton()
        self._simulate_btn.clicked.connect(self.simulate_repair)
        repair_controls.addWidget(self._simulate_btn)
        self._verify_budget_label = QLabel()
        repair_controls.addWidget(self._verify_budget_label)
        self._verify_duration = QSpinBox()
        self._verify_duration.setRange(1, 300)
        self._verify_duration.setValue(60)
        repair_controls.addWidget(self._verify_duration)
        self._verify_btn = QPushButton()
        self._verify_btn.clicked.connect(self.verify_repair)
        repair_controls.addWidget(self._verify_btn)
        self._real_repair_btn = QPushButton()
        self._real_repair_btn.setEnabled(False)
        # No signal connection or real-repair handler is available.
        repair_controls.addWidget(self._real_repair_btn)
        layout.addLayout(repair_controls)
        self._repair_preview = QPlainTextEdit()
        self._repair_preview.setReadOnly(True)
        self._repair_preview.setMaximumHeight(110)
        layout.addWidget(self._repair_preview)
        self._display_timer = QTimer(self)
        self._display_timer.setInterval(200)
        self._display_timer.timeout.connect(self._tick_display)
        self._retranslate()
        self._update_controls()

    @property
    def language(self):
        return self._language

    def _t(self, key, **params):
        return translate(self._language, key, **params)

    def set_language(self, language, *, persist=True):
        if language not in LANGUAGES:
            raise ValueError("Unsupported interface language")
        self._language = language
        if persist:
            self._preference_saved = save_language_preference(language)
        self._retranslate()
        self.language_changed.emit(language)

    def _on_language_selected(self, index):
        self.set_language(self._language_combo.itemData(index))

    def _retranslate(self):
        install_standard_button_translator(self._language)
        for widget, key in (
                (self._title, "ui.section"), (self._language_label, "ui.language"),
                (self._description, "ui.description"), (self._website_label, "ui.website"),
                (self._budget_label, "ui.budget"), (self._start_btn, "ui.start"),
                (self._cancel_btn, "ui.cancel"), (self._save_btn, "ui.save"),
                (self._summary_label, "ui.summary"), (self._repair_note, "ui.repair.note"),
                (self._simulate_btn, "ui.simulate"), (self._verify_budget_label, "ui.verify.budget"),
                (self._verify_btn, "ui.verify"), (self._real_repair_btn, "ui.real.disabled")):
            widget.setText(self._t(key))
        blocked = self._language_combo.blockSignals(True)
        self._language_combo.setCurrentIndex(LANGUAGES.index(self._language))
        self._language_combo.blockSignals(blocked)
        self._language_combo.setAccessibleName(self._t("ui.language"))
        self._website_input.setAccessibleName(self._t("ui.website.accessible"))
        self._duration.setAccessibleName(self._t("ui.budget.accessible"))
        self._verify_duration.setAccessibleName(self._t("ui.verify.accessible"))
        self._duration.setSuffix(self._t("ui.seconds"))
        self._verify_duration.setSuffix(self._t("ui.seconds"))
        self._summary_preview.setPlaceholderText(self._t("ui.summary.placeholder"))
        self._preview.setPlaceholderText(self._t("ui.details.placeholder"))
        self._repair_preview.setPlaceholderText(self._t("ui.repair.placeholder"))
        self._render_status()
        self._remaining.setText(self._t(self._remaining_message, **self._remaining_parameters))
        self._preference_note.setText(self._t("ui.preference.failed"))
        self._preference_note.setVisible(not self._preference_saved)
        self._toggle_details(self._details_btn.isChecked())
        self._render_results()

    def _toggle_details(self, expanded):
        self._preview.setVisible(bool(expanded))
        self._details_btn.setText(self._t("ui.details.hide" if expanded else "ui.details.show"))

    def _render_status(self):
        params = dict(self._state_parameters)
        if "status_code" in params:
            params["status"] = _code(self._language, "status", params["status_code"])
        self._state.setText(self._t(self._state_message, **params))

    def _set_status(self, key, **params):
        self._state_message, self._state_parameters = key, params
        self._render_status()

    def _set_remaining(self, key, **params):
        self._remaining_message, self._remaining_parameters = key, params
        self._remaining.setText(self._t(key, **params))

    def _render_results(self):
        if self._summary_model is not None:
            self._summary_preview.setPlainText(format_user_summary(self._summary_model, self._language))
        if self._report is not None:
            self._preview.setPlainText(format_session_report(_redacted_snapshot(self._report.to_dict()), self._language))
        if self._repair_record is not None:
            safe = _redacted_snapshot(self._repair_record)
            brief = format_repair_record(safe, self._language, include_details=False)
            if self._verification_summary_model is not None:
                brief += "\n\n" + self._t("repair.summary.heading") + "\n" + format_user_summary(self._verification_summary_model, self._language)
            self._repair_preview.setPlainText(brief)
            baseline = self._preview.toPlainText()
            self._preview.setPlainText(baseline + "\n\n" + format_repair_record(safe, self._language))
        else:
            self._repair_preview.setPlainText(self._t("ui.repair.placeholder"))

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
        self._language_combo.setEnabled(not self._closing)
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
        try:
            worker.start()
        except Exception as exc:
            self._set_error("state.worker.error", kind=_error_kind(type(exc).__name__))
            if worker.isRunning():
                worker.cancel()
            else:
                self._worker = self._worker_kind = None
                self._display_timer.stop()
                self._set_remaining("remaining.not_started")
                worker.deleteLater()
                self.cleanup_finished.emit()
            self._update_controls()

    def start_session(self):
        if self._closing or self.is_running:
            return
        try:
            url = self._website_input.text().strip()
            request = SessionRequest(
                duration_seconds=self._duration.value(), ping_targets=tuple(self._config.public_ping_targets),
                dns_hostnames=tuple(self._config.dns_test_hostnames),
                extended_diagnostics=True, website_urls=(url,) if url else ())
            worker = SessionWorker(request, self)
        except (TypeError, ValueError) as exc:
            self._set_status("state.start.error", kind=_error_kind(type(exc).__name__))
            return
        self._active_request, self._report = request, None
        self._repair_controller = self._repair_record = None
        self._summary_model = self._verification_summary_model = None
        self._summary_preview.clear()
        self._preview.clear()
        self._repair_preview.clear()
        self._set_status("state.collecting")
        self._start_worker(worker, "diagnosis")

    def cancel_session(self):
        if self._worker is None:
            return
        self._worker.cancel()
        self._cancel_btn.setEnabled(False)
        self._set_status("state.cancelling")

    def _tick_display(self):
        worker = self._worker
        if worker is None:
            return
        budget = 60 if self._worker_kind == "simulate" else worker.request.duration_seconds
        elapsed = max(0.0, time.monotonic() - worker.started_monotonic)
        self._set_remaining("remaining.current", seconds=math.ceil(max(0.0, budget - elapsed)))
        self._progress.setValue(min(99, int(elapsed * 100 / budget)))

    @Slot(object)
    def _on_progress(self, progress):
        if not self._source_is_current() or self._worker is None:
            return
        self._set_remaining("remaining.current", seconds=max(0, math.ceil(progress.remaining_seconds)))
        if not self._worker.cancel_event.is_set():
            # Native phases can include unsanitized target labels. Display only
            # this typed count, never raw phase text or exception strings.
            count = progress.completed_count if type(progress.completed_count) is int else 0
            self._set_status("state.progress", count=max(0, count))

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
            raw = report.to_dict()
            model = build_user_summary(raw)
            # Validate rendering before accepting the current report.
            format_session_report(_redacted_snapshot(raw), self._language)
            format_user_summary(model, self._language)
        except Exception as exc:
            self._report = None
            self._set_error("state.report.error", kind=_error_kind(type(exc).__name__))
            return
        self._report, self._summary_model = report, model
        self._render_results()
        self._set_status("state.session", status_code=report.status)
        self._save_btn.setEnabled(False)

    def _on_repair_result(self, record):
        try:
            raw = json.loads(json.dumps(record, allow_nan=False))
            format_repair_record(_redacted_snapshot(raw), self._language)
            verification_report = (raw.get("verification") or {}).get("report")
            model = build_user_summary(verification_report) if verification_report is not None else None
        except Exception as exc:
            self._repair_record = None
            self._set_error("state.repair.error", kind=_error_kind(type(exc).__name__))
            return
        self._repair_record, self._verification_summary_model = raw, model
        self._render_results()
        self._set_status("state.simulation")
        self._save_btn.setEnabled(False)

    def _set_error(self, key, **params):
        self._set_status(key, **params)
        self._save_btn.setEnabled(False)

    @Slot(str)
    def _on_error(self, message):
        if self._source_is_current():
            self._set_error("state.tool.error", kind=_error_kind(message))

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
            self._set_remaining("remaining.finished", seconds=math.ceil(remaining))
        elif kind in {"simulate", "verify"}:
            self._set_remaining("remaining.worker_finished")
        worker.deleteLater()
        self.cleanup_finished.emit()

    def simulate_repair(self):
        if (self.is_running or self._closing or self._repair_controller is not None
                or not self._simulate_btn.isEnabled()):
            return
        from losshound.core.repair import RepairController, RepairRequest, SimulatedRepairExecutor
        try:
            controller = RepairController(RepairRequest(verification_seconds=self._verify_duration.value()),
                self._active_request, self._report, executor=SimulatedRepairExecutor())
            offer = controller.prepare()
            answer = QMessageBox.question(self, self._t("dialog.confirm.title"),
                self._t("dialog.confirm.body", seconds=offer["verification_seconds"]),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            # A modal dialog has a nested event loop. A late answer after
            # shutdown started cannot create new work.
            if self._closing:
                return
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
            self._set_error("state.simulate.error", kind=_error_kind(type(exc).__name__))
            self._update_controls()
            return
        self._set_status("state.simulating")
        self._start_worker(worker, "simulate")

    def verify_repair(self):
        if self.is_running or self._closing or not self._verify_btn.isEnabled():
            return
        try:
            worker = SimulatedRepairWorker(self._repair_controller, operation="verify", parent=self)
        except Exception as exc:
            self._set_error("state.verify.error", kind=_error_kind(type(exc).__name__))
            return
        self._set_status("state.verifying")
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
        filename, _ = QFileDialog.getSaveFileName(self, self._t("dialog.save.title"),
                                                 "diagnostic-evidence.json", "JSON (*.json)")
        if not filename:
            return
        try:
            raw = self._repair_record if self._repair_record is not None else self._report.to_dict()
            prepared = json.dumps(_redacted_snapshot(raw), ensure_ascii=False, indent=2, allow_nan=False)
            Path(filename).write_text(prepared, encoding="utf-8")
        except (OSError, TypeError, ValueError):
            QMessageBox.warning(self, self._t("dialog.save.failed.title"), self._t("dialog.save.failed.body"))
