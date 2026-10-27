"""GUI wiring contracts using inert Qt and current-session memory-only fakes.

These tests do not launch Qt, Windows commands or network probes. They verify
code integration; real GUI rendering and Windows acceptance remain separate.
"""
from __future__ import annotations

import json
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from losshound.core import repair, session_context, session_process
from losshound.core.dns_cache import WindowsDnsCacheExecutor
from losshound.core.session import (
    NetworkEpoch, ProbeEvidence, ProbeOutcome, SessionController,
    SessionReport, SessionRequest,
)
from test_s1_gui import _gui_modules
from test_session_context_s1 import StableObserver
from test_session_s1 import FakeClock, FakeProvider


def _config():
    return types.SimpleNamespace(
        public_ping_targets=["1.1.1.1"], dns_test_hostnames=["private.example"],
        lan_discovery_firewall_enabled=True, auto_benchmark_interval_minutes=1,
        close_to_tray=True,
    )


def _baseline(seconds=60):
    request = SessionRequest(
        seconds, ping_targets=("1.1.1.1",), dns_hostnames=("private.example",),
        extended_diagnostics=True, ipv6_targets=(), tcp_targets=("1.1.1.1:443",),
        website_urls=("https://private.example/private?token=secret",),
    )
    report = SessionReport(
        "deadline", seconds, duration_seconds=seconds, schema_version=3,
        epochs=[NetworkEpoch(1, "raw-network-identity", 0, {
            "identity": "raw-network-identity", "gateway": "192.168.37.1",
            "wifi": [{"ssid": "Private SSID"}],
        })],
        evidence=[
            ProbeEvidence(1, "2026-10-26T00:00:00Z", 1, 1.1, 1, "dns6",
                "IPv6", "private.example", ProbeOutcome.NOT_ATTEMPTED,
                comparable=False, data={"context_status": "UNKNOWN", "role": "dns"}),
            ProbeEvidence(2, "2026-10-26T00:00:01Z", 2, 2.1, 1, "tcp",
                "IPv4", "192.168.37.22:443", ProbeOutcome.EXECUTION_ERROR,
                error="private native stderr", comparable=False,
                data={"context_status": "UNKNOWN", "role": "target",
                      "stdout": "private stdout"}),
            ProbeEvidence(3, "2026-10-26T00:00:02Z", 3, 3.1, 1, "https",
                "IPv4", "https://private.example/private?token=secret",
                ProbeOutcome.SUCCESS, comparable=True,
                data={"context_status": "IDENTIFIED", "role": "target",
                      "resolved_ip": "192.168.37.22", "http_status": 200,
                      "tls_verified": True}),
        ],
        analysis={
            "schema_version": 1,
            "findings": [{
                "scope": "unknown", "family": "IPv4", "epoch_id": 1,
                "confidence": "insufficient", "evidence_sequences": [2],
                "supporting_evidence": [2], "contradictions": [3],
                "explanation": "Tool error is not network loss at private.example",
                "limitations": ["UNKNOWN context is not a health result"],
                "alternatives": ["The probe tool may be unavailable"],
                "recommendations": ["Repeat the read-only observation when possible"],
            }],
            "intermittent": [], "limitations": ["Only current-session evidence"],
            "coverage": {"read_only": True},
        },
    )
    return request, report


def _confirmed_controller(*, seconds=60):
    request, report = _baseline(seconds)
    executor = repair.SimulatedRepairExecutor()
    controller = repair.RepairController(
        repair.RepairRequest(verification_seconds=seconds),
        request, report, executor=executor,
    )
    offer = controller.prepare()
    controller.confirm(offer["request_id"], accepted=True,
                       acknowledge_impact=True, acknowledge_no_restore=True)
    return controller, executor


class SimulatedRepairWorkerContracts(unittest.TestCase):
    def test_simulation_result_does_not_start_verification_or_native_collection(self):
        controller, executor = _confirmed_controller()
        clock = FakeClock()
        with _gui_modules(real_core=True) as (worker_module, _panel, _window), \
             patch.object(worker_module, "time", types.SimpleNamespace(monotonic=clock)), \
             patch.object(session_process, "WindowsProbeProvider",
                          side_effect=AssertionError("No implicit probes")) as provider, \
             patch.object(session_context, "WindowsContextObserver",
                          side_effect=AssertionError("No implicit observer")) as observer:
            worker = worker_module.SimulatedRepairWorker(controller)
            results, failures = [], []
            worker.report_ready.connect(results.append)
            worker.failed.connect(failures.append)
            worker.run()
        self.assertEqual(failures, [])
        self.assertEqual(executor.calls, 1)
        self.assertEqual(results[0]["execution"]["status"], "simulated_success")
        self.assertIs(results[0]["execution"]["system_change_performed"], False)
        self.assertEqual(results[0]["verification"]["status"], "pending")
        self.assertEqual(results[0]["comparison"]["status"], "inconclusive")
        provider.assert_not_called()
        observer.assert_not_called()

    def test_cancel_and_expired_queue_start_no_simulation(self):
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                controller, executor = _confirmed_controller()
                clock = FakeClock()
                with _gui_modules(real_core=True) as (worker_module, _panel, _window), \
                     patch.object(worker_module, "time", types.SimpleNamespace(monotonic=clock)):
                    worker = worker_module.SimulatedRepairWorker(controller)
                    if cancelled:
                        worker.cancel()
                    else:
                        clock.now = 161.0
                    results = []
                    worker.report_ready.connect(results.append)
                    worker.run()
                self.assertEqual(executor.calls, 0)
                execution = results[0]["execution"]
                self.assertEqual(execution["status"], "cancelled" if cancelled else "timed_out")
                self.assertIs(execution["command_started"], False)
                self.assertIs(execution["system_change_performed"], False)
                self.assertEqual(results[0]["verification"]["status"], "not_started")

    def test_native_mode_is_rejected_at_construction_and_rechecked_before_run(self):
        class InertCommandRunner:
            simulation_only = True
            calls = 0

            def run(self, **_kwargs):
                self.calls += 1
                raise AssertionError("GUI must never call a command runner")

        runner = InertCommandRunner()
        request, report = _baseline()
        command_controller = repair.RepairController(
            repair.RepairRequest(), request, report,
            executor=WindowsDnsCacheExecutor(command_runner=runner),
        )
        with _gui_modules(real_core=True) as (worker_module, _panel, _window):
            with self.assertRaises(ValueError):
                worker_module.SimulatedRepairWorker(command_controller)
            controller, _executor = _confirmed_controller()
            worker = worker_module.SimulatedRepairWorker(controller)
            failures = []
            worker.failed.connect(failures.append)
            record = controller.record()
            record["request"]["execution_mode"] = "windows_dns_cache"
            with patch.object(controller, "record", return_value=record), \
                 patch.object(controller, "execute",
                              side_effect=AssertionError("Guard must precede execute")) as execute:
                worker.run()
            self.assertEqual(failures, ["ValueError"])
            execute.assert_not_called()
            with self.assertRaises(ValueError):
                worker_module.SimulatedRepairWorker(controller, operation="real")
        self.assertEqual(runner.calls, 0)

    def test_independent_verify_uses_explicit_fakes_and_original_deadline(self):
        controller, executor = _confirmed_controller()
        clock, observer = FakeClock(), StableObserver()
        controller.execute(clock=clock)
        provider = FakeProvider(clock)
        original_controller = SessionController

        def with_fake_wait(request, probe_provider, supplied_clock, _wait,
                           *, context_observer):
            return original_controller(request, probe_provider, supplied_clock,
                                       clock.wait, context_observer=context_observer)

        with _gui_modules(real_core=True) as (worker_module, _panel, _window), \
             patch.object(worker_module, "time", types.SimpleNamespace(monotonic=clock)), \
             patch.object(session_process, "WindowsProbeProvider", return_value=provider) as created_provider, \
             patch.object(session_context, "WindowsContextObserver", return_value=observer) as created_observer, \
             patch.object(repair, "SessionController", side_effect=with_fake_wait) as created_controller:
            worker = worker_module.SimulatedRepairWorker(controller, operation="verify")
            results, failures = [], []
            worker.report_ready.connect(results.append)
            worker.failed.connect(failures.append)
            clock.now = 105.0
            worker.run()
        self.assertEqual(failures, [])
        self.assertEqual(worker.started_monotonic, 100.0)
        self.assertTrue(provider.probes)
        self.assertTrue(provider.closed and observer.closed)
        self.assertTrue(all(deadline <= 160.0 for deadline in provider.deadlines))
        self.assertLessEqual(clock(), 160.0)
        self.assertLessEqual(results[0]["verification"]["duration_seconds"], 60)
        self.assertEqual(results[0]["verification"]["status"], "completed")
        self.assertEqual(results[0]["comparison"]["causal_attribution"], "not_established")
        self.assertEqual(executor.calls, 1)
        created_provider.assert_called_once_with(clock=clock, extended_diagnostics=True)
        created_observer.assert_called_once_with(clock=clock)
        created_controller.assert_called_once()

    def test_precancelled_verify_cleans_explicit_fakes_without_probe(self):
        controller, executor = _confirmed_controller()
        clock, observer = FakeClock(), StableObserver()
        controller.execute(clock=clock)
        provider = FakeProvider(clock)
        with _gui_modules(real_core=True) as (worker_module, _panel, _window), \
             patch.object(worker_module, "time", types.SimpleNamespace(monotonic=clock)), \
             patch.object(session_process, "WindowsProbeProvider", return_value=provider), \
             patch.object(session_context, "WindowsContextObserver", return_value=observer):
            worker = worker_module.SimulatedRepairWorker(controller, operation="verify")
            worker.cancel()
            results = []
            worker.report_ready.connect(results.append)
            worker.run()
        self.assertEqual(provider.network_calls, 0)
        self.assertEqual(provider.probes, [])
        self.assertTrue(provider.closed and observer.closed)
        self.assertEqual(results[0]["verification"]["status"], "cancelled")
        self.assertEqual(results[0]["comparison"]["status"], "inconclusive")
        self.assertEqual(executor.calls, 1)


class SessionPanelIntegrationContracts(unittest.TestCase):
    def load_baseline(self, panel_module, panel=None):
        panel = panel or panel_module.SessionPanel(_config())
        panel._website_input.setText("https://private.example/private?token=secret")
        panel.start_session()
        worker = panel._worker
        _request, report = _baseline(panel._active_request.duration_seconds)
        report.incomplete.append("Private check detail at private.example")
        before_view = report.to_dict()
        worker.report_ready.emit(report)
        self.assertEqual(report.to_dict(), before_view)
        self.assertIs(panel._worker, worker)
        self.assertFalse(panel._save_btn.isEnabled())
        worker.active = False
        worker.finished.emit()
        self.assertIsNone(panel._worker)
        self.assertTrue(worker.deleted)
        return panel, report, worker

    def test_diagnosis_parameters_url_validation_and_explicit_budgets(self):
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            panel = panel_module.SessionPanel(_config())
            self.assertEqual(panel._duration.value(), 60)
            self.assertEqual(panel._duration._range, (1, 300))
            self.assertEqual(panel._verify_duration.value(), 60)
            self.assertEqual(panel._verify_duration._range, (1, 300))
            self.assertIsNone(panel._worker)
            panel._website_input.setText("ftp://private.example/file")
            panel.start_session()
            self.assertIsNone(panel._worker)
            self.assertIn("Cannot start session", panel._state.text())
            self.assertFalse(panel._display_timer.active)
            panel._duration.setValue(300)
            panel._website_input.setText("  https://private.example/check  ")
            panel.start_session()
            worker = panel._worker
            self.assertIsInstance(worker.request, SessionRequest)
            self.assertTrue(worker.request.extended_diagnostics)
            self.assertEqual(worker.request.duration_seconds, 300)
            self.assertEqual(worker.request.website_urls, ("https://private.example/check",))
            self.assertEqual(worker.request.ping_targets, ("1.1.1.1",))
            self.assertEqual(worker.request.dns_hostnames, ("private.example",))
            self.assertEqual(panel._worker_kind, "diagnosis")
            panel.start_session()
            panel.simulate_repair()
            panel.verify_repair()
            self.assertIs(panel._worker, worker)
            self.assertIsNone(panel._repair_controller)
            self.assertFalse(panel._website_input.isEnabled())
            panel.cancel_session()
            self.assertTrue(worker.cancel_event.is_set())
            worker.active = False
            worker.finished.emit()

    def test_redacted_view_and_save_preserve_outcomes_refs_and_raw_report(self):
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            panel, report, _old_worker = self.load_baseline(panel_module)
            report.evidence.append(ProbeEvidence(
                4, "2026-10-26T00:00:03Z", 4, 4.1, 1, "network",
                "unspecified", "localhost", ProbeOutcome.SUCCESS,
                comparable=True, data={"context_status": "IDENTIFIED", "role": "local",
                    "diagnostics": {"families": {
                        "IPv4": {"status": "configured",
                            "addresses": [{"address": "192.168.37.44"}],
                            "default_route": {"gateway": "192.168.37.1",
                                "source_address_candidate": "192.168.37.44"}},
                        "IPv6": {"status": "unknown",
                            "addresses": [{"address": "fd00:37::44"}],
                            "default_route": None},
                    }}}))
            original = report.to_dict()
            panel._on_report(report)
            self.assertEqual(report.to_dict(), original)
            rendered = panel._preview.toPlainText()
            for expected in (
                "IPv4", "IPv6", "DNS", "ICMP", "TCP", "HTTP(S)",
                "Not tested", "Tool error; network outcome UNKNOWN",
                "Support: E2", "Counterevidence: E3",
                "confidence: insufficient (qualitative)", "Alternative:", "Limitation:",
                "Advice:", "Unfinished", "not proof of health",
                "E4 local snapshot:", "no connectivity verdict", "Default gateway:",
                "Source address candidate (not actual route proof):",
                "Default route: UNKNOWN / no confirmed route summary",
            ):
                self.assertIn(expected, rendered)
            for secret in ("private.example", "192.168.37.22", "192.168.37.1",
                           "raw-network-identity", "Private SSID", "token=secret",
                           "private native stderr", "private stdout",
                           "192.168.37.44", "fd00:37::44"):
                self.assertNotIn(secret, rendered)
            with patch.object(panel_module.QFileDialog, "getSaveFileName",
                              return_value=("memory-only.json", "JSON"), create=True), \
                 patch.object(Path, "write_text", return_value=1) as write:
                panel._save_report()
            write.assert_called_once()
            exported = json.loads(write.call_args.args[0])
            self.assertIs(exported["redaction"]["applied"], True)
            self.assertEqual(exported["evidence"][0]["protocol"], "dns6")
            self.assertEqual(exported["evidence"][0]["family"], "IPv6")
            self.assertEqual(exported["evidence"][0]["outcome"], "not_attempted")
            self.assertEqual(exported["evidence"][1]["outcome"], "execution_error")
            self.assertEqual(exported["analysis"]["findings"][0]["supporting_evidence"], [2])
            self.assertEqual(exported["analysis"]["findings"][0]["contradictions"], [3])
            self.assertNotIn("stdout", exported["evidence"][1]["data"])
            self.assertNotIn("token=secret", write.call_args.args[0])
            self.assertNotIn("192.168.37.44", write.call_args.args[0])
            self.assertNotIn("fd00:37::44", write.call_args.args[0])
            self.assertEqual(report.to_dict(), original)
            self.assertIs(panel._report, report)
            self.assertIsNone(panel._repair_controller)

            # An unsampled short name has no target alias or dotted-host regex.
            controller, _executor = _confirmed_controller()
            raw_repair = controller.execute(clock=FakeClock())
            raw_repair["baseline_request"]["dns_hostnames"] = ["privatebox"]
            self.assertNotIn("privatebox", json.dumps(raw_repair["before_report"]))
            self.assertNotIn("privatebox", json.dumps(raw_repair["verification"]))
            before_repair_view = json.loads(json.dumps(raw_repair))
            panel._on_repair_result(raw_repair)
            self.assertNotIn("privatebox", panel._repair_preview.toPlainText())
            with patch.object(panel_module.QFileDialog, "getSaveFileName",
                              return_value=("memory-only.json", "JSON"), create=True), \
                 patch.object(Path, "write_text", return_value=1) as repair_write:
                panel._save_report()
            repair_write.assert_called_once()
            repaired_export = json.loads(repair_write.call_args.args[0])
            self.assertNotIn("privatebox", repair_write.call_args.args[0])
            self.assertNotIn("baseline_request", repaired_export)
            self.assertIn("baseline_request",
                          repaired_export["redaction"]["removed_fields"])
            self.assertEqual(raw_repair, before_repair_view)
            self.assertEqual(panel._repair_record, before_repair_view)
            self.assertEqual(report.to_dict(), original)

    def test_confirmation_defaults_to_no_and_real_repair_has_no_callback(self):
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            panel, report, _old_worker = self.load_baseline(panel_module)
            original = report.to_dict()
            self.assertTrue(panel._simulate_btn.isEnabled())
            self.assertFalse(panel._real_repair_btn.isEnabled())
            self.assertEqual(panel._real_repair_btn.clicked.callbacks, [])
            with patch.object(panel_module.QMessageBox, "question",
                              wraps=panel_module.QMessageBox.question) as question:
                panel.simulate_repair()
            question.assert_called_once()
            self.assertEqual(question.call_args.args[-1],
                             panel_module.QMessageBox.StandardButton.No)
            disclosure = question.call_args.args[2]
            self.assertIn("DNS", disclosure)
            self.assertIn("cannot be restored", disclosure)
            self.assertIn("no elevation", disclosure)
            self.assertIn("60 seconds", disclosure)
            self.assertIsNone(panel._worker)
            record = panel._repair_controller.record()
            self.assertEqual(record["confirmation"]["status"], "declined")
            self.assertEqual(record["execution"]["status"], "not_attempted")
            self.assertEqual(panel._repair_controller._executor.calls, 0)
            self.assertFalse(panel._verify_btn.isEnabled())
            panel._real_repair_btn.clicked.emit()
            panel.verify_repair()
            self.assertIsNone(panel._worker)
            self.assertEqual(report.to_dict(), original)

    def test_confirmed_simulation_requires_separate_verify_and_saves_existing_record(self):
        clock = FakeClock()
        with _gui_modules(real_core=True) as (worker_module, panel_module, _window), \
             patch.object(worker_module, "time", types.SimpleNamespace(monotonic=clock)):
            panel, report, _old_worker = self.load_baseline(panel_module)
            original = report.to_dict()
            panel._verify_duration.setValue(300)
            with patch.object(panel_module.QMessageBox, "question",
                              return_value=panel_module.QMessageBox.StandardButton.Yes):
                panel.simulate_repair()
            worker = panel._worker
            controller = worker.controller
            self.assertEqual(panel._worker_kind, "simulate")
            self.assertEqual(worker.operation, "simulate")
            self.assertEqual(controller.verification_request.duration_seconds, 300)
            record = controller.record()
            self.assertEqual(record["request"]["execution_mode"], "simulation")
            self.assertIs(record["request"]["simulation_only"], True)
            self.assertEqual(record["confirmation"]["status"], "confirmed")
            self.assertIs(record["confirmation"]["acknowledge_impact"], True)
            self.assertIs(record["confirmation"]["acknowledge_no_restore"], True)
            self.assertFalse(panel._verify_btn.isEnabled())
            worker.run()
            self.assertIs(panel._worker, worker)
            self.assertFalse(panel._save_btn.isEnabled())
            self.assertFalse(panel._verify_btn.isEnabled())
            self.assertIn("SIMULATION ONLY", panel._repair_preview.toPlainText())
            self.assertIn("simulated_success", panel._repair_preview.toPlainText())
            self.assertIn("inconclusive", panel._repair_preview.toPlainText())
            worker.active = False
            worker.finished.emit()
            self.assertIsNone(panel._worker)
            self.assertEqual(controller._executor.calls, 1)
            self.assertEqual(controller.record()["verification"]["status"], "pending")
            self.assertTrue(panel._verify_btn.isEnabled())
            with patch.object(panel_module.QFileDialog, "getSaveFileName",
                              return_value=("memory-only.json", "JSON"), create=True), \
                 patch.object(Path, "write_text", return_value=1) as write:
                panel._save_report()
            exported = json.loads(write.call_args.args[0])
            self.assertEqual(exported["request"]["execution_mode"], "simulation")
            self.assertEqual(exported["execution"]["status"], "simulated_success")
            self.assertIs(exported["execution"]["system_change_performed"], False)
            self.assertEqual(exported["verification"]["status"], "pending")
            self.assertIs(exported["redaction"]["applied"], True)
            self.assertNotIn("private.example", write.call_args.args[0])
            panel._website_input.setText("https://changed.example/")
            panel._duration.setValue(1)
            panel._verify_duration.setValue(1)
            panel.verify_repair()
            verification = panel._worker
            self.assertIs(verification.controller, controller)
            self.assertEqual(verification.operation, "verify")
            self.assertEqual(panel._worker_kind, "verify")
            self.assertEqual(verification.request.duration_seconds, 300)
            self.assertEqual(verification.request.website_urls,
                             ("https://private.example/private?token=secret",))
            self.assertEqual(controller._executor.calls, 1)
            self.assertFalse(panel._real_repair_btn.isEnabled())
            panel.cancel_session()
            self.assertTrue(verification.cancel_event.is_set())
            verification.active = False
            verification.finished.emit()
            self.assertEqual(report.to_dict(), original)

    def test_failed_worker_start_restores_idle_without_exposing_exception_text(self):
        with _gui_modules(real_core=True) as (worker_module, panel_module, _window):
            panel = panel_module.SessionPanel(_config())
            created = []
            original_worker = worker_module.SessionWorker

            def create_worker(*args):
                worker = original_worker(*args)
                created.append(worker)
                return worker

            with patch.object(panel_module, "SessionWorker", side_effect=create_worker), \
                 patch.object(original_worker, "start", side_effect=RuntimeError("private start details")):
                panel.start_session()
            self.assertIsNone(panel._worker)
            self.assertFalse(panel._display_timer.active)
            self.assertTrue(panel._start_btn.isEnabled())
            self.assertFalse(panel._cancel_btn.isEnabled())
            self.assertFalse(panel._save_btn.isEnabled())
            self.assertTrue(created[0].deleted)
            self.assertIn("RuntimeError", panel._state.text())
            self.assertNotIn("private start details", panel._state.text())
            self.assertEqual(panel._progress.value(), 0)

    def test_start_failure_after_thread_becomes_active_retains_until_finished(self):
        with _gui_modules(real_core=True) as (worker_module, panel_module, _window):
            panel = panel_module.SessionPanel(_config())

            def start_then_fail(worker):
                worker.active = True
                raise RuntimeError("synthetic startup failure")

            with patch.object(worker_module.SessionWorker, "start", start_then_fail):
                panel.start_session()
            worker = panel._worker
            self.assertIsNotNone(worker)
            self.assertTrue(worker.cancel_event.is_set())
            self.assertFalse(hasattr(worker, "deleted"))
            self.assertFalse(panel._start_btn.isEnabled())
            worker.active = False
            worker.finished.emit()
            self.assertIsNone(panel._worker)
            self.assertTrue(worker.deleted)
            self.assertFalse(panel._display_timer.active)
            self.assertTrue(panel._start_btn.isEnabled())

    def test_shutdown_during_confirmation_cannot_start_simulation(self):
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            panel, _report, _old_worker = self.load_baseline(panel_module)

            def close_while_confirming(*_args):
                self.assertTrue(panel.begin_shutdown())
                return panel_module.QMessageBox.StandardButton.Yes

            with patch.object(panel_module.QMessageBox, "question", side_effect=close_while_confirming), \
                 patch.object(panel_module, "SimulatedRepairWorker") as create_worker:
                panel.simulate_repair()
            create_worker.assert_not_called()
            self.assertIsNone(panel._worker)
            self.assertIsNone(panel._repair_controller)
            self.assertTrue(panel._closing)
            self.assertFalse(panel._display_timer.active)
            self.assertFalse(panel._start_btn.isEnabled())

    def test_stale_worker_signals_cannot_replace_current_report_or_release_worker(self):
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            panel, report, old_worker = self.load_baseline(panel_module)
            panel.start_session()
            current = panel._worker
            before_state, before_remaining = panel._state.text(), panel._remaining.text()
            panel._sender = old_worker
            old_worker.report_ready.emit(report)
            old_worker.progress.emit(types.SimpleNamespace(
                remaining_seconds=0, phase="stale", completed_count=999))
            old_worker.failed.emit("stale error")
            old_worker.finished.emit()
            self.assertIs(panel._worker, current)
            self.assertIsNone(panel._report)
            self.assertEqual(panel._state.text(), before_state)
            self.assertEqual(panel._remaining.text(), before_remaining)
            self.assertTrue(panel._display_timer.active)
            panel._sender = current
            current.report_ready.emit(report)
            self.assertIs(panel._worker, current)
            self.assertIs(panel._report, report)
            self.assertFalse(panel._save_btn.isEnabled())
            current.active = False
            current.finished.emit()
            self.assertIsNone(panel._worker)
            self.assertTrue(current.deleted)
            self.assertTrue(panel._save_btn.isEnabled())
            panel._sender = None

    def test_close_cancels_simulation_and_waits_for_worker_finished(self):
        clock = FakeClock()
        with _gui_modules(real_core=True) as (worker_module, panel_module, window_module), \
             patch.object(worker_module, "time", types.SimpleNamespace(monotonic=clock)):
            window = window_module.MainWindow(_config())
            panel, _report, _old_worker = self.load_baseline(panel_module, window._session)
            with patch.object(panel_module.QMessageBox, "question",
                              return_value=panel_module.QMessageBox.StandardButton.Yes):
                panel.simulate_repair()
            worker = panel._worker
            event = types.SimpleNamespace(
                ignore=lambda: setattr(event, "ignored", True),
                accept=lambda: setattr(event, "accepted", True),
            )
            window.closeEvent(event)
            self.assertTrue(event.ignored)
            self.assertTrue(worker.cancel_event.is_set())
            self.assertIs(panel._worker, worker)
            self.assertFalse(panel._start_btn.isEnabled())
            worker.run()
            self.assertEqual(worker.controller._executor.calls, 0)
            self.assertIs(panel._worker, worker)
            self.assertEqual(window.close_count, 0)
            worker.active = False
            worker.finished.emit()
            self.assertIsNone(panel._worker)
            self.assertTrue(worker.deleted)
            self.assertEqual(window.close_count, 1)
            self.assertFalse(panel._start_btn.isEnabled())
