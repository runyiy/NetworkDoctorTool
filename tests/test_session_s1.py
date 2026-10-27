"""Deterministic S1 contract tests; no Qt, probes or network mutations."""
from __future__ import annotations

import json
import threading
import unittest
from unittest.mock import patch

from losshound.core.session import (
    ProbeEvidence, ProbeOutcome, SessionController, SessionRequest,
)


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def wait(self, event, seconds):
        self.now += seconds
        return event.is_set()


class FakeProvider:
    def __init__(self, clock, identities=None, outcome="success", cancel_on_probe=False):
        self.clock = clock
        self.identities = list(identities or ["A"])
        self.outcome = outcome
        self.cancel_on_probe = cancel_on_probe
        self.network_calls = 0
        self.probes = []
        self.deadlines = []
        self.cleanup_deadline = None
        self.closed = False
        self.cleanup_errors = []
        self.raise_probe = False

    def set_cleanup_deadline(self, deadline):
        self.cleanup_deadline = deadline

    def read_network(self, deadline, cancel_event):
        self.deadlines.append(deadline)
        self.clock.now += min(0.01, max(0, deadline - self.clock.now))
        identity = self.identities[min(self.network_calls, len(self.identities) - 1)]
        self.network_calls += 1
        if identity is None:
            return {"outcome": "execution_error", "error": "context unavailable"}
        gateway = "192.0.2.1" if identity == "A" else "198.51.100.1"
        return {"outcome": "success", "data": {"identity": identity, "gateway": gateway}}

    def probe(self, protocol, target, deadline, cancel_event):
        self.deadlines.append(deadline)
        self.probes.append((protocol, target))
        self.clock.now += min(0.01, max(0, deadline - self.clock.now))
        if self.raise_probe:
            raise OSError("tool unavailable")
        if self.cancel_on_probe:
            cancel_event.set()
            return {"outcome": "cancelled", "error": "cancelled"}
        return {
            "outcome": self.outcome,
            "packets_sent": 1 if protocol == "icmp" else None,
            "packets_received": (1 if self.outcome == "success" else 0) if protocol == "icmp" else None,
            "rtt_ms": 2.0 if self.outcome == "success" else None,
            "data": {},
        }

    def close(self, deadline):
        self.closed = True
        self.close_deadline = deadline
        self.clock.now += min(0.1, max(0, deadline - self.clock.now))
        return self.cleanup_errors


class SessionTests(unittest.TestCase):
    def setUp(self):
        from test_session_context_s1 import StableObserver
        self.observer = StableObserver()
        replacement = patch("losshound.core.session_context.WindowsContextObserver", return_value=self.observer)
        replacement.start()
        self.addCleanup(replacement.stop)

    def run_session(self, *, duration=2, identities=None, outcome="success", provider=None, event=None, progress=None):
        clock = provider.clock if provider is not None else FakeClock()
        provider = provider or FakeProvider(clock, identities, outcome)
        request = SessionRequest(duration, ("203.0.113.1",), ("example.com",))
        controller = SessionController(request, provider, clock, clock.wait)
        return controller.run(event, progress), provider, clock

    def test_default_and_maximum_budget(self):
        self.assertEqual(SessionRequest().duration_seconds, 60)
        self.assertEqual(SessionRequest(300).duration_seconds, 300)
        for invalid in (0, -1, 301, True, 1.0, float("nan"), float("inf"), "60"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                SessionRequest(invalid)

    def test_requests_bound_work_and_freeze_target_input(self):
        source = ["1.1.1.1", "1.1.1.1"]
        request = SessionRequest(ping_targets=source)
        source.append("8.8.8.8")
        self.assertEqual(request.ping_targets, ("1.1.1.1",))
        with self.assertRaises(ValueError):
            SessionRequest(ping_targets=tuple(str(i) for i in range(9)))

    def test_one_absolute_budget_includes_cleanup(self):
        report, provider, clock = self.run_session(duration=1)
        self.assertEqual(report.status, "deadline")
        self.assertLessEqual(report.duration_seconds, 1)
        self.assertEqual(provider.cleanup_deadline, 100.95)
        self.assertEqual(provider.close_deadline, 100.95)
        self.assertTrue(provider.closed)
        self.assertTrue(all(deadline == 100.8 for deadline in provider.deadlines))
        self.assertLessEqual(clock.now, 101)
        self.assertTrue(report.incomplete)

    def test_network_transition_does_not_reset_deadline_or_mix_sample(self):
        report, provider, _ = self.run_session(identities=["A", "A", "B", "B"])
        self.assertEqual([epoch.identity for epoch in report.epochs], ["A", "B"])
        self.assertFalse(report.evidence[0].comparable)
        self.assertIsNone(report.evidence[0].loss_percent)
        self.assertIsNone(report.evidence[0].epoch_id)
        self.assertTrue(any(item.epoch_id == 2 and item.comparable for item in report.evidence))
        self.assertEqual(provider.cleanup_deadline, 101.95)
        self.assertTrue(all(value == 101.6 for value in provider.deadlines))

    def test_a_b_notification_during_probe_isolates_the_new_network(self):
        provider = FakeProvider(FakeClock())
        original = provider.probe
        def probe(*args):
            result = original(*args)
            if len(provider.probes) == 1:
                self.observer.generation += 1
                provider.identities = ["B"]
            return result
        provider.probe = probe
        report, provider, clock = self.run_session(provider=provider)
        self.assertEqual([epoch.identity for epoch in report.epochs[:2]], ["A", "B"])
        self.assertIsNone(report.evidence[0].epoch_id)
        self.assertIsNone(report.evidence[0].loss_percent)
        self.assertTrue(any(item.epoch_id == 2 and item.comparable for item in report.evidence))
        self.assertTrue(all(value == 101.6 for value in provider.deadlines))
        self.assertLessEqual(clock(), 102)

    def test_a_b_a_during_probe_breaks_epoch_without_resetting_deadline(self):
        provider = FakeProvider(FakeClock())
        original = provider.probe
        def probe(*args):
            result = original(*args)
            if len(provider.probes) == 1:
                self.observer.generation += 2
            return result
        provider.probe = probe
        report, provider, clock = self.run_session(provider=provider)
        self.assertEqual([epoch.identity for epoch in report.epochs[:2]], ["A", "A"])
        self.assertEqual([epoch.context["change_generation"] for epoch in report.epochs[:2]], [0, 2])
        self.assertIsNone(report.evidence[0].epoch_id)
        self.assertEqual(report.evidence[0].data["context_status"], "UNKNOWN")
        self.assertIsNone(report.evidence[0].loss_percent)
        self.assertTrue(any(item.epoch_id == 2 and item.comparable for item in report.evidence))
        self.assertTrue(all(value == 101.6 for value in provider.deadlines))
        self.assertLessEqual(clock(), 102)
        self.assertTrue(self.observer.closed)

    def test_unavailable_event_coverage_does_not_confirm_same_network(self):
        self.observer.status = "UNKNOWN"
        report, provider, _ = self.run_session()
        self.assertTrue(report.context_blind_spots)
        self.assertTrue(all(item.epoch_id is None and not item.comparable for item in report.evidence))
        self.assertTrue(all(item.loss_percent is None for item in report.evidence))
        self.assertTrue(all(item.data["context_status"] == "UNKNOWN" for item in report.evidence))
        self.assertTrue(provider.closed)

    def test_probe_and_observer_cleanup_share_one_cancellation_deadline(self):
        clock = FakeClock()
        event = threading.Event()
        provider = FakeProvider(clock, cancel_on_probe=True)
        deadlines = []
        cleanup_start = []
        def close_provider(deadline):
            cleanup_start.append(clock())
            deadlines.append(deadline)
            clock.now += min(1.5, max(0, deadline - clock()))
            return []
        def close_observer(deadline):
            deadlines.append(deadline)
            clock.now += min(1, max(0, deadline - clock()))
            return []
        provider.close = close_provider
        self.observer.close = close_observer
        controller = SessionController(SessionRequest(300), provider, clock, clock.wait)
        report = controller.run(event)
        self.assertEqual(report.status, "cancelled")
        self.assertEqual(deadlines[0], deadlines[1])
        self.assertAlmostEqual(clock() - cleanup_start[0], 2)
        self.assertLess(report.duration_seconds, 3)

    def test_cancel_request_and_return_durations_are_separate(self):
        clock = FakeClock()
        event = threading.Event()
        provider = FakeProvider(clock)
        original = provider.probe
        def probe(*args):
            result = original(*args)
            event.requested_monotonic = clock()
            event.set()
            return result
        provider.probe = probe
        report, _, _ = self.run_session(provider=provider, event=event)
        self.assertEqual(report.status, "cancelled")
        self.assertAlmostEqual(report.duration_seconds,
                               report.cancel_request_elapsed_seconds + report.cancel_to_return_seconds)
        self.assertGreaterEqual(report.cancel_to_return_seconds, 0)

    def test_gateway_is_refreshed_before_probe(self):
        report, provider, _ = self.run_session(identities=["A", "B", "B"])
        self.assertEqual(provider.probes[0], ("icmp", "198.51.100.1"))
        self.assertEqual(report.evidence[0].epoch_id, 2)

    def test_unknown_network_breaks_continuity(self):
        report, _, _ = self.run_session(identities=["A", "A", None, "A", "A"])
        self.assertEqual([epoch.identity for epoch in report.epochs[:2]], ["A", "A"])
        self.assertFalse(report.evidence[0].comparable)
        self.assertTrue(any("Network context unavailable" in item for item in report.incomplete))

    def test_cancelled_before_start_does_not_schedule_any_probe(self):
        event = threading.Event()
        event.set()
        report, provider, _ = self.run_session(event=event)
        self.assertEqual(report.status, "cancelled")
        self.assertEqual(provider.network_calls, 0)
        self.assertFalse(provider.probes)
        self.assertTrue(provider.closed)

    def test_cancellation_stops_schedule_and_does_not_invent_packets(self):
        provider = FakeProvider(FakeClock(), cancel_on_probe=True)
        report, provider, _ = self.run_session(provider=provider)
        self.assertEqual(report.status, "cancelled")
        self.assertEqual(len(provider.probes), 1)
        self.assertEqual(len(report.evidence), 1)
        evidence = report.evidence[0]
        self.assertEqual(evidence.outcome, ProbeOutcome.CANCELLED)
        self.assertIsNone(evidence.packets_sent)
        self.assertIsNone(evidence.loss_percent)
        self.assertTrue(any("cancelled" in item for item in report.incomplete))
        self.assertTrue(provider.closed)

    def test_only_real_completed_icmp_attempts_have_loss(self):
        for outcome in ProbeOutcome:
            with self.subTest(outcome=outcome):
                report, _, _ = self.run_session(outcome=outcome.value)
                sample = next(item for item in report.evidence if item.protocol == "icmp" and item.comparable)
                if outcome == ProbeOutcome.SUCCESS:
                    self.assertEqual(sample.loss_percent, 0)
                elif outcome in {ProbeOutcome.REPLY_TIMEOUT, ProbeOutcome.UNREACHABLE}:
                    self.assertEqual(sample.loss_percent, 100)
                else:
                    self.assertIsNone(sample.loss_percent)
                self.assertTrue(all(item.loss_percent is None for item in report.evidence if item.protocol == "dns"))

    def test_probe_failure_closes_provider_without_network_verdict(self):
        provider = FakeProvider(FakeClock())
        provider.raise_probe = True
        report, provider, _ = self.run_session(provider=provider)
        self.assertEqual(report.status, "execution_error")
        self.assertTrue(provider.closed)
        self.assertFalse(report.evidence)
        self.assertIn("no causal diagnosis", report.summary)

    def test_cleanup_failure_is_not_reported_as_success(self):
        provider = FakeProvider(FakeClock())
        provider.cleanup_errors = ["owned process did not exit"]
        report, _, _ = self.run_session(provider=provider)
        self.assertEqual(report.status, "cleanup_failed")
        self.assertEqual(report.cleanup_errors, provider.cleanup_errors)

    def test_progress_failure_cannot_skip_cleanup(self):
        def broken(_progress):
            raise ValueError("UI callback failed")
        report, provider, _ = self.run_session(progress=broken)
        self.assertTrue(provider.closed)
        self.assertTrue(any("Progress callback failed" in item for item in report.incomplete))

    def test_progress_remaining_decreases_and_finishes_after_cleanup(self):
        updates = []
        report, provider, _ = self.run_session(progress=updates.append)
        self.assertEqual(updates[0].phase, "starting")
        self.assertEqual(updates[-1].phase, "finished")
        self.assertTrue(provider.closed)
        remaining = [item.remaining_seconds for item in updates]
        self.assertTrue(all(a >= b for a, b in zip(remaining, remaining[1:])))
        self.assertEqual(updates[-1].completed_count, len(report.evidence))

    def test_report_serializes_typed_outcomes_without_false_loss(self):
        report, _, _ = self.run_session(outcome="execution_error")
        raw = json.loads(report.to_json())
        self.assertEqual(raw["schema_version"], 2)
        self.assertTrue(all(item["loss_percent"] is None for item in raw["evidence"]))
        self.assertIn("error", raw["evidence"][0])
        self.assertTrue(any("execution_error" in item for item in raw["incomplete"]))

    def test_invalid_counts_never_produce_loss(self):
        evidence = ProbeEvidence(1, "now", 0, 1, 1, "icmp", "IPv4", "x", ProbeOutcome.SUCCESS)
        self.assertIsNone(evidence.loss_percent)

    def test_early_cancellation_cleanup_is_not_given_remaining_300_seconds(self):
        provider = FakeProvider(FakeClock(), cancel_on_probe=True)
        report, provider, _ = self.run_session(duration=300, provider=provider)
        self.assertEqual(report.status, "cancelled")
        self.assertLessEqual(provider.close_deadline, 102.1)
        self.assertLess(report.duration_seconds, 1)

    def test_overrun_is_explicit_instead_of_claiming_bounded_success(self):
        provider = FakeProvider(FakeClock())
        original_close = provider.close
        def slow_close(deadline):
            result = original_close(deadline)
            provider.clock.now += 2
            return result
        provider.close = slow_close
        report, _, _ = self.run_session(duration=1, provider=provider)
        self.assertEqual(report.status, "execution_error")
        self.assertGreater(report.duration_seconds, report.budget_seconds)
        self.assertTrue(any("budget exceeded" in item for item in report.incomplete))

    def test_json_reflects_final_report_metadata_instead_of_an_earlier_snapshot(self):
        report, _, _ = self.run_session()
        initial = json.loads(report.to_json())
        report.duration_seconds += 0.1
        report.status = "output_error"
        report.output_errors.append("delivery failed")
        final = json.loads(report.to_json())
        self.assertGreater(final["duration_seconds"], initial["duration_seconds"])
        self.assertEqual(final["duration_seconds"], report.duration_seconds)
        self.assertEqual(final["status"], "output_error")
        self.assertEqual(final["output_errors"], ["delivery failed"])

    def test_report_preparation_time_is_accounted_and_overrun_is_serialized(self):
        clock = FakeClock()
        provider = FakeProvider(clock)
        controller = SessionController(SessionRequest(1, (), ()), provider, clock, clock.wait)
        original_dumps = json.dumps
        def slow_dumps(*args, **kwargs):
            clock.now += 0.2
            return original_dumps(*args, **kwargs)
        with patch("losshound.core.session.json.dumps", side_effect=slow_dumps):
            report = controller.run()
        raw = json.loads(report.to_json())
        self.assertEqual(report.status, "execution_error")
        self.assertEqual(raw["status"], report.status)
        self.assertEqual(raw["duration_seconds"], report.duration_seconds)
        self.assertAlmostEqual(report.duration_seconds, clock() - 100.0)
        self.assertGreater(raw["duration_seconds"], raw["budget_seconds"])
        self.assertTrue(any("budget exceeded" in item for item in raw["incomplete"]))

    def test_finished_progress_time_is_included_in_final_budget_check(self):
        clock = FakeClock()
        provider = FakeProvider(clock)
        def progress(value):
            if value.phase == "finished":
                clock.now += 2.0
        controller = SessionController(SessionRequest(1, (), ()), provider, clock, clock.wait)
        report = controller.run(on_progress=progress)
        self.assertTrue(provider.closed)
        self.assertEqual(report.status, "execution_error")
        self.assertAlmostEqual(report.duration_seconds, clock() - 100.0)
        self.assertTrue(any("budget exceeded" in item for item in json.loads(report.to_json())["incomplete"]))

    def test_finished_progress_failure_is_retained_in_final_json(self):
        def progress(value):
            if value.phase == "finished":
                raise ValueError("finished callback failed")
        report, provider, _ = self.run_session(progress=progress)
        self.assertTrue(provider.closed)
        self.assertTrue(any("Progress callback failed" in item for item in json.loads(report.to_json())["incomplete"]))

    def test_output_reserve_shares_absolute_budget_and_preserves_probe_cleanup_time(self):
        clock = FakeClock()
        provider = FakeProvider(clock)
        controller = SessionController(SessionRequest(2, (), ()), provider, clock, clock.wait)
        report = controller.run(output_reserve_seconds=0.25)
        self.assertAlmostEqual(provider.cleanup_deadline, 101.7)
        self.assertTrue(all(abs(value - 101.35) < 1e-8 for value in provider.deadlines))
        self.assertLessEqual(provider.close_deadline, 101.7)
        self.assertLessEqual(report.duration_seconds, 1.75)
        self.assertEqual(report.budget_seconds, 2)

    def test_output_reserve_is_capped_when_startup_consumed_most_of_the_budget(self):
        clock = FakeClock()
        provider = FakeProvider(clock)
        controller = SessionController(SessionRequest(60, (), ()), provider, clock, clock.wait)
        report = controller.run(absolute_deadline=100.1, output_reserve_seconds=0.5)
        self.assertAlmostEqual(provider.cleanup_deadline, 100.075)
        self.assertTrue(all(abs(value - 100.06) < 1e-8 for value in provider.deadlines))
        self.assertLessEqual(clock(), 100.08)
        self.assertLessEqual(report.duration_seconds, 60)

    def test_output_reserve_rejects_nonfinite_invalid_or_overbudget_values(self):
        for reserve in (-1, True, None, "0.5", float("nan"), float("inf"), 61):
            with self.subTest(reserve=reserve):
                clock = FakeClock()
                provider = FakeProvider(clock)
                controller = SessionController(SessionRequest(60), provider, clock, clock.wait)
                with self.assertRaises(ValueError):
                    controller.run(output_reserve_seconds=reserve)
                self.assertFalse(provider.probes)
                self.assertEqual(provider.network_calls, 0)

    def test_pre_cancelled_report_names_unattempted_configured_targets(self):
        event = threading.Event()
        event.set()
        report, _, _ = self.run_session(event=event)
        self.assertTrue(any("icmp 203.0.113.1: not attempted" == item for item in report.incomplete))
        self.assertTrue(any("dns example.com: not attempted" == item for item in report.incomplete))

    def test_external_startup_time_consumes_same_absolute_budget(self):
        clock = FakeClock()
        absolute_deadline = clock() + 2
        clock.now += 0.5  # Bounded output startup already consumed this time.
        provider = FakeProvider(clock)
        progress = []
        controller = SessionController(SessionRequest(2, ("203.0.113.1",), ()), provider, clock, clock.wait)
        report = controller.run(on_progress=progress.append, absolute_deadline=absolute_deadline)
        self.assertEqual(progress[0].elapsed_seconds, 0.5)
        self.assertEqual(progress[0].remaining_seconds, 1.5)
        self.assertLessEqual(clock(), absolute_deadline)
        self.assertLessEqual(report.duration_seconds, 2)
        self.assertAlmostEqual(provider.cleanup_deadline, absolute_deadline - 0.05)
        self.assertTrue(all(value <= absolute_deadline for value in provider.deadlines))
        self.assertTrue(all(item.started_seconds >= 0.5 for item in report.evidence))

    def test_external_deadline_preserves_existing_cancellation(self):
        clock = FakeClock()
        provider = FakeProvider(clock)
        cancelled = threading.Event()
        cancelled.set()
        controller = SessionController(SessionRequest(60), provider, clock, clock.wait)
        report = controller.run(cancelled, absolute_deadline=101)
        self.assertEqual(report.status, "cancelled")
        self.assertFalse(provider.probes)
        self.assertEqual(provider.network_calls, 0)
        self.assertTrue(provider.closed)
        self.assertLessEqual(provider.close_deadline, 101)

    def test_external_deadline_validation_rejects_extension_and_nonfinite_values(self):
        for deadline in (float("nan"), float("inf"), True, "160", 161):
            with self.subTest(deadline=deadline):
                clock = FakeClock()
                provider = FakeProvider(clock)
                controller = SessionController(SessionRequest(60), provider, clock, clock.wait)
                with self.assertRaises(ValueError):
                    controller.run(absolute_deadline=deadline)
                self.assertFalse(provider.probes)
                self.assertEqual(provider.network_calls, 0)

    def test_almost_consumed_external_budget_keeps_report_reserve_bounded(self):
        clock = FakeClock()
        provider = FakeProvider(clock)
        controller = SessionController(SessionRequest(60, (), ()), provider, clock, clock.wait)
        report = controller.run(absolute_deadline=100.1)
        self.assertLessEqual(clock(), 100.1)
        self.assertLessEqual(provider.cleanup_deadline, 100.1)
        self.assertTrue(all(value < provider.cleanup_deadline for value in provider.deadlines))
        self.assertLessEqual(report.duration_seconds, 60)

    def test_controller_cannot_restart_or_extend_same_session(self):
        clock = FakeClock()
        provider = FakeProvider(clock)
        controller = SessionController(SessionRequest(1, (), ()), provider, clock, clock.wait)
        controller.run()
        with self.assertRaises(RuntimeError):
            controller.run()


if __name__ == "__main__":
    unittest.main()
