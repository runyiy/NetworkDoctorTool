"""S3 request/confirmation/execution/verification contracts; memory-only fakes."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict
import hashlib
import json
import threading
import unittest
from unittest.mock import patch

from losshound.core import repair
from losshound.core.session import SessionController, SessionReport, SessionRequest
from test_session_context_s1 import StableObserver
from test_session_s1 import FakeClock, FakeProvider


def diagnostic_request(seconds=60):
    return SessionRequest(seconds, ("203.0.113.7",), ("example.test",),
                          extended_diagnostics=True, ipv6_targets=(),
                          tcp_targets=("203.0.113.7:443",),
                          website_urls=("http://example.test/check",))


class RepairFlowTests(unittest.TestCase):
    def make_controller(self, *, seconds=60, outcome="success"):
        request = diagnostic_request(seconds)
        baseline = SessionReport("deadline", seconds, duration_seconds=seconds,
                                 incomplete=["controlled baseline; no real observations"])
        executor = repair.SimulatedRepairExecutor(outcome)
        controller = repair.RepairController(repair.RepairRequest(verification_seconds=seconds),
                                             request, baseline, executor=executor)
        return controller, executor, request, baseline

    def confirmed(self, **kwargs):
        controller, executor, request, baseline = self.make_controller(**kwargs)
        offer = controller.prepare()
        controller.confirm(offer["request_id"], accepted=True, acknowledge_impact=True,
                           acknowledge_no_restore=True)
        return controller, executor, request, baseline

    def verify(self, controller, *, provider=None, event=None, progress=None):
        clock = provider.clock if provider is not None else FakeClock()
        provider = provider if provider is not None else FakeProvider(clock)
        observer = StableObserver()
        result = controller.verify(provider=provider, context_observer=observer,
                                   clock=clock, wait=clock.wait,
                                   cancel_event=event, on_progress=progress)
        return result, provider, observer, clock

    def test_request_is_frozen_and_only_exact_action_and_integer_budget_are_accepted(self):
        request = repair.RepairRequest()
        self.assertEqual(request.action, repair.DNS_CACHE_FLUSH)
        self.assertEqual(request.verification_seconds, 60)
        self.assertEqual(repair.RepairRequest(verification_seconds=300).verification_seconds, 300)
        with self.assertRaises(FrozenInstanceError):
            request.verification_seconds = 300
        for seconds in (0, -1, 301, True, False, 1.0, float("nan"), float("inf"), "60", None):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                repair.RepairRequest(verification_seconds=seconds)
        for action in ("", "netsh", "reset_network", "FLUSH_WINDOWS_DNS_CACHE", None, True):
            with self.subTest(action=action), self.assertRaises(ValueError):
                repair.RepairRequest(action=action)

    def test_simulator_rejects_unknown_outcome_or_non_whitelisted_request(self):
        for outcome in ("real", "retry", None):
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                repair.SimulatedRepairExecutor(outcome)
        executor = repair.SimulatedRepairExecutor()
        with self.assertRaises(ValueError):
            executor.execute(object())
        self.assertEqual(executor.calls, 0)

    def test_offer_discloses_impact_no_restore_permissions_and_binds_baseline(self):
        controller, executor, _, baseline = self.make_controller()
        offer = controller.prepare()
        for key in ("request_id", "action", "impact", "no_restore_warning", "permissions", "baseline_sha256"):
            self.assertTrue(offer[key], key)
        self.assertEqual(offer["action"], repair.DNS_CACHE_FLUSH)
        self.assertIs(offer["simulation_only"], True)
        self.assertIn("DNS", offer["impact"])
        self.assertIn("cannot be restored", offer["no_restore_warning"])
        self.assertIn("no elevation", offer["permissions"])
        expected = hashlib.sha256(json.dumps(baseline.to_dict(), sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(offer["baseline_sha256"], expected)
        self.assertEqual(executor.calls, 0)
        self.assertEqual(controller.record()["execution"]["status"], "not_attempted")
        self.assertEqual(controller.record()["verification"]["status"], "not_started")

    def test_confirmation_requires_disclosure_matching_request_and_strict_booleans(self):
        controller, executor, _, _ = self.make_controller()
        with self.assertRaises(RuntimeError):
            controller.confirm("unpresented", accepted=True, acknowledge_impact=True,
                               acknowledge_no_restore=True)
        offer = controller.prepare()
        class StringSubclass(str):
            pass
        class EqualID:
            def __eq__(self, _other):
                return True
        for request_id in ("another-request", None, 1, True, StringSubclass(offer["request_id"]), EqualID()):
            with self.subTest(request_id_type=type(request_id).__name__), self.assertRaises(ValueError):
                controller.confirm(request_id, accepted=True, acknowledge_impact=True,
                                   acknowledge_no_restore=True)
        for field in ("accepted", "acknowledge_impact", "acknowledge_no_restore"):
            for value in (1, "yes", None):
                arguments = dict(accepted=True, acknowledge_impact=True, acknowledge_no_restore=True)
                arguments[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    controller.confirm(offer["request_id"], **arguments)
        self.assertEqual(executor.calls, 0)
        self.assertEqual(controller.record()["confirmation"]["status"], "not_confirmed")

    def test_any_decline_or_missing_ack_blocks_execution_and_cannot_replay(self):
        for accepted, impact, restore in ((False, True, True), (True, False, True), (True, True, False)):
            with self.subTest(accepted=accepted, impact=impact, restore=restore):
                controller, executor, _, _ = self.make_controller()
                offer = controller.prepare()
                confirmation = controller.confirm(offer["request_id"], accepted=accepted,
                    acknowledge_impact=impact, acknowledge_no_restore=restore)
                self.assertEqual(confirmation["status"], "declined")
                self.assertEqual(controller.execute()["execution"]["status"], "blocked")
                self.assertEqual(executor.calls, 0)
                with self.assertRaises(RuntimeError):
                    controller.execute()
                with self.assertRaises(RuntimeError):
                    controller.confirm(offer["request_id"], accepted=True,
                        acknowledge_impact=True, acknowledge_no_restore=True)

    def test_unprepared_or_unconfirmed_execution_is_blocked_without_executor(self):
        for prepare in (False, True):
            with self.subTest(prepare=prepare):
                controller, executor, _, _ = self.make_controller()
                if prepare:
                    controller.prepare()
                result = controller.execute()
                self.assertEqual(result["execution"]["status"], "blocked")
                self.assertIs(result["execution"]["system_change_performed"], False)
                self.assertEqual(executor.calls, 0)
                with self.assertRaises(RuntimeError):
                    controller.execute()

    def test_confirmed_request_cannot_be_confirmed_again_before_execution(self):
        controller, executor, _, _ = self.confirmed()
        request_id = controller.record()["request"]["request_id"]
        with self.assertRaises(RuntimeError):
            controller.confirm(request_id, accepted=True, acknowledge_impact=True,
                               acknowledge_no_restore=True)
        self.assertEqual(executor.calls, 0)
        self.assertEqual(controller.execute()["execution"]["status"], "simulated_success")
        self.assertEqual(executor.calls, 1)

    def test_confirmed_action_budget_and_diagnostic_targets_cannot_be_replaced(self):
        controller, executor, request, _ = self.confirmed()
        original = controller.request
        replacements = {"request": repair.RepairRequest(verification_seconds=300),
                        "baseline_request": diagnostic_request(300),
                        "verification_request": diagnostic_request(300)}
        for name, value in replacements.items():
            with self.subTest(name=name), self.assertRaises(AttributeError):
                setattr(controller, name, value)
        self.assertIs(controller.request, original)
        self.assertEqual(controller.baseline_request, request)
        self.assertEqual(controller.verification_request.duration_seconds, 60)
        self.assertEqual(controller.execute()["verification"]["budget_seconds"], 60)
        self.assertEqual(executor.calls, 1)

    def test_confirmation_cannot_be_transferred_to_another_request(self):
        first, _, _, _ = self.make_controller()
        second, executor, _, _ = self.make_controller()
        first_offer, second_offer = first.prepare(), second.prepare()
        self.assertNotEqual(first_offer["request_id"], second_offer["request_id"])
        with self.assertRaises(ValueError):
            second.confirm(first_offer["request_id"], accepted=True,
                           acknowledge_impact=True, acknowledge_no_restore=True)
        self.assertEqual(second.execute()["execution"]["status"], "blocked")
        self.assertEqual(executor.calls, 0)

    def test_custom_or_subclass_executor_is_rejected_without_calling_it(self):
        class CustomExecutor:
            calls = 0
            def execute(self, _request):
                self.calls += 1
                raise AssertionError("Custom executor must never be invoked")
        class Subclass(repair.SimulatedRepairExecutor):
            pass
        _, _, request, baseline = self.make_controller()
        for executor in (CustomExecutor(), Subclass()):
            with self.subTest(executor=type(executor).__name__), self.assertRaises(TypeError):
                repair.RepairController(repair.RepairRequest(), request, baseline, executor=executor)
            self.assertEqual(executor.calls, 0)

        simulator = repair.SimulatedRepairExecutor()
        callbacks = []
        def injected(_request):
            callbacks.append("unexpected callback")
        for name, value in (("execute", injected), ("outcome", "failure"), ("calls", 99)):
            with self.subTest(simulator_attribute=name), self.assertRaises(AttributeError):
                setattr(simulator, name, value)
        self.assertEqual(callbacks, [])
        self.assertEqual(simulator.outcome, "success")
        self.assertEqual(simulator.calls, 0)

    def test_each_simulated_outcome_is_recorded_once_without_system_change_or_retry(self):
        for outcome in ("success", "failure", "tool_error"):
            with self.subTest(outcome=outcome):
                controller, executor, _, _ = self.confirmed(outcome=outcome)
                result = controller.execute()
                self.assertEqual(result["execution"]["status"], "simulated_" + outcome)
                self.assertIs(result["execution"]["simulation_only"], True)
                self.assertIs(result["execution"]["system_change_performed"], False)
                self.assertEqual(result["verification"]["status"], "pending")
                self.assertEqual(result["comparison"]["status"], "inconclusive")
                self.assertEqual(executor.calls, 1)
                with self.assertRaises(RuntimeError):
                    controller.execute()
                self.assertEqual(executor.calls, 1)

    def test_pre_cancelled_execution_starts_no_simulation_and_no_verification(self):
        controller, executor, _, _ = self.confirmed()
        event = threading.Event()
        event.set()
        result = controller.execute(event)
        self.assertEqual(result["execution"]["status"], "cancelled")
        self.assertEqual(result["verification"]["status"], "not_started")
        self.assertEqual(executor.calls, 0)
        with self.assertRaises(RuntimeError):
            self.verify(controller)
        self.assertEqual(executor.calls, 0)

    def test_verification_requires_explicit_provider_and_observer_without_native_fallback(self):
        controller, executor, _, _ = self.confirmed()
        controller.execute()
        clock = FakeClock()
        for provider, observer in ((None, StableObserver()), (FakeProvider(clock), None), (None, None)):
            with self.subTest(provider=provider is None, observer=observer is None), \
                 patch.object(repair, "SessionController", side_effect=AssertionError("No native fallback")) as created:
                with self.assertRaises(ValueError):
                    controller.verify(provider=provider, context_observer=observer, clock=clock, wait=clock.wait)
                created.assert_not_called()
        self.assertEqual(executor.calls, 1)
        self.assertEqual(controller.record()["verification"]["status"], "pending")

    def test_verification_uses_new_real_controller_and_preserves_targets_with_60_or_300_budget(self):
        for seconds in (60, 300):
            with self.subTest(seconds=seconds):
                controller, executor, request, baseline = self.confirmed(seconds=seconds)
                before = baseline.to_dict()
                controller.execute()
                with patch.object(repair, "SessionController", wraps=SessionController) as created:
                    result, provider, observer, clock = self.verify(controller)
                created.assert_called_once()
                verification_request = created.call_args.args[0]
                self.assertIsNot(verification_request, request)
                self.assertEqual(asdict(verification_request), asdict(request))
                self.assertEqual(result["verification"]["budget_seconds"], seconds)
                self.assertEqual(result["verification"]["status"], "completed")
                self.assertEqual(result["verification"]["session_status"], "deadline")
                self.assertEqual(result["verification"]["report"]["budget_seconds"], seconds)
                self.assertLessEqual(result["verification"]["duration_seconds"], seconds)
                self.assertLessEqual(clock(), 100 + seconds)
                self.assertTrue(provider.probes)
                self.assertTrue(provider.closed and observer.closed)
                self.assertEqual(executor.calls, 1)
                self.assertEqual(baseline.to_dict(), before)
                self.assertEqual(result["comparison"]["status"], "inconclusive")
                self.assertIsNone(result["comparison"]["network_problem_resolved"])

    def test_failed_verification_does_not_retry_simulation_or_verification(self):
        controller, executor, _, _ = self.confirmed(outcome="failure")
        controller.execute()
        provider = FakeProvider(FakeClock())
        provider.raise_probe = True
        result, provider, observer, _ = self.verify(controller, provider=provider)
        self.assertEqual(result["verification"]["status"], "execution_error")
        self.assertEqual(result["comparison"]["status"], "inconclusive")
        self.assertTrue(provider.closed and observer.closed)
        calls = len(provider.probes)
        with self.assertRaises(RuntimeError):
            self.verify(controller, provider=provider)
        self.assertEqual(len(provider.probes), calls)
        self.assertEqual(executor.calls, 1)

    def test_cancelled_verification_is_separate_from_simulated_operation_result(self):
        for pre_cancelled in (False, True):
            with self.subTest(pre_cancelled=pre_cancelled):
                controller, executor, _, _ = self.confirmed()
                controller.execute()
                event = threading.Event()
                if pre_cancelled:
                    event.set()
                provider = FakeProvider(FakeClock(), cancel_on_probe=True)
                result, provider, observer, _ = self.verify(controller, provider=provider, event=event)
                self.assertEqual(result["execution"]["status"], "simulated_success")
                self.assertEqual(result["verification"]["status"], "cancelled")
                self.assertEqual(result["comparison"]["status"], "inconclusive")
                self.assertTrue(provider.closed and observer.closed)
                self.assertTrue(all(not item["comparable"] for item in result["verification"]["report"]["evidence"]))
                if pre_cancelled:
                    self.assertEqual(provider.network_calls, 0)
                    self.assertEqual(provider.probes, [])
                self.assertEqual(executor.calls, 1)

    def test_verification_budget_overrun_is_not_reported_as_improvement(self):
        controller, executor, _, _ = self.confirmed(seconds=1)
        controller.execute()
        provider = FakeProvider(FakeClock())
        def overrun_close(_deadline):
            provider.closed = True
            provider.clock.now += 2
            return []
        provider.close = overrun_close
        result, _, observer, _ = self.verify(controller, provider=provider)
        self.assertEqual(result["verification"]["status"], "budget_exceeded")
        self.assertEqual(result["comparison"]["status"], "inconclusive")
        self.assertTrue(observer.closed)
        self.assertEqual(executor.calls, 1)

        with self.subTest(stage="late_final_return_copy"):
            controller, executor, _, _ = self.confirmed()
            controller.execute()
            clock, observer = FakeClock(), StableObserver()
            provider = FakeProvider(clock)
            deadline = clock() + 60
            original_copy = repair._copy
            advanced = []
            def late_final_copy(value):
                copied = original_copy(value)
                if value is controller._record:
                    advanced.append(True)
                    clock.now = deadline + 0.25
                return copied
            with patch.object(repair, "_copy", side_effect=late_final_copy):
                result = controller.verify(provider=provider, context_observer=observer,
                                           clock=clock, wait=clock.wait)
            self.assertEqual(len(advanced), 1)
            self.assertEqual(result["verification"]["status"], "budget_exceeded")
            self.assertEqual(result["comparison"]["status"], "inconclusive")
            self.assertGreater(result["verification"]["duration_seconds"], 60)
            internal = controller.record()
            self.assertEqual(internal["verification"], result["verification"])
            self.assertEqual(internal["comparison"], result["comparison"])
            self.assertTrue(provider.closed and observer.closed)
            self.assertEqual(executor.calls, 1)

    def test_records_offers_confirmation_and_baseline_are_defensive_copies(self):
        controller, executor, _, baseline = self.make_controller()
        original = baseline.to_dict()
        offer = controller.prepare()
        request_id = offer["request_id"]
        offer["action"] = "injected"
        offer["impact"] = "hidden"
        confirmation = controller.confirm(request_id, accepted=True,
            acknowledge_impact=True, acknowledge_no_restore=True)
        confirmation["status"] = "declined"
        execution = controller.execute()
        execution["execution"]["system_change_performed"] = True
        execution["before_report"]["incomplete"].append("external mutation")
        result, _, _, _ = self.verify(controller)
        result["verification"]["report"]["status"] = "external mutation"
        fresh = controller.record()
        self.assertEqual(fresh["request"]["action"], repair.DNS_CACHE_FLUSH)
        self.assertEqual(fresh["confirmation"]["status"], "confirmed")
        self.assertIs(fresh["execution"]["system_change_performed"], False)
        self.assertEqual(fresh["before_report"], original)
        self.assertEqual(baseline.to_dict(), original)
        self.assertEqual(fresh["verification"]["report"]["status"], "deadline")
        self.assertEqual(json.loads(controller.to_json()), fresh)
        fresh["request"]["action"] = "another external mutation"
        self.assertEqual(controller.record()["request"]["action"], repair.DNS_CACHE_FLUSH)
        self.assertEqual(executor.calls, 1)

    def test_confirmed_simulation_then_independent_dns_verification_end_to_end(self):
        class DNSProvider(FakeProvider):
            def __init__(self, clock, dns_outcome):
                super().__init__(clock)
                self.dns_outcome = dns_outcome

            def probe(self, protocol, target, deadline, cancel_event):
                result = super().probe(protocol, target, deadline, cancel_event)
                if protocol == "dns":
                    result["outcome"] = self.dns_outcome
                    result["data"] = {"family": "IPv4", "resolver_result_only": True,
                                      "addresses": ["192.0.2.53"] if self.dns_outcome == "success" else []}
                    result["rtt_ms"] = 2.0 if self.dns_outcome == "success" else None
                return result

        request = SessionRequest(60, ping_targets=(), dns_hostnames=("lookup.example",),
                                 ipv6_targets=(), tcp_targets=())
        before_clock, before_observer = FakeClock(), StableObserver()
        before_provider = DNSProvider(before_clock, "reply_timeout")
        baseline = SessionController(request, before_provider, before_clock, before_clock.wait,
                                     context_observer=before_observer).run()
        original_baseline = baseline.to_dict()
        original_request = asdict(request)
        self.assertTrue(before_provider.closed and before_observer.closed)
        self.assertEqual(baseline.status, "deadline")
        self.assertLessEqual(baseline.duration_seconds, 60)
        self.assertTrue(any(item.protocol == "dns" and item.comparable
                            and item.outcome.value == "reply_timeout" for item in baseline.evidence))
        for simulated_outcome in ("success", "failure"):
            with self.subTest(simulated_outcome=simulated_outcome):
                executor = repair.SimulatedRepairExecutor(simulated_outcome)
                controller = repair.RepairController(repair.RepairRequest(), request, baseline,
                                                     executor=executor)
                offer = controller.prepare()
                controller.confirm(offer["request_id"], accepted=True, acknowledge_impact=True,
                                   acknowledge_no_restore=True)
                executed = controller.execute()
                self.assertEqual(executed["execution"]["status"], "simulated_" + simulated_outcome)
                after_clock, after_observer = FakeClock(), StableObserver()
                after_provider = DNSProvider(after_clock, "success")
                with patch.object(repair, "SessionController", wraps=SessionController) as created:
                    result = controller.verify(provider=after_provider, context_observer=after_observer,
                                               clock=after_clock, wait=after_clock.wait)
                created.assert_called_once()
                self.assertEqual(result["verification"]["status"], "completed")
                self.assertEqual(result["comparison"]["status"], "observed_dns_improvement")
                self.assertEqual(result["comparison"]["causal_attribution"], "not_established")
                self.assertIsNone(result["comparison"]["network_problem_resolved"])
                self.assertIs(result["execution"]["system_change_performed"], False)
                self.assertEqual(executor.calls, 1)
                self.assertTrue(after_provider.closed and after_observer.closed)
                self.assertEqual(result["verification"]["report"]["cleanup_errors"], [])
                self.assertLessEqual(result["verification"]["duration_seconds"], 60)
                self.assertEqual(baseline.to_dict(), original_baseline)
                self.assertEqual(asdict(request), original_request)
