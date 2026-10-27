"""S3 adapter tests using simulated runners and fake WinAPI handles only.

No test in this module may invoke the real DNS-cache command or native loader.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import threading
import unittest
from unittest.mock import patch

from losshound.core import dns_cache, repair, windows_commands
from losshound.core.session import SessionReport, SessionRequest
from test_session_context_s1 import StableObserver
from test_session_s1 import FakeClock, FakeProvider


class RecordingRunner:
    simulation_only = True

    def __init__(self, *, status="succeeded", started=True, cleanup_confirmed=True,
                 cleanup_errors=(), exit_code=0, hook=None):
        self.calls = 0
        self.deadlines = []
        self.hook = hook
        self.result = dict(status=status, command_started=started, cleanup_confirmed=cleanup_confirmed,
                           cleanup_errors=list(cleanup_errors), exit_code=exit_code,
                           stage="SIMULATED-command", errno=None, winerror=None)

    def run(self, *, cancel_event, clock, deadline):
        self.calls += 1
        self.deadlines.append(deadline)
        if self.hook is not None:
            self.hook()
        return copy.deepcopy(self.result)


def native_adapter_for(recorder):
    # Keep the exact native type while replacing its bound method before binding.
    # The executor must retain this method, never look up the real method later.
    def simulated_native_run(_self, *, cancel_event, clock, deadline):
        return recorder.run(cancel_event=cancel_event, clock=clock, deadline=deadline)
    with patch.object(dns_cache.NativeDnsCommandRunner, "run", simulated_native_run):
        return dns_cache.WindowsDnsCacheExecutor(dns_cache.NativeDnsCommandRunner())


def controller_for(recorder=None, *, simulated_runner=False):
    recorder = recorder or RecordingRunner()
    adapter = (dns_cache.WindowsDnsCacheExecutor(recorder) if simulated_runner
               else native_adapter_for(recorder))
    request = SessionRequest(1, (), (), ipv6_targets=(), tcp_targets=())
    baseline = SessionReport("deadline", 1, duration_seconds=1,
                             incomplete=["SIMULATED baseline; insufficient comparison evidence"])
    controller = repair.RepairController(
        repair.RepairRequest(verification_seconds=1), request, baseline, executor=adapter)
    return controller, recorder, adapter


def approve(controller):
    offer = controller.prepare()
    confirmation = controller.confirm(
        offer["request_id"], accepted=True, acknowledge_impact=True,
        acknowledge_no_restore=True)
    return offer, confirmation


def direct_confirmation(request_id="SIMULATED-request"):
    return dict(status="confirmed", request_id=request_id, action=repair.DNS_CACHE_FLUSH,
                execution_mode="windows_dns_cache", accepted=True,
                acknowledge_impact=True, acknowledge_no_restore=True)


class NativeAdapterFlowTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(dns_cache, "_load_native",
                             side_effect=AssertionError("real native facilities are forbidden"))
        self.native_loader = guard.start()
        self.addCleanup(guard.stop)

    def verify_simulated(self, controller):
        clock = FakeClock()
        provider, observer = FakeProvider(clock), StableObserver()
        result = controller.verify(provider=provider, context_observer=observer,
                                   clock=clock, wait=clock.wait)
        self.assertTrue(provider.closed and observer.closed)
        return result

    def test_runner_is_explicit_mode_is_readonly_and_simulation_binding_cannot_be_swapped(self):
        with self.assertRaises(TypeError):
            dns_cache.WindowsDnsCacheExecutor()
        with self.assertRaises(TypeError):
            dns_cache.WindowsDnsCacheExecutor(object())
        recorder = RecordingRunner()
        adapter = dns_cache.WindowsDnsCacheExecutor(recorder)
        for attribute, value in (("mode", "simulation"), ("simulation_only", False),
                                 ("command_runner", RecordingRunner())):
            with self.subTest(attribute=attribute), self.assertRaises(AttributeError):
                setattr(adapter, attribute, value)
        recorder.simulation_only = False
        replacement_calls = []
        recorder.run = lambda **_kwargs: replacement_calls.append(True)
        result = adapter.execute(repair.RepairRequest(), request_id="SIMULATED-request",
                                 confirmation=direct_confirmation(), clock=FakeClock())
        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["system_change_performed"])
        self.assertEqual(recorder.calls, 1)
        self.assertEqual(replacement_calls, [])
        with self.assertRaises(RuntimeError):
            adapter.execute(repair.RepairRequest(), request_id="SIMULATED-request",
                            confirmation=direct_confirmation(), clock=FakeClock())

    def test_native_and_default_simulation_disclosures_are_distinct_without_native_fallback(self):
        controller, recorder, _adapter = controller_for()
        offer, confirmation = approve(controller)
        self.assertEqual(offer["execution_mode"], "windows_dns_cache")
        self.assertEqual(confirmation["execution_mode"], offer["execution_mode"])
        self.assertFalse(offer["simulation_only"])
        self.assertNotIn("simulation changes nothing", offer["impact"].lower())
        self.assertIn("cannot", offer["no_restore_warning"].lower())
        self.assertEqual(recorder.calls, 0)
        request = SessionRequest(1, (), (), ipv6_targets=(), tcp_targets=())
        default = repair.RepairController(repair.RepairRequest(verification_seconds=1),
                                          request, SessionReport("deadline", 1))
        default_offer, default_confirmation = approve(default)
        self.assertEqual(default_offer["execution_mode"], "simulation")
        self.assertEqual(default_confirmation["execution_mode"], "simulation")
        self.assertEqual(default.execute()["execution"]["status"], "simulated_success")
        with self.assertRaises(ValueError):
            default.verify(provider=None, context_observer=None)
        self.native_loader.assert_not_called()

    def test_preparation_confirmation_id_acknowledgements_and_mode_are_all_required(self):
        for phase in ("unprepared", "unconfirmed", "accepted", "acknowledge_impact",
                      "acknowledge_no_restore"):
            with self.subTest(phase=phase):
                controller, recorder, _adapter = controller_for()
                if phase != "unprepared":
                    offer = controller.prepare()
                    if phase != "unconfirmed":
                        values = dict(accepted=True, acknowledge_impact=True,
                                      acknowledge_no_restore=True)
                        values[phase] = False
                        controller.confirm(offer["request_id"], **values)
                result = controller.execute(clock=FakeClock())
                self.assertEqual(result["execution"]["status"], "blocked")
                self.assertEqual(recorder.calls, 0)
        controller, recorder, _adapter = controller_for()
        offer = controller.prepare()
        with self.assertRaises(ValueError):
            controller.confirm(offer["request_id"] + "-other", accepted=True,
                               acknowledge_impact=True, acknowledge_no_restore=True)
        wrong_mode = direct_confirmation()
        wrong_mode["execution_mode"] = "simulation"
        with self.assertRaises(ValueError):
            _adapter.execute(repair.RepairRequest(), request_id="SIMULATED-request",
                             confirmation=wrong_mode, clock=FakeClock())
        self.assertEqual(recorder.calls, 0)

    def test_concurrent_and_repeated_execution_claim_only_one_command(self):
        entered, release, start = threading.Event(), threading.Event(), threading.Barrier(3)
        def block():
            entered.set()
            if not release.wait(3):
                raise AssertionError("SIMULATED runner was not released")
        controller, recorder, _adapter = controller_for(RecordingRunner(hook=block))
        approve(controller)
        results, errors = [], []
        def execute():
            start.wait()
            try:
                results.append(controller.execute(clock=FakeClock()))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=execute) for _ in range(2)]
        for thread in threads:
            thread.start()
        try:
            start.wait()
            self.assertTrue(entered.wait(2))
        finally:
            release.set()
            for thread in threads:
                thread.join(3)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(recorder.calls, 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)
        with self.assertRaises(RuntimeError):
            controller.execute(clock=FakeClock())
        self.assertEqual(recorder.calls, 1)

    def test_operation_success_is_not_improvement_and_verification_is_independent_and_single_use(self):
        controller, recorder, _adapter = controller_for()
        approve(controller)
        result = controller.execute(clock=FakeClock())
        self.assertEqual(result["execution"]["status"], "succeeded")
        self.assertTrue(result["execution"]["command_started"])
        self.assertIsNone(result["execution"]["system_change_performed"])
        self.assertEqual(result["verification"]["status"], "pending")
        self.assertIsNone(result["verification"]["report"])
        self.assertEqual(result["comparison"]["status"], "inconclusive")
        verified = self.verify_simulated(controller)
        self.assertEqual(verified["comparison"]["causal_attribution"], "not_established")
        self.assertNotEqual(verified["comparison"]["status"], "observed_dns_improvement")
        self.assertEqual(recorder.calls, 1)
        with self.assertRaises(RuntimeError):
            self.verify_simulated(controller)

    def test_no_start_or_unconfirmed_cleanup_refuses_independent_verification(self):
        cases = (
            RecordingRunner(status="permission_denied", started=False, exit_code=None),
            RecordingRunner(status="cleanup_failed", cleanup_confirmed=False,
                            cleanup_errors=("SIMULATED child not reaped",)),
            RecordingRunner(cleanup_confirmed=None),
        )
        for recorder in cases:
            with self.subTest(result=recorder.result):
                controller, recorder, _adapter = controller_for(recorder)
                approve(controller)
                controller.execute(clock=FakeClock())
                with self.assertRaises(RuntimeError):
                    self.verify_simulated(controller)
                self.assertEqual(recorder.calls, 1)

    def test_started_failure_or_uncertain_start_with_confirmed_cleanup_can_be_verified(self):
        for status, started, exit_code in (("failed", True, 42),
                                          ("timed_out", True, None),
                                          ("execution_error", None, None)):
            with self.subTest(status=status):
                controller, recorder, _adapter = controller_for(
                    RecordingRunner(status=status, started=started, exit_code=exit_code))
                approve(controller)
                executed = controller.execute(clock=FakeClock())
                self.assertEqual(executed["verification"]["status"], "pending")
                verified = self.verify_simulated(controller)
                self.assertNotEqual(verified["verification"]["status"], "not_started")
                self.assertEqual(recorder.calls, 1)

    def test_concurrent_verifications_claim_only_one_new_session(self):
        controller, recorder, _adapter = controller_for()
        approve(controller)
        controller.execute(clock=FakeClock())
        entered, release, start = threading.Event(), threading.Event(), threading.Barrier(3)
        clock = FakeClock()
        class BlockingProvider(FakeProvider):
            def read_network(self, *args):
                if not entered.is_set():
                    entered.set()
                    if not release.wait(3):
                        raise AssertionError("SIMULATED verification was not released")
                return super().read_network(*args)
        provider, observer = BlockingProvider(clock), StableObserver()
        results, errors = [], []
        def verify():
            start.wait()
            try:
                results.append(controller.verify(provider=provider, context_observer=observer,
                                                 clock=clock, wait=clock.wait))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=verify) for _ in range(2)]
        for thread in threads:
            thread.start()
        try:
            start.wait()
            self.assertTrue(entered.wait(2))
        finally:
            release.set()
            for thread in threads:
                thread.join(3)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertEqual(recorder.calls, 1)
        self.assertTrue(provider.closed and observer.closed)

    def test_execution_budget_is_sixty_seconds_and_only_explicitly_tightened(self):
        controller, recorder, _adapter = controller_for()
        approve(controller)
        clock = FakeClock()
        controller.execute(clock=clock)
        self.assertEqual(recorder.deadlines, [160.0])
        tightened, tightened_runner, _adapter = controller_for()
        approve(tightened)
        tightened.execute(clock=FakeClock(), absolute_deadline=100.5)
        self.assertEqual(tightened_runner.deadlines, [100.5])
        for reason in ("cancelled", "timed_out"):
            with self.subTest(reason=reason):
                controller, recorder, _adapter = controller_for()
                approve(controller)
                event = threading.Event()
                if reason == "cancelled":
                    event.set()
                result = controller.execute(cancel_event=event, clock=FakeClock(),
                                            absolute_deadline=99.0 if reason == "timed_out" else None)
                self.assertEqual(result["execution"]["status"], reason)
                self.assertEqual(recorder.calls, 0)
        invalid, recorder, _adapter = controller_for()
        approve(invalid)
        with self.assertRaises(ValueError):
            invalid.execute(clock=FakeClock(), absolute_deadline=161.0)
        self.assertEqual(recorder.calls, 0)

    def test_contradictory_success_or_failure_facts_do_not_allow_verification(self):
        for status, started, exit_code in (("succeeded", False, 0), ("failed", True, 0)):
            with self.subTest(status=status):
                controller, recorder, _adapter = controller_for(
                    RecordingRunner(status=status, started=started, exit_code=exit_code))
                approve(controller)
                result = controller.execute(clock=FakeClock())
                self.assertEqual(result["execution"]["status"], "execution_error")
                self.assertFalse(result["execution"]["cleanup_confirmed"])
                self.assertIsNone(result["execution"]["system_change_performed"])
                with self.assertRaises(RuntimeError):
                    self.verify_simulated(controller)


class FakeNative:
    """Entirely in-memory fake for the one owned process, thread and Job."""

    def __init__(self, *, behavior="success", close_failure=None, resume_count=1):
        self.clock, self.event = FakeClock(), threading.Event()
        self.behavior, self.close_failure, self.resume_count = behavior, close_failure, resume_count
        self.events, self.close_attempts, self.create_args = [], [], None
        self.done = False
        self.api = self
        self.kernel = self
        outer = self
        class Job:
            def __init__(self, process):
                outer.events.append("assign")
                outer.assigned_process = process
                self.handle = 303
                if outer.behavior == "assignment_failure":
                    raise OSError("SIMULATED job assignment failure")
            def active_count(self):
                return 0 if outer.done else 1
            def terminate(self):
                outer.events.append("terminate_job")
                outer.done = True
            def close(self):
                outer.events.append("close_job")
                self.handle = None
        self.job_type = Job

    def CreateProcess(self, *args):
        self.events.append("create")
        self.create_args = args
        if self.behavior == "permission_denied":
            error = PermissionError(13, "SIMULATED access denied")
            error.winerror = 5
            raise error
        if self.behavior == "cancel_before_resume":
            self.event.set()
        if self.behavior == "timeout_before_resume":
            self.clock.now = 101.0
        return 101, 102, 1001, 1002

    def ResumeThread(self, handle):
        self.events.append("resume")
        if handle != 102:
            raise AssertionError("wrong primary thread handle")
        if self.behavior == "resume_exception":
            raise OSError("SIMULATED ResumeThread uncertainty")
        if self.behavior == "cancel_after_resume":
            self.event.set()
        return self.resume_count

    def WaitForSingleObject(self, handle, milliseconds):
        self.events.append("wait")
        if handle != 101:
            raise AssertionError("wrong process handle")
        if self.done:
            return dns_cache.WAIT_OBJECT_0
        if self.behavior == "timeout_after_resume":
            self.clock.now += max(0.001, milliseconds / 1000.0)
            return dns_cache.WAIT_TIMEOUT
        self.done = True
        return dns_cache.WAIT_OBJECT_0

    def GetExitCodeProcess(self, handle):
        self.events.append("exit")
        return 42 if self.behavior == "exit_failure" else 0

    def TerminateProcess(self, handle, exit_code):
        self.events.append("terminate_process")
        self.done = True

    def CloseHandle(self, handle):
        self.close_attempts.append(handle)
        self.events.append("close_" + str(handle))
        if handle == self.close_failure:
            raise OSError("SIMULATED handle release failure")


@contextmanager
def mocked_native(fake):
    with patch.object(dns_cache.sys, "platform", "win32"), \
         patch.object(dns_cache, "_load_native",
                      return_value=(fake.api, fake.kernel, fake.job_type, object)), \
         patch.object(windows_commands, "windows_command",
                      return_value=[r"C:\Windows\System32\ipconfig.exe", "/flushdns"]) as resolve, \
         patch.object(dns_cache.time, "sleep",
                      side_effect=lambda seconds: setattr(fake.clock, "now", fake.clock.now + seconds)):
        yield resolve


class NativeCommandRunnerTests(unittest.TestCase):
    def run_fake(self, fake, *, deadline=101.0):
        with mocked_native(fake) as resolve:
            result = dns_cache.NativeDnsCommandRunner().run(
                cancel_event=fake.event, clock=fake.clock, deadline=deadline)
        return result, resolve

    def assert_handles_released(self, fake):
        self.assertEqual(fake.close_attempts.count(101), 1)
        self.assertEqual(fake.close_attempts.count(102), 1)

    def test_fixed_command_is_suspended_owned_then_resumed_and_all_handles_are_released(self):
        fake = FakeNative()
        result, resolve = self.run_fake(fake)
        resolve.assert_called_once_with(["ipconfig", "/flushdns"])
        self.assertEqual(fake.create_args[0], r"C:\Windows\System32\ipconfig.exe")
        self.assertIn("/flushdns", fake.create_args[1])
        self.assertFalse(fake.create_args[4])
        flags = fake.create_args[5]
        self.assertTrue(flags & dns_cache.CREATE_SUSPENDED)
        self.assertTrue(flags & dns_cache.CREATE_NO_WINDOW)
        self.assertLess(fake.events.index("create"), fake.events.index("assign"))
        self.assertLess(fake.events.index("assign"), fake.events.index("resume"))
        self.assertLess(fake.events.index("resume"), fake.events.index("wait"))
        self.assertEqual(fake.assigned_process._handle, 101)
        self.assertEqual(fake.assigned_process.pid, 1001)
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["command_started"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(result["cleanup_errors"], [])
        self.assertIn(303, fake.close_attempts)
        self.assert_handles_released(fake)

    def test_pre_cancel_expired_deadline_and_unsupported_platform_never_create_command(self):
        for case in ("cancel", "deadline", "unsupported"):
            with self.subTest(case=case):
                fake = FakeNative()
                if case == "cancel":
                    fake.event.set()
                with mocked_native(fake), patch.object(
                        dns_cache.sys, "platform", "linux" if case == "unsupported" else "win32"):
                    result = dns_cache.NativeDnsCommandRunner().run(
                        cancel_event=fake.event, clock=fake.clock,
                        deadline=99.0 if case == "deadline" else 101.0)
                self.assertEqual(result["status"], {"cancel": "cancelled", "deadline": "timed_out",
                                                   "unsupported": "unsupported"}[case])
                self.assertFalse(result["command_started"])
                self.assertNotIn("create", fake.events)

    def test_permission_denial_and_nonzero_exit_keep_distinct_execution_facts(self):
        denied, _resolve = self.run_fake(FakeNative(behavior="permission_denied"))
        self.assertEqual(denied["status"], "permission_denied")
        self.assertFalse(denied["command_started"])
        self.assertEqual(denied["winerror"], 5)
        fake = FakeNative(behavior="exit_failure")
        failed, _resolve = self.run_fake(fake)
        self.assertEqual(failed["status"], "failed")
        self.assertTrue(failed["command_started"])
        self.assertEqual(failed["exit_code"], 42)
        self.assertTrue(failed["cleanup_confirmed"])
        self.assert_handles_released(fake)

    def test_assignment_failure_never_resumes_and_reaps_the_suspended_child(self):
        fake = FakeNative(behavior="assignment_failure")
        result, _resolve = self.run_fake(fake)
        self.assertEqual(result["status"], "execution_error")
        self.assertFalse(result["command_started"])
        self.assertNotIn("resume", fake.events)
        self.assertIn("terminate_process", fake.events)
        self.assertTrue(result["cleanup_confirmed"])
        self.assert_handles_released(fake)

    def test_resume_uncertainty_does_not_claim_that_the_command_was_not_started(self):
        for behavior, count in (("success", 0), ("resume_exception", 1)):
            with self.subTest(behavior=behavior):
                fake = FakeNative(behavior=behavior, resume_count=count)
                result, _resolve = self.run_fake(fake)
                self.assertEqual(result["status"], "execution_error")
                self.assertIsNone(result["command_started"])
                self.assertTrue(result["cleanup_confirmed"])
                self.assertIn("terminate_job", fake.events)
                self.assert_handles_released(fake)

    def test_cancel_or_deadline_after_create_is_rechecked_before_resume_and_after_resume(self):
        cases = (("cancel_before_resume", "cancelled", False, 101.0),
                 ("timeout_before_resume", "timed_out", False, 101.0),
                 ("cancel_after_resume", "cancelled", True, 101.0),
                 ("timeout_after_resume", "timed_out", True, 100.2))
        for behavior, expected, started, deadline in cases:
            with self.subTest(behavior=behavior):
                fake = FakeNative(behavior=behavior)
                result, _resolve = self.run_fake(fake, deadline=deadline)
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["command_started"], started)
                self.assertTrue(result["cleanup_confirmed"])
                self.assertEqual("resume" in fake.events, started)
                self.assertIn("terminate_job", fake.events)
                self.assert_handles_released(fake)

    def test_job_or_thread_handle_release_failure_is_not_reported_as_successful_cleanup(self):
        for handle in (303, 102):
            with self.subTest(handle=handle):
                fake = FakeNative(close_failure=handle)
                result, _resolve = self.run_fake(fake)
                self.assertEqual(result["status"], "cleanup_failed")
                self.assertEqual(result["operation_status"], "succeeded")
                self.assertFalse(result["cleanup_confirmed"])
                self.assertTrue(result["cleanup_errors"])
                self.assert_handles_released(fake)


if __name__ == "__main__":
    unittest.main()
