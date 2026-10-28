"""Deterministic S1 process-provider checks; no commands/network/registry access."""
from __future__ import annotations

import base64
import io
import json
import threading
import sys
import types
import unittest
from unittest.mock import Mock, patch
import subprocess

from losshound.core import session_process as probes


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class FakeProcess:
    def __init__(self, clock, event, *, behavior="success"):
        self.pid = 1234
        self.clock = clock
        self.event = event
        self.behavior = behavior
        self.returncode = None
        self.owned = False
        self.killed = False
        self.inputs = []
        self.stdin, self.stdout, self.stderr = io.StringIO(), io.StringIO(), io.StringIO()

    def communicate(self, input=None, timeout=None):
        if self.killed:
            self.returncode = 1
            return "", ""
        if not self.owned:
            raise AssertionError("Request supplied before private job assignment")
        self.inputs.append(input)
        if self.behavior == "exit_error":
            self.returncode = 7
            return "worker partial output", "native permission details"
        if self.behavior == "malformed":
            self.returncode = 0
            return "{bad json", "parse provenance"
        if self.behavior == "success":
            self.returncode = 0
            return json.dumps(probes._result("success", packets_sent=1, packets_received=1)), ""
        self.clock.value += timeout
        if self.behavior == "cancel":
            self.event.set()
        raise subprocess.TimeoutExpired("owned-probe", timeout)

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = 1


class FakeJob:
    def __init__(self, process):
        self.process = process
        process.owned = True
        self.closed = False
        self.handle = 1
        self.name = "Local\\Losshound-S1-" + "a" * 32

    def terminate(self):
        self.process.kill()

    def active_count(self):
        return 0

    def close(self):
        self.closed = True
        self.handle = None


class ProcessProviderTests(unittest.TestCase):
    def run_fake(self, behavior="success"):
        clock, event = FakeClock(), threading.Event()
        process = FakeProcess(clock, event, behavior=behavior)
        provider = probes.WindowsProbeProvider(clock)
        provider.set_cleanup_deadline(4.0)
        with patch.object(probes.sys, "platform", "win32"), \
             patch.object(probes.WindowsProbeProvider, "_command", return_value=["trusted-python"]), \
             patch.object(probes.subprocess, "Popen", return_value=process) as popen, \
             patch.object(probes, "_OwnedJob", side_effect=FakeJob):
            result = provider.probe("icmp", "127.0.0.1", 2.0, event)
        return provider, result, process, popen

    def test_worker_gets_request_only_after_private_job_assignment(self):
        provider, result, process, popen = self.run_fake()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["packets_sent"], 1)
        request = json.loads(process.inputs[0])
        self.assertEqual(request["protocol"], "icmp")
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertEqual(provider.active_pids, [])
        self.assertEqual(provider.cleanup_errors, [])

    def test_startup_allowance_preserves_native_timeout_and_absolute_deadline(self):
        clock, event = FakeClock(), threading.Event()
        process = FakeProcess(clock, event, behavior="stall")
        original = process.communicate
        def delayed(input=None, timeout=None):
            if clock() >= 2.1:
                process.behavior = "success"
            return original(input, timeout)
        process.communicate = delayed
        provider = probes.WindowsProbeProvider(clock)
        provider.set_cleanup_deadline(3.5)
        with patch.object(probes.sys, "platform", "win32"), \
             patch.object(provider, "_command", return_value=["trusted-python"]), \
             patch.object(probes.subprocess, "Popen", return_value=process), \
             patch.object(probes, "_OwnedJob", side_effect=FakeJob):
            result = provider.probe("icmp", "127.0.0.1", 3.0, event)
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(json.loads(process.inputs[0])["timeout_ms"], 1000)
        self.assertGreaterEqual(result["data"]["parent_timing"]["response_elapsed_seconds"], 2.1)
        self.assertLessEqual(result["data"]["parent_timing"]["return_elapsed_seconds"], 3.0)
        self.assertEqual(provider.active_pids, [])
        self.assertEqual(provider.cleanup_errors, [])

    def test_startup_allowance_is_clipped_by_short_subdeadline(self):
        clock, event = FakeClock(), threading.Event()
        process = FakeProcess(clock, event, behavior="stall")
        provider = probes.WindowsProbeProvider(clock)
        provider.set_cleanup_deadline(1.0)
        with patch.object(probes.sys, "platform", "win32"), \
             patch.object(provider, "_command", return_value=["trusted-python"]), \
             patch.object(probes.subprocess, "Popen", return_value=process), \
             patch.object(probes, "_OwnedJob", side_effect=FakeJob):
            result = provider.probe("icmp", "127.0.0.1", 1.0, event)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertLessEqual(clock(), 1.0)
        self.assertTrue(process.killed)
        self.assertEqual(provider.active_pids, [])
        self.assertEqual(json.loads(process.inputs[0])["timeout_ms"], 1000)

    def test_cancelled_running_worker_is_reaped_without_inventing_packet_counts(self):
        provider, result, process, _ = self.run_fake("cancel")
        self.assertEqual(result["outcome"], "cancelled")
        self.assertIsNone(result["packets_sent"])
        self.assertIsNone(result["packets_received"])
        self.assertTrue(process.killed)
        self.assertEqual(provider.active_pids, [])

    def test_execution_watchdog_is_tool_error_not_network_timeout(self):
        provider, result, process, _ = self.run_fake("stall")
        self.assertEqual(result["outcome"], "execution_error")
        self.assertIsNone(result["packets_sent"])
        self.assertTrue(process.killed)
        self.assertLessEqual(provider.clock(), 4.0)

    def test_job_assignment_failure_never_sends_request(self):
        clock, event = FakeClock(), threading.Event()
        process = FakeProcess(clock, event)
        provider = probes.WindowsProbeProvider(clock)
        provider.set_cleanup_deadline(2)
        with patch.object(probes.sys, "platform", "win32"), \
             patch.object(probes.WindowsProbeProvider, "_command", return_value=["trusted-python"]), \
             patch.object(probes.subprocess, "Popen", return_value=process), \
             patch.object(probes, "_OwnedJob", side_effect=OSError("Cannot contain worker")):
            result = provider.probe("icmp", "127.0.0.1", 1, event)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertEqual(process.inputs, [])
        self.assertTrue(process.killed)

    def test_job_assignment_error_preserves_stage_and_native_error(self):
        clock, event = FakeClock(), threading.Event()
        process = FakeProcess(clock, event)
        failure = PermissionError(13, "private job access denied")
        failure.winerror = 5
        provider = probes.WindowsProbeProvider(clock)
        with patch.object(probes.sys, "platform", "win32"), \
             patch.object(probes.WindowsProbeProvider, "_command", return_value=["trusted-python"]), \
             patch.object(probes.subprocess, "Popen", return_value=process), \
             patch.object(probes, "_OwnedJob", side_effect=failure):
            result = provider.read_network(1, event)
        self.assertEqual(result["data"]["stage"], "worker_job_assignment")
        self.assertEqual(result["data"]["errno"], 13)
        self.assertEqual(result["data"]["winerror"], 5)
        self.assertIn("private job access denied", result["data"]["exception_message"])
        self.assertEqual(result["data"]["context_status"], "UNKNOWN")
        self.assertEqual(process.inputs, [])
        self.assertTrue(process.killed)

    def test_nonzero_and_malformed_worker_replies_preserve_streams(self):
        for behavior, stage in (("exit_error", "worker_response"),
                                ("malformed", "worker_response_json")):
            with self.subTest(behavior=behavior):
                _, result, _, _ = self.run_fake(behavior)
                self.assertEqual(result["outcome"], "execution_error")
                self.assertEqual(result["data"]["stage"], stage)
                self.assertTrue(result["data"]["stdout"])
                self.assertTrue(result["data"]["stderr"])
                self.assertIsNone(result["packets_sent"])

    def test_expired_or_cancelled_work_is_never_launched(self):
        provider = probes.WindowsProbeProvider(lambda: 3)
        event = threading.Event()
        with patch.object(probes.subprocess, "Popen") as popen:
            self.assertEqual(provider.probe("icmp", "127.0.0.1", 2, event)["outcome"], "not_attempted")
            event.set()
            self.assertEqual(provider.probe("icmp", "127.0.0.1", 9, event)["outcome"], "cancelled")
        popen.assert_not_called()

    def test_protocol_allowlist_cannot_execute_optimizer_input(self):
        with patch.object(probes.subprocess, "Popen") as popen:
            result = probes.WindowsProbeProvider().probe("optimize", "anything", 999, threading.Event())
        self.assertEqual(result["outcome"], "unsupported")
        popen.assert_not_called()

    def test_closed_job_is_never_queried_as_the_current_process_job(self):
        job = probes._OwnedJob.__new__(probes._OwnedJob)
        job.handle = None
        job.api = Mock()
        with self.assertRaises(OSError):
            job.active_count()
        job.api.QueryInformationJobObject.assert_not_called()

    def test_cleanup_failure_is_reported_and_still_kills_owned_worker(self):
        clock, event = FakeClock(), threading.Event()
        process = FakeProcess(clock, event)
        job = FakeJob(process)
        job.terminate = Mock(side_effect=OSError("job termination failed"))
        provider = probes.WindowsProbeProvider(clock)
        provider._stop(process, job, 1)
        self.assertTrue(process.killed)
        self.assertTrue(provider.cleanup_errors)
        self.assertTrue(job.closed)

    def test_source_command_excludes_site_packages_and_pythonpath(self):
        with patch.object(probes.sys, "frozen", False, create=True):
            command = probes.WindowsProbeProvider._command()
        self.assertEqual(command[1:4], ["-I", "-S", "-B"])
        self.assertTrue(command[0].lower().endswith(("python.exe", "python", "python3")))
        self.assertTrue(command[-2].endswith("session_process.py"))

    def test_frozen_command_uses_internal_readonly_worker(self):
        with patch.object(probes.sys, "frozen", True, create=True):
            command = probes.WindowsProbeProvider._command()
        self.assertEqual(command[1:], ["--s1-probe-worker"])


class WorkerTests(unittest.TestCase):
    def network(self, context, wifi):
        completed = subprocess.CompletedProcess(["trusted-powershell"], 0, json.dumps(context), "")
        with patch.object(probes, "_trusted_imports", return_value=lambda command: command), \
             patch.object(probes.subprocess, "run", return_value=completed) as run, \
             patch.object(probes, "_wifi_identity", return_value=wifi):
            result = probes._network()
        self.assertFalse(run.call_args.kwargs["shell"])
        return result

    def test_network_key_tracks_ext_and_vpn_without_signal_churn(self):
        context = {"adapters": [], "routes": [{"DestinationPrefix": "0.0.0.0/0"}], "gateway": "192.0.2.1"}
        wifi = [{"guid": "same", "ssid_hex": "aa", "bssid": "00:11:22:33:44:55", "state": 1}]
        first = self.network(context, wifi)
        same = self.network(context, list(wifi))
        ext = self.network(context, [{**wifi[0], "bssid": "00:11:22:33:44:66"}])
        vpn = self.network({**context, "routes": [{"DestinationPrefix": "0.0.0.0/1"}]}, wifi)
        self.assertEqual(first["data"]["identity"], same["data"]["identity"])
        self.assertNotEqual(first["data"]["identity"], ext["data"]["identity"])
        self.assertNotEqual(first["data"]["identity"], vpn["data"]["identity"])

    def test_identity_failure_does_not_generate_old_or_empty_identity(self):
        completed = subprocess.CompletedProcess([], 1, "", "")
        with patch.object(probes, "_trusted_imports", return_value=lambda command: command), \
             patch.object(probes.subprocess, "run", return_value=completed):
            result = probes._network()
        self.assertEqual(result["outcome"], "execution_error")
        self.assertNotIn("identity", result["data"])

    def test_network_error_retains_native_stage_and_exact_bounded_bytes(self):
        raw = {"stage": "Get-NetAdapter", "exception_type": "CimException",
               "exception_message": "CIM access was unavailable", "winerror": 5,
               "error_record": "native error record"}
        stderr = json.dumps(raw).encode("utf-8")
        completed = subprocess.CompletedProcess([], 1, b"", stderr)
        with patch.object(probes, "_trusted_imports", return_value=lambda command: command), \
             patch.object(probes.subprocess, "run", return_value=completed):
            result = probes._network()
        data = result["data"]
        self.assertEqual(data["stage"], "Get-NetAdapter")
        self.assertEqual(data["context_status"], "UNKNOWN")
        self.assertEqual(data["exit_code"], 1)
        self.assertEqual(data["powershell_error"]["winerror"], 5)
        self.assertEqual(data["powershell_error"]["exception_type"], "CimException")
        self.assertEqual(base64.b64decode(data["stderr_raw_base64"]), stderr)
        self.assertNotIn("identity", data)

    def test_network_timeout_and_invalid_json_keep_error_origin_and_streams(self):
        for failure, stage in (
            (subprocess.TimeoutExpired("trusted-powershell", 4, b"partial", b"blocked"), "network_query"),
            (subprocess.CompletedProcess([], 0, b"{invalid", b"diagnostic"), "network_json"),
        ):
            with self.subTest(stage=stage):
                kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with patch.object(probes, "_trusted_imports", return_value=lambda command: command), \
                     patch.object(probes.subprocess, "run", **kwargs):
                    result = probes._network()
                self.assertEqual(result["outcome"], "execution_error")
                self.assertEqual(result["data"]["stage"], stage)
                self.assertEqual(result["data"]["context_status"], "UNKNOWN")
                self.assertTrue(result["data"]["exception_message"])
                self.assertTrue(result["data"]["stdout"])
                self.assertTrue(result["data"]["stderr"])
                self.assertNotIn("identity", result["data"])

    def test_wlan_permission_denial_invalidates_all_network_context(self):
        failure = probes._native_failure("WlanQueryInterface", 5)
        completed = subprocess.CompletedProcess([], 0, '{"adapters":[]}', "")
        with patch.object(probes, "_trusted_imports", return_value=lambda command: command), \
             patch.object(probes.subprocess, "run", return_value=completed), \
             patch.object(probes, "_wifi_identity", side_effect=failure):
            result = probes._network()
        self.assertEqual(result["data"]["stage"], "WlanQueryInterface")
        self.assertEqual(result["data"]["winerror"], 5)
        self.assertEqual(result["data"]["context_status"], "UNKNOWN")
        self.assertNotIn("identity", result["data"])

    def test_diagnostic_values_are_bounded_without_losing_original_bytes(self):
        raw = bytes([255]) * (probes._MAX_DIAGNOSTIC_BYTES + 20)
        data = probes._diagnostics("read", ValueError("x" * 10000), stderr=raw)
        self.assertLessEqual(len(data["exception_message"]), probes._MAX_DIAGNOSTIC_BYTES)
        self.assertEqual(base64.b64decode(data["stderr_raw_base64"]),
                         raw[:probes._MAX_DIAGNOSTIC_BYTES])
        self.assertTrue(data["stderr_truncated"])

    def test_icmp_access_denied_is_tool_error_before_any_packet_is_sent(self):
        import losshound.core as core
        native = types.ModuleType("losshound.core.icmp_ping")
        native._iphlpapi = Mock()
        native._iphlpapi.IcmpCreateFile.return_value = None
        native._INVALID_HANDLE_VALUE = -1
        with patch.object(probes, "_trusted_imports"), \
             patch.object(core, "icmp_ping", native, create=True), \
             patch.dict(sys.modules, {"losshound.core.icmp_ping": native}), \
             patch.object(probes.ctypes, "get_last_error", return_value=5, create=True):
            result = probes._icmp("127.0.0.1", 500)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertEqual(result["data"]["stage"], "IcmpCreateFile")
        self.assertEqual(result["data"]["winerror"], 5)
        self.assertEqual(result["data"]["native_status"], 5)
        self.assertIsNone(result["packets_sent"])
        self.assertIsNone(result["packets_received"])
        native._iphlpapi.IcmpSendEcho.assert_not_called()
        native._iphlpapi.IcmpCloseHandle.assert_not_called()

    def test_icmp_send_access_denied_has_unknown_sent_count_and_closes_handle(self):
        import losshound.core as core
        native = types.ModuleType("losshound.core.icmp_ping")
        native._iphlpapi = Mock()
        native._iphlpapi.IcmpCreateFile.return_value = 42
        native._iphlpapi.IcmpSendEcho.return_value = 0
        native._INVALID_HANDLE_VALUE = -1
        native._ICMP_ECHO_REPLY = probes.ctypes.c_uint32
        native._PAYLOAD = b"diagnostic"
        with patch.object(probes, "_trusted_imports"), \
             patch.object(core, "icmp_ping", native, create=True), \
             patch.dict(sys.modules, {"losshound.core.icmp_ping": native}), \
             patch.object(probes.ctypes, "get_last_error", return_value=5, create=True):
            result = probes._icmp("127.0.0.1", 500)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertEqual(result["data"]["stage"], "IcmpSendEcho")
        self.assertEqual(result["data"]["winerror"], 5)
        self.assertIsNone(result["packets_sent"])
        self.assertIsNone(result["packets_received"])
        native._iphlpapi.IcmpCloseHandle.assert_called_once_with(42)

    def test_network_script_contains_readonly_commands_only(self):
        script = probes._NETWORK_SCRIPT.lower()
        for forbidden in ("set-net", "new-net", "remove-net", "restart-", "clear-", "netsh", "invoke-expression"):
            self.assertNotIn(forbidden, script)
        self.assertIn("get-netroute", script)
        self.assertIn("destinationprefix", script)

    def test_ipv6_literal_dispatches_to_bounded_native_probe(self):
        from losshound.core import session_protocols
        expected = probes._result("success", packets_sent=1, packets_received=1,
                                  data={"family": "IPv6"})
        with patch.object(session_protocols, "icmp6_probe", return_value=expected) as native:
            result = probes._icmp("::1", 1000)
        native.assert_called_once_with("::1", 1000)
        self.assertIs(result, expected)

    def test_dns_uses_os_ipv4_resolver_without_claiming_wire_packets(self):
        with patch.object(probes.socket, "getaddrinfo", return_value=[(0, 0, 0, "", ("127.0.0.1", 0))]) as resolve:
            result = probes._dns("localhost")
        self.assertEqual(resolve.call_args.args[2], probes.socket.AF_INET)
        self.assertEqual(result["outcome"], "success")
        self.assertIsNone(result["packets_sent"])

    def test_dns_error_retains_error_provenance(self):
        with patch.object(probes.socket, "getaddrinfo", side_effect=probes.socket.gaierror(11001, "missing")):
            result = probes._dns("example.invalid")
        self.assertEqual(result["outcome"], "unreachable")
        self.assertEqual(result["data"]["resolver_error"], 11001)
        self.assertEqual(result["data"]["errno"], 11001)
        self.assertEqual(result["data"]["exception_type"], "gaierror")
        self.assertIn("missing", result["data"]["exception_message"])
        self.assertEqual(result["data"]["target_scope"], "non_localhost")
        self.assertIsNone(result["packets_sent"])

    def test_localhost_resolution_does_not_establish_non_localhost_dns(self):
        answers = [(0, 0, 0, "", ("127.0.0.1", 0))]
        with patch.object(probes.socket, "getaddrinfo", return_value=answers):
            localhost = probes._dns("LOCALHOST.")
            other = probes._dns("example.com")
        self.assertEqual(localhost["data"]["target_scope"], "localhost")
        self.assertEqual(other["data"]["target_scope"], "non_localhost")
        for result in (localhost, other):
            self.assertTrue(result["data"]["resolver_result_only"])
            self.assertIsNone(result["packets_sent"])
            self.assertNotIn("healthy", result["data"])

    def test_dns_temporary_and_permission_failures_preserve_raw_errors_as_tool_errors(self):
        for failure in (probes.socket.gaierror(11002, "try again"),
                        PermissionError(13, "resolver access denied")):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(probes.socket, "getaddrinfo", side_effect=failure):
                    result = probes._dns("example.com")
                self.assertEqual(result["outcome"], "execution_error")
                self.assertEqual(result["data"]["stage"], "getaddrinfo")
                self.assertEqual(result["data"]["errno"], failure.errno)
                self.assertEqual(result["data"]["exception_message"], str(failure))
                self.assertEqual(result["data"]["target_scope"], "non_localhost")
                self.assertIsNone(result["packets_sent"])
                self.assertIsNone(result["packets_received"])

    def test_worker_rejects_arbitrary_commands_without_running_them(self):
        request = json.dumps({"protocol": "network", "target": "", "timeout_ms": 1000, "command": "bad"})
        output = io.StringIO()
        with patch.object(probes.sys, "stdin", io.StringIO(request)), \
             patch.object(probes.sys, "stdout", output), \
             patch.object(probes, "_repair_frozen_streams"), \
             patch.object(probes, "_network") as network:
            code = probes.worker_main()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["outcome"], "execution_error")
        network.assert_not_called()

    def test_direct_worker_request_cannot_probe_without_private_job(self):
        output = io.StringIO()
        request = {"protocol": "dns", "target": "localhost", "timeout_ms": 1000,
                   "job_name": "Local\\Losshound-S1-" + "a" * 32}
        with patch.object(probes.sys, "stdin", io.StringIO(json.dumps(request))), \
             patch.object(probes.sys, "stdout", output), \
             patch.object(probes.sys, "platform", "win32"), \
             patch.object(probes, "_repair_frozen_streams"), \
             patch.object(probes, "_verify_private_job", return_value=False), \
             patch.object(probes, "_dns") as dns:
            probes.worker_main()
        self.assertEqual(json.loads(output.getvalue())["outcome"], "execution_error")
        dns.assert_not_called()

    def test_private_job_name_validation_fails_closed(self):
        for name in (None, "", "SomeOtherJob", "Local\\Losshound-S1-" + "x" * 32):
            self.assertFalse(probes._verify_private_job(name))

    def test_worker_rejects_out_of_range_or_noninteger_timeout(self):
        for timeout in (0, 1001, True, "1000"):
            output = io.StringIO()
            with patch.object(probes.sys, "stdin", io.StringIO(json.dumps(
                    {"protocol": "icmp", "target": "127.0.0.1", "timeout_ms": timeout,
                     "job_name": "Local\\Losshound-S1-" + "a" * 32}))), \
                 patch.object(probes.sys, "stdout", output), \
                 patch.object(probes, "_repair_frozen_streams"), \
                 patch.object(probes, "_icmp") as icmp:
                probes.worker_main()
            self.assertEqual(json.loads(output.getvalue())["outcome"], "execution_error")
            icmp.assert_not_called()


if __name__ == "__main__":
    unittest.main()




