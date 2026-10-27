"""Offline tests for dual-stack owned-worker probe contracts."""
import ctypes
import io
import json
import socket
import ssl
import unittest
import uuid
from unittest.mock import MagicMock, patch

from losshound.core import session_process as workers
from losshound.core import session_protocols as probes


class ProtocolValidationTests(unittest.TestCase):
    def test_tcp_explicit_ipv4_ipv6_scope_and_port(self):
        self.assertEqual(probes.parse_tcp_target("example.com:443"), ("example.com", 443))
        self.assertEqual(probes.parse_tcp_target("[fe80::1%7]:80"), ("fe80::1%7", 80))
        for target in ("::1:80", "host:0", "host:65536", "host:abc", "user@host:80", "host:80/path"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                probes.parse_tcp_target(target)

    def test_web_rejects_credentials_fragment_controls_and_non_http(self):
        self.assertEqual(probes.validate_web_url("https://example.com/path"), "https://example.com/path")
        for target in ("ftp://example.com/", "http://user:secret@example.com/", "http://@example.com/",
                       "https://example.com/#", "https://example.com/#secret", "http://example.com/\r\nHeader:x",
                       "http://example.com:65536/", "http://example.com:/", "http://example.com\\evil/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                probes.validate_web_url(target)

    def test_protocol_and_url_scheme_must_match(self):
        with self.assertRaises(ValueError):
            probes.validate_target("https6", "http://example.com/")
        with self.assertRaises(ValueError):
            probes.validate_target("shell", "anything")


class NetworkSummaryTests(unittest.TestCase):
    def snapshot(self):
        return {
            "interfaces": [{"AddressFamily": 2, "InterfaceIndex": 2, "InterfaceMetric": 100},
                           {"AddressFamily": 2, "InterfaceIndex": 7, "InterfaceMetric": 5},
                           {"AddressFamily": 23, "InterfaceIndex": 7, "InterfaceMetric": 8}],
            "addresses": [{"IPAddress": "192.168.1.5", "InterfaceIndex": 2, "AddressState": 4},
                          {"IPAddress": "10.0.0.5", "InterfaceIndex": 7, "AddressState": 4},
                          {"IPAddress": "2001:db8::5", "InterfaceIndex": 7, "AddressState": 4},
                          {"IPAddress": "fe80::5", "InterfaceIndex": 7, "AddressState": 4}],
            "routes": [{"AddressFamily": 2, "InterfaceIndex": 2, "DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.1.1", "RouteMetric": 1},
                       {"AddressFamily": 2, "InterfaceIndex": 7, "DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1", "RouteMetric": 20},
                       {"AddressFamily": 23, "InterfaceIndex": 7, "DestinationPrefix": "::/0", "NextHop": "fe80::1", "RouteMetric": 2}],
            "wifi": {"interfaces": [{"state": "connected"}]},
        }

    def test_dual_stack_metrics_and_scoped_ipv6_gateway(self):
        snapshot = self.snapshot()
        result = probes.summarize_network(snapshot)
        v4, v6 = result["families"]["IPv4"], result["families"]["IPv6"]
        self.assertEqual(v4["default_route"]["interface_index"], 7)
        self.assertEqual(v4["default_route"]["metric"], 25)
        self.assertEqual(v6["default_route"]["gateway"], "fe80::1%7")
        self.assertEqual(v6["default_route"]["metric"], 10)
        self.assertTrue(v4["available"] and v6["available"])
        self.assertEqual(result["wifi"], snapshot["wifi"])
        self.assertEqual(snapshot["routes"][2]["NextHop"], "fe80::1")

    def test_wifi_summary_preserves_correlated_observations(self):
        snapshot = self.snapshot()
        snapshot["wifi_observations"] = [{"interface_index": 7, "state": 1, "signal_quality": 19}]
        result = probes.summarize_network(snapshot)
        self.assertEqual(result["wifi"], snapshot["wifi_observations"])
        self.assertIsNot(result["wifi"][0], snapshot["wifi_observations"][0])

    def test_no_ipv6_is_configuration_absence_not_health(self):
        snapshot = self.snapshot()
        snapshot["routes"] = snapshot["routes"][:2]
        snapshot["addresses"] = snapshot["addresses"][:2]
        v6 = probes.summarize_network(snapshot)["families"]["IPv6"]
        self.assertFalse(v6["available"])
        self.assertEqual(v6["status"], "incomplete")
        self.assertIsNone(v6["default_route"])

    def test_disconnected_interface_cannot_confirm_default_route(self):
        snapshot = self.snapshot()
        for interface in snapshot["interfaces"]:
            interface["ConnectionState"] = 0
        families = probes.summarize_network(snapshot)["families"]
        self.assertIsNone(families["IPv4"]["default_route"])
        self.assertFalse(families["IPv6"]["available"])

    def test_deprecated_address_enum_is_three_and_tentative_is_not_usable(self):
        snapshot = self.snapshot()
        for address in snapshot["addresses"]:
            address["AddressState"] = 3
        self.assertTrue(probes.summarize_network(snapshot)["families"]["IPv6"]["available"])
        for address in snapshot["addresses"]:
            address["AddressState"] = 1
        self.assertFalse(probes.summarize_network(snapshot)["families"]["IPv6"]["available"])

    def test_route_selection_requires_a_usable_source_on_the_same_interface(self):
        snapshot = self.snapshot()
        for address in snapshot["addresses"]:
            if address["InterfaceIndex"] == 7:
                address["SkipAsSource"] = True
        families = probes.summarize_network(snapshot)["families"]
        self.assertEqual(families["IPv4"]["default_route"]["interface_index"], 2)
        self.assertEqual(families["IPv4"]["default_route"]["metric"], 101)
        self.assertEqual(families["IPv4"]["default_route"]["source_address_candidate"], "192.168.1.5")
        self.assertIsNone(families["IPv6"]["default_route"])

    def test_missing_snapshot_is_unknown(self):
        result = probes.summarize_network({})
        self.assertIsNone(result["families"]["IPv4"]["available"])
        self.assertEqual(result["families"]["IPv6"]["status"], "unknown")

    def test_missing_metric_and_skip_as_source_cannot_confirm_configuration(self):
        snapshot = self.snapshot()
        snapshot["interfaces"] = []
        result = probes.summarize_network(snapshot)
        self.assertIsNone(result["families"]["IPv4"]["default_route"])
        snapshot = self.snapshot()
        for address in snapshot["addresses"]:
            address["SkipAsSource"] = True
        self.assertFalse(probes.summarize_network(snapshot)["families"]["IPv4"]["available"])


class SocketProbeTests(unittest.TestCase):
    def setUp(self):
        self.addresses = patch.object(probes.socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.9", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.10", 443))])
        self.resolve = self.addresses.start()
        self.addCleanup(self.addresses.stop)
        self.sockets = patch.object(probes.socket, "socket")
        self.create = self.sockets.start()
        self.addCleanup(self.sockets.stop)
        self.sock = self.create.return_value

    def test_tcp_success_uses_one_resolved_address_and_closes(self):
        result = probes.tcp_probe("example.com:443", socket.AF_INET, 1000)
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["data"]["resolved_ip"], "192.0.2.9")
        self.assertEqual(result["data"]["family"], "IPv4")
        self.sock.connect.assert_called_once_with(("192.0.2.9", 443))
        self.sock.close.assert_called_once()
        self.assertIsNone(result["packets_sent"])

    def test_tcp_refused_timeout_and_os_error_are_distinct(self):
        for exc, expected, outcome in ((ConnectionRefusedError(10061, "refused"), "connection_refused", "unreachable"),
                                       (TimeoutError(), "timeout", "reply_timeout"),
                                       (OSError(10013, "denied"), "os_error", "execution_error")):
            with self.subTest(expected=expected):
                self.sock.connect.side_effect = exc
                result = probes.tcp_probe("example.com:443", socket.AF_INET, 1000)
                self.assertEqual(result["data"]["error_category"], expected)
                self.assertEqual(result["outcome"], outcome)
                self.assertIsNone(result["packets_sent"])
        self.assertEqual(self.sock.connect.call_count, 3)

    def test_tcp_ipv6_family_and_scope_retained(self):
        self.resolve.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("fe80::1", 80, 0, 7))]
        result = probes.tcp_probe("[fe80::1%7]:80", socket.AF_INET6, 1000)
        self.assertEqual(result["data"]["scope_id"], 7)
        self.assertEqual(result["data"]["family"], "IPv6")
        self.resolve.assert_called_once_with("fe80::1%7", 80, socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def test_operation_deadline_not_restarted_after_resolver(self):
        with patch.object(probes.time, "monotonic", side_effect=[10.0, 11.5]):
            result = probes.tcp_probe("example.com:443", socket.AF_INET, 1000)
        self.assertEqual(result["data"]["error_category"], "timeout")
        self.assertEqual(result["outcome"], "execution_error")
        self.assertTrue(result["data"]["local_deadline"])
        self.assertEqual(result["data"]["stage"], "resolve")
        self.create.assert_not_called()

    def test_resolver_timeout_does_not_claim_a_tcp_response_timeout(self):
        self.resolve.side_effect = TimeoutError("resolver did not finish")
        result = probes.tcp_probe("example.com:443", socket.AF_INET, 1000)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertEqual(result["data"]["stage"], "resolve")
        self.assertEqual(result["data"]["error_category"], "timeout")
        self.create.assert_not_called()
        self.assertIsNone(result["packets_sent"])

    def test_http_local_deadline_before_sending_is_not_a_response_timeout(self):
        with patch.object(probes, "_connect_once", return_value=self.sock), patch.object(probes, "_remaining", side_effect=probes._OperationDeadline("expired")), patch.object(probes.http.client, "HTTPConnection") as make_http:
            result = probes.http_probe("https://example.com/", socket.AF_INET, 1000)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertTrue(result["data"]["local_deadline"])
        make_http.assert_not_called()

    def test_https_verifies_original_hostname_and_has_no_proxy_lookup(self):
        with patch.object(probes.ssl, "create_default_context") as create_context, patch.object(probes.http.client, "HTTPConnection") as make_http:
            tls = create_context.return_value.wrap_socket.return_value
            response = make_http.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b"ok"
            result = probes.http_probe("https://example.com/a", socket.AF_INET, 1000)
            self.assertEqual(result["outcome"], "success")
            create_context.return_value.wrap_socket.assert_called_once_with(self.sock, server_hostname="example.com")
            self.assertIs(make_http.return_value.sock, tls)
            self.assertTrue(result["data"]["tls_verified"])
            self.assertFalse(result["data"]["proxy_used"])
            headers = make_http.return_value.request.call_args.kwargs["headers"]
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)

    def test_http_ipv6_zone_is_used_for_connection_but_not_sent_in_host_header(self):
        self.resolve.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("fe80::1", 80, 0, 7))]
        with patch.object(probes.http.client, "HTTPConnection") as make_http:
            response = make_http.return_value.getresponse.return_value
            response.status, response.read.return_value = 200, b"ok"
            result = probes.http_probe("http://[fe80::1%257]/", socket.AF_INET6, 1000)
            self.assertEqual(result["data"]["scope_id"], 7)
            self.resolve.assert_called_once_with("fe80::1%7", 80, socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.assertEqual(make_http.return_value.request.call_args.kwargs["headers"]["Host"], "[fe80::1]")

    def test_tls_validation_failure_stops_before_http(self):
        with patch.object(probes.ssl, "create_default_context") as context, patch.object(probes.http.client, "HTTPConnection") as make_http:
            context.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(1, "certificate secret")
            result = probes.http_probe("https://example.com/", socket.AF_INET, 1000)
            self.assertEqual(result["data"]["error_category"], "tls_validation")
            self.assertEqual(result["data"]["exception_type"], "SSLCertVerificationError")
            self.assertEqual(result["outcome"], "execution_error")
            self.assertEqual(result["data"]["stage"], "tls")
            self.assertNotIn("certificate secret", result["error"])
            make_http.assert_not_called()

    def test_tls_handshake_error_does_not_claim_certificate_validation(self):
        with patch.object(probes.ssl, "create_default_context") as context, patch.object(probes.http.client, "HTTPConnection") as make_http:
            context.return_value.wrap_socket.side_effect = ssl.SSLError(1, "WRONG_VERSION_NUMBER")
            result = probes.http_probe("https://example.com/", socket.AF_INET, 1000)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertEqual(result["data"]["error_category"], "tls_handshake")
        self.assertEqual(result["data"]["exception_type"], "SSLError")
        self.assertEqual(result["data"]["stage"], "tls")
        self.assertNotIn("WRONG_VERSION_NUMBER", result["error"])
        make_http.assert_not_called()

    def test_http_redirect_is_reported_without_body_or_followup(self):
        with patch.object(probes.http.client, "HTTPConnection") as make_http:
            response = make_http.return_value.getresponse.return_value
            response.status = 302
            result = probes.http_probe("http://example.com/", socket.AF_INET, 1000)
            self.assertEqual(result["outcome"], "success")
            self.assertEqual(result["data"]["http_status"], 302)
            self.assertEqual(result["data"]["redirects_followed"], 0)
            response.read.assert_not_called()
            make_http.return_value.request.assert_called_once()

    def test_http_body_read_is_capped_at_16_kib(self):
        with patch.object(probes.http.client, "HTTPConnection") as make_http:
            response = make_http.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b"x" * probes.HTTP_BODY_LIMIT
            result = probes.http_probe("http://example.com/", socket.AF_INET, 1000)
            response.read.assert_called_once_with(16384)
            self.assertEqual(result["data"]["body_bytes"], 16384)
            self.assertTrue(result["data"]["body_limit_reached"])
            make_http.return_value.close.assert_called_once()

    def test_http_403_is_an_observed_status_not_loss(self):
        with patch.object(probes.http.client, "HTTPConnection") as make_http:
            response = make_http.return_value.getresponse.return_value
            response.status, response.read.return_value = 403, b""
            result = probes.http_probe("http://example.com/", socket.AF_INET, 1000)
            self.assertEqual(result["outcome"], "success")
            self.assertEqual(result["data"]["error_category"], "http_status")
            self.assertIsNone(result["packets_sent"])


class Icmp6Tests(unittest.TestCase):
    def api(self, status=0, count=1):
        api = MagicMock()
        api.Icmp6CreateFile.return_value = 7
        def send(*args):
            reply = ctypes.cast(args[9], ctypes.POINTER(probes._Icmp6Reply)).contents
            reply.status, reply.rtt = status, 3
            return count
        api.Icmp6SendEcho2.side_effect = send
        return api

    def test_native_struct_sizes_and_scoped_destination(self):
        self.assertEqual(ctypes.sizeof(probes._SockaddrIn6), 28)
        self.assertEqual(ctypes.sizeof(probes._Icmp6Reply), 36)
        api = self.api()
        with patch.object(probes, "_icmp6_api", return_value=api):
            result = probes.icmp6_probe("fe80::1%7", 1000)
        self.assertEqual(result["outcome"], "success")
        self.assertEqual((result["packets_sent"], result["packets_received"]), (1, 1))
        destination = ctypes.cast(api.Icmp6SendEcho2.call_args.args[5], ctypes.POINTER(probes._SockaddrIn6)).contents
        self.assertEqual(destination.scope_id, 7)
        self.assertEqual(bytes(destination.address), socket.inet_pton(socket.AF_INET6, "fe80::1"))
        api.IcmpCloseHandle.assert_called_once_with(7)

    def test_timeout_has_one_sent_and_create_error_has_unknown_count(self):
        api = self.api(count=0)
        with patch.object(probes, "_icmp6_api", return_value=api), patch.object(probes, "_last_error", return_value=11010):
            result = probes.icmp6_probe("2001:db8::1", 1000)
        self.assertEqual(result["outcome"], "reply_timeout")
        self.assertEqual((result["packets_sent"], result["packets_received"]), (1, 0))
        api.Icmp6CreateFile.return_value = 0
        api.IcmpCloseHandle.reset_mock()
        with patch.object(probes, "_icmp6_api", return_value=api), patch.object(probes, "_last_error", return_value=5):
            result = probes.icmp6_probe("2001:db8::1", 1000)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertIsNone(result["packets_sent"])
        api.IcmpCloseHandle.assert_not_called()

    def test_native_send_error_and_missing_scope_do_not_create_loss(self):
        api = self.api(count=0)
        with patch.object(probes, "_icmp6_api", return_value=api), patch.object(probes, "_last_error", return_value=87):
            result = probes.icmp6_probe("2001:db8::1", 1000)
        self.assertEqual(result["outcome"], "execution_error")
        self.assertIsNone(result["packets_sent"])
        with patch.object(probes, "_icmp6_api") as create_api:
            result = probes.icmp6_probe("fe80::1", 1000)
            create_api.assert_not_called()
        self.assertIsNone(result["packets_sent"])

    def test_icmp_dispatches_ipv6_to_native_worker(self):
        with patch.object(workers, "_trusted_imports"), patch.object(probes, "icmp6_probe", return_value={"outcome": "success"}) as run:
            self.assertEqual(workers._icmp("::1", 1000)["outcome"], "success")
            run.assert_called_once_with("::1", 1000)


class WifiObservationTests(unittest.TestCase):
    def native_api(self):
        guid = uuid.UUID("12345678-abcd-4321-9876-123456789abc")
        buffer = ctypes.create_string_buffer(8 + ctypes.sizeof(workers._WLAN_INTERFACE))
        ctypes.cast(buffer, ctypes.POINTER(workers.wintypes.DWORD))[0] = 1
        interface = workers._WLAN_INTERFACE.from_buffer(buffer, 8)
        interface.guid.bytes[:] = guid.bytes_le
        interface.state = 1
        connection = workers._CONNECTION()
        connection.state = 1
        connection.association.ssid.length = 2
        connection.association.ssid.value[:2] = b"ab"
        connection.association.signal = 19
        connection.association.rx_rate = 30000
        connection.association.tx_rate = 40000
        api = MagicMock()
        def opened(_version, _reserved, negotiated, handle):
            ctypes.cast(negotiated, ctypes.POINTER(workers.wintypes.DWORD)).contents.value = 2
            ctypes.cast(handle, ctypes.POINTER(workers.wintypes.HANDLE)).contents.value = 7
            return 0
        def enumerated(_handle, _reserved, pointer):
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = ctypes.addressof(buffer)
            return 0
        def queried(_handle, _guid, opcode, _reserved, size, pointer, _value_type):
            self.assertEqual(opcode, 7)
            ctypes.cast(size, ctypes.POINTER(workers.wintypes.DWORD)).contents.value = ctypes.sizeof(connection)
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = ctypes.addressof(connection)
            return 0
        api.WlanOpenHandle.side_effect = opened
        api.WlanEnumInterfaces.side_effect = enumerated
        api.WlanQueryInterface.side_effect = queried
        return api, (buffer, connection)

    def test_signal_opt_in_uses_same_connection_query_and_default_identity_is_unchanged(self):
        api, keep_alive = self.native_api()
        with patch.object(workers.ctypes, "WinDLL", return_value=api, create=True):
            observed = workers._wifi_identity(include_signals=True)
            self.assertEqual(observed[0]["signal_quality"], 19)
            api.WlanQueryInterface.assert_called_once()
            api.WlanQueryInterface.reset_mock()
            identity = workers._wifi_identity()
        api.WlanQueryInterface.assert_called_once()
        self.assertNotIn("signal_quality", identity[0])
        self.assertNotIn("rx_rate", identity[0])
        self.assertEqual({key: value for key, value in observed[0].items() if key != "signal_quality"}, identity[0])
        self.assertEqual(api.WlanCloseHandle.call_count, 2)

    def test_network2_weak_signal_is_correlated_without_churning_s1_identity(self):
        guid = uuid.UUID("12345678-abcd-4321-9876-123456789abc")
        context = {"adapters": [{"InterfaceGuid": str(guid), "ifIndex": 7}], "routes": []}
        identity = {"guid": guid.bytes_le.hex(), "state": 1, "ssid_hex": "6162", "bssid": "00:11:22:33:44:55"}
        def run(wifi, extended):
            completed = workers.subprocess.CompletedProcess([], 0, json.dumps(context).encode(), b"")
            with patch.object(workers, "_trusted_imports", return_value=lambda args: args), patch.object(workers.subprocess, "run", return_value=completed), patch.object(workers, "_wifi_identity", return_value=[wifi]) as read:
                result = workers._network(include_signals=True) if extended else workers._network()
            read.assert_called_once_with(include_signals=True) if extended else read.assert_called_once_with()
            return result
        baseline = run(identity, False)
        weak = run({**identity, "signal_quality": 19, "rx_rate": 1000, "tx_rate": 2000}, True)
        strong = run({**identity, "signal_quality": 91, "rx_rate": 9000, "tx_rate": 8000}, True)
        self.assertEqual(baseline["data"]["identity"], weak["data"]["identity"])
        self.assertEqual(weak["data"]["identity"], strong["data"]["identity"])
        self.assertEqual(weak["data"]["wifi_observations"][0]["interface_index"], 7)
        self.assertEqual(weak["data"]["wifi_observations"][0]["signal_quality"], 19)
        self.assertEqual(weak["data"]["wifi"], [identity])
        self.assertNotIn("wifi_observations", baseline["data"])

    def test_unknown_adapter_and_invalid_quality_stay_unconfirmed(self):
        records = workers._wifi_observations({"adapters": []}, [{"guid": "unknown", "state": 1, "signal_quality": True}])
        self.assertIsNone(records[0]["interface_index"])
        self.assertIsNone(records[0]["signal_quality"])

    def test_provider_requires_explicit_network2_opt_in(self):
        cancel = object()
        for enabled, protocol in ((False, "network"), (True, "network2")):
            provider = workers.WindowsProbeProvider(extended_diagnostics=enabled)
            with patch.object(provider, "_run") as run:
                provider.read_network(10.0, cancel)
            run.assert_called_once_with(protocol, "", 10.0, cancel, timeout=5.0)


class WorkerProtocolTests(unittest.TestCase):
    def run_worker(self, request):
        stdout = io.StringIO()
        with patch.object(workers, "_repair_frozen_streams"), patch.object(workers, "_trusted_imports"), patch.object(workers, "_verify_private_job", return_value=True), patch.object(workers.sys, "stdin", io.StringIO(json.dumps(request))), patch.object(workers.sys, "stdout", stdout), patch.object(workers.sys, "platform", "win32"):
            code = workers.worker_main()
        self.assertEqual(code, 0)
        return json.loads(stdout.getvalue())

    def test_network2_worker_enables_only_readonly_signal_observations(self):
        with patch.object(workers, "_network", return_value={"outcome": "success"}) as network:
            result = self.run_worker({"protocol": "network2", "target": "", "timeout_ms": 1000, "job_name": "test-owned-job"})
        self.assertEqual(result["outcome"], "success")
        network.assert_called_once_with(include_signals=True)

    def test_worker_dispatches_new_protocols(self):
        for protocol, target, function in (("tcp", "example.com:443", "tcp_probe"), ("tcp6", "[::1]:443", "tcp_probe"), ("http", "http://example.com/", "http_probe"), ("http6", "http://example.com/", "http_probe"), ("https", "https://example.com/", "http_probe"), ("https6", "https://example.com/", "http_probe")):
            with self.subTest(protocol=protocol), patch.object(probes, function, return_value={"outcome": "success"}) as run:
                result = self.run_worker({"protocol": protocol, "target": target, "timeout_ms": 1000, "job_name": "test-owned-job"})
                self.assertEqual(result["outcome"], "success")
                self.assertEqual(run.call_args.args[1], socket.AF_INET6 if protocol.endswith("6") else socket.AF_INET)

    def test_worker_rejects_bad_shapes_timeouts_targets_before_execution(self):
        base = {"protocol": "https6", "target": "https://example.com/", "timeout_ms": 1000, "job_name": "test-owned-job"}
        invalid = [{**base, "script": "anything"}, {**base, "timeout_ms": True}, {**base, "timeout_ms": 0},
                   {**base, "timeout_ms": 1001}, {**base, "target": "https://u:p@example.com/"},
                   {**base, "target": "http://example.com/"}, {**base, "target": "x" * 2049},
                   {**base, "protocol": "shell"}]
        with patch.object(probes, "http_probe") as execute:
            for request in invalid:
                with self.subTest(request=request):
                    self.assertEqual(self.run_worker(request)["outcome"], "execution_error")
            execute.assert_not_called()

    def test_dns6_queries_aaaa_and_keeps_resolver_result_scope(self):
        records = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0))]
        with patch.object(workers.socket, "getaddrinfo", return_value=records) as resolve:
            result = self.run_worker({"protocol": "dns6", "target": "example.com", "timeout_ms": 1000, "job_name": "test-owned-job"})
        self.assertEqual(result["data"]["family"], "IPv6")
        self.assertTrue(result["data"]["resolver_result_only"])
        self.assertEqual(result["data"]["addresses"], ["2001:db8::1"])
        resolve.assert_called_once_with("example.com", None, socket.AF_INET6)


if __name__ == "__main__":
    unittest.main()
