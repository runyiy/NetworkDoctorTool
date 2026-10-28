"""S2 session integration checks using finite simulated observations only."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from losshound import app
from losshound.cli import runner
from losshound.core.session import SessionController, SessionReport, SessionRequest, _extended_tasks
from test_session_s1 import FakeClock, FakeProvider
from test_session_context_s1 import StableObserver


def context(dual=True):
    result = {
        "identity": "A", "gateway": "192.0.2.1",
        "adapters": [{"ifIndex": 7, "Status": "Up", "InterfaceType": 6}],
        "addresses": [{"AddressFamily": 2, "InterfaceIndex": 7,
                       "IPAddress": "192.0.2.2", "PrefixLength": 24, "AddressState": 4}],
        "routes": [{"AddressFamily": 2, "InterfaceIndex": 7,
                    "DestinationPrefix": "0.0.0.0/0", "NextHop": "192.0.2.1", "RouteMetric": 1}],
        "interfaces": [{"AddressFamily": 2, "InterfaceIndex": 7,
                        "InterfaceMetric": 5, "ConnectionState": "Connected"}],
        "dns": [], "wifi": {},
    }
    if dual:
        result["addresses"].append({"AddressFamily": 23, "InterfaceIndex": 7,
                                    "IPAddress": "2001:db8::2", "PrefixLength": 64, "AddressState": 4})
        result["routes"].append({"AddressFamily": 23, "InterfaceIndex": 7,
                                 "DestinationPrefix": "::/0", "NextHop": "fe80::1", "RouteMetric": 1})
        result["interfaces"].append({"AddressFamily": 23, "InterfaceIndex": 7,
                                     "InterfaceMetric": 5, "ConnectionState": "Connected"})
    return result


class Provider(FakeProvider):
    def __init__(self, clock, *, dual=True, icmp="success", dns="success", on_probe=None):
        super().__init__(clock)
        self.context = context(dual)
        self.icmp_outcome, self.dns_outcome = icmp, dns
        self.on_probe = on_probe

    def read_network(self, deadline, cancel_event):
        self.deadlines.append(deadline)
        self.clock.now += min(0.005, max(0, deadline-self.clock.now))
        return {"outcome": "success", "data": self.context}

    def probe(self, protocol, target, deadline, cancel_event):
        self.probes.append((protocol, target))
        self.deadlines.append(deadline)
        self.clock.now += min(0.01, max(0, deadline-self.clock.now))
        if self.on_probe:
            self.on_probe(protocol, target, cancel_event)
        family = "IPv6" if protocol.endswith("6") or ":" in target and protocol == "icmp" else "IPv4"
        address = "2001:db8::90" if family == "IPv6" else "203.0.113.90"
        outcome = self.icmp_outcome if protocol == "icmp" else self.dns_outcome if protocol in {"dns", "dns6"} else "success"
        data = {"family": family, "stage": "getaddrinfo" if protocol.startswith("dns") else "response",
                "resolved_ip": address}
        if protocol.startswith("dns"):
            data.update(addresses=[address] if outcome == "success" else [], resolver_result_only=True,
                        source="os_resolver")
        if protocol.startswith("http"):
            data["http_status"] = 200
        return {"outcome": outcome, "packets_sent": 1 if protocol == "icmp" else None,
                "packets_received": (1 if outcome == "success" else 0) if protocol == "icmp" else None,
                "rtt_ms": 2.0 if outcome == "success" else None, "data": data}


def request(**overrides):
    data = dict(duration_seconds=3, ping_targets=("203.0.113.1",), dns_hostnames=("example.com",),
                extended_diagnostics=True, ipv6_targets=("2001:db8::1",),
                tcp_targets=("203.0.113.1:443", "[2001:db8::1]:443"),
                website_urls=("https://example.com/check?private=token",))
    data.update(overrides)
    return SessionRequest(**data)


class ExtendedSessionTests(unittest.TestCase):
    def run_simulated(self, provider=None, req=None, observer=None, event=None, progress=None):
        clock = provider.clock if provider is not None else FakeClock()
        provider = provider or Provider(clock)
        observer = observer or StableObserver()
        report = SessionController(req or request(), provider, clock, clock.wait,
                                   context_observer=observer).run(event, progress)
        return report, provider, observer

    def test_website_tasks_replace_only_exact_public_duplicates(self):
        req = request(
            website_urls=("http://192.0.2.90:8080/check", "https://[2001:db8::90]:8443/check"),
            ping_targets=("192.0.2.90", "192.0.2.91"),
            ipv6_targets=("2001:db8::90", "2001:db8::91"),
            tcp_targets=("192.0.2.90:8080", "192.0.2.90:8081", "192.0.2.91:8080",
                         "[2001:db8::90]:8443", "[2001:db8::90]:8444", "[2001:db8::91]:8443"),
            dns_hostnames=(),
        )
        tasks, missing = _extended_tasks(req, {})
        for protocol, target, family in (
            ("icmp", "192.0.2.90", "IPv4"), ("tcp", "192.0.2.90:8080", "IPv4"),
            ("icmp", "2001:db8::90", "IPv6"), ("tcp6", "[2001:db8::90]:8443", "IPv6"),
        ):
            with self.subTest(protocol=protocol, target=target):
                matches = [task for task in tasks if (task["protocol"], task["target"], task["family"])
                           == (protocol, target, family)]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0]["role"], "target")
        public = {(task["protocol"], task["target"], task["family"])
                  for task in tasks if task["role"] == "public"}
        self.assertEqual(public, {
            ("icmp", "192.0.2.91", "IPv4"), ("icmp", "2001:db8::91", "IPv6"),
            ("tcp", "192.0.2.90:8081", "IPv4"), ("tcp", "192.0.2.91:8080", "IPv4"),
            ("tcp6", "[2001:db8::90]:8444", "IPv6"), ("tcp6", "[2001:db8::91]:8443", "IPv6"),
        })
        self.assertTrue(any(task["protocol"] == "http" and task["role"] == "target" for task in tasks))
        self.assertTrue(any(task["protocol"] == "https6" and task["role"] == "target" for task in tasks))
        self.assertEqual({task["family"] for task in missing}, {"IPv4", "IPv6"})

    def test_website_deduplication_preserves_independent_later_rounds(self):
        url = "http://203.0.113.90:8080/check"
        req = request(website_urls=(url,), ping_targets=("203.0.113.90",),
                      tcp_targets=("203.0.113.90:8080",), ipv6_targets=(), dns_hostnames=())
        report, _provider, _observer = self.run_simulated(req=req)
        for protocol, target in (("icmp", "203.0.113.90"),
                                 ("tcp", "203.0.113.90:8080"), ("http", url)):
            with self.subTest(protocol=protocol):
                rows = [row for row in report.evidence if row.protocol == protocol and row.target == target]
                self.assertEqual(len(rows), len({row.data["round_index"] for row in rows}))
                self.assertTrue(all(row.data["role"] == "target" for row in rows))
                self.assertGreaterEqual(len([row for row in rows if row.comparable]), 2)

    def test_target_protocol_priority_preserves_tasks_and_background_order(self):
        req = request(website_urls=("http://192.0.2.90:8080/check", "https://example.com/", "http://[2001:db8::90]/"),
                      ping_targets=("192.0.2.91",), ipv6_targets=("2001:db8::91",),
                      tcp_targets=("192.0.2.91:443", "[2001:db8::91]:443"), dns_hostnames=("reference.example",))
        network = {"gateway": "192.0.2.1", "diagnostics": {"families": {
            "IPv4": {"default_route": {"gateway": "192.0.2.1"}},
            "IPv6": {"default_route": {"gateway": "fe80::1"}}}}}
        tasks, missing = _extended_tasks(req, network)
        self.assertEqual(missing, [])
        self.assertEqual([(task["protocol"], task["target"], task["role"]) for task in tasks], [
            ("tcp", "192.0.2.90:8080", "target"), ("http", "http://192.0.2.90:8080/check", "target"),
            ("dns", "example.com", "target"), ("dns6", "example.com", "target"),
            ("tcp", "example.com:443", "target"), ("https", "https://example.com/", "target"),
            ("tcp6", "example.com:443", "target"), ("https6", "https://example.com/", "target"),
            ("tcp6", "[2001:db8::90]:80", "target"), ("http6", "http://[2001:db8::90]/", "target"),
            ("icmp", "192.0.2.90", "target"), ("icmp", "2001:db8::90", "target"),
            ("icmp", "192.0.2.1", "gateway"), ("icmp", "fe80::1", "gateway"),
            ("icmp", "192.0.2.91", "public"), ("icmp", "2001:db8::91", "public"),
            ("tcp", "192.0.2.91:443", "public"), ("tcp6", "[2001:db8::91]:443", "public"),
            ("dns", "reference.example", "dns"), ("dns6", "reference.example", "dns")])
        report, _provider, _observer = self.run_simulated(req=req)
        first = [row for row in report.evidence if row.data.get("round_index") == 1
                 and row.protocol != "network"]
        targets = [row for row in first if row.data.get("role") == "target"]
        self.assertEqual(len(targets), 14)  # All 12 configured tasks plus two DNS-derived ICMP checks.
        first_icmp = next(index for index, row in enumerate(targets) if row.protocol == "icmp")
        self.assertTrue(all(row.protocol != "icmp" for row in targets[:first_icmp]))
        self.assertTrue(all(row.protocol == "icmp" for row in targets[first_icmp:]))
        self.assertEqual({row.target for row in targets if row.protocol == "icmp"},
                         {"192.0.2.90", "2001:db8::90", "203.0.113.90", "2001:db8::90"})

    def test_slow_late_round_keeps_repeated_tcp_http_and_honest_unsent_checks(self):
        class SlowProvider(Provider):
            probe_budget_seconds = 3.0
            cleanup_budget_seconds = 2.0
            def read_network(self, deadline, cancel_event):
                result = super().read_network(deadline, cancel_event)
                self.clock.now += min(3.995, max(0.0, deadline - self.clock()))
                return result
            def probe(self, protocol, target, deadline, cancel_event):
                result = super().probe(protocol, target, deadline, cancel_event)
                cost = 1.5 if protocol == "icmp" else 2.8 if protocol.startswith("dns") else 1.6
                remaining = max(0.0, deadline - self.clock())
                self.clock.now += min(cost - 0.01, remaining)
                if remaining < cost - 0.01:
                    return {"outcome": "execution_error", "error": "Simulated bounded worker deadline",
                            "data": {"stage": "worker_response"}}
                if protocol == "http":
                    result["outcome"] = "unreachable"
                    result["data"].update(http_status=503, error_category="http_status")
                return result
        url = "http://203.0.113.90:8080/check"
        req = request(duration_seconds=60, website_urls=(url,), ping_targets=("203.0.113.90",),
                      tcp_targets=("203.0.113.90:8080",), ipv6_targets=("::1",), dns_hostnames=("reference.example",))
        report, provider, observer = self.run_simulated(SlowProvider(FakeClock()), req=req)
        rows = [row for row in report.evidence if row.comparable and row.epoch_id == 1 and row.family == "IPv4"]
        snapshots = [row for row in report.evidence if row.comparable and row.epoch_id == 1
                     and row.protocol == "network" and row.outcome.value == "success"]
        anchor = max(row.finished_seconds for row in rows + snapshots)
        recent = [row for row in rows if row.started_seconds >= anchor - 30.0 and row.data.get("role") == "target"]
        tcp = [row for row in recent if row.protocol == "tcp" and row.outcome.value == "success"]
        web = [row for row in recent if row.protocol == "http" and row.data.get("http_status") == 503]
        self.assertGreaterEqual(len(tcp), 2)
        self.assertGreaterEqual(len(web), 2)
        self.assertEqual({(row.epoch_id, row.family, row.data.get("resolved_ip")) for row in tcp + web},
                         {(1, "IPv4", "203.0.113.90")})
        self.assertGreaterEqual(len({row.data["round_index"] for row in tcp + web}), 2)
        self.assertTrue(any(finding["scope"] == "target" and finding["confidence"] == "medium"
                            for finding in report.analysis["findings"]))
        configured = {(task["protocol"], task["target"]) for task in _extended_tasks(req, report.epochs[0].context)[0]}
        self.assertTrue(configured <= {(row.protocol, row.target) for row in report.evidence})
        unsent = [row for row in report.evidence if row.data.get("stage") == "closing_context_reserve"]
        self.assertTrue(unsent)
        self.assertTrue(all(row.outcome.value == "not_attempted" and not row.comparable
                            and row.packets_sent is None for row in unsent))
        self.assertLessEqual(report.duration_seconds, 60)
        self.assertTrue(provider.closed and observer.closed)

    def test_dual_stack_cross_protocol_collection_and_current_analysis(self):
        report, provider, _ = self.run_simulated()
        protocols = {p for p, _ in provider.probes}
        self.assertTrue({"icmp", "dns", "dns6", "tcp", "tcp6", "https", "https6"} <= protocols)
        self.assertIn(("icmp", "203.0.113.90"), provider.probes)
        self.assertIn(("icmp", "2001:db8::90"), provider.probes)
        self.assertEqual(report.schema_version, 3)
        self.assertTrue(report.analysis)
        self.assertIsInstance(report.analysis["findings"], list)
        self.assertEqual({e.family for e in report.evidence if e.protocol in {"dns", "dns6"}}, {"IPv4", "IPv6"})
        self.assertTrue(all(e.epoch_id == 1 for e in report.evidence if e.comparable))
        self.assertTrue(provider.closed)
        self.assertLessEqual(report.duration_seconds, report.budget_seconds)
        self.assertEqual(json.loads(report.to_json())["schema_version"], 3)

    def test_ping_failure_does_not_block_tcp_dns_or_https(self):
        report, provider, _ = self.run_simulated(Provider(FakeClock(), icmp="reply_timeout"))
        self.assertTrue(any(p == "tcp" for p, _ in provider.probes))
        self.assertTrue(any(p == "https" for p, _ in provider.probes))
        self.assertTrue(any(p == "dns6" for p, _ in provider.probes))
        self.assertFalse(any(f["scope"] == "wan_or_isp" for f in report.analysis["findings"]))

    def test_dns_failure_does_not_suppress_independent_tcp_and_https(self):
        _, provider, _ = self.run_simulated(Provider(FakeClock(), dns="unreachable"))
        self.assertIn(("tcp", "example.com:443"), provider.probes)
        self.assertIn(("https", "https://example.com/check?private=token"), provider.probes)
        self.assertNotIn(("icmp", "203.0.113.90"), provider.probes)

    def test_missing_ipv6_route_is_not_attempted_not_packet_loss(self):
        report, provider, _ = self.run_simulated(Provider(FakeClock(), dual=False))
        self.assertTrue(any(p == "dns6" for p, _ in provider.probes))
        self.assertFalse(any(p in {"tcp6", "https6"} for p, _ in provider.probes))
        v6 = [e for e in report.evidence if e.family == "IPv6" and e.protocol != "dns6"]
        self.assertTrue(v6)
        self.assertTrue(all(e.outcome.value == "not_attempted" for e in v6))
        self.assertTrue(all(e.loss_percent is None for e in v6))

    def test_epoch_transition_excludes_affected_sample_without_extending_budget(self):
        observer = StableObserver()
        provider = Provider(FakeClock())
        def transition(protocol, target, event):
            if len(provider.probes) == 1:
                observer.generation += 2
        provider.on_probe = transition
        report, provider, _ = self.run_simulated(provider, observer=observer)
        first = next(e for e in report.evidence if e.protocol != "network")
        self.assertFalse(first.comparable)
        self.assertIsNone(first.epoch_id)
        self.assertIsNone(first.loss_percent)
        self.assertGreaterEqual(len(report.epochs), 2)
        self.assertEqual(max(provider.deadlines), provider.deadlines[0])
        self.assertTrue(all(0 < value <= provider.deadlines[0] for value in provider.deadlines))
        self.assertLessEqual(report.duration_seconds, 3)

    def test_cancelled_dns_result_does_not_schedule_its_discovered_address(self):
        def cancel(protocol, target, event):
            if protocol == "dns": event.set()
        provider = Provider(FakeClock(), on_probe=cancel)
        report, provider, observer = self.run_simulated(provider)
        self.assertEqual(report.status, "cancelled")
        self.assertNotIn(("icmp", "203.0.113.90"), provider.probes)
        self.assertTrue(provider.closed and observer.closed)

    def test_pre_cancelled_300_second_request_starts_no_probe(self):
        event = threading.Event(); event.set()
        report, provider, _ = self.run_simulated(req=request(duration_seconds=300), event=event)
        self.assertEqual(provider.probes, [])
        self.assertEqual(report.status, "cancelled")
        self.assertLess(report.duration_seconds, 2)
        self.assertTrue(report.incomplete)

    def test_unknown_observation_does_not_confirm_comparability(self):
        observer = StableObserver(); observer.status = "UNKNOWN"
        report, _, _ = self.run_simulated(observer=observer)
        self.assertTrue(all(not e.comparable for e in report.evidence))
        self.assertTrue(all(f["scope"] == "unknown" for f in report.analysis["findings"]))

    def test_scoped_literal_website_protocols_share_one_decoded_interface(self):
        report, provider, _ = self.run_simulated(req=request(website_urls=("http://[fe80::1%257]/",)))
        self.assertIn(("icmp", "fe80::1%7"), provider.probes)
        self.assertIn(("tcp6", "[fe80::1%7]:80"), provider.probes)
        self.assertIn(("http6", "http://[fe80::1%257]/"), provider.probes)
        self.assertLessEqual(report.duration_seconds, 3)

    def test_extended_progress_does_not_expose_private_target(self):
        progress = []
        self.run_simulated(progress=progress.append)
        phases = " ".join(item.phase for item in progress)
        for private in ("example.com", "private=token", "203.0.113", "2001:db8"):
            self.assertNotIn(private, phases)
        self.assertIn("target", phases)

    def test_request_bounds_and_explicit_website_opt_in(self):
        for change in ({"extended_diagnostics": 1}, {"ipv6_targets": ("192.0.2.1",)},
                       {"tcp_targets": ("localhost:0",)},
                       {"website_urls": ("https://user:password@example.com/",)},
                       {"website_urls": tuple("https://example.com/"+str(i) for i in range(9))}):
            with self.subTest(change=change), self.assertRaises(ValueError): request(**change)
        with self.assertRaises(ValueError): SessionRequest(website_urls=("https://example.com",))
        self.assertFalse(SessionRequest().extended_diagnostics)


class ExtendedEntryTests(unittest.TestCase):
    def test_extended_options_cannot_start_gui_or_hidden_replay(self):
        for arguments in (("--extended",), ("--website", "https://example.com"),
                          ("--cli", "--website", "https://example.com"),
                          ("--analyze-report", "old.json"),
                          ("--cli", "--extended", "--gui-smoke-test")):
            with self.subTest(arguments=arguments), patch.object(sys, "argv", ["losshound", *arguments]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                app.main()
            self.assertEqual(error.exception.code, 2)

    def test_extended_cli_output_redacts_private_targets_without_mutating_report(self):
        config = SimpleNamespace(public_ping_targets=[], dns_test_hostnames=[])
        report = SessionReport("deadline", 1, schema_version=3,
                               analysis={"findings": [], "limitations": []})
        report.incomplete = ["https://private.example/path?token=secret not attempted"]
        output, progress = io.StringIO(), io.StringIO()
        with patch.object(runner, "SessionController") as controller, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(progress):
            controller.return_value.run.return_value = report
            result = runner.run_cli(config, duration_seconds=1, extended_diagnostics=True)
        raw = output.getvalue()
        self.assertNotIn("token=secret", raw)
        self.assertNotIn("private.example", raw)
        self.assertTrue(json.loads(raw)["redaction"]["applied"])
        self.assertIn("token=secret", result.incomplete[0])
        self.assertTrue(controller.call_args.args[0].extended_diagnostics)


from urllib.parse import urlsplit


class FailureScenarioProvider(Provider):
    """SIMULATED outcomes only; no sockets, system commands or network changes."""
    simulation_label = "SIMULATED"

    def __init__(self, clock, scenario):
        super().__init__(clock, dual=scenario == "insufficient")
        self.scenario = scenario
        self.calls = {}
        if scenario == "offline":
            self.context.update(identity="SIMULATED-OFFLINE", gateway=None,
                                addresses=[], routes=[], interfaces=[])
            self.context["adapters"][0]["Status"] = "Disconnected"

    def probe(self, protocol, target, deadline, cancel_event):
        result = super().probe(protocol, target, deadline, cancel_event)
        self.clock.now += min(0.2, max(0, deadline - self.clock.now))
        if protocol.startswith(("http", "https")):
            host = urlsplit(target).hostname
        elif protocol.startswith("tcp"):
            host = urlsplit("tcp://" + target).hostname
        else:
            host = target
        family = result["data"]["family"]
        resolved = ({"problem.example": "9.9.9.9", "healthy.example": "149.112.112.112"}
                    .get(host, host))
        if protocol.startswith("dns"):
            resolved = "2606:4700:4700::9999" if family == "IPv6" else "9.9.9.9"
        count_key = (protocol, target)
        self.calls[count_key] = self.calls.get(count_key, 0) + 1
        outcome = "success"
        if self.scenario == "dns" and protocol.startswith("dns"):
            outcome = "unreachable"
        elif self.scenario == "icmp_filtered" and protocol == "icmp":
            outcome = "reply_timeout"
        elif self.scenario == "partial_target" and host in ("problem.example", "9.9.9.9") and not protocol.startswith("dns"):
            outcome = "reply_timeout"
        elif self.scenario == "intermittent" and protocol == "icmp" and target == "1.1.1.1" and self.calls[count_key] == 2:
            outcome = "reply_timeout"
        elif self.scenario == "offline":
            outcome = "execution_error"
        result["outcome"] = outcome
        data = {"family": family, "resolved_ip": resolved, "simulation": self.simulation_label,
                "stage": "getaddrinfo" if protocol.startswith("dns") else "response"}
        if protocol.startswith("dns"):
            data.update(addresses=[resolved] if outcome == "success" else [],
                        source="os_resolver", resolver_result_only=True)
        elif protocol.startswith("http") and outcome == "success":
            data["http_status"] = 200
        if outcome == "reply_timeout":
            data["error_category"] = "timeout"
        elif outcome == "execution_error":
            data.update(error_category="os_error", winerror=10051, stage="SIMULATED-before-send")
            result["error"] = "SIMULATED network unavailable; no probe packet was sent"
        if protocol == "icmp" and outcome in ("success", "reply_timeout"):
            result.update(packets_sent=1, packets_received=1 if outcome == "success" else 0)
        else:
            result.update(packets_sent=None, packets_received=None)
        result["data"] = data
        if self.scenario == "insufficient":
            cancel_event.requested_monotonic = self.clock()
            cancel_event.set()
        return result


class CurrentSessionScenarioTests(unittest.TestCase):
    """Additional controller-to-analysis coverage; all failures are SIMULATED."""

    def run_current(self, scenario, **overrides):
        clock = FakeClock()
        provider = FailureScenarioProvider(clock, scenario)
        options = dict(duration_seconds=60, ping_targets=("1.1.1.1", "8.8.8.8"),
                       dns_hostnames=(), extended_diagnostics=True, ipv6_targets=(),
                       tcp_targets=("1.1.1.1:443", "8.8.8.8:443"), website_urls=())
        options.update(overrides)
        observer = StableObserver()
        report = SessionController(SessionRequest(**options), provider, clock, clock.wait,
                                   context_observer=observer).run()
        self.assertTrue(provider.closed and observer.closed)
        self.assertLessEqual(report.duration_seconds, report.budget_seconds)
        self.assertEqual(max(provider.deadlines), provider.deadlines[0])
        self.assertTrue(all(0 < value <= provider.deadlines[0] for value in provider.deadlines))
        raw = json.loads(report.to_json())
        self.assertTrue(raw["analysis"]["findings"])
        self.assertNotIn("healthy", {item["category"] for item in raw["analysis"]["findings"]})
        evidence = {item["sequence"]: item for item in raw["evidence"]}
        for finding in [*raw["analysis"]["findings"], *raw["analysis"]["intermittent"]]:
            support = set(finding["supporting_evidence"])
            counter = set(finding["contradictions"])
            self.assertFalse(support & counter)
            self.assertTrue(finding["alternatives"])
            self.assertTrue(finding["limitations"])
            self.assertTrue(all(isinstance(text, str) for text in finding["recommendations"]))
            self.assertIn(finding["confidence"], ("low", "medium"))
            for sequence in support | counter:
                self.assertIn(sequence, evidence)
                item = evidence[sequence]
                self.assertEqual(item["epoch_id"], finding["epoch_id"])
                self.assertTrue(item["comparable"])
                if item["protocol"] != "network":
                    self.assertEqual(item["family"], finding["family"])
            window = finding["window"]
            if window["started_seconds"] is not None:
                self.assertLessEqual(window["finished_seconds"] - window["started_seconds"], 30.00001)
        return raw, provider

    def test_simulated_dns_fault_reaches_current_report_with_global_cross_protocol_baseline(self):
        raw, provider = self.run_current("dns", dns_hostnames=("resolver-check.invalid",))
        findings = [item for item in raw["analysis"]["findings"] if item["scope"] == "dns"]
        self.assertTrue(findings)
        finding = next(item for item in findings if item["family"] == "IPv4")
        selected = [item for item in raw["evidence"] if item["sequence"] in finding["supporting_evidence"]]
        self.assertTrue(any(item["protocol"] == "dns" and item["outcome"] == "unreachable" for item in selected))
        self.assertTrue({"icmp", "tcp"} <= {item["protocol"] for item in selected})
        self.assertIn("hosts", " ".join(finding["limitations"]))
        self.assertIn(("tcp", "1.1.1.1:443"), provider.probes)

    def test_simulated_icmp_filter_does_not_hide_tcp_http_or_claim_network_outage(self):
        raw, provider = self.run_current("icmp_filtered", website_urls=("http://9.9.9.9/check",))
        self.assertIn(("tcp", "1.1.1.1:443"), provider.probes)
        self.assertIn(("http", "http://9.9.9.9/check"), provider.probes)
        self.assertTrue(any(item["protocol"] == "icmp" and item["outcome"] == "reply_timeout" for item in raw["evidence"]))
        self.assertTrue(any(item["protocol"] in ("tcp", "http") and item["outcome"] == "success" for item in raw["evidence"]))
        self.assertFalse(any(item["scope"] in ("gateway", "wan_or_isp") for item in raw["analysis"]["findings"]))
        self.assertTrue(any(item["contradictions"] for item in raw["analysis"]["findings"] if item["family"] == "IPv4"))

    def test_simulated_unconfigured_ipv6_preserves_ipv4_findings_and_missing_coverage(self):
        raw, _provider = self.run_current("dns", dns_hostnames=("resolver-check.invalid",))
        self.assertTrue(any(item["scope"] == "local" and item["family"] == "IPv6"
                            for item in raw["analysis"]["findings"]))
        self.assertTrue(any(item["scope"] == "dns" and item["family"] == "IPv4"
                            for item in raw["analysis"]["findings"]))
        not_sent = [item for item in raw["evidence"] if item["family"] == "IPv6" and item["protocol"] != "dns6"]
        self.assertTrue(not_sent)
        self.assertTrue(all(item["outcome"] == "not_attempted" and item["loss_percent"] is None for item in not_sent))

    def test_simulated_partial_target_failure_is_isolated_to_same_current_peer(self):
        raw, provider = self.run_current("partial_target", website_urls=(
            "https://problem.example/check", "http://healthy.example/check"))
        finding = next(item for item in raw["analysis"]["findings"] if item["scope"] == "target")
        support = [item for item in raw["evidence"] if item["sequence"] in finding["supporting_evidence"]]
        self.assertTrue(any(item["data"].get("target_host") == "problem.example" for item in support))
        self.assertTrue(any(item["protocol"] == "https" and item["target"].startswith("https://problem.example/")
                            for item in support))
        self.assertTrue(any(item["protocol"] == "http" and item["outcome"] == "success"
                            for item in raw["evidence"]))
        self.assertNotIn("wan_or_isp", {item["scope"] for item in raw["analysis"]["findings"]})
        self.assertIn(("icmp", "9.9.9.9"), provider.probes)

    def test_simulated_intermittent_current_session_keeps_fresh_sequence_and_partial_cancel_unknown(self):
        raw, _provider = self.run_current("intermittent")
        item = next(item for item in raw["analysis"]["intermittent"]
                    if item["protocol"] == "icmp" and item["target"] == "1.1.1.1")
        rows = {entry["sequence"]: entry for entry in raw["evidence"]}
        self.assertEqual([rows[sequence]["outcome"] for sequence in item["evidence_sequences"]],
                         ["success", "reply_timeout", "success"])
        self.assertIn("彻底修复", " ".join(item["limitations"]))
        cancelled, provider = self.run_current("insufficient", duration_seconds=300)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(len(provider.probes), 1)
        self.assertLess(cancelled["duration_seconds"], 2)
        self.assertTrue(all(finding["scope"] == "unknown" for finding in cancelled["analysis"]["findings"]))

    def test_simulated_offline_current_session_still_collects_local_context_and_serializes_report(self):
        raw, provider = self.run_current("offline", ping_targets=("1.1.1.1",),
                                         tcp_targets=("1.1.1.1:443",), dns_hostnames=("offline.invalid",))
        self.assertEqual(raw["status"], "deadline")
        self.assertTrue(any(item["protocol"] == "network" and item["outcome"] == "success"
                            for item in raw["evidence"]))
        failed = [item for item in raw["evidence"] if item["protocol"] != "network"]
        self.assertTrue(any(item["outcome"] == "execution_error" for item in failed))
        self.assertTrue(all(item["loss_percent"] is None for item in failed))
        self.assertTrue(raw["incomplete"])
        self.assertTrue(raw["analysis"]["limitations"])
        self.assertTrue(any(item["scope"] == "local" for item in raw["analysis"]["findings"]))
        self.assertNotIn("wan_or_isp", {item["scope"] for item in raw["analysis"]["findings"]})
        self.assertTrue(provider.probes)


class CohortBoundaryTests(unittest.TestCase):
    def run_case(self, provider, observer=None, req=None, event=None):
        observer = observer or StableObserver()
        return SessionController(req or request(), provider, provider.clock, provider.clock.wait,
                                 context_observer=observer).run(event)

    def test_startup_wait_obtains_ready_before_first_identity_query(self):
        provider = Provider(FakeClock())
        started = provider.clock()
        observer = StableObserver()
        original_snapshot = observer.snapshot
        def snapshot():
            value = original_snapshot()
            if provider.clock() < started + 0.25:
                value["status"] = "UNKNOWN"
            return value
        observer.snapshot = snapshot
        reads = []
        original_read = provider.read_network
        def read(*args):
            reads.append(provider.clock())
            return original_read(*args)
        provider.read_network = read
        report = self.run_case(provider, observer)
        self.assertGreaterEqual(reads[0] - started, 0.25)
        self.assertLessEqual(reads[0] - started, 1.0)
        self.assertEqual(report.context_observations[0]["continuity"], "OBSERVED")
        self.assertTrue(any(row.comparable for row in report.evidence))
        self.assertLessEqual(report.duration_seconds, report.budget_seconds)

    def test_cancel_during_startup_wait_sends_no_context_or_probe(self):
        provider = Provider(FakeClock())
        started = provider.clock()
        observer = StableObserver()
        observer.status = "UNKNOWN"
        event = threading.Event()
        def wait(cancel, seconds):
            provider.clock.now += seconds
            if provider.clock() >= started + 0.1:
                cancel.set()
        report = SessionController(request(), provider, provider.clock, wait,
                                   context_observer=observer).run(event)
        self.assertEqual(report.status, "cancelled")
        self.assertEqual(report.context_observations, [])
        self.assertEqual(provider.probes, [])
        self.assertLess(report.duration_seconds, 1.0)
        self.assertTrue(provider.closed and observer.closed)

    def test_closing_reserve_keeps_samples_and_records_unattempted_remainder(self):
        provider = Provider(FakeClock())
        original_read, original_probe = provider.read_network, provider.probe
        reads, probe_deadlines = [], []
        def read(deadline, cancel):
            reads.append((provider.clock(), deadline))
            provider.clock.now += min(0.15, max(0.0, deadline-provider.clock()))
            return original_read(deadline, cancel)
        def probe(protocol, target, deadline, cancel):
            probe_deadlines.append(deadline)
            provider.clock.now += min(0.2, max(0.0, deadline-provider.clock()))
            return original_probe(protocol, target, deadline, cancel)
        provider.read_network, provider.probe = read, probe
        report = self.run_case(provider)
        self.assertEqual(len(reads), 2)
        self.assertTrue(probe_deadlines)
        self.assertTrue(all(value < reads[0][1] for value in probe_deadlines))
        self.assertLess(reads[-1][0], reads[-1][1])
        self.assertTrue(any(row.comparable and row.protocol != "network" for row in report.evidence))
        unsent = [row for row in report.evidence if row.data.get("stage") == "closing_context_reserve"]
        self.assertTrue(unsent)
        self.assertTrue(all(row.outcome.value == "not_attempted" and row.packets_sent is None
                            and not row.comparable for row in unsent))
        self.assertLessEqual(report.duration_seconds, report.budget_seconds)
        self.assertTrue(provider.closed)

    def test_adjacent_rounds_share_real_enclosing_query_without_redating(self):
        provider = Provider(FakeClock())
        started, reads = provider.clock(), []
        original = provider.read_network
        def read(*args):
            before = provider.clock()
            result = original(*args)
            reads.append((before - started, provider.clock() - started))
            return result
        provider.read_network = read
        report = self.run_case(provider)
        confirmed = [row for row in report.evidence if row.comparable]
        self.assertTrue(any(row.protocol == "http" or row.protocol == "https" for row in confirmed))
        self.assertTrue(all(row.data["context_confirmation"] == "round_identity_and_notifications_confirmed"
                            for row in confirmed))
        network = [row for row in confirmed if row.protocol == "network"]
        self.assertGreaterEqual(len(network), 2)
        self.assertEqual(len(reads), len(network) + 1)
        self.assertEqual(len(report.context_observations), len(reads))
        self.assertEqual(len({row.data["context_query_index"] for row in network}), len(network))
        for index, row in enumerate(network):
            with self.subTest(round_index=index + 1):
                query = report.context_observations[row.data["context_query_index"]]
                self.assertEqual((row.started_seconds, row.finished_seconds), reads[index])
                self.assertEqual(row.timestamp, query["timestamp"])
                self.assertEqual(row.started_seconds, query["query_started_seconds"])
                self.assertEqual(row.finished_seconds, query["query_finished_seconds"])
                self.assertEqual(row.data["shared_adjacent_boundary"], index > 0)
                samples = [item for item in confirmed if item.protocol != "network"
                           and item.data.get("round_index") == row.data["round_index"]]
                self.assertTrue(samples)
                self.assertTrue(all(reads[index][1] <= item.started_seconds
                                    and item.finished_seconds <= reads[index + 1][0] for item in samples))
                if index:
                    self.assertGreater(min(item.started_seconds for item in samples) - row.finished_seconds, 0.9)
        self.assertLessEqual(report.duration_seconds, report.budget_seconds)

    def test_handoff_rejects_generation_observer_and_transient_unknown_gaps(self):
        for change in ("generation", "observer", "unknown"):
            with self.subTest(change=change):
                provider, observer = Provider(FakeClock()), StableObserver()
                reads, ticks, observer_id = [], [], ["first"]
                original_read, original_snapshot = provider.read_network, observer.snapshot
                observer.snapshot = lambda: dict(original_snapshot(), observer_id=observer_id[0])
                def read(*args):
                    reads.append(provider.clock())
                    return original_read(*args)
                provider.read_network = read
                def wait(event, seconds):
                    provider.clock.wait(event, seconds)
                    if len(reads) == 2:
                        ticks.append(True)
                        if len(ticks) == 1:
                            if change == "generation": observer.generation += 2
                            elif change == "observer": observer_id[0] = "replacement"
                            else: observer.status = "UNKNOWN"
                        elif change == "unknown":
                            observer.status = "READY"
                report = SessionController(request(), provider, provider.clock, wait,
                                           context_observer=observer).run()
                network = [row for row in report.evidence if row.protocol == "network"]
                self.assertGreaterEqual(len(network), 2)
                self.assertFalse(network[1].data["shared_adjacent_boundary"])
                self.assertEqual(network[1].data["context_query_index"], 2)
                self.assertNotEqual(network[0].epoch_id, network[1].epoch_id)
                self.assertEqual(len(report.context_observations), len(reads))
                self.assertTrue(network[0].comparable and network[1].comparable)
                self.assertTrue(provider.closed and observer.closed)

    def test_failed_closing_query_cannot_be_shared_with_next_round(self):
        provider = Provider(FakeClock())
        reads = []
        original = provider.read_network
        def read(*args):
            reads.append(provider.clock())
            result = original(*args)
            if len(reads) == 2:
                return {"outcome": "execution_error", "error": "SIMULATED closing identity unavailable"}
            return result
        provider.read_network = read
        report = self.run_case(provider)
        network = [row for row in report.evidence if row.protocol == "network"]
        self.assertGreaterEqual(len(network), 2)
        self.assertFalse(network[0].comparable)
        self.assertFalse(network[1].data["shared_adjacent_boundary"])
        self.assertEqual(network[1].data["context_query_index"], 2)
        self.assertTrue(network[1].comparable)
        self.assertEqual(len(report.context_observations), len(reads))

    def test_cancel_between_rounds_does_not_publish_shared_boundary(self):
        provider, observer, event = Provider(FakeClock()), StableObserver(), threading.Event()
        reads = []
        original = provider.read_network
        def read(*args):
            self.assertFalse(event.is_set())
            reads.append(provider.clock())
            return original(*args)
        provider.read_network = read
        def wait(cancel, seconds):
            provider.clock.wait(cancel, seconds)
            if len(reads) == 2: cancel.set()
        report = SessionController(request(), provider, provider.clock, wait,
                                   context_observer=observer).run(event)
        self.assertEqual(report.status, "cancelled")
        self.assertEqual(len(reads), 2)
        self.assertEqual(len(report.context_observations), 2)
        network = [row for row in report.evidence if row.protocol == "network"]
        self.assertEqual(len(network), 1)
        self.assertFalse(network[0].data["shared_adjacent_boundary"])
        self.assertTrue(all(row.comparable for row in report.evidence))
        self.assertTrue(provider.closed and observer.closed)

    def test_generation_race_after_handoff_validation_cannot_certify_probes(self):
        provider, observer = Provider(FakeClock()), StableObserver()
        reads, gap_start, raced = [], [], []
        original_read, original_snapshot = provider.read_network, observer.snapshot
        def read(*args):
            reads.append(provider.clock())
            return original_read(*args)
        provider.read_network = read
        def snapshot():
            value = original_snapshot()
            if len(reads) == 2 and gap_start and provider.clock() >= gap_start[0] + 1.0 and not raced:
                observer.generation += 2
                raced.append(True)
            return value
        observer.snapshot = snapshot
        def progress(value):
            if value.phase == "observing" and not gap_start: gap_start.append(provider.clock())
        report = SessionController(request(), provider, provider.clock, provider.clock.wait,
                                   context_observer=observer).run(on_progress=progress)
        self.assertTrue(raced)
        second = [row for row in report.evidence if row.data.get("round_index") == 2]
        self.assertTrue(second)
        self.assertTrue(all(row.protocol == "network" for row in second))
        self.assertTrue(second[0].data["shared_adjacent_boundary"])
        self.assertTrue(all(not row.comparable and row.epoch_id is None for row in second))
        self.assertTrue(provider.closed and observer.closed)

    def test_unknown_then_ready_is_sticky_and_breaks_the_epoch(self):
        observer = StableObserver()
        original = observer.snapshot
        calls = []
        def snapshot():
            calls.append(True)
            value = original()
            if len(calls) == 4:
                value["status"] = "UNKNOWN"
            return value
        observer.snapshot = snapshot
        report = self.run_case(Provider(FakeClock()), observer)
        first_round = [row for row in report.evidence if row.data.get("round_index") == 1]
        self.assertTrue(first_round)
        self.assertTrue(all(not row.comparable and row.epoch_id is None for row in first_round))
        self.assertTrue(all(row.loss_percent is None for row in first_round))
        self.assertGreaterEqual(len(report.epochs), 2)
        self.assertTrue(any(row.comparable and row.epoch_id != 1 for row in report.evidence))

    def test_cancellation_does_not_query_afterwards_or_certify_partial_round(self):
        event = threading.Event(); reads = []
        provider = Provider(FakeClock(), on_probe=lambda protocol,_target,e: e.set() if protocol == "icmp" else None)
        original = provider.read_network
        def read(*args):
            self.assertFalse(event.is_set())
            reads.append(True)
            return original(*args)
        provider.read_network = read
        report = self.run_case(provider, event=event)
        self.assertEqual(len(reads), 1)
        self.assertEqual(report.status, "cancelled")
        self.assertTrue(all(not row.comparable and row.epoch_id is None for row in report.evidence))
        sent = [row for row in report.evidence if row.protocol == "icmp"]
        self.assertTrue(any(row.packets_sent == 1 for row in sent))
        self.assertTrue(all(row.loss_percent is None for row in sent))
        self.assertTrue(provider.closed)

    def test_unconfirmed_second_round_keeps_first_round_confirmed(self):
        provider = Provider(FakeClock())
        reads = []
        original = provider.read_network
        def read(*args):
            reads.append(True)
            if len(reads) == 3:
                return {"outcome": "execution_error", "error": "SIMULATED closing identity unavailable"}
            return original(*args)
        provider.read_network = read
        report = self.run_case(provider, req=request(duration_seconds=2))
        first = [row for row in report.evidence if row.data.get("round_index") == 1]
        second = [row for row in report.evidence if row.data.get("round_index") == 2]
        self.assertTrue(first and second)
        self.assertTrue(all(row.comparable for row in first))
        self.assertTrue(all(not row.comparable and row.epoch_id is None for row in second))

    def test_probe_exception_cannot_leave_provisional_evidence_comparable(self):
        provider = Provider(FakeClock())
        def fail(*_args): raise OSError("SIMULATED owned probe failure")
        provider.probe = fail
        report = self.run_case(provider)
        self.assertEqual(report.status, "execution_error")
        self.assertTrue(all(not row.comparable and row.epoch_id is None for row in report.evidence))
        self.assertTrue(provider.closed)


if __name__ == "__main__":
    unittest.main()
