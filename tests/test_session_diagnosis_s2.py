"""Offline S2 inference contract tests; all evidence is synthetic."""
from __future__ import annotations

import copy
import json
import socket
import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from losshound.core.session_diagnosis import analyze_report, MAX_EVIDENCE


class Scenario:
    def __init__(self):
        self.context = {"diagnostics": {"families": {
            "IPv4": {"available": True, "default_route": {"gateway": "192.168.1.1", "interface_index": 7}},
            "IPv6": {"available": True, "default_route": {"gateway": "fe80::1%7", "interface_index": 7}},
        }, "wifi": []}}
        self.report = {"schema_version": 3, "epochs": [{"epoch_id": 1, "identity": "A", "context": self.context}], "evidence": []}

    def add(self, protocol="icmp", target="1.1.1.1", outcome="success", role="public",
            family="IPv4", *, epoch=1, at=None, resolved_ip=None, extra=None, host=None):
        sequence = len(self.report["evidence"]) + 1
        moment = sequence / 10 if at is None else at
        data = {"role": role, "context_status": "IDENTIFIED"}
        if resolved_ip is not None:
            data["resolved_ip"] = resolved_ip
        if host is not None:
            data["target_host"] = host
        if extra:
            data.update(extra)
        row = {"sequence": sequence, "epoch_id": epoch, "protocol": protocol, "family": family,
               "target": target, "outcome": outcome, "comparable": True, "data": data,
               "started_seconds": moment, "finished_seconds": moment + 0.01,
               "packets_sent": 1 if protocol == "icmp" and outcome in ("success", "reply_timeout", "unreachable") else None,
               "packets_received": (1 if outcome == "success" else 0) if protocol == "icmp" and outcome in ("success", "reply_timeout", "unreachable") else None}
        self.report["evidence"].append(row)
        return row

    def network(self, at=0):
        return self.add("network", "local_network", role="local", at=at, extra=copy.deepcopy(self.context))

    def gateway(self, outcome="success", **kwargs):
        return [self.add(target="192.168.1.1", role="gateway", outcome=outcome, **kwargs) for _ in range(2)]

    def public(self, outcome="success", *, addresses=("1.1.1.1", "8.8.8.8"), family="IPv4", epoch=1):
        for address in addresses:
            for protocol in ("icmp", "tcp6" if family == "IPv6" else "tcp"):
                target = address if protocol == "icmp" else ("[" + address + "]" if ":" in address else address) + ":443"
                for _ in range(2):
                    self.add(protocol, target, outcome, family=family, epoch=epoch)

    def target_failure(self, *, address="9.9.9.9", second_address=None, family="IPv4", epoch=1):
        for protocol in ("icmp", "tcp6" if family == "IPv6" else "tcp"):
            for _ in range(2):
                self.add(protocol, address if protocol == "icmp" else "site.example:443",
                         "reply_timeout", "target", family, epoch=epoch, host="site.example",
                         resolved_ip=(second_address or address) if protocol != "icmp" else address)

    def analysis(self):
        return analyze_report(self.report)


def scopes(analysis):
    return {finding["scope"] for finding in analysis["findings"]}


class DiagnosisS2Tests(unittest.TestCase):
    def test_empty_and_legacy_missing_data_remain_unknown(self):
        for report in ({}, None, {"schema_version": 2, "epochs": [], "evidence": []}):
            with self.subTest(report=report):
                result = analyze_report(report)
                self.assertEqual(scopes(result), {"unknown"})
                self.assertFalse(result["intermittent"])
                self.assertNotIn("healthy", json.dumps(result))

    def test_current_session_input_is_unchanged_and_prior_analysis_ignored(self):
        case = Scenario()
        case.gateway()
        case.public()
        case.report["analysis"] = {"findings": [{"scope": "wan_or_isp"}]}
        before = copy.deepcopy(case.report)
        result = case.analysis()
        self.assertEqual(case.report, before)
        self.assertNotIn("wan_or_isp", scopes(result))
        json.dumps(result, allow_nan=False)

    def test_local_configuration_finding_has_snapshot_reference_and_family_boundary(self):
        case = Scenario()
        case.context["diagnostics"]["families"]["IPv6"]["available"] = False
        snapshot = case.network()
        result = case.analysis()
        local = next(item for item in result["findings"] if item["scope"] == "local")
        self.assertEqual(local["family"], "IPv6")
        self.assertEqual(local["supporting_evidence"], [snapshot["sequence"]])
        self.assertTrue(local["context_fields"])
        self.assertIn("IPv4", " ".join(local["alternatives"]))

    def test_static_missing_configuration_without_snapshot_is_not_proven_fault(self):
        case = Scenario()
        case.context["diagnostics"]["families"]["IPv6"]["available"] = False
        self.assertEqual(scopes(case.analysis()), {"unknown"})

    def test_gateway_path_requires_repeated_public_cross_protocol_evidence(self):
        case = Scenario()
        case.gateway("reply_timeout")
        self.assertEqual(scopes(case.analysis()), {"unknown"})
        case.public("reply_timeout")
        finding = next(item for item in case.analysis()["findings"] if item["scope"] == "gateway")
        self.assertEqual(finding["confidence"], "low")
        self.assertTrue(finding["alternatives"])
        self.assertGreater(len(finding["supporting_evidence"]), 2)

    def test_gateway_success_and_public_multitarget_failure_only_suspects_wan(self):
        case = Scenario()
        gateway = case.gateway()
        case.public("reply_timeout")
        case.add("dns", "example.com", role="dns")
        finding = next(item for item in case.analysis()["findings"] if item["scope"] == "wan_or_isp")
        self.assertEqual(finding["confidence"], "low")
        self.assertIn("疑似", finding["explanation"])
        self.assertIn("不能确认 ISP", " ".join(finding["alternatives"]))
        self.assertEqual(finding["contradictions"], [])
        self.assertTrue({row["sequence"] for row in gateway}.issubset(finding["supporting_evidence"]))

    def test_weak_wifi_is_only_a_hypothesis_with_same_route_interface_and_direct_signal(self):
        case = Scenario()
        case.context["diagnostics"]["wifi"] = [{"interface_index": 7, "state": 1, "signal_quality": 15}]
        case.network()
        case.gateway("reply_timeout")
        case.public("reply_timeout")
        finding = next(item for item in case.analysis()["findings"] if item["scope"] == "wifi")
        self.assertEqual(finding["confidence"], "low")
        self.assertTrue(finding["context_fields"])
        for missing in (None, 8):
            with self.subTest(interface=missing):
                altered = copy.deepcopy(case.report)
                altered["epochs"][0]["context"]["diagnostics"]["wifi"][0]["interface_index"] = missing
                altered["evidence"][0]["data"]["diagnostics"]["wifi"][0]["interface_index"] = missing
                self.assertNotIn("wifi", scopes(analyze_report(altered)))

    def test_identity_only_wifi_does_not_assign_wireless_cause(self):
        case = Scenario()
        case.context["diagnostics"]["wifi"] = [{"guid": "test", "state": 1}]
        case.network()
        case.gateway("reply_timeout")
        case.public("reply_timeout")
        self.assertNotIn("wifi", scopes(case.analysis()))

    def test_dns_scope_requires_live_public_baseline_and_retains_resolver_limit(self):
        case = Scenario()
        for _ in range(2):
            case.add("dns", "example.invalid", "unreachable", "dns")
        self.assertNotIn("dns", scopes(case.analysis()))
        case.public()
        finding = next(item for item in case.analysis()["findings"] if item["scope"] == "dns")
        self.assertIn("hosts", " ".join(finding["limitations"]))
        self.assertFalse(set(finding["supporting_evidence"]) & set(finding["contradictions"]))

    def test_target_scope_compares_same_actual_address(self):
        case = Scenario()
        case.public()
        case.target_failure()
        self.assertIn("target", scopes(case.analysis()))
        other = Scenario()
        other.public()
        other.target_failure(second_address="149.112.112.112")
        self.assertNotIn("target", scopes(other.analysis()))

    def test_hostname_without_resolved_peer_cannot_be_transport_cross_check(self):
        case = Scenario()
        case.public()
        case.target_failure()
        for row in case.report["evidence"]:
            if row["data"]["role"] == "target" and row["protocol"] == "tcp":
                row["data"].pop("resolved_ip", None)
        self.assertNotIn("target", scopes(case.analysis()))

    def test_each_public_actual_address_needs_multiple_protocols(self):
        case = Scenario()
        case.gateway()
        for _ in range(2):
            case.add("icmp", "1.1.1.1", "reply_timeout")
            case.add("tcp", "8.8.8.8:443", "reply_timeout")
        self.assertNotIn("wan_or_isp", scopes(case.analysis()))

    def test_private_loopback_reserved_and_multicast_public_labels_cannot_support_wan_or_dns(self):
        pairs = (("127.0.0.1", "127.0.0.2"), ("192.168.1.2", "192.168.1.3"),
                 ("169.254.1.2", "169.254.1.3"), ("224.0.0.1", "224.0.0.2"),
                 ("0.0.0.0", "198.18.0.1"), ("192.0.2.1", "198.51.100.1"))
        for addresses in pairs:
            with self.subTest(addresses=addresses):
                failed = Scenario()
                failed.gateway()
                failed.public("reply_timeout", addresses=addresses)
                self.assertNotIn("wan_or_isp", scopes(failed.analysis()))
                passed = Scenario()
                passed.public(addresses=addresses)
                for _ in range(2):
                    passed.add("dns", "example.invalid", "unreachable", "dns")
                self.assertNotIn("dns", scopes(passed.analysis()))

    def test_unknown_context_unsent_and_tool_errors_do_not_become_network_failure(self):
        for outcome in ("execution_error", "unsupported", "skipped", "not_attempted", "cancelled"):
            with self.subTest(outcome=outcome):
                case = Scenario()
                case.gateway()
                case.public(outcome)
                self.assertNotIn("wan_or_isp", scopes(case.analysis()))
        case = Scenario()
        case.gateway()
        case.public("reply_timeout")
        for row in case.report["evidence"]:
            if row["data"]["role"] == "public":
                row["data"]["context_status"] = "UNKNOWN"
        self.assertNotIn("wan_or_isp", scopes(case.analysis()))

    def test_single_observation_and_invalid_icmp_counts_do_not_establish_failure(self):
        case = Scenario()
        case.gateway()
        for address in ("1.1.1.1", "8.8.8.8"):
            case.add("icmp", address, "reply_timeout")
            case.add("tcp", address + ":443", "reply_timeout")
        self.assertNotIn("wan_or_isp", scopes(case.analysis()))
        case = Scenario()
        case.gateway()
        case.public("reply_timeout")
        for row in case.report["evidence"]:
            if row["protocol"] == "icmp" and row["data"]["role"] == "public":
                row["packets_sent"] = 0
        self.assertNotIn("wan_or_isp", scopes(case.analysis()))

    def test_reachability_counterevidence_blocks_broad_failure_and_is_traceable(self):
        case = Scenario()
        case.gateway()
        case.public("reply_timeout")
        counter = case.add("tcp", "1.1.1.1:443", "success")
        result = case.analysis()
        self.assertNotIn("wan_or_isp", scopes(result))
        unknown = next(item for item in result["findings"] if item["scope"] == "unknown")
        self.assertIn(counter["sequence"], unknown["contradictions"])
        self.assertFalse(set(unknown["supporting_evidence"]) & set(unknown["contradictions"]))

    def test_epoch_and_address_family_evidence_are_not_mixed(self):
        case = Scenario()
        case.gateway()
        case.report["epochs"].append({"epoch_id": 2, "identity": "B", "context": copy.deepcopy(case.context)})
        case.public("reply_timeout", epoch=2)
        self.assertNotIn("wan_or_isp", scopes(case.analysis()))
        family = Scenario()
        family.public()
        family.target_failure(address="2606:4700:4700::1111", family="IPv6")
        self.assertNotIn("target", scopes(family.analysis()))

    def test_ipv6_suffix_protocols_keep_family_and_actual_address(self):
        case = Scenario()
        case.public(addresses=("2606:4700:4700::1111", "2001:4860:4860::8888"), family="IPv6")
        for _ in range(2):
            case.add("dns6", "example.invalid", "unreachable", "dns", "IPv6")
        dns = next(item for item in case.analysis()["findings"] if item["scope"] == "dns")
        self.assertEqual(dns["family"], "IPv6")

    def test_refused_tls_and_http_status_errors_do_not_establish_network_outage(self):
        for category in ("connection_refused", "tls_validation", "tls_handshake", "http_status"):
            with self.subTest(category=category):
                case = Scenario()
                case.gateway()
                case.public("unreachable")
                for row in case.report["evidence"]:
                    if row["protocol"] == "tcp":
                        row["data"]["error_category"] = category
                self.assertNotIn("wan_or_isp", scopes(case.analysis()))
        for protocol, outcome, extra in (
                ("http", "success", {"http_status": 503}),
                ("https", "execution_error", {"error_category": "tls_validation"}),
                ("https", "execution_error", {"error_category": "tls_handshake"})):
            case = Scenario()
            for _ in range(2):
                case.add("tcp", "site.example:443", role="target", resolved_ip="9.9.9.9")
                case.add(protocol, protocol + "://site.example/", outcome, "target", resolved_ip="9.9.9.9", extra=extra)
            result = case.analysis()
            self.assertIn("target", scopes(result))
            self.assertNotIn("wan_or_isp", scopes(result))
            self.assertFalse(result["intermittent"])

    def test_scope_does_not_combine_very_old_baseline_with_new_failure(self):
        case = Scenario()
        case.gateway(at=1)
        case.public("reply_timeout")
        for row in case.report["evidence"]:
            if row["data"]["role"] == "public":
                row["started_seconds"] += 100
                row["finished_seconds"] += 100
        self.assertNotIn("wan_or_isp", scopes(case.analysis()))

    def test_fresh_success_failure_success_records_only_current_same_protocol_target(self):
        case = Scenario()
        for at, outcome in ((1, "success"), (2, "reply_timeout"), (3, "success")):
            case.add(outcome=outcome, at=at)
        item = case.analysis()["intermittent"][0]
        self.assertEqual(item["evidence_sequences"], [1, 2, 3])
        self.assertEqual(item["window"], {"started_seconds": 1.0, "finished_seconds": 3.01})
        self.assertIn("彻底修复", " ".join(item["limitations"]))

    def test_intermittent_does_not_cross_errors_families_epochs_peers_or_stale_time(self):
        for change in ("error", "family", "epoch", "address", "stale", "unsent"):
            with self.subTest(change=change):
                case = Scenario()
                case.report["epochs"].append({"epoch_id": 2, "identity": "B", "context": copy.deepcopy(case.context)})
                case.add(at=1)
                failure = case.add(outcome="reply_timeout", at=2)
                last = case.add(at=3)
                if change == "error":
                    failure["outcome"] = "execution_error"
                elif change == "family":
                    failure["family"] = "IPv6"
                    failure["target"] = "2606:4700:4700::1111"
                elif change == "epoch":
                    failure["epoch_id"] = 2
                elif change == "address":
                    failure["target"] = "8.8.8.8"
                elif change == "stale":
                    last.update(started_seconds=100, finished_seconds=100.01)
                else:
                    failure["packets_sent"] = 0
                self.assertEqual(case.analysis()["intermittent"], [])

    def test_missing_timestamps_and_duplicate_sequences_do_not_infer_scope(self):
        case = Scenario()
        case.gateway()
        case.public("reply_timeout")
        for row in case.report["evidence"]:
            row.pop("started_seconds")
        self.assertNotIn("wan_or_isp", scopes(case.analysis()))
        duplicate = Scenario()
        duplicate.gateway()
        duplicate.public("reply_timeout")
        for row in duplicate.report["evidence"]:
            row["sequence"] = 1
        self.assertEqual(scopes(duplicate.analysis()), {"unknown"})

    def test_analysis_is_bounded_and_oversized_input_does_not_use_selected_prefix_as_fault(self):
        case = Scenario()
        case.gateway()
        case.public("reply_timeout")
        while len(case.report["evidence"]) <= MAX_EVIDENCE:
            case.add("icmp", "1.1.1.1", "reply_timeout")
        result = case.analysis()
        self.assertTrue(result["coverage"]["truncated"])
        self.assertEqual(scopes(result), {"unknown"})
        self.assertEqual(result["intermittent"], [])

    def test_malformed_json_values_remain_bounded_and_serializable(self):
        case = Scenario()
        case.add("https", "https://site.example/", "execution_error", "target",
                 resolved_ip="9.9.9.9", extra={"error_category": ["tls_validation"], "http_status": []})
        oversized_time = case.add()
        oversized_time.update(started_seconds=10 ** 500, finished_seconds=10 ** 500)
        case.report["evidence"].extend([None, [], {"sequence": True, "epoch_id": 1}])
        result = case.analysis()
        json.dumps(result, allow_nan=False)
        self.assertEqual(scopes(result), {"unknown"})

    def test_no_io_process_network_or_input_mutation_occurs(self):
        case = Scenario()
        case.gateway()
        case.public("reply_timeout")
        before = copy.deepcopy(case.report)
        with patch("builtins.open", side_effect=AssertionError("I/O")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("resolver")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            result = case.analysis()
        self.assertIn("wan_or_isp", scopes(result))
        self.assertEqual(case.report, before)
        for finding in result["findings"]:
            for field in ("supporting_evidence", "contradictions", "alternatives", "confidence",
                          "evidence_sequences", "limitations", "recommendations"):
                self.assertIn(field, finding)
            self.assertFalse(set(finding["supporting_evidence"]) & set(finding["contradictions"]))


if __name__ == "__main__":
    unittest.main()
