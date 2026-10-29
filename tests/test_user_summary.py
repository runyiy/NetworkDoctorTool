"""Synthetic, offline user-summary and safe-enum redaction contracts."""
from __future__ import annotations

import copy
import json
import unittest

from losshound.core.session_diagnosis import analyze_report, DIAGNOSIS_MESSAGE_IDS
from losshound.core.session_report import redact_report
from losshound.core.session_summary import build_user_summary, SUMMARY_MESSAGE_IDS
from test_session_diagnosis_s2 import Scenario


def _finish(case, *, incomplete=()):
    case.report.update(status="deadline", budget_seconds=60, duration_seconds=59.0,
                       incomplete=list(incomplete), cleanup_errors=[], output_errors=[],
                       context_blind_spots=[])
    case.report["analysis"] = analyze_report(case.report)
    return case.report


def _group(model, family="IPv4", epoch=1):
    return next(item for item in model["groups"]
                if item["family"] == family and item["epoch_id"] == epoch)


def _part(model, part, family="IPv4", epoch=1):
    return next(item for item in _group(model, family, epoch)["observations"] if item["part"] == part)


def user_report_scenario():
    """The requested shape only; no original user report or network data."""
    case = Scenario()
    case.network()
    for _ in range(2):
        case.add("dns", "example.test", role="dns", extra={"addresses": ["203.0.113.4"]})
        case.add("dns6", "example.test", family="IPv6", role="dns",
                 extra={"addresses": ["2001:db8::4"]})
    for _ in range(5):
        case.add("icmp", "192.0.2.4")
    case.add("icmp", "192.0.2.4", "reply_timeout")
    for _ in range(3):
        case.add("icmp", "2001:db8::4", family="IPv6")
    return _finish(case, incomplete=("Synthetic opaque diagnostic detail",))


class UserSummaryTests(unittest.TestCase):
    def test_requested_synthetic_report_keeps_positive_observations_and_limits(self):
        raw = user_report_scenario()
        model = build_user_summary(raw)
        self.assertEqual(_part(model, "dns")["coverage_status"], "responses")
        self.assertEqual(_part(model, "connectivity")["coverage_status"], "mixed")
        self.assertEqual(_part(model, "connectivity")["params"]["failures"], 1)
        self.assertGreater(_part(model, "connectivity")["params"]["responses"], 1)
        self.assertEqual(_part(model, "connectivity", "IPv6")["coverage_status"], "responses")
        self.assertEqual(_part(model, "website")["message_id"], "summary.website.not_tested")
        self.assertEqual(_part(model, "website", "IPv6")["message_id"], "summary.website.not_tested")
        self.assertEqual(model["overall"]["message_id"], "summary.overall.anomalies")
        self.assertEqual(model["coverage"]["message_id"], "summary.coverage.partial")
        self.assertIn("reason_unavailable", model["coverage"]["reason_codes"])
        self.assertFalse(any(item["scope"] == "dns" for group in model["groups"] for item in group["findings"]))
        ids = [item["message_id"] for item in model["next_steps"]]
        self.assertIn("summary.advice.review_failures", ids)
        self.assertIn("summary.advice.website", ids)
        self.assertLessEqual(len(ids), 3)
        self.assertNotIn("reset", json.dumps(model))
        self.assertNotIn("healthy", json.dumps(model))

    def test_output_contains_only_safe_messages_counts_and_associations(self):
        raw = user_report_scenario()
        raw["incomplete"].append("Private opaque SyntheticPerson path C:\\SyntheticData\\private-file")
        raw["epochs"][0]["context"]["wifi"] = [{"ssid": "Synthetic family secret"}]
        before = copy.deepcopy(raw)
        model = build_user_summary(raw)
        encoded = json.dumps(model, allow_nan=False)
        self.assertEqual(raw, before)
        for value in ("203.0.113.4", "2001:db8::4", "192.0.2.4", "example.test",
                      "SyntheticPerson", "Synthetic family secret", "opaque diagnostic"):
            self.assertNotIn(value, encoded)
        source = {row["sequence"]: row for row in raw["evidence"]}
        for group in model["groups"]:
            for item in group["observations"]:
                self.assertTrue(set(item["evidence_sequences"]) <= source.keys())
                for seq in item["evidence_sequences"]:
                    row = source[seq]
                    self.assertEqual(row["epoch_id"], group["epoch_id"])
                    self.assertTrue(row["family"] == group["family"] or row["protocol"] == "network")
                self.assertTrue(all(type(count) is int and count >= 0 for count in item["params"].values()))

    def test_supported_dns_scope_comes_from_existing_cross_protocol_rule(self):
        case = Scenario()
        case.public()
        for _ in range(2):
            case.add("dns", "example.test", "unreachable", "dns")
        model = build_user_summary(_finish(case))
        dns = next(item for item in _group(model)["findings"] if item["scope"] == "dns")
        self.assertEqual(dns["message_id"], "diagnosis.dns_resolution")
        self.assertTrue(dns["supporting_evidence"])
        self.assertEqual(model["overall"]["message_id"], "summary.overall.suspected")
        self.assertIn("summary.advice.inspect_dns", [item["message_id"] for item in model["next_steps"]])

    def test_ipv6_unconfigured_and_failed_connections_are_different(self):
        unconfigured = Scenario()
        unconfigured.context["diagnostics"]["families"]["IPv6"]["available"] = False
        snapshot = unconfigured.network()
        absent = _part(build_user_summary(_finish(unconfigured)), "connectivity", "IPv6")
        self.assertEqual(absent["coverage_status"], "not_configured")
        self.assertEqual(absent["evidence_sequences"], [snapshot["sequence"]])
        self.assertEqual(absent["params"]["failures"], 0)
        failed = Scenario()
        failed.network()
        failed.add("icmp", "2001:db8::4", "reply_timeout", family="IPv6")
        actual = _part(build_user_summary(_finish(failed)), "connectivity", "IPv6")
        self.assertEqual(actual["coverage_status"], "failures")
        self.assertNotEqual(actual["coverage_status"], absent["coverage_status"])

    def test_configuration_without_comparable_snapshot_is_not_claimed_observed(self):
        case = Scenario()
        case.context["diagnostics"]["families"]["IPv6"]["available"] = False
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "connectivity", "IPv6")["coverage_status"], "not_tested")

    def test_all_unmeasured_and_tool_error_cases_are_not_network_failures(self):
        for outcome, expected in (("not_attempted", "not_tested"), ("execution_error", "tool_error")):
            with self.subTest(outcome=outcome):
                case = Scenario()
                case.add("dns", "example.test", outcome, "dns")
                model = build_user_summary(_finish(case))
                self.assertEqual(_part(model, "dns")["coverage_status"], expected)
                self.assertEqual(model["overall"]["message_id"], "summary.overall.unknown")
                self.assertFalse(any(item["scope"] != "unknown" for group in model["groups"] for item in group["findings"]))

    def test_family_success_does_not_overwrite_other_family_failure(self):
        case = Scenario()
        case.add("tcp", "192.0.2.4:443")
        case.add("tcp6", "[2001:db8::4]:443", "reply_timeout", family="IPv6")
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "connectivity")["coverage_status"], "responses")
        self.assertEqual(_part(model, "connectivity", "IPv6")["coverage_status"], "failures")

    def test_epochs_remain_separate_and_cannot_create_repeated_failure_proof(self):
        case = Scenario()
        case.report["epochs"].append({"epoch_id": 2, "identity": "B", "context": copy.deepcopy(case.context)})
        case.add("dns", "example.test", "unreachable", "dns", epoch=1)
        case.add("dns", "example.test", "success", "dns", epoch=2, extra={"addresses": ["203.0.113.4"]})
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "dns", epoch=1)["coverage_status"], "failures")
        self.assertEqual(_part(model, "dns", epoch=2)["coverage_status"], "responses")
        self.assertIn("summary.coverage.multiple_epochs", model["coverage"]["message_ids"])
        for group in model["groups"]:
            self.assertFalse(any(item["scope"] == "dns" for item in group["findings"]))

    def test_no_comparable_evidence_cannot_be_reported_as_positive(self):
        case = Scenario()
        row = case.add("tcp", "192.0.2.4:443")
        row["comparable"] = False
        row["data"]["context_status"] = "UNKNOWN"
        model = build_user_summary(_finish(case))
        item = _part(model, "connectivity")
        self.assertEqual(item["coverage_status"], "no_comparable")
        self.assertEqual(item["params"]["responses"], 0)
        self.assertEqual(item["evidence_sequences"], [])
        self.assertEqual(item["excluded_evidence_sequences"], [row["sequence"]])
        self.assertEqual(model["overall"]["message_id"], "summary.overall.unknown")

    def test_tcp_response_is_not_a_web_result(self):
        case = Scenario()
        case.add("tcp", "192.0.2.4:443", role="target")
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "connectivity")["coverage_status"], "responses")
        self.assertEqual(_part(model, "website")["message_id"], "summary.website.not_tested")
        self.assertEqual(model["coverage"]["message_id"], "summary.coverage.partial")

    def test_http_error_and_certificate_failure_are_not_whole_network_outage(self):
        for protocol, category, code, expected in (
                ("http", "http_status", 503, "http_error"),
                ("https", "tls_validation", None, "tls_error")):
            with self.subTest(protocol=protocol):
                case = Scenario()
                for _ in range(2):
                    case.add("tcp", "example.test:443", role="target", resolved_ip="192.0.2.4")
                    case.add(protocol, protocol + "://example.test/", role="target",
                             outcome="success" if code else "execution_error", resolved_ip="192.0.2.4",
                             extra={"error_category": category, "http_status": code})
                model = build_user_summary(_finish(case))
                self.assertEqual(_part(model, "website")["coverage_status"], expected)
                self.assertEqual(_part(model, "connectivity")["coverage_status"], "responses")
                self.assertFalse(any(item["scope"] in {"wan_or_isp", "gateway"} for group in model["groups"] for item in group["findings"]))
                self.assertIn("summary.advice.keep_tls", [item["message_id"] for item in model["next_steps"]])

    def test_https_success_requires_actual_validation_fact(self):
        case = Scenario()
        row = case.add("https", "https://example.test/", role="target", extra={"http_status": 200})
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "website")["coverage_status"], "tool_error")
        row["data"]["tls_verified"] = True
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "website")["coverage_status"], "responses")

    def test_empty_dns_answer_list_is_not_an_observed_resolution(self):
        case = Scenario()
        case.add("dns", "example.test", role="dns", extra={"addresses": []})
        self.assertEqual(_part(build_user_summary(_finish(case)), "dns")["coverage_status"], "tool_error")

    def test_zero_sent_icmp_is_not_a_network_timeout(self):
        case = Scenario()
        row = case.add("icmp", "192.0.2.4", "reply_timeout")
        row["packets_sent"] = 0
        item = _part(build_user_summary(_finish(case)), "connectivity")
        self.assertEqual(item["params"]["failures"], 0)
        self.assertEqual(item["coverage_status"], "tool_error")

    def test_incomplete_reason_is_not_guessed_from_private_error_text(self):
        case = Scenario()
        raw = _finish(case, incomplete=("timeout IPv6 DNS private arbitrary exception",))
        raw["status"] = "deadline"
        model = build_user_summary(raw)
        self.assertIn("reason_unavailable", model["coverage"]["reason_codes"])
        self.assertNotIn("timeout", model["coverage"]["reason_codes"])
        self.assertNotIn("private arbitrary exception", json.dumps(model))

    def test_duplicate_ids_are_excluded_not_independent_samples(self):
        case = Scenario()
        row = case.add("dns", "example.test", role="dns", extra={"addresses": ["203.0.113.4"]})
        case.report["evidence"].append(copy.deepcopy(row))
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "dns")["coverage_status"], "not_tested")
        self.assertEqual(model["overall"]["message_id"], "summary.overall.unknown")
        self.assertEqual(model["coverage"]["params"]["excluded_count"], 2)

    def test_redacted_alias_input_is_rejected(self):
        with self.assertRaises(ValueError):
            build_user_summary(redact_report(user_report_scenario()))

    def test_ids_are_additive_and_old_machine_fields_remain_unchanged(self):
        case = Scenario()
        case.network()
        original = copy.deepcopy(case.report)
        analysis = analyze_report(case.report)
        self.assertEqual(case.report, original)
        self.assertEqual(analysis["schema_version"], 1)
        for finding in analysis["findings"]:
            for key in ("scope", "category", "confidence", "supporting_evidence", "contradictions",
                        "explanation", "recommendations", "limitations"):
                self.assertIn(key, finding)
            self.assertIn(finding["message_id"], DIAGNOSIS_MESSAGE_IDS)
        model = build_user_summary(_finish(case))
        self.assertIn(model["overall"]["message_id"], SUMMARY_MESSAGE_IDS)
        self.assertLessEqual(len(model["next_steps"]), 3)

    def test_supported_analysis_with_other_family_refs_is_not_repeated(self):
        case = Scenario()
        ipv6 = case.add("icmp", "2001:db8::4", "reply_timeout", family="IPv6")
        raw = _finish(case)
        raw["analysis"]["findings"].append({
            "scope": "dns", "family": "IPv4", "epoch_id": 1, "confidence": "medium",
            "message_id": "diagnosis.dns_resolution", "supporting_evidence": [ipv6["sequence"]],
        })
        model = build_user_summary(raw)
        self.assertFalse(any(item["scope"] == "dns" for group in model["groups"] for item in group["findings"]))



    def test_redirect_response_is_not_relabelled_as_network_failure(self):
        case = Scenario()
        case.add("http", "http://example.test/", role="target",
                 extra={"http_status": 302, "error_category": "http_status"})
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "website")["coverage_status"], "responses")
        self.assertEqual(_part(model, "website")["params"]["failures"], 0)
        self.assertFalse(any(item["scope"] == "wan_or_isp" for group in model["groups"] for item in group["findings"]))

    def test_unknown_context_tool_error_remains_coverage_not_network_failure(self):
        case = Scenario()
        row = case.add("dns", "example.test", "execution_error", "dns")
        row["comparable"] = False
        row["epoch_id"] = None
        row["data"]["context_status"] = "UNKNOWN"
        model = build_user_summary(_finish(case))
        item = _part(model, "dns", epoch=None)
        self.assertEqual(item["coverage_status"], "tool_error")
        self.assertEqual(item["params"]["failures"], 0)
        self.assertEqual(item["params"]["tool_errors"], 1)
        self.assertEqual(item["evidence_sequences"], [])
        self.assertEqual(item["excluded_evidence_sequences"], [row["sequence"]])

    def test_unknown_context_never_sent_is_explicitly_not_tested(self):
        case = Scenario()
        row = case.add("dns", "example.test", "not_attempted", "dns")
        row["comparable"] = False
        row["data"]["context_status"] = "UNKNOWN"
        model = build_user_summary(_finish(case))
        self.assertEqual(_part(model, "dns")["coverage_status"], "not_tested")


    def test_repeated_redirect_with_tcp_does_not_invent_service_failure(self):
        case = Scenario()
        for _ in range(2):
            case.add("tcp", "example.test:80", role="target", resolved_ip="192.0.2.4")
            case.add("http", "http://example.test/", role="target", resolved_ip="192.0.2.4",
                     extra={"http_status": 302, "error_category": "http_status"})
        raw = _finish(case)
        self.assertFalse(any(item["message_id"] == "diagnosis.target_service" for item in raw["analysis"]["findings"]))
        model = build_user_summary(raw)
        self.assertEqual(_part(model, "website")["coverage_status"], "responses")
        self.assertEqual(model["overall"]["message_id"], "summary.overall.responses")

    def test_repeated_503_still_has_original_service_evidence(self):
        case = Scenario()
        expected = []
        for _ in range(2):
            tcp = case.add("tcp", "example.test:80", role="target", resolved_ip="192.0.2.4")
            http = case.add("http", "http://example.test/", role="target", resolved_ip="192.0.2.4",
                            extra={"http_status": 503, "error_category": "http_status"})
            expected.extend((tcp["sequence"], http["sequence"]))
        raw = _finish(case)
        finding = next(item for item in raw["analysis"]["findings"] if item["message_id"] == "diagnosis.target_service")
        self.assertEqual(finding["supporting_evidence"], sorted(expected))
        self.assertEqual(finding["confidence"], "medium")
        self.assertEqual(finding["epoch_id"], 1)
        self.assertEqual(finding["family"], "IPv4")

    def test_redirect_is_retained_as_service_counterevidence_without_new_veto_rule(self):
        case = Scenario()
        for _ in range(2):
            case.add("tcp", "example.test:80", role="target", resolved_ip="192.0.2.4")
            case.add("http", "http://example.test/", role="target", resolved_ip="192.0.2.4",
                     extra={"http_status": 503, "error_category": "http_status"})
        redirect = case.add("http", "http://example.test/", role="target", resolved_ip="192.0.2.4",
                            extra={"http_status": 302, "error_category": "http_status"})
        raw = _finish(case)
        finding = next(item for item in raw["analysis"]["findings"] if item["message_id"] == "diagnosis.target_service")
        self.assertIn(redirect["sequence"], finding["contradictions"])
        self.assertNotIn(redirect["sequence"], finding["supporting_evidence"])
        model = build_user_summary(raw)
        self.assertEqual(_part(model, "website")["coverage_status"], "mixed")
        self.assertIn(redirect["sequence"], _group(model)["findings"][0]["contradictions"])

    def test_http_status_tag_without_typed_status_cannot_invent_service_error(self):
        for invalid_code in (None, "503", True, 999):
            with self.subTest(invalid_code=invalid_code):
                case = Scenario()
                for _ in range(2):
                    case.add("tcp", "example.test:80", role="target", resolved_ip="192.0.2.4")
                    case.add("http", "http://example.test/", role="target", resolved_ip="192.0.2.4",
                             extra={"http_status": invalid_code, "error_category": "http_status"})
                raw = _finish(case)
                self.assertFalse(any(item["message_id"] == "diagnosis.target_service" for item in raw["analysis"]["findings"]))
                model = build_user_summary(raw)
                self.assertEqual(_part(model, "website")["coverage_status"], "tool_error")
                self.assertEqual(_part(model, "website")["params"]["failures"], 0)

class FixedEnumRedactionTests(unittest.TestCase):

    def test_context_fixed_configuration_and_continuity_codes_are_readable(self):
        raw = {"context": {"status": "configured", "continuity": "OBSERVED",
                           "diagnostics": {"families": {"IPv4": {"status": "configured"},
                                                       "IPv6": {"status": "incomplete"}}}},
               "status": "READY"}
        safe = redact_report(raw)
        self.assertEqual(safe["context"]["status"], "configured")
        self.assertEqual(safe["context"]["continuity"], "OBSERVED")
        self.assertEqual(safe["context"]["diagnostics"]["families"]["IPv6"]["status"], "incomplete")
        self.assertEqual(safe["status"], "READY")


    def test_private_value_collision_does_not_redact_typed_machine_codes(self):
        for private_value in ("icmp", "success", "IPv4", "IDENTIFIED", "tls_validation",
                              "diagnosis.dns_resolution", "summary.overall.responses"):
            with self.subTest(private_value=private_value):
                raw = {
                    "epochs": [{"epoch_id": 1, "identity": private_value,
                                "context": {"wifi": [{"ssid": private_value}]}}],
                    "status": "success", "evidence": [{
                        "protocol": "icmp", "family": "IPv4", "outcome": "success",
                        "data": {"context_status": "IDENTIFIED", "error_category": "tls_validation"},
                    }],
                    "analysis": {"findings": [{"message_id": "diagnosis.dns_resolution"}]},
                    "user_summary": {"overall": {"message_id": "summary.overall.responses"}},
                }
                safe = redact_report(raw)
                self.assertNotEqual(safe["epochs"][0]["identity"], private_value)
                self.assertNotEqual(safe["epochs"][0]["context"]["wifi"][0]["ssid"], private_value)
                self.assertEqual(safe["status"], "success")
                self.assertEqual(safe["evidence"][0]["protocol"], "icmp")
                self.assertEqual(safe["evidence"][0]["family"], "IPv4")
                self.assertEqual(safe["evidence"][0]["outcome"], "success")
                self.assertEqual(safe["evidence"][0]["data"]["context_status"], "IDENTIFIED")
                self.assertEqual(safe["evidence"][0]["data"]["error_category"], "tls_validation")
                self.assertEqual(safe["analysis"]["findings"][0]["message_id"], "diagnosis.dns_resolution")
                self.assertEqual(safe["user_summary"]["overall"]["message_id"], "summary.overall.responses")

    def test_unknown_codes_and_raw_error_fields_keep_original_privacy_boundary(self):
        raw = {
            "context": {"wifi": {"ssid": "Synthetic private marker"}},
            "protocol": "Synthetic private marker", "message_id": "Synthetic private marker",
            "error_category": "Synthetic private marker", "error": "success",
            "incomplete": ["tls_validation"], "data": {"stdout": "success"},
        }
        safe = redact_report(raw)
        self.assertNotIn("Synthetic private marker", json.dumps(safe))
        self.assertEqual(safe["error"], "[redacted diagnostic detail]")
        self.assertEqual(safe["incomplete"], ["[redacted diagnostic detail]"])
        self.assertNotIn("stdout", safe["data"])

    def test_summary_round_trip_keeps_enum_readability_and_private_input_absent(self):
        model = build_user_summary(user_report_scenario())
        safe = redact_report(model)
        self.assertEqual(safe["overall"]["message_id"], model["overall"]["message_id"])
        self.assertEqual(safe["groups"][0]["family"], "IPv4")
        self.assertEqual(safe["groups"][0]["observations"][0]["coverage_status"], "mixed")
        self.assertEqual(safe["coverage"]["reason_codes"], model["coverage"]["reason_codes"])
        self.assertNotIn("example.test", json.dumps(safe))


if __name__ == "__main__":
    unittest.main()
