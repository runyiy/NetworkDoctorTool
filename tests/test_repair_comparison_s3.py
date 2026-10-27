"""SIMULATED S3 before/after comparisons; never executes a repair or probe."""
from __future__ import annotations

import copy
import socket
import subprocess
import unittest
from dataclasses import replace
from unittest.mock import patch

from losshound.core.repair import compare_reports
from losshound.core.session import (
    NetworkEpoch, ProbeEvidence, ProbeOutcome, SessionReport, SessionRequest,
)

RAW_IDENTITY = "a" * 64
DNS_TARGET = "lookup.example"


def comparison_request(**changes):
    options = dict(duration_seconds=60, extended_diagnostics=True,
                   ping_targets=(), dns_hostnames=(DNS_TARGET,), ipv6_targets=(),
                   tcp_targets=(), website_urls=())
    options.update(changes)
    return SessionRequest(**options)


def dns_sample(sequence, outcome, *, family="IPv4", start=50.0, epoch=1,
               target=DNS_TARGET, role="dns"):
    address = "1.1.1.1" if family == "IPv4" else "2606:4700:4700::1111"
    protocol = "dns" if family == "IPv4" else "dns6"
    return ProbeEvidence(
        sequence=sequence, timestamp="2026-10-26T10:00:50+00:00",
        started_seconds=start, finished_seconds=start + 0.1, epoch_id=epoch,
        protocol=protocol, family=family, target=target, outcome=ProbeOutcome(outcome),
        comparable=True,
        data={"role": role, "target_host": target, "family": family,
              "context_status": "IDENTIFIED", "source": "os_resolver",
              "resolver_result_only": True,
              "addresses": [address] if outcome == "success" else []},
    )


def comparison_report(outcomes=("reply_timeout", "reply_timeout"), *, status="deadline"):
    report = SessionReport(
        status=status, budget_seconds=60, duration_seconds=58.0, schema_version=3,
        epochs=[NetworkEpoch(1, RAW_IDENTITY, 0.0,
                             {"identity": RAW_IDENTITY, "context_status": "IDENTIFIED"})],
        # These routine limitations are not themselves evidence of bad collection.
        incomplete=["The observation window does not establish continuous health."],
        context_blind_spots=["OS change notifications can be delayed or omitted."],
        analysis={"intermittent": []},
    )
    for family_index, family in enumerate(("IPv4", "IPv6")):
        for index, outcome in enumerate(outcomes):
            report.evidence.append(dns_sample(len(report.evidence) + 1, outcome,
                                             family=family, start=49.0 + 2 * family_index + index))
    report.evidence.append(ProbeEvidence(
        sequence=len(report.evidence) + 1, timestamp="2026-10-26T10:00:57+00:00",
        started_seconds=56.9, finished_seconds=57.0, epoch_id=1,
        protocol="network", family="unspecified", target="local_network",
        outcome=ProbeOutcome.SUCCESS, comparable=True,
        data={"role": "local", "identity": RAW_IDENTITY, "context_status": "IDENTIFIED"},
    ))
    return report


def add_before_closing_snapshot(report, samples):
    closing = report.evidence.pop()
    for sample in samples:
        report.evidence.append(replace(sample, sequence=len(report.evidence) + 1))
    report.evidence.append(replace(closing, sequence=len(report.evidence) + 1))


def add_transport(report, peer="1.1.1.1"):
    rows = [
        ProbeEvidence(
            sequence=1, timestamp="2026-10-26T10:00:54+00:00",
            started_seconds=54.0 + index, finished_seconds=54.1 + index,
            epoch_id=1, protocol="tcp", family="IPv4", target="edge.example:443",
            outcome=ProbeOutcome.SUCCESS, comparable=True,
            data={"role": "public", "target_host": "edge.example",
                  "resolved_ip": peer, "family": "IPv4", "context_status": "IDENTIFIED"},
        )
        for index in range(2)
    ]
    add_before_closing_snapshot(report, rows)


class RepairComparisonTests(unittest.TestCase):
    """Typed current-session snapshots only; no history or repair execution."""

    def compare(self, before, after, baseline=None, verification=None):
        baseline = baseline or comparison_request()
        verification = verification or baseline
        original = copy.deepcopy((before, after, baseline, verification))
        result = compare_reports(before, after, baseline, verification)
        self.assertEqual((before, after, baseline, verification), original)
        for key in ("status", "comparable", "reasons", "comparisons", "limitations",
                    "causal_attribution"):
            self.assertIn(key, result)
        self.assertIsInstance(result["comparable"], bool)
        self.assertIsInstance(result["reasons"], list)
        self.assertIsInstance(result["comparisons"], list)
        self.assertTrue(result["limitations"])
        self.assertEqual(result["causal_attribution"], "not_established")
        return result

    def assert_inconclusive(self, before, after, baseline=None, verification=None):
        result = self.compare(before, after, baseline, verification)
        self.assertEqual(result["status"], "inconclusive")
        self.assertTrue(result["reasons"])
        return result

    def test_repeated_dns_failure_then_success_is_observation_not_causal_repair(self):
        for before_status, after_status in (("deadline", "completed"), ("completed", "deadline")):
            with self.subTest(before=before_status, after=after_status):
                before = comparison_report(status=before_status)
                after = comparison_report(("success", "success"), status=after_status)
                result = self.compare(before, after)
                self.assertTrue(result["comparable"])
                self.assertEqual(result["status"], "observed_dns_improvement")
                self.assertTrue(result["comparisons"])

    def test_continuous_failure_after_verification_has_no_observed_dns_improvement(self):
        before = comparison_report(("reply_timeout", "unreachable"))
        after = comparison_report(("unreachable", "reply_timeout"))
        result = self.compare(before, after)
        self.assertTrue(result["comparable"])
        self.assertEqual(result["status"], "no_dns_improvement_observed")

    def test_healthy_baseline_does_not_count_as_improvement(self):
        result = self.compare(comparison_report(("success", "success")),
                              comparison_report(("success", "success")))
        self.assertNotEqual(result["status"], "observed_dns_improvement")

    def test_mixed_or_previously_intermittent_baseline_cannot_be_cleared_by_non_reproduction(self):
        mixed = comparison_report(("reply_timeout", "reply_timeout"))
        add_before_closing_snapshot(mixed, [dns_sample(1, "success", start=54.0)])
        self.assert_inconclusive(mixed, comparison_report(("success", "success")))
        intermittent = comparison_report()
        intermittent.analysis["intermittent"] = [{"protocol": "dns", "target": DNS_TARGET}]
        self.assert_inconclusive(intermittent, comparison_report(("success", "success")))

    def test_cancelled_and_cleanup_or_output_failures_preclude_comparison(self):
        for field, value in (("status", "cancelled"),
                             ("cleanup_errors", ["SIMULATED owned cleanup failed"]),
                             ("output_errors", ["SIMULATED report delivery failed"])):
            with self.subTest(field=field):
                after = comparison_report(("success", "success"))
                setattr(after, field, value)
                result = self.assert_inconclusive(comparison_report(), after)
                self.assertFalse(result["comparable"])

    def test_different_request_targets_and_observation_budgets_preclude_comparison(self):
        before, after = comparison_report(), comparison_report(("success", "success"))
        baseline = comparison_request()
        for verification in (
                comparison_request(duration_seconds=30),
                comparison_request(dns_hostnames=("different.example",))):
            with self.subTest(verification=verification):
                self.assert_inconclusive(before, after, baseline, verification)
        mismatched_report = comparison_report(("success", "success"))
        mismatched_report.budget_seconds = 30
        self.assert_inconclusive(before, mismatched_report)

    def test_raw_identity_is_required_and_aliases_or_network_change_are_rejected(self):
        for identity in ("", "[identity-1]", "[context-1]", "redacted-network", "b" * 64):
            with self.subTest(identity=identity):
                after = comparison_report(("success", "success"))
                after.epochs[0].identity = identity
                after.epochs[0].context["identity"] = identity
                result = self.assert_inconclusive(comparison_report(), after)
                self.assertFalse(result["comparable"])

    def test_multiple_confirmed_epochs_cannot_be_combined(self):
        before = comparison_report()
        before.epochs.append(NetworkEpoch(2, RAW_IDENTITY, 53.0, {"identity": RAW_IDENTITY}))
        add_before_closing_snapshot(before, [
            dns_sample(1, "reply_timeout", start=54.0, epoch=2),
            dns_sample(2, "reply_timeout", start=55.0, epoch=2),
        ])
        before.evidence[-1].epoch_id = 2
        self.assert_inconclusive(before, comparison_report(("success", "success")))

    def test_unknown_unsent_tool_failure_or_too_few_valid_dns_samples_are_not_failure_baselines(self):
        for kind in ("execution_error", "not_attempted", "unsupported", "non_comparable"):
            with self.subTest(kind=kind):
                before = comparison_report()
                first = next(sample for sample in before.evidence if sample.protocol == "dns")
                if kind == "non_comparable":
                    first.comparable = False
                else:
                    first.outcome = ProbeOutcome(kind)
                self.assert_inconclusive(before, comparison_report(("success", "success")))

    def test_dns_success_requires_addresses_of_its_declared_family(self):
        for addresses in ([], ["2606:4700:4700::1111"], ["not-an-address"]):
            with self.subTest(addresses=addresses):
                after = comparison_report(("success", "success"))
                for sample in after.evidence:
                    if sample.protocol == "dns":
                        sample.data["addresses"] = list(addresses)
                self.assert_inconclusive(comparison_report(), after)

    def test_configured_dns_targets_and_extended_families_must_be_observed(self):
        before, after = comparison_report(), comparison_report(("success", "success"))
        request = comparison_request(dns_hostnames=(DNS_TARGET, "missing.example"))
        self.assert_inconclusive(before, after, request)
        for report in (before, after):
            report.evidence = [sample for sample in report.evidence if sample.protocol != "dns6"]
        self.assert_inconclusive(before, after)

    def test_transport_comparison_requires_same_actual_peer_and_matching_role(self):
        request = comparison_request(tcp_targets=("edge.example:443",))
        before, after = comparison_report(), comparison_report(("success", "success"))
        add_transport(before)
        add_transport(after)
        self.assertEqual(self.compare(before, after, request)["status"], "observed_dns_improvement")
        changed_peer = copy.deepcopy(after)
        for sample in changed_peer.evidence:
            if sample.protocol == "tcp":
                sample.data["resolved_ip"] = "8.8.8.8"
        self.assert_inconclusive(before, changed_peer, request)
        changed_role = copy.deepcopy(after)
        for sample in changed_role.evidence:
            if sample.protocol == "tcp":
                sample.data["role"] = "target"
        self.assert_inconclusive(before, changed_role, request)

    def test_configured_transport_missing_from_both_reports_does_not_hide_required_coverage(self):
        request = comparison_request(tcp_targets=("edge.example:443",))
        self.assert_inconclusive(comparison_report(), comparison_report(("success", "success")), request)

    def test_dns_derived_icmp_after_success_is_supplementary_not_new_fault(self):
        before, after = comparison_report(), comparison_report(("success", "success"))
        add_before_closing_snapshot(after, [
            ProbeEvidence(
                sequence=1, timestamp="2026-10-26T10:00:54+00:00",
                started_seconds=54.0, finished_seconds=54.1, epoch_id=1,
                protocol="icmp", family="IPv4", target="1.1.1.1",
                outcome=ProbeOutcome.REPLY_TIMEOUT, packets_sent=1, packets_received=0,
                comparable=True, data={"role": "target", "target_host": DNS_TARGET,
                                      "context_status": "IDENTIFIED"},
            ),
        ])
        result = self.compare(before, after)
        self.assertEqual(result["status"], "observed_dns_improvement")
        self.assertFalse(any(item["protocol"] == "icmp" for item in result["comparisons"]))

    def test_only_fresh_final_window_observations_support_comparison(self):
        before = comparison_report()
        for sample in before.evidence:
            if sample.protocol == "dns":
                sample.started_seconds -= 40.0
                sample.finished_seconds -= 40.0
        self.assert_inconclusive(before, comparison_report(("success", "success")))

    def test_comparison_has_no_network_process_or_file_effects(self):
        before, after = comparison_report(), comparison_report(("success", "success"))
        with patch("builtins.open", side_effect=AssertionError("comparison must not access files")), \
             patch.object(socket, "socket", side_effect=AssertionError("comparison must not use network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("comparison must not resolve")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("comparison must not launch repair")):
            result = self.compare(before, after)
        self.assertEqual(result["status"], "observed_dns_improvement")


if __name__ == "__main__":
    unittest.main()
