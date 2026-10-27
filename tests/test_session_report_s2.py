"""Deterministic offline S2 report tests; no active diagnostics or dependencies."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from losshound.core.session_report import redact_report


def fixture():
    return {
        "schema_version": 2, "status": "completed",
        "budget_seconds": 60, "duration_seconds": 2.0,
        "epochs": [{
            "epoch_id": 1, "identity": "private-network-hash",
            "started_seconds": 0.0,
            "context": {
                "context_status": "KNOWN",
                "gateway": "192.168.4.1",
                "addresses": [{"IPAddress": "192.168.4.12", "AddressFamily": 2}],
                "routes": [{"DestinationPrefix": "192.168.4.0/24",
                            "NextHop": "192.168.4.1", "RouteMetric": 20}],
                "dns": [{"ServerAddresses": ["192.168.4.1"]}],
                "adapters": [{"Name": "Alice private WLAN", "MacAddress": "01:23:45:67:89:ab",
                              "InterfaceGuid": "{private-interface-guid}"}],
                "wifi": {"ssid": "Family private SSID", "bssid": "01:23:45:67:89:ab",
                         "profile": "Family-private-profile"},
            },
        }],
        "evidence": [{
            "sequence": 1, "timestamp": "2026-10-26T12:00:00+00:00",
            "started_seconds": 0.0, "finished_seconds": 0.1, "epoch_id": 1,
            "protocol": "icmp", "family": "IPv4", "target": "192.168.4.1",
            "outcome": "success", "packets_sent": 1, "packets_received": 1,
            "rtt_ms": 2.0, "error": None, "comparable": True,
            "data": {"context_status": "IDENTIFIED", "stdout": "private raw output",
                     "stdout_raw_base64": "cHJpdmF0ZSByYXcgb3V0cHV0"},
        }],
        "incomplete": [], "cleanup_errors": [], "output_errors": [],
        "context_observations": [], "context_blind_spots": [],
        "summary": "An observed gateway is 192.168.4.1.",
        "analysis": {"intermittent": [{"target": "192.168.4.1"}],
                     "findings": [{"scope": "local", "category": "lan_issue", "evidence_sequences": [1],
                                   "explanation": "Family private SSID through 192.168.4.1."}]},
    }


class RedactionTests(unittest.TestCase):
    def test_copy_hides_context_and_raw_text_preserving_associations(self):
        original = fixture()
        before = deepcopy(original)
        result = redact_report(original)
        self.assertEqual(original, before)
        text = json.dumps(result)
        for secret in ("192.168.4.1", "192.168.4.12", "192.168.4.0/24",
                       "Alice private WLAN", "Family private SSID",
                       "Family-private-profile", "01:23:45:67:89:ab",
                       "{private-interface-guid}", "private-network-hash",
                       "private raw output", "cHJpdmF0ZSByYXcgb3V0cHV0"):
            self.assertNotIn(secret, text)
        gateway = result["epochs"][0]["context"]["gateway"]
        self.assertEqual(gateway, result["evidence"][0]["target"])
        self.assertEqual(gateway, result["analysis"]["intermittent"][0]["target"])
        self.assertEqual(gateway, result["epochs"][0]["context"]["dns"][0]["ServerAddresses"][0])
        self.assertEqual(result["evidence"][0]["packets_sent"], 1)
        self.assertEqual(result["evidence"][0]["outcome"], "success")
        self.assertEqual(result["epochs"][0]["context"]["context_status"], "KNOWN")
        self.assertEqual(result["analysis"]["findings"][0]["category"], "lan_issue")
        self.assertTrue(result["redaction"]["applied"])
        self.assertFalse(result["redaction"]["reversible"])

    def test_url_path_query_fragment_and_credentials_are_not_retained(self):
        report = fixture()
        url = "https://private-user:private-password@secret.example:8443/private-path?token=private-token#private-fragment"
        report["evidence"][0]["target"] = url
        report["analysis"]["intermittent"] = [{"target": "secret.example"}, {"target": url}]
        report["summary"] = "Website " + url
        result = redact_report(report)
        serialized = json.dumps(result)
        for secret in ("private-user", "private-password", "secret.example",
                       "private-path", "private-token", "private-fragment"):
            self.assertNotIn(secret, serialized)
        host = result["analysis"]["intermittent"][0]["target"]
        self.assertEqual(result["evidence"][0]["target"], f"https://{host}:8443")
        self.assertEqual(result["evidence"][0]["target"],
                         result["analysis"]["intermittent"][1]["target"])

    def test_errors_and_arbitrary_raw_context_details_are_removed(self):
        report = fixture()
        report["evidence"][0]["error"] = {"custom": "private arbitrary exception"}
        report["evidence"][0]["data"].update({
            "stderr": "private stderr", "error_data": {"opaque": "private error object"},
            "headers": {"Authorization": "Bearer private-token"},
            "exception_message": "C:\\Users\\private-user",
        })
        report["incomplete"] = ["private incomplete message"]
        report["cleanup_errors"] = ["private cleanup path"]
        report["epochs"][0]["context"]["unknown_extension"] = "private unexpected context"
        result = redact_report(report)
        serialized = json.dumps(result)
        for secret in ("private arbitrary exception", "private stderr", "private error object",
                       "private-token", "private-user", "private incomplete message",
                       "private cleanup path", "private unexpected context"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(len(result["incomplete"]), 1)
        self.assertNotIn("headers", result["evidence"][0]["data"])

    def test_ipv6_mac_and_single_label_targets_use_consistent_aliases(self):
        report = fixture()
        report["epochs"][0]["context"]["gateway"] = "fe80::1%12"
        report["evidence"][0]["target"] = "fe80::1%12"
        report["analysis"]["intermittent"] = [{"target": "https://printer/private"},
                                            {"target": "printer"}]
        report["summary"] = "Route fe80::1%12 and 01:23:45:67:89:ab."
        result = redact_report(report)
        self.assertEqual(result["epochs"][0]["context"]["gateway"], result["evidence"][0]["target"])
        self.assertNotIn("fe80::1", json.dumps(result))
        self.assertEqual(result["analysis"]["intermittent"][0]["target"],
                         "https://" + result["analysis"]["intermittent"][1]["target"])

    def test_alias_mapping_is_local_and_not_exported(self):
        one, two = fixture(), fixture()
        two["evidence"][0]["target"] = "198.51.100.99"
        result = redact_report(two)
        self.assertNotIn("198.51.100.99", json.dumps(result))
        self.assertNotIn("mapping", result["redaction"])
        self.assertEqual(redact_report(one), redact_report(one))



    def test_short_hostname_is_aliased_in_target_host_and_free_text(self):
        report = fixture()
        report["evidence"][0]["target"] = "db"
        report["evidence"][0]["data"]["target_host"] = "db"
        report["analysis"]["intermittent"] = [{"target": "https://db/private"}]
        report["summary"] = "Target db failed; the database remains unknown."
        result = redact_report(report)
        host = result["evidence"][0]["target"]
        self.assertEqual(host, result["evidence"][0]["data"]["target_host"])
        self.assertEqual("https://" + host, result["analysis"]["intermittent"][0]["target"])
        self.assertNotIn("Target db", result["summary"])
        self.assertIn("database", result["summary"])

    def test_short_ssid_hex_is_removed_inside_and_outside_context(self):
        report = fixture()
        report["epochs"][0]["context"]["wifi"]["ssid_hex"] = "41"
        report["evidence"][0]["data"]["ssid_hex"] = "41"
        report["summary"] = "SSID bytes 41."
        result = redact_report(report)
        value = result["epochs"][0]["context"]["wifi"]["ssid_hex"]
        self.assertNotEqual(value, "41")
        self.assertEqual(value, result["evidence"][0]["data"]["ssid_hex"])
        self.assertNotIn("bytes 41", result["summary"])


if __name__ == "__main__":
    unittest.main()
