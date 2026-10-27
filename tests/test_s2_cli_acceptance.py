"""Native Windows CLI acceptance against owned loopback peers; no Qt/packages."""
from __future__ import annotations

import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "build" / "s2-evidence" / "non-gui-acceptance-20261026"
MARKER = "s2-owned-private-marker-735b"
PRODUCT_FILES = ("src/losshound/app.py", "src/losshound/cli/runner.py",
                 "src/losshound/core/session.py", "src/losshound/core/session_process.py",
                 "src/losshound/core/session_protocols.py", "src/losshound/core/session_diagnosis.py",
                 "src/losshound/core/session_report.py", "src/losshound/core/session_output.py")


def hashes():
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in PRODUCT_FILES}


class OwnedHTTP(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.requests.append({"monotonic": time.monotonic(), "method": "GET"})
        self.server.request_seen.set()
        if self.server.stall:
            self.server.stop_event.wait(4)
        body = b"owned-cli-peer"
        try:
            self.send_response(self.server.response_status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Synthetic-Private", MARKER)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def summarise(report):
    evidence = report.get("evidence", [])
    groups = {}
    for item in evidence:
        actual_ip = item.get("data", {}).get("resolved_ip")
        if actual_ip is None and item.get("protocol") == "icmp":
            actual_ip = item.get("target")
        key = (item.get("protocol"), item.get("family"), item.get("target"), item.get("epoch_id"), actual_ip)
        value = groups.setdefault(key, {"count": 0, "comparable": 0, "outcomes": {}, "durations": [], "starts": [], "comparable_starts": []})
        value["count"] += 1
        value["comparable"] += int(item.get("comparable") is True)
        outcome = item.get("outcome")
        value["outcomes"][outcome] = value["outcomes"].get(outcome, 0) + 1
        value["durations"].append(item.get("finished_seconds", 0) - item.get("started_seconds", 0))
        value["starts"].append(item.get("started_seconds"))
        if item.get("comparable") is True:
            value["comparable_starts"].append(item.get("started_seconds"))
    context_times = [item["elapsed_seconds"] for item in report.get("context_observations", [])]
    return {"status": report.get("status"), "budget_seconds": report.get("budget_seconds"),
            "duration_seconds": report.get("duration_seconds"), "evidence_count": len(evidence),
            "context_observations": len(context_times), "context_observation_times": context_times,
            "protocol_groups": [{"protocol": key[0], "family": key[1], "target": key[2], "epoch_id": key[3], "actual_ip": key[4],
                                "comparable_window_start": min(value["comparable_starts"]) if value["comparable_starts"] else None,
                                "comparable_window_end": max(value["comparable_starts"]) if value["comparable_starts"] else None, **value} for key, value in groups.items()],
            "analysis": report.get("analysis"), "cleanup_errors": report.get("cleanup_errors"),
            "output_errors": report.get("output_errors"), "redaction": report.get("redaction")}



def service_response_checks(report):
    """Use the frozen per-epoch/family observation anchor, not report end."""
    evidence = report.get("evidence", [])
    service_findings = [finding for finding in report.get("analysis", {}).get("findings", [])
                        if finding.get("scope") == "target" and finding.get("confidence") == "medium"]
    supported = complete_details = False
    all_sequences = {item.get("sequence") for item in evidence}
    windows = []
    for finding in service_findings:
        epoch, family = finding.get("epoch_id"), finding.get("family")
        timed = [item for item in evidence if item.get("comparable") is True
                 and item.get("epoch_id") == epoch and item.get("family") == family]
        snapshots = [item for item in evidence if item.get("comparable") is True
                     and item.get("epoch_id") == epoch and item.get("protocol") == "network"
                     and item.get("outcome") == "success"]
        anchor = max((item.get("finished_seconds", 0) for item in timed + snapshots), default=0)
        cutoff = anchor - 30
        recent = [item for item in timed if item.get("started_seconds", -1) >= cutoff]
        sequences = set(finding.get("evidence_sequences", []))
        rows = [item for item in recent if item.get("sequence") in sequences
                and item.get("data", {}).get("role") == "target"]
        web = [item for item in rows if item.get("protocol") == "http"
               and item.get("data", {}).get("http_status") == 503]
        tcp = [item for item in rows if item.get("protocol") == "tcp" and item.get("outcome") == "success"]
        keys = {(item.get("epoch_id"), item.get("family"), item.get("data", {}).get("resolved_ip"))
                for item in web + tcp}
        match = (len(web) >= 2 and len(tcp) >= 2 and len(keys) == 1
                 and all(key[2] is not None for key in keys))
        supported |= match
        contradictions = finding.get("contradictions")
        complete_details |= (match and bool(finding.get("explanation"))
            and set(finding.get("supporting_evidence", [])) == sequences
            and sequences <= all_sequences and isinstance(contradictions, list)
            and set(contradictions) <= all_sequences and not set(contradictions) & sequences
            and bool(finding.get("alternatives")) and bool(finding.get("recommendations")))
        windows.append({"epoch_id": epoch, "family": family, "anchor_seconds": anchor,
                        "cutoff_seconds": cutoff, "support_sequences": sorted(sequences),
                        "tcp_success_count": len(tcp), "http503_count": len(web),
                        "same_actual_address": len(keys) == 1, "matched": match})
    return {"repeated_503_target_service_explanation": supported,
            "service_finding_support_counterevidence_alternatives_recommendations": complete_details,
            "service_response_not_wan_failure": not any(
                finding.get("scope") in ("wan", "wan_or_isp") or finding.get("category") == "isp_wan_issue"
                for finding in report.get("analysis", {}).get("findings", []))}, windows

@unittest.skipUnless(sys.platform == "win32" and sys.version_info >= (3, 12), "Native Windows Python 3.12+ required")
class NativeCLI(unittest.TestCase):
    def run_cli(self, label, *, cancel=False, response_status=200):
        from losshound.core.session_process import _OwnedJob
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        runtime = EVIDENCE / (label + "-runtime")
        runtime.mkdir(exist_ok=False)
        for name in ("appdata", "temp"):
            (runtime / name).mkdir()
        # An explicit valid config avoids the user's original config and DB.
        config = runtime / "controlled-config.json"
        config.write_text(json.dumps({"public_ping_targets": ["127.0.0.1"],
            "dns_test_hostnames": ["localhost"], "log_level": "WARNING",
            "alerts": {"enabled": False}, "lan_discovery_firewall_enabled": False}), encoding="utf-8")
        config_before = hashlib.sha256(config.read_bytes()).hexdigest()
        server = OwnedHTTP(("127.0.0.1", 0), Handler)
        server.requests, server.stall = [], cancel
        server.response_status = response_status
        server.request_seen, server.stop_event = threading.Event(), threading.Event()
        serving = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, name="owned-cli-http")
        serving.start()
        port = server.server_address[1]
        bootstrap = "import runpy,sys;sys.path.insert(0," + repr(str(ROOT / "src")) + ");"
        if cancel:
            bootstrap += "import signal,threading;t=threading.Timer(8,lambda:signal.raise_signal(signal.SIGINT));t.daemon=True;t.start();"
        bootstrap += "runpy.run_module('losshound',run_name='__main__')"
        argv = [sys.executable, "-I", "-S", "-B", "-c", bootstrap, "--cli", "--extended", "--config", str(config),
                "--ipv6-target", "::1", "--tcp-target", "127.0.0.1:" + str(port),
                "--website", "http://127.0.0.1:" + str(port) + "/" + MARKER + "?token=" + MARKER]
        env = dict(os.environ, LOCALAPPDATA=str(runtime / "appdata"), TEMP=str(runtime / "temp"), TMP=str(runtime / "temp"))
        before = hashes()
        process = job = None
        stdout = stderr = ""
        result = {"label": label, "argv": argv, "source_hashes_before": before,
                  "isolation": {"LOCALAPPDATA": "workspace-owned-runtime/appdata", "TEMP": "workspace-owned-runtime/temp"},
                  "includes_default_gateway_icmp": True, "public_targets_configured": False,
                  "cancellation": "controlled Python SIGINT at 8 seconds; not physical keyboard input" if cancel else "none",
                  "owned_http_response_status": response_status}
        started = time.monotonic()
        try:
            process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding="utf-8", errors="strict", creationflags=subprocess.CREATE_NO_WINDOW)
            job = _OwnedJob(process)
            stdout, stderr = process.communicate(timeout=64)
            result.update(exit_code=process.returncode, cli_wall_seconds=time.monotonic()-started)
            report = json.loads(stdout)
            result["report_summary"] = summarise(report)
            result["checks"] = {
                "complete_json": isinstance(report, dict), "default_budget_60": report.get("budget_seconds") == 60,
                "report_within_60": report.get("duration_seconds", 999) <= 60,
                "expected_exit": process.returncode == (130 if cancel else 0),
                "expected_stop": report.get("status") == ("cancelled" if cancel else "deadline"),
                "analysis_present": isinstance(report.get("analysis"), dict),
                "redaction_marked": bool(report.get("redaction")),
                "report_text_is_readable_utf8": chr(0xfffd) not in stdout and (not report.get("analysis", {}).get("findings") or any(ord(c)>127 for c in report["analysis"]["findings"][0].get("explanation", ""))),
                "synthetic_private_marker_absent_from_stdout_stderr": MARKER not in stdout and MARKER not in stderr,
                "raw_loopback_address_absent_from_output": "127.0.0.1" not in stdout and "127.0.0.1" not in stderr,
                "http_peer_was_reached_when_not_cancelled": cancel or bool(server.requests),
                "log_created_in_owned_appdata": (runtime / "appdata" / "Losshound" / "losshound.log").is_file(),
                "config_unchanged": hashlib.sha256(config.read_bytes()).hexdigest() == config_before,
                "no_database_created": not list(runtime.rglob("*.db")),
                "owned_process_tree_empty_before_fixture_cleanup": job.active_count() == 0,
                "source_unchanged": before == hashes(),
            }
            if cancel:
                requested = report.get("cancel_request_elapsed_seconds")
                pending = [item for item in report.get("evidence", [])
                           if item.get("data", {}).get("context_confirmation") == "round_not_confirmed"]
                result["checks"]["pending_round_not_comparable"] = bool(pending) and all(
                    item.get("comparable") is False and item.get("epoch_id") is None for item in pending)
                result["checks"]["no_evidence_started_after_cancel"] = isinstance(requested, (int, float)) and all(
                    item.get("started_seconds", 0) <= requested for item in report.get("evidence", []))
                result["cancellation_observations"] = {
                    "request_elapsed_seconds": requested,
                    "cancel_to_return_seconds": report.get("cancel_to_return_seconds"),
                    "pending_unconfirmed_evidence_count": len(pending),
                    "context_completion_times": [item.get("elapsed_seconds") for item in report.get("context_observations", [])],
                    "query_start_trace_available": False,
                    "limit": "Context timestamps record completion, not individual provider query start; source stop checks and returned evidence constrain this conclusion."}
            if response_status == 503:
                result["checks"].update(service_response_checks(report)[0])
        except Exception as exc:
            result["failure"] = {"type": type(exc).__name__, "message": str(exc)}
            if process is not None:
                result["exit_code"] = process.poll()
            raise
        finally:
            if process is not None and process.poll() is None:
                if job is not None:
                    job.terminate()
                else:
                    process.kill()
                remaining_out, remaining_err = process.communicate(timeout=3)
                stdout = stdout or remaining_out
                stderr = stderr or remaining_err
            if job is not None:
                result["remaining_job_processes_after_cleanup"] = job.active_count()
                job.close()
            server.stop_event.set()
            server.shutdown()
            server.server_close()
            serving.join(timeout=2)
            result["http_server_closed"] = not serving.is_alive()
            result["http_requests"] = list(server.requests)
            result["source_hashes_after"] = hashes()
            result["runtime_files"] = [str(path.relative_to(runtime)) for path in runtime.rglob("*") if path.is_file()]
            result["wall_seconds"] = time.monotonic() - started
            (EVIDENCE / (label + ".stdout.json")).write_text(stdout, encoding="utf-8")
            (EVIDENCE / (label + ".stderr.log")).write_text(stderr, encoding="utf-8")
            (EVIDENCE / (label + ".json")).write_text(json.dumps(result, indent=2), encoding="utf-8")
        self.assertTrue(all(result["checks"].values()), result["checks"])
        self.assertEqual(result["remaining_job_processes_after_cleanup"], 0)
        self.assertTrue(result["http_server_closed"])
        return result

    def test_actual_entry_default_60(self):
        result = self.run_cli(getattr(self, "default_label", "cli-default60-r1"))
        print(json.dumps({"label": result["label"], "exit_code": result["exit_code"], "wall_seconds": result["wall_seconds"],
                          "evidence_count": result["report_summary"]["evidence_count"], "checks": result["checks"]}), flush=True)

    def test_actual_entry_controlled_sigint(self):
        result = self.run_cli(getattr(self, "cancel_label", "cli-sigint-r1"), cancel=True)
        print(json.dumps({"label": result["label"], "exit_code": result["exit_code"],
                          "cli_wall_seconds": result["cli_wall_seconds"], "checks": result["checks"]}), flush=True)

    def test_actual_entry_http503(self):
        result = self.run_cli("cli-http503-r1", response_status=503)
        print(json.dumps({"label": result["label"], "exit_code": result["exit_code"],
                          "cli_wall_seconds": result["cli_wall_seconds"],
                          "evidence_count": result["report_summary"]["evidence_count"],
                          "checks": result["checks"]}), flush=True)
