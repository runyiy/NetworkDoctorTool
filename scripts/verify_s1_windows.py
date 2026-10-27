"""Explicit, non-admin Windows S1 verification; standard library only.

Runs only read-only probes and controlled owned-process lifecycle fixtures.
Timer boundaries and expected fixture errors are recorded with raw results.
No Qt, package installation, connection switching or repair functions are used.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from losshound.core.session import SessionController, SessionRequest
from losshound.core.session_process import WindowsProbeProvider
from losshound.core.session_context import WindowsContextObserver


TIMER_DEFINITIONS = {
    "session_total_seconds": (
        "time.monotonic immediately before SessionController.run until immediately "
        "after its return; includes worker startup, collection/waits, owned-process "
        "cleanup, controller report preparation and progress callbacks; excludes "
        "the verifier's later JSON serialization, process scans and stdout printing"
    ),
    "session_plus_verifier_serialization_seconds": (
        "same start, through an explicit report.to_json and json.loads after return; "
        "includes cleanup and both controller preparation and verifier serialization"
    ),
    "cancellation_request_to_return_seconds": (
        "time.monotonic immediately before cancel_event.set until controller/provider "
        "cleanup returns; separate from session total and timer-thread join"
    ),
    "provider_total_seconds": (
        "time.monotonic immediately before owned-worker launch until _run and explicit "
        "provider.close return; excludes the verifier's later process scan and printing"
    ),
    "legacy_elapsed_seconds": (
        "The former finite_native_session.elapsed_seconds started before controller.run "
        "and ended after report.to_json plus json.loads: it included cleanup and report "
        "preparation/serialization. The former cancelled-session elapsed_seconds used "
        "session start, not cancellation request, and also included timer-thread join."
    ),
}


def process_alive(pid):
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.OpenProcess(0x00100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return False
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        result = api.WaitForSingleObject(handle, 0)
        if result == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        return result == 258
    finally:
        api.CloseHandle(handle)


def lifecycle_fixture(cancel):
    # These children never perform ICMP/DNS. A deliberate stall tests ownership.
    marker = Path(tempfile.gettempdir()) / ("losshound-s1-pids-" + uuid.uuid4().hex + ".json")
    child_code = (
        "import sys,subprocess,time,json;from pathlib import Path;"
        "sys.stdin.read();"
        "p=subprocess.Popen([sys.executable,'-I','-S','-B','-c','import time;time.sleep(30)']);"
        "Path(" + repr(str(marker)) + ").write_text(json.dumps([p.pid]),encoding='ascii');"
        "time.sleep(30)"
    )
    class FixtureProvider(WindowsProbeProvider):
        @staticmethod
        def _command():
            return [sys.executable, "-I", "-S", "-B", "-c", child_code]
    provider = FixtureProvider()
    event = threading.Event()
    started = time.monotonic()
    provider.set_cleanup_deadline(started + 8.0)
    monitor_stop = threading.Event()
    cancellation_requested = []
    def request_cancel():
        until = started + 3.0
        while time.monotonic() < until and not marker.is_file() and not monitor_stop.is_set():
            monitor_stop.wait(0.02)
        if not monitor_stop.is_set():
            cancellation_requested.append(time.monotonic())
            event.set()
    timer = threading.Thread(target=request_cancel) if cancel else None
    try:
        if timer:
            timer.start()
        result = provider._run("icmp", "127.0.0.1", started + 6.0, event,
                               timeout=5.0 if cancel else 2.0)
        errors = provider.close(min(started + 8.0, time.monotonic() + 2.0))
        returned = time.monotonic()
        descendants = json.loads(marker.read_text(encoding="ascii")) if marker.is_file() else []
        all_pids = provider.started_pids + descendants
        remaining = [pid for pid in all_pids if process_alive(pid)]
        expected = "cancelled" if cancel else "execution_error"
        assertions = {
            "expected_tool_outcome": result["outcome"] == expected,
            "descendant_was_observed": bool(descendants),
            "owned_tree_cleanup_confirmed": not remaining and not errors and not provider.active_pids,
            "no_packet_count_invented": result["packets_sent"] is None,
            "provider_time_bound_met": returned - started <= (5.0 if cancel else 4.0),
        }
        if cancel:
            assertions["cancellation_latency_bound_met"] = (
                bool(cancellation_requested) and returned - cancellation_requested[0] <= 2.5
            )
        return {
            "check": "owned_tree_cancel" if cancel else "owned_tree_execution_watchdog",
            "passed": all(assertions.values()),
            "evaluation_scope": "controlled process-tree lifecycle, not network reachability",
            "expected_outcome": expected,
            "interpretation": (
                "The fixture deliberately stalls without sending any network probe. "
                "Its execution_error is the expected watchdog/tool result, never packet loss."
                if not cancel else
                "The fixture deliberately stalls without sending any network probe; cancellation must reap its tree."
            ),
            "provider_total_seconds": returned - started,
            "cancellation_request_to_return_seconds": (
                returned - cancellation_requested[0] if cancellation_requested else None
            ),
            "assertions": assertions,
            "started_pids": provider.started_pids,
            "descendant_pids": descendants,
            "remaining_pids": remaining,
            "cleanup_errors": errors,
            "raw_result": result,
        }
    finally:
        if timer:
            monitor_stop.set()
            timer.join(timeout=1.0)
        if provider.active_pids:
            provider.close(min(started + 8.0, time.monotonic() + 2.0))
        marker.unlink(missing_ok=True)


def observer_fixture():
    observer = WindowsContextObserver()
    event = threading.Event()
    started = time.monotonic()
    observed_states = []
    try:
        observer.start(started + 3.0, event)
        while True:
            state = observer.snapshot()
            if not observed_states or state != observed_states[-1]:
                observed_states.append(state)
            if state.get("status") == "READY" or state.get("errors") or time.monotonic() >= started + 1.0:
                break
            time.sleep(0.02)
    finally:
        errors = observer.close(min(started + 3.0, time.monotonic() + 2.0))
    returned = time.monotonic()
    remaining = [pid for pid in observer.started_pids if process_alive(pid)]
    lifecycle_passed = (bool(observer.started_pids) and not remaining
                        and not observer.active_pids and not errors)
    return {
        "check": "native_context_observer_readiness_and_cleanup",
        "passed": lifecycle_passed and state.get("status") == "READY",
        "lifecycle_passed": lifecycle_passed,
        "evaluation_scope": "native notification registration and owned-child cleanup; no connection switches",
        "provider_total_seconds": returned - started,
        "started_pids": observer.started_pids,
        "remaining_pids": remaining,
        "cleanup_errors": errors,
        "raw_observer_states": observed_states,
        "notification_status": state.get("status", "UNKNOWN"),
    }


def classify_context(result):
    """Describe the observed snapshot without inferring EXT/VPN identity."""
    context = result.get("data") if isinstance(result.get("data"), dict) else {}
    confirmed = result.get("outcome") == "success" and bool(context.get("identity"))
    wifi = context.get("wifi") if isinstance(context.get("wifi"), list) else []
    connected_wifi = [item for item in wifi if isinstance(item, dict) and item.get("state") == 1]
    adapters = context.get("adapters") if isinstance(context.get("adapters"), list) else []
    active_adapters = [
        item for item in adapters if isinstance(item, dict) and item.get("Status") in {"Up", 1}
    ]
    return {
        "observation_only": True,
        "identity_confirmed": confirmed,
        "identity": context.get("identity") if confirmed else None,
        "classification": (
            "unavailable_in_current_process" if not confirmed else
            "connected_wifi_snapshot" if connected_wifi else
            "adapter_snapshot_without_confirmed_connected_wifi"
        ),
        "default_ipv4_gateway": context.get("gateway") if confirmed else None,
        "connected_wifi": connected_wifi,
        "active_adapters": active_adapters,
        "vpn_presence": "not_determined_from_snapshot",
        "ext_repeater_presence": "not_determined_from_snapshot",
        "network_switching_performed": False,
        "physical_wifi_ext_vpn_transition_acceptance": "NOT_RUN",
        "limitation": (
            "A current snapshot does not establish physical connection changes or "
            "general network health. Matching before/after snapshots can miss A-to-B-to-A changes."
        ),
    }


def run(session_duration=None, execution_context="native-windows-unverified"):
    if sys.platform != "win32":
        raise RuntimeError("Requires native Windows; WSL is not an acceptance substitute")
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Run this verification without Administrator privileges")
    results = []
    provider = WindowsProbeProvider()
    started = time.monotonic()
    provider.set_cleanup_deadline(started + 20.0)
    event = threading.Event()
    for name, protocol, target in (
        ("native_icmp_loopback", "icmp", "127.0.0.1"),
        ("native_dns_localhost", "dns", "localhost"),
        ("native_dns_external_example_com", "dns", "example.com"),
    ):
        before = time.monotonic()
        result = provider.probe(protocol, target, min(started + 18.0, before + 3.0), event)
        returned = time.monotonic()
        results.append({
            "check": name,
            "protocol": protocol,
            "target": target,
            "passed": result["outcome"] == "success",
            "evaluation_scope": "this single read-only target in the current process environment",
            "health_inference": "none",
            "probe_total_seconds": returned - before,
            "raw_result": result,
        })
    result = provider.read_network(min(started + 18.0, time.monotonic() + 5.0), event)
    context_classification = classify_context(result)
    results.append({
        "check": "windows_network_context",
        "passed": result["outcome"] == "success" and context_classification["identity_confirmed"],
        "classification": context_classification,
        "raw_result": result,
    })
    errors = provider.close(min(started + 20.0, time.monotonic() + 2.0))
    remaining = [pid for pid in provider.started_pids if process_alive(pid)]
    results.append({
        "check": "native_probe_cleanup",
        "passed": not errors and not remaining,
        "started_pids": provider.started_pids,
        "remaining_pids": remaining,
        "cleanup_errors": errors,
    })
    results.append(observer_fixture())
    results.extend((lifecycle_fixture(True), lifecycle_fixture(False)))
    cancel_provider = WindowsProbeProvider()
    cancel_observer = WindowsContextObserver()
    cancel_event = threading.Event()
    cancellation_requested = []
    def request_cancel():
        requested = time.monotonic()
        cancel_event.requested_monotonic = requested
        cancellation_requested.append(requested)
        cancel_event.set()
    cancel_timer = threading.Timer(0.75, request_cancel)
    before = time.monotonic()
    cancel_timer.start()
    try:
        cancelled = SessionController(SessionRequest(300, ("127.0.0.1",), ("localhost",)),
                                      provider=cancel_provider, context_observer=cancel_observer).run(cancel_event=cancel_event)
        returned = time.monotonic()
    finally:
        cancel_timer.cancel()
        cancel_timer.join(timeout=1.0)
    cancellation_latency = returned - cancellation_requested[0] if cancellation_requested else None
    cancel_pids = cancel_provider.started_pids + cancel_observer.started_pids
    remaining = [pid for pid in cancel_pids if process_alive(pid)]
    results.append({
        "check": "early_cancel_session_with_300_second_budget",
        "budget_seconds": 300,
        "passed": (cancelled.status == "cancelled" and returned - before <= 3.0
                   and cancellation_latency is not None and cancellation_latency <= 2.25
                   and not remaining and not cancelled.cleanup_errors),
        "evaluation_scope": "early cancellation and cleanup; does not test natural 300-second completion",
        "session_total_seconds": returned - before,
        "cancellation_requested_after_session_start_seconds": (
            cancellation_requested[0] - before if cancellation_requested else None
        ),
        "cancellation_request_to_return_seconds": cancellation_latency,
        "status": cancelled.status,
        "started_pids": cancel_pids,
        "probe_started_pids": cancel_provider.started_pids,
        "observer_started_pids": cancel_observer.started_pids,
        "observer_active_pids_after_return": cancel_observer.active_pids,
        "observer_last_state": dict(cancel_observer.last_state),
        "remaining_pids": remaining,
        "raw_report": cancelled.to_dict(),
    })
    natural_300_observed = False
    if session_duration is not None:
        session_provider = WindowsProbeProvider()
        session_observer = WindowsContextObserver()
        before = time.monotonic()
        report = SessionController(SessionRequest(session_duration, ("127.0.0.1",), ("localhost",)),
                                   provider=session_provider, context_observer=session_observer).run()
        returned = time.monotonic()
        serialized = json.loads(report.to_json())
        serialized_at = time.monotonic()
        session_pids = session_provider.started_pids + session_observer.started_pids
        remaining = [pid for pid in session_pids if process_alive(pid)]
        finite_passed = (returned - before <= session_duration and not remaining
                         and not report.cleanup_errors and report.status == "deadline")
        natural_300_observed = session_duration == 300 and finite_passed
        results.append({
            "check": "finite_native_session",
            "budget_seconds": session_duration,
            "passed": finite_passed,
            "evaluation_scope": "finite lifecycle, cleanup and reporting; does not assert network probe success",
            "session_total_seconds": returned - before,
            "session_plus_verifier_serialization_seconds": serialized_at - before,
            "reported_total_seconds": serialized["duration_seconds"],
            "status": report.status,
            "started_pids": session_pids,
            "probe_started_pids": session_provider.started_pids,
            "observer_started_pids": session_observer.started_pids,
            "observer_active_pids_after_return": session_observer.active_pids,
            "observer_last_state": dict(session_observer.last_state),
            "remaining_pids": remaining,
            "raw_report": serialized,
        })
    return {
        "schema_version": 2,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "python_flags": {
            "isolated": bool(sys.flags.isolated),
            "no_site": bool(sys.flags.no_site),
            "dont_write_bytecode": bool(sys.dont_write_bytecode),
        },
        "administrator": False,
        "third_party_imports": False,
        "network_configuration_writes": False,
        "network_connection_switches": False,
        "execution_context": execution_context,
        "normal_non_sandbox_native_windows_acceptance": {
            "status": "BLOCKED" if execution_context == "managed-sandbox" else "NOT_ESTABLISHED",
            "reason": (
                "Only the managed Windows execution context was available; an independent "
                "normal/non-sandbox native Windows environment was not available."
                if execution_context == "managed-sandbox" else
                "This run does not independently verify that its environment is outside a sandbox."
            ),
        },
        "timer_definitions": TIMER_DEFINITIONS,
        "current_environment_identity": context_classification,
        "natural_300_second_deadline": {
            "status": "OBSERVED" if natural_300_observed else "NOT_RUN",
            "early_cancellation_is_substitute": False,
        },
        "gui_acceptance": "NOT_RUN",
        "physical_network_switch_acceptance": "NOT_RUN",
        "results": results,
        "passed": all(item["passed"] for item in results),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-duration", type=int, default=None)
    parser.add_argument("--execution-context", choices=("native-windows-unverified", "managed-sandbox"),
                        default="native-windows-unverified")
    args = parser.parse_args()
    if args.session_duration is not None:
        SessionRequest(args.session_duration)
    result = run(args.session_duration, args.execution_context)
    print(json.dumps(result, indent=2, allow_nan=False), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
