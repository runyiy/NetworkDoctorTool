"""S3 repair coordination; simulation by default and no startup wiring.

Diagnosis, explicit operation confirmation and independent verification are
separate. The narrow Windows adapter requires an explicitly supplied runner;
implementation/test approval never constitutes authority to run a real repair.
No cache backup or rollback is claimed. Records are in-memory JSON, not history.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, replace
import hashlib
import ipaddress
import json
import math
import threading
import time
from uuid import uuid4

from losshound.core.session import SessionController, SessionReport, SessionRequest, _extended_tasks
from losshound.core.session_diagnosis import COMPARISON_WINDOW_SECONDS, MAX_EVIDENCE, MAX_EPOCHS, REPEAT_SAMPLES

DNS_CACHE_FLUSH = "flush_windows_dns_cache"
IMPACT = ("Would clear only the Windows local DNS resolver cache. Subsequent name "
          "lookups may make new queries and briefly take longer. This simulation changes nothing.")
NO_RESTORE_WARNING = "The original DNS cache contents cannot be restored exactly. No rollback is provided."
PERMISSIONS = "Simulation requires no elevation or system change. Real repair requires separate authorization."
LIMITATIONS = [
    "A comparison does not establish that a DNS cache operation changed the system.",
    "Matching snapshots do not prove uninterrupted network continuity between sessions.",
    "Changed observations do not establish repair causality or permanent recovery.",
    "System resolver results may come from hosts or caches, not a specific DNS server.",
]


def _copy(value):
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _unknown(reason):
    return {"status": "inconclusive", "comparable": False, "reasons": [reason],
            "comparisons": [], "causal_attribution": "not_established",
            "network_problem_resolved": None, "limitations": list(LIMITATIONS)}


@dataclass(frozen=True)
class RepairRequest:
    action: str = DNS_CACHE_FLUSH
    verification_seconds: int = 60

    def __post_init__(self):
        if type(self.action) is not str or self.action != DNS_CACHE_FLUSH:
            raise ValueError("Only Windows local DNS cache clearing is permitted")
        if type(self.verification_seconds) is not int or not 1 <= self.verification_seconds <= 300:
            raise ValueError("Verification budget must be an integer from 1 to 300 seconds")


class SimulatedRepairExecutor:
    """Fixed data outcomes only: deliberately no command/callback/backend field."""

    __slots__ = ("_outcome", "_calls")

    def __init__(self, outcome: str = "success"):
        if type(outcome) is not str or outcome not in {"success", "failure", "tool_error"}:
            raise ValueError("Unknown simulated outcome")
        self._outcome = outcome
        self._calls = 0

    @property
    def outcome(self):
        return self._outcome

    @property
    def calls(self):
        return self._calls

    def execute(self, request: RepairRequest) -> dict:
        if type(request) is not RepairRequest or request.action != DNS_CACHE_FLUSH:
            raise ValueError("Repair action is not whitelisted")
        if type(self._calls) is not int or self._calls < 0:
            raise ValueError("Invalid simulation counter")
        self._calls += 1
        if type(self.outcome) is not str or self.outcome not in {"success", "failure", "tool_error"}:
            raise ValueError("Unknown simulated outcome")
        return {"status": "simulated_" + self.outcome, "simulation_only": True,
                "system_change_performed": False,
                "detail": "Data-only simulated result; no system command was run."}


def _number(value):
    return type(value) in {int, float} and math.isfinite(value) and value >= 0


def _peer(row):
    data = row.get("data") or {}
    if row["protocol"] in {"dns", "dns6"}:
        return None
    value = data.get("resolved_ip") or (row["target"] if row["protocol"] == "icmp" else "")
    try:
        address = ipaddress.ip_address(value)
        if "IPv" + str(address.version) != row["family"]:
            return None
        return str(address)
    except (ValueError, TypeError):
        return None


def _sample_state(row):
    outcome, proto, data = row.get("outcome"), row["protocol"], row.get("data") or {}
    if outcome not in {"success", "reply_timeout", "unreachable"}:
        return "unknown"
    if proto == "icmp":
        sent, received = row.get("packets_sent"), row.get("packets_received")
        if type(sent) is not int or type(received) is not int or not 0 <= received <= sent or sent <= 0:
            return "unknown"
        if outcome == "success" and received == sent:
            return "success"
        if outcome != "success" and received == 0:
            return "failure"
        return "mixed"
    if proto in {"dns", "dns6"} and outcome == "success":
        addresses = data.get("addresses")
        if not isinstance(addresses, list) or not addresses:
            return "unknown"
        try:
            if any("IPv" + str(ipaddress.ip_address(value).version) != row["family"] for value in addresses):
                return "unknown"
        except (ValueError, TypeError):
            return "unknown"
    if outcome == "success":
        code = data.get("http_status")
        if proto.startswith(("http", "https")):
            if type(code) is not int or not 100 <= code <= 599:
                return "unknown"
            if proto.startswith("https") and data.get("tls_verified") is not True:
                return "unknown"
            if code >= 400:
                return "service_error"
        return "success"
    return "failure"


def _groups(report):
    evidence, epochs = report.get("evidence", []), report.get("epochs", [])
    if len(evidence) > MAX_EVIDENCE or len(epochs) > MAX_EPOCHS:
        return None, None, "evidence_limit_exceeded"
    ids = [row.get("sequence") for row in evidence]
    if any(type(seq) is not int or seq <= 0 for seq in ids) or len(set(ids)) != len(ids):
        return None, None, "invalid_or_duplicate_evidence_sequence"
    active = {row.get("epoch_id") for row in evidence if row.get("comparable") is True}
    if len(active) != 1 or None in active:
        return None, None, "no_single_confirmed_epoch"
    matching = [epoch for epoch in epochs if epoch.get("epoch_id") in active]
    if len(matching) != 1:
        return None, None, "invalid_epoch_reference"
    identity = matching[0].get("identity")
    if not isinstance(identity, str) or not identity or identity.startswith("[") or "redacted" in identity.lower():
        return None, None, "raw_network_identity_required"
    rows = []
    for row in evidence:
        if (row.get("comparable") is not True or row.get("epoch_id") not in active
                or row.get("data", {}).get("context_status") != "IDENTIFIED"):
            continue
        if row.get("protocol") == "network":
            continue
        if row.get("protocol") not in {"icmp", "dns", "dns6", "tcp", "tcp6", "http", "http6", "https", "https6"}:
            continue
        if row.get("family") not in {"IPv4", "IPv6"} or not isinstance(row.get("target"), str):
            return None, None, "invalid_protocol_target_or_family"
        start, end = row.get("started_seconds"), row.get("finished_seconds")
        if not _number(start) or not _number(end) or start > end:
            return None, None, "invalid_observation_window"
        if end > report.get("duration_seconds", 0):
            return None, None, "observation_outside_session"
        rows.append(row)
    anchors = {}
    for row in rows:
        anchors[row["family"]] = max(anchors.get(row["family"], 0), row["finished_seconds"])
    for row in evidence:
        if row.get("protocol") == "network" and row.get("comparable") is True and row.get("epoch_id") in active:
            end = row.get("finished_seconds")
            if _number(end):
                for family in anchors:
                    anchors[family] = max(anchors[family], end)
    grouped = defaultdict(list)
    for row in rows:
        if row["started_seconds"] < anchors[row["family"]] - COMPARISON_WINDOW_SECONDS:
            continue
        data = row.get("data") or {}
        # DNS-derived ICMP addresses can legitimately appear only after DNS starts
        # succeeding. They are supplementary, never a replacement comparison peer.
        if row["protocol"] == "icmp" and data.get("role") == "target" and data.get("target_host") != row["target"]:
            continue
        peer = _peer(row)
        if row["protocol"] not in {"dns", "dns6"} and peer is None:
            return None, None, "actual_peer_missing"
        key = (row["protocol"], row["family"], row["target"], data.get("role", ""), peer)
        grouped[key].append(row)
    return identity, grouped, None


def _compare(before, after, baseline_request, verification_request):
    if replace(baseline_request, duration_seconds=verification_request.duration_seconds) != verification_request:
        return _unknown("configured_targets_or_protocols_changed")
    if baseline_request.duration_seconds != verification_request.duration_seconds:
        return _unknown("observation_budgets_differ")
    for report, request in ((before, baseline_request), (after, verification_request)):
        if report.get("status") not in {"completed", "deadline"}:
            return _unknown("session_cancelled_or_failed")
        if report.get("cleanup_errors") or report.get("output_errors"):
            return _unknown("cleanup_or_output_failed")
        if (report.get("budget_seconds") != request.duration_seconds
                or not _number(report.get("duration_seconds"))
                or report["duration_seconds"] > request.duration_seconds):
            return _unknown("invalid_or_exceeded_session_budget")
    left_id, left, error = _groups(before)
    if error:
        return _unknown("before:" + error)
    right_id, right, error = _groups(after)
    if error:
        return _unknown("after:" + error)
    if left_id != right_id:
        return _unknown("network_identity_changed")
    if set(left) != set(right):
        return _unknown("protocol_target_family_or_actual_peer_changed")
    if not left:
        return _unknown("no_comparable_observations")
    if baseline_request.extended_diagnostics:
        tasks, _ = _extended_tasks(baseline_request, {})
        expected = {(task["protocol"], task["target"]) for task in tasks}
        expected_dns = {(task["target"], task["family"]) for task in tasks
                        if task["protocol"] in {"dns", "dns6"}}
    else:
        expected = ({("icmp", host) for host in baseline_request.ping_targets}
                    | {("dns", host) for host in baseline_request.dns_hostnames})
        expected_dns = {(host, "IPv4") for host in baseline_request.dns_hostnames}
    if not expected <= {(key[0], key[2]) for key in left}:
        return _unknown("configured_probe_observations_missing")
    actual_dns = {(key[2], key[1]) for key in left if key[0] in {"dns", "dns6"}}
    if not expected_dns or not expected_dns <= actual_dns:
        return _unknown("configured_dns_observations_missing")
    result = _unknown("no_repeated_dns_improvement")
    result["comparable"] = True
    result["reasons"] = []
    any_improved = any_failed = uncertain = worsened = False
    for key in sorted(left, key=str):
        a, b = left[key], right[key]
        states_a, states_b = [_sample_state(row) for row in a], [_sample_state(row) for row in b]
        enough = len(a) >= REPEAT_SAMPLES and len(b) >= REPEAT_SAMPLES
        consistent = enough and len(set(states_a)) == len(set(states_b)) == 1 and "unknown" not in states_a + states_b and "mixed" not in states_a + states_b
        change = "inconclusive"
        if consistent:
            first, last = states_a[0], states_b[0]
            if first == "failure" and last == "success":
                change = "improved"
            elif first == "success" and last in {"failure", "service_error"}:
                change = "worsened"
                worsened = True
            elif first == last:
                change = "unchanged_" + first
            else:
                uncertain = True
        else:
            uncertain = True
        if key[0] in {"dns", "dns6"}:
            any_improved |= change == "improved"
            any_failed |= change == "unchanged_failure"
        result["comparisons"].append({
            "protocol": key[0], "family": key[1], "target": key[2], "role": key[3], "actual_peer": key[4],
            "change": change, "before_sequences": [r["sequence"] for r in a],
            "after_sequences": [r["sequence"] for r in b], "before_states": states_a, "after_states": states_b,
            "before_window": [min(r["started_seconds"] for r in a), max(r["finished_seconds"] for r in a)],
            "after_window": [min(r["started_seconds"] for r in b), max(r["finished_seconds"] for r in b)],
        })
    if before.get("analysis", {}).get("intermittent") or after.get("analysis", {}).get("intermittent"):
        uncertain = True
        result["reasons"].append("intermittent_not_resolved_by_non_reproduction")
    if uncertain or worsened:
        result["reasons"].append("insufficient_mixed_or_worsened_observations")
    elif any_improved:
        result["status"] = "observed_dns_improvement"
    elif any_failed:
        result["status"] = "no_dns_improvement_observed"
    else:
        result["reasons"].append("no_failed_dns_baseline")
    return result


def compare_reports(before: SessionReport, after: SessionReport,
                    baseline_request: SessionRequest, verification_request: SessionRequest) -> dict:
    """Compare current raw reports only; no file loading, history, or repair."""
    return _compare(_copy(before.to_dict()), _copy(after.to_dict()), baseline_request, verification_request)


class RepairController:
    """One disclosed request, one confirmation, one operation, one verification."""

    def __init__(self, request: RepairRequest, baseline_request: SessionRequest,
                 baseline_report: SessionReport, *, executor=None):
        if type(request) is not RepairRequest or not isinstance(baseline_request, SessionRequest):
            raise TypeError("A repair request and diagnostic request are required")
        if not isinstance(baseline_report, SessionReport):
            raise TypeError("A raw current-session report is required")
        command_execution = False
        if executor is not None and type(executor) is not SimulatedRepairExecutor:
            from losshound.core.dns_cache import WindowsDnsCacheExecutor
            if type(executor) is not WindowsDnsCacheExecutor:
                raise TypeError("Only the built-in simulator or explicit DNS cache adapter is allowed")
            command_execution = True
        self._request, self._baseline_request = request, baseline_request
        self._verification_request = replace(baseline_request, duration_seconds=request.verification_seconds)
        self._executor = executor if executor is not None else SimulatedRepairExecutor()
        self._command_execution = command_execution
        self._mode = "windows_dns_cache" if command_execution else "simulation"
        self._simulation_only = self._executor.simulation_only if command_execution else True
        self._phase_lock = threading.Lock()
        self._verification_eligible = False
        before = _copy(baseline_report.to_dict())
        fingerprint = hashlib.sha256(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self._presented = self._attempted = self._verified = False
        self._record = {
            "schema_version": 1, "request": dict(asdict(request), request_id=uuid4().hex,
                impact=(IMPACT if not command_execution else
                        "Windows DNS cache command mode clears only the local resolver cache; "
                        "new lookups may take longer. " +
                        ("The explicitly supplied command runner is simulated." if self._simulation_only else
                         "This would be a real system operation; implementation approval does not authorize execution.")),
                no_restore_warning=NO_RESTORE_WARNING,
                permissions=(PERMISSIONS if not command_execution else
                             "No automatic elevation. Access may be denied; real execution requires separate authorization."),
                execution_mode=self._mode, simulation_only=self._simulation_only, baseline_sha256=fingerprint),
            "baseline_request": asdict(baseline_request), "before_report": before,
            "confirmation": {"status": "not_confirmed"},
            "execution": {"status": "not_attempted", "simulation_only": self._simulation_only, "system_change_performed": False},
            "verification": {"status": "not_started", "budget_seconds": request.verification_seconds, "report": None},
            "comparison": _unknown("verification_not_run"),
        }

    @property
    def request(self):
        return self._request

    @property
    def baseline_request(self):
        return self._baseline_request

    @property
    def verification_request(self):
        return self._verification_request

    def prepare(self) -> dict:
        with self._phase_lock:
            self._presented = True
            return _copy(self._record["request"])

    def confirm(self, request_id: str, *, accepted: bool, acknowledge_impact: bool,
                acknowledge_no_restore: bool) -> dict:
        with self._phase_lock:
            if self._attempted or self._record["confirmation"]["status"] != "not_confirmed":
                raise RuntimeError("This confirmation is single-use")
            if not self._presented:
                raise RuntimeError("Disclose the operation before confirmation")
            if type(request_id) is not str or request_id != self._record["request"]["request_id"]:
                raise ValueError("Confirmation does not match this request")
            if any(type(value) is not bool for value in (accepted, acknowledge_impact, acknowledge_no_restore)):
                raise ValueError("Confirmation and acknowledgements must be explicit booleans")
            status = "confirmed" if accepted and acknowledge_impact and acknowledge_no_restore else "declined"
            self._record["confirmation"] = {"status": status, "request_id": request_id,
                "action": self.request.action, "execution_mode": self._mode,
                "accepted": accepted, "acknowledge_impact": acknowledge_impact,
                "acknowledge_no_restore": acknowledge_no_restore}
            return _copy(self._record["confirmation"])

    def execute(self, cancel_event: threading.Event | None = None, *, clock=time.monotonic,
                absolute_deadline: float | None = None) -> dict:
        started = clock()
        deadline = started + 60.0
        if absolute_deadline is not None:
            if (type(absolute_deadline) not in {int, float} or not math.isfinite(absolute_deadline)
                    or absolute_deadline > deadline):
                raise ValueError("Operation deadline may only tighten the 60-second budget")
            deadline = float(absolute_deadline)
        with self._phase_lock:
            if self._attempted:
                raise RuntimeError("One operation per request; no automatic retry")
            self._attempted = True
            confirmed = (self._presented and self._record["confirmation"]["status"] == "confirmed"
                         and self._record["confirmation"].get("execution_mode") == self._mode)
            confirmation = _copy(self._record["confirmation"])
        if not confirmed:
            self._record["execution"]["status"] = "blocked"
        elif cancel_event is not None and cancel_event.is_set():
            self._record["execution"].update(status="cancelled", command_started=False)
        elif clock() >= deadline:
            self._record["execution"].update(status="timed_out", command_started=False,
                                            system_change_performed=False)
        else:
            try:
                if self._command_execution:
                    self._record["execution"] = self._executor.execute(
                        self.request, request_id=self._record["request"]["request_id"],
                        confirmation=confirmation, cancel_event=cancel_event,
                        clock=clock, absolute_deadline=deadline)
                else:
                    self._record["execution"] = self._executor.execute(self.request)
            except Exception as exc:
                self._record["execution"].update(
                    status="execution_error" if self._command_execution else "simulated_tool_error",
                    error=type(exc).__name__)
                if self._command_execution:
                    self._record["execution"].update(
                        command_started=None, system_change_performed=False if self._simulation_only else None,
                        cleanup_confirmed=False, cleanup_errors=["Execution cleanup was not confirmed"])
        execution = self._record["execution"]
        result = self.record()
        finished = clock()
        execution["duration_seconds"] = max(0.0, finished - started)
        result["execution"]["duration_seconds"] = execution["duration_seconds"]
        if finished > deadline and execution["status"] not in {"blocked", "cleanup_failed"}:
            execution.setdefault("operation_status", execution["status"])
            execution["status"] = "timed_out"
            result["execution"].update(status="timed_out", operation_status=execution["operation_status"])
        with self._phase_lock:
            self._verification_eligible = (
                execution["status"].startswith("simulated_") or (
                    self._command_execution and execution.get("command_started") is not False
                    and execution["status"] not in {"blocked", "cleanup_failed"}
                    and execution.get("cleanup_confirmed") is True
                    and not execution.get("cleanup_errors")))
            if self._verification_eligible:
                self._record["verification"]["status"] = "pending"
                result["verification"]["status"] = "pending"
        return result

    def verify(self, *, provider, context_observer, clock=time.monotonic, wait=None,
               cancel_event=None, on_progress=None, absolute_deadline: float | None = None) -> dict:
        if provider is None or context_observer is None:
            raise ValueError("Explicit verification provider and context observer are required; no native fallback")
        entered = clock()
        deadline = entered + self.request.verification_seconds
        if absolute_deadline is not None:
            if (type(absolute_deadline) not in {int, float} or not math.isfinite(absolute_deadline)
                    or absolute_deadline > deadline):
                raise ValueError("Verification deadline may only tighten the requested budget")
            deadline = float(absolute_deadline)
        # An external deadline includes queueing and worker construction in the
        # original budget, matching SessionController's absolute-deadline clock.
        started = deadline - self.request.verification_seconds
        with self._phase_lock:
            if not self._attempted or not self._verification_eligible:
                raise RuntimeError("Verification requires an attempted operation with completed cleanup")
            if self._verified:
                raise RuntimeError("One independent verification per request; no automatic retry")
            self._verified = True
        verification = self._record["verification"]
        try:
            report = SessionController(self.verification_request, provider, clock, wait,
                                       context_observer=context_observer).run(
                cancel_event=cancel_event, on_progress=on_progress, absolute_deadline=deadline)
            verification["report"] = _copy(report.to_dict())
            verification["session_status"] = report.status
            verification["status"] = ("completed" if report.status in {"completed", "deadline"}
                                      else "cancelled" if report.status == "cancelled" else "execution_error")
            self._record["comparison"] = _compare(self._record["before_report"], verification["report"],
                                                  self.baseline_request, self.verification_request)
            if cancel_event is not None and cancel_event.is_set():
                verification["status"] = "cancelled"
                self._record["comparison"] = _unknown("verification_cancelled")
        except Exception as exc:
            verification["status"] = "execution_error"
            verification["error"] = type(exc).__name__
            self._record["comparison"] = _unknown("verification_failed")
        # Preparing the defensive return snapshot is report work within the
        # same verification budget, not unmeasured work after the final check.
        result = self.record()
        finished = clock()
        verification["duration_seconds"] = max(0.0, finished - started)
        result["verification"]["duration_seconds"] = verification["duration_seconds"]
        if finished > deadline:
            verification["status"] = "budget_exceeded"
            self._record["comparison"] = _unknown("verification_budget_exceeded")
            result["verification"]["status"] = "budget_exceeded"
            result["comparison"] = _unknown("verification_budget_exceeded")
        return result

    def record(self) -> dict:
        return _copy(self._record)

    def to_json(self) -> str:
        return json.dumps(self._record, ensure_ascii=False, indent=2, allow_nan=False)
