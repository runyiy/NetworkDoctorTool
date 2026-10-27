"""Finite read-only diagnostic sessions, independent of Qt.

Collection and owned-process cleanup share one immutable monotonic deadline.
An observation is a fact with coverage/context, never a causal diagnosis.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
import math
import threading
import time
from typing import Callable, Protocol

DEFAULT_DURATION_SECONDS = 60
MAX_DURATION_SECONDS = 300
MAX_CLEANUP_SECONDS = 2.0
REPORT_RESERVE_SECONDS = 0.05
MAX_TARGETS_PER_KIND = 8
SAMPLE_INTERVAL_SECONDS = 1.0


class ProbeOutcome(str, Enum):
    SUCCESS = "success"
    REPLY_TIMEOUT = "reply_timeout"
    UNREACHABLE = "unreachable"
    EXECUTION_ERROR = "execution_error"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True)
class SessionRequest:
    duration_seconds: int = DEFAULT_DURATION_SECONDS
    ping_targets: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
    dns_hostnames: tuple[str, ...] = ("google.com", "chatgpt.com")
    extended_diagnostics: bool = False
    ipv6_targets: tuple[str, ...] = ("2606:4700:4700::1111", "2001:4860:4860::8888")
    tcp_targets: tuple[str, ...] = ("1.1.1.1:443", "8.8.8.8:53",
                                    "[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:53")
    website_urls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, int)
            or not 1 <= self.duration_seconds <= MAX_DURATION_SECONDS
        ):
            raise ValueError("Session duration must be an integer from 1 to 300 seconds")
        if not isinstance(self.extended_diagnostics, bool):
            raise ValueError("extended_diagnostics must be a boolean")
        if self.website_urls and not self.extended_diagnostics:
            raise ValueError("Website checks require extended diagnostics")
        for name in ("ping_targets", "dns_hostnames", "ipv6_targets", "tcp_targets", "website_urls"):
            raw = getattr(self, name)
            if not isinstance(raw, (tuple, list)) or len(raw) > MAX_TARGETS_PER_KIND:
                raise ValueError(f"{name} must contain at most {MAX_TARGETS_PER_KIND} targets")
            limit = 2048 if name == "website_urls" else 253
            if any(not isinstance(value, str) or not value or len(value) > limit for value in raw):
                raise ValueError(f"{name} contains an invalid target")
            object.__setattr__(self, name, tuple(dict.fromkeys(raw)))
        from losshound.core.session_protocols import parse_tcp_target, validate_web_url
        for target in self.ipv6_targets:
            try:
                ipaddress.IPv6Address(target)
            except ValueError as exc:
                raise ValueError("IPv6 targets must be IPv6 literals") from exc
        for target in self.tcp_targets:
            parse_tcp_target(target)
        for target in self.website_urls:
            validate_web_url(target)


@dataclass(frozen=True)
class SessionProgress:
    phase: str
    remaining_seconds: float
    elapsed_seconds: float
    completed_count: int


@dataclass
class NetworkEpoch:
    epoch_id: int
    identity: str
    started_seconds: float
    context: dict = field(default_factory=dict)


@dataclass
class ProbeEvidence:
    sequence: int
    timestamp: str
    started_seconds: float
    finished_seconds: float
    epoch_id: int | None
    protocol: str
    family: str
    target: str
    outcome: ProbeOutcome
    packets_sent: int | None = None
    packets_received: int | None = None
    rtt_ms: float | None = None
    error: str | None = None
    comparable: bool = False
    data: dict = field(default_factory=dict)

    @property
    def loss_percent(self) -> float | None:
        """Loss requires completed ICMP attempts in a confirmed context."""
        if (
            self.protocol != "icmp"
            or not self.comparable
            or self.outcome not in {
                ProbeOutcome.SUCCESS, ProbeOutcome.REPLY_TIMEOUT, ProbeOutcome.UNREACHABLE,
            }
            or self.packets_sent is None
            or self.packets_sent <= 0
            or self.packets_received is None
        ):
            return None
        return 100.0 * (self.packets_sent - self.packets_received) / self.packets_sent


@dataclass
class SessionReport:
    status: str
    budget_seconds: int
    duration_seconds: float = 0.0
    epochs: list[NetworkEpoch] = field(default_factory=list)
    evidence: list[ProbeEvidence] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    cleanup_errors: list[str] = field(default_factory=list)
    output_errors: list[str] = field(default_factory=list)
    context_observations: list[dict] = field(default_factory=list)
    context_blind_spots: list[str] = field(default_factory=list)
    cancel_request_elapsed_seconds: float | None = None
    cancel_to_return_seconds: float | None = None
    schema_version: int = 2
    summary: str = "S1 evidence collection only; no causal diagnosis or repair was performed."
    analysis: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = asdict(self)
        for raw, evidence in zip(result["evidence"], self.evidence):
            raw["outcome"] = evidence.outcome.value
            raw["loss_percent"] = evidence.loss_percent
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, allow_nan=False)


def _task(protocol, target, role, family=None, target_host=None):
    if family is None:
        family = "IPv6" if protocol.endswith("6") else "IPv4" if protocol == "dns" else "unspecified"
        try:
            family = "IPv" + str(ipaddress.ip_address(target.strip("[]")).version)
        except ValueError:
            pass
    return dict(protocol=protocol, target=target, role=role, family=family,
                target_host=target if target_host is None else target_host)


def _gateway(context, family):
    route = context.get("diagnostics", {}).get("families", {}).get(family, {}).get("default_route")
    if isinstance(route, dict) and isinstance(route.get("gateway"), str):
        return route["gateway"]
    return context.get("gateway") if family == "IPv4" else None


def _extended_tasks(request, context):
    from urllib.parse import unquote, urlsplit
    from losshound.core.session_protocols import parse_tcp_target
    tasks, missing = [], []
    for family in ("IPv4", "IPv6"):
        gateway = _gateway(context, family)
        if gateway:
            tasks.append(_task("icmp", gateway, "gateway", family))
        else:
            missing.append(_task("icmp", "default_gateway_" + family.lower(), "gateway", family))
    # Explicit website requests precede background reference targets, so a short
    # observation window does not always starve the requested website.
    website_hosts = set()
    for url in request.website_urls:
        parsed = urlsplit(url)
        host = unquote(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        canonical_endpoint = ("[" + host + "]" if ":" in host else host) + ":" + str(port)
        host, _ = parse_tcp_target(canonical_endpoint)
        website_hosts.add(host)
        try:
            address = ipaddress.ip_address(host)
            families = (address.version,)
            tasks.append(_task("icmp", host, "target", "IPv" + str(address.version), host))
        except ValueError:
            families = (4, 6)
            tasks.extend(_task("dns" if version == 4 else "dns6", host, "target", "IPv" + str(version), host)
                         for version in families)
        endpoint = ("[" + host + "]" if ":" in host else host) + ":" + str(port)
        for version in families:
            suffix = "6" if version == 6 else ""
            tasks.append(_task("tcp" + suffix, endpoint, "target", "IPv" + str(version), host))
            tasks.append(_task(parsed.scheme + suffix, url, "target", "IPv" + str(version), host))
    tasks.extend(_task("icmp", target, "public") for target in request.ping_targets
                 if target != _gateway(context, "IPv4"))
    tasks.extend(_task("icmp", target, "public", "IPv6") for target in request.ipv6_targets
                 if target != _gateway(context, "IPv6"))
    for target in request.tcp_targets:
        host, _port = parse_tcp_target(target)
        try:
            family = "IPv" + str(ipaddress.ip_address(host).version)
        except ValueError:
            family = "IPv4"
        tasks.append(_task("tcp6" if family == "IPv6" else "tcp", target, "public", family, host))
    for host in request.dns_hostnames:
        if host not in website_hosts:
            tasks.extend((_task("dns", host, "dns", "IPv4"), _task("dns6", host, "dns", "IPv6")))
    return tasks, missing


class ProbeProvider(Protocol):
    def set_cleanup_deadline(self, deadline: float) -> None: ...
    def read_network(self, deadline: float, cancel_event: threading.Event) -> dict: ...
    def probe(self, protocol: str, target: str, deadline: float, cancel_event: threading.Event) -> dict: ...
    def close(self, deadline: float) -> list[str]: ...


class SessionController:
    def __init__(
        self,
        request: SessionRequest,
        provider: ProbeProvider | None = None,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[threading.Event, float], bool] | None = None,
        context_observer=None,
    ) -> None:
        self.request = request
        self._provider = provider
        self._clock = clock
        self._wait = wait or (lambda event, seconds: event.wait(seconds))
        self._used = False
        self._context_observer = context_observer

    def run(
        self,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[SessionProgress], None] | None = None,
        *,
        absolute_deadline: float | None = None,
        output_reserve_seconds: float = 0.0,
    ) -> SessionReport:
        if self._used:
            raise RuntimeError("Each controller represents exactly one session")
        entered = self._clock()
        if absolute_deadline is not None and (
            isinstance(absolute_deadline, bool)
            or not isinstance(absolute_deadline, (int, float))
            or not math.isfinite(absolute_deadline)
            or absolute_deadline > entered + self.request.duration_seconds
        ):
            raise ValueError("Absolute deadline must be finite and cannot extend the requested budget")
        if (
            isinstance(output_reserve_seconds, bool)
            or not isinstance(output_reserve_seconds, (int, float))
            or not math.isfinite(output_reserve_seconds)
            or not 0 <= output_reserve_seconds <= self.request.duration_seconds
        ):
            raise ValueError("Output reserve must be finite and within the requested budget")
        self._used = True
        cancel = cancel_event if cancel_event is not None else threading.Event()
        total_deadline = entered + self.request.duration_seconds if absolute_deadline is None else float(absolute_deadline)
        # The caller may have spent part of this exact budget launching bounded
        # output. Keep that elapsed time in progress/evidence/report timestamps.
        started = total_deadline - self.request.duration_seconds
        remaining_budget = max(0.0, total_deadline - entered)
        reserve = min(MAX_CLEANUP_SECONDS, remaining_budget * 0.2)
        output_reserve = min(float(output_reserve_seconds), remaining_budget * 0.2)
        report_reserve = min(0.25 if self.request.extended_diagnostics else REPORT_RESERVE_SECONDS, reserve * 0.25)
        collection_deadline = total_deadline - reserve - output_reserve
        cleanup_deadline = total_deadline - report_reserve - output_reserve
        report = SessionReport("completed", self.request.duration_seconds)
        if self.request.extended_diagnostics:
            report.schema_version = 3
            report.summary = "Bounded read-only dual-stack observations with qualified explanations; no repair was performed."
        latest_network_result = {}
        round_index = 0
        pending_cohort_start = None
        cohort_epoch = None
        cohort_identity = None
        cohort_context = {}
        cohort_disrupted = False
        provider = self._provider
        active_epoch: NetworkEpoch | None = None
        last_identity = None
        observer = self._context_observer
        callback = on_progress

        def progress(phase: str) -> None:
            nonlocal callback
            if callback is not None:
                now = self._clock()
                try:
                    callback(SessionProgress(
                        phase, max(0.0, total_deadline - now),
                        max(0.0, now - started), len(report.evidence),
                    ))
                except Exception as exc:
                    report.incomplete.append(f"Progress callback failed: {type(exc).__name__}")
                    callback = None

        def stopped() -> bool:
            return cancel.is_set() or self._clock() >= collection_deadline

        def reason() -> str:
            return "cancelled" if cancel.is_set() else "deadline"

        def network() -> tuple[object, dict]:
            nonlocal active_epoch, last_identity, latest_network_result
            if stopped():
                return None, {}
            progress("network_context")
            before_watch = observer.snapshot()
            result = provider.read_network(collection_deadline, cancel)
            latest_network_result = result
            after_watch = observer.snapshot()
            context = result.get("data") if isinstance(result.get("data"), dict) else {}
            identity = context.get("identity") if result.get("outcome") == "success" else None
            if self.request.extended_diagnostics and result.get("outcome") == "success":
                from losshound.core.session_protocols import summarize_network
                context = dict(context, diagnostics=summarize_network(context))
            # A generation change can detect A->B->A even when identities match.
            # A context query spanning an event is itself unconfirmed.
            watch_ready = before_watch.get("status") == after_watch.get("status") == "READY"
            before_token = (before_watch.get("observer_id"), before_watch.get("generation"))
            after_token = (after_watch.get("observer_id"), after_watch.get("generation"))
            watch_stable = watch_ready and before_token == after_token
            if watch_ready and not watch_stable:
                identity = None
            identity_known = isinstance(identity, str) and bool(identity)
            report.context_observations.append({
                "elapsed_seconds": max(0.0, self._clock() - started),
                "status": "IDENTIFIED" if identity_known else "UNKNOWN",
                "identity": identity if identity_known else None,
                "continuity": "OBSERVED" if watch_stable else "UNKNOWN",
                "observer": after_watch,
                "query_outcome": result.get("outcome"), "error": result.get("error"),
                "error_data": context if not identity_known else {},
            })
            if not watch_stable:
                report.context_blind_spots.append("Change observation unavailable, starting, or changing; affected evidence is UNKNOWN")
            if not identity_known:
                last_identity = None
                active_epoch = None
                if result.get("outcome") not in {"cancelled", "not_attempted"}:
                    report.incomplete.append("Network context unavailable: " + str(result.get("error") or "change during context query"))
                return None, context
            key = (identity, after_token if watch_stable else None)
            if key != last_identity:
                active_epoch = NetworkEpoch(
                    len(report.epochs) + 1, identity,
                    max(0.0, self._clock() - started), dict(context, change_generation=after_watch.get("generation")),
                )
                report.epochs.append(active_epoch)
                last_identity = key
            # Identity alone cannot establish continuity without event coverage.
            return key if watch_stable else None, context

        def cohort_boundary() -> tuple[object, dict]:
            """Observe continuity inside an S2 round; never certify it alone.

            Both enclosing full identity queries must also agree before any
            enclosed probe may remain comparable in the returned report.
            """
            nonlocal cohort_disrupted, active_epoch, last_identity
            if stopped():
                return None, cohort_context
            watch = observer.snapshot()
            token = (watch.get("observer_id"), watch.get("generation"))
            if (cohort_disrupted or cohort_identity is None or watch.get("status") != "READY"
                    or token != cohort_identity[1]):
                cohort_disrupted = True
                last_identity = None
                active_epoch = None
                return None, cohort_context
            return cohort_identity, cohort_context

        def finish_cohort(ending_identity) -> None:
            nonlocal pending_cohort_start
            if pending_cohort_start is None:
                return
            confirmed = (cohort_identity is not None and not cohort_disrupted
                         and ending_identity == cohort_identity)
            for evidence in report.evidence[pending_cohort_start:]:
                evidence.comparable = bool(confirmed and evidence.comparable)
                evidence.epoch_id = cohort_epoch.epoch_id if evidence.comparable and cohort_epoch else None
                evidence.data["context_status"] = "IDENTIFIED" if evidence.comparable else "UNKNOWN"
                evidence.data["context_confirmation"] = ("round_identity_and_notifications_confirmed"
                                                         if evidence.comparable else "round_not_confirmed")
                if not evidence.comparable:
                    evidence.data["context_note"] = (
                        "The complete S2 sampling round could not be confirmed; excluded from comparisons")
            if not confirmed:
                report.incomplete.append("S2 sampling round identity/notification continuity was not confirmed")
            pending_cohort_start = None

        def append(protocol: str, target: str, result: dict, before: float,
                   epoch: NetworkEpoch | None, comparable: bool, finished: float | None = None,
                   timestamp: str | None = None) -> None:
            try:
                outcome = ProbeOutcome(result.get("outcome", "execution_error"))
            except ValueError:
                outcome = ProbeOutcome.EXECUTION_ERROR
            sent = result.get("packets_sent")
            received = result.get("packets_received")
            counts_valid = (
                isinstance(sent, int) and not isinstance(sent, bool) and sent >= 0
                and isinstance(received, int) and not isinstance(received, bool)
                and 0 <= received <= sent
            )
            if protocol != "icmp" or not counts_valid:
                sent = received = None
            rtt = result.get("rtt_ms")
            if not isinstance(rtt, (int, float)) or isinstance(rtt, bool) or not math.isfinite(rtt) or rtt < 0:
                rtt = None
            data = dict(result.get("data")) if isinstance(result.get("data"), dict) else {}
            data["context_status"] = "IDENTIFIED" if comparable else "UNKNOWN"
            if not comparable:
                epoch = None
            family = "IPv4" if protocol == "dns" else "unspecified"
            try:
                family = "IPv" + str(ipaddress.ip_address(target.strip("[]")).version)
            except ValueError:
                pass
            if self.request.extended_diagnostics and data.get("family") in {"IPv4", "IPv6"}:
                family = data["family"]
            report.evidence.append(ProbeEvidence(
                len(report.evidence) + 1, timestamp or datetime.now(timezone.utc).isoformat(),
                max(0.0, before - started), max(0.0, (self._clock() if finished is None else finished) - started),
                epoch.epoch_id if epoch else None, protocol, family, target, outcome,
                sent, received, rtt, result.get("error"), comparable, data,
            ))

        try:
            if provider is None:
                from losshound.core.session_process import WindowsProbeProvider
                provider = (WindowsProbeProvider(clock=self._clock, extended_diagnostics=True)
                            if self.request.extended_diagnostics else WindowsProbeProvider(clock=self._clock))
            provider.set_cleanup_deadline(cleanup_deadline)
            if observer is None:
                from losshound.core.session_context import WindowsContextObserver
                observer = WindowsContextObserver(clock=self._clock)
            observer.start(collection_deadline, cancel)
            report.context_blind_spots.append("OS notifications may be delayed or omitted; startup, failed registration, and gaps are not confirmed stability")
            progress("starting")
            while not stopped():
                round_index += 1
                round_started = self._clock()
                round_identity, context = network()
                if stopped():
                    break
                gateway = context.get("gateway")
                if self.request.extended_diagnostics:
                    cohort_identity, cohort_context, cohort_epoch = round_identity, context, active_epoch
                    cohort_disrupted = False
                    pending_cohort_start = len(report.evidence)
                    context_result = dict(latest_network_result)
                    context_result["data"] = dict(context, role="local", round_index=round_index)
                    append("network", "local_network", context_result, round_started,
                           active_epoch, round_identity is not None)
                    tasks, missing = _extended_tasks(self.request, context)
                    for task in missing:
                        append("icmp", task["target"], {"outcome": "not_attempted",
                               "error": "No confirmed default gateway for this address family",
                               "data": {"family": task["family"], "role": "gateway", "round_index": round_index}},
                               self._clock(), active_epoch, round_identity is not None)
                else:
                    tasks = [_task("icmp", gateway, "gateway")] if isinstance(gateway, str) and gateway else []
                    if not tasks:
                        append("icmp", "default_gateway", {
                            "outcome": "not_attempted", "packets_sent": 0,
                            "packets_received": 0, "error": "No confirmed IPv4 default gateway",
                        }, self._clock(), active_epoch, False)
                    tasks.extend(_task("icmp", target, "public") for target in self.request.ping_targets if target != gateway)
                    tasks.extend(_task("dns", target, "dns") for target in self.request.dns_hostnames)
                for index, task in enumerate(tasks):
                    protocol, target = task["protocol"], task["target"]
                    if stopped():
                        report.incomplete.extend(f"{pending['protocol']} {pending['target']}: {reason()}" for pending in tasks[index:])
                        break
                    before_identity, probe_context = (cohort_boundary() if self.request.extended_diagnostics else network())
                    if (self.request.extended_diagnostics and cohort_identity is not None
                            and before_identity is None and cohort_disrupted):
                        report.incomplete.append("Network change or observer gap interrupted S2 sampling")
                        break
                    epoch = active_epoch
                    if stopped():
                        report.incomplete.extend(f"{pending['protocol']} {pending['target']}: {reason()}" for pending in tasks[index:])
                        break
                    if task["role"] == "gateway" and protocol == "icmp":
                        current_gateway = _gateway(probe_context, task["family"]) if self.request.extended_diagnostics else probe_context.get("gateway")
                        if not isinstance(current_gateway, str) or not current_gateway:
                            append("icmp", "default_gateway", {
                                "outcome": "not_attempted", "packets_sent": 0,
                                "packets_received": 0, "error": "Gateway changed or unavailable before probe",
                            }, self._clock(), epoch, False)
                            continue
                        target = current_gateway
                    if self.request.extended_diagnostics and task["family"] == "IPv6" and protocol != "dns6":
                        available = probe_context.get("diagnostics", {}).get("families", {}).get("IPv6", {}).get("available")
                        try:
                            endpoint_host = task["target_host"].split("%", 1)[0]
                            local_target = ipaddress.ip_address(endpoint_host).is_loopback or ipaddress.ip_address(endpoint_host).is_link_local
                        except ValueError:
                            local_target = False
                        if available is False and not local_target:
                            append(protocol, target, {"outcome": "not_attempted",
                                   "error": "No configured IPv6 source address and default route; no connectivity verdict",
                                   "data": {"family": "IPv6", "role": task["role"], "target_host": task["target_host"], "round_index": round_index}},
                                   self._clock(), epoch, before_identity is not None)
                            continue
                    progress(f"{protocol}: {task['role']} {task['family']}"
                             if self.request.extended_diagnostics else f"{protocol}: {target}")
                    before = self._clock()
                    result = provider.probe(protocol, target, collection_deadline, cancel)
                    completed_at = self._clock()
                    completed_timestamp = datetime.now(timezone.utc).isoformat()
                    after_identity, _ = (cohort_boundary() if self.request.extended_diagnostics else network())
                    comparable = before_identity is not None and before_identity == after_identity
                    if not comparable:
                        result = dict(result)
                        result["data"] = dict(result.get("data") or {})
                        result["data"]["context_note"] = "Network changed or could not be confirmed around this probe; excluded from comparisons"
                    if self.request.extended_diagnostics:
                        result = dict(result)
                        result["data"] = dict(result.get("data") or {}, role=task["role"],
                                              target_host=task["target_host"], round_index=round_index)
                        if task["family"] in {"IPv4", "IPv6"}:
                            result["data"]["family"] = task["family"]
                    append(protocol, target, result, before, epoch, comparable, completed_at, completed_timestamp)
                    if (self.request.extended_diagnostics and protocol in {"dns", "dns6"}
                            and task["role"] == "target" and comparable and result.get("outcome") == "success"):
                        addresses = result.get("data", {}).get("addresses", [])
                        if isinstance(addresses, list) and addresses:
                            try:
                                address = str(ipaddress.ip_address(addresses[0]))
                                expected = 6 if protocol == "dns6" else 4
                                if ipaddress.ip_address(address).version == expected:
                                    tasks.insert(index + 1, _task("icmp", address, "target", task["family"], task["target_host"]))
                            except (ValueError, TypeError):
                                pass
                if self.request.extended_diagnostics:
                    ending_identity, _ = network()
                    finish_cohort(ending_identity)
                if stopped():
                    break
                progress("observing")
                self._wait(cancel, min(SAMPLE_INTERVAL_SECONDS, max(0.0, collection_deadline - self._clock())))
            report.status = reason()
            report.incomplete.append("Observation ended: " + report.status + "; additional evidence was not collected")
        except Exception as exc:
            report.status = "execution_error"
            report.incomplete.append(f"Session collection error: {type(exc).__name__}: {exc}")
        finally:
            # Cancellation, deadline or an exception cannot publish an enclosing
            # round that never obtained its second full identity boundary.
            finish_cohort(None)
            progress("cleanup")
            close_deadline = min(cleanup_deadline, self._clock() + MAX_CLEANUP_SECONDS)
            if provider is not None:
                try:
                    report.cleanup_errors.extend(provider.close(close_deadline))
                except Exception as exc:
                    report.cleanup_errors.append(f"{type(exc).__name__}: {exc}")
            if observer is not None:
                try:
                    report.cleanup_errors.extend(observer.close(close_deadline))
                except Exception as exc:
                    report.cleanup_errors.append(f"Context observer cleanup: {type(exc).__name__}: {exc}")
            if report.cleanup_errors:
                report.status = "cleanup_failed"
            attempted = {(item.protocol, item.target) for item in report.evidence
                         if item.outcome not in {ProbeOutcome.NOT_ATTEMPTED, ProbeOutcome.SKIPPED}}
            configured = [("icmp", host) for host in self.request.ping_targets]
            configured.extend(("dns", host) for host in self.request.dns_hostnames)
            if self.request.extended_diagnostics:
                configured = [(task["protocol"], task["target"]) for task in _extended_tasks(self.request, {})[0]]
            report.incomplete.extend(f"{kind} {host}: not attempted" for kind, host in configured
                                     if (kind, host) not in attempted)
            report.incomplete.extend(
                f"{item.protocol} {item.target}: {item.outcome.value}"
                for item in report.evidence if item.outcome in {
                    ProbeOutcome.EXECUTION_ERROR, ProbeOutcome.UNSUPPORTED,
                    ProbeOutcome.SKIPPED, ProbeOutcome.CANCELLED, ProbeOutcome.NOT_ATTEMPTED,
                }
            )
            if not report.epochs:
                report.incomplete.append("Network context was not confirmed")
            report.incomplete = list(dict.fromkeys(report.incomplete))
            report.context_blind_spots = list(dict.fromkeys(report.context_blind_spots))
            report.duration_seconds = max(0.0, self._clock() - started)
            if self.request.extended_diagnostics:
                from losshound.core.session_diagnosis import analyze_report
                try:
                    report.analysis = analyze_report(report.to_dict())
                except (ValueError, TypeError, KeyError) as exc:
                    report.incomplete.append(f"Offline analysis incomplete: {type(exc).__name__}")
                    report.analysis = {"findings": [], "intermittent": [],
                                       "limitations": ["Analysis failed; raw evidence is not a health verdict"]}
            # Exercise report preparation inside the same budget. Later callers
            # serialize current metadata, including preparation/callback overruns;
            # a cached earlier snapshot would hide those final changes.
            report.to_json()
            progress("finished")
            report.duration_seconds = max(0.0, self._clock() - started)
            request_time = getattr(cancel, "requested_monotonic", None)
            if cancel.is_set() and isinstance(request_time, (int, float)) and started <= request_time <= self._clock():
                report.cancel_request_elapsed_seconds = request_time - started
                report.cancel_to_return_seconds = max(0.0, self._clock() - request_time)
            if self._clock() > total_deadline:
                report.status = "execution_error" if not report.cleanup_errors else "cleanup_failed"
                report.incomplete.append("Total session budget exceeded; bounded completion was not established")
        return report
