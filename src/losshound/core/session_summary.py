"""Small, evidence-linked presentation of an existing bounded session.

This module performs no diagnosis, collection or repair. Observations describe
recorded comparable checks; only the existing analysis may supply a suspected
scope. Build from original structured facts, never report-local address aliases.
"""
from __future__ import annotations

from collections import Counter
import math

from losshound.core.session_diagnosis import (
    DIAGNOSIS_MESSAGE_IDS, MAX_EPOCHS, MAX_EVIDENCE, PROTOCOLS, SCOPE_MESSAGE_IDS,
)

PARTS = ("connectivity", "dns", "gateway", "website")
COUNTS = ("responses", "failures", "tool_errors", "not_tested", "excluded")
COVERAGE_REASON_CODES = frozenset({
    "reason_unavailable", "not_tested", "tool_error", "not_comparable",
    "context_blind_spots", "multiple_epochs", "truncated",
})
SUMMARY_MESSAGE_IDS = frozenset(
    "summary.observation." + value for value in (
        "responses", "mixed", "failures", "not_tested", "tool_error",
        "no_comparable", "not_configured", "http_error", "tls_error",
    )
) | frozenset({
    "summary.website.not_tested", "summary.overall.anomalies",
    "summary.overall.suspected", "summary.overall.responses", "summary.overall.unknown",
    "summary.coverage.complete", "summary.coverage.partial", "summary.coverage.multiple_epochs",
}) | frozenset("summary.advice." + value for value in (
    "website", "review_failures", "review_tools", "review_coverage", "inspect_dns",
    "inspect_configuration", "inspect_gateway", "inspect_target", "keep_tls", "single_epoch",
))

_NOT_TESTED = {"unsupported", "skipped", "cancelled", "not_attempted"}
_FAILURES = {"reply_timeout", "unreachable"}
_WEB = {"http", "http6", "https", "https6"}
_SCOPES = {"local", "wifi", "gateway", "wan_or_isp", "dns", "target", "unknown"}


def _integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _time(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and 0 <= value <= 1000000 and math.isfinite(value))


def _message(message_id, rows=(), **extra):
    return {"message_id": message_id, "params": {},
            "evidence_sequences": sorted({row["sequence"] for row in rows}), **extra}


def _observation(rows, excluded, part, snapshot):
    counts = dict.fromkeys(COUNTS, 0)
    counts["excluded"] = len(excluded)
    http_errors = tls_errors = 0
    for row in rows:
        outcome, data, protocol = row["outcome"], row["data"], row["protocol"]
        category = data.get("error_category")
        if protocol in _WEB and category in {"tls_validation", "tls_handshake"}:
            counts["failures"] += 1
            tls_errors += 1
        elif protocol in _WEB and (
                isinstance(data.get("http_status"), int)
                and not isinstance(data["http_status"], bool)
                and 400 <= data["http_status"] <= 599):
            counts["failures"] += 1
            http_errors += 1
        elif outcome in _NOT_TESTED:
            counts["not_tested"] += 1
        elif outcome in _FAILURES:
            # A failure before sending an ICMP request is not a missing reply.
            if protocol in {"icmp", "icmp6"} and not (
                    _integer(row.get("packets_sent")) and row.get("packets_received") == 0):
                counts["tool_errors"] += 1
            else:
                counts["failures"] += 1
        elif outcome == "success":
            valid = True
            if protocol in {"icmp", "icmp6"}:
                valid = (_integer(row.get("packets_sent"))
                         and _integer(row.get("packets_received"))
                         and row["packets_received"] <= row["packets_sent"])
            elif protocol in {"dns", "dns6"} and "addresses" in data:
                valid = isinstance(data["addresses"], list) and bool(data["addresses"])
            elif protocol in _WEB:
                code = data.get("http_status")
                valid = isinstance(code, int) and not isinstance(code, bool) and 100 <= code < 400
                if protocol.startswith("https"):
                    valid = valid and data.get("tls_verified") is True
            counts["responses" if valid else "tool_errors"] += 1
        else:
            counts["tool_errors"] += 1
    # A known tool failure or a never-sent check remains useful coverage even
    # without confirmed context. It is never counted as a network failure.
    for row in excluded:
        if row["outcome"] == "execution_error":
            counts["tool_errors"] += 1
        elif row["outcome"] in _NOT_TESTED:
            counts["not_tested"] += 1
    if counts["responses"] and counts["failures"]:
        status = "mixed"
    elif tls_errors:
        status = "tls_error"
    elif http_errors:
        status = "http_error"
    elif counts["failures"]:
        status = "failures"
    elif counts["responses"]:
        status = "responses"
    elif (part == "connectivity" and snapshot is not None
          and snapshot[1].get("available") is False):
        status = "not_configured"
    elif counts["tool_errors"]:
        status = "tool_error"
    elif counts["not_tested"] and counts["not_tested"] == len(rows) + len(excluded):
        status = "not_tested"
    elif counts["excluded"]:
        status = "no_comparable"
    else:
        status = "not_tested"
    message_id = "summary.observation." + status
    if part == "website" and status == "not_tested":
        message_id = "summary.website.not_tested"
    references = list(rows)
    if status == "not_configured":
        references.append(snapshot[0])
    # Excluded sequences are traceable coverage, never evidence for a response.
    result = _message(message_id, references, part=part, params=counts,
                      coverage_status=status,
                      excluded_evidence_sequences=sorted({row["sequence"] for row in excluded}))
    return result


def _safe_finding(finding, epoch, family, usable):
    if not isinstance(finding, dict) or finding.get("epoch_id") != epoch or finding.get("family") != family:
        return None
    scope = finding.get("scope")
    if scope not in _SCOPES:
        return None
    proof = finding.get("supporting_evidence", finding.get("evidence_sequences", []))
    if not isinstance(proof, list):
        return None
    refs = sorted({value for value in proof if _integer(value) and value in usable})
    if scope != "unknown" and (not refs or any(not _integer(value) for value in proof) or len(refs) != len(set(proof))):
        return None
    message_id = finding.get("message_id", SCOPE_MESSAGE_IDS.get(scope))
    expected_ids = {SCOPE_MESSAGE_IDS[scope]} | ({"diagnosis.target_service"} if scope == "target" else set()) | ({"diagnosis.unknown_evidence"} if scope == "unknown" else set())
    if message_id not in expected_ids:
        return None
    result = {
        "scope": scope, "epoch_id": epoch, "family": family, "message_id": message_id,
        "confidence": finding.get("confidence") if finding.get("confidence") in {"low", "medium", "high", "insufficient"} else "unknown",
        "evidence_sequences": refs, "supporting_evidence": refs,
        "contradictions": sorted({value for value in finding.get("contradictions", [])
                                if _integer(value) and value in usable}),
    }
    for key in ("alternative_message_ids", "recommendation_message_ids", "limitation_message_ids"):
        values = finding.get(key, [])
        result[key] = [value for value in values if value in DIAGNOSIS_MESSAGE_IDS] if isinstance(values, list) else []
    return result


def build_user_summary(report_dict):
    """Return safe message IDs/counts/refs without changing the source report.

    All observation totals are scoped to one recorded Epoch and address family.
    They are not fault rules or a health certificate. No raw target or identity,
    original diagnostic string or translated prose is copied into this model.
    """
    if not isinstance(report_dict, dict):
        raise ValueError("A structured session report is required")
    if (isinstance(report_dict.get("redaction"), dict)
            and report_dict["redaction"].get("applied") is True):
        raise ValueError("Build a summary from original facts before redaction")
    raw_epochs = report_dict.get("epochs") if isinstance(report_dict.get("epochs"), list) else []
    raw_rows = report_dict.get("evidence") if isinstance(report_dict.get("evidence"), list) else []
    epoch_counts = Counter(item.get("epoch_id") for item in raw_epochs[:MAX_EPOCHS]
                           if isinstance(item, dict) and _integer(item.get("epoch_id")))
    epochs = [item["epoch_id"] for item in raw_epochs[:MAX_EPOCHS] if isinstance(item, dict)
              and _integer(item.get("epoch_id")) and epoch_counts[item["epoch_id"]] == 1
              and isinstance(item.get("identity"), str) and bool(item["identity"])]
    seq_counts = Counter(row.get("sequence") for row in raw_rows[:MAX_EVIDENCE]
                         if isinstance(row, dict) and _integer(row.get("sequence")))
    scoped, usable_rows = {}, {}
    examined = raw_rows[:MAX_EVIDENCE]
    for row in examined:
        if not isinstance(row, dict) or not _integer(row.get("sequence")) or seq_counts[row["sequence"]] != 1:
            continue
        epoch, protocol, family = row.get("epoch_id"), row.get("protocol"), row.get("family")
        if protocol not in {"network", *PROTOCOLS}:
            continue
        data = row.get("data") if isinstance(row.get("data"), dict) else {}
        if protocol != "network":
            if family not in {"IPv4", "IPv6"}:
                continue
            if protocol.endswith("6") and family != "IPv6":
                continue
        confirmed_epoch = epoch in epochs
        if not confirmed_epoch:
            epoch = None
        valid = (confirmed_epoch and row.get("comparable") is True and data.get("context_status") != "UNKNOWN"
                 and _time(row.get("started_seconds")) and _time(row.get("finished_seconds"))
                 and row["started_seconds"] <= row["finished_seconds"])
        copied = {**row, "data": data, "outcome": row.get("outcome")}
        if valid:
            usable_rows[row["sequence"]] = copied
        if protocol == "network":
            for af in ("IPv4", "IPv6"):
                scoped.setdefault((epoch, af), []).append((copied, valid))
        else:
            scoped.setdefault((epoch, family), []).append((copied, valid))
    groups, supported = [], []
    totals = dict.fromkeys(COUNTS, 0)
    analysis = report_dict.get("analysis") if isinstance(report_dict.get("analysis"), dict) else {}
    findings = analysis.get("findings") if isinstance(analysis.get("findings"), list) else []
    summary_epochs = epochs + ([None] if any(key[0] is None for key in scoped) else [])
    for epoch in summary_epochs or [None]:
        for family in ("IPv4", "IPv6"):
            entries = scoped.get((epoch, family), [])
            snapshots = [row for row, valid in entries if valid and row["protocol"] == "network"
                         and row["outcome"] == "success"]
            snapshot = None
            for row in sorted(snapshots, key=lambda value: value["finished_seconds"], reverse=True):
                diagnostics = row["data"].get("diagnostics")
                families = diagnostics.get("families") if isinstance(diagnostics, dict) else {}
                configured = families.get(family) if isinstance(families, dict) else None
                if isinstance(configured, dict):
                    snapshot = row, configured
                    break
            selected = {
                "connectivity": [(row, valid) for row, valid in entries
                                 if row["protocol"] in {"icmp", "icmp6", "tcp", "tcp6"}],
                "dns": [(row, valid) for row, valid in entries if row["protocol"] in {"dns", "dns6"}],
                "gateway": [(row, valid) for row, valid in entries
                            if row["protocol"] in {"icmp", "icmp6", "tcp", "tcp6"} and row["data"].get("role") == "gateway"],
                "website": [(row, valid) for row, valid in entries if row["protocol"] in _WEB],
            }
            observations = [_observation([row for row, valid in selected[part] if valid],
                                         [row for row, valid in selected[part] if not valid], part, snapshot)
                            for part in PARTS]
            # Gateway is a subset of connectivity: never double count totals.
            for item in observations:
                if item["part"] != "gateway":
                    for key in COUNTS:
                        totals[key] += item["params"][key]
            valid_for_group = {row["sequence"] for row, valid in entries if valid}
            safe = [_safe_finding(item, epoch, family, valid_for_group) for item in findings]
            safe = [item for item in safe if item is not None]
            supported.extend(item for item in safe if item["scope"] != "unknown")
            groups.append({"epoch_id": epoch, "family": family, "observations": observations, "findings": safe})
    if supported:
        overall_id = "summary.overall.suspected"
    elif totals["failures"]:
        overall_id = "summary.overall.anomalies"
    elif totals["responses"]:
        overall_id = "summary.overall.responses"
    else:
        overall_id = "summary.overall.unknown"
    next_steps = []
    def advise(message_id, refs=(), *, epoch=None, family="UNKNOWN", coverage="partial"):
        item = _message(message_id, params={}, evidence_sequences=sorted(set(refs)),
                        epoch_id=epoch, family=family, coverage_status=coverage)
        if len(next_steps) < 3 and not any((old["message_id"], old["epoch_id"], old["family"]) ==
                                        (message_id, epoch, family) for old in next_steps):
            next_steps.append(item)
    for item in supported:
        code = {
            "local": "inspect_configuration", "wifi": "inspect_gateway", "gateway": "inspect_gateway",
            "wan_or_isp": "inspect_gateway", "dns": "inspect_dns", "target": "inspect_target",
        }[item["scope"]]
        if item["message_id"] == "diagnosis.target_service":
            code = "keep_tls"
        advise("summary.advice." + code, item["supporting_evidence"],
               epoch=item["epoch_id"], family=item["family"], coverage="supported_scope")
    for group in groups:
        for item in group["observations"]:
            if item["params"]["failures"]:
                advise("summary.advice.keep_tls" if item["coverage_status"] == "tls_error" else "summary.advice.review_failures",
                       item["evidence_sequences"], epoch=group["epoch_id"], family=group["family"],
                       coverage=item["coverage_status"])
    if all(item["coverage_status"] == "not_tested" for group in groups for item in group["observations"] if item["part"] == "website"):
        advise("summary.advice.website", coverage="not_tested")
    if len(epochs) > 1:
        advise("summary.advice.single_epoch", coverage="multiple_epochs")
    if totals["tool_errors"]:
        advise("summary.advice.review_tools", coverage="tool_error")
    incomplete = report_dict.get("incomplete") if isinstance(report_dict.get("incomplete"), list) else []
    excluded = len(examined) - len(usable_rows)
    truncated = len(raw_rows) > MAX_EVIDENCE or len(raw_epochs) > MAX_EPOCHS
    missing_coverage = any(item["coverage_status"] in {"not_tested", "no_comparable", "not_configured"}
                           for group in groups for item in group["observations"])
    totals["excluded"] = excluded
    partial = bool(incomplete or excluded or missing_coverage or totals["not_tested"] or totals["tool_errors"] or
                   report_dict.get("cleanup_errors") or report_dict.get("output_errors") or
                   report_dict.get("context_blind_spots") or truncated or not usable_rows)
    if partial:
        advise("summary.advice.review_coverage", coverage="partial")
    reasons = []
    if incomplete:
        reasons.append("reason_unavailable")  # No parsing of arbitrary diagnostic text.
    if totals["not_tested"] or any(item["coverage_status"] == "not_tested" for group in groups for item in group["observations"]):
        reasons.append("not_tested")
    if totals["tool_errors"] or report_dict.get("cleanup_errors") or report_dict.get("output_errors"):
        reasons.append("tool_error")
    if excluded or not usable_rows:
        reasons.append("not_comparable")
    if report_dict.get("context_blind_spots"):
        reasons.append("context_blind_spots")
    if len(epochs) > 1:
        reasons.append("multiple_epochs")
    if truncated:
        reasons.append("truncated")
    coverage_ids = ["summary.coverage.partial" if partial else "summary.coverage.complete"]
    if len(epochs) > 1:
        coverage_ids.append("summary.coverage.multiple_epochs")
    return {
        "schema_version": 1,
        "overall": _message(overall_id, usable_rows.values(), params=totals, coverage_codes=reasons),
        "groups": groups, "next_steps": next_steps,
        "coverage": {"message_id": coverage_ids[0], "message_ids": coverage_ids,
                     "params": {"incomplete_count": len(incomplete), "excluded_count": excluded},
                     "reason_codes": reasons, "epoch_count": len(epochs)},
    }
