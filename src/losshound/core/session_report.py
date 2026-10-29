"""Current-session report redaction; no file reads or active diagnostics.

Redaction preserves report-local associations, not an anonymity guarantee.
Raw diagnostic text is deliberately removed; keep the original explicitly if needed.
"""
from __future__ import annotations

from copy import deepcopy
import ipaddress
import re
from urllib.parse import urlsplit

from losshound.core.session_diagnosis import DIAGNOSIS_MESSAGE_IDS
from losshound.core.session_summary import COVERAGE_REASON_CODES, SUMMARY_MESSAGE_IDS

# Only exact enums in these exact fields bypass free-text alias substitution.
# Raw diagnostic/private fields never receive an exemption.
_SAFE_CODES = {
    "protocol": {"network", "icmp", "icmp6", "dns", "dns6", "tcp", "tcp6", "http", "http6", "https", "https6"},
    "family": {"IPv4", "IPv6", "UNKNOWN"},
    "outcome": {"success", "reply_timeout", "unreachable", "execution_error", "unsupported", "skipped", "cancelled", "not_attempted"},
    "contextstatus": {"KNOWN", "UNKNOWN", "IDENTIFIED"},
    "status": {"KNOWN", "UNKNOWN", "IDENTIFIED", "READY", "configured", "incomplete", "unknown", "success", "unavailable", "unsupported",
               "completed", "deadline", "cancelled", "execution_error", "cleanup_failed",
               "pending", "confirmed", "not_confirmed", "rejected", "not_started",
               "simulated_success", "simulated_failure", "simulated_tool_error", "declined", "not_attempted",
               "observed_dns_improvement", "no_dns_improvement_observed",
               "inconclusive", "failed", "timed_out", "permission_denied", "not_executed"},
    "continuity": {"OBSERVED", "UNKNOWN"},
    "change": {"improved", "worsened", "inconclusive", "unchanged_success", "unchanged_failure", "unchanged_service_error"},
    "scope": {"local", "wifi", "gateway", "wan_or_isp", "dns", "target", "unknown"},
    "category": {"lan_issue", "isp_wan_issue", "dns_issue", "unknown"},
    "confidence": {"low", "medium", "high", "unknown", "insufficient"},
    "role": {"local", "gateway", "public", "dns", "target", "unknown"},
    "source": {"os_resolver"},
    "targetscope": {"localhost", "non_localhost"},
    "errorcategory": {"tls_validation", "tls_handshake", "http_status", "timeout",
                      "network_unreachable", "host_unreachable", "connection_refused", "os_error"},
    "part": {"connectivity", "dns", "gateway", "website"},
    "coveragestatus": {"responses", "mixed", "failures", "not_tested", "tool_error",
                       "no_comparable", "not_configured", "http_error", "tls_error",
                       "partial", "complete", "supported_scope", "multiple_epochs"},
    "reasoncode": COVERAGE_REASON_CODES,
    "reasoncodes": COVERAGE_REASON_CODES,
    "coveragecodes": COVERAGE_REASON_CODES,
    "contextfields": {"context.diagnostics.families.IPv4", "context.diagnostics.families.IPv6",
                      "context.diagnostics.wifi"},
}
_MESSAGE_FIELDS = {
    "messageid", "messageids", "alternativemessageids", "recommendationmessageids",
    "limitationmessageids", "scopeobservationmessageid", "intermittentobservationmessageid",
}
_MESSAGE_IDS = DIAGNOSIS_MESSAGE_IDS | SUMMARY_MESSAGE_IDS


def _safe_code(field, value):
    return (type(value) is str and
            (value in _MESSAGE_IDS if field in _MESSAGE_FIELDS else value in _SAFE_CODES.get(field, ())))

_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?:%[\w.-]+)?(?:/\d{1,3})?(?![\w:])")
_MAC = re.compile(r"(?<![\w:.-])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![\w:.-])")
_HOST = re.compile(r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]{0,62}(?![\w.-])")
_PRIVATE_KEYS = {
    "ssid", "bssid", "mac", "macaddress", "name", "description", "alias",
    "interfacename", "interfacealias", "interfaceguid", "guid", "profile",
    "identity", "hostname", "computername", "username", "ssidhex",
}
_RAW_KEYS = {
    "errordata", "errorrecord", "powershellerror", "headers", "requestheaders",
    "responseheaders", "authorization", "cookie", "credentials", "body",
}
_DETAIL_KEYS = {
    "error", "errors", "exceptionmessage", "incomplete", "cleanuperrors",
    "outputerrors", "fullyqualifiederrorid",
}
_CONTEXT_VALUES = {
    "KNOWN", "UNKNOWN", "IDENTIFIED", "IPv4", "IPv6", "Up", "Down",
    "Connected", "Disconnected", "Preferred", "Deprecated", "Tentative",
    "Invalid", "Duplicate", "WellKnown", "Manual", "Dhcp",
    "RouterAdvertisement", "Unicast", "unknown", "success", "unavailable",
    "unsupported", "os_resolver", "localhost", "non_localhost",
}


def redact_report(report_dict) -> dict:
    """Return a local, irreversibly redacted copy after diagnosis is complete.

    IPs, names and targets receive consistent aliases within this report only.
    Raw context strings and diagnostic errors are removed or replaced. This
    reduces disclosure; timing, topology and remaining facts can still identify
    an environment. No mapping is exported and no file is changed.
    """
    if not isinstance(report_dict, dict):
        raise ValueError("A session report must be an object")
    report = deepcopy(report_dict)
    aliases, replacements, counts = {}, {}, {}
    removed = set()

    def alias(raw, kind="value"):
        raw = str(raw)
        if not raw:
            return raw
        key = raw
        try:
            address = ipaddress.ip_network(raw, strict=False) if "/" in raw else ipaddress.ip_address(raw)
            kind, key = ("network" if "/" in raw else "address"), str(address)
        except ValueError:
            if _MAC.fullmatch(raw):
                kind, key = "mac", raw.lower().replace("-", ":")
            elif kind == "host" or _HOST.fullmatch(raw.rstrip(".")):
                kind, key = "host", raw.rstrip(".").lower()
        identity = kind, key
        if identity not in aliases:
            counts[kind] = counts.get(kind, 0) + 1
            aliases[identity] = f"[{kind}-{counts[kind]}]"
        replacements[raw] = aliases[identity]
        return aliases[identity]

    def target(raw):
        raw = str(raw)
        if not raw:
            return raw
        try:
            if "://" in raw:
                url = urlsplit(raw)
                if not url.hostname:
                    return alias(raw, "target")
                host = alias(url.hostname, "host")
                port = f":{url.port}" if url.port is not None else ""
                result = f"{url.scheme.lower()}://{host}{port}"
            else:
                try:
                    ipaddress.ip_address(raw)
                    return alias(raw, "address")
                except ValueError:
                    pass
                parsed = urlsplit("//" + raw)
                if parsed.hostname and (parsed.port is not None or _HOST.fullmatch(raw.rstrip("."))):
                    host = alias(parsed.hostname, "host")
                    result = host + (f":{parsed.port}" if parsed.port is not None else "")
                else:
                    kind = "host" if re.fullmatch(r"[A-Za-z0-9_-]+", raw) else "target"
                    return alias(raw, kind)
        except ValueError:
            return alias(raw, "target")
        replacements[raw] = result
        return result

    def normal(key):
        return key.replace("_", "").replace("-", "").lower()

    def is_raw(key):
        return key in _RAW_KEYS or "stdout" in key or "stderr" in key or "rawbase64" in key

    def collect(value, key="", context=False):
        field = normal(key)
        if is_raw(field) or field in _DETAIL_KEYS:
            return
        if _safe_code(field, value):
            return
        context = context or field == "context"
        if isinstance(value, dict):
            for child_key, child in value.items():
                collect(child, child_key, context)
        elif isinstance(value, list):
            for child in value:
                collect(child, key, context)
        elif isinstance(value, str):
            if field in {"target", "targethost"} or field.endswith("url"):
                target(value)
            elif field in _PRIVATE_KEYS:
                alias(value, field)
            elif context and value not in _CONTEXT_VALUES:
                alias(value, "context")

    collect(report)
    known = dict(replacements)
    patterns = [re.escape(raw) if len(raw) >= 3 else r"(?<!\w)" + re.escape(raw) + r"(?!\w)"
                for raw in sorted(known, key=len, reverse=True)]
    pattern = re.compile("|".join(patterns)) if patterns else None

    def text(value):
        value = _URL.sub(lambda match: target(match.group()), value)
        if pattern is not None:
            value = pattern.sub(lambda match: known[match.group()], value)
        value = _MAC.sub(lambda match: alias(match.group(), "mac"), value)
        value = _IPV4.sub(lambda match: alias(match.group(), "address"), value)
        value = _IPV6.sub(lambda match: alias(match.group(), "address"), value)
        return _HOST.sub(lambda match: alias(match.group(), "host"), value)

    def redact(value, key="", context=False):
        field = normal(key)
        context = context or field == "context"
        if field in _DETAIL_KEYS and value is not None:
            removed.add(field)
            if isinstance(value, list):
                return ["[redacted diagnostic detail]" for _ in value]
            return "[redacted diagnostic detail]"
        if isinstance(value, dict):
            result = {}
            for child_key, child in value.items():
                if is_raw(normal(child_key)):
                    removed.add(normal(child_key))
                    continue
                result[child_key] = redact(child, child_key, context)
            return result
        if isinstance(value, list):
            return [redact(child, key, context) for child in value]
        if not isinstance(value, str):
            return value
        if field in {"target", "targethost"} or field.endswith("url"):
            return target(value)
        if field in _PRIVATE_KEYS:
            return alias(value, field)
        if _safe_code(field, value):
            return value
        if context and value not in _CONTEXT_VALUES:
            return alias(value, "context")
        return text(value)

    result = redact(report)
    result["redaction"] = {
        "applied": True,
        "scope": "Report-local aliases; original input unchanged",
        "reversible": False,
        "removed_fields": sorted(removed),
        "limitations": [
            "This is not a guarantee of anonymity; timing, topology and remaining facts can identify an environment.",
            "Raw diagnostic text and private context values are removed or aliased; they cannot be recovered from this copy.",
            "Alias meanings are local to this report and must not be compared across reports.",
        ],
    }
    return result
