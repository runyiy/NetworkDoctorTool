"""Interpret only one finite session's evidence; no I/O, collection or repair.

The legacy Diagnosis vocabulary is retained through category/explanation/
confidence/evidence fields. Legacy observations and stored history are not read.
"""
from __future__ import annotations

from collections import defaultdict
import ipaddress
import math
from urllib.parse import urlsplit

MAX_EVIDENCE = 512
MAX_EPOCHS = 64
MAX_FINDINGS = 32
MAX_INTERMITTENT = 32
MAX_REFERENCES = 32
REPEAT_SAMPLES = 2
COMPARISON_WINDOW_SECONDS = 30.0
PROTOCOLS = {name + suffix: (name, suffix == "6")
             for name in ("icmp", "dns", "tcp", "http", "https")
             for suffix in ("", "6")}
WINDOW_LIMIT = "仅解释本轮同一网络环境和地址族的有限窗口；置信等级不是概率，也不证明根因。"
DNS_LIMIT = "系统解析可能来自 hosts 或缓存；未观察 DNS 线上数据包，不能确认某台 DNS 服务器故障。"
CATEGORIES = {"local": "lan_issue", "wifi": "lan_issue", "gateway": "lan_issue",
              "wan_or_isp": "isp_wan_issue", "dns": "dns_issue"}


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value, limit=1024):
    return value if isinstance(value, str) and 0 < len(value) <= limit else ""


def _time(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1000000 and math.isfinite(value)


def _ip(value):
    try:
        return str(ipaddress.ip_address(value)) if _text(value, 253) else None
    except ValueError:
        return None


def _category(row):
    return _text(row["data"].get("error_category"), 32)


def _response(row):
    if row["protocol"] not in ("tcp", "http", "https"):
        return False
    data = row["data"]
    status = data.get("http_status")
    return ((_int(status) and 100 <= status <= 599)
            or _category(row) in ("connection_refused", "tls_validation", "tls_handshake", "http_status"))


def _good(row):
    if row["outcome"] in ("cancelled", "unsupported", "skipped", "not_attempted", ""):
        return False
    if row["protocol"] != "dns" and _response(row):
        return True  # Reachability evidence, not successful application service.
    if row["outcome"] != "success":
        return False
    if row["protocol"] != "icmp":
        return True
    sent, received = row["sent"], row["received"]
    return _int(sent) and _int(received) and 0 < received <= sent


def _bad(row):
    if row["outcome"] not in ("reply_timeout", "unreachable") or _response(row):
        return False
    category = _category(row)
    if category == "os_error" and (row["data"].get("errno") in (10051, 10065, 101, 113) or row["data"].get("winerror") in (10051, 10065)):
        category = "network_unreachable"
    if category not in ("", "timeout", "network_unreachable", "host_unreachable"):
        return False
    if row["protocol"] != "icmp":
        return True
    return _int(row["sent"]) and row["sent"] > 0 and row["received"] == 0 and _int(row["received"])


def _rows(raw_rows, epochs):
    rows, seen, duplicate = [], set(), set()
    for raw in raw_rows[:MAX_EVIDENCE]:
        if not isinstance(raw, dict):
            continue
        seq, epoch = raw.get("sequence"), raw.get("epoch_id")
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        proto = _text(raw.get("protocol"), 16).lower()
        target = _text(raw.get("target"))
        if (not _int(seq) or seq <= 0 or not _int(epoch) or epoch not in epochs
                or raw.get("comparable") is not True or data.get("context_status") == "UNKNOWN"):
            continue
        if seq in seen:
            duplicate.add(seq)
        seen.add(seq)
        if proto == "network":
            protocol, family, host, address = "network", "UNKNOWN", "local_network", None
        else:
            info = PROTOCOLS.get(proto)
            if info is None or not target:
                continue
            protocol, v6 = info
            family = {"ipv4": "IPv4", "ipv6": "IPv6"}.get(_text(raw.get("family"), 16).lower())
            family = family or ("IPv6" if v6 else None)
            if not family or (v6 and family != "IPv6"):
                continue
            try:
                parsed = urlsplit(target if protocol in ("http", "https") else "tcp://" + target) if protocol in ("tcp", "http", "https") else None
                if parsed and (parsed.username or parsed.password):
                    continue
                parsed_host = parsed.hostname if parsed else target.strip("[]")
            except ValueError:
                continue
            host = (_text(data.get("target_host"), 253) or parsed_host or "").rstrip(".").lower()
            if not host:
                continue
            address = _ip(data.get("resolved_ip")) or _ip(parsed_host)
            if address and ("IPv" + str(ipaddress.ip_address(address).version)) != family:
                continue
        role = _text(data.get("role"), 16)
        role = role if role in ("local", "gateway", "public", "dns", "target") else "unknown"
        start, end = raw.get("started_seconds"), raw.get("finished_seconds")
        timed = _time(start) and _time(end) and start <= end
        rows.append({"sequence": seq, "epoch": epoch, "protocol": protocol, "family": family,
                     "target": target, "host": host, "address": address, "role": role,
                     "outcome": _text(raw.get("outcome"), 32), "data": data,
                     "sent": raw.get("packets_sent"), "received": raw.get("packets_received"),
                     "start": float(start) if timed else None, "end": float(end) if timed else None})
    return [row for row in rows if row["sequence"] not in duplicate], bool(duplicate)


def _repeat(rows, good):
    groups = defaultdict(list)
    for row in rows:
        # A hostname must have a known same destination for transport comparison.
        endpoint = row["host"] if row["protocol"] == "dns" else row["address"]
        if endpoint is not None:
            groups[(row["protocol"], row["target"], endpoint)].append(row)
    proof = []
    for values in groups.values():
        matching = [row for row in values if (_good(row) if good else _bad(row))]
        opposite = any((_bad(row) if good else _good(row)) for row in values)
        if len(matching) >= REPEAT_SAMPLES and not opposite:
            proof.extend(matching[:REPEAT_SAMPLES])
    return proof


def _public(row):
    try:
        address = ipaddress.ip_address(row["address"])
        return (address.is_global and not address.is_private and not address.is_loopback
                and not address.is_link_local and not address.is_multicast
                and not address.is_unspecified and not address.is_reserved
                and not getattr(address, "is_site_local", False)
                and getattr(address, "ipv4_mapped", None) is None)
    except (ValueError, TypeError):
        return False


def _cross(rows, targets=1):
    protocols = defaultdict(set)
    for row in rows:
        if row["protocol"] not in ("dns", "network") and row["address"]:
            protocols[row["address"]].add(row["protocol"])
    return sum(len(values) >= 2 for values in protocols.values()) >= targets


def _refs(rows):
    return sorted({row["sequence"] for row in rows})[:MAX_REFERENCES]


def _finding(scope, key, proof, contradictions, explanation, alternatives, recommendations, *, fields=(), confidence="low"):
    references = _refs(proof)
    counters = [value for value in _refs(contradictions) if value not in references]
    starts = [row["start"] for row in proof if row["start"] is not None]
    ends = [row["end"] for row in proof if row["end"] is not None]
    return {"scope": scope, "category": CATEGORIES.get(scope, "unknown"),
            "family": key[1], "epoch_id": key[0], "confidence": confidence,
            "supporting_evidence": references, "evidence_sequences": references,
            "contradictions": counters, "context_fields": list(fields),
            "window": {"started_seconds": min(starts) if starts else None,
                       "finished_seconds": max(ends) if ends else None},
            "explanation": explanation, "alternatives": list(alternatives),
            "limitations": [WINDOW_LIMIT], "recommendations": list(recommendations)}


def _intermittent(rows):
    groups, result = defaultdict(list), []
    for row in rows:
        if row["protocol"] != "network" and row["start"] is not None:
            endpoint = row["host"] if row["protocol"] == "dns" else row["address"]
            if endpoint:
                groups[(row["epoch"], row["family"], row["protocol"], row["target"], endpoint)].append(row)
    for key, values in groups.items():
        baseline, failures = None, []
        for row in sorted(values, key=lambda item: item["sequence"]):
            if baseline and (row["start"] < baseline["start"] or row["end"] - baseline["start"] > COMPARISON_WINDOW_SECONDS):
                baseline, failures = None, []
            if row["outcome"] == "success" and _good(row):
                if baseline and failures:
                    proof = [baseline, *failures, row]
                    result.append({"epoch_id": key[0], "family": key[1], "protocol": key[2],
                                   "target": key[3], "resolved_ip": key[4] if key[2] != "dns" else None,
                                   "evidence_sequences": _refs(proof), "supporting_evidence": _refs(proof),
                                   "contradictions": [], "confidence": "medium",
                                   "window": {"started_seconds": baseline["start"], "finished_seconds": row["end"]},
                                   "explanation": "同一环境、地址族、实际目标和协议在新鲜窗口内出现成功、网络响应失败、再次成功。",
                                   "alternatives": ["暂时的目标响应策略或路径变化也可能产生这一序列，不能确认根因。"],
                                   "limitations": [WINDOW_LIMIT, "再次响应不代表彻底修复。", *([DNS_LIMIT] if key[2] == "dns" else [])],
                                   "recommendations": ["保留该序列，必要时由用户另行选择有限窗口进行对照。"]})
                    if len(result) == MAX_INTERMITTENT:
                        return result
                baseline, failures = row, []
            elif _bad(row) and baseline:
                failures.append(row)
            else:
                baseline, failures = None, []
    return result


def analyze_report(report_dict: dict) -> dict:
    """Return bounded interpretation, retaining uncertainty and input unchanged."""
    report = report_dict if isinstance(report_dict, dict) else {}
    raw_epochs = report.get("epochs") if isinstance(report.get("epochs"), list) else []
    evidence = report.get("evidence") if isinstance(report.get("evidence"), list) else []
    epochs, duplicate_epochs = {}, set()
    for raw in raw_epochs[:MAX_EPOCHS]:
        if not isinstance(raw, dict) or not _int(raw.get("epoch_id")) or raw["epoch_id"] <= 0 or not _text(raw.get("identity"), 256):
            continue
        if raw["epoch_id"] in epochs:
            duplicate_epochs.add(raw["epoch_id"])
        epochs[raw["epoch_id"]] = raw.get("context") if isinstance(raw.get("context"), dict) else {}
    for epoch in duplicate_epochs:
        epochs.pop(epoch, None)
    rows, duplicates = _rows(evidence, epochs)
    truncated = len(evidence) > MAX_EVIDENCE or len(raw_epochs) > MAX_EPOCHS
    limitations = [WINDOW_LIMIT, "范围线索要求每协议/实际目标至少2次一致观察，使用每环境和地址族最后30秒的证据；这不是健康认证。"]
    if truncated:
        limitations.append("输入超过分析上限，停止范围推断与间歇性判定，保留 UNKNOWN。")
    if duplicates or duplicate_epochs:
        limitations.append("重复的证据序号或环境编号已排除，不能当作独立重复样本。")
    if report.get("incomplete"):
        limitations.append("采集存在未完成项目；未测、工具错误、取消及不支持不能视作失败或成功。")
    if report.get("context_blind_spots"):
        limitations.append("网络环境观察存在盲区，只使用明确可比较的同环境证据。")
    if any(row["protocol"] == "dns" for row in rows):
        limitations.append(DNS_LIMIT)
    findings, groups = [], defaultdict(list)
    for row in rows:
        if row["protocol"] != "network":
            groups[(row["epoch"], row["family"])].append(row)
    for epoch, context in epochs.items():
        diagnostics = context.get("diagnostics") if isinstance(context.get("diagnostics"), dict) else {}
        families = diagnostics.get("families") if isinstance(diagnostics.get("families"), dict) else {}
        for family in ("IPv4", "IPv6"):
            configured = families.get(family)
            if isinstance(configured, dict) and configured.get("available") is False:
                groups.setdefault((epoch, family), [])
    for key, group in groups.items():
        if len(findings) >= MAX_FINDINGS:
            break
        before = len(findings)
        timed = [row for row in group if row["start"] is not None]
        snapshots = [row for row in rows if row["epoch"] == key[0] and row["protocol"] == "network"
                     and row["outcome"] == "success" and row["start"] is not None]
        anchor = max((row["end"] for row in timed + snapshots), default=0)
        recent = [row for row in timed if row["start"] >= anchor - COMPARISON_WINDOW_SECONDS]
        snapshots = [row for row in snapshots if row["start"] >= anchor - COMPARISON_WINDOW_SECONDS]
        context = snapshots[-1]["data"] if snapshots else epochs[key[0]]
        diagnostics = context.get("diagnostics") if isinstance(context.get("diagnostics"), dict) else {}
        families = diagnostics.get("families") if isinstance(diagnostics.get("families"), dict) else {}
        configured = families.get(key[1]) if isinstance(families.get(key[1]), dict) else {}
        available = configured.get("available")
        by_role = {role: [row for row in recent if row["role"] == role and row["protocol"] != "dns" and (role != "public" or _public(row))]
                   for role in ("gateway", "public", "target")}
        good = {role: _repeat(values, True) for role, values in by_role.items()}
        bad = {role: _repeat(values, False) for role, values in by_role.items()}
        public_good = _cross(good["public"], 2)
        public_bad = _cross(bad["public"], 2) and not any(_good(row) for row in by_role["public"])
        gateway_good = bool(good["gateway"]) and not any(_bad(row) for row in by_role["gateway"])
        gateway_bad = bool(bad["gateway"]) and not any(_good(row) for row in by_role["gateway"])
        positive = [row for row in recent if _good(row)]
        if not truncated:
            if snapshots and available is False and not any(_good(row) for row in by_role["public"]):
                findings.append(_finding("local", key, snapshots[-1:], [row for row in by_role["public"] if _good(row)],
                    "该地址族的静态摘要未同时具备可用地址与默认路由，限制了该族的外网路径。",
                    ["单栈配置可能是正常选择，缺少 IPv6 默认路由不代表 IPv4 或整个网络故障。"],
                    ["核对该地址族的地址与默认路由记录，分别查看另一地址族的证据。"],
                    fields=("context.diagnostics.families." + key[1],), confidence="medium"))
            if gateway_bad and public_bad:
                findings.append(_finding("gateway", key, bad["gateway"] + bad["public"], [row for row in by_role["gateway"] if _good(row)],
                    "到网关和多个公网基线目标出现重复响应失败，线索涉及本机到网关及其邻近路径。",
                    ["网关可能限制 ICMP；本机链路问题与独立上游故障也可能同时存在。"],
                    ["对照连接介质、网关设备状态和这些同窗口证据，保持网络配置不变。"]))
                wifi = diagnostics.get("wifi", context.get("wifi"))
                wifi = [wifi] if isinstance(wifi, dict) else wifi if isinstance(wifi, list) else []
                route = configured.get("default_route")
                interface = route.get("interface_index") if isinstance(route, dict) else None
                for item in wifi[:8]:
                    if not isinstance(item, dict) or interface is None or item.get("interface_index") != interface:
                        continue
                    signal = item.get("signal_quality", item.get("signal_percent"))
                    if _time(signal) and signal < 30 and item.get("state") in (1, "connected", "associated") and snapshots:
                        findings.append(_finding("wifi", key, snapshots[-1:] + bad["gateway"], [row for row in by_role["gateway"] if _good(row)],
                            "相同路由接口记录了偏弱无线信号，并出现网关路径失败，Wi-Fi 是待核对范围之一。",
                            ["弱信号可能与故障无关，网关响应策略、本机或上游路径仍可能影响结果。"],
                            ["查看对应无线信号和链路记录，必要时由用户另选位置进行有限窗口比较。"],
                            fields=("context.diagnostics.wifi",), confidence="low"))
                        break
            elif gateway_good and public_bad and available is True:
                findings.append(_finding("wan_or_isp", key, good["gateway"] + bad["public"], [row for row in by_role["public"] if _good(row)],
                    "网关重复响应，但多个公网目标在多协议下重复失败；WAN/ISP 路径仅为疑似范围。",
                    ["网关出口、防火墙、中间路径和目标侧响应策略均可能产生相同证据；不能确认 ISP 故障。"],
                    ["保留证据并核对网关出口状态，必要时提供同窗口结果供服务商对照。"]))
            if public_good:
                dns_rows = [row for row in recent if row["protocol"] == "dns" and row["role"] in ("dns", "target")]
                dns_bad = _repeat(dns_rows, False)
                if dns_bad and not any(_good(row) for row in dns_rows):
                    item = _finding("dns", key, dns_bad + good["public"], [row for row in dns_rows if _good(row)],
                        "公网基线有多协议响应，系统名称解析却重复失败，解析路径是疑似范围。",
                        ["本机解析配置、hosts、缓存、名称本身及解析服务均可能影响结果。"],
                        ["核对原始系统解析错误和既有解析配置，需变更时另行确认。"])
                    item["limitations"].append(DNS_LIMIT)
                    findings.append(item)
                by_destination = defaultdict(list)
                for row in by_role["target"]:
                    if row["address"]:
                        by_destination[(row["host"], row["address"])].append(row)
                for target_rows in by_destination.values():
                    failing = _repeat(target_rows, False)
                    if _cross(failing) and not any(_good(row) for row in target_rows):
                        findings.append(_finding("target", key, failing + good["public"], [row for row in target_rows if _good(row)],
                            "公网基线有重复响应，而同一指定目标实际地址在多协议下重复失败。",
                            ["目标服务、目标侧策略或到该地址的路径可能有差异，不能据此判断整网故障。"],
                            ["对照该目标服务状态与证据中的实际地址、端口和协议。"]))
            by_destination = defaultdict(list)
            for row in by_role["target"]:
                if row["address"]:
                    by_destination[(row["host"], row["address"])].append(row)
            for target_rows in by_destination.values():
                tcp_good = _repeat([row for row in target_rows if row["protocol"] == "tcp"], True)
                web_errors = [row for row in target_rows if row["protocol"] in ("http", "https")
                              and (_category(row) in ("tls_validation", "tls_handshake", "http_status")
                                   or (_int(row["data"].get("http_status")) and row["data"]["http_status"] >= 400))]
                if tcp_good and len(web_errors) >= 2 and len({(row["protocol"], row["target"], _category(row), row["data"].get("http_status") if _int(row["data"].get("http_status")) else None) for row in web_errors}) == 1:
                    findings.append(_finding("target", key, tcp_good + web_errors[:2], [row for row in target_rows if row["protocol"] in ("http", "https") and row["outcome"] == "success" and not _category(row) and (_int(row["data"].get("http_status")) and row["data"]["http_status"] < 400)],
                        "同一目标实际地址有 TCP 响应，同时 HTTP 状态或 TLS 握手/验证重复报错。",
                        ["服务状态、授权、应用协议或 TLS 配置问题不同于网络不可达，不能据此归因 ISP。"],
                        ["查看对应服务或协议错误，并保持 TLS 证书验证启用。"], confidence="medium"))
        if len(findings) == before:
            findings.append(_finding("unknown", key, [row for row in recent if not _good(row)], positive,
                "证据不足或存在反证，未满足新鲜、同环境、同地址族、实际地址与多协议重复对照条件。",
                ["目标策略、暂时异常、未测与工具限制可能影响观察。"],
                ["先查看未完成项与原始证据，必要时由用户另选有限窗口诊断。"]))
    if not findings:
        findings.append(_finding("unknown", (None, "UNKNOWN"), [], [],
            "缺少可比较的同环境证据，不能判断健康或故障原因。",
            ["采集未开始、环境未知或工具不可用均可能造成证据缺失。"],
            ["查看采集状态和未完成项，再决定是否另行诊断。"]))
    intermittent = [] if truncated else _intermittent(rows)
    limitations.append("没有可关联当前路由接口的直接 Wi-Fi 信号/链路证据时，不作无线根因判断。")
    if len(findings) > MAX_FINDINGS:
        limitations.append("发现项已达到输出上限，其余范围未评价。")
    return {"schema_version": 1, "findings": findings[:MAX_FINDINGS], "intermittent": intermittent,
            "limitations": limitations, "coverage": {
                "input_evidence_count": len(evidence), "examined_evidence_count": min(len(evidence), MAX_EVIDENCE),
                "comparable_evidence_count": len(rows), "excluded_evidence_count": min(len(evidence), MAX_EVIDENCE) - len(rows),
                "epoch_count": len(epochs), "truncated": truncated,
                "comparison_window_seconds": COMPARISON_WINDOW_SECONDS,
                "repeat_samples_per_protocol_target": REPEAT_SAMPLES,
                "scope_observation": "范围推断受限。" if truncated else "仅对最后一个新鲜窗口给出保守范围线索。",
                "intermittent_observation": "覆盖受限，未评价。" if truncated else
                    "本轮观察到间歇性序列。" if intermittent else "本轮未观察到符合条件的序列；不等于健康或彻底恢复。"}}
