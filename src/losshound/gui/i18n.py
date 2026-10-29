"""Local UI messages and a separate, atomic language-only preference."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from losshound.core.config import _app_data_dir

LANGUAGES = ("zh-CN", "en")
DEFAULT_LANGUAGE = "zh-CN"
# Translation IDs never participate in diagnostic decisions.
MESSAGES = {
    "window.title": ("Losshound - 网络诊断", "Losshound - Network Diagnosis"),
    "header.subtitle": ("网络诊断", "NETWORK DIAGNOSIS"),
    "ui.language": ("界面语言", "Language"),
    "ui.section": ("只读网络诊断", "READ-ONLY NETWORK DIAGNOSIS"),
    "ui.description": ("各协议共用有限预算，包含清理；不会修改网络设置。独立验证复用本轮目标。", "Protocols share a finite budget including cleanup. No network settings are changed. Independent verification reuses the completed diagnosis targets."),
    "ui.website": ("检测网站（可选）", "Website for next diagnosis (optional)"),
    "ui.website.accessible": ("可选的 HTTP 或 HTTPS 诊断目标", "Optional HTTP or HTTPS diagnosis target"),
    "ui.budget": ("诊断预算", "Diagnostic budget"),
    "ui.budget.accessible": ("诊断总预算（秒）", "Diagnostic total budget in seconds"),
    "ui.seconds": (" 秒", " seconds"),
    "ui.start": ("开始诊断", "Start diagnosis"),
    "ui.cancel": ("取消", "Cancel"),
    "ui.save": ("保存脱敏 JSON", "Save redacted JSON"),
    "ui.summary": ("用户摘要", "User summary"),
    "ui.summary.placeholder": ("点击“开始诊断”后查看观察结果、覆盖范围和下一步。", "Start a diagnosis to see observations, coverage and next steps."),
    "ui.details.show": ("查看技术详情", "Show technical details"),
    "ui.details.hide": ("收起技术详情", "Hide technical details"),
    "ui.details.placeholder": ("这里显示证据编号、协议记录、反证及局限。", "Protocol evidence, fault explanations and uncertainty appear here."),
    "ui.repair.note": ("DNS 缓存方案：仅模拟。原缓存不能原样恢复；真实修复不可用，诊断绝不自动修复。", "DNS cache plan: simulation only. The original cache cannot be restored exactly. Real repair is unavailable; diagnosis never starts a repair."),
    "ui.simulate": ("预览并确认模拟", "Preview and confirm simulation"),
    "ui.verify.budget": ("独立验证预算", "Independent verification budget"),
    "ui.verify.accessible": ("独立验证总预算（秒）", "Independent verification total budget in seconds"),
    "ui.verify": ("开始独立验证", "Run independent verification"),
    "ui.real.disabled": ("真实修复不可用", "Real repair unavailable"),
    "ui.repair.placeholder": ("仅模拟。尚未执行模拟或独立验证。", "SIMULATION ONLY. No repair or verification has run."),
    "ui.preference.failed": ("语言已切换，但无法记住此选择。", "Language changed, but the preference could not be saved."),
    "state.ready": ("尚未开始；没有检测或后台监控在运行。", "Ready. No checks have run; no background monitoring is active."),
    "state.collecting": ("正在收集只读多协议证据……", "Collecting read-only multi-protocol evidence..."),
    "state.progress": ("正在收集只读证据，已取得 {count} 条。", "Collecting read-only evidence: {count} items collected."),
    "state.cancelling": ("正在取消：停止自有探测，并保留部分证据……", "Cancelling: stopping owned probes and preparing partial evidence..."),
    "state.session": ("本轮{status}。结论仅适用于本次观察窗口。", "Session {status}. Conclusions are limited to this observation window."),
    "state.simulation": ("仅模拟，未真实清空 DNS 缓存；独立观察另行执行。", "SIMULATION ONLY. No real DNS cache clearing; independent observations are separate."),
    "state.simulating": ("仅模拟：执行单独确认的数据模拟操作……", "SIMULATION ONLY: running the separately confirmed data-only operation..."),
    "state.verifying": ("正在独立只读验证，不会执行修复。", "Read-only independent verification. No repair will run."),
    "state.start.error": ("无法开始诊断：{kind}", "Cannot start session: {kind}"),
    "state.worker.error": ("无法启动工作线程：{kind}", "Cannot start worker: {kind}"),
    "state.report.error": ("报告呈现失败：{kind}", "Report presentation error: {kind}"),
    "state.repair.error": ("模拟结果不可用：{kind}", "Simulation result unavailable: {kind}"),
    "state.simulate.error": ("无法准备模拟：{kind}", "Cannot prepare simulation: {kind}"),
    "state.verify.error": ("无法启动验证：{kind}", "Cannot start verification: {kind}"),
    "state.tool.error": ("工具错误：{kind}；不能据此判断网络故障。", "Tool error: {kind}; this is not a network failure verdict."),
    "state.cleanup.pending": ("清理尚未完成；工作线程仍被保留。", "Cleanup has not completed; session worker is still retained."),
    "remaining.current": ("剩余：{seconds} 秒", "Remaining: {seconds} seconds"),
    "remaining.finished": ("结束时剩余：{seconds} 秒", "Remaining at finish: {seconds} seconds"),
    "remaining.not_started": ("工作线程未启动。", "Worker did not start."),
    "remaining.worker_finished": ("工作线程已结束，未执行真实修复。", "Worker finished. No real repair was performed."),
    "dialog.confirm.title": ("仅确认模拟", "Confirm simulation only"),
    "dialog.confirm.body": ("仅模拟 Windows 本机 DNS 缓存清理，不运行命令，也不改变缓存。真实清理会使后续解析重新查询，短时可能更慢。\n\n原缓存不能原样恢复，没有回滚。\n\n模拟无需提权或系统修改；真实修复须单独授权。\n独立验证预算：{seconds} 秒，须另行点击启动。\n\n是否明确知晓上述影响及不可原样恢复限制，并执行此次模拟？", "Simulate only the Windows local DNS resolver-cache operation. No command runs and no cache changes. Real clearing would make subsequent lookups query again and briefly take longer.\n\nThe original DNS cache contents cannot be restored exactly. No rollback is provided.\n\nSimulation requires no elevation or system change; real repair requires separate authorization.\nIndependent verification budget: {seconds} seconds, started only by a separate click.\n\nAcknowledge the impact and inability to restore exactly, and run the simulation?"),
    "dialog.save.title": ("保存脱敏证据", "Save redacted evidence"),
    "dialog.save.failed.title": ("保存失败", "Save failed"),
    "dialog.save.failed.body": ("无法保存脱敏证据，请检查目标位置是否可写。", "The redacted evidence could not be saved. Check that the destination is writable."),
    "detail.session": ("本轮状态：{status}", "Session: {status}"),
    "detail.caution": ("响应是证据，不是全网健康证明；未测不能视作正常。", "A response is evidence, not proof of health. Missing checks remain UNKNOWN."),
    "detail.checks": ("{family} 检查", "{family} checks"),
    "detail.snapshot": ("  E{sequence} 本机快照：{status}（{qualifier}；不代表连通性正常）", "  E{sequence} local snapshot: {status} ({qualifier}; no connectivity verdict)"),
    "detail.confirmed": ("已确认可比较", "confirmed"),
    "detail.not_comparable": ("不可比较", "not comparable"),
    "detail.addresses": ("    地址：{addresses}", "    Addresses: {addresses}"),
    "detail.no_addresses": ("未记录可用地址", "UNKNOWN / not recorded"),
    "detail.gateway": ("    默认网关：{gateway}", "    Default gateway: {gateway}"),
    "detail.source": ("    候选源地址（不是实际选路证明）：{source}", "    Source address candidate (not actual route proof): {source}"),
    "detail.route_unknown": ("    默认路由：尚未确认", "    Default route: UNKNOWN / no confirmed route summary"),
    "detail.protocol_missing": ("  {protocol}：未检测 / 没有记录结果", "  {protocol}: NOT TESTED / no recorded result"),
    "detail.not_comparable_note": ("；不可比较", "; not comparable"),
    "detail.http_note": ("；HTTP {code}（服务健康须单独判断）", "; HTTP {code} (service health is separate)"),
    "detail.category_note": ("；原因类别：{category}", "; category: {category}"),
    "detail.faults": ("故障范围与证据", "Fault scope and evidence"),
    "detail.no_finding": ("原因暂不能确定；这不抹去已有响应，也不代表全部健康。", "Cause remains unknown; confirmed responses still stand, and this is not a health verdict."),
    "detail.confidence": ("{scope} | 可信度：{confidence}（定性）", "{scope} | confidence: {confidence} (qualitative)"),
    "detail.support": ("支持证据：{refs}", "Support: {refs}"),
    "detail.counter": ("反证：{refs}", "Counterevidence: {refs}"),
    "detail.alternative": ("替代解释：{text}", "Alternative: {text}"),
    "detail.limitation": ("局限：{text}", "Limitation: {text}"),
    "detail.advice": ("建议：{text}", "Advice: {text}"),
    "detail.unavailable": ("没有可安全显示的具体说明；请结合证据与覆盖状态。", "Specific safe detail is unavailable; consult the evidence and coverage."),
    "detail.intermittent": ("有限窗口内的变化观察", "Intermittent observations in this limited window"),
    "detail.unfinished": ("未完成检查（安全类别）：", "Unfinished checks (safe categories):"),
    "detail.unfinished_unknown": ("部分检查未完成，具体原因不可用。", "Some checks were incomplete; a specific safe reason is unavailable."),
    "detail.cleanup_errors": ("已记录工具、清理或输出错误；不能视为成功完成的会话。", "Tool / cleanup errors recorded; this is not a successful complete session."),
    "detail.refs_session": ("证据编号仅属于本轮会话。", "Evidence numbers refer only to this session."),
    "refs.none": ("未记录", "None recorded"),
    "scope.local": ("本机配置（疑似）", "This device (suspected)"),
    "scope.wifi": ("Wi-Fi 链路（疑似）", "Wi-Fi link (suspected)"),
    "scope.gateway": ("网关路径（疑似）", "Gateway path (suspected)"),
    "scope.wan_or_isp": ("上游 / ISP（疑似）", "Upstream / ISP (suspected)"),
    "scope.dns": ("名称解析（疑似）", "Name resolution (suspected)"),
    "scope.target": ("指定网站 / 服务（疑似）", "Requested site / service (suspected)"),
    "scope.unknown": ("原因未定", "UNKNOWN"),
    "confidence.low": ("低", "low"),
    "confidence.moderate": ("中等", "moderate"),
    "confidence.medium": ("中等", "medium"),
    "confidence.insufficient": ("不足", "insufficient"),
    "confidence.unknown": ("未知", "unknown"),
    "outcome.success": ("收到响应", "Response received"),
    "outcome.reply_timeout": ("本次检查超时，未收到响应", "No reply within this check"),
    "outcome.unreachable": ("连接或解析失败", "Connection or resolution failed"),
    "outcome.execution_error": ("工具错误；网络结果未定", "Tool error; network outcome UNKNOWN"),
    "outcome.unsupported": ("不支持，未检测", "Unsupported; not tested"),
    "outcome.skipped": ("已跳过，未检测", "Skipped; not tested"),
    "outcome.cancelled": ("已取消，未完成", "Cancelled; incomplete"),
    "outcome.not_attempted": ("未检测", "Not tested"),
    "outcome.unknown": ("结果状态未知", "Unknown result state"),
    "status.completed": ("已完成", "completed"),
    "status.deadline": ("已到本轮采集截止", "deadline"),
    "status.cancelled": ("已取消", "cancelled"),
    "status.execution_error": ("工具错误", "execution_error"),
    "status.not_attempted": ("未尝试", "not_attempted"),
    "status.not_started": ("未开始", "not_started"),
    "status.not_confirmed": ("未确认", "not_confirmed"),
    "status.confirmed": ("已单独确认", "confirmed"),
    "status.declined": ("已拒绝", "declined"),
    "status.pending": ("等待单独启动", "pending"),
    "status.simulated_success": ("模拟操作成功（未修改系统）", "simulated_success (no system change)"),
    "status.simulated_failure": ("模拟操作失败", "simulated_failure"),
    "status.simulated_tool_error": ("模拟工具错误", "simulated_tool_error"),
    "status.inconclusive": ("无法确定是否改善", "inconclusive"),
    "status.observed_dns_improvement": ("本轮观察到 DNS 改善，因果未证实", "observed_dns_improvement; causality unproven"),
    "status.no_dns_improvement_observed": ("本轮未观察到 DNS 改善", "no_dns_improvement_observed"),
    "status.timed_out": ("已超时", "timed_out"),
    "status.blocked": ("执行被阻止", "blocked"),
    "status.budget_exceeded": ("超过预算", "budget_exceeded"),
    "status.configured": ("已配置", "configured"),
    "status.incomplete": ("配置或路由信息不完整", "configuration or route information incomplete"),
    "status.no_usable_address": ("无可用地址", "no usable address"),
    "status.no_default_route": ("无默认路由", "no default route"),
    "status.unavailable": ("不可用", "unavailable"),
    "status.unknown": ("未知", "unknown"),
    "repair.heading": ("仅模拟 —— 未真实清空 DNS 缓存", "SIMULATION ONLY - no real DNS cache clearing"),
    "repair.plan": ("唯一方案：Windows 本机 DNS 解析缓存清理的模拟。", "Only plan: simulate clearing the Windows local DNS resolver cache."),
    "repair.impact": ("真实清理会使后续解析重新查询，短时可能更慢；本次模拟不改变系统。", "Real clearing would make subsequent lookups query again and briefly take longer; this simulation changes nothing."),
    "repair.no_restore": ("原 DNS 缓存不能原样恢复，没有回滚。", "The original DNS cache contents cannot be restored exactly. No rollback is provided."),
    "repair.confirmation": ("确认：{status}", "Confirmation: {status}"),
    "repair.execution": ("模拟操作结果：{status}", "Simulated operation result: {status}"),
    "repair.verification": ("独立验证：{status}", "Independent verification: {status}"),
    "repair.change": ("观察变化：{status}", "Observed change: {status}"),
    "repair.causality": ("尚不能证明操作导致改善，也不证明永久恢复。", "Causality and permanent recovery remain unproven."),
    "repair.reason": ("原因：{reason}", "Reason: {reason}"),
    "repair.before_after": ("之前：{before}；之后：{after}", "Before: {before}; after: {after}"),
    "repair.evidence": ("独立验证证据（E 编号属于另一轮会话）：", "Independent verification evidence (its E numbers belong to a separate session):"),
    "repair.summary.heading": ("独立验证摘要（另一轮会话）：", "Independent verification summary (separate session):"),
    "repair.limit.system": ("比较不能证明 DNS 缓存操作实际改变系统。", "A comparison does not establish that a DNS cache operation changed the system."),
    "repair.limit.continuity": ("两次快照匹配，不证明会话之间网络始终连续。", "Matching snapshots do not prove uninterrupted network continuity between sessions."),
    "repair.limit.cause": ("观察改变，不证明修复因果或永久恢复。", "Changed observations do not establish repair causality or permanent recovery."),
    "repair.limit.cache": ("解析结果可能来自 hosts 或缓存，不能指向特定 DNS 服务器。", "System resolver results may come from hosts or caches, not a specific DNS server."),
    "repair.change.improved": ("本轮观察改善", "improved"),
    "repair.change.worsened": ("本轮观察变差", "worsened"),
    "repair.change.unchanged_success": ("本轮仍有响应", "unchanged_success"),
    "repair.change.unchanged_failure": ("本轮仍失败", "unchanged_failure"),
    "repair.change.inconclusive": ("结果不可确定", "inconclusive"),
    "summary.heading.overall": ("总体观察", "Overall observation"),
    "summary.heading.parts": ("分项结果", "Results by part"),
    "summary.heading.cause": ("原因判断", "Cause assessment"),
    "summary.heading.next": ("下一步", "Next steps"),
    "summary.group": ("环境 {epoch} · {family}", "Environment {epoch} · {family}"),
    "summary.group.unknown": ("环境未确认 · {family}", "Unconfirmed environment · {family}"),
    "summary.part.connectivity": ("连接观察", "Connectivity observations"),
    "summary.part.dns": ("DNS 解析", "DNS resolution"),
    "summary.part.gateway": ("网关", "Gateway"),
    "summary.part.website": ("网站访问", "Website access"),
    "summary.no_cause": ("暂不能定位具体原因。正向观察、异常和未测项分别列出；没有匹配故障规则不等于全网正常。", "A cause has not been established. Responses, anomalies and missing coverage are shown separately; no matched fault rule does not mean the whole network is healthy."),
    "summary.overall.anomalies": ("本轮观察到超时或失败，原因尚未确定；已收到响应的项目仍单独列出。", "Timeouts or failures were observed; cause remains unconfirmed. Positive observations are shown separately."),
    "summary.overall.suspected": ("既有证据支持一个疑似故障范围，仍不证明根因或整个网络均有故障。", "Existing evidence supports a suspected fault scope, not proof of a root cause or whole-network failure."),
    "summary.overall.responses": ("已测项目收到响应，本轮未观察到这些已测项目的相关异常；未测与未完成项不能视作正常。", "Tested checks responded; no related anomaly was observed in those checks in this window. Untested or unfinished items are not a health result."),
    "summary.overall.unknown": ("本轮未取得足够可比较观察；请查看未检测、工具错误及覆盖范围。", "This window lacks sufficient comparable observations; review untested checks, tool errors and coverage."),
    "summary.observation.coverage": ("另有 {tool_errors} 项工具错误、{not_tested} 项未检测、{excluded} 条不可比较证据。", "Also {tool_errors} tool errors, {not_tested} untested checks and {excluded} excluded observations."),
    "summary.coverage.reason": ("覆盖说明：{reason}。", "Coverage note: {reason}."),
    "summary.observation.responses": ("{responses} 次有响应；本轮未观察到这些已测项目的相关异常。", "{responses} responses; no related anomaly observed in these tested checks in this window."),
    "summary.observation.mixed": ("{responses} 次有响应，{failures} 次超时或失败；原因未定。", "{responses} responses and {failures} timeouts or failures; cause is not established."),
    "summary.observation.failures": ("观察到 {failures} 次超时或失败；尚不能定位原因。", "{failures} timeouts or failures observed; cause is not yet localized."),
    "summary.observation.not_tested": ("未检测，不能视为正常或故障。", "Not tested; this is neither a health nor failure verdict."),
    "summary.observation.tool_error": ("存在 {tool_errors} 项工具错误；没有足够可比较结果。", "{tool_errors} tool errors; insufficient comparable results."),
    "summary.observation.no_comparable": ("已取得的结果不可比较，不能混用或据此归因。", "Available observations are not comparable and must not be mixed or used for attribution."),
    "summary.observation.not_configured": ("本轮未记录到该地址族可用的配置/默认路由；未确认连接，这与连接失败不同。", "No usable configuration/default route was recorded for this address family; connectivity is unconfirmed, which differs from connection failure."),
    "summary.observation.http_error": ("服务器有响应，但返回 HTTP 错误；不能据此判断整网断线。", "The server responded with an HTTP error; this does not establish whole-network loss."),
    "summary.observation.tls_error": ("TLS 握手或证书验证失败，原因待核对；验证仍启用，不能据此判断整网断线。", "TLS handshake or certificate validation failed and needs review; verification remains enabled, and this does not establish whole-network loss."),
    "summary.website.not_tested": ("本轮未检测网页访问，可填写具体网站后检测。", "Website access was not tested in this session. Enter a specific website to test it."),
    "summary.coverage.complete": ("仅覆盖本轮实际完成的检查，不是全网健康认证。", "Coverage is limited to checks actually completed in this window, not a whole-network health certificate."),
    "summary.coverage.partial": ("有 {incomplete_count} 项未完成、{excluded_count} 条不可比较证据；不能宣称全网完全正常。", "{incomplete_count} incomplete checks and {excluded_count} excluded observations; full network health cannot be claimed."),
    "summary.coverage.multiple_epochs": ("本轮存在不同网络环境；各环境、地址族分别显示，证据不混用。", "This session spans different network environments; each environment and address family is shown separately without mixing evidence."),
    "summary.advice.website": ("若要确认网页访问，请填写具体网站，再由你开始一次有限诊断。", "To check website access, enter a specific website and start a finite diagnosis yourself."),
    "summary.advice.review_failures": ("查看失败项目对应协议与证据，核对同一目标是否仍失败；先不要修改网络设置。", "Review failed protocols and evidence, then check whether the same target still fails; do not change network settings on this evidence alone."),
    "summary.advice.review_tools": ("查看工具错误类别；确认检查工具可用后，再选择一次有限诊断。", "Review tool-error categories; confirm the check tool is available before choosing another finite diagnosis."),
    "summary.advice.review_coverage": ("查看未完成项目与覆盖范围；仅在需要时，由你重新开始有限诊断。", "Review unfinished checks and coverage; start another finite diagnosis only if needed."),
    "summary.advice.inspect_dns": ("对照系统解析设置和同目标解析结果，确认是否仍失败；不能断言更换 DNS 即可修复。", "Compare resolver settings and resolution of the same target to confirm whether it still fails; this does not prove changing DNS will fix it."),
    "summary.advice.inspect_configuration": ("只读核对当前网卡地址和默认路由；不要自动重置网络。", "Read the current adapter address and default route; do not automatically reset the network."),
    "summary.advice.inspect_gateway": ("对照网关与其他协议结果并检查本地连接；单次 Ping 无响应不证明路由器故障。", "Compare gateway and other protocol results and inspect the local link; one unanswered ping does not prove a router fault."),
    "summary.advice.inspect_target": ("对照具体网站或服务与其他已测目标；单个目标失败不等于整网中断。", "Compare the specific website or service against other tested targets; one target failure does not mean whole-network loss."),
    "summary.advice.keep_tls": ("保留证书与主机名验证，核对目标和信任链；不要绕过证书错误。", "Keep certificate and hostname verification enabled and review the target and trust chain; do not bypass certificate errors."),
    "summary.advice.single_epoch": ("确认环境稳定后，再由你开始新的有限会话；不要混用切换前后证据。", "Once the environment is stable, start a new finite session yourself; do not mix evidence from before and after a change."),
}

_DIAGNOSIS = {
    "local_configuration": ("本机快照未同时记录该地址族可用地址与默认路由，提示该地址族可能存在配置限制；不代表另一地址族或全网故障。", "The local snapshot did not record both a usable address and a default route for this address family, suggesting a possible configuration limitation in this family; this does not establish a fault in the other family or the whole network."),
    "gateway_path": ("重复跨协议证据支持疑似网关路径异常，不能仅凭一次 Ping 判断。", "Repeated cross-protocol evidence supports a suspected gateway-path issue, not a verdict from a single ping."),
    "wifi_link": ("与当前路由接口关联的直接无线证据支持疑似 Wi-Fi 链路问题。", "Direct wireless evidence associated with the current routed interface supports a suspected Wi-Fi-link issue."),
    "upstream_path": ("本地与网关相对可达而多个外部目标重复失败，支持疑似上游路径范围。", "Local and gateway comparisons respond while multiple external targets repeatedly fail, supporting a suspected upstream-path scope."),
    "dns_resolution": ("重复解析异常与其他协议对照支持疑似名称解析范围；未证明具体服务器故障。", "Repeated resolution anomalies and other protocol comparisons support a suspected name-resolution scope, not a proven DNS-server fault."),
    "target_path": ("参考目标有响应而指定目标重复失败，支持疑似目标路径或服务范围。", "Reference targets respond while the requested target repeatedly fails, supporting a suspected target-path or service scope."),
    "target_service": ("已到达目标但 HTTP/TLS 服务结果异常，不代表整网断线。", "The target is reached but HTTP/TLS service results are abnormal; this does not establish whole-network loss."),
    "unknown_window": ("有效窗口内的可比较证据不足，暂不能定位原因。", "Comparable evidence in the valid window is insufficient to localize a cause."),
    "unknown_evidence": ("证据未满足既有归因条件或存在反证，暂不能定位原因。", "Evidence does not meet existing attribution conditions or includes counterevidence; a cause is not established."),
    "intermittent": ("本轮同环境、同目标的可比较结果变化，不证明持续故障。", "Comparable results of the same target and environment varied in this window; persistence is not established."),
}
_ALT = {
    "local_configuration": ("网卡、VPN、选路或采集工具限制可能影响结果。", "Adapter state, VPNs, route selection or collection-tool limitations may affect the result."),
    "gateway_path": ("网关响应策略、本机链路或设备策略仍是替代解释。", "Gateway response policy, the local link or device policy remains an alternative."),
    "wifi_link": ("无线证据仅关联当前接口，不能排除其他路径因素。", "Wireless evidence is local to the associated interface and does not exclude other path factors."),
    "upstream_path": ("目标策略、路径过滤或共同网络因素仍可能产生相似现象。", "Target policy, path filtering or shared network factors may produce similar observations."),
    "dns_resolution": ("hosts、缓存、目标策略及系统解析器限制仍需考虑。", "Hosts entries, caches, target policy and system-resolver limitations remain alternatives."),
    "target_path": ("目标策略、单目标路径和服务限制仍需核对。", "Target policy, a target-specific path and service restrictions still need review."),
    "target_service": ("目标服务、证书链或中间网络干预仍需核对。", "Target-service state, the certificate chain or network interference still need review."),
    "unknown_window": ("未测、工具限制和暂时变化都可能减少有效证据。", "Missing checks, tool limitations and temporary changes can reduce valid evidence."),
    "unknown_evidence": ("目标策略、暂时异常、未测或工具限制可能影响观察。", "Target policy, transient anomalies, missing checks or tool limitations may affect observations."),
    "intermittent": ("限流、探测策略和短暂变化不等于持续故障。", "Rate limits, probe policy and transient changes do not establish a persistent fault."),
}
_ADVICE = {"local_configuration": "inspect_configuration", "gateway_path": "inspect_gateway", "wifi_link": "review_failures", "upstream_path": "review_failures", "dns_resolution": "inspect_dns", "target_path": "inspect_target", "target_service": "inspect_target", "unknown_window": "review_coverage", "unknown_evidence": "review_coverage", "intermittent": "review_failures"}
for _rule, _texts in _DIAGNOSIS.items():
    MESSAGES["diagnosis." + _rule] = _texts
    MESSAGES["diagnosis.alt." + _rule] = _ALT[_rule]
    MESSAGES["diagnosis.advice." + _rule] = MESSAGES["summary.advice." + _ADVICE[_rule]]
MESSAGES.update({
    "diagnosis.limit.window": ("仅解释同一环境和地址族的本轮有限窗口；可信度不是概率，也不证明根因。", "This covers this session's finite window in one environment and address family; confidence is not a probability or proof of a root cause."),
    "diagnosis.limit.dns_cache": ("系统解析可能来自 hosts 或缓存；未观察线上 DNS 数据包，不能确认某台服务器故障。", "Resolution may use hosts or caches; no on-wire DNS packets were observed, so a specific DNS-server fault is not established."),
    "diagnosis.limit.response_not_repair": ("本轮收到响应，不证明已经永久恢复。", "A response in this window does not prove permanent recovery."),
    "diagnosis.limit.repeat_window": ("归因仍要求原30秒窗口内同环境、地址族、实际目标的重复跨协议证据；不是健康认证。", "Attribution still requires repeated cross-protocol evidence in the original 30-second window, environment, address family and actual target; this is not a health certificate."),
    "diagnosis.limit.truncated": ("分析输入达到既有限制，部分证据未参与。", "Analysis input reached the existing bound; some evidence was not included."),
    "diagnosis.limit.duplicates": ("重复证据编号已排除，不能作为独立样本。", "Duplicate evidence IDs were excluded and cannot count as independent samples."),
    "diagnosis.limit.incomplete": ("部分检查未完成；未测、错误、取消、不支持都不能当作成功或网络失败。", "Some checks were incomplete; untested, erroneous, cancelled and unsupported checks are neither success nor network failure."),
    "diagnosis.limit.blind_spots": ("网络观察存在盲区；只使用明确可比较的同环境证据。", "Network observation contains blind spots; only clearly comparable evidence from one environment is used."),
    "diagnosis.limit.no_wifi": ("没有与当前路由接口关联的直接无线证据时，不判断无线根因。", "Without direct wireless evidence tied to the current routed interface, no wireless root cause is inferred."),
    "diagnosis.limit.findings_limit": ("结论数量达到既有限制，不能把遗漏视为正常。", "The existing finding bound was reached; omitted findings cannot be treated as healthy."),
    "diagnosis.coverage.scope_limited": ("覆盖有限，未确认具体故障范围。", "Coverage is limited; no specific fault scope is established."),
    "diagnosis.coverage.scope_window": ("故障范围仅适用于本轮窗口。", "Fault scope is limited to this session's window."),
    "diagnosis.coverage.intermittent_limited": ("当前证据不能判断间歇性。", "Current evidence cannot assess intermittency."),
    "diagnosis.coverage.intermittent_seen": ("本轮观察到可比较结果变化。", "Comparable results varied in this window."),
    "diagnosis.coverage.intermittent_not_seen": ("本轮未观察到符合条件的变化，不代表永远稳定。", "No qualifying variation was observed; permanent stability is not established."),
})
_REASONS = {
    "timeout": ("检查超时", "check timed out"), "network_unreachable": ("网络路径不可达", "network path unreachable"),
    "host_unreachable": ("目标不可达", "target unreachable"), "connection_refused": ("连接被拒绝", "connection refused"),
    "dns_resolution": ("名称解析失败", "name resolution failed"), "dns_not_found": ("名称未找到", "name not found"),
    "name_not_found": ("名称未找到", "name not found"), "tls_validation": ("TLS 证书验证失败", "TLS certificate validation failed"),
    "tls_handshake": ("TLS 握手失败", "TLS handshake failed"), "http_status": ("HTTP 状态异常", "HTTP status error"),
    "os_error": ("系统调用错误", "operating-system call error"), "tool_error": ("工具错误", "tool error"),
    "execution_error": ("工具执行错误", "tool execution error"), "cancelled": ("用户取消", "cancelled"),
    "deadline": ("本轮截止", "session deadline"), "unsupported": ("当前环境不支持", "unsupported in this environment"),
    "not_attempted": ("尚未检测", "not tested"), "context_unknown": ("网络环境未确认", "network context unconfirmed"),
    "context_changed": ("网络环境变化", "network context changed"), "identity_unconfirmed": ("网络身份未确认", "network identity unconfirmed"),
    "no_usable_address": ("没有可用地址", "no usable address"), "no_default_route": ("没有默认路由", "no default route"),
    "budget": ("预算不足", "insufficient remaining budget"), "not_comparable": ("不可比较", "not comparable"),
    "context_blind_spots": ("网络观察存在盲区", "network observation blind spots"), "multiple_epochs": ("网络环境不同", "multiple network environments"),
    "truncated": ("输入达到限制", "input bound reached"), "not_tested": ("未检测", "not tested"),
    "reason_unavailable": ("具体原因不可用", "specific safe reason unavailable"), "unknown": ("具体原因不可用", "specific safe reason unavailable"),
}
for _reason, _texts in _REASONS.items():
    MESSAGES["reason." + _reason] = _texts
_REPAIR_REASONS = {
    "verification_not_run": ("尚未进行独立验证。", "Independent verification has not run."),
    "verification_cancelled": ("独立验证已取消。", "Independent verification was cancelled."),
    "verification_failed": ("独立验证工具失败。", "Independent verification failed."),
    "verification_budget_exceeded": ("独立验证超过预算。", "Independent verification exceeded its budget."),
    "configured_targets_or_protocols_changed": ("前后目标或协议不同，不能比较。", "Configured targets or protocols differ and cannot be compared."),
    "observation_budgets_differ": ("前后观察预算不同，不能比较。", "Observation budgets differ and cannot be compared."),
    "session_cancelled_or_failed": ("某轮已取消或工具失败。", "A session was cancelled or failed."),
    "cleanup_or_output_failed": ("清理或输出未成功。", "Cleanup or output failed."),
    "invalid_or_exceeded_session_budget": ("某轮预算无效或超出。", "A session budget is invalid or exceeded."),
    "network_identity_changed": ("网络环境不同，不能证明可比较。", "Network identities differ and comparability is not established."),
    "protocol_target_family_or_actual_peer_changed": ("协议、目标、地址族或实际地址不同。", "Protocol, target, address family or actual peer differs."),
    "intermittent_not_resolved_by_non_reproduction": ("本轮未复现间歇异常，不等于已解决。", "Non-reproduction of an intermittent anomaly does not establish resolution."),
    "insufficient_mixed_or_worsened_observations": ("前后观察不足、混合或变差，不能确认改善。", "Observations are insufficient, mixed or worse; improvement is not established."),
    "no_failed_dns_baseline": ("修复前未确认 DNS 失败，不能声称修复改善。", "No failed DNS baseline was established, so repair improvement cannot be claimed."),
    "actual_peer_missing": ("缺少实际目标地址，不能比较。", "The actual peer address is missing; comparison is unavailable."),
    "invalid_observation_window": ("观察窗口无效。", "The observation window is invalid."),
    "observation_outside_session": ("观察超出会话窗口。", "An observation lies outside the session."),
}
for _reason, _texts in _REPAIR_REASONS.items():
    MESSAGES["repair.reason." + _reason] = _texts

def normalize_language(value):
    return value if value in LANGUAGES else DEFAULT_LANGUAGE

def translate(language, message_id, **params):
    index = 0 if normalize_language(language) == "zh-CN" else 1
    pair = MESSAGES.get(message_id, MESSAGES["detail.unavailable"])
    try:
        return pair[index].format(**params)
    except (KeyError, ValueError, TypeError):
        return MESSAGES["detail.unavailable"][index]

def has_message(message_id):
    return message_id in MESSAGES

def load_language_preference():
    try:
        path = _app_data_dir() / "ui-language.json"
        if path.is_symlink() or path.stat().st_size > 2048:
            return DEFAULT_LANGUAGE
        value = json.loads(path.read_text(encoding="utf-8"))
        if type(value) is dict and type(value.get("schema_version")) is int and value.get("schema_version") == 1:
            return normalize_language(value.get("language"))
    except (OSError, ValueError, TypeError):
        pass
    return DEFAULT_LANGUAGE

def save_language_preference(language):
    if language not in LANGUAGES:
        raise ValueError("Unsupported interface language")
    temporary = None
    try:
        destination = _app_data_dir() / "ui-language.json"
        if destination.is_symlink():
            return False
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         prefix=".ui-language-", suffix=".tmp",
                                         dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump({"schema_version": 1, "language": language}, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
        return True
    except (OSError, ValueError):
        return False
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

def install_standard_button_translator(language):
    """Translate only fixed Qt standard buttons; native OS dialogs retain OS locale."""
    from PySide6.QtCore import QCoreApplication, QTranslator
    app = QCoreApplication.instance()
    if app is None:
        return
    translator = getattr(app, "_losshound_button_translator", None)
    if translator is None:
        class StandardButtonTranslator(QTranslator):
            def translate(self, context, source_text, disambiguation=None, n=-1):
                if context not in {"QPlatformTheme", "QDialogButtonBox", "QMessageBox"}:
                    return source_text
                pairs = {"&Yes": ("是(&Y)", "&Yes"), "Yes": ("是", "Yes"),
                         "&No": ("否(&N)", "&No"), "No": ("否", "No"),
                         "OK": ("确定", "OK"), "&OK": ("确定(&O)", "&OK"),
                         "Cancel": ("取消", "Cancel"), "&Cancel": ("取消(&C)", "&Cancel"),
                         "Save": ("保存", "Save"), "&Save": ("保存(&S)", "&Save"),
                         "Close": ("关闭", "Close"), "&Close": ("关闭(&C)", "&Close")}
                texts = pairs.get(source_text)
                # A Python empty string is an accepted empty Qt translation, not
                # a missing translation. Preserve Qt source text for other UI
                # labels; diagnostic data never uses this standard-button path.
                return texts[0 if self.language == "zh-CN" else 1] if texts else source_text
        translator = StandardButtonTranslator(app)
        translator.language = normalize_language(language)
        app._losshound_button_translator = translator
        app.installTranslator(translator)
    translator.language = normalize_language(language)
