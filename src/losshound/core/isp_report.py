"""ISP Report Generator — produces a comprehensive network quality report.

Generates a structured report suitable for sharing with an ISP support team
to demonstrate network issues with hard data.
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from losshound.storage.history import HistoryStore
from losshound.core.windows_commands import windows_command

logger = logging.getLogger(__name__)


@dataclass
class IspReportData:
    """All data needed for an ISP report."""
    generated_at: str
    report_period_hours: int
    system_info: dict
    # Aggregate stats
    total_observations: int = 0
    total_benchmarks: int = 0
    avg_latency_ms: Optional[float] = None
    avg_jitter_ms: Optional[float] = None
    avg_loss_pct: Optional[float] = None
    max_latency_ms: Optional[float] = None
    max_loss_pct: Optional[float] = None
    avg_dns_ms: Optional[float] = None
    # Score
    avg_score: Optional[float] = None
    latest_grade: str = ""
    # Issue breakdown
    issue_counts: dict = field(default_factory=dict)
    # Observations (sampled)
    observations: list[dict] = field(default_factory=list)
    # Benchmarks
    benchmarks: list[dict] = field(default_factory=list)
    # Diagnoses
    diagnoses: list[dict] = field(default_factory=list)
    # Route
    latest_route: list[dict] = field(default_factory=list)


def get_system_info() -> dict:
    """Gather system/network environment info."""
    import subprocess
    info = {
        "os": platform.platform(),
        "hostname": platform.node(),
        "architecture": platform.machine(),
    }

    # Get adapter info
    try:
        proc = subprocess.run(
            windows_command(["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
             "Select-Object Name, InterfaceDescription, LinkSpeed, MacAddress "
             "| ConvertTo-Json -Depth 2"]),
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            import json
            adapters = json.loads(proc.stdout)
            if isinstance(adapters, dict):
                adapters = [adapters]
            info["active_adapters"] = [
                {
                    "name": a.get("Name", ""),
                    "description": a.get("InterfaceDescription", ""),
                    "link_speed": a.get("LinkSpeed", ""),
                }
                for a in adapters
            ]
    except Exception:
        pass

    # Get default gateway
    try:
        proc = subprocess.run(
            windows_command(["powershell", "-NoProfile", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
             "Select-Object -First 1).NextHop"]),
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc.returncode == 0:
            info["default_gateway"] = proc.stdout.strip()
    except Exception:
        pass

    return info


def generate_isp_report(history: HistoryStore, hours: int = 24) -> IspReportData:
    """Generate a comprehensive ISP report from stored history."""
    report = IspReportData(
        generated_at=datetime.now().isoformat(),
        report_period_hours=hours,
        system_info=get_system_info(),
    )

    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()

    # Observations
    conn = history._conn
    obs_rows = conn.execute(
        """SELECT timestamp, gateway_ip, gateway_loss, gateway_rtt_avg,
                  public_loss_avg, public_rtt_avg, dns_fail_count, dns_total_count
           FROM observations WHERE timestamp > ?
           ORDER BY timestamp""",
        (cutoff,),
    ).fetchall()

    report.total_observations = len(obs_rows)

    if obs_rows:
        latencies = [r[5] for r in obs_rows if r[5] is not None]
        losses = [r[4] for r in obs_rows if r[4] is not None]
        gw_latencies = [r[3] for r in obs_rows if r[3] is not None]

        all_latencies = latencies + gw_latencies
        all_losses = losses + [r[2] for r in obs_rows if r[2] is not None]

        if all_latencies:
            report.avg_latency_ms = sum(all_latencies) / len(all_latencies)
            report.max_latency_ms = max(all_latencies)
        if all_losses:
            report.avg_loss_pct = sum(all_losses) / len(all_losses)
            report.max_loss_pct = max(all_losses)

        # Sample up to 50 observations evenly
        step = max(1, len(obs_rows) // 50)
        for r in obs_rows[::step][:50]:
            report.observations.append({
                "timestamp": r[0], "gateway_ip": r[1],
                "gateway_loss": r[2], "gateway_rtt": r[3],
                "public_loss": r[4], "public_rtt": r[5],
                "dns_failures": r[6], "dns_total": r[7],
            })

    # Benchmarks
    benchmarks = history.get_benchmarks(hours=hours)
    report.total_benchmarks = len(benchmarks)
    report.benchmarks = benchmarks[-30:]  # last 30

    if benchmarks:
        scores = [b["overall_score"] for b in benchmarks if b.get("overall_score") is not None]
        jitters = [b["avg_jitter_ms"] for b in benchmarks if b.get("avg_jitter_ms") is not None]
        dns_times = [b["avg_dns_ms"] for b in benchmarks if b.get("avg_dns_ms") is not None]

        if scores:
            report.avg_score = sum(scores) / len(scores)
        if jitters:
            report.avg_jitter_ms = sum(jitters) / len(jitters)
        if dns_times:
            report.avg_dns_ms = sum(dns_times) / len(dns_times)
        if benchmarks[-1].get("grade"):
            report.latest_grade = benchmarks[-1]["grade"]

    # Diagnoses
    diag_rows = conn.execute(
        """SELECT timestamp, category, summary, explanation, confidence
           FROM diagnoses WHERE timestamp > ?
           ORDER BY timestamp DESC LIMIT 100""",
        (cutoff,),
    ).fetchall()

    issue_counts: dict[str, int] = {}
    for r in diag_rows:
        cat = r[1]
        issue_counts[cat] = issue_counts.get(cat, 0) + 1
        if len(report.diagnoses) < 30:
            report.diagnoses.append({
                "timestamp": r[0], "category": r[1],
                "summary": r[2], "explanation": r[3],
                "confidence": r[4],
            })
    report.issue_counts = issue_counts

    # Latest route
    route_row = conn.execute(
        """SELECT hops_json FROM route_snapshots
           ORDER BY timestamp DESC LIMIT 1""",
    ).fetchone()
    if route_row and route_row[0]:
        import json
        report.latest_route = json.loads(route_row[0])

    return report


def format_isp_report(report: IspReportData) -> str:
    """Format the ISP report as a human-readable text document."""
    lines = []
    w = 70

    lines.append("=" * w)
    lines.append("LOSSHOUND — ISP NETWORK QUALITY REPORT")
    lines.append("=" * w)
    lines.append(f"Generated:     {report.generated_at[:19]}")
    lines.append(f"Report Period: Last {report.report_period_hours} hours")
    lines.append(f"Data Points:   {report.total_observations} observations, "
                 f"{report.total_benchmarks} benchmarks")
    lines.append("")

    # System info
    lines.append("-" * w)
    lines.append("SYSTEM ENVIRONMENT")
    lines.append("-" * w)
    si = report.system_info
    lines.append(f"  OS:              {si.get('os', 'Unknown')}")
    lines.append(f"  Hostname:        {si.get('hostname', 'Unknown')}")
    lines.append(f"  Default Gateway: {si.get('default_gateway', 'Unknown')}")
    for adapter in si.get("active_adapters", []):
        lines.append(f"  Adapter:         {adapter.get('description', '')} "
                     f"({adapter.get('link_speed', '')})")
    lines.append("")

    # Executive summary
    lines.append("-" * w)
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * w)

    def _fmt(val, unit, fmt=".1f"):
        return f"{val:{fmt}}{unit}" if val is not None else "N/A"

    lines.append(f"  Network Score:     {_fmt(report.avg_score, '', '.0f')} / 100 "
                 f"(Grade: {report.latest_grade or 'N/A'})")
    lines.append(f"  Avg Latency:       {_fmt(report.avg_latency_ms, ' ms')}")
    lines.append(f"  Max Latency:       {_fmt(report.max_latency_ms, ' ms')}")
    lines.append(f"  Avg Jitter:        {_fmt(report.avg_jitter_ms, ' ms')}")
    lines.append(f"  Avg Packet Loss:   {_fmt(report.avg_loss_pct, '%')}")
    lines.append(f"  Max Packet Loss:   {_fmt(report.max_loss_pct, '%')}")
    lines.append(f"  Avg DNS Response:  {_fmt(report.avg_dns_ms, ' ms')}")
    lines.append("")

    # Quality assessment
    issues_total = sum(v for k, v in report.issue_counts.items() if k != "healthy")
    healthy_count = report.issue_counts.get("healthy", 0)
    total_diags = issues_total + healthy_count

    if total_diags > 0:
        issue_pct = (issues_total / total_diags) * 100
        lines.append(f"  Issue Rate:        {issue_pct:.0f}% of checks detected problems")
    lines.append("")

    # Issue breakdown
    if report.issue_counts:
        lines.append("-" * w)
        lines.append("ISSUE BREAKDOWN")
        lines.append("-" * w)
        for cat, count in sorted(report.issue_counts.items(), key=lambda x: -x[1]):
            label = cat.replace("_", " ").title()
            bar = "#" * min(count, 40)
            lines.append(f"  {label:<25} {count:>4}  {bar}")
        lines.append("")

    # Benchmark history
    if report.benchmarks:
        lines.append("-" * w)
        lines.append("BENCHMARK HISTORY (recent)")
        lines.append("-" * w)
        lines.append(f"  {'Timestamp':<22} {'Score':<8} {'Grade':<6} "
                     f"{'Latency':<10} {'Jitter':<10} {'Loss':<8}")
        lines.append(f"  {'-'*22} {'-'*8} {'-'*6} {'-'*10} {'-'*10} {'-'*8}")
        for b in report.benchmarks[-15:]:
            ts = b["timestamp"][:19] if b.get("timestamp") else "--"
            score = f"{b['overall_score']:.0f}" if b.get("overall_score") is not None else "--"
            grade = b.get("grade") or "--"
            lat = f"{b['avg_latency_ms']:.1f}ms" if b.get("avg_latency_ms") is not None else "--"
            jit = f"{b['avg_jitter_ms']:.1f}ms" if b.get("avg_jitter_ms") is not None else "--"
            loss = f"{b['avg_loss_pct']:.1f}%" if b.get("avg_loss_pct") is not None else "--"
            lines.append(f"  {ts:<22} {score:<8} {grade:<6} {lat:<10} {jit:<10} {loss:<8}")
        lines.append("")

    # Recent diagnoses
    if report.diagnoses:
        lines.append("-" * w)
        lines.append("RECENT NETWORK ISSUES")
        lines.append("-" * w)
        for d in report.diagnoses[:15]:
            ts = d["timestamp"][:19] if d.get("timestamp") else "--"
            cat = d.get("category", "").replace("_", " ").title()
            lines.append(f"  {ts}  [{cat}]")
            lines.append(f"    {d.get('summary', '')}")
            if d.get("explanation"):
                lines.append(f"    Detail: {d['explanation'][:80]}")
        lines.append("")

    # Route
    if report.latest_route:
        lines.append("-" * w)
        lines.append("LATEST TRACEROUTE")
        lines.append("-" * w)
        for hop in report.latest_route:
            ip = hop.get("ip", "*")
            rtt = hop.get("rtt", [])
            rtt_str = "  ".join(
                f"{r:.0f}ms" if r is not None else "*" for r in rtt[:3]
            )
            lines.append(f"  Hop {hop.get('hop', '?'):>2}  {ip:<16}  {rtt_str}")
        lines.append("")

    # Observation samples
    if report.observations:
        lines.append("-" * w)
        lines.append("OBSERVATION SAMPLES")
        lines.append("-" * w)
        lines.append(f"  {'Timestamp':<22} {'GW IP':<16} {'GW Loss':<10} "
                     f"{'GW RTT':<10} {'Pub Loss':<10} {'Pub RTT':<10}")
        lines.append(f"  {'-'*22} {'-'*16} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
        for o in report.observations[:20]:
            ts = o["timestamp"][:19] if o.get("timestamp") else "--"
            gw_ip = o.get("gateway_ip") or "--"
            gw_l = f"{o['gateway_loss']:.1f}%" if o.get("gateway_loss") is not None else "--"
            gw_r = f"{o['gateway_rtt']:.0f}ms" if o.get("gateway_rtt") is not None else "--"
            pu_l = f"{o['public_loss']:.1f}%" if o.get("public_loss") is not None else "--"
            pu_r = f"{o['public_rtt']:.0f}ms" if o.get("public_rtt") is not None else "--"
            lines.append(f"  {ts:<22} {gw_ip:<16} {gw_l:<10} {gw_r:<10} {pu_l:<10} {pu_r:<10}")
        lines.append("")

    # Footer
    lines.append("=" * w)
    lines.append("This report was generated by Losshound network diagnosis tool.")
    lines.append("Data is collected automatically via ICMP ping, DNS resolution,")
    lines.append("and traceroute tests. All timestamps are local time.")
    lines.append("=" * w)

    return "\n".join(lines)
