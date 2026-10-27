"""CLI interface for the network optimizer."""

from __future__ import annotations

import sys


def run_optimizer_command(args):
    """Fail closed before importing any legacy dispatcher or optimizer module."""
    raise SystemExit(
        "Legacy commands are unavailable in read-only S1; "
        "use losshound --cli [--duration SECONDS]."
    )


def _cmd_optimize(opt, *, skip_dns: bool, skip_mtu: bool, apply_dns: bool):
    """Run full network optimization."""
    is_admin = opt.check_admin()
    print("Losshound Network Optimizer")
    print("=" * 60)
    print(f"  Admin: {'Yes' if is_admin else 'No (some optimizations will be skipped)'}")
    print()

    if not is_admin:
        print("  TIP: Re-run as Administrator for full optimization.")
        print()

    print("Creating backup of current settings...")
    print("Running optimizations...\n")

    report = opt.optimize_all(
        skip_dns=skip_dns,
        skip_mtu=skip_mtu,
        apply_dns=apply_dns,
    )

    _print_results(report.results)

    print()
    print(f"Summary: {report.summary}")
    print(f"Backup saved — run 'losshound restore' to undo.")


def _cmd_dns_benchmark(opt):
    """Benchmark DNS servers."""
    print("Losshound DNS Benchmark")
    print("=" * 60)
    print("Testing 14 public DNS servers...\n")

    results = opt.benchmark_dns()

    print(f"{'Rank':<5} {'Server':<18} {'Provider':<22} {'Avg ms':<10} {'Min ms':<10} {'Success':<8}")
    print("-" * 73)

    for i, r in enumerate(results):
        avg = f"{r.avg_ms:.1f}" if r.avg_ms != float("inf") else "N/A"
        mn = f"{r.min_ms:.1f}" if r.min_ms != float("inf") else "N/A"
        success = f"{r.success_rate * 100:.0f}%"

        marker = " "
        if i == 0:
            marker = "*"  # fastest

        print(f" {marker}{i+1:<4} {r.server:<18} {r.name:<22} {avg:<10} {mn:<10} {success:<8}")

    print()
    if results and results[0].success_rate > 0.5:
        print(f"  Fastest DNS: {results[0].name} ({results[0].server}) — {results[0].avg_ms:.1f}ms avg")
        print(f"  Run 'losshound optimize' to apply the fastest DNS automatically.")


def _cmd_status(opt):
    """Show current network optimization status."""
    print("Losshound Network Status")
    print("=" * 60)

    status = opt.get_optimization_status()

    is_admin = status.get("admin", False)
    print(f"  Admin privileges:     {'Yes' if is_admin else 'No'}")
    print()

    tcp = status.get("tcp", {})
    print("  TCP/IP Settings:")
    print(f"    Auto-tuning level:  {tcp.get('auto_tuning_level', 'unknown')}")
    print(f"    Congestion provider:{tcp.get('congestion_provider', 'unknown')}")
    print(f"    ECN capability:     {tcp.get('ecn_capability', 'unknown')}")
    print(f"    RSS:                {tcp.get('rss', 'unknown')}")
    print(f"    DCA:                {tcp.get('dca', 'unknown')}")
    print(f"    Timestamps:         {tcp.get('timestamps', 'unknown')}")
    print()

    print("  Network:")
    print(f"    DNS primary:        {status.get('dns_primary', 'auto') or 'auto'}")
    print(f"    DNS secondary:      {status.get('dns_secondary', '') or 'none'}")
    print(f"    MTU:                {status.get('mtu', 1500)}")

    throttling = status.get("network_throttling_index")
    if throttling is None:
        thr_text = "default (may be throttled)"
    elif throttling == 0xFFFFFFFF or throttling == -1:
        thr_text = "disabled (optimal)"
    else:
        thr_text = f"enabled ({throttling})"
    print(f"    Network throttling: {thr_text}")

    print(f"    Backup exists:      {'Yes' if status.get('backup_exists') else 'No'}")


def _cmd_restore(opt):
    """Restore settings from backup."""
    print("Losshound Restore")
    print("=" * 60)

    if not opt.check_admin():
        print("  WARNING: Running without admin — some settings cannot be restored.")
        print()

    print("Restoring from backup...\n")
    results = opt.restore_backup()

    if not results:
        print("  No backup found. Run 'losshound optimize' first.")
        return

    _print_results(results)

    succeeded = sum(1 for r in results if r.success)
    print(f"\nRestored {succeeded}/{len(results)} settings.")


def _print_results(results):
    """Print a table of optimization results."""
    print(f"  {'Optimization':<28} {'Status':<18} {'Before':<18} {'After':<18} {'Note'}")
    print(f"  {'-'*28} {'-'*18} {'-'*18} {'-'*18} {'-'*30}")

    for r in results:
        # Use the new status field; fall back to legacy logic
        status = r.status
        if not status:
            if r.success:
                status = "Applied"
            elif r.needs_admin and r.error and "Administrator" in r.error:
                status = "Skipped"
            else:
                status = "Failed"

        before = (r.before or "--")[:16]
        after = (r.after or "--")[:16]
        note = (r.note or r.error or "")[:40]
        print(f"  {r.name:<28} {status:<18} {before:<18} {after:<18} {note}")


def _cmd_benchmark(label: str, ping_count: int):
    """Run a full network performance benchmark."""
    from losshound.core.benchmark import (
        format_snapshot, run_benchmark, save_snapshot,
    )

    print("Losshound Network Benchmark")
    print("=" * 65)
    print(f"  Label: {label}")
    print(f"  Pings per target: {ping_count}")
    print()

    snapshot = run_benchmark(
        label=label,
        ping_count=ping_count,
        progress_callback=lambda msg: print(f"  {msg}"),
    )
    save_snapshot(snapshot)

    print()
    print(format_snapshot(snapshot))
    print()
    print(f"Benchmark saved as '{label}'.")

    if label == "before":
        print("  Now run 'losshound optimize' then 'losshound benchmark --label after'")
        print("  Finally run 'losshound compare' to see the difference!")
    elif label == "after":
        print("  Run 'losshound compare' to see before vs after!")


def _cmd_compare():
    """Compare before vs after benchmarks."""
    from losshound.core.benchmark import (
        compare_snapshots, format_comparison, get_latest_snapshot,
    )

    before = get_latest_snapshot("before")
    after = get_latest_snapshot("after")

    if not before:
        print("No 'before' benchmark found. Run: losshound benchmark --label before")
        return
    if not after:
        print("No 'after' benchmark found. Run: losshound benchmark --label after")
        return

    report = compare_snapshots(before, after)
    print()
    print(format_comparison(report))
    print()


def _cmd_load_benchmark(label: str):
    """Run a full network load benchmark."""
    from losshound.core.load_benchmark import (
        format_load_snapshot, run_load_benchmark, save_load_snapshot,
    )

    print("Losshound LOAD Benchmark")
    print("=" * 65)
    print(f"  Label: {label}")
    print(f"  Tests: idle latency, latency under load, bufferbloat,")
    print(f"         throughput, small packet responsiveness")
    print(f"  This will take ~60 seconds...")
    print()

    snapshot = run_load_benchmark(
        label=label,
        progress_callback=lambda msg: print(f"  {msg}"),
    )
    save_load_snapshot(snapshot)

    print()
    print(format_load_snapshot(snapshot))
    print()
    print(f"Load benchmark saved as '{label}'.")

    if label == "before":
        print("  Now run 'losshound optimize' then 'losshound load-benchmark --label after'")
        print("  Finally run 'losshound load-compare' to see the real difference!")
    elif label == "after":
        print("  Run 'losshound load-compare' to see before vs after!")


def _cmd_load_compare():
    """Compare before vs after load benchmarks."""
    from losshound.core.load_benchmark import (
        compare_load_snapshots, format_load_comparison, get_latest_load_snapshot,
    )

    before = get_latest_load_snapshot("before")
    after = get_latest_load_snapshot("after")

    if not before:
        print("No 'before' load benchmark found. Run: losshound load-benchmark --label before")
        return
    if not after:
        print("No 'after' load benchmark found. Run: losshound load-benchmark --label after")
        return

    report = compare_load_snapshots(before, after)
    print()
    print(format_load_comparison(report))
    print()


def _cmd_score(ping_count: int):
    """Run a benchmark and display the network score."""
    from losshound.core.benchmark import run_benchmark, save_snapshot
    from losshound.core.scoring import format_score, score_snapshot

    print("Losshound Network Score")
    print("=" * 55)
    print("Running benchmark...\n")

    snapshot = run_benchmark(
        label="score",
        ping_count=ping_count,
        progress_callback=lambda msg: print(f"  {msg}"),
    )
    save_snapshot(snapshot)

    score = score_snapshot(snapshot)
    print()
    print(format_score(score))


def _cmd_trends(hours: int):
    """Show network performance trends from stored history."""
    from losshound.core.trending import analyze_trends, format_trends
    from losshound.storage.history import HistoryStore

    store = HistoryStore()
    benchmarks = store.get_benchmarks(hours=hours)
    store.close()

    if not benchmarks:
        print("No benchmark history found.")
        print("Run 'losshound score' or 'losshound benchmark' a few times to build up data.")
        return

    summary = analyze_trends(benchmarks, hours=hours)
    print()
    print(format_trends(summary))


def _cmd_history(count: int):
    """List recent benchmark snapshots with scores."""
    from losshound.storage.history import HistoryStore

    store = HistoryStore()
    benchmarks = store.get_benchmarks(hours=8760)  # up to 1 year
    store.close()

    if not benchmarks:
        print("No benchmark history found.")
        print("Run 'losshound score' or 'losshound benchmark' to create entries.")
        return

    # Show most recent N
    entries = benchmarks[-count:]

    print("Losshound Benchmark History")
    print("=" * 80)
    print(f"  {'Timestamp':<22} {'Label':<10} {'Score':<8} {'Grade':<6} "
          f"{'Latency':<10} {'Jitter':<10} {'Loss':<8}")
    print(f"  {'-'*22} {'-'*10} {'-'*8} {'-'*6} {'-'*10} {'-'*10} {'-'*8}")

    for b in entries:
        ts = b["timestamp"][:19] if b.get("timestamp") else "--"
        label = b.get("label", "--") or "--"
        score = f"{b['overall_score']:.0f}" if b.get("overall_score") is not None else "--"
        grade = b.get("grade") or "--"
        lat = f"{b['avg_latency_ms']:.1f}ms" if b.get("avg_latency_ms") is not None else "--"
        jit = f"{b['avg_jitter_ms']:.1f}ms" if b.get("avg_jitter_ms") is not None else "--"
        loss = f"{b['avg_loss_pct']:.1f}%" if b.get("avg_loss_pct") is not None else "--"
        print(f"  {ts:<22} {label:<10} {score:<8} {grade:<6} {lat:<10} {jit:<10} {loss:<8}")

    print(f"\n  Showing {len(entries)}/{len(benchmarks)} entries.")


def _cmd_wifi():
    """Run WiFi diagnostics and display results."""
    from losshound.core.wifi_diag import run_wifi_diagnostics, format_wifi_report

    print("Losshound WiFi Diagnostics")
    print("=" * 65)
    print("Scanning...\n")

    report = run_wifi_diagnostics()
    print(format_wifi_report(report))


def _cmd_drop_analyze(duration: int, interval: float, wan_target: str):
    """Run connectivity drop analysis."""
    from losshound.core.drop_analyzer import (
        format_drop_report, run_drop_analysis,
    )
    from losshound.core.gateway import detect_gateway

    print("Losshound Drop Analyzer")
    print("=" * 65)
    print("  Detecting gateway...")

    gw = detect_gateway()
    if not gw:
        print("  ERROR: Could not detect gateway. Check your network connection.")
        return

    print(f"  Gateway:      {gw}")
    print(f"  WAN target:   {wan_target}")
    print(f"  Duration:     {duration}s")
    print(f"  Poll interval:{interval}s")
    print()
    print("  Starting rapid connectivity monitoring...")
    print("  (Press Ctrl+C to stop early)\n")

    try:
        report = run_drop_analysis(
            gateway=gw,
            wan_target=wan_target,
            duration_seconds=duration,
            poll_interval=interval,
            progress_callback=lambda msg: print(msg),
        )
    except KeyboardInterrupt:
        print("\n  Scan interrupted — analyzing collected data...\n")
        return

    print()
    print(format_drop_report(report))


def _cmd_qos(app: str, priority: str):
    """Add and apply a QoS rule for an application."""
    from pathlib import Path
    from losshound.core.qos import (
        PRIORITY_PRESETS, QosRule, apply_rule, load_saved_rules, save_rules,
    )

    if priority not in PRIORITY_PRESETS:
        print(f"Unknown priority '{priority}'. Choose from: {', '.join(PRIORITY_PRESETS)}")
        return

    dscp = PRIORITY_PRESETS[priority]
    name = Path(app).stem if "\\" in app or "/" in app else app.replace(".exe", "")

    rule = QosRule(
        name=name, app_path=app,
        priority_preset=priority, dscp_value=dscp,
    )

    print(f"Losshound QoS — {name}")
    print("=" * 50)
    print(f"  App:      {app}")
    print(f"  Priority: {priority} (DSCP {dscp})")
    print()

    result = apply_rule(rule)
    if result.success:
        print(f"  OK: {result.message}")
        # Save to persistent rules
        rules = load_saved_rules()
        rules = [r for r in rules if r.name != name]
        rules.append(rule)
        save_rules(rules)
        print(f"  Rule saved.")
    else:
        print(f"  FAILED: {result.message}")


def _cmd_qos_list():
    """List all QoS rules."""
    from losshound.core.qos import get_existing_policies, load_saved_rules

    print("Losshound QoS Rules")
    print("=" * 60)

    rules = load_saved_rules()
    if rules:
        print(f"\n  Saved rules ({len(rules)}):")
        print(f"  {'Name':<20} {'App':<25} {'Priority':<12} {'DSCP':<6}")
        print(f"  {'-'*20} {'-'*25} {'-'*12} {'-'*6}")
        for r in rules:
            print(f"  {r.name:<20} {r.app_path:<25} {r.priority_preset:<12} {r.dscp_value:<6}")
    else:
        print("\n  No saved rules.")

    policies = get_existing_policies()
    lh_policies = [p for p in policies if p.get("Name", "").startswith("Losshound_")]
    if lh_policies:
        print(f"\n  Active Windows policies ({len(lh_policies)}):")
        for p in lh_policies:
            print(f"    {p.get('Name', '')} -> DSCP {p.get('DSCPAction', 'N/A')}")


def _cmd_qos_clear():
    """Remove all Losshound QoS policies."""
    from losshound.core.qos import remove_all_losshound_policies

    print("Removing all Losshound QoS policies...")
    results = remove_all_losshound_policies()
    if not results:
        print("  No Losshound policies found.")
    for r in results:
        status = "OK" if r.success else "FAILED"
        print(f"  [{status}] {r.rule_name}: {r.message}")


def _cmd_isp_report(hours: int, output: str | None, pdf_path: str | None = None):
    """Generate ISP report (text or PDF)."""
    from losshound.core.isp_report import format_isp_report, generate_isp_report
    from losshound.storage.history import HistoryStore

    print(f"Generating ISP report (last {hours} hours)...")

    store = HistoryStore()
    try:
        report = generate_isp_report(store, hours)
    finally:
        store.close()

    if pdf_path:
        from pathlib import Path
        from losshound.core.isp_report_pdf import render_isp_report_pdf
        out = render_isp_report_pdf(report, Path(pdf_path))
        print(f"PDF report saved to: {out}")
        return

    text = format_isp_report(report)
    if output:
        from pathlib import Path
        Path(output).write_text(text, encoding="utf-8")
        print(f"Report saved to: {output}")
    else:
        print(text)
