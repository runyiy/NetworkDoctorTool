"""Historical trend analysis for network benchmarks.

Analyses stored benchmark snapshots to detect patterns such as
time-of-day degradation, progressive worsening, volatility, and
improvement.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TrendPattern:
    """A detected pattern in the benchmark history."""

    pattern_type: str     # "degradation", "time_of_day", "improving", "stable", "volatile"
    metric: str           # "latency", "jitter", "loss", "dns", "score"
    description: str      # human-readable
    confidence: float     # 0-1
    data: dict = field(default_factory=dict)


@dataclass
class MetricTrend:
    """Summary statistics for a single metric over time."""

    metric: str
    current: Optional[float]
    average: float
    best: float
    worst: float
    trend_direction: str       # "improving", "degrading", "stable"
    percent_change_24h: Optional[float] = None


@dataclass
class TrendSummary:
    """Full trend analysis result."""

    period_hours: int
    snapshot_count: int
    current_score: Optional[float]
    avg_score: Optional[float]
    best_score: Optional[float]
    worst_score: Optional[float]
    score_trend: str                     # "improving", "degrading", "stable"
    patterns: list[TrendPattern] = field(default_factory=list)
    metric_summaries: dict[str, MetricTrend] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Metric extraction
# ---------------------------------------------------------------------------

# Maps metric name to the column key in the benchmark dict rows
_METRIC_KEYS = {
    "latency": "avg_latency_ms",
    "jitter":  "avg_jitter_ms",
    "loss":    "avg_loss_pct",
    "dns":     "avg_dns_ms",
    "tcp":     "avg_tcp_ms",
    "score":   "overall_score",
}

# For these metrics, lower is better
_LOWER_IS_BETTER = {"latency", "jitter", "loss", "dns", "tcp"}


def _extract(benchmarks: list[dict], key: str) -> list[tuple[str, float]]:
    """Return (timestamp, value) pairs for a given key, skipping nulls."""
    pairs: list[tuple[str, float]] = []
    for b in benchmarks:
        val = b.get(key)
        if val is not None:
            pairs.append((b.get("timestamp", ""), float(val)))
    return pairs


# ---------------------------------------------------------------------------
# Pattern detection & Noise thresholds
# ---------------------------------------------------------------------------

_NOISE_THRESHOLDS = {
    "latency": {"min_diff": 5.0, "min_val": 25.0, "min_stdev": 3.0},
    "jitter": {"min_diff": 1.0, "min_val": 3.0, "min_stdev": 0.8},
    "loss": {"min_diff": 0.5, "min_val": 1.0, "min_stdev": 0.3},
    "dns": {"min_diff": 10.0, "min_val": 25.0, "min_stdev": 5.0},
    "tcp": {"min_diff": 20.0, "min_val": 50.0, "min_stdev": 10.0},
    "score": {"min_diff": 5.0, "min_val": 0.0, "min_stdev": 3.0},
}


def detect_time_patterns(
    benchmarks: list[dict], metric: str,
) -> list[TrendPattern]:
    """Group benchmarks by hour-of-day and flag problematic windows."""
    key = _METRIC_KEYS.get(metric)
    if not key:
        return []

    pairs = _extract(benchmarks, key)
    if len(pairs) < 6:
        return []

    # Group by hour
    by_hour: dict[int, list[float]] = {}
    for ts_str, val in pairs:
        try:
            hour = datetime.fromisoformat(ts_str).hour
        except (ValueError, TypeError):
            continue
        by_hour.setdefault(hour, []).append(val)

    if not by_hour:
        return []

    overall_avg = statistics.mean(v for _, v in pairs)
    if overall_avg == 0:
        return []

    lower_better = metric in _LOWER_IS_BETTER
    patterns: list[TrendPattern] = []

    # Scan 4-hour windows
    for start_hour in range(24):
        window_hours = [h % 24 for h in range(start_hour, start_hour + 4)]
        window_vals = []
        for h in window_hours:
            window_vals.extend(by_hour.get(h, []))

        if len(window_vals) < 3:
            continue

        window_avg = statistics.mean(window_vals)
        pct_diff = ((window_avg - overall_avg) / overall_avg) * 100

        # If this window is >30% worse than overall
        is_worse = pct_diff > 30 if lower_better else pct_diff < -30
        
        # Apply absolute noise threshold
        abs_diff = abs(window_avg - overall_avg)
        thresholds = _NOISE_THRESHOLDS.get(metric, {"min_diff": 0.0, "min_val": 0.0})
        min_diff = thresholds.get("min_diff", 0.0)
        min_val = thresholds.get("min_val", 0.0)

        if lower_better:
            meets_threshold = (window_avg >= min_val or overall_avg >= min_val) and abs_diff >= min_diff
        else:
            meets_threshold = abs_diff >= min_diff

        if is_worse and meets_threshold:
            end_hour = (start_hour + 3) % 24
            
            base_conf = min(0.7, len(window_vals) / 12)
            effect_boost = min(0.2, (abs(pct_diff) - 30) / 200)
            confidence = round(base_conf + effect_boost, 2)

            patterns.append(TrendPattern(
                pattern_type="time_of_day",
                metric=metric,
                description=(
                    f"{metric.capitalize()} is {abs(pct_diff):.0f}% worse "
                    f"between {start_hour:02d}:00–{end_hour:02d}:59 "
                    f"(avg {window_avg:.1f} vs overall {overall_avg:.1f})"
                ),
                confidence=confidence,
                data={
                    "start_hour": start_hour,
                    "end_hour": end_hour,
                    "window_avg": round(window_avg, 2),
                    "overall_avg": round(overall_avg, 2),
                    "pct_diff": round(pct_diff, 1),
                },
            ))
            break  # report the worst window only

    return patterns


def detect_degradation(
    benchmarks: list[dict], metric: str,
) -> Optional[TrendPattern]:
    """Compare the newest 25% of snapshots against the oldest 25%."""
    key = _METRIC_KEYS.get(metric)
    if not key:
        return None

    pairs = _extract(benchmarks, key)
    if len(pairs) < 8:
        return None

    quarter = max(2, len(pairs) // 4)
    oldest = [v for _, v in pairs[:quarter]]
    newest = [v for _, v in pairs[-quarter:]]

    old_avg = statistics.mean(oldest)
    new_avg = statistics.mean(newest)

    if old_avg == 0:
        return None

    pct_change = ((new_avg - old_avg) / old_avg) * 100
    lower_better = metric in _LOWER_IS_BETTER

    # >15% worsening
    is_degraded = pct_change > 15 if lower_better else pct_change < -15
    is_improved = pct_change < -15 if lower_better else pct_change > 15

    abs_diff = abs(new_avg - old_avg)
    thresholds = _NOISE_THRESHOLDS.get(metric, {"min_diff": 0.0, "min_val": 0.0})
    min_diff = thresholds.get("min_diff", 0.0)
    min_val = thresholds.get("min_val", 0.0)

    if lower_better:
        meets_degrade_threshold = (new_avg >= min_val) and abs_diff >= min_diff
        meets_improve_threshold = (old_avg >= min_val) and abs_diff >= min_diff
    else:
        meets_degrade_threshold = abs_diff >= min_diff
        meets_improve_threshold = abs_diff >= min_diff

    base_conf = min(0.7, len(pairs) / 25)

    if is_degraded and meets_degrade_threshold:
        effect_boost = min(0.2, (abs(pct_change) - 15) / 100)
        confidence = round(base_conf + effect_boost, 2)
        return TrendPattern(
            pattern_type="degradation",
            metric=metric,
            description=(
                f"{metric.capitalize()} has degraded {abs(pct_change):.0f}% "
                f"(was {old_avg:.1f}, now {new_avg:.1f})"
            ),
            confidence=confidence,
            data={
                "old_avg": round(old_avg, 2),
                "new_avg": round(new_avg, 2),
                "pct_change": round(pct_change, 1),
            },
        )
    if is_improved and meets_improve_threshold:
        effect_boost = min(0.2, (abs(pct_change) - 15) / 100)
        confidence = round(base_conf + effect_boost, 2)
        return TrendPattern(
            pattern_type="improving",
            metric=metric,
            description=(
                f"{metric.capitalize()} has improved {abs(pct_change):.0f}% "
                f"(was {old_avg:.1f}, now {new_avg:.1f})"
            ),
            confidence=confidence,
            data={
                "old_avg": round(old_avg, 2),
                "new_avg": round(new_avg, 2),
                "pct_change": round(pct_change, 1),
            },
        )
    return None


def detect_volatility(
    benchmarks: list[dict], metric: str,
) -> Optional[TrendPattern]:
    """Flag a metric if its coefficient of variation exceeds 0.3."""
    key = _METRIC_KEYS.get(metric)
    if not key:
        return None

    vals = [v for _, v in _extract(benchmarks, key)]
    if len(vals) < 5:
        return None

    mean = statistics.mean(vals)
    if mean == 0:
        return None

    stdev = statistics.stdev(vals)
    cv = stdev / mean

    thresholds = _NOISE_THRESHOLDS.get(metric, {"min_stdev": 0.0})
    min_stdev = thresholds.get("min_stdev", 0.0)

    if cv > 0.3 and stdev >= min_stdev:
        base_conf = min(0.7, len(vals) / 12)
        effect_boost = min(0.2, (cv - 0.3) / 1.0)
        confidence = round(base_conf + effect_boost, 2)

        return TrendPattern(
            pattern_type="volatile",
            metric=metric,
            description=(
                f"{metric.capitalize()} is highly variable "
                f"(CV={cv:.2f}, mean={mean:.1f}, stdev={stdev:.1f})"
            ),
            confidence=confidence,
            data={
                "cv": round(cv, 3),
                "mean": round(mean, 2),
                "stdev": round(stdev, 2),
            },
        )
    return None


def detect_weekday_weekend_patterns(
    benchmarks: list[dict], metric: str,
) -> Optional[TrendPattern]:
    """Compare weekday (Mon-Fri) vs weekend (Sat-Sun) average performance."""
    key = _METRIC_KEYS.get(metric)
    if not key:
        return None

    pairs = _extract(benchmarks, key)
    
    # Group by weekday vs weekend
    weekday_vals = []
    weekend_vals = []
    
    for ts_str, val in pairs:
        try:
            dt = datetime.fromisoformat(ts_str)
            if dt.weekday() < 5:
                weekday_vals.append(val)
            else:
                weekend_vals.append(val)
        except (ValueError, TypeError):
            continue

    if len(weekday_vals) < 3 or len(weekend_vals) < 3:
        return None

    weekday_avg = statistics.mean(weekday_vals)
    weekend_avg = statistics.mean(weekend_vals)
    
    if weekday_avg == 0 or weekend_avg == 0:
        return None

    lower_better = metric in _LOWER_IS_BETTER

    pct_diff = ((weekend_avg - weekday_avg) / weekday_avg) * 100
    
    thresholds = _NOISE_THRESHOLDS.get(metric, {"min_diff": 0.0, "min_val": 0.0})
    min_diff = thresholds.get("min_diff", 0.0)
    min_val = thresholds.get("min_val", 0.0)
    
    abs_diff = abs(weekend_avg - weekday_avg)
    
    is_weekend_worse = pct_diff > 30 if lower_better else pct_diff < -30
    is_weekday_worse = pct_diff < -30 if lower_better else pct_diff > 30
    
    if lower_better:
        meets_weekend_worse = (weekend_avg >= min_val) and abs_diff >= min_diff
        meets_weekday_worse = (weekday_avg >= min_val) and abs_diff >= min_diff
    else:
        meets_weekend_worse = abs_diff >= min_diff
        meets_weekday_worse = abs_diff >= min_diff
        
    base_conf = min(0.7, (len(weekday_vals) + len(weekend_vals)) / 25)
    
    if is_weekend_worse and meets_weekend_worse:
        effect_boost = min(0.2, (abs(pct_diff) - 30) / 200)
        confidence = round(base_conf + effect_boost, 2)
        desc = (
            f"{metric.capitalize()} is {abs(pct_diff):.0f}% worse on weekends "
            f"(avg {weekend_avg:.1f} vs weekday {weekday_avg:.1f})"
        )
        return TrendPattern(
            pattern_type="weekday_vs_weekend",
            metric=metric,
            description=desc,
            confidence=confidence,
            data={
                "weekday_avg": round(weekday_avg, 2),
                "weekend_avg": round(weekend_avg, 2),
                "pct_diff": round(pct_diff, 1),
                "worse_on": "weekend",
            }
        )
    elif is_weekday_worse and meets_weekday_worse:
        pct_diff_relative_to_weekend = ((weekday_avg - weekend_avg) / weekend_avg) * 100
        effect_boost = min(0.2, (abs(pct_diff_relative_to_weekend) - 30) / 200)
        confidence = round(base_conf + effect_boost, 2)
        desc = (
            f"{metric.capitalize()} is {abs(pct_diff_relative_to_weekend):.0f}% worse on weekdays "
            f"(avg {weekday_avg:.1f} vs weekend {weekend_avg:.1f})"
        )
        return TrendPattern(
            pattern_type="weekday_vs_weekend",
            metric=metric,
            description=desc,
            confidence=confidence,
            data={
                "weekday_avg": round(weekday_avg, 2),
                "weekend_avg": round(weekend_avg, 2),
                "pct_diff": round(pct_diff_relative_to_weekend, 1),
                "worse_on": "weekday",
            }
        )

    return None


# ---------------------------------------------------------------------------
# Metric trend summary
# ---------------------------------------------------------------------------

def _metric_trend(
    benchmarks: list[dict], metric: str,
) -> Optional[MetricTrend]:
    """Compute summary statistics for a single metric."""
    key = _METRIC_KEYS.get(metric)
    if not key:
        return None

    pairs = _extract(benchmarks, key)
    if not pairs:
        return None

    vals = [v for _, v in pairs]
    current = vals[-1]
    avg = statistics.mean(vals)
    best = min(vals) if metric in _LOWER_IS_BETTER else max(vals)
    worst = max(vals) if metric in _LOWER_IS_BETTER else min(vals)

    # Trend direction: compare last 25% vs first 25%
    direction = "stable"
    if len(vals) >= 4:
        quarter = max(2, len(vals) // 4)
        old_avg = statistics.mean(vals[:quarter])
        new_avg = statistics.mean(vals[-quarter:])
        if old_avg > 0:
            pct = ((new_avg - old_avg) / old_avg) * 100
            lower_better = metric in _LOWER_IS_BETTER
            if abs(pct) >= 10:
                if (pct > 0) == lower_better:
                    direction = "degrading"
                else:
                    direction = "improving"

    # 24h change: compare most recent vs 24h ago (if data spans that far)
    pct_24h: Optional[float] = None
    if len(pairs) >= 2:
        try:
            latest_ts = datetime.fromisoformat(pairs[-1][0])
            for ts_str, val in pairs:
                ts = datetime.fromisoformat(ts_str)
                diff_hours = (latest_ts - ts).total_seconds() / 3600
                if 20 <= diff_hours <= 28:  # approximately 24h ago
                    if val > 0:
                        pct_24h = ((current - val) / val) * 100
                    break
        except (ValueError, TypeError):
            pass

    return MetricTrend(
        metric=metric,
        current=round(current, 2),
        average=round(avg, 2),
        best=round(best, 2),
        worst=round(worst, 2),
        trend_direction=direction,
        percent_change_24h=round(pct_24h, 1) if pct_24h is not None else None,
    )


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_trends(benchmarks: list[dict], hours: int = 168) -> TrendSummary:
    """Run full trend analysis on benchmark history.

    Parameters
    ----------
    benchmarks:
        List of dicts with keys matching the ``benchmark_snapshots`` table
        columns (timestamp, avg_latency_ms, overall_score, etc.).
    hours:
        The lookback window that produced *benchmarks* (for display).
    """
    if not benchmarks:
        return TrendSummary(
            period_hours=hours, snapshot_count=0,
            current_score=None, avg_score=None,
            best_score=None, worst_score=None,
            score_trend="stable",
        )

    # Score summary
    scores = [b["overall_score"] for b in benchmarks if b.get("overall_score") is not None]
    current_score = scores[-1] if scores else None
    avg_score = round(statistics.mean(scores), 1) if scores else None
    best_score = round(max(scores), 1) if scores else None
    worst_score = round(min(scores), 1) if scores else None

    # Score trend
    score_trend = "stable"
    if len(scores) >= 4:
        q = max(2, len(scores) // 4)
        old = statistics.mean(scores[:q])
        new = statistics.mean(scores[-q:])
        if old > 0:
            pct = ((new - old) / old) * 100
            if pct > 10:
                score_trend = "improving"
            elif pct < -10:
                score_trend = "degrading"

    # Per-metric summaries
    metric_summaries: dict[str, MetricTrend] = {}
    for metric in ("latency", "jitter", "loss", "dns", "tcp"):
        mt = _metric_trend(benchmarks, metric)
        if mt:
            metric_summaries[metric] = mt

    # Detect patterns
    patterns: list[TrendPattern] = []
    for metric in ("latency", "jitter", "loss", "dns", "tcp", "score"):
        patterns.extend(detect_time_patterns(benchmarks, metric))
        deg = detect_degradation(benchmarks, metric)
        if deg:
            patterns.append(deg)
        vol = detect_volatility(benchmarks, metric)
        if vol:
            patterns.append(vol)
        wday = detect_weekday_weekend_patterns(benchmarks, metric)
        if wday:
            patterns.append(wday)

    return TrendSummary(
        period_hours=hours,
        snapshot_count=len(benchmarks),
        current_score=current_score,
        avg_score=avg_score,
        best_score=best_score,
        worst_score=worst_score,
        score_trend=score_trend,
        patterns=patterns,
        metric_summaries=metric_summaries,
    )


def format_trends(summary: TrendSummary) -> str:
    """Format a :class:`TrendSummary` for terminal display."""
    lines: list[str] = []
    lines.append("NETWORK TRENDS")
    lines.append("=" * 65)
    lines.append(f"  Period: last {summary.period_hours}h  |  Snapshots: {summary.snapshot_count}")
    lines.append("")

    if summary.current_score is not None:
        lines.append(f"  Current score: {summary.current_score:.0f}/100")
        lines.append(f"  Average score: {summary.avg_score:.0f}/100  "
                      f"(best: {summary.best_score:.0f}, worst: {summary.worst_score:.0f})")
        arrow = {"improving": "trending up", "degrading": "trending down", "stable": "stable"}
        lines.append(f"  Score trend:   {arrow.get(summary.score_trend, summary.score_trend)}")
    else:
        lines.append("  No scored benchmarks yet. Run: losshound score")

    # Metric summaries
    if summary.metric_summaries:
        lines.append("")
        lines.append(f"  {'Metric':<12} {'Current':<10} {'Avg':<10} {'Best':<10} {'Worst':<10} {'Trend':<12}")
        lines.append(f"  {'-'*12} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*12}")
        for mt in summary.metric_summaries.values():
            cur = f"{mt.current:.1f}" if mt.current is not None else "N/A"
            lines.append(
                f"  {mt.metric:<12} {cur:<10} {mt.average:<10.1f} "
                f"{mt.best:<10.1f} {mt.worst:<10.1f} {mt.trend_direction:<12}"
            )

    # Patterns
    if summary.patterns:
        lines.append("")
        lines.append("  DETECTED PATTERNS")
        lines.append(f"  {'-'*60}")
        for p in summary.patterns:
            icon = {
                "degradation": "[!]",
                "time_of_day": "[T]",
                "improving": "[+]",
                "volatile": "[~]",
                "weekday_vs_weekend": "[W]",
                "stable": "[ ]",
            }.get(p.pattern_type, "[ ]")
            lines.append(f"  {icon} {p.description}")
    elif summary.snapshot_count >= 5:
        lines.append("")
        lines.append("  No concerning patterns detected.")

    lines.append("")
    return "\n".join(lines)

