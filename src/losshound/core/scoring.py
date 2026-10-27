"""Network quality scoring engine.

Converts a :class:`BenchmarkSnapshot` (and optionally a
:class:`LoadBenchmarkSnapshot`) into a 0–100 network score with
per-metric sub-scores.  The scoring is tuned for gaming / real-time
communication where low latency and low jitter matter most.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SubScore:
    """Individual metric score."""

    name: str
    value: float          # 0-100
    raw_value: float      # original measurement
    raw_unit: str         # "ms", "%", "grade"
    weight: float         # weight used in composite
    rating: str           # "Excellent", "Good", "Fair", "Poor", "Bad"


@dataclass
class NetworkScore:
    """Composite network quality score."""

    overall: float                    # 0-100 weighted composite
    grade: str                        # A / B / C / D / F
    rating: str                       # "Excellent" … "Bad"
    sub_scores: list[SubScore] = field(default_factory=list)
    timestamp: str = ""
    label: str = ""


# ---------------------------------------------------------------------------
# Scoring curves
# ---------------------------------------------------------------------------

# Each tuple is (ideal_value, worst_value).  Score is 100 at ideal, 0 at worst,
# linearly interpolated and clamped.

_CURVES: dict[str, tuple[float, float]] = {
    "latency":   (10.0, 200.0),   # ms
    "jitter":    (1.0,  50.0),    # ms
    "loss":      (0.0,  5.0),     # %
    "dns":       (10.0, 200.0),   # ms
    "tcp":       (20.0, 500.0),   # ms
}

# Weights for the gaming/real-time profile
_WEIGHTS: dict[str, float] = {
    "latency":    0.30,
    "jitter":     0.20,
    "loss":       0.25,
    "dns":        0.10,
    "tcp":        0.05,
    "bufferbloat": 0.10,
}

_GRADE_MAP = {
    "A": "Excellent for gaming and real-time apps",
    "B": "Good for most online activities",
    "C": "Adequate but may have occasional lag",
    "D": "Poor — noticeable lag and instability",
    "F": "Very poor — significant connectivity issues",
}


def _clamp_score(value: float, ideal: float, worst: float) -> float:
    """Linear interpolation between ideal (100) and worst (0), clamped."""
    if worst == ideal:
        return 100.0
    score = 100.0 - ((value - ideal) / (worst - ideal)) * 100.0
    return max(0.0, min(100.0, score))


def _rating(score: float) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Poor"
    return "Bad"


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _bufferbloat_score(grade: str) -> float:
    """Convert a letter grade from BufferbloatResult to 0-100."""
    return {"A": 100, "B": 80, "C": 60, "D": 30, "F": 0}.get(grade.upper(), 50)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_snapshot(
    snap,   # BenchmarkSnapshot — imported lazily to avoid circular deps
    load_snap=None,  # Optional[LoadBenchmarkSnapshot]
) -> NetworkScore:
    """Compute a :class:`NetworkScore` from benchmark data.

    Parameters
    ----------
    snap:
        A ``BenchmarkSnapshot`` with aggregate metrics.
    load_snap:
        An optional ``LoadBenchmarkSnapshot``.  If provided, its
        bufferbloat grade is used; otherwise bufferbloat is estimated
        from jitter/loss.
    """
    subs: list[SubScore] = []
    active_weights: dict[str, float] = {}

    # Helper to add a sub-score if the metric is available
    def _add(name: str, raw: Optional[float], unit: str, curve_key: str):
        if raw is None:
            return
        ideal, worst = _CURVES[curve_key]
        val = _clamp_score(raw, ideal, worst)
        w = _WEIGHTS[curve_key]
        active_weights[curve_key] = w
        subs.append(SubScore(
            name=name, value=round(val, 1), raw_value=round(raw, 2),
            raw_unit=unit, weight=w, rating=_rating(val),
        ))

    _add("Latency", snap.avg_latency_ms, "ms", "latency")
    _add("Jitter", snap.avg_jitter_ms, "ms", "jitter")
    _add("Packet Loss", snap.avg_loss_pct, "%", "loss")
    _add("DNS", snap.avg_dns_ms, "ms", "dns")
    _add("TCP Connect", snap.avg_tcp_ms, "ms", "tcp")

    # Bufferbloat
    if load_snap is not None and hasattr(load_snap, "bufferbloat"):
        bb_grade = load_snap.bufferbloat.grade if load_snap.bufferbloat else "C"
        bb_val = _bufferbloat_score(bb_grade)
        raw_val = load_snap.bufferbloat.latency_increase_pct if load_snap.bufferbloat else 0
    else:
        # Estimate from jitter & loss: high jitter + loss suggests bufferbloat
        jit = snap.avg_jitter_ms or 0
        loss = snap.avg_loss_pct or 0
        # Heuristic: a perfect network has <2ms jitter and 0% loss
        estimated = max(0, 100 - (jit * 3 + loss * 10))
        bb_val = estimated
        bb_grade = _grade(bb_val)
        raw_val = jit

    w = _WEIGHTS["bufferbloat"]
    active_weights["bufferbloat"] = w
    subs.append(SubScore(
        name="Bufferbloat",
        value=round(bb_val, 1),
        raw_value=round(raw_val, 2),
        raw_unit="grade" if load_snap else "ms (est.)",
        weight=w,
        rating=_rating(bb_val),
    ))

    # Compute weighted composite (re-normalise weights for available metrics)
    total_weight = sum(active_weights.values())
    if total_weight > 0 and subs:
        overall = sum(
            s.value * (s.weight / total_weight) for s in subs
        )
    else:
        overall = 0.0

    overall = round(overall, 1)

    return NetworkScore(
        overall=overall,
        grade=_grade(overall),
        rating=_rating(overall),
        sub_scores=subs,
        timestamp=getattr(snap, "timestamp", ""),
        label=getattr(snap, "label", ""),
    )


def format_score(score: NetworkScore) -> str:
    """Format a :class:`NetworkScore` for terminal display."""
    lines: list[str] = []
    lines.append("NETWORK SCORE")
    lines.append("=" * 55)
    lines.append("")
    lines.append(f"  Overall: {score.overall:.0f}/100  ({score.grade})  — {score.rating}")
    lines.append(f"  {_GRADE_MAP.get(score.grade, '')}")
    lines.append("")
    lines.append(f"  {'Metric':<16} {'Score':<10} {'Raw':<14} {'Rating':<12}")
    lines.append(f"  {'-'*16} {'-'*10} {'-'*14} {'-'*12}")

    for s in score.sub_scores:
        raw_str = f"{s.raw_value:.1f}{s.raw_unit}"
        lines.append(
            f"  {s.name:<16} {s.value:>5.0f}/100  {raw_str:<14} {s.rating:<12}"
        )

    lines.append("")
    return "\n".join(lines)
