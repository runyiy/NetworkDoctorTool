import pytest
from datetime import datetime, timedelta
from losshound.core.trending import (
    analyze_trends,
    detect_time_patterns,
    detect_degradation,
    detect_volatility,
    detect_weekday_weekend_patterns,
)

def test_no_trends():
    summary = analyze_trends([])
    assert summary.snapshot_count == 0
    assert summary.current_score is None

def test_noise_thresholds_filtering():
    # Latency goes from 1.0ms to 1.4ms (a 40% change), but absolute difference is 0.4ms
    # This should NOT trigger degradation because of the noise threshold (min_diff = 5.0, min_val = 25.0)
    benchmarks = []
    base_time = datetime(2026, 5, 26, 12, 0, 0)
    for i in range(20):
        # 10 oldest: 1.0 ms. 10 newest: 1.4 ms
        lat = 1.0 if i < 10 else 1.4
        benchmarks.append({
            "timestamp": (base_time + timedelta(hours=i)).isoformat(),
            "avg_latency_ms": lat,
            "overall_score": 95.0,
        })
        
    summary = analyze_trends(benchmarks)
    # Check that no degradation pattern is detected for latency
    lat_patterns = [p for p in summary.patterns if p.metric == "latency"]
    assert len(lat_patterns) == 0

def test_degradation_detected_above_threshold():
    # Latency goes from 10ms to 30ms (a 200% change, absolute diff is 20ms, which is > 5ms, and 30ms is > 25ms)
    benchmarks = []
    base_time = datetime(2026, 5, 26, 12, 0, 0)
    for i in range(20):
        lat = 10.0 if i < 10 else 30.0
        benchmarks.append({
            "timestamp": (base_time + timedelta(hours=i)).isoformat(),
            "avg_latency_ms": lat,
            "overall_score": 95.0,
        })
        
    summary = analyze_trends(benchmarks)
    lat_patterns = [p for p in summary.patterns if p.metric == "latency" and p.pattern_type == "degradation"]
    assert len(lat_patterns) == 1
    assert lat_patterns[0].pattern_type == "degradation"
    assert "degraded" in lat_patterns[0].description
    assert lat_patterns[0].confidence > 0.0

def test_weekday_vs_weekend_pattern():
    # Create 10 weekdays (e.g. Wednesday) and 10 weekends (e.g. Sunday)
    # We want weekday latency to be 40ms, weekend latency to be 10ms
    # Difference = 30ms, which is > 5ms and 40ms > 25ms. Relative diff relative to weekend is 300%.
    benchmarks = []
    
    # 2026-05-27 is Wednesday (weekday)
    weekday_base = datetime(2026, 5, 27, 12, 0, 0)
    # 2026-05-31 is Sunday (weekend)
    weekend_base = datetime(2026, 5, 31, 12, 0, 0)
    
    for i in range(5):
        benchmarks.append({
            "timestamp": (weekday_base + timedelta(days=i*7)).isoformat(),
            "avg_latency_ms": 40.0,
            "overall_score": 80.0,
        })
        benchmarks.append({
            "timestamp": (weekend_base + timedelta(days=i*7)).isoformat(),
            "avg_latency_ms": 10.0,
            "overall_score": 95.0,
        })
        
    summary = analyze_trends(benchmarks)
    wday_patterns = [p for p in summary.patterns if p.pattern_type == "weekday_vs_weekend"]
    assert len(wday_patterns) > 0
    # The worse group is weekday
    assert wday_patterns[0].data["worse_on"] == "weekday"
    assert "worse on weekdays" in wday_patterns[0].description
