"""Keep displayed units and conclusions faithful to the benchmark evidence."""
from dataclasses import replace

import pytest
from PySide6.QtWidgets import QApplication, QLabel

from losshound.core.scoring import SubScore
from losshound.core.trending import MetricTrend, TrendSummary
from losshound.gui.score_tab import ScoreTab


@pytest.fixture
def score_tab(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ScoreTab, "_on_refresh_trends", lambda self: None)
    tab = ScoreTab()
    yield tab
    tab.shutdown()
    tab.close()
    app.processEvents()


def test_bufferbloat_estimate_is_not_displayed_as_measured_percentage(score_tab):
    estimated = SubScore("Bufferbloat", 76, 8.1, "ms (est.)", 0.1, "Good")
    card = score_tab._make_metric_card(estimated)
    reading = card.findChild(QLabel, "metric-reading").text()
    assert "76" in reading and "estimated" in reading
    assert "%" not in reading
    assert "inferred from jitter and loss" in card.findChild(QLabel, "metric-detail").text()
    measured = score_tab._make_metric_card(replace(estimated, raw_value=12, raw_unit="grade"))
    assert "+12" in measured.findChild(QLabel, "metric-reading").text()
    assert "% under load" in measured.findChild(QLabel, "metric-reading").text()


def test_one_benchmark_is_a_baseline_and_metric_units_are_visible(score_tab):
    summary = TrendSummary(
        168, 1, 83, 83, 83, 83, "stable",
        metric_summaries={"dns": MetricTrend("dns", 65.7, 65.7, 65.7, 65.7, "stable")},
    )
    score_tab._populate_metric_table(summary)
    score_tab._populate_patterns(summary)
    assert score_tab._metric_table.item(0, 0).text() == "DNS (ms)"
    assert score_tab._metric_table.item(0, 5).text() == "Baseline"
    assert "1 of 5" in score_tab._patterns_label.text()
    score_tab._populate_metric_table(replace(summary, snapshot_count=5))
    assert score_tab._metric_table.item(0, 5).text() == "Stable"


def test_compact_history_keeps_all_recent_records_in_newest_first_order(score_tab):
    entries = [{"timestamp": f"2026-09-05T10:{i:02d}:00", "label": f"run {i}"} for i in range(35)]
    score_tab._populate_history_table(entries)
    table = score_tab._history_table
    assert table.rowCount() == 30
    assert table.item(0, 1).text() == "run 34"
    assert table.item(29, 1).text() == "run 5"
    assert entries[0]["label"] == "run 0"
