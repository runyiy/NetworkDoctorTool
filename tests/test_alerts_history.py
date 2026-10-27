from datetime import datetime, timedelta
from pathlib import Path

from losshound.storage.history import HistoryStore, AlertRow


def test_save_and_recent_alert(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    try:
        ts = datetime(2026, 5, 11, 18, 0, 0)
        alert_id = store.save_alert(
            ts, "lan_issue", "warning",
            "LAN issue", "Gateway unreachable",
        )
        assert alert_id > 0

        rows = store.recent_alerts()
        assert len(rows) == 1
        row = rows[0]
        assert isinstance(row, AlertRow)
        assert row.category == "lan_issue"
        assert row.severity == "warning"
        assert row.resolved_at is None
    finally:
        store.close()


def test_resolve_alert_marks_latest(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    try:
        t0 = datetime(2026, 5, 11, 18, 0, 0)
        store.save_alert(t0, "dns_issue", "warning", "DNS", "DNS slow")
        store.save_alert(
            t0 + timedelta(minutes=1),
            "dns_issue", "critical", "DNS", "DNS failing",
        )

        resolved_at = t0 + timedelta(minutes=5)
        resolved_id = store.resolve_alert("dns_issue", resolved_at)
        assert resolved_id > 0

        rows = store.recent_alerts()
        assert rows[0].resolved_at == resolved_at.isoformat()
        assert rows[1].resolved_at is None  # only latest resolved
    finally:
        store.close()


def test_resolve_alert_returns_minus_one_when_no_open_alert(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    try:
        assert store.resolve_alert("lan_issue", datetime.now()) == -1
    finally:
        store.close()
