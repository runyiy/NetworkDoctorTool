from datetime import datetime
from pathlib import Path

from losshound.core.alerts import AlertEngine, AlertEvent
from losshound.core.config import AlertsConfig
from losshound.core.models import Diagnosis, DiagnosisCategory
from losshound.storage.history import HistoryStore


def _store(tmp_path: Path) -> HistoryStore:
    return HistoryStore(tmp_path / "h.db")


def _diag(category: DiagnosisCategory, ts: datetime) -> Diagnosis:
    return Diagnosis(
        timestamp=ts, category=category,
        summary="test", explanation="",
        confidence="high", evidence={},
    )


def test_healthy_diagnosis_returns_none(tmp_path: Path):
    store = _store(tmp_path)
    try:
        engine = AlertEngine(AlertsConfig(), store)
        result = engine.feed(_diag(DiagnosisCategory.HEALTHY, datetime.now()))
        assert result is None
    finally:
        store.close()


from datetime import timedelta


def test_idle_then_pending_then_alerted(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(min_duration_seconds=10)
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        # First unhealthy: IDLE → PENDING, no event
        assert engine.feed(_diag(DiagnosisCategory.LAN_ISSUE, t0)) is None

        # Inside min_duration: still PENDING, no event
        assert engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=5))
        ) is None

        # Past min_duration: ALERTED, event fires
        event = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=11))
        )
        assert event is not None
        assert event.category == "lan_issue"
        assert event.severity == "warning"
        assert event.is_resolution is False
    finally:
        store.close()


def test_resolution_emitted_when_alerted_then_healthy(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(min_duration_seconds=5)
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        engine.feed(_diag(DiagnosisCategory.DNS_ISSUE, t0))
        warning = engine.feed(
            _diag(DiagnosisCategory.DNS_ISSUE, t0 + timedelta(seconds=6))
        )
        assert warning is not None and not warning.is_resolution

        resolution = engine.feed(
            _diag(DiagnosisCategory.HEALTHY, t0 + timedelta(seconds=20))
        )
        assert resolution is not None
        assert resolution.is_resolution is True
        assert resolution.category == "dns_issue"
        assert resolution.severity == "info"
    finally:
        store.close()


def test_pending_then_healthy_emits_no_event(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(min_duration_seconds=30)
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        # PENDING but never promoted
        engine.feed(_diag(DiagnosisCategory.LAN_ISSUE, t0))

        result = engine.feed(
            _diag(DiagnosisCategory.HEALTHY, t0 + timedelta(seconds=10))
        )
        assert result is None
    finally:
        store.close()


def test_debounce_silences_within_window(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(min_duration_seconds=5, debounce_seconds=60)
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        engine.feed(_diag(DiagnosisCategory.LAN_ISSUE, t0))
        first = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=6))
        )
        assert first is not None

        # 30s after the alert: within debounce window
        again = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=36))
        )
        assert again is None

        # 70s after the alert: outside debounce window
        again2 = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=80))
        )
        assert again2 is not None
    finally:
        store.close()


def test_snooze_mutes_reemits_but_not_initial_promotion(tmp_path: Path):
    """Snooze only blocks debounce re-emits while a slot is already ALERTED.

    The first IDLE→PENDING→ALERTED promotion still fires; only subsequent
    re-emits inside the snooze window are muted.
    """
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(min_duration_seconds=1, debounce_seconds=1)
        engine = AlertEngine(cfg, store)
        engine.snooze_all(600)

        t0 = datetime.now() + timedelta(seconds=10)
        engine.feed(_diag(DiagnosisCategory.LAN_ISSUE, t0))
        first = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=2))
        )
        assert first is not None  # initial promotion still fires

        again = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=60))
        )
        assert again is None
    finally:
        store.close()


def test_category_disabled_in_config_is_skipped(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(
            min_duration_seconds=1,
            categories=["dns_issue"],   # LAN_ISSUE excluded
        )
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        engine.feed(_diag(DiagnosisCategory.LAN_ISSUE, t0))
        result = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=5))
        )
        assert result is None
    finally:
        store.close()


def test_isp_wan_issue_is_critical_immediately(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(min_duration_seconds=5)
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        engine.feed(_diag(DiagnosisCategory.ISP_WAN_ISSUE, t0))
        event = engine.feed(
            _diag(DiagnosisCategory.ISP_WAN_ISSUE, t0 + timedelta(seconds=6))
        )
        assert event is not None
        assert event.severity == "critical"
    finally:
        store.close()


def test_alerts_disabled_master_returns_none(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(enabled=False, min_duration_seconds=1)
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        engine.feed(_diag(DiagnosisCategory.LAN_ISSUE, t0))
        result = engine.feed(
            _diag(DiagnosisCategory.LAN_ISSUE, t0 + timedelta(seconds=5))
        )
        assert result is None
    finally:
        store.close()


def test_alert_persisted_to_history(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(min_duration_seconds=1)
        engine = AlertEngine(cfg, store)

        t0 = datetime(2026, 5, 11, 18, 0, 0)
        engine.feed(_diag(DiagnosisCategory.DNS_ISSUE, t0))
        engine.feed(_diag(DiagnosisCategory.DNS_ISSUE, t0 + timedelta(seconds=5)))

        rows = store.recent_alerts()
        assert len(rows) == 1
        assert rows[0].category == "dns_issue"
        assert rows[0].severity == "warning"
        assert rows[0].resolved_at is None

        # Recovery resolves the row
        engine.feed(_diag(DiagnosisCategory.HEALTHY, t0 + timedelta(seconds=30)))
        rows2 = store.recent_alerts()
        assert rows2[0].resolved_at is not None
    finally:
        store.close()


def test_snooze_uses_configured_duration(tmp_path: Path):
    store = _store(tmp_path)
    try:
        cfg = AlertsConfig(snooze_seconds=120)
        engine = AlertEngine(cfg, store)

        applied = engine.snooze()
        assert applied == 120
        # _snooze_until should be ~120s in the future (within 5s slack)
        gap = (engine._snooze_until - datetime.now()).total_seconds()
        assert 115 <= gap <= 121
    finally:
        store.close()
