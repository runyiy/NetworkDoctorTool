"""Smart tray-alert engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from losshound.core.config import AlertsConfig
from losshound.core.models import Diagnosis, DiagnosisCategory
from losshound.storage.history import HistoryStore

logger = logging.getLogger(__name__)


class _State(Enum):
    IDLE = "idle"
    PENDING = "pending"
    ALERTED = "alerted"


@dataclass
class _Slot:
    state: _State = _State.IDLE
    since: Optional[datetime] = None
    last_fired: Optional[datetime] = None


@dataclass
class AlertEvent:
    timestamp: datetime
    category: str          # DiagnosisCategory.value
    severity: str          # "info" | "warning" | "critical"
    title: str
    message: str
    is_resolution: bool = False


class AlertEngine:
    """State machine that converts Diagnosis stream to AlertEvent stream."""

    def __init__(self, config: AlertsConfig, history: HistoryStore):
        self._config = config
        self._history = history
        self._slots: dict[str, _Slot] = {}
        self._snooze_until: Optional[datetime] = None

    def update_config(self, config: AlertsConfig) -> None:
        self._config = config

    def snooze_all(self, seconds: int) -> None:
        self._snooze_until = datetime.now() + timedelta(seconds=seconds)

    def snooze(self) -> int:
        """Snooze for the duration configured in AlertsConfig.snooze_seconds.

        Returns the seconds applied — useful for displaying a confirmation.
        """
        seconds = self._config.snooze_seconds
        self.snooze_all(seconds)
        return seconds

    def recent_alerts(self, limit: int = 10):
        """Return the most recent persisted alerts (delegates to history store)."""
        return self._history.recent_alerts(limit)

    def feed(self, diag: Diagnosis) -> Optional[AlertEvent]:
        if not self._config.enabled:
            return None
        if diag.category == DiagnosisCategory.HEALTHY:
            return self._handle_healthy(diag.timestamp)
        return self._handle_unhealthy(diag)

    # -- private --------------------------------------------------------

    def _handle_healthy(self, now: datetime) -> Optional[AlertEvent]:
        resolution: Optional[AlertEvent] = None
        for cat, slot in list(self._slots.items()):
            if slot.state == _State.ALERTED:
                slot.state = _State.IDLE
                slot.since = None
                slot.last_fired = None
                self._history.resolve_alert(cat, now)
                if resolution is None:
                    resolution = AlertEvent(
                        timestamp=now, category=cat,
                        severity="info",
                        title="Network recovered",
                        message=f"{cat.replace('_', ' ').title()} cleared.",
                        is_resolution=True,
                    )
            elif slot.state == _State.PENDING:
                slot.state = _State.IDLE
                slot.since = None
        return resolution

    def _handle_unhealthy(self, diag: Diagnosis) -> Optional[AlertEvent]:
        cat = diag.category.value
        if cat not in self._config.categories:
            self._slots.pop(cat, None)  # clear any stale state
            return None

        slot = self._slots.setdefault(cat, _Slot())
        now = diag.timestamp

        if slot.state == _State.IDLE:
            slot.state = _State.PENDING
            slot.since = now
            return None

        if slot.state == _State.PENDING:
            elapsed = (now - (slot.since or now)).total_seconds()
            if elapsed >= self._config.min_duration_seconds:
                slot.state = _State.ALERTED
                slot.last_fired = now
                return self._fire(cat, diag, now, slot, escalated=False)
            return None

        # ALERTED
        if self._snooze_until and now < self._snooze_until:
            return None
        gap = (now - (slot.last_fired or now)).total_seconds()
        if gap < self._config.debounce_seconds:
            return None
        slot.last_fired = now
        return self._fire(cat, diag, now, slot, escalated=True)

    def _fire(self, cat: str, diag: Diagnosis, now: datetime,
              slot: _Slot, escalated: bool) -> AlertEvent:
        if diag.category == DiagnosisCategory.ISP_WAN_ISSUE:
            severity = "critical"
        elif escalated and slot.since and \
                (now - slot.since).total_seconds() >= 300:
            severity = "critical"
        else:
            severity = "warning"

        title = diag.category.value.replace("_", " ").title()
        message = diag.summary or "Network issue detected."

        self._history.save_alert(now, cat, severity, title, message)
        return AlertEvent(
            timestamp=now, category=cat, severity=severity,
            title=title, message=message, is_resolution=False,
        )
