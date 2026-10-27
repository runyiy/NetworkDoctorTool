from __future__ import annotations

from datetime import datetime, timedelta


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def format_ago(dt: datetime) -> str:
    delta = datetime.now() - dt
    secs = delta.total_seconds()
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs / 60:.0f}m ago"
    if secs < 86400:
        return f"{secs / 3600:.0f}h ago"
    return f"{secs / 86400:.0f}d ago"


def format_loss(loss: float) -> str:
    if loss == 0:
        return "0%"
    if loss == 100:
        return "100%"
    return f"{loss:.1f}%"
