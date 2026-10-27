"""Webhook notification dispatcher."""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Optional

from losshound.core.alerts import AlertEvent
from losshound.core.config import AlertsConfig

logger = logging.getLogger(__name__)


_SEVERITY_COLORS = {
    "info":     0x89b4fa,  # blue (resolution)
    "warning":  0xf9e2af,  # yellow
    "critical": 0xf38ba8,  # red
}


def format_discord_payload(event: AlertEvent) -> dict:
    """Build a Discord webhook payload with a colored embed."""
    color = _SEVERITY_COLORS.get(event.severity, 0x6c7086)
    return {
        "embeds": [{
            "title": f"Losshound — {event.title}",
            "description": event.message,
            "color": color,
            "timestamp": event.timestamp.isoformat(),
            "footer": {"text": f"Severity: {event.severity}"},
        }]
    }


def format_generic_payload(event: AlertEvent) -> dict:
    """Build a generic JSON payload — flat dict with all event fields.

    Stable contract: fields only get added in future versions, never
    renamed or removed.
    """
    return {
        "source": "losshound",
        "timestamp": event.timestamp.isoformat(),
        "category": event.category,
        "severity": event.severity,
        "title": event.title,
        "message": event.message,
        "is_resolution": event.is_resolution,
    }


def post_webhook(url: str, payload: dict, timeout: float = 10.0) -> bool:
    """POST ``payload`` as JSON to ``url``. Returns True on 2xx.

    Logs failure categories without URLs or exception text, which can contain
    webhook credentials. Never raises — callers that
    fire-and-forget can ignore the return value.
    """
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Losshound/0.1",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 0)
            return 200 <= status < 300
    except urllib.error.HTTPError as exc:
        logger.warning("Webhook POST returned HTTP %s", exc.code)
        return False
    except urllib.error.URLError:
        logger.warning("Webhook POST failed (network)")
        return False
    except Exception as exc:
        # Tracebacks/exception messages can repeat the secret-bearing URL.
        logger.warning("Webhook POST failed (%s)", type(exc).__name__)
        return False


class NotificationDispatcher:
    """Routes AlertEvents to configured webhook channels.

    Each dispatch fires-and-forgets in daemon threads so the GUI
    thread is never blocked by network I/O.
    """

    def __init__(self, config: AlertsConfig):
        self._config = config

    def update_config(self, config: AlertsConfig) -> None:
        self._config = config

    def dispatch(self, event: AlertEvent) -> list[threading.Thread]:
        """Dispatch an event to all configured channels.

        Returns the list of threads spawned (empty if nothing was
        configured). Callers may join() them for deterministic tests;
        production callers can ignore the return value.
        """
        # Snapshot the config locally so a concurrent update_config can't
        # cause us to read a half-replaced state (e.g. new discord URL
        # but old generic URL).
        cfg = self._config
        discord = _clean_url(cfg.discord_webhook_url)
        generic = _clean_url(cfg.generic_webhook_url)

        threads: list[threading.Thread] = []
        if discord:
            threads.append(
                self._spawn(discord, format_discord_payload(event), "discord")
            )
        if generic:
            threads.append(
                self._spawn(generic, format_generic_payload(event), "generic")
            )
        return threads

    def _spawn(self, url: str, payload: dict, channel: str) -> threading.Thread:
        thread = threading.Thread(
            target=_send,
            args=(url, payload, channel),
            daemon=True,
        )
        thread.start()
        return thread


def _send(url: str, payload: dict, channel: str) -> None:
    ok = post_webhook(url, payload)
    if ok:
        logger.debug("%s webhook delivered", channel)
    else:
        logger.warning("%s webhook FAILED", channel)


def _clean_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return None
    stripped = url.strip()
    if not stripped:
        return None
    return stripped
