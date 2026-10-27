from datetime import datetime

import logging
import urllib.error
from unittest.mock import MagicMock

import pytest

from losshound.core.alerts import AlertEvent
from losshound.core.config import AlertsConfig
from losshound.core.notifications import (
    format_discord_payload,
    format_generic_payload,
)


def _event(severity: str = "warning", is_resolution: bool = False) -> AlertEvent:
    return AlertEvent(
        timestamp=datetime(2026, 5, 11, 18, 42, 13),
        category="lan_issue",
        severity=severity,
        title="Lan Issue",
        message="Gateway 192.168.1.1 is unreachable.",
        is_resolution=is_resolution,
    )


# -- Discord payload -----------------------------------------------

def test_format_discord_payload_basic():
    payload = format_discord_payload(_event(severity="warning"))

    assert "embeds" in payload
    assert isinstance(payload["embeds"], list)
    assert len(payload["embeds"]) == 1

    embed = payload["embeds"][0]
    assert embed["title"] == "Losshound — Lan Issue"
    assert "Gateway 192.168.1.1 is unreachable." in embed["description"]
    assert embed["timestamp"] == "2026-05-11T18:42:13"
    assert embed["color"] == 0xf9e2af  # warning -> yellow
    assert "warning" in embed["footer"]["text"]


def test_format_discord_payload_critical_is_red():
    payload = format_discord_payload(_event(severity="critical"))
    assert payload["embeds"][0]["color"] == 0xf38ba8


def test_format_discord_payload_resolution_is_blue():
    payload = format_discord_payload(
        _event(severity="info", is_resolution=True)
    )
    assert payload["embeds"][0]["color"] == 0x89b4fa


# -- Generic payload -----------------------------------------------

def test_format_generic_payload_basic():
    payload = format_generic_payload(_event(severity="warning"))

    assert payload["source"] == "losshound"
    assert payload["timestamp"] == "2026-05-11T18:42:13"
    assert payload["category"] == "lan_issue"
    assert payload["severity"] == "warning"
    assert payload["title"] == "Lan Issue"
    assert payload["message"] == "Gateway 192.168.1.1 is unreachable."
    assert payload["is_resolution"] is False


def test_format_generic_payload_resolution():
    payload = format_generic_payload(
        _event(severity="info", is_resolution=True)
    )
    assert payload["is_resolution"] is True
    assert payload["severity"] == "info"


# -- post_webhook --------------------------------------------------

def test_post_webhook_returns_true_on_2xx(monkeypatch):
    from losshound.core.notifications import post_webhook
    captured = {}

    class _FakeResponse:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return b""

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["data"] = req.data
        captured["timeout"] = timeout
        return _FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    ok = post_webhook("https://example.com/h", {"hello": "world"}, timeout=5)
    assert ok is True
    assert captured["url"] == "https://example.com/h"
    assert b'"hello"' in captured["data"]
    assert captured["timeout"] == 5


def test_post_webhook_returns_false_on_http_error(monkeypatch):
    from losshound.core.notifications import post_webhook
    import urllib.error

    def _fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 500, "Server Error", {}, None
        )

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    ok = post_webhook("https://example.com/h", {})
    assert ok is False


def test_post_webhook_returns_false_on_url_error(monkeypatch):
    from losshound.core.notifications import post_webhook
    import urllib.error

    def _fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    ok = post_webhook("https://example.com/h", {})
    assert ok is False


def test_post_webhook_returns_false_on_unexpected_exception(monkeypatch):
    from losshound.core.notifications import post_webhook

    def _fake_urlopen(req, timeout=None):
        raise RuntimeError("something weird")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    ok = post_webhook("https://example.com/h", {})
    assert ok is False


# -- NotificationDispatcher ----------------------------------------

def test_dispatcher_skips_when_no_urls_configured(monkeypatch):
    from losshound.core.notifications import NotificationDispatcher
    calls = []
    monkeypatch.setattr(
        "losshound.core.notifications.post_webhook",
        lambda *a, **kw: calls.append(a) or True,
    )

    cfg = AlertsConfig()
    dispatcher = NotificationDispatcher(cfg)
    threads = dispatcher.dispatch(_event())
    for t in threads:
        t.join(timeout=2.0)

    assert calls == []


def test_dispatcher_posts_to_discord_only(monkeypatch):
    from losshound.core.notifications import NotificationDispatcher
    captured = []
    monkeypatch.setattr(
        "losshound.core.notifications.post_webhook",
        lambda url, payload, timeout=10.0: captured.append((url, payload)) or True,
    )

    cfg = AlertsConfig(discord_webhook_url="https://discord.example/h")
    dispatcher = NotificationDispatcher(cfg)
    threads = dispatcher.dispatch(_event())
    for t in threads:
        t.join(timeout=2.0)

    assert len(captured) == 1
    url, payload = captured[0]
    assert url == "https://discord.example/h"
    assert "embeds" in payload  # Discord shape


def test_dispatcher_posts_to_both_when_both_configured(monkeypatch):
    from losshound.core.notifications import NotificationDispatcher
    captured = []
    monkeypatch.setattr(
        "losshound.core.notifications.post_webhook",
        lambda url, payload, timeout=10.0: captured.append((url, payload)) or True,
    )

    cfg = AlertsConfig(
        discord_webhook_url="https://discord.example/h",
        generic_webhook_url="https://generic.example/h",
    )
    dispatcher = NotificationDispatcher(cfg)
    threads = dispatcher.dispatch(_event())
    for t in threads:
        t.join(timeout=2.0)

    urls = sorted(u for u, _ in captured)
    assert urls == ["https://discord.example/h", "https://generic.example/h"]

    # Verify each got the right payload shape
    discord_payload = next(p for u, p in captured if "discord" in u)
    generic_payload = next(p for u, p in captured if "generic" in u)
    assert "embeds" in discord_payload
    assert generic_payload.get("source") == "losshound"


def test_dispatcher_update_config_swaps_urls(monkeypatch):
    from losshound.core.notifications import NotificationDispatcher
    captured = []
    monkeypatch.setattr(
        "losshound.core.notifications.post_webhook",
        lambda url, payload, timeout=10.0: captured.append(url) or True,
    )

    cfg = AlertsConfig(discord_webhook_url="https://old.example/h")
    dispatcher = NotificationDispatcher(cfg)

    new_cfg = AlertsConfig(discord_webhook_url="https://new.example/h")
    dispatcher.update_config(new_cfg)

    threads = dispatcher.dispatch(_event())
    for t in threads:
        t.join(timeout=2.0)
    assert captured == ["https://new.example/h"]


def test_dispatcher_treats_blank_urls_as_unconfigured(monkeypatch):
    """Empty string in config should be treated like None."""
    from losshound.core.notifications import NotificationDispatcher
    calls = []
    monkeypatch.setattr(
        "losshound.core.notifications.post_webhook",
        lambda *a, **kw: calls.append(a) or True,
    )

    cfg = AlertsConfig(
        discord_webhook_url="",
        generic_webhook_url="   ",
    )
    dispatcher = NotificationDispatcher(cfg)
    threads = dispatcher.dispatch(_event())
    for t in threads:
        t.join(timeout=2.0)

    assert calls == []


@pytest.mark.parametrize("failure", ["http", "network", "unexpected", "non_2xx"])
def test_failed_webhooks_never_log_url_credentials_or_exception_text(monkeypatch, caplog, failure):
    from losshound.core.notifications import _send

    url = "https://SYNTHETIC_USER:SYNTHETIC_PASSWORD@example.invalid/SYNTHETIC_PATH?token=SYNTHETIC_TOKEN"

    def fail_request(req, timeout):
        if failure == "http":
            raise urllib.error.HTTPError(url, 401, url, {}, None)
        if failure == "network":
            raise urllib.error.URLError(url)
        if failure == "unexpected":
            raise RuntimeError(url)
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 400
        return response

    monkeypatch.setattr("urllib.request.urlopen", fail_request)
    with caplog.at_level(logging.WARNING, logger="losshound.core.notifications"):
        _send(url, {}, "discord")
    assert "discord webhook FAILED" in caplog.text
    for secret in (url, "SYNTHETIC_USER", "SYNTHETIC_PASSWORD", "SYNTHETIC_PATH", "SYNTHETIC_TOKEN"):
        assert secret not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


def test_invalid_webhook_url_does_not_leak_into_logs(caplog):
    from losshound.core.notifications import post_webhook

    with caplog.at_level(logging.WARNING, logger="losshound.core.notifications"):
        assert post_webhook("SYNTHETIC_INVALID_SECRET", {}) is False
    assert "SYNTHETIC_INVALID_SECRET" not in caplog.text
    assert "ValueError" in caplog.text
