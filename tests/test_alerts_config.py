from losshound.core.config import AppConfig, AlertsConfig, load_config, save_config


def test_default_alerts_config():
    c = AppConfig()
    assert c.alerts.enabled is True
    assert c.alerts.min_duration_seconds == 30
    assert "lan_issue" in c.alerts.categories


def test_pdf_default_dir_defaults_to_none():
    c = AppConfig()
    assert c.pdf_default_dir is None


def test_alerts_config_round_trip(tmp_path):
    cfg = AppConfig()
    cfg.alerts.min_duration_seconds = 90
    cfg.alerts.categories = ["dns_issue"]
    cfg.pdf_default_dir = str(tmp_path)

    dest = tmp_path / "config.json"
    save_config(cfg, str(dest))
    loaded = load_config(str(dest))

    assert loaded.alerts.min_duration_seconds == 90
    assert loaded.alerts.categories == ["dns_issue"]
    assert loaded.pdf_default_dir == str(tmp_path)


def test_webhook_urls_default_to_none():
    c = AppConfig()
    assert c.alerts.discord_webhook_url is None
    assert c.alerts.generic_webhook_url is None


def test_webhook_urls_round_trip(tmp_path):
    cfg = AppConfig()
    cfg.alerts.discord_webhook_url = "https://discord.com/api/webhooks/123/abc"
    cfg.alerts.generic_webhook_url = "https://webhook.site/test"

    dest = tmp_path / "config.json"
    save_config(cfg, str(dest))
    loaded = load_config(str(dest))

    assert loaded.alerts.discord_webhook_url == cfg.alerts.discord_webhook_url
    assert loaded.alerts.generic_webhook_url == cfg.alerts.generic_webhook_url
