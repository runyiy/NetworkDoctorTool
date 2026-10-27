import json

import pytest

from losshound.core.read_only_policy import NetworkModificationDisabledError
from unittest.mock import MagicMock, patch

from losshound.core.qos import (
    PRIORITY_PRESETS,
    QosRule,
    _run,
    apply_rule,
    build_lag_mitigation_rule,
    load_saved_rules,
    remove_rule,
)


def test_qos_runner_uses_interruptible_subprocess():
    with patch(
        "losshound.core.qos.run_subprocess_interruptible",
        return_value=("out", "err", 7),
    ) as mock_run:
        result = _run(["powershell", "-NoProfile"], timeout=3)

    mock_run.assert_called_once_with(["powershell", "-NoProfile"], 3)
    assert result.stdout == "out"
    assert result.stderr == "err"
    assert result.returncode == 7


def test_build_lag_mitigation_rule_defaults_to_bulk_priority():
    rule = build_lag_mitigation_rule("C:\\Program Files\\Steam\\steam.exe")

    assert rule.name == "LagMitigation_steam"
    assert rule.app_path == "steam.exe"
    assert rule.priority_preset == "Bulk"
    assert rule.dscp_value == PRIORITY_PRESETS["Bulk"]
    assert "lag attribution" in rule.note


def test_build_lag_mitigation_rule_bounds_long_rule_names():
    rule = build_lag_mitigation_rule("x" * 100 + ".exe")
    assert len(rule.name) <= 64


def test_apply_rule_is_disabled_before_admin_check():
    rule = QosRule(name="LagMitigation_steam", app_path="steam.exe", priority_preset="Bulk", dscp_value=8)
    with patch("losshound.core.qos.check_admin", return_value=False) as admin, \
         patch("losshound.core.qos._run") as run:
        with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
            apply_rule(rule)
    admin.assert_not_called()
    run.assert_not_called()


def test_qos_write_entries_reject_valid_and_injection_inputs_before_commands():
    rules = [
        QosRule(name="Game_Rule", app_path=r"C:\games\game.exe", priority_preset="Realtime", dscp_value=46),
        QosRule(name="Game'; Start-Process calc; '", app_path="game.exe", priority_preset="Realtime", dscp_value=46),
        QosRule(name="GameRule", app_path="game.exe'; Start-Process calc; '", priority_preset="Realtime", dscp_value=46),
    ]
    with patch("losshound.core.qos.check_admin", return_value=True) as admin, \
         patch("losshound.core.qos._run") as run:
        for rule in rules:
            with pytest.raises(NetworkModificationDisabledError):
                apply_rule(rule)
            with pytest.raises(NetworkModificationDisabledError):
                remove_rule(rule.name)
    admin.assert_not_called()
    run.assert_not_called()


def test_apply_rule_rejects_tampered_dscp_before_powershell():
    rule = QosRule(name="GameRule", app_path="game.exe", priority_preset="Realtime", dscp_value="0; Start-Process calc; #")
    with patch("losshound.core.qos.check_admin") as admin, \
         patch("losshound.core.qos._run") as run:
        with pytest.raises(NetworkModificationDisabledError):
            apply_rule(rule)
    admin.assert_not_called()
    run.assert_not_called()


def test_load_saved_rules_skips_tampered_dscp(tmp_path):
    rules_path = tmp_path / "qos_rules.json"
    rules_path.write_text(
        json.dumps([
            {
                "name": "Good",
                "app_path": "good.exe",
                "priority_preset": "Realtime",
                "dscp_value": 46,
            },
            {
                "name": "Bad",
                "app_path": "bad.exe",
                "priority_preset": "Realtime",
                "dscp_value": "0; Start-Process calc; #",
            },
            {
                "name": 123,
                "app_path": "bad.exe",
                "priority_preset": "Realtime",
                "dscp_value": 46,
            },
            {
                "name": "BadPath",
                "app_path": None,
                "priority_preset": "Realtime",
                "dscp_value": 46,
            },
            {
                "name": "BadPriority",
                "app_path": "bad.exe",
                "priority_preset": "Injected",
                "dscp_value": 46,
            },
            {
                "name": "BadActive",
                "app_path": "bad.exe",
                "priority_preset": "Realtime",
                "dscp_value": 46,
                "active": "yes",
            },
            {
                "name": "BadNote",
                "app_path": "bad.exe",
                "priority_preset": "Realtime",
                "dscp_value": 46,
                "note": [],
            },
            ["not", "a", "rule"],
        ]),
        encoding="utf-8",
    )

    with patch("losshound.core.qos._rules_path", return_value=rules_path):
        rules = load_saved_rules()

    assert [rule.name for rule in rules] == ["Good"]
    assert rules[0].dscp_value == 46
