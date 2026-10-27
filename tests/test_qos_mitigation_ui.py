import os

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_dashboard_qos_offer_emits_requested_app(qapp, mock_dashboard_interface):
    from losshound.gui.dashboard import DashboardTab

    dashboard = DashboardTab()
    requested: list[str] = []
    dashboard.qos_apply_requested.connect(requested.append)

    dashboard.show_qos_offer("steam.exe", "local traffic 10 down / 2 up Mbps")
    dashboard.qos_mitigation_panel._apply_button.click()

    assert requested == ["steam.exe"]
    assert not dashboard.qos_mitigation_panel.isHidden()


def test_qos_tab_lag_mitigation_saves_and_applies(qapp, monkeypatch):
    import losshound.gui.qos_tab as qos_tab

    saved_snapshots = []
    monkeypatch.setattr(qos_tab, "load_saved_rules", lambda: [])
    monkeypatch.setattr(
        qos_tab,
        "save_rules",
        lambda rules: saved_snapshots.append(list(rules)),
    )

    tab = qos_tab.QosTab()
    applied = []
    monkeypatch.setattr(tab, "_apply_single", lambda rule: applied.append(rule))

    rule = tab.apply_lag_mitigation("steam.exe")

    assert rule.name == "LagMitigation_steam"
    assert rule.priority_preset == "Bulk"
    assert saved_snapshots[-1] == [rule]
    assert applied == [rule]


def test_qos_delete_keeps_saved_rule_until_policy_removal_is_verified(qapp, monkeypatch):
    import losshound.gui.qos_tab as qos_tab
    from losshound.core.qos import QosResult, QosRule

    rule = QosRule("GameRule", "game.exe", "High", 34)
    saved_snapshots = []
    monkeypatch.setattr(qos_tab, "load_saved_rules", lambda: [rule])
    monkeypatch.setattr(
        qos_tab,
        "save_rules",
        lambda rules: saved_snapshots.append(list(rules)),
    )
    tab = qos_tab.QosTab()

    assert tab._table.item(0, 3).text() == "Ready to apply"

    failed_worker = qos_tab._RemoveWorker(rule.name)
    tab._threads.append(failed_worker)
    tab._pending_deletes[failed_worker] = rule
    failed_worker.finished.connect(tab._on_delete_policy_done)
    failed_worker.finished.emit(
        QosResult(rule.name, False, "failed", "access denied")
    )

    assert tab._rules == [rule]
    assert saved_snapshots == []
    assert "saved rule kept" in tab._status_label.text()

    success_worker = qos_tab._RemoveWorker(rule.name)
    tab._threads.append(success_worker)
    tab._pending_deletes[success_worker] = rule
    success_worker.finished.connect(tab._on_delete_policy_done)
    success_worker.finished.emit(
        QosResult(rule.name, True, "removed", "removed")
    )

    assert tab._rules == []
    assert saved_snapshots[-1] == []
