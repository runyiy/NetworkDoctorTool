"""S1 firewall boundary tests: legacy preferences never change Windows rules.

The former rule-creation/update tests are replaced by refusal tests because
S1 intentionally makes those actions unreachable, including elevated builds.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from losshound.core import firewall
from losshound.core.read_only_policy import NetworkModificationDisabledError


@pytest.mark.parametrize("platform", ["win32", "linux"])
@pytest.mark.parametrize("admin", [False, True])
@pytest.mark.parametrize("frozen", [False, True])
@pytest.mark.parametrize("action,args", [
    (firewall.ensure_lan_discovery_firewall_rules, ()),
    (firewall.remove_lan_discovery_firewall_rules, ()),
    (firewall.apply_firewall_preference, (True,)),
    (firewall.apply_firewall_preference, (False,)),
    (firewall._run_powershell, ("New-NetFirewallRule -Name 'Legacy'",)),
])
def test_legacy_firewall_action_is_blocked_before_any_system_work(
    platform, admin, frozen, action, args,
):
    with patch.object(firewall.sys, "platform", platform), \
         patch.object(firewall.sys, "frozen", frozen, create=True), \
         patch.object(firewall, "_is_running_as_admin", return_value=admin) as is_admin, \
         patch.object(firewall, "_current_executable", return_value=r"C:\Mom's Files\losshound.exe") as executable, \
         patch("subprocess.run") as run:
        with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
            action(*args)
    is_admin.assert_not_called()
    executable.assert_not_called()
    run.assert_not_called()


def test_source_checkout_executable_query_remains_read_only():
    with patch.object(firewall.sys, "platform", "win32"), \
         patch.object(firewall.sys, "frozen", False, create=True), \
         patch("subprocess.run") as run:
        assert firewall._current_executable() == ""
    run.assert_not_called()


def test_frozen_executable_query_does_not_reconcile_firewall():
    with patch.object(firewall.sys, "platform", "win32"), \
         patch.object(firewall.sys, "frozen", True, create=True), \
         patch.object(firewall.sys, "executable", r"C:\app\Losshound.exe"), \
         patch("subprocess.run") as run:
        assert firewall._current_executable() == r"C:\app\Losshound.exe"
    run.assert_not_called()
