"""S1 keeps read-only/result tests and rejects legacy optimizer mutations.

Historical exact-restore scenarios now assert no write or backup access; no
restore capability is approved in S1.
"""
from types import SimpleNamespace

import pytest

from losshound.core.read_only_policy import NetworkModificationDisabledError
from unittest.mock import MagicMock, patch

from losshound.core.optimizer import (
    BackupData,
    DnsState,
    NetworkOptimizer,
    TcpSettings,
    _make_result,
)


def _proc(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_make_result_rejects_unchanged_wrong_readback():
    result = _make_result(
        name="TCP auto-tuning",
        success=True,
        before="disabled",
        after="disabled",
        desired="normal",
        needs_admin=True,
        verification="Post-apply read: disabled",
    )

    assert not result.success
    assert result.status == "Failed"
    assert "expected Normal" in result.error
    assert result.after == "Disabled"


@patch("losshound.core.optimizer._run", return_value=_proc())
@patch("losshound.core.optimizer.NetworkOptimizer.get_tcp_settings")
@patch(
    "losshound.core.optimizer.NetworkOptimizer.check_admin",
    return_value=True,
)
def test_optimize_tcp_requires_observed_desired_state(
    _mock_admin, mock_get_tcp_settings, _mock_run,
):
    with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
        NetworkOptimizer().optimize_tcp()
    _mock_admin.assert_not_called()
    mock_get_tcp_settings.assert_not_called()
    _mock_run.assert_not_called()


@patch("losshound.core.optimizer._run")
def test_dns_read_fallback_is_scoped_to_requested_adapter(mock_run):
    mock_run.side_effect = [
        _proc(returncode=1, stderr="PowerShell unavailable"),
        _proc(
            stdout=(
                'Configuration for interface "Ethernet"\n'
                "Statically Configured DNS Servers: 1.1.1.1\n"
                "                                    8.8.8.8\n"
            ),
        ),
    ]

    state = NetworkOptimizer()._get_dns_state("Ethernet")

    assert state == DnsState(
        "Ethernet", ("1.1.1.1", "8.8.8.8"), False, True,
    )
    fallback_command = mock_run.call_args_list[1].args[0]
    assert "name=Ethernet" in fallback_command


@patch("losshound.core.optimizer._run")
@patch("losshound.core.dns_bench.query_dns_server", return_value=1.0)
@patch(
    "losshound.core.optimizer.NetworkOptimizer._active_adapter_name",
    return_value="Ethernet",
)
@patch("losshound.core.optimizer.NetworkOptimizer._get_dns_state")
@patch(
    "losshound.core.optimizer.NetworkOptimizer.check_admin",
    return_value=True,
)
def test_dns_secondary_command_failure_rolls_back_exact_state(
    _mock_admin,
    mock_get_dns_state,
    _mock_adapter,
    _mock_query,
    mock_run,
):
    with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
        NetworkOptimizer().apply_dns("9.9.9.9", "149.112.112.112")
    _mock_admin.assert_not_called()
    mock_get_dns_state.assert_not_called()
    _mock_adapter.assert_not_called()
    _mock_query.assert_not_called()
    mock_run.assert_not_called()


@patch("losshound.core.optimizer._run")
@patch("losshound.core.dns_bench.query_dns_server", return_value=1.0)
@patch(
    "losshound.core.optimizer.NetworkOptimizer._active_adapter_name",
    return_value="Ethernet",
)
@patch("losshound.core.optimizer.NetworkOptimizer._get_dns_state")
@patch(
    "losshound.core.optimizer.NetworkOptimizer.check_admin",
    return_value=True,
)
def test_dns_success_requires_primary_and_secondary_readback(
    _mock_admin,
    mock_get_dns_state,
    _mock_adapter,
    _mock_query,
    mock_run,
):
    with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
        NetworkOptimizer().apply_dns("9.9.9.9", "149.112.112.112")
    _mock_admin.assert_not_called()
    mock_get_dns_state.assert_not_called()
    _mock_adapter.assert_not_called()
    _mock_query.assert_not_called()
    mock_run.assert_not_called()


@patch("losshound.core.optimizer._run", return_value=_proc())
@patch("losshound.core.optimizer.NetworkOptimizer._get_dns_state")
@patch("losshound.core.optimizer.NetworkOptimizer._active_adapter_name")
@patch("losshound.core.optimizer.NetworkOptimizer.apply_mtu")
@patch(
    "losshound.core.optimizer.NetworkOptimizer.check_admin",
    return_value=True,
)
def test_restore_dns_uses_backed_up_adapter_not_current_active(
    _mock_admin,
    mock_apply_mtu,
    mock_active_adapter,
    mock_get_dns_state,
    mock_run,
):
    backup = BackupData("2026-07-09T00:00:00+00:00", TcpSettings(), ("1.1.1.1", "8.8.8.8"), 1500, None, False,
        dns_adapter_name="Ethernet", dns_automatic=False, dns_server_list=("1.1.1.1", "8.8.8.8"))
    with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
        NetworkOptimizer().restore_backup(backup)
    _mock_admin.assert_not_called()
    mock_apply_mtu.assert_not_called()
    mock_active_adapter.assert_not_called()
    mock_get_dns_state.assert_not_called()
    mock_run.assert_not_called()


@patch("losshound.core.optimizer._run", return_value=_proc())
@patch("losshound.core.optimizer.NetworkOptimizer._get_dns_state")
@patch("losshound.core.optimizer.NetworkOptimizer.apply_mtu")
@patch(
    "losshound.core.optimizer.NetworkOptimizer.check_admin",
    return_value=True,
)
def test_restore_dns_preserves_automatic_mode(
    _mock_admin, mock_apply_mtu, mock_get_dns_state, mock_run,
):
    backup = BackupData("2026-07-09T00:00:00+00:00", TcpSettings(), ("192.168.1.1", ""), 1500, None, False,
        dns_adapter_name="Ethernet", dns_automatic=True, dns_server_list=("192.168.1.1",))
    with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
        NetworkOptimizer().restore_backup(backup)
    _mock_admin.assert_not_called()
    mock_apply_mtu.assert_not_called()
    mock_get_dns_state.assert_not_called()
    mock_run.assert_not_called()


@patch("losshound.core.optimizer._read_registry_dword_snapshot")
@patch("winreg.DeleteValue")
@patch("winreg.OpenKey")
@patch("losshound.core.optimizer.NetworkOptimizer.apply_mtu")
@patch(
    "losshound.core.optimizer.NetworkOptimizer.check_admin",
    return_value=True,
)
def test_restore_deletes_only_values_known_absent_in_backup(
    _mock_admin,
    mock_apply_mtu,
    _mock_open_key,
    mock_delete_value,
    mock_registry_snapshot,
):
    backup = BackupData("2026-07-09T00:00:00+00:00", TcpSettings(), ("", ""), 1500, None, False,
        network_throttling_present=False, fast_send_datagram_threshold_present=False, system_responsiveness_present=False)
    with pytest.raises(NetworkModificationDisabledError, match="read-only diagnostics"):
        NetworkOptimizer().restore_backup(backup)
    _mock_admin.assert_not_called()
    mock_apply_mtu.assert_not_called()
    _mock_open_key.assert_not_called()
    mock_delete_value.assert_not_called()
    mock_registry_snapshot.assert_not_called()


def test_restore_retains_retry_backup_when_step_is_unsupported(tmp_path):
    backup_file = tmp_path / "optimizer_backup.json"
    backup_file.write_text("{}", encoding="utf-8")
    original = backup_file.read_bytes()
    with patch("losshound.core.optimizer._BACKUP_FILE", backup_file), \
         patch.object(NetworkOptimizer, "_load_backup") as load, \
         patch("losshound.core.optimizer._run") as run, \
         patch("winreg.SetValueEx") as set_value, \
         patch("winreg.DeleteValue") as delete_value:
        with pytest.raises(NetworkModificationDisabledError):
            NetworkOptimizer().restore_backup()
    load.assert_not_called()
    run.assert_not_called()
    set_value.assert_not_called()
    delete_value.assert_not_called()
    assert backup_file.read_bytes() == original
