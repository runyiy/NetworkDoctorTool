"""Legacy optimizer getters remain covered; S1 write tests assert refusal.

Former apply/restore expectations are intentionally replaced by no-side-effect
boundary checks. No production guard is relaxed for these tests.
"""
import sys
import unittest
from unittest.mock import MagicMock, patch
import winreg

from losshound.core.read_only_policy import NetworkModificationDisabledError

from losshound.core.optimizer import (
    AdapterBackup,
    BackupData,
    DnsState,
    NetworkOptimizer,
    TcpSettings,
)
from losshound.core.models import PingResult

class TestOptimizerExtensions(unittest.TestCase):

    def setUp(self):
        import tempfile
        from pathlib import Path
        import losshound.core.optimizer
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_backup_file = losshound.core.optimizer._BACKUP_FILE
        losshound.core.optimizer._BACKUP_FILE = Path(self.temp_dir.name) / "optimizer_backup.json"

    def tearDown(self):
        import losshound.core.optimizer
        losshound.core.optimizer._BACKUP_FILE = self.old_backup_file
        self.temp_dir.cleanup()

    @patch("losshound.core.optimizer._run")
    def test_get_tcp_heuristics(self, mock_run):
        mock_run.return_value.stdout = (
            "TCP Window Scaling heuristics Parameters\n"
            "----------------------------------------------\n"
            "Window Scaling heuristics         : disabled \n"
        )
        opt = NetworkOptimizer()
        val = opt.get_tcp_heuristics()
        self.assertEqual(val, "disabled")

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_tcp_heuristics")
    @patch("losshound.core.optimizer._run")
    def test_disable_tcp_heuristics(self, mock_run, mock_get_heuristics, mock_check_admin):
        opt = NetworkOptimizer()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.disable_tcp_heuristics()
        mock_run.assert_not_called()
        mock_get_heuristics.assert_not_called()
        mock_check_admin.assert_not_called()

    @patch("winreg.OpenKey")
    @patch("winreg.QueryValueEx")
    def test_get_system_responsiveness(self, mock_query, mock_open):
        mock_query.return_value = (10, winreg.REG_DWORD)
        opt = NetworkOptimizer()
        val = opt.get_system_responsiveness()
        self.assertEqual(val, 10)

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_system_responsiveness")
    @patch("winreg.OpenKey")
    @patch("winreg.SetValueEx")
    def test_apply_system_responsiveness(self, mock_set_val, mock_open_key, mock_get_resp, mock_check_admin):
        opt = NetworkOptimizer()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.apply_system_responsiveness(10)
        mock_set_val.assert_not_called()
        mock_open_key.assert_not_called()
        mock_get_resp.assert_not_called()
        mock_check_admin.assert_not_called()

    @patch("losshound.core.optimizer._run")
    def test_find_optimal_mtu_skips_inconclusive_probes(self, mock_run):
        mock_run.return_value.stdout = "Request timed out."

        opt = NetworkOptimizer()

        self.assertIsNone(opt.find_optimal_mtu())

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_system_responsiveness")
    @patch("losshound.core.optimizer.NetworkOptimizer.apply_system_responsiveness")
    @patch("losshound.core.ping.ping")
    def test_benchmark_optimal_responsiveness(self, mock_ping, mock_apply_resp, mock_get_resp, mock_check_admin):
        opt = NetworkOptimizer()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.benchmark_optimal_responsiveness(target="8.8.8.8")
        mock_ping.assert_not_called()
        mock_apply_resp.assert_not_called()
        mock_get_resp.assert_not_called()
        mock_check_admin.assert_not_called()

    @patch("losshound.core.optimizer.NetworkOptimizer._save_backup")
    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_tcp_settings")
    @patch("losshound.core.optimizer.NetworkOptimizer._get_dns_state")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_current_mtu")
    @patch("losshound.core.optimizer._read_registry_dword_snapshot")
    @patch("losshound.core.optimizer.NetworkOptimizer._backup_adapter_settings")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_tcp_heuristics")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_system_responsiveness")
    @patch("winreg.OpenKey")
    @patch("winreg.QueryValueEx")
    @patch("winreg.EnumKey")
    def test_backup_and_load(self, mock_enum, mock_query, mock_open_key, mock_get_resp, mock_get_heuristics, mock_backup_adapter, mock_registry_snapshot, mock_get_mtu, mock_get_dns_state, mock_get_tcp, mock_check_admin, mock_save):
        mock_check_admin.return_value = True
        mock_get_tcp.return_value = TcpSettings()
        mock_get_dns_state.return_value = DnsState(
            "Ethernet", ("1.1.1.1", "8.8.8.8"), False, True,
        )
        mock_get_mtu.return_value = 1500
        mock_registry_snapshot.side_effect = [
            (True, 10),    # NetworkThrottlingIndex
            (True, 10),    # SystemResponsiveness
            (True, 1),     # TcpAckFrequency
            (True, 1),     # TCPNoDelay
            (True, 0),     # TcpDelAckTicks
            (True, 1024),  # FastSendDatagramThreshold
        ]
        mock_backup_adapter.return_value = AdapterBackup("Ethernet", True, True, False, False, "0")
        mock_get_heuristics.return_value = "disabled"
        mock_get_resp.return_value = 10
        mock_enum.side_effect = ["mock-guid-123", OSError()]
        mock_query.side_effect = [
            (["192.168.1.1"], winreg.REG_SZ),  # DhcpDefaultGateway
        ]

        opt = NetworkOptimizer()
        backup = opt.create_backup()

        self.assertEqual(backup.tcp_heuristics, "disabled")
        self.assertEqual(backup.system_responsiveness, 10)
        self.assertEqual(backup.tcp_del_ack_ticks, 0)
        self.assertEqual(backup.fast_send_datagram_threshold, 1024)
        self.assertEqual(backup.dns_adapter_name, "Ethernet")
        self.assertFalse(backup.dns_automatic)
        self.assertEqual(backup.dns_server_list, ("1.1.1.1", "8.8.8.8"))
        self.assertEqual(backup.adapter.eee_enabled, "0")

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_active_adapter")
    @patch("losshound.core.optimizer._run")
    def test_optimize_eee(self, mock_run, mock_get_adapter, mock_check_admin):
        opt = NetworkOptimizer()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.optimize_eee(disable=True)
        mock_run.assert_not_called()
        mock_get_adapter.assert_not_called()
        mock_check_admin.assert_not_called()

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_active_adapter")
    @patch("losshound.core.optimizer._run")
    def test_optimize_rsc(self, mock_run, mock_get_adapter, mock_check_admin):
        opt = NetworkOptimizer()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.optimize_rsc(disable=True)
        mock_run.assert_not_called()
        mock_get_adapter.assert_not_called()
        mock_check_admin.assert_not_called()

    def test_make_result_status_derivation(self):
        from losshound.core.optimizer import _make_result

        # 1. Test reboot_required bypass when already optimal
        res = _make_result(
            name="Test", success=True, before="1500", after="1500", desired="1500",
            reboot_required=True, note="reboot recommended", needs_admin=True
        )
        self.assertEqual(res.status, "Verified")
        self.assertEqual(res.note, "Already optimized (set to 1500)")

        # 2. Test reboot_required active when not optimal
        res = _make_result(
            name="Test", success=True, before="1400", after="1500", desired="1500",
            reboot_required=True, note="reboot recommended", needs_admin=True
        )
        self.assertEqual(res.status, "Reboot required")
        self.assertEqual(res.note, "reboot recommended")

        # 3. Test unsupported adapter property errors
        res = _make_result(
            name="Test", success=False, before="--", after="--",
            error="Adapter does not support RSC", needs_admin=True
        )
        self.assertEqual(res.status, "Unsupported")

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.create_backup")
    @patch("losshound.core.optimizer.NetworkOptimizer.optimize_winsock_datagram_threshold")
    @patch("losshound.core.optimizer.NetworkOptimizer.disable_tcp_heuristics")
    @patch("losshound.core.optimizer.NetworkOptimizer.apply_system_responsiveness")
    @patch("losshound.core.optimizer.NetworkOptimizer.optimize_nagle")
    @patch("losshound.core.optimizer.NetworkOptimizer.optimize_tcp")
    @patch("losshound.core.optimizer.NetworkOptimizer.optimize_adapter")
    @patch("losshound.core.optimizer.NetworkOptimizer.disable_network_throttling")
    def test_optimize_report_summary_formatting(self, mock_throttling, mock_adapter, mock_tcp, mock_nagle, mock_resp, mock_heur, mock_afd, mock_backup, mock_check_admin):
        opt = NetworkOptimizer()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.optimize_all(skip_dns=True, skip_mtu=True)
        mock_throttling.assert_not_called()
        mock_adapter.assert_not_called()
        mock_tcp.assert_not_called()
        mock_nagle.assert_not_called()
        mock_resp.assert_not_called()
        mock_heur.assert_not_called()
        mock_afd.assert_not_called()
        mock_backup.assert_not_called()
        mock_check_admin.assert_not_called()

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_tcp_settings")
    @patch("losshound.core.optimizer.NetworkOptimizer._get_dns_state")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_current_mtu")
    @patch("losshound.core.optimizer._read_registry_dword_snapshot")
    @patch("losshound.core.optimizer.NetworkOptimizer._backup_adapter_settings")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_tcp_heuristics")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_system_responsiveness")
    @patch("winreg.OpenKey")
    @patch("winreg.QueryValueEx")
    @patch("winreg.EnumKey")
    def test_optimize_twice_preserves_backup(self, mock_enum, mock_query, mock_open_key, mock_get_resp, mock_get_heuristics, mock_backup_adapter, mock_registry_snapshot, mock_get_mtu, mock_get_dns_state, mock_get_tcp, mock_check_admin):
        mock_check_admin.return_value = True
        mock_get_tcp.return_value = TcpSettings(auto_tuning_level="normal")
        mock_get_dns_state.return_value = DnsState(
            "Ethernet", ("1.1.1.1", "8.8.8.8"), False, True,
        )
        mock_get_mtu.return_value = 1500
        mock_registry_snapshot.side_effect = [
            (True, 10), (True, 10), (True, 1),
            (True, 1), (True, 0), (True, 1024),
        ]
        mock_backup_adapter.return_value = AdapterBackup("Ethernet", True, True, False, False, "0")
        mock_get_heuristics.return_value = "disabled"
        mock_get_resp.return_value = 10
        mock_enum.side_effect = ["mock-guid-123", OSError()]
        mock_query.side_effect = [
            (["192.168.1.1"], winreg.REG_SZ),  # DhcpDefaultGateway
        ]

        opt = NetworkOptimizer()
        backup1 = opt.create_backup()
        self.assertEqual(backup1.tcp_settings.auto_tuning_level, "normal")

        # Now, modify the active status to simulate changes post-optimization
        mock_get_tcp.return_value = TcpSettings(auto_tuning_level="disabled")
        backup2 = opt.create_backup()
        # The backup must NOT be overwritten, so backup2 should still have "normal"
        self.assertEqual(backup2.tcp_settings.auto_tuning_level, "normal")

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer._get_dns_state")
    @patch("losshound.core.optimizer.NetworkOptimizer._active_adapter_name")
    @patch("losshound.core.dns_bench.query_dns_server")
    @patch("losshound.core.optimizer._run")
    def test_dns_apply_dead_resolver_aborts(self, mock_run, mock_query, mock_adapter, mock_get_dns_state, mock_check_admin):
        opt = NetworkOptimizer()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.apply_dns("9.9.9.9", "8.8.4.4")
        mock_run.assert_not_called()
        mock_query.assert_not_called()
        mock_adapter.assert_not_called()
        mock_get_dns_state.assert_not_called()
        mock_check_admin.assert_not_called()

    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer.NetworkOptimizer.get_tcp_heuristics")
    @patch("losshound.core.optimizer.NetworkOptimizer.apply_system_responsiveness")
    @patch("losshound.core.optimizer._run")
    def test_restore_backup_partial_failure_retains_backup_file(self, mock_run, mock_apply_resp, mock_get_heuristics, mock_check_admin):
        opt = NetworkOptimizer()
        import losshound.core.optimizer as optimizer_module
        backup_file = optimizer_module._BACKUP_FILE
        backup_file.write_text("{\"original\": true}", encoding="utf-8")
        original = backup_file.read_bytes()
        with self.assertRaises(NetworkModificationDisabledError):
            opt.restore_backup()
        mock_run.assert_not_called()
        mock_apply_resp.assert_not_called()
        mock_get_heuristics.assert_not_called()
        mock_check_admin.assert_not_called()
        self.assertEqual(backup_file.read_bytes(), original)

    @patch("winreg.OpenKey", side_effect=OSError())
    @patch("losshound.core.optimizer.NetworkOptimizer.apply_mtu")
    @patch("losshound.core.optimizer.NetworkOptimizer.check_admin")
    @patch("losshound.core.optimizer._run")
    def test_restore_backup_rejects_tampered_eee_value(
        self, mock_run, mock_check_admin, mock_apply_mtu, mock_open_key,
    ):
        opt = NetworkOptimizer()
        backup = BackupData("2026-05-30T12:00:00", TcpSettings(), ("", ""), 1500, None, True,
            adapter=AdapterBackup("Ethernet", None, None, None, None, "0; Start-Process calc; #"))
        with self.assertRaises(NetworkModificationDisabledError):
            opt.restore_backup(backup)
        mock_run.assert_not_called()
        mock_check_admin.assert_not_called()
        mock_apply_mtu.assert_not_called()
        mock_open_key.assert_not_called()


