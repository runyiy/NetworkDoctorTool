"""Focused WLAN regressions using fake native callbacks, clocks and probes only.

These tests never switch networks or establish native Windows acceptance.
"""
from __future__ import annotations

import ctypes
import socket
import subprocess
import unittest
from unittest.mock import patch

from losshound.core import session_context as watch
from losshound.core.session import SessionController, SessionRequest
from test_session_s1 import FakeClock, FakeProvider


class _Function:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class _FixtureStop(Exception):
    pass


class _Notifications:
    """Retain the production callbacks after mocked registration completes."""

    def __init__(self):
        self.shared = bytearray(watch.SIZE)
        self.ip_callbacks = {}
        self.wlan_callback = None
        self.registration_sources = None
        ip, wlan = type("API", (), {})(), type("API", (), {})()

        def ip_registration(name):
            def register(_family, callback, _context, initial, _handle):
                if initial != 0:
                    raise AssertionError("Fixture must not fabricate initial IP changes")
                self.ip_callbacks[name] = callback
                return 0
            return _Function(register)

        for name in ("NotifyIpInterfaceChange", "NotifyUnicastIpAddressChange", "NotifyRouteChange2"):
            setattr(ip, name, ip_registration(name))
        wlan.WlanOpenHandle = _Function(lambda *_args: 0)

        def register_wlan(_handle, sources, _ignore_duplicate, callback, *_args):
            self.registration_sources = sources
            self.wlan_callback = callback
            return 0

        wlan.WlanRegisterNotification = _Function(register_wlan)
        with patch.object(watch.ctypes, "WinDLL", side_effect=[ip, wlan], create=True), \
             patch.object(watch.time, "sleep", side_effect=_FixtureStop), \
             patch.object(watch.os, "_exit", side_effect=AssertionError("No fixture may exit the test process")):
            try:
                watch._observe(self.shared, 1)
            except _FixtureStop:
                pass
            else:
                raise AssertionError("Observer did not reach its controlled registration boundary")
        if self.wlan_callback is None:
            raise AssertionError("The real WLAN callback was not registered")

    def emit(self, source, code):
        header = watch._WLAN_NOTIFICATION_HEADER()
        header.NotificationSource = source
        header.NotificationCode = code
        self.wlan_callback(ctypes.pointer(header), None)

    def state(self):
        return watch._read_state(self.shared)


class _Observer:
    def __init__(self, notifications, clock, unknown=False):
        self.notifications, self.clock, self.unknown = notifications, clock, unknown
        self.closed = False

    def start(self, deadline, cancel):
        self.collection_deadline = deadline

    def snapshot(self):
        state = dict(self.notifications.state(), observer_id="fake-native-wlan")
        if self.unknown:
            state["status"] = "UNKNOWN"
        return state

    def close(self, deadline):
        self.closed = True
        self.close_deadline = deadline
        self.clock.now += min(0.1, max(0, deadline - self.clock()))
        return []


class WlanNotificationTests(unittest.TestCase):
    def setUp(self):
        # A missed fake must fail rather than register real callbacks or probe.
        for patcher in (
            patch.object(watch.ctypes, "WinDLL", side_effect=AssertionError("Live native API forbidden"), create=True),
            patch.object(subprocess, "Popen", side_effect=AssertionError("Live child process forbidden")),
            patch.object(socket, "socket", side_effect=AssertionError("Live socket forbidden")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_session(self, events=(), *, unknown=False, identities=None, each_probe=False):
        notifications = _Notifications()
        clock = FakeClock()
        provider = FakeProvider(clock, identities=identities)
        observer = _Observer(notifications, clock, unknown)
        original = provider.probe

        def probe(*args):
            result = original(*args)
            if each_probe or len(provider.probes) == 1:
                for source, code in events:
                    notifications.emit(source, code)
            # An actually attempted batch's loss must survive harmless events.
            result.update(packets_sent=2, packets_received=1)
            return result

        provider.probe = probe
        controller = SessionController(
            SessionRequest(60, (), ()), provider, clock, clock.wait,
            context_observer=observer,
        )
        return controller.run(), provider, observer, clock, notifications

    def assert_budget_and_cleanup(self, report, provider, observer, clock):
        self.assertEqual(report.status, "deadline")
        self.assertEqual(observer.collection_deadline, 158)
        self.assertTrue(provider.deadlines)
        self.assertTrue(all(value == 158 for value in provider.deadlines))
        self.assertEqual(provider.close_deadline, observer.close_deadline)
        self.assertEqual(provider.cleanup_deadline, 159.95)
        self.assertTrue(provider.closed and observer.closed)
        self.assertEqual(report.cleanup_errors, [])
        self.assertLessEqual(clock(), 160)
        self.assertLessEqual(report.duration_seconds, 60)

    def test_signal_scan_and_other_nonconnection_callbacks_preserve_generation(self):
        notifications = _Notifications()
        self.assertEqual(notifications.registration_sources, 0x08 | 0x10)
        self.assertEqual(notifications.state()["status"], "READY")
        benign = [(0x08, code) for code in (1, 2, 3, 4, 6, 7, 8, 12, 15, 16, 17, 18, 19, 23, 24, 25, 26)]
        benign += [(0x10, code) for code in (8, 15, 16)]
        for source, code in benign:
            with self.subTest(source=source, code=code):
                notifications.emit(source, code)
                self.assertEqual(notifications.state()["generation"], 0)
                self.assertEqual(notifications.state()["status"], "READY")

    def test_notification_source_disambiguates_identical_numeric_codes(self):
        notifications = _Notifications()
        self.assertEqual(ctypes.sizeof(watch._WLAN_NOTIFICATION_HEADER), 8)
        self.assertEqual(watch._WLAN_NOTIFICATION_HEADER.NotificationCode.offset, 4)
        notifications.emit(0x08, 7)  # ACM scan complete.
        self.assertEqual(notifications.state()["generation"], 0)
        notifications.emit(0x10, 7)  # MSM radio state change, same numeric code.
        self.assertEqual(notifications.state()["generation"], 1)
        notifications.emit(0x08, 4)  # ACM background scan disabled.
        self.assertEqual(notifications.state()["generation"], 1)
        notifications.emit(0x10, 4)  # MSM connected.
        self.assertEqual(notifications.state()["generation"], 2)

    def test_connection_roam_and_interface_callbacks_increment_generation(self):
        notifications = _Notifications()
        changes = [(0x08, code) for code in (5, 9, 10, 11, 13, 14, 20, 21, 22, 27)]
        changes += [(0x10, code) for code in (1, 2, 3, 4, 5, 6, 7, 9, 10, 13, 14)]
        for expected, (source, code) in enumerate(changes, 1):
            with self.subTest(source=source, code=code):
                notifications.emit(source, code)
                self.assertEqual(notifications.state()["generation"], expected)

    def test_unknown_or_malformed_wlan_callbacks_fail_conservatively(self):
        notifications = _Notifications()
        unknown = ((0x08, 999), (0x10, 26), (0x100, 8), (0x18, 8), (0, 8))
        for expected, (source, code) in enumerate(unknown, 1):
            with self.subTest(source=source, code=code):
                notifications.emit(source, code)
                self.assertEqual(notifications.state()["generation"], expected)
        notifications.wlan_callback(None, None)
        self.assertEqual(notifications.state()["generation"], len(unknown) + 1)

    def test_ip_interface_address_and_route_changes_still_break_continuity(self):
        notifications = _Notifications()
        for expected, callback in enumerate(notifications.ip_callbacks.values(), 1):
            callback(None, None, 1)
            self.assertEqual(notifications.state()["generation"], expected)

    def test_normal_notifications_keep_one_epoch_and_actual_packet_loss(self):
        events = ((0x10, 8), (0x08, 7), (0x08, 8), (0x08, 26))
        report, provider, observer, clock, notifications = self.run_session(events, each_probe=True)
        self.assertEqual(notifications.state()["generation"], 0)
        self.assertEqual(len(report.epochs), 1)
        self.assertTrue(report.evidence)
        for sample in report.evidence:
            self.assertEqual(sample.epoch_id, 1)
            self.assertTrue(sample.comparable)
            self.assertEqual(sample.data["context_status"], "IDENTIFIED")
            self.assertEqual((sample.packets_sent, sample.packets_received), (2, 1))
            self.assertEqual(sample.loss_percent, 50)
        self.assert_budget_and_cleanup(report, provider, observer, clock)

    def test_disconnect_reconnect_between_snapshots_preserves_a_b_a_isolation(self):
        # Identity snapshots see A both times; callback generations retain the
        # unseen disconnect/reconnect and exclude the crossing probe.
        report, provider, observer, clock, notifications = self.run_session(((0x10, 10), (0x10, 4)))
        self.assertEqual(notifications.state()["generation"], 2)
        self.assertEqual([row.identity for row in report.epochs[:2]], ["A", "A"])
        self.assertEqual([row.context["change_generation"] for row in report.epochs[:2]], [0, 2])
        crossing = report.evidence[0]
        self.assertIsNone(crossing.epoch_id)
        self.assertIsNone(crossing.loss_percent)
        self.assertFalse(crossing.comparable)
        self.assertEqual(crossing.data["context_status"], "UNKNOWN")
        self.assertTrue(any(row.epoch_id == 2 and row.loss_percent == 50 for row in report.evidence))
        self.assert_budget_and_cleanup(report, provider, observer, clock)

    def test_roam_callbacks_exclude_crossing_probe_and_resume_new_epoch(self):
        report, provider, observer, clock, notifications = self.run_session(((0x10, 5), (0x10, 6)))
        self.assertEqual(notifications.state()["generation"], 2)
        self.assertIsNone(report.evidence[0].epoch_id)
        self.assertIsNone(report.evidence[0].loss_percent)
        self.assertTrue(any(row.epoch_id == 2 and row.comparable for row in report.evidence))
        self.assert_budget_and_cleanup(report, provider, observer, clock)

    def test_harmless_notifications_do_not_clear_unknown_notification_coverage(self):
        report, provider, observer, clock, notifications = self.run_session(((0x10, 8),), unknown=True, each_probe=True)
        self.assertEqual(notifications.state()["generation"], 0)
        self.assertTrue(report.context_blind_spots)
        self.assertTrue(report.evidence)
        for sample in report.evidence:
            self.assertIsNone(sample.epoch_id)
            self.assertIsNone(sample.loss_percent)
            self.assertFalse(sample.comparable)
            self.assertEqual(sample.data["context_status"], "UNKNOWN")
        self.assert_budget_and_cleanup(report, provider, observer, clock)

    def test_harmless_notifications_do_not_hide_failed_identity_query(self):
        report, provider, observer, clock, notifications = self.run_session(
            ((0x10, 8),), identities=["A", "A", None, "A"], each_probe=True,
        )
        self.assertEqual(notifications.state()["generation"], 0)
        self.assertIsNone(report.evidence[0].epoch_id)
        self.assertIsNone(report.evidence[0].loss_percent)
        self.assertTrue(any("Network context unavailable" in text for text in report.incomplete))
        self.assertTrue(any(row.comparable and row.loss_percent == 50 for row in report.evidence[1:]))
        self.assert_budget_and_cleanup(report, provider, observer, clock)


if __name__ == "__main__":
    unittest.main()

