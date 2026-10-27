"""S1 context-event regression tests; no live network changes."""
from __future__ import annotations
import json
import struct
import threading
import unittest
from unittest.mock import patch

from losshound.core import session_context as watch


class StableObserver:
    def __init__(self):
        self.generation = 0
        self.status = 'READY'
        self.closed = False
    def start(self, deadline, cancel):
        self.deadline = deadline
    def snapshot(self):
        return {'status': self.status, 'generation': self.generation, 'observer_id': 'simulated'}
    def close(self, deadline):
        self.closed = True
        return []


class ObserverProtocolTests(unittest.TestCase):
    def test_in_progress_write_and_invalid_frame_are_unknown(self):
        shared = bytearray(watch.SIZE)
        self.assertEqual(watch._read_state(shared)['status'], 'UNKNOWN')
        struct.pack_into('<II', shared, 0, 1, 2)
        self.assertEqual(watch._read_state(shared)['status'], 'UNKNOWN')
        struct.pack_into('<II', shared, 0, 2, watch.SIZE)
        self.assertEqual(watch._read_state(shared)['status'], 'UNKNOWN')

    def test_worker_notifications_retain_both_a_b_a_transitions(self):
        shared = bytearray(watch.SIZE)
        callbacks = []
        class Function:
            def __init__(self, function): self.function = function
            def __call__(self, *args): return self.function(*args)
        class API: pass
        ip, wlan = API(), API()
        def notify(_family, callback, _context, initial, _handle):
            self.assertEqual(initial, 0)
            callbacks.append(callback)
            return 0
        for name in ('NotifyIpInterfaceChange', 'NotifyUnicastIpAddressChange', 'NotifyRouteChange2'):
            setattr(ip, name, Function(notify))
        wlan.WlanOpenHandle = Function(lambda *_args: 0)
        wlan.WlanRegisterNotification = Function(lambda *_args: 0)
        def observed_interval(_seconds):
            self.assertEqual(watch._read_state(shared)['generation'], 0)
            callbacks[0](None, None, 1)  # A->B
            callbacks[0](None, None, 2)  # B->A, no identity snapshot between them
            self.assertEqual(watch._read_state(shared)['generation'], 2)
            self.assertEqual(watch._read_state(shared)['status'], 'READY')
            raise InterruptedError('controlled fixture exit')
        with patch.object(watch.ctypes, 'WinDLL', side_effect=[ip, wlan], create=True), \
             patch.object(watch.time, 'sleep', side_effect=observed_interval):
            with self.assertRaisesRegex(InterruptedError, 'fixture exit'):
                watch._observe(shared, 1)
        self.assertEqual(len(callbacks), 3)

    def test_inactive_wlan_service_does_not_confirm_full_session_coverage(self):
        shared = bytearray(watch.SIZE)
        class Function:
            def __init__(self, function): self.function = function
            def __call__(self, *args): return self.function(*args)
        class API: pass
        ip, wlan = API(), API()
        for name in ('NotifyIpInterfaceChange', 'NotifyUnicastIpAddressChange', 'NotifyRouteChange2'):
            setattr(ip, name, Function(lambda *_args: 0))
        wlan.WlanOpenHandle = Function(lambda *_args: 1062)
        with patch.object(watch.ctypes, 'WinDLL', side_effect=[ip, wlan], create=True), \
             patch.object(watch.time, 'sleep', side_effect=InterruptedError('controlled fixture')):
            with self.assertRaises(InterruptedError):
                watch._observe(shared, 1)
        state = watch._read_state(shared)
        self.assertEqual(state['status'], 'UNKNOWN')
        self.assertEqual(state['errors'][0]['winerror'], 1062)

    def test_direct_worker_cannot_register_notifications(self):
        import io
        request={'job_name':'invalid','mapping':watch.PREFIX+'a'*32,'lifetime_seconds':1}
        with patch.object(watch, '_support', return_value=(None, lambda _name: False, lambda: None)), \
             patch.object(watch.sys, 'stdin', io.StringIO(json.dumps(request))), \
             patch.object(watch, '_observe') as observe:
            self.assertEqual(watch.worker_main(), 2)
        observe.assert_not_called()

    def test_no_running_worker_never_claims_ready(self):
        observer=watch.WindowsContextObserver()
        self.assertEqual(observer.snapshot()['status'], 'UNKNOWN')
        self.assertEqual(observer.close(0), [])

@unittest.skipUnless(__import__('sys').platform == 'win32', 'Native Windows required; not WSL')
class NativeObserverLifecycleTests(unittest.TestCase):
    def test_registration_reports_coverage_and_owned_child_exits(self):
        import time
        observer = watch.WindowsContextObserver()
        started = time.monotonic()
        try:
            observer.start(started + 4, threading.Event())
            state = observer.snapshot()
            while time.monotonic() < started + 2.5 and 'generation' not in state:
                time.sleep(0.02)
                state = observer.snapshot()
            self.assertIn('generation', state, state)
            self.assertIn(state['status'], ('READY', 'UNKNOWN'))
            if state['status'] == 'UNKNOWN':
                self.assertTrue(state.get('errors'), state)
            self.assertEqual(state['generation'], int(state['generation']))
        finally:
            errors = observer.close(min(started + 4, time.monotonic() + 1))
        self.assertEqual(errors, [])
        self.assertEqual(observer.active_pids, [])
        self.assertLess(time.monotonic() - started, 4)
