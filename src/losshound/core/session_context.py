"""Read-only Windows change notifications in a private, deadline-owned process.

IP address/interface/route and connection-related WLAN notifications increment
a generation even when the next identity snapshot has returned to A. Ordinary
WLAN quality/scan/status notifications do not establish a continuity break.
Missing coverage is never stability.
API references: NotifyIpInterfaceChange, NotifyRouteChange2,
NotifyUnicastIpAddressChange and WlanRegisterNotification (Microsoft Learn).
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
import uuid

SIZE = 8192
PREFIX = 'Local\\Losshound-S1-watch-'


class _WLAN_NOTIFICATION_HEADER(ctypes.Structure):
    """Fixed-width prefix of WLAN_NOTIFICATION_DATA; never read its payload."""
    _fields_ = [('NotificationSource', ctypes.c_uint32),
                ('NotificationCode', ctypes.c_uint32)]


# NotificationCode is meaningful only within its exact NotificationSource.
# Microsoft WLAN_NOTIFICATION_ACM/MSM enums (wlanapi.h): scan/profile/policy
# status and link quality alone do not establish an association transition.
_WLAN_NON_CONNECTION_CODES = {
    0x08: frozenset({
        1, 2,                 # autoconf enabled/disabled
        3, 4,                 # background scan enabled/disabled
        6, 7, 8,              # power setting, scan complete/fail
        12, 15, 16, 17,       # filter/profile changes, profiles exhausted
        18, 19,               # network availability, not connection state
        23, 24, 25, 26,       # profile block, screen power, scan list refresh
    }),
    0x10: frozenset({8, 15, 16}),  # signal quality, link degraded/improved
}


def _wlan_breaks_continuity(source: int, code: int) -> bool:
    """Ignore known non-connection events; unknown notifications stay conservative.

    Connection/disconnection, roaming, radio and interface changes still advance
    the generation. Unknown codes or combined/unknown sources must not hide a
    possible A->B->A transition between identity snapshots.
    """
    return code not in _WLAN_NON_CONNECTION_CODES.get(source, ())


def _support():
    if not getattr(sys, 'frozen', False):
        root = str(Path(__file__).resolve().parents[2])
        if root not in sys.path:
            sys.path.insert(0, root)
    from losshound.core.session_process import _OwnedJob, _verify_private_job, _repair_frozen_streams
    return _OwnedJob, _verify_private_job, _repair_frozen_streams


def _read_state(shared):
    # A seqlock prevents a torn cross-process sample from confirming continuity.
    before = struct.unpack_from('<I', shared, 0)[0]
    if not before or before & 1:
        return {'status': 'UNKNOWN', 'error': 'Observer startup or concurrent update'}
    size = struct.unpack_from('<I', shared, 4)[0]
    if not 0 < size <= SIZE - 8:
        return {'status': 'UNKNOWN', 'error': 'Invalid observer frame size'}
    raw = shared[8:8 + size]
    after = struct.unpack_from('<I', shared, 0)[0]
    if before != after:
        return {'status': 'UNKNOWN', 'error': 'Concurrent observer update'}
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        return {'status': 'UNKNOWN', 'error': 'Invalid observer frame'}


class WindowsContextObserver:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.provider = None
        self.proc = self.job = self.shared = None
        self.error = None
        self.name = PREFIX + uuid.uuid4().hex
        self.started_pids = []
        self._closed = False
        self.last_state = {'status': 'UNKNOWN', 'error': 'Observer not started'}

    @staticmethod
    def _command():
        if getattr(sys, 'frozen', False):
            return [sys.executable, '--s1-context-worker']
        return [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), '--worker']

    def start(self, deadline, cancel_event):
        if sys.platform != 'win32':
            self.error = 'Windows notifications require native Windows'
            return
        if cancel_event.is_set() or self.clock() >= deadline:
            self.error = 'Observer not started before cancellation/deadline'
            return
        try:
            owned, _verify, _repair = _support()
            from losshound.core.session_process import WindowsProbeProvider
            self.provider = WindowsProbeProvider(clock=self.clock)
            self.shared = mmap.mmap(-1, SIZE, tagname=self.name)
            self.proc = subprocess.Popen(self._command(), stdin=subprocess.PIPE,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         text=True, encoding='utf-8', shell=False,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
            self.started_pids.append(self.proc.pid)
            self.job = owned(self.proc)
            request = {'job_name': self.job.name, 'mapping': self.name,
                       'lifetime_seconds': min(300.0, max(0.01, deadline - self.clock()))}
            # Tiny fixed request; the child performs no operation before job assignment.
            self.proc.stdin.write(json.dumps(request))
            self.proc.stdin.close()
            self.proc.stdin = None
            # No synchronous readiness wait. Later samples mark the startup blind spot.
        except (OSError, ValueError, AttributeError) as exc:
            self.error = f'{type(exc).__name__}: {exc}'

    def snapshot(self):
        if self.error:
            state = {'status': 'UNKNOWN', 'error': self.error}
        elif self.proc is None:
            state = {'status': 'UNKNOWN', 'error': 'Observer process is not running'}
        elif self._closed or self.shared is None:
            state = {'status': 'UNKNOWN', 'error': 'Observer mapping unavailable'}
        else:
            state = _read_state(self.shared)
            if self.proc.poll() is not None:
                state = dict(state, status='UNKNOWN', exit_code=self.proc.returncode,
                             error='Observer process exited; continuity is unconfirmed')
        self.last_state = state
        return dict(state, observer_id=self.name)

    def close(self, deadline):
        if self._closed:
            return []
        self._closed = True
        errors = []
        if self.proc is not None and self.provider is not None:
            self.provider._stop(self.proc, self.job, deadline)
            errors.extend(self.provider.cleanup_errors)
        if self.shared is not None:
            self.shared.close()
        return errors

    @property
    def active_pids(self):
        return [self.proc.pid] if self.proc is not None and self.proc.poll() is None else []


def _observe(shared, lifetime):
    ip = ctypes.WinDLL('iphlpapi', use_last_error=True)
    wlan = ctypes.WinDLL('wlanapi', use_last_error=True)
    lock = threading.Lock()
    state = {'status': 'UNKNOWN', 'generation': 0, 'sources': [], 'errors': [],
             'note': 'Notification delivery has latency; no guarantee for undelivered OS events'}
    sequence = 0

    def publish():
        nonlocal sequence
        sequence += 2
        raw = json.dumps(state, ensure_ascii=True).encode('ascii')
        struct.pack_into('<I', shared, 0, sequence - 1)
        struct.pack_into('<I', shared, 4, len(raw))
        shared[8:8 + len(raw)] = raw
        struct.pack_into('<I', shared, 0, sequence)

    def event(source, notification_source=None, notification_code=None):
        with lock:
            state['generation'] += 1
            state['last_event_source'] = source
            state['last_event_monotonic'] = time.monotonic()
            state.pop('last_event_notification_source', None)
            state.pop('last_event_notification_code', None)
            if notification_source is not None:
                state['last_event_notification_source'] = notification_source
                state['last_event_notification_code'] = notification_code
            publish()

    callbacks, handles = [], []
    ip_callback = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    for function in ('NotifyIpInterfaceChange', 'NotifyUnicastIpAddressChange', 'NotifyRouteChange2'):
        callback = ip_callback(lambda _context, _row, _kind, source=function: event(source))
        callbacks.append(callback)  # Retain native callback lifetime through worker exit.
        notify = getattr(ip, function)
        notify.argtypes = [ctypes.c_ushort, ip_callback, ctypes.c_void_p,
                           ctypes.c_ubyte, ctypes.POINTER(wintypes.HANDLE)]
        notify.restype = wintypes.ULONG
        handle = wintypes.HANDLE()
        code = notify(0, callback, None, 0, ctypes.byref(handle))
        if code:
            state['errors'].append({'stage': function, 'winerror': code,
                                    'message': ctypes.FormatError(code)})
        else:
            handles.append(handle)
            state['sources'].append(function)

    wlan.WlanOpenHandle.argtypes = [wintypes.DWORD, ctypes.c_void_p,
                                   ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.HANDLE)]
    wlan.WlanOpenHandle.restype = wintypes.DWORD
    version, handle = wintypes.DWORD(), wintypes.HANDLE()
    code = wlan.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle))
    if code:
        state['errors'].append({'stage': 'WlanOpenHandle', 'winerror': code,
                                'message': ctypes.FormatError(code)})
    else:
        def wlan_event(data, _context):
            if not data:
                # An invalid notification cannot establish continuous coverage.
                event('WLAN_ACM_MSM')
                return
            notification = data.contents
            source, code = notification.NotificationSource, notification.NotificationCode
            if _wlan_breaks_continuity(source, code):
                event('WLAN_ACM_MSM', source, code)

        callback_type = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_WLAN_NOTIFICATION_HEADER),
                                          ctypes.c_void_p)
        callback = callback_type(wlan_event)
        callbacks.append(callback)
        wlan.WlanRegisterNotification.argtypes = [wintypes.HANDLE, wintypes.DWORD,
            wintypes.BOOL, callback_type, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD)]
        wlan.WlanRegisterNotification.restype = wintypes.DWORD
        # No settings/consent changes: an OS capability/privacy denial remains a gap.
        code = wlan.WlanRegisterNotification(handle, 0x08 | 0x10, False, callback, None, None, None)
        if code:
            state['errors'].append({'stage': 'WlanRegisterNotification', 'winerror': code,
                                    'message': ctypes.FormatError(code)})
        else:
            state['sources'].append('WLAN_ACM_MSM')
    with lock:
        state['status'] = 'READY' if not state['errors'] else 'UNKNOWN'
        publish()
    # This entire process, including registrations/callbacks, belongs to a private
    # Job Object. The parent reaps it instead of blocking on native unregistration
    # or terminating any shared Python/Qt thread.
    time.sleep(lifetime)
    os._exit(0)  # Keep callback objects alive until the OS destroys this private worker.


def worker_main():
    shared = None
    try:
        _owned, verify, repair = _support()
        repair()
        request = json.loads(sys.stdin.read(2049))
        if (not isinstance(request, dict) or set(request) != {'job_name', 'mapping', 'lifetime_seconds'}
                or not isinstance(request['mapping'], str) or not request['mapping'].startswith(PREFIX)
                or len(request['mapping']) != len(PREFIX) + 32
                or any(c not in '0123456789abcdef' for c in request['mapping'][len(PREFIX):])
                or isinstance(request['lifetime_seconds'], bool)
                or not isinstance(request['lifetime_seconds'], (int, float))
                or not 0 < request['lifetime_seconds'] <= 300
                or not verify(request['job_name'])):
            return 2
        shared = mmap.mmap(-1, SIZE, tagname=request['mapping'])
        _observe(shared, request['lifetime_seconds'])
        return 0
    except Exception as exc:
        if shared is not None:
            state = {'status': 'UNKNOWN', 'errors': [{
                'stage': 'observer_registration', 'exception_type': type(exc).__name__,
                'message': str(exc)[:1000], 'winerror': getattr(exc, 'winerror', None),
                'errno': getattr(exc, 'errno', None)}]}
            raw = json.dumps(state, ensure_ascii=True).encode('ascii')
            struct.pack_into('<II', shared, 0, 1, len(raw))
            shared[8:8 + len(raw)] = raw
            struct.pack_into('<I', shared, 0, 2)
        return 2
    finally:
        if shared is not None:
            shared.close()


if __name__ == '__main__':
    raise SystemExit(worker_main() if sys.argv[1:] == ['--worker'] else 2)
