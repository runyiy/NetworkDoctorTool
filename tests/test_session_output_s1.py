"""Stdlib output regressions; native cases own no network probes or settings."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from losshound.core.session_output import BoundedSessionOutput, _FramedPipe


class OutputContractTests(unittest.TestCase):
    def test_memory_output_uses_no_child_and_preserves_report(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        writer = BoundedSessionOutput(stdout, stderr, time.monotonic() + 1)
        with patch('losshound.core.session_output.subprocess.Popen') as launch:
            self.assertTrue(writer.start())
            self.assertTrue(writer.progress('cleanup: 1 second remaining'))
            self.assertTrue(writer.finish('{"status":"cancelled"}'))
        launch.assert_not_called()
        self.assertEqual(json.loads(stdout.getvalue())["status"], "cancelled")
        self.assertIn('remaining', stderr.getvalue())
        self.assertEqual(writer.errors, [])

    def test_expired_output_never_starts_a_process(self):
        writer = BoundedSessionOutput(io.StringIO(), io.StringIO(), 0, clock=lambda: 1)
        with patch('losshound.core.session_output.subprocess.Popen') as launch:
            self.assertFalse(writer.start())
            self.assertFalse(writer.finish('{}'))
        launch.assert_not_called()
        self.assertTrue(writer.errors)

    def test_unknown_sink_does_not_invoke_arbitrary_stream_methods(self):
        class UnsafeStream:
            def fileno(self):
                raise AssertionError('must not call unknown stream code')
            write = flush = fileno
        writer = BoundedSessionOutput(UnsafeStream(), io.StringIO(), time.monotonic() + 1)
        with patch('losshound.core.session_output.subprocess.Popen') as launch:
            self.assertFalse(writer.start())
        launch.assert_not_called()
        self.assertTrue(writer.errors)

    def test_backpressure_retains_partial_frame_and_rejects_new_progress(self):
        pipe = _FramedPipe(123)
        writes = []
        def write(_fd, data):
            writes.append(data)
            if len(writes) == 1:
                return 2
            if len(writes) == 2:
                raise BlockingIOError()
            return len(data)
        with patch('losshound.core.session_output.os.write', side_effect=write):
            self.assertTrue(pipe.queue(b'first'))
            remaining = pipe.pending
            self.assertFalse(pipe.queue(b'second'))
            pipe.flush_once()
            self.assertEqual(pipe.pending, remaining)
            pipe.flush_once()
        self.assertEqual(writes[0], b'\x00\x00\x00\x05first')
        self.assertEqual(writes[2], writes[0][2:])
        self.assertFalse(pipe.pending)


    def test_windows_311_os_output_fails_closed_but_memory_output_remains_available(self):
        with patch('losshound.core.session_output._process_support',
                   side_effect=AssertionError('No OS output helper on Windows 3.11')) as support, \
             patch('losshound.core.session_output.subprocess.Popen',
                   side_effect=AssertionError('No child on Windows 3.11')) as launch, \
             patch.object(BoundedSessionOutput, '_fd',
                          side_effect=AssertionError('No OS sink inspection')) as descriptor, \
             patch('losshound.core.session_output.sys.platform', 'win32'), \
             patch('losshound.core.session_output.sys.version_info', (3, 11, 18)):
            writer = BoundedSessionOutput(object(), io.StringIO(), 101, clock=lambda: 100)
            self.assertFalse(writer.start())
            self.assertFalse(writer.finish('{}'))
            self.assertEqual(writer.active_pids, [])
            self.assertEqual(writer.started_pids, [])
            self.assertEqual(writer.errors, [
                'Bounded OS CLI output requires Windows Python 3.12+; unsupported stream',
            ])
            stdout, stderr = io.StringIO(), io.StringIO()
            memory = BoundedSessionOutput(stdout, stderr, 101, clock=lambda: 100)
            self.assertTrue(memory.start())
            self.assertTrue(memory.progress('read-only cleanup'))
            self.assertTrue(memory.finish('{"status":"cancelled"}'))
            self.assertEqual(json.loads(stdout.getvalue())['status'], 'cancelled')
            self.assertIn('read-only cleanup', stderr.getvalue())
            self.assertEqual(memory.errors, [])
            support.assert_not_called()
            launch.assert_not_called()
            descriptor.assert_not_called()


@unittest.skipUnless(sys.platform == 'win32' and sys.version_info >= (3, 12),
                     'Native Windows Python 3.12+ required; no WSL substitute')
class NativeOutputLifecycleTests(unittest.TestCase):
    def test_real_child_delivers_json_and_exits(self):
        with tempfile.TemporaryDirectory(prefix='losshound-s1-output-', dir=Path(__file__).resolve().parents[1]) as folder:
            path = Path(folder) / 'evidence.json'
            with path.open('w', encoding='utf-8') as stdout, open(os.devnull, 'w') as stderr:
                writer = BoundedSessionOutput(stdout, stderr, time.monotonic() + 5)
                try:
                    self.assertTrue(writer.start(), writer.errors)
                    self.assertTrue(writer.progress('read-only evidence'))
                    self.assertTrue(writer.finish('{"status":"cancelled","evidence":[]}'), writer.errors)
                finally:
                    writer.close()
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['status'], 'cancelled')
            self.assertEqual(writer.active_pids, [])
            self.assertEqual(writer.errors, [])

    def test_undrained_sink_cannot_wait_out_a_300_second_session(self):
        read_fd, write_fd = os.pipe()
        started = time.monotonic()
        try:
            with os.fdopen(write_fd, 'wb', buffering=0) as stdout, open(os.devnull, 'w') as stderr:
                writer = BoundedSessionOutput(stdout, stderr, started + 300)
                try:
                    self.assertTrue(writer.start(), writer.errors)
                    self.assertFalse(writer.finish(json.dumps({'evidence': 'x' * 1_000_000})))
                finally:
                    writer.close()
                self.assertEqual(writer.active_pids, [])
                self.assertTrue(writer.errors)
                self.assertFalse(any('cleanup' in error for error in writer.errors), writer.errors)
        finally:
            os.close(read_fd)
        self.assertLess(time.monotonic() - started, 3.0)


if __name__ == '__main__':
    unittest.main()
