"""Deadline-bound CLI output isolated from console and redirected-sink stalls.

Only exact in-memory StringIO streams are written in the caller. All OS output
is performed by one private, kill-on-close child. Its control pipe is explicitly
nonblocking; there are no shared output threads or blocking output fallbacks.
"""
from __future__ import annotations

import io
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_PROGRESS_BYTES = 2048
CLEANUP_RESERVE_SECONDS = 0.25
MAX_CLEANUP_SECONDS = 2.0


def _process_support():
    # Source workers run with -I -S, so explicitly add only our source root.
    if not getattr(sys, "frozen", False):
        root = str(Path(__file__).resolve().parents[2])
        if root not in sys.path:
            sys.path.insert(0, root)
    from losshound.core.session_process import _OwnedJob, _repair_frozen_streams, _verify_private_job
    return _OwnedJob, _repair_frozen_streams, _verify_private_job


class _FramedPipe:
    """Retain partial records; drop a new progress record only before sending it."""
    def __init__(self, fd):
        self.fd = fd
        self.pending = b""

    def queue(self, data):
        if self.pending:
            return False
        self.pending = struct.pack("!I", len(data)) + data
        self.flush_once()
        return True

    def flush_once(self):
        if not self.pending:
            return
        try:
            sent = os.write(self.fd, self.pending)
        except BlockingIOError:
            return
        if sent:
            self.pending = self.pending[sent:]


class BoundedSessionOutput:
    """Single-session writer using the same absolute deadline as collection."""
    def __init__(self, stdout, stderr, deadline, *, clock=time.monotonic):
        if not math.isfinite(deadline):
            raise ValueError("Output deadline must be finite")
        self.stdout, self.stderr = stdout, stderr
        self.deadline, self.clock = deadline, clock
        self.errors = []
        self.started_pids = []
        self._proc = self._job = self._pipe = None
        self._started = False
        self._closed = False
        self._finish_deadline = None
        self._memory = {
            "report": type(stdout) is io.StringIO,
            "progress": type(stderr) is io.StringIO,
        }

    @property
    def active_pids(self):
        return [self._proc.pid] if self._proc is not None and self._proc.poll() is None else []

    def _error(self, text):
        if text not in self.errors:
            self.errors.append(text)

    @staticmethod
    def _fd(stream):
        # Do not call arbitrary wrappers' write/flush/fileno methods in-session.
        if type(stream) not in (io.TextIOWrapper, io.FileIO, io.BufferedWriter):
            raise OSError("Unsupported CLI stream; no blocking fallback is permitted")
        descriptor = stream.fileno()
        if not isinstance(descriptor, int) or descriptor < 0:
            raise OSError("CLI stream has no usable OS handle")
        return descriptor

    @staticmethod
    def _command():
        executable = str(Path(sys.executable).resolve(strict=True))
        if getattr(sys, "frozen", False):
            return [executable, "--s1-output-worker"]
        return [executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker"]

    def start(self):
        if self._started:
            return not self.errors
        self._started = True
        if self.clock() >= self.deadline:
            self._error("Output startup deadline reached")
            return False
        if all(self._memory.values()):
            return True
        if sys.platform != "win32" or sys.version_info < (3, 12):
            self._error("Bounded OS CLI output requires Windows Python 3.12+; unsupported stream")
            return False
        try:
            owned_job, _repair, _verify = _process_support()
            stdout = subprocess.DEVNULL if self._memory["report"] else self._fd(self.stdout)
            stderr = subprocess.DEVNULL if self._memory["progress"] else self._fd(self.stderr)
            self._proc = subprocess.Popen(
                self._command(), stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                bufsize=0, shell=False, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            self.started_pids.append(self._proc.pid)
            # The child reads no output request before private ownership exists.
            self._job = owned_job(self._proc)
            os.set_blocking(self._proc.stdin.fileno(), False)
            if os.get_blocking(self._proc.stdin.fileno()):
                raise OSError("Output control pipe is not nonblocking")
            self._pipe = _FramedPipe(self._proc.stdin.fileno())
            return True
        except (OSError, ValueError, AttributeError) as exc:
            self._error(f"Output worker startup failed: {type(exc).__name__}: {exc}")
            self.close()
            return False

    def _record(self, channel, text):
        return json.dumps({"channel": channel, "text": text, "job_name": self._job.name},
                          ensure_ascii=True, allow_nan=False).encode("ascii")

    def progress(self, text):
        """Never wait for sink/pipe capacity; retain any partial prior frame."""
        if self._closed or self.errors or self.clock() >= self.deadline:
            return False
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_PROGRESS_BYTES:
            return False
        if not self.start():
            return False
        try:
            if self._memory["progress"]:
                self.stderr.write(text + "\n")
                return True
            self._pipe.flush_once()
            return self._pipe.queue(self._record("progress", text))
        except (OSError, ValueError) as exc:
            self._error(f"CLI progress output failed: {type(exc).__name__}")
            return False

    def _drain(self, deadline):
        while self._pipe.pending and self.clock() < deadline:
            self._pipe.flush_once()
            if self._pipe.pending:
                time.sleep(min(0.005, max(0.0, deadline - self.clock())))
        return not self._pipe.pending

    def finish(self, report_json):
        """Deliver or explicitly fail, then reap the output child before deadline."""
        if not isinstance(report_json, str) or len(report_json.encode("utf-8")) > MAX_FRAME_BYTES // 2:
            self._error("CLI report exceeds bounded output size")
            self.close()
            return False
        if self.errors or not self.start():
            self.close()
            return False
        # Early cancellation/error must not wait out an unused 300-second
        # observation budget just because an output sink stopped consuming.
        self._finish_deadline = min(self.deadline, self.clock() + MAX_CLEANUP_SECONDS)
        remaining = max(0.0, self._finish_deadline - self.clock())
        work_deadline = self._finish_deadline - min(CLEANUP_RESERVE_SECONDS, remaining * 0.4)
        try:
            if self.clock() >= work_deadline:
                self._error("CLI report output deadline reached")
                return False
            if self._memory["report"]:
                self.stdout.write(report_json + "\n")
            if self._proc is None:
                return True
            if not self._drain(work_deadline):
                self._error("CLI output control pipe remained full before deadline")
                return False
            channel = "finish" if self._memory["report"] else "report"
            payload = self._record(channel, "" if channel == "finish" else report_json)
            if len(payload) > MAX_FRAME_BYTES:
                self._error("Encoded CLI report exceeds bounded frame size")
                return False
            self._pipe.queue(payload)
            if not self._drain(work_deadline):
                self._error("CLI report could not be queued before deadline")
                return False
            self._proc.stdin.close()
            while self._proc.poll() is None and self.clock() < work_deadline:
                time.sleep(min(0.005, max(0.0, work_deadline - self.clock())))
            if self._proc.poll() is None:
                self._error("CLI sink did not complete before deadline")
                return False
            if self._proc.returncode != 0:
                self._error(f"CLI output worker exited {self._proc.returncode}; report delivery unconfirmed")
                return False
            return True
        except (OSError, ValueError) as exc:
            self._error(f"CLI report output failed: {type(exc).__name__}")
            return False
        finally:
            self.close()

    def close(self):
        if self._closed:
            return
        self._closed = True
        proc, job = self._proc, self._job
        if proc is None:
            return
        cleanup_deadline = min(self.deadline, self.clock() + MAX_CLEANUP_SECONDS)
        if self._finish_deadline is not None:
            cleanup_deadline = min(cleanup_deadline, self._finish_deadline)
        try:
            if proc.poll() is None:
                if job is not None:
                    job.terminate()
                else:
                    proc.kill()
            while self.clock() < cleanup_deadline:
                active = job.active_count() if job is not None else int(proc.poll() is None)
                if proc.poll() is not None and not active:
                    break
                time.sleep(min(0.005, max(0.0, cleanup_deadline - self.clock())))
            if proc.poll() is None or (job is not None and job.active_count()):
                self._error("Output worker cleanup was not confirmed before total deadline")
        except OSError as exc:
            self._error(f"Output worker cleanup failed: {type(exc).__name__}")
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
        finally:
            if job is not None:
                job.close()
            if proc.poll() is not None and proc.stdin is not None:
                proc.stdin.close()


def _read_exact(stream, size):
    chunks = []
    while size:
        data = stream.read(size)
        if not data:
            raise ValueError("Incomplete output frame")
        chunks.append(data)
        size -= len(data)
    return b"".join(chunks)


def worker_main():
    """Private output-only worker; accepts text, never commands or file paths."""
    try:
        _owned_job, repair, verify = _process_support()
        repair()
        if sys.platform == "win32" and getattr(sys, "frozen", False) and sys.stderr is None:
            import ctypes
            import msvcrt
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetStdHandle.argtypes = [wintypes.DWORD]
            kernel.GetStdHandle.restype = wintypes.HANDLE
            handle = kernel.GetStdHandle((-12) & 0xFFFFFFFF)
            if not handle or handle == ctypes.c_void_p(-1).value:
                return 2
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            sys.stderr = os.fdopen(fd, "w", encoding="utf-8", errors="replace")
        for stream in (sys.stdout, sys.stderr):
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace", write_through=True)
        source = sys.stdin.buffer
        for _ in range(1024):
            size = struct.unpack("!I", _read_exact(source, 4))[0]
            if not 1 <= size <= MAX_FRAME_BYTES:
                return 2
            record = json.loads(_read_exact(source, size))
            if (not isinstance(record, dict) or set(record) != {"channel", "text", "job_name"}
                    or record["channel"] not in {"progress", "report", "finish"}
                    or not isinstance(record["text"], str) or not verify(record["job_name"])):
                return 2
            if record["channel"] == "finish":
                return 0 if not record["text"] else 2
            stream = sys.stderr if record["channel"] == "progress" else sys.stdout
            stream.write(record["text"] + "\n")
            stream.flush()
            if record["channel"] == "report":
                return 0
        return 2
    except Exception:
        # Error logging here could itself block on the failing sink.
        return 2


if __name__ == "__main__":
    raise SystemExit(worker_main() if sys.argv[1:] == ["--worker"] else 2)
