"""Shared helpers for stopping background QThreads at app shutdown."""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from PySide6.QtCore import QThread

logger = logging.getLogger(__name__)


def stop_qthread(thread: Optional[QThread], wait_ms: int = 1500) -> None:
    """Politely stop a QThread, terminating as a last resort.

    No-op when ``thread`` is None or already finished. ``wait_ms`` is the
    grace period before terminate() is called. The child process side of
    things is handled separately by the Job Object on Windows.
    """
    if thread is None:
        return
    try:
        if not thread.isRunning():
            return
        thread.requestInterruption()
        thread.quit()
        if thread.wait(wait_ms):
            return
        logger.debug("QThread did not stop in %dms; terminating", wait_ms)
        thread.terminate()
        thread.wait(500)
    except RuntimeError:
        # Underlying C++ object already gone — nothing to do.
        pass
    except Exception:
        logger.exception("Error stopping QThread")


def stop_qthreads(threads: Iterable[QThread], wait_ms: int = 1500) -> None:
    """Stop every QThread in an iterable. Safe to pass a live list."""
    for t in list(threads):
        stop_qthread(t, wait_ms)
