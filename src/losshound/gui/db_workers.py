"""Generic background database QThread workers.

Allows the GUI dashboard tabs to execute SQLite queries and database write
operations asynchronously in background threads, keeping the main GUI
thread completely responsive and stutter-free.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QThread, Signal

from losshound.storage.history import HistoryStore

logger = logging.getLogger(__name__)


class DbQueryWorker(QThread):
    """Generic background worker to run a database query function cleanly."""

    finished = Signal(object)  # Emits the query result
    error = Signal(str)

    def __init__(
        self,
        db_path: Path,
        query_fn: Callable[[HistoryStore], Any],
        parent=None,
    ):
        super().__init__(parent)
        self._db_path = db_path
        self._query_fn = query_fn

    def run(self):
        try:
            with HistoryStore(self._db_path) as store:
                result = self._query_fn(store)
                self.finished.emit(result)
        except Exception as exc:
            logger.exception("Database query worker failed")
            self.error.emit(str(exc))


class DbWriteWorker(QThread):
    """Generic background worker to run a database write operation lag-free."""

    finished = Signal()
    error = Signal(str)

    def __init__(
        self,
        db_path: Path,
        task_fn: Callable[[HistoryStore], None],
        parent=None,
    ):
        super().__init__(parent)
        self._db_path = db_path
        self._task_fn = task_fn

    def run(self):
        try:
            with HistoryStore(self._db_path) as store:
                self._task_fn(store)
                self.finished.emit()
        except Exception as exc:
            logger.exception("Database write worker failed")
            self.error.emit(str(exc))
