"""S1 GUI contract tests using inert Qt stubs, without third-party imports.

These verify wiring and lifetime logic only, not Qt rendering or Windows GUI
acceptance. Real Qt/Windows checks remain separate after the dependency gate.
"""
from __future__ import annotations

import ast
import importlib
import json
import sys
import threading
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


class _EventSignal:
    def __init__(self):
        self.callbacks = []

    def connect(self, callback, *_args, **_kwargs):
        self.callbacks.append(callback)

    def emit(self, *args):
        for callback in tuple(self.callbacks):
            callback(*args)


class _Signal:
    def __init__(self, *_args):
        self.name = ""

    def __set_name__(self, _owner, name):
        self.name = name

    def __get__(self, instance, _owner):
        if instance is None:
            return self
        return instance.__dict__.setdefault("signal_" + self.name, _EventSignal())


class _Widget:
    def __init__(self, *args, **_kwargs):
        self._text = args[0] if args and isinstance(args[0], str) else ""
        self._value = 0
        self._enabled = True
        self._range = (0, 100)
        self.clicked = _EventSignal()
        self.timeout = _EventSignal()
        self.close_count = 0
        self.hidden = False
        self.active = False

    def setText(self, value): self._text = value
    def text(self): return self._text
    def setPlainText(self, value): self._text = value
    def toPlainText(self): return self._text
    def clear(self): self._text = ""
    def setEnabled(self, value): self._enabled = value
    def isEnabled(self): return self._enabled
    def setRange(self, low, high): self._range = (low, high)
    def setValue(self, value): self._value = max(self._range[0], min(value, self._range[1]))
    def value(self): return self._value
    def hide(self): self.hidden = True
    def close(self): self.close_count += 1
    def start(self): self.active = True
    def stop(self): self.active = False
    def deleteLater(self): self.deleted = True
    def setObjectName(self, *_args): pass
    def setWordWrap(self, *_args): pass
    def setSuffix(self, *_args): pass
    def setAccessibleName(self, *_args): pass
    def setStyleSheet(self, *_args): pass
    def setReadOnly(self, *_args): pass
    def setPlaceholderText(self, *_args): pass
    def setInterval(self, *_args): pass
    def setContentsMargins(self, *_args): pass
    def setSpacing(self, *_args): pass
    def addWidget(self, *_args): pass
    def addLayout(self, *_args): pass
    def addStretch(self): pass
    def setWindowTitle(self, *_args): pass
    def setWindowIcon(self, *_args): pass
    def setMinimumSize(self, *_args): pass
    def resize(self, *_args): pass
    def setCentralWidget(self, widget): self.central = widget
    def sender(self): return getattr(self, "_sender", None)
    def setToolTip(self, *_args): pass


class _MessageBox(_Widget):
    class StandardButton:
        Yes = 1
        No = 2

    @staticmethod
    def question(*_args, **_kwargs):
        return _MessageBox.StandardButton.No

    @staticmethod
    def warning(*_args, **_kwargs):
        return _MessageBox.StandardButton.No


class _Timer(_Widget):
    @staticmethod
    def singleShot(_delay, callback): callback()


class _Thread(_Widget):
    finished = _Signal()

    def start(self): self.active = True
    def wait(self, timeout):
        self.wait_timeout = timeout
        return not self.active


class _Header(_Widget):
    def __init__(self):
        super().__init__()
        self._pause_btn = _Widget()
        self._run_btn = _Widget()


class _Request:
    def __init__(self, duration_seconds=60, ping_targets=(), dns_hostnames=(), *,
                 extended_diagnostics=False, website_urls=(), ipv6_targets=(), tcp_targets=()):
        if not isinstance(duration_seconds, int) or not 1 <= duration_seconds <= 300:
            raise ValueError("duration must be between 1 and 300")
        self.duration_seconds = duration_seconds
        self.ping_targets = ping_targets
        self.dns_hostnames = dns_hostnames
        self.extended_diagnostics = extended_diagnostics
        self.website_urls = tuple(website_urls)
        self.ipv6_targets = tuple(ipv6_targets)
        self.tcp_targets = tuple(tcp_targets)


class _Report:
    status = "cancelled"
    budget_seconds = 60
    duration_seconds = 1.5

    def to_dict(self):
        return {
            "schema_version": 3, "status": self.status,
            "budget_seconds": self.budget_seconds, "duration_seconds": self.duration_seconds,
            "epochs": [], "evidence": [], "incomplete": ["DNS"],
            "cleanup_errors": [], "output_errors": [], "context_blind_spots": [],
            "analysis": {"findings": [], "intermittent": [], "limitations": [], "coverage": {}},
        }

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


@contextmanager
def _gui_modules(real_core=False):
    """Use inert Qt; optionally preserve the real current-session core modules."""
    qt = types.ModuleType("PySide6")
    core = types.ModuleType("PySide6.QtCore")
    core.QThread, core.Signal, core.QTimer = _Thread, _Signal, _Timer
    core.Slot = lambda *_args, **_kwargs: (lambda function: function)
    core.Qt = types.SimpleNamespace(ConnectionType=types.SimpleNamespace(QueuedConnection=1))
    widgets = types.ModuleType("PySide6.QtWidgets")
    for name in (
        "QFileDialog", "QHBoxLayout", "QLabel", "QMessageBox", "QPlainTextEdit",
        "QProgressBar", "QPushButton", "QSpinBox", "QVBoxLayout", "QWidget", "QMainWindow", "QLineEdit",
    ):
        setattr(widgets, name, _Widget)
    widgets.QMessageBox = _MessageBox
    gui = types.ModuleType("PySide6.QtGui")
    gui.QCloseEvent = object
    session = types.ModuleType("losshound.core.session")
    session.SessionRequest = _Request
    session.SessionReport = _Report
    session.SessionController = lambda _request: None
    process = types.ModuleType("losshound.core.session_process")
    process.MAX_CLEANUP_SECONDS = 2.0
    theme = types.ModuleType("losshound.gui.theme")
    theme.button_style = lambda *_args: ""
    theme.get_dark_stylesheet = lambda: ""
    branding = types.ModuleType("losshound.gui.branding")
    branding.app_icon = lambda: None
    painted = types.ModuleType("losshound.gui.painted")
    painted.TexturedSurface = _Widget
    gui_widgets = types.ModuleType("losshound.gui.widgets")
    gui_widgets.LosshoundHeader = _Header
    replacements = {
        "PySide6": qt, "PySide6.QtCore": core,
        "PySide6.QtWidgets": widgets, "PySide6.QtGui": gui,
        "losshound.core.session": session, "losshound.core.session_process": process,
        "losshound.gui.theme": theme, "losshound.gui.branding": branding,
        "losshound.gui.painted": painted, "losshound.gui.widgets": gui_widgets,
    }
    if real_core:
        replacements.pop("losshound.core.session")
        replacements.pop("losshound.core.session_process")
    names = (
        "losshound.gui.session_worker", "losshound.gui.session_panel",
        "losshound.gui.main_window",
    )
    old_modules = {name: sys.modules.pop(name, None) for name in names}
    old_path = sys.path[:]
    sys.path.insert(0, str(SRC))
    try:
        # Load these against the genuine session module before the old S1 stub
        # replaces its import entry; otherwise a later real_core context could
        # inherit a RepairController bound to fake report/request classes.
        for name in ("losshound.core.session", "losshound.core.repair",
                     "losshound.core.session_report"):
            importlib.import_module(name)
        with patch.dict(sys.modules, replacements):
            worker = importlib.import_module(names[0])
            panel = importlib.import_module(names[1])
            window = importlib.import_module(names[2])
            yield worker, panel, window
    finally:
        sys.path[:] = old_path
        for name in names:
            sys.modules.pop(name, None)
            if old_modules[name] is not None:
                sys.modules[name] = old_modules[name]


class SessionGuiContracts(unittest.TestCase):
    def config(self):
        return types.SimpleNamespace(
            public_ping_targets=["1.1.1.1"], dns_test_hostnames=["example.com"],
            lan_discovery_firewall_enabled=True, auto_benchmark_interval_minutes=1,
            close_to_tray=True,
        )

    def test_startup_does_not_import_legacy_workers_or_mutation_tabs(self):
        source = ROOT / "src/losshound/gui/main_window.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertFalse(any(
            token in name for name in imported for token in
            ("scheduler", "optimizer", "qos", "firewall", "settings_tab", "lan_tab", "drop_tab")
        ))
        with _gui_modules() as (_worker, _panel, window_module):
            window = window_module.MainWindow(self.config())
            self.assertIsNone(window._session._worker)
            self.assertFalse(window._session._display_timer.active)
            self.assertTrue(window._header._pause_btn.hidden)
            self.assertTrue(window._header._run_btn.hidden)
            self.assertFalse(hasattr(window, "_monitor"))
            self.assertFalse(hasattr(window, "_optimizer_tab"))
            self.assertFalse(hasattr(window, "_tray"))

    def test_duration_default_and_limit_are_explicit(self):
        with _gui_modules() as (_worker, panel_module, _window):
            panel = panel_module.SessionPanel(self.config())
            self.assertEqual(panel._duration.value(), 60)
            self.assertEqual(panel._duration._range, (1, 300))
            with self.assertRaises(ValueError):
                panel_module.SessionPanel(self.config(), 301)

    def test_cancel_is_cooperative_and_report_keeps_worker_until_thread_exits(self):
        with _gui_modules() as (_worker, panel_module, _window):
            panel = panel_module.SessionPanel(self.config())
            panel.start_session()
            worker = panel._worker
            self.assertTrue(worker.active)
            self.assertFalse(panel._duration.isEnabled())
            panel.start_session()
            self.assertIs(panel._worker, worker)
            panel.cancel_session()
            self.assertTrue(worker.cancel_event.is_set())
            self.assertIs(panel._worker, worker)
            worker.report_ready.emit(_Report())
            self.assertIs(panel._worker, worker)
            self.assertFalse(panel._start_btn.isEnabled())
            self.assertFalse(panel._save_btn.isEnabled())
            self.assertIn("Unfinished", panel._preview.toPlainText())
            worker.active = False
            worker.finished.emit()
            self.assertIsNone(panel._worker)
            self.assertTrue(panel._save_btn.isEnabled())
            self.assertTrue(panel._start_btn.isEnabled())

    def test_close_waits_for_real_thread_finish_without_destroying_worker(self):
        with _gui_modules() as (_worker, _panel, window_module):
            window = window_module.MainWindow(self.config())
            window._session.start_session()
            worker = window._session._worker
            event = types.SimpleNamespace(ignore=lambda: setattr(event, "ignored", True),
                                          accept=lambda: setattr(event, "accepted", True))
            window.closeEvent(event)
            self.assertTrue(event.ignored)
            self.assertTrue(worker.cancel_event.is_set())
            self.assertIs(window._session._worker, worker)
            worker.report_ready.emit(_Report())
            self.assertEqual(window.close_count, 0)
            worker.active = False
            worker.finished.emit()
            self.assertEqual(window.close_count, 1)
            self.assertFalse(window._session._start_btn.isEnabled())

    def test_failed_shutdown_wait_is_bounded_and_retains_worker(self):
        with _gui_modules() as (_worker, _panel, window_module):
            window = window_module.MainWindow(self.config())
            window._session.start_session()
            worker = window._session._worker
            self.assertFalse(window.shutdown_all())
            self.assertEqual(worker.wait_timeout, 2250)
            self.assertIs(window._session._worker, worker)
            self.assertIn("not completed", window._session._state.text())

    def test_invalid_legacy_config_cannot_start_any_worker(self):
        with _gui_modules() as (_worker, panel_module, _window):
            panel = panel_module.SessionPanel(self.config())
            def reject(**_kwargs):
                raise ValueError("at most eight targets")
            panel_module.SessionRequest = reject
            panel.start_session()
            self.assertIsNone(panel._worker)
            self.assertIn("Cannot start session", panel._state.text())
            self.assertTrue(panel._start_btn.isEnabled())
            self.assertFalse(panel._display_timer.active)

    def test_worker_passes_same_cancel_event_to_controller(self):
        with _gui_modules() as (worker_module, _panel, _window):
            captured = {}
            class Controller:
                def __init__(self, request): captured["request"] = request
                def run(self, *, cancel_event, on_progress, absolute_deadline):
                    captured["event"] = cancel_event
                    captured["callback"] = on_progress
                    captured["deadline"] = absolute_deadline
                    return _Report()
            worker_module.SessionController = Controller
            worker = worker_module.SessionWorker(_Request())
            reports = []
            worker.report_ready.connect(reports.append)
            worker.cancel()
            worker.run()
            self.assertIs(captured["event"], worker.cancel_event)
            self.assertTrue(captured["event"].is_set())
            self.assertEqual(captured["deadline"], worker.started_monotonic + worker.request.duration_seconds)
            self.assertEqual(len(reports), 1)

    def test_thread_scheduling_delay_consumes_original_session_budget(self):
        with _gui_modules() as (worker_module, _panel, _window):
            captured = {}
            class Controller:
                def __init__(self, request): captured["request"] = request
                def run(self, *, cancel_event, on_progress, absolute_deadline):
                    captured["deadline"] = absolute_deadline
                    captured["run_at"] = worker_module.time.monotonic()
                    return _Report()
            worker_module.SessionController = Controller
            with patch.object(worker_module.time, "monotonic", return_value=100.0) as clock:
                worker = worker_module.SessionWorker(_Request(60))
                self.assertEqual(worker.started_monotonic, 100.0)
                reports, failures = [], []
                worker.report_ready.connect(reports.append)
                worker.failed.connect(failures.append)
                clock.return_value = 105.0
                worker.run()
            self.assertEqual(captured["run_at"], 105.0)
            self.assertEqual(captured["deadline"], 160.0)
            self.assertEqual(worker.started_monotonic, 100.0)
            self.assertEqual(len(reports), 1)
            self.assertEqual(failures, [])

    def test_gui_does_not_force_terminate_a_qthread(self):
        for filename in ("main_window.py", "session_panel.py", "session_worker.py"):
            tree = ast.parse((ROOT / "src/losshound/gui" / filename).read_text(encoding="utf-8"))
            calls = [node.func.attr for node in ast.walk(tree)
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
            self.assertNotIn("terminate", calls)
            self.assertNotIn("quit", calls)


if __name__ == "__main__":
    unittest.main()
