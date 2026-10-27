"""S1 public entry-point boundaries; no third-party imports or live probes."""

from __future__ import annotations

import builtins
import contextlib
import io
import json
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from losshound import app


class EntryPointBoundaryTests(unittest.TestCase):
    def test_legacy_commands_stop_before_config_or_legacy_imports(self):
        commands = (
            ["optimize", "--apply-dns"], ["restore"], ["qos", "browser.exe"],
            ["qos-clear"], ["load-benchmark"], ["drop-analyze"],
            ["benchmark"], ["score"], ["wifi"], ["dns-benchmark"],
            ["net-status"], ["compare"], ["load-compare"], ["trends"],
            ["history"], ["qos-list"], ["isp-report"],
        )
        real_import = builtins.__import__
        forbidden = (
            "losshound.core.config", "losshound.core.optimizer",
            "losshound.core.qos", "losshound.core.firewall",
            "losshound.cli.optimizer_cli",
        )

        def checked_import(name, *args, **kwargs):
            if any(name == item or name.startswith(item + ".") for item in forbidden):
                self.fail(f"legacy dispatch imported {name}")
            return real_import(name, *args, **kwargs)

        for command in commands:
            with self.subTest(command=command):
                with mock.patch.object(sys, "argv", ["losshound", *command]):
                    with mock.patch("builtins.__import__", side_effect=checked_import):
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit) as error:
                                app.main()
                self.assertEqual(error.exception.code, 2)

    def test_smoke_flag_does_not_bypass_legacy_command_rejection(self):
        with mock.patch.object(sys, "argv", ["losshound", "--gui-smoke-test", "optimize"]):
            with mock.patch.object(app, "_run_gui_smoke_test") as smoke:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        app.main()
        self.assertEqual(error.exception.code, 2)
        smoke.assert_not_called()

    def test_duration_rejects_nonfinite_fractional_and_out_of_range_before_startup(self):
        for duration in ("0", "301", "-1", "nan", "inf", "1.5", "invalid"):
            with self.subTest(duration=duration):
                with mock.patch.object(sys, "argv", ["losshound", "--cli", "--duration", duration]):
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as error:
                            app.main()
                self.assertEqual(error.exception.code, 2)
        for duration in ("1", "60", "300"):
            self.assertEqual(app._duration_seconds(duration), int(duration))

    def test_cli_dispatch_has_explicit_finite_budget(self):
        config = SimpleNamespace(log_level="INFO")
        config_module = types.ModuleType("losshound.core.config")
        config_module.load_config = mock.Mock(return_value=config)
        logger_module = types.ModuleType("losshound.core.logger")
        logger_module.setup_logging = mock.Mock()
        cli_module = types.ModuleType("losshound.cli.runner")
        cli_module.run_cli = mock.Mock(return_value=SimpleNamespace(status="deadline"))
        modules = {
            "losshound.core.config": config_module,
            "losshound.core.logger": logger_module,
            "losshound.cli.runner": cli_module,
        }
        for chosen, expected in (([], 60), (["--duration", "300"], 300)):
            with self.subTest(chosen=chosen):
                with mock.patch.dict(sys.modules, modules):
                    with mock.patch.object(sys, "argv", ["losshound", "--cli", *chosen]):
                        app.main()
                cli_module.run_cli.assert_called_with(config, duration_seconds=expected)

    def test_cli_exit_codes_distinguish_cancelled_and_failed_cleanup(self):
        config_module = types.ModuleType("losshound.core.config")
        config_module.load_config = lambda _path: SimpleNamespace(log_level="INFO")
        logger_module = types.ModuleType("losshound.core.logger")
        logger_module.setup_logging = lambda _level: None
        for status, code in (("cancelled", 130), ("cleanup_failed", 1), ("execution_error", 1), ("output_error", 1)):
            with self.subTest(status=status):
                cli_module = types.ModuleType("losshound.cli.runner")
                cli_module.run_cli = lambda *_args, **_kwargs: SimpleNamespace(status=status)
                with mock.patch.dict(sys.modules, {
                    "losshound.core.config": config_module,
                    "losshound.core.logger": logger_module,
                    "losshound.cli.runner": cli_module,
                }):
                    with mock.patch.object(sys, "argv", ["losshound", "--cli"]):
                        with self.assertRaises(SystemExit) as error:
                            app.main()
                self.assertEqual(error.exception.code, code)

    def test_direct_legacy_dispatch_is_also_closed(self):
        from losshound.cli.optimizer_cli import run_optimizer_command
        for command in ("optimize", "restore", "qos", "qos-clear", "load-benchmark"):
            with self.subTest(command=command):
                with self.assertRaises(SystemExit):
                    run_optimizer_command(SimpleNamespace(command=command))

    def test_gui_ignores_persisted_firewall_opt_in(self):
        application = SimpleNamespace(
            setApplicationName=mock.Mock(), setApplicationVersion=mock.Mock(),
            setWindowIcon=mock.Mock(), aboutToQuit=SimpleNamespace(connect=mock.Mock()),
            exec=mock.Mock(return_value=0),
        )
        widgets = types.ModuleType("PySide6.QtWidgets")
        widgets.QApplication = mock.Mock(return_value=application)
        branding = types.ModuleType("losshound.gui.branding")
        branding.app_icon = mock.Mock(return_value=object())
        window = SimpleNamespace(shutdown_all=mock.Mock(), show=mock.Mock())
        main_window = types.ModuleType("losshound.gui.main_window")
        main_window.MainWindow = mock.Mock(return_value=window)
        real_import = builtins.__import__

        def checked_import(name, *args, **kwargs):
            if name == "losshound.core.firewall":
                self.fail("GUI startup must not import firewall reconciliation")
            return real_import(name, *args, **kwargs)

        config = SimpleNamespace(lan_discovery_firewall_enabled=True)
        with mock.patch.dict(sys.modules, {
            "PySide6": types.ModuleType("PySide6"),
            "PySide6.QtWidgets": widgets,
            "losshound.gui.branding": branding,
            "losshound.gui.main_window": main_window,
        }):
            with mock.patch("builtins.__import__", side_effect=checked_import):
                with self.assertRaises(SystemExit) as error:
                    app._run_gui(config, duration_seconds=300)
        self.assertEqual(error.exception.code, 0)
        main_window.MainWindow.assert_called_once_with(config, duration_seconds=300)
        application.aboutToQuit.connect.assert_called_once_with(window.shutdown_all)

    def test_frozen_worker_dispatch_precedes_console_and_config(self):
        for module_name, flag in (
            ("losshound.core.session_process", "--s1-probe-worker"),
            ("losshound.core.session_output", "--s1-output-worker"),
            ("losshound.core.session_context", "--s1-context-worker"),
        ):
            with self.subTest(flag=flag):
                worker = types.ModuleType(module_name)
                worker.worker_main = mock.Mock(return_value=0)
                with mock.patch.dict(sys.modules, {module_name: worker}):
                    with mock.patch.object(sys, "frozen", True, create=True):
                        with mock.patch.object(sys, "argv", ["Losshound.exe", flag]):
                            with mock.patch.object(app, "_ensure_command_line_streams") as console:
                                with self.assertRaises(SystemExit) as error:
                                    app.main()
                self.assertEqual(error.exception.code, 0)
                worker.worker_main.assert_called_once_with()
                console.assert_not_called()


class BoundedCliTests(unittest.TestCase):
    def test_all_cli_reports_redact_private_context_and_preserve_raw_api_result(self):
        from losshound.cli import runner
        from losshound.core.session import NetworkEpoch, ProbeEvidence, ProbeOutcome, SessionReport

        config = SimpleNamespace(public_ping_targets=[], dns_test_hostnames=[])
        for extended in (False, True):
            with self.subTest(extended=extended):
                report = SessionReport("cancelled", 60)
                report.epochs = [NetworkEpoch(1, "synthetic-network-identity", 0.0, {
                    "wifi": {"ssid": "synthetic-private-ssid"},
                    "adapters": [{"Name": "synthetic-private-adapter"}],
                    "gateway": "192.0.2.17",
                })]
                report.evidence = [ProbeEvidence(
                    1, "2026-10-27T00:00:00+00:00", 0.0, 0.1, 1,
                    "icmp", "IPv4", "192.0.2.17", ProbeOutcome.EXECUTION_ERROR,
                    error="synthetic-private-error",
                    data={"stdout": "synthetic-private-raw-output"},
                )]
                report.incomplete = ["synthetic-private-incomplete"]
                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(runner, "SessionController") as controller, \
                     mock.patch.object(runner.signal, "signal"), \
                     contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    controller.return_value.run.return_value = report
                    returned = runner.run_cli(config, extended_diagnostics=extended)
                public = json.loads(stdout.getvalue())
                self.assertTrue(public.get("redaction", {}).get("applied"))
                for private in ("synthetic-network-identity", "synthetic-private-ssid",
                                "synthetic-private-adapter", "192.0.2.17",
                                "synthetic-private-error", "synthetic-private-raw-output",
                                "synthetic-private-incomplete"):
                    self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())
                self.assertEqual(public["status"], "cancelled")
                self.assertEqual(public["evidence"][0]["outcome"], "execution_error")
                self.assertEqual(public["epochs"][0]["context"]["gateway"],
                                 public["evidence"][0]["target"])
                self.assertIs(returned, report)
                self.assertEqual(returned.epochs[0].context["wifi"]["ssid"],
                                 "synthetic-private-ssid")

    def test_ctrl_c_requests_cancellation_then_prints_final_evidence(self):
        from losshound.cli import runner

        config = SimpleNamespace(
            public_ping_targets=["1.1.1.1"], dns_test_hostnames=["example.com"],
            auto_benchmark_interval_minutes=1, lan_discovery_firewall_enabled=True,
            close_to_tray=True,
        )
        signals = []
        cancel_seen = []
        prior = object()

        def set_handler(_signum, handler):
            signals.append(handler)
            return prior

        class Controller:
            def __init__(self, request):
                self.request = request
                self_test.assertEqual(request.duration_seconds, 60)
                self_test.assertEqual(tuple(request.ping_targets), ("1.1.1.1",))

            def run(self, *, cancel_event, on_progress, absolute_deadline, output_reserve_seconds):
                self_test.assertEqual(output_reserve_seconds, 0.5)
                self_test.assertEqual(absolute_deadline, output_factory.call_args.args[2])
                signals[0](2, None)
                cancel_seen.append(cancel_event.is_set())
                on_progress(SimpleNamespace(phase="cleanup", remaining_seconds=58, completed_count=0))
                return SimpleNamespace(
                    status="cancelled",
                    to_dict=lambda: {"status": "cancelled", "evidence": [], "incomplete": ["icmp"]},
                )

        self_test = self
        output, progress = io.StringIO(), io.StringIO()
        original_print = builtins.print
        with mock.patch.object(runner, "SessionController", Controller):
            with mock.patch.object(runner.signal, "signal", side_effect=set_handler):
                with mock.patch.object(runner, "BoundedSessionOutput", wraps=runner.BoundedSessionOutput) as output_factory:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(progress):
                        report = runner.run_cli(config)
        self.assertEqual(report.status, "cancelled")
        self.assertEqual(cancel_seen, [True])
        self.assertIs(signals[-1], prior)
        self.assertIs(builtins.print, original_print)
        self.assertEqual(json.loads(output.getvalue())["status"], "cancelled")
        self.assertIn("remaining", progress.getvalue())

    def test_windows_311_public_cli_os_sink_returns_error_without_collection(self):
        from losshound.cli import runner
        from losshound.core.session import SessionController

        config_module = types.ModuleType("losshound.core.config")
        config_module.load_config = mock.Mock(return_value=SimpleNamespace(
            log_level="INFO", public_ping_targets=["127.0.0.1"],
            dns_test_hostnames=["localhost"],
        ))
        logger_module = types.ModuleType("losshound.core.logger")
        logger_module.setup_logging = mock.Mock()
        provider = mock.Mock()
        provider.close.return_value = []
        observer = mock.Mock()
        observer.close.return_value = []
        cancellations = []
        observer.start.side_effect = lambda _deadline, cancel: cancellations.append(cancel.is_set())
        reports = []
        original_run = runner.run_cli

        def controller(request):
            return SessionController(request, provider=provider, context_observer=observer)

        def record_run(*args, **kwargs):
            report = original_run(*args, **kwargs)
            reports.append(report)
            return report

        class OsSink:
            def write(self, _text):
                raise AssertionError("Unsupported output must not be written")
            def fileno(self):
                raise AssertionError("Unsupported output must not inspect an OS handle")

        with mock.patch.dict(sys.modules, {
            "losshound.core.config": config_module,
            "losshound.core.logger": logger_module,
        }), mock.patch.object(sys, "platform", "win32"), \
             mock.patch.object(sys, "version_info", (3, 11, 18)), \
             mock.patch.object(sys, "frozen", False, create=True), \
             mock.patch.object(sys, "argv", ["losshound", "--cli"]), \
             mock.patch.object(sys, "stdout", OsSink()), \
             mock.patch.object(sys, "stderr", OsSink()), \
             mock.patch.object(runner, "SessionController", side_effect=controller), \
             mock.patch.object(runner, "run_cli", side_effect=record_run), \
             mock.patch.object(runner.signal, "signal", return_value=object()), \
             mock.patch("losshound.core.session_output._process_support") as support, \
             mock.patch("losshound.core.session_output.subprocess.Popen") as launch:
            with self.assertRaises(SystemExit) as error:
                app.main()

        self.assertEqual(error.exception.code, 1)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].status, "output_error")
        self.assertIn("Bounded OS CLI output requires Windows Python 3.12+; unsupported stream",
                      reports[0].output_errors)
        self.assertEqual(reports[0].evidence, [])
        self.assertEqual(cancellations, [True])
        provider.read_network.assert_not_called()
        provider.probe.assert_not_called()
        observer.snapshot.assert_not_called()
        provider.close.assert_called_once()
        observer.close.assert_called_once()
        support.assert_not_called()
        launch.assert_not_called()

    def test_controller_failure_restores_cli_signal_handler(self):
        from losshound.cli import runner

        prior = object()
        config = SimpleNamespace(public_ping_targets=[], dns_test_hostnames=[])
        controller = mock.Mock()
        controller.run.side_effect = RuntimeError("fixture failure")
        with mock.patch.object(runner, "SessionController", return_value=controller):
            with mock.patch.object(runner.signal, "signal", return_value=prior) as signal_call:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                        runner.run_cli(config, duration_seconds=1)
        self.assertEqual(signal_call.call_args, mock.call(runner.signal.SIGINT, prior))


class InheritedStdioTests(unittest.TestCase):
    @contextlib.contextmanager
    def native_stdio(self, *, handles=None, file_types=None, streams=None):
        """All Windows, CRT, stream-open and close operations are inert mocks."""
        handles = handles if handles is not None else {-10: 10, -11: 11, -12: 12}
        file_types = file_types or {}
        streams = streams or {}
        events, opened = [], {}

        class Handle:
            def __init__(self, value=None):
                self.value = value

        kernel = SimpleNamespace()
        kernel.GetStdHandle = mock.Mock(side_effect=lambda identifier: handles.get(identifier))
        kernel.GetFileType = mock.Mock(side_effect=lambda handle: file_types.get(handle, 3))
        kernel.GetCurrentProcess = mock.Mock(return_value=777)

        def duplicate(_source_process, original, _target_process, result,
                      _access, inherit, options):
            events.append(("duplicate", original))
            self.assertIs(inherit, False)
            self.assertEqual(options, 2)
            result.value = original + 1000
            return True

        kernel.DuplicateHandle = mock.Mock(side_effect=duplicate)
        kernel.CloseHandle = mock.Mock(return_value=True)
        kernel.AttachConsole = mock.Mock(side_effect=lambda _parent: events.append(("attach",)) or True)
        kernel.AllocConsole = mock.Mock(return_value=True)
        native = types.ModuleType("ctypes")
        native.WinDLL = mock.Mock(return_value=kernel)
        native.wintypes = SimpleNamespace(DWORD=int, BOOL=int, HANDLE=Handle)
        native.POINTER = lambda kind: kind
        native.byref = lambda value: value
        native.c_void_p = lambda value: SimpleNamespace(value=(1 << 64) - 1 if value == -1 else value)
        native.get_last_error = mock.Mock(return_value=0)
        crt = types.ModuleType("msvcrt")
        crt.open_osfhandle = mock.Mock(side_effect=lambda handle, _flags: handle + 2000)

        def open_stream(target, mode, **_kwargs):
            events.append(("open", target))
            stream = SimpleNamespace(read=mock.Mock(), write=mock.Mock(),
                                     close=mock.Mock(side_effect=lambda: events.append(("close", target))))
            opened[target] = stream
            return stream

        file_open = mock.Mock(side_effect=open_stream)
        close_fd = mock.Mock()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {"ctypes": native, "msvcrt": crt}))
            stack.enter_context(mock.patch.object(sys, "platform", "win32"))
            stack.enter_context(mock.patch.object(sys, "frozen", True, create=True))
            for attribute in ("stdin", "stdout", "stderr"):
                stack.enter_context(mock.patch.object(sys, attribute, streams.get(attribute)))
            stack.enter_context(mock.patch("builtins.open", file_open))
            stack.enter_context(mock.patch.object(app.os, "close", close_fd))
            stack.enter_context(mock.patch.object(app.os, "O_BINARY", 0x8000, create=True))
            stack.enter_context(mock.patch.object(app.os, "O_NOINHERIT", 0x0080, create=True))
            yield SimpleNamespace(kernel=kernel, native=native, crt=crt,
                                  opened=opened, events=events, file_open=file_open,
                                  close_fd=close_fd)

    def test_pipe_and_disk_handles_are_owned_duplicates_without_console(self):
        with self.native_stdio(file_types={10: 3, 11: 1, 12: 3}) as env:
            app._ensure_command_line_streams(["Losshound.exe", "--cli"])
            self.assertIs(sys.stdin, env.opened[3010])
            self.assertIs(sys.stdout, env.opened[3011])
            self.assertIs(sys.stderr, env.opened[3012])
            self.assertEqual(env.crt.open_osfhandle.call_args_list, [
                mock.call(1010, app.os.O_RDONLY | app.os.O_BINARY | app.os.O_NOINHERIT),
                mock.call(1011, app.os.O_WRONLY | app.os.O_BINARY | app.os.O_NOINHERIT),
                mock.call(1012, app.os.O_WRONLY | app.os.O_BINARY | app.os.O_NOINHERIT),
            ])
            for call in env.file_open.call_args_list:
                self.assertIs(call.kwargs["closefd"], True)
                self.assertEqual(call.kwargs["encoding"], "utf-8")
            env.kernel.AttachConsole.assert_not_called()
            env.kernel.AllocConsole.assert_not_called()
            env.kernel.CloseHandle.assert_not_called()
            env.close_fd.assert_not_called()

    def test_mixed_missing_handles_duplicate_before_console_and_keep_pipe(self):
        with self.native_stdio(handles={-11: 11}) as env:
            app._ensure_command_line_streams(["Losshound.exe", "--help"])
            self.assertIs(sys.stdout, env.opened[3011])
            self.assertIs(sys.stdin, env.opened["CONIN$"])
            self.assertIs(sys.stderr, env.opened["CONOUT$"])
            self.assertLess(env.events.index(("duplicate", 11)), env.events.index(("attach",)))
            self.assertLess(env.events.index(("open", 3011)), env.events.index(("attach",)))
            env.kernel.DuplicateHandle.assert_called_once()
            env.kernel.AttachConsole.assert_called_once_with(0xFFFFFFFF)
            env.kernel.AllocConsole.assert_not_called()
            env.kernel.CloseHandle.assert_not_called()

    def test_existing_python_streams_are_unchanged_and_need_no_native_api(self):
        existing_in, existing_out, existing_err = mock.Mock(), mock.Mock(), mock.Mock()
        with self.native_stdio(
            streams={"stdin": existing_in, "stdout": existing_out},
            file_types={12: 1},
        ) as env:
            app._ensure_command_line_streams(["Losshound.exe", "--cli"])
            self.assertIs(sys.stdin, existing_in)
            self.assertIs(sys.stdout, existing_out)
            self.assertIs(sys.stderr, env.opened[3012])
            env.kernel.GetStdHandle.assert_called_once_with(-12)
            existing_in.close.assert_not_called()
            existing_out.close.assert_not_called()
            env.kernel.AttachConsole.assert_not_called()
        with self.native_stdio(streams={
            "stdin": existing_in, "stdout": existing_out, "stderr": existing_err,
        }) as env:
            app._ensure_command_line_streams(["Losshound.exe", "--help"])
            env.native.WinDLL.assert_not_called()
            env.file_open.assert_not_called()

    def test_duplicate_failure_cleans_prior_owned_stream_without_console_fallback(self):
        existing_in = mock.Mock()
        with self.native_stdio(streams={"stdin": existing_in}) as env:
            duplicate = env.kernel.DuplicateHandle.side_effect
            def fail_second(*args):
                if args[1] == 12:
                    return False
                return duplicate(*args)
            env.kernel.DuplicateHandle.side_effect = fail_second
            env.native.get_last_error.return_value = 5
            with self.assertRaisesRegex(OSError, "Cannot duplicate inherited stderr"):
                app._ensure_command_line_streams(["Losshound.exe", "--cli"])
            self.assertIsNone(sys.stdout)
            self.assertIsNone(sys.stderr)
            self.assertIs(sys.stdin, existing_in)
            env.opened[3011].close.assert_called_once()
            env.kernel.CloseHandle.assert_not_called()
            env.close_fd.assert_not_called()
            env.kernel.AttachConsole.assert_not_called()
            env.kernel.AllocConsole.assert_not_called()
            existing_in.close.assert_not_called()

    def test_crt_wrap_failure_closes_only_owned_duplicate_and_does_not_redirect(self):
        with self.native_stdio(streams={"stdin": mock.Mock(), "stderr": mock.Mock()}) as env:
            env.crt.open_osfhandle.side_effect = OSError("CRT wrapping failed")
            with self.assertRaisesRegex(OSError, "CRT wrapping failed"):
                app._ensure_command_line_streams(["Losshound.exe", "--cli"])
            env.kernel.CloseHandle.assert_called_once_with(1011)
            env.close_fd.assert_not_called()
            env.file_open.assert_not_called()
            env.kernel.AttachConsole.assert_not_called()
            env.kernel.AllocConsole.assert_not_called()
            self.assertIsNone(sys.stdout)

    def test_python_wrap_failure_closes_only_owned_fd_and_does_not_redirect(self):
        with self.native_stdio(streams={"stdin": mock.Mock(), "stderr": mock.Mock()}) as env:
            env.file_open.side_effect = OSError("Text wrapping failed")
            with self.assertRaisesRegex(OSError, "Text wrapping failed"):
                app._ensure_command_line_streams(["Losshound.exe", "--cli"])
            env.close_fd.assert_called_once_with(3011)
            env.kernel.CloseHandle.assert_not_called()
            self.assertEqual(env.file_open.call_count, 1)
            env.kernel.AttachConsole.assert_not_called()
            env.kernel.AllocConsole.assert_not_called()
            self.assertIsNone(sys.stdout)

    def test_only_missing_or_invalid_handles_use_original_console_fallback(self):
        with self.native_stdio(
            handles={-10: None, -11: 0, -12: (1 << 64) - 1},
        ) as env:
            env.kernel.AttachConsole.side_effect = None
            env.kernel.AttachConsole.return_value = False
            env.native.get_last_error.return_value = 5  # Already attached.
            app._ensure_command_line_streams(["Losshound.exe", "--help"])
            self.assertEqual(tuple(call.args[0] for call in env.file_open.call_args_list),
                             ("CONIN$", "CONOUT$", "CONOUT$"))
            env.kernel.AllocConsole.assert_not_called()
            env.kernel.DuplicateHandle.assert_not_called()
            env.crt.open_osfhandle.assert_not_called()
            env.kernel.CloseHandle.assert_not_called()

        with self.subTest(stdout_failure="console unavailable"), self.native_stdio(
            handles={-10: None, -11: None, -12: None},
        ) as env:
            env.kernel.AttachConsole.side_effect = None
            env.kernel.AttachConsole.return_value = False
            env.kernel.AllocConsole.return_value = False
            with self.assertRaisesRegex(OSError, "Cannot restore standard output"):
                app._ensure_command_line_streams(["Losshound.exe", "--cli"])
            self.assertIsNone(sys.stdout)
            self.assertEqual(tuple(call.args[0] for call in env.file_open.call_args_list),
                             (app.os.devnull,))
            env.opened[app.os.devnull].close.assert_called_once()
            env.kernel.AllocConsole.assert_called_once_with()

        with self.subTest(stdout_failure="CONOUT$ open failed"), self.native_stdio(
            handles={-10: None, -11: None, -12: None},
        ) as env:
            open_stream = env.file_open.side_effect
            def fail_console_output(target, mode, **kwargs):
                if target == "CONOUT$":
                    raise OSError("Console output unavailable")
                return open_stream(target, mode, **kwargs)
            env.file_open.side_effect = fail_console_output
            with self.assertRaisesRegex(OSError, "Console output unavailable"):
                app._ensure_command_line_streams(["Losshound.exe", "--cli"])
            self.assertIsNone(sys.stdout)
            self.assertEqual(tuple(call.args[0] for call in env.file_open.call_args_list),
                             ("CONIN$", "CONOUT$"))
            self.assertNotIn(app.os.devnull, env.opened)
            env.opened["CONIN$"].close.assert_called_once()

        existing_out = mock.Mock()
        with self.native_stdio(handles={}, streams={"stdout": existing_out}) as env:
            env.kernel.AttachConsole.side_effect = None
            env.kernel.AttachConsole.return_value = False
            env.kernel.AllocConsole.return_value = False
            app._ensure_command_line_streams(["Losshound.exe", "--help"])
            self.assertIs(sys.stdout, existing_out)
            self.assertEqual(tuple(call.args[0] for call in env.file_open.call_args_list),
                             (app.os.devnull,) * 2)
            existing_out.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
