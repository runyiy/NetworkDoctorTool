from __future__ import annotations

import argparse
import math
import os
import sys

from losshound import __version__


def _duration_seconds(value: str) -> int:
    """Validate an explicitly chosen finite session budget before startup."""
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("duration must be a number of seconds") from exc
    if not math.isfinite(seconds) or not seconds.is_integer() or not 1 <= seconds <= 300:
        raise argparse.ArgumentTypeError("duration must be an integer between 1 and 300 seconds")
    return int(seconds)


def _needs_console(argv: list[str] | tuple[str, ...] | None = None) -> bool:
    """Return whether a windowed build was invoked from the command line.

    A normal Explorer launch has no arguments and should remain console-free.
    Any supplied argument can lead to argparse output (including an error for a
    typo), so packaged command-line launches need real standard streams.
    """

    return len(sys.argv if argv is None else argv) > 1


def _ensure_command_line_streams(
    argv: list[str] | tuple[str, ...] | None = None,
) -> None:
    """Restore inherited stdio before any console attachment can replace it.

    A windowed frozen executable may have valid inherited PIPE/DISK handles
    even though its Python streams are None. Wrap only owned duplicates; the
    process's standard handles remain owned by the process. Only absent or
    invalid handles use the existing console fallback.
    """

    if (
        sys.platform != "win32"
        or not getattr(sys, "frozen", False)
        or not _needs_console(argv)
    ):
        return

    missing = [
        (attribute, identifier, console, mode)
        for attribute, identifier, console, mode, method in (
            ("stdin", -10, "CONIN$", "r", "read"),
            ("stdout", -11, "CONOUT$", "w", "write"),
            ("stderr", -12, "CONOUT$", "w", "write"),
        )
        if not callable(getattr(getattr(sys, attribute), method, None))
    ]
    if not missing:
        return

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
    kernel32.GetStdHandle.restype = wintypes.HANDLE
    kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    kernel32.GetFileType.restype = wintypes.DWORD
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    restored = {}
    fallback = []
    try:
        # Duplicate every usable inherited handle before AttachConsole or
        # AllocConsole can replace the process's standard-handle table.
        for attribute, identifier, console, mode in missing:
            handle = kernel32.GetStdHandle(identifier)
            if (handle in (None, 0, ctypes.c_void_p(-1).value)
                    or kernel32.GetFileType(handle) & ~0x8000 not in {1, 2, 3}):
                fallback.append((attribute, console, mode))
                continue
            duplicate = wintypes.HANDLE()
            process = kernel32.GetCurrentProcess()
            if not kernel32.DuplicateHandle(
                process, handle, process, ctypes.byref(duplicate), 0, False, 2,
            ):
                raise OSError(ctypes.get_last_error(), "Cannot duplicate inherited " + attribute)
            descriptor = None
            try:
                import msvcrt

                flags = os.O_BINARY | os.O_NOINHERIT | (os.O_RDONLY if mode == "r" else os.O_WRONLY)
                descriptor = msvcrt.open_osfhandle(duplicate.value, flags)
                restored[attribute] = open(
                    descriptor, mode, encoding="utf-8", errors="replace",
                    buffering=1, closefd=True,
                )
            except BaseException:
                if descriptor is None:
                    kernel32.CloseHandle(duplicate.value)
                else:
                    os.close(descriptor)
                raise

        if fallback:
            console_available = False
            try:
                kernel32.AttachConsole.argtypes = [wintypes.DWORD]
                kernel32.AttachConsole.restype = wintypes.BOOL
                kernel32.AllocConsole.argtypes = []
                kernel32.AllocConsole.restype = wintypes.BOOL
                # ERROR_ACCESS_DENIED also means a console already exists.
                if kernel32.AttachConsole(0xFFFFFFFF) or ctypes.get_last_error() == 5:
                    console_available = True
                else:
                    console_available = bool(kernel32.AllocConsole())
            except (AttributeError, OSError):
                console_available = False

            for attribute, console, mode in fallback:
                if attribute == "stdout" and not console_available:
                    raise OSError("Cannot restore standard output without an inherited handle or console")
                target = console if console_available else os.devnull
                try:
                    restored[attribute] = open(
                        target, mode, encoding="utf-8", errors="replace", buffering=1,
                    )
                except OSError:
                    if attribute == "stdout":
                        raise
                    restored[attribute] = open(
                        os.devnull, mode, encoding="utf-8", errors="replace",
                    )
    except BaseException:
        # These streams own only duplicates or newly opened console/devnull
        # files. Never close a process standard handle or an existing stream.
        for stream in restored.values():
            stream.close()
        raise

    for attribute, stream in restored.items():
        setattr(sys, attribute, stream)


def main():
    # A frozen, windowed build cannot invoke a Python source worker. This exact
    # internal entry accepts only the worker's validated read-only JSON protocol
    # and must run before console attachment, config or GUI imports.
    if getattr(sys, "frozen", False) and sys.argv[1:] == ["--s1-probe-worker"]:
        from losshound.core.session_process import worker_main
        raise SystemExit(worker_main())

    if getattr(sys, "frozen", False) and sys.argv[1:] == ["--s1-output-worker"]:
        from losshound.core.session_output import worker_main
        raise SystemExit(worker_main())

    if getattr(sys, "frozen", False) and sys.argv[1:] == ["--s1-context-worker"]:
        from losshound.core.session_context import worker_main
        raise SystemExit(worker_main())

    _ensure_command_line_streams()

    parser = argparse.ArgumentParser(
        prog="losshound",
        description="Losshound - Lightweight Windows network diagnosis tool",
    )
    parser.add_argument(
        "--cli", action="store_true",
        help="Run one bounded, read-only diagnostic session (no GUI)",
    )
    parser.add_argument(
        "--duration", dest="duration_seconds", type=_duration_seconds, default=60,
        help="Total session budget including cleanup/reporting: 1-300 seconds (default: 60)",
    )
    parser.add_argument("--extended", action="store_true",
                        help="Include dual-stack and cross-protocol explanations in --cli")
    parser.add_argument("--website", action="append", default=[], metavar="URL",
                        help="Explicit HTTP(S) target for --cli --extended; at most eight")
    parser.add_argument("--ipv6-target", action="append", default=None, metavar="IP",
                        help="IPv6 reference target for --cli --extended; at most eight")
    parser.add_argument("--tcp-target", action="append", default=None, metavar="HOST:PORT",
                        help="TCP reference endpoint for --cli --extended; bracket IPv6 literals")
    parser.add_argument("--gui-smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--config", type=str, default=None,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--log-level", type=str, default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )

    # Keep legacy argument shapes so callers get an explicit S1 boundary rather
    # than silently reaching an old unbounded or configuration-modifying path.
    sub = parser.add_subparsers(dest="command", title="Legacy commands (unavailable in S1)")

    opt_parser = sub.add_parser("optimize", help="Optimize network performance")
    opt_parser.add_argument(
        "--skip-dns", action="store_true",
        help="Skip DNS benchmark and optimization",
    )
    opt_parser.add_argument(
        "--apply-dns", action="store_true",
        help="Allow optimize to change DNS servers after benchmarking",
    )
    opt_parser.add_argument(
        "--skip-mtu", action="store_true",
        help="Skip MTU discovery and optimization",
    )

    sub.add_parser("dns-benchmark", help="Benchmark DNS servers")
    sub.add_parser("net-status", help="Show current network optimization status")
    sub.add_parser("restore", help="Restore network settings from backup")

    bench_parser = sub.add_parser("benchmark", help="Run network performance benchmark")
    bench_parser.add_argument(
        "--label", type=str, default="snapshot",
        help="Label for this benchmark (e.g. 'before' or 'after')",
    )
    bench_parser.add_argument(
        "--pings", type=int, default=20,
        help="Number of pings per target (default: 20)",
    )
    sub.add_parser("compare", help="Compare last 'before' vs 'after' benchmarks")

    load_bench_parser = sub.add_parser(
        "load-benchmark", help="Benchmark under network load (bufferbloat, throughput)",
    )
    load_bench_parser.add_argument(
        "--label", type=str, default="snapshot",
        help="Label for this benchmark (e.g. 'before' or 'after')",
    )
    sub.add_parser("load-compare", help="Compare before vs after load benchmarks")

    score_parser = sub.add_parser("score", help="Run benchmark and show network score")
    score_parser.add_argument(
        "--pings", type=int, default=20,
        help="Number of pings per target (default: 20)",
    )

    trends_parser = sub.add_parser("trends", help="Show network performance trends")
    trends_parser.add_argument(
        "--hours", type=int, default=168,
        help="Lookback period in hours (default: 168 = 7 days)",
    )

    history_parser = sub.add_parser("history", help="List recent benchmark snapshots with scores")
    history_parser.add_argument(
        "--count", type=int, default=20,
        help="Number of entries to show (default: 20)",
    )

    sub.add_parser("wifi", help="Run WiFi diagnostics (channel scan, signal, interference)")

    drop_parser = sub.add_parser(
        "drop-analyze",
        help="Analyze connectivity drops (jammer/ISP/cable diagnosis)",
    )
    drop_parser.add_argument(
        "--duration", type=int, default=120,
        help="Monitoring duration in seconds (default: 120)",
    )
    drop_parser.add_argument(
        "--interval", type=float, default=3.0,
        help="Polling interval in seconds (default: 3.0)",
    )
    drop_parser.add_argument(
        "--wan-target", type=str, default="8.8.8.8",
        help="Public IP to ping for WAN check (default: 8.8.8.8)",
    )

    qos_parser = sub.add_parser("qos", help="Add a per-app QoS priority rule")
    qos_parser.add_argument("app", help="Application name or path (e.g. chrome.exe)")
    qos_parser.add_argument(
        "--priority", type=str, default="High",
        choices=["Realtime", "High", "Normal", "Low", "Bulk"],
        help="Priority preset (default: High)",
    )
    sub.add_parser("qos-list", help="List all QoS rules and active policies")
    sub.add_parser("qos-clear", help="Remove all Losshound QoS policies")

    isp_parser = sub.add_parser("isp-report", help="Generate comprehensive ISP report")
    isp_parser.add_argument(
        "--hours", type=int, default=24,
        help="Report period in hours (default: 24)",
    )
    isp_parser.add_argument(
        "--output", type=str, default=None,
        help="Save text report to file instead of printing",
    )
    isp_parser.add_argument(
        "--pdf", type=str, default=None,
        help="Save report as a PDF to the given path (overrides --output)",
    )

    args = parser.parse_args()
    if args.command:
        parser.error(
            f"legacy command '{args.command}' is unavailable in read-only S1; "
            "use --cli [--duration SECONDS] for a bounded diagnostic session"
        )
    if args.extended or args.website or args.ipv6_target or args.tcp_target:
        if not args.cli or not args.extended or args.gui_smoke_test:
            parser.error("Extended targets require --cli --extended and cannot start a GUI")
        from losshound.core.session import SessionRequest
        optional = {}
        if args.ipv6_target is not None:
            optional["ipv6_targets"] = tuple(args.ipv6_target)
        if args.tcp_target is not None:
            optional["tcp_targets"] = tuple(args.tcp_target)
        try:
            SessionRequest(duration_seconds=args.duration_seconds, extended_diagnostics=True,
                           website_urls=tuple(args.website), **optional)
        except ValueError as exc:
            parser.error(str(exc))
    if args.gui_smoke_test:
        try:
            _run_gui_smoke_test()
        except Exception:
            import traceback
            traceback.print_exc()
            raise SystemExit(1)
        raise SystemExit(0)

    from losshound.core.config import load_config
    config = load_config(args.config)

    if args.log_level:
        config.log_level = args.log_level

    from losshound.core.logger import setup_logging
    setup_logging(config.log_level)

    if args.cli:
        from losshound.cli.runner import run_cli
        if args.extended:
            report = run_cli(config, duration_seconds=args.duration_seconds,
                             extended_diagnostics=True, website_urls=tuple(args.website),
                             ipv6_targets=None if args.ipv6_target is None else tuple(args.ipv6_target),
                             tcp_targets=None if args.tcp_target is None else tuple(args.tcp_target))
        else:
            report = run_cli(config, duration_seconds=args.duration_seconds)
        if report.status in {"cleanup_failed", "execution_error", "output_error"}:
            raise SystemExit(1)
        if report.status == "cancelled":
            raise SystemExit(130)
    else:
        _run_gui(config, duration_seconds=args.duration_seconds)


def _run_gui_smoke_test():
    """Exercise packaged Qt imports, the platform plugin and painting only.

    CI uses the offscreen platform. No configuration, database, monitoring,
    firewall setup or other application workers are started.
    """
    from PySide6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget
    from losshound.gui.branding import app_icon
    from losshound.gui.main_window import MainWindow  # Check transitive GUI imports.

    app = QApplication.instance() or QApplication(["losshound-gui-smoke-test"])
    window = QWidget()
    window.setWindowTitle("Losshound GUI smoke test")
    window.setWindowIcon(app_icon())
    layout = QVBoxLayout(window)
    layout.addWidget(QLabel(MainWindow.__name__))
    window.resize(320, 120)
    try:
        window.show()
        app.processEvents()
        if window.grab().isNull() or window.windowIcon().isNull():
            raise RuntimeError("Qt could not render the smoke-test window or load its icon")
    finally:
        window.close()
        app.processEvents()


def _run_gui(config, duration_seconds: int = 60):
    from PySide6.QtWidgets import QApplication
    from losshound.gui.branding import app_icon
    from losshound.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Losshound")
    app.setApplicationVersion(__version__)
    app.setWindowIcon(app_icon())

    window = MainWindow(config, duration_seconds=duration_seconds)
    app.aboutToQuit.connect(window.shutdown_all)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
