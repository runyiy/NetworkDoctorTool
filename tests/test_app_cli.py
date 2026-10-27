import pytest

from losshound import app


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["Losshound.exe"], False),
        (["Losshound.exe", "--help"], True),
        (["Losshound.exe", "benchmark"], True),
        (["Losshound.exe", "--cli"], True),
        (["Losshound.exe", "--unknown-option"], True),
    ],
)
def test_console_is_requested_for_every_argument_driven_launch(argv, expected):
    assert app._needs_console(argv) is expected


def test_stream_repair_is_a_noop_outside_frozen_windows(monkeypatch):
    stdin, stdout, stderr = app.sys.stdin, app.sys.stdout, app.sys.stderr
    monkeypatch.setattr(app.sys, "platform", "linux")

    app._ensure_command_line_streams(["losshound", "--help"])

    assert (app.sys.stdin, app.sys.stdout, app.sys.stderr) == (stdin, stdout, stderr)


@pytest.mark.parametrize(
    "argv",
    [
        ["losshound", "benchmark", "--pings", "0"],
        ["losshound", "score", "--pings", "-1"],
        ["losshound", "trends", "--hours", "0"],
        ["losshound", "history", "--count", "0"],
        ["losshound", "isp-report", "--hours", "-5"],
        ["losshound", "drop-analyze", "--duration", "0"],
        ["losshound", "drop-analyze", "--interval", "0.5"],
    ],
)
def test_cli_rejects_non_positive_numeric_arguments(monkeypatch, argv):
    monkeypatch.setattr(app.sys, "argv", argv)

    with pytest.raises(SystemExit) as exc:
        app.main()

    assert exc.value.code == 2


def test_cli_help_exits_without_initializing_runtime(monkeypatch):
    monkeypatch.setattr(app.sys, "argv", ["losshound", "--help"])

    with pytest.raises(SystemExit) as exc:
        app.main()

    assert exc.value.code == 0


@pytest.mark.parametrize("fails", [False, True])
def test_gui_smoke_test_reports_failure_without_starting_app(monkeypatch, fails):
    from losshound.core import config

    def smoke_test():
        if fails:
            raise ImportError("DLL load failed while importing QtWidgets")

    def unexpected_startup(*args, **kwargs):
        pytest.fail("Smoke test must not start configuration or monitoring")

    monkeypatch.setattr(app.sys, "argv", ["losshound", "--gui-smoke-test"])
    monkeypatch.setattr(app, "_run_gui_smoke_test", smoke_test)
    monkeypatch.setattr(config, "load_config", unexpected_startup)
    monkeypatch.setattr(app, "_run_gui", unexpected_startup)
    with pytest.raises(SystemExit) as exc:
        app.main()
    assert exc.value.code == int(fails)
