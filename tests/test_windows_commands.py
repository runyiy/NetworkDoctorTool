import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from losshound.core import subprocess_runner, wifi_diag, windows_commands


def test_command_ignores_working_directory_path_and_windows_environment(tmp_path, monkeypatch):
    system_dir = tmp_path / "trusted" / "System32"
    trusted = system_dir / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    trusted.parent.mkdir(parents=True)
    trusted.write_bytes(b"inert test file; never executed")
    untrusted = tmp_path / "untrusted"
    untrusted.mkdir()
    (untrusted / "powershell.exe").write_bytes(b"inert test file; never executed")
    monkeypatch.chdir(untrusted)
    for variable in ("PATH", "WINDIR", "SystemRoot"):
        monkeypatch.setenv(variable, str(untrusted))
    monkeypatch.setattr(windows_commands, "_system_directory", lambda: system_dir)
    original = ["PowerShell.EXE", "-NoProfile", "-Command", "Get-Date"]
    assert windows_commands.windows_command(original) == [str(trusted), *original[1:]]
    assert original[0] == "PowerShell.EXE"


def test_missing_system_tool_does_not_fall_back_to_path(tmp_path, monkeypatch):
    monkeypatch.setattr(windows_commands, "_system_directory", lambda: tmp_path / "missing")
    monkeypatch.setenv("PATH", str(tmp_path))
    (tmp_path / "ping.exe").write_bytes(b"inert test file; never executed")
    with pytest.raises(FileNotFoundError):
        windows_commands.windows_command(["ping", "127.0.0.1"])


@pytest.mark.parametrize("name", ["cmd", "unknown", "../ping", r"C:\untrusted\ping.exe"])
def test_rejects_shell_unknown_tools_and_explicit_paths(name):
    with pytest.raises(OSError, match="Unapproved"):
        windows_commands.windows_command([name])


def test_process_and_cleanup_use_absolute_system_tools():
    proc = MagicMock()
    proc.poll.return_value = 0
    proc.communicate.return_value = ("output", "")
    with patch.object(subprocess_runner.subprocess, "Popen", return_value=proc) as popen:
        result = subprocess_runner.run_subprocess_interruptible(["ping", "-n", "1", "127.0.0.1"], 5)
    assert result == ("output", "", 0)
    launched = Path(popen.call_args.args[0][0])
    assert launched.is_absolute() and launched.name.lower() == "ping.exe"
    proc.poll.side_effect = [None, 0]
    with patch.object(subprocess_runner.subprocess, "run") as run:
        run.return_value.returncode = 0
        subprocess_runner._terminate_process_tree(proc)
    assert Path(run.call_args.args[0][0]).is_absolute()
    assert Path(run.call_args.args[0][0]).name.lower() == "taskkill.exe"


def test_wifi_does_not_spawn_a_shell():
    with patch.object(wifi_diag, "run_subprocess_interruptible", return_value=("", "", 0)) as run:
        wifi_diag._run(["netsh", "wlan", "show", "interfaces"])
    run.assert_called_once_with(["netsh", "wlan", "show", "interfaces"], 15, encoding="oem")


def test_all_subprocess_launches_pass_through_trusted_resolution():
    """Prevent a new direct subprocess call from reintroducing PATH lookup."""
    source = Path(__file__).parents[1] / "src" / "losshound"
    for path in source.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if not isinstance(node.func.value, ast.Name) or node.func.value.id != "subprocess":
                continue
            if node.func.attr not in ("run", "Popen", "call", "check_call", "check_output"):
                continue
            command = node.args[0]
            assert (
                isinstance(command, ast.Call)
                and isinstance(command.func, ast.Name)
                and command.func.id == "windows_command"
            ), f"Unsafe command lookup: {path}:{node.lineno}"
            assert not any(
                kw.arg == "shell" and not (
                    isinstance(kw.value, ast.Constant) and kw.value.value is False
                ) for kw in node.keywords
            )
