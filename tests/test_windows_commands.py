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


_OWNED_WORKERS = {
    ("core/session_context.py", "WindowsContextObserver", "start"): "--s1-context-worker",
    ("core/session_process.py", "WindowsProbeProvider", "_run"): "--s1-probe-worker",
    ("core/session_output.py", "BoundedSessionOutput", "start"): "--s1-output-worker",
}


def _assert_launch_origin(tree, relative_path, node):
    # Check shell policy before considering either narrowly reviewed origin.
    assert not any(kw.arg == "shell" and not (
        isinstance(kw.value, ast.Constant) and kw.value.value is False)
        for kw in node.keywords)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    owner, function, current = None, None, parents.get(node)
    owner_node = function_node = None
    while current is not None:
        if function is None and isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function, function_node = current.name, current
        if owner is None and isinstance(current, ast.ClassDef):
            owner, owner_node = current.name, current
        current = parents.get(current)
    assert node.args, "A reviewed positional command is required"
    command = node.args[0]
    if isinstance(command, ast.Call) and isinstance(command.func, ast.Name) and command.func.id == "windows_command":
        return "system"
    site = (relative_path, owner, function)
    if site in _OWNED_WORKERS:
        assert parents.get(function_node) is owner_node and parents.get(owner_node) is tree
        assert node.func.attr == "Popen"
        assert isinstance(command, ast.Call) and not command.args and not command.keywords
        assert isinstance(command.func, ast.Attribute) and command.func.attr == "_command"
        assert isinstance(command.func.value, ast.Name) and command.func.value.id == "self"
        assert any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                   and kw.value.value is False for kw in node.keywords)
        return site
    assert site == ("core/session_process.py", None, "_network") and node.func.attr == "run"
    assert isinstance(command, ast.Name) and command.id == "args"
    network = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_network")
    block = network.body[1]
    assert isinstance(block, ast.Try) and block.body[3].value is node
    expected = ast.parse("command = _trusted_imports()\nargs = command(['powershell', '-NoProfile', '-NonInteractive', '-Command', _NETWORK_SCRIPT])\nstage = 'network_query'")
    assert [ast.dump(item) for item in block.body[:3]] == [ast.dump(item) for item in expected.body]
    helper = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_trusted_imports")
    trusted = ast.parse("from losshound.core.windows_commands import windows_command\nreturn windows_command")
    assert [ast.dump(item) for item in helper.body[-2:]] == [ast.dump(item) for item in trusted.body]
    return "network"


def test_all_subprocess_launches_pass_through_trusted_resolution():
    """Check system resolution and exact owned-worker sites without file exemptions."""
    source = Path(__file__).parents[1] / "src" / "losshound"
    seen = []
    for path in source.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
                    and node.func.attr in ("run", "Popen", "call", "check_call", "check_output")):
                seen.append(_assert_launch_origin(tree, path.relative_to(source).as_posix(), node))
    assert all(seen.count(site) == 1 for site in _OWNED_WORKERS)
    assert seen.count("network") == 1


def _assert_worker_command(command, module, dispatch, frozen):
    assert Path(command[0]).is_absolute()
    assert Path(command[0]).resolve(strict=True) == Path(module.sys.executable).resolve(strict=True)
    assert command[1:] == ([dispatch] if frozen else [
        "-I", "-S", "-B", str(Path(module.__file__).resolve()), "--worker"])


@pytest.mark.parametrize("name,owner,dispatch", [
    ("session_context", "WindowsContextObserver", "--s1-context-worker"),
    ("session_process", "WindowsProbeProvider", "--s1-probe-worker"),
    ("session_output", "BoundedSessionOutput", "--s1-output-worker"),
])
def test_owned_worker_commands_are_absolute_and_exact(name, owner, dispatch):
    import importlib
    module = importlib.import_module("losshound.core." + name)
    for frozen in (False, True):
        with patch.object(module.sys, "frozen", frozen, create=True):
            command = getattr(module, owner)._command()
        _assert_worker_command(command, module, dispatch, frozen)
        with pytest.raises(AssertionError):
            _assert_worker_command([command[0], "--arbitrary-dispatch"], module, dispatch, frozen)


@pytest.mark.parametrize("source", [
    "class Unknown:\n def start(self):\n  subprocess.Popen(self._command(), shell=False)",
    "class WindowsContextObserver:\n def another(self):\n  subprocess.Popen(self._command(), shell=False)",
    "class WindowsContextObserver:\n def start(self):\n  def start(self):\n   subprocess.Popen(self._command(), shell=False)",
    "subprocess.run(windows_command(['ping']), shell=True)",
])
def test_unreviewed_command_or_shell_is_rejected(source):
    tree = ast.parse(source)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and node.func.attr in {"run", "Popen"})
    with pytest.raises(AssertionError):
        _assert_launch_origin(tree, "core/session_context.py", call)


def test_network_command_binding_cannot_be_replaced_with_an_untrusted_alias():
    path = Path(__file__).parents[1] / "src/losshound/core/session_process.py"
    source = path.read_text(encoding="utf-8")
    for original, replacement in (("command = _trusted_imports()", "command = unsafe_command"),
                                  ("args = command([", "args = list([")):
        assert source.count(original) == 1
        tree = ast.parse(source.replace(original, replacement))
        call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "run"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess")
        with pytest.raises(AssertionError):
            _assert_launch_origin(tree, "core/session_process.py", call)
