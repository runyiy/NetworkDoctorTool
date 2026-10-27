"""Resolve the app's Windows tools without searching CWD or PATH."""

from __future__ import annotations

import ctypes
from pathlib import Path
import sys


_TOOLS = {
    name: f"{name}.exe"
    for name in (
        "arp", "ipconfig", "netsh", "netstat", "nslookup", "ping",
        "taskkill", "tasklist", "tracert", "wevtutil",
    )
}
_TOOLS["powershell"] = "WindowsPowerShell/v1.0/powershell.exe"


def _system_directory() -> Path:
    if sys.platform != "win32":
        raise OSError("Windows system tools are only available on Windows")
    # Environment variables can be overridden by a launcher; ask Windows itself.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_directory = kernel32.GetSystemDirectoryW
    get_directory.argtypes = (ctypes.c_wchar_p, ctypes.c_uint)
    get_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if not length:
        raise ctypes.WinError(ctypes.get_last_error())
    if length >= len(buffer):
        raise OSError("Windows system directory path exceeds buffer size")
    directory = Path(buffer.value)
    if not directory.is_absolute():
        raise OSError("Windows returned a non-absolute system directory")
    return directory.resolve(strict=True)


def windows_command(args: list[str]) -> list[str]:
    """Return a new argument list with an approved absolute executable path.

    Missing/unknown tools fail closed: never fall back to a searched executable.
    Arguments remain separate, so subprocess does not invoke a command shell.
    """
    if not args:
        raise OSError("A Windows tool name is required")
    name = args[0].lower().removesuffix(".exe")
    relative = _TOOLS.get(name)
    if relative is None:
        raise OSError("Unapproved Windows tool")
    system_dir = _system_directory()
    executable = (system_dir / relative).resolve(strict=True)
    if not executable.is_relative_to(system_dir) or not executable.is_file():
        raise OSError("Windows tool is outside the trusted system directory")
    return [str(executable), *args[1:]]
