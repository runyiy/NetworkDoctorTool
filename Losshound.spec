# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for a portable, single-file Losshound.exe.

Build:   pyinstaller Losshound.spec
Output:  dist/Losshound.exe   (no installer — copy it anywhere and run)

This produces a one-file, windowed (no console) executable. The app's data
(history, settings, logs) is written to %LOCALAPPDATA%\\Losshound at runtime,
never next to the exe — so the binary itself stays portable and deletable.
"""

import os
import sys
from pathlib import Path

# Developer-tool PATH entries can supply incompatible copies of Windows DLLs
# (for example Poppler's ICU instead of Windows ICU). Qt's package hooks add
# their own DLL directories; ambient tools must not participate in discovery.
trusted_binary_roots = [Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()]
if sys.platform == 'win32':
    windows_root = Path(os.environ['WINDIR']).resolve()
    trusted_binary_roots.append(windows_root / 'System32')
    os.environ['PATH'] = os.pathsep.join(map(str, [
        Path(sys.executable).parent, Path(sys.base_prefix),
        windows_root / 'System32', windows_root,
    ]))

a = Analysis(
    ['src/losshound/app.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        ('config.default.json', '.'),
        ('assets/losshound-logo.png', 'assets'),
        ('assets/panel-texture.png', 'assets'),
        ('assets/header-halo.png', 'assets'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Unused QDom implementation: CVE-2026-15037 (see docs/CI_SECURITY.md).
    excludes=['tkinter', 'PySide6.QtXml'],
    noarchive=False,
    optimize=0,
)

# Fail if a hook or native dependency reintroduces the excluded component.
# Do not silently remove a DLL another component requires.
for entry in a.binaries + a.datas + a.pure:
    if any(marker in entry[0].lower() for marker in ('qtxml', 'qt6xml')):
        raise RuntimeError(f'Qt XML must not be bundled: {entry[0]}')

# Refuse unreviewed native libraries even if a hook adds another search path.
for name, source, _kind in a.binaries:
    resolved_source = Path(source).resolve()
    if not any(resolved_source.is_relative_to(root) for root in trusted_binary_roots):
        raise RuntimeError(f'Native library outside approved Python/Windows roots: {name}: {source}')

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Losshound',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/losshound.ico',
    version='scripts/version_info.txt',
)
