import locale
import shutil
import subprocess
import tempfile
from pathlib import Path


def _decode_powershell_output(value: bytes) -> str:
    for encoding in ("utf-8", "cp936", locale.getpreferredencoding(False)):
        try:
            return value.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode("utf-8", errors="replace")


def test_powershell_output_decoder_preserves_cp936_chinese_error():
    message = "未找到项目虚拟环境中的 Python"

    assert _decode_powershell_output(message.encode("cp936")) == message


def test_build_script_reports_missing_virtual_environment_python():
    source_script = Path("build.ps1").resolve()
    scratch_root = Path("build").resolve()
    scratch_root.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="build-contract-", dir=scratch_root) as temp:
        isolated_root = Path(temp)
        isolated_script = isolated_root / "build.ps1"
        if source_script.exists():
            shutil.copy2(source_script, isolated_script)

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                isolated_script,
            ],
            cwd=isolated_root,
            capture_output=True,
            check=False,
        )

    assert result.returncode != 0
    output = _decode_powershell_output(result.stdout + result.stderr)
    assert "未找到项目虚拟环境中的" in output
    assert "Python" in output
