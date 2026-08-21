import shutil
import subprocess
import tempfile
from pathlib import Path


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
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "未找到项目虚拟环境中的" in output
    assert "Python" in output
