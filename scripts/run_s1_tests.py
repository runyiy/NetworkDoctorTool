"""Reproducible stdlib-only S1 validation; no pytest, Qt app, or live probes.

Run with native Windows Python 3.12+: -I -S -B scripts/run_s1_tests.py
--mode all --log build/s1-evidence/tests.log --json build/s1-evidence/tests.json.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
DETERMINISTIC = (
    "test_session_s1", "test_session_process_s1", "test_s1_entrypoints",
    "test_s1_gui", "test_s1_read_only_policy", "test_session_context_s1.ObserverProtocolTests",
    "test_session_output_s1.OutputContractTests",
)
NATIVE_OUTPUT = ("test_session_output_s1.NativeOutputLifecycleTests",)
NATIVE_CONTEXT = ("test_session_context_s1.NativeObserverLifecycleTests",)


class Tee:
    def __init__(self, console, logfile):
        self.console, self.logfile = console, logfile

    def write(self, text):
        for stream in (self.console, self.logfile):
            stream.write(text)
            stream.flush()
        return len(text)

    def flush(self):
        self.console.flush()
        self.logfile.flush()


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed_ids = []

    def addSuccess(self, test):
        self.passed_ids.append(test.id())
        super().addSuccess(test)


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def source_manifest():
    """Hash repository source, reviewed tests, scripts and dependency/instruction files."""
    paths = set()
    for name in ("src", "tests", "scripts"):
        paths.update(path for path in (ROOT / name).rglob("*")
                     if path.is_file() and not path.is_symlink()
                     and "__pycache__" not in path.parts and path.suffix != ".pyc")
    for pattern in ("requirements*.txt", "requirements*.in", "*.spec", "pyproject.toml",
                    "setup.py", "setup.cfg", "agents.md", "AGENTS.md",
                    "config.default.json", "run_as_admin.bat"):
        paths.update(path for path in ROOT.glob(pattern) if path.is_file() and not path.is_symlink())
    files = {}
    for path in sorted(paths):
        contents = path.read_bytes()
        files[path.relative_to(ROOT).as_posix()] = {
            "sha256": hashlib.sha256(contents).hexdigest(), "size_bytes": len(contents),
        }
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"sha256": digest, "files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("all", "deterministic", "native-output", "native-context"), default="all")
    parser.add_argument("--log", type=Path, required=True, help="UTF-8 command, environment, test IDs, and unittest log")
    parser.add_argument("--json", type=Path, help="Structured results; defaults to the log path with .json suffix")
    args = parser.parse_args()
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        parser.error("Run with Python -I -S -B; isolated stdlib validation is required")
    if args.mode != "deterministic" and (sys.platform != "win32" or sys.version_info < (3, 12)):
        parser.error("Native output validation requires native Windows Python 3.12+; no WSL substitute")
    log_path = args.log.resolve()
    json_path = (args.json or args.log.with_suffix(".json")).resolve()
    if log_path == json_path:
        parser.error("--log and --json must be different paths")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT / "tests"))
    state = {"group": "deterministic", "blocked": [], "allowed_output_launches": [], "allowed_context_launches": []}
    allowed_workers = {"native-output": str((ROOT / "src/losshound/core/session_output.py").resolve()),
                       "native-context": str((ROOT / "src/losshound/core/session_context.py").resolve())}
    allowed_executable = str(Path(sys.executable).resolve())

    def audit_guard(event, values):
        reason = None
        if event.startswith("socket.") or event == "os.system" or event.startswith("os.exec") or event.startswith("os.spawn"):
            reason = "network or shell activity is outside the reviewed S1 tests"
        elif event == "subprocess.Popen":
            executable, argv = values[0], values[1]
            expected = [allowed_executable, "-I", "-S", "-B", allowed_workers.get(state["group"]), "--worker"]
            argv_matches = (argv == subprocess.list2cmdline(expected) if isinstance(argv, str) else list(argv) == expected) if state["group"] in allowed_workers else False
            if argv_matches and (executable is None or str(executable) == allowed_executable):
                key = "allowed_output_launches" if state["group"] == "native-output" else "allowed_context_launches"
                state[key].append(expected)
            else:
                reason = "only the exact isolated worker for the selected native group is permitted"
        if reason:
            state["blocked"].append({"group": state["group"], "event": event, "reason": reason})
            raise AssertionError("S1 audit guard: " + event + ": " + reason)

    sys.addaudithook(audit_guard)
    argv = list(getattr(sys, "orig_argv", [sys.executable, *sys.argv]))
    command = "& '" + argv[0].replace("'", "''") + "' " + " ".join("'" + item.replace("'", "''") + "'" for item in argv[1:])
    metadata = {
        "schema_version": 1,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "command_powershell": command, "argv": argv,
        "cwd": str(Path.cwd()), "repository": str(ROOT),
        "python_executable": sys.executable, "python_version": sys.version,
        "platform": sys.platform, "windows_version": str(sys.getwindowsversion()) if sys.platform == "win32" else None,
        "flags": {"isolated": sys.flags.isolated, "no_site": sys.flags.no_site, "dont_write_bytecode": sys.dont_write_bytecode},
        "mode": args.mode, "groups": [],
        "source_manifest_start": source_manifest(),
    }
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8", newline="\n") as logfile:
        stream = Tee(sys.stdout, logfile)
        stream.write("S1 reviewed stdlib validation\n" + json.dumps({k: v for k, v in metadata.items() if k != "groups"}, indent=2) + "\n")
        groups = []
        if args.mode in ("all", "deterministic"):
            groups.append(("deterministic", DETERMINISTIC))
        if args.mode in ("all", "native-output"):
            groups.append(("native-output", NATIVE_OUTPUT))
        if args.mode in ("all", "native-context"):
            groups.append(("native-context", NATIVE_CONTEXT))
        for name, selectors in groups:
            state["group"] = name
            suite = unittest.TestLoader().loadTestsFromNames(selectors)
            selected_ids = list(test_ids(suite))
            stream.write("\nGROUP " + name + "\nSELECTORS " + json.dumps(selectors) + "\nSELECTED_TEST_IDS\n" + "\n".join(selected_ids) + "\n")
            group_started = time.monotonic()
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordedResult).run(suite)
            record = {
                "name": name, "selectors": list(selectors), "selected_ids": selected_ids,
                "passed_ids": result.passed_ids, "tests_run": result.testsRun,
                "failures": [{"id": test.id(), "traceback": detail} for test, detail in result.failures],
                "errors": [{"id": test.id(), "traceback": detail} for test, detail in result.errors],
                "skipped": [{"id": test.id(), "reason": reason} for test, reason in result.skipped],
                "expected_failures": [{"id": test.id(), "traceback": detail} for test, detail in result.expectedFailures],
                "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
                "duration_seconds": time.monotonic() - group_started,
                "successful": result.wasSuccessful(),
            }
            metadata["groups"].append(record)
        metadata["source_manifest_end"] = source_manifest()
        before = metadata["source_manifest_start"]["files"]
        after = metadata["source_manifest_end"]["files"]
        metadata["source_files_changed"] = sorted(name for name in before.keys() | after.keys()
                                                   if before.get(name) != after.get(name))
        metadata["audit_guard"] = state
        metadata["duration_seconds"] = time.monotonic() - started
        metadata["finished_utc"] = datetime.now(timezone.utc).isoformat()
        metadata["tests_run"] = sum(group["tests_run"] for group in metadata["groups"])
        metadata["failure_count"] = sum(len(group["failures"]) for group in metadata["groups"])
        metadata["error_count"] = sum(len(group["errors"]) for group in metadata["groups"])
        metadata["skipped_count"] = sum(len(group["skipped"]) for group in metadata["groups"])
        metadata["exit_code"] = int(bool(state["blocked"]) or bool(metadata["source_files_changed"]) or not all(group["successful"] for group in metadata["groups"]))
        stream.write("\nS1_RESULT " + json.dumps({key: metadata[key] for key in ("tests_run", "failure_count", "error_count", "skipped_count", "exit_code", "duration_seconds")}) + "\n")
        stream.write("AUDIT " + json.dumps(state) + "\n")
        stream.write("SOURCE_MANIFEST_END " + json.dumps(metadata["source_manifest_end"]) + "\n")
        stream.write("SOURCE_FILES_CHANGED " + json.dumps(metadata["source_files_changed"]) + "\n")
    json_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return metadata["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
