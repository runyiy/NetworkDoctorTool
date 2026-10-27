"""Check staged/indexed files for high-confidence privacy risks; no network access."""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

PRIVATE_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".cache", ".tox", ".nox",
    "build", "dist", "reports", "diagnostic-reports", "network-reports",
    "logs", "captures", "evidence", "backups", ".local", ".audit-local",
    ".migration-local",
}
PRIVATE_NAMES = {
    "config.json", "optimizer_backup.json", "benchmark_history.json",
    "load_benchmark_history.json", "s1_windows_evidence.json", "diagnostic-evidence.json",
    "id_rsa", "id_ed25519", "id_ecdsa",
}
PRIVATE_GLOBS = (
    ".env", ".env.*", "*.local.*", "credentials*.json", "secrets*.json",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "*.db", "*.db-*", "*.sqlite", "*.sqlite-*", "*.sqlite3", "*.sqlite3-*",
    "*.log", "*.pcap", "*.pcapng", "*.dmp", "*.etl", "*.evtx",
    "*.exe", "*.dll", "*.pdb", "*.msi", "*.msix", "*.whl",
    "*.zip", "*.7z", "*.tar", "*.tar.gz", "*.tgz", "*zone.identifier",
    "diagnostic-report*.json", "diagnostic_report*.json",
    "network-report*.json", "network_report*.json", "session-report*.json",
    "losshound_report_*.txt", "losshound_report_*.json", "losshound-isp-report-*.pdf",
)
STRONG = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("provider-token", re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{40,}|(?:AKIA|ASIA)[0-9A-Z]{16}|sk-(?:proj-)?[A-Za-z0-9_-]{24,}|xox[baprs]-[A-Za-z0-9-]{20,})")),
    ("user-home-path", re.compile(r"(?:[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[^\\/\s\"']+|/(?:home|Users)/[^/\s\"']+|\\\\wsl(?:\.localhost|\$)[\\/][^\"'\s]+)", re.I)),
)
URL = re.compile(r"https?://[^\s<>\"')]+", re.I)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.I)
ASSIGNMENT = re.compile(r"\b(?:password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)[\"']?\s*[:=]\s*[\"']([^\"'\r\n]+)[\"']", re.I)
PLACEHOLDERS = {"user", "username", "pass", "password", "secret", "token", "example", "test", "dummy", "redacted", "changeme", "<redacted>", "not-a-secret"}


def reserved_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == "localhost" or host == "example.com" or host.endswith((".example.com", ".test", ".invalid"))


def scan(path: str, data: bytes) -> list[tuple[str, int, str]]:
    parts = PurePosixPath(path).parts
    name = parts[-1].lower()
    issues = []
    if (any(p.lower() in PRIVATE_DIRS or p.lower().endswith("-evidence") for p in parts[:-1])
            or name in PRIVATE_NAMES or any(fnmatch.fnmatchcase(name, pat) for pat in PRIVATE_GLOBS)):
        issues.append((path, 0, "private-file"))
    text = data.decode("utf-8", errors="replace")
    for kind, pattern in STRONG:
        for match in pattern.finditer(text):
            issues.append((path, text.count("\n", 0, match.start()) + 1, kind))
    if name.endswith((".png", ".ico")):
        return sorted(set(issues))  # Full image metadata still needs manual review.
    for match in URL.finditer(text):
        try:
            url = urlsplit(match.group())
            if url.username is None and url.password is None:
                continue
            fixture = (path.startswith("tests/") and reserved_host(url.hostname or "")
                       and unquote(url.username or "").lower() in PLACEHOLDERS
                       and unquote(url.password or "").lower() in PLACEHOLDERS)
        except ValueError:
            fixture = False
        if not fixture:
            issues.append((path, text.count("\n", 0, match.start()) + 1, "credential-url"))
    for match in EMAIL.finditer(text):
        domain = match.group(1).lower()
        if not (reserved_host(domain) or domain == "users.noreply.github.com"):
            issues.append((path, text.count("\n", 0, match.start()) + 1, "contact-email"))
    for match in ASSIGNMENT.finditer(text):
        if match.group(1).lower() not in PLACEHOLDERS:
            issues.append((path, text.count("\n", 0, match.start()) + 1, "credential-literal"))
    return sorted(set(issues))


def git(*args: str) -> bytes:
    result = subprocess.run(["git", *args], capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("Git read failed")
    return result.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all-tracked", action="store_true", help="check all index blobs, not working-tree files")
    args = parser.parse_args(argv)
    try:
        entries = {}
        for item in git("ls-files", "--stage", "-z").split(b"\0"):
            if not item:
                continue
            meta, raw_path = item.split(b"\t", 1)
            mode, sha, stage = meta.split()
            if stage != b"0" or mode not in (b"100644", b"100755", b"120000"):
                raise RuntimeError("Unmerged or unsupported index entry")
            entries[raw_path.decode("utf-8")] = sha.decode("ascii")
        selected = set(entries) if args.all_tracked else {
            p.decode("utf-8") for p in git("diff", "--cached", "--name-only", "--diff-filter=ACM", "--no-renames", "-z").split(b"\0") if p
        }
        issues = []
        for path in sorted(selected):
            issues.extend(scan(path, git("cat-file", "blob", entries[path])))
    except (OSError, RuntimeError, ValueError, KeyError, UnicodeError):
        print("ERROR: index check incomplete; no safe result.")
        return 2
    for path, line, kind in issues:
        print(f"{json.dumps(path, ensure_ascii=True)}:{line}: {kind}")
    if issues:
        return 1
    print(f"PASS: checked {len(selected)} indexed files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
