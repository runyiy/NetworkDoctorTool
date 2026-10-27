"""Check pinned CI packages before installation; use only the Python stdlib.

Run with -I -S to avoid importing installed packages or executing .pth hooks.
OSV does not cover every bundled native library; explicit Qt checks supplement it.
This is a known-advisory/provenance gate, not a guarantee that software is benign.
"""

import argparse
import ast
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(text):
    pins = []
    seen = set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==(\d+(?:\.\d+)*(?:\.post\d+)?)", line)
        if not match:
            raise ValueError(f"Line {number}: expected an exact stable name==version pin")
        name, version = match.groups()
        if normalized(name) in seen:
            raise ValueError(f"Duplicate package: {name}")
        seen.add(normalized(name))
        pins.append((name, version))
    if not pins:
        raise ValueError("No dependency pins found")
    return pins


def fetch_json(url, body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(url, data=data, headers={
        "Content-Type": "application/json", "User-Agent": "Losshound-CI-dependency-check",
    })
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def validate_qt_xml_exclusion(spec_text, sources):
    """Conservative regression check; does not execute the spec or source."""
    analyses = [
        node for node in ast.walk(ast.parse(spec_text))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "Analysis"
    ]
    if len(analyses) != 1:
        raise ValueError("Expected one PyInstaller Analysis")
    excludes = next((kw.value for kw in analyses[0].keywords if kw.arg == "excludes"), None)
    if excludes is None or "PySide6.QtXml" not in ast.literal_eval(excludes):
        raise ValueError("The spec must explicitly exclude PySide6.QtXml")
    if not sources:
        raise ValueError("No source files checked for Qt XML use")
    for path, text in sources:
        if re.search(r"QtXml|QDom", text, re.IGNORECASE):
            raise ValueError(f"{path}: Qt XML/QDom reference requires a new applicability review")


def qt_advisories(name, version, *, qt_xml_excluded=False):
    if normalized(name) not in {"pyside6", "pyside6-essentials", "pyside6-addons"}:
        return []
    parts = version.split(".")
    value = tuple(int(part) for part in parts + ["0"] * max(0, 3 - len(parts)))
    issues = []
    # Only the reviewed 6.11.2 pins qualify; other advisories are untouched.
    if value < (6, 12, 0) and not (qt_xml_excluded and value == (6, 11, 2)):
        issues.append("CVE-2026-15037: Qt XML; vendor fix is Qt 6.12")
    if (6, 7, 0) <= value < (6, 8, 8) or (6, 9, 0) <= value < (6, 11, 1):
        issues.append("CVE-2026-6210: Qt SVG; vendor fix is Qt 6.8.8 / 6.11.1")
    if value < (6, 8, 8) or (6, 9, 0) <= value < (6, 11, 1):
        issues.append("CVE-2026-9499: Qt codec handling; vendor fix is Qt 6.8.8 / 6.11.1")
    return issues


def wheel_hashes(name, version, metadata, now):
    info = metadata["info"]
    if normalized(info["name"]) != normalized(name) or info["version"] != version:
        raise ValueError(f"{name}: PyPI identity/version mismatch")
    wheels = [item for item in metadata["urls"] if item["packagetype"] == "bdist_wheel"]
    if not wheels:
        raise ValueError(f"{name}: no published wheels; source builds are not permitted")
    hashes = set()
    for item in wheels:
        url = urlparse(item["url"])
        if url.scheme != "https" or url.hostname != "files.pythonhosted.org":
            raise ValueError(f"{name}: unexpected distribution host")
        if item["yanked"]:
            raise ValueError(f"{name}: release contains a yanked wheel")
        uploaded = datetime.fromisoformat(item["upload_time_iso_8601"].replace("Z", "+00:00"))
        if now - uploaded < timedelta(days=14):
            raise ValueError(f"{name}: wheel is less than 14 days old; review before adopting")
        digest = item["digests"]["sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{name}: invalid SHA-256 metadata")
        hashes.add(digest)
    return sorted(hashes)


def check(pins, fetch=fetch_json, now=None, *, qt_xml_excluded=False):
    now = now or datetime.now(timezone.utc)
    response = fetch("https://api.osv.dev/v1/querybatch", {"queries": [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in pins
    ]})
    results = response["results"]
    if len(results) != len(pins):
        raise ValueError("Incomplete OSV response")
    errors, lock = [], []
    for (name, version), result in zip(pins, results):
        if "error" in result or result.get("next_page_token"):
            raise ValueError(f"{name}: incomplete OSV result")
        issues = [item["id"] for item in result.get("vulns", [])]
        issues.extend(qt_advisories(name, version, qt_xml_excluded=qt_xml_excluded))
        errors.extend(f"{name}=={version}: {issue}" for issue in issues)
        metadata = fetch(f"https://pypi.org/pypi/{quote(name)}/{quote(version)}/json")
        errors.extend(f"{name}=={version}: {item['id']}" for item in metadata.get("vulnerabilities", []))
        hashes = wheel_hashes(name, version, metadata, now)
        lock.append(f"{name}=={version} " + " ".join(f"--hash=sha256:{digest}" for digest in hashes))
    return errors, "\n".join(lock) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("requirements", type=Path)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument(
        "--losshound-qt-xml-exclusion", action="store_true",
        help="Apply the documented 6.11.2 Qt XML assessment after checking this checkout",
    )
    args = parser.parse_args()
    try:
        if args.losshound_qt_xml_exclusion:
            root = Path(__file__).resolve().parents[1]
            sources = [
                (str(path.relative_to(root)), path.read_text(encoding="utf-8"))
                for folder in ("src", "tests") for path in (root / folder).rglob("*.py")
            ]
            validate_qt_xml_exclusion(
                (root / "Losshound.spec").read_text(encoding="utf-8"), sources,
            )
            print("CVE-2026-15037: scoped Qt 6.11.2 exclusion; source/spec checked. "
                  "The built EXE must also pass the Qt XML absence check.")
        errors, lock = check(
            read_pins(args.requirements.read_text(encoding="utf-8")),
            qt_xml_excluded=args.losshound_qt_xml_exclusion,
        )
        if errors:
            print("Dependency check BLOCKED; nothing may be installed or launched:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        args.lock.parent.mkdir(parents=True, exist_ok=True)
        args.lock.write_text(lock, encoding="utf-8")
        print(f"Dependency checks passed; wheel hashes recorded in {args.lock}")
        return 0
    except Exception as exc:
        print(f"Dependency check failed closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
