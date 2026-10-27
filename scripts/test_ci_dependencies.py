"""Offline tests for the dependency gate; no application or third-party imports."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "ci_gate", Path(__file__).with_name("check_ci_dependencies.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)
METADATA = {
    "info": {"name": "demo", "version": "1.0"},
    "urls": [{
        "packagetype": "bdist_wheel",
        "url": "https://files.pythonhosted.org/packages/demo.whl",
        "yanked": False,
        "upload_time_iso_8601": "2026-07-01T00:00:00Z",
        "digests": {"sha256": "a" * 64},
    }],
}

class DependencyGateTests(unittest.TestCase):
    def test_exact_pins_only(self):
        self.assertEqual(gate.read_pins("# comment\ndemo==1.0\n"), [("demo", "1.0")])
        for invalid in ("demo>=1", "demo==1.0rc1", "--extra-index-url https://example.com", "", "demo==1\nDEMO==2"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                gate.read_pins(invalid)

    def test_qt_vendor_advisory_is_not_lost_when_osv_is_empty(self):
        metadata = deepcopy(METADATA)
        metadata["info"] = {"name": "PySide6", "version": "6.11.2"}
        def fetch(url, body=None):
            return {"results": [{}]} if body is not None else metadata
        errors, _ = gate.check([("PySide6", "6.11.2")], fetch, NOW)
        self.assertTrue(any("CVE-2026-15037" in error for error in errors))
        self.assertEqual(len(gate.qt_advisories("PySide6", "6.11.0")), 3)
        self.assertEqual(gate.qt_advisories("PySide6", "6.12"), [])
        self.assertEqual(gate.qt_advisories("unrelated", "1.0"), [])

    def test_osv_advisory_blocks(self):
        def fetch(url, body=None):
            return {"results": [{"vulns": [{"id": "GHSA-example"}]}]} if body else METADATA
        errors, _ = gate.check([("demo", "1.0")], fetch, NOW)
        self.assertEqual(errors, ["demo==1.0: GHSA-example"])

    def test_invalid_or_incomplete_osv_response_fails(self):
        for response in ({}, {"results": []}, {"results": [{"error": "unavailable"}]}, {"results": [{"next_page_token": "more"}]}):
            with self.subTest(response=response), self.assertRaises((KeyError, ValueError)):
                gate.check([("demo", "1.0")], lambda *args: response, NOW)

    def test_unavailable_service_fails(self):
        def fetch(*args):
            raise TimeoutError("service unavailable")
        with self.assertRaises(TimeoutError):
            gate.check([("demo", "1.0")], fetch, NOW)

    def test_distribution_metadata_rejections(self):
        for field, value in (
            ("yanked", True),
            ("upload_time_iso_8601", "2026-09-04T00:00:00Z"),
            ("url", "https://untrusted.example/demo.whl"),
            ("packagetype", "sdist"),
            ("digests", {"sha256": "invalid"}),
        ):
            metadata = deepcopy(METADATA)
            metadata["urls"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.wheel_hashes("demo", "1.0", metadata, NOW)

    def test_identity_mismatch_fails(self):
        with self.assertRaises(ValueError):
            gate.wheel_hashes("other", "1.0", METADATA, NOW)

    def test_pass_produces_hash_bound_lock(self):
        def fetch(url, body=None):
            return {"results": [{}]} if body else METADATA
        errors, lock = gate.check([("demo", "1.0")], fetch, NOW)
        self.assertEqual(errors, [])
        self.assertEqual(lock, "demo==1.0 --hash=sha256:" + "a" * 64 + "\n")

class QtXmlExclusionTests(unittest.TestCase):
    def test_only_reviewed_qt_version_gets_vendor_xml_exception(self):
        for name in ("PySide6", "PySide6_Essentials", "PySide6_Addons"):
            self.assertEqual(gate.qt_advisories(name, "6.11.2", qt_xml_excluded=True), [])
            for version in ("6.11.0", "6.11.1", "6.11.3"):
                self.assertTrue(any(
                    "CVE-2026-15037" in issue
                    for issue in gate.qt_advisories(name, version, qt_xml_excluded=True)
                ))
        self.assertEqual(len(gate.qt_advisories("PySide6", "6.11.0", qt_xml_excluded=True)), 3)

    def test_scoped_exception_does_not_hide_database_advisories(self):
        metadata = deepcopy(METADATA)
        metadata["info"] = {"name": "PySide6", "version": "6.11.2"}
        metadata["vulnerabilities"] = [{"id": "CVE-from-PyPI"}]
        def fetch(url, body=None):
            return {"results": [{"vulns": [{"id": "GHSA-from-OSV"}]}]} if body else metadata
        errors, _ = gate.check([("PySide6", "6.11.2")], fetch, NOW, qt_xml_excluded=True)
        self.assertEqual(errors, [
            "PySide6==6.11.2: GHSA-from-OSV", "PySide6==6.11.2: CVE-from-PyPI",
        ])
        metadata.pop("vulnerabilities")
        errors, _ = gate.check(
            [("PySide6", "6.11.2")],
            lambda url, body=None: {"results": [{}]} if body else metadata,
            NOW, qt_xml_excluded=True,
        )
        self.assertEqual(errors, [])

    def test_new_xml_usage_requires_review(self):
        spec_text = "a = Analysis([], excludes=['PySide6.QtXml'])"
        gate.validate_qt_xml_exclusion(
            spec_text, [("app.py", "from PySide6.QtWidgets import QApplication")]
        )
        for source in (
            "from PySide6 import QtXml",
            "from PySide6.QtXml import QDomDocument",
            'importlib.import_module("PySide6.QtXml")',
            'getattr(module, "QDomDocument")',
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                gate.validate_qt_xml_exclusion(spec_text, [("app.py", source)])
        with self.assertRaises(ValueError):
            gate.validate_qt_xml_exclusion(spec_text, [])

    def test_missing_or_dynamic_spec_exclusion_fails(self):
        for spec_text in (
            "", "a = Analysis([])", "a = Analysis([], excludes=['tkinter'])",
            "a = Analysis([], excludes=dynamic_excludes)",
            "a = Analysis([]); b = Analysis([])",
        ):
            with self.subTest(spec=spec_text), self.assertRaises(ValueError):
                gate.validate_qt_xml_exclusion(spec_text, [("app.py", "pass")])

    def run_spec(self, **entries):
        # Execute only our spec with inert builders: no PyInstaller/app imports.
        import os
        import sys
        from unittest.mock import patch
        from types import SimpleNamespace
        captured = {}
        def analysis(*args, **kwargs):
            captured.update(kwargs)
            captured["build_path"] = os.environ.get("PATH", "")
            return SimpleNamespace(
                binaries=entries.get("binaries", [("PySide6/Qt6Core.dll", str(Path(sys.prefix) / "core.dll"), "BINARY")]),
                datas=entries.get("datas", []), pure=entries.get("pure", []), scripts=[],
            )
        namespace = {"Analysis": analysis, "PYZ": lambda *args: None,
                     "EXE": lambda *args, **kwargs: captured.update(built=True)}
        spec_path = Path(__file__).resolve().parents[1] / "Losshound.spec"
        with patch.dict(os.environ):
            exec(compile(spec_path.read_text(encoding="utf-8"), str(spec_path), "exec"), namespace)
        return captured

    def test_actual_spec_builds_without_xml(self):
        captured = self.run_spec()
        self.assertTrue(captured["built"])
        self.assertIn("PySide6.QtXml", captured["excludes"])

    def test_actual_spec_rejects_reintroduced_module_or_native_dll(self):
        for collection, name in (
            ("binaries", "PySide6/Qt6Xml.dll"),
            ("binaries", "PySide6\\QtXml.pyd"),
            ("datas", "vendor/QT6XML.DLL"),
            ("pure", "PySide6.QtXml"),
        ):
            with self.subTest(collection=collection, name=name):
                with self.assertRaisesRegex(RuntimeError, "Qt XML must not be bundled"):
                    self.run_spec(**{collection: [(name, "unused", "BINARY")]})

    def test_actual_spec_rejects_external_native_library(self):
        with self.assertRaisesRegex(RuntimeError, "outside approved Python/Windows roots"):
            self.run_spec(binaries=[("icuuc.dll", str(Path(__file__).parent / "unexpected.dll"), "BINARY")])

    def test_actual_spec_excludes_ambient_tool_path_on_windows(self):
        import os
        import sys
        from unittest.mock import patch
        if sys.platform != "win32":
            self.skipTest("Windows DLL search policy")
        external = str(Path(__file__).parent / "unrelated-tools")
        with patch.dict(os.environ, {"PATH": external + os.pathsep + os.environ.get("PATH", "")}):
            captured = self.run_spec()
        self.assertNotIn(external, captured["build_path"].split(os.pathsep))


if __name__ == "__main__":
    unittest.main()
