"""Synthetic bilingual UI contracts; no network, real Qt or repair commands."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import tempfile
import types
import unittest
from unittest.mock import patch

from losshound.core.session_diagnosis import DIAGNOSIS_MESSAGE_IDS
from losshound.core.session_summary import SUMMARY_MESSAGE_IDS, build_user_summary
from losshound.gui import i18n
import test_gui_integration as fixtures
from test_gui_integration import _baseline, _config
from test_s1_gui import _gui_modules
from test_user_summary import user_report_scenario


class TranslationContracts(unittest.TestCase):
    def test_catalog_covers_all_structured_messages_in_both_languages(self):
        for key in DIAGNOSIS_MESSAGE_IDS | SUMMARY_MESSAGE_IDS:
            with self.subTest(message_id=key):
                self.assertTrue(i18n.has_message(key), key)
        for key, pair in i18n.MESSAGES.items():
            with self.subTest(message_id=key):
                self.assertEqual(len(pair), 2)
                self.assertTrue(all(type(value) is str and value for value in pair))
                self.assertEqual(set(re.findall(r"\{([^{}]+)\}", pair[0])),
                                 set(re.findall(r"\{([^{}]+)\}", pair[1])))
                self.assertIsNone(re.search(r"[\u3400-\u9fff]", pair[1]))

    def test_local_configuration_wording_does_not_require_repeated_snapshots(self):
        chinese = i18n.translate("zh-CN", "diagnosis.local_configuration")
        english = i18n.translate("en", "diagnosis.local_configuration")
        self.assertIn("未同时记录该地址族可用地址与默认路由", chinese)
        self.assertIn("both a usable address and a default route for this address family", english)
        self.assertIn("可能", chinese)
        self.assertIn("possible", english)
        self.assertIn("不代表另一地址族或全网故障", chinese)
        self.assertIn("does not establish a fault in the other family or the whole network", english)
        self.assertNotIn("外部探测", chinese)
        self.assertNotIn("external probes", english)
        self.assertNotIn("重复", chinese)
        self.assertNotIn("repeated", english.lower())

    def test_unknown_messages_and_parameters_do_not_echo_private_strings(self):
        private = "untrusted-private-machine-name"
        for language in i18n.LANGUAGES:
            self.assertNotIn(private, i18n.translate(language, private))
            self.assertNotIn(private, i18n.translate(language, "detail.session"))

    def test_default_chinese_and_only_language_preference_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "config.json"
            original = '{"unchanged":"synthetic-existing-user-configuration"}'
            existing.write_text(original, encoding="utf-8")
            with patch.object(i18n, "_app_data_dir", return_value=root):
                self.assertEqual(i18n.load_language_preference(), "zh-CN")
                self.assertTrue(i18n.save_language_preference("en"))
                self.assertEqual(i18n.load_language_preference(), "en")
                value = json.loads((root / "ui-language.json").read_text(encoding="utf-8"))
                self.assertEqual(value, {"schema_version": 1, "language": "en"})
                self.assertEqual(existing.read_text(encoding="utf-8"), original)
                self.assertEqual(list(root.glob(".ui-language-*")), [])

    def test_invalid_or_oversized_preference_falls_back_without_executing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(i18n, "_app_data_dir", return_value=root):
                for value in ("not-json", '{"schema_version":1,"language":"private-value"}',
                              '{"schema_version":2,"language":"en"}', " " * 2049):
                    (root / "ui-language.json").write_text(value, encoding="utf-8")
                    self.assertEqual(i18n.load_language_preference(), "zh-CN")
                with self.assertRaises(ValueError):
                    i18n.save_language_preference("fr")

    def test_failed_atomic_preference_save_retains_previous_value_and_removes_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(i18n, "_app_data_dir", return_value=root):
                self.assertTrue(i18n.save_language_preference("en"))
                before = (root / "ui-language.json").read_bytes()
                with patch.object(i18n.os, "replace", side_effect=PermissionError):
                    self.assertFalse(i18n.save_language_preference("zh-CN"))
                self.assertEqual((root / "ui-language.json").read_bytes(), before)
                self.assertEqual(list(root.glob(".ui-language-*")), [])

    def test_qt_standard_buttons_use_only_fixed_local_catalog(self):
        app = types.SimpleNamespace(installed=[])
        app.installTranslator = app.installed.append
        class Translator:
            def __init__(self, _parent): pass
        core = types.ModuleType("PySide6.QtCore")
        core.QTranslator = Translator
        core.QCoreApplication = types.SimpleNamespace(instance=lambda: app)
        with patch.dict("sys.modules", {"PySide6.QtCore": core}):
            i18n.install_standard_button_translator("zh-CN")
            translator = app.installed[0]
            self.assertEqual(translator.translate("QMessageBox", "&Yes"), "是(&Y)")
            self.assertEqual(translator.translate("QPlatformTheme", "&Yes"), "是(&Y)")
            self.assertEqual(translator.translate("QPlatformTheme", "&No"), "否(&N)")
            self.assertEqual(translator.translate("OtherContext", "&Yes"), "&Yes")
            self.assertEqual(translator.translate("QPlatformTheme", "Synthetic untouched"), "Synthetic untouched")
            self.assertEqual(translator.translate("OtherContext", "Synthetic untouched"), "Synthetic untouched")
            i18n.install_standard_button_translator("en")
            self.assertEqual(len(app.installed), 1)
            self.assertEqual(translator.translate("QMessageBox", "&Yes"), "&Yes")


class NativeStandardButtonContracts(unittest.TestCase):
    def test_real_qt_message_box_labels_are_nonempty_and_default_no(self):
        # A real widget exercises QPlatformTheme, unlike direct Core translate calls.
        # Keep this subprocess-only: no visible window or interaction is required.
        import importlib.util
        import os
        import subprocess
        import sys
        if importlib.util.find_spec("PySide6") is None:
            self.skipTest("Reviewed real Qt runtime is not installed in this environment")
        source = str(Path(__file__).resolve().parents[1] / "src")
        program = """
import json,sys
sys.path.insert(0, sys.argv[1])
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication,QMessageBox
from losshound.gui.i18n import install_standard_button_translator
app=QApplication([])
results={}
for language in ('zh-CN','en'):
    install_standard_button_translator(language)
    box=QMessageBox(QMessageBox.Icon.Question,'Synthetic title','Synthetic text',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
    box.setDefaultButton(QMessageBox.StandardButton.No)
    results[language]=[box.button(QMessageBox.StandardButton.Yes).text(),box.button(QMessageBox.StandardButton.No).text(),box.defaultButton()==box.button(QMessageBox.StandardButton.No)]
    assert QCoreApplication.translate('OtherContext','Synthetic untouched')=='Synthetic untouched'
    assert QCoreApplication.translate('QPlatformTheme','Synthetic untouched')=='Synthetic untouched'
    box.deleteLater()
print(json.dumps(results,ensure_ascii=False))
"""
        with tempfile.TemporaryDirectory(prefix="qt-buttons-") as directory:
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("COVERAGE_", "PYTHON", "QT_", "QML"))}
            for key in ("LOCALAPPDATA", "TEMP", "TMP", "MPLCONFIGDIR"):
                destination = Path(directory) / key.lower()
                destination.mkdir()
                environment[key] = str(destination)
            environment["QT_QPA_PLATFORM"] = "offscreen"
            result = subprocess.run([sys.executable, "-X", "utf8", "-I", "-B", "-c", program, source],
                                    env=environment, capture_output=True, text=True,
                                    encoding="utf-8", timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print("Qt standard buttons:", result.stdout.strip())
        self.assertEqual(json.loads(result.stdout), {
            "zh-CN": ["是(&Y)", "否(&N)", True],
            "en": ["&Yes", "&No", True],
        })


class BilingualPanelContracts(unittest.TestCase):
    def load_baseline(self, panel_module, panel=None):
        # Reuse the existing synthetic product/GUI boundary fixture.
        return fixtures.SessionPanelIntegrationContracts().load_baseline(panel_module, panel)

    def test_first_window_is_chinese_and_idle_with_details_folded(self):
        with _gui_modules(real_core=True, language="zh-CN") as (_worker, panel_module, window_module):
            window = window_module.MainWindow(_config())
            panel = window._session
            self.assertEqual(panel.language, "zh-CN")
            self.assertEqual(panel._start_btn.text(), "开始诊断")
            self.assertIn("网络诊断", window._window_title)
            self.assertEqual(window._header._subtitle.text(), "网络诊断")
            self.assertIsNone(panel._worker)
            self.assertFalse(panel._display_timer.active)
            self.assertTrue(panel._preview.hidden)
            self.assertFalse(panel._details_btn.isChecked())
            self.assertFalse(panel._real_repair_btn.isEnabled())
            self.assertEqual(panel._real_repair_btn.clicked.callbacks, [])

    def test_active_switch_keeps_worker_clock_request_cancel_and_progress(self):
        with _gui_modules(real_core=True, language="zh-CN") as (_worker, panel_module, _window):
            panel = panel_module.SessionPanel(_config())
            panel.start_session()
            worker, request = panel._worker, panel._active_request
            started, cancel = worker.started_monotonic, worker.cancel_event
            panel._on_progress(types.SimpleNamespace(remaining_seconds=41.2, completed_count=7,
                                                    phase="tcp: private-target-label"))
            timer = panel._display_timer
            progress = panel._progress.value()
            panel._language_combo.setCurrentIndex(1)
            self.assertEqual(panel.language, "en")
            self.assertEqual(panel._start_btn.text(), "Start diagnosis")
            self.assertIn("7 items", panel._state.text())
            self.assertNotIn("private-target-label", panel._state.text())
            self.assertIn("42 seconds", panel._remaining.text())
            self.assertIs(panel._worker, worker)
            self.assertIs(panel._active_request, request)
            self.assertIs(worker.cancel_event, cancel)
            self.assertEqual(worker.started_monotonic, started)
            self.assertIs(panel._display_timer, timer)
            self.assertTrue(timer.active)
            self.assertEqual(panel._progress.value(), progress)
            self.assertFalse(panel._save_btn.isEnabled())
            panel.cancel_session()
            self.assertTrue(cancel.is_set())
            panel.set_language("zh-CN", persist=False)
            self.assertIn("正在取消", panel._state.text())
            self.assertFalse(panel._cancel_btn.isEnabled())

    def test_completed_switch_rerenders_without_changing_evidence_or_export(self):
        with _gui_modules(real_core=True, language="zh-CN") as (_worker, panel_module, _window):
            panel, report, old_worker = self.load_baseline(panel_module)
            original = copy.deepcopy(report.to_dict())
            self.assertIn("总体观察", panel._summary_preview.toPlainText())
            self.assertIsNone(re.search(r"\bE\d+\b", panel._summary_preview.toPlainText()))
            self.assertIn("E3", panel._preview.toPlainText())
            self.assertTrue(panel._preview.hidden)
            panel._details_btn.setChecked(True)
            self.assertFalse(panel._preview.hidden)
            with patch.object(panel_module.QFileDialog, "getSaveFileName", return_value=("memory-only.json", "JSON"), create=True), \
                 patch.object(Path, "write_text", return_value=1) as write:
                panel._save_report()
                chinese_export = write.call_args.args[0]
                panel.set_language("en", persist=False)
                panel._save_report()
                english_export = write.call_args.args[0]
            self.assertEqual(chinese_export, english_export)
            self.assertEqual(report.to_dict(), original)
            self.assertIs(panel._report, report)
            self.assertIsNone(panel._worker)
            self.assertTrue(old_worker.deleted)
            self.assertFalse(panel._preview.hidden)
            self.assertTrue(panel._details_btn.isChecked())
            self.assertIn("Overall observation", panel._summary_preview.toPlainText())
            self.assertIn("Session deadline", panel._state.text())
            self.assertIsNone(re.search(r"[\u3400-\u9fff]", panel._preview.toPlainText()))
            for private in ("private.example", "Private SSID", "raw-network-identity", "token=secret"):
                self.assertNotIn(private, panel._summary_preview.toPlainText())
                self.assertNotIn(private, panel._preview.toPlainText())

    def test_simulation_confirmation_and_completed_record_survive_switch(self):
        with _gui_modules(real_core=True, language="zh-CN") as (_worker, panel_module, _window):
            panel, report, _old_worker = self.load_baseline(panel_module)
            with patch.object(panel_module.QMessageBox, "question", return_value=panel_module.QMessageBox.StandardButton.Yes) as question:
                panel.simulate_repair()
            disclosure = question.call_args.args[2]
            self.assertIn("仅模拟", disclosure)
            self.assertIn("不能原样恢复", disclosure)
            self.assertIn("须另行点击", disclosure)
            controller, worker = panel._repair_controller, panel._worker
            before = copy.deepcopy(controller.record())
            started = worker.started_monotonic
            panel.set_language("en", persist=False)
            self.assertIs(panel._worker, worker)
            self.assertIs(panel._repair_controller, controller)
            self.assertEqual(controller.record(), before)
            self.assertEqual(worker.started_monotonic, started)
            worker.run()
            worker.active = False
            worker.finished.emit()
            record = copy.deepcopy(panel._repair_record)
            self.assertIn("SIMULATION ONLY", panel._repair_preview.toPlainText())
            self.assertIn("inconclusive", panel._repair_preview.toPlainText())
            panel.set_language("zh-CN", persist=False)
            self.assertIn("仅模拟", panel._repair_preview.toPlainText())
            self.assertIn("无法确定是否改善", panel._repair_preview.toPlainText())
            self.assertEqual(panel._repair_record, record)
            self.assertEqual(controller._executor.calls, 1)
            self.assertIs(record["execution"]["system_change_performed"], False)
            self.assertEqual(record["verification"]["status"], "pending")
            self.assertFalse(panel._real_repair_btn.isEnabled())

    def test_requested_report_summary_is_plain_and_keeps_family_observations(self):
        raw = user_report_scenario()
        original = copy.deepcopy(raw)
        model = build_user_summary(raw)
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            chinese = panel_module.format_user_summary(model, "zh-CN")
            english = panel_module.format_user_summary(model, "en")
        self.assertEqual(raw, original)
        self.assertEqual(chinese.count("本轮未检测网页访问，可填写具体网站后检测。"), 1)
        self.assertEqual(english.count("Website access was not tested in this session."), 1)
        self.assertIn("IPv4", chinese)
        self.assertIn("IPv6", chinese)
        self.assertIn("5 次有响应，1 次超时或失败", chinese)
        self.assertIn("3 次有响应", chinese)
        self.assertIn("DNS 解析: 2 次有响应", chinese)
        self.assertIn("不能宣称全网完全正常", chinese)
        self.assertNotIn("重置 IPv6", chinese)
        self.assertNotIn("DNS故障", chinese)
        self.assertIsNone(re.search(r"\bE\d+\b", chinese))
        self.assertIsNone(re.search(r"[\u3400-\u9fff]", english))
        self.assertLessEqual(len(model["next_steps"]), 3)
        for text in (chinese, english):
            self.assertNotIn("192.0.2.4", text)
            self.assertNotIn("2001:db8::4", text)
            self.assertNotIn("example.test", text)
    def test_positive_dns_keeps_tool_unmeasured_and_incomplete_coverage_visible(self):
        raw = user_report_scenario()
        source = next(row for row in raw["evidence"] if row["protocol"] == "dns")
        for outcome in ("execution_error", "not_attempted"):
            row = copy.deepcopy(source)
            row.update(sequence=max(item["sequence"] for item in raw["evidence"]) + 1,
                       outcome=outcome, comparable=False)
            raw["evidence"].append(row)
        model = build_user_summary(raw)
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            chinese = panel_module.format_user_summary(model, "zh-CN")
            english = panel_module.format_user_summary(model, "en")
        self.assertIn("DNS 解析: 2 次有响应", chinese)
        self.assertIn("1 项工具错误", chinese)
        self.assertIn("1 项未检测", chinese)
        self.assertIn("部分检查未完成，具体原因不可用。", chinese)
        self.assertIn("Coverage note: tool error", english)
        self.assertNotIn("DNS故障", chinese)
        self.assertNotIn("Synthetic opaque diagnostic detail", english)
        self.assertIsNone(re.search(r"[\u3400-\u9fff]", english))
    def test_language_save_failure_is_visible_and_does_not_affect_session(self):
        with _gui_modules(real_core=True, language="zh-CN") as (_worker, panel_module, _window):
            panel = panel_module.SessionPanel(_config())
            panel.start_session()
            worker = panel._worker
            with patch.object(panel_module, "save_language_preference", return_value=False):
                panel.set_language("en")
            self.assertFalse(panel._preference_note.hidden)
            self.assertIn("could not be saved", panel._preference_note.text())
            self.assertIs(panel._worker, worker)
            self.assertFalse(worker.cancel_event.is_set())

    def test_unknown_tool_error_text_is_not_exposed_in_either_language(self):
        with _gui_modules(real_core=True) as (_worker, panel_module, _window):
            panel = panel_module.SessionPanel(_config())
            for language in i18n.LANGUAGES:
                panel.set_language(language, persist=False)
                panel._on_error("private credential and local-path detail")
                self.assertNotIn("private credential", panel._state.text())
                self.assertIn("Exception", panel._state.text())


if __name__ == "__main__":
    unittest.main()
