"""QoS (Quality of Service) management tab — per-app network priority rules."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from losshound.gui.theme import button_style
from losshound.core.qos import (
    PRESET_DESCRIPTIONS, PRIORITY_PRESETS,
    QosResult, QosRule,
    apply_rule, build_lag_mitigation_rule, load_saved_rules,
    remove_all_losshound_policies, remove_rule, save_rules,
)

logger = logging.getLogger(__name__)


class _ApplyWorker(QThread):
    finished = Signal(object)  # QosResult

    def __init__(self, rule: QosRule):
        super().__init__()
        self._rule = rule

    def run(self):
        try:
            result = apply_rule(self._rule)
        except InterruptedError:
            return
        except Exception as exc:
            logger.exception("QoS apply failed")
            result = QosResult(
                rule_name=self._rule.name,
                success=False,
                action="failed",
                message=str(exc)[:200],
            )
        if not self.isInterruptionRequested():
            self.finished.emit(result)


class _RemoveWorker(QThread):
    finished = Signal(object)

    def __init__(self, rule_name: str):
        super().__init__()
        self._name = rule_name

    def run(self):
        try:
            result = remove_rule(self._name)
        except InterruptedError:
            return
        except Exception as exc:
            logger.exception("QoS remove failed")
            result = QosResult(
                rule_name=self._name,
                success=False,
                action="failed",
                message=str(exc)[:200],
            )
        if not self.isInterruptionRequested():
            self.finished.emit(result)


class _RemoveAllWorker(QThread):
    finished = Signal(object)

    def run(self):
        try:
            results = remove_all_losshound_policies()
        except InterruptedError:
            return
        except Exception as exc:
            logger.exception("QoS remove-all failed")
            results = [
                QosResult(
                    rule_name="all",
                    success=False,
                    action="failed",
                    message=str(exc)[:200],
                )
            ]
        if not self.isInterruptionRequested():
            self.finished.emit(results)


class QosTab(QWidget):
    rule_apply_finished = Signal(object)  # QosResult

    def shutdown(self):
        from losshound.gui._shutdown import stop_qthreads
        stop_qthreads(getattr(self, "_threads", []))

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rules: list[QosRule] = load_saved_rules()
        self._threads: list[QThread] = []
        self._verified_rules: set[str] = set()
        self._pending_deletes: dict[QThread, QosRule] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # Header
        header = QLabel("Per-App Network Priority (QoS)")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #d8dee9;")
        layout.addWidget(header)

        admin_note = QLabel(
            "Requires Administrator privileges. "
            "Rules use DSCP markings to prioritize traffic at the OS level."
        )
        admin_note.setStyleSheet("color: #788596; font-size: 11px;")
        admin_note.setWordWrap(True)
        layout.addWidget(admin_note)

        # Add rule row
        add_row = QHBoxLayout()

        self._app_input = QLineEdit()
        self._app_input.setPlaceholderText("App name or path (e.g. chrome.exe)")
        self._app_input.setMinimumWidth(200)
        add_row.addWidget(self._app_input)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_app)
        add_row.addWidget(browse_btn)

        self._priority_combo = QComboBox()
        for preset in PRIORITY_PRESETS:
            self._priority_combo.addItem(preset)
        self._priority_combo.setCurrentText("High")
        self._priority_combo.currentTextChanged.connect(self._update_desc)
        add_row.addWidget(self._priority_combo)

        add_btn = QPushButton("Add Rule")
        add_btn.setStyleSheet(button_style("success"))
        add_btn.clicked.connect(self._add_rule)
        add_row.addWidget(add_btn)

        layout.addLayout(add_row)

        # Preset description
        self._desc_label = QLabel("")
        self._desc_label.setStyleSheet("color: #788596; font-size: 11px; padding-left: 4px;")
        layout.addWidget(self._desc_label)
        self._update_desc(self._priority_combo.currentText())

        # Rules table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels([
            "Application", "Priority", "DSCP", "Status", "Actions",
        ])
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        for col in range(1, 5):
            self._table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)

        # Bottom buttons
        bottom = QHBoxLayout()

        apply_all_btn = QPushButton("Apply All Rules")
        apply_all_btn.setStyleSheet(button_style("primary"))
        apply_all_btn.clicked.connect(self._apply_all)
        bottom.addWidget(apply_all_btn)

        remove_all_btn = QPushButton("Remove All Policies")
        remove_all_btn.setStyleSheet(button_style("danger"))
        remove_all_btn.clicked.connect(self._remove_all)
        bottom.addWidget(remove_all_btn)

        bottom.addStretch()

        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #788596;")
        bottom.addWidget(self._status_label)

        layout.addLayout(bottom)

        # Populate table
        self._refresh_table()

    def _update_desc(self, preset: str):
        desc = PRESET_DESCRIPTIONS.get(preset, "")
        dscp = PRIORITY_PRESETS.get(preset, 0)
        self._desc_label.setText(f"DSCP {dscp} — {desc}")

    def _browse_app(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Application",
            "C:/Program Files",
            "Executables (*.exe);;All Files (*)",
        )
        if path:
            self._app_input.setText(path)

    def _add_rule(self):
        app_path = self._app_input.text().strip()
        if not app_path:
            self._status_label.setText("Enter an app name or browse for an .exe first")
            self._status_label.setStyleSheet("color: #d9b65f;")
            return

        preset = self._priority_combo.currentText()
        dscp = PRIORITY_PRESETS[preset]
        name = Path(app_path).stem if "\\" in app_path or "/" in app_path else app_path.replace(".exe", "")

        # Check for duplicate
        for r in self._rules:
            if r.name == name:
                self._status_label.setText(f"Rule for '{name}' already exists")
                return

        rule = QosRule(
            name=name,
            app_path=app_path,
            priority_preset=preset,
            dscp_value=dscp,
        )
        self._rules.append(rule)
        save_rules(self._rules)
        self._refresh_table()
        self._app_input.clear()
        self._status_label.setText(f"Added rule for {name}")

    def apply_lag_mitigation(self, app_name: str) -> QosRule:
        """Save and apply the automatic low-priority rule for a lag suspect."""
        rule = self._upsert_rule(build_lag_mitigation_rule(app_name))
        self._status_label.setText(f"Applying lag QoS rule for {rule.app_path}...")
        self._status_label.setStyleSheet("color: #d9b65f;")
        self._apply_single(rule)
        return rule

    def _upsert_rule(self, rule: QosRule) -> QosRule:
        lowered_app = rule.app_path.lower()
        for idx, existing in enumerate(self._rules):
            if existing.name == rule.name or existing.app_path.lower() == lowered_app:
                updated = QosRule(
                    name=existing.name,
                    app_path=existing.app_path,
                    priority_preset=rule.priority_preset,
                    dscp_value=rule.dscp_value,
                    active=True,
                    note=rule.note,
                )
                self._rules[idx] = updated
                save_rules(self._rules)
                self._refresh_table()
                return updated

        self._rules.append(rule)
        save_rules(self._rules)
        self._refresh_table()
        return rule

    def _refresh_table(self):
        self._table.setRowCount(0)
        for i, rule in enumerate(self._rules):
            row = self._table.rowCount()
            self._table.insertRow(row)

            self._table.setItem(row, 0, QTableWidgetItem(rule.app_path))
            self._table.setItem(row, 1, QTableWidgetItem(rule.priority_preset))
            self._table.setItem(row, 2, QTableWidgetItem(str(rule.dscp_value)))

            if not rule.active:
                status = "Disabled"
            elif rule.name in self._verified_rules:
                status = "Applied"
            else:
                status = "Ready to apply"
            status_item = QTableWidgetItem(status)
            self._table.setItem(row, 3, status_item)

            # Action buttons
            actions = QWidget()
            actions_layout = QHBoxLayout(actions)
            actions_layout.setContentsMargins(4, 2, 4, 2)

            apply_btn = QPushButton("Apply")
            apply_btn.setFixedWidth(60)
            apply_btn.clicked.connect(lambda checked, r=rule: self._apply_single(r))
            actions_layout.addWidget(apply_btn)

            del_btn = QPushButton("Delete")
            del_btn.setFixedWidth(60)
            del_btn.setStyleSheet("color: #e06363;")
            del_btn.clicked.connect(lambda checked, r=rule: self._delete_rule(r))
            actions_layout.addWidget(del_btn)

            self._table.setCellWidget(row, 4, actions)

    def _apply_single(self, rule: QosRule):
        self._status_label.setText(f"Applying {rule.name}...")
        worker = _ApplyWorker(rule)
        worker.finished.connect(self._on_apply_done)
        worker.start()
        self._threads.append(worker)

    def _on_apply_done(self, result: QosResult):
        worker = self.sender()
        if worker in self._threads:
            self._threads.remove(worker)

        if result.success:
            self._verified_rules.add(result.rule_name)
            self._status_label.setText(f"{result.rule_name}: {result.action}")
            self._status_label.setStyleSheet("color: #75c884;")
        else:
            self._verified_rules.discard(result.rule_name)
            self._status_label.setText(f"{result.rule_name}: {result.message[:60]}")
            self._status_label.setStyleSheet("color: #e06363;")
        self._refresh_table()
        self.rule_apply_finished.emit(result)

    def _delete_rule(self, rule: QosRule):
        if any(pending.name == rule.name for pending in self._pending_deletes.values()):
            return
        reply = QMessageBox.question(
            self,
            "Delete QoS rule",
            f"Remove the Windows policy and delete the saved rule '{rule.name}'?\n\n"
            "The saved rule will be kept if Windows cannot verify policy removal.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._status_label.setText(f"Removing Windows policy for {rule.name}...")
        self._status_label.setStyleSheet("color: #d9b65f;")

        worker = _RemoveWorker(rule.name)
        worker.finished.connect(self._on_delete_policy_done)
        self._pending_deletes[worker] = rule
        worker.start()
        self._threads.append(worker)

    def _on_delete_policy_done(self, result: QosResult):
        worker = self.sender()
        if worker in self._threads:
            self._threads.remove(worker)
        pending_rule = self._pending_deletes.pop(worker, None)
        name = pending_rule.name if pending_rule else result.rule_name

        if result.success:
            self._rules = [r for r in self._rules if r.name != name]
            self._verified_rules.discard(name)
            save_rules(self._rules)
            self._refresh_table()
            self._status_label.setText(f"Removed Windows policy: {name}")
            self._status_label.setStyleSheet("color: #75c884;")
        else:
            self._status_label.setText(
                f"Policy removal failed; saved rule kept: {result.message[:70]}"
            )
            self._status_label.setStyleSheet("color: #d9b65f;")

    def _apply_all(self):
        if not self._rules:
            self._status_label.setText("No rules to apply")
            return
        self._status_label.setText("Applying all rules...")
        for rule in self._rules:
            if rule.active:
                self._apply_single(rule)

    def _remove_all(self):
        reply = QMessageBox.question(
            self, "Remove All QoS Policies",
            "Remove all Losshound QoS policies from Windows?\n"
            "(Saved rules will be kept.)",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._status_label.setText("Removing Losshound QoS policies...")
        self._status_label.setStyleSheet("color: #d9b65f;")

        worker = _RemoveAllWorker()
        worker.finished.connect(self._on_remove_all_done)
        worker.start()
        self._threads.append(worker)

    def _on_remove_all_done(self, results: list[QosResult]):
        worker = self.sender()
        if worker in self._threads:
            self._threads.remove(worker)

        removed = sum(1 for r in results if r.success)
        if removed:
            self._verified_rules.clear()
            self._refresh_table()
        self._status_label.setText(f"Removed {removed} policies")
        self._status_label.setStyleSheet("color: #d9b65f;")
