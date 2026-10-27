from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox, QDoubleSpinBox, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton, QScrollArea,
    QSpinBox, QVBoxLayout, QWidget,
)

from losshound.core.config import AlertsConfig, AppConfig, DiagnosisConfig, save_config
from losshound.gui.theme import button_style


class SettingsTab(QWidget):
    config_changed = Signal(object)  # AppConfig

    def __init__(self, config: AppConfig, parent=None):
        super().__init__(parent)
        self._config = config

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        main_layout = QVBoxLayout(content)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # Targets group
        targets_group = QGroupBox("Targets")
        targets_form = QFormLayout(targets_group)

        self._public_targets = QLineEdit(", ".join(config.public_ping_targets))
        targets_form.addRow("Public ping targets:", self._public_targets)

        self._dns_hostnames = QLineEdit(", ".join(config.dns_test_hostnames))
        targets_form.addRow("DNS test hostnames:", self._dns_hostnames)

        self._tracert_target = QLineEdit(config.tracert_target)
        targets_form.addRow("Tracert target:", self._tracert_target)

        main_layout.addWidget(targets_group)

        # Intervals group
        intervals_group = QGroupBox("Intervals")
        intervals_form = QFormLayout(intervals_group)

        self._ping_interval = QSpinBox()
        self._ping_interval.setRange(5, 600)
        self._ping_interval.setValue(config.ping_interval_seconds)
        self._ping_interval.setSuffix(" sec")
        intervals_form.addRow("Ping interval:", self._ping_interval)

        self._dns_interval = QSpinBox()
        self._dns_interval.setRange(10, 600)
        self._dns_interval.setValue(config.dns_interval_seconds)
        self._dns_interval.setSuffix(" sec")
        intervals_form.addRow("DNS interval:", self._dns_interval)

        self._route_interval = QSpinBox()
        self._route_interval.setRange(60, 3600)
        self._route_interval.setValue(config.route_interval_seconds)
        self._route_interval.setSuffix(" sec")
        intervals_form.addRow("Route interval:", self._route_interval)

        self._ping_count = QSpinBox()
        self._ping_count.setRange(1, 20)
        self._ping_count.setValue(config.ping_count)
        intervals_form.addRow("Pings per check:", self._ping_count)

        self._ping_timeout = QSpinBox()
        self._ping_timeout.setRange(500, 10000)
        self._ping_timeout.setValue(config.ping_timeout_ms)
        self._ping_timeout.setSuffix(" ms")
        intervals_form.addRow("Ping timeout:", self._ping_timeout)

        self._retention = QSpinBox()
        self._retention.setRange(1, 168)
        self._retention.setValue(config.history_retention_hours)
        self._retention.setSuffix(" hours")
        intervals_form.addRow("History retention:", self._retention)

        main_layout.addWidget(intervals_group)

        # Diagnosis thresholds
        diag_group = QGroupBox("Diagnosis Thresholds")
        diag_form = QFormLayout(diag_group)

        dc = config.diagnosis

        self._gw_loss = QDoubleSpinBox()
        self._gw_loss.setRange(1, 100)
        self._gw_loss.setValue(dc.gateway_loss_threshold)
        self._gw_loss.setSuffix(" %")
        diag_form.addRow("Gateway loss threshold:", self._gw_loss)

        self._pub_loss = QDoubleSpinBox()
        self._pub_loss.setRange(1, 100)
        self._pub_loss.setValue(dc.public_loss_threshold)
        self._pub_loss.setSuffix(" %")
        diag_form.addRow("Public loss threshold:", self._pub_loss)

        self._dns_fail = QDoubleSpinBox()
        self._dns_fail.setRange(1.0, 100.0)
        self._dns_fail.setValue(dc.dns_failure_threshold * 100.0)
        self._dns_fail.setSingleStep(5.0)
        self._dns_fail.setSuffix(" %")
        self._dns_fail.setToolTip(
            "Warn when this percentage of DNS checks fail in the diagnosis window."
        )
        diag_form.addRow("DNS failure threshold:", self._dns_fail)

        self._latency_warn = QDoubleSpinBox()
        self._latency_warn.setRange(10, 5000)
        self._latency_warn.setValue(dc.latency_warning_ms)
        self._latency_warn.setSuffix(" ms")
        diag_form.addRow("Latency warning:", self._latency_warn)

        self._jitter_warn = QDoubleSpinBox()
        self._jitter_warn.setRange(1, 500)
        self._jitter_warn.setValue(dc.jitter_warning_ms)
        self._jitter_warn.setSuffix(" ms")
        diag_form.addRow("Jitter warning:", self._jitter_warn)

        self._route_sensitivity = QSpinBox()
        self._route_sensitivity.setRange(1, 50)
        self._route_sensitivity.setValue(dc.route_change_sensitivity)
        diag_form.addRow("Route change sensitivity:", self._route_sensitivity)

        self._min_obs = QSpinBox()
        self._min_obs.setRange(1, 20)
        self._min_obs.setValue(dc.min_observations)
        diag_form.addRow("Min observations:", self._min_obs)

        self._window = QSpinBox()
        self._window.setRange(1, 60)
        self._window.setValue(dc.window_minutes)
        self._window.setSuffix(" min")
        diag_form.addRow("Diagnosis window:", self._window)

        main_layout.addWidget(diag_group)

        # Alerts group
        alerts_group = QGroupBox("Alerts")
        alerts_form = QFormLayout(alerts_group)

        self._alerts_enabled = QCheckBox("Enable alerts")
        self._alerts_enabled.setChecked(config.alerts.enabled)
        alerts_form.addRow("Master:", self._alerts_enabled)

        cats = [
            ("lan_issue", "LAN issues"),
            ("isp_wan_issue", "ISP / WAN issues"),
            ("dns_issue", "DNS issues"),
            ("upstream_route_issue", "Upstream route changes"),
            ("intermittent", "Intermittent loss"),
        ]
        cats_widget = QWidget()
        cats_grid = QGridLayout(cats_widget)
        cats_grid.setContentsMargins(0, 0, 0, 0)
        self._alert_cat_boxes: dict[str, QCheckBox] = {}
        for i, (cat_key, cat_label) in enumerate(cats):
            cb = QCheckBox(cat_label)
            cb.setChecked(cat_key in config.alerts.categories)
            self._alert_cat_boxes[cat_key] = cb
            cats_grid.addWidget(cb, i // 2, i % 2)
        alerts_form.addRow("Categories:", cats_widget)

        self._alert_min_duration = QSpinBox()
        self._alert_min_duration.setRange(5, 600)
        self._alert_min_duration.setSuffix(" sec")
        self._alert_min_duration.setValue(config.alerts.min_duration_seconds)
        alerts_form.addRow("Wait before alerting:", self._alert_min_duration)

        self._alert_snooze = QSpinBox()
        self._alert_snooze.setRange(60, 3600)
        self._alert_snooze.setSuffix(" sec")
        self._alert_snooze.setValue(config.alerts.snooze_seconds)
        alerts_form.addRow("Snooze duration:", self._alert_snooze)

        self._alert_debounce = QSpinBox()
        self._alert_debounce.setRange(30, 600)
        self._alert_debounce.setSuffix(" sec")
        self._alert_debounce.setValue(config.alerts.debounce_seconds)
        alerts_form.addRow("Debounce:", self._alert_debounce)

        self._discord_webhook = QLineEdit()
        self._discord_webhook.setText(config.alerts.discord_webhook_url or "")
        self._discord_webhook.setPlaceholderText(
            "https://discord.com/api/webhooks/..."
        )
        self._discord_webhook.setToolTip(
            "Paste a webhook URL from Discord → Channel Settings → "
            "Integrations → Webhooks. Empty = disabled."
        )
        alerts_form.addRow("Discord webhook URL:", self._discord_webhook)

        self._generic_webhook = QLineEdit()
        self._generic_webhook.setText(config.alerts.generic_webhook_url or "")
        self._generic_webhook.setPlaceholderText(
            "https://example.com/hook  (POSTs JSON)"
        )
        self._generic_webhook.setToolTip(
            "Plain JSON POST to any URL. Fields: source, timestamp, "
            "category, severity, title, message, is_resolution."
        )
        alerts_form.addRow("Generic webhook URL:", self._generic_webhook)

        main_layout.addWidget(alerts_group)

        # Behavior group
        behavior_group = QGroupBox("Behavior")
        behavior_form = QFormLayout(behavior_group)

        self._close_to_tray = QCheckBox("Minimize to tray instead of quitting")
        self._close_to_tray.setChecked(config.close_to_tray)
        self._close_to_tray.setToolTip(
            "When enabled, clicking the X keeps Losshound monitoring "
            "in the system tray. Right-click the tray icon to quit."
        )
        behavior_form.addRow("Close button:", self._close_to_tray)

        self._lan_firewall = QCheckBox(
            "Enable LAN discovery firewall rule (administrator required)"
        )
        self._lan_firewall.setChecked(config.lan_discovery_firewall_enabled)
        self._lan_firewall.setToolTip(
            "Adds a narrow inbound UDP rule (mDNS, LLMNR, SSDP, NetBIOS) scoped "
            "to the packaged Losshound executable only — never python.exe. "
            "Required to receive friendly device names on Public Wi-Fi profiles. "
            "Changing this setting asks for confirmation and requires administrator."
        )
        behavior_form.addRow("LAN discovery:", self._lan_firewall)

        firewall_note = (
            "LAN discovery firewall preference is enabled. Losshound verifies changes "
            "only in an elevated packaged build."
            if config.lan_discovery_firewall_enabled
            else "Off by default. Losshound changes Windows Firewall only after you "
            "enable this setting and confirm the change."
        )
        self._lan_firewall_note = QLabel(firewall_note)
        self._lan_firewall_note.setWordWrap(True)
        self._lan_firewall_note.setProperty("role", "muted")
        behavior_form.addRow("", self._lan_firewall_note)

        self._lan_http_scan = QCheckBox("Enable LAN HTTP scanner (Warning: can trigger corporate EDR alarms)")
        self._lan_http_scan.setChecked(config.lan_http_scan_enabled)
        self._lan_http_scan.setToolTip(
            "Gathers additional details (such as HTTP home page titles) from local network devices. "
            "Uncheck this in corporate environments to avoid triggering intrusion detection systems."
        )
        behavior_form.addRow("LAN HTTP scanner:", self._lan_http_scan)

        main_layout.addWidget(behavior_group)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self._reset_defaults)
        btn_row.addWidget(reset_btn)

        save_btn = QPushButton("Save")
        save_btn.setProperty("class", "primary")
        save_btn.setStyleSheet(button_style("primary"))
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn)

        main_layout.addLayout(btn_row)
        main_layout.addStretch()

        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _build_config(self) -> AppConfig:
        pub_targets = [
            t.strip() for t in self._public_targets.text().split(",") if t.strip()
        ]
        dns_hosts = [
            t.strip() for t in self._dns_hostnames.text().split(",") if t.strip()
        ]

        diag = DiagnosisConfig(
            gateway_loss_threshold=self._gw_loss.value(),
            public_loss_threshold=self._pub_loss.value(),
            dns_failure_threshold=self._dns_fail.value() / 100.0,
            latency_warning_ms=self._latency_warn.value(),
            jitter_warning_ms=self._jitter_warn.value(),
            route_change_sensitivity=self._route_sensitivity.value(),
            timeout_burst_threshold=self._config.diagnosis.timeout_burst_threshold,
            min_observations=self._min_obs.value(),
            window_minutes=self._window.value(),
        )

        return AppConfig(
            ping_interval_seconds=self._ping_interval.value(),
            dns_interval_seconds=self._dns_interval.value(),
            route_interval_seconds=self._route_interval.value(),
            history_retention_hours=self._retention.value(),
            public_ping_targets=pub_targets,
            dns_test_hostnames=dns_hosts,
            tracert_target=self._tracert_target.text().strip(),
            tracert_max_hops=self._config.tracert_max_hops,
            ping_count=self._ping_count.value(),
            ping_timeout_ms=self._ping_timeout.value(),
            auto_benchmark_interval_minutes=self._config.auto_benchmark_interval_minutes,
            close_to_tray=self._close_to_tray.isChecked(),
            lan_discovery_firewall_enabled=self._lan_firewall.isChecked(),
            lan_http_scan_enabled=self._lan_http_scan.isChecked(),
            pdf_default_dir=self._config.pdf_default_dir,
            alerts=AlertsConfig(
                enabled=self._alerts_enabled.isChecked(),
                categories=[
                    cat for cat, cb in self._alert_cat_boxes.items()
                    if cb.isChecked()
                ],
                min_duration_seconds=self._alert_min_duration.value(),
                snooze_seconds=self._alert_snooze.value(),
                debounce_seconds=self._alert_debounce.value(),
                discord_webhook_url=self._discord_webhook.text().strip() or None,
                generic_webhook_url=self._generic_webhook.text().strip() or None,
            ),
            diagnosis=diag,
            log_level=self._config.log_level,
        )

    def _save(self):
        config = self._build_config()
        errors = []
        
        from losshound.core.validation import validate_target

        if not config.public_ping_targets:
            errors.append("Public ping targets cannot be empty.")
        else:
            for target in config.public_ping_targets:
                if not validate_target(target):
                    errors.append(f"Invalid public ping target: {target}")

        if not config.dns_test_hostnames:
            errors.append("DNS test hostnames cannot be empty.")
        else:
            for target in config.dns_test_hostnames:
                if not validate_target(target):
                    errors.append(f"Invalid DNS hostname: {target}")

        if not config.tracert_target:
            errors.append("Tracert target cannot be empty.")
        elif not validate_target(config.tracert_target):
            errors.append(f"Invalid tracert target: {config.tracert_target}")

        if errors:
            QMessageBox.warning(
                self, "Settings — invalid",
                "Please fix the following before saving:\n\n• " +
                "\n• ".join(errors),
            )
            return

        # Firewall state is the only Settings change that mutates the OS. Ask
        # separately, apply it before persisting, and keep the previous value
        # if Windows cannot verify the operation.
        firewall_changed = (
            config.lan_discovery_firewall_enabled
            != self._config.lan_discovery_firewall_enabled
        )
        if firewall_changed and config.lan_discovery_firewall_enabled:
            reply = QMessageBox.question(
                self,
                "Enable LAN discovery firewall rule",
                "Allow inbound UDP discovery responses on ports 5353, 5355, "
                "1900, and 137 for this packaged Losshound executable?\n\n"
                "The rule is limited to Losshound and can be removed here later.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                config.lan_discovery_firewall_enabled = (
                    self._config.lan_discovery_firewall_enabled
                )
                self._lan_firewall.setChecked(
                    self._config.lan_discovery_firewall_enabled
                )
                firewall_changed = False

        if firewall_changed:
            from losshound.core.firewall import apply_firewall_preference
            applied = apply_firewall_preference(config.lan_discovery_firewall_enabled)
            if not applied:
                config.lan_discovery_firewall_enabled = (
                    self._config.lan_discovery_firewall_enabled
                )
                self._lan_firewall.setChecked(
                    self._config.lan_discovery_firewall_enabled
                )
                QMessageBox.warning(
                    self, "LAN discovery firewall rule",
                    "Windows couldn't verify the firewall change, so Losshound kept "
                    "the previous setting. Use the packaged Losshound.exe and restart "
                    "it as administrator before trying again.",
                )
                self._lan_firewall_note.setText(
                    "Firewall change not applied; the previous verified setting is still active."
                )
            else:
                state = "active" if config.lan_discovery_firewall_enabled else "removed"
                self._lan_firewall_note.setText(
                    f"LAN discovery firewall rule verified {state}."
                )

        save_config(config)

        self._config = config
        self.config_changed.emit(config)
        QMessageBox.information(self, "Settings", "Settings saved successfully.")

    def _reset_defaults(self):
        default = AppConfig()
        self._ping_interval.setValue(default.ping_interval_seconds)
        self._dns_interval.setValue(default.dns_interval_seconds)
        self._route_interval.setValue(default.route_interval_seconds)
        self._ping_count.setValue(default.ping_count)
        self._ping_timeout.setValue(default.ping_timeout_ms)
        self._retention.setValue(default.history_retention_hours)
        self._public_targets.setText(", ".join(default.public_ping_targets))
        self._dns_hostnames.setText(", ".join(default.dns_test_hostnames))
        self._tracert_target.setText(default.tracert_target)
        self._close_to_tray.setChecked(default.close_to_tray)
        self._lan_firewall.setChecked(default.lan_discovery_firewall_enabled)
        self._lan_http_scan.setChecked(default.lan_http_scan_enabled)

        dc = default.diagnosis
        self._gw_loss.setValue(dc.gateway_loss_threshold)
        self._pub_loss.setValue(dc.public_loss_threshold)
        self._dns_fail.setValue(dc.dns_failure_threshold * 100.0)
        self._latency_warn.setValue(dc.latency_warning_ms)
        self._jitter_warn.setValue(dc.jitter_warning_ms)
        self._route_sensitivity.setValue(dc.route_change_sensitivity)
        self._min_obs.setValue(dc.min_observations)
        self._window.setValue(dc.window_minutes)

        default_alerts = AlertsConfig()
        self._alerts_enabled.setChecked(default_alerts.enabled)
        for cat_key, cb in self._alert_cat_boxes.items():
            cb.setChecked(cat_key in default_alerts.categories)
        self._alert_min_duration.setValue(default_alerts.min_duration_seconds)
        self._alert_snooze.setValue(default_alerts.snooze_seconds)
        self._alert_debounce.setValue(default_alerts.debounce_seconds)
        self._discord_webhook.setText("")
        self._generic_webhook.setText("")
