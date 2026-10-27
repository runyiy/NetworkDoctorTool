import os

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication



@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app












def test_header_actions_follow_pause_state_and_remain_accessible(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from losshound.gui.widgets import LosshoundHeader

    header = LosshoundHeader()
    header.show()
    calls = []
    header.run_now_clicked.connect(lambda: calls.append("run"))
    header.pause_clicked.connect(lambda: calls.append("pause"))
    assert header._run_btn.text() == "Run check"
    assert header._pause_btn.text() == "Pause monitor"
    assert header._pause_btn.accessibleName() == "Pause monitoring"
    QTest.mouseClick(header._run_btn, Qt.MouseButton.LeftButton)
    QTest.mouseClick(header._pause_btn, Qt.MouseButton.LeftButton)
    assert calls == ["run", "pause"]

    header.set_paused(True)
    assert header._pause_btn.text() == "Resume monitor"
    assert header._pause_btn.accessibleName() == "Resume monitoring"
    assert not header._run_btn.isEnabled()
    QTest.mouseClick(header._run_btn, Qt.MouseButton.LeftButton)
    assert calls == ["run", "pause"]
    header._pause_btn.setFocus()
    QTest.keyClick(header._pause_btn, Qt.Key.Key_Space)
    assert calls == ["run", "pause", "pause"]

    header.set_paused(False)
    assert header._run_btn.isEnabled()
    assert header._pause_btn.accessibleName() == "Pause monitoring"
    QTest.mouseClick(header._run_btn, Qt.MouseButton.LeftButton)
    assert calls[-1] == "run"
    header.close()


def test_all_tabs_fit_or_scroll_at_minimum_width(qapp):
    from losshound.gui.painted import LosshoundTabBar

    tabs = LosshoundTabBar()
    names = [
        "Dashboard", "History", "Routes", "Optimizer", "QoS", "Score",
        "WiFi", "LAN Monitor", "Drops", "Settings", "Export",
    ]
    for name in names:
        tabs.addTab(name)

    total_hint = sum(tabs.tabSizeHint(i).width() for i in range(tabs.count()))
    assert total_hint <= 1200
    assert tabs.usesScrollButtons()
    assert tabs.accessibleName() == "Primary navigation"


def test_resume_caption_fits_after_parent_styles_are_applied(qapp):
    from PySide6.QtWidgets import QStyle, QStyleOptionButton, QVBoxLayout, QWidget
    from losshound.gui.theme import get_dark_stylesheet
    from losshound.gui.widgets import LosshoundHeader

    # Production applies QSS to MainWindow, then reparents the new header.
    window = QWidget()
    window.setStyleSheet(get_dark_stylesheet())
    header = LosshoundHeader()
    QVBoxLayout(window).addWidget(header)
    window.resize(1200, 120)
    window.show()
    widths = []
    try:
        for paused in (False, True, False):
            header.set_paused(paused)
            button = header._pause_btn
            button.setFocus()
            qapp.processEvents()
            option = QStyleOptionButton()
            button.initStyleOption(option)
            contents = button.style().subElementRect(
                QStyle.SubElement.SE_PushButtonContents, option, button,
            )
            assert contents.width() >= button.fontMetrics().horizontalAdvance(button.text())
            widths.append(button.width())
        assert len(set(widths)) == 1
    finally:
        window.close()


def test_focus_styles_cover_primary_keyboard_controls():
    from losshound.gui.theme import get_dark_stylesheet

    stylesheet = get_dark_stylesheet()
    assert "QPushButton:focus" in stylesheet
    assert "QComboBox:focus" in stylesheet
    assert "QCheckBox:focus" in stylesheet
    assert "QTableWidget:focus" in stylesheet
