"""Navigation must preserve every page and follow contextual page changes."""
import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QTabWidget, QVBoxLayout, QWidget

from losshound.gui.main_window import MainWindow
from losshound.gui.navigation import PageNavigation

NAMES = ("Dashboard", "History", "Routes", "Optimizer", "QoS", "Score", "WiFi",
         "LAN Monitor", "Drops", "Settings", "Export")


@pytest.fixture
def shell():
    app = QApplication.instance() or QApplication([])
    window = QWidget()
    layout = QVBoxLayout(window)
    tabs = QTabWidget()
    for name in NAMES:
        page = QWidget()
        page.setObjectName(name)
        tabs.addTab(page, name)
    navigation = PageNavigation(tabs)
    layout.addWidget(navigation)
    layout.addWidget(tabs)
    window.resize(1200, 720)
    window.show()
    app.processEvents()
    yield tabs, navigation, window
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_all_pages_are_reachable_and_keep_their_widget(shell):
    tabs, nav, _ = shell
    pages = [tabs.widget(i) for i in range(tabs.count())]
    reached = set()
    for button, title, indices in nav._buttons:
        if button.menu() is not None:
            for action, index in zip(button.menu().actions(), indices):
                action.trigger()
                assert tabs.currentWidget() is pages[index]
                assert button.isChecked()
                assert tabs.tabText(index) in button.text()
                reached.add(index)
        else:
            QTest.mouseClick(button, Qt.MouseButton.LeftButton)
            assert tabs.currentWidget() is pages[indices[0]]
            QTest.mouseClick(button, Qt.MouseButton.LeftButton)
            assert button.isChecked()
            reached.add(indices[0])
    assert reached == set(range(len(NAMES)))
    assert [tabs.widget(i) for i in range(tabs.count())] == pages


def test_contextual_links_update_group_and_active_menu_item(shell):
    tabs, nav, _ = shell
    from types import SimpleNamespace
    for name in ("QoS", "WiFi", "Settings", "Dashboard"):
        index = NAMES.index(name)
        MainWindow._open_tab(SimpleNamespace(_tabs=tabs), tabs.widget(index))
        active = [button for button, _, _ in nav._buttons if button.isChecked()]
        assert len(active) == 1
        assert name in active[0].text()
        if index in nav._actions:
            assert nav._actions[index].isChecked()
    assert not any(action.isChecked() for action in nav._actions.values())


def test_navigation_fits_minimum_window_width_for_each_page(shell):
    tabs, nav, window = shell
    for index in range(tabs.count()):
        tabs.setCurrentIndex(index)
        QApplication.processEvents()
        assert window.width() == 1200
        for button, _, _ in nav._buttons:
            assert nav.rect().contains(button.geometry())


def test_diagnostics_menu_can_be_used_and_dismissed_by_keyboard(shell):
    tabs, nav, _ = shell
    button = next(button for button, title, _ in nav._buttons if title == "Diagnostics")
    menu = button.menu()
    button.setFocus()
    # Exercise the actual button's menu, not only QAction.trigger().
    def choose():
        menu.setActiveAction(menu.actions()[2])  # WiFi
        QTest.keyClick(menu, Qt.Key.Key_Return)

    QTimer.singleShot(0, choose)
    QTest.keyClick(button, Qt.Key.Key_Space)
    QApplication.processEvents()
    assert tabs.currentWidget().objectName() == "WiFi"
    assert button.isChecked()
    QTimer.singleShot(0, lambda: QTest.keyClick(menu, Qt.Key.Key_Escape))
    QTest.keyClick(button, Qt.Key.Key_Space)
    QApplication.processEvents()
    assert tabs.currentWidget().objectName() == "WiFi"
    assert button.isChecked()
