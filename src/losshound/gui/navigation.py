"""Compact navigation; existing tabs retain page and worker ownership."""
from functools import partial

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QMenu, QPushButton, QTabWidget, QWidget


class PageNavigation(QWidget):
    """Keep monitoring close and group specialist tools without recreating pages."""

    def __init__(self, tabs: QTabWidget, parent=None):
        super().__init__(parent)
        self._tabs = tabs
        self._buttons: list[tuple[QPushButton, str, list[int]]] = []
        self._actions = {}
        self.setObjectName("page-navigation")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAccessibleName("Page navigation")
        self.setStyleSheet("""
            QWidget#page-navigation { background: #080c0e; border-bottom: 1px solid #28333b; }
            QWidget#page-navigation QPushButton {
                background: transparent; color: #aebbc6; border: none;
                border-bottom: 2px solid transparent; border-radius: 0;
                font-family: 'Segoe UI'; font-size: 13px; font-weight: 600;
                text-transform: none; letter-spacing: 0; padding: 12px 16px;
            }
            QWidget#page-navigation QPushButton:hover { background: #152127; color: #eef3f5; }
            QWidget#page-navigation QPushButton:checked {
                background: #12242a; color: #8ad4ec; border-bottom-color: #62c7d8;
            }
            QWidget#page-navigation QPushButton:focus { border: 1px solid #8ad4ec; }
            QWidget#page-navigation QPushButton::menu-indicator { width: 0; }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 0, 8, 0)
        layout.setSpacing(4)
        pages = {tabs.tabText(i): i for i in range(tabs.count())}
        for name in ("Dashboard", "History", "Drops"):
            self._add_button(layout, name, [pages[name]])
        for group, names in (
            ("Diagnostics", ("Routes", "Score", "WiFi", "LAN Monitor")),
            ("Tuning", ("Optimizer", "QoS")),
        ):
            self._add_button(layout, group, [pages[name] for name in names])
        layout.addStretch()
        for name in ("Settings", "Export"):
            self._add_button(layout, name, [pages[name]])
        tabs.tabBar().hide()
        tabs.currentChanged.connect(self._sync_selection)
        self._sync_selection(tabs.currentIndex())

    def _add_button(self, layout, title: str, indices: list[int]):
        button = QPushButton(title)
        button.setCheckable(True)
        button.setAutoDefault(False)
        if len(indices) == 1:
            button.clicked.connect(partial(self._select_page, indices[0]))
        else:
            menu = QMenu(button)
            menu.setStyleSheet("""
                QMenu { background: #10191e; border: 1px solid #43535e;
                        color: #dce5ea; padding: 6px; }
                QMenu::item { font-family: 'Segoe UI'; font-size: 13px;
                              padding: 10px 28px 10px 14px; }
                QMenu::item:selected { background: #23414c; color: #eef3f5; }
                QMenu::item:checked { color: #8ad4ec; }
            """)
            for index in indices:
                action = menu.addAction(self._tabs.tabText(index))
                action.setCheckable(True)
                action.triggered.connect(partial(self._select_page, index))
                self._actions[index] = action
            menu.aboutToHide.connect(lambda: self._sync_selection(self._tabs.currentIndex()))
            button.setMenu(menu)
            button.setToolTip(f"{title}: " + ", ".join(self._tabs.tabText(i) for i in indices))
        self._buttons.append((button, title, indices))
        layout.addWidget(button)

    def _select_page(self, index: int, _checked=False):
        self._tabs.setCurrentIndex(index)
        self._sync_selection(index)

    def _sync_selection(self, current: int):
        for button, title, indices in self._buttons:
            selected = current in indices
            button.setChecked(selected)
            caption = title
            if len(indices) > 1:
                if selected:
                    caption += f" · {self._tabs.tabText(current)}"
                caption += " ▾"
            button.setText(caption)
        for index, action in self._actions.items():
            action.setChecked(index == current)
