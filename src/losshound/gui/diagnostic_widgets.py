"""Shared presentation for the compact diagnostic tool pages."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QPushButton, QSizePolicy, QTableWidget, QVBoxLayout
from shiboken6 import isValid


def page_style(name: str) -> str:
    return f"""
        QWidget#{name} QLabel, QWidget#{name} QCheckBox, QWidget#{name} QComboBox {{
            font-family: 'Segoe UI'; font-size: 13px; color: #aebbc6;
        }}
        QWidget#{name} QLabel {{ background: transparent; border: none; }}
        QWidget#{name} QGroupBox {{
            border: none; border-top: 1px solid #28333b;
            margin-top: 22px; padding: 18px 0 0 0;
        }}
        QWidget#{name} QGroupBox::title {{
            subcontrol-origin: margin; subcontrol-position: top left;
            padding: 0 12px 0 0; color: #aebbc6;
            font-family: 'Segoe UI'; font-size: 14px; font-weight: 600;
            letter-spacing: 0; text-transform: none;
        }}
        QWidget#{name} QTableWidget {{
            background: #080c0e; alternate-background-color: #101619;
            border: none; font-family: 'Consolas'; font-size: 13px;
            selection-background-color: #203640;
        }}
        QWidget#{name} QHeaderView::section {{
            background: #080c0e; color: #90a4b2; border: none;
            border-bottom: 1px solid #28333b; font-family: 'Segoe UI';
            font-size: 12px; font-weight: 600; text-transform: none;
            letter-spacing: 0; padding: 8px;
        }}
    """


def style_action(button: QPushButton, kind: str = "default") -> None:
    bg, border, text, hover = {
        "primary": ("#17343c", "#62c7d8", "#eef3f5", "#234955"),
        "danger": ("#170f11", "#75464c", "#e8acb0", "#342025"),
        "default": ("#101519", "#43535e", "#dce5ea", "#1a272e"),
    }.get(kind, ("#101519", "#43535e", "#dce5ea", "#1a272e"))
    button.setMinimumHeight(40)
    button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
    button.setStyleSheet(f"""
        QPushButton {{
            background: {bg}; border: 1px solid {border}; color: {text};
            border-radius: 0; font-family: 'Segoe UI'; font-size: 13px;
            font-weight: 600; letter-spacing: 0; text-transform: none;
            padding: 9px 16px;
        }}
        QPushButton:hover {{ background: {hover}; border-color: #90b7c8; }}
        QPushButton:pressed {{ background: #080c0e; }}
        QPushButton:focus {{ border: 2px solid #8ad4ec; padding: 8px 15px; }}
        QPushButton:disabled {{ background: #0b1013; border-color: #2b363d; color: #73828d; }}
    """)


class ReadingTile(QFrame):
    """A separate caption and plain-text value; network names cannot become HTML."""
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("diagnostic-reading")
        self.setStyleSheet("QFrame#diagnostic-reading { background: #101519; border: 1px solid #27333b; }")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        self.title_label = QLabel(title)
        self.title_label.setTextFormat(Qt.TextFormat.PlainText)
        self.title_label.setStyleSheet("font-size: 12px; color: #90a4b2; border: none;")
        self.value_label = QLabel("--")
        self.value_label.setTextFormat(Qt.TextFormat.PlainText)
        self.value_label.setWordWrap(True)
        self.value_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label, 1)
        self.setMinimumHeight(88)
        self.set_reading(title, "--", "#90a4b2")

    def set_reading(self, title: str, value: str, color: str = "#eef3f5"):
        self.title_label.setText(title)
        self.value_label.setText(value)
        self.value_label.setToolTip(value)
        self.value_label.setStyleSheet(
            f"font-family: 'Consolas'; font-size: 19px; color: {color}; border: none;"
        )


def compact_table(table: QTableWidget, empty_label: QLabel | None, max_rows: int = 6):
    """Fit the visible rows while retaining scroll access to every result."""
    table.setShowGrid(False)
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(34)
    table.horizontalHeader().setMinimumSectionSize(72)
    table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def fit(*_):
        # Qt resets the internal model while destroying its owning table.
        if not isValid(table):
            return
        count = table.rowCount()
        height = table.horizontalHeader().sizeHint().height() + sum(
            table.rowHeight(row) for row in range(min(count, max_rows))
        ) + table.horizontalScrollBar().sizeHint().height() + 4
        if table.height() != height:
            table.setFixedHeight(height)
        table.setVisible(count > 0)
        if empty_label is not None:
            empty_label.setVisible(count == 0)

    table.model().rowsInserted.connect(fit)
    table.model().rowsRemoved.connect(fit)
    table.model().modelReset.connect(fit)
    fit()
