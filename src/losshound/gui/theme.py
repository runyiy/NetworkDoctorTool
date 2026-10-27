"""Application-wide QSS, generated from the palette tokens."""
from __future__ import annotations

from losshound.gui.palette import FONT_CHROME_FAMILIES, FONT_MONO_FAMILIES, c


def button_style(kind: str = "default") -> str:
    variants = {
        "default": (c("bg_panel"),       c("border_strong"), c("text_primary"), c("bg_panel_hover")),
        "primary": (c("bg_panel"),       c("mint"),          c("text_primary"), "#13352a"),
        "success": (c("bg_panel"),       c("mint"),          c("text_primary"), "#13352a"),
        "warning": ("#21190b",           c("warn"),          "#f3e3b4",         "#3a2b13"),
        "danger":  ("#2a0f12",           c("error"),         "#f0d7d7",         "#42161b"),
    }
    bg, border, text, hover = variants.get(kind, variants["default"])
    return f"""
    QPushButton {{
        background-color: {bg};
        color: {text};
        border: 1px solid {border};
        border-radius: 0px;
        font-family: {FONT_CHROME_FAMILIES};
        font-weight: 600;
        letter-spacing: 1px;
        text-transform: uppercase;
        padding: 7px 16px;
    }}
    QPushButton:hover {{
        background-color: {hover};
        border-color: {c("mint")};
    }}
    QPushButton:pressed {{
        background-color: {c("bg_window")};
    }}
    QPushButton:focus {{
        border: 2px solid {c("border_focus")};
        padding: 6px 15px;
    }}
    QPushButton:disabled {{
        background-color: {c("bg_panel_inner")};
        color: {c("text_dim")};
        border-color: {c("border")};
    }}
    """


def get_dark_stylesheet() -> str:
    return f"""
    QWidget {{
        background-color: {c("bg_window")};
        color: {c("text_primary")};
        font-family: {FONT_CHROME_FAMILIES};
        font-size: 12px;
    }}

    QMainWindow {{
        background-color: {c("bg_window")};
    }}

    QTabWidget::pane {{
        border: 1px solid {c("border")};
        border-top: 1px solid {c("border")};
        border-radius: 0px;
        background-color: {c("bg_window")};
        top: -1px;
    }}

    /* The default QTabBar is hidden — main_window installs a custom one. */
    QTabBar {{
        background-color: {c("bg_window")};
        qproperty-drawBase: 0;
    }}

    QTabBar::tab {{
        background: transparent;
        color: {c("text_secondary")};
        padding: 10px 22px;
        margin: 0px;
        border: none;
        font-family: {FONT_CHROME_FAMILIES};
        font-weight: 600;
        font-size: 11px;
        letter-spacing: 2px;
        text-transform: uppercase;
    }}

    QTabBar::tab:selected {{
        color: {c("text_primary")};
        border-bottom: 1px solid {c("mint")};
    }}

    QTabBar::tab:hover:!selected {{
        color: {c("text_primary")};
    }}

    QLabel {{
        background: transparent;
        color: {c("text_secondary")};
    }}

    QLabel[role="title"] {{
        color: {c("info")};
        font-family: {FONT_CHROME_FAMILIES};
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 2px;
        text-transform: uppercase;
    }}

    QLabel[role="hero"] {{
        color: {c("text_primary")};
        font-family: {FONT_MONO_FAMILIES};
        font-size: 30px;
        font-weight: 300;
    }}

    QLabel[role="hero-live"] {{
        color: {c("mint")};
        font-family: {FONT_MONO_FAMILIES};
        font-size: 30px;
        font-weight: 300;
    }}

    QLabel[role="metric-label"] {{
        color: {c("info_dim")};
        font-family: {FONT_CHROME_FAMILIES};
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }}

    QLabel[role="metric-value"] {{
        color: {c("mint")};
        font-family: {FONT_MONO_FAMILIES};
        font-size: 12px;
        font-weight: 500;
    }}

    QLabel[role="metric-value-neutral"] {{
        color: {c("text_primary")};
        font-family: {FONT_MONO_FAMILIES};
        font-size: 12px;
        font-weight: 500;
    }}

    QLabel[role="row-key"] {{
        color: {c("text_secondary")};
        font-family: {FONT_CHROME_FAMILIES};
        font-size: 11px;
    }}

    QLabel[role="row-value"] {{
        color: {c("text_primary")};
        font-family: {FONT_MONO_FAMILIES};
        font-size: 11px;
    }}

    QPushButton {{
        background-color: {c("bg_panel")};
        color: {c("text_primary")};
        border: 1px solid {c("border_strong")};
        padding: 7px 16px;
        border-radius: 0px;
        font-family: {FONT_CHROME_FAMILIES};
        font-weight: 600;
        letter-spacing: 1px;
        text-transform: uppercase;
    }}

    QPushButton:hover {{
        background-color: {c("bg_panel_hover")};
        border-color: {c("mint")};
    }}

    QPushButton:pressed {{
        background-color: {c("bg_window")};
    }}

    QPushButton:focus {{
        border: 2px solid {c("border_focus")};
        padding: 6px 15px;
    }}

    QPushButton:disabled {{
        background-color: {c("bg_panel_inner")};
        color: {c("text_dim")};
        border-color: {c("border")};
    }}

    QPushButton.primary {{
        background-color: {c("bg_panel")};
        color: {c("text_primary")};
        border-color: {c("mint")};
    }}

    QPushButton.primary:hover {{
        background-color: #13352a;
    }}

    QTableWidget, QTableView {{
        background-color: {c("bg_table")};
        alternate-background-color: {c("bg_table_alt")};
        border: none;
        border-radius: 0px;
        gridline-color: {c("border_faint")};
        selection-background-color: #11302a;
        selection-color: {c("text_primary")};
        font-family: {FONT_MONO_FAMILIES};
        font-size: 11px;
    }}

    QTableWidget::item, QTableView::item {{
        padding: 6px 12px;
        border-bottom: 1px solid {c("border_faint")};
    }}

    QTableWidget QComboBox,
    QTableWidget QLineEdit,
    QTableView QComboBox,
    QTableView QLineEdit {{
        background-color: {c("bg_panel")};
        color: {c("text_primary")};
        border: 1px solid {c("border_strong")};
        border-radius: 0px;
        padding: 2px 6px;
        margin: 2px;
    }}

    QHeaderView::section {{
        background-color: {c("bg_window")};
        color: {c("info")};
        padding: 8px 12px;
        border: none;
        border-bottom: 1px solid {c("border")};
        font-family: {FONT_CHROME_FAMILIES};
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }}

    QHeaderView:vertical {{
        qproperty-defaultSectionSize: 30;
    }}

    QTextEdit {{
        background-color: {c("bg_table")};
        border: 1px solid {c("border")};
        border-radius: 0px;
        padding: 10px;
        font-family: {FONT_MONO_FAMILIES};
        font-size: 12px;
        color: {c("text_primary")};
    }}

    QScrollBar:vertical {{
        background-color: transparent;
        width: 6px;
        margin: 0px;
    }}

    QScrollBar::handle:vertical {{
        background-color: {c("border_strong")};
        border-radius: 0px;
        min-height: 30px;
    }}

    QScrollBar::handle:vertical:hover {{
        background-color: {c("mint_dim")};
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}

    QScrollBar:horizontal {{
        background-color: transparent;
        height: 6px;
        margin: 0px;
    }}

    QScrollBar::handle:horizontal {{
        background-color: {c("border_strong")};
        border-radius: 0px;
        min-width: 30px;
    }}

    QScrollBar::handle:horizontal:hover {{
        background-color: {c("mint_dim")};
    }}

    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}

    QSpinBox, QDoubleSpinBox, QLineEdit {{
        background-color: {c("bg_panel")};
        color: {c("text_primary")};
        border: 1px solid {c("border_strong")};
        border-radius: 0px;
        padding: 6px 10px;
        font-family: {FONT_MONO_FAMILIES};
    }}

    QSpinBox:focus, QDoubleSpinBox:focus, QLineEdit:focus {{
        border-color: {c("mint")};
        border-width: 2px;
    }}

    QComboBox:focus {{
        border: 2px solid {c("border_focus")};
        padding: 5px 9px;
    }}

    QCheckBox:focus {{
        color: {c("text_primary")};
        border: 1px dotted {c("border_focus")};
    }}

    QTableWidget:focus, QTableView:focus, QTextEdit:focus {{
        border: 1px solid {c("border_focus")};
    }}

    QGroupBox {{
        border: 1px solid {c("border")};
        border-radius: 0px;
        margin-top: 16px;
        padding-top: 20px;
        font-family: {FONT_CHROME_FAMILIES};
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: {c("info")};
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 14px;
        padding: 0 6px;
        color: {c("info")};
        background-color: {c("bg_window")};
    }}

    QStatusBar {{
        background-color: {c("bg_window")};
        color: {c("text_secondary")};
        border-top: 1px solid {c("border")};
    }}

    QComboBox {{
        background-color: {c("bg_panel")};
        color: {c("text_primary")};
        border: 1px solid {c("border_strong")};
        border-radius: 0px;
        padding: 6px 10px;
        font-family: {FONT_CHROME_FAMILIES};
    }}

    QComboBox::drop-down {{
        border: none;
    }}

    QComboBox QAbstractItemView {{
        background-color: {c("bg_panel")};
        color: {c("text_primary")};
        selection-background-color: {c("bg_panel_hover")};
        border: 1px solid {c("border_strong")};
    }}

    QProgressBar {{
        background-color: {c("bg_panel_inner")};
        border: 1px solid {c("border")};
        border-radius: 0px;
        text-align: center;
        color: {c("text_primary")};
        font-family: {FONT_MONO_FAMILIES};
        height: 22px;
        font-weight: 600;
    }}

    QProgressBar::chunk {{
        background-color: {c("mint_dim")};
        border-right: 1px solid {c("mint")};
        border-radius: 0px;
    }}

    QMenu {{
        background-color: {c("bg_panel")};
        color: {c("text_primary")};
        border: 1px solid {c("border_strong")};
    }}

    QMenu::item {{
        padding: 6px 18px;
    }}

    QMenu::item:selected {{
        background-color: {c("bg_panel_hover")};
        color: {c("mint")};
    }}
    """
