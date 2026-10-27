from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap


def losshound_pixmap(size: int = 64) -> QPixmap:
    """Load the generated Losshound shield mark, with a small fallback."""
    asset = _asset_logo_path()
    if asset is not None:
        source = QPixmap(str(asset))
        if not source.isNull():
            return source.scaled(
                size,
                size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
    return _fallback_pixmap(size)


def _asset_logo_path() -> Path | None:
    base = getattr(sys, "_MEIPASS", None)
    root = Path(base) if base is not None else Path(__file__).resolve().parents[3]
    path = root / "assets" / "losshound-logo.png"
    return path if path.exists() else None


def _fallback_pixmap(size: int = 64) -> QPixmap:
    """Render a simple LH network monogram if the PNG asset is unavailable."""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

    s = size / 64
    u = lambda value: round(value * s)

    painter.fillRect(0, 0, size, size, QColor("#101318"))

    border = QPen(QColor("#62c7d8"))
    border.setWidth(max(1, u(2)))
    painter.setPen(border)
    painter.drawRect(1, 1, size - 3, size - 3)

    cyan = QColor("#62c7d8")
    green = QColor("#75c884")
    amber = QColor("#d9b65f")
    panel = QColor("#17212b")

    painter.fillRect(u(8), u(8), u(48), u(48), panel)

    # L stem + foot.
    painter.fillRect(u(13), u(14), u(7), u(36), cyan)
    painter.fillRect(u(13), u(43), u(22), u(7), cyan)

    # H stem + bridge.
    painter.fillRect(u(39), u(14), u(7), u(36), cyan)
    painter.fillRect(u(28), u(29), u(18), u(6), cyan)

    # Packet route across the monogram.
    route = QPen(green)
    route.setWidth(max(2, u(4)))
    painter.setPen(route)
    painter.drawLine(u(20), u(38), u(29), u(30))
    painter.drawLine(u(29), u(30), u(40), u(30))

    painter.fillRect(u(48), u(13), u(6), u(6), amber)
    painter.fillRect(u(10), u(10), u(10), u(3), amber)
    painter.fillRect(u(50), u(48), u(5), u(5), green)

    painter.end()
    return pixmap


def app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(losshound_pixmap(size))
    return icon
