"""Custom-painted widgets and primitives for the HUD theme.

Everything in this module is a ``QWidget`` (or mixin) that paints itself via
``paintEvent`` because the look it produces — dotted bitmap textures, soft
spotlights, sparklines, blinking dots, animated halos — is outside what
QSS can express.
"""
from __future__ import annotations

import math
import time
from collections import deque
from typing import Deque, Iterable, Optional

from PySide6.QtCore import (
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    Qt,
    Signal,
    QTimer,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QCursor,
    QFont,
    QFontMetrics,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QGraphicsOpacityEffect,
    QSizePolicy,
    QStylePainter,
    QTabBar,
    QVBoxLayout,
    QWidget,
)

from losshound.gui.palette import (
    chrome_font,
    dotted_texture,
    flowing_dot_field,
    halo_pixmap,
    label_font,
    mono_font,
    ocean_halftone,
    qc,
)


# ---------------------------------------------------------------------------
# TexturedSurface — paints the continuous dotted field beneath all panels.
# ---------------------------------------------------------------------------


class TexturedSurface(QWidget):
    """Static high-fidelity halftone "ocean swell" backdrop.

    The wave field is rendered once per size and cached (see
    ``palette.ocean_halftone``), then simply blitted — there is no animation
    timer, so the backdrop costs nothing per frame at any resolution. During a
    live resize the cached pixmap is stretched to fit and a crisp one is
    regenerated once the drag settles.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setAutoFillBackground(False)

        self._bg_pixmap = None

        # Regenerate the crisp wave field shortly after a resize settles.
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._rebuild)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self._bg_pixmap is None:
            self._rebuild()
        else:
            # Old pixmap stretches to fit until a crisp one is regenerated.
            self._resize_timer.start(120)

    def _rebuild(self) -> None:
        w = self.width()
        h = self.height()
        if w < 2 or h < 2:
            self._bg_pixmap = None
            return
        self._bg_pixmap = ocean_halftone(w, h)
        self.update()

    def paintEvent(self, event):  # type: ignore[override]
        painter = QPainter(self)
        rect = self.rect()
        if rect.width() < 1 or rect.height() < 1:
            return
        if self._bg_pixmap is None or self._bg_pixmap.isNull():
            painter.fillRect(rect, qc("bg_window"))
            self._rebuild()
            if self._bg_pixmap is None or self._bg_pixmap.isNull():
                return
        # 1:1 when sizes match; only stretched mid-resize before _rebuild fires.
        painter.drawPixmap(rect, self._bg_pixmap)


# ---------------------------------------------------------------------------
# BracketedPanel — every dashboard panel sits inside one of these.
# ---------------------------------------------------------------------------


class BracketedPanel(QWidget):
    """A 1px-bordered panel filled with the HUD dotted texture.

    Optionally renders a small uppercase title strip at the top-left and a
    radial spotlight that mimics the bleed-through visible in the reference.
    """

    def __init__(
        self,
        title: Optional[str] = None,
        spotlight: bool = True,
        title_color_token: str = "info",
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._title = title.upper() if title else None
        self._spotlight = spotlight
        self._title_color = qc(title_color_token)
        if title:
            self.setAccessibleName(title)

        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setAutoFillBackground(False)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout = QVBoxLayout(self)
        # Reserve space for the title strip + border breathing room.
        top_margin = 32 if self._title else 14
        layout.setContentsMargins(14, top_margin, 14, 12)
        layout.setSpacing(8)

    def set_title(self, title: str) -> None:
        self._title = title.upper()
        self.setAccessibleName(title)
        margins = self.layout().contentsMargins()
        self.layout().setContentsMargins(
            margins.left(), 32, margins.right(), margins.bottom()
        )
        self.update()

    def paintEvent(self, event):  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        rect = self.rect()

        # Transparent background — the dashboard paints the continuous
        # texture beneath us. We only contribute a light 1px divider and
        # an uppercase title strip.

        painter.fillRect(rect.adjusted(1, 1, -1, -1), QColor(0, 0, 0, 66))

        # Title strip
        if self._title:
            painter.setPen(self._title_color)
            font = label_font()
            font.setPointSize(9)
            painter.setFont(font)
            metrics = QFontMetrics(font)
            text_rect = QRect(14, 8, rect.width() - 28, metrics.height() + 4)
            painter.drawText(
                text_rect,
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                self._title,
            )

        # Light 1px border so panels read as discrete cells against the
        # unified textured field.
        pen = QPen(qc("border"))
        pen.setWidth(1)
        pen.setCosmetic(True)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(rect.adjusted(0, 0, -1, -1))


# ---------------------------------------------------------------------------
# Sparkline
# ---------------------------------------------------------------------------


class Sparkline(QWidget):
    """A compact inline live chart of the last N numeric samples."""

    def __init__(
        self,
        capacity: int = 40,
        height: int = 18,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._values: Deque[float] = deque(maxlen=capacity)
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def push(self, value: Optional[float]) -> None:
        if value is None:
            return
        self._values.append(float(value))
        self.update()

    def clear(self) -> None:
        self._values.clear()
        self.update()

    def set_history(self, values: Iterable[float]) -> None:
        self._values.clear()
        for v in values:
            if v is None:
                continue
            self._values.append(float(v))
        self.update()

    def paintEvent(self, event):  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = self.rect()
        if len(self._values) < 2:
            return

        lo = min(self._values)
        hi = max(self._values)
        if hi - lo < 1e-6:
            hi = lo + 1.0
        n = len(self._values)

        w = rect.width()
        h = rect.height()
        padding = 2
        usable_h = h - padding * 2

        points = []
        for i, v in enumerate(self._values):
            x = (i / (n - 1)) * (w - 1)
            y = padding + (1.0 - (v - lo) / (hi - lo)) * usable_h
            points.append(QPointF(x, y))

        # Fill under the curve with a faint mint gradient.
        path = QPainterPath()
        path.moveTo(points[0].x(), h)
        for p in points:
            path.lineTo(p)
        path.lineTo(points[-1].x(), h)
        path.closeSubpath()

        gradient = QLinearGradient(0, 0, 0, h)
        gradient.setColorAt(0.0, QColor(95, 214, 160, 70))
        gradient.setColorAt(1.0, QColor(95, 214, 160, 0))
        painter.setBrush(QBrush(gradient))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(path)

        # Stroke
        pen = QPen(qc("mint"))
        pen.setWidth(1)
        pen.setCosmetic(True)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for i in range(1, len(points)):
            painter.drawLine(points[i - 1], points[i])

        # Trailing dot at the latest sample.
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(qc("mint"))
        last = points[-1]
        painter.drawEllipse(last, 2.0, 2.0)


# ---------------------------------------------------------------------------
# LiveDot — soft blinking presence indicator.
# ---------------------------------------------------------------------------


class LiveDot(QWidget):
    """A 7px circle that breathes softly via an opacity animation."""

    def __init__(
        self,
        color_token: str = "mint",
        size: int = 8,
        period_ms: int = 1400,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._color = qc(color_token)
        self._size = size
        self.setFixedSize(size + 2, size + 2)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

        self._effect = QGraphicsOpacityEffect(self)
        self._effect.setOpacity(1.0)
        self.setGraphicsEffect(self._effect)

        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setStartValue(1.0)
        self._anim.setKeyValueAt(0.5, 0.35)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(period_ms)
        self._anim.setLoopCount(-1)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._anim.start()

    def set_color(self, token: str) -> None:
        self._color = qc(token)
        self.update()

    def stop(self) -> None:
        self._anim.stop()
        self._effect.setOpacity(0.4)

    def start(self) -> None:
        if self._anim.state() != QPropertyAnimation.State.Running:
            self._effect.setOpacity(1.0)
            self._anim.start()

    def paintEvent(self, event):  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)

        # Faint outer glow
        glow = QColor(self._color)
        glow.setAlpha(70)
        painter.setBrush(glow)
        painter.drawEllipse(self.rect())

        # Solid core
        painter.setBrush(self._color)
        d = self._size
        margin = (self.width() - d) // 2
        painter.drawEllipse(margin, margin, d, d)


# ---------------------------------------------------------------------------
# AlertGlyph — small shape painted before a feed row.
# ---------------------------------------------------------------------------


class AlertGlyph(QWidget):
    """Coloured dot/triangle/cross prefix for AlertsFeed rows."""

    KINDS = ("info", "warn", "error")

    def __init__(self, kind: str = "info", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._kind = kind if kind in self.KINDS else "info"
        self.setFixedSize(14, 14)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def set_kind(self, kind: str) -> None:
        if kind in self.KINDS and kind != self._kind:
            self._kind = kind
            self.update()

    def paintEvent(self, event):  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)

        rect = QRectF(2, 2, 10, 10)
        if self._kind == "info":
            painter.setBrush(qc("mint"))
            painter.drawEllipse(rect)
        elif self._kind == "warn":
            painter.setBrush(qc("warn"))
            triangle = QPolygonF(
                [
                    QPointF(rect.center().x(), rect.top()),
                    QPointF(rect.right(), rect.bottom()),
                    QPointF(rect.left(), rect.bottom()),
                ]
            )
            painter.drawPolygon(triangle)
        else:
            painter.setBrush(qc("error"))
            painter.drawEllipse(rect)
            painter.setPen(QPen(QColor("#0a0d11"), 2))
            painter.drawLine(
                rect.left() + 2.5,
                rect.center().y(),
                rect.right() - 2.5,
                rect.center().y(),
            )


# ---------------------------------------------------------------------------
# LosshoundTabBar — flat tabs with mint underline.
# ---------------------------------------------------------------------------


class LosshoundTabBar(QTabBar):
    """A custom QTabBar with vertical dividers and a mint selection underline."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setDrawBase(False)
        self.setExpanding(True)
        self.setUsesScrollButtons(True)
        self.setElideMode(Qt.TextElideMode.ElideRight)
        self.setAccessibleName("Primary navigation")
        self.setFont(mono_font(10))

    def tabSizeHint(self, index: int) -> QSize:  # type: ignore[override]
        size = super().tabSizeHint(index)
        size.setHeight(38)
        # Eleven tool tabs must remain reachable at the 1200 px window minimum.
        # Compact cells fit at that width; scroll buttons remain as a fallback
        # for high text scaling and narrower host layouts.
        size.setWidth(max(72, min(size.width() + 14, 108)))
        return size

    def paintEvent(self, event):  # type: ignore[override]
        painter = QStylePainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

        painter.fillRect(self.rect(), qc("bg_window"))

        font = mono_font(10, QFont.Weight.Medium)
        font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 106)
        font.setCapitalization(QFont.Capitalization.AllUppercase)
        painter.setFont(font)

        cell_pen = QPen(qc("border"))
        cell_pen.setWidth(1)
        cell_pen.setCosmetic(True)
        active_pen = QPen(qc("info"))
        active_pen.setWidth(2)
        active_pen.setCosmetic(True)

        for i in range(self.count()):
            r = self.tabRect(i)
            selected = i == self.currentIndex()
            painter.setPen(cell_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(r.adjusted(0, 0, -1, -1))

            color = qc("text_primary") if selected else qc("text_secondary")
            painter.setPen(color)
            painter.drawText(r, int(Qt.AlignmentFlag.AlignCenter), self.tabText(i))

            if selected:
                painter.setPen(active_pen)
                painter.drawLine(r.left() + 1, r.bottom() - 2, r.right() - 1, r.bottom() - 2)
                if self.hasFocus():
                    focus_pen = QPen(qc("border_focus"))
                    focus_pen.setWidth(1)
                    focus_pen.setStyle(Qt.PenStyle.DashLine)
                    focus_pen.setCosmetic(True)
                    painter.setPen(focus_pen)
                    painter.drawRect(r.adjusted(3, 3, -4, -5))

        pen = QPen(qc("border"))
        pen.setWidth(1)
        pen.setCosmetic(True)
        painter.setPen(pen)
        painter.drawLine(0, self.height() - 1, self.width(), self.height() - 1)




