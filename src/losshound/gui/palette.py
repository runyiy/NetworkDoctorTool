"""Design tokens for the Losshound HUD theme.

Single source of truth for colour, typography, and texture so QSS in
``theme.py`` and the custom-painted widgets in ``painted.py`` agree.
"""
from __future__ import annotations

import sys
from functools import lru_cache
from math import exp, sin
from pathlib import Path

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontDatabase,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
    QRadialGradient,
)


def _assets_dir() -> Path:
    """Locate the project ``assets/`` directory.

    Works in a source checkout and in a PyInstaller bundle, where data files
    are unpacked under ``sys._MEIPASS``.
    """
    base = getattr(sys, "_MEIPASS", None)
    if base is not None:
        return Path(base) / "assets"
    return Path(__file__).resolve().parents[3] / "assets"


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

PALETTE = {
    # Surfaces
    "bg_window":        "#020303",
    "bg_panel":         "#050606",
    "bg_panel_inner":   "#030404",
    "bg_panel_hover":   "#0b0f10",
    "bg_table":         "#030404",
    "bg_table_alt":     "#060707",
    "bg_header":        "#020303",
    "bg_chip":          "#080a0b",

    # Lines (panel dividers — light, sitting ABOVE the textured background)
    "border_faint":     "#263139",
    "border":           "#3f4b53",
    "border_strong":    "#69737a",
    "border_focus":     "#4eb6e8",
    "grid":             "#2b353d",

    # Mint accent (live / healthy / hero)
    "mint":             "#63bf4f",
    "mint_bright":      "#78db64",
    "mint_dim":         "#3c8735",
    "mint_glow":        "#63bf4f44",

    # Info blue (section titles, INFO badges, "RTT/LOGS" labels)
    "info":             "#4db3e6",
    "info_dim":         "#6da4c3",

    # Text
    "text_primary":     "#f2f0ea",
    "text_secondary":   "#c9c4bd",
    "text_dim":         "#818b91",
    "text_inverse":     "#050708",

    # Semantic
    "warn":             "#f0bd62",
    "warn_dim":         "#8a632b",
    "error":            "#ff646a",
    "error_dim":        "#8c3034",
    "ok":               "#63bf4f",  # alias of mint for clarity
}


def c(token: str) -> str:
    """Return the hex string for *token*."""
    return PALETTE[token]


def qc(token: str, alpha: int | None = None) -> QColor:
    """Return a ``QColor`` for *token*, optionally with an alpha override."""
    color = QColor(PALETTE[token])
    if alpha is not None:
        color.setAlpha(alpha)
    return color


# ---------------------------------------------------------------------------
# Typography
# ---------------------------------------------------------------------------

FONT_CHROME_FAMILIES = '"Bahnschrift SemiCondensed", "Bahnschrift", "Segoe UI", sans-serif'
FONT_MONO_FAMILIES = '"Cascadia Mono", "Cascadia Code", "Consolas", monospace'

_CHROME_FAMILY = "Bahnschrift SemiCondensed"
_MONO_FAMILY = "Cascadia Mono"


def _resolve_family(preferred: str, fallbacks: tuple[str, ...]) -> str:
    db = QFontDatabase
    available = set(db.families())
    for name in (preferred, *fallbacks):
        if name in available:
            return name
    return preferred


def chrome_font(size: int = 11, weight: QFont.Weight = QFont.Weight.Medium) -> QFont:
    family = _resolve_family(
        _CHROME_FAMILY, ("Bahnschrift", "Segoe UI", "Arial"),
    )
    font = QFont(family, size)
    font.setWeight(weight)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return font


def mono_font(
    size: int = 11,
    weight: QFont.Weight = QFont.Weight.Normal,
) -> QFont:
    family = _resolve_family(
        _MONO_FAMILY, ("Cascadia Code", "Consolas", "Courier New"),
    )
    font = QFont(family, size)
    font.setWeight(weight)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return font


def label_font() -> QFont:
    font = mono_font(9, QFont.Weight.Medium)
    font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 110)
    font.setCapitalization(QFont.Capitalization.AllUppercase)
    return font


# ---------------------------------------------------------------------------
# Textures
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def dotted_texture() -> QPixmap:
    """Tileable dotted texture used inside panels.

    Loads the noise-enriched PNG from ``assets/panel-texture.png``. Falls
    back to a procedural grid if the asset is missing so dev environments
    without ``scripts/_extract_textures.py`` having been run still work.
    """
    path = _assets_dir() / "panel-texture.png"
    if path.exists():
        pix = QPixmap(str(path))
        if not pix.isNull():
            return pix

    # Fallback — procedural uniform grid.
    cell, dot_size, alpha = 6, 1, 150
    size = cell * 16
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(230, 236, 246, alpha))
    for y in range(0, size, cell):
        for x in range(0, size, cell):
            painter.drawRect(x, y, dot_size, dot_size)
    painter.end()
    return pixmap


@lru_cache(maxsize=16)
def flowing_dot_field(width: int, height: int) -> QPixmap:
    """Dashboard-sized halftone exposure field.

    The reference uses dots that bloom, thin out, and drift across the
    screen. A generated field avoids the wallpaper feel of a repeated tile
    while staying deterministic and cheap after the first paint.
    """
    import random

    width = max(1, int(width))
    height = max(1, int(height))

    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
    painter.setPen(Qt.PenStyle.NoPen)

    rng = random.Random(width * 73856093 ^ height * 19349663)
    cell = 5
    dot = 2

    # Anisotropic exposure lobes measured by eye from the reference. These
    # are deliberately broad and eased, so the field reads like analog
    # halftone exposure instead of a set of computer-generated blobs.
    lobes = (
        (0.45, -0.02, 0.18, 0.22, 1.35),
        (0.205, 0.23, 0.030, 0.20, 1.10),
        (0.305, 0.315, 0.15, 0.050, 0.95),
        (0.445, 0.32, 0.030, 0.19, 1.08),
        (0.505, 0.47, 0.15, 0.22, 0.68),
        (0.640, 0.90, 0.33, 0.12, 0.82),
        (0.735, 0.48, 0.13, 0.29, 0.52),
        (0.985, 0.34, 0.026, 0.25, 0.50),
    )

    for y in range(0, height, cell):
        yn = y / height
        for x in range(0, width, cell):
            xn = x / width

            energy = 0.0
            for cx, cy, sx, sy, strength in lobes:
                dx = (xn - cx) / sx
                dy = (yn - cy) / sy
                energy += strength * exp(-0.5 * (dx * dx + dy * dy))

            ridge_x = 0.435 + 0.020 * sin(yn * 10.5)
            ridge = exp(-0.5 * ((xn - ridge_x) / 0.018) ** 2)
            ridge *= exp(-0.5 * ((yn - 0.45) / 0.40) ** 2)
            energy += 0.54 * ridge

            energy *= 0.92 + 0.10 * sin((xn * 4.2 + yn * 2.6) * 3.14159)
            energy += rng.uniform(-0.030, 0.040)

            energy = max(0.0, energy)
            exposure = 1.0 - exp(-0.78 * energy)
            base = 0.020 if rng.random() > 0.30 else 0.006
            exposure = max(base, exposure) ** 1.24

            alpha = int(max(0, min(205, (5 + 168 * exposure) * rng.uniform(0.94, 1.05))))
            if alpha < 7:
                continue

            tone = int(rng.uniform(222, 246))
            painter.setBrush(QColor(tone, tone + 2, min(255, tone + 8), alpha))
            painter.drawRect(x, y, dot, dot)

    painter.end()
    return pixmap


@lru_cache(maxsize=8)
def halo_pixmap(width: int = 360, height: int = 90) -> QPixmap:
    """Perforated radial halo painted behind the brand banner.

    Loads the extracted PNG from ``assets/header-halo.png`` and scales it
    to the requested footprint. Falls back to a procedural radial gradient
    if the asset is missing.
    """
    path = _assets_dir() / "header-halo.png"
    if path.exists():
        pix = QPixmap(str(path))
        if not pix.isNull():
            return pix.scaled(
                width,
                height,
                Qt.AspectRatioMode.IgnoreAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )

    # Fallback — procedural radial halo.
    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setPen(Qt.PenStyle.NoPen)
    cx = width / 2
    cy = -height * 0.1
    gradient = QRadialGradient(QPointF(cx, cy), width * 0.55)
    gradient.setColorAt(0.0, QColor(220, 230, 240, 160))
    gradient.setColorAt(0.4, QColor(220, 230, 240, 60))
    gradient.setColorAt(1.0, QColor(220, 230, 240, 0))
    painter.setBrush(QBrush(gradient))
    painter.drawRect(0, 0, width, height)
    painter.end()
    return pixmap


@lru_cache(maxsize=4)
def panel_spotlight(width: int, height: int) -> QPixmap:
    """Backwards-compat alias; current panels use ``panel_glow`` instead."""
    return panel_glow(width, height)


@lru_cache(maxsize=64)
def panel_glow(width: int, height: int) -> QPixmap:
    """A halo-style perforated glow sized to fill an entire panel.

    Mirrors the aesthetic of the banner halo: a soft radial bloom plus a
    field of bright perforated dots whose alpha falls off with distance
    from the panel's centre. Each panel becomes its own self-contained
    "lit-from-behind" instrument.
    """
    import random

    if width <= 4 or height <= 4:
        return QPixmap(1, 1)

    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setPen(Qt.PenStyle.NoPen)

    cx = width / 2
    cy = height * 0.5
    radius = max(width, height) * 0.65

    # Step 1: soft radial bloom underneath.
    gradient = QRadialGradient(QPointF(cx, cy), radius)
    gradient.setColorAt(0.0, QColor(255, 255, 255, 70))
    gradient.setColorAt(0.45, QColor(255, 255, 255, 22))
    gradient.setColorAt(1.0, QColor(255, 255, 255, 0))
    painter.setBrush(QBrush(gradient))
    painter.drawRect(0, 0, width, height)

    # Step 2: perforated dots, brightness modulated by distance from centre.
    rng = random.Random(width * 1000 + height)
    cell = 5
    dot_size = 2
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
    for y in range(0, height, cell):
        for x in range(0, width, cell):
            dx = (x - cx) / radius
            dy = (y - cy) / radius
            d = (dx * dx + dy * dy) ** 0.5
            if d > 1.5:
                continue
            base = max(0.0, 1.0 - d * 0.85)
            noise = rng.uniform(0.45, 1.0)
            outlier = 0.25 if rng.random() < 0.05 else 0.0
            alpha = int(255 * min(1.0, base * 0.7 * noise + outlier))
            if alpha < 6:
                continue
            painter.setBrush(QColor(228, 234, 244, alpha))
            painter.drawRect(x, y, dot_size, dot_size)

    painter.end()
    return pixmap


@lru_cache(maxsize=4)
def ocean_halftone(width: int, height: int) -> QPixmap:
    """Static high-fidelity halftone "ocean swell" backdrop.

    Domain-warped layered sine waves sampled onto a fine dot grid produce
    bright specular crests over dark troughs — a calm sea of dots beneath the
    dashboard. Rendered once per size and cached, so it is effectively free to
    blit every frame at any resolution (it never animates).
    """
    width = max(1, int(width))
    height = max(1, int(height))

    pixmap = QPixmap(width, height)
    pixmap.fill(qc("bg_window"))
    if width < 4 or height < 4:
        return pixmap

    try:
        import numpy as np
    except Exception:
        return pixmap  # plain background if numpy is unavailable

    cell = 8
    max_r = 4.0
    cols = max(1, width // cell)
    rows = max(1, height // cell)
    xs = (np.arange(cols) + 0.5) * cell
    ys = (np.arange(rows) + 0.5) * cell
    aspect = width / height
    XN = xs / width
    YN = ys / height
    U, V = np.meshgrid(XN * aspect, YN)

    # Domain-warp the coordinates so the swell reads as organic water, then sum
    # a few directional sine waves into an ocean of overlapping crests.
    UU = U + 0.20 * np.sin(U * 3.1 + V * 2.3)
    VV = V + 0.15 * np.cos(U * 2.2 - V * 3.7)
    field = (
        np.sin(UU * 8.5 + VV * 3.5)
        + 0.70 * np.sin(UU * 5.0 - VV * 7.5 + 1.3)
        + 0.50 * np.sin(UU * 13.5 + VV * 9.0 + 2.1)
        + 0.32 * np.sin(UU * 21.0 - VV * 5.5 + 0.7)
    )
    B = (field - field.min()) / (field.max() - field.min() + 1e-6)
    B = B ** 1.7                       # sharpen crests into specular highlights
    B = np.maximum(B, 0.05)            # a faint dot grid survives in the troughs

    # Damp brightness where the dashboard content sits so the data stays legible.
    GXN, GYN = np.meshgrid(XN, YN)
    central = np.exp(-0.5 * (((GXN - 0.5) / 0.46) ** 2 + ((GYN - 0.52) / 0.50) ** 2))
    B = np.clip(B * (1.0 - 0.40 * central), 0.0, 1.0)

    # Vectorised colour ramp: black -> deep blue -> steel -> light blue -> warm white.
    ts = [0.0, 0.25, 0.5, 0.75, 1.0]
    rc = np.interp(B, ts, [14, 38, 90, 180, 246]).astype(int).tolist()
    gc = np.interp(B, ts, [19, 62, 132, 202, 242]).astype(int).tolist()
    bc = np.interp(B, ts, [30, 96, 168, 224, 232]).astype(int).tolist()
    Bl = B.tolist()
    xs_l = xs.tolist()
    ys_l = ys.tolist()

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setPen(Qt.PenStyle.NoPen)
    for r in range(rows):
        cy = ys_l[r]
        brow, rr, gg, cc = Bl[r], rc[r], gc[r], bc[r]
        for c in range(cols):
            rad = max(0.8, max_r * brow[c])
            painter.setBrush(QColor(rr[c], gg[c], cc[c]))
            cx = xs_l[c]
            painter.drawEllipse(cx - rad, cy - rad, rad * 2, rad * 2)

    # Seat the field with a soft bottom vignette.
    grad = QLinearGradient(0, 0, 0, height)
    grad.setColorAt(0.0, QColor(0, 0, 0, 0))
    grad.setColorAt(0.72, QColor(0, 0, 0, 18))
    grad.setColorAt(1.0, QColor(0, 0, 0, 96))
    painter.fillRect(0, 0, width, height, QBrush(grad))
    painter.end()
    return pixmap


def panel_inner_pen() -> QPen:
    pen = QPen(qc("border"))
    pen.setWidth(1)
    pen.setCosmetic(True)
    return pen


__all__ = [
    "PALETTE",
    "c",
    "qc",
    "chrome_font",
    "mono_font",
    "label_font",
    "dotted_texture",
    "flowing_dot_field",
    "halo_pixmap",
    "panel_glow",
    "panel_spotlight",
    "panel_inner_pen",
    "FONT_CHROME_FAMILIES",
    "FONT_MONO_FAMILIES",
]
