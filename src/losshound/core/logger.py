from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from losshound.core.config import _app_data_dir


def setup_logging(level: str = "INFO") -> None:
    """Configure application-wide logging."""
    log_dir = _app_data_dir()
    log_file = log_dir / "losshound.log"

    root = logging.getLogger("losshound")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    if root.handlers:
        return

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(fmt)
    root.addHandler(stderr_handler)
