"""Fail-closed boundary for legacy network modification entry points.

S1 only authorizes read-only diagnostics. There is deliberately no setting,
environment variable or privilege check that enables legacy writes. Any future
approved repair must have its own reviewed entry point and confirmation flow.
"""

from __future__ import annotations

from typing import NoReturn


class NetworkModificationDisabledError(RuntimeError):
    """A legacy entry point attempted a network or related system change."""


def reject_network_modification(operation: str) -> NoReturn:
    """Refuse a legacy mutation before permission checks or side effects."""
    raise NetworkModificationDisabledError(
        f"{operation} is unavailable: S1 permits read-only diagnostics only. "
        "No network or system setting was changed."
    )
