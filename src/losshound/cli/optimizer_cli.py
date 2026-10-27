from __future__ import annotations


def run_optimizer_command(args):
    """Fail closed before importing any legacy dispatcher or optimizer module."""
    raise SystemExit(
        "Legacy commands are unavailable in read-only S1; "
        "use losshound --cli [--duration SECONDS]."
    )
