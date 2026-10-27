from __future__ import annotations

import ipaddress
import re


def validate_target(target: str) -> bool:
    """Validate a target host.

    Accepts:
    - Valid IPv4 address
    - Valid IPv6 address
    - Valid RFC 1123 hostname (alphanumeric, dots, hyphens; max length 253; label max 63)

    Explicitly rejects:
    - Empty strings or spaces
    - Leading hyphen (to prevent CLI argument injection)
    - Shell metacharacters (&, |, ;, <, >, $, `, etc.)
    """
    if not target:
        return False

    target = target.strip()
    if not target:
        return False

    # Prevent CLI argument injection
    if target.startswith("-"):
        return False

    # Prevent shell metacharacters and whitespace
    if any(char in target for char in ("&", "|", ";", "<", ">", "$", "`", '"', "'", "\n", "\r", " ", "\t")):
        return False

    # Check if it is a valid IP address
    try:
        # Strip brackets if it is an IPv6 literal
        ip_str = target.strip("[]")
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        pass

    # Validate as a hostname (RFC 1123)
    if len(target) > 253:
        return False

    # Check each label in the hostname
    labels = target.split(".")
    hostname_regex = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    for label in labels:
        if not label:
            return False
        if not hostname_regex.match(label):
            return False

    return True
