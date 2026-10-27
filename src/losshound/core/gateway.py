from __future__ import annotations

import logging
import re
import subprocess
from typing import Optional

from losshound.core.windows_commands import windows_command

logger = logging.getLogger(__name__)


def detect_gateway() -> Optional[str]:
    """Detect the default gateway IP address on Windows."""
    from losshound.core.windows_network import get_active_network_interface

    active = get_active_network_interface()
    gw = active.gateway if active else _detect_via_ipconfig()
    if gw:
        logger.info("Detected gateway: %s", gw)
    else:
        logger.warning("Could not detect default gateway")
    return gw


def _detect_via_ipconfig() -> Optional[str]:
    """Parse ipconfig output to find the default gateway."""
    try:
        result = subprocess.run(
            windows_command(["ipconfig"]),
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("ipconfig failed: %s", exc)
        return None

    # Match "Default Gateway" lines with an IPv4 address
    pattern = re.compile(r"Default Gateway.*?:\s*([\d]+\.[\d]+\.[\d]+\.[\d]+)")
    candidates = pattern.findall(output)

    for gw in candidates:
        if gw != "0.0.0.0" and not gw.startswith("169.254."):
            return gw

    return None
