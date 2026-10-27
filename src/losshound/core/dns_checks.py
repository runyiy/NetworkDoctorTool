from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from datetime import datetime

from losshound.core.models import DnsResult

logger = logging.getLogger(__name__)

_PENDING_LOCK = threading.Lock()
# Hostnames with a resolver thread still outstanding after a timeout. Tracked
# per hostname so one stuck lookup can't fail checks for unrelated hostnames.
_PENDING_HOSTNAMES: set[str] = set()


def check_dns(hostname: str, timeout: float = 5.0) -> DnsResult:
    """Test DNS resolution for a hostname and measure timing."""
    now = datetime.now()

    start = time.perf_counter()
    result_queue: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    with _PENDING_LOCK:
        if hostname in _PENDING_HOSTNAMES:
            return DnsResult(
                hostname=hostname,
                timestamp=now,
                resolved=False,
                error="Previous DNS resolution still pending",
            )
        _PENDING_HOSTNAMES.add(hostname)

    def _resolve():
        try:
            result_queue.put((
                True,
                socket.getaddrinfo(hostname, None, socket.AF_INET),
            ))
        except BaseException as exc:
            result_queue.put((False, exc))
        finally:
            with _PENDING_LOCK:
                _PENDING_HOSTNAMES.discard(hostname)

    thread = threading.Thread(
        target=_resolve,
        name="LosshoundDNSResolver",
        daemon=True,
    )
    thread.start()

    try:
        ok, payload = result_queue.get(timeout=timeout)
    except queue.Empty:
        return DnsResult(
            hostname=hostname,
            timestamp=now,
            resolved=False,
            error="DNS resolution timed out",
        )

    if not ok:
        exc = payload
        if isinstance(exc, socket.timeout):
            return DnsResult(
                hostname=hostname,
                timestamp=now,
                resolved=False,
                error="DNS resolution timed out",
            )
        if isinstance(exc, socket.gaierror):
            logger.debug("DNS %s failed: %s", hostname, exc)
            return DnsResult(
                hostname=hostname,
                timestamp=now,
                resolved=False,
                error=str(exc),
            )
        if isinstance(exc, OSError):
            return DnsResult(
                hostname=hostname,
                timestamp=now,
                resolved=False,
                error=str(exc),
            )
        if isinstance(exc, BaseException):
            raise exc
        raise RuntimeError(str(exc))

    results = payload
    elapsed_ms = (time.perf_counter() - start) * 1000

    if results:
        resolved_ip = results[0][4][0]
        logger.debug("DNS %s -> %s (%.1f ms)", hostname, resolved_ip, elapsed_ms)
        return DnsResult(
            hostname=hostname,
            timestamp=now,
            resolved=True,
            resolved_ip=resolved_ip,
            resolution_time_ms=elapsed_ms,
        )

    return DnsResult(
        hostname=hostname,
        timestamp=now,
        resolved=False,
        error="No results returned",
    )
