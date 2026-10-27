"""Small, bounded HTTP fetches for untrusted LAN device descriptions."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit


MAX_DOCUMENT_BYTES = 256 * 1024
MAX_REDIRECTS = 3
_DEVICE_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10",
))


def _device_url(url: str, device_ip: str):
    """Require a local IP literal matching the device, without DNS or credentials."""
    if any(ord(char) <= 32 or ord(char) == 127 for char in url) or "%" in device_ip:
        raise ValueError("Invalid device URL")
    device = ipaddress.ip_address(device_ip)
    if not any(device in network for network in _DEVICE_NETWORKS):
        raise ValueError("Device address must be a private or link-local LAN address")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Device URL must use HTTP(S) with an IP literal")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Device URLs must not contain credentials")
    if "%" in parsed.hostname or ipaddress.ip_address(parsed.hostname) != device:
        raise ValueError("Device URL must stay on the responding device")
    # Accessing port also rejects malformed and out-of-range ports.
    port = parsed.port
    if port == 0:
        raise ValueError("Invalid device port")
    return parsed


def _abort_socket(sock: socket.socket) -> None:
    # Interrupt slow headers/chunk framing too, not just reads between chunks.
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        sock.close()


def fetch_device_document(
    url: str, *, device_ip: str, timeout: float = 3.0,
    max_bytes: int = MAX_DOCUMENT_BYTES,
) -> bytes:
    """Fetch at most 256 KiB, following at most three same-device redirects.

    Direct IP connections bypass environment/system HTTP proxies. Self-signed
    HTTPS is accepted only for this unauthenticated local discovery operation.
    A shared deadline covers redirects and response handling; a watchdog closes
    the connected socket even if a peer drips headers or chunk framing forever.
    """
    if timeout <= 0 or max_bytes <= 0:
        raise ValueError("Fetch limits must be positive")
    deadline = time.monotonic() + timeout

    for redirect in range(MAX_REDIRECTS + 1):
        parsed = _device_url(url, device_ip)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Device download deadline exceeded")
        connection_timeout = min(remaining, 1.5)
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(
                parsed.hostname, parsed.port, timeout=connection_timeout, context=context,
            )
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname, parsed.port, timeout=connection_timeout,
            )
        watchdog = None
        try:
            connection.connect()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Device download deadline exceeded")
            connected_socket = connection.sock
            connected_socket.settimeout(min(remaining, 1.5))
            watchdog = threading.Timer(remaining, _abort_socket, (connected_socket,))
            watchdog.daemon = True
            watchdog.start()
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            connection.request("GET", target, headers={
                "User-Agent": "Losshound/1.0", "Accept-Encoding": "identity",
                "Connection": "close",
            })
            with connection.getresponse() as response:
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if not location or redirect == MAX_REDIRECTS:
                        raise ValueError("Device redirect limit exceeded or missing location")
                    url = urljoin(url, location)
                    # Validate before opening another connection; never read a redirect body.
                    _device_url(url, device_ip)
                    continue
                if not 200 <= response.status < 300:
                    raise ValueError("Device returned an unsuccessful HTTP status")
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
                    raise ValueError("Compressed device descriptions are not accepted")
                length = response.getheader("Content-Length")
                if length is not None and not 0 <= int(length) <= max_bytes:
                    raise ValueError("Device description exceeds size limit")
                body = bytearray()
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Device download deadline exceeded")
                    chunk = response.read1(min(16384, max_bytes + 1 - len(body)))
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Device download deadline exceeded")
                    if not chunk:
                        return bytes(body)
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise ValueError("Device description exceeds size limit")
        finally:
            if watchdog is not None:
                watchdog.cancel()
            connection.close()
    raise ValueError("Device redirect limit exceeded")
