"""Native ICMP echo via the Windows IcmpSendEcho API.

Replaces subprocess `ping.exe` for IPv4 literal targets: no process spawn
per probe, no locale-dependent text parsing, and RTT comes straight from
the ICMP driver. No administrator rights are required — IcmpSendEcho uses
the kernel ICMP helper, not raw sockets.

This module is transport only: it sends echoes and returns raw RTTs.
Aggregation into a PingResult lives in losshound.core.ping, shared with
the subprocess fallback path.

Follows the same interruption contract as subprocess_runner: QThread
interruption requests raise InterruptedError between probes.
"""
from __future__ import annotations

import ctypes
import logging
import socket
import struct
import sys
import time

logger = logging.getLogger(__name__)

_IP_SUCCESS = 0
_IP_REQ_TIMED_OUT = 11010

# Same payload as Windows ping.exe (32 bytes).
_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IP_OPTION_INFORMATION),
    ]


_iphlpapi = None
if sys.platform == "win32":
    try:
        _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        _iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
        _iphlpapi.IcmpCreateFile.argtypes = []
        _iphlpapi.IcmpCloseHandle.restype = ctypes.c_bool
        _iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        _iphlpapi.IcmpSendEcho.restype = ctypes.c_ulong
        _iphlpapi.IcmpSendEcho.argtypes = [
            ctypes.c_void_p,   # IcmpHandle
            ctypes.c_ulong,    # DestinationAddress (network byte order)
            ctypes.c_char_p,   # RequestData
            ctypes.c_ushort,   # RequestSize
            ctypes.c_void_p,   # RequestOptions
            ctypes.c_void_p,   # ReplyBuffer
            ctypes.c_ulong,    # ReplySize
            ctypes.c_ulong,    # Timeout (ms)
        ]
    except OSError as exc:  # pragma: no cover - iphlpapi ships with Windows
        logger.warning("iphlpapi unavailable, native ICMP disabled: %s", exc)
        _iphlpapi = None


def available() -> bool:
    """True when the native ICMP API can be used on this platform."""
    return _iphlpapi is not None


def _check_interruption() -> None:
    from PySide6.QtCore import QThread

    thread = QThread.currentThread()
    if thread and thread.isInterruptionRequested():
        raise InterruptedError("ICMP ping aborted due to thread interruption request.")


def send_echoes(
    target_ip: str,
    count: int = 4,
    timeout_ms: int = 2000,
    interval_s: float = 1.0,
) -> list[float]:
    """Send *count* ICMP echoes to an IPv4 literal and return reply RTTs in ms.

    Lost probes are simply absent from the returned list. Probes are paced
    *interval_s* apart to match ping.exe measurement semantics.

    Raises:
        InterruptedError: If QThread interruption was requested.
        OSError: If the ICMP handle cannot be created or the address is
            not a valid IPv4 literal (caller should fall back to subprocess).
    """
    if _iphlpapi is None:
        raise OSError("Native ICMP API not available")

    try:
        # inet_aton yields network byte order; unpack little-endian so the
        # in-memory u32 keeps that byte order, as IcmpSendEcho expects.
        dest = struct.unpack("<L", socket.inet_aton(target_ip))[0]
    except OSError as exc:
        raise OSError(f"Not an IPv4 literal: {target_ip!r}") from exc

    handle = _iphlpapi.IcmpCreateFile()
    if handle is None or handle == _INVALID_HANDLE_VALUE:
        raise OSError(f"IcmpCreateFile failed (error {ctypes.get_last_error()})")

    reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(_PAYLOAD) + 8
    reply_buffer = ctypes.create_string_buffer(reply_size)

    rtts: list[float] = []
    try:
        for i in range(count):
            _check_interruption()

            sent_at = time.perf_counter()
            replies = _iphlpapi.IcmpSendEcho(
                handle,
                dest,
                _PAYLOAD,
                len(_PAYLOAD),
                None,
                reply_buffer,
                reply_size,
                timeout_ms,
            )
            elapsed_ms = (time.perf_counter() - sent_at) * 1000

            if replies > 0:
                reply = ctypes.cast(
                    reply_buffer, ctypes.POINTER(_ICMP_ECHO_REPLY)
                ).contents
                if reply.Status == _IP_SUCCESS:
                    rtt = float(reply.RoundTripTime)
                    if rtt == 0.0:
                        # Driver reports whole ms; sub-ms replies (LAN/gateway)
                        # come back as 0. Use the measured wall time, capped
                        # to keep the "<1ms" meaning.
                        rtt = round(min(elapsed_ms, 0.9), 3)
                    rtts.append(rtt)
                else:
                    logger.debug(
                        "ICMP reply from %s with status %s", target_ip, reply.Status
                    )
            else:
                err = ctypes.get_last_error()
                if err != _IP_REQ_TIMED_OUT:
                    logger.debug("IcmpSendEcho to %s failed (error %s)", target_ip, err)

            # Pace probes like ping.exe (~1/s), staying interruptible.
            if i < count - 1:
                remaining = interval_s - (time.perf_counter() - sent_at)
                while remaining > 0:
                    _check_interruption()
                    time.sleep(min(0.05, remaining))
                    remaining = interval_s - (time.perf_counter() - sent_at)
    finally:
        _iphlpapi.IcmpCloseHandle(handle)

    return rtts
