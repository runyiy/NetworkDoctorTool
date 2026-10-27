"""Shared test fixtures and sample data."""

import pytest


@pytest.fixture
def mock_dashboard_interface(monkeypatch):
    """Keep dashboard UI tests independent of Windows interface discovery."""
    monkeypatch.setattr(
        "losshound.gui.dashboard._resolve_active_interface", lambda _signals: None
    )


# Sample Windows ping output (English locale, codepage 437)
PING_SUCCESS_OUTPUT = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57
Reply from 1.1.1.1: bytes=32 time=11ms TTL=57
Reply from 1.1.1.1: bytes=32 time=13ms TTL=57
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 11ms, Maximum = 13ms, Average = 12ms
"""

PING_PARTIAL_LOSS_OUTPUT = """
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=15ms TTL=118
Request timed out.
Reply from 8.8.8.8: bytes=32 time=14ms TTL=118
Request timed out.

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),
Approximate round trip times in milli-seconds:
    Minimum = 14ms, Maximum = 15ms, Average = 14ms
"""

PING_TIMEOUT_OUTPUT = """
Pinging 192.168.1.1 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),
"""

TRACERT_OUTPUT = """
Tracing route to 8.8.8.8 over a maximum of 20 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    11 ms    12 ms  10.0.0.1
  4    15 ms    14 ms    15 ms  172.16.0.1
  5    20 ms    19 ms    21 ms  8.8.8.8

Trace complete.
"""

TRACERT_INCOMPLETE_OUTPUT = """
Tracing route to 10.99.99.99 over a maximum of 5 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2    10 ms    11 ms    10 ms  10.0.0.1
  3     *        *        *     Request timed out.
  4     *        *        *     Request timed out.
  5     *        *        *     Request timed out.

Trace complete.
"""

IPCONFIG_OUTPUT = """
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : local
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Ethernet adapter vEthernet (WSL):

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 172.28.0.1
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . :
"""
