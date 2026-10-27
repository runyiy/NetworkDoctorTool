"""DNS server benchmarking via raw UDP queries.

Sends minimal DNS A-record query packets directly to each server on port 53,
measures round-trip time, and ranks servers by average latency.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known public DNS servers
# ---------------------------------------------------------------------------

DNS_SERVERS: dict[str, str] = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare Secondary",
    "8.8.8.8": "Google",
    "8.8.4.4": "Google Secondary",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9 Secondary",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS Secondary",
    "76.76.2.0": "Control D",
    "76.76.10.0": "Control D Secondary",
    "94.140.14.14": "AdGuard",
    "94.140.15.15": "AdGuard Secondary",
    "185.228.168.9": "CleanBrowsing",
    "76.223.122.150": "Alternate DNS",
}

# Domains used for benchmark queries.  Chosen because they are globally
# distributed, reliably answerable, and represent realistic lookups.
TEST_DOMAINS: list[str] = [
    "google.com",
    "amazon.com",
    "cloudflare.com",
    "microsoft.com",
    "github.com",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DnsBenchmarkResult:
    """Benchmark outcome for a single DNS server."""

    server: str
    name: str
    avg_ms: float
    min_ms: float
    max_ms: float
    success_rate: float  # 0.0 – 1.0


# ---------------------------------------------------------------------------
# DNS packet helpers
# ---------------------------------------------------------------------------

def build_dns_query(domain: str, query_id: int | None = None) -> bytes:
    """Build a minimal DNS A-record query packet.

    The packet consists of a 12-byte header followed by a question section.
    Only standard A (IPv4) queries are produced.

    Parameters
    ----------
    domain:
        The domain name to look up (e.g. ``"google.com"``).
    query_id:
        Optional 16-bit transaction ID.  A random one is generated if omitted.

    Returns
    -------
    bytes
        A ready-to-send DNS query packet.
    """
    if query_id is None:
        query_id = random.randint(0, 0xFFFF)

    # --- Header (12 bytes) ---
    # Flags: standard query, recursion desired (0x0100)
    flags = 0x0100
    qdcount = 1  # one question
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack(
        "!HHHHHH", query_id, flags, qdcount, ancount, nscount, arcount,
    )

    # --- Question section ---
    # Encode domain name as a sequence of length-prefixed labels.
    question = b""
    for label in domain.rstrip(".").split("."):
        encoded = label.encode("ascii")
        question += struct.pack("!B", len(encoded)) + encoded
    question += b"\x00"  # root label terminator

    # QTYPE=A (1), QCLASS=IN (1)
    question += struct.pack("!HH", 1, 1)

    return header + question


def _is_valid_dns_response(data: bytes, expected_id: int) -> bool:
    """Return *True* if *data* looks like a valid DNS response."""
    if len(data) < 12:
        return False
    resp_id, flags = struct.unpack("!HH", data[:4])
    if resp_id != expected_id:
        return False
    # QR bit (bit 15) must be 1 (response)
    if not (flags & 0x8000):
        return False
    # RCODE (bits 0-3) should be 0 (no error) or 3 (NXDOMAIN is still a
    # valid response from the server for benchmark purposes)
    rcode = flags & 0x000F
    return rcode in (0, 3)


# ---------------------------------------------------------------------------
# Single-query helper
# ---------------------------------------------------------------------------

def query_dns_server(
    server: str,
    domain: str,
    timeout: float = 2.0,
) -> float | None:
    """Send a single DNS A-record query and return the round-trip time in ms.

    Returns ``None`` if the query fails or times out.
    """
    query_id = random.randint(0, 0xFFFF)
    packet = build_dns_query(domain, query_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(1024)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if _is_valid_dns_response(data, query_id):
            return elapsed_ms

        logger.debug(
            "Invalid DNS response from %s for %s", server, domain,
        )
        return None
    except (socket.timeout, OSError) as exc:
        logger.debug(
            "DNS query to %s for %s failed: %s", server, domain, exc,
        )
        return None
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Per-server benchmark
# ---------------------------------------------------------------------------

def benchmark_server(
    server: str,
    domains: list[str] | None = None,
    rounds: int = 2,
) -> DnsBenchmarkResult:
    """Benchmark a single DNS server over multiple domains and rounds.

    Each domain is queried *rounds* times.  Results are aggregated into a
    single :class:`DnsBenchmarkResult`.

    Parameters
    ----------
    server:
        IPv4 address of the DNS server to test.
    domains:
        Domains to resolve.  Defaults to :data:`TEST_DOMAINS`.
    rounds:
        Number of resolution attempts per domain.
    """
    if domains is None:
        domains = TEST_DOMAINS

    name = DNS_SERVERS.get(server, "Custom")
    latencies: list[float] = []
    total_queries = 0

    for _round in range(rounds):
        for domain in domains:
            total_queries += 1
            result = query_dns_server(server, domain)
            if result is not None:
                latencies.append(result)

    if not latencies:
        return DnsBenchmarkResult(
            server=server,
            name=name,
            avg_ms=float("inf"),
            min_ms=float("inf"),
            max_ms=float("inf"),
            success_rate=0.0,
        )

    return DnsBenchmarkResult(
        server=server,
        name=name,
        avg_ms=sum(latencies) / len(latencies),
        min_ms=min(latencies),
        max_ms=max(latencies),
        success_rate=len(latencies) / total_queries,
    )


# ---------------------------------------------------------------------------
# Full benchmark
# ---------------------------------------------------------------------------

def benchmark_all(
    servers: list[str] | None = None,
    domains: list[str] | None = None,
    rounds: int = 2,
) -> list[DnsBenchmarkResult]:
    """Benchmark all specified (or default) DNS servers.

    Returns results sorted by average latency (fastest first).

    Parameters
    ----------
    servers:
        List of DNS server IPs.  Defaults to :data:`DNS_SERVERS` keys.
    domains:
        Domains to resolve per server.  Defaults to :data:`TEST_DOMAINS`.
    rounds:
        Resolution attempts per domain per server.
    """
    if servers is None:
        servers = list(DNS_SERVERS.keys())
    if domains is None:
        domains = TEST_DOMAINS

    logger.info(
        "Starting DNS benchmark: %d servers, %d domains, %d rounds",
        len(servers), len(domains), rounds,
    )

    results: list[DnsBenchmarkResult] = []
    for server in servers:
        logger.debug("Benchmarking DNS server %s ...", server)
        result = benchmark_server(server, domains, rounds)
        results.append(result)
        logger.info(
            "  %s (%s): avg=%.1f ms, success=%.0f%%",
            server, result.name, result.avg_ms, result.success_rate * 100,
        )

    results.sort(key=lambda r: r.avg_ms)
    return results
