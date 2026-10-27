"""WiFi diagnostics — channel scan, signal quality, and interference detection.

Uses ``netsh wlan`` commands available on all WiFi-capable Windows machines.
No admin privileges required for most operations.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from losshound.core.subprocess_runner import run_subprocess_interruptible

logger = logging.getLogger(__name__)

@dataclass
class _CommandResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


def _run(cmd: list[str], timeout: float = 15) -> _CommandResult:
    """Run netsh directly, decoding its Windows OEM output without a shell."""
    try:
        stdout, stderr, returncode = run_subprocess_interruptible(
            cmd,
            timeout,
            encoding="oem",
        )
        return _CommandResult(stdout=stdout, stderr=stderr, returncode=returncode)
    except subprocess.TimeoutExpired:
        return _CommandResult(
            stderr=f"Command timed out after {timeout} seconds",
            returncode=124,
        )


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class WifiNetwork:
    """A visible WiFi network from a scan."""

    ssid: str
    signal_pct: int           # 0-100%
    channel: int
    frequency_ghz: float      # 2.4 or 5.0
    band: str                 # "2.4GHz" or "5GHz"
    auth: str                 # e.g. "WPA2-Personal"
    bssid: str = ""
    radio_type: str = ""      # e.g. "802.11ax"


@dataclass
class WifiInterface:
    """Current WiFi adapter state."""

    name: str
    state: str                # "connected", "disconnected"
    ssid: str
    bssid: str
    channel: int
    signal_pct: int
    speed_mbps: float
    radio_type: str
    auth: str
    band: str = ""
    frequency_ghz: float = 0.0


@dataclass
class ChannelCongestion:
    """Congestion analysis for a single channel."""

    channel: int
    band: str
    network_count: int
    avg_signal: float
    strongest_signal: int
    networks: list[str]       # SSIDs on this channel


@dataclass
class WifiDiagReport:
    """Complete WiFi diagnostics report."""

    interface: Optional[WifiInterface]
    visible_networks: list[WifiNetwork]
    channel_congestion: list[ChannelCongestion]
    current_channel_rank: int     # 1 = least congested
    recommended_channel: int
    recommendation: str           # human-readable advice
    signal_quality: str           # "Excellent", "Good", "Fair", "Poor", "Bad"
    issues: list[str]             # detected problems


# ---------------------------------------------------------------------------
# Channel / frequency helpers
# ---------------------------------------------------------------------------

_CHANNEL_FREQ = {
    # 2.4 GHz
    1: 2.412, 2: 2.417, 3: 2.422, 4: 2.427, 5: 2.432,
    6: 2.437, 7: 2.442, 8: 2.447, 9: 2.452, 10: 2.457,
    11: 2.462, 12: 2.467, 13: 2.472, 14: 2.484,
    # 5 GHz (common)
    36: 5.180, 40: 5.200, 44: 5.220, 48: 5.240,
    52: 5.260, 56: 5.280, 60: 5.300, 64: 5.320,
    100: 5.500, 104: 5.520, 108: 5.540, 112: 5.560,
    116: 5.580, 120: 5.600, 124: 5.620, 128: 5.640,
    132: 5.660, 136: 5.680, 140: 5.700, 144: 5.720,
    149: 5.745, 153: 5.765, 157: 5.785, 161: 5.805, 165: 5.825,
}

# 2.4GHz channels that overlap with a given channel (20MHz bandwidth)
_24GHZ_OVERLAP = {
    1:  [1, 2, 3, 4, 5],
    2:  [1, 2, 3, 4, 5, 6],
    3:  [1, 2, 3, 4, 5, 6, 7],
    4:  [1, 2, 3, 4, 5, 6, 7, 8],
    5:  [1, 2, 3, 4, 5, 6, 7, 8, 9],
    6:  [2, 3, 4, 5, 6, 7, 8, 9, 10],
    7:  [3, 4, 5, 6, 7, 8, 9, 10, 11],
    8:  [4, 5, 6, 7, 8, 9, 10, 11],
    9:  [5, 6, 7, 8, 9, 10, 11],
    10: [6, 7, 8, 9, 10, 11],
    11: [7, 8, 9, 10, 11],
}


def _channel_from_freq(freq_mhz: int) -> int:
    """Convert frequency in MHz to channel number."""
    if 2400 <= freq_mhz <= 2500:
        return round((freq_mhz - 2407) / 5)
    if 5000 <= freq_mhz <= 5900:
        return round((freq_mhz - 5000) / 5)
    return 0


def _band_from_channel(ch: int) -> str:
    return "2.4GHz" if ch <= 14 else "5GHz"


def _freq_from_channel(ch: int) -> float:
    return _CHANNEL_FREQ.get(ch, 0.0)


def _signal_quality(pct: int) -> str:
    if pct >= 80:
        return "Excellent"
    if pct >= 60:
        return "Good"
    if pct >= 40:
        return "Fair"
    if pct >= 20:
        return "Poor"
    return "Bad"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def get_wifi_interface() -> Optional[WifiInterface]:
    """Read current WiFi adapter state via ``netsh wlan show interfaces``."""
    try:
        proc = _run(["netsh", "wlan", "show", "interfaces"])
        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        text = proc.stdout
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                fields[key.strip().lower()] = val.strip()

        state = fields.get("state", "unknown")
        ssid = fields.get("ssid", "")
        bssid = fields.get("bssid", "")
        signal_str = fields.get("signal", "0%").replace("%", "")
        channel_str = fields.get("channel", "0")
        speed_str = fields.get("receive rate (mbps)", "0")
        radio = fields.get("radio type", "")
        auth = fields.get("authentication", "")
        name = fields.get("name", "Wi-Fi")

        signal = int(signal_str) if signal_str.isdigit() else 0
        channel = int(channel_str) if channel_str.isdigit() else 0

        # Parse speed — may have decimal
        try:
            speed = float(speed_str)
        except ValueError:
            speed = 0.0

        return WifiInterface(
            name=name,
            state=state.lower(),
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            signal_pct=signal,
            speed_mbps=speed,
            radio_type=radio,
            auth=auth,
            band=_band_from_channel(channel),
            frequency_ghz=_freq_from_channel(channel),
        )
    except InterruptedError:
        raise
    except Exception as exc:
        logger.warning("Failed to get WiFi interface: %s", exc)
        return None


def scan_networks() -> list[WifiNetwork]:
    """Scan for visible WiFi networks via ``netsh wlan show networks mode=bssid``."""
    try:
        proc = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        if proc.returncode != 0:
            return []

        networks: list[WifiNetwork] = []
        current: dict[str, str] = {}

        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("SSID") and ":" in stripped and "BSSID" not in stripped:
                # Start of a new network — save previous if any
                if current.get("ssid") is not None:
                    networks.append(_parse_network(current))
                current = {}
                _, _, val = stripped.partition(":")
                current["ssid"] = val.strip()
            elif ":" in stripped:
                key, _, val = stripped.partition(":")
                current[key.strip().lower()] = val.strip()

        # Don't forget the last one
        if current.get("ssid") is not None:
            networks.append(_parse_network(current))

        return networks
    except InterruptedError:
        raise
    except Exception as exc:
        logger.warning("WiFi scan failed: %s", exc)
        return []


def _parse_network(fields: dict[str, str]) -> WifiNetwork:
    """Parse a single network block into a WifiNetwork."""
    ssid = fields.get("ssid", "(hidden)")
    signal_str = fields.get("signal", "0%").replace("%", "")
    signal = int(signal_str) if signal_str.isdigit() else 0

    channel_str = fields.get("channel", "0")
    channel = int(channel_str) if channel_str.isdigit() else 0

    bssid = fields.get("bssid", "")
    radio = fields.get("radio type", "")
    auth = fields.get("authentication", "")

    band = _band_from_channel(channel)
    freq = _freq_from_channel(channel)

    return WifiNetwork(
        ssid=ssid or "(hidden)",
        signal_pct=signal,
        channel=channel,
        frequency_ghz=freq,
        band=band,
        auth=auth,
        bssid=bssid,
        radio_type=radio,
    )


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_channel_congestion(
    networks: list[WifiNetwork],
) -> list[ChannelCongestion]:
    """Group networks by channel and compute congestion metrics."""
    by_channel: dict[int, list[WifiNetwork]] = {}
    for net in networks:
        by_channel.setdefault(net.channel, []).append(net)

    results: list[ChannelCongestion] = []
    for ch in sorted(by_channel.keys()):
        nets = by_channel[ch]
        signals = [n.signal_pct for n in nets]
        results.append(ChannelCongestion(
            channel=ch,
            band=_band_from_channel(ch),
            network_count=len(nets),
            avg_signal=sum(signals) / len(signals),
            strongest_signal=max(signals),
            networks=[n.ssid for n in nets],
        ))

    # Sort by congestion (most congested first)
    results.sort(key=lambda c: (-c.network_count, -c.avg_signal))
    return results


def find_best_channel(
    networks: list[WifiNetwork],
    current_band: str = "2.4GHz",
) -> int:
    """Recommend the least congested channel for the given band.

    For 2.4GHz considers overlapping channels (only 1, 6, 11 are
    non-overlapping).  For 5GHz each channel is independent.
    """
    if current_band == "2.4GHz":
        candidates = [1, 6, 11]
    else:
        # Common 5GHz channels
        candidates = [36, 40, 44, 48, 149, 153, 157, 161]

    band_networks = [n for n in networks if n.band == current_band]

    # Score each candidate: lower = less interference
    scores: dict[int, float] = {}
    for ch in candidates:
        interference = 0.0
        if current_band == "2.4GHz":
            overlapping = _24GHZ_OVERLAP.get(ch, [ch])
            for net in band_networks:
                if net.channel in overlapping:
                    interference += net.signal_pct / 100.0
        else:
            for net in band_networks:
                if net.channel == ch:
                    interference += net.signal_pct / 100.0
        scores[ch] = interference

    if not scores:
        return candidates[0]

    return min(scores, key=scores.get)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Full diagnosis
# ---------------------------------------------------------------------------

def run_wifi_diagnostics() -> WifiDiagReport:
    """Run a complete WiFi diagnostic scan and return a report."""
    interface = get_wifi_interface()
    networks = scan_networks()
    congestion = analyze_channel_congestion(networks)

    issues: list[str] = []
    recommendation = ""
    recommended_channel = 0
    current_rank = 0
    sig_quality = "Unknown"

    if interface is None:
        issues.append("No WiFi adapter detected or WiFi is disabled")
        return WifiDiagReport(
            interface=None,
            visible_networks=networks,
            channel_congestion=congestion,
            current_channel_rank=0,
            recommended_channel=0,
            recommendation="No WiFi adapter found. Connect to WiFi or check adapter.",
            signal_quality="Unknown",
            issues=issues,
        )

    if interface.state != "connected":
        issues.append(f"WiFi adapter is {interface.state}, not connected")

    # Signal quality
    sig_quality = _signal_quality(interface.signal_pct)
    if interface.signal_pct < 40:
        issues.append(
            f"Weak signal ({interface.signal_pct}%) — move closer to the router "
            f"or reduce obstructions"
        )
    elif interface.signal_pct < 60:
        issues.append(
            f"Moderate signal ({interface.signal_pct}%) — consider repositioning"
        )

    # Channel congestion analysis
    current_band = interface.band or "2.4GHz"
    recommended_channel = find_best_channel(networks, current_band)

    # Count networks on same channel
    same_channel = [n for n in networks if n.channel == interface.channel]
    same_channel_count = len(same_channel) - 1  # exclude self

    if current_band == "2.4GHz":
        overlapping = _24GHZ_OVERLAP.get(interface.channel, [interface.channel])
        overlapping_nets = [n for n in networks if n.channel in overlapping]
        overlap_count = len(overlapping_nets) - 1  # exclude self

        if overlap_count >= 8:
            issues.append(
                f"Heavy interference: {overlap_count} networks overlap with "
                f"channel {interface.channel}"
            )
        elif overlap_count >= 4:
            issues.append(
                f"Moderate interference: {overlap_count} networks overlap with "
                f"channel {interface.channel}"
            )

        if interface.channel not in (1, 6, 11):
            issues.append(
                f"Channel {interface.channel} is not a non-overlapping channel. "
                f"Best 2.4GHz channels are 1, 6, or 11"
            )

    if same_channel_count >= 5:
        issues.append(
            f"{same_channel_count} other networks share channel {interface.channel}"
        )

    # Rank current channel
    band_congestion = [c for c in congestion if c.band == current_band]
    sorted_by_count = sorted(band_congestion, key=lambda c: c.network_count)
    for i, c in enumerate(sorted_by_count):
        if c.channel == interface.channel:
            current_rank = i + 1
            break

    # 5GHz recommendation
    has_5ghz = any(n.band == "5GHz" for n in networks)
    if current_band == "2.4GHz" and has_5ghz and same_channel_count >= 3:
        issues.append(
            "Consider switching to 5GHz band for less interference "
            "and higher throughput (shorter range)"
        )

    # Build recommendation
    if recommended_channel == interface.channel:
        recommendation = (
            f"You're already on the best channel ({interface.channel}) "
            f"for {current_band}."
        )
    else:
        recommendation = (
            f"Switch from channel {interface.channel} to channel "
            f"{recommended_channel} on your router for less interference."
        )

    if not issues:
        recommendation += " Your WiFi looks healthy."

    return WifiDiagReport(
        interface=interface,
        visible_networks=networks,
        channel_congestion=congestion,
        current_channel_rank=current_rank,
        recommended_channel=recommended_channel,
        recommendation=recommendation,
        signal_quality=sig_quality,
        issues=issues,
    )


# ---------------------------------------------------------------------------
# CLI formatting
# ---------------------------------------------------------------------------

def format_wifi_report(report: WifiDiagReport) -> str:
    """Format a WiFi diagnostics report for terminal display."""
    lines: list[str] = []
    lines.append("WIFI DIAGNOSTICS")
    lines.append("=" * 65)

    if report.interface:
        iface = report.interface
        lines.append("")
        lines.append("  YOUR CONNECTION")
        lines.append(f"    SSID:         {iface.ssid}")
        lines.append(f"    Signal:       {iface.signal_pct}% ({report.signal_quality})")
        lines.append(f"    Channel:      {iface.channel} ({iface.band})")
        lines.append(f"    Speed:        {iface.speed_mbps:.0f} Mbps")
        lines.append(f"    Radio:        {iface.radio_type}")
        lines.append(f"    Auth:         {iface.auth}")
    else:
        lines.append("")
        lines.append("  No WiFi adapter detected.")

    # Visible networks
    if report.visible_networks:
        lines.append("")
        lines.append(f"  VISIBLE NETWORKS ({len(report.visible_networks)})")
        lines.append(f"  {'SSID':<24} {'Signal':<8} {'Ch':<5} {'Band':<8} {'Radio':<12}")
        lines.append(f"  {'-'*24} {'-'*8} {'-'*5} {'-'*8} {'-'*12}")
        # Sort by signal strength
        sorted_nets = sorted(report.visible_networks, key=lambda n: -n.signal_pct)
        for n in sorted_nets[:20]:  # top 20
            lines.append(
                f"  {n.ssid[:23]:<24} {n.signal_pct:>3}%    "
                f"{n.channel:<5} {n.band:<8} {n.radio_type:<12}"
            )

    # Channel congestion
    if report.channel_congestion:
        lines.append("")
        lines.append("  CHANNEL CONGESTION")
        lines.append(f"  {'Channel':<10} {'Band':<8} {'Networks':<10} {'Avg Signal':<12}")
        lines.append(f"  {'-'*10} {'-'*8} {'-'*10} {'-'*12}")
        for c in report.channel_congestion:
            marker = " <-- you" if (report.interface and c.channel == report.interface.channel) else ""
            lines.append(
                f"  {c.channel:<10} {c.band:<8} {c.network_count:<10} "
                f"{c.avg_signal:>5.0f}%{marker}"
            )

    # Issues
    if report.issues:
        lines.append("")
        lines.append("  ISSUES DETECTED")
        for issue in report.issues:
            lines.append(f"    [!] {issue}")

    # Recommendation
    lines.append("")
    lines.append(f"  RECOMMENDATION: {report.recommendation}")
    lines.append("")

    return "\n".join(lines)
