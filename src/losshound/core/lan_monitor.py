from __future__ import annotations

import logging
import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser
from typing import Optional, List, Dict
from urllib.parse import urlparse

from losshound.core.lan_http import fetch_device_document
from losshound.core.windows_commands import windows_command

logger = logging.getLogger(__name__)


def is_lan_scoped_ip(value: str) -> bool:
    """Return True only for IP literals that should never require internet routing."""
    try:
        addr = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False

    if addr.is_multicast or addr.is_unspecified:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def is_lan_scoped_url(url: str) -> bool:
    """Allow only HTTP(S) URLs whose host is a local IP literal, avoiding DNS lookups."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    return is_lan_scoped_ip(parsed.hostname)

# Expanded local OUI dictionary for popular manufacturers. Completely offline.
_OUI_DB = {
    # Liteon (User's device)
    "30-16-9D": "Liteon",
    
    # Apple
    "00-03-93": "Apple",
    "00-14-51": "Apple",
    "00-1C-B3": "Apple",
    "00-1D-4F": "Apple",
    "00-1E-C2": "Apple",
    "00-23-12": "Apple",
    "00-24-36": "Apple",
    "00-25-00": "Apple",
    "00-26-4A": "Apple",
    "00-26-BB": "Apple",
    "00-26-82": "Apple",
    "04-0C-CE": "Apple",
    "0C-80-63": "Apple",
    "10-DD-B1": "Apple",
    "14-10-9F": "Apple",
    "24-A0-74": "Apple",
    "28-0B-5C": "Apple",
    "28-37-37": "Apple",
    "28-5A-EB": "Apple",
    "28-CF-E9": "Apple",
    "28-E7-CF": "Apple",
    "30-35-AD": "Apple",
    "38-CA-DA": "Apple",
    "3C-07-54": "Apple",
    "40-30-04": "Apple",
    "40-8D-5C": "Apple",
    "40-A6-D9": "Apple",
    "44-00-10": "Apple",
    "44-D8-84": "Apple",
    "48-43-7C": "Apple",
    "48-D7-05": "Apple",
    "4C-7C-5F": "Apple",
    "50-BC-96": "Apple",
    "54-E4-3A": "Apple",
    "58-1F-28": "Apple",
    "58-55-CA": "Apple",
    "5C-8D-4E": "Apple",
    "5C-95-AE": "Apple",
    "5C-F9-38": "Apple",
    "60-03-08": "Apple",
    "60-30-74": "Apple",
    "60-F8-1D": "Apple",
    "64-09-80": "Apple",
    "64-70-EC": "Apple",
    "64-A3-CB": "Apple",
    "64-B9-E8": "Apple",
    "68-09-27": "Apple",
    "68-5B-35": "Apple",
    "68-AE-20": "Apple",
    "6C-40-08": "Apple",
    "6C-70-9F": "Apple",
    "6C-96-CF": "Apple",
    "70-11-24": "Apple",
    "70-3E-AC": "Apple",
    "70-CD-60": "Apple",
    "7C-D3-0A": "Apple",
    "80-E6-50": "Apple",
    "84-78-8B": "Apple",
    "84-FC-AC": "Apple",
    "88-66-A5": "Apple",
    "88-C6-63": "Apple",
    "8C-85-90": "Apple",
    "90-72-40": "Apple",
    "90-B1-1C": "Apple",
    "98-01-A7": "Apple",
    "98-CA-33": "Apple",
    "A0-18-28": "Apple",
    "A4-31-35": "Apple",
    "A4-83-E7": "Apple",
    "AC-3C-0B": "Apple",
    "AC-87-A3": "Apple",
    "B0-34-95": "Apple",
    "B4-18-D1": "Apple",
    "B4-F0-9B": "Apple",
    "B8-C7-5D": "Apple",
    "B8-E8-56": "Apple",
    "C0-84-7A": "Apple",
    "C4-2C-03": "Apple",
    "C8-69-CD": "Apple",
    "D0-03-4B": "Apple",
    "D0-D2-B0": "Apple",
    "D4-90-9C": "Apple",
    "D8-1C-79": "Apple",
    "D8-FC-93": "Apple",
    "E0-66-78": "Apple",
    "E0-F5-C6": "Apple",
    "E4-25-E9": "Apple",
    "E4-9A-DC": "Apple",
    "E8-80-2E": "Apple",
    "EC-35-86": "Apple",
    "F0-18-98": "Apple",
    "F0-B4-79": "Apple",
    "F0-C1-B1": "Apple",
    "F4-0F-24": "Apple",
    "F4-F9-51": "Apple",
    "FC-25-3F": "Apple",
    
    # Intel
    "00-A0-C9": "Intel",
    "00-1B-21": "Intel",
    "00-1C-C0": "Intel",
    "00-1E-64": "Intel",
    "00-27-10": "Intel",
    "30-52-CB": "Intel",
    "34-13-E8": "Intel",
    "34-E6-AD": "Intel",
    "3C-5C-C4": "Intel",
    "40-E2-30": "Intel",
    "48-51-B7": "Intel",
    "4C-34-88": "Intel",
    "58-94-6B": "Intel",
    "60-57-18": "Intel",
    "64-1C-AE": "Intel",
    "64-51-06": "Intel",
    "70-85-C2": "Intel",
    "70-EF-25": "Intel",
    "74-E6-B8": "Intel",
    "7C-50-79": "Intel",
    "80-86-F2": "Intel",
    "84-F3-EB": "Intel",
    "90-2E-16": "Intel",
    "94-E9-79": "Intel",
    "9C-B6-D0": "Intel",
    "A0-C5-89": "Intel",
    "AC-D1-B8": "Intel",
    "B4-8B-19": "Intel",
    "C4-9E-E2": "Intel",
    "D0-7E-35": "Intel",
    "D4-3B-04": "Intel",
    "E0-D5-5E": "Intel",
    "E4-A7-A0": "Intel",
    "EC-0E-C4": "Intel",
    "F4-37-B7": "Intel",
    "F8-E9-03": "Intel",
    "FC-F8-AE": "Intel",
    
    # Samsung
    "00-07-AB": "Samsung",
    "00-12-47": "Samsung",
    "00-12-FB": "Samsung",
    "00-17-C9": "Samsung",
    "00-1E-7D": "Samsung",
    "1C-5A-3E": "Samsung",
    "24-FC-E5": "Samsung",
    "2C-F0-A2": "Samsung",
    "38-AA-3C": "Samsung",
    "3C-5A-37": "Samsung",
    "40-F3-08": "Samsung",
    "48-2C-A0": "Samsung",
    "50-3E-AA": "Samsung",
    "50-B7-C3": "Samsung",
    "5C-0A-5B": "Samsung",
    "60-AF-6D": "Samsung",
    "64-B3-10": "Samsung",
    "78-47-1D": "Samsung",
    "78-E1-03": "Samsung",
    "84-25-3F": "Samsung",
    "8C-C8-CD": "Samsung",
    "90-18-7C": "Samsung",
    "94-65-2D": "Samsung",
    "98-0D-2E": "Samsung",
    "9C-02-98": "Samsung",
    "A4-70-D6": "Samsung",
    "A4-77-33": "Samsung",
    "AC-5F-3E": "Samsung",
    "B0-C9-43": "Samsung",
    "B8-55-10": "Samsung",
    "C4-93-D9": "Samsung",
    "C8-3A-35": "Samsung",
    "D0-17-6A": "Samsung",
    "D8-90-E8": "Samsung",
    "E4-7C-F5": "Samsung",
    "E8-E5-D6": "Samsung",
    "F0-2F-A7": "Samsung",
    "F4-7B-5E": "Samsung",
    "F8-04-2E": "Samsung",
    "FC-AA-14": "Samsung",
    
    # Google
    "00-1A-11": "Google",
    "3C-5A-37": "Google",
    "F4-F5-D8": "Google",
    "DA-E7-0D": "Google",
    "DA-A1-19": "Google",
    "E4-F0-42": "Google",
    
    # Xiaomi
    "14-7D-DA": "Xiaomi",
    "18-59-36": "Xiaomi",
    "28-6C-07": "Xiaomi",
    "34-80-B3": "Xiaomi",
    "3C-BD-3E": "Xiaomi",
    "50-EC-50": "Xiaomi",
    "58-E8-76": "Xiaomi",
    "64-09-80": "Xiaomi",
    "7C-1D-D9": "Xiaomi",
    "8C-BE-BE": "Xiaomi",
    "9C-B6-54": "Xiaomi",
    "AC-F1-DF": "Xiaomi",
    "C0-A4-4D": "Xiaomi",
    "D8-C4-6A": "Xiaomi",
    "E4-47-90": "Xiaomi",
    "F4-8B-32": "Xiaomi",
    
    # Sony
    "00-01-4A": "Sony",
    "00-04-1F": "Sony",
    "00-13-15": "Sony",
    "00-15-C1": "Sony",
    "00-1D-BA": "Sony",
    "00-1F-A7": "Sony",
    "00-24-33": "Sony",
    "08-00-46": "Sony",
    "10-08-C1": "Sony",
    "28-0D-FC": "Sony",
    "30-39-26": "Sony",
    "40-40-A7": "Sony",
    "70-9E-29": "Sony",
    "7C-6D-62": "Sony",
    "A8-E3-EE": "Sony",
    "B4-52-7E": "Sony",
    "D4-C9-3F": "Sony",
    "E4-22-FB": "Sony",
    "FC-0F-E6": "Sony",
    
    # LG Electronics
    "00-05-C9": "LG",
    "00-0E-7B": "LG",
    "00-1C-62": "LG",
    "00-1E-75": "LG",
    "00-22-A9": "LG",
    "00-26-E2": "LG",
    "10-68-3F": "LG",
    "34-4B-50": "LG",
    "58-A2-B5": "LG",
    "64-99-5D": "LG",
    "6C-D0-32": "LG",
    "70-05-14": "LG",
    "88-C9-D0": "LG",
    "94-44-44": "LG",
    "A8-23-FE": "LG",
    "BC-F5-AC": "LG",
    "E8-5B-5B": "LG",
    
    # TP-Link
    "00-1D-0F": "TP-Link",
    "14-CF-92": "TP-Link",
    "3C-84-3D": "TP-Link",
    "50-C7-BF": "TP-Link",
    "70-4F-57": "TP-Link",
    "74-DA-38": "TP-Link",
    "84-16-F9": "TP-Link",
    "8F-C1-88": "TP-Link",
    "90-F6-52": "TP-Link",
    "98-DE-D0": "TP-Link",
    "A8-57-4E": "TP-Link",
    "B0-4E-26": "TP-Link",
    "C0-25-E9": "TP-Link",
    "E8-48-B8": "TP-Link",
    "E8-94-F6": "TP-Link",
    "F4-3E-61": "TP-Link",
    
    # Realtek
    "00-E0-4C": "Realtek",
    "00-0A-F7": "Realtek",
    "00-13-D4": "Realtek",
    "52-54-00": "Realtek",
    "B8-97-5A": "Realtek",
    
    # Microsoft
    "00-03-FF": "Microsoft",
    "00-0D-3A": "Microsoft",
    "00-12-5A": "Microsoft",
    "00-15-5D": "Microsoft",
    "00-1D-D8": "Microsoft",
    "00-50-F2": "Microsoft",
    "28-18-78": "Microsoft",
    "48-50-73": "Microsoft",
    "50-1A-C5": "Microsoft",
    "60-45-BD": "Microsoft",
    "7C-1E-52": "Microsoft",
    "98-5F-D3": "Microsoft",
    
    # Asus
    "00-0E-8E": "ASUS",
    "00-11-2F": "ASUS",
    "00-15-F2": "ASUS",
    "00-1B-FC": "ASUS",
    "00-1E-8C": "ASUS",
    "00-26-18": "ASUS",
    "04-D9-F5": "ASUS",
    "10-7B-44": "ASUS",
    "1C-87-2C": "ASUS",
    "2C-56-DC": "ASUS",
    "38-D5-47": "ASUS",
    "50-46-5D": "ASUS",
    "74-D0-2B": "ASUS",
    "AC-22-0B": "ASUS",
    "D0-50-99": "ASUS",
    "D8-50-E6": "ASUS",
    "E0-3F-49": "ASUS",
    "F9-D0-AC": "ASUS",
    
    # HP
    "00-0F-20": "HP",
    "00-10-83": "HP",
    "00-17-08": "HP",
    "00-1A-4B": "HP",
    "00-1E-0B": "HP",
    "00-25-B3": "HP",
    "08-00-09": "HP",
    "1C-3B-F3": "HP",
    "3C-D9-2B": "HP",
    "66-D2-3D": "HP",
    "D8-D3-85": "HP",
    
    # Dell
    "00-14-22": "Dell",
    "00-21-70": "Dell",
    "00-23-AE": "Dell",
    "00-25-64": "Dell",
    "00-26-B9": "Dell",
    "14-18-77": "Dell",
    "18-03-73": "Dell",
    "24-B6-FD": "Dell",
    "34-17-EB": "Dell",
    "70-54-B4": "Dell",
    "B8-CA-3A": "Dell",
    "D4-BE-D9": "Dell",
    
    # Cisco
    "00-00-0C": "Cisco",
    "00-01-42": "Cisco",
    "00-01-64": "Cisco",
    "00-01-97": "Cisco",
    "00-01-C7": "Cisco",
    "00-02-16": "Cisco",
    "00-02-4A": "Cisco",
    "00-02-B9": "Cisco",
    "00-03-9F": "Cisco",
    "00-03-A0": "Cisco",
    "28-52-61": "Cisco",
    
    # Netgear
    "00-09-5B": "Netgear",
    "00-0F-B5": "Netgear",
    "00-14-6C": "Netgear",
    "00-18-4D": "Netgear",
    "00-1B-2F": "Netgear",
    "00-1E-2A": "Netgear",
    "00-22-3F": "Netgear",
    "00-24-B2": "Netgear",
    "00-26-F2": "Netgear",
    "20-4E-7F": "Netgear",
    "28-80-88": "Netgear",
    "2C-30-33": "Netgear",
    "30-46-9A": "Netgear",
    "44-94-FC": "Netgear",
    "50-6A-03": "Netgear",
    
    # Linksys
    "00-06-25": "Linksys",
    "00-0F-66": "Linksys",
    "00-18-39": "Linksys",
    "00-20-06": "Linksys",
    "00-22-6B": "Linksys",
    "00-23-69": "Linksys",
    "00-25-9C": "Linksys",
    
    # D-Link
    "00-05-5D": "D-Link",
    "00-15-E9": "D-Link",
    "00-17-9A": "D-Link",
    "00-19-5B": "D-Link",
    "00-21-91": "D-Link",
    "1C-7E-E5": "D-Link",
    "28-10-7B": "D-Link",
    
    # Raspberry Pi
    "B8-27-EB": "Raspberry Pi",
    "3A-80-DF": "Raspberry Pi",
    "D8-3A-DD": "Raspberry Pi",
    "E4-5F-01": "Raspberry Pi",
    
    # Standard Virtualization
    "00-05-69": "VMware",
    "00-0C-29": "VMware",
    "00-50-56": "VMware",
    "90-DD-5D": "VMware",
    "08-00-27": "VirtualBox",
    "00-1C-42": "Parallels",
    "00-15-5D": "Hyper-V",
}


def run_command_resilient(args: List[str]) -> str:
    """Run a subprocess command and decode its output using CP850 fallback to avoid crashes."""
    try:
        res = subprocess.run(
            windows_command(args),
            capture_output=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        # Try cp850 (standard OEM codepage on Western Windows) then utf-8, ignoring decoding errors
        try:
            return res.stdout.decode("cp850", errors="ignore")
        except Exception:
            return res.stdout.decode("utf-8", errors="ignore")
    except Exception as exc:
        logger.warning("Failed running command %s: %s", args, exc)
        return ""


def get_local_network_info() -> Dict[str, str]:
    """Get the default-route IPv4 network, with ipconfig as a fallback."""
    from losshound.core.windows_network import get_active_network_interface

    active = get_active_network_interface()
    if active:
        try:
            mask = str(
                ipaddress.IPv4Network(f"0.0.0.0/{active.prefix_length}").netmask
            )
            return {"ip": active.ipv4_address, "mask": mask}
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            logger.debug(
                "Invalid active-interface prefix: %s/%s",
                active.ipv4_address,
                active.prefix_length,
            )

    output = run_command_resilient(["ipconfig"])
    
    # We look for sections containing "IPv4 Address" and "Subnet Mask"
    ip_pattern = re.compile(r"IPv4 Address.*?:\s*([\d\.]+)")
    mask_pattern = re.compile(r"Subnet Mask.*?:\s*([\d\.]+)")
    
    ips = ip_pattern.findall(output)
    masks = mask_pattern.findall(output)
    
    result = {"ip": "", "mask": ""}
    for ip, mask in zip(ips, masks):
        # Skip APIPA (Automatic Private IP Addressing) address range
        if ip != "0.0.0.0" and not ip.startswith("169.254."):
            result["ip"] = ip
            result["mask"] = mask
            break
            
    return result


def get_subnet_ips(
    local_ip: str,
    subnet_mask: str = "",
    max_hosts: int = 254,
) -> List[str]:
    """Return local subnet host IPs, capped to avoid oversized scan bursts."""
    if not local_ip:
        return []

    if subnet_mask:
        try:
            network = ipaddress.ip_network(f"{local_ip}/{subnet_mask}", strict=False)
            hosts = [str(ip) for ip in network.hosts() if str(ip) != local_ip]
            if len(hosts) <= max_hosts:
                return hosts

            # Avoid sweeping very large office/VPN subnets. Keeping the local
            # /24 neighborhood preserves the previous upper bound.
            prefix = ".".join(local_ip.split(".")[:3]) + "."
            nearby_hosts = [ip for ip in hosts if ip.startswith(prefix)]
            return nearby_hosts[:max_hosts]
        except ValueError:
            logger.debug("Invalid subnet data for LAN scan: %s/%s", local_ip, subnet_mask)

    parts = local_ip.split(".")
    if len(parts) == 4:
        prefix = ".".join(parts[:3])
        return [
            f"{prefix}.{i}"
            for i in range(1, 255)
            if f"{prefix}.{i}" != local_ip
        ][:max_hosts]
    return []


def ping_ip(ip: str) -> None:
    """Send a single low-timeout ping to trigger ARP tables."""
    try:
        subprocess.run(
            windows_command(["ping", "-n", "1", "-w", "150", ip]),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def run_ping_sweep(ips: List[str], max_workers: int = 16) -> None:
    """Ping all subnet IPs concurrently to populate the system's ARP cache."""
    if not ips:
        return
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as executor:
        executor.map(ping_ip, ips)


def lookup_vendor(mac: str) -> str:
    """Resolve vendor name using local OUI dictionary. Completely offline and private."""
    clean_mac = mac.replace(":", "-").upper()
    prefix = clean_mac[:8]
    return _OUI_DB.get(prefix, "Unknown")


def decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode compressed labels in a DNS packet according to RFC 1035."""
    labels = []
    visited = set()
    curr = offset
    pointer_followed = False
    next_offset = -1
    
    while True:
        if curr >= len(data):
            break
        length = data[curr]
        
        # Pointer check
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[curr+1]
            if pointer in visited:
                break
            visited.add(pointer)
            if not pointer_followed:
                next_offset = curr + 2
                pointer_followed = True
            curr = pointer
            continue
            
        curr += 1
        if length == 0:
            break
            
        if curr + length > len(data):
            break
            
        label = data[curr:curr+length].decode("utf-8", errors="ignore")
        labels.append(label)
        curr += length
        
    final_offset = next_offset if pointer_followed else curr
    return ".".join(labels), final_offset


def resolve_mdns_name(ip: str) -> str:
    """Query link-local mDNS multicast (224.0.0.251:5353) to fetch the real device name."""
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
        
    rev_name = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
    
    # Standard DNS Header: ID=0, Flags=0, QDCount=1, ANCount=0, NSCount=0, ARCount=0
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    
    query = b""
    for part in rev_name.split("."):
        query += bytes([len(part)]) + part.encode("ascii")
    query += b"\x00"
    query += b"\x00\x0c\x00\x01"  # Type: PTR (12), Class: IN (1)
    
    packet = header + query
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.4)
        sock.sendto(packet, ("224.0.0.251", 5353))
        
        # Read matching response (try up to 3 responses)
        for _ in range(3):
            data, _ = sock.recvfrom(1500)
            if len(data) < 12:
                continue
                
            qdcount = (data[4] << 8) | data[5]
            ancount = (data[6] << 8) | data[7]
            
            if ancount == 0:
                continue
                
            offset = 12
            for _ in range(qdcount):
                _, offset = decode_dns_name(data, offset)
                offset += 4  # Skip Type & Class
                
            for _ in range(ancount):
                if offset >= len(data):
                    break
                _, offset = decode_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                ans_type = (data[offset] << 8) | data[offset+1]
                rdlength = (data[offset+8] << 8) | data[offset+9]
                offset += 10
                
                if offset + rdlength > len(data):
                    break
                    
                if ans_type == 12:  # PTR Record type
                    host, _ = decode_dns_name(data, offset)
                    if host.endswith(".local"):
                        host = host[:-6]
                    if host:
                        return host
                offset += rdlength
    except Exception:
        pass
    finally:
        if sock:
            sock.close()
            
    # Regex fallback search inside raw payload for safety
    try:
        if "data" in locals() and len(data) > 0:
            text = data.decode("ascii", errors="ignore")
            matches = re.findall(r"([a-zA-Z0-9\-]+)\.local", text)
            if matches:
                return matches[0]
    except Exception:
        pass
        
    return ""


def resolve_netbios_name(ip: str) -> str:
    """Attempt to resolve hostname of an IP via a UDP NetBIOS Node Status query on port 137."""
    query = (
        b"\x85\x7e"  # Transaction ID
        b"\x00\x00"  # Flags
        b"\x00\x01"  # Questions
        b"\x00\x00"  # Answer RRs
        b"\x00\x00"  # Authority RRs
        b"\x00\x00"  # Additional RRs
        b"\x20"      # Name length (32)
        b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # "*" padded wildcard representation
        b"\x00"      # Name terminator
        b"\x00\x21"  # Type: NBSTAT
        b"\x00\x01"  # Class: IN
    )
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.4)
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        
        if len(data) < 57:
            return ""
            
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name = data[offset:offset+15].strip().decode("ascii", errors="ignore")
            name_type = data[offset+15]
            if name_type == 0x00:  # Workstation name
                return name.strip()
            offset += 18
    except Exception:
        pass
    finally:
        if sock:
            sock.close()
    return ""


def resolve_llmnr_name(ip: str) -> str:
    """Query link-local LLMNR multicast (224.0.0.252:5355) to fetch the real device name."""
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
        
    rev_name = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
    
    # Standard LLMNR Header: ID=0x1234, Flags=0, QDCount=1, ANCount=0, NSCount=0, ARCount=0
    header = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    
    query = b""
    for part in rev_name.split("."):
        query += bytes([len(part)]) + part.encode("ascii")
    query += b"\x00"
    query += b"\x00\x0c\x00\x01"  # Type: PTR (12), Class: IN (1)
    
    packet = header + query
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.4)
        sock.sendto(packet, ("224.0.0.252", 5355))

        # Read matching response (try up to 3 responses)
        for _ in range(3):
            data, _ = sock.recvfrom(1500)
            if len(data) < 12:
                continue

            # Verify response ID matches our query (0x1234) to avoid stray LLMNR traffic
            if data[0] != 0x12 or data[1] != 0x34:
                continue

            qdcount = (data[4] << 8) | data[5]
            ancount = (data[6] << 8) | data[7]

            if ancount == 0:
                continue
                
            offset = 12
            for _ in range(qdcount):
                _, offset = decode_dns_name(data, offset)
                offset += 4  # Skip Type & Class
                
            for _ in range(ancount):
                if offset >= len(data):
                    break
                _, offset = decode_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                ans_type = (data[offset] << 8) | data[offset+1]
                rdlength = (data[offset+8] << 8) | data[offset+9]
                offset += 10
                
                if offset + rdlength > len(data):
                    break
                    
                if ans_type == 12:  # PTR Record type
                    host, _ = decode_dns_name(data, offset)
                    if host:
                        return host
                offset += rdlength
    except Exception:
        pass
    finally:
        if sock:
            sock.close()

    return ""


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title_parts = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False


_META_REFRESH_RE = re.compile(
    r'<meta\s+[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'>\s]+)',
    re.IGNORECASE,
)


def _extract_title(html: str) -> str:
    parser = TitleParser()
    try:
        parser.feed(html)
    except Exception:
        return ""
    title = "".join(parser.title_parts).strip()
    return " ".join(title.split()) if title else ""


def _fetch_html(url: str, device_ip: str) -> str:
    html_bytes = fetch_device_document(url, device_ip=device_ip)
    try:
        return html_bytes.decode("utf-8")
    except Exception:
        return html_bytes.decode("cp850", errors="ignore")


def resolve_http_title(ip: str) -> str:
    """Fetch HTTP/HTTPS root, extract <title>, follow one meta-refresh hop if root has none.

    Many routers serve a tiny meta-refresh stub at / that redirects to the real
    UI page; following that redirect once lets us pick up a real title instead
    of falling back to a vendor label.
    """
    if not is_lan_scoped_ip(ip):
        return ""

    for proto in ["http", "https"]:
        try:
            base_url = f"{proto}://{ip}/"
            html = _fetch_html(base_url, ip)
        except Exception:
            continue

        title = _extract_title(html)
        if title:
            return title

        # Root had no <title>; follow at most one same-host meta-refresh hop.
        match = _META_REFRESH_RE.search(html)
        if not match:
            continue

        target = match.group(1).strip().strip('"\'')
        # Only follow same-host paths to avoid being redirected to a public site.
        try:
            from urllib.parse import urljoin, urlparse
            absolute = urljoin(base_url, target)
            parsed = urlparse(absolute)
            if parsed.hostname != ip:
                continue
            html2 = _fetch_html(absolute, ip)
        except Exception:
            continue

        title2 = _extract_title(html2)
        if title2:
            return title2

    return ""


def scan_ssdp() -> Dict[str, str]:
    """Broadcast SSDP M-SEARCH and fetch only LAN-scoped location XML friendly names."""
    ip_to_name = {}
    
    query = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    
    sock = None
    locations = {}  # ip -> xml_url
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(query.encode("ascii"), ("239.255.255.250", 1900))

        for _ in range(50):
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            except Exception:
                # Skip malformed packet from one device, keep scanning others
                continue

            try:
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")

                loc_match = re.search(r"LOCATION:\s*([^\r\n]+)", text, re.IGNORECASE)
                if loc_match:
                    url = loc_match.group(1).strip()
                    if is_lan_scoped_url(url):
                        locations[ip] = url
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if sock:
            sock.close()
            
    if locations:
        def fetch_friendly_name(ip_url_tuple):
            ip, url = ip_url_tuple
            try:
                xml = fetch_device_document(url, device_ip=ip, timeout=2.0).decode("utf-8", errors="ignore")
                fn_match = re.search(r"<friendlyName>([^<]+)</friendlyName>", xml, re.IGNORECASE)
                if fn_match:
                    return ip, fn_match.group(1).strip()
                mn_match = re.search(r"<modelName>([^<]+)</modelName>", xml, re.IGNORECASE)
                if mn_match:
                    return ip, mn_match.group(1).strip()
            except Exception:
                pass
            return ip, None
            
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(fetch_friendly_name, locations.items())
            for ip, name in results:
                if name:
                    ip_to_name[ip] = name
                    
    return ip_to_name


def resolve_hostname_safe(ip: str) -> str:
    """Resolve IP to hostname using LAN-only mDNS, LLMNR, then NetBIOS probes."""
    if not is_lan_scoped_ip(ip):
        return ""

    # mDNS
    mdns_name = resolve_mdns_name(ip)
    if mdns_name:
        return mdns_name
        
    # LLMNR
    llmnr_name = resolve_llmnr_name(ip)
    if llmnr_name:
        return llmnr_name
        
    # NetBIOS
    nb_name = resolve_netbios_name(ip)
    if nb_name:
        return nb_name
        
    return ""


def parse_arp_table(local_ip: str) -> List[Dict[str, str]]:
    """Parse the system's ARP table to find connected devices, ignoring broadcast/multicast."""
    output = run_command_resilient(["arp", "-a"])
    
    # Matches dynamic or static entry: IP physical-address type
    # e.g., 192.168.1.1           1c-3b-f3-ea-bb-cc     dynamic
    pattern = re.compile(
        r"^\s*([\d\.]+)\s+([0-9a-fA-F\-:]{17})\s+(\w+)", re.MULTILINE
    )
    matches = pattern.findall(output)
    
    devices = []
    seen_macs = set()
    
    for ip, mac, entry_type in matches:
        clean_mac = mac.replace(":", "-").upper()
        
        # Skip self, broadcast and multicast entries
        if ip == local_ip:
            continue
        if clean_mac == "FF-FF-FF-FF-FF-FF":
            continue
        if clean_mac.startswith("01-00-5E"):  # IPv4 multicast
            continue
        if ip.startswith("224.") or ip.startswith("239."):
            continue
        if ip.endswith(".255"):
            continue
            
        if clean_mac not in seen_macs:
            seen_macs.add(clean_mac)
            devices.append({
                "ip": ip,
                "mac": clean_mac,
                "type": entry_type,
            })
            
    return devices


def scan_local_network(history_store=None, enable_http_scan: bool = False) -> List[Dict[str, str]]:
    """Perform a full LAN scan: sweeps subnet, parses ARP table, resolves hostnames & vendors."""
    net_info = get_local_network_info()
    local_ip = net_info["ip"]
    
    if not local_ip:
        logger.warning("Could not identify local IP for scanning")
        return []
        
    logger.info("Starting LAN scan on interface: %s", local_ip)
    
    # Sweep subnet and run SSDP discovery concurrently
    ips = get_subnet_ips(local_ip, net_info.get("mask", ""))
    
    ssdp_names = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        sweep_future = executor.submit(run_ping_sweep, ips)
        ssdp_future = executor.submit(scan_ssdp)
        
        sweep_future.result()
        try:
            ssdp_names = ssdp_future.result()
        except Exception as exc:
            logger.warning("SSDP scan failed during sweep: %s", exc)
            
    # Parse ARP cache
    raw_devices = parse_arp_table(local_ip)
    
    # Resolve details in parallel
    def resolve_device_details(dev: Dict[str, str]) -> Dict[str, str]:
        ip = dev["ip"]
        mac = dev["mac"]
        vendor = lookup_vendor(mac)
        
        # Priority 1: SSDP Friendly Name
        hostname = ssdp_names.get(ip, "")
        
        # Priority 2: DNS / mDNS / LLMNR / NetBIOS hostname
        if not hostname:
            hostname = resolve_hostname_safe(ip)
            
        # Priority 3: HTTP page title
        if not hostname and enable_http_scan:
            hostname = resolve_http_title(ip)
            
        # Priority 4: Fallback to vendor or generic label
        if not hostname:
            if vendor and vendor != "Unknown":
                hostname = f"{vendor} Device"
            else:
                hostname = "Local Network Device"
        
        return {
            "mac_address": mac,
            "ip_address": ip,
            "hostname": hostname,
            "vendor": vendor,
        }
        
    with ThreadPoolExecutor(max_workers=16) as executor:
        resolved_devices = list(executor.map(resolve_device_details, raw_devices))
        
    if history_store:
        # Check database for alerts on new devices
        existing_devices = {d["mac_address"]: d for d in history_store.get_devices()}
        try:
            with history_store._conn:
                history_store.set_all_devices_inactive(commit=False)
                
                for dev in resolved_devices:
                    mac = dev["mac_address"]
                    ip = dev["ip_address"]
                    hostname = dev["hostname"]
                    vendor = dev["vendor"]
                    
                    # Check if this MAC was never seen before
                    if mac not in existing_devices:
                        # Log an alert in the database
                        title = "New LAN Device Detected"
                        msg = f"Device '{hostname or 'Unknown'}' ({ip}) with MAC {mac} ({vendor}) joined the network."
                        history_store.save_alert(
                            timestamp=datetime.now(),
                            category="lan_issue",
                            severity="warning",
                            title=title,
                            message=msg,
                            commit=False
                        )
                        
                    history_store.save_device(
                        mac=mac,
                        ip=ip,
                        hostname=hostname,
                        vendor=vendor,
                        commit=False
                    )
        except Exception as exc:
            logger.exception("Failed to save discovered devices to history store in batch transaction: %s", exc)
            
    return resolved_devices
