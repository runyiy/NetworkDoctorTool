from __future__ import annotations

import csv
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, wait
from io import StringIO
from typing import List, Dict, Set

from losshound.core.lan_monitor import run_command_resilient, resolve_hostname_safe, is_lan_scoped_ip

logger = logging.getLogger(__name__)

# Local hostname cache to avoid repeated slow lookups
_HOSTNAME_CACHE: Dict[str, str] = {}
_HOSTNAME_LOOKUP_TIMEOUT_SECONDS = 1.0
_MAX_HOSTNAME_LOOKUP_WORKERS = 4
_MAX_HOSTNAME_LOOKUPS_PER_REFRESH = 8


def resolve_connection_hostname(ip: str) -> str:
    """Resolve IP address to name. If LAN-scoped, use LAN local resolution. Otherwise, use public DNS reverse lookup."""
    if is_lan_scoped_ip(ip):
        return resolve_hostname_safe(ip)
        
    # Public IP: do standard DNS reverse lookup
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname:
            return hostname
    except Exception:
        pass
    return ""


def get_pid_to_process_name() -> Dict[int, str]:
    """Get mapping of PID to process name using Windows tasklist."""
    output = run_command_resilient(["tasklist", "/FO", "CSV", "/NH"])
    pid_map = {}
    
    if not output:
        return pid_map
        
    try:
        reader = csv.reader(StringIO(output.strip()))
        for row in reader:
            if len(row) >= 2:
                name = row[0]
                try:
                    pid = int(row[1])
                    pid_map[pid] = name
                except ValueError:
                    continue
    except Exception as exc:
        logger.warning("Error parsing tasklist output: %s", exc)
        
    return pid_map


def get_active_connections() -> List[Dict[str, str]]:
    """Parse netstat -ano to find active external connections."""
    output = run_command_resilient(["netstat", "-ano"])
    
    # Matches TCP/UDP connections
    # Proto  Local Address          Foreign Address        State           PID
    # TCP    192.168.1.5:54321      142.250.74.46:443      ESTABLISHED     4888
    # UDP    0.0.0.0:5353           *:*                                    2140
    pattern = re.compile(
        r"^\s*(TCP|UDP)\s+(\S+)\s+(\S+)(?:\s+([A-Z_]+))?\s+(\d+)\s*$", re.IGNORECASE
    )
    
    pid_map = get_pid_to_process_name()
    connections = []
    
    # We resolve hostnames of unique remote IPs in a thread pool to avoid GUI freeze
    unique_ips: Set[str] = set()
    
    lines = output.splitlines()
    for line in lines:
        match = pattern.match(line)
        if not match:
            continue
            
        proto = match.group(1).upper()
        local_addr = match.group(2)
        remote_addr = match.group(3)
        state = match.group(4) or ""
        pid_str = match.group(5)
        
        try:
            pid = int(pid_str)
        except ValueError:
            continue
            
        # Parse remote IP and port
        if ":" in remote_addr:
            remote_ip, _, remote_port = remote_addr.rpartition(":")
            remote_ip = remote_ip.strip("[]")
        else:
            remote_ip = remote_addr
            remote_port = ""
            
        # Filter out listening, loopback, and broadcast addresses
        if remote_ip in ("0.0.0.0", "[::]", "::", "*", "127.0.0.1", "::1", "[::1]", ""):
            continue
        if remote_port in ("*", "0") or not remote_port or state == "LISTENING":
            continue
            
        proc_name = pid_map.get(pid, "Unknown")
        
        # Track unique remote IPs for hostname lookup
        if remote_ip not in _HOSTNAME_CACHE:
            unique_ips.add(remote_ip)
            
        connections.append({
            "process": proc_name,
            "pid": str(pid),
            "protocol": proto,
            "local_address": local_addr,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
        })
        
    # Resolve a small batch of newly seen remote IPs. The executor is
    # intentionally not used as a context manager: after the timeout, the
    # caller should get results promptly instead of waiting on slow DNS.
    if unique_ips:
        lookup_ips = sorted(unique_ips)[:_MAX_HOSTNAME_LOOKUPS_PER_REFRESH]
        for ip in unique_ips - set(lookup_ips):
            _HOSTNAME_CACHE[ip] = ip

        executor = ThreadPoolExecutor(
            max_workers=min(_MAX_HOSTNAME_LOOKUP_WORKERS, len(lookup_ips))
        )
        try:
            future_to_ip = {
                executor.submit(resolve_connection_hostname, ip): ip
                for ip in lookup_ips
            }
            done, not_done = wait(
                future_to_ip.keys(),
                timeout=_HOSTNAME_LOOKUP_TIMEOUT_SECONDS,
            )
            for future in done:
                ip = future_to_ip[future]
                try:
                    name = future.result()
                    _HOSTNAME_CACHE[ip] = name if name else ip
                except Exception:
                    _HOSTNAME_CACHE[ip] = ip
            for future in not_done:
                ip = future_to_ip[future]
                future.cancel()
                _HOSTNAME_CACHE[ip] = ip
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
                
    # Attach resolved domain names to connections list
    for conn in connections:
        ip = conn["remote_ip"]
        conn["resolved_name"] = _HOSTNAME_CACHE.get(ip, ip)
        
    return connections
