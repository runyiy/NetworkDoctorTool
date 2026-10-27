"""Small read-only dual-stack probes for private session workers.

The owning WindowsProbeProvider enforces one absolute operation deadline around
this entire worker, including a resolver or peer that ignores socket timeouts.
No proxy discovery, credentials, redirects, retries or application imports.
"""
from __future__ import annotations

import ctypes
import errno
import http.client
import ipaddress
import socket
import ssl
import sys
import time
from urllib.parse import quote, unquote, urlsplit

PROBE_PROTOCOLS = frozenset({"icmp", "dns", "dns6", "tcp", "tcp6", "http", "http6", "https", "https6"})
HTTP_BODY_LIMIT = 16 * 1024
MAX_TARGET_LENGTH = 2048


def _result(outcome, *, data=None, error=None, packets_sent=None, packets_received=None, rtt_ms=None):
    return dict(outcome=outcome, data=data or {}, error=error, packets_sent=packets_sent,
                packets_received=packets_received, rtt_ms=rtt_ms)



def _clean_target(target, limit=MAX_TARGET_LENGTH):
    if (not isinstance(target, str) or not target or len(target) > limit
            or any(ord(char) <= 32 or ord(char) == 127 for char in target)):
        raise ValueError("Invalid probe target")
    return target


def _host(value):
    _clean_target(value, 253)
    if any(char in value for char in "/\\@?#[]"):
        raise ValueError("Invalid target hostname")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if ":" in value or "%" in value:
            raise ValueError("Invalid target address") from None
        ascii_name = value.encode("idna").decode("ascii")
        if len(ascii_name) > 253 or any(not part or len(part) > 63
                or part.startswith("-") or part.endswith("-")
                or any(not (char.isalnum() or char == "-") for char in part)
                for part in ascii_name.rstrip(".").split(".")):
            raise ValueError("Invalid target hostname")
        return ascii_name


def parse_tcp_target(target):
    """Validate an explicit host:port or [IPv6%scope]:port pair."""
    _clean_target(target)
    if target.startswith("["):
        closing = target.find("]")
        if closing < 0 or target[closing + 1:closing + 2] != ":":
            raise ValueError("TCP IPv6 target requires [address]:port")
        host, port_text = target[1:closing], target[closing + 2:]
        if ipaddress.ip_address(host).version != 6:
            raise ValueError("Bracketed TCP target must be IPv6")
    else:
        if target.count(":") != 1:
            raise ValueError("TCP target requires host:port")
        host, port_text = target.rsplit(":", 1)
    host = _host(host)
    if not port_text.isascii() or not port_text.isdecimal() or not 1 <= int(port_text) <= 65535:
        raise ValueError("Invalid TCP port")
    return host, int(port_text)


def validate_web_url(url):
    """Validate an explicit HTTP(S) URL without credentials or a fragment."""
    _clean_target(url)
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Website target requires an explicit http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None or "#" in url:
        raise ValueError("Website URL must not contain credentials or a fragment")
    _host(unquote(parsed.hostname))
    if parsed.netloc.endswith(":") or parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid website port")
    return url


def validate_target(protocol, target):
    if protocol not in PROBE_PROTOCOLS:
        raise ValueError("Unsupported probe protocol")
    if protocol == "icmp":
        _clean_target(target, 253)
        ipaddress.ip_address(target)
    elif protocol in {"dns", "dns6"}:
        _host(target)
    elif protocol in {"tcp", "tcp6"}:
        parse_tcp_target(target)
    else:
        validate_web_url(target)
        if urlsplit(target).scheme != ("https" if protocol.startswith("https") else "http"):
            raise ValueError("Website protocol and URL scheme disagree")


class _OperationDeadline(TimeoutError):
    """The local operation budget ended; this is not a peer response."""


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _OperationDeadline("Probe operation deadline reached")
    return remaining


def _connect_once(host, port, family, deadline, data):
    data["stage"] = "resolve"
    # One selected address only: no hidden fallback attempts or fresh deadlines.
    records = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    _remaining(deadline)
    if not records:
        raise OSError("OS resolver returned no address for the requested family")
    af, kind, proto, _canonical, address = records[0]
    if af != family:
        raise OSError("OS resolver returned a different address family")
    data.update(resolved_ip=address[0], port=port, stage="connect")
    if family == socket.AF_INET6:
        data["scope_id"] = address[3]
    sock = socket.socket(af, kind, proto)
    try:
        sock.settimeout(_remaining(deadline))
        sock.connect(address)
        return sock
    except BaseException:
        sock.close()
        raise


def _failure(exc, data):
    data = dict(data)
    data.update(exception_type=type(exc).__name__, errno=getattr(exc, "errno", None),
                winerror=getattr(exc, "winerror", None))
    if isinstance(exc, ssl.SSLCertVerificationError):
        category, outcome = "tls_validation", "execution_error"
    elif isinstance(exc, ssl.SSLError):
        category, outcome = "tls_handshake", "execution_error"
    elif isinstance(exc, (TimeoutError, socket.timeout)):
        category = "timeout"
        local = isinstance(exc, _OperationDeadline) or data.get("stage") in {"resolve", "target_validation"}
        outcome = "execution_error" if local else "reply_timeout"
        data["local_deadline"] = isinstance(exc, _OperationDeadline)
    elif isinstance(exc, ConnectionRefusedError) or getattr(exc, "errno", None) in {errno.ECONNREFUSED, 10061}:
        category, outcome = "connection_refused", "unreachable"
    else:
        category, outcome = "os_error", "execution_error"
    data["error_category"] = category
    # Do not copy peer text, URLs, response bodies or certificate contents.
    return _result(outcome, data=data, error=f"{data.get('stage', 'probe')}: {type(exc).__name__}")


def tcp_probe(target, family, timeout_ms):
    data = {"family": "IPv6" if family == socket.AF_INET6 else "IPv4", "stage": "target_validation"}
    sock = None
    try:
        host, port = parse_tcp_target(target)
        deadline = time.monotonic() + timeout_ms / 1000
        started = time.perf_counter()
        sock = _connect_once(host, port, family, deadline, data)
        data["stage"] = "connect"
        return _result("success", data=data, rtt_ms=(time.perf_counter() - started) * 1000)
    except Exception as exc:
        return _failure(exc, data)
    finally:
        if sock is not None:
            sock.close()


def http_probe(target, family, timeout_ms):
    data = {"family": "IPv6" if family == socket.AF_INET6 else "IPv4", "stage": "target_validation", "proxy_used": False}
    sock = connection = response = None
    try:
        validate_web_url(target)
        parsed = urlsplit(target)
        host = _host(unquote(parsed.hostname))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        deadline = time.monotonic() + timeout_ms / 1000
        sock = _connect_once(host, port, family, deadline, data)
        if parsed.scheme == "https":
            data["stage"] = "tls"
            sock.settimeout(_remaining(deadline))
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            # Connect to the selected address while verifying the original host.
            sock = context.wrap_socket(sock, server_hostname=host.split("%", 1)[0])
            data["tls_verified"] = True
        connection = http.client.HTTPConnection(host, port, timeout=_remaining(deadline))
        connection.sock = sock  # Already connected directly; no proxy or resolver fallback.
        sock.settimeout(_remaining(deadline))
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parsed.query:
            path += "?" + quote(parsed.query, safe="%:@!$&'()*+,;=/?-._~")
        http_host = host.split("%", 1)[0]
        header_host = f"[{http_host}]" if ":" in http_host else http_host
        if port != (443 if parsed.scheme == "https" else 80):
            header_host += f":{port}"
        data["stage"] = "request"
        connection.request("GET", path, headers={"Host": header_host, "Connection": "close",
                           "Accept-Encoding": "identity", "Range": f"bytes=0-{HTTP_BODY_LIMIT-1}",
                           "User-Agent": "Losshound-read-only-diagnostics"})
        data["stage"] = "response"
        sock.settimeout(_remaining(deadline))
        response = connection.getresponse()
        data.update(http_status=response.status, redirects_followed=0, body_bytes=0)
        if not 200 <= response.status < 300:
            data["error_category"] = "http_status"
        # A redirect is evidence only. Never read a redirect body or send another request.
        if not 300 <= response.status < 400:
            sock.settimeout(_remaining(deadline))
            body = response.read(HTTP_BODY_LIMIT)
            data.update(body_bytes=len(body), body_limit_reached=len(body) == HTTP_BODY_LIMIT)
        return _result("success", data=data)
    except Exception as exc:
        return _failure(exc, data)
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        elif sock is not None:
            sock.close()


class _SockaddrIn6(ctypes.Structure):
    _fields_ = [("family", ctypes.c_uint16), ("port", ctypes.c_uint16),
                ("flowinfo", ctypes.c_uint32), ("address", ctypes.c_ubyte * 16),
                ("scope_id", ctypes.c_uint32)]


class _IPv6AddressEx(ctypes.Structure):
    _fields_ = [("port", ctypes.c_uint16), ("flowinfo", ctypes.c_uint32),
                ("address", ctypes.c_ubyte * 16), ("scope_id", ctypes.c_uint32)]


class _Icmp6Reply(ctypes.Structure):
    _fields_ = [("address", _IPv6AddressEx), ("status", ctypes.c_uint32), ("rtt", ctypes.c_uint32)]


def _icmp6_api():
    if sys.platform != "win32":
        return None
    try:
        api = ctypes.WinDLL("iphlpapi", use_last_error=True)
        api.Icmp6CreateFile.argtypes, api.Icmp6CreateFile.restype = [], ctypes.c_void_p
        api.IcmpCloseHandle.argtypes, api.IcmpCloseHandle.restype = [ctypes.c_void_p], ctypes.c_bool
        api.Icmp6SendEcho2.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.POINTER(_SockaddrIn6), ctypes.POINTER(_SockaddrIn6),
            ctypes.c_void_p, ctypes.c_uint16, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32]
        api.Icmp6SendEcho2.restype = ctypes.c_uint32
        return api
    except (OSError, AttributeError):
        return None


def _last_error():
    return ctypes.get_last_error()


def icmp6_probe(target, timeout_ms):
    data = {"family": "IPv6", "stage": "icmp_target_validation"}
    api = handle = None
    try:
        address = ipaddress.IPv6Address(target)
        zone = address.scope_id
        scope = (int(zone) if zone.isdecimal() else socket.if_nametoindex(zone)) if zone else 0
        if not 0 <= scope <= 0xffffffff or address.is_link_local and not scope:
            raise ValueError("Link-local IPv6 probes require an interface scope")
        data.update(resolved_ip=str(address), scope_id=scope, stage="icmp_native_load")
        api = _icmp6_api()
        if api is None:
            return _result("unsupported", data=data, error="Native Windows IPv6 ICMP is unavailable")
        data["stage"] = "Icmp6CreateFile"
        handle = api.Icmp6CreateFile()
        if handle in (None, 0, ctypes.c_void_p(-1).value):
            code = _last_error()
            handle = None
            return _result("execution_error", data={**data, "native_status": code, "error_category": "os_error"},
                           error="Icmp6CreateFile failed; sent count is unknown")
        source = _SockaddrIn6(family=socket.AF_INET6, scope_id=scope)
        destination = _SockaddrIn6(family=socket.AF_INET6, scope_id=scope)
        destination.address[:] = address.packed
        payload = ctypes.create_string_buffer(b"Losshound IPv6 read-only echo")
        size = ctypes.sizeof(_Icmp6Reply) + ctypes.sizeof(payload) + 8 + 2 * ctypes.sizeof(ctypes.c_void_p)
        reply_buffer = ctypes.create_string_buffer(size)
        data["stage"] = "Icmp6SendEcho2"
        count = api.Icmp6SendEcho2(handle, None, None, None, ctypes.byref(source),
            ctypes.byref(destination), payload, len(payload.raw)-1, None, reply_buffer, size, timeout_ms)
        reply = ctypes.cast(reply_buffer, ctypes.POINTER(_Icmp6Reply)).contents if count else None
        status = reply.status if reply is not None else _last_error()
        data["native_status"] = status
        if count and status == 0:
            return _result("success", data=data, packets_sent=1, packets_received=1, rtt_ms=float(reply.rtt))
        if status == 11010:
            return _result("reply_timeout", data={**data, "error_category": "timeout"}, packets_sent=1, packets_received=0)
        if status in {11002, 11003, 11004, 11005, 11009, 11013}:
            return _result("unreachable", data=data, error="Native ICMPv6 returned unreachable/prohibited")
        return _result("execution_error", data={**data, "error_category": "os_error"}, error="Native ICMPv6 failed; sent count is unknown")
    except Exception as exc:
        return _failure(exc, data)
    finally:
        if api is not None and handle is not None:
            api.IcmpCloseHandle(handle)


def _number(value):
    if isinstance(value, bool):
        raise ValueError("Boolean is not an interface number")
    return int(value)


def _family(value):
    if value in (2, "IPv4", "ipv4", "2"):
        return "IPv4"
    if value in (23, "IPv6", "ipv6", "23"):
        return "IPv6"
    return None


def summarize_network(context):
    """Summarize one existing snapshot; configuration is not connectivity."""
    context = context if isinstance(context, dict) else {}
    complete = all(isinstance(context.get(key), list) for key in ("addresses", "routes", "interfaces"))
    families = {name: {"addresses": [], "default_routes": [], "default_route": None,
                      "available": None if not complete else False,
                      "status": "unknown" if not complete else "incomplete"} for name in ("IPv4", "IPv6")}
    interfaces = {}
    for item in context.get("interfaces", []) if isinstance(context.get("interfaces"), list) else []:
        try:
            family = _family(item.get("AddressFamily"))
            index = _number(item["InterfaceIndex"])
            metric = _number(item["InterfaceMetric"])
            connected = item.get("ConnectionState") in (None, 1, "Connected")
            if family and index > 0 and metric >= 0 and connected:
                interfaces[(family, index)] = metric
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    for item in context.get("addresses", []) if isinstance(context.get("addresses"), list) else []:
        try:
            address = ipaddress.ip_address(item["IPAddress"])
            name = "IPv" + str(address.version)
            index = _number(item["InterfaceIndex"])
            state = item.get("AddressState")
            usable = not item.get("SkipAsSource", False) and state in (None, 3, 4, "Preferred", "Deprecated")
            usable = usable and not (address.is_loopback or address.is_unspecified or address.is_multicast)
            scope = int(address.scope_id) if address.version == 6 and address.scope_id and address.scope_id.isdecimal() else (index if address.version == 6 and address.is_link_local else 0)
            families[name]["addresses"].append({"address": str(address), "interface_index": index,
                "prefix_length": item.get("PrefixLength"), "scope_id": scope, "usable": usable})
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    for item in context.get("routes", []) if isinstance(context.get("routes"), list) else []:
        try:
            name = _family(item.get("AddressFamily"))
            if not name or item.get("DestinationPrefix") != ("0.0.0.0/0" if name == "IPv4" else "::/0"):
                continue
            index = _number(item["InterfaceIndex"])
            interface_metric = interfaces.get((name, index))
            metric = _number(item["RouteMetric"])
            gateway = ipaddress.ip_address(item["NextHop"])
            if interface_metric is None or metric < 0 or gateway.version != (4 if name == "IPv4" else 6) or gateway.is_unspecified:
                continue
            scope = int(gateway.scope_id) if gateway.version == 6 and gateway.scope_id and gateway.scope_id.isdecimal() else (index if gateway.version == 6 and gateway.is_link_local else 0)
            next_hop = str(gateway)
            if scope and "%" not in next_hop:
                next_hop += "%" + str(scope)
            families[name]["default_routes"].append({"gateway": next_hop, "interface_index": index,
                "route_metric": metric, "interface_metric": interface_metric,
                "metric": metric + interface_metric, "scope_id": scope})
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    for value in families.values():
        value["default_routes"].sort(key=lambda route: (route["metric"], route["interface_index"], route["gateway"]))
        # An interface metric alone is not enough: choose a default only
        # where that same family/interface has a usable source address. A
        # link-local source cannot be the source for an off-link default.
        for route in value["default_routes"]:
            sources = [address for address in value["addresses"] if address["usable"]
                       and address["interface_index"] == route["interface_index"]
                       and not ipaddress.ip_address(address["address"]).is_link_local]
            if sources:
                value["default_route"] = dict(route, source_address_candidate=sources[0]["address"])
                break
        if complete:
            value["available"] = value["default_route"] is not None
            value["status"] = "configured" if value["available"] else "incomplete"
    wifi = context.get("wifi_observations", context.get("wifi"))
    if isinstance(wifi, list):
        wifi = [dict(item) for item in wifi if isinstance(item, dict)]
    else:
        wifi = dict(wifi) if isinstance(wifi, dict) else {}
    return {"families": families, "wifi": wifi, "read_only": True}
