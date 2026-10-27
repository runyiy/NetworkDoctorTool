import http.client
import io
import threading
import time
from unittest.mock import MagicMock
import socket

import pytest

from losshound.core import lan_http, lan_monitor


class _MemorySocket:
    def __init__(self, wire):
        self.stream = io.BytesIO(wire)
        self.aborted = threading.Event()
        self.closed = False

    def makefile(self, *args):
        return self.stream

    def settimeout(self, timeout):
        self.timeout = timeout

    def shutdown(self, how):
        self.aborted.set()

    def close(self):
        self.closed = True


def _transport(monkeypatch, wires, socket_factory=_MemorySocket):
    """Real HTTP parsing over in-memory bytes; no network connections."""
    connections = []
    wires = iter(wires)

    class Connection:
        def __init__(self, host, port, **kwargs):
            self.host, self.port, self.options = host, port, kwargs
            self.sock = socket_factory(next(wires))
            connections.append(self)

        def connect(self):
            pass

        def request(self, method, target, headers):
            self.requested = (method, target, headers)

        def getresponse(self):
            response = http.client.HTTPResponse(self.sock, method="GET")
            response.begin()
            return response

        def close(self):
            self.sock.close()

    monkeypatch.setattr(lan_http.http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(lan_http.http.client, "HTTPSConnection", Connection)
    return connections


def test_same_device_redirect_and_chunked_description_work_without_proxy(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:9999")
    connections = _transport(monkeypatch, [
        b"HTTP/1.1 302 Found\r\nLocation: https://192.168.1.1:8443/description\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    ])
    assert lan_http.fetch_device_document("http://192.168.1.1/", device_ip="192.168.1.1") == b"hello"
    assert [connection.host for connection in connections] == ["192.168.1.1"] * 2
    assert connections[1].port == 8443
    assert connections[1].requested[1] == "/description"
    assert all(connection.sock.closed for connection in connections)


@pytest.mark.parametrize("destination", [
    "http://8.8.8.8/", "http://192.168.1.2/", "http://127.0.0.1/",
    "http://example.com/", "ftp://192.168.1.1/", "http://secret@192.168.1.1/",
])
def test_redirect_escape_is_blocked_before_second_connection(monkeypatch, destination):
    wire = f"HTTP/1.1 302 Found\r\nLocation: {destination}\r\n\r\n".encode()
    connections = _transport(monkeypatch, [wire])
    with pytest.raises(ValueError):
        lan_http.fetch_device_document("http://192.168.1.1/", device_ip="192.168.1.1")
    assert len(connections) == 1
    assert connections[0].sock.closed


@pytest.mark.parametrize("url,device", [
    ("http://127.0.0.1/", "127.0.0.1"),
    ("http://8.8.8.8/", "8.8.8.8"),
    ("http://192.168.1.2/", "192.168.1.1"),
    ("http://localhost/", "192.168.1.1"),
    ("http://192.168.1.1:0/", "192.168.1.1"),
])
def test_untrusted_initial_location_never_connects(monkeypatch, url, device):
    connections = _transport(monkeypatch, [])
    with pytest.raises(ValueError):
        lan_http.fetch_device_document(url, device_ip=device)
    assert connections == []


def test_redirect_loop_is_bounded(monkeypatch):
    connections = _transport(monkeypatch, [
        b"HTTP/1.1 302 Found\r\nLocation: /again\r\n\r\n"
    ] * 4)
    with pytest.raises(ValueError, match="redirect limit"):
        lan_http.fetch_device_document("http://192.168.1.1/", device_ip="192.168.1.1")
    assert len(connections) == 4
    assert all(connection.sock.closed for connection in connections)


@pytest.mark.parametrize("wire", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n",
    b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 33,
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n21\r\n" + b"x" * 33 + b"\r\n0\r\n\r\n",
])
def test_declared_undeclared_and_chunked_oversized_bodies_are_rejected(monkeypatch, wire):
    connections = _transport(monkeypatch, [wire])
    with pytest.raises(ValueError, match="size limit"):
        lan_http.fetch_device_document("http://192.168.1.1/", device_ip="192.168.1.1", max_bytes=32)
    assert connections[0].sock.closed


@pytest.mark.parametrize("phase", ["headers", "body", "chunk_framing"])
def test_watchdog_interrupts_slow_headers_bodies_and_chunk_framing(monkeypatch, phase):
    class SlowSocket(_MemorySocket):
        def __init__(self, wire):
            super().__init__(wire)
            aborted = self.aborted

            class SlowStream(io.BytesIO):
                def readline(self, *args):
                    if phase == "headers" or (phase == "chunk_framing" and self.tell() == len(wire)):
                        assert aborted.wait(2), "watchdog failed to interrupt the peer"
                        return b""
                    return super().readline(*args)

                def read1(self, *args):
                    assert aborted.wait(2), "watchdog failed to interrupt the peer"
                    return b""

            self.stream = SlowStream(wire)

    wire = b"HTTP/1.1 200 OK\r\n"
    if phase == "chunk_framing":
        wire += b"Transfer-Encoding: chunked\r\n"
    wire += b"\r\n"
    connections = _transport(monkeypatch, [wire], SlowSocket)
    started = time.monotonic()
    with pytest.raises((OSError, http.client.HTTPException)):
        lan_http.fetch_device_document("http://192.168.1.1/", device_ip="192.168.1.1", timeout=0.1)
    assert time.monotonic() - started < 1.5
    assert connections[0].sock.aborted.is_set()
    assert connections[0].sock.closed


def test_redirects_share_the_same_deadline(monkeypatch):
    connections = _transport(monkeypatch, [
        b"HTTP/1.1 302 Found\r\nLocation: /again\r\n\r\n",
    ])
    times = iter([0.0, 0.0, 0.0, 4.0])
    monkeypatch.setattr(lan_http.time, "monotonic", lambda: next(times))
    with pytest.raises(TimeoutError):
        lan_http.fetch_device_document("http://192.168.1.1/", device_ip="192.168.1.1")
    assert len(connections) == 1


def test_http_title_consumer_cannot_escape_via_redirect(monkeypatch):
    connections = _transport(monkeypatch, [
        b"HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\n\r\n",
    ] * 2)
    assert lan_monitor.resolve_http_title("192.168.1.1") == ""
    assert len(connections) == 2  # HTTP and HTTPS retry, both still the device.
    assert all(connection.host == "192.168.1.1" for connection in connections)


@pytest.mark.parametrize("location,wire,expected_connections", [
    ("http://192.168.1.2/desc", [], 0),
    ("http://192.168.1.1/desc", [b"HTTP/1.1 302 Found\r\nLocation: http://8.8.8.8/\r\n\r\n"], 1),
])
def test_ssdp_consumer_restricts_locations_and_redirects_to_sender(monkeypatch, location, wire, expected_connections):
    connections = _transport(monkeypatch, wire)
    discovery = MagicMock()
    discovery.recvfrom.side_effect = [
        (f"HTTP/1.1 200 OK\r\nLOCATION: {location}\r\n\r\n".encode(), ("192.168.1.1", 1900)),
        socket.timeout(),
    ]
    monkeypatch.setattr(lan_monitor.socket, "socket", lambda *args: discovery)
    assert lan_monitor.scan_ssdp() == {}
    assert len(connections) == expected_connections
