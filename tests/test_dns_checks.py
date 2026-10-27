import socket
import threading
import time
from unittest.mock import patch

from losshound.core.dns_checks import check_dns


def test_dns_success():
    fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('142.250.80.46', 0))]
    with patch("socket.getaddrinfo", return_value=fake_result):
        result = check_dns("google.com")
        assert result.resolved
        assert result.resolved_ip == "142.250.80.46"
        assert result.resolution_time_ms is not None
        assert result.error is None


def test_dns_failure():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name not found")):
        result = check_dns("nonexistent.invalid")
        assert not result.resolved
        assert result.error is not None
        assert "Name not found" in result.error


def test_dns_timeout():
    with patch("socket.getaddrinfo", side_effect=socket.timeout()):
        result = check_dns("slow.example.com", timeout=0.1)
        assert not result.resolved
        assert "timed out" in result.error


def test_stuck_resolver_does_not_fail_other_hostnames():
    """One hung getaddrinfo must not poison DNS checks for other hostnames.

    A global in-flight guard would make every hostname report failure while
    one lookup hangs, inflating dns_fail_rate and triggering false DNS_ISSUE
    diagnoses.  The guard must be per hostname.
    """
    release = threading.Event()
    fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 0))]

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "stuck.example.com":
            release.wait(5)
        return fake_result

    try:
        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            stuck = check_dns("stuck.example.com", timeout=0.1)
            assert not stuck.resolved
            assert "timed out" in stuck.error

            # Unrelated hostname resolves fine while the other lookup hangs.
            other = check_dns("fine.example.com", timeout=2.0)
            assert other.resolved
            assert other.resolved_ip == "1.2.3.4"

            # The stuck hostname itself is guarded — no thread pile-up.
            again = check_dns("stuck.example.com", timeout=0.1)
            assert not again.resolved
            assert "pending" in again.error.lower()

            # Once the stale resolution completes, the hostname works again.
            release.set()
            deadline = time.monotonic() + 2.0
            final = again
            while time.monotonic() < deadline and not final.resolved:
                time.sleep(0.05)
                final = check_dns("stuck.example.com", timeout=1.0)
            assert final.resolved
    finally:
        release.set()
