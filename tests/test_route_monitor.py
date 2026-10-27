from datetime import datetime

from losshound.core.route_monitor import _parse_tracert_output, diff_routes
from losshound.core.models import RouteHop, RouteSnapshot
from tests.conftest import TRACERT_OUTPUT, TRACERT_INCOMPLETE_OUTPUT


def test_parse_tracert():
    snap = _parse_tracert_output(TRACERT_OUTPUT, "8.8.8.8", datetime.now())
    assert len(snap.hops) == 5
    assert snap.hops[0].ip == "192.168.1.1"
    assert snap.hops[1].ip is None  # timed out hop
    assert snap.hops[2].ip == "10.0.0.1"
    assert snap.hops[4].ip == "8.8.8.8"
    assert snap.completed


def test_parse_tracert_incomplete():
    snap = _parse_tracert_output(TRACERT_INCOMPLETE_OUTPUT, "10.99.99.99", datetime.now())
    assert len(snap.hops) == 5
    assert snap.hops[0].ip == "192.168.1.1"
    assert snap.hops[1].ip == "10.0.0.1"
    assert snap.hops[2].ip is None
    assert not snap.completed


def test_responsive_last_hop_is_not_complete_unless_it_is_destination():
    output = """
Tracing route to 8.8.8.8 over a maximum of 2 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2    10 ms    11 ms    10 ms  10.0.0.1

Trace complete.
"""
    snap = _parse_tracert_output(output, "8.8.8.8", datetime.now())

    assert snap.hops[-1].ip == "10.0.0.1"
    assert not snap.completed


def test_hostname_route_completes_at_resolved_header_destination():
    output = """
Tracing route to dns.google [8.8.8.8] over a maximum of 20 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2    20 ms    19 ms    21 ms  8.8.8.8

Trace complete.
"""
    snap = _parse_tracert_output(output, "dns.google", datetime.now())

    assert snap.completed


def test_parse_tracert_rtt():
    snap = _parse_tracert_output(TRACERT_OUTPUT, "8.8.8.8", datetime.now())
    hop1 = snap.hops[0]
    assert len(hop1.rtt_samples) == 3
    assert all(r is not None for r in hop1.rtt_samples)


def test_diff_routes_no_change():
    now = datetime.now()
    hops = [RouteHop(1, "192.168.1.1"), RouteHop(2, "10.0.0.1")]
    s1 = RouteSnapshot("8.8.8.8", now, hops=hops)
    s2 = RouteSnapshot("8.8.8.8", now, hops=hops)
    rd = diff_routes(s1, s2)
    assert len(rd.changed_hops) == 0
    assert not rd.is_significant


def test_diff_routes_single_change():
    now = datetime.now()
    s1 = RouteSnapshot("8.8.8.8", now, hops=[
        RouteHop(1, "192.168.1.1"), RouteHop(2, "10.0.0.1"),
    ])
    s2 = RouteSnapshot("8.8.8.8", now, hops=[
        RouteHop(1, "192.168.1.1"), RouteHop(2, "10.0.0.2"),
    ])
    rd = diff_routes(s1, s2)
    assert 2 in rd.changed_hops
    assert not rd.is_significant  # single hop change = not significant


def test_diff_routes_significant():
    now = datetime.now()
    s1 = RouteSnapshot("8.8.8.8", now, hops=[
        RouteHop(1, "192.168.1.1"), RouteHop(2, "10.0.0.1"), RouteHop(3, "172.16.0.1"),
    ])
    s2 = RouteSnapshot("8.8.8.8", now, hops=[
        RouteHop(1, "192.168.1.1"), RouteHop(2, "10.0.0.99"), RouteHop(3, "172.16.0.99"),
    ])
    rd = diff_routes(s1, s2)
    assert len(rd.changed_hops) == 2
    assert rd.is_significant


def test_trace_route_builds_arg_list():
    from unittest.mock import patch
    from losshound.core.route_monitor import trace_route

    with patch("losshound.core.route_monitor.run_subprocess_interruptible") as mock_run:
        mock_run.return_value = ("Hop 1 192.168.1.1 1ms", "", 0)
        trace_route("8.8.8.8", max_hops=20, timeout_ms=3000)
        
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert isinstance(args, list)
        assert args[0] == "tracert"
        assert "-d" in args
        assert "8.8.8.8" in args
        # Check there is no cmd or shell wrapping
        assert "cmd" not in args
        assert "cmd.exe" not in args
        assert "/c" not in args

