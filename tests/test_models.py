import pytest

from network_doctor.models import PingStats


def test_ping_stats_calculates_loss_average_and_jitter():
    stats = PingStats(target="1.1.1.1", sent=4, latencies_ms=(20.0, 35.0, 25.0))

    assert stats.packet_loss_percent == 25.0
    assert stats.average_latency_ms == pytest.approx(26.67, abs=0.01)
    assert stats.jitter_ms == pytest.approx(12.5)
    assert stats.reachable is True


def test_jitter_is_unavailable_with_fewer_than_two_replies():
    stats = PingStats(target="1.1.1.1", sent=4, latencies_ms=(20.0,))

    assert stats.jitter_ms is None


def test_no_replies_is_unreachable_and_full_loss():
    stats = PingStats(target="1.1.1.1", sent=4, latencies_ms=())

    assert stats.reachable is False
    assert stats.packet_loss_percent == 100.0
    assert stats.average_latency_ms is None


def test_zero_sent_probes_have_unavailable_packet_loss():
    stats = PingStats(target="1.1.1.1", sent=0)

    assert stats.packet_loss_percent is None
