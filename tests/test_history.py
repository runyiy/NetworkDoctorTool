import tempfile
from datetime import datetime
from pathlib import Path

from losshound.core.models import (
    Diagnosis,
    DiagnosisCategory,
    DnsResult,
    Observation,
    PingResult,
    RouteHop,
    RouteSnapshot,
)
from losshound.core.drop_analyzer import (
    ConnSample,
    DropAnalysisReport,
    DropForensicsEpisode,
    GatewayStateSnapshot,
)
from losshound.storage.history import HistoryStore


def _make_store():
    tmp = tempfile.mktemp(suffix=".db")
    return HistoryStore(Path(tmp))


def _make_obs() -> Observation:
    now = datetime.now()
    return Observation(
        timestamp=now,
        gateway_ip="192.168.1.1",
        gateway_ping=PingResult(
            target="192.168.1.1", timestamp=now,
            packets_sent=4, packets_received=4, loss_percent=0.0,
            rtt_avg=5.0,
        ),
        public_pings=[
            PingResult(
                target="1.1.1.1", timestamp=now,
                packets_sent=4, packets_received=4, loss_percent=0.0,
                rtt_avg=12.0,
            ),
        ],
        dns_results=[
            DnsResult(
                hostname="google.com", timestamp=now,
                resolved=True, resolved_ip="142.250.80.46",
                resolution_time_ms=15.0,
            ),
        ],
    )


def test_save_and_load_observation():
    store = _make_store()
    obs = _make_obs()
    store.save_observation(obs)

    loaded = store.get_recent_observations(minutes=5)
    assert len(loaded) == 1
    assert loaded[0].gateway_ip == "192.168.1.1"
    store.close()


def test_save_and_load_diagnosis():
    store = _make_store()
    diag = Diagnosis(
        timestamp=datetime.now(),
        category=DiagnosisCategory.HEALTHY,
        summary="Connection healthy",
        explanation="All good",
        confidence="high",
        evidence={"gateway_loss_avg": 0.0},
    )
    store.save_diagnosis(diag)

    loaded = store.get_recent_diagnoses(10)
    assert len(loaded) == 1
    assert loaded[0]["category"] == "healthy"
    assert loaded[0]["summary"] == "Connection healthy"
    store.close()


def test_save_route_snapshot():
    store = _make_store()
    snap = RouteSnapshot(
        target="8.8.8.8",
        timestamp=datetime.now(),
        hops=[
            RouteHop(1, "192.168.1.1", [1.0, 1.0, 1.0]),
            RouteHop(2, "10.0.0.1", [10.0, 11.0, 10.0]),
        ],
        completed=True,
    )
    store.save_route_snapshot(snap)

    loaded = store.get_route_snapshots(hours=1)
    assert len(loaded) == 1
    assert len(loaded[0].hops) == 2
    assert loaded[0].hops[0].ip == "192.168.1.1"
    store.close()


def test_save_and_load_drop_forensics():
    store = _make_store()
    now = datetime.now()
    sample = ConnSample(
        timestamp=now,
        link_up=True,
        connection_type="ethernet",
        speed_mbps=100.0,
        wifi_signal_pct=0,
        wifi_ssid="",
        wifi_channel=0,
        gateway_reachable=True,
        gateway_rtt_ms=2.0,
        wan_reachable=False,
        wan_rtt_ms=None,
        dns_ok=True,
    )
    report = DropAnalysisReport(
        scan_duration_seconds=1.0,
        connection_type="ethernet",
        total_samples=1,
        samples=[sample],
        drops=[],
        events=[],
        verdict="ISP / WAN ISSUE",
        confidence="medium",
        details=[],
        recommendations=[],
        drop_regularity=None,
    )
    episode = DropForensicsEpisode(
        timestamp=now,
        trigger="timeout_burst",
        timeout_streak=3,
        gateway_ip="192.168.1.1",
        wan_target="8.8.8.8",
        report=report,
        wifi_before=None,
        wifi_after=None,
        gateway_before=GatewayStateSnapshot("192.168.1.1", True, 2.0),
        gateway_after=GatewayStateSnapshot("192.168.1.1", True, 2.0),
        cause="isp",
        confidence="medium",
        summary="Gateway stayed reachable while WAN failed",
    )

    row_id = store.save_drop_forensics(episode)
    loaded = store.recent_drop_forensics()

    assert row_id > 0
    assert loaded[0]["cause"] == "isp"
    assert loaded[0]["timeout_streak"] == 3
    assert loaded[0]["raw"]["report"]["samples"][0]["wan_reachable"] is False
    store.close()


def test_export_report():
    store = _make_store()
    store.save_observation(_make_obs())
    store.save_diagnosis(Diagnosis(
        timestamp=datetime.now(),
        category=DiagnosisCategory.HEALTHY,
        summary="Healthy",
        explanation="OK",
        confidence="high",
    ))

    report = store.export_report(hours=1)
    assert "generated_at" in report
    assert len(report["observations"]) >= 1
    assert len(report["diagnoses"]) >= 1
    store.close()


def test_prune():
    store = _make_store()
    store.save_observation(_make_obs())
    # Prune with 0 hours retention should remove everything
    removed = store.prune(retention_hours=0)
    assert removed >= 1

    loaded = store.get_recent_observations(minutes=60)
    assert len(loaded) == 0
    store.close()


def test_discovered_devices():
    store = _make_store()
    
    # Save a device
    store.save_device("00-11-22-33-44-55", "192.168.1.50", "Test-Device", "Intel")
    devices = store.get_devices()
    assert len(devices) == 1
    assert devices[0]["mac_address"] == "00-11-22-33-44-55"
    assert devices[0]["status"] == "unknown"
    assert devices[0]["is_active"] is True
    
    # Update device status
    store.update_device_status("00-11-22-33-44-55", "authorized")
    devices = store.get_devices()
    assert devices[0]["status"] == "authorized"
    
    # Set active status to inactive
    store.set_all_devices_inactive()
    devices = store.get_devices()
    assert devices[0]["is_active"] is False
    
    # Update device active status by saving again
    store.save_device("00-11-22-33-44-55", "192.168.1.50", "Test-Device", "Intel")
    devices = store.get_devices()
    assert devices[0]["is_active"] is True
    
    # Clear devices
    store.clear_discovered_devices()
    devices = store.get_devices()
    assert len(devices) == 0

    store.close()


def test_device_custom_name():
    store = _make_store()
    mac = "00-11-22-33-44-55"

    store.save_device(mac, "192.168.1.50", "auto-detected-host", "Intel")
    assert store.get_devices()[0]["custom_name"] is None

    # Setting a custom name persists it without affecting the auto-detected hostname
    store.set_device_custom_name(mac, "Mom's Laptop")
    dev = store.get_devices()[0]
    assert dev["custom_name"] == "Mom's Laptop"
    assert dev["hostname"] == "auto-detected-host"

    # A subsequent scan saving the same device with a new auto-resolved hostname
    # must not overwrite the user's custom name.
    store.save_device(mac, "192.168.1.50", "different-auto-name", "Intel")
    dev = store.get_devices()[0]
    assert dev["custom_name"] == "Mom's Laptop"
    assert dev["hostname"] == "different-auto-name"

    # Whitespace-only input is treated as a clear (revert to auto-detected)
    store.set_device_custom_name(mac, "   ")
    assert store.get_devices()[0]["custom_name"] is None

    # Explicit None also clears
    store.set_device_custom_name(mac, "Something")
    store.set_device_custom_name(mac, None)
    assert store.get_devices()[0]["custom_name"] is None

    store.close()


def test_device_custom_name_migration():
    """Databases created before the custom_name column was added should auto-migrate."""
    import sqlite3
    tmp = tempfile.mktemp(suffix=".db")

    # Build a legacy schema (no custom_name column) by hand
    conn = sqlite3.connect(tmp)
    conn.execute(
        """CREATE TABLE discovered_devices (
            mac_address TEXT PRIMARY KEY,
            ip_address TEXT NOT NULL,
            hostname TEXT,
            vendor TEXT,
            status TEXT NOT NULL DEFAULT 'unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )"""
    )
    conn.execute(
        """INSERT INTO discovered_devices
           (mac_address, ip_address, hostname, vendor, status, first_seen, last_seen, is_active)
           VALUES ('aa-bb-cc-dd-ee-ff', '192.168.1.10', 'legacy', 'HP', 'unknown',
                   '2026-01-01', '2026-01-01', 1)"""
    )
    conn.commit()
    conn.close()

    # Opening through HistoryStore must migrate without losing the legacy row
    store = HistoryStore(Path(tmp))
    devices = store.get_devices()
    assert len(devices) == 1
    assert devices[0]["hostname"] == "legacy"
    assert devices[0]["custom_name"] is None

    store.set_device_custom_name("aa-bb-cc-dd-ee-ff", "Migrated Device")
    assert store.get_devices()[0]["custom_name"] == "Migrated Device"

    store.close()
