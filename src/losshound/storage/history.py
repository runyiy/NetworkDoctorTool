from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from losshound.core.config import _app_data_dir
from losshound.core.models import (
    AlertRow,
    Diagnosis,
    DiagnosisCategory,
    Observation,
    RouteSnapshot,
    observation_to_json,
    diagnosis_to_json,
)

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    gateway_ip TEXT,
    gateway_loss REAL,
    gateway_rtt_avg REAL,
    public_loss_avg REAL,
    public_rtt_avg REAL,
    dns_fail_count INTEGER DEFAULT 0,
    dns_total_count INTEGER DEFAULT 0,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS diagnoses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    explanation TEXT,
    confidence TEXT,
    evidence_json TEXT
);

CREATE TABLE IF NOT EXISTS route_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    target TEXT,
    hops_json TEXT,
    completed INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS benchmark_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    label TEXT,
    avg_latency_ms REAL,
    avg_jitter_ms REAL,
    avg_loss_pct REAL,
    avg_dns_ms REAL,
    avg_tcp_ms REAL,
    overall_score REAL,
    grade TEXT,
    raw_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(timestamp);
CREATE INDEX IF NOT EXISTS idx_diag_ts ON diagnoses(timestamp);
CREATE INDEX IF NOT EXISTS idx_route_ts ON route_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_bench_ts ON benchmark_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_bench_label ON benchmark_snapshots(label);

CREATE TABLE IF NOT EXISTS drop_forensics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    cause TEXT NOT NULL,
    summary TEXT NOT NULL,
    confidence TEXT,
    gateway_ip TEXT,
    wan_target TEXT,
    timeout_streak INTEGER DEFAULT 0,
    raw_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_drop_forensics_ts ON drop_forensics(timestamp);
CREATE INDEX IF NOT EXISTS idx_drop_forensics_cause ON drop_forensics(cause);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    message     TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);

CREATE TABLE IF NOT EXISTS discovered_devices (
    mac_address TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    vendor TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    custom_name TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_active ON discovered_devices(is_active);
"""


def _migrate_discovered_devices(conn: sqlite3.Connection) -> None:
    """Add custom_name column to pre-existing databases that predate manual naming."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(discovered_devices)").fetchall()}
    if "custom_name" not in cols:
        conn.execute("ALTER TABLE discovered_devices ADD COLUMN custom_name TEXT")
        conn.commit()


class HistoryStore:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = _app_data_dir() / "history.db"
        self._db_path = db_path
        self._conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,
            timeout=10,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        _migrate_discovered_devices(self._conn)
        self._conn.commit()
        logger.info("History store opened at %s", db_path)

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def save_observation(self, obs: Observation) -> None:
        gw_loss = obs.gateway_ping.loss_percent if obs.gateway_ping else None
        gw_rtt = obs.gateway_ping.rtt_avg if obs.gateway_ping else None

        pub_losses = [p.loss_percent for p in obs.public_pings]
        pub_rtts = [p.rtt_avg for p in obs.public_pings if p.rtt_avg is not None]
        pub_loss_avg = sum(pub_losses) / len(pub_losses) if pub_losses else None
        pub_rtt_avg = sum(pub_rtts) / len(pub_rtts) if pub_rtts else None

        dns_fail = sum(1 for d in obs.dns_results if not d.resolved)
        dns_total = len(obs.dns_results)

        self._conn.execute(
            """INSERT INTO observations
               (timestamp, gateway_ip, gateway_loss, gateway_rtt_avg,
                public_loss_avg, public_rtt_avg, dns_fail_count, dns_total_count, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                obs.timestamp.isoformat(),
                obs.gateway_ip,
                gw_loss, gw_rtt,
                pub_loss_avg, pub_rtt_avg,
                dns_fail, dns_total,
                observation_to_json(obs),
            ),
        )
        self._conn.commit()

    def save_diagnosis(self, diag: Diagnosis) -> None:
        self._conn.execute(
            """INSERT INTO diagnoses
               (timestamp, category, summary, explanation, confidence, evidence_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                diag.timestamp.isoformat(),
                diag.category.value,
                diag.summary,
                diag.explanation,
                diag.confidence,
                json.dumps(diag.evidence),
            ),
        )
        self._conn.commit()

    def save_route_snapshot(self, snap: RouteSnapshot) -> None:
        hops_data = [
            {"hop": h.hop_number, "ip": h.ip, "rtt": h.rtt_samples}
            for h in snap.hops
        ]
        self._conn.execute(
            """INSERT INTO route_snapshots
               (timestamp, target, hops_json, completed)
               VALUES (?, ?, ?, ?)""",
            (
                snap.timestamp.isoformat(),
                snap.target,
                json.dumps(hops_data),
                1 if snap.completed else 0,
            ),
        )
        self._conn.commit()

    def save_drop_forensics(self, episode) -> int:
        """Persist an automatic disconnect-forensics episode."""
        from losshound.core.drop_analyzer import drop_forensics_to_json

        cursor = self._conn.execute(
            """INSERT INTO drop_forensics
               (timestamp, cause, summary, confidence, gateway_ip, wan_target,
                timeout_streak, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                episode.timestamp.isoformat(),
                episode.cause,
                episode.summary,
                episode.confidence,
                episode.gateway_ip,
                episode.wan_target,
                episode.timeout_streak,
                drop_forensics_to_json(episode),
            ),
        )
        self._conn.commit()
        return cursor.lastrowid

    def recent_drop_forensics(self, limit: int = 20) -> list[dict]:
        rows = self._conn.execute(
            """SELECT id, timestamp, cause, summary, confidence, gateway_ip,
                      wan_target, timeout_streak, raw_json
               FROM drop_forensics ORDER BY timestamp DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "cause": r[2],
                "summary": r[3],
                "confidence": r[4],
                "gateway_ip": r[5],
                "wan_target": r[6],
                "timeout_streak": r[7],
                "raw": json.loads(r[8]) if r[8] else {},
            }
            for r in rows
        ]

    def get_recent_observations(self, minutes: int = 10) -> list[Observation]:
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        rows = self._conn.execute(
            "SELECT raw_json FROM observations WHERE timestamp > ? ORDER BY timestamp",
            (cutoff,),
        ).fetchall()

        results = []
        for (raw,) in rows:
            try:
                results.append(_deserialize_observation(raw))
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.debug("Failed to deserialize observation: %s", exc)
        return results

    def get_recent_diagnoses(self, count: int = 50) -> list[dict]:
        rows = self._conn.execute(
            """SELECT timestamp, category, summary, explanation, confidence, evidence_json
               FROM diagnoses ORDER BY timestamp DESC LIMIT ?""",
            (count,),
        ).fetchall()

        return [
            {
                "timestamp": row[0],
                "category": row[1],
                "summary": row[2],
                "explanation": row[3],
                "confidence": row[4],
                "evidence": json.loads(row[5]) if row[5] else {},
            }
            for row in reversed(rows)
        ]

    def get_route_snapshots(self, hours: int = 24) -> list[RouteSnapshot]:
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        rows = self._conn.execute(
            """SELECT timestamp, target, hops_json, completed
               FROM route_snapshots WHERE timestamp > ?
               ORDER BY timestamp""",
            (cutoff,),
        ).fetchall()

        from losshound.core.models import RouteHop

        results = []
        for ts, target, hops_json, completed in rows:
            hops_data = json.loads(hops_json) if hops_json else []
            hops = [
                RouteHop(
                    hop_number=h["hop"],
                    ip=h.get("ip"),
                    rtt_samples=h.get("rtt", []),
                )
                for h in hops_data
            ]
            results.append(RouteSnapshot(
                target=target,
                timestamp=datetime.fromisoformat(ts),
                hops=hops,
                completed=bool(completed),
            ))
        return results

    # ------------------------------------------------------------------
    # Benchmark snapshots
    # ------------------------------------------------------------------

    def save_benchmark(self, snap_dict: dict, score: float | None = None, grade: str = "") -> None:
        """Persist a benchmark snapshot with its score."""
        self._conn.execute(
            """INSERT INTO benchmark_snapshots
               (timestamp, label, avg_latency_ms, avg_jitter_ms, avg_loss_pct,
                avg_dns_ms, avg_tcp_ms, overall_score, grade, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snap_dict.get("timestamp", ""),
                snap_dict.get("label", ""),
                snap_dict.get("avg_latency_ms"),
                snap_dict.get("avg_jitter_ms"),
                snap_dict.get("avg_loss_pct"),
                snap_dict.get("avg_dns_ms"),
                snap_dict.get("avg_tcp_ms"),
                score,
                grade,
                json.dumps(snap_dict),
            ),
        )
        self._conn.commit()

    def get_benchmarks(self, hours: int = 168, label: str | None = None) -> list[dict]:
        """Return benchmark rows from the last *hours* hours."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        query = """SELECT timestamp, label, avg_latency_ms, avg_jitter_ms,
                          avg_loss_pct, avg_dns_ms, avg_tcp_ms,
                          overall_score, grade
                   FROM benchmark_snapshots WHERE timestamp > ?"""
        params: list = [cutoff]
        if label:
            query += " AND label = ?"
            params.append(label)
        query += " ORDER BY timestamp"
        rows = self._conn.execute(query, params).fetchall()
        return [
            {
                "timestamp": r[0], "label": r[1],
                "avg_latency_ms": r[2], "avg_jitter_ms": r[3],
                "avg_loss_pct": r[4], "avg_dns_ms": r[5],
                "avg_tcp_ms": r[6], "overall_score": r[7],
                "grade": r[8],
            }
            for r in rows
        ]

    def get_benchmark_count(self) -> int:
        """Return total number of stored benchmarks."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM benchmark_snapshots"
        ).fetchone()
        return row[0] if row else 0

    def prune(self, retention_hours: int = 24) -> int:
        cutoff = (datetime.now() - timedelta(hours=retention_hours)).isoformat()
        total = 0
        for table in [
            "observations",
            "diagnoses",
            "route_snapshots",
            "benchmark_snapshots",
            "drop_forensics",
        ]:
            cursor = self._conn.execute(
                f"DELETE FROM {table} WHERE timestamp <= ?", (cutoff,)
            )
            total += cursor.rowcount
        self._conn.commit()
        if total:
            logger.info("Pruned %d old records", total)
        return total

    def save_alert(
        self, timestamp: datetime, category: str, severity: str,
        title: str, message: str, commit: bool = True,
    ) -> int:
        cursor = self._conn.execute(
            """INSERT INTO alerts (timestamp, category, severity, title, message)
               VALUES (?, ?, ?, ?, ?)""",
            (timestamp.isoformat(), category, severity, title, message),
        )
        if commit:
            self._conn.commit()
        return cursor.lastrowid

    def resolve_alert(self, category: str, resolved_at: datetime) -> int:
        """Mark the most recent unresolved alert for *category* as resolved.

        Returns the row id of the resolved alert, or -1 if none was found.
        """
        row = self._conn.execute(
            """SELECT id FROM alerts
               WHERE category = ? AND resolved_at IS NULL
               ORDER BY timestamp DESC LIMIT 1""",
            (category,),
        ).fetchone()
        if not row:
            return -1
        alert_id = row[0]
        self._conn.execute(
            "UPDATE alerts SET resolved_at = ? WHERE id = ?",
            (resolved_at.isoformat(), alert_id),
        )
        self._conn.commit()
        return alert_id

    def recent_alerts(self, limit: int = 10) -> list[AlertRow]:
        rows = self._conn.execute(
            """SELECT id, timestamp, category, severity, title, message, resolved_at
               FROM alerts ORDER BY timestamp DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            AlertRow(
                id=r[0], timestamp=r[1], category=r[2],
                severity=r[3], title=r[4], message=r[5],
                resolved_at=r[6],
            )
            for r in rows
        ]

    def export_report(self, hours: int = 1) -> dict:
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()

        obs_rows = self._conn.execute(
            """SELECT timestamp, gateway_ip, gateway_loss, gateway_rtt_avg,
                      public_loss_avg, public_rtt_avg, dns_fail_count, dns_total_count
               FROM observations WHERE timestamp > ?
               ORDER BY timestamp DESC LIMIT 20""",
            (cutoff,),
        ).fetchall()

        diag_rows = self._conn.execute(
            """SELECT timestamp, category, summary, explanation, confidence
               FROM diagnoses WHERE timestamp > ?
               ORDER BY timestamp DESC LIMIT 10""",
            (cutoff,),
        ).fetchall()

        route_rows = self._conn.execute(
            """SELECT timestamp, target, hops_json, completed
               FROM route_snapshots
               ORDER BY timestamp DESC LIMIT 1""",
        ).fetchall()

        return {
            "generated_at": datetime.now().isoformat(),
            "observations": [
                {
                    "timestamp": r[0], "gateway_ip": r[1],
                    "gateway_loss": r[2], "gateway_rtt": r[3],
                    "public_loss": r[4], "public_rtt": r[5],
                    "dns_failures": r[6], "dns_total": r[7],
                }
                for r in obs_rows
            ],
            "diagnoses": [
                {
                    "timestamp": r[0], "category": r[1],
                    "summary": r[2], "explanation": r[3],
                    "confidence": r[4],
                }
                for r in diag_rows
            ],
            "latest_route": (
                json.loads(route_rows[0][2]) if route_rows and route_rows[0][2] else []
            ),
        }

    def save_device(
        self,
        mac: str,
        ip: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        status: Optional[str] = None,
        commit: bool = True,
    ) -> None:
        """Insert or update a discovered LAN device."""
        now = datetime.now().isoformat()
        existing = self._conn.execute(
            "SELECT status, first_seen FROM discovered_devices WHERE mac_address = ?",
            (mac,)
        ).fetchone()

        if existing:
            current_status = status if status else existing[0]
            self._conn.execute(
                """UPDATE discovered_devices
                   SET ip_address = ?, hostname = ?, vendor = ?, status = ?, last_seen = ?, is_active = 1
                   WHERE mac_address = ?""",
                (ip, hostname, vendor, current_status, now, mac)
            )
        else:
            current_status = status if status else "unknown"
            self._conn.execute(
                """INSERT INTO discovered_devices
                   (mac_address, ip_address, hostname, vendor, status, first_seen, last_seen, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                (mac, ip, hostname, vendor, current_status, now, now)
            )
        if commit:
            self._conn.commit()

    def get_devices(self) -> list[dict]:
        """Retrieve all discovered LAN devices."""
        rows = self._conn.execute(
            """SELECT mac_address, ip_address, hostname, vendor, status,
                      first_seen, last_seen, is_active, custom_name
               FROM discovered_devices ORDER BY ip_address"""
        ).fetchall()
        return [
            {
                "mac_address": r[0],
                "ip_address": r[1],
                "hostname": r[2],
                "vendor": r[3],
                "status": r[4],
                "first_seen": r[5],
                "last_seen": r[6],
                "is_active": bool(r[7]),
                "custom_name": r[8],
            }
            for r in rows
        ]

    def set_device_custom_name(self, mac: str, name: Optional[str]) -> None:
        """Set or clear the user-assigned custom name for a device.

        Passing None or empty string clears it (falls back to auto-resolved hostname).
        """
        clean = (name or "").strip() or None
        self._conn.execute(
            "UPDATE discovered_devices SET custom_name = ? WHERE mac_address = ?",
            (clean, mac),
        )
        self._conn.commit()

    def update_device_status(self, mac: str, status: str) -> None:
        """Update authorization status of a device."""
        self._conn.execute(
            "UPDATE discovered_devices SET status = ? WHERE mac_address = ?",
            (status, mac)
        )
        self._conn.commit()

    def set_all_devices_inactive(self, commit: bool = True) -> None:
        """Mark all devices as inactive (used before starting a scan)."""
        self._conn.execute("UPDATE discovered_devices SET is_active = 0")
        if commit:
            self._conn.commit()

    def clear_discovered_devices(self) -> None:
        """Clear all entries from the discovered_devices table."""
        self._conn.execute("DELETE FROM discovered_devices")
        self._conn.commit()


def _deserialize_observation(raw_json: str) -> Observation:
    """Reconstruct an Observation from stored JSON."""
    from losshound.core.models import PingResult, DnsResult, RouteHop

    d = json.loads(raw_json)
    ts = datetime.fromisoformat(d["timestamp"])

    gw_ping = None
    if d.get("gateway_ping"):
        gp = d["gateway_ping"]
        gw_ping = PingResult(
            target=gp["target"],
            timestamp=datetime.fromisoformat(gp["timestamp"]),
            packets_sent=gp["packets_sent"],
            packets_received=gp["packets_received"],
            loss_percent=gp["loss_percent"],
            rtt_min=gp.get("rtt_min"),
            rtt_avg=gp.get("rtt_avg"),
            rtt_max=gp.get("rtt_max"),
            rtt_jitter=gp.get("rtt_jitter"),
            timed_out=gp.get("timed_out", False),
            error=gp.get("error"),
        )

    pub_pings = []
    for pp in d.get("public_pings", []):
        pub_pings.append(PingResult(
            target=pp["target"],
            timestamp=datetime.fromisoformat(pp["timestamp"]),
            packets_sent=pp["packets_sent"],
            packets_received=pp["packets_received"],
            loss_percent=pp["loss_percent"],
            rtt_min=pp.get("rtt_min"),
            rtt_avg=pp.get("rtt_avg"),
            rtt_max=pp.get("rtt_max"),
            rtt_jitter=pp.get("rtt_jitter"),
            timed_out=pp.get("timed_out", False),
            error=pp.get("error"),
        ))

    dns_results = []
    for dr in d.get("dns_results", []):
        dns_results.append(DnsResult(
            hostname=dr["hostname"],
            timestamp=datetime.fromisoformat(dr["timestamp"]),
            resolved=dr["resolved"],
            resolved_ip=dr.get("resolved_ip"),
            resolution_time_ms=dr.get("resolution_time_ms"),
            error=dr.get("error"),
        ))

    route_snapshot = None
    if d.get("route_snapshot"):
        rs = d["route_snapshot"]
        hops = [
            RouteHop(
                hop_number=h["hop_number"],
                ip=h.get("ip"),
                rtt_samples=h.get("rtt_samples", []),
            )
            for h in rs.get("hops", [])
        ]
        route_snapshot = RouteSnapshot(
            target=rs["target"],
            timestamp=datetime.fromisoformat(rs["timestamp"]),
            hops=hops,
            completed=rs.get("completed", True),
            error=rs.get("error"),
        )

    return Observation(
        timestamp=ts,
        gateway_ip=d.get("gateway_ip"),
        gateway_ping=gw_ping,
        public_pings=pub_pings,
        dns_results=dns_results,
        route_snapshot=route_snapshot,
    )
