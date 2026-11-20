"""SQLite storage for events, alerts and incidents.

Tables are created with ``executescript`` because the schema holds several
CREATE TABLE statements. The database path comes from ``SIEM_DB_PATH``
(see :mod:`server.config`) so tests can point it at a temporary file.
"""

import json
import sqlite3
from datetime import datetime, timezone

from server import config
from shared.schemas import Alert, Incident, LogEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    host TEXT NOT NULL,
    service TEXT NOT NULL,
    user TEXT,
    source_ip TEXT,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    raw TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    source_ip TEXT,
    user TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    alert_ids TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the tables if they do not exist yet."""
    with _connect() as conn:
        conn.executescript(SCHEMA)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- events ---------------------------------------------------------------

def insert_events(events: list[LogEvent]) -> int:
    """Store events, return how many were stored."""
    with _connect() as conn:
        conn.executemany(
            "INSERT INTO events (timestamp, host, service, user, source_ip,"
            " event_type, message, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (e.timestamp, e.host, e.service, e.user, e.source_ip, e.event_type, e.message, e.raw)
                for e in events
            ],
        )
    return len(events)


def get_events(limit: int = 500) -> list[LogEvent]:
    """Return the most recent stored events (newest first)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT timestamp, host, service, user, source_ip, event_type, message, raw"
            " FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [LogEvent(**dict(row)) for row in rows]


# --- alerts ---------------------------------------------------------------

def insert_alert(alert: Alert) -> Alert:
    """Store an alert and return it with its new id."""
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO alerts (alert_type, severity, title, description,"
            " source_ip, user, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.alert_type,
                alert.severity,
                alert.title,
                alert.description,
                alert.source_ip,
                alert.user,
                alert.status,
                _now(),
            ),
        )
        alert.id = cursor.lastrowid
    return alert


def get_alerts(severity: str | None = None, status: str | None = None) -> list[Alert]:
    """Return alerts (newest first), optionally filtered by severity/status."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list[str] = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY id DESC"
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [Alert(**dict(row)) for row in rows]


def get_alert(alert_id: int) -> Alert | None:
    """Return one alert by id, or None."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return Alert(**dict(row)) if row else None


def acknowledge_alert(alert_id: int) -> bool:
    """Mark an alert acknowledged; True when an alert was updated."""
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = 'acknowledged' WHERE id = ?", (alert_id,)
        )
    return cursor.rowcount > 0


# --- incidents ------------------------------------------------------------

def insert_incident(incident: Incident) -> Incident:
    """Store an incident and return it with its new id."""
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO incidents (title, severity, alert_ids, status, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                incident.title,
                incident.severity,
                json.dumps(incident.alert_ids),
                incident.status,
                _now(),
            ),
        )
        incident.id = cursor.lastrowid
    return incident


def get_incidents() -> list[Incident]:
    """Return incidents (newest first)."""
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
    incidents = []
    for row in rows:
        data = dict(row)
        data["alert_ids"] = json.loads(data["alert_ids"])
        incidents.append(Incident(**data))
    return incidents


# --- stats ----------------------------------------------------------------

def get_stats() -> dict:
    """Counts for the dashboard and CLI."""
    with _connect() as conn:
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
        ).fetchone()[0]
        by_severity = {
            row["severity"]: row["count"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
            ).fetchall()
        }
        total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    return {
        "events": total_events,
        "alerts": total_alerts,
        "open_alerts": open_alerts,
        "alerts_by_severity": by_severity,
        "incidents": total_incidents,
    }
