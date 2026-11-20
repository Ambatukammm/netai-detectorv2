"""SQLite storage: detection events (one per window) and incidents (groups of flagged windows)."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from .config import DB_PATH, MAX_EVENTS, hand_back_to_user

class EventStore:
    def __init__(self, path: Path | str = DB_PATH, max_events: int = MAX_EVENTS,
                 max_incidents: int = 5000):
        self.path = Path(path)
        self.max_events = max_events
        self.max_incidents = max_incidents
        self._inserts = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        hand_back_to_user(self.path.parent)
        hand_back_to_user(self.path)

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    is_anomaly INTEGER NOT NULL,
                    score REAL,
                    threshold REAL,
                    details TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    ended_at TEXT,
                    close_reason TEXT,
                    peak_severity TEXT NOT NULL,
                    severity_reason TEXT,
                    peak_score REAL,
                    windows INTEGER NOT NULL,
                    attack_type TEXT NOT NULL,
                    hints TEXT NOT NULL,
                    culprits TEXT NOT NULL,
                    top_features TEXT NOT NULL,
                    evidence_path TEXT,
                    evidence_packets INTEGER NOT NULL DEFAULT 0
                )
            """)
            # Incidents left open by a crash or shutdown can never receive more windows: close them.
            conn.execute("""UPDATE incidents SET status='closed', close_reason='monitor restarted',
                            ended_at=last_seen_at WHERE status='open'""")

    def add_event(self, result: dict, source: str = "api", details: dict | None = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO events
                (created_at, source, severity, is_anomaly, score, threshold, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (datetime.now(timezone.utc).isoformat(), source, result["severity"],
                 int(result["is_anomaly"]), result.get("score"), result.get("threshold"),
                 json.dumps(details or {}))
            )
            event_id = int(cur.lastrowid)
        self._inserts += 1
        if self._inserts % 200 == 0:
            self.prune()
        return event_id

    def prune(self) -> None:
        """Keep only the newest `max_events` rows so a long-running monitor cannot fill the disk."""
        with self._connect() as conn:
            conn.execute("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?",
                         (self.max_events,))

    def delete_by_source(self, source: str) -> int:
        with self._connect() as conn:
            return conn.execute("DELETE FROM events WHERE source = ?", (source,)).rowcount

    def recent(self, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item["details"])
            item["is_anomaly"] = bool(item["is_anomaly"])
            output.append(item)
        return output

    # ------------------------------------------------------------------ incidents
    _INCIDENT_JSON = ("hints", "culprits", "top_features")

    def save_incident(self, incident: dict) -> int:
        """Insert (no id) or update (with id) an incident. Returns its id."""
        cols = ["source", "status", "started_at", "last_seen_at", "ended_at", "close_reason",
                "peak_severity", "severity_reason", "peak_score", "windows", "attack_type", "hints", "culprits",
                "top_features", "evidence_path", "evidence_packets"]
        values = [json.dumps(incident.get(c) or ([] if c != "culprits" else {}))
                  if c in self._INCIDENT_JSON else incident.get(c) for c in cols]
        values[cols.index("evidence_packets")] = int(incident.get("evidence_packets") or 0)
        with self._connect() as conn:
            if incident.get("id"):
                conn.execute(f"UPDATE incidents SET {', '.join(c + '=?' for c in cols)} WHERE id=?",
                             values + [incident["id"]])
                return int(incident["id"])
            cur = conn.execute(f"INSERT INTO incidents ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                               values)
            new_id = int(cur.lastrowid)
            conn.execute("DELETE FROM incidents WHERE id <= ?", (new_id - self.max_incidents,))
            return new_id

    def _incident_row(self, row) -> dict:
        item = dict(row)
        for key in self._INCIDENT_JSON:
            item[key] = json.loads(item[key] or "null")
        return item

    def incidents(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
                                (max(1, min(limit, 500)),)).fetchall()
        return [self._incident_row(r) for r in rows]

    def incident(self, incident_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return self._incident_row(row) if row else None

    def evidence_paths(self) -> set[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT evidence_path FROM incidents WHERE evidence_path IS NOT NULL").fetchall()
        return {r[0] for r in rows}

    def clear_evidence(self, path: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE incidents SET evidence_path=NULL WHERE evidence_path=?", (path,))

    def delete_incidents_by_source(self, source: str) -> int:
        with self._connect() as conn:
            return conn.execute("DELETE FROM incidents WHERE source = ?", (source,)).rowcount

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            anomalies = conn.execute("SELECT COUNT(*) FROM events WHERE is_anomaly=1").fetchone()[0]
            high = conn.execute("SELECT COUNT(*) FROM events WHERE severity='high'").fetchone()[0]
            incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
        return {"events": total, "anomalies": anomalies, "high_severity": high,
                "incidents": incidents, "open_incidents": open_incidents}
