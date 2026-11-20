"""SQLite event storage."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from .config import DB_PATH, MAX_EVENTS, hand_back_to_user

class EventStore:
    def __init__(self, path: Path | str = DB_PATH, max_events: int = MAX_EVENTS):
        self.path = Path(path)
        self.max_events = max_events
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

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            anomalies = conn.execute("SELECT COUNT(*) FROM events WHERE is_anomaly=1").fetchone()[0]
            high = conn.execute("SELECT COUNT(*) FROM events WHERE severity='high'").fetchone()[0]
        return {"events": total, "anomalies": anomalies, "high_severity": high}
