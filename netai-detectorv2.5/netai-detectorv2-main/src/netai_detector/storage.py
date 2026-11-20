"""SQLite storage: detection events (one per window) and incidents (groups of flagged windows)."""
from __future__ import annotations
from contextlib import contextmanager
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

    @contextmanager
    def _connect(self):
        """Commit on success, roll back on error, and always close (sqlite3's own context manager
        only commits, leaving connections open until garbage collection)."""
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

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
            # Device inventory: one row per IPv4 address, merged from every discovery source.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    label TEXT, hostname TEXT, dns_name TEXT, netbios_name TEXT,
                    mac TEXT, vendor TEXT, os TEXT,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    seen_by TEXT NOT NULL DEFAULT '[]',
                    ports TEXT NOT NULL DEFAULT '{}',
                    packets INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    up INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile TEXT NOT NULL, targets TEXT NOT NULL, status TEXT NOT NULL,
                    started_at TEXT NOT NULL, finished_at TEXT, hosts_up INTEGER, message TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    job_id INTEGER NOT NULL, ip TEXT NOT NULL,
                    hostname TEXT, mac TEXT, vendor TEXT, os TEXT,
                    ports TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (job_id, ip)
                )
            """)
            try:   # added in 2.5: link each scan to Aya's review of it
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN report_id INTEGER")
            except sqlite3.OperationalError:
                pass
            conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL, created_at TEXT NOT NULL, title TEXT NOT NULL,
                    grade TEXT, data TEXT NOT NULL
                )
            """)
            conn.execute("""UPDATE scan_jobs SET status='stopped', message='NetAI restarted during the scan'
                            WHERE status='running'""")
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

    # ------------------------------------------------------------------ device inventory
    _DEVICE_FIELDS = ("label", "hostname", "dns_name", "netbios_name", "mac", "vendor", "os")

    def upsert_device(self, ip: str, *, seen_by: str | None = None, ports: dict | None = None,
                      packets: int = 0, nbytes: int = 0, up: bool | None = None,
                      when: str | None = None, **fields) -> None:
        """Merge new knowledge about a device. Empty values never overwrite known ones;
        ports are merged by key ("tcp/22") with the newest details winning."""
        now = when or datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO devices (ip, first_seen, last_seen) VALUES (?, ?, ?)", (ip, now, now))
                row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
            current = dict(row)
            sources = json.loads(current["seen_by"] or "[]")
            if seen_by and seen_by not in sources:
                sources.append(seen_by)
            merged = json.loads(current["ports"] or "{}")
            for key, info in (ports or {}).items():
                merged[key] = {**merged.get(key, {}), **{k: v for k, v in info.items() if v not in (None, "")}}
            updates = {k: v for k, v in fields.items() if k in self._DEVICE_FIELDS and v not in (None, "")}
            updates.update(last_seen=max(current["last_seen"], now), seen_by=json.dumps(sources),
                           ports=json.dumps(merged), packets=current["packets"] + int(packets),
                           bytes=current["bytes"] + int(nbytes))
            if up is not None:
                updates["up"] = int(up)
            conn.execute(f"UPDATE devices SET {', '.join(k + '=?' for k in updates)} WHERE ip=?",
                         list(updates.values()) + [ip])

    def set_device_label(self, ip: str, label: str) -> None:
        with self._connect() as conn:
            if not conn.execute("SELECT 1 FROM devices WHERE ip=?", (ip,)).fetchone():
                now = datetime.now(timezone.utc).isoformat()
                conn.execute("INSERT INTO devices (ip, first_seen, last_seen, seen_by) VALUES (?, ?, ?, ?)",
                             (ip, now, now, json.dumps(["manual"])))
            conn.execute("UPDATE devices SET label=? WHERE ip=?", (label.strip() or None, ip))

    @staticmethod
    def _device_row(row) -> dict:
        item = dict(row)
        item["seen_by"] = json.loads(item["seen_by"] or "[]")
        item["ports"] = json.loads(item["ports"] or "{}")
        item["up"] = None if item["up"] is None else bool(item["up"])
        return item

    def devices(self, limit: int = 5000) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [self._device_row(r) for r in rows]

    def device(self, ip: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        return self._device_row(row) if row else None

    def device_names(self, ips) -> dict[str, dict]:
        ips = [i for i in set(ips) if i]
        if not ips:
            return {}
        out = {}
        with self._connect() as conn:
            for start in range(0, len(ips), 500):
                chunk = ips[start:start + 500]
                rows = conn.execute(
                    f"SELECT ip, label, hostname, dns_name, netbios_name, vendor FROM devices "
                    f"WHERE ip IN ({','.join('?' * len(chunk))})", chunk).fetchall()
                out.update({r["ip"]: dict(r) for r in rows})
        return out

    def delete_device(self, ip: str) -> bool:
        with self._connect() as conn:
            return conn.execute("DELETE FROM devices WHERE ip=?", (ip,)).rowcount > 0

    # ------------------------------------------------------------------ scan jobs and settings
    def add_scan_job(self, profile: str, targets: list[str]) -> int:
        with self._connect() as conn:
            cur = conn.execute("INSERT INTO scan_jobs (profile, targets, status, started_at) VALUES (?, ?, ?, ?)",
                               (profile, json.dumps(targets), "running", datetime.now(timezone.utc).isoformat()))
            return int(cur.lastrowid)

    def finish_scan_job(self, job_id: int, status: str, hosts_up: int | None, message: str = "") -> None:
        with self._connect() as conn:
            conn.execute("UPDATE scan_jobs SET status=?, finished_at=?, hosts_up=?, message=? WHERE id=?",
                         (status, datetime.now(timezone.utc).isoformat(), hosts_up, message, job_id))

    def save_scan_results(self, job_id: int, hosts: list[dict], keep_jobs: int = 200) -> None:
        """Keep the full result of every scan on this machine (newest `keep_jobs` scans)."""
        with self._connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO scan_results (job_id, ip, hostname, mac, vendor, os, ports) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(job_id, h["ip"], h.get("hostname"), h.get("mac"), h.get("vendor"), h.get("os"),
                  json.dumps(h.get("ports") or {})) for h in hosts])
            conn.execute("DELETE FROM scan_results WHERE job_id <= ?", (job_id - keep_jobs,))

    def scan_results(self, job_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scan_results WHERE job_id=? ORDER BY ip", (job_id,)).fetchall()
        out = [{**dict(r), "ports": json.loads(r["ports"] or "{}")} for r in rows]
        out.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
        return out

    def scan_job(self, job_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        return {**dict(row), "targets": json.loads(row["targets"])} if row else None

    def set_scan_report(self, job_id: int, report_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE scan_jobs SET report_id=? WHERE id=?", (report_id, job_id))

    def scan_jobs(self, limit: int = 20) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "targets": json.loads(r["targets"])} for r in rows]

    # ------------------------------------------------------------------ reports
    def save_report(self, report: dict, keep: int = 200) -> int:
        with self._connect() as conn:
            cur = conn.execute("INSERT INTO reports (kind, created_at, title, grade, data) VALUES (?, ?, ?, ?, ?)",
                               (report["kind"], report["generated_at"], report["title"], report.get("grade"),
                                json.dumps(report, default=str)))
            new_id = int(cur.lastrowid)
            conn.execute("DELETE FROM reports WHERE id <= ?", (new_id - keep,))
            return new_id

    def reports(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id, kind, created_at, title, grade FROM reports ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def report(self, report_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT id, data FROM reports WHERE id=?", (report_id,)).fetchone()
        return {**json.loads(row["data"]), "id": row["id"]} if row else None

    def latest_report(self) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT id, data FROM reports ORDER BY id DESC LIMIT 1").fetchone()
        return {**json.loads(row["data"]), "id": row["id"]} if row else None

    def get_setting(self, key: str, default=None):
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_setting(self, key: str, value) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            anomalies = conn.execute("SELECT COUNT(*) FROM events WHERE is_anomaly=1").fetchone()[0]
            high = conn.execute("SELECT COUNT(*) FROM events WHERE severity='high'").fetchone()[0]
            incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
            devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            high_incidents = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE peak_severity='high'").fetchone()[0]
        return {"events": total, "anomalies": anomalies, "high_severity": high,
                "incidents": incidents, "open_incidents": open_incidents,
                "high_incidents": high_incidents, "devices": devices}
