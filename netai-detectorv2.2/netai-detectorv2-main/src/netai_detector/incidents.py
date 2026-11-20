"""Group consecutive flagged windows into incidents.

Forty flagged rows in a row are one attack, not forty. An incident opens on the first flagged window,
absorbs the ones that follow (merging hosts, hints and peak severity), and closes after a few normal
windows in a row, or when nothing has been flagged for a while.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timezone
from .config import INCIDENT_CLOSE_AFTER, INCIDENT_GAP_SECONDS
from .forensics import is_internal

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


class _Open:
    """In-memory aggregate of the incident currently open for one source."""

    def __init__(self, source: str, ts: float):
        self.source = source
        self.record: dict = {"source": source, "status": "open", "started_at": iso(ts),
                             "last_seen_at": iso(ts), "peak_severity": "low", "peak_score": None,
                             "windows": 0, "attack_type": "unknown", "hints": [], "culprits": {},
                             "top_features": [], "evidence_path": None, "evidence_packets": 0}
        self.last_ts = ts
        self.normal_streak = 0
        self.packets = self.bytes = 0
        self.seconds = 0.0
        self.src: dict = defaultdict(lambda: [0, 0, 0, 0])   # packets, bytes, max peers, max ports
        self.dst: dict = defaultdict(lambda: [0, 0, 0, 0])
        self.flows: dict = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set(), "syn": 0.0})
        self.ports: Counter = Counter()
        self.protocols: Counter = Counter()
        self.hints: dict = {}
        self.features: dict = {}
        self.hosts: set[str] = set()      # attacker/target addresses of recognised patterns

    def absorb(self, ts: float, result: dict, analysis: dict, top_features: list | None) -> dict:
        rec = self.record
        before = rec["peak_severity"]
        rec["windows"] += 1
        rec["last_seen_at"] = iso(ts)
        self.last_ts, self.normal_streak = ts, 0
        sev = result.get("severity", "low")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(rec["peak_severity"], 0):
            rec["peak_severity"] = sev
        score = result.get("score")
        if score is not None and (rec["peak_score"] is None or score > rec["peak_score"]):
            rec["peak_score"] = float(score)

        c = analysis.get("culprits") or {}
        self.packets += c.get("packets", 0)
        self.bytes += c.get("bytes", 0)
        self.seconds += c.get("seconds", 0.0)
        self.protocols.update(c.get("protocols") or {})
        for table, rows, peer_key in ((self.src, c.get("top_sources"), "destinations"),
                                      (self.dst, c.get("top_destinations"), "sources")):
            for r in rows or []:
                agg = table[r["ip"]]
                agg[0] += r["packets"]; agg[1] += r["bytes"]
                agg[2] = max(agg[2], r.get(peer_key, 0)); agg[3] = max(agg[3], r.get("distinct_ports", 0))
        for f in c.get("top_flows") or []:
            agg = self.flows[(f["src"], f["dst"], f["proto"])]
            agg["packets"] += f["packets"]; agg["bytes"] += f["bytes"]
            agg["ports"].update(f.get("top_dst_ports") or [])
            agg["distinct"] = max(agg.get("distinct", 0), f.get("distinct_dst_ports", 0))
            agg["syn"] = max(agg["syn"], f.get("syn_only_ratio", 0.0))
        for p in c.get("top_dst_ports") or []:
            self.ports[(p["proto"], p["port"])] += p["packets"]

        for h in analysis.get("hints") or []:
            cur = self.hints.get(h["type"])
            if cur is None:
                self.hints[h["type"]] = {**h, "windows": 1, "ports": list(h.get("ports") or [])}
            else:
                cur["windows"] += 1
                cur["evidence"] = h["evidence"]  # latest numbers
                cur["ports"] = sorted(set(cur["ports"]) | set(h.get("ports") or []))[:20]
                if _CONF_RANK[h["confidence"]] > _CONF_RANK[cur["confidence"]]:
                    cur["confidence"] = h["confidence"]
                cur["attacker_count"] = max(cur.get("attacker_count") or 0, h.get("attacker_count") or 0) or None
                cur["attacker"] = cur.get("attacker") or h.get("attacker")
                cur["target"] = cur.get("target") or h.get("target")
        for f in top_features or []:
            prev = self.features.get(f["feature"])
            if prev is None or abs(f["z"]) > abs(prev["z"]):
                self.features[f["feature"]] = f

        hints = sorted(self.hints.values(), key=lambda h: (-_CONF_RANK[h["confidence"]], -h["windows"]))
        rec["hints"] = hints
        rec["attack_type"] = hints[0]["type"] if hints else "unknown"
        # Severity combines the model score with the pattern match: a known attack recognised with
        # high confidence is high severity even if the statistical score alone said medium.
        if hints and hints[0]["type"] != "unknown" and hints[0]["confidence"] == "high" \
                and SEVERITY_RANK.get(rec["peak_severity"], 0) < SEVERITY_RANK["high"]:
            rec["peak_severity"] = "high"
            rec["severity_reason"] = f"raised to high: clear {hints[0]['title'].lower()} pattern"
        rec["top_features"] = sorted(self.features.values(), key=lambda f: -abs(f["z"]))[:5]
        rec["culprits"] = self._culprits()
        return {"escalated": SEVERITY_RANK.get(rec["peak_severity"], 0) > SEVERITY_RANK.get(before, 0)}

    def _culprits(self, top: int = 10) -> dict:
        def rows(table, peer_key):
            out = sorted(table.items(), key=lambda kv: -kv[1][0])[:top]
            return [{"ip": ip, "internal": is_internal(ip), "packets": v[0], "bytes": v[1],
                     peer_key: v[2], "distinct_ports": v[3]} for ip, v in out]
        flows = sorted(self.flows.items(), key=lambda kv: -kv[1]["packets"])[:top]
        return {
            "packets": self.packets, "bytes": self.bytes, "seconds": round(self.seconds, 1),
            "protocols": dict(self.protocols),
            "top_sources": rows(self.src, "destinations"),
            "top_destinations": rows(self.dst, "sources"),
            "top_flows": [{"src": s, "dst": d, "proto": p, "packets": v["packets"], "bytes": v["bytes"],
                           "distinct_dst_ports": max(v.get("distinct", 0), len(v["ports"])),
                           "top_dst_ports": sorted(v["ports"])[:10], "syn_only_ratio": v["syn"]}
                          for (s, d, p), v in flows],
            "top_dst_ports": [{"proto": pr, "port": po, "packets": n}
                              for (pr, po), n in self.ports.most_common(top)],
        }


def window_hosts(analysis: dict) -> set[str]:
    """The specific addresses a window's recognised attack patterns point at."""
    return {ip for h in analysis.get("hints") or [] if h.get("type") != "unknown"
            for ip in (h.get("attacker"), h.get("target")) if ip}


class IncidentTracker:
    """Groups flagged windows into incidents and persists every change.

    Windows are matched to an open incident by the hosts involved, so two unrelated attacks running
    at the same time (a scan from one host, a flood against another) become two incidents. A window
    with no recognisable pattern joins the most recent open incident. An incident closes after
    `close_after` windows in a row that weren't part of it, or `gap_seconds` without activity."""

    def __init__(self, store, close_after: int = INCIDENT_CLOSE_AFTER,
                 gap_seconds: float = INCIDENT_GAP_SECONDS):
        self.store, self.close_after, self.gap_seconds = store, close_after, gap_seconds
        self._open: dict[str, list[_Open]] = {}

    def anomaly(self, source: str, ts: float, result: dict, analysis: dict,
                top_features: list | None = None) -> dict:
        """Record a flagged window. Returns {"incident": record, "new": bool, "escalated": bool}."""
        live = []
        for inc in self._open.get(source, []):
            if ts - inc.last_ts > self.gap_seconds:
                self._close(inc, "quiet period")
            else:
                live.append(inc)
        hosts = window_hosts(analysis)
        match = None
        if hosts:
            match = next((o for o in reversed(live) if o.hosts & hosts), None)
            if match is None:   # an incident that so far had no recognisable pattern adopts this one
                match = next((o for o in reversed(live) if not o.hosts), None)
        elif live:
            match = max(live, key=lambda o: o.last_ts)
        new = match is None
        if new:
            match = _Open(source, ts)
            live.append(match)
        for other in live:
            if other is not match:
                other.normal_streak += 1
        self._open[source] = live
        change = match.absorb(ts, result, analysis, top_features)
        match.hosts |= hosts
        match.record["id"] = self.store.save_incident(match.record)
        for other in [o for o in live if o is not match and o.normal_streak >= self.close_after]:
            self._close(other, "activity stopped")
        return {"incident": match.record, "new": new, "escalated": change["escalated"] and not new}

    def normal(self, source: str, ts: float) -> list[dict]:
        """Record a normal window. Returns the incidents this closed."""
        closed = []
        for inc in list(self._open.get(source, [])):
            inc.normal_streak += 1
            if inc.normal_streak >= self.close_after or ts - inc.last_ts > self.gap_seconds:
                closed.append(self._close(inc, "traffic back to normal"))
        return closed

    def open_incidents(self, source: str | None = None) -> list[dict]:
        return [o.record for s, items in self._open.items() if source is None or s == source
                for o in items]

    def close_all(self, reason: str, source: str | None = None) -> list[dict]:
        targets = [o for s, items in list(self._open.items()) if source is None or s == source
                   for o in items]
        return [self._close(o, reason) for o in targets]

    def _close(self, current: _Open, reason: str) -> dict:
        rec = current.record
        rec.update(status="closed", ended_at=iso(current.last_ts), close_reason=reason)
        self.store.save_incident(rec)
        items = self._open.get(current.source, [])
        if current in items:
            items.remove(current)
        if not items:
            self._open.pop(current.source, None)
        return rec
