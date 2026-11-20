"""Culprit summaries, attack hints, incidents, advisor, evidence and alerts, tested with the
simulated attacks."""
import socket
import struct
import time
import numpy as np
import pytest
from netai_detector import alerts as alerts_module
from netai_detector import config
from netai_detector.advisor import advise
from netai_detector.alerts import Alerter, format_alert
from netai_detector.capture import parse_ipv4
from netai_detector.demo import SCENARIOS, DemoSource, synth_packets, synth_window
from netai_detector.detection import AnomalyDetector
from netai_detector.evidence import EvidenceStore, read_pcap
from netai_detector.forensics import analyse, is_internal
from netai_detector.incidents import IncidentTracker
from netai_detector.monitor import Monitor
from netai_detector.storage import EventStore

EXPECTED = {"portscan": "port_scan", "flood": "udp_flood", "exfil": "exfiltration",
            "synflood": "syn_flood", "bruteforce": "brute_force", "sweep": "host_sweep",
            "dnstunnel": "dns_tunnelling"}


# ------------------------------------------------------------------ hints and culprits
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_each_simulated_attack_gets_the_right_hint(scenario):
    rng = np.random.default_rng(5)
    for _ in range(5):
        packets, seconds, _ = synth_packets(rng, anomaly=scenario)
        result = analyse(packets, seconds)
        assert result["hints"], scenario
        assert result["hints"][0]["type"] == EXPECTED[scenario]
        assert result["culprits"]["top_flows"]


def test_normal_traffic_rarely_gets_attack_hints():
    rng = np.random.default_rng(6)
    hinted = sum(bool(analyse(*synth_packets(rng)[:2])["hints"]) for _ in range(100))
    assert hinted <= 2


def test_culprit_summary_names_scanner_and_target():
    packets, seconds, _ = synth_packets(np.random.default_rng(1), anomaly="portscan")
    c = analyse(packets, seconds)["culprits"]
    flow = c["top_flows"][0]
    assert (flow["src"], flow["dst"], flow["proto"]) == ("192.168.1.66", "192.168.1.1", "tcp")
    assert flow["distinct_dst_ports"] == 100 and flow["syn_only_ratio"] == 1.0
    assert c["top_sources"][0]["ip"] == "192.168.1.66" and c["top_sources"][0]["internal"]


def test_internal_means_local_networks_only():
    assert is_internal("192.168.1.5") and is_internal("10.1.2.3") and is_internal("172.20.0.1")
    assert not is_internal("203.0.113.9") and not is_internal("8.8.8.8") and not is_internal("junk")


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_model_flags_every_simulated_attack(scenario):
    rng = np.random.default_rng(11)
    det = AnomalyDetector()
    det.fit(np.stack([synth_window(rng)[0] for _ in range(80)]))
    assert all(det.predict(synth_window(rng, anomaly=scenario)[0])["is_anomaly"] for _ in range(5))


# ------------------------------------------------------------------ incidents
def _flag(tracker, kind, ts, severity="high", source="live:eth0"):
    packets, seconds, _ = synth_packets(np.random.default_rng(int(ts)), anomaly=kind)
    return tracker.anomaly(source, ts, {"severity": severity, "score": 0.7, "is_anomaly": True},
                           analyse(packets, seconds), [{"feature": "syn_ratio", "value": 1, "z": 9.8}])


def test_consecutive_windows_merge_into_one_incident(tmp_path):
    store = EventStore(tmp_path / "e.db")
    tracker = IncidentTracker(store, close_after=3, gap_seconds=120)
    first = _flag(tracker, "portscan", 1000, "medium")
    assert first["new"] and first["incident"]["peak_severity"] == "high"   # clear scan pattern
    second = _flag(tracker, "portscan", 1005, "high")
    assert not second["new"] and not second["escalated"]
    _flag(tracker, "portscan", 1010)
    for t in (1015, 1020):
        assert tracker.normal("live:eth0", t) == []
    closed = tracker.normal("live:eth0", 1025)
    assert closed and closed[0]["status"] == "closed"
    stored = store.incidents()
    assert len(stored) == 1
    inc = stored[0]
    assert inc["windows"] == 3 and inc["peak_severity"] == "high" and inc["attack_type"] == "port_scan"
    assert inc["hints"][0]["windows"] == 3
    assert inc["culprits"]["top_sources"][0]["ip"] == "192.168.1.66"
    assert inc["culprits"]["top_sources"][0]["packets"] == 300


def test_clear_attack_pattern_raises_incident_to_high(tmp_path):
    store = EventStore(tmp_path / "e.db")
    inc = _flag(IncidentTracker(store), "synflood", 1000, "medium")["incident"]
    assert inc["peak_severity"] == "high" and "syn flood" in inc["severity_reason"]
    assert store.incident(inc["id"])["severity_reason"] == inc["severity_reason"]
    store2 = EventStore(tmp_path / "f.db")
    tracker = IncidentTracker(store2)
    packets, seconds, _ = synth_packets(np.random.default_rng(1))
    plain = tracker.anomaly("live:x", 1000, {"severity": "medium", "score": 0.6, "is_anomaly": True},
                            analyse(packets, seconds))["incident"]
    assert plain["peak_severity"] == "medium"          # no clear pattern: stays as the model said
    later = tracker.anomaly("live:x", 1005, {"severity": "high", "score": 0.8, "is_anomaly": True},
                            analyse(packets, seconds))
    assert later["escalated"] and later["incident"]["peak_severity"] == "high"


def test_unrelated_simultaneous_attacks_are_separate_incidents(tmp_path):
    store = EventStore(tmp_path / "e.db")
    tracker = IncidentTracker(store, close_after=3, gap_seconds=120)
    scan = _flag(tracker, "portscan", 1000)["incident"]["id"]
    brute = _flag(tracker, "bruteforce", 1001)["incident"]["id"]
    assert scan != brute
    assert _flag(tracker, "portscan", 1002)["incident"]["id"] == scan       # interleaved: same ids
    assert _flag(tracker, "bruteforce", 1003)["incident"]["id"] == brute
    for t in range(1004, 1007):                                              # scan stops, brute goes on
        _flag(tracker, "bruteforce", t)
    assert store.incident(scan)["status"] == "closed" and store.incident(scan)["close_reason"] == "activity stopped"
    assert store.incident(brute)["status"] == "open"
    assert store.incident(scan)["attack_type"] == "port_scan" and store.incident(brute)["attack_type"] == "brute_force"


def test_long_gap_starts_a_new_incident(tmp_path):
    store = EventStore(tmp_path / "e.db")
    tracker = IncidentTracker(store, close_after=3, gap_seconds=60)
    a = _flag(tracker, "bruteforce", 1000)["incident"]["id"]
    b = _flag(tracker, "bruteforce", 1200)["incident"]["id"]
    assert a != b
    assert store.incident(a)["status"] == "closed" and store.incident(a)["close_reason"] == "quiet period"


def test_open_incidents_are_closed_after_a_restart(tmp_path):
    store = EventStore(tmp_path / "e.db")
    _flag(IncidentTracker(store), "sweep", 1000)
    assert store.stats()["open_incidents"] == 1
    reopened = EventStore(tmp_path / "e.db")
    assert reopened.stats()["open_incidents"] == 0
    assert reopened.incidents()[0]["close_reason"] == "monitor restarted"


# ------------------------------------------------------------------ advisor
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_advisor_gives_a_filled_in_plan_for_each_attack(tmp_path, scenario):
    store = EventStore(tmp_path / "e.db")
    inc = _flag(IncidentTracker(store), scenario, 1000)["incident"]
    plan = advise(inc)
    assert plan["attack_type"] == EXPECTED[scenario]
    assert plan["summary"] and plan["steps"] and plan["disclaimer"]
    text = " ".join(i for s in plan["steps"] for i in s["items"])
    assert plan["target"] in text or plan["attacker"] in text  # real addresses, not placeholders


def test_advisor_blocks_external_attacker_but_isolates_internal_one(tmp_path):
    store = EventStore(tmp_path / "e.db")
    brute = advise(_flag(IncidentTracker(store), "bruteforce", 1000)["incident"])
    assert brute["attacker"] == "203.0.113.77" and not brute["attacker_internal"]
    assert any("203.0.113.77" in c["run"] and "Inbound" in c["run"] for c in brute["commands"])
    assert all(c["undo"] for c in brute["commands"])
    scan = advise(_flag(IncidentTracker(store), "portscan", 2000, source="other")["incident"])
    assert scan["attacker_internal"] and not scan["commands"]
    assert any("Find the device" in i for s in scan["steps"] for i in s["items"])
    exfil = advise(_flag(IncidentTracker(store), "exfil", 3000, source="x")["incident"])
    assert any("203.0.113.9" in c["run"] and "Outbound" in c["run"] for c in exfil["commands"])


def test_advisor_mentions_trusted_hosts(tmp_path, monkeypatch):
    from netai_detector import advisor
    monkeypatch.setattr(advisor, "TRUSTED_HOSTS", {"192.168.1.66"})
    store = EventStore(tmp_path / "e.db")
    plan = advise(_flag(IncidentTracker(store), "portscan", 1000)["incident"])
    assert plan["trusted_note"] and "192.168.1.66" in plan["trusted_note"]


# ------------------------------------------------------------------ evidence
def _raw_tcp_with_payload(payload=b"SECRET-PASSWORD=hunter2" * 20):
    tcp = struct.pack("!HHIIBBHHH", 51000, 22, 1, 0, 5 << 4, 0x18, 1000, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     socket.inet_aton("203.0.113.77"), socket.inet_aton("192.168.1.5"))
    return ip + tcp + payload, total


def test_evidence_keeps_headers_and_never_the_payload(tmp_path):
    data, total = _raw_tcp_with_payload()
    packets = [parse_ipv4(data, ts=1000.0 + i) for i in range(5)]
    ev = EvidenceStore(tmp_path / "ev")
    path = ev.path_for(1)
    assert ev.append(path, packets) == 5
    records = read_pcap(path)
    assert len(records) == 5
    ts, captured, orig = records[0]
    assert ts == 1000.0 and len(captured) == 40 and orig == total   # IP 20 + TCP 20 bytes only
    assert b"SECRET" not in path.read_bytes()
    again = parse_ipv4(captured)
    assert (again["IP"].src, again["IP"].dst, again["TCP"].dport) == ("203.0.113.77", "192.168.1.5", 22)


def test_evidence_from_simulated_packets_is_valid(tmp_path):
    packets, _, _ = synth_packets(np.random.default_rng(2), anomaly="synflood")
    ev = EvidenceStore(tmp_path / "ev")
    path = ev.path_for(7, "demo")
    ev.append(path, packets)
    records = read_pcap(path)
    assert len(records) == 100
    hdr = records[0][1][:20]
    total = sum(struct.unpack("!10H", hdr))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    assert total == 0xFFFF                                   # IPv4 header checksum is valid
    p = parse_ipv4(records[0][1])
    assert p["IP"].dst == "192.168.1.5" and p["TCP"].flags == 0x02


def test_evidence_respects_packet_and_size_caps(tmp_path):
    packets, _, _ = synth_packets(np.random.default_rng(3), anomaly="portscan")
    ev = EvidenceStore(tmp_path / "ev", max_mb=1, max_packets=150)
    path = ev.path_for(1)
    assert ev.append(path, packets) == 100
    assert ev.append(path, packets, already=100) == 50
    assert ev.append(path, packets, already=150) == 0
    ev.max_bytes = 5000                           # tiny cap: older files must go first
    old = tmp_path / "ev" / "old.pcap"
    old.write_bytes(b"x" * 4000)
    import os
    os.utime(old, (1, 1))
    deleted = ev.enforce_cap(keep={str(path)})
    assert str(old) in deleted and path.exists()


# ------------------------------------------------------------------ alerts
def test_alert_text_and_redaction():
    inc = {"id": 4, "source": "live:eth0", "peak_severity": "high", "attack_type": "brute_force",
           "started_at": "2026-11-20T00:41:00+00:00", "windows": 3,
           "hints": [{"evidence": "203.0.113.77 opened 34 connections to SSH on 192.168.1.5"}],
           "culprits": {"top_flows": [{"src": "203.0.113.77", "dst": "192.168.1.5", "proto": "tcp",
                                       "packets": 300}]}}
    title, body = format_alert(inc)
    assert "HIGH" in title and "brute-force" in title and "203.0.113.77" in body
    _, redacted = format_alert(inc, include_hosts=False)
    assert "203.0.113.77" not in redacted and "[address]" in redacted


def test_alerts_fire_once_per_incident_and_again_on_escalation(monkeypatch):
    monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "medium")
    sent = []
    alerter = Alerter(senders={"desktop": lambda t, b: sent.append(t)})
    inc = {"id": 1, "source": "live:eth0", "peak_severity": "low", "attack_type": "port_scan"}
    assert not alerter.consider(inc, "new")                    # below threshold
    inc["peak_severity"] = "medium"
    assert alerter.consider(inc, "new")
    assert not alerter.consider(inc, "new")                    # no repeat
    inc["peak_severity"] = "high"
    assert alerter.consider(inc, "escalated")
    assert not alerter.consider({**inc, "id": 2, "source": "demo"}, "new")   # demo never alerts
    deadline = time.time() + 5
    while len(sent) < 2 and time.time() < deadline:
        time.sleep(0.05)
    assert len(sent) == 2 and "escalated" in sent[1]


def test_slack_and_email_use_their_settings(monkeypatch):
    monkeypatch.setattr(config, "SLACK_WEBHOOK", "https://hooks.slack.example/T/B/X")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "SMTP_FROM", "netai@example.com")
    monkeypatch.setattr(config, "ALERT_EMAIL_TO", ["me@example.com"])
    monkeypatch.setattr(config, "ALERT_INCLUDE_HOSTS", False)
    calls = {}

    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout):
        calls["slack"] = (req.full_url, req.data.decode())
        return Resp()

    class FakeSMTP:
        def __init__(self, host, port, timeout): calls["smtp"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context): calls["tls"] = True
        def login(self, u, p): pass
        def send_message(self, msg): calls["mail"] = (msg["To"], msg.get_content())

    monkeypatch.setattr(alerts_module.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(alerts_module.smtplib, "SMTP", FakeSMTP)
    alerter = Alerter(senders={"email": alerts_module._email, "slack": alerts_module._slack})
    inc = {"id": 9, "source": "live:eth0", "peak_severity": "high", "attack_type": "syn_flood",
           "hints": [{"evidence": "flood to 192.168.1.5"}]}
    assert alerter.send(inc) == {"email": "sent", "slack": "sent"}
    assert calls["slack"][0].startswith("https://hooks.slack.example")
    assert "192.168.1.5" not in calls["slack"][1] and "192.168.1.5" not in calls["mail"][1]
    assert calls["mail"][0] == "me@example.com" and calls["tls"]


def test_failed_alert_becomes_a_dashboard_warning():
    warnings = []

    def broken(t, b):
        raise OSError("no route")
    alerter = Alerter(on_error=warnings.append, senders={"desktop": broken})
    result = alerter.send({"id": 1, "source": "live:x", "peak_severity": "high", "attack_type": "unknown"})
    assert result["desktop"].startswith("failed") and "desktop" in warnings[0]


# ------------------------------------------------------------------ end to end
class AttackingLive(DemoSource):
    kind = "live"
    interface = "test0"


def test_monitor_investigates_records_evidence_and_alerts(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "low")
    sent = []
    rng = np.random.default_rng(3)
    det = AnomalyDetector()
    det.fit(np.stack([synth_window(rng)[0] for _ in range(60)]))
    det.metadata["synthetic"] = False
    det.save(tmp_path / "m.joblib")
    store = EventStore(tmp_path / "e.db")
    source = AttackingLive(learn_pace=0, monitor_pace=0.01, anomaly_rate=1.0, seed=4,
                           scenarios=("bruteforce",))
    mon = Monitor(store, tmp_path / "m.joblib", tmp_path / "b.npz", mode="auto", learn_windows=20,
                  source_factory=lambda: source, retrain_every=0,
                  evidence=EvidenceStore(tmp_path / "ev"), evidence_level="all",
                  alerter=Alerter(senders={"desktop": lambda t, b: sent.append((t, b))}))
    mon.start()
    try:
        assert _wait(lambda: store.stats()["incidents"] >= 1 and store.stats()["anomalies"] >= 3)
    finally:
        mon.stop()
    inc = store.incidents()[0]
    assert inc["attack_type"] == "brute_force" and inc["status"] == "closed"
    assert inc["culprits"]["top_sources"][0]["ip"] == "203.0.113.77"
    assert inc["evidence_packets"] >= 300 and read_pcap(inc["evidence_path"])
    flagged = [e for e in store.recent(50) if e["is_anomaly"]]
    assert flagged[0]["details"]["incident_id"] == inc["id"]
    assert flagged[0]["details"]["hints"][0]["type"] == "brute_force"
    normal = [e for e in store.recent(50) if not e["is_anomaly"]]
    assert all("culprits" not in e["details"] for e in normal)   # no host data for normal traffic
    assert _wait(lambda: sent, 5) and "brute-force" in sent[0][0]
    assert mon.status()["investigation"]["evidence"] == "all"


def test_evidence_waits_for_high_severity_but_keeps_the_start(tmp_path):
    store = EventStore(tmp_path / "e.db")
    mon = Monitor(store, tmp_path / "m.joblib", tmp_path / "b.npz", mode="off",
                  evidence=EvidenceStore(tmp_path / "ev"), evidence_level="high",
                  alerter=Alerter(senders={}))
    packets, _, _ = synth_packets(np.random.default_rng(1))       # unusual, but no clear pattern
    details = {"top_features": []}
    medium = {"severity": "medium", "score": 0.6, "is_anomaly": True}
    inc = mon._investigate(medium, details, packets, 1.5, "live:x", 1000)
    mon._collect_evidence(inc, packets)
    assert not inc.get("evidence_path")                        # not yet: only medium
    high = {"severity": "high", "score": 0.9, "is_anomaly": True}
    inc = mon._investigate(high, dict(details), packets, 1.5, "live:x", 1005)
    mon._collect_evidence(inc, packets)
    assert inc["evidence_packets"] == 200                      # held window + current one
    assert len(read_pcap(inc["evidence_path"])) == 200


def _wait(cond, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False
