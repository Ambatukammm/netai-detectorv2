"""Removing data: reports, scans, incidents (with evidence), events, devices, terminal log."""
import numpy as np
import pytest
from netai_detector.demo import synth_packets
from netai_detector.forensics import analyse
from netai_detector.incidents import IncidentTracker
from netai_detector.notifications import NotificationSettings
from netai_detector.notifier import Notifier, ReportService
from netai_detector.storage import EventStore


def filled(tmp_path):
    store = EventStore(tmp_path / "e.db")
    store.upsert_device("192.168.1.5", seen_by="nmap", label="FS01", ports={"tcp/23": {"service": "telnet"}})
    job = store.add_scan_job("ports", ["192.168.1.0/24"])
    store.save_scan_results(job, [{"ip": "192.168.1.5", "ports": {"tcp/23": {}}}])
    store.finish_scan_job(job, "done", 1)
    running = store.add_scan_job("ports", ["10.0.0.0/24"])
    reports = ReportService(store, NotificationSettings(store))
    review = reports.review_scan(job)
    report = reports.generate("network")
    tracker = IncidentTracker(store)
    packets, seconds, _ = synth_packets(np.random.default_rng(1), anomaly="portscan")
    ended = tracker.anomaly("live:a", 1000, {"severity": "high", "score": 0.9}, analyse(packets, seconds))["incident"]
    tracker.close_all("done", source="live:a")
    ongoing = tracker.anomaly("live:b", 1000, {"severity": "high", "score": 0.9}, analyse(packets, seconds))["incident"]
    store.add_event({"is_anomaly": False, "score": 0.4, "severity": "low"}, "live:x", {})
    store.add_terminal_history("nmap -sn 192.168.1.0/24", "sh")
    return store, {"job": job, "running": running, "review": review["id"], "report": report["id"],
                   "ended": ended["id"], "ongoing": ongoing["id"]}


def test_delete_report_unlinks_it_from_its_scan(tmp_path):
    store, ids = filled(tmp_path)
    assert store.delete_report(ids["review"])
    assert store.scan_job(ids["job"])["report_id"] is None
    assert not store.delete_report(ids["review"])
    assert store.delete_all_reports() == 1 and store.reports() == []


def test_delete_scan_removes_results_and_review_but_not_devices(tmp_path):
    store, ids = filled(tmp_path)
    assert store.delete_scan(ids["job"])
    assert store.scan_job(ids["job"]) is None and store.scan_results(ids["job"]) == []
    assert store.report(ids["review"]) is None and store.report(ids["report"]) is not None
    assert store.device("192.168.1.5")["label"] == "FS01"
    assert not store.delete_scan(ids["running"])                     # running scans are kept
    assert store.delete_all_scans() == 0 and store.scan_job(ids["running"])


def test_only_ended_incidents_can_be_deleted(tmp_path):
    store, ids = filled(tmp_path)
    assert store.delete_incident(ids["ongoing"]) == (False, None)
    assert store.delete_incident(ids["ended"])[0]
    assert [i["id"] for i in store.incidents()] == [ids["ongoing"]]
    assert store.delete_ended_incidents()[0] == 0


def test_clearing_devices_resets_the_new_device_check(tmp_path):
    store, _ = filled(tmp_path)
    settings = NotificationSettings(store)
    settings.update({"smtp_host": "smtp.example.com", "smtp_user": "a@example.com", "email_to": "a@example.com",
                     "notify_new_devices": True})
    mails = []
    notifier = Notifier(store, settings, ReportService(store, settings), mailer=lambda *a: mails.append(a))
    notifier.check()                                                  # baseline recorded
    assert store.clear_devices() == 1
    store.upsert_device("192.168.1.5", seen_by="passive")               # rediscovered
    notifier.check()
    assert mails == []                                                # no "new device" email flood


def test_summary_events_terminal_and_compact(tmp_path):
    store, _ = filled(tmp_path)
    summary = store.data_summary()
    assert summary["events"] == 1 and summary["reports"] == 2 and summary["scans"] == 2
    assert summary["incidents"] == 2 and summary["open_incidents"] == 1 and summary["terminal"] == 1
    assert store.clear_events() == 1 and store.clear_terminal_history() == 1
    store.compact()
    assert store.data_summary()["events"] == 0


# ------------------------------------------------------------------ API (runs where FastAPI is installed)
def test_api_deletes_and_wipe(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from netai_detector import api
    store, ids = filled(tmp_path)
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    evidence = ev_dir / "incident-1.pcap"
    evidence.write_bytes(b"x")
    outside = tmp_path / "keep.pcap"
    outside.write_bytes(b"x")
    inc = store.incident(ids["ended"])
    inc["evidence_path"] = str(evidence)
    store.save_incident(inc)
    monkeypatch.setattr(api, "store", store)
    monkeypatch.setattr(api, "EVIDENCE_DIR", ev_dir)
    monkeypatch.setattr(api, "API_KEY", "")
    c = TestClient(api.app)
    ctrl = {"X-Requested-With": "netai"}
    assert c.delete(f"/api/reports/{ids['report']}").status_code == 403          # needs the dashboard header
    assert c.delete(f"/api/reports/{ids['report']}", headers=ctrl).json() == {"deleted": 1}
    assert c.delete(f"/api/incidents/{ids['ongoing']}", headers=ctrl).status_code == 409
    assert c.delete(f"/api/incidents/{ids['ended']}", headers=ctrl).json()["evidence_files"] == 1
    assert not evidence.exists() and outside.exists()
    assert c.get("/api/data").json()["evidence_files"] == 0
    assert c.post("/api/data/wipe", json={"confirm": "yes"}, headers=ctrl).status_code == 422
    wiped = c.post("/api/data/wipe", json={"confirm": "DELETE"}, headers=ctrl).json()
    assert wiped["devices"] == 1 and wiped["events"] == 1
    left = c.get("/api/data").json()
    assert left["devices"] == 0 and left["reports"] == 0 and left["open_incidents"] == 1
