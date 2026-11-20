"""Notification settings, email, reports, AI summaries (with a fake API) and the notifier."""
from datetime import datetime, timedelta, timezone
import pytest
from netai_detector.notifications import MASK, NotificationSettings, send_email
from netai_detector.notifier import Notifier, ReportService
from netai_detector.reports import build_report, render_html, render_text
from netai_detector.storage import EventStore


def office(store):
    store.upsert_device("192.168.15.5", seen_by="nmap", hostname="fs01.corp.local", up=True,
                        ports={"tcp/445": {"service": "microsoft-ds", "risk": "SMB…"},
                               "tcp/3389": {"service": "ms-wbt-server", "risk": "RDP…"}})
    store.upsert_device("192.168.15.40", seen_by="nmap", vendor="Hikvision", up=True,
                        ports={"tcp/23": {"service": "telnet", "risk": "Telnet…"}, "tcp/554": {"service": "rtsp"}})
    store.upsert_device("192.168.15.21", seen_by="passive", up=True)
    store.upsert_device("8.8.8.8", seen_by="name lookup", dns_name="dns.google")      # not an inventory device


EMAIL = {"smtp_host": "smtp.example.com", "smtp_port": 587, "smtp_user": "it@example.com",
         "smtp_password": "app-pass", "email_to": ["boss@example.com"], "email_enabled": True}


class FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout, context=None):
        self.host = host
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self, context): pass
    def login(self, user, password): FakeSMTP.login_as = (user, password)
    def send_message(self, msg): FakeSMTP.sent.append(msg)


# ------------------------------------------------------------------ settings and email
def test_settings_validate_save_and_hide_secrets(tmp_path):
    store = EventStore(tmp_path / "e.db")
    settings = NotificationSettings(store)
    public = settings.update({**EMAIL, "email_to": "boss@example.com, it@example.com", "min_severity": "medium"})
    assert public["smtp_password"] == MASK and public["email_ready"]
    assert settings.get()["smtp_password"] == "app-pass" and settings.get()["email_to"] == ["boss@example.com", "it@example.com"]
    settings.update({"smtp_password": MASK, "smtp_host": "smtp2.example.com"})          # mask keeps the secret
    assert settings.get()["smtp_password"] == "app-pass"
    settings.update({"clear": ["smtp_password"]})
    assert settings.get()["smtp_password"] == ""
    for bad in ({"email_to": "not-an-email"}, {"smtp_port": 70000}, {"report_schedule": "hourly"},
                {"min_severity": "low"}, {"report_hour": 25}):
        with pytest.raises(ValueError):
            settings.update(bad)
    assert "unknown_key" not in settings.update({"unknown_key": 1})


def test_email_has_text_and_html_versions():
    FakeSMTP.sent = []
    send_email(EMAIL, "Subject", "plain body", "<p>html body</p>", smtp_factory=FakeSMTP)
    msg = FakeSMTP.sent[0]
    assert msg["To"] == "boss@example.com" and msg["From"] == "it@example.com"
    assert FakeSMTP.login_as == ("it@example.com", "app-pass")
    kinds = [part.get_content_type() for part in msg.walk()]
    assert "text/plain" in kinds and "text/html" in kinds
    with pytest.raises(RuntimeError, match="isn't set up"):
        send_email({"smtp_host": ""}, "s", "t")


# ------------------------------------------------------------------ reports
def test_network_report_prioritises_risky_services(tmp_path):
    store = EventStore(tmp_path / "e.db")
    office(store)
    report = build_report("network", store, scan_info={"installed": True, "jobs": []})
    titles = [f["title"] for f in report["findings"]]
    assert report["findings"][0]["severity"] == "high"
    assert any("Telnet" in t for t in titles) and any("Remote Desktop" in t for t in titles)
    assert any("never been scanned" in t for t in titles)
    assert any("no name" in t for t in titles)                    # 192.168.15.21 and the camera
    stats = dict(report["stats"])
    assert stats["Devices"] == 3 and stats["Risky services"] == 3   # internet server not counted
    assert report["grade"] in "ABCDF" and 0 <= report["score"] <= 100
    assert report["tables"][0]["rows"][0][1] == "192.168.15.5"


def test_grade_scale():
    from netai_detector.reports import deduction, grade
    assert grade(100 - deduction("high", 1)) == "B"
    assert grade(100 - deduction("high", 3)) == "C"
    assert grade(100 - deduction("high", 20) - deduction("medium", 20) - deduction("low", 20)) == "F"
    assert deduction("info", 50) == 0 and deduction("high", 0) == 0


def test_reports_track_changes_since_the_previous_one(tmp_path):
    store = EventStore(tmp_path / "e.db")
    office(store)
    first = build_report("full", store)
    assert first["changes"] is None
    assert not any("new device" in f["title"] or "appeared" in f["title"] for f in first["findings"])
    store.save_report(first)
    store.upsert_device("192.168.15.99", seen_by="passive", ports={"tcp/5900": {"service": "VNC"}})
    second = build_report("full", store, previous=store.latest_report())
    assert second["changes"]["new_devices"] == ["192.168.15.99"]
    assert second["changes"]["new_services"] == ["192.168.15.99 tcp/5900"]
    titles = [f["title"] for f in second["findings"]]
    assert any("1 new device" in t for t in titles) and any("risky service(s) appeared" in t for t in titles)


def test_span_and_incident_reports(tmp_path):
    from netai_detector.demo import synth_packets
    from netai_detector.forensics import analyse
    from netai_detector.incidents import IncidentTracker
    import numpy as np
    store = EventStore(tmp_path / "e.db")
    span = build_report("span", store, passive_status={"enabled": True, "mirroring_detected": False,
                                                       "foreign_traffic_ratio": 0.02})
    assert any("Mirroring isn't working" in f["title"] for f in span["findings"])
    tracker = IncidentTracker(store)
    now = datetime.now(timezone.utc).timestamp()
    for i in range(3):
        packets, seconds, _ = synth_packets(np.random.default_rng(i), anomaly="bruteforce")
        tracker.anomaly(f"live:{i}", now, {"severity": "high", "score": 0.9}, analyse(packets, seconds))
    inc = build_report("incidents", store)
    titles = [f["title"] for f in inc["findings"]]
    assert any("Login brute-force incident" in t for t in titles)
    assert any("3 or more incidents" in t for t in titles)          # 203.0.113.77 repeat source
    assert any("still ongoing" in t for t in titles)


def test_html_report_escapes_hostile_device_names(tmp_path):
    store = EventStore(tmp_path / "e.db")
    store.upsert_device("192.168.15.66", seen_by="name lookup", netbios_name="<script>alert(1)</script>",
                        ports={"tcp/23": {"service": "telnet"}})
    report = build_report("full", store)
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "Telnet" in render_text(report)


# ------------------------------------------------------------------ notifier
def _notifier(store, now, **settings):
    mails = []
    s = NotificationSettings(store)
    s.update({**EMAIL, **settings})
    reports = ReportService(store, s, mailer=lambda *a: mails.append(a))
    n = Notifier(store, s, reports, mailer=lambda s_, subj, text, html=None: mails.append((subj, text, html)),
                 clock=lambda: now)
    return n, mails


def test_notifier_emails_new_devices_and_risky_services_but_not_on_first_run(tmp_path):
    store = EventStore(tmp_path / "e.db")
    office(store)
    n, mails = _notifier(store, datetime(2026, 11, 20, 9, 0).astimezone(),
                         notify_new_devices=True, notify_risky_services=True)
    assert n.check() == {"new_devices": 0, "new_risky": 0, "report": None} and not mails
    store.upsert_device("192.168.15.77", seen_by="passive", vendor="Raspberry Pi",
                        ports={"tcp/23": {"service": "telnet"}})
    result = n.check()
    assert result["new_devices"] == 1 and result["new_risky"] == 1
    assert "1 new device" in mails[0][0] and "Raspberry Pi" in mails[0][1]
    assert "Telnet" in mails[1][1]
    assert n.check()["new_devices"] == 0                              # not repeated


def test_scheduled_reports_daily_and_weekly(tmp_path):
    store = EventStore(tmp_path / "e.db")
    office(store)
    morning = datetime(2026, 11, 23, 8, 30).astimezone()              # a Monday
    n, mails = _notifier(store, morning, report_schedule="daily", report_hour=7)
    n.check()
    assert any("daily report" in m[0] for m in mails) and mails[-1][2].startswith("<!doctype html>")
    count = len(mails)
    n.check()
    assert len(mails) == count                                        # once per day
    n.clock = lambda: morning + timedelta(days=1)
    n.check()
    assert len(mails) == count + 1
    store2 = EventStore(tmp_path / "w.db")
    office(store2)
    early, _ = _notifier(store2, datetime(2026, 11, 23, 6, 0).astimezone(), report_schedule="weekly",
                         report_weekday=0, report_hour=7)
    assert not early.report_due(early.settings.get())                 # before the hour
    tuesday, _ = _notifier(store2, datetime(2026, 11, 24, 9, 0).astimezone(), report_schedule="weekly",
                           report_weekday=0, report_hour=7)
    assert not tuesday.report_due(tuesday.settings.get())             # wrong day


def test_finished_scan_gets_reviewed_and_emailed(tmp_path):
    store = EventStore(tmp_path / "e.db")
    office(store)
    job = store.add_scan_job("ports", ["192.168.15.0/24"])
    store.save_scan_results(job, [{"ip": "192.168.15.40", "ports": {"tcp/23": {"service": "telnet"}}}])
    store.finish_scan_job(job, "done", 1, "Found 1 device(s).")
    n, mails = _notifier(store, datetime.now().astimezone(), notify_scans=True)
    report = n.scan_finished({"id": job, "status": "done", "targets": ["192.168.15.0/24"]})
    assert report["kind"] == "scan" and report["aya"]["text"].startswith("WHAT I FOUND")
    assert store.scan_job(job)["report_id"] == report["id"]
    assert mails and "Scan finished" in mails[0][1]
    assert n.scan_finished({"id": job, "status": "cancelled"}) is None and len(mails) == 1
