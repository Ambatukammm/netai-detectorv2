"""Report generation service and the background email notifier.

The notifier checks once a minute for:
  * new devices and newly seen risky services (compared with what it saw last time)
  * a scheduled daily/weekly report that is due
and emails when the Settings page says to. Finished nmap scans can email a network report.
Its first check only records what exists, so turning it on never floods your inbox.
"""
from __future__ import annotations
from datetime import datetime
import logging
import threading
from .aya import review
from .devices import display_name
from .forensics import is_internal
from .notifications import NotificationSettings, email_ready, send_email
from .passive import RISKY, service_name
from .reports import KINDS, build_report, render_html, render_text
from .scanner import compare_scans

log = logging.getLogger("netai")


class ReportService:
    def __init__(self, store, settings: NotificationSettings, passive_status=None, scan_info=None,
                 reviewer=review, mailer=send_email):
        self.store, self.settings = store, settings
        self.passive_status = passive_status or (lambda: None)
        self.scan_info = scan_info or (lambda: None)
        self.reviewer, self.mailer = reviewer, mailer
        self._lock = threading.Lock()

    def _previous(self) -> dict | None:
        """Latest saved report that has an inventory snapshot (scan reviews don't)."""
        for row in self.store.reports(50):
            if row["kind"] != "scan":
                return self.store.report(row["id"])
        return None

    def generate(self, kind: str = "full") -> dict:
        """Build a report, have Aya review it, and save it on this machine."""
        if kind not in KINDS:
            raise ValueError(f"Unknown report type '{kind}'")
        with self._lock:
            report = build_report(kind, self.store, self.passive_status(), self.scan_info(),
                                  previous=self._previous())
            report["aya"] = self.reviewer(report, self.settings.get())
            report["id"] = self.store.save_report(report)
        return report

    def review_scan(self, job_id: int) -> dict:
        """Aya's review of one finished scan, compared with the previous scan of the same networks."""
        with self._lock:
            report = build_report("scan", self.store, scan=compare_scans(self.store, job_id))
            report["aya"] = self.reviewer(report, self.settings.get())
            report["id"] = self.store.save_report(report)
            self.store.set_scan_report(job_id, report["id"])
        return report

    def email(self, report: dict, subject_prefix: str = "") -> None:
        s = self.settings.get()
        if not email_ready(s):
            raise RuntimeError("Email isn't set up yet. Fill in the Email section of Settings first.")
        subject = f"{subject_prefix}{report['title']}: grade {report['grade']} · {report['headline']}"
        self.mailer(s, subject, render_text(report), render_html(report))


class Notifier:
    def __init__(self, store, settings: NotificationSettings, reports: ReportService, interval: float = 60,
                 mailer=send_email, on_error=None, clock=None):
        self.store, self.settings, self.reports = store, settings, reports
        self.interval, self.mailer = interval, mailer
        self.on_error = on_error or (lambda msg: log.warning(msg))
        self.clock = clock or (lambda: datetime.now().astimezone())   # local time for schedules
        self.sent = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netai-notifier", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.check()
            except Exception as exc:
                log.exception("Notifier error")
                self.on_error(f"Email notifications hit an error: {exc}")

    # -------------------------------------------------------------- checks
    def _mail(self, subject: str, text: str, html: str | None = None) -> bool:
        try:
            self.mailer(self.settings.get(), subject, text, html)
            self.sent += 1
            return True
        except Exception as exc:
            self.on_error(f"Couldn't send a notification email ({exc}). Check Settings → Email.")
            return False

    def check(self) -> dict:
        s = self.settings.get()
        result = {"new_devices": 0, "new_risky": 0, "report": None}
        devices = [d for d in self.store.devices() if is_internal(d["ip"])]
        current_dev = {d["ip"] for d in devices}
        current_risky = {f"{d['ip']} {k}" for d in devices for k, p in d["ports"].items()
                         if p.get("risk") or int(k.split("/")[1]) in RISKY}
        snap = self.store.get_setting("notify_snapshot")
        self.store.set_setting("notify_snapshot", {"devices": sorted(current_dev), "risky": sorted(current_risky)})
        if snap is not None and email_ready(s):
            by_ip = {d["ip"]: d for d in devices}
            new_dev = sorted(current_dev - set(snap.get("devices", [])))
            new_risky = sorted(current_risky - set(snap.get("risky", [])))
            if new_dev and s.get("notify_new_devices"):
                lines = [f"- {_label(by_ip[ip])}" + (f" · {by_ip[ip]['vendor']}" if by_ip[ip].get("vendor") else "")
                         for ip in new_dev[:50]]
                self._mail(f"NetAI: {len(new_dev)} new device(s) on your network",
                           "These devices appeared since the last check:\n" + "\n".join(lines)
                           + "\n\nIf you don't recognise one, find it (router's DHCP list) and check it. "
                             "Name known devices on the Network & devices page.")
                result["new_devices"] = len(new_dev)
            if new_risky and s.get("notify_risky_services"):
                lines = []
                for item in new_risky[:50]:
                    ip, key = item.split(" ")
                    port = int(key.split("/")[1])
                    lines.append(f"- {_label(by_ip[ip])}: {service_name(port)} ({key})\n  {RISKY.get(port, '')}")
                self._mail(f"NetAI: {len(new_risky)} risky service(s) found",
                           "Newly found services that are worth a second look:\n" + "\n".join(lines))
                result["new_risky"] = len(new_risky)
        if self.report_due(s):
            report = self.reports.generate(s.get("report_kind", "full"))
            if self._mail(f"NetAI {s['report_schedule']} report: {report['title']} · grade {report['grade']}",
                          render_text(report), render_html(report)):
                self.store.set_setting("report_last_sent", self.clock().isoformat())
            result["report"] = report["id"]
        return result

    def report_due(self, s: dict) -> bool:
        schedule = s.get("report_schedule", "off")
        if schedule == "off" or not email_ready(s):
            return False
        now = self.clock()
        if now.hour < int(s.get("report_hour", 7)):
            return False
        if schedule == "weekly" and now.weekday() != int(s.get("report_weekday", 0)):
            return False
        last = self.store.get_setting("report_last_sent")
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last)
        except ValueError:
            return True
        return last_dt.date() != now.date() if schedule == "daily" else (now - last_dt).days >= 6

    def scan_finished(self, job: dict) -> dict | None:
        """Called by the scanner when a scan ends. Aya always reviews a completed scan (saved on this
        machine and linked from the scan); it is emailed too if Settings asks for it."""
        # Finished scans, and stopped/cancelled ones that still found something, get Aya's review.
        if not job.get("id") or job.get("status") not in ("done", "cancelled", "stopped") or \
                (job.get("status") != "done" and not job.get("hosts_up")):
            return None
        try:
            report = self.reports.review_scan(job["id"])
        except Exception as exc:
            self.on_error(f"Aya couldn't review the scan ({exc}).")
            return None
        s = self.settings.get()
        if s.get("notify_scans") and email_ready(s):
            try:
                self.reports.email(report, subject_prefix="Scan finished · ")
                self.sent += 1
            except Exception as exc:
                self.on_error(f"Couldn't email the scan review ({exc}).")
        return report


def _label(dev: dict) -> str:
    name = display_name(dev)
    return f"{name} ({dev['ip']})" if name else dev["ip"]
