"""Alerts, so someone finds out without watching the dashboard.

Channels: a desktop notification (on by default), email (SMTP) and Slack (incoming webhook) when
configured. Each incident alerts once when it opens at or above NETAI_ALERT_MIN_SEVERITY and once
more if it escalates. Sending happens on a background thread so it can never stall monitoring.
"""
from __future__ import annotations
from email.message import EmailMessage
import json
import logging
import os
import queue
import re
import shutil
import smtplib
import ssl
import subprocess
import sys
import threading
import urllib.request
from . import config
from .forensics import ATTACK_TITLES

log = logging.getLogger("netai")
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def format_alert(incident: dict, reason: str = "new", include_hosts: bool = True) -> tuple[str, str]:
    """(title, body) in plain text."""
    sev = incident.get("peak_severity", "?").upper()
    kind = ATTACK_TITLES.get(incident.get("attack_type", "unknown"), "Unusual traffic")
    verb = "escalated to" if reason == "escalated" else "detected:"
    title = f"NetAI {sev} — {kind}" + (" (escalated)" if reason == "escalated" else "")
    lines = [f"Incident #{incident.get('id')} {verb} {sev.lower()} severity, "
             f"source {incident.get('source')}.",
             f"Started {incident.get('started_at', '?')[:19].replace('T', ' ')} UTC, "
             f"{incident.get('windows', 0)} flagged window(s) so far."]
    hints = incident.get("hints") or []
    if hints:
        lines.append(f"Why: {hints[0].get('evidence', '')}")
    flows = (incident.get("culprits") or {}).get("top_flows") or []
    if flows:
        f = flows[0]
        lines.append(f"Main traffic: {f['src']} → {f['dst']} ({f['proto'].upper()}, {f['packets']} packets)")
    if str(incident.get("source", "")).startswith("demo"):
        lines.append("(This is SIMULATED demo traffic.)")
    if config.DASHBOARD_URL:
        lines.append(f"Details and suggested next steps: {config.DASHBOARD_URL}")
    else:
        lines.append("Open the NetAI dashboard for details and suggested next steps.")
    body = "\n".join(lines)
    if not include_hosts:
        body = _IP.sub("[address]", body)
    return title, body


# ------------------------------------------------------------------ channels
def _desktop(title: str, body: str) -> None:
    short = body.split("\n")
    message = " ".join(short[:3])[:250]
    env = {**os.environ, "NETAI_T": title[:120], "NETAI_M": message}
    uid, user = os.environ.get("SUDO_UID"), os.environ.get("SUDO_USER")
    if os.name == "nt":
        script = ("Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
                  "$n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Warning; "
                  "$n.Visible=$true; $n.ShowBalloonTip(15000,$env:NETAI_T,$env:NETAI_M,"
                  "[System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -Seconds 16; $n.Dispose()")
        subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
                         env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    elif sys.platform == "darwin":
        cmd = ["osascript", "-e", 'display notification (system attribute "NETAI_M") with title '
                                  '(system attribute "NETAI_T") sound name "Basso"']
        if uid and user and os.geteuid() == 0:  # started via sudo: show it in the user's session
            cmd = ["launchctl", "asuser", uid, "sudo", "-u", user, "-E"] + cmd
        subprocess.Popen(cmd, env=env)
    else:
        if not shutil.which("notify-send"):
            raise RuntimeError("notify-send not found (install libnotify-bin)")
        cmd = ["notify-send", "-u", "critical", "-a", "NetAI Detector", title[:120], message]
        if uid and user and os.geteuid() == 0:  # root can't reach the user's desktop bus directly
            cmd = ["sudo", "-u", user, "env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                   f"DISPLAY={os.environ.get('DISPLAY', ':0')}"] + cmd
        subprocess.Popen(cmd, env=env)


def _slack(title: str, body: str) -> None:
    data = json.dumps({"text": f"*{title}*\n{body}"}).encode()
    req = urllib.request.Request(config.SLACK_WEBHOOK, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"Slack answered {resp.status}")


def _email(title: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = title, config.SMTP_FROM, ", ".join(config.ALERT_EMAIL_TO)
    msg.set_content(body + "\n\n-- NetAI Detector")
    ctx = ssl.create_default_context()
    if config.SMTP_TLS == "ssl":
        server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=15, context=ctx)
    else:
        server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
    with server:
        if config.SMTP_TLS == "starttls":
            server.starttls(context=ctx)
        if config.SMTP_USER:
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
        server.send_message(msg)


def channels() -> dict:
    """Which channels are configured (never includes secrets)."""
    return {"desktop": config.ALERT_DESKTOP,
            "email": bool(config.SMTP_HOST and config.ALERT_EMAIL_TO and config.SMTP_FROM),
            "slack": bool(config.SLACK_WEBHOOK),
            "min_severity": config.ALERT_MIN_SEVERITY,
            "include_hosts_in_remote": config.ALERT_INCLUDE_HOSTS}


class Alerter:
    def __init__(self, on_error=None, senders: dict | None = None):
        self.on_error = on_error or (lambda msg: log.warning(msg))
        self.senders = senders or {"desktop": _desktop, "email": _email, "slack": _slack}
        self.sent = 0
        self._alerted: dict[int, int] = {}       # incident id -> highest severity rank alerted
        self._queue: queue.Queue = queue.Queue(maxsize=100)
        self._thread: threading.Thread | None = None

    def _enabled(self) -> list[str]:
        on = channels()
        return [name for name in ("desktop", "email", "slack") if on[name] and name in self.senders]

    def consider(self, incident: dict, reason: str) -> bool:
        """Queue an alert for this incident if it qualifies. Returns True if one was queued."""
        if str(incident.get("source", "")).startswith("demo"):
            return False            # simulated attacks are shown on the dashboard only
        rank = SEVERITY_RANK.get(incident.get("peak_severity", "low"), 0)
        if rank < SEVERITY_RANK.get(config.ALERT_MIN_SEVERITY, 2):
            return False
        iid = int(incident.get("id") or 0)
        if self._alerted.get(iid, -1) >= rank:
            return False
        first = iid not in self._alerted
        self._alerted[iid] = rank
        if len(self._alerted) > 1000:
            self._alerted.pop(next(iter(self._alerted)))
        self._enqueue(dict(incident), "new" if first else "escalated")
        return True

    def _enqueue(self, incident: dict, reason: str) -> None:
        if not self._enabled():
            return
        try:
            self._queue.put_nowait((incident, reason))
        except queue.Full:
            return
        if not self._thread or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._worker, name="netai-alerts", daemon=True)
            self._thread.start()

    def _worker(self) -> None:
        while True:
            try:
                incident, reason = self._queue.get(timeout=30)
            except queue.Empty:
                return
            self.send(incident, reason)

    def send(self, incident: dict, reason: str = "new") -> dict:
        """Send on every enabled channel now. Returns {channel: "sent" | error message}."""
        results = {}
        for name in self._enabled():
            remote = name != "desktop"
            title, body = format_alert(incident, reason,
                                       include_hosts=config.ALERT_INCLUDE_HOSTS or not remote)
            try:
                self.senders[name](title, body)
                results[name] = "sent"
                self.sent += 1
            except Exception as exc:
                results[name] = f"failed: {exc}"
                self.on_error(f"The {name} alert could not be sent ({exc}). Check its settings in .env.")
        return results

    def test(self) -> dict:
        sample = {"id": 0, "source": "test", "peak_severity": "high", "attack_type": "port_scan",
                  "started_at": "test", "windows": 1,
                  "hints": [{"evidence": "This is a test alert from NetAI Detector. No attack is happening."}]}
        results = self.send(sample, "new")
        return results or {"none": "No alert channel is enabled. See the Alerts section of the README."}
