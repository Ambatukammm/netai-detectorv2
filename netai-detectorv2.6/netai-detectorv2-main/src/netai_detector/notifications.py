"""Notification and AI settings that can be changed from the dashboard, plus the email sender.

Settings saved on the Settings page are stored in the local database and override .env values.
Secrets (the email password, the AI API key) are stored in that database on this machine and are
never sent back to the browser.
"""
from __future__ import annotations
from email.message import EmailMessage
import re
import smtplib
import ssl
from . import config

MASK = "********"
SECRETS = ("smtp_password", "aya_api_key")
SEVERITIES = ("medium", "high")
SCHEDULES = ("off", "daily", "weekly")
REPORT_KINDS = ("full", "network", "span", "incidents")
TLS_MODES = ("starttls", "ssl", "none")
AYA_ENGINES = ("builtin", "ollama", "openai")
_EMAIL = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


def env_defaults() -> dict:
    """Values from .env / the environment (read at call time so changes in tests apply)."""
    return {
        "email_enabled": True,
        "smtp_host": config.SMTP_HOST, "smtp_port": config.SMTP_PORT, "smtp_tls": config.SMTP_TLS,
        "smtp_user": config.SMTP_USER, "smtp_password": config.SMTP_PASSWORD,
        "smtp_from": config.SMTP_FROM, "email_to": list(config.ALERT_EMAIL_TO),
        "min_severity": config.ALERT_MIN_SEVERITY if config.ALERT_MIN_SEVERITY in SEVERITIES else "high",
        "include_hosts": config.ALERT_INCLUDE_HOSTS,
        "notify_incidents": True, "notify_new_devices": False, "notify_risky_services": True,
        "notify_scans": False,
        "report_schedule": "off", "report_kind": "full", "report_hour": 7, "report_weekday": 0,
        "aya_engine": config.AYA_ENGINE if config.AYA_ENGINE in AYA_ENGINES else "builtin",
        "aya_url": config.AYA_URL, "aya_model": config.AYA_MODEL, "aya_api_key": "",
    }


class NotificationSettings:
    """Effective settings = .env defaults overlaid with what was saved on the Settings page."""

    def __init__(self, store=None):
        self.store = store

    def get(self) -> dict:
        values = env_defaults()
        if self.store is not None:
            saved = self.store.get_setting("notifications", {}) or {}
            stale = [k for k in saved if k not in values]
            if stale:   # e.g. the cloud-AI key saved by version 2.4: delete it from disk
                self.store.set_setting("notifications", {k: v for k, v in saved.items() if k in values})
            values.update({k: v for k, v in saved.items() if k in values})
        return values

    def public(self) -> dict:
        """Safe for the browser: secrets replaced by a mask (or empty when unset)."""
        values = self.get()
        for key in SECRETS:
            values[key] = MASK if values.get(key) else ""
        values["email_ready"] = email_ready(self.get())
        values["aya_uses_model"] = aya_uses_model(self.get())
        return values

    def update(self, changes: dict) -> dict:
        """Validate and save. A secret left as the mask (or empty) keeps its current value;
        send `"clear": ["smtp_password"]` to remove one."""
        if self.store is None:
            raise RuntimeError("Settings can't be saved without a database")
        current = self.get()
        saved = dict(self.store.get_setting("notifications", {}) or {})
        clean = validate(changes, current)
        for key in SECRETS:
            if key in clean and clean[key] in ("", MASK):
                clean.pop(key)
        for key in changes.get("clear", []) or []:
            if key in SECRETS:
                clean[key] = ""
        saved.update(clean)
        self.store.set_setting("notifications", saved)
        return self.public()


def validate(changes: dict, current: dict) -> dict:
    """Check types and allowed values. Raises ValueError with a readable message."""
    out: dict = {}
    defaults = env_defaults()
    for key, value in changes.items():
        if key not in defaults:
            continue
        expected = defaults[key]
        if key == "email_to":
            items = value if isinstance(value, list) else re.split(r"[\s,;]+", str(value or ""))
            items = [i.strip() for i in items if i.strip()]
            bad = [i for i in items if not _EMAIL.match(i)]
            if bad:
                raise ValueError(f"Not an email address: {', '.join(bad)}")
            if len(items) > 20:
                raise ValueError("At most 20 recipients")
            out[key] = items
        elif key == "smtp_from":
            value = str(value or "").strip()
            if value and not _EMAIL.match(value):
                raise ValueError(f"'From' must be an email address: {value}")
            out[key] = value
        elif isinstance(expected, bool):
            out[key] = bool(value)
        elif isinstance(expected, int):
            try:
                number = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a number") from None
            limits = {"smtp_port": (1, 65535), "report_hour": (0, 23), "report_weekday": (0, 6)}
            low, high = limits.get(key, (0, 10**9))
            if not low <= number <= high:
                raise ValueError(f"{key} must be between {low} and {high}")
            out[key] = number
        else:
            value = str(value if value is not None else "").strip()
            allowed = {"smtp_tls": TLS_MODES, "min_severity": SEVERITIES, "report_schedule": SCHEDULES,
                       "report_kind": REPORT_KINDS, "aya_engine": AYA_ENGINES}.get(key)
            if allowed and value not in allowed:
                raise ValueError(f"{key} must be one of: {', '.join(allowed)}")
            if key == "aya_url" and value and not re.match(r"^https?://[^\s/]+(:\d+)?/?$", value):
                raise ValueError("Server address must look like http://127.0.0.1:11434")
            if len(value) > 300:
                raise ValueError(f"{key} is too long")
            out[key] = value
    return out


def email_ready(s: dict) -> bool:
    return bool(s.get("email_enabled") and s.get("smtp_host") and s.get("email_to")
                and (s.get("smtp_from") or s.get("smtp_user")))


def aya_uses_model(s: dict) -> bool:
    return s.get("aya_engine") in ("ollama", "openai") and bool(s.get("aya_model"))


def send_email(s: dict, subject: str, text: str, html: str | None = None,
               smtp_factory=None, ssl_factory=None) -> None:
    """Send one email (plain text, plus an HTML version when given). Raises on failure."""
    if not (s.get("smtp_host") and s.get("email_to")):
        raise RuntimeError("Email isn't set up: add a mail server and at least one recipient in Settings.")
    sender = s.get("smtp_from") or s.get("smtp_user")
    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = sender
    msg["To"] = ", ".join(s["email_to"])
    msg.set_content(text + "\n\n-- NetAI Detector")
    if html:
        msg.add_alternative(html, subtype="html")
    ctx = ssl.create_default_context()
    port = int(s.get("smtp_port") or 587)
    tls = s.get("smtp_tls", "starttls")
    if tls == "ssl":
        server = (ssl_factory or smtplib.SMTP_SSL)(s["smtp_host"], port, timeout=20, context=ctx)
    else:
        server = (smtp_factory or smtplib.SMTP)(s["smtp_host"], port, timeout=20)
    with server:
        if tls == "starttls":
            server.starttls(context=ctx)
        if s.get("smtp_user"):
            server.login(s["smtp_user"], s.get("smtp_password") or "")
        server.send_message(msg)
