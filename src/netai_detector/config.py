"""Configuration. Reads the process environment and, automatically, a .env file in the project root."""
from __future__ import annotations
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_dotenv(path: Path) -> None:
    """Tiny .env loader (no dependency). Real environment variables always win."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


load_dotenv(ROOT / ".env")


def env_path(name: str, default: str) -> Path:
    value = os.getenv(name, default)
    path = Path(value).expanduser()
    return path if path.is_absolute() else ROOT / path


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip().lower()
    if not value:
        return default
    return value not in ("0", "false", "no", "off")


DB_PATH = env_path("NETAI_DB", "data/netai.db")
MODEL_PATH = env_path("NETAI_MODEL", "models/anomaly_model.joblib")
BASELINE_PATH = env_path("NETAI_BASELINE", "data/baseline.npz")
LOG_PATH = env_path("NETAI_LOG", "logs/netai.log")
HOST = os.getenv("NETAI_HOST", "127.0.0.1")
PORT = env_int("NETAI_PORT", 8000)
API_KEY = os.getenv("NETAI_API_KEY", "").strip()

# --- Automatic operation -------------------------------------------------------------------
# auto = watch the network if possible, otherwise run a clearly-labelled simulated demo.
# live = never simulate.   demo = always simulate.   off = no background monitoring at all.
MODE = os.getenv("NETAI_MODE", "auto").strip().lower()
INTERFACE = os.getenv("NETAI_INTERFACE", "").strip() or None   # None = system default
WINDOW_PACKETS = max(10, env_int("NETAI_WINDOW_PACKETS", 100))
WINDOW_FLUSH_SECONDS = max(1, env_int("NETAI_WINDOW_FLUSH_SECONDS", 20))
LEARN_WINDOWS = max(20, env_int("NETAI_LEARN_WINDOWS", 60))
CONTAMINATION = 0.02
MAX_EVENTS = max(1000, env_int("NETAI_MAX_EVENTS", 50000))
OPEN_BROWSER = env_bool("NETAI_OPEN_BROWSER", True)
MAX_PCAP_MB = env_int("NETAI_MAX_PCAP_MB", 500)
# Re-learn automatically from recent *normal* traffic this often (0 = never).
RETRAIN_HOURS = env_int("NETAI_RETRAIN_HOURS", 168)

# --- Investigation ---------------------------------------------------------------------------
# Consecutive flagged windows are merged into one incident. It closes after this many normal
# windows in a row, or when nothing has been flagged for INCIDENT_GAP_SECONDS.
INCIDENT_CLOSE_AFTER = max(1, env_int("NETAI_INCIDENT_CLOSE_AFTER", 3))
INCIDENT_GAP_SECONDS = max(10, env_int("NETAI_INCIDENT_GAP_SECONDS", 120))
# Addresses you expect to behave unusually (an authorised scanner, the backup server). Comma list.
TRUSTED_HOSTS = {h.strip() for h in os.getenv("NETAI_TRUSTED_HOSTS", "").split(",") if h.strip()}

# Evidence: headers-only .pcap files for incidents (payload is cut off, never saved).
# off = never · high = incidents that reach high severity (default) · medium · all
EVIDENCE = os.getenv("NETAI_EVIDENCE", "high").strip().lower()
EVIDENCE_DIR = env_path("NETAI_EVIDENCE_DIR", "data/evidence")
EVIDENCE_MAX_MB = max(1, env_int("NETAI_EVIDENCE_MAX_MB", 200))
EVIDENCE_MAX_PACKETS = max(100, env_int("NETAI_EVIDENCE_MAX_PACKETS", 20000))  # per incident

# Alerts. The desktop one is on by default; email and Slack switch on when configured.
ALERT_MIN_SEVERITY = os.getenv("NETAI_ALERT_MIN_SEVERITY", "high").strip().lower()
ALERT_DESKTOP = env_bool("NETAI_ALERT_DESKTOP", True)
ALERT_INCLUDE_HOSTS = env_bool("NETAI_ALERT_INCLUDE_HOSTS", True)  # 0 = leave IPs out of email/Slack
SLACK_WEBHOOK = os.getenv("NETAI_SLACK_WEBHOOK", "").strip()
SMTP_HOST = os.getenv("NETAI_SMTP_HOST", "").strip()
SMTP_PORT = env_int("NETAI_SMTP_PORT", 587)
SMTP_USER = os.getenv("NETAI_SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("NETAI_SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("NETAI_SMTP_FROM", "").strip() or SMTP_USER
SMTP_TLS = os.getenv("NETAI_SMTP_TLS", "starttls").strip().lower()   # starttls | ssl | none
ALERT_EMAIL_TO = [a.strip() for a in os.getenv("NETAI_ALERT_EMAIL_TO", "").split(",") if a.strip()]
DASHBOARD_URL = os.getenv("NETAI_DASHBOARD_URL", "").strip()  # link put in alerts (optional)

# --- Devices, network scanning and SPAN ------------------------------------------------------
RESOLVE_NAMES = env_bool("NETAI_RESOLVE_NAMES", True)       # reverse DNS + NetBIOS lookups
NMAP_PATH = os.getenv("NETAI_NMAP", "").strip()             # empty = find nmap automatically
SCAN_MAX_MINUTES = max(0, env_int("NETAI_SCAN_MAX_MINUTES", 0))   # 0 = no limit (scans run until done)
PASSIVE_DISCOVERY = env_bool("NETAI_PASSIVE_DISCOVERY", True)  # learn devices/services from traffic
PROMISCUOUS = env_bool("NETAI_PROMISCUOUS", True)           # see mirrored (SPAN) traffic, not just ours


def hand_back_to_user(path: Path) -> None:
    """If we were started through sudo, give files we create back to the real user."""
    try:
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if os.name == "posix" and os.geteuid() == 0 and uid and gid:
            os.chown(path, int(uid), int(gid))
    except OSError:
        pass

# --- Aya (local AI analyst for reports) -----------------------------------------------------
# builtin = no setup; ollama / openai = a local model server (also settable on the Settings page).
AYA_ENGINE = os.getenv("NETAI_AYA_ENGINE", "builtin").strip().lower()
AYA_URL = os.getenv("NETAI_AYA_URL", "").strip()
AYA_MODEL = os.getenv("NETAI_AYA_MODEL", "").strip()
AYA_TIMEOUT = max(10, env_int("NETAI_AYA_TIMEOUT", 300))   # local models on a CPU can be slow

# --- Terminal ----------------------------------------------------------------------------------
# auto = available only when the dashboard is bound to this computer (127.0.0.1). on = also when
# reachable from the network (requires NETAI_API_KEY). off = never.
TERMINAL = os.getenv("NETAI_TERMINAL", "auto").strip().lower()
TERMINAL_TIMEOUT = max(10, env_int("NETAI_TERMINAL_TIMEOUT_MINUTES", 30) * 60)
# Extra host names the dashboard may be opened with (comma list), e.g. netai.office.lan. Only
# checked when bound to 127.0.0.1, where it blocks "DNS rebinding" attacks from malicious websites.
ALLOWED_HOSTS = {h.strip().lower() for h in os.getenv("NETAI_ALLOWED_HOSTS", "").split(",") if h.strip()}
