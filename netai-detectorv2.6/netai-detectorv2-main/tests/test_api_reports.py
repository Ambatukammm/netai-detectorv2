"""API for settings, email tests and reports (needs FastAPI + httpx: pip install -e ".[dev]")."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402
from netai_detector import api  # noqa: E402
from netai_detector.alerts import Alerter  # noqa: E402
from netai_detector.devices import DeviceDirectory  # noqa: E402
from netai_detector.evidence import EvidenceStore  # noqa: E402
from netai_detector.monitor import Monitor  # noqa: E402
from netai_detector.notifications import MASK  # noqa: E402
from netai_detector.notifier import ReportService  # noqa: E402
from netai_detector.passive import PassiveDiscovery  # noqa: E402
from netai_detector.storage import EventStore  # noqa: E402

CTRL = {"X-Requested-With": "netai"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "e.db")
    mon = Monitor(store, tmp_path / "m.joblib", tmp_path / "b.npz", mode="off",
                  evidence=EvidenceStore(tmp_path / "ev"), alerter=Alerter(senders={}),
                  devices=DeviceDirectory(store, lookups={}), passive=PassiveDiscovery(store, local_ips=set()))
    mails = []
    reports = ReportService(store, mon.notify_settings, mailer=lambda *a: mails.append(a))
    monkeypatch.setattr(api, "store", store)
    monkeypatch.setattr(api, "monitor", mon)
    monkeypatch.setattr(api, "settings", mon.notify_settings)
    monkeypatch.setattr(api, "reports", reports)
    monkeypatch.setattr(api, "send_email", lambda *a, **k: mails.append(a))
    monkeypatch.setattr(api, "API_KEY", "")
    store.upsert_device("192.168.15.40", seen_by="nmap", ports={"tcp/23": {"service": "telnet"}})
    c = TestClient(api.app)
    c.mails = mails
    return c


def test_pages_render(client):
    assert "Create a report" in client.get("/reports").text
    assert "What to email" in client.get("/settings").text


def test_settings_round_trip_hides_secrets(client):
    body = {"smtp_host": "smtp.gmail.com", "smtp_user": "it@example.com", "smtp_password": "app-pass",
            "email_to": "it@example.com", "notify_new_devices": True}
    assert client.post("/api/settings/notifications", json=body).status_code == 403
    saved = client.post("/api/settings/notifications", json=body, headers=CTRL).json()
    assert saved["smtp_password"] == MASK and saved["email_ready"] and saved["notify_new_devices"]
    assert "app-pass" not in client.get("/api/settings/notifications").text
    bad = client.post("/api/settings/notifications", json={"email_to": "nope"}, headers=CTRL)
    assert bad.status_code == 422


def test_test_email_needs_setup_then_sends(client):
    assert client.post("/api/settings/notifications/test-email", headers=CTRL).status_code == 409
    client.post("/api/settings/notifications", headers=CTRL,
                json={"smtp_host": "smtp.example.com", "smtp_user": "it@example.com", "email_to": "it@example.com"})
    assert client.post("/api/settings/notifications/test-email", headers=CTRL).json()["sent_to"] == ["it@example.com"]
    assert client.mails


def test_reports_create_view_download_email(client):
    created = client.post("/api/reports", json={"kind": "network"}, headers=CTRL).json()
    listing = client.get("/api/reports").json()
    assert listing["items"][0]["id"] == created["id"] and not listing["aya_uses_model"]
    assert created["aya_engine"] == "built-in"
    report = client.get(f"/api/reports/{created['id']}").json()
    assert any("Telnet" in f["title"] for f in report["findings"])
    html = client.get(f"/api/reports/{created['id']}/html?download=1")
    assert html.headers["content-disposition"].startswith("attachment") and "Telnet" in html.text
    assert client.post(f"/api/reports/{created['id']}/email", headers=CTRL).status_code == 409   # email not set up
    client.post("/api/settings/notifications", headers=CTRL,
                json={"smtp_host": "smtp.example.com", "smtp_user": "it@example.com", "email_to": "it@example.com"})
    assert client.post(f"/api/reports/{created['id']}/email", headers=CTRL).status_code == 200
    assert client.post("/api/reports", json={"kind": "bogus"}, headers=CTRL).status_code == 422
    assert client.post("/api/aya/test", headers=CTRL).status_code == 409
    assert client.get("/api/aya").json()["engine"] == "builtin"
