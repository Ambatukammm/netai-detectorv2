"""API endpoints for incidents, evidence and alerts (needs FastAPI + httpx: pip install -e ".[dev]")."""
import numpy as np
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402
from netai_detector import api  # noqa: E402
from netai_detector.alerts import Alerter  # noqa: E402
from netai_detector.demo import synth_packets  # noqa: E402
from netai_detector.evidence import EvidenceStore  # noqa: E402
from netai_detector.monitor import Monitor  # noqa: E402
from netai_detector.storage import EventStore  # noqa: E402

CTRL = {"X-Requested-With": "netai"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "e.db")
    ev_dir = tmp_path / "ev"
    mon = Monitor(store, tmp_path / "m.joblib", tmp_path / "b.npz", mode="off",
                  evidence=EvidenceStore(ev_dir), evidence_level="all",
                  alerter=Alerter(senders={"desktop": lambda t, b: None}))
    monkeypatch.setattr(api, "store", store)
    monkeypatch.setattr(api, "monitor", mon)
    monkeypatch.setattr(api, "EVIDENCE_DIR", ev_dir)
    monkeypatch.setattr(api, "API_KEY", "")
    packets, seconds, _ = synth_packets(np.random.default_rng(1), anomaly="bruteforce")
    result = {"severity": "high", "score": 0.9, "is_anomaly": True}
    inc = mon._investigate(result, {"top_features": []}, packets, seconds, "live:eth0", 1000)
    mon._collect_evidence(inc, packets)
    return TestClient(api.app), inc["id"]


def test_incident_list_and_detail_with_plan(client):
    c, iid = client
    items = c.get("/api/incidents").json()["items"]
    assert items[0]["id"] == iid and items[0]["evidence_available"]
    detail = c.get(f"/api/incidents/{iid}").json()
    assert detail["attack_type"] == "brute_force"
    assert detail["plan"]["attacker"] == "203.0.113.77" and detail["plan"]["steps"]
    assert c.get("/api/incidents/9999").status_code == 404


def test_evidence_download_is_a_pcap(client):
    c, iid = client
    resp = c.get(f"/api/incidents/{iid}/evidence")
    assert resp.status_code == 200 and resp.content[:4] == b"\xd4\xc3\xb2\xa1"


def test_evidence_outside_folder_is_refused(client, tmp_path):
    c, iid = client
    inc = api.store.incident(iid)
    outside = tmp_path / "elsewhere.pcap"
    outside.write_bytes(b"x")
    inc["evidence_path"] = str(outside)
    api.store.save_incident(inc)
    assert c.get(f"/api/incidents/{iid}/evidence").status_code == 404


def test_test_alert_needs_dashboard_header(client):
    c, _ = client
    assert c.post("/api/alerts/test").status_code == 403
    assert c.post("/api/alerts/test", headers=CTRL).json()["results"]["desktop"] == "sent"


def test_host_data_needs_the_api_key_when_one_is_set(client, monkeypatch):
    c, iid = client
    monkeypatch.setattr(api, "API_KEY", "s3cret")
    for url in ("/api/events", "/api/incidents", f"/api/incidents/{iid}", f"/api/incidents/{iid}/evidence"):
        assert c.get(url).status_code == 401
    assert c.get("/api/incidents", headers={"X-API-Key": "s3cret"}).status_code == 200
