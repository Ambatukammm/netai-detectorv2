"""API for devices, nmap scans and SPAN discovery (needs FastAPI + httpx: pip install -e ".[dev]")."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402
from netai_detector import api  # noqa: E402
from netai_detector.alerts import Alerter  # noqa: E402
from netai_detector.demo import _packet  # noqa: E402
from netai_detector.devices import DeviceDirectory  # noqa: E402
from netai_detector.evidence import EvidenceStore  # noqa: E402
from netai_detector.monitor import Monitor  # noqa: E402
from netai_detector.passive import PassiveDiscovery  # noqa: E402
from netai_detector.scanner import ScanManager  # noqa: E402
from netai_detector.storage import EventStore  # noqa: E402

CTRL = {"X-Requested-With": "netai"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "e.db")
    devices = DeviceDirectory(store, lookups={})
    passive = PassiveDiscovery(store, local_ips={"192.168.15.240"})
    mon = Monitor(store, tmp_path / "m.joblib", tmp_path / "b.npz", mode="off",
                  evidence=EvidenceStore(tmp_path / "ev"), alerter=Alerter(senders={}),
                  devices=devices, passive=passive)
    monkeypatch.setattr(api, "store", store)
    monkeypatch.setattr(api, "monitor", mon)
    monkeypatch.setattr(api, "scanner", ScanManager(store, devices, find=lambda: None))
    monkeypatch.setattr(api, "API_KEY", "")
    passive.observe([_packet("192.168.15.5", "192.168.15.30", 6, 60, 64, 3389, 51000, flags=0x12)])
    passive.flush()
    return TestClient(api.app)


def test_pages_render(client):
    for url, text in (("/", "Incidents"), ("/network", "Device inventory"), ("/span", "SPAN discovery")):
        resp = client.get(url)
        assert resp.status_code == 200 and text in resp.text


def test_devices_and_labels(client):
    items = client.get("/api/devices").json()["items"]
    assert items[0]["ip"] == "192.168.15.5" and items[0]["name"] is None
    assert client.post("/api/devices/192.168.15.5/label", json={"label": "FS01"}).status_code == 403
    resp = client.post("/api/devices/192.168.15.5/label", json={"label": "FS01"}, headers=CTRL)
    assert resp.json()["name"] == "FS01"
    assert client.post("/api/devices/not-an-ip/label", json={"label": "x"}, headers=CTRL).status_code == 422


def test_span_lists_services_with_risk(client):
    data = client.get("/api/span").json()
    svc = data["items"][0]
    assert (svc["ip"], svc["port"], svc["proto"], svc["source"]) == ("192.168.15.5", 3389, "tcp", "passive")
    assert svc["risk"] and data["status"]["enabled"]


def test_network_without_nmap_explains_and_refuses_to_scan(client):
    data = client.get("/api/network").json()
    assert not data["nmap"]["installed"] and "nmap.org" in data["nmap"]["hint"]
    assert data["subnets"]                                   # still guesses this computer's subnet
    resp = client.post("/api/scan", json={"targets": ["192.168.15.0/24"], "authorised": False}, headers=CTRL)
    assert resp.status_code == 403
    resp = client.post("/api/scan", json={"targets": ["192.168.15.0/24"], "authorised": True}, headers=CTRL)
    assert resp.status_code == 409 and "nmap" in resp.json()["detail"]


def test_custom_subnets_are_validated(client):
    ok = client.post("/api/network/subnets", json={"subnets": ["192.168.30.0/24"]}, headers=CTRL)
    assert ok.json()["custom"] == ["192.168.30.0/24"]
    bad = client.post("/api/network/subnets", json={"subnets": ["10.0.0.0/8"]}, headers=CTRL)
    assert bad.status_code == 422
    assert "192.168.30.0/24" in {s["cidr"] for s in client.get("/api/network").json()["subnets"]}
