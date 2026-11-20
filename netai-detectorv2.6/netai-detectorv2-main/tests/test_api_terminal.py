"""Terminal API and the DNS-rebinding host check (needs FastAPI + httpx: pip install -e ".[dev]")."""
import os
import time
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402
from netai_detector import api, config  # noqa: E402
from netai_detector.storage import EventStore  # noqa: E402
from netai_detector.terminal import Terminal  # noqa: E402

CTRL = {"X-Requested-With": "netai"}
pytestmark = pytest.mark.skipif(os.name == "nt", reason="uses POSIX commands")


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "e.db")
    monkeypatch.setattr(api, "store", store)
    monkeypatch.setattr(api, "terminal", Terminal(store))
    monkeypatch.setattr(api, "API_KEY", "")
    monkeypatch.setattr(config, "API_KEY", "")
    monkeypatch.setattr(config, "HOST", "127.0.0.1")
    monkeypatch.setattr(config, "TERMINAL", "auto")
    return TestClient(api.app)


def test_run_and_read_a_command(client):
    assert "netai&gt;" in client.get("/terminal").text
    assert client.post("/api/terminal/run", json={"command": "echo hi"}).status_code == 403   # no header
    run = client.post("/api/terminal/run", json={"command": "echo hello-from-netai"}, headers=CTRL).json()
    for _ in range(100):
        r = client.get(f"/api/terminal/runs/{run['id']}", headers=CTRL).json()
        if not r["running"]:
            break
        time.sleep(0.05)
    assert "hello-from-netai" in r["output"] and r["exit_code"] == 0
    info = client.get("/api/terminal").json()
    assert info["enabled"] and info["history"][0]["command"] == "echo hello-from-netai"


def test_terminal_refuses_when_disabled(client, monkeypatch):
    monkeypatch.setattr(config, "TERMINAL", "off")
    assert client.get("/api/terminal").json()["enabled"] is False
    assert client.post("/api/terminal/run", json={"command": "echo hi"}, headers=CTRL).status_code == 403


def test_dns_rebinding_host_is_rejected(client):
    assert client.get("/api/status", headers={"Host": "evil.example.com"}).status_code == 400
    assert client.get("/health", headers={"Host": "127.0.0.1:8000"}).status_code == 200
    assert client.get("/health", headers={"Host": "localhost:8000"}).status_code == 200
    assert client.get("/health", headers={"Host": "[::1]:8000"}).status_code == 200
