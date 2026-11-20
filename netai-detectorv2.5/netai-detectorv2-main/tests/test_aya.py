"""Aya, the local AI analyst: built-in reviews, Ollama and OpenAI-compatible local servers (real HTTP
servers standing in for them), fallback, and automatic scan reviews with stored scan results."""
import json
import os
import stat
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from netai_detector import aya
from netai_detector.notifications import NotificationSettings
from netai_detector.notifier import Notifier, ReportService
from netai_detector.reports import build_report, render_html
from netai_detector.scanner import ScanManager, compare_scans, results_csv
from netai_detector.storage import EventStore


def office(store):
    store.upsert_device("192.168.15.5", seen_by="nmap", hostname="fs01.corp.local",
                        ports={"tcp/3389": {"service": "ms-wbt-server", "risk": "RDP"}})
    store.upsert_device("192.168.15.40", seen_by="nmap", vendor="Hikvision",
                        ports={"tcp/23": {"service": "telnet", "risk": "Telnet"}})


class FakeModelServer:
    """Answers like Ollama (/api/...) or an OpenAI-compatible server (/v1/...)."""

    def __init__(self, answer="WHAT I FOUND: two risky devices.\nMY ASSESSMENT: Fix Telnet first."):
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _send(self, obj, code=200):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.requests.append(("GET", self.path, dict(self.headers), None))
                if self.path == "/api/tags":
                    return self._send({"models": [{"name": "llama3.1:8b"}, {"name": "qwen2.5:7b"}]})
                if self.path == "/v1/models":
                    return self._send({"data": [{"id": "local-model"}]})
                self._send({"error": "nope"}, 404)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(("POST", self.path, dict(self.headers), body))
                if body.get("model") == "missing":
                    return self._send({"error": "model 'missing' not found"}, 404)
                if self.path == "/api/chat":
                    return self._send({"message": {"role": "assistant", "content": outer.answer}})
                if self.path == "/v1/chat/completions":
                    return self._send({"choices": [{"message": {"content": outer.answer}}]})
                self._send({"error": "nope"}, 404)

        self.answer = answer
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def model_server():
    srv = FakeModelServer()
    yield srv
    srv.close()


# ------------------------------------------------------------------ built-in Aya
def test_builtin_aya_gives_opinion_and_improvements(tmp_path):
    store = EventStore(tmp_path / "e.db")
    office(store)
    report = build_report("network", store, scan_info={"installed": True, "jobs": []})
    text = aya.builtin_review(report)
    for label in ("WHAT I FOUND:", "MY ASSESSMENT:", "WHAT TO IMPROVE:", "SINCE LAST TIME:"):
        assert label in text
    assert "Telnet on 192.168.15.40" in text and "fs01.corp.local (192.168.15.5)" in text
    assert text.count("firewall rules") == 1                                         # generic advice said once
    assert "first report" in text
    result = aya.review(report, {"aya_engine": "builtin"})
    assert result["engine"] == "built-in" and result["note"] is None


def test_aya_section_in_html_report_is_escaped(tmp_path):
    store = EventStore(tmp_path / "e.db")
    report = build_report("network", store)
    report["aya"] = {"text": "WHAT I FOUND: <img src=x onerror=alert(1)>", "engine": "Ollama · m", "note": None}
    html = render_html(report)
    assert "Aya's review" in html and "<img src=x" not in html and "&lt;img" in html
    assert "<b style=\"color:#0b1220\">WHAT I FOUND:</b>" in html


# ------------------------------------------------------------------ local model servers
def test_aya_with_ollama(tmp_path, model_server):
    store = EventStore(tmp_path / "e.db")
    office(store)
    settings = {"aya_engine": "ollama", "aya_url": model_server.url, "aya_model": "llama3.1:8b"}
    assert aya.list_models(settings) == ["llama3.1:8b", "qwen2.5:7b"]
    result = aya.review(build_report("network", store), settings)
    assert result["engine"] == "Ollama · llama3.1:8b" and "Fix Telnet first" in result["text"]
    method, path, _, body = model_server.requests[-1]
    assert path == "/api/chat" and body["stream"] is False and body["model"] == "llama3.1:8b"
    assert body["messages"][0]["role"] == "system" and "You are Aya" in body["messages"][0]["content"]
    assert "192.168.15.40" in body["messages"][1]["content"]       # real data: it never leaves the machine


def test_aya_with_openai_compatible_server_and_key(tmp_path, model_server):
    store = EventStore(tmp_path / "e.db")
    settings = {"aya_engine": "openai", "aya_url": model_server.url, "aya_model": "local-model",
                "aya_api_key": "lm-studio"}
    assert aya.list_models(settings) == ["local-model"]
    model_server.answer = "<think>planning…</think>WHAT I FOUND: all good."
    result = aya.review(build_report("network", store), settings)
    assert result["text"] == "WHAT I FOUND: all good."                 # reasoning scratchpad removed
    _, path, headers, _ = model_server.requests[-1]
    assert path == "/v1/chat/completions" and headers["Authorization"] == "Bearer lm-studio"


def test_aya_falls_back_when_model_is_unavailable(tmp_path, model_server):
    store = EventStore(tmp_path / "e.db")
    office(store)
    report = build_report("network", store)
    down = aya.review(report, {"aya_engine": "ollama", "aya_url": "http://127.0.0.1:9", "aya_model": "x"})
    assert down["engine"] == "built-in" and "couldn't reach" in down["note"] and "WHAT TO IMPROVE" in down["text"]
    missing = aya.review(report, {"aya_engine": "ollama", "aya_url": model_server.url, "aya_model": "missing"})
    assert "wasn't found" in missing["note"]
    with pytest.raises(aya.AyaError, match="no model"):
        aya.ask_model({"aya_engine": "ollama", "aya_url": model_server.url}, "s", "u")


def test_local_url_detection():
    assert aya.is_local_url("http://127.0.0.1:11434") and aya.is_local_url("http://localhost:1234")
    assert aya.is_local_url("http://192.168.15.20:11434")
    assert not aya.is_local_url("http://8.8.8.8:11434")


def test_aya_settings_validate_and_ignore_old_cloud_keys(tmp_path):
    store = EventStore(tmp_path / "e.db")
    store.set_setting("notifications", {"ai_provider": "anthropic", "ai_api_key": "sk-old"})   # from 2.4
    settings = NotificationSettings(store)
    assert settings.get()["aya_engine"] == "builtin" and "ai_api_key" not in settings.get()
    assert "sk-old" not in str(store.get_setting("notifications"))      # old cloud key removed from disk
    pub = settings.update({"aya_engine": "ollama", "aya_url": "http://127.0.0.1:11434", "aya_model": "llama3.1:8b"})
    assert pub["aya_uses_model"]
    with pytest.raises(ValueError):
        settings.update({"aya_engine": "cloud"})
    with pytest.raises(ValueError):
        settings.update({"aya_url": "file:///etc/passwd"})


# ------------------------------------------------------------------ scans stored and reviewed
FAKE_NMAP = r'''#!{python}
import sys, os
args = sys.argv[1:]
if "--version" in args: print("Nmap version 7.95"); sys.exit(0)
if "--iflist" in args: sys.exit(0)
out = args[args.index("-oX") + 1]
second = os.path.exists({marker!r})
open({marker!r}, "w").write("x")
hosts = [("192.168.15.5", '<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>')]
if second:
    hosts = [("192.168.15.5", hosts[0][1] + '<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>'),
             ("192.168.15.77", "")]
xml = "<nmaprun>" + "".join(f'<host><status state="up"/><address addr="{{ip}}" addrtype="ipv4"/><ports>{{p}}</ports></host>' for ip, p in hosts) + "</nmaprun>"
open(out, "w").write(xml)
'''


def test_two_scans_are_stored_compared_and_reviewed_by_aya(tmp_path):
    if os.name == "nt":
        pytest.skip("stand-in nmap uses a shebang script")
    script = tmp_path / "nmap"
    script.write_text(FAKE_NMAP.format(python=sys.executable, marker=str(tmp_path / "ran")))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    store = EventStore(tmp_path / "e.db")
    settings = NotificationSettings(store)
    reports = ReportService(store, settings)
    notifier = Notifier(store, settings, reports, mailer=lambda *a: None)
    scans = ScanManager(store, nmap=str(script))
    scans.on_finish = notifier.scan_finished

    def run():
        scans.start(["192.168.15.0/24"], "ports", authorised=True)
        end = time.time() + 15
        while time.time() < end and (scans.status()["current"]["status"] == "running"
                                     or not store.scan_jobs(1)[0].get("report_id")):
            time.sleep(0.05)
        return store.scan_jobs(1)[0]

    first = run()
    assert [h["ip"] for h in store.scan_results(first["id"])] == ["192.168.15.5"]
    first_review = store.report(first["report_id"])
    assert "first scan" in first_review["aya"]["text"]
    second = run()
    diff = compare_scans(store, second["id"])
    assert [h["ip"] for h in diff["new_hosts"]] == ["192.168.15.77"]
    assert [o["port"] for o in diff["opened"]] == ["tcp/3389"]
    review = store.report(second["report_id"])
    titles = [f["title"] for f in review["findings"]]
    assert any("newly open since the last scan, 1 of them risky" in t for t in titles)
    assert any("weren't there last scan" in t for t in titles)
    assert review["findings"][0]["severity"] == "high"
    assert "Compared with the scan on" in review["aya"]["text"]
    assert "192.168.15.77" in render_html(review)
    csv = results_csv(store.scan_results(second["id"]))
    assert csv.splitlines()[0].startswith("ip,hostname") and "192.168.15.5,,,,,3389,tcp,ms-wbt-server" in csv
