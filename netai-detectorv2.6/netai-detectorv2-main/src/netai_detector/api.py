"""FastAPI application and self-contained dashboard.

Everything is automatic: starting the app starts the monitor, which learns, trains and watches
the network by itself. The endpoints below exist for the dashboard and for integrations; nobody
has to call them by hand.
"""
from __future__ import annotations
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import os
import tempfile
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
from . import __version__
from .advisor import advise
from .capture import CaptureUnavailable
from . import config
from .config import API_KEY, EVIDENCE_DIR, MAX_PCAP_MB
from .dashboard import DASHBOARD, NETWORK_PAGE, REPORTS_PAGE, SETTINGS_PAGE, SPAN_PAGE, TERMINAL_PAGE
from .features import FEATURE_NAMES, FEATURE_VERSION
from .devices import display_name, valid_ipv4
from .forensics import is_internal
from .aya import ENGINES, AyaError, ask_model, is_local_url, list_models, prompt_for, SYSTEM
from .monitor import Monitor, incident_ips
from .notifications import aya_uses_model, email_ready, send_email
from .notifier import Notifier, ReportService
from .reports import KINDS, build_report, render_html
from .passive import service_name
from .scanner import ScanManager, results_csv
from .terminal import Terminal, available_shells, nmap_targets, terminal_policy
from .storage import EventStore

store = EventStore()
monitor = Monitor(store)
scanner = ScanManager(store, monitor.devices)
settings = monitor.notify_settings
reports = ReportService(store, settings, passive_status=lambda: monitor.passive.status(),
                        scan_info=lambda: {**scanner.available(), "jobs": store.scan_jobs(10)})
notifier = Notifier(store, settings, reports, on_error=monitor._warn)
scanner.on_finish = notifier.scan_finished
terminal = Terminal(store, find_nmap=lambda: scanner.nmap,
                    on_nmap_results=lambda cmd, xml: scanner.import_results(cmd, xml, nmap_targets(cmd)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    monitor.start()
    notifier.start()
    yield
    notifier.stop()
    terminal.stop_all()
    monitor.stop()


app = FastAPI(
    title="NetAI Detector",
    description="Automatic network anomaly detection and monitoring. Made by Ruel.",
    version=__version__,
    lifespan=lifespan,
)


LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", "testserver"}


def host_allowed(host_header: str) -> bool:
    """When NetAI listens only on this computer, accept only requests addressed to it by a local name.
    This stops 'DNS rebinding': a web page pointing its own domain at 127.0.0.1 to reach this API."""
    if config.HOST not in ("127.0.0.1", "localhost", "::1"):
        return True
    host = (host_header or "").strip().lower()
    if host.startswith("["):                      # [::1]:8000
        host = host[1:host.find("]")] if "]" in host else host
    elif host.count(":") == 1:
        host = host.split(":")[0]
    return host in LOCAL_NAMES or host in config.ALLOWED_HOSTS


@app.middleware("http")
async def check_host(request: Request, call_next):
    if not host_allowed(request.headers.get("host", "")):
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse("Invalid Host header. Open NetAI at http://127.0.0.1 (or add the name to "
                                 "NETAI_ALLOWED_HOSTS).", status_code=400)
    return await call_next(request)


class PredictionRequest(BaseModel):
    features: list[float] = Field(..., min_length=len(FEATURE_NAMES), max_length=len(FEATURE_NAMES))
    source: str = Field(default="api", max_length=100)
    details: dict = Field(default_factory=dict)


def require_key(x_api_key: str | None):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_control(x_api_key: str | None, x_requested_with: str | None):
    """Dashboard actions: API key (if configured) plus a custom header that other websites cannot
    send cross-origin, so a random web page cannot drive your local instance."""
    require_key(x_api_key)
    if x_requested_with != "netai":
        raise HTTPException(status_code=403, detail="Missing X-Requested-With: netai header")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard():
    return HTMLResponse(DASHBOARD)


@app.get("/network", response_class=HTMLResponse, include_in_schema=False)
def network_page():
    return HTMLResponse(NETWORK_PAGE)


@app.get("/span", response_class=HTMLResponse, include_in_schema=False)
def span_page():
    return HTMLResponse(SPAN_PAGE)


@app.get("/reports", response_class=HTMLResponse, include_in_schema=False)
def reports_page():
    return HTMLResponse(REPORTS_PAGE)


@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
def settings_page():
    return HTMLResponse(SETTINGS_PAGE)


@app.get("/terminal", response_class=HTMLResponse, include_in_schema=False)
def terminal_page():
    return HTMLResponse(TERMINAL_PAGE)


@app.get("/health")
def health():
    status = monitor.status()
    return {"status": "ok", "application": "NetAI Detector", "version": __version__,
            "model_loaded": monitor.model_ready, "phase": status["phase"],
            "feature_version": FEATURE_VERSION, "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/status")
def get_status():
    """Live state of the automatic monitor: phase, learning progress, warnings, model info."""
    return monitor.status()


@app.get("/api/stats")
def get_stats():
    return {**store.stats(), "model_loaded": monitor.model_ready}


@app.get("/api/features")
def get_features():
    return {"version": FEATURE_VERSION, "count": len(FEATURE_NAMES), "names": FEATURE_NAMES}


@app.get("/api/events")
def get_events(limit: int = Query(100, ge=1, le=500), x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)  # flagged events include IP addresses
    items = store.recent(limit)
    ips = {ip for e in items for f in ((e["details"].get("culprits") or {}).get("top_flows") or [])[:1]
           for ip in (f.get("src"), f.get("dst"))}
    return {"items": items, "names": monitor.devices.names_for(ips, resolve=False)}


def _evidence_file(incident: dict) -> Path | None:
    """The incident's evidence file, only if it exists inside the evidence folder."""
    raw = incident.get("evidence_path")
    if not raw:
        return None
    path = Path(raw).resolve()
    try:
        path.relative_to(Path(EVIDENCE_DIR).resolve())
    except ValueError:
        return None
    return path if path.is_file() else None


@app.get("/api/incidents")
def get_incidents(limit: int = Query(50, ge=1, le=500), x_api_key: str | None = Header(default=None)):
    """Incidents (groups of consecutive flagged windows), newest first."""
    require_key(x_api_key)
    items = store.incidents(limit)
    ips = set()
    for item in items:
        item["evidence_available"] = _evidence_file(item) is not None
        ips |= {ip for f in ((item.get("culprits") or {}).get("top_flows") or [])[:1]
                for ip in (f.get("src"), f.get("dst"))}
    return {"items": items, "names": monitor.devices.names_for(ips, resolve=False)}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int, x_api_key: str | None = Header(default=None)):
    """One incident with the offline advisor's response plan (suggestions only, nothing is run)."""
    require_key(x_api_key)
    incident = store.incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="No such incident")
    evidence = _evidence_file(incident)
    incident["evidence_available"] = evidence is not None
    incident["evidence_note"] = (
        f"Headers-only capture, {incident['evidence_packets']} packets. Open it in Wireshark." if evidence
        else ("The dropped capture file itself is the evidence." if incident["source"].startswith("pcap:")
              else "No evidence file for this incident (below the evidence severity setting, "
                   "turned off, or removed to keep within the size limit)."))
    names = monitor.devices.names_for(incident_ips(incident))
    incident["names"] = names
    incident["plan"] = advise(incident, names)
    return incident


@app.get("/api/incidents/{incident_id}/evidence")
def get_evidence(incident_id: int, x_api_key: str | None = Header(default=None)):
    """Download the headers-only .pcap for an incident."""
    require_key(x_api_key)
    incident = store.incident(incident_id)
    path = _evidence_file(incident) if incident else None
    if path is None:
        raise HTTPException(status_code=404, detail="No evidence file for this incident")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=path.name)


# ------------------------------------------------------------------ devices, network scans, SPAN
class LabelRequest(BaseModel):
    label: str = Field(default="", max_length=80)


class SubnetsRequest(BaseModel):
    subnets: list[str] = Field(default_factory=list, max_length=200)


class ScanRequest(BaseModel):
    targets: list[str] = Field(default_factory=list, max_length=200)
    profile: str = Field(default="discover", max_length=20)
    exclude: list[str] = Field(default_factory=list, max_length=200)
    authorised: bool = False


class DeviceScanRequest(BaseModel):
    authorised: bool = False


def _check_ip(ip: str) -> None:
    if not valid_ipv4(ip):
        raise HTTPException(status_code=422, detail="Not an IPv4 address")


def _scan_errors(call):
    try:
        return call()
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/devices")
def get_devices(x_api_key: str | None = Header(default=None)):
    """The device inventory: every device found by scans, traffic and name lookups."""
    require_key(x_api_key)
    items = [d for d in store.devices() if is_internal(d["ip"])]   # your devices, not internet servers
    for item in items:
        item["name"] = display_name(item)
    return {"items": items}


@app.post("/api/devices/{ip}/label")
def label_device(ip: str, body: LabelRequest, x_api_key: str | None = Header(default=None),
                 x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    _check_ip(ip)
    store.set_device_label(ip, body.label)
    return {"ip": ip, "name": display_name(store.device(ip))}


@app.delete("/api/devices/{ip}")
def forget_device(ip: str, x_api_key: str | None = Header(default=None),
                  x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    _check_ip(ip)
    return {"deleted": store.delete_device(ip)}


@app.get("/api/network")
async def get_network(x_api_key: str | None = Header(default=None)):
    """nmap status, suggested subnets/VLANs and the current scan."""
    require_key(x_api_key)
    nmap = await run_in_threadpool(scanner.available)
    subnets = await run_in_threadpool(scanner.subnets)
    return {"nmap": nmap, "subnets": subnets, "custom": store.get_setting("scan_subnets", []) or [],
            "scan": scanner.status()}


@app.post("/api/network/subnets")
def save_subnets(body: SubnetsRequest, x_api_key: str | None = Header(default=None),
                 x_requested_with: str | None = Header(default=None)):
    """Replace your own list of subnets/VLANs to scan."""
    require_control(x_api_key, x_requested_with)
    from .scanner import validate_targets
    clean = _scan_errors(lambda: validate_targets(body.subnets)) if body.subnets else []
    store.set_setting("scan_subnets", clean)
    return {"custom": clean}


@app.get("/api/scan")
def get_scan(x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    return scanner.status()


@app.get("/api/scans/{job_id}/results")
def scan_results(job_id: int, format: str = Query("json", pattern="^(json|csv)$"),
                 x_api_key: str | None = Header(default=None)):
    """Everything one scan found, as stored on this machine (JSON or CSV download)."""
    require_key(x_api_key)
    job = store.scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="No such scan")
    hosts = store.scan_results(job_id)
    if format == "csv":
        from fastapi.responses import Response
        return Response(results_csv(hosts), media_type="text/csv", headers={
            "Content-Disposition": f'attachment; filename="netai-scan-{job_id}.csv"'})
    return {"job": job, "hosts": hosts}


@app.post("/api/scans/{job_id}/review")
async def rereview_scan(job_id: int, x_api_key: str | None = Header(default=None),
                        x_requested_with: str | None = Header(default=None)):
    """Ask Aya to review a finished scan again (e.g. after setting up a local model)."""
    require_control(x_api_key, x_requested_with)
    job = store.scan_job(job_id)
    if not job or job["status"] != "done":
        raise HTTPException(status_code=404, detail="No finished scan with that number")
    report = await run_in_threadpool(reports.review_scan, job_id)
    return {"report_id": report["id"]}


@app.post("/api/scan")
def start_scan(body: ScanRequest, x_api_key: str | None = Header(default=None),
               x_requested_with: str | None = Header(default=None)):
    """Start an nmap scan in the background (one at a time)."""
    require_control(x_api_key, x_requested_with)
    return _scan_errors(lambda: scanner.start(body.targets, body.profile, body.exclude, body.authorised))


@app.post("/api/scan/cancel")
def cancel_scan(x_api_key: str | None = Header(default=None),
                x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    return {"cancelled": scanner.cancel()}


@app.post("/api/devices/{ip}/scan")
def scan_device(ip: str, body: DeviceScanRequest, x_api_key: str | None = Header(default=None),
                x_requested_with: str | None = Header(default=None)):
    """Active port scan of one device: 1000 ports, service versions, OS guess."""
    require_control(x_api_key, x_requested_with)
    _check_ip(ip)
    return _scan_errors(lambda: scanner.start([ip], "services", None, body.authorised))


@app.get("/api/span")
def get_span(x_api_key: str | None = Header(default=None)):
    """Passive (SPAN/mirror) discovery status and every service found, passive or nmap."""
    require_key(x_api_key)
    status = monitor.status()
    items, devices = [], [d for d in store.devices() if is_internal(d["ip"])]
    for dev in devices:
        name = display_name(dev)
        for key, info in dev["ports"].items():
            proto, _, port = key.partition("/")
            items.append({"ip": dev["ip"], "name": name, "proto": proto, "port": int(port),
                          "service": info.get("service") or service_name(int(port)),
                          "product": info.get("product"), "source": info.get("source"),
                          "risk": info.get("risk"), "last_seen": info.get("last_seen") or dev["last_seen"]})
    items.sort(key=lambda s: (not s["risk"], s["ip"], s["port"]))
    return {"status": status["passive"], "source": status["source"], "interface": status["interface"],
            "devices": len(devices), "items": items}


# ------------------------------------------------------------------ settings and reports
@app.get("/api/settings/notifications")
def get_notification_settings(x_api_key: str | None = Header(default=None)):
    """Email, notification, schedule and AI settings. Secrets are masked."""
    require_key(x_api_key)
    return settings.public()


@app.post("/api/settings/notifications")
def save_notification_settings(body: dict, x_api_key: str | None = Header(default=None),
                               x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    try:
        return settings.update(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/settings/notifications/test-email")
async def test_email(x_api_key: str | None = Header(default=None),
                     x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    s = settings.get()
    if not email_ready(s):
        raise HTTPException(status_code=409, detail="Fill in the mail server and at least one recipient, then Save.")
    try:
        await run_in_threadpool(send_email, s, "NetAI Detector test email",
                                "Email notifications from NetAI Detector are working.",
                                "<p>Email notifications from <b>NetAI Detector</b> are working.</p>")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Sending failed: {exc}") from exc
    return {"sent_to": s["email_to"]}


@app.get("/api/aya")
async def aya_status(x_api_key: str | None = Header(default=None)):
    """Aya's engine, whether her model server answers, and the models installed on it."""
    require_key(x_api_key)
    s = settings.get()
    info = {"engine": s["aya_engine"], "engines": ENGINES, "model": s["aya_model"], "url": s["aya_url"],
            "uses_model": aya_uses_model(s), "reachable": None, "models": [], "error": None, "local": True}
    if s["aya_engine"] in ("ollama", "openai"):
        from .aya import DEFAULT_URLS
        url = s["aya_url"] or DEFAULT_URLS[s["aya_engine"]]
        info["url"] = url
        info["local"] = await run_in_threadpool(is_local_url, url)
        try:
            info["models"] = await run_in_threadpool(list_models, s)
            info["reachable"] = True
        except AyaError as exc:
            info["reachable"], info["error"] = False, str(exc)
    return info


@app.post("/api/aya/test")
async def aya_test(x_api_key: str | None = Header(default=None),
                   x_requested_with: str | None = Header(default=None)):
    """Ask Aya's model to review the current network inventory (nothing is saved)."""
    require_control(x_api_key, x_requested_with)
    s = settings.get()
    if not aya_uses_model(s):
        raise HTTPException(status_code=409, detail="Aya is using her built-in analysis. Choose Ollama or a "
                                                    "local server and a model, then Save.")
    report = build_report("network", store, monitor.passive.status(), None)
    try:
        text = await run_in_threadpool(ask_model, s, SYSTEM, prompt_for(report))
    except AyaError as exc:
        raise HTTPException(status_code=502, detail=f"Aya couldn't use the model: {exc}") from exc
    return {"review": text}


class ReportRequest(BaseModel):
    kind: str = Field(default="full", max_length=20)


@app.get("/api/reports")
def list_reports(x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    s = settings.get()
    return {"items": store.reports(50), "kinds": KINDS, "aya_uses_model": aya_uses_model(s),
            "aya_model": s.get("aya_model"), "email_ready": email_ready(s)}


@app.post("/api/reports")
async def create_report(body: ReportRequest, x_api_key: str | None = Header(default=None),
                        x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    if body.kind not in KINDS:
        raise HTTPException(status_code=422, detail="Unknown report type")
    report = await run_in_threadpool(reports.generate, body.kind)
    return {"id": report["id"], "grade": report["grade"], "headline": report["headline"],
            "aya_engine": (report.get("aya") or {}).get("engine"), "aya_note": (report.get("aya") or {}).get("note")}


def _report_or_404(report_id: int) -> dict:
    report = store.report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="No such report")
    return report


@app.get("/api/reports/{report_id}")
def get_report(report_id: int, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    return _report_or_404(report_id)


@app.get("/api/reports/{report_id}/html", response_class=HTMLResponse)
def get_report_html(report_id: int, download: bool = False, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    report = _report_or_404(report_id)
    headers = ({"Content-Disposition": f'attachment; filename="netai-{report["kind"]}-report-{report_id}.html"'}
               if download else {})
    return HTMLResponse(render_html(report), headers=headers)


@app.post("/api/reports/{report_id}/email")
async def email_report(report_id: int, x_api_key: str | None = Header(default=None),
                       x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    report = _report_or_404(report_id)
    try:
        await run_in_threadpool(reports.email, report)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Sending failed: {exc}") from exc
    return {"sent_to": settings.get()["email_to"]}


# ------------------------------------------------------------------ terminal
class TerminalRequest(BaseModel):
    command: str = Field(..., max_length=2000)
    shell: str | None = Field(default=None, max_length=20)


def _terminal_allowed() -> None:
    enabled, reason = terminal_policy()
    if not enabled:
        raise HTTPException(status_code=403, detail=reason)


@app.get("/api/terminal")
def terminal_info(x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    enabled, reason = terminal_policy()
    return {"enabled": enabled, "reason": reason, "shells": available_shells(), "nmap": scanner.nmap,
            "windows": os.name == "nt", "running": terminal.running() if enabled else [],
            "history": store.terminal_history(40)}


@app.post("/api/terminal/run")
def terminal_run(body: TerminalRequest, x_api_key: str | None = Header(default=None),
                 x_requested_with: str | None = Header(default=None)):
    """Run one command on this computer (with NetAI's rights) and return a run id to poll."""
    require_control(x_api_key, x_requested_with)
    _terminal_allowed()
    try:
        return terminal.run(body.command, body.shell)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/terminal/runs/{run_id}")
def terminal_read(run_id: str, offset: int = Query(0, ge=0), x_api_key: str | None = Header(default=None),
                  x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    _terminal_allowed()
    try:
        return terminal.read(run_id, offset)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such command run") from exc


@app.post("/api/terminal/runs/{run_id}/stop")
def terminal_stop(run_id: str, x_api_key: str | None = Header(default=None),
                  x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    _terminal_allowed()
    return {"stopped": terminal.stop(run_id)}


@app.post("/api/alerts/test")
async def test_alert(x_api_key: str | None = Header(default=None),
                     x_requested_with: str | None = Header(default=None)):
    """Send a test alert on every configured channel and report what happened."""
    require_control(x_api_key, x_requested_with)
    return {"results": await run_in_threadpool(monitor.alerter.test)}


@app.post("/api/monitor/{action}")
def control_monitor(action: str, x_api_key: str | None = Header(default=None),
                    x_requested_with: str | None = Header(default=None)):
    require_control(x_api_key, x_requested_with)
    actions = {"pause": monitor.pause, "resume": monitor.resume, "relearn": monitor.relearn}
    if action not in actions:
        raise HTTPException(status_code=404, detail="Unknown action")
    actions[action]()
    return monitor.status()


@app.post("/api/pcap")
async def upload_pcap(request: Request, name: str = Query("capture.pcap", max_length=100),
                      baseline: bool = Query(False), x_api_key: str | None = Header(default=None),
                      x_requested_with: str | None = Header(default=None)):
    """Analyse a dropped capture file. With no real model yet (or baseline=true) it is used to
    learn what normal looks like; otherwise every window is scored and stored as an event."""
    require_control(x_api_key, x_requested_with)
    safe_name = Path(name).name or "capture.pcap"
    limit, size = MAX_PCAP_MB * 1024 * 1024, 0
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    try:
        with tmp:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail=f"File larger than {MAX_PCAP_MB} MB")
                tmp.write(chunk)
        if size == 0:
            raise HTTPException(status_code=422, detail="Empty file")
        return await run_in_threadpool(monitor.analyze_pcap, tmp.name, safe_name, baseline)
    except CaptureUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:  # unreadable/corrupt capture file
        raise HTTPException(status_code=422, detail=f"Could not read that capture file: {exc}") from exc
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@app.post("/api/predict")
def predict(request: PredictionRequest, x_api_key: str | None = Header(default=None)):
    """Optional integration endpoint: score a feature vector from another tool."""
    require_key(x_api_key)
    detector = monitor.detector
    if not detector or not detector.is_trained:
        raise HTTPException(status_code=503, detail="The model is still being learned. See /api/status.")
    try:
        result = detector.predict(request.features)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    event_id = store.add_event(result, request.source, request.details)
    return {"event_id": event_id, **result}
