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
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from . import __version__
from .capture import CaptureUnavailable
from .config import API_KEY, MAX_PCAP_MB
from .dashboard import DASHBOARD
from .features import FEATURE_NAMES, FEATURE_VERSION
from .monitor import Monitor
from .storage import EventStore

store = EventStore()
monitor = Monitor(store)


@asynccontextmanager
async def lifespan(app: FastAPI):
    monitor.start()
    yield
    monitor.stop()


app = FastAPI(
    title="NetAI Detector",
    description="Automatic network anomaly detection and monitoring. Made by Ruel.",
    version=__version__,
    lifespan=lifespan,
)


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
def get_events(limit: int = Query(100, ge=1, le=500)):
    return {"items": store.recent(limit)}


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
