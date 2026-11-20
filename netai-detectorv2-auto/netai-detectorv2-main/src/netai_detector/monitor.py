"""The automatic engine: learn -> train -> monitor, with no commands from the user.

Lifecycle (runs in one background thread, started with the web app):

  1. If a compatible trained model exists, go straight to monitoring.
  2. Otherwise watch the network and collect `learn_windows` windows of traffic (the baseline),
     train the model, save it, and continue to monitoring.
  3. Score every new window and record it as an event. Anomalies include the features that
     deviated most from the baseline, to speed up triage.

If live capture cannot start (no admin rights, no Npcap/libpcap) and there is no real model yet, a
clearly-labelled simulated demo runs instead, so the dashboard is never an empty page. It is
replaced by real capture, and its events are removed, as soon as live capture works.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
import logging
import random
import threading
import time
import numpy as np
from . import config
from .capture import CaptureUnavailable, extract_pcap, open_live
from .demo import DemoSource
from .detection import AnomalyDetector
from .storage import EventStore

log = logging.getLogger("netai")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Monitor:
    def __init__(self, store: EventStore, model_path: Path = config.MODEL_PATH,
                 baseline_path: Path = config.BASELINE_PATH, mode: str = config.MODE,
                 interface: str | None = config.INTERFACE, learn_windows: int = config.LEARN_WINDOWS,
                 source_factory: Callable[[], object] | None = None,
                 retrain_every: float = config.RETRAIN_HOURS * 3600):
        self.store, self.model_path, self.baseline_path = store, Path(model_path), Path(baseline_path)
        self.mode, self.interface, self.learn_windows = mode, interface, max(20, learn_windows)
        self._source_factory = source_factory  # tests inject fake sources here
        self.retrain_every = retrain_every      # seconds; 0 disables scheduled retraining
        self._trained_mono = time.monotonic()
        self._reservoir: list = []              # representative sample of recent normal windows
        self._seen_normal = 0
        self.detector: AnomalyDetector | None = None
        self._lock = threading.RLock()
        self._stop, self._paused, self._relearn = threading.Event(), threading.Event(), threading.Event()
        self._halt = threading.Event()
        self._thread: threading.Thread | None = None
        self._state = {"phase": "starting", "message": "Starting…", "source": None, "interface": None,
                       "progress": {"done": 0, "target": self.learn_windows}, "warnings": [],
                       "windows_scored": 0, "last_window_at": None, "last_anomaly_at": None}

    # ----------------------------------------------------------------- public controls
    def start(self) -> None:
        if self.mode == "off":
            self._set(phase="idle", message="Background monitoring is turned off (NETAI_MODE=off).")
            self._load_model()
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="netai-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._halt.set()
        if self._thread:
            self._thread.join(timeout=5)

    def pause(self) -> None:
        self._paused.set()
        self._halt.set()
        self._set(phase="paused", message="Paused. Nothing is being captured.")

    def resume(self) -> None:
        self._paused.clear()
        self._set(phase="starting", message="Resuming…")

    def relearn(self) -> None:
        """Throw away the idea of 'normal' and learn it again. The old model stays active until the new one is ready."""
        self._relearn.set()
        self._halt.set()

    def status(self) -> dict:
        with self._lock:
            state = {**self._state, "progress": dict(self._state["progress"]),
                     "warnings": list(self._state["warnings"])}
            det = self.detector
        meta = det.metadata if det else {}
        state["model"] = {"loaded": bool(det and det.is_trained),
                          "trained_at": meta.get("trained_at"),
                          "training_samples": meta.get("training_samples"),
                          "simulated": bool(meta.get("synthetic"))}
        state["paused"] = self._paused.is_set()
        return state

    @property
    def model_ready(self) -> bool:
        return bool(self.detector and self.detector.is_trained)

    # ----------------------------------------------------------------- state helpers
    def _set(self, **changes) -> None:
        with self._lock:
            self._state.update(changes)

    def _warn(self, message: str) -> None:
        log.warning(message)
        with self._lock:
            if message not in self._state["warnings"]:
                self._state["warnings"] = (self._state["warnings"] + [message])[-5:]

    def _real_model(self) -> bool:
        d = self.detector
        return bool(d and d.is_trained and not d.metadata.get("synthetic"))

    # ----------------------------------------------------------------- main loop
    def _run(self) -> None:
        self._load_model()
        while not self._stop.is_set():
            if self._paused.is_set():
                self._stop.wait(0.5)
                continue
            source = None
            try:
                source = self._open_source()
                if source is None:
                    self._idle()
                    continue
                self._set(source=source.kind, interface=source.interface)
                self._session(source)
            except Exception as exc:  # keep the service alive; show the problem on the dashboard
                log.exception("Monitor error")
                self._set(phase="error", message=f"{exc} Retrying in 15 seconds.")
                self._stop.wait(15)
            finally:
                if source is not None:
                    source.close()
        self._set(phase="stopped", message="Stopped.")

    def _session(self, source) -> None:
        while not self._stop.is_set() and not self._paused.is_set():
            if source.kind == "demo" and self._real_model():
                return  # a real model (e.g. from a PCAP) arrived; stop simulating
            if self._needs_learning(source):
                self._learn(source)
            else:
                self._monitor(source)

    def _needs_learning(self, source) -> bool:
        d = self.detector
        if d is None or not d.is_trained or self._relearn.is_set():
            return True
        return bool(d.metadata.get("synthetic")) and source.kind == "live"

    def _idle(self) -> None:
        self._set(phase="idle", source=None,
                  message="Live capture is unavailable. Drop a PCAP file on the dashboard to analyse it.")
        self._relearn.clear()
        while not self._stop.is_set() and not self._paused.is_set():
            self._stop.wait(1.0)

    def _open_source(self):
        if self._source_factory:
            return self._source_factory()
        if self.mode == "demo":
            return DemoSource().open()
        self._set(phase="starting", message="Opening the network interface…")
        try:
            return open_live(self.interface)
        except CaptureUnavailable as exc:
            if self.mode == "live":
                raise
            self._warn(str(exc))
            if self._real_model():
                return None
            self._warn("Showing simulated demo traffic until live capture works.")
            return DemoSource().open()

    def _halting(self, stop_on_relearn: bool) -> threading.Event:
        event = threading.Event()
        with self._lock:
            self._halt = event
            if self._stop.is_set() or self._paused.is_set() or (stop_on_relearn and self._relearn.is_set()):
                event.set()
        return event

    # ----------------------------------------------------------------- phases
    def _learn(self, source) -> None:
        self._relearn.clear()
        halt = self._halting(stop_on_relearn=False)
        if hasattr(source, "fast"):
            source.fast = True   # demo source: generate learning data quickly
        samples: list = []
        what = "simulated traffic" if source.kind == "demo" else "your network"
        self._set(progress={"done": 0, "target": self.learn_windows}, phase="learning",
                  message=f"Learning what normal looks like on {what}. Use the network as usual.")
        for vector in source.windows(halt):
            if halt.is_set():
                return  # paused, stopped or restarted; partial data is discarded
            samples.append(vector)
            self._set(progress={"done": len(samples), "target": self.learn_windows})
            if len(samples) >= self.learn_windows:
                break
        else:
            return
        self._train(np.asarray(samples, dtype=np.float32), source.kind)

    def _train(self, samples: np.ndarray, kind: str) -> None:
        self._set(phase="training", message="Training the anomaly model…")
        detector = AnomalyDetector()
        detector.fit(samples, config.CONTAMINATION)
        detector.metadata.update({"data_source": kind, "synthetic": kind == "demo"})
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(self.baseline_path, features=samples)
        detector.save(self.model_path)
        for path in (self.baseline_path, self.model_path):
            config.hand_back_to_user(path)
        with self._lock:
            self.detector = detector
        self._trained_mono = time.monotonic()
        self._reservoir, self._seen_normal = [], 0
        frac = detector.metadata.get("trimmed_fraction", 0.0)
        if frac >= 0.10:
            self._warn(f"{frac:.0%} of the traffic seen while learning looked unusual and was ignored. "
                       "If the network was under attack or doing something odd then, use Relearn baseline.")
        if kind != "demo":
            self.store.delete_by_source("demo")
        log.info("Model trained on %d windows (%s)", len(samples), kind)

    def _monitor(self, source) -> None:
        halt = self._halting(stop_on_relearn=True)
        if halt.is_set():
            return
        if hasattr(source, "fast"):
            source.fast = False  # demo source: real-time pace with occasional simulated attacks
        if source.kind == "demo":
            self._set(phase="monitoring", message="Monitoring SIMULATED traffic (demo mode).")
        else:
            self._set(phase="monitoring", message=f"Watching {source.interface}.")
        for vector in source.windows(halt):
            if halt.is_set():
                return
            if source.kind == "demo" and self._real_model():
                return
            self._score(vector, source)
            self._maybe_retrain(source)

    def _score(self, vector: np.ndarray, source) -> None:
        detector = self.detector
        if detector is None:
            return
        try:
            result = detector.predict(vector)
        except ValueError:
            return
        details: dict = {"interface": source.interface}
        if result["is_anomaly"]:
            details["top_features"] = detector.explain(vector)
        if source.kind == "demo":
            details["simulated_scenario"] = getattr(source, "last_label", "normal")
        label = "demo" if source.kind == "demo" else f"live:{source.interface}"[:100]
        self.store.add_event(result, label, details)
        if not result["is_anomaly"]:
            self._remember_normal(vector)
        now = _now()
        with self._lock:
            self._state["windows_scored"] += 1
            self._state["last_window_at"] = now
            if result["is_anomaly"]:
                self._state["last_anomaly_at"] = now

    # ----------------------------------------------------------------- scheduled retraining
    def _remember_normal(self, vector: np.ndarray, cap: int = 1000) -> None:
        """Reservoir sampling: keeps an even sample of normal windows across the whole period."""
        self._seen_normal += 1
        if len(self._reservoir) < cap:
            self._reservoir.append(vector)
        else:
            j = random.randrange(self._seen_normal)
            if j < cap:
                self._reservoir[j] = vector

    def _maybe_retrain(self, source) -> None:
        """Refresh the model from recent normal traffic. Windows flagged as anomalies are never
        included, and the trimming in AnomalyDetector.fit removes remaining outliers."""
        if (self.retrain_every <= 0 or source.kind != "live"
                or time.monotonic() - self._trained_mono < self.retrain_every
                or len(self._reservoir) < self.learn_windows):
            return
        samples = np.asarray(self._reservoir, dtype=np.float32)
        try:
            self._train(samples, "live")
            log.info("Model refreshed from %d recent normal windows", len(samples))
        except Exception as exc:
            self._trained_mono = time.monotonic()
            self._warn(f"Scheduled model refresh failed: {exc}")
        self._set(phase="monitoring", message=f"Watching {source.interface}.")

    # ----------------------------------------------------------------- model persistence
    def _load_model(self) -> None:
        if not self.model_path.exists():
            return
        try:
            self.detector = AnomalyDetector.load(self.model_path)
            try:
                trained = datetime.fromisoformat(self.detector.metadata["trained_at"])
                age = (datetime.now(timezone.utc) - trained).total_seconds()
                self._trained_mono = time.monotonic() - max(age, 0.0)
            except (KeyError, ValueError, TypeError):
                pass
        except ValueError:
            self._warn("The saved model is from an older version, so it is being relearned automatically.")
        except Exception as exc:
            self._warn(f"The saved model could not be read ({exc}); learning a new one.")

    # ----------------------------------------------------------------- PCAP drop
    def analyze_pcap(self, path: str | Path, name: str, as_baseline: bool = False) -> dict:
        """Handle a dropped capture file: train from it if we have no real model, otherwise score it."""
        windows = extract_pcap(path)
        if as_baseline or not self._real_model():
            if len(windows) < 20:
                raise ValueError(f"That capture only produced {len(windows)} windows; at least 20 "
                                 "(about 2,000 IPv4 packets) are needed to learn a baseline.")
            self._train(windows, "pcap")
            return {"action": "trained", "windows": int(len(windows)),
                    "message": f"Learned a baseline from {len(windows)} windows in {name}."}
        anomalies = 0
        for vector in windows:
            result = self.detector.predict(vector)
            details = {"file": name}
            if result["is_anomaly"]:
                anomalies += 1
                details["top_features"] = self.detector.explain(vector)
            self.store.add_event(result, f"pcap:{name}"[:100], details)
        return {"action": "analyzed", "windows": int(len(windows)), "anomalies": anomalies,
                "message": f"Analysed {len(windows)} windows from {name}: {anomalies} flagged as anomalous."}
