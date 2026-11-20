import time
import numpy as np
import pytest
from netai_detector import monitor as monitor_module
from netai_detector.demo import DemoSource, synth_window
from netai_detector.detection import AnomalyDetector
from netai_detector.features import FEATURE_NAMES
from netai_detector.monitor import Monitor
from netai_detector.storage import EventStore


class LiveLike(DemoSource):
    """Pretends to be a real capture source (same traffic, different kind)."""
    kind = "live"
    interface = "test0"


def make(tmp_path, source=lambda: DemoSource(learn_pace=0, monitor_pace=0.01, seed=1), **kw):
    kw.setdefault("retrain_every", 0)
    store = EventStore(tmp_path / "e.db")
    return Monitor(store, tmp_path / "m.joblib", tmp_path / "b.npz", mode="auto",
                   learn_windows=20, source_factory=source, **kw), store


def wait_for(cond, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_learns_trains_and_monitors_by_itself(tmp_path):
    mon, store = make(tmp_path)
    mon.start()
    try:
        assert wait_for(lambda: mon.status()["phase"] == "monitoring" and store.stats()["events"] >= 5)
        assert mon.model_ready
        assert (tmp_path / "m.joblib").exists() and (tmp_path / "b.npz").exists()
        assert store.recent(1)[0]["source"] == "demo"
    finally:
        mon.stop()


def test_existing_model_skips_learning(tmp_path):
    rng = np.random.default_rng(3)
    det = AnomalyDetector()
    det.fit(np.stack([synth_window(rng)[0] for _ in range(40)]))
    det.metadata["synthetic"] = False
    det.save(tmp_path / "m.joblib")
    mon, store = make(tmp_path, source=lambda: LiveLike(learn_pace=0, monitor_pace=0.01, seed=2))
    mon.start()
    try:
        assert wait_for(lambda: store.stats()["events"] >= 3)
        assert mon.status()["progress"]["done"] == 0  # never entered learning
    finally:
        mon.stop()


def test_relearn_replaces_model(tmp_path):
    mon, store = make(tmp_path)
    mon.start()
    try:
        assert wait_for(lambda: mon.model_ready and mon.status()["phase"] == "monitoring")
        first = mon.detector.metadata["trained_at"]
        time.sleep(0.01)
        mon.relearn()
        assert wait_for(lambda: mon.detector.metadata["trained_at"] != first)
        assert wait_for(lambda: mon.status()["phase"] == "monitoring")
    finally:
        mon.stop()


def test_pause_and_resume(tmp_path):
    mon, store = make(tmp_path)
    mon.start()
    try:
        assert wait_for(lambda: store.stats()["events"] >= 3)
        mon.pause()
        time.sleep(0.3)
        count = store.stats()["events"]
        time.sleep(0.5)
        assert store.stats()["events"] == count
        assert mon.status()["phase"] == "paused"
        mon.resume()
        assert wait_for(lambda: store.stats()["events"] > count)
    finally:
        mon.stop()


def test_real_capture_replaces_demo_model_and_events(tmp_path):
    mon, store = make(tmp_path)  # first run: demo
    mon.start()
    try:
        assert wait_for(lambda: store.stats()["events"] >= 3)
    finally:
        mon.stop()
    assert AnomalyDetector.load(tmp_path / "m.joblib").metadata["synthetic"] is True
    mon2, store2 = make(tmp_path, source=lambda: LiveLike(learn_pace=0, monitor_pace=0.01, seed=5))
    mon2.start()
    try:
        assert wait_for(lambda: mon2.detector is not None and not mon2.detector.metadata.get("synthetic")
                        and mon2.status()["phase"] == "monitoring")
        assert wait_for(lambda: store2.stats()["events"] > 0)
        assert all(not e["source"] == "demo" for e in store2.recent(50))
    finally:
        mon2.stop()


def test_incompatible_saved_model_is_relearned_with_warning(tmp_path):
    import joblib
    joblib.dump({"feature_version": 0, "model": None, "scaler": None}, tmp_path / "m.joblib")
    mon, store = make(tmp_path)
    mon.start()
    try:
        assert wait_for(lambda: mon.model_ready)
        assert any("older version" in w for w in mon.status()["warnings"])
    finally:
        mon.stop()


def test_demo_scenarios_are_detectable_and_normal_mostly_is_not():
    rng = np.random.default_rng(11)
    det = AnomalyDetector()
    det.fit(np.stack([synth_window(rng)[0] for _ in range(80)]))
    for scenario in ("portscan", "flood", "exfil"):
        vector, _ = synth_window(rng, anomaly=scenario)
        res = det.predict(vector)
        assert res["is_anomaly"], scenario
        assert det.explain(vector)  # explains why
    false_alarms = sum(det.predict(synth_window(rng)[0])["is_anomaly"] for _ in range(100))
    assert false_alarms <= 10


def test_pcap_drop_trains_when_no_real_model_then_scores(tmp_path, monkeypatch):
    rng = np.random.default_rng(4)
    windows = np.stack([synth_window(rng)[0] for _ in range(30)])
    monkeypatch.setattr(monitor_module, "extract_pcap", lambda path: windows)
    mon, store = make(tmp_path)
    first = mon.analyze_pcap("x.pcap", "x.pcap")
    assert first["action"] == "trained" and mon.model_ready
    scan = np.stack([synth_window(rng, anomaly="portscan")[0] for _ in range(3)] + [windows[0]])
    monkeypatch.setattr(monitor_module, "extract_pcap", lambda path: scan)
    second = mon.analyze_pcap("y.pcap", "y.pcap")
    assert second["action"] == "analyzed" and second["anomalies"] >= 3
    assert store.recent(1)[0]["source"] == "pcap:y.pcap"


def test_pcap_too_small_for_baseline(tmp_path, monkeypatch):
    rng = np.random.default_rng(4)
    monkeypatch.setattr(monitor_module, "extract_pcap",
                        lambda path: np.stack([synth_window(rng)[0] for _ in range(5)]))
    mon, _ = make(tmp_path)
    with pytest.raises(ValueError, match="at least 20"):
        mon.analyze_pcap("x.pcap", "x.pcap")


def test_storage_prunes_old_events(tmp_path):
    store = EventStore(tmp_path / "p.db", max_events=100)
    for _ in range(450):
        store.add_event({"severity": "low", "is_anomaly": False, "score": 0.1, "threshold": 0.5})
    assert store.stats()["events"] <= 100 + 200
    store.prune()
    assert store.stats()["events"] == 100


def test_scheduled_retrain_uses_recent_normal_traffic(tmp_path):
    mon, store = make(tmp_path, source=lambda: LiveLike(learn_pace=0, monitor_pace=0.01, seed=8),
                      retrain_every=1.0)
    mon.start()
    try:
        assert wait_for(lambda: mon.model_ready and mon.status()["phase"] == "monitoring")
        first = mon.detector.metadata["trained_at"]
        assert wait_for(lambda: mon.detector.metadata["trained_at"] != first, timeout=30)  # no relearn() call
        assert mon.status()["phase"] == "monitoring"
    finally:
        mon.stop()
