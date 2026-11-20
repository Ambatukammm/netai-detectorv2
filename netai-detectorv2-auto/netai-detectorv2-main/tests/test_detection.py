import numpy as np
import pytest
from netai_detector.detection import AnomalyDetector
from netai_detector.features import FEATURE_NAMES

def test_train_predict_and_round_trip(tmp_path):
    rng = np.random.default_rng(7)
    samples = rng.normal(size=(100, len(FEATURE_NAMES))).astype("float32")
    detector = AnomalyDetector()
    detector.fit(samples)
    result = detector.predict(samples[0])
    assert "is_anomaly" in result and result["score"] >= 0
    path = tmp_path / "model.joblib"
    detector.save(path)
    loaded = AnomalyDetector.load(path)
    assert loaded.predict(samples[0])["threshold"] == pytest.approx(detector.threshold)

def test_training_rejects_too_few_samples():
    detector = AnomalyDetector()
    with pytest.raises(ValueError):
        detector.fit(np.zeros((5, len(FEATURE_NAMES))))


def test_poisoned_baseline_still_catches_attacks():
    from netai_detector.demo import synth_window
    rng = np.random.default_rng(1)
    normal = [synth_window(rng)[0] for _ in range(54)]
    attacks_in_baseline = [synth_window(rng, anomaly=a)[0] for a in ("portscan", "flood", "exfil") * 2]
    detector = AnomalyDetector()
    detector.fit(np.stack(normal + attacks_in_baseline))   # ~10% attack traffic while "learning"
    assert detector.metadata["trimmed_samples"] >= 4
    caught = [detector.predict(synth_window(rng, anomaly=a)[0])["is_anomaly"]
              for a in ("portscan", "flood", "exfil") for _ in range(5)]
    assert all(caught)


def test_clean_baseline_is_barely_trimmed():
    from netai_detector.demo import synth_window
    rng = np.random.default_rng(2)
    detector = AnomalyDetector()
    detector.fit(np.stack([synth_window(rng)[0] for _ in range(60)]))
    assert detector.metadata["trimmed_fraction"] <= 0.10
