"""Train and run a reproducible Isolation Forest anomaly detector."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from .features import FEATURE_NAMES, FEATURE_VERSION

class AnomalyDetector:
    def __init__(self, model=None, scaler=None, threshold: float = 0.0, metadata=None):
        self.model = model
        self.scaler = scaler
        self.threshold = float(threshold)
        self.metadata = metadata or {}

    @property
    def is_trained(self) -> bool:
        return self.model is not None and self.scaler is not None

    def fit(self, samples: np.ndarray, contamination: float = 0.02) -> dict:
        values = np.asarray(samples, dtype=np.float32)
        if values.ndim != 2 or values.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected a 2D array with {len(FEATURE_NAMES)} features")
        if len(values) < 20:
            raise ValueError("At least 20 feature windows are required for training")
        if not 0.001 <= contamination <= 0.25:
            raise ValueError("contamination must be between 0.001 and 0.25")
        # Robust training: if the baseline accidentally contains attacks or odd bursts, they would
        # otherwise teach the model that they are "normal". Fit once, drop windows that are extreme
        # outliers (median + 4 MAD, at most 20% of the data), then refit on the rest.
        scaler, model = self._fit_once(values, contamination)
        scores = -model.score_samples(scaler.transform(values))
        median = float(np.median(scores))
        mad = float(np.median(np.abs(scores - median))) * 1.4826 + 1e-9
        keep = scores <= median + 4.0 * mad
        max_trim = 0.20
        if keep.mean() < 1.0 - max_trim:
            keep = scores <= np.quantile(scores, 1.0 - max_trim)
        if keep.all() or keep.sum() < 20:
            keep = np.ones(len(values), dtype=bool)
        trimmed = int((~keep).sum())
        if trimmed:
            values = values[keep]
            scaler, model = self._fit_once(values, contamination)
        self.scaler, self.model = scaler, model
        scaled = self.scaler.transform(values)
        scores = -self.model.score_samples(scaled)
        self.threshold = float(np.quantile(scores, 1.0 - contamination))
        self.metadata = {
            "feature_version": FEATURE_VERSION,
            "feature_names": FEATURE_NAMES,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_samples": int(len(values)),
            "trimmed_samples": trimmed,
            "trimmed_fraction": trimmed / (trimmed + len(values)),
            "contamination": contamination,
            "algorithm": "IsolationForest",
        }
        return {"samples": int(len(values)), "threshold": self.threshold,
                "mean_anomaly_score": float(np.mean(scores))}

    @staticmethod
    def _fit_once(values: np.ndarray, contamination: float):
        scaler = StandardScaler()
        scaled = scaler.fit_transform(values)
        model = IsolationForest(n_estimators=250, contamination=contamination,
                                random_state=42, n_jobs=-1)
        model.fit(scaled)
        return scaler, model

    def predict(self, features: np.ndarray) -> dict:
        if not self.is_trained:
            raise RuntimeError("No trained model found. Train a model first.")
        values = np.asarray(features, dtype=np.float32).reshape(1, -1)
        if values.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected {len(FEATURE_NAMES)} features")
        scaled = self.scaler.transform(values)
        score = float(-self.model.score_samples(scaled)[0])
        label = int(self.model.predict(scaled)[0])
        return {
            "is_anomaly": label == -1 or score > self.threshold,
            "score": score,
            "threshold": self.threshold,
            "severity": "high" if score > self.threshold * 1.5 else (
                "medium" if score > self.threshold else "low"
            ),
            "model": self.metadata.get("algorithm", "IsolationForest"),
        }

    def explain(self, features: np.ndarray, top: int = 3) -> list[dict]:
        """The features that deviate most from the training baseline (in standard deviations)."""
        values = np.asarray(features, dtype=np.float32).reshape(1, -1)
        z = self.scaler.transform(values)[0]
        order = np.argsort(-np.abs(z))[:top]
        return [{"feature": FEATURE_NAMES[i], "value": round(float(values[0][i]), 4),
                 "z": round(float(z[i]), 2)} for i in order]

    def save(self, path: str | Path) -> None:
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained model")
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model, "scaler": self.scaler,
            "threshold": self.threshold, "metadata": self.metadata,
            "feature_version": FEATURE_VERSION,
        }, destination)

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetector":
        payload = joblib.load(path)
        if payload.get("feature_version") != FEATURE_VERSION:
            raise ValueError("Model feature version is incompatible with this application")
        return cls(payload["model"], payload["scaler"],
                   payload["threshold"], payload.get("metadata", {}))
