"""
Model persistence + bootstrap training.

Responsibilities:

  * Load a fitted IsolationForest from disk so the AI engine starts
    "warm" -- no first-run cold path.
  * Generate a synthetic-but-plausible "normal traffic" baseline so the
    detector is usable even before any operator-collected baseline data
    exists. The baseline can be replaced at any time by calling
    train_from_vectors() with real captures.
  * Save / reload via joblib.
  * Track retrain age so the engine can self-retrain on a configurable
    cadence.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional, Tuple

import numpy as np

try:
    import joblib
except ImportError as e:  # pragma: no cover
    joblib = None  # type: ignore[assignment]
    _JOBLIB_ERR: Optional[ImportError] = e
else:
    _JOBLIB_ERR = None

from .anomaly_detector import AnomalyDetector
from .config import CONFIG
from .feature_extractor import FEATURE_NAMES, FEATURE_RANGES


_log = logging.getLogger("ai_detection.model_manager")


class ModelManager:
    """Owns the on-disk artifact and the in-memory AnomalyDetector."""

    def __init__(self, path: str = CONFIG.MODEL_PATH):
        if _JOBLIB_ERR is not None:
            raise RuntimeError(
                "joblib is required for ModelManager. Install with: pip install joblib"
            ) from _JOBLIB_ERR
        self._path = path
        self._detector = AnomalyDetector()
        self._fitted_at: float = 0.0

    # ---- Detector access ---------------------------------------------------

    @property
    def detector(self) -> AnomalyDetector:
        return self._detector

    def is_fitted(self) -> bool:
        return self._detector.is_fitted()

    def age_seconds(self) -> float:
        if self._fitted_at <= 0:
            return float("inf")
        return time.time() - self._fitted_at

    def needs_retrain(self) -> bool:
        if CONFIG.MODEL_RETRAIN_INTERVAL <= 0:
            return False
        return self.age_seconds() > CONFIG.MODEL_RETRAIN_INTERVAL

    # ---- Persistence -------------------------------------------------------

    def load_or_bootstrap(self) -> None:
        """
        Try to load from disk; if that fails, fit a synthetic baseline so
        the detector is always usable.
        """
        if os.path.isfile(self._path):
            try:
                self.load()
                _log.info("Loaded anomaly model from %s (fitted %.0fs ago)",
                          self._path, self.age_seconds())
                return
            except Exception as e:
                _log.warning("Failed to load model %s: %s -- regenerating",
                             self._path, e)
        self.train_synthetic_baseline()
        try:
            self.save()
        except Exception as e:
            _log.warning("Could not persist bootstrap model: %s", e)

    def load(self) -> None:
        payload = joblib.load(self._path)
        model = payload["model"]
        lo = float(payload.get("score_lo", -0.5))
        hi = float(payload.get("score_hi",  0.5))
        self._fitted_at = float(payload.get("fitted_at", time.time()))
        self._detector.load(model, lo, hi)

    def save(self) -> None:
        model, lo, hi = self._detector.snapshot()
        if model is None:
            raise RuntimeError("Cannot save -- model has not been fitted")
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        joblib.dump(
            {
                "model":     model,
                "score_lo":  lo,
                "score_hi":  hi,
                "fitted_at": self._fitted_at,
                "features":  list(FEATURE_NAMES),
            },
            self._path,
        )
        _log.info("Saved anomaly model -> %s", self._path)

    # ---- Training ----------------------------------------------------------

    def train_from_vectors(self, X: np.ndarray, persist: bool = True) -> None:
        self._detector.fit(X)
        self._fitted_at = time.time()
        if persist:
            try:
                self.save()
            except Exception as e:
                _log.warning("Trained model but failed to persist: %s", e)

    def train_synthetic_baseline(self, n_samples: int = 600) -> None:
        """
        Build a plausible "normal traffic" feature matrix and fit on it.

        This is intentionally conservative: most features hug the low end
        of their normalisation range with mild jitter, mimicking a quiet
        host (light browsing / DNS / a handful of long-lived connections).
        It is *not* meant to replace a real baseline -- it is the warm-start
        the operator can override via train_from_vectors().
        """
        _log.info("Fitting synthetic normal-traffic baseline (%d samples)",
                  n_samples)
        rng = np.random.default_rng(CONFIG.IF_RANDOM_STATE)
        X = np.zeros((n_samples, len(FEATURE_NAMES)), dtype=np.float64)

        # Per-feature target means (raw units) for normal traffic.
        # Anything not listed keeps its default mean of 0 (which is the
        # quiet/neutral end of the normalised range).
        means_raw = {
            "packets_per_second":        2.0,
            "bytes_per_second":          12_000.0,
            "avg_packet_size":           600.0,
            "packet_size_variance":      120_000.0,
            "session_duration":          8.0,
            "inbound_outbound_ratio":    0.5,
            "syn_ratio":                 0.08,
            "rst_ratio":                 0.02,
            "fin_ratio":                 0.05,
            "ack_ratio":                 0.7,
            "unique_ports_contacted":    2.0,
            "sequential_port_pattern":   0.05,
            "failed_connection_ratio":   0.05,
            "connection_rate":           0.5,
            "retry_frequency":           1.2,
            "request_interval_variance": 1.5,
            "destination_entropy":       1.0,
            "protocol_entropy":          0.4,
            "repeated_target_frequency": 0.6,
            "known_bad_ip_match":        0.0,
            "unusual_protocol_usage":    0.0,
            "abnormal_port_access":      0.0,
            "suspicious_timing_pattern": 0.1,
            "total_packets":             24.0,
            "total_bytes":               140_000.0,
            "unique_destinations":       3.0,
        }
        # Build the raw matrix, then normalise it the same way live
        # vectors are normalised so the trained model and runtime
        # observations share a coordinate system.
        for i, name in enumerate(FEATURE_NAMES):
            lo, hi = FEATURE_RANGES[name]
            mean = means_raw.get(name, lo)
            # Sigma scales with the normalisation span. Wide enough that
            # benign-but-bursty traffic (HTTPS sessions, video streaming)
            # isn't immediately flagged as anomalous; narrow enough that
            # attack-shaped flows still stand out.
            sigma = max((hi - lo) * 0.18, 1e-3)
            col = rng.normal(loc=mean, scale=sigma, size=n_samples)
            col = np.clip(col, lo, hi)
            X[:, i] = col

        # Normalise -> [0,1]
        for i, name in enumerate(FEATURE_NAMES):
            lo, hi = FEATURE_RANGES[name]
            span = hi - lo if hi > lo else 1.0
            X[:, i] = np.clip((X[:, i] - lo) / span, 0.0, 1.0)

        self._detector.fit(X)
        self._fitted_at = time.time()


def default_manager() -> ModelManager:
    """Convenience factory used by the orchestrator."""
    return ModelManager()
