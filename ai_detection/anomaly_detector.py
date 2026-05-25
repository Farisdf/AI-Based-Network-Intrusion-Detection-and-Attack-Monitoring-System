"""
Unsupervised anomaly detection.

Wraps an IsolationForest from scikit-learn. The model is trained on a
"normal traffic" baseline; at inference time decision_function() gives a
real number where lower = more anomalous. We rescale that to a 0..1
anomaly_score where 1 means "very anomalous" so the score plays nicely
with the similarity score in the threat-scoring step.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except ImportError as e:  # pragma: no cover - surfaced at import via _IMPORT_ERR
    IsolationForest = None        # type: ignore[assignment]
    _IMPORT_ERR: Optional[ImportError] = e
else:
    _IMPORT_ERR = None

from .config import CONFIG


_log = logging.getLogger("ai_detection.anomaly")


class AnomalyDetector:
    """
    Thread-safe wrapper around an IsolationForest.

    The detector is usable even before a model has been fitted -- predict()
    just returns 0.0 (neutral). Callers should treat is_fitted() as a guard.
    """

    def __init__(self,
                 n_estimators: int = CONFIG.IF_N_ESTIMATORS,
                 contamination: float = CONFIG.IF_CONTAMINATION,
                 random_state: int = CONFIG.IF_RANDOM_STATE):
        if _IMPORT_ERR is not None:
            raise RuntimeError(
                "scikit-learn is required for AnomalyDetector. "
                "Install with: pip install scikit-learn"
            ) from _IMPORT_ERR
        self._params = {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": random_state,
            "n_jobs": 1,
        }
        self._model: Optional[IsolationForest] = None
        self._score_lo: float = -0.5   # calibration -- updated on fit()
        self._score_hi: float =  0.5
        self._lock = threading.Lock()

    # ---- Lifecycle ---------------------------------------------------------

    def fit(self, X: np.ndarray) -> None:
        """Train the model on a matrix of normal-traffic feature vectors."""
        if X.ndim != 2:
            raise ValueError(f"Expected 2D matrix, got shape {X.shape}")
        if X.shape[0] < 10:
            raise ValueError(f"Need at least 10 samples to fit (got {X.shape[0]})")
        _log.info("Fitting IsolationForest on %d samples (%d features)",
                  X.shape[0], X.shape[1])
        model = IsolationForest(**self._params)
        model.fit(X)
        scores = model.decision_function(X)
        with self._lock:
            self._model = model
            # Calibrate using the fit-set extremes so anomaly_score sits in [0,1].
            self._score_lo = float(np.min(scores))
            self._score_hi = float(np.max(scores))
            if self._score_hi - self._score_lo < 1e-6:
                # Pathological constant features -- pick safe defaults.
                self._score_lo, self._score_hi = -0.5, 0.5
        _log.info("Model fitted. Calibration window: [%.4f, %.4f]",
                  self._score_lo, self._score_hi)

    def load(self, model, score_lo: float, score_hi: float) -> None:
        """Install a pre-fitted model (used by model_manager.load_model)."""
        with self._lock:
            self._model = model
            self._score_lo = score_lo
            self._score_hi = score_hi

    def snapshot(self):
        """Return (model, lo, hi) for serialisation."""
        with self._lock:
            return self._model, self._score_lo, self._score_hi

    def is_fitted(self) -> bool:
        return self._model is not None

    # ---- Inference ---------------------------------------------------------

    def predict(self, vector: np.ndarray) -> float:
        """
        Return an anomaly_score in [0, 1]. 1.0 = very anomalous.
        Returns 0.0 if the model is unfitted (neutral, safe default).
        """
        if vector.ndim == 1:
            vector = vector.reshape(1, -1)
        with self._lock:
            model = self._model
            lo, hi = self._score_lo, self._score_hi
        if model is None:
            return 0.0
        raw = float(model.decision_function(vector)[0])
        # Lower decision_function -> more anomalous. Flip then min/max scale.
        scaled = (hi - raw) / max(1e-6, hi - lo)
        return max(0.0, min(1.0, scaled))

    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """Vectorised version of predict()."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        with self._lock:
            model = self._model
            lo, hi = self._score_lo, self._score_hi
        if model is None:
            return np.zeros(X.shape[0])
        raw = model.decision_function(X)
        scaled = (hi - raw) / max(1e-6, hi - lo)
        return np.clip(scaled, 0.0, 1.0)
