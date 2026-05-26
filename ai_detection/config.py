"""
AI detection module configuration.

All thresholds and feature-engineering knobs live here so they can be
tuned in one place without touching the analysis code. Values can be
overridden via environment variables (handy for ops / CI).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class AIConfig:
    """Immutable configuration snapshot for the AI engine."""

    # Master switch. When False, the IDS skips AI hooks entirely.
    AI_ENABLED: bool = _env_bool("AI_ENABLED", True)

    # Similarity threshold (cosine, 0..1). >= triggers a "similarity match" alert.
    SIMILARITY_THRESHOLD: float = _env_float("SIMILARITY_THRESHOLD", 0.80)

    # IsolationForest decision_function output is reshaped to a 0..1 anomaly score
    # (1 = most anomalous). >= this fires an anomaly alert.
    ANOMALY_THRESHOLD: float = _env_float("ANOMALY_THRESHOLD", 0.65)

    # Final combined threat score (0..100). >= this fires the unified AI alert.
    THREAT_ALERT_THRESHOLD: int = _env_int("THREAT_ALERT_THRESHOLD", 70)

    # Periodic retrain cadence in seconds. 0 disables auto-retrain.
    MODEL_RETRAIN_INTERVAL: int = _env_int("MODEL_RETRAIN_INTERVAL", 24 * 3600)

    # Per-source-IP flow window for feature extraction.
    FLOW_WINDOW_SECONDS: float = _env_float("FLOW_WINDOW_SECONDS", 10.0)
    # Minimum packets in the window before we run inference.
    MIN_PACKETS_FOR_ANALYSIS: int = _env_int("MIN_PACKETS_FOR_ANALYSIS", 8)
    # Maximum per-IP flow records held in memory.
    MAX_TRACKED_IPS: int = _env_int("MAX_TRACKED_IPS", 4096)

    # Background-worker queue. If full, the IDS drops AI samples rather than
    # blocking the capture loop -- the legacy detectors still run.
    WORKER_QUEUE_SIZE: int = _env_int("AI_WORKER_QUEUE_SIZE", 2048)

    # Persisted model location.
    MODEL_PATH: str = os.environ.get(
        "AI_MODEL_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "isoforest.joblib"),
    )

    # IsolationForest hyperparameters.
    IF_N_ESTIMATORS: int = _env_int("AI_IF_N_ESTIMATORS", 150)
    IF_CONTAMINATION: float = _env_float("AI_IF_CONTAMINATION", 0.08)
    IF_RANDOM_STATE: int = _env_int("AI_IF_RANDOM_STATE", 42)


CONFIG = AIConfig()
