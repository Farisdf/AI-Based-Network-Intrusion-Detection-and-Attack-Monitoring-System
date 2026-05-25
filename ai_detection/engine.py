"""
AI detection orchestrator.

`AIDetectionEngine` is the single entry-point the IDS uses. Its API is
deliberately tiny so it can be dropped into the existing packet loop
without changing the project's architecture:

    engine = AIDetectionEngine().start()
    ...
    engine.observe_packet(...)        # called per-packet by IDS._process_packet
    engine.note_behavioral_hits(...)  # called when BehaviorEngine fires
    ...
    engine.stop()

Internally:

  Producer side (the IDS thread):
    observe_packet()     - O(1), just updates the FlowAggregator.

  Worker side (background thread):
    - every FLUSH_INTERVAL_SECONDS the worker drains ready flows,
      extracts feature vectors, runs similarity + anomaly inference,
      blends a threat score, and emits AI alerts.

  Auto-retrain:
    - on the same loop, the worker checks ModelManager.needs_retrain()
      and refreshes the IsolationForest from the rolling buffer of
      "normal-looking" feature vectors it has seen since boot.

If `AI_ENABLED=false`, every public method short-circuits to a no-op.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np

from .alerting import build_alert, deliver_alert, recommended_action
from .config import CONFIG
from .feature_extractor import (
    FEATURE_NAMES,
    FeatureExtractor,
    FlowAggregator,
    _FlowState,            # noqa: F401  -- type only
)
from .model_manager import ModelManager
from .scoring import compute_threat_score
from .similarity_engine import SimilarityEngine


_log = logging.getLogger("ai_detection.engine")
if not _log.handlers:
    # Sensible default formatting if the host program hasn't configured logging.
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    _log.addHandler(h)
    _log.setLevel(logging.INFO)


_FLUSH_INTERVAL_SECONDS = 2.0       # how often the worker drains ready flows
_NORMAL_BUFFER_MAX      = 5000      # cap on rolling-normal vectors kept for retrain


class AIDetectionEngine:
    """Sidecar AI engine that runs alongside the existing IDS."""

    def __init__(self,
                 enabled: bool = CONFIG.AI_ENABLED,
                 similarity_threshold: float = CONFIG.SIMILARITY_THRESHOLD,
                 anomaly_threshold: float = CONFIG.ANOMALY_THRESHOLD,
                 threat_threshold: int = CONFIG.THREAT_ALERT_THRESHOLD):
        self._enabled = bool(enabled)
        self._similarity_threshold = float(similarity_threshold)
        self._anomaly_threshold    = float(anomaly_threshold)
        self._threat_threshold     = int(threat_threshold)

        self._aggregator = FlowAggregator()
        self._extractor  = FeatureExtractor()
        self._similarity = SimilarityEngine()
        self._model: Optional[ModelManager] = None

        # ip -> list of pending behavioural-hit dicts to incorporate at flush.
        self._behavioral_hits: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._hits_lock = threading.Lock()

        # Rolling buffer of vectors classified as "normal" -- used for retraining.
        self._normal_buffer: Deque[np.ndarray] = deque(maxlen=_NORMAL_BUFFER_MAX)

        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._alerts_emitted = 0
        self._flushes_done = 0

        # Errors that should never crash packet capture get logged here.
        self._last_error: Optional[str] = None

    # ---- Lifecycle ---------------------------------------------------------

    def start(self) -> "AIDetectionEngine":
        """Initialise the model and spin up the background worker."""
        if not self._enabled:
            _log.info("AI detection disabled via config -- engine is a no-op.")
            return self
        try:
            self._model = ModelManager()
            self._model.load_or_bootstrap()
        except Exception as e:
            _log.exception("Failed to initialise anomaly model: %s", e)
            self._model = None  # similarity still works without an anomaly model
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._worker_loop, name="ai-detection-worker", daemon=True,
        )
        self._worker.start()
        _log.info(
            "AIDetectionEngine started "
            "(similarity>=%.2f, anomaly>=%.2f, threat>=%d, model_fitted=%s)",
            self._similarity_threshold, self._anomaly_threshold,
            self._threat_threshold,
            bool(self._model and self._model.is_fitted()),
        )
        return self

    def stop(self, timeout: float = 5.0) -> None:
        if not self._enabled:
            return
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
        # Final drain so we don't lose the last partial window.
        try:
            self._flush_once(force=True)
        except Exception as e:
            _log.warning("Final flush failed: %s", e)

    def is_enabled(self) -> bool:
        return self._enabled

    def stats(self) -> Dict[str, Any]:
        return {
            "enabled":           self._enabled,
            "tracked_ips":       len(self._aggregator),
            "flushes":           self._flushes_done,
            "alerts_emitted":    self._alerts_emitted,
            "normal_buffer":     len(self._normal_buffer),
            "model_fitted":      bool(self._model and self._model.is_fitted()),
            "last_error":        self._last_error,
        }

    # ---- Producer-side API (called by the IDS) -----------------------------

    def observe_packet(
        self,
        src_ip: str,
        dst_ip: Optional[str],
        dst_port: Optional[int],
        protocol: Optional[str],
        is_syn: bool,
        tcp_flags: Optional[int],
        packet_size: int,
        ts: float,
        bad_ip_match: bool = False,
    ) -> None:
        """Record one packet's metadata. Lightweight + non-blocking."""
        if not self._enabled:
            return
        try:
            self._aggregator.observe(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                is_syn=is_syn,
                tcp_flags=tcp_flags,
                packet_size=packet_size,
                ts=ts,
                bad_ip_match=bad_ip_match,
            )
        except Exception as e:
            # Capture must NEVER crash because of the AI sidecar.
            self._last_error = f"observe_packet: {e}"
            _log.debug("observe_packet error swallowed: %s", e)

    def note_behavioral_hits(self, src_ip: str, hits: List[Dict[str, Any]]) -> None:
        """Hand off the legacy BehaviorEngine's hits so they boost the AI score."""
        if not self._enabled or not hits:
            return
        with self._hits_lock:
            self._behavioral_hits[src_ip].extend(hits)

    # ---- Worker side -------------------------------------------------------

    def _worker_loop(self) -> None:
        _log.info("AI worker thread up.")
        while not self._stop_event.is_set():
            try:
                self._flush_once()
                self._maybe_retrain()
            except Exception as e:
                self._last_error = f"worker_loop: {e}"
                _log.exception("AI worker loop iteration failed: %s", e)
            # Wait with periodic wake-ups so stop() is responsive.
            self._stop_event.wait(timeout=_FLUSH_INTERVAL_SECONDS)
        _log.info("AI worker thread shutting down.")

    def _flush_once(self, force: bool = False) -> None:
        if force:
            ready = self._aggregator.force_flush_all()
        else:
            ready = self._aggregator.drain_ready()
        if not ready:
            return
        for src_ip, state in ready:
            try:
                self._analyze_flow(src_ip, state)
            except Exception as e:
                _log.exception("Flow analysis failed for %s: %s", src_ip, e)
        self._flushes_done += 1

    def _analyze_flow(self, src_ip: str, state) -> None:
        # 1) Feature extraction.
        raw_features, _raw_vec, norm_vec = self._extractor.extract(state)

        # 2) Similarity to attack profiles.
        ranked = self._similarity.analyze(norm_vec, raw_features)
        best = ranked[0]

        # 3) Anomaly inference.
        if self._model is not None and self._model.is_fitted():
            anomaly = float(self._model.detector.predict(norm_vec))
        else:
            anomaly = 0.0

        # 4) Behavioural / IoC corroboration.
        with self._hits_lock:
            beh = self._behavioral_hits.pop(src_ip, [])
        ioc_score = float(raw_features.get("known_bad_ip_match", 0.0)) * 10.0
        traffic_severity = min(
            1.0, float(raw_features.get("packets_per_second", 0.0)) / 200.0
        )

        # 5) Combined score.
        ts_obj = compute_threat_score(
            similarity_score=best.similarity,
            anomaly_score=anomaly,
            ioc_score=ioc_score,
            behavioral_alerts=beh,
            traffic_severity=traffic_severity,
        )

        _log.debug(
            "flow %s top=%s sim=%.2f anom=%.2f threat=%d",
            src_ip, best.attack_type, best.similarity, anomaly, ts_obj.score,
        )

        # 6) Honour any admin decision for this source IP. allow=suppress,
        # block=confirm and bump severity, review=note in description but
        # still alert. Failures (missing module, file lock) degrade open --
        # we never *fail closed* and drop the alert because of a triage bug.
        decision = None
        try:
            from .triage import get_decision   # local import: optional dep
            decision = get_decision(src_ip)
        except Exception as e:
            _log.debug("triage lookup failed for %s: %s", src_ip, e)

        if decision and decision.get("decision") == "allow":
            # Admin has whitelisted this IP -- contribute to the normal buffer
            # and skip the alert path entirely.
            _log.info("AI alert suppressed for %s (admin decision: allow)", src_ip)
            self._normal_buffer.append(norm_vec.copy())
            return

        # 7) Decide whether to alert.
        should_alert = (
            best.similarity >= self._similarity_threshold
            or anomaly      >= self._anomaly_threshold
            or ts_obj.score >= self._threat_threshold
        )
        if should_alert:
            # Pick the most informative label for the alert.
            if best.similarity >= self._similarity_threshold:
                suspected = best.attack_type
                matched   = best.matched_features
            else:
                suspected = "anomalous behaviour"
                matched   = best.matched_features or ["unmatched behaviour profile"]
            # An explicit "block" decision is the admin saying "this IP is
            # confirmed bad" -- escalate every future AI alert from that IP
            # to high severity so it isn't lost in the noise.
            severity = ts_obj.severity
            extra = list(matched)
            if decision and decision.get("decision") == "block":
                severity = "high"
                extra = ["[admin: BLOCKED]"] + extra
            elif decision and decision.get("decision") == "review":
                extra = ["[admin: review]"] + extra

            alert = build_alert(
                source_ip=src_ip,
                destination_ip=_top_destination(state),
                suspected_attack=suspected,
                similarity_score=best.similarity,
                anomaly_score=anomaly,
                threat_score=ts_obj.score,
                matched_features=extra,
                raw_features=raw_features,
                recommended_action=recommended_action(ts_obj.score),
                severity=severity,
            )
            if deliver_alert(alert):
                self._alerts_emitted += 1
        else:
            # Quiet flow -- contribute to the normal-traffic buffer so future
            # retrains adapt to this environment.
            self._normal_buffer.append(norm_vec.copy())

    def _maybe_retrain(self) -> None:
        if self._model is None or not self._model.needs_retrain():
            return
        if len(self._normal_buffer) < 200:
            # Not enough observed normal to retrain reliably; skip until next tick.
            return
        try:
            X = np.vstack(list(self._normal_buffer))
            _log.info("Retraining anomaly model on %d observed normal samples", X.shape[0])
            self._model.train_from_vectors(X, persist=True)
        except Exception as e:
            self._last_error = f"retrain: {e}"
            _log.exception("Retrain failed: %s", e)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _top_destination(state) -> Optional[str]:
    if not state.destinations:
        return None
    return max(state.destinations, key=state.destinations.get)
