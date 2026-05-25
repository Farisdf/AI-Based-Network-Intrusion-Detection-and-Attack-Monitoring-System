"""
AI behavioural detection package.

This package is a sidecar to the existing IDS:

  * It NEVER replaces the legacy IDS logic (Check_IP, BehaviorEngine,
    alerting). The signature/rule pipeline still runs unchanged.
  * It adds a parallel "behaviour DNA" layer that extracts feature
    vectors from observed flows, compares them against attack
    fingerprints, runs IsolationForest anomaly detection, blends a
    0..100 threat score, and emits structured AI alerts.

Public surface area (kept small on purpose):

    from ai_detection import AIDetectionEngine, CONFIG

    engine = AIDetectionEngine().start()
    engine.observe_packet(...)
    engine.note_behavioral_hits(ip, hits)
    engine.stop()
"""

from .config import CONFIG, AIConfig
from .engine import AIDetectionEngine
from .feature_extractor import FEATURE_NAMES, FeatureExtractor, FlowAggregator
from .similarity_engine import SimilarityEngine, SimilarityResult
from .anomaly_detector import AnomalyDetector
from .model_manager import ModelManager
from .scoring import ThreatScore, compute_threat_score, severity_band
from .alerting import build_alert, deliver_alert, recommended_action
from .attack_profiles import ATTACK_PROFILES, list_profiles, get_profile

__all__ = [
    "CONFIG",
    "AIConfig",
    "AIDetectionEngine",
    "FEATURE_NAMES",
    "FeatureExtractor",
    "FlowAggregator",
    "SimilarityEngine",
    "SimilarityResult",
    "AnomalyDetector",
    "ModelManager",
    "ThreatScore",
    "compute_threat_score",
    "severity_band",
    "build_alert",
    "deliver_alert",
    "recommended_action",
    "ATTACK_PROFILES",
    "list_profiles",
    "get_profile",
]
