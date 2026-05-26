"""
Per-row AI triage helpers + admin-decision persistence.

The dashboard renders a half-circle "AI confidence" gauge on every threat
row. This module is the single source of truth for two things:

  1. compute_ai_confidence(row) -- assigns a 0..100 score to ANY row in
     threat_log.csv, including legacy rule-based hits, by feeding a
     reconstructed feature vector through the SimilarityEngine. For AI
     rows we already have a blended threat score; we use it directly.

  2. Decisions log -- ai_decisions.csv records admin choices ("allow" or
     "block") per source IP. Decisions are read by the AI engine at
     alert-time so allowed IPs are suppressed and blocked IPs are
     marked as confirmed.
"""

from __future__ import annotations

import csv
import os
import re
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .attack_profiles import ATTACK_PROFILES
from .feature_extractor import FEATURE_NAMES, FEATURE_RANGES, normalize_vector, vector_from_features
from .similarity_engine import SimilarityEngine


# ---------------------------------------------------------------------------
# AI confidence per row
# ---------------------------------------------------------------------------

# Map legacy threat_type substrings -> attack profile name. We use this to
# decide which profile the AI engine should compare each row against.
_LEGACY_PROFILE_MAP = (
    ("ai:",              None),                  # handled specially below
    ("syn flood",        "ddos"),
    ("packet flood",     "ddos"),
    ("dos",              "ddos"),
    ("port scan",        "port_scan"),
    ("brute",            "brute_force"),
    ("malicious",        None),                  # reputation -> heuristic score
)

_SIM_ENGINE = SimilarityEngine()


def _legacy_features(threat_type: str, severity: str, score: int) -> Dict[str, float]:
    """
    Build a representative feature dict from a legacy detector row.

    The legacy log only carries `threat_type / severity / score` -- not the
    full per-packet flow -- so we approximate the flow that *would have*
    produced this row, parameterised by the score (which IS the intensity
    in the legacy format: 30 distinct ports, 100 SYNs, etc.).
    """
    t = (threat_type or "").lower()
    s = max(1, int(score) if score is not None else 1)
    # Defaults that look like a benign flow; profile-specific lines overwrite.
    feats: Dict[str, float] = {n: 0.0 for n in FEATURE_NAMES}
    feats["session_duration"]   = 10.0
    feats["inbound_outbound_ratio"] = 1.0
    feats["ack_ratio"]          = 0.3

    if "port scan" in t:
        feats["unique_ports_contacted"]  = min(200.0, float(s))
        feats["syn_ratio"]               = 0.95
        feats["sequential_port_pattern"] = 0.85
        feats["failed_connection_ratio"] = 0.8
        feats["packets_per_second"]      = min(150.0, float(s) * 1.5)
        feats["total_packets"]           = float(s) * 2
        feats["repeated_target_frequency"] = 0.9
        feats["ack_ratio"]               = 0.05
    elif "syn flood" in t:
        feats["syn_ratio"]               = 0.95
        feats["ack_ratio"]               = 0.0
        feats["packets_per_second"]      = min(200.0, float(s) / 10.0)
        feats["total_packets"]           = float(s)
        feats["bytes_per_second"]        = float(s) * 60.0
        feats["request_interval_variance"] = 0.02
        feats["suspicious_timing_pattern"] = 0.7
    elif "packet flood" in t or ("dos" in t and "syn" not in t):
        feats["packets_per_second"]      = min(200.0, float(s) / 10.0)
        feats["total_packets"]           = float(s)
        feats["bytes_per_second"]        = float(s) * 250.0
        feats["syn_ratio"]               = 0.5
        feats["request_interval_variance"] = 0.04
        feats["suspicious_timing_pattern"] = 0.6
    elif "brute" in t:
        feats["retry_frequency"]         = min(50.0, float(s))
        feats["repeated_target_frequency"] = 0.95
        feats["unique_ports_contacted"]  = 1.0
        feats["unique_destinations"]     = 1.0
        feats["syn_ratio"]               = 0.7
        feats["packets_per_second"]      = min(60.0, float(s) / 3.0)
        feats["total_packets"]           = float(s)
        feats["destination_entropy"]     = 0.0
    elif "malicious" in t:
        feats["known_bad_ip_match"]      = 1.0
        feats["packets_per_second"]      = 5.0
    return feats


def _heuristic_reputation_confidence(score: int, direction: str) -> int:
    """
    The similarity engine doesn't have a "known-bad-IP" profile -- reputation
    is a *fact*, not a behaviour. So we score reputation rows directly:
    higher IPsum score = higher confidence, and outbound (your host calling
    a known-bad IP) is intrinsically more alarming than inbound noise.
    """
    s = int(score) if score is not None else 0
    base = 45 + min(40, s * 5)        # IPsum scores cap around 10
    if str(direction).lower() == "outbound":
        base = min(100, base + 10)
    return max(0, min(100, base))


def compute_ai_confidence(row: Dict[str, Any]) -> int:
    """
    Return a 0..100 "AI confidence this is a real threat" score for any row.

    Dispatch rules:
      * AI rows  -- the row already carries the AI's blended threat score.
      * Legacy   -- synthesise a flow vector, run SimilarityEngine, scale.
      * Reputation -- pure heuristic (IPsum is a fact, not a behaviour).
    """
    threat_type = str(row.get("threat_type", "")).lower()
    severity    = str(row.get("severity", "medium"))
    try:
        score = int(row.get("score") or 0)
    except (TypeError, ValueError):
        score = 0

    if threat_type.startswith("ai:"):
        return max(0, min(100, int(row.get("score") or 0)))
    if "malicious" in threat_type:
        return _heuristic_reputation_confidence(score, str(row.get("direction", "")))

    features = _legacy_features(threat_type, severity, score)
    raw_vec = vector_from_features(features)
    norm = normalize_vector(raw_vec)
    best = _SIM_ENGINE.best_match(norm, features)
    # Cosine-blended similarity is 0..1; scale to 0..100 and floor at 30
    # so a row that exists at all isn't ever drawn as "0% confidence".
    return max(30, min(100, int(round(best.similarity * 100))))


def confidence_tier(c: int) -> str:
    if c >= 80:
        return "crit"
    if c >= 60:
        return "high"
    if c >= 40:
        return "med"
    return "low"


def best_match_for_row(row: Dict[str, Any]):
    """Return the SimilarityResult for the row (used by the review page)."""
    threat_type = str(row.get("threat_type", "")).lower()
    severity    = str(row.get("severity", "medium"))
    try:
        score = int(row.get("score") or 0)
    except (TypeError, ValueError):
        score = 0
    if threat_type.startswith("ai:"):
        # Try to parse the AI's own verdict out of the threat_type itself.
        verdict = row.get("threat_type", "")[3:].strip().lower().replace(" ", "_")
        if verdict in ATTACK_PROFILES:
            features = _legacy_features(verdict.replace("_", " "), severity, score)
            raw_vec = vector_from_features(features)
            norm = normalize_vector(raw_vec)
            return _SIM_ENGINE.best_match(norm, features)
    features = _legacy_features(threat_type, severity, score)
    raw_vec = vector_from_features(features)
    norm = normalize_vector(raw_vec)
    return _SIM_ENGINE.best_match(norm, features)


# ---------------------------------------------------------------------------
# Admin decisions
# ---------------------------------------------------------------------------

# Stored next to threat_log.csv so it's discoverable.
_DECISIONS_PATH = os.environ.get(
    "AI_DECISIONS_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "ai_decisions.csv"),
)
_DECISIONS_HEADER = ["timestamp", "ip", "decision", "threat_type", "score", "notes"]
_DECISIONS_LOCK = threading.Lock()

# Cache so the dashboard isn't re-reading the file on every row render.
_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_MTIME: float = 0.0


_ALLOWED_DECISIONS = ("allow", "block", "review")


def _load_decisions_locked() -> Dict[str, Dict[str, Any]]:
    """Build {ip: latest-decision} from the CSV. Caller holds _DECISIONS_LOCK."""
    global _CACHE, _CACHE_MTIME
    if not os.path.isfile(_DECISIONS_PATH):
        _CACHE = {}
        _CACHE_MTIME = 0.0
        return _CACHE
    mtime = os.path.getmtime(_DECISIONS_PATH)
    if mtime == _CACHE_MTIME and _CACHE:
        return _CACHE
    out: Dict[str, Dict[str, Any]] = {}
    try:
        with open(_DECISIONS_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = (row.get("ip") or "").strip()
                if not ip:
                    continue
                # Last write wins (per-IP).
                out[ip] = {
                    "timestamp":   row.get("timestamp", ""),
                    "decision":    (row.get("decision") or "").lower(),
                    "threat_type": row.get("threat_type", ""),
                    "score":       row.get("score", ""),
                    "notes":       row.get("notes", ""),
                }
    except Exception:
        # Bad file -> behave as if no decisions exist.
        return {}
    _CACHE = out
    _CACHE_MTIME = mtime
    return out


def load_decisions() -> Dict[str, Dict[str, Any]]:
    """{ip: latest-decision dict}. Cached against the file's mtime."""
    with _DECISIONS_LOCK:
        return dict(_load_decisions_locked())


def get_decision(ip: str) -> Optional[Dict[str, Any]]:
    return load_decisions().get(ip)


def record_decision(
    ip: str,
    decision: str,
    threat_type: str = "",
    score: int = 0,
    notes: str = "",
) -> Dict[str, Any]:
    """
    Append a decision row to ai_decisions.csv and refresh the cache.

    Validates the decision label (allow / block / review). Returns the
    persisted row dict.
    """
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("ip is required")
    decision = (decision or "").lower().strip()
    if decision not in _ALLOWED_DECISIONS:
        raise ValueError(f"decision must be one of {_ALLOWED_DECISIONS}, got {decision!r}")
    notes = re.sub(r"[\r\n]+", " ", notes or "").strip()[:240]

    row = {
        "timestamp":   datetime.now().isoformat(),
        "ip":          ip,
        "decision":    decision,
        "threat_type": (threat_type or "")[:80],
        "score":       int(score) if score is not None else 0,
        "notes":       notes,
    }

    with _DECISIONS_LOCK:
        new_file = not os.path.isfile(_DECISIONS_PATH) \
            or os.path.getsize(_DECISIONS_PATH) == 0
        with open(_DECISIONS_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_DECISIONS_HEADER)
            if new_file:
                writer.writeheader()
            writer.writerow(row)
        # Invalidate cache so the next read picks the new row up.
        global _CACHE_MTIME
        _CACHE_MTIME = 0.0

    return row


def decisions_path() -> str:
    return _DECISIONS_PATH
