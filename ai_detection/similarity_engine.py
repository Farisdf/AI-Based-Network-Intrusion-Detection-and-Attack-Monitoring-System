"""
Behavioural similarity engine.

Compares a flow's normalised feature vector against every known attack
fingerprint. Three signals are blended into a single 0..1 similarity
score per profile:

  1. Cosine similarity         - direction in feature-space
  2. Weighted Euclidean        - magnitude proximity with per-feature weights
  3. Feature-range hit-rate    - fraction of "expected range" features the
                                 observation actually lands inside

The final per-profile score is the weighted mean of the three. We then
return a ranked list, and label the strongest match with a confidence
band so alerts can be filtered downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np

from .attack_profiles import ATTACK_PROFILES, AttackProfile
from .feature_extractor import FEATURE_NAMES, FEATURE_RANGES


_COSINE_WEIGHT     = 0.45
_EUCLIDEAN_WEIGHT  = 0.30
_RANGE_HIT_WEIGHT  = 0.25


@dataclass
class SimilarityResult:
    """One profile <-> observation match."""

    attack_type: str
    similarity: float           # 0..1, higher = more similar
    cosine: float
    euclidean: float            # 0..1 (1 = identical, 0 = far)
    range_hit_rate: float       # 0..1
    confidence: str             # "low" | "medium" | "high" | "critical"
    matched_features: List[str] # rationale strings for the alert

    def to_dict(self) -> Dict[str, object]:
        return {
            "attack_type":      self.attack_type,
            "similarity":       round(self.similarity, 4),
            "cosine":           round(self.cosine, 4),
            "euclidean":        round(self.euclidean, 4),
            "range_hit_rate":   round(self.range_hit_rate, 4),
            "confidence":       self.confidence,
            "matched_features": self.matched_features,
        }


class SimilarityEngine:
    """Caches profile vectors and runs the similarity comparison."""

    def __init__(self, profiles: Dict[str, AttackProfile] = ATTACK_PROFILES):
        self._profiles = profiles

    # ---- Public API --------------------------------------------------------

    def analyze(self, norm_vector: np.ndarray, raw_features: Dict[str, float]
                ) -> List[SimilarityResult]:
        """
        Compare a normalised feature vector against every profile.

        Returns a list of SimilarityResult sorted descending by similarity.
        """
        results: List[SimilarityResult] = []
        for name, profile in self._profiles.items():
            results.append(self._score(name, profile, norm_vector, raw_features))
        results.sort(key=lambda r: r.similarity, reverse=True)
        return results

    def best_match(self, norm_vector: np.ndarray,
                   raw_features: Dict[str, float]) -> SimilarityResult:
        return self.analyze(norm_vector, raw_features)[0]

    # ---- Per-profile scoring ----------------------------------------------

    @staticmethod
    def _cosine(a: np.ndarray, b: np.ndarray) -> float:
        na = float(np.linalg.norm(a))
        nb = float(np.linalg.norm(b))
        if na == 0.0 or nb == 0.0:
            return 0.0
        return float(np.dot(a, b) / (na * nb))

    @staticmethod
    def _weighted_euclidean(a: np.ndarray, b: np.ndarray, w: np.ndarray) -> float:
        """Euclidean distance in [0, sqrt(sum(w))] folded to a [0,1] similarity."""
        diff = a - b
        d = float(np.sqrt(np.sum(w * diff * diff)))
        # max possible weighted distance (each axis 0<->1)
        d_max = float(np.sqrt(np.sum(w))) or 1.0
        return max(0.0, 1.0 - d / d_max)

    def _range_hit_rate(
        self,
        profile: AttackProfile,
        raw_features: Dict[str, float],
    ) -> Tuple[float, List[str]]:
        feat_ranges: Dict[str, Tuple[float, float]] = profile["feature_ranges"]  # type: ignore[assignment]
        rationale_map: Dict[str, str] = profile["rationale"]                     # type: ignore[assignment]
        if not feat_ranges:
            return 0.0, []
        hits = 0
        matched: List[str] = []
        for name, (lo, hi) in feat_ranges.items():
            v = float(raw_features.get(name, 0.0))
            if lo <= v <= hi:
                hits += 1
                if name in rationale_map and rationale_map[name] not in matched:
                    matched.append(rationale_map[name])
        return hits / len(feat_ranges), matched

    def _score(
        self,
        name: str,
        profile: AttackProfile,
        norm_vector: np.ndarray,
        raw_features: Dict[str, float],
    ) -> SimilarityResult:
        target: np.ndarray = profile["vector"]    # type: ignore[assignment]
        weights: np.ndarray = profile["weights"]  # type: ignore[assignment]

        cosine = self._cosine(norm_vector, target)
        # Cosine over non-negative vectors is already in [0,1].
        cosine = max(0.0, min(1.0, cosine))

        euclidean = self._weighted_euclidean(norm_vector, target, weights)
        range_hit, matched_feats = self._range_hit_rate(profile, raw_features)

        similarity = (
            _COSINE_WEIGHT     * cosine +
            _EUCLIDEAN_WEIGHT  * euclidean +
            _RANGE_HIT_WEIGHT  * range_hit
        )
        similarity = max(0.0, min(1.0, similarity))

        return SimilarityResult(
            attack_type=name,
            similarity=similarity,
            cosine=cosine,
            euclidean=euclidean,
            range_hit_rate=range_hit,
            confidence=_confidence_band(similarity),
            matched_features=matched_feats,
        )


def _confidence_band(score: float) -> str:
    if score >= 0.90:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"
