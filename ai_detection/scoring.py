"""
Combined threat-score computation.

Blends:

  * similarity_score   - best cosine/range match against attack profiles
  * anomaly_score      - IsolationForest deviation from normal baseline
  * ioc_score          - IPsum reputation (0..10+, normalised)
  * behavioral_alerts  - count/severity of legacy detector hits in this window
  * traffic_severity   - quick "loud traffic" booster (high pps/bps)

Output is an int 0..100 plus a severity band that matches the existing
dashboard's risk tiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


# Weight contributions sum to 100 at maximum. The constants below let us
# tune which signal dominates the final score without changing the
# scoring formula.
_W_SIMILARITY    = 45
_W_ANOMALY       = 25
_W_IOC           = 15
_W_BEHAVIORAL    = 10
_W_TRAFFIC       =  5


@dataclass
class ThreatScore:
    score: int                 # 0..100
    severity: str              # low / medium / high / critical
    contributors: Dict[str, int]   # per-signal contribution (for explainability)

    def to_dict(self) -> Dict[str, object]:
        return {
            "score":        int(self.score),
            "severity":     self.severity,
            "contributors": dict(self.contributors),
        }


def severity_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def compute_threat_score(
    similarity_score: float,
    anomaly_score: float,
    ioc_score: float = 0.0,
    behavioral_alerts: Optional[List[Dict[str, object]]] = None,
    traffic_severity: float = 0.0,
) -> ThreatScore:
    """
    Combine signals into a single 0..100 threat score.

    Each input is in its native units:

      similarity_score  -- 0..1
      anomaly_score     -- 0..1
      ioc_score         -- raw IPsum score (caps at 10)
      behavioral_alerts -- list of dicts from BehaviorEngine.inspect()
      traffic_severity  -- 0..1, e.g. min(1, packets_per_second / 200)
    """
    similarity_score = _clip01(similarity_score)
    anomaly_score    = _clip01(anomaly_score)
    traffic_severity = _clip01(traffic_severity)

    sim_part     = int(round(similarity_score * _W_SIMILARITY))
    anom_part    = int(round(anomaly_score    * _W_ANOMALY))
    ioc_part     = int(round(min(1.0, ioc_score / 10.0) * _W_IOC))
    traffic_part = int(round(traffic_severity * _W_TRAFFIC))

    behav_part = 0
    if behavioral_alerts:
        # Cap at full weight; each legacy hit contributes proportionally to
        # its severity label.
        sev_map = {"low": 0.4, "medium": 0.7, "high": 1.0, "critical": 1.0}
        intensity = 0.0
        for hit in behavioral_alerts:
            sev = str(hit.get("severity", "medium")).lower()
            intensity += sev_map.get(sev, 0.5)
        behav_part = int(round(min(1.0, intensity) * _W_BEHAVIORAL))

    total = sim_part + anom_part + ioc_part + behav_part + traffic_part
    total = max(0, min(100, total))

    return ThreatScore(
        score=total,
        severity=severity_band(total),
        contributors={
            "similarity":  sim_part,
            "anomaly":     anom_part,
            "ioc":         ioc_part,
            "behavioral":  behav_part,
            "traffic":     traffic_part,
        },
    )


def _clip01(x: float) -> float:
    if x != x:        # NaN guard
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)
