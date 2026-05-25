"""
AI alert formatting + delivery.

Producing an alert is split from *delivering* it on purpose: the format
is the spec deliverable, and delivery just calls the project's existing
`alerting.log_threat()` so the row shows up in `threat_log.csv` and the
dashboard without changing the dashboard schema.

Threat-type strings start with "AI: " so legacy rows are unaffected and
operators can filter the new ones in the UI.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional

# Project-root alerting module (the existing one).
try:
    import alerting as project_alerting        # type: ignore[import-not-found]
except Exception:                              # pragma: no cover
    project_alerting = None                    # type: ignore[assignment]


_log = logging.getLogger("ai_detection.alerting")


def build_alert(
    source_ip: str,
    destination_ip: Optional[str],
    suspected_attack: str,
    similarity_score: float,
    anomaly_score: float,
    threat_score: int,
    matched_features: List[str],
    raw_features: Optional[Dict[str, float]] = None,
    recommended_action: str = "investigate",
    severity: str = "medium",
) -> Dict[str, object]:
    """Return the canonical AI-alert dict (also handy for tests / external sinks)."""
    return {
        "timestamp":           datetime.now().isoformat(),
        "source_ip":           source_ip,
        "destination_ip":      destination_ip or "",
        "suspected_attack":    suspected_attack,
        "similarity_score":    round(float(similarity_score), 4),
        "anomaly_score":       round(float(anomaly_score),    4),
        "threat_score":        int(threat_score),
        "severity":            severity,
        "matched_features":    list(matched_features),
        "recommended_action":  recommended_action,
        "feature_snapshot":    {k: round(float(v), 4) for k, v in (raw_features or {}).items()},
    }


def deliver_alert(alert: Dict[str, object]) -> bool:
    """
    Write the AI alert to the same CSV the dashboard reads.

    Returns True if the alert was logged, False if the project's
    alerting module is unavailable (in which case we still print it so
    the operator sees it during dev).
    """
    threat_type = f"AI: {alert['suspected_attack']}"
    description = _build_description(alert)
    severity    = str(alert.get("severity", "medium"))
    score       = int(alert.get("threat_score", 0))
    src         = str(alert.get("source_ip", ""))

    if project_alerting is None:
        _log.warning("project alerting module unavailable -- emitting to stderr only")
        print(f"[AI-ALERT] {threat_type} src={src} score={score} -- {description}")
        return False

    try:
        project_alerting.log_threat(
            ip=src,
            direction="inbound",
            threat_type=threat_type,
            severity=severity,
            score=score,
            description=description,
        )
        _log.info("AI alert logged: %s src=%s score=%d", threat_type, src, score)
        return True
    except Exception as e:
        _log.error("Failed to deliver AI alert: %s", e)
        return False


def _build_description(alert: Dict[str, object]) -> str:
    """One-line description that fits the dashboard's column."""
    matched: List[str] = list(alert.get("matched_features") or [])   # type: ignore[arg-type]
    matched_part = "; ".join(matched[:4]) if matched else "no specific feature match"
    sim = float(alert.get("similarity_score", 0.0))
    anom = float(alert.get("anomaly_score", 0.0))
    return (
        f"AI similarity={sim:.2f} anomaly={anom:.2f} -- {matched_part}. "
        f"Action: {alert.get('recommended_action', 'investigate')}."
    )


def recommended_action(threat_score: int) -> str:
    if threat_score >= 85:
        return "isolate host and investigate immediately"
    if threat_score >= 70:
        return "investigate -- escalate to on-call"
    if threat_score >= 40:
        return "monitor closely"
    return "log only"
