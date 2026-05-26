"""
Attack fingerprint profiles.

Each profile is a target behaviour-DNA shape that real attacks produce.
Profiles are deliberately data-only -- the similarity engine is the
single place that knows how to compare an observed vector against them.

Each profile contains:

    features  - expected raw-feature ranges (lo, hi). The midpoint is the
                "ideal" value of that feature for this attack type.
    weights   - per-feature importance, higher = features that *must* match
                for the profile to fire. Features not listed default to 0.5.
    rationale - short human-readable string used in alert "matched_features".
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np

from .feature_extractor import (
    FEATURE_NAMES,
    FEATURE_RANGES,
    normalize_vector,
    vector_from_features,
)


AttackProfile = Dict[str, object]


_RAW_PROFILES: Dict[str, Dict[str, object]] = {
    # nmap-style horizontal scan: many distinct ports, lots of SYNs.
    "port_scan": {
        "features": {
            "packets_per_second":      (20.0, 150.0),
            "syn_ratio":               (0.7,  1.0),
            "ack_ratio":               (0.0,  0.2),
            "unique_ports_contacted":  (30.0, 200.0),
            "sequential_port_pattern": (0.4,  1.0),
            "failed_connection_ratio": (0.5,  1.0),
            "avg_packet_size":         (40.0, 120.0),
            "repeated_target_frequency": (0.6, 1.0),
            "destination_entropy":     (0.0,  1.0),
            "abnormal_port_access":    (5.0,  100.0),
        },
        "weights": {
            "syn_ratio":               1.0,
            "unique_ports_contacted":  1.0,
            "sequential_port_pattern": 0.8,
            "failed_connection_ratio": 0.8,
            "ack_ratio":               0.6,
            "repeated_target_frequency": 0.4,
        },
        "rationale": {
            "syn_ratio":               "high SYN ratio",
            "unique_ports_contacted":  "many distinct destination ports",
            "sequential_port_pattern": "sequential port access",
            "failed_connection_ratio": "many half-open connections",
        },
    },

    # SYN-only scan: even purer than port_scan, lower volume.
    "syn_scan": {
        "features": {
            "packets_per_second":      (10.0, 100.0),
            "syn_ratio":               (0.85, 1.0),
            "ack_ratio":               (0.0,  0.05),
            "rst_ratio":               (0.0,  0.5),
            "unique_ports_contacted":  (10.0, 150.0),
            "failed_connection_ratio": (0.7,  1.0),
            "avg_packet_size":         (40.0, 80.0),
        },
        "weights": {
            "syn_ratio":               1.0,
            "ack_ratio":               1.0,
            "failed_connection_ratio": 0.9,
            "unique_ports_contacted":  0.7,
        },
        "rationale": {
            "syn_ratio":               "near-100% SYN ratio (no follow-up)",
            "ack_ratio":               "no ACKs returned",
            "failed_connection_ratio": "half-open scan signature",
        },
    },

    # Hydra/medusa-style auth pounding: high rate but only one dst:port.
    "brute_force": {
        "features": {
            "packets_per_second":      (5.0,   60.0),
            "syn_ratio":               (0.4,   0.9),
            "unique_ports_contacted":  (1.0,   3.0),
            "unique_destinations":     (1.0,   3.0),
            "repeated_target_frequency": (0.8, 1.0),
            "retry_frequency":         (5.0,   50.0),
            "destination_entropy":     (0.0,   0.5),
            "request_interval_variance": (0.0, 0.4),
            "abnormal_port_access":    (0.0,   1.0),
        },
        "weights": {
            "retry_frequency":            1.0,
            "repeated_target_frequency":  1.0,
            "unique_ports_contacted":     0.9,
            "destination_entropy":        0.6,
            "syn_ratio":                  0.6,
        },
        "rationale": {
            "retry_frequency":            "repeated attempts to one service",
            "unique_ports_contacted":     "traffic concentrated on a single port",
            "repeated_target_frequency":  "single target dominates traffic",
        },
    },

    # Volumetric flood from a single source.
    "ddos": {
        "features": {
            "packets_per_second":      (80.0,  200.0),
            "bytes_per_second":        (200_000.0, 2_000_000.0),
            "syn_ratio":               (0.4,   1.0),
            "request_interval_variance": (0.0, 0.05),
            "total_packets":           (500.0, 2000.0),
            "unique_destinations":     (1.0,   5.0),
            "avg_packet_size":         (40.0,  500.0),
            "suspicious_timing_pattern": (0.5,  1.0),
        },
        "weights": {
            "packets_per_second":      1.0,
            "total_packets":           1.0,
            "bytes_per_second":        0.8,
            "syn_ratio":               0.6,
            "suspicious_timing_pattern": 0.4,
        },
        "rationale": {
            "packets_per_second":      "very high packet rate",
            "total_packets":           "sustained packet flood",
            "bytes_per_second":        "high bandwidth consumption",
        },
    },

    # ARP cache poisoning: non-IP protocol, high repetition, low payload.
    "arp_spoof": {
        "features": {
            "unusual_protocol_usage":  (1.0, 1.0),
            "avg_packet_size":         (40.0, 80.0),
            "packets_per_second":      (1.0, 30.0),
            "syn_ratio":               (0.0, 0.05),
            "ack_ratio":               (0.0, 0.05),
            "protocol_entropy":        (0.0, 0.3),
        },
        "weights": {
            "unusual_protocol_usage": 1.0,
            "protocol_entropy":       0.7,
            "avg_packet_size":        0.5,
        },
        "rationale": {
            "unusual_protocol_usage": "non-IP / ARP-heavy traffic",
            "protocol_entropy":       "single non-standard protocol",
        },
    },

    # DNS-tunnel exfiltration: heavy UDP/53, large per-query bytes.
    "dns_tunneling": {
        "features": {
            "avg_packet_size":         (180.0, 1500.0),
            "packets_per_second":      (5.0,   80.0),
            "unique_ports_contacted":  (1.0,   3.0),
            "repeated_target_frequency": (0.7, 1.0),
            "protocol_entropy":        (0.0,   0.5),
            "bytes_per_second":        (5_000.0, 500_000.0),
        },
        "weights": {
            "avg_packet_size":            1.0,
            "repeated_target_frequency":  0.8,
            "unique_ports_contacted":     0.7,
            "bytes_per_second":           0.6,
        },
        "rationale": {
            "avg_packet_size":            "abnormally large DNS-style payloads",
            "repeated_target_frequency":  "all traffic to one resolver",
            "unique_ports_contacted":     "single destination port",
        },
    },

    # C2 beaconing: low rate, very regular intervals, one destination.
    "beaconing": {
        "features": {
            "packets_per_second":         (0.1, 5.0),
            "request_interval_variance":  (0.0, 0.05),
            "suspicious_timing_pattern":  (0.6, 1.0),
            "unique_destinations":        (1.0, 2.0),
            "repeated_target_frequency":  (0.9, 1.0),
            "avg_packet_size":            (60.0, 400.0),
        },
        "weights": {
            "suspicious_timing_pattern":  1.0,
            "request_interval_variance":  0.9,
            "repeated_target_frequency":  0.8,
            "unique_destinations":        0.7,
        },
        "rationale": {
            "suspicious_timing_pattern":  "near-periodic timing (beacon)",
            "request_interval_variance":  "very low inter-arrival jitter",
            "repeated_target_frequency":  "fixed C2 destination",
        },
    },

    # Internal east-west traversal: many internal destinations, modest rate.
    "lateral_movement": {
        "features": {
            "unique_destinations":     (8.0,   60.0),
            "destination_entropy":     (2.5,   6.0),
            "inbound_outbound_ratio":  (0.6,   1.0),
            "packets_per_second":      (2.0,   40.0),
            "syn_ratio":               (0.3,   0.9),
            "unique_ports_contacted":  (1.0,   10.0),
        },
        "weights": {
            "unique_destinations":     1.0,
            "destination_entropy":     0.9,
            "inbound_outbound_ratio":  0.6,
            "syn_ratio":               0.5,
        },
        "rationale": {
            "unique_destinations":     "many internal targets contacted",
            "destination_entropy":     "spread across many hosts",
            "inbound_outbound_ratio":  "traffic stays inside the LAN",
        },
    },
}


def _build(profile: Dict[str, object]) -> AttackProfile:
    """Compute the ideal vector + weight vector for one profile."""
    feat_ranges: Dict[str, Tuple[float, float]] = profile["features"]  # type: ignore[assignment]
    weights_dict: Dict[str, float] = profile["weights"]                # type: ignore[assignment]

    ideal: Dict[str, float] = {}
    for name in FEATURE_NAMES:
        if name in feat_ranges:
            lo, hi = feat_ranges[name]
            ideal[name] = (lo + hi) / 2.0
        else:
            # neutral midpoint of the feature's normalisation range
            lo, hi = FEATURE_RANGES[name]
            ideal[name] = (lo + hi) / 2.0

    raw_vec = vector_from_features(ideal)
    norm_vec = normalize_vector(raw_vec)

    weights = np.asarray(
        [weights_dict.get(n, 0.1) for n in FEATURE_NAMES],
        dtype=np.float64,
    )

    return {
        "vector":        norm_vec,
        "weights":       weights,
        "raw_features":  ideal,
        "feature_ranges": feat_ranges,
        "rationale":     profile.get("rationale", {}),
    }


# Compiled once at import-time so the lookup is O(1) at runtime.
ATTACK_PROFILES: Dict[str, AttackProfile] = {
    name: _build(spec) for name, spec in _RAW_PROFILES.items()
}


def list_profiles() -> List[str]:
    return list(ATTACK_PROFILES.keys())


def get_profile(name: str) -> AttackProfile:
    return ATTACK_PROFILES[name]
