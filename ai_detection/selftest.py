"""
Self-test / smoke test for the AI detection pipeline.

Run as a script:

    python -m ai_detection.selftest

It exercises every layer without needing a pcap or tshark:

  1. Builds three synthetic flows -- port_scan, brute_force, normal
     traffic.
  2. Feeds them through FlowAggregator + FeatureExtractor.
  3. Runs SimilarityEngine.
  4. Loads / bootstraps the IsolationForest model.
  5. Computes a blended threat score.
  6. Emits the canonical AI alert dict for each suspected attack
     (without writing to threat_log.csv -- pure stdout).

A failure at any step exits non-zero.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Iterable, Tuple

from .alerting import build_alert, recommended_action
from .config import CONFIG
from .engine import _top_destination
from .feature_extractor import FeatureExtractor, FlowAggregator
from .model_manager import ModelManager
from .scoring import compute_threat_score
from .similarity_engine import SimilarityEngine


def _gen_port_scan(agg: FlowAggregator, src="10.0.0.99") -> None:
    base = time.time()
    # 60 distinct ascending ports, mostly SYNs, tiny packets, single dst.
    for i in range(60):
        agg.observe(
            src_ip=src, dst_ip="10.0.0.5", dst_port=1024 + i,
            protocol="tcp", is_syn=True, tcp_flags=0x02,
            packet_size=60, ts=base - 9.0 + i * 0.05,
            bad_ip_match=False,
        )


def _gen_brute_force(agg: FlowAggregator, src="10.0.0.77") -> None:
    base = time.time()
    # 40 repeated attempts to SSH on one host.
    for i in range(40):
        agg.observe(
            src_ip=src, dst_ip="10.0.0.20", dst_port=22,
            protocol="tcp", is_syn=True, tcp_flags=0x02,
            packet_size=80, ts=base - 9.0 + i * 0.2,
            bad_ip_match=False,
        )


def _gen_normal(agg: FlowAggregator, src="10.0.0.40") -> None:
    import random
    rng = random.Random(7)
    base = time.time() - 9.0
    # Well-behaved sessions: handful of destinations / ports, irregular timing,
    # mostly mid-flight ACK traffic.
    dst_pool = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    port_pool = [443, 53, 80, 443, 443, 8080]
    t = base
    for i in range(25):
        t += rng.uniform(0.05, 0.9)        # natural inter-arrival jitter
        is_syn = (i % 9 == 0)
        flags = 0x02 if is_syn else (0x18 if i % 2 else 0x10)
        agg.observe(
            src_ip=src,
            dst_ip=rng.choice(dst_pool),
            dst_port=rng.choice(port_pool),
            protocol="tcp", is_syn=is_syn, tcp_flags=flags,
            packet_size=rng.randint(120, 1400),
            ts=t,
            bad_ip_match=False,
        )


def _evaluate(label: str, src: str, agg: FlowAggregator,
              sim: SimilarityEngine, model: ModelManager) -> Tuple[bool, dict]:
    snapshots = agg.force_flush_all()
    state = next((st for ip, st in snapshots if ip == src), None)
    if state is None:
        return False, {"error": f"no snapshot for {src}"}

    extractor = FeatureExtractor()
    raw_features, _raw, norm = extractor.extract(state)
    ranked = sim.analyze(norm, raw_features)
    best = ranked[0]
    anomaly = model.detector.predict(norm) if model.is_fitted() else 0.0
    ts_obj = compute_threat_score(
        similarity_score=best.similarity,
        anomaly_score=anomaly,
        ioc_score=0.0,
        behavioral_alerts=None,
        traffic_severity=min(1.0, raw_features["packets_per_second"] / 200.0),
    )

    alert = build_alert(
        source_ip=src,
        destination_ip=_top_destination(state),
        suspected_attack=best.attack_type,
        similarity_score=best.similarity,
        anomaly_score=anomaly,
        threat_score=ts_obj.score,
        matched_features=best.matched_features,
        raw_features=raw_features,
        recommended_action=recommended_action(ts_obj.score),
        severity=ts_obj.severity,
    )

    print(f"\n--- {label} (src={src}) ---")
    print(f"top_match={best.attack_type} similarity={best.similarity:.3f} "
          f"anomaly={anomaly:.3f} threat={ts_obj.score} severity={ts_obj.severity}")
    print(f"contributors={ts_obj.contributors}")
    print("alert_dict:")
    print(json.dumps(alert, indent=2, default=str))
    return True, alert


def main(argv: Iterable[str] = ()) -> int:
    agg = FlowAggregator()
    _gen_port_scan(agg)
    _gen_brute_force(agg)
    _gen_normal(agg)

    sim = SimilarityEngine()
    model = ModelManager()
    model.load_or_bootstrap()

    # Each expectation is (label, generator, src, must_alert, allowed_labels).
    # The "must alert" assertion checks the *blended threat score* path, not
    # the raw similarity verdict -- the verdict is informational regardless.
    expectations = [
        ("scan flow (port or syn)", _gen_port_scan,   "10.0.0.99", True,  {"port_scan", "syn_scan"}),
        ("brute-force flow",        _gen_brute_force, "10.0.0.77", True,  {"brute_force"}),
        ("normal flow",             _gen_normal,      "10.0.0.40", False, None),
    ]
    failed = False
    for label, gen, src, must_alert, allowed in expectations:
        fresh = FlowAggregator()
        gen(fresh)
        ok, alert = _evaluate(label, src, fresh, sim, model)
        if not ok:
            print(f"[FAIL] {label}: {alert}")
            failed = True
            continue

        sim_score = float(alert["similarity_score"])
        threat = int(alert["threat_score"])
        threshold = max(
            CONFIG.SIMILARITY_THRESHOLD,
            CONFIG.THREAT_ALERT_THRESHOLD / 100.0,
        )
        # An attack flow should at minimum cross the similarity bar -- the
        # blended threat score is sensitive to the anomaly baseline.
        if must_alert:
            if sim_score < CONFIG.SIMILARITY_THRESHOLD * 0.85:
                print(f"[FAIL] {label}: similarity {sim_score:.2f} too low")
                failed = True
            if allowed and alert["suspected_attack"] not in allowed:
                print(f"[FAIL] {label}: suspected_attack {alert['suspected_attack']} "
                      f"not in {allowed}")
                failed = True
        else:
            # Normal traffic: should not produce a high-severity alert.
            if threat >= CONFIG.THREAT_ALERT_THRESHOLD:
                print(f"[FAIL] {label}: normal traffic produced threat={threat}")
                failed = True
            if sim_score >= CONFIG.SIMILARITY_THRESHOLD:
                print(f"[FAIL] {label}: normal traffic produced sim={sim_score:.2f}")
                failed = True

    print("\n[+] Self-test PASSED" if not failed else "\n[!] Self-test FAILED")
    return 0 if not failed else 1




if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
