"""
Train the AI anomaly model from a pcap of *known-good* traffic.

The IsolationForest model is bootstrapped automatically the first time
the IDS starts (via ai_detection.model_manager.train_synthetic_baseline)
so the AI engine is usable out of the box. This script lets the operator
replace that bootstrap model with one fitted on a real-world quiet
capture from their own environment -- a much higher-quality baseline.

Usage:
    python train_ai_baseline.py path/to/normal_traffic.pcap [more.pcap ...]

What it does:
    * Replays each pcap through the same FlowAggregator the runtime uses.
    * Forces a flush at the end so every IP contributes a feature vector.
    * Fits the IsolationForest on the resulting matrix.
    * Persists to ai_detection/models/isoforest.joblib (configurable
      via the AI_MODEL_PATH env var).
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import List

import numpy as np

import pyshark

from ai_detection import (
    AIDetectionEngine,        # noqa: F401  -- demonstrates import surface
    FeatureExtractor,
    FlowAggregator,
    ModelManager,
)


def _collect_vectors(pcap_paths: List[str]) -> np.ndarray:
    aggregator = FlowAggregator()
    extractor = FeatureExtractor()

    for path in pcap_paths:
        print(f"[*] Replaying {path}")
        asyncio.set_event_loop(asyncio.new_event_loop())
        cap = pyshark.FileCapture(path, keep_packets=False)
        count = 0
        for pkt in cap:
            try:
                src = pkt.ip.src
                dst = pkt.ip.dst
            except AttributeError:
                continue
            try:
                ts = float(pkt.sniff_timestamp)
            except (AttributeError, ValueError):
                ts = time.time()

            size = 0
            for attr in ("length", "captured_length"):
                raw = getattr(pkt, attr, None)
                if raw is not None:
                    try:
                        size = int(raw)
                        break
                    except (TypeError, ValueError):
                        pass

            dst_port, is_syn, tcp_flags = None, False, None
            layer = getattr(pkt, "transport_layer", None)
            protocol = (layer or getattr(pkt, "highest_layer", "") or "").upper() or None
            if layer:
                sub = getattr(pkt, layer.lower(), None)
                if sub is not None:
                    try:
                        dst_port = int(sub.dstport)
                    except (AttributeError, ValueError):
                        dst_port = None
                    if layer == "TCP":
                        try:
                            tcp_flags = int(str(sub.flags), 16)
                            is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
                        except (AttributeError, ValueError):
                            tcp_flags = None
            aggregator.observe(
                src_ip=src, dst_ip=dst, dst_port=dst_port,
                protocol=protocol, is_syn=is_syn, tcp_flags=tcp_flags,
                packet_size=size, ts=ts, bad_ip_match=False,
            )
            count += 1
        cap.close()
        print(f"    {count} packets ingested.")

    snapshots = aggregator.force_flush_all()
    print(f"[*] Aggregated {len(snapshots)} per-IP flow snapshots.")
    vectors = []
    for _ip, state in snapshots:
        _raw, _vec, norm = extractor.extract(state)
        vectors.append(norm)
    if not vectors:
        raise SystemExit("No flow vectors extracted -- supply more traffic.")
    return np.vstack(vectors)


def main() -> None:
    paths = sys.argv[1:]
    if not paths:
        print(__doc__)
        sys.exit(2)

    X = _collect_vectors(paths)
    print(f"[*] Training IsolationForest on {X.shape[0]} samples "
          f"({X.shape[1]} features)")
    manager = ModelManager()
    manager.train_from_vectors(X, persist=True)
    print(f"[+] Model saved to: {manager._path}")


if __name__ == "__main__":
    main()
