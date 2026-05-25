"""
Feature extraction.

Converts the stream of per-packet observations the IDS already produces
into compact "behaviour DNA" vectors -- one vector per source IP per
flush window.

Two pieces:

* FlowAggregator -- thread-safe accumulator. The IDS calls observe() for
  every packet; the aggregator buckets state per source IP.

* FeatureExtractor -- consumes an aggregator snapshot for one source IP
  and produces (feature_dict, numerical_vector) tuples ready for
  similarity / anomaly scoring.

The feature vector is fixed-length and in a fixed order (FEATURE_NAMES);
all downstream components rely on that contract.
"""

from __future__ import annotations

import math
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

import numpy as np

from .config import CONFIG


# ---------------------------------------------------------------------------
# Feature contract
# ---------------------------------------------------------------------------

FEATURE_NAMES: Tuple[str, ...] = (
    "packets_per_second",
    "bytes_per_second",
    "avg_packet_size",
    "packet_size_variance",
    "session_duration",
    "inbound_outbound_ratio",
    "syn_ratio",
    "rst_ratio",
    "fin_ratio",
    "ack_ratio",
    "unique_ports_contacted",
    "sequential_port_pattern",
    "failed_connection_ratio",
    "connection_rate",
    "retry_frequency",
    "request_interval_variance",
    "destination_entropy",
    "protocol_entropy",
    "repeated_target_frequency",
    "known_bad_ip_match",
    "unusual_protocol_usage",
    "abnormal_port_access",
    "suspicious_timing_pattern",
    "total_packets",
    "total_bytes",
    "unique_destinations",
)

# Empirical normalisation ranges. Anything outside the range is clipped --
# the vector that hits an attack profile should saturate, not blow up the
# downstream distance metric.
FEATURE_RANGES: Dict[str, Tuple[float, float]] = {
    "packets_per_second":        (0.0, 200.0),
    "bytes_per_second":          (0.0, 2_000_000.0),
    "avg_packet_size":           (0.0, 1500.0),
    "packet_size_variance":      (0.0, 250_000.0),
    "session_duration":          (0.0, 60.0),
    "inbound_outbound_ratio":    (0.0, 1.0),
    "syn_ratio":                 (0.0, 1.0),
    "rst_ratio":                 (0.0, 1.0),
    "fin_ratio":                 (0.0, 1.0),
    "ack_ratio":                 (0.0, 1.0),
    "unique_ports_contacted":    (0.0, 200.0),
    "sequential_port_pattern":   (0.0, 1.0),
    "failed_connection_ratio":   (0.0, 1.0),
    "connection_rate":           (0.0, 100.0),
    "retry_frequency":           (0.0, 50.0),
    "request_interval_variance": (0.0, 5.0),
    "destination_entropy":       (0.0, 6.0),
    "protocol_entropy":          (0.0, 2.0),
    "repeated_target_frequency": (0.0, 1.0),
    "known_bad_ip_match":        (0.0, 1.0),
    "unusual_protocol_usage":    (0.0, 1.0),
    "abnormal_port_access":      (0.0, 100.0),
    "suspicious_timing_pattern": (0.0, 1.0),
    "total_packets":             (0.0, 2000.0),
    "total_bytes":               (0.0, 20_000_000.0),
    "unique_destinations":       (0.0, 200.0),
}


def normalize_vector(vec: np.ndarray) -> np.ndarray:
    """Scale a raw feature vector to the unit range using FEATURE_RANGES."""
    out = np.empty_like(vec, dtype=np.float64)
    for i, name in enumerate(FEATURE_NAMES):
        lo, hi = FEATURE_RANGES[name]
        span = hi - lo if hi > lo else 1.0
        x = (float(vec[i]) - lo) / span
        out[i] = max(0.0, min(1.0, x))
    return out


def vector_from_features(features: Dict[str, float]) -> np.ndarray:
    """Project a feature dict to the canonical FEATURE_NAMES order."""
    return np.asarray([features.get(n, 0.0) for n in FEATURE_NAMES], dtype=np.float64)


# ---------------------------------------------------------------------------
# Per-source-IP flow state
# ---------------------------------------------------------------------------

@dataclass
class _FlowState:
    """Mutable rolling state for one source IP."""

    first_ts: float
    last_ts: float
    packets: int = 0
    bytes_total: int = 0
    packet_sizes: Deque[int] = field(default_factory=lambda: deque(maxlen=2048))
    timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=2048))
    inbound: int = 0  # we are observing from src perspective; outbound counter is below
    outbound: int = 0
    syn: int = 0
    rst: int = 0
    fin: int = 0
    ack: int = 0
    syn_no_followup: int = 0  # SYNs from src with zero subsequent traffic to same dest:port
    pending_syn_keys: set = field(default_factory=set)
    port_hits: Counter = field(default_factory=Counter)
    port_sequence: Deque[int] = field(default_factory=lambda: deque(maxlen=128))
    destinations: Counter = field(default_factory=Counter)
    protocols: Counter = field(default_factory=Counter)
    bad_ip_flag: int = 0
    last_flushed_ts: float = 0.0


class FlowAggregator:
    """Thread-safe per-source-IP rolling flow aggregator."""

    def __init__(self, window_seconds: float = CONFIG.FLOW_WINDOW_SECONDS,
                 max_ips: int = CONFIG.MAX_TRACKED_IPS):
        self._window = window_seconds
        self._max_ips = max_ips
        self._flows: Dict[str, _FlowState] = {}
        self._lock = threading.Lock()

    # -- API used by IDS -----------------------------------------------------

    def observe(
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
        """Record one packet under its source IP."""
        if not src_ip:
            return
        with self._lock:
            state = self._flows.get(src_ip)
            if state is None:
                if len(self._flows) >= self._max_ips:
                    # Evict the oldest flow to keep memory bounded.
                    victim = min(self._flows, key=lambda k: self._flows[k].last_ts)
                    del self._flows[victim]
                state = _FlowState(first_ts=ts, last_ts=ts)
                self._flows[src_ip] = state

            state.last_ts = ts
            state.packets += 1
            state.bytes_total += max(0, packet_size)
            state.packet_sizes.append(max(0, packet_size))
            state.timestamps.append(ts)
            if bad_ip_match:
                state.bad_ip_flag = 1

            if protocol:
                state.protocols[protocol.lower()] += 1

            if dst_ip:
                state.destinations[dst_ip] += 1
                # Heuristic direction: traffic from a private src to a public dst
                # is "outbound"; otherwise "inbound" relative to the local net.
                if _is_private(dst_ip):
                    state.inbound += 1
                else:
                    state.outbound += 1

            if dst_port is not None:
                state.port_hits[dst_port] += 1
                state.port_sequence.append(dst_port)

            if tcp_flags is not None:
                if tcp_flags & 0x02:
                    state.syn += 1
                    if dst_ip is not None and dst_port is not None:
                        state.pending_syn_keys.add((dst_ip, dst_port))
                if tcp_flags & 0x04:
                    state.rst += 1
                if tcp_flags & 0x01:
                    state.fin += 1
                if tcp_flags & 0x10:
                    state.ack += 1
                    # ACK / SYN-ACK seen -> the SYN got a follow-up.
                    if dst_ip is not None and dst_port is not None:
                        state.pending_syn_keys.discard((dst_ip, dst_port))

            elif is_syn:
                state.syn += 1

    # -- Snapshot / flush ----------------------------------------------------

    def drain_ready(self, now: Optional[float] = None) -> List[Tuple[str, _FlowState]]:
        """
        Return (src_ip, snapshot) pairs whose flow window has elapsed and that
        have enough packets to score. The drained state is reset in place so
        the next window starts cleanly.
        """
        if now is None:
            now = time.time()
        ready: List[Tuple[str, _FlowState]] = []
        with self._lock:
            for ip, state in list(self._flows.items()):
                age = now - state.first_ts
                if age < self._window:
                    continue
                if state.packets < CONFIG.MIN_PACKETS_FOR_ANALYSIS:
                    # not enough signal - reset the window and move on
                    self._flows[ip] = _FlowState(first_ts=now, last_ts=now)
                    continue
                # Hand back a frozen snapshot, then start a fresh window.
                ready.append((ip, state))
                self._flows[ip] = _FlowState(first_ts=now, last_ts=now)
        return ready

    def force_flush_all(self, now: Optional[float] = None) -> List[Tuple[str, _FlowState]]:
        """Drain every tracked IP regardless of window age. Used at shutdown."""
        if now is None:
            now = time.time()
        with self._lock:
            out = [(ip, st) for ip, st in self._flows.items()
                   if st.packets >= CONFIG.MIN_PACKETS_FOR_ANALYSIS]
            self._flows.clear()
        return out

    def __len__(self) -> int:
        with self._lock:
            return len(self._flows)


# ---------------------------------------------------------------------------
# Feature extraction from a snapshot
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """Translates _FlowState snapshots into normalised feature vectors."""

    @staticmethod
    def extract(state: _FlowState) -> Tuple[Dict[str, float], np.ndarray, np.ndarray]:
        """
        Return (raw_features, raw_vector, normalised_vector).

        The raw dict is what we surface in alerts (human-readable);
        the normalised vector is what the similarity / anomaly engines
        consume.
        """
        duration = max(1e-3, state.last_ts - state.first_ts)
        total_pkts = max(1, state.packets)

        sizes = np.asarray(state.packet_sizes, dtype=np.float64) if state.packet_sizes else np.zeros(1)
        ts = np.asarray(state.timestamps, dtype=np.float64) if state.timestamps else np.zeros(1)
        intervals = np.diff(ts) if ts.size > 1 else np.asarray([0.0])

        # Direction ratio in [0,1]: 1.0 == purely inbound, 0.0 == purely outbound.
        dir_total = state.inbound + state.outbound
        inbound_outbound_ratio = (state.inbound / dir_total) if dir_total else 0.5

        # TCP flag ratios
        syn_ratio = state.syn / total_pkts
        rst_ratio = state.rst / total_pkts
        fin_ratio = state.fin / total_pkts
        ack_ratio = state.ack / total_pkts

        # Port-level signals
        unique_ports = len(state.port_hits)
        sequential = _sequential_port_score(state.port_sequence)
        abnormal_port_access = sum(1 for p in state.port_hits if p > 49152)

        # Failed connection ratio: SYNs without follow-up over total SYNs.
        failed_ratio = (len(state.pending_syn_keys) / state.syn) if state.syn else 0.0
        failed_ratio = min(1.0, failed_ratio)

        # Connection rate: distinct destinations per second.
        unique_dests = len(state.destinations)
        connection_rate = unique_dests / duration

        # Retry frequency: average hits per port that received >1 attempts.
        retried = [c for c in state.port_hits.values() if c > 1]
        retry_frequency = float(np.mean(retried)) if retried else 0.0

        # Interval variance and beaconing indicator.
        if intervals.size and float(np.mean(intervals)) > 0:
            iv = float(np.var(intervals))
            request_interval_variance = iv
            # Low variance + many packets -> beacon-like timing.
            beacon = math.exp(-iv * 8.0) if total_pkts >= 12 else 0.0
            suspicious_timing = min(1.0, beacon)
        else:
            request_interval_variance = 0.0
            suspicious_timing = 0.0

        # Destination & protocol entropy (Shannon, base 2).
        destination_entropy = _entropy(state.destinations)
        protocol_entropy = _entropy(state.protocols)

        # Repeated-target frequency: share of traffic landing on the single
        # most-contacted destination.
        if state.destinations:
            top_dest_share = max(state.destinations.values()) / total_pkts
        else:
            top_dest_share = 0.0
        repeated_target_frequency = float(top_dest_share)

        # Unusual protocol: anything not TCP/UDP/ICMP/ARP.
        unusual_protocol_usage = 0.0
        for proto, _ in state.protocols.items():
            if proto not in ("tcp", "udp", "icmp", "arp"):
                unusual_protocol_usage = 1.0
                break

        features: Dict[str, float] = {
            "packets_per_second":        total_pkts / duration,
            "bytes_per_second":          state.bytes_total / duration,
            "avg_packet_size":           float(np.mean(sizes)),
            "packet_size_variance":      float(np.var(sizes)),
            "session_duration":          duration,
            "inbound_outbound_ratio":    inbound_outbound_ratio,
            "syn_ratio":                 syn_ratio,
            "rst_ratio":                 rst_ratio,
            "fin_ratio":                 fin_ratio,
            "ack_ratio":                 ack_ratio,
            "unique_ports_contacted":    float(unique_ports),
            "sequential_port_pattern":   sequential,
            "failed_connection_ratio":   failed_ratio,
            "connection_rate":           connection_rate,
            "retry_frequency":           retry_frequency,
            "request_interval_variance": request_interval_variance,
            "destination_entropy":       destination_entropy,
            "protocol_entropy":          protocol_entropy,
            "repeated_target_frequency": repeated_target_frequency,
            "known_bad_ip_match":        float(state.bad_ip_flag),
            "unusual_protocol_usage":    unusual_protocol_usage,
            "abnormal_port_access":      float(abnormal_port_access),
            "suspicious_timing_pattern": suspicious_timing,
            "total_packets":             float(state.packets),
            "total_bytes":               float(state.bytes_total),
            "unique_destinations":       float(unique_dests),
        }

        raw_vec = vector_from_features(features)
        return features, raw_vec, normalize_vector(raw_vec)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for v in counter.values():
        p = v / total
        if p > 0:
            h -= p * math.log2(p)
    return h


def _sequential_port_score(ports: Deque[int]) -> float:
    """
    Fraction of port hits that immediately follow a port differing by 1.
    A clean nmap-style ascending scan saturates at 1.0; random traffic is ~0.
    """
    if len(ports) < 2:
        return 0.0
    n = 0
    for a, b in zip(list(ports)[:-1], list(ports)[1:]):
        if abs(b - a) == 1:
            n += 1
    return n / (len(ports) - 1)


def _is_private(ip: str) -> bool:
    """Quick RFC1918 / link-local / loopback check that avoids the ipaddress import."""
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return ip.startswith("169.254.") or ip == "::1"
