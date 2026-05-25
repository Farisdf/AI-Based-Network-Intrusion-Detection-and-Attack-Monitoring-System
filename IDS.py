"""
Packet capture and analysis.

Two capture sources, both fed through the same analysis path:

  * _read_pcap(interface, IoCs) - live capture from a network adapter
  * _read_file(pcap_path, IoCs) - replay a saved .pcap / .pcapng file

Each packet is checked three ways:
  1. IP reputation    - is the source/destination IP on the blocklist? (Check_IP)
  2. Behavior         - does the source IP look like a scan / DoS / brute force?
                        (detectors.BehaviorEngine)
  3. AI behavioural   - does the flow's behaviour-DNA match a known attack
                        profile, or look anomalous vs the normal baseline?
                        (ai_detection.AIDetectionEngine -- sidecar, optional)

The AI layer is additive: it never replaces or suppresses the existing
checks. If `ai_detection` (or its dependencies) is unavailable, the IDS
runs exactly as before.
"""

import asyncio
import time

import pyshark
from pyshark.capture.capture import TSharkCrashException

import Check_IP as check_ip
from alerting import alert, alert_behavior
from detectors import BehaviorEngine

# ---- Optional AI sidecar -------------------------------------------------
# Imported lazily so a missing scikit-learn / numpy install does not break
# the core IDS. The AI engine is started inside _read_pcap / _read_file.
try:
    from ai_detection import AIDetectionEngine
    _AI_AVAILABLE = True
except Exception as _ai_err:                       # pragma: no cover
    AIDetectionEngine = None                       # type: ignore[assignment]
    _AI_AVAILABLE = False
    _AI_IMPORT_ERROR = _ai_err
else:
    _AI_IMPORT_ERROR = None


def _extract(packet):
    """
    Pull the fields the analyzers need from a packet.

    Returns a dict with keys:
        src_ip, dst_ip, dst_port, is_syn, ts,
        packet_size, protocol, tcp_flags
    or None if the packet has no IP layer.
    """
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
    except AttributeError:
        return None

    try:
        ts = float(packet.sniff_timestamp)
    except (AttributeError, ValueError):
        ts = time.time()

    # Packet size: pyshark exposes either `length` or `captured_length`.
    packet_size = 0
    for attr in ("length", "captured_length"):
        raw = getattr(packet, attr, None)
        if raw is not None:
            try:
                packet_size = int(raw)
                break
            except (TypeError, ValueError):
                continue

    dst_port, is_syn, tcp_flags = None, False, None
    layer = getattr(packet, "transport_layer", None)   # 'TCP', 'UDP', or None
    protocol = (layer or getattr(packet, "highest_layer", "") or "").upper() or None

    if layer:
        sub = getattr(packet, layer.lower(), None)
        if sub is not None:
            try:
                dst_port = int(sub.dstport)
            except (AttributeError, ValueError):
                dst_port = None
            if layer == "TCP":
                try:
                    tcp_flags = int(str(sub.flags), 16)
                    # SYN set and ACK clear == a new connection attempt.
                    is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
                except (AttributeError, ValueError):
                    tcp_flags = None
                    is_syn = False

    return {
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "dst_port":    dst_port,
        "is_syn":      is_syn,
        "ts":          ts,
        "packet_size": packet_size,
        "protocol":    protocol,
        "tcp_flags":   tcp_flags,
    }


def _process_packet(packet, engine, IoCs, source="", ai_engine=None):
    """Run IP-reputation, behavioural and AI checks on a single packet."""
    fields = _extract(packet)
    if fields is None:
        return                                  # no IP layer (e.g. ARP)

    src_ip      = fields["src_ip"]
    dst_ip      = fields["dst_ip"]
    dst_port    = fields["dst_port"]
    is_syn      = fields["is_syn"]
    ts          = fields["ts"]
    packet_size = fields["packet_size"]
    protocol    = fields["protocol"]
    tcp_flags   = fields["tcp_flags"]

    # ---- 1. IP reputation (blocklist) ----
    bad_ip_match = False
    if IoCs == 1:
        src_score = check_ip.check_IP_offline(src_ip)
        if src_score:
            bad_ip_match = True
            if alert(src_ip, "inbound", src_score, interface=source):
                print(f"[ALERT] Inbound from malicious IP {src_ip} (score {src_score})")

        dst_score = check_ip.check_IP_offline(dst_ip)
        if dst_score:
            bad_ip_match = True
            if alert(dst_ip, "outbound", dst_score, interface=source):
                print(f"[ALERT] Outbound to malicious IP {dst_ip} (score {dst_score})")

    # ---- 2. Behavioural detection (scan / DoS / brute force) ----
    hits = engine.inspect(src_ip, dst_port, is_syn, now=ts)
    for hit in hits:
        if alert_behavior(src_ip, hit["type"], hit["severity"], hit["score"], hit["detail"]):
            print(f"[ALERT] {hit['type']} from {src_ip} - {hit['detail']}")

    # ---- 3. AI behavioural sidecar (additive, never blocks capture) ----
    if ai_engine is not None and ai_engine.is_enabled():
        try:
            ai_engine.observe_packet(
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
            if hits:
                # Let the AI engine factor legacy detector hits into the
                # blended threat score for this flow window.
                ai_engine.note_behavioral_hits(src_ip, hits)
        except Exception as e:
            # Capture must never crash because of the AI sidecar.
            print(f"[WARN] AI engine ignored packet: {e}")


def _make_ai_engine():
    """Construct and start the AI engine (or return None if disabled / unavailable)."""
    if not _AI_AVAILABLE:
        print(f"[*] AI detection unavailable -- continuing with legacy IDS only "
              f"({_AI_IMPORT_ERROR})")
        return None
    try:
        engine = AIDetectionEngine()
        if not engine.is_enabled():
            print("[*] AI detection disabled via configuration.")
            return engine          # observe_packet() will short-circuit safely
        engine.start()
        return engine
    except Exception as e:
        print(f"[WARN] Failed to start AI engine: {e}")
        return None


def _read_pcap(interface, IoCs):
    """Live packet capture from a network interface."""
    asyncio.set_event_loop(asyncio.new_event_loop())
    engine = BehaviorEngine()
    ai_engine = _make_ai_engine()
    capture = pyshark.LiveCapture(interface=interface)
    print(f"[*] Starting packet sniffing on {interface}. Press Ctrl+C to stop.")

    try:
        for packet in capture.sniff_continuously():
            _process_packet(packet, engine, IoCs, source=interface, ai_engine=ai_engine)
    except KeyboardInterrupt:
        print("\n[*] Packet capture stopped by user.")
    except TSharkCrashException as e:
        print(f"[ERROR] TShark crashed unexpectedly: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        if ai_engine is not None:
            try:
                ai_engine.stop()
            except Exception as e:
                print(f"[WARN] AI engine shutdown error: {e}")


def _read_file(pcap_path, IoCs):
    """Replay a saved capture file (.pcap / .pcapng) through the analyzers."""
    asyncio.set_event_loop(asyncio.new_event_loop())
    engine = BehaviorEngine()
    ai_engine = _make_ai_engine()
    print(f"[*] Replaying capture file: {pcap_path}")

    try:
        capture = pyshark.FileCapture(pcap_path, keep_packets=False)
        count = 0
        for packet in capture:
            _process_packet(packet, engine, IoCs, source=pcap_path, ai_engine=ai_engine)
            count += 1
        capture.close()
        print(f"[*] Finished replaying {count} packets from {pcap_path}.")
    except FileNotFoundError:
        print(f"[ERROR] Capture file not found: {pcap_path}")
    except TSharkCrashException as e:
        print(f"[ERROR] TShark crashed unexpectedly: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        if ai_engine is not None:
            try:
                ai_engine.stop()
                if ai_engine.is_enabled():
                    s = ai_engine.stats()
                    print(f"[*] AI engine summary: "
                          f"flushes={s['flushes']} alerts={s['alerts_emitted']} "
                          f"tracked_ips={s['tracked_ips']}")
            except Exception as e:
                print(f"[WARN] AI engine shutdown error: {e}")
