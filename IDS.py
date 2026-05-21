"""
Packet capture and analysis.

Two capture sources, both fed through the same analysis path:

  * _read_pcap(interface, IoCs) - live capture from a network adapter
  * _read_file(pcap_path, IoCs) - replay a saved .pcap / .pcapng file

Each packet is checked two ways:
  1. IP reputation  - is the source/destination IP on the blocklist? (Check_IP)
  2. Behavior       - does the source IP look like a scan / DoS / brute force?
                      (detectors.BehaviorEngine)
"""

import asyncio
import time
import pyshark
from pyshark.capture.capture import TSharkCrashException
import Check_IP as check_ip
from alerting import alert, alert_behavior
from detectors import BehaviorEngine


def _extract(packet):
    """
    Pull the fields the analyzers need from a packet.

    Returns (src_ip, dst_ip, dst_port, is_syn, timestamp) or None if the
    packet has no IP layer.
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

    dst_port, is_syn = None, False
    layer = getattr(packet, "transport_layer", None)   # 'TCP', 'UDP', or None
    if layer:
        sub = getattr(packet, layer.lower(), None)
        if sub is not None:
            try:
                dst_port = int(sub.dstport)
            except (AttributeError, ValueError):
                dst_port = None
            if layer == "TCP":
                try:
                    flags = int(str(sub.flags), 16)
                    # SYN set and ACK clear == a new connection attempt.
                    is_syn = bool(flags & 0x02) and not bool(flags & 0x10)
                except (AttributeError, ValueError):
                    is_syn = False

    return src_ip, dst_ip, dst_port, is_syn, ts


def _process_packet(packet, engine, IoCs, source=""):
    """Run IP-reputation and behavioral checks on a single packet."""
    fields = _extract(packet)
    if fields is None:
        return                       # no IP layer (e.g. ARP)
    src_ip, dst_ip, dst_port, is_syn, ts = fields

    # ---- 1. IP reputation (blocklist) ----
    if IoCs == 1:
        src_score = check_ip.check_IP_offline(src_ip)
        if src_score and alert(src_ip, "inbound", src_score, interface=source):
            print(f"[ALERT] Inbound from malicious IP {src_ip} (score {src_score})")

        dst_score = check_ip.check_IP_offline(dst_ip)
        if dst_score and alert(dst_ip, "outbound", dst_score, interface=source):
            print(f"[ALERT] Outbound to malicious IP {dst_ip} (score {dst_score})")

    # ---- 2. Behavioral detection (scan / DoS / brute force) ----
    for hit in engine.inspect(src_ip, dst_port, is_syn, now=ts):
        if alert_behavior(src_ip, hit["type"], hit["severity"], hit["score"], hit["detail"]):
            print(f"[ALERT] {hit['type']} from {src_ip} - {hit['detail']}")


def _read_pcap(interface, IoCs):
    """Live packet capture from a network interface."""
    asyncio.set_event_loop(asyncio.new_event_loop())
    engine = BehaviorEngine()
    capture = pyshark.LiveCapture(interface=interface)
    print(f"[*] Starting packet sniffing on {interface}. Press Ctrl+C to stop.")

    try:
        for packet in capture.sniff_continuously():
            _process_packet(packet, engine, IoCs, source=interface)
    except KeyboardInterrupt:
        print("\n[*] Packet capture stopped by user.")
    except TSharkCrashException as e:
        print(f"[ERROR] TShark crashed unexpectedly: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")


def _read_file(pcap_path, IoCs):
    """Replay a saved capture file (.pcap / .pcapng) through the analyzers."""
    asyncio.set_event_loop(asyncio.new_event_loop())
    engine = BehaviorEngine()
    print(f"[*] Replaying capture file: {pcap_path}")

    try:
        capture = pyshark.FileCapture(pcap_path, keep_packets=False)
        count = 0
        for packet in capture:
            _process_packet(packet, engine, IoCs, source=pcap_path)
            count += 1
        capture.close()
        print(f"[*] Finished replaying {count} packets from {pcap_path}.")
    except FileNotFoundError:
        print(f"[ERROR] Capture file not found: {pcap_path}")
    except TSharkCrashException as e:
        print(f"[ERROR] TShark crashed unexpectedly: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
