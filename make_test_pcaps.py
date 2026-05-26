"""
Generate attack capture files for testing the IDS behavioral detectors.

Creates three small .pcap files - each one contains crafted TCP packets
that trip exactly one detector:

    portscan.pcap     -> Port scan      (40 ports probed by one IP)
    dos.pcap          -> DoS            (700 SYN packets from one IP)
    bruteforce.pcap   -> Brute force    (25 SSH connection attempts)

Pure standard library - packets are built with `struct` and written in
classic pcap format, so no scapy / extra install is needed.

Run it, then replay a file through the IDS:

    python make_test_pcaps.py
    python main.py portscan.pcap
"""

import struct

# Documentation / private addresses (RFC 5737, RFC 1918) - safe and non-routable.
VICTIM         = "10.0.0.5"
ATTACKER_SCAN  = "203.0.113.10"
ATTACKER_DOS   = "198.51.100.20"
ATTACKER_BRUTE = "192.0.2.30"

SYN = 0x02   # TCP SYN flag


def _ip_bytes(ip):
    return bytes(int(octet) for octet in ip.split("."))


def _checksum(data):
    """Standard 16-bit one's-complement checksum (used for the IPv4 header)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _tcp_frame(src_ip, dst_ip, src_port, dst_port, flags=SYN):
    """Build a complete Ethernet + IPv4 + TCP frame (no payload)."""
    eth = (b"\x02\x00\x00\x00\x00\x02"   # destination MAC
           b"\x02\x00\x00\x00\x00\x01"   # source MAC
           b"\x08\x00")                  # ethertype = IPv4

    tcp = struct.pack(">HHIIBBHHH",
                      src_port, dst_port,
                      0,        # sequence number
                      0,        # acknowledgement number
                      0x50,     # data offset (5 32-bit words) + reserved
                      flags,    # TCP flags
                      8192,     # window size
                      0,        # checksum (0 = left unverified; fine for dissection)
                      0)        # urgent pointer

    ip = struct.pack(">BBHHHBBH",
                     0x45,            # version (4) + header length (5 words)
                     0,               # DSCP / ECN
                     20 + len(tcp),   # total length
                     0,               # identification
                     0x4000,          # flags (Don't Fragment)
                     64,              # TTL
                     6,               # protocol = TCP
                     0)               # header checksum placeholder
    ip += _ip_bytes(src_ip) + _ip_bytes(dst_ip)
    ip = ip[:10] + struct.pack(">H", _checksum(ip)) + ip[12:]

    return eth + ip + tcp


def _write_pcap(path, packets):
    """Write `packets` (list of (timestamp, frame_bytes)) as a classic pcap file."""
    with open(path, "wb") as f:
        # Global header: magic, version 2.4, tz=0, sigfigs=0, snaplen, linktype=1 (Ethernet)
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
    print(f"[+] Wrote {path}  ({len(packets)} packets)")


def make_portscan(path="portscan.pcap"):
    """One IP probes 40 different ports in ~6 s -> trips the port-scan detector."""
    base = 1_700_000_000
    packets = [
        (base + i * 0.15,
         _tcp_frame(ATTACKER_SCAN, VICTIM, 40000 + i, dst_port=1 + i))
        for i in range(40)
    ]
    _write_pcap(path, packets)


def make_dos(path="dos.pcap"):
    """One IP sends 700 SYN packets to port 80 in ~7 s -> trips the DoS detector."""
    base = 1_700_000_100
    packets = [
        (base + i * 0.01,
         _tcp_frame(ATTACKER_DOS, VICTIM, 50000 + (i % 5000), dst_port=80))
        for i in range(700)
    ]
    _write_pcap(path, packets)


def make_bruteforce(path="bruteforce.pcap"):
    """One IP makes 25 connection attempts to SSH (port 22) in ~20 s -> brute force."""
    base = 1_700_000_200
    packets = [
        (base + i * 0.8,
         _tcp_frame(ATTACKER_BRUTE, VICTIM, 60000 + i, dst_port=22))
        for i in range(25)
    ]
    _write_pcap(path, packets)


if __name__ == "__main__":
    make_portscan()
    make_dos()
    make_bruteforce()
    print("[*] Done. Test a file with:  python main.py portscan.pcap")
