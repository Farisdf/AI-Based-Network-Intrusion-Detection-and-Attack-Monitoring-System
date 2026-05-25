"""
Behavioral attack detection.

The IP-reputation check (Check_IP) answers "is this IP known-bad?". This
module answers "is this IP *behaving* like an attack?" by tracking, per
source IP over sliding time windows:

  * Port scan   - many distinct destination ports probed
  * DoS         - an abnormally high packet / TCP-SYN rate
  * Brute force - many connection attempts to a login service port

Each window is keyed off the packet's own capture timestamp, so the engine
works identically for a live capture and for a replayed .pcap file.

All thresholds below are easy to tune for your test environment.
"""

import time
from collections import deque, defaultdict, Counter

# ---- Tunable thresholds --------------------------------------------------
PORTSCAN_WINDOW = 10      # seconds
PORTSCAN_PORTS  = 15      # distinct dst ports from one IP -> port scan

DOS_WINDOW      = 10      # seconds
DOS_PACKETS     = 500     # packets from one IP -> packet flood
DOS_SYN         = 100     # TCP SYNs from one IP -> SYN flood

BRUTE_WINDOW    = 30      # seconds
BRUTE_ATTEMPTS  = 10      # connection attempts to one service -> brute force

# Login / service ports worth watching for brute force.
SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3",
    143: "IMAP", 389: "LDAP", 445: "SMB", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
}

_GC_EVERY = 5000          # sweep idle per-IP state every N packets
_MAXLEN   = 4000          # hard cap on per-IP timestamp history (bounds memory)


class BehaviorEngine:
    """Stateful detector. Feed it one packet at a time via inspect()."""

    def __init__(self):
        self._ports   = defaultdict(deque)                          # ip -> deque[(ts, port)]
        self._portcnt = defaultdict(Counter)                        # ip -> Counter(port -> live count)
        self._pkts    = defaultdict(lambda: deque(maxlen=_MAXLEN))   # ip -> deque[ts]
        self._syns    = defaultdict(lambda: deque(maxlen=_MAXLEN))   # ip -> deque[ts]
        self._brute   = defaultdict(lambda: deque(maxlen=_MAXLEN))   # (ip, port) -> deque[ts]
        self._seen = 0

    def inspect(self, src_ip, dst_port, is_syn, now=None):
        """
        Feed one packet's fields.

          src_ip   - source IP (str)
          dst_port - destination port (int) or None if no TCP/UDP layer
          is_syn   - True for a TCP SYN connection attempt
          now      - packet capture timestamp (epoch float); defaults to wall clock

        Returns a list of detection dicts: {type, severity, score, detail}.
        """
        if now is None:
            now = time.time()
        hits = []

        # ---- Port scan: many distinct destination ports ----
        if dst_port is not None:
            ports = self._ports[src_ip]
            counts = self._portcnt[src_ip]
            ports.append((now, dst_port))
            counts[dst_port] += 1
            cutoff = now - PORTSCAN_WINDOW
            while ports and ports[0][0] < cutoff:
                _, old = ports.popleft()
                counts[old] -= 1
                if counts[old] <= 0:
                    del counts[old]
            distinct = len(counts)
            if distinct >= PORTSCAN_PORTS:
                hits.append({
                    "type": "Port scan", "severity": "high", "score": distinct,
                    "detail": f"{distinct} distinct ports probed within {PORTSCAN_WINDOW}s",
                })

        # ---- DoS: raw packet flood ----
        pkts = self._pkts[src_ip]
        pkts.append(now)
        cutoff = now - DOS_WINDOW
        while pkts and pkts[0] < cutoff:
            pkts.popleft()
        if len(pkts) >= DOS_PACKETS:
            hits.append({
                "type": "DoS / packet flood", "severity": "high", "score": len(pkts),
                "detail": f"{len(pkts)} packets within {DOS_WINDOW}s",
            })

        # ---- DoS: TCP SYN flood ----
        if is_syn:
            syns = self._syns[src_ip]
            syns.append(now)
            while syns and syns[0] < cutoff:
                syns.popleft()
            if len(syns) >= DOS_SYN:
                hits.append({
                    "type": "DoS / SYN flood", "severity": "high", "score": len(syns),
                    "detail": f"{len(syns)} TCP SYN packets within {DOS_WINDOW}s",
                })

        # ---- Brute force: repeated attempts to a login service ----
        if is_syn and dst_port in SERVICE_PORTS:
            attempts = self._brute[(src_ip, dst_port)]
            attempts.append(now)
            bcut = now - BRUTE_WINDOW
            while attempts and attempts[0] < bcut:
                attempts.popleft()
            if len(attempts) >= BRUTE_ATTEMPTS:
                svc = SERVICE_PORTS[dst_port]
                hits.append({
                    "type": "Brute force", "severity": "high", "score": len(attempts),
                    "detail": (f"{len(attempts)} connection attempts to {svc} "
                               f"(port {dst_port}) within {BRUTE_WINDOW}s"),
                })

        self._seen += 1
        if self._seen % _GC_EVERY == 0:
            self._gc(now)
        return hits

    def _gc(self, now):
        """Drop per-IP state that has gone idle, to keep memory bounded."""
        for ip in list(self._pkts):
            dq = self._pkts[ip]
            while dq and dq[0] < now - DOS_WINDOW:
                dq.popleft()
            if not dq:
                del self._pkts[ip]
        for ip in list(self._syns):
            dq = self._syns[ip]
            while dq and dq[0] < now - DOS_WINDOW:
                dq.popleft()
            if not dq:
                del self._syns[ip]
        for ip in list(self._ports):
            dq = self._ports[ip]
            counts = self._portcnt[ip]
            while dq and dq[0][0] < now - PORTSCAN_WINDOW:
                _, old = dq.popleft()
                counts[old] -= 1
                if counts[old] <= 0:
                    del counts[old]
            if not dq:
                del self._ports[ip]
                self._portcnt.pop(ip, None)
        for key in list(self._brute):
            dq = self._brute[key]
            while dq and dq[0] < now - BRUTE_WINDOW:
                dq.popleft()
            if not dq:
                del self._brute[key]
