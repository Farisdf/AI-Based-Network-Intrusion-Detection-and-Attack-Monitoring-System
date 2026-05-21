# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A lightweight network intrusion detection system (IDS). It refreshes an IP
blocklist from an open-source threat feed, captures network traffic, and
raises alerts two ways:

- **IP reputation** — a packet's source/destination IP is on the blocklist.
- **Behavioral detection** — a source IP behaves like a *port scan*, *DoS*,
  or *brute force* attack.

A web dashboard visualises every detected attack.

## Running

The IDS and the dashboard run as two separate processes (two terminals):

```sh
python main.py              # live capture on the configured NIC (needs admin)
python main.py attack.pcap  # replay a capture file (no admin, no download)
python dashboard.py         # web dashboard at http://127.0.0.1:5000
```

Install dependencies:

```sh
pip install -r requirements.txt
```

Runtime prerequisites:
- **Wireshark / TShark** must be installed and on PATH — `pyshark` shells out to it.
- **Elevated privileges** are required for *live* packet capture (`python main.py`
  with no argument). Replay mode and `dashboard.py` do not need admin.
- The live capture interface is hardcoded as `NIC = "WiFi"` in [main.py](main.py);
  change it to match the local adapter (`tshark -D` lists interfaces).

## Architecture

1. **[main.py](main.py)** — entry point. No CLI argument → *live mode* (refresh
   IoCs, then sniff `NIC`). A `.pcap` path argument → *replay mode* (feed the
   file through the analyzers; no download).
2. **[get_iocs.py](get_iocs.py)** — `update_from_IoCs()` downloads the IPsum
   threat feed (`stamparm/ipsum`, raw `ipsum.txt`) over HTTPS with `urllib`,
   keeps IPs with score >= `min_score`, and overwrites `Malicious_IP.csv`
   (`ip,score`). On any failure the existing CSV is left intact.
3. **[IDS.py](IDS.py)** — capture + analysis. `_read_pcap()` does live capture,
   `_read_file()` replays a saved file; both feed `_process_packet()`, which
   runs the IP-reputation check **and** the behavioral engine on every packet.
4. **[Check_IP.py](Check_IP.py)** — `check_IP_offline()` looks an IP up in
   `Malicious_IP.csv` (lazily loaded into the `malicious_ips` dict, `ip ->
   score`). Returns the score (0 if not listed).
5. **[detectors.py](detectors.py)** — `BehaviorEngine` tracks per-source-IP
   sliding windows and flags **port scans** (many distinct dst ports), **DoS**
   (high packet / TCP-SYN rate), and **brute force** (many attempts to a login
   port). Thresholds are module-level constants — easy to tune.
6. **[alerting.py](alerting.py)** — `alert()` records IP-reputation hits;
   `alert_behavior()` records behavioral hits. Both write to `threat_log.csv`
   via `log_threat()` and apply a per-IP cooldown. SMTP email is optional.
7. **[dashboard.py](dashboard.py)** — Flask web app. Reads `threat_log.csv`
   and serves an auto-refreshing page with stats, a filterable detection
   table, and a top-attackers list. JSON feed at `/api/data`.

**[make_test_pcaps.py](make_test_pcaps.py)** — generates `portscan.pcap`,
`dos.pcap`, and `bruteforce.pcap` (pure-stdlib crafted captures) for testing
the behavioral detectors in replay mode.

Data flow: `Malicious_IP.csv` is written by `get_iocs.py`, read by
`Check_IP.py`. `threat_log.csv` is the append-only alert log — written by
`alerting.py`, read by `dashboard.py`.

## Important details

- **Behavioral thresholds** ([detectors.py](detectors.py)): port scan = 15
  distinct ports / 10 s; DoS = 500 packets or 100 SYNs / 10 s; brute force =
  10 attempts to a service port / 30 s. Windows key off each packet's capture
  timestamp, so detection is identical for live capture and pcap replay.
- **IoC feed:** IPsum aggregates 30+ public blocklists; each IP's score is the
  number of lists that flagged it. `min_score` (default 3) filters
  low-confidence entries. No `git`/GitPython dependency.
- **`threat_log.csv` schema:** header row plus
  `timestamp,ip,direction,threat_type,severity,score,description`. For
  reputation hits `score` is the IPsum score; for behavioral hits it is the
  intensity that triggered (port/packet/attempt count).
- **Alert cooldown:** `ALERT_COOLDOWN` (60 s) in `alerting.py` — the same
  IP+direction (reputation) or IP+attack-type (behavioral) is logged at most
  once per minute.
- **SMTP alerting is opt-in.** `ENABLE_EMAIL` in [alerting.py](alerting.py) is
  `False` by default. CSV logging always works regardless.
- **`check_ioc` flag:** `main.py` passes `check_ioc = 1` for offline checking.
  Any other value disables the IP-reputation check; behavioral detection still
  runs.
- **Lief.py is not wired into `main.py`.** Standalone PE-binary inspector that
  also *modifies* the binary. Logs findings via `log_threat()`.
- **error.txt** is a resolved historical asyncio traceback; not part of the
  program. **threat_log.csv.bak** is a backup of the pre-rewrite alert log.
