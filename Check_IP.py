"""
Offline IP reputation lookup.

Loads Malicious_IP.csv (written by get_iocs.py) into memory once, then answers
membership queries. The blocklist is keyed by IP and maps to the IPsum score,
so callers can use the score for alert severity.
"""

import pandas as pd

BLOCKLIST_FILE = "Malicious_IP.csv"

malicious_ips = {}   # ip (str) -> score (int)
_loaded = False      # avoids re-reading the file on every packet


def load_malicious_ips():
    """Read the blocklist CSV into the module-level `malicious_ips` dict."""
    global malicious_ips
    try:
        df = pd.read_csv(BLOCKLIST_FILE, usecols=["ip", "score"])
        malicious_ips = dict(
            zip(df["ip"].astype(str), df["score"].astype(int))
        )
        print(f"[+] Loaded {len(malicious_ips)} malicious IPs for checking.")
    except Exception as e:
        print(f"[ERROR] Could not read {BLOCKLIST_FILE}: {e}")
        malicious_ips = {}


def check_IP_offline(ip):
    """
    Return the threat score (int > 0) if `ip` is on the blocklist,
    otherwise 0. The blocklist is loaded lazily on the first call.
    """
    global _loaded
    if not _loaded:
        load_malicious_ips()
        _loaded = True
    return malicious_ips.get(str(ip), 0)
